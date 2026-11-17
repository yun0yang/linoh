// test_channel_stats.cpp — B4 通道公平性计数器测试（v1.7.0.2 P1）
//
// 覆盖：
//   - ChannelStatsRegistry 构造/析构
//   - record_send/recv/loss 基本功能
//   - snapshot 单通道读取
//   - all_snapshots 9 通道
//   - fairness_ratio 边界（全零/单通道/均匀/不均匀）
//   - reset
//   - 线程安全（并发 record + snapshot）
//   - 按 ChannelType 隔离
//   - 字节与包独立计数
//   - 大数累加不溢出

#include "linoh/multimodal/channel_stats.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::multimodal;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 测试 1: 构造与初始状态
// ============================================================================
static void test_construction() {
    std::printf("[test] construction...\n");

    ChannelStatsRegistry reg;
    auto s = reg.snapshot(ChannelType::LLM_HIDDEN);
    CHECK(s.type == ChannelType::LLM_HIDDEN);
    CHECK(s.bytes_sent == 0);
    CHECK(s.bytes_received == 0);
    CHECK(s.packets_sent == 0);
    CHECK(s.packets_received == 0);
    CHECK(s.lost_packets == 0);
}

// ============================================================================
// 测试 2: record_send 基本功能
// ============================================================================
static void test_record_send_basic() {
    std::printf("[test] record_send basic...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 1000);
    reg.record_send(ChannelType::LLM_HIDDEN, 500, 2);

    auto s = reg.snapshot(ChannelType::LLM_HIDDEN);
    CHECK(s.bytes_sent == 1500);
    CHECK(s.packets_sent == 3);  // 1 + 2
}

// ============================================================================
// 测试 3: record_recv 基本功能
// ============================================================================
static void test_record_recv_basic() {
    std::printf("[test] record_recv basic...\n");

    ChannelStatsRegistry reg;
    reg.record_recv(ChannelType::VIDEO_FEATURE, 2048);
    reg.record_recv(ChannelType::VIDEO_FEATURE, 1024, 4);

    auto s = reg.snapshot(ChannelType::VIDEO_FEATURE);
    CHECK(s.bytes_received == 3072);
    CHECK(s.packets_received == 5);  // 1 + 4
}

// ============================================================================
// 测试 4: record_loss 基本功能
// ============================================================================
static void test_record_loss_basic() {
    std::printf("[test] record_loss basic...\n");

    ChannelStatsRegistry reg;
    reg.record_loss(ChannelType::IMG_FEATURE);
    reg.record_loss(ChannelType::IMG_FEATURE, 5);

    auto s = reg.snapshot(ChannelType::IMG_FEATURE);
    CHECK(s.lost_packets == 6);
}

// ============================================================================
// 测试 5: 按 ChannelType 隔离
// ============================================================================
static void test_channel_isolation() {
    std::printf("[test] channel isolation...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 1000);
    reg.record_send(ChannelType::VIDEO_FEATURE, 2000);
    reg.record_send(ChannelType::IMG_FEATURE, 3000);

    auto s_llm = reg.snapshot(ChannelType::LLM_HIDDEN);
    auto s_vid = reg.snapshot(ChannelType::VIDEO_FEATURE);
    auto s_img = reg.snapshot(ChannelType::IMG_FEATURE);
    auto s_ctrl = reg.snapshot(ChannelType::CONTROL);

    CHECK(s_llm.bytes_sent == 1000);
    CHECK(s_vid.bytes_sent == 2000);
    CHECK(s_img.bytes_sent == 3000);
    CHECK(s_ctrl.bytes_sent == 0);  // 控制信道未记录
}

// ============================================================================
// 测试 6: all_snapshots 返回 9 个通道
// ============================================================================
static void test_all_snapshots_count() {
    std::printf("[test] all_snapshots count...\n");

    ChannelStatsRegistry reg;
    auto all = reg.all_snapshots();
    CHECK(all.size() == 9);

    // 验证枚举顺序
    CHECK(all[0].type == ChannelType::CONTROL);
    CHECK(all[1].type == ChannelType::LLM_HIDDEN);
    CHECK(all[2].type == ChannelType::IMG_FEATURE);
    CHECK(all[3].type == ChannelType::VIDEO_FEATURE);
    CHECK(all[4].type == ChannelType::AUDIO_FEATURE);
    CHECK(all[5].type == ChannelType::FUSION);
    CHECK(all[6].type == ChannelType::EP_DISPATCH);
    CHECK(all[7].type == ChannelType::EP_COMBINE);
    CHECK(all[8].type == ChannelType::EP_SYNC);
}

// ============================================================================
// 测试 7: fairness_ratio 全零返回 1.0
// ============================================================================
static void test_fairness_ratio_all_zero() {
    std::printf("[test] fairness_ratio all zero...\n");

    ChannelStatsRegistry reg;
    CHECK(reg.fairness_ratio() == 1.0);
}

// ============================================================================
// 测试 8: fairness_ratio 单通道（只有 LLM_HIDDEN 有数据）
// ============================================================================
static void test_fairness_ratio_single_channel() {
    std::printf("[test] fairness_ratio single channel...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 1000);

    // 仅一个数据通道有数据，max==min==1000，比率 1.0
    CHECK(reg.fairness_ratio() == 1.0);
}

// ============================================================================
// 测试 9: fairness_ratio 均匀分布（所有数据通道字节数相等）
// ============================================================================
static void test_fairness_ratio_uniform() {
    std::printf("[test] fairness_ratio uniform...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 1000);
    reg.record_send(ChannelType::VIDEO_FEATURE, 1000);
    reg.record_send(ChannelType::IMG_FEATURE, 1000);

    CHECK(reg.fairness_ratio() == 1.0);
}

// ============================================================================
// 测试 10: fairness_ratio 不均匀
// ============================================================================
static void test_fairness_ratio_skewed() {
    std::printf("[test] fairness_ratio skewed...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 1000);
    reg.record_send(ChannelType::VIDEO_FEATURE, 500);
    reg.record_send(ChannelType::IMG_FEATURE, 100);

    // max=1000, min=100, ratio=10.0
    double r = reg.fairness_ratio();
    CHECK(r >= 9.9 && r <= 10.1);
}

// ============================================================================
// 测试 11: fairness_ratio 排除 CONTROL 通道
// ============================================================================
static void test_fairness_ratio_excludes_control() {
    std::printf("[test] fairness_ratio excludes control...\n");

    ChannelStatsRegistry reg;
    // 仅 CONTROL 有数据
    reg.record_send(ChannelType::CONTROL, 10000);

    // 没有数据通道，应返回 1.0
    CHECK(reg.fairness_ratio() == 1.0);
}

// ============================================================================
// 测试 12: fairness_ratio CONTROL 不参与计算
// ============================================================================
static void test_fairness_ratio_control_not_counted() {
    std::printf("[test] fairness_ratio control not counted...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::CONTROL, 10000);      // 不参与
    reg.record_send(ChannelType::LLM_HIDDEN, 1000);   // 数据通道 1
    reg.record_send(ChannelType::VIDEO_FEATURE, 500); // 数据通道 2

    // max=1000, min=500, ratio=2.0（CONTROL 的 10000 不影响）
    double r = reg.fairness_ratio();
    CHECK(r >= 1.9 && r <= 2.1);
}

// ============================================================================
// 测试 13: reset 清零所有计数器
// ============================================================================
static void test_reset() {
    std::printf("[test] reset...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 1000);
    reg.record_recv(ChannelType::VIDEO_FEATURE, 2000);
    reg.record_loss(ChannelType::IMG_FEATURE, 5);

    reg.reset();

    for (auto &s : reg.all_snapshots()) {
        CHECK(s.bytes_sent == 0);
        CHECK(s.bytes_received == 0);
        CHECK(s.packets_sent == 0);
        CHECK(s.packets_received == 0);
        CHECK(s.lost_packets == 0);
    }
}

// ============================================================================
// 测试 14: 字节与包独立计数
// ============================================================================
static void test_bytes_packets_independent() {
    std::printf("[test] bytes packets independent...\n");

    ChannelStatsRegistry reg;
    // 一次发送 1000 字节，但 10 个包
    reg.record_send(ChannelType::VIDEO_FEATURE, 1000, 10);

    auto s = reg.snapshot(ChannelType::VIDEO_FEATURE);
    CHECK(s.bytes_sent == 1000);
    CHECK(s.packets_sent == 10);

    // 再发 500 字节，1 个包
    reg.record_send(ChannelType::VIDEO_FEATURE, 500, 1);
    s = reg.snapshot(ChannelType::VIDEO_FEATURE);
    CHECK(s.bytes_sent == 1500);
    CHECK(s.packets_sent == 11);
}

// ============================================================================
// 测试 15: send 和 recv 独立计数
// ============================================================================
static void test_send_recv_independent() {
    std::printf("[test] send recv independent...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 1000);
    reg.record_recv(ChannelType::LLM_HIDDEN, 2000);

    auto s = reg.snapshot(ChannelType::LLM_HIDDEN);
    CHECK(s.bytes_sent == 1000);
    CHECK(s.bytes_received == 2000);
}

// ============================================================================
// 测试 16: 大数累加不溢出
// ============================================================================
static void test_large_accumulation() {
    std::printf("[test] large accumulation...\n");

    ChannelStatsRegistry reg;
    // 累加 1GB
    std::uint64_t one_gb = 1024ULL * 1024ULL * 1024ULL;
    for (int i = 0; i < 100; ++i) {
        reg.record_send(ChannelType::VIDEO_FEATURE, one_gb, 1);
    }

    auto s = reg.snapshot(ChannelType::VIDEO_FEATURE);
    CHECK(s.bytes_sent == one_gb * 100);
    CHECK(s.packets_sent == 100);
}

// ============================================================================
// 测试 17: 未知 ChannelType 防御（超出枚举范围）
// ============================================================================
static void test_unknown_channel_type() {
    std::printf("[test] unknown channel type...\n");

    ChannelStatsRegistry reg;
    // 强制转换为超出范围的值
    auto unknown = static_cast<ChannelType>(255);
    reg.record_send(unknown, 100);

    // 应写入索引 0（CONTROL）而非越界
    auto s_ctrl = reg.snapshot(ChannelType::CONTROL);
    CHECK(s_ctrl.bytes_sent == 100);
}

// ============================================================================
// 测试 18: EP 通道类型统计
// ============================================================================
static void test_ep_channels() {
    std::printf("[test] EP channels...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::EP_DISPATCH, 1000);
    reg.record_send(ChannelType::EP_COMBINE, 2000);
    reg.record_send(ChannelType::EP_SYNC, 500);

    CHECK(reg.snapshot(ChannelType::EP_DISPATCH).bytes_sent == 1000);
    CHECK(reg.snapshot(ChannelType::EP_COMBINE).bytes_sent == 2000);
    CHECK(reg.snapshot(ChannelType::EP_SYNC).bytes_sent == 500);
}

// ============================================================================
// 测试 19: record_recv 包数默认参数
// ============================================================================
static void test_record_recv_default_packets() {
    std::printf("[test] record_recv default packets...\n");

    ChannelStatsRegistry reg;
    reg.record_recv(ChannelType::AUDIO_FEATURE, 256);  // 默认 1 包

    auto s = reg.snapshot(ChannelType::AUDIO_FEATURE);
    CHECK(s.bytes_received == 256);
    CHECK(s.packets_received == 1);
}

// ============================================================================
// 测试 20: record_loss 默认参数
// ============================================================================
static void test_record_loss_default() {
    std::printf("[test] record_loss default...\n");

    ChannelStatsRegistry reg;
    reg.record_loss(ChannelType::FUSION);  // 默认 1

    auto s = reg.snapshot(ChannelType::FUSION);
    CHECK(s.lost_packets == 1);
}

// ============================================================================
// 测试 21: fairness_ratio 极端不均衡（100:1）
// ============================================================================
static void test_fairness_ratio_extreme() {
    std::printf("[test] fairness_ratio extreme...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 10000);
    reg.record_send(ChannelType::IMG_FEATURE, 100);

    double r = reg.fairness_ratio();
    CHECK(r >= 99.0 && r <= 101.0);
}

// ============================================================================
// 测试 22: 多次 reset 不影响功能
// ============================================================================
static void test_multiple_reset() {
    std::printf("[test] multiple reset...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 100);
    reg.reset();
    reg.reset();
    reg.record_send(ChannelType::LLM_HIDDEN, 50);

    CHECK(reg.snapshot(ChannelType::LLM_HIDDEN).bytes_sent == 50);
}

// ============================================================================
// 测试 23: 并发 record_send + snapshot（线程安全）
// ============================================================================
static void test_concurrent_record_and_snapshot() {
    std::printf("[test] concurrent record and snapshot...\n");

    ChannelStatsRegistry reg;
    std::atomic<bool> stop{false};
    std::atomic<int> errors{0};

    std::vector<std::thread> recorders;
    for (int t = 0; t < 4; ++t) {
        recorders.emplace_back([&reg, t, &stop]() {
            ChannelType types[] = {
                ChannelType::LLM_HIDDEN,
                ChannelType::VIDEO_FEATURE,
                ChannelType::IMG_FEATURE,
                ChannelType::AUDIO_FEATURE,
            };
            for (int i = 0; i < 10000; ++i) {
                reg.record_send(types[t], 100, 1);
            }
        });
    }

    std::thread snapshooter([&]() {
        while (!stop.load()) {
            auto s = reg.snapshot(ChannelType::LLM_HIDDEN);
            // 仅验证不崩溃，不验证具体值
            (void)s;
        }
    });

    std::thread fairness([&]() {
        while (!stop.load()) {
            double r = reg.fairness_ratio();
            (void)r;  // 仅验证不崩溃
        }
    });

    for (auto &t : recorders) t.join();
    stop = true;
    snapshooter.join();
    fairness.join();

    CHECK(errors.load() == 0);

    // 最终每个通道应有 10000 * 100 = 1000000 字节
    CHECK(reg.snapshot(ChannelType::LLM_HIDDEN).bytes_sent == 1000000);
    CHECK(reg.snapshot(ChannelType::VIDEO_FEATURE).bytes_sent == 1000000);
}

// ============================================================================
// 测试 24: 并发 record_send + record_recv + record_loss
// ============================================================================
static void test_concurrent_mixed_records() {
    std::printf("[test] concurrent mixed records...\n");

    ChannelStatsRegistry reg;
    std::vector<std::thread> threads;

    threads.emplace_back([&reg]() {
        for (int i = 0; i < 1000; ++i) {
            reg.record_send(ChannelType::LLM_HIDDEN, 100);
        }
    });
    threads.emplace_back([&reg]() {
        for (int i = 0; i < 1000; ++i) {
            reg.record_recv(ChannelType::LLM_HIDDEN, 200);
        }
    });
    threads.emplace_back([&reg]() {
        for (int i = 0; i < 1000; ++i) {
            reg.record_loss(ChannelType::LLM_HIDDEN, 1);
        }
    });

    for (auto &t : threads) t.join();

    auto s = reg.snapshot(ChannelType::LLM_HIDDEN);
    CHECK(s.bytes_sent == 100000);
    CHECK(s.bytes_received == 200000);
    CHECK(s.lost_packets == 1000);
}

// ============================================================================
// 测试 25: snapshot 一致性（5 个字段同时读取）
// ============================================================================
static void test_snapshot_consistency() {
    std::printf("[test] snapshot consistency...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::VIDEO_FEATURE, 1000, 10);
    reg.record_recv(ChannelType::VIDEO_FEATURE, 2000, 20);
    reg.record_loss(ChannelType::VIDEO_FEATURE, 5);

    auto s = reg.snapshot(ChannelType::VIDEO_FEATURE);
    // 所有字段应一致地反映已记录的值
    CHECK(s.type == ChannelType::VIDEO_FEATURE);
    CHECK(s.bytes_sent == 1000);
    CHECK(s.bytes_received == 2000);
    CHECK(s.packets_sent == 10);
    CHECK(s.packets_received == 20);
    CHECK(s.lost_packets == 5);
}

// ============================================================================
// 测试 26: all_snapshots 内容正确
// ============================================================================
static void test_all_snapshots_content() {
    std::printf("[test] all_snapshots content...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 100);
    reg.record_send(ChannelType::VIDEO_FEATURE, 200);
    reg.record_send(ChannelType::EP_DISPATCH, 300);

    auto all = reg.all_snapshots();

    CHECK(all[1].bytes_sent == 100);  // LLM_HIDDEN
    CHECK(all[3].bytes_sent == 200);  // VIDEO_FEATURE
    CHECK(all[6].bytes_sent == 300);  // EP_DISPATCH
    CHECK(all[0].bytes_sent == 0);    // CONTROL 未记录
}

// ============================================================================
// 测试 27: fairness_ratio 重置后恢复 1.0
// ============================================================================
static void test_fairness_ratio_after_reset() {
    std::printf("[test] fairness_ratio after reset...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 1000);
    reg.record_send(ChannelType::VIDEO_FEATURE, 100);
    CHECK(reg.fairness_ratio() > 1.0);

    reg.reset();
    CHECK(reg.fairness_ratio() == 1.0);
}

// ============================================================================
// 测试 28: 0 字节 record_send 不影响 fairness_ratio
// ============================================================================
static void test_zero_byte_record_no_effect() {
    std::printf("[test] zero byte record no effect...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 0);  // 0 字节
    reg.record_send(ChannelType::VIDEO_FEATURE, 1000);

    // LLM_HIDDEN 0 字节不计入 fairness（min_bytes 过滤掉 0）
    // 仅 VIDEO_FEATURE 有数据，max==min==1000，ratio=1.0
    CHECK(reg.fairness_ratio() == 1.0);
}

// ============================================================================
// 测试 29: record_send(0, 0) 不崩溃
// ============================================================================
static void test_zero_record_safe() {
    std::printf("[test] zero record safe...\n");

    ChannelStatsRegistry reg;
    reg.record_send(ChannelType::LLM_HIDDEN, 0, 0);
    reg.record_recv(ChannelType::LLM_HIDDEN, 0, 0);
    reg.record_loss(ChannelType::LLM_HIDDEN, 0);

    auto s = reg.snapshot(ChannelType::LLM_HIDDEN);
    CHECK(s.bytes_sent == 0);
    CHECK(s.packets_sent == 0);
    CHECK(s.bytes_received == 0);
    CHECK(s.lost_packets == 0);
}

// ============================================================================
// 测试 30: 长期运行稳定性（100 万次 record）
// ============================================================================
static void test_long_run_stability() {
    std::printf("[test] long run stability...\n");

    ChannelStatsRegistry reg;
    for (int i = 0; i < 100000; ++i) {
        reg.record_send(ChannelType::LLM_HIDDEN, 1, 1);
        reg.record_recv(ChannelType::LLM_HIDDEN, 1, 1);
    }

    auto s = reg.snapshot(ChannelType::LLM_HIDDEN);
    CHECK(s.bytes_sent == 100000);
    CHECK(s.bytes_received == 100000);
    CHECK(s.packets_sent == 100000);
    CHECK(s.packets_received == 100000);
}

int main() {
    std::printf("=== test_channel_stats (v1.7.0.2 P1 B4) ===\n");

    test_construction();
    test_record_send_basic();
    test_record_recv_basic();
    test_record_loss_basic();
    test_channel_isolation();
    test_all_snapshots_count();
    test_fairness_ratio_all_zero();
    test_fairness_ratio_single_channel();
    test_fairness_ratio_uniform();
    test_fairness_ratio_skewed();
    test_fairness_ratio_excludes_control();
    test_fairness_ratio_control_not_counted();
    test_reset();
    test_bytes_packets_independent();
    test_send_recv_independent();
    test_large_accumulation();
    test_unknown_channel_type();
    test_ep_channels();
    test_record_recv_default_packets();
    test_record_loss_default();
    test_fairness_ratio_extreme();
    test_multiple_reset();
    test_concurrent_record_and_snapshot();
    test_concurrent_mixed_records();
    test_snapshot_consistency();
    test_all_snapshots_content();
    test_fairness_ratio_after_reset();
    test_zero_byte_record_no_effect();
    test_zero_record_safe();
    test_long_run_stability();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
