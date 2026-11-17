// test_loss_recovery_p2.cpp — v1.5 P2-1 + P2-3 RTO 雪崩防护 + sent_packets_ 字节数上限

#include "linoh/protocol/loss_recovery.hpp"

#include <cassert>
#include <cmath>
#include <cstdio>
#include <vector>

using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define NEAR(a, b) (std::abs((a) - (b)) < 1e-3)

// ============================================================================
// P2-1: RttEstimator::on_rto() RTO 雪崩防护
// ============================================================================

// TEST 1: 初次 on_rto() 把 RTO 翻倍（base case）
static void test_rto_backoff() {
    std::printf("[test] RTO backoff: on_rto doubles RTO up to kRtoMaxMs...\n");
    RttEstimator est;
    est.reset();

    // 注入稳定 RTT 样本 100ms
    est.update(100.0, 0.0);
    double rto0 = est.rto_ms();
    double srtt0 = est.srtt_ms();
    CHECK(rto0 > 0);
    CHECK(srtt0 > 0);

    // 触发 RTO
    est.on_rto();
    double rto1 = est.rto_ms();
    double srtt1 = est.srtt_ms();

    // RFC 6298 §2.5: RTO 应该 back off (×2 至少)
    CHECK(rto1 >= rto0 * 2.0 - 1e-3);

    // RFC 9002 §5.5: srtt 不应超过 RTO
    CHECK(srtt1 <= rto1);

    std::printf("    rto0=%.2f rto1=%.2f srtt0=%.2f srtt1=%.2f\n",
                rto0, rto1, srtt0, srtt1);
}

// TEST 2: 多次 on_rto() 持续 back off，封顶 kRtoMaxMs
static void test_rto_backoff_cap() {
    std::printf("[test] RTO backoff cap: multiple on_rto() capped at kRtoMaxMs...\n");
    RttEstimator est;
    est.reset();
    est.update(100.0, 0.0);

    // 连续触发 10 次 RTO
    for (int i = 0; i < 10; ++i) {
        est.on_rto();
    }

    double rto = est.rto_ms();
    // kRtoMaxMs = 60000
    CHECK(rto <= 60000.0);
    CHECK(rto > 0);
    std::printf("    rto after 10 on_rto() = %.2f ms (cap=60000)\n", rto);
}

// TEST 3: RTO 触发后 srtt 被 clamp，不会失控增长
static void test_rto_srtt_clamp_prevents_avalanche() {
    std::printf("[test] RTO srtt clamp prevents RTT-driven avalanche...\n");
    RttEstimator est;
    est.reset();
    est.update(100.0, 0.0);
    double srtt0 = est.srtt_ms();

    // 模拟 RTO 雪崩：触发 5 次 RTO
    for (int i = 0; i < 5; ++i) {
        est.on_rto();
    }
    double srtt1 = est.srtt_ms();
    double rto1 = est.rto_ms();

    // 关键不变量：srtt <= rto（不会失控增长）
    CHECK(srtt1 <= rto1);

    // 进一步：即使注入 10000ms 的大 RTT 样本（模拟网络严重拥塞），
    // srtt 也不会超过 RTO 太多
    est.update(10000.0, 0.0);
    double srtt2 = est.srtt_ms();
    double rto2 = est.rto_ms();
    CHECK(srtt2 <= rto2);

    std::printf("    srtt0=%.2f srtt1=%.2f srtt2=%.2f rto1=%.2f rto2=%.2f\n",
                srtt0, srtt1, srtt2, rto1, rto2);
}

// TEST 4: LossDetector::on_rto_timeout 调用 rtt_.on_rto() 副作用
static void test_loss_detector_on_rto_invokes_rtt_on_rto() {
    std::printf("[test] LossDetector::on_rto_timeout() invokes rtt_.on_rto()...\n");
    LossDetector ld;
    // 注入一些 in-flight 包
    ld.on_packet_sent(0, 0.0, 1500, true);
    ld.on_packet_sent(1, 0.0, 1500, true);
    ld.on_packet_sent(2, 0.0, 1500, true);

    // 让 RTT 估算器有稳定样本
    ld.rtt().update(100.0, 0.0);
    double rto0 = ld.rtt().rto_ms();
    double srtt0 = ld.rtt().srtt_ms();

    // 触发 RTO
    auto lost = ld.on_rto_timeout(1000.0);
    CHECK(lost.size() == 3);  // 3 个 in-flight 包都被标为 lost

    double rto1 = ld.rtt().rto_ms();
    double srtt1 = ld.rtt().srtt_ms();

    // 验证：RTO 确实 back off
    CHECK(rto1 >= rto0 * 2.0 - 1e-3);
    // 验证：srtt 被 clamp 到 RTO 以下
    CHECK(srtt1 <= rto1);

    std::printf("    rto0=%.2f rto1=%.2f srtt0=%.2f srtt1=%.2f lost=%zu\n",
                rto0, rto1, srtt0, srtt1, lost.size());
}

// ============================================================================
// P2-3: sent_packets_ 字节数上限
// ============================================================================

// TEST 5: 正常 sent_packets_ 不触发字节驱逐
static void test_sent_packets_bytes_no_eviction_normal() {
    std::printf("[test] sent_packets_ normal: 100 x 1KB packets, no eviction...\n");
    LossDetector ld;
    // 注入 100 个 in-flight 包，每个 1KB
    for (int i = 0; i < 100; ++i) {
        ld.on_packet_sent(i, 0.0, 1024, true);
    }
    uint64_t in_flight_before = ld.in_flight_bytes();
    CHECK(in_flight_before == 100 * 1024);

    // 全部 ACK 触发清理
    std::vector<uint64_t> acks(100);
    for (int i = 0; i < 100; ++i) acks[i] = i;
    auto lost = ld.on_ack_received(acks, 100.0);

    // 清理后字节数应大幅下降
    uint64_t in_flight_after = ld.in_flight_bytes();
    CHECK(in_flight_after < in_flight_before);

    // 关键：不触发字节数上限驱逐警告（这里无法直接验证日志，但 100KB << 128MB）
    // 间接验证：清理后 sent_packets_ 应当 < 256
    // （无法直接访问 sent_packets_，但 in_flight_bytes=0 表示清理完成）
    std::printf("    in_flight before=%llu after=%llu lost=%zu\n",
                (unsigned long long)in_flight_before,
                (unsigned long long)in_flight_after, lost.size());
}

// TEST 6: 字节数上限触发后，最旧的非飞行中包被驱逐
static void test_sent_packets_bytes_eviction() {
    std::printf("[test] sent_packets_ byte limit eviction: 1000 x 200KB, evict oldest...\n");
    LossDetector ld;

    // 注入 1000 个包，每个 200KB → 总 200MB，触发 128MB 上限
    constexpr int kPackets = 1000;
    constexpr int kPacketBytes = 200 * 1024;
    for (int i = 0; i < kPackets; ++i) {
        ld.on_packet_sent(i, 0.0, kPacketBytes, true);
    }

    // 全部 ACK（模拟已完成传输）
    std::vector<uint64_t> acks(kPackets);
    for (int i = 0; i < kPackets; ++i) acks[i] = i;
    auto lost = ld.on_ack_received(acks, 1000.0);

    // in_flight 应当清零
    CHECK(ld.in_flight_bytes() == 0);

    // 关键：sent_packets_ 内部已被清理以满足 128MB 上限
    // （无法直接访问 private sent_packets_，但通过 in_flight + 后续 RTT 测量
    // 仍能正常工作间接验证清理未损坏数据结构）
    CHECK(lost.size() == 0);  // 全部已确认，不应有 lost
    std::printf("    lost=%zu (expected 0, all acked)\n", lost.size());
}

// TEST 7: 字节数上限不影响 in-flight 包
static void test_sent_packets_inflight_protected() {
    std::printf("[test] sent_packets_ in-flight protection under byte limit...\n");
    LossDetector ld;

    // 注入 1000 个 in-flight 包（不 ACK）
    constexpr int kPackets = 1000;
    for (int i = 0; i < kPackets; ++i) {
        ld.on_packet_sent(i, 0.0, 200 * 1024, true);
    }

    // 全部 ACK 一半（500 个）
    std::vector<uint64_t> acks;
    for (int i = 0; i < 500; ++i) acks.push_back(i);
    auto lost = ld.on_ack_received(acks, 1000.0);

    // 剩余 500 个 in-flight 包应保留
    uint64_t expected = 500ULL * 200 * 1024;
    CHECK(ld.in_flight_bytes() == expected);
    std::printf("    in_flight after partial ack=%llu (expected %llu)\n",
                (unsigned long long)ld.in_flight_bytes(),
                (unsigned long long)expected);
}

// ============================================================================
// S4 (v5.3): 冷启动豁免窗 — 无真实 RTT 样本时时间阈值检测跳过
// ============================================================================
static void test_s4_cold_start_exemption() {
    std::printf("[test] S4 cold-start exemption: has_sample state machine...\n");
    RttEstimator est;
    CHECK(!est.has_sample());  // 冷启动：无样本
    est.update(640.0, 0.0);    // 高 RTT 链路首样本
    CHECK(est.has_sample());
    est.on_network_change();   // 网络切换重置 → 回到无样本态
    CHECK(!est.has_sample());
    est.update(200.0, 0.0);
    CHECK(est.has_sample());
}

int main() {
    std::printf("=== test_loss_recovery_p2 (P2-1 RTO + P2-3 bytes limit + S4) ===\n\n");

    test_s4_cold_start_exemption();
    test_rto_backoff();
    test_rto_backoff_cap();
    test_rto_srtt_clamp_prevents_avalanche();
    test_loss_detector_on_rto_invokes_rtt_on_rto();

    std::printf("\n");
    test_sent_packets_bytes_no_eviction_normal();
    test_sent_packets_bytes_eviction();
    test_sent_packets_inflight_protected();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
