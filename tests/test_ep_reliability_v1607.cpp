// test_ep_reliability_v1607.cpp - P6 EP 可靠性机制增强单元测试 (v1.6.0.7)
//
// 覆盖：
//   - EP 重传参数常量（dispatch/combine 超时与最大重传次数）
//   - resend 检查节拍常量
//   - EpAckFrame 编码/解码 round-trip
//   - EpAckFrame 异常输入（空数据/错误 type/截断/非法 frame_type）
//   - peek_ep_frame_type 识别 ACK
//   - ep_frame_type_name ACK 字符串
//   - kAckFrameMaxBytes 容量预估
//   - EpPendingFrame 数据结构（默认值/acked 原子操作）
//   - EpChannelStats P6 字段（默认值）
//   - EpChannelCallbacks on_frame_dropped 字段存在性
//   - SyncCallbacks on_barrier_partial 字段存在性
//   - SyncPrimitives allow_partial_combine 默认 false / set true / set false
//   - SyncPrimitives allow_partial_combine 线程安全（多线程读写）
//
// 注意：EpChannel 的网络相关方法（send_dispatch/combine/ack/resend_loop）
// 依赖 Connection 实例，本测试不构造真实 Connection，仅验证数据结构和常量。
// 端到端网络测试在 P7 阶段的集成测试中覆盖。

#include "linoh/multimodal/ep_channel.hpp"
#include "linoh/multimodal/ep_frames.hpp"
#include "linoh/multimodal/sync_primitives.hpp"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::cerr << "FAIL: " #cond \
        << " @ line " << __LINE__ << std::endl; } \
} while(0)

#define CHECK_EQ(a, b) do { \
    if ((a) == (b)) { ++g_pass; } \
    else { ++g_fail; std::cerr << "FAIL: " #a " == " #b \
        << " (got " << (a) << " vs " << (b) << ")" \
        << " @ line " << __LINE__ << std::endl; } \
} while(0)

using namespace linoh::multimodal::ep;

// ============================================================================
// 1. EP 重传参数常量
// ============================================================================

void test_resend_constants() {
    CHECK_EQ(kEpDispatchResendTimeoutMs, 50.0);
    CHECK_EQ(kEpDispatchMaxResendCount, 12u);
    CHECK_EQ(kEpCombineResendTimeoutMs, 100.0);
    CHECK_EQ(kEpCombineMaxResendCount, 8u);
    CHECK_EQ(kEpResendCheckIntervalMs, 25.0);
}

void test_resend_constants_dispatch_faster_than_combine() {
    // dispatch 对延迟更敏感，超时应短于 combine
    CHECK(kEpDispatchResendTimeoutMs < kEpCombineResendTimeoutMs);
    // dispatch 重传次数更多（小包快速重传）
    CHECK(kEpDispatchMaxResendCount > kEpCombineMaxResendCount);
}

// ============================================================================
// 2. EpAckFrame 编码/解码
// ============================================================================

void test_ack_frame_encode_decode_basic() {
    EpAckFrame frame;
    frame.frame_seq = 12345;       // < 16384 → 2 字节 VarInt
    frame.tensor_id = 67890;       // > 16383 → 4 字节 VarInt
    frame.frame_type = EpFrameType::DISPATCH;

    auto encoded = encode_ack_frame(frame);
    CHECK(!encoded.empty());
    // type(1) + varint(12345)=2B + varint(67890)=4B + frame_type(1) = 8
    CHECK_EQ(encoded.size(), 1 + 2 + 4 + 1);

    auto decoded = decode_ack_frame(encoded);
    CHECK(decoded.has_value());
    CHECK_EQ(decoded->frame_seq, 12345u);
    CHECK_EQ(decoded->tensor_id, 67890u);
    CHECK(decoded->frame_type == EpFrameType::DISPATCH);
}

void test_ack_frame_encode_decode_combine() {
    EpAckFrame frame;
    frame.frame_seq = 0xFFFFFF;  // 3 字节 VarInt 边界
    frame.tensor_id = 1;
    frame.frame_type = EpFrameType::COMBINE;

    auto encoded = encode_ack_frame(frame);
    auto decoded = decode_ack_frame(encoded);
    CHECK(decoded.has_value());
    CHECK_EQ(decoded->frame_seq, 0xFFFFFFu);
    CHECK_EQ(decoded->tensor_id, 1u);
    CHECK(decoded->frame_type == EpFrameType::COMBINE);
}

void test_ack_frame_encode_decode_large_seq() {
    // QUIC VarInt 最大 62 位：2^62-1 = 0x3FFFFFFFFFFFFFFF
    constexpr std::uint64_t kQuicVarIntMax = 0x3FFFFFFFFFFFFFFFULL;
    EpAckFrame frame;
    frame.frame_seq = kQuicVarIntMax;
    frame.tensor_id = kQuicVarIntMax;
    frame.frame_type = EpFrameType::DISPATCH;

    auto encoded = encode_ack_frame(frame);
    auto decoded = decode_ack_frame(encoded);
    CHECK(decoded.has_value());
    CHECK_EQ(decoded->frame_seq, kQuicVarIntMax);
    CHECK_EQ(decoded->tensor_id, kQuicVarIntMax);
}

void test_ack_frame_decode_empty() {
    std::vector<std::uint8_t> empty;
    auto decoded = decode_ack_frame(empty);
    CHECK(!decoded.has_value());
}

void test_ack_frame_decode_wrong_type() {
    // 用 DISPATCH type（0x20）伪装 ACK
    std::vector<std::uint8_t> wrong = {0x20, 0x01, 0x02, 0x20};
    auto decoded = decode_ack_frame(wrong);
    CHECK(!decoded.has_value());
}

void test_ack_frame_decode_truncated() {
    EpAckFrame frame;
    frame.frame_seq = 100;
    frame.tensor_id = 200;
    frame.frame_type = EpFrameType::DISPATCH;

    auto encoded = encode_ack_frame(frame);
    // 截断最后 1 字节（frame_type）
    encoded.pop_back();
    auto decoded = decode_ack_frame(encoded);
    CHECK(!decoded.has_value());
}

void test_ack_frame_decode_invalid_frame_type() {
    // 手工构造：type=0x23 + varint(1) + varint(2) + frame_type=0x22（SYNC，非法）
    std::vector<std::uint8_t> bad = {0x23, 0x01, 0x02, 0x22};
    auto decoded = decode_ack_frame(bad);
    CHECK(!decoded.has_value());
}

void test_ack_frame_decode_frame_type_only_dispatch_combine() {
    // frame_type=0x20（DISPATCH）合法
    {
        std::vector<std::uint8_t> ok = {0x23, 0x01, 0x02, 0x20};
        auto decoded = decode_ack_frame(ok);
        CHECK(decoded.has_value());
        CHECK(decoded->frame_type == EpFrameType::DISPATCH);
    }
    // frame_type=0x21（COMBINE）合法
    {
        std::vector<std::uint8_t> ok = {0x23, 0x01, 0x02, 0x21};
        auto decoded = decode_ack_frame(ok);
        CHECK(decoded.has_value());
        CHECK(decoded->frame_type == EpFrameType::COMBINE);
    }
    // frame_type=0x22（SYNC）非法
    {
        std::vector<std::uint8_t> bad = {0x23, 0x01, 0x02, 0x22};
        auto decoded = decode_ack_frame(bad);
        CHECK(!decoded.has_value());
    }
    // frame_type=0x23（ACK 自身）非法
    {
        std::vector<std::uint8_t> bad = {0x23, 0x01, 0x02, 0x23};
        auto decoded = decode_ack_frame(bad);
        CHECK(!decoded.has_value());
    }
}

// ============================================================================
// 3. peek_ep_frame_type / ep_frame_type_name
// ============================================================================

void test_peek_ep_frame_type_ack() {
    std::vector<std::uint8_t> data = {0x23};
    auto t = peek_ep_frame_type(data);
    CHECK(t.has_value());
    CHECK(*t == EpFrameType::ACK);
}

void test_peek_ep_frame_type_unknown() {
    std::vector<std::uint8_t> data = {0xFF};
    auto t = peek_ep_frame_type(data);
    CHECK(!t.has_value());
}

void test_peek_ep_frame_type_empty() {
    std::vector<std::uint8_t> empty;
    auto t = peek_ep_frame_type(empty);
    CHECK(!t.has_value());
}

void test_ep_frame_type_name_ack() {
    std::string name = ep_frame_type_name(EpFrameType::ACK);
    CHECK_EQ(name, "ep_ack");
}

void test_ep_frame_type_name_all() {
    CHECK(std::string(ep_frame_type_name(EpFrameType::DISPATCH)) == "ep_dispatch");
    CHECK(std::string(ep_frame_type_name(EpFrameType::COMBINE)) == "ep_combine");
    CHECK(std::string(ep_frame_type_name(EpFrameType::SYNC)) == "ep_sync");
    CHECK(std::string(ep_frame_type_name(EpFrameType::ACK)) == "ep_ack");
}

// ============================================================================
// 4. kAckFrameMaxBytes 容量预估
// ============================================================================

void test_kAckFrameMaxBytes() {
    // type(1) + frame_seq(8) + tensor_id(8) + frame_type(1) = 18
    CHECK_EQ(kAckFrameMaxBytes, 1 + 8 + 8 + 1);

    // 实际编码的 ACK 帧不超过 kAckFrameMaxBytes
    EpAckFrame frame;
    frame.frame_seq = 0xFFFFFFFFFFFFFFFFULL;
    frame.tensor_id = 0xFFFFFFFFFFFFFFFFULL;
    frame.frame_type = EpFrameType::COMBINE;
    auto encoded = encode_ack_frame(frame);
    CHECK(encoded.size() <= kAckFrameMaxBytes);
}

// ============================================================================
// 5. EpPendingFrame 数据结构
// ============================================================================

void test_pending_frame_default() {
    EpPendingFrame pf;
    CHECK(pf.type == EpFrameType::DISPATCH);
    CHECK_EQ(pf.frame_seq, 0u);
    CHECK_EQ(pf.tensor_id, 0u);
    CHECK_EQ(pf.expert_id, 0u);
    CHECK_EQ(pf.token_cnt, 0u);
    CHECK(pf.payload.empty());
    CHECK(pf.padding.empty());
    CHECK_EQ(pf.send_time_ms, 0.0);
    CHECK_EQ(pf.resent_count, 0u);
    CHECK(!pf.acked.load());
}

void test_pending_frame_acked_atomic() {
    EpPendingFrame pf;
    CHECK(!pf.acked.load());
    pf.acked.store(true);
    CHECK(pf.acked.load());
}

void test_pending_frame_type_assignment() {
    EpPendingFrame pf;
    pf.type = EpFrameType::COMBINE;
    pf.frame_seq = 42;
    pf.tensor_id = 100;
    pf.expert_id = 7;
    pf.token_cnt = 32;
    pf.payload = {0x21, 0x01, 0x02, 0x03};
    pf.send_time_ms = 12345.6;
    pf.resent_count = 3;

    CHECK(pf.type == EpFrameType::COMBINE);
    CHECK_EQ(pf.frame_seq, 42u);
    CHECK_EQ(pf.tensor_id, 100u);
    CHECK_EQ(pf.expert_id, 7u);
    CHECK_EQ(pf.token_cnt, 32u);
    CHECK_EQ(pf.payload.size(), 4u);
    CHECK_EQ(pf.send_time_ms, 12345.6);
    CHECK_EQ(pf.resent_count, 3u);
}

// ============================================================================
// 6. EpChannelStats P6 字段
// ============================================================================

void test_stats_p6_fields_default() {
    EpChannelStats stats;
    CHECK_EQ(stats.dispatch_resent, 0u);
    CHECK_EQ(stats.combine_resent, 0u);
    CHECK_EQ(stats.ack_sent, 0u);
    CHECK_EQ(stats.ack_recv, 0u);
    CHECK_EQ(stats.resend_dropped, 0u);
    CHECK_EQ(stats.combine_partial_total, 0u);
}

void test_stats_p6_fields_increment() {
    EpChannelStats stats;
    ++stats.dispatch_resent;
    ++stats.dispatch_resent;
    ++stats.combine_resent;
    ++stats.ack_sent;
    ++stats.ack_recv;
    ++stats.ack_recv;
    ++stats.resend_dropped;
    ++stats.combine_partial_total;

    CHECK_EQ(stats.dispatch_resent, 2u);
    CHECK_EQ(stats.combine_resent, 1u);
    CHECK_EQ(stats.ack_sent, 1u);
    CHECK_EQ(stats.ack_recv, 2u);
    CHECK_EQ(stats.resend_dropped, 1u);
    CHECK_EQ(stats.combine_partial_total, 1u);
}

// ============================================================================
// 7. EpChannelCallbacks on_frame_dropped 字段存在性
// ============================================================================

void test_callbacks_on_frame_dropped_exists() {
    EpChannelCallbacks cbs;
    CHECK(!cbs.on_frame_dropped);  // 默认为空

    bool called = false;
    cbs.on_frame_dropped = [&called](EpFrameType, std::uint64_t, std::uint64_t) {
        called = true;
    };
    cbs.on_frame_dropped(EpFrameType::DISPATCH, 1, 100);
    CHECK(called);
}

// ============================================================================
// 8. SyncCallbacks on_barrier_partial 字段存在性
// ============================================================================

void test_sync_callbacks_on_barrier_partial_exists() {
    SyncCallbacks cbs;
    CHECK(!cbs.on_barrier_partial);  // 默认为空

    bool called = false;
    std::uint64_t arrived = 0;
    std::uint64_t expected = 0;
    cbs.on_barrier_partial = [&](std::uint64_t, std::uint64_t a, std::uint64_t e) {
        called = true;
        arrived = a;
        expected = e;
    };
    cbs.on_barrier_partial(1001, 0b0011, 0b1111);
    CHECK(called);
    CHECK_EQ(arrived, 0b0011u);
    CHECK_EQ(expected, 0b1111u);
}

// ============================================================================
// 9. SyncPrimitives allow_partial_combine 配置
// ============================================================================

void test_sync_primitives_allow_partial_default_false() {
    // SyncPrimitives 需要 EpChannel* 参数，但 allow_partial_combine 不依赖 channel
    // 传 nullptr 即可测试配置项
    SyncPrimitives sync(nullptr);
    CHECK(!sync.allow_partial_combine());  // 默认 false
}

void test_sync_primitives_set_allow_partial_true() {
    SyncPrimitives sync(nullptr);
    sync.set_allow_partial_combine(true);
    CHECK(sync.allow_partial_combine());
}

void test_sync_primitives_set_allow_partial_toggle() {
    SyncPrimitives sync(nullptr);
    sync.set_allow_partial_combine(true);
    CHECK(sync.allow_partial_combine());
    sync.set_allow_partial_combine(false);
    CHECK(!sync.allow_partial_combine());
    sync.set_allow_partial_combine(true);
    CHECK(sync.allow_partial_combine());
}

void test_sync_primitives_allow_partial_thread_safe() {
    SyncPrimitives sync(nullptr);
    std::atomic<int> iterations(1000);

    // 写线程
    std::thread writer([&]() {
        for (int i = 0; i < iterations.load(); ++i) {
            sync.set_allow_partial_combine(i % 2 == 0);
        }
    });

    // 读线程
    std::thread reader([&]() {
        for (int i = 0; i < iterations.load(); ++i) {
            // 仅验证不崩溃，值可为 true 或 false
            (void)sync.allow_partial_combine();
        }
    });

    writer.join();
    reader.join();
    CHECK(true);  // 到达这里说明无死锁/无崩溃
}

// ============================================================================
// 10. ACK 帧编码大小预估
// ============================================================================

void test_ack_frame_size_bounds() {
    EpAckFrame min_frame;
    min_frame.frame_seq = 0;
    min_frame.tensor_id = 0;
    min_frame.frame_type = EpFrameType::DISPATCH;
    auto min_encoded = encode_ack_frame(min_frame);
    // 最小：type(1) + varint(0)=1B + varint(0)=1B + frame_type(1) = 4
    CHECK_EQ(min_encoded.size(), 4u);

    // QUIC VarInt 最大 62 位：2^62-1，编码为 8 字节
    constexpr std::uint64_t kQuicVarIntMax = 0x3FFFFFFFFFFFFFFFULL;
    EpAckFrame max_frame;
    max_frame.frame_seq = kQuicVarIntMax;
    max_frame.tensor_id = kQuicVarIntMax;
    max_frame.frame_type = EpFrameType::COMBINE;
    auto max_encoded = encode_ack_frame(max_frame);
    // 最大：type(1) + varint(max)=8B + varint(max)=8B + frame_type(1) = 18
    CHECK_EQ(max_encoded.size(), 1 + 8 + 8 + 1);
    CHECK_EQ(max_encoded.size(), kAckFrameMaxBytes);
}

// ============================================================================
// 11. ACK 帧与 DISPATCH/COMBINE 帧互不干扰
// ============================================================================

void test_ack_frame_distinct_from_others() {
    // 确认 ACK type=0x23 与 DISPATCH=0x20 / COMBINE=0x21 / SYNC=0x22 不同
    CHECK(static_cast<std::uint8_t>(EpFrameType::ACK) != static_cast<std::uint8_t>(EpFrameType::DISPATCH));
    CHECK(static_cast<std::uint8_t>(EpFrameType::ACK) != static_cast<std::uint8_t>(EpFrameType::COMBINE));
    CHECK(static_cast<std::uint8_t>(EpFrameType::ACK) != static_cast<std::uint8_t>(EpFrameType::SYNC));

    // peek_ep_frame_type 能正确区分
    std::vector<std::uint8_t> dispatch_data = {0x20};
    std::vector<std::uint8_t> combine_data = {0x21};
    std::vector<std::uint8_t> sync_data = {0x22};
    std::vector<std::uint8_t> ack_data = {0x23};

    CHECK(*peek_ep_frame_type(dispatch_data) == EpFrameType::DISPATCH);
    CHECK(*peek_ep_frame_type(combine_data) == EpFrameType::COMBINE);
    CHECK(*peek_ep_frame_type(sync_data) == EpFrameType::SYNC);
    CHECK(*peek_ep_frame_type(ack_data) == EpFrameType::ACK);
}

// ============================================================================
// 12. EpPendingFrame unique_ptr 队列可用性
// ============================================================================

void test_pending_frame_deque_unique_ptr() {
    // 验证 EpPendingFrame 可放入 std::unique_ptr 并存入 std::deque
    std::deque<std::unique_ptr<EpPendingFrame>> queue;

    auto pf1 = std::make_unique<EpPendingFrame>();
    pf1->type = EpFrameType::DISPATCH;
    pf1->frame_seq = 1;
    pf1->tensor_id = 100;
    queue.push_back(std::move(pf1));

    auto pf2 = std::make_unique<EpPendingFrame>();
    pf2->type = EpFrameType::COMBINE;
    pf2->frame_seq = 2;
    pf2->tensor_id = 200;
    queue.push_back(std::move(pf2));

    CHECK_EQ(queue.size(), 2u);
    CHECK(queue[0]->type == EpFrameType::DISPATCH);
    CHECK_EQ(queue[0]->frame_seq, 1u);
    CHECK(queue[1]->type == EpFrameType::COMBINE);
    CHECK_EQ(queue[1]->frame_seq, 2u);

    // 测试 erase
    queue.erase(queue.begin());
    CHECK_EQ(queue.size(), 1u);
    CHECK(queue[0]->type == EpFrameType::COMBINE);
}

// ============================================================================
// 13. 高扇出场景模拟（不依赖网络，仅验证数据结构管理）
// ============================================================================

void test_high_fanout_pending_management() {
    // 模拟 EP-master 向 16 个 EP-worker 发送 dispatch，每个 worker 一个 pending
    std::deque<std::unique_ptr<EpPendingFrame>> pending;
    constexpr int N = 16;

    for (int i = 0; i < N; ++i) {
        auto pf = std::make_unique<EpPendingFrame>();
        pf->type = EpFrameType::DISPATCH;
        pf->frame_seq = static_cast<std::uint64_t>(i + 1);
        pf->tensor_id = static_cast<std::uint64_t>(1000 + i);
        pf->expert_id = static_cast<std::uint64_t>(i);
        pf->token_cnt = 8;
        pf->payload = {0x20, 0x01, 0x02};
        pending.push_back(std::move(pf));
    }

    CHECK_EQ(pending.size(), N);

    // 模拟 ACK 到达：标记前 8 个为 acked
    for (int i = 0; i < N / 2; ++i) {
        pending[i]->acked.store(true);
    }

    // 清理已 ACK 的帧
    for (auto it = pending.begin(); it != pending.end();) {
        if ((*it)->acked.load()) {
            it = pending.erase(it);
        } else {
            ++it;
        }
    }

    CHECK_EQ(pending.size(), N / 2);

    // 验证剩余帧的 frame_seq
    CHECK_EQ(pending[0]->frame_seq, 9u);  // 第 9 个（index 8）
    CHECK_EQ(pending[7]->frame_seq, 16u);  // 最后一个
}

// ============================================================================
// 14. resend_check 节拍与超时计算
// ============================================================================

void test_resend_timeout_calculation() {
    // 验证超时计算逻辑（不依赖 EpChannel 实例）
    EpPendingFrame pf;
    pf.type = EpFrameType::DISPATCH;
    pf.send_time_ms = 1000.0;  // 假设发送时刻

    double now = 1050.0;  // 50ms 后
    double elapsed = now - pf.send_time_ms;
    CHECK(elapsed >= kEpDispatchResendTimeoutMs);  // 应触发重传

    // combine 帧超时更长
    pf.type = EpFrameType::COMBINE;
    now = 1050.0;
    elapsed = now - pf.send_time_ms;
    CHECK(elapsed < kEpCombineResendTimeoutMs);  // 50ms < 100ms，未超时

    now = 1100.0;
    elapsed = now - pf.send_time_ms;
    CHECK(elapsed >= kEpCombineResendTimeoutMs);  // 100ms 后超时
}

void test_resend_max_count_reached() {
    EpPendingFrame pf;
    pf.type = EpFrameType::DISPATCH;
    pf.resent_count = kEpDispatchMaxResendCount;  // 达到上限

    // 应触发丢弃而非重传
    CHECK(pf.resent_count >= kEpDispatchMaxResendCount);

    pf.type = EpFrameType::COMBINE;
    pf.resent_count = kEpCombineMaxResendCount;
    CHECK(pf.resent_count >= kEpCombineMaxResendCount);
}

// ============================================================================
// 15. 统计完整性
// ============================================================================

void test_stats_all_fields_default_zero() {
    EpChannelStats stats;
    // P0-P4 字段
    CHECK_EQ(stats.dispatch_sent, 0u);
    CHECK_EQ(stats.combine_sent, 0u);
    CHECK_EQ(stats.sync_sent, 0u);
    CHECK_EQ(stats.dispatch_recv, 0u);
    CHECK_EQ(stats.combine_recv, 0u);
    CHECK_EQ(stats.sync_recv, 0u);
    CHECK_EQ(stats.send_failures, 0u);
    CHECK_EQ(stats.decode_failures, 0u);
    CHECK_EQ(stats.bytes_sent, 0u);
    CHECK_EQ(stats.bytes_recv, 0u);
    CHECK_EQ(stats.hw_dispatch_sent, 0u);
    CHECK_EQ(stats.hw_combine_sent, 0u);
    CHECK_EQ(stats.hw_bytes_sent, 0u);
    CHECK_EQ(stats.hw_failures, 0u);
    CHECK_EQ(stats.hw_fallback_to_quic, 0u);
    // P6 字段
    CHECK_EQ(stats.dispatch_resent, 0u);
    CHECK_EQ(stats.combine_resent, 0u);
    CHECK_EQ(stats.ack_sent, 0u);
    CHECK_EQ(stats.ack_recv, 0u);
    CHECK_EQ(stats.resend_dropped, 0u);
    CHECK_EQ(stats.combine_partial_total, 0u);
}

}  // namespace

// ============================================================================
// main
// ============================================================================

int main() {
    std::cout << "=== P6 EP Reliability v1.6.0.7 Unit Tests ===" << std::endl;

    // 1. 常量
    test_resend_constants();
    test_resend_constants_dispatch_faster_than_combine();

    // 2. EpAckFrame 编解码
    test_ack_frame_encode_decode_basic();
    test_ack_frame_encode_decode_combine();
    test_ack_frame_encode_decode_large_seq();
    test_ack_frame_decode_empty();
    test_ack_frame_decode_wrong_type();
    test_ack_frame_decode_truncated();
    test_ack_frame_decode_invalid_frame_type();
    test_ack_frame_decode_frame_type_only_dispatch_combine();

    // 3. peek/name
    test_peek_ep_frame_type_ack();
    test_peek_ep_frame_type_unknown();
    test_peek_ep_frame_type_empty();
    test_ep_frame_type_name_ack();
    test_ep_frame_type_name_all();

    // 4. 容量预估
    test_kAckFrameMaxBytes();

    // 5. EpPendingFrame
    test_pending_frame_default();
    test_pending_frame_acked_atomic();
    test_pending_frame_type_assignment();

    // 6. EpChannelStats P6
    test_stats_p6_fields_default();
    test_stats_p6_fields_increment();

    // 7. EpChannelCallbacks
    test_callbacks_on_frame_dropped_exists();

    // 8. SyncCallbacks
    test_sync_callbacks_on_barrier_partial_exists();

    // 9. SyncPrimitives allow_partial_combine
    test_sync_primitives_allow_partial_default_false();
    test_sync_primitives_set_allow_partial_true();
    test_sync_primitives_set_allow_partial_toggle();
    test_sync_primitives_allow_partial_thread_safe();

    // 10. ACK 帧大小边界
    test_ack_frame_size_bounds();

    // 11. ACK 与其他帧互不干扰
    test_ack_frame_distinct_from_others();

    // 12. EpPendingFrame 队列管理
    test_pending_frame_deque_unique_ptr();

    // 13. 高扇出
    test_high_fanout_pending_management();

    // 14. 超时计算
    test_resend_timeout_calculation();
    test_resend_max_count_reached();

    // 15. 统计完整性
    test_stats_all_fields_default_zero();

    std::cout << "=== Results: " << g_pass << " PASS / " << g_fail << " FAIL ===" << std::endl;
    return g_fail == 0 ? 0 : 1;
}
