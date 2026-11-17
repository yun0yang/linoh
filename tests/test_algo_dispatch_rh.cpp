// test_algo_dispatch_rh.cpp — P4-E 算法分派单元测试（v2.3 Phase 4 / 方向 E）
//
// 验证 P4-E 交付物（handle_sync_frame 的 algo 路由逻辑 — RH 路径）：
//   1. all_reduce algo=2 (RH) 路径：无 partner 时 RH 降级到简化版
//   2. reduce_scatter algo=2 (RH) 路径：无 partner 时 RH 降级到简化版
//   3. all_reduce algo=0 (Ring) 不进入 RH 分派
//   4. reduce_scatter algo=0 (Ring) 不进入 RH 分派
//   5. all_reduce algo=1 (Tree) 不进入 RH 分派（all_reduce 无 Tree 路径）
//   6. 被动会话分派：handle_sync_frame 注入 AllReduce RH 帧时，会话不存在
//      → use_rh=false → 简化版 handle_all_reduce_ 创建被动会话
//   7. 被动会话分派：handle_sync_frame 注入 ReduceScatter RH 帧时，会话不存在
//      → use_rh=false → 简化版 handle_reduce_scatter_
//   8. 混合 algo 会话独立：不同 sync_id 用不同 algo 互不干扰
//   9. RH 路径接管失败（send 失败）→ 会话擦除 → 无泄漏
//  10. Signal/Barrier/未知 op 不参与 algo 分派
//  11. AllReduce N=2 RH 路径接管（null-channel）→ rh_algo 创建后 send 失败降级
//  12. ReduceScatter N=2 RH 路径接管（null-channel）→ rh_algo 创建后 send 失败降级
//  13. handle_sync_frame AllReduce RH 帧到达简化版被动会话 → 简化版处理
//  14. 多次 RH 调用无会话累积
//  15. all_reduce algo=RH N=4 null-channel partners → send 失败降级
//  16. AllReduce RH 帧到达后第二帧仍走简化版（被动会话 rh_algo=nullopt）
//
// 测试策略：
//   - SyncPrimitives(nullptr) 构造（channel_ 无效）
//   - all_reduce/reduce_scatter 的简化版在 channel_ 无效时不创建会话，
//     可通过 session_count()==0 验证 RH session 被正确擦除（无泄漏）
//   - EpChannel(nullptr) 作为 peer channel（conn_ 无效，send_sync 返回 false），
//     触发 all_reduce_rh_ 的 step 0 发送失败 → 会话擦除 → 降级简化版
//   - 通过 handle_sync_frame 注入 EpSyncFrame 模拟被动接收，验证分派路由
//   - 被动会话由简化版 handle_all_reduce_ 创建，algo=0（默认），rh_algo=nullopt
//
// 注：RH 状态机成功接管（rh_algo.has_value()==true 且多步通信完成）需要
//     真实 QUIC 连接，属集成测试范畴。算法正确性由 test_rh_engine.cpp 覆盖。
//     本测试聚焦于分派逻辑的可观察行为：降级路径、无泄漏、被动会话路由。

#include "linoh/multimodal/sync_primitives.hpp"
#include "linoh/multimodal/ep_channel.hpp"
#include "linoh/multimodal/rh_engine.hpp"

#include <cstdint>
#include <cstdio>
#include <span>
#include <vector>

using namespace linoh::multimodal::ep;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ============================================================================
// 辅助函数
// ============================================================================

static std::vector<std::uint8_t> make_u64(std::initializer_list<std::uint64_t> vals) {
    std::vector<std::uint8_t> data;
    data.reserve(vals.size() * 8);
    for (auto v : vals) {
        for (int i = 0; i < 8; ++i) {
            data.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
        }
    }
    return data;
}

/// 构造 AllReduce RH 帧（用于 handle_sync_frame 注入）
static EpSyncFrame make_allreduce_rh_frame(std::uint64_t sync_id,
                                            std::uint64_t from_bit,
                                            std::uint64_t participant_mask,
                                            const std::vector<std::uint8_t> &payload,
                                            std::uint16_t step = 0) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::AllReduce;
    frame.algo = 2;  // RH
    frame.participant_mask = participant_mask;
    frame.shard_idx = 0;
    frame.total_shards = 1;
    frame.payload = payload;
    frame.from_node_id = from_bit;
    frame.step = step;
    return frame;
}

/// 构造 ReduceScatter RH 帧（用于 handle_sync_frame 注入）
static EpSyncFrame make_rs_rh_frame(std::uint64_t sync_id,
                                     std::uint64_t from_bit,
                                     std::uint64_t participant_mask,
                                     const std::vector<std::uint8_t> &payload,
                                     std::uint16_t step = 0) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::ReduceScatter;
    frame.algo = 2;  // RH
    frame.participant_mask = participant_mask;
    frame.shard_idx = 0;
    frame.total_shards = 1;
    frame.payload = payload;
    frame.from_node_id = from_bit;
    frame.step = step;
    return frame;
}

// ============================================================================
// 测试 1: all_reduce algo=RH 无 partner → RH 降级，简化版 channel_ 无效 → nullopt
// ============================================================================
static void test_all_reduce_algo_rh_degrades() {
    std::printf("[test] all_reduce algo=RH (no partner) degrades to simple...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto data = make_u64({1, 2});
    auto result = sync.all_reduce(9301, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 2);
    CHECK(!result.has_value());  // RH guard fail + simple channel_ invalid → nullopt
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));  // no session leak
}

// ============================================================================
// 测试 2: reduce_scatter algo=RH 无 partner → RH 降级
//    注：reduce_scatter 简化版在 channel_ 检查前创建会话，故会话保留（algo=2, rh_algo=nullopt）
// ============================================================================
static void test_reduce_scatter_algo_rh_degrades() {
    std::printf("[test] reduce_scatter algo=RH (no partner) degrades to simple...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto data = make_u64({10, 20});
    auto result = sync.reduce_scatter(9302, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(500), 2);
    CHECK(!result.has_value());
    // reduce_scatter 简化版创建会话后因 channel_ 无效返回 nullopt，会话保留
    auto s = sync.get_session(9302);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(2));  // algo=RH 被记录
    CHECK(!s->rh_algo.has_value());  // RH 降级，无 rh_algo 状态
    sync.cleanup_finished();
}

// ============================================================================
// 测试 3: all_reduce algo=0 (Ring) 不进入 RH 分派
// ============================================================================
static void test_all_reduce_algo_ring_skips_rh() {
    std::printf("[test] all_reduce algo=0 (Ring) skips RH dispatch...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});  // 配置 RH peers

    auto data = make_u64({1, 2});
    // algo=0 (Ring) → 不进入 RH 分派；Ring peers 未配置 → Ring 降级
    // 简化版 channel_ 无效 → nullopt
    auto result = sync.all_reduce(9303, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 4: reduce_scatter algo=0 (Ring) 不进入 RH 分派
//    注：reduce_scatter 简化版在 channel_ 检查前创建会话，故会话保留（algo=0）
// ============================================================================
static void test_reduce_scatter_algo_ring_skips_rh() {
    std::printf("[test] reduce_scatter algo=0 (Ring) skips RH dispatch...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({10, 20});
    auto result = sync.reduce_scatter(9304, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());
    // Ring 路径未接管 → 简化版创建会话（algo=0），channel_ 无效 → nullopt
    auto s = sync.get_session(9304);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));  // algo=Ring
    CHECK(!s->rh_algo.has_value());  // 无 RH
    sync.cleanup_finished();
}

// ============================================================================
// 测试 5: all_reduce algo=1 (Tree) 不进入 RH 分派（all_reduce 无 Tree 路径）
// ============================================================================
static void test_all_reduce_algo_tree_skips_rh() {
    std::printf("[test] all_reduce algo=1 (Tree) skips RH dispatch...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});
    // algo=1 (Tree) → all_reduce 无 Tree 路径 → 直接简化版
    auto result = sync.all_reduce(9305, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 1);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 6: all_reduce algo=RH + null-channel partner → RH send 失败 → 降级
// ============================================================================
static void test_all_reduce_algo_rh_send_fail_degrades() {
    std::printf("[test] all_reduce algo=RH (null-channel partner) send fail degrades...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=2: self=bit0, partner=bit1(0x02)
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});  // 16 字节，N=2 可整除
    auto result = sync.all_reduce(9306, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(300), 2);
    // RH: partner channel 已配置 → 创建 session → send 失败 → 擦除 → false
    // 简化版: channel_ 无效 → nullopt
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));  // RH session 已擦除
}

// ============================================================================
// 测试 7: reduce_scatter algo=RH + null-channel partner → RH send 失败 → 降级
//    注：RH session 擦除后，简化版创建新会话（algo=2, rh_algo=nullopt）
// ============================================================================
static void test_reduce_scatter_algo_rh_send_fail_degrades() {
    std::printf("[test] reduce_scatter algo=RH (null-channel partner) send fail degrades...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({10, 20});
    auto result = sync.reduce_scatter(9307, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(300), 2);
    CHECK(!result.has_value());
    // RH session 已擦除，简化版创建新会话（algo=2, rh_algo=nullopt）
    auto s = sync.get_session(9307);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(2));
    CHECK(!s->rh_algo.has_value());  // RH session 已擦除，简化版无 rh_algo
    sync.cleanup_finished();
}

// ============================================================================
// 测试 8: 被动会话 — AllReduce RH 帧到达，会话不存在 → 简化版创建被动会话
// ============================================================================
static void test_passive_allreduce_rh_frame_degrades() {
    std::printf("[test] passive AllReduce RH frame (no session) → simple...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);

    // 注入 AllReduce RH 帧，但无对应会话 → use_rh=false → handle_all_reduce_（简化版）
    auto payload = make_u64({100});
    auto frame = make_allreduce_rh_frame(9308, 0x01, 0b0011, payload, 0);

    sync.handle_sync_frame(frame);

    // 简化版 handle_all_reduce_ 创建被动会话
    auto s = sync.get_session(9308);
    CHECK(s.has_value());
    CHECK(!s->rh_algo.has_value());  // 被动会话无 rh_algo
    sync.cleanup_finished();
}

// ============================================================================
// 测试 9: 被动会话 — ReduceScatter RH 帧到达，会话不存在 → 简化版
// ============================================================================
static void test_passive_rs_rh_frame_degrades() {
    std::printf("[test] passive ReduceScatter RH frame (no session) → simple...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);

    auto payload = make_u64({50});
    auto frame = make_rs_rh_frame(9309, 0x01, 0b0011, payload, 0);

    sync.handle_sync_frame(frame);

    // 简化版 handle_reduce_scatter_ 处理（可能创建被动会话或忽略）
    // 关键验证：不崩溃，且 rh_algo 不会被创建
    auto s = sync.get_session(9309);
    if (s.has_value()) {
        CHECK(!s->rh_algo.has_value());  // 被动会话无 rh_algo
    }
    sync.cleanup_finished();
}

// ============================================================================
// 测试 10: 混合 algo 会话独立 — 不同 sync_id 用不同 algo 互不干扰
//          使用 all_gather 创建会话（简化版会创建会话）
// ============================================================================
static void test_mixed_algo_sessions_independent() {
    std::printf("[test] mixed algo sessions independent...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // sync 9310: all_gather algo=0 (Ring)
    auto chunk1 = make_u64({1});
    sync.all_gather(9310, 0b0011, 0,
                    std::span<const std::uint8_t>(chunk1.data(), chunk1.size()),
                    std::chrono::milliseconds(300), 0);

    // sync 9311: all_gather algo=1 (Tree)
    auto chunk2 = make_u64({2});
    sync.all_gather(9311, 0b0011, 0,
                    std::span<const std::uint8_t>(chunk2.data(), chunk2.size()),
                    std::chrono::milliseconds(300), 1);

    auto s1 = sync.get_session(9310);
    auto s2 = sync.get_session(9311);
    CHECK(s1.has_value());
    CHECK(s2.has_value());
    CHECK_EQ(s1->algo, static_cast<std::uint8_t>(0));  // Ring
    CHECK_EQ(s2->algo, static_cast<std::uint8_t>(1));  // Tree
    CHECK(!s1->rh_algo.has_value());  // 无 RH
    CHECK(!s2->rh_algo.has_value());  // 无 RH

    sync.cleanup_finished();
}

// ============================================================================
// 测试 11: RH 路径接管失败后无会话泄漏
// ============================================================================
static void test_rh_no_session_leak() {
    std::printf("[test] RH path failure no session leak...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});
    // 多次调用，每次 RH 失败后简化版 channel_ 无效 → nullopt
    for (int i = 0; i < 3; ++i) {
        sync.all_reduce(9320 + i, 0b0011, 0,
                        std::span<const std::uint8_t>(data.data(), data.size()),
                        ReduceOp::SUM, ReduceDType::U64,
                        std::chrono::milliseconds(200), 2);
    }
    sync.cleanup_finished();
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 12: AllReduce N=2 RH 路径接管（null-channel）→ rh_algo 创建后 send 失败降级
//          验证 rh_algo 在 send 失败后被正确擦除（session_count==0）
// ============================================================================
static void test_allreduce_rh_takeover_then_fail() {
    std::printf("[test] AllReduce N=2 RH takeover then send fail...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=2: self=bit0, partner=bit1(0x02)
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});
    auto result = sync.all_reduce(9330, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(300), 2);
    // RH: partner channel 已配置 → 创建 session + rh_algo
    //       send step 0 → send_to_peer_ 调用 null_ch.send_sync → 返回 false
    //       → 擦除 session → return false → 降级简化版
    // 简化版: channel_ 无效 → nullopt
    CHECK(!result.has_value());
    // rh_algo session 已擦除，简化版未创建会话
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 13: ReduceScatter N=2 RH 路径接管（null-channel）→ rh_algo 创建后 send 失败
//    注：RH session 擦除后，简化版创建新会话（algo=2, rh_algo=nullopt）
// ============================================================================
static void test_rs_rh_takeover_then_fail() {
    std::printf("[test] ReduceScatter N=2 RH takeover then send fail...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({10, 20});
    auto result = sync.reduce_scatter(9331, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(300), 2);
    CHECK(!result.has_value());
    // RH: partner channel 已配置 → 创建 session + rh_algo
    //     send step 0 → send_to_peer_ → null_ch.send_sync → false
    //     → 擦除 session → return false → 降级简化版
    // 简化版: 创建新会话（algo=2），channel_ 无效 → nullopt
    auto s = sync.get_session(9331);
    CHECK(s.has_value());
    CHECK(!s->rh_algo.has_value());  // rh_algo 已随 RH session 擦除
    sync.cleanup_finished();
}

// ============================================================================
// 测试 14: handle_sync_frame — AllReduce RH 帧到达简化版被动会话 → 简化版处理
//          （会话存在但 rh_algo=nullopt → use_rh=false → handle_all_reduce_）
// ============================================================================
static void test_allreduce_rh_frame_to_simple_session() {
    std::printf("[test] AllReduce RH frame to simple session → simple handler...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);

    // 先注入 AllReduce RH 帧创建被动会话（简化版，rh_algo=nullopt）
    auto payload1 = make_u64({10});
    auto frame1 = make_allreduce_rh_frame(9340, 0x01, 0b0011, payload1, 0);
    sync.handle_sync_frame(frame1);

    auto s = sync.get_session(9340);
    CHECK(s.has_value());
    CHECK(!s->rh_algo.has_value());  // 简化版被动会话

    // 再注入第二帧 → use_rh=false（rh_algo=nullopt）→ handle_all_reduce_（简化版）
    auto payload2 = make_u64({20});
    auto frame2 = make_allreduce_rh_frame(9340, 0x02, 0b0011, payload2, 1);
    sync.handle_sync_frame(frame2);  // 不应崩溃

    auto s2 = sync.get_session(9340);
    CHECK(s2.has_value());
    CHECK(!s2->rh_algo.has_value());  // 仍为简化版会话

    sync.cleanup_finished();
}

// ============================================================================
// 测试 15: Signal 帧不参与 RH 分派
// ============================================================================
static void test_signal_not_rh_dispatched() {
    std::printf("[test] Signal frame not RH dispatched...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // 注入 Signal 帧
    EpSyncFrame frame;
    frame.sync_id = 9350;
    frame.sync_op = EpSyncOp::Signal;
    frame.algo = 2;  // algo=RH（但 Signal 不参与分派）
    frame.participant_mask = 0x01;
    frame.from_node_id = 0x02;

    sync.handle_sync_frame(frame);  // 不应崩溃
    // Signal 不创建会话（仅触发 on_signal_received 回调）
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 16: Barrier 帧不参与 RH 分派
// ============================================================================
static void test_barrier_not_rh_dispatched() {
    std::printf("[test] Barrier frame not RH dispatched...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpSyncFrame frame;
    frame.sync_id = 9351;
    frame.sync_op = EpSyncOp::Barrier;
    frame.algo = 2;  // algo=RH（但 Barrier 不参与分派）
    frame.participant_mask = 0b0011;
    frame.from_node_id = 0x02;

    sync.handle_sync_frame(frame);  // 不应崩溃
    sync.cleanup_finished();
}

// ============================================================================
// 测试 17: 多次 RH 调用无会话累积
// ============================================================================
static void test_no_session_accumulation_rh() {
    std::printf("[test] multiple RH calls no session accumulation...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});
    for (int i = 0; i < 5; ++i) {
        auto result = sync.all_reduce(9360 + i, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(200), 2);
        CHECK(!result.has_value());
    }
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 18: AllReduce algo=RH N=4 null-channel partners → send 失败降级
// ============================================================================
static void test_allreduce_rh_n4_null_partners() {
    std::printf("[test] AllReduce algo=RH N=4 null-channel partners...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=4: self=bit0, partners=bit1(0x02), bit2(0x04)
    sync.set_rh_peers({{0x02, &null_ch}, {0x04, &null_ch}});

    auto data = make_u64({1, 2, 3, 4});  // 32 字节, N=4, 32%4=8 可整除
    auto result = sync.all_reduce(9370, 0b1111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(300), 2);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 19: AllReduce algo=RH N=4 partner 部分缺失 → RH 拒绝，无 session
// ============================================================================
static void test_allreduce_rh_n4_partial_partners() {
    std::printf("[test] AllReduce algo=RH N=4 partial partners (missing)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=4 需要 2 个 partner: bit1(0x02), bit2(0x04)
    // 只配置 bit1，缺 bit2 → RH 守卫拒绝
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2, 3, 4});
    auto result = sync.all_reduce(9371, 0b1111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 2);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 20: AllReduce algo=RH N=3（非 2 的幂）→ RH 拒绝
// ============================================================================
static void test_allreduce_rh_n3_not_power_of_two() {
    std::printf("[test] AllReduce algo=RH N=3 (not power of two)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}, {0x04, &null_ch}});

    // N=3, data=24 字节（3 u64），24%3=0 可整除，但 N 非 2 的幂
    auto data = make_u64({10, 20, 30});
    auto result = sync.all_reduce(9372, 0b0111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 2);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== AlgoDispatchRH (P4-E Algorithm Dispatch) Unit Tests ===\n\n");

    test_all_reduce_algo_rh_degrades();
    test_reduce_scatter_algo_rh_degrades();
    test_all_reduce_algo_ring_skips_rh();
    test_reduce_scatter_algo_ring_skips_rh();
    test_all_reduce_algo_tree_skips_rh();
    test_all_reduce_algo_rh_send_fail_degrades();
    test_reduce_scatter_algo_rh_send_fail_degrades();
    test_passive_allreduce_rh_frame_degrades();
    test_passive_rs_rh_frame_degrades();
    test_mixed_algo_sessions_independent();
    test_rh_no_session_leak();
    test_allreduce_rh_takeover_then_fail();
    test_rs_rh_takeover_then_fail();
    test_allreduce_rh_frame_to_simple_session();
    test_signal_not_rh_dispatched();
    test_barrier_not_rh_dispatched();
    test_no_session_accumulation_rh();
    test_allreduce_rh_n4_null_partners();
    test_allreduce_rh_n4_partial_partners();
    test_allreduce_rh_n3_not_power_of_two();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
