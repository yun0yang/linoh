// test_algo_dispatch_pe.cpp — P4-F 算法分派单元测试（v2.3 Phase 4 / 方向 F）
//
// 验证 P4-F 交付物（handle_sync_frame 的 algo 路由逻辑 — PE 路径）：
//   1. all_to_all algo=3 (PE) 路径：无 partner 时 PE 降级到简化版
//   2. all_to_all algo=0 (Ring) 不进入 PE 分派
//   3. all_to_all algo=1 (Tree) 不进入 PE 分派
//   4. all_to_all algo=PE + null-channel partner → send 失败 → 降级
//   5. 被动会话分派：handle_sync_frame 注入 AllToAll PE 帧时，会话不存在
//      → use_pe=false → 简化版 handle_all_to_all_ 创建被动会话
//   6. 混合 algo 会话独立：不同 sync_id 用不同 algo 互不干扰
//   7. PE 路径接管失败（send 失败）→ 会话擦除 → 降级简化版创建新会话
//   8. AllToAll N=2 PE 路径接管（null-channel）→ pe_algo 创建后 send 失败降级
//   9. handle_sync_frame AllToAll PE 帧到达简化版被动会话 → 简化版处理
//  10. Signal/Barrier 帧不参与 PE 分派
//  11. 多次 PE 调用无会话累积
//  12. AllToAll algo=PE N=4 null-channel partners → send 失败降级
//  13. AllToAll algo=PE N=3（非 2 的幂）→ PE 拒绝
//  14. AllToAll algo=PE N=4 partner 部分缺失 → PE 守卫拒绝
//  15. 未知 op（Release）不参与 PE 分派
//
// 测试策略：
//   - SyncPrimitives(nullptr) 构造（channel_ 无效）
//   - all_to_all 简化版在 channel_ 检查前创建会话（与 reduce_scatter 一致），
//     PE 守卫失败后简化版创建会话（algo=3, pe_algo=nullopt），可通过 get_session 验证
//   - EpChannel(nullptr) 作为 peer channel（conn_ 无效，send_sync 返回 false），
//     触发 all_to_all_pe_ 的 step 0 发送失败 → 会话擦除 → 降级简化版
//   - 通过 handle_sync_frame 注入 EpSyncFrame 模拟被动接收，验证分派路由
//   - 被动会话由简化版 handle_all_to_all_ 创建，algo=3（传入值），pe_algo=nullopt
//
// 注：PE 状态机成功接管（pe_algo.has_value()==true 且多步通信完成）需要
//     真实 QUIC 连接，属集成测试范畴。算法正确性由 test_pe_engine.cpp 覆盖。
//     本测试聚焦于分派逻辑的可观察行为：降级路径、无泄漏、被动会话路由。

#include "linoh/multimodal/sync_primitives.hpp"
#include "linoh/multimodal/ep_channel.hpp"
#include "linoh/multimodal/pe_engine.hpp"

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

/// 构造 AllToAll PE 帧（用于 handle_sync_frame 注入）
static EpSyncFrame make_alltoall_pe_frame(std::uint64_t sync_id,
                                          std::uint64_t from_bit,
                                          std::uint64_t participant_mask,
                                          const std::vector<std::uint8_t> &payload,
                                          std::uint16_t step = 0) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::AllToAll;
    frame.algo = 3;  // PE
    frame.participant_mask = participant_mask;
    frame.shard_idx = 0;
    frame.total_shards = 1;
    frame.payload = payload;
    frame.from_node_id = from_bit;
    frame.step = step;
    return frame;
}

// ============================================================================
// 测试 1: all_to_all algo=PE 无 partner → PE 降级，简化版创建会话（algo=3）
// ============================================================================
static void test_all_to_all_algo_pe_degrades() {
    std::printf("[test] all_to_all algo=PE (no partner) degrades to simple...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto data = make_u64({1, 2});
    auto result = sync.all_to_all(9501, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(500), 3);
    CHECK(!result.has_value());  // PE guard fail + simple channel_ invalid → nullopt
    // 简化版创建会话（algo=3, pe_algo=nullopt）
    auto s = sync.get_session(9501);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(3));  // algo=PE 被记录
    CHECK(!s->pe_algo.has_value());  // PE 降级，无 pe_algo 状态
    sync.cleanup_finished();
}

// ============================================================================
// 测试 2: all_to_all algo=0 (Ring) 不进入 PE 分派
// ============================================================================
static void test_all_to_all_algo_ring_skips_pe() {
    std::printf("[test] all_to_all algo=0 (Ring) skips PE dispatch...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_pe_peers({{0x02, &null_ch}});  // 配置 PE peers

    auto data = make_u64({1, 2});
    // algo=0 → 不进入 PE 分派；简化版创建会话（algo=0）
    auto result = sync.all_to_all(9502, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());
    auto s = sync.get_session(9502);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));  // algo=Ring
    CHECK(!s->pe_algo.has_value());
    sync.cleanup_finished();
}

// ============================================================================
// 测试 3: all_to_all algo=1 (Tree) 不进入 PE 分派
// ============================================================================
static void test_all_to_all_algo_tree_skips_pe() {
    std::printf("[test] all_to_all algo=1 (Tree) skips PE dispatch...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});
    auto result = sync.all_to_all(9503, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(500), 1);
    CHECK(!result.has_value());
    auto s = sync.get_session(9503);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(1));  // algo=Tree
    CHECK(!s->pe_algo.has_value());
    sync.cleanup_finished();
}

// ============================================================================
// 测试 4: all_to_all algo=PE + null-channel partner → PE send 失败 → 降级
// ============================================================================
static void test_all_to_all_algo_pe_send_fail_degrades() {
    std::printf("[test] all_to_all algo=PE (null-channel partner) send fail degrades...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=2: self=bit0, partner=bit1(0x02)
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});  // 16 字节，N=2 可整除
    auto result = sync.all_to_all(9504, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(300), 3);
    // PE: partner channel 已配置 → 创建 session + pe_algo → send 失败 → 擦除 → false
    // 简化版: 创建新会话（algo=3, pe_algo=nullopt）→ channel_ 无效 → nullopt
    CHECK(!result.has_value());
    auto s = sync.get_session(9504);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(3));
    CHECK(!s->pe_algo.has_value());  // PE session 已擦除，简化版无 pe_algo
    sync.cleanup_finished();
}

// ============================================================================
// 测试 5: 被动会话 — AllToAll PE 帧到达，会话不存在 → 简化版创建被动会话
// ============================================================================
static void test_passive_alltoall_pe_frame_degrades() {
    std::printf("[test] passive AllToAll PE frame (no session) → simple...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);

    // 注入 AllToAll PE 帧，但无对应会话 → use_pe=false → handle_all_to_all_（简化版）
    auto payload = make_u64({100, 200});
    auto frame = make_alltoall_pe_frame(9505, 0x01, 0b0011, payload, 0);

    sync.handle_sync_frame(frame);

    // 简化版 handle_all_to_all_ 创建被动会话
    auto s = sync.get_session(9505);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // 被动会话无 pe_algo
    sync.cleanup_finished();
}

// ============================================================================
// 测试 6: 混合 algo 会话独立 — 不同 sync_id 用不同 algo 互不干扰
//    使用 all_to_all 创建会话（简化版会创建会话）
// ============================================================================
static void test_mixed_algo_sessions_independent() {
    std::printf("[test] mixed algo sessions independent...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // sync 9506: all_to_all algo=0 (Ring)
    auto chunk1 = make_u64({1, 2});
    sync.all_to_all(9506, 0b0011, 0,
                    std::span<const std::uint8_t>(chunk1.data(), chunk1.size()),
                    std::chrono::milliseconds(300), 0);

    // sync 9507: all_to_all algo=3 (PE)
    auto chunk2 = make_u64({3, 4});
    sync.all_to_all(9507, 0b0011, 0,
                    std::span<const std::uint8_t>(chunk2.data(), chunk2.size()),
                    std::chrono::milliseconds(300), 3);

    auto s1 = sync.get_session(9506);
    auto s2 = sync.get_session(9507);
    CHECK(s1.has_value());
    CHECK(s2.has_value());
    CHECK_EQ(s1->algo, static_cast<std::uint8_t>(0));  // Ring
    CHECK_EQ(s2->algo, static_cast<std::uint8_t>(3));  // PE
    CHECK(!s1->pe_algo.has_value());  // 无 PE 状态
    CHECK(!s2->pe_algo.has_value());  // PE 降级，无 pe_algo

    sync.cleanup_finished();
}

// ============================================================================
// 测试 7: PE 路径接管失败后无会话泄漏
// ============================================================================
static void test_pe_no_session_leak() {
    std::printf("[test] PE path failure no session leak...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});
    for (int i = 0; i < 3; ++i) {
        sync.all_to_all(9520 + i, 0b0011, 0,
                        std::span<const std::uint8_t>(data.data(), data.size()),
                        std::chrono::milliseconds(200), 3);
    }
    // all_to_all 简化版创建 Waiting 会话，cleanup_finished 不清理
    // 验证：3 次调用产生 3 个会话，无额外泄漏
    sync.cleanup_finished();
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(3));
}

// ============================================================================
// 测试 8: AllToAll N=2 PE 路径接管（null-channel）→ pe_algo 创建后 send 失败降级
//    验证 pe_algo 在 send 失败后被正确擦除（简化版会话 pe_algo=nullopt）
// ============================================================================
static void test_alltoall_pe_takeover_then_fail() {
    std::printf("[test] AllToAll N=2 PE takeover then send fail...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=2: self=bit0, partner=bit1(0x02)
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});
    auto result = sync.all_to_all(9530, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(300), 3);
    // PE: partner channel 已配置 → 创建 session + pe_algo
    //     send step 0 → send_to_peer_ → null_ch.send_sync → false
    //     → 擦除 session → return false → 降级简化版
    // 简化版: 创建新会话（algo=3, pe_algo=nullopt）→ channel_ 无效 → nullopt
    CHECK(!result.has_value());
    auto s = sync.get_session(9530);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // pe_algo 已随 PE session 擦除
    sync.cleanup_finished();
}

// ============================================================================
// 测试 9: handle_sync_frame — AllToAll PE 帧到达简化版被动会话 → 简化版处理
//    （会话存在但 pe_algo=nullopt → use_pe=false → handle_all_to_all_）
// ============================================================================
static void test_alltoall_pe_frame_to_simple_session() {
    std::printf("[test] AllToAll PE frame to simple session → simple handler...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);

    // 先注入 AllToAll PE 帧创建被动会话（简化版，pe_algo=nullopt）
    auto payload1 = make_u64({10, 20});
    auto frame1 = make_alltoall_pe_frame(9540, 0x01, 0b0011, payload1, 0);
    sync.handle_sync_frame(frame1);

    auto s = sync.get_session(9540);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // 简化版被动会话

    // 再注入第二帧 → use_pe=false（pe_algo=nullopt）→ handle_all_to_all_（简化版）
    auto payload2 = make_u64({30, 40});
    auto frame2 = make_alltoall_pe_frame(9540, 0x02, 0b0011, payload2, 1);
    sync.handle_sync_frame(frame2);  // 不应崩溃

    auto s2 = sync.get_session(9540);
    CHECK(s2.has_value());
    CHECK(!s2->pe_algo.has_value());  // 仍为简化版会话

    sync.cleanup_finished();
}

// ============================================================================
// 测试 10: Signal 帧不参与 PE 分派
// ============================================================================
static void test_signal_not_pe_dispatched() {
    std::printf("[test] Signal frame not PE dispatched...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpSyncFrame frame;
    frame.sync_id = 9550;
    frame.sync_op = EpSyncOp::Signal;
    frame.algo = 3;  // algo=PE（但 Signal 不参与分派）
    frame.participant_mask = 0x01;
    frame.from_node_id = 0x02;

    sync.handle_sync_frame(frame);  // 不应崩溃
    // Signal 不创建会话（仅触发 on_signal_received 回调）
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 11: Barrier 帧不参与 PE 分派
// ============================================================================
static void test_barrier_not_pe_dispatched() {
    std::printf("[test] Barrier frame not PE dispatched...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpSyncFrame frame;
    frame.sync_id = 9551;
    frame.sync_op = EpSyncOp::Barrier;
    frame.algo = 3;  // algo=PE（但 Barrier 不参与分派）
    frame.participant_mask = 0b0011;
    frame.from_node_id = 0x02;

    sync.handle_sync_frame(frame);  // 不应崩溃
    sync.cleanup_finished();
}

// ============================================================================
// 测试 12: 多次 PE 调用无会话累积
// ============================================================================
static void test_no_session_accumulation_pe() {
    std::printf("[test] multiple PE calls no session accumulation...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});
    for (int i = 0; i < 5; ++i) {
        auto result = sync.all_to_all(9560 + i, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      std::chrono::milliseconds(200), 3);
        CHECK(!result.has_value());
    }
    // all_to_all 简化版创建 Waiting 会话，cleanup_finished 不清理
    // 验证：5 次调用产生 5 个会话，无额外泄漏
    sync.cleanup_finished();
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(5));
}

// ============================================================================
// 测试 13: AllToAll algo=PE N=4 null-channel partners → send 失败降级
// ============================================================================
static void test_alltoall_pe_n4_null_partners() {
    std::printf("[test] AllToAll algo=PE N=4 null-channel partners...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=4: self=bit0, partners=bit1(0x02) step0, bit2(0x04) step1
    sync.set_pe_peers({{0x02, &null_ch}, {0x04, &null_ch}});

    auto data = make_u64({1, 2, 3, 4});  // 32 字节, N=4, 32%4=8 可整除
    auto result = sync.all_to_all(9570, 0b1111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(300), 3);
    CHECK(!result.has_value());
    auto s = sync.get_session(9570);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // PE session 已擦除
    sync.cleanup_finished();
}

// ============================================================================
// 测试 14: AllToAll algo=PE N=3（非 2 的幂）→ PE 拒绝
// ============================================================================
static void test_alltoall_pe_n3_not_power_of_two() {
    std::printf("[test] AllToAll algo=PE N=3 (not power of two)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_pe_peers({{0x02, &null_ch}, {0x04, &null_ch}});

    // N=3, data=24 字节（3 u64），24%3=0 可整除，但 N 非 2 的幂
    auto data = make_u64({10, 20, 30});
    auto result = sync.all_to_all(9571, 0b0111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(500), 3);
    CHECK(!result.has_value());
    auto s = sync.get_session(9571);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // PE 守卫拒绝
    sync.cleanup_finished();
}

// ============================================================================
// 测试 15: AllToAll algo=PE N=4 partner 部分缺失 → PE 守卫拒绝
// ============================================================================
static void test_alltoall_pe_n4_partial_partners() {
    std::printf("[test] AllToAll algo=PE N=4 partial partners (missing)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=4 需要 2 个 partner: bit1(0x02), bit2(0x04)
    // 只配置 bit1，缺 bit2 → PE 守卫拒绝
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2, 3, 4});
    auto result = sync.all_to_all(9572, 0b1111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(500), 3);
    CHECK(!result.has_value());
    auto s = sync.get_session(9572);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // PE 守卫拒绝
    sync.cleanup_finished();
}

// ============================================================================
// 测试 16: AllToAll algo=PE N=2 + 完整 partner 但 self=bit1（非 bit0）
//    验证非 bit0 的 self_node_id 也能正确路由 partner
// ============================================================================
static void test_alltoall_pe_self_bit1() {
    std::printf("[test] AllToAll algo=PE N=2 self=bit1...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);  // self=bit1

    EpChannel null_ch(nullptr);
    // N=2: self=bit1(rank 1), partner=bit0(0x01) step0
    sync.set_pe_peers({{0x01, &null_ch}});

    auto data = make_u64({5, 6});
    auto result = sync.all_to_all(9580, 0b0011, 1,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(300), 3);
    // PE: partner=bit0 已配置 → 创建 session + pe_algo → send 失败 → 擦除 → 降级
    CHECK(!result.has_value());
    auto s = sync.get_session(9580);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // PE session 已擦除
    sync.cleanup_finished();
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== AlgoDispatchPE (P4-F Algorithm Dispatch) Unit Tests ===\n\n");

    test_all_to_all_algo_pe_degrades();
    test_all_to_all_algo_ring_skips_pe();
    test_all_to_all_algo_tree_skips_pe();
    test_all_to_all_algo_pe_send_fail_degrades();
    test_passive_alltoall_pe_frame_degrades();
    test_mixed_algo_sessions_independent();
    test_pe_no_session_leak();
    test_alltoall_pe_takeover_then_fail();
    test_alltoall_pe_frame_to_simple_session();
    test_signal_not_pe_dispatched();
    test_barrier_not_pe_dispatched();
    test_no_session_accumulation_pe();
    test_alltoall_pe_n4_null_partners();
    test_alltoall_pe_n3_not_power_of_two();
    test_alltoall_pe_n4_partial_partners();
    test_alltoall_pe_self_bit1();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
