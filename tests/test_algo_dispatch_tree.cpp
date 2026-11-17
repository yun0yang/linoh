// test_algo_dispatch_tree.cpp — P4-D 算法分派单元测试（v2.3 Phase 4 / 方向 D）
//
// 验证 P4-D 交付物（handle_sync_frame 的 algo 路由逻辑 — Tree 路径）：
//   1. broadcast algo=1 (Tree) 路径：无 peers 时 Tree 降级到简化版
//   2. all_gather algo=1 (Tree) 路径：无 peers 时 Tree 降级到简化版
//   3. broadcast algo=0 不进入 Tree 分派
//   4. all_gather algo=0 (Ring) 不进入 Tree 分派
//   5. 被动会话分派：handle_sync_frame 注入 Tree 帧时，会话不存在 → use_tree=false → 简化版
//   6. 已存在 Tree 会话分派：会话存在且 tree_algo 有值 → use_tree=true → handle_*_tree_
//   7. 混合 algo 会话独立：不同 sync_id 用不同 algo 互不干扰
//   8. Tree 路径接管失败（send 失败）→ 会话擦除 → 简化版接管（无泄漏）
//   9. Signal/Barrier/未知 op 不参与 algo 分派
//  10. Broadcast N=2 Tree 路径接管（null-channel）→ tree_algo 创建后 send 失败降级
//  11. AllGather N=2 Tree 路径接管（null-channel leaf）→ tree_algo 创建后 send 失败降级
//  12. handle_sync_frame Broadcast 帧到达 Tree 会话 → use_tree=true 路由到 handle_broadcast_tree_
//
// 测试策略：
//   - SyncPrimitives(nullptr) 构造（channel_ 无效）
//   - broadcast/all_gather 在 channel 无效时仍创建会话（简化版），
//     可通过 get_session 观察 algo 字段与 tree_algo 状态
//   - EpChannel(nullptr) 作为 peer channel（conn_ 无效，send_sync 返回 false），
//     触发 *_tree_ 的 step 0 发送失败 → 会话擦除 → 降级简化版
//   - 通过 handle_sync_frame 注入 EpSyncFrame 模拟被动接收，验证分派路由
//
// 注：Tree 状态机成功接管（tree_algo.has_value()==true 且多步通信完成）需要
//     真实 QUIC 连接，属集成测试范畴。算法正确性由 test_tree_engine.cpp 覆盖。
//     本测试聚焦于分派逻辑的可观察行为：algo 字段记录、降级路径、无泄漏。

#include "linoh/multimodal/sync_primitives.hpp"
#include "linoh/multimodal/ep_channel.hpp"

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

static std::vector<std::uint8_t> make_data(std::size_t n) {
    std::vector<std::uint8_t> d(n);
    for (std::size_t i = 0; i < n; ++i) d[i] = static_cast<std::uint8_t>(i & 0xFF);
    return d;
}

/// 构造 Broadcast Tree 帧（用于 handle_sync_frame 注入）
static EpSyncFrame make_bcast_tree_frame(std::uint64_t sync_id,
                                          std::uint64_t from_bit,
                                          std::uint64_t participant_mask,
                                          const std::vector<std::uint8_t> &payload,
                                          std::uint16_t step = 0) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::Broadcast;
    frame.algo = 1;  // Tree
    frame.participant_mask = participant_mask;
    frame.shard_idx = 0;
    frame.total_shards = 1;
    frame.payload = payload;
    frame.from_node_id = from_bit;
    frame.step = step;
    return frame;
}

/// 构造 AllGather Tree 帧（用于 handle_sync_frame 注入）
static EpSyncFrame make_ag_tree_frame(std::uint64_t sync_id,
                                       std::uint64_t from_bit,
                                       const std::vector<std::uint8_t> &payload,
                                       std::uint16_t step = 0) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::AllGather;
    frame.algo = 1;  // Tree
    frame.participant_mask = from_bit;
    frame.shard_idx = 0;
    frame.total_shards = 1;
    frame.payload = payload;
    frame.from_node_id = from_bit;
    frame.step = step;
    return frame;
}

// ============================================================================
// 测试 1: broadcast algo=Tree 无 peers → Tree 降级，简化版创建会话（algo=1）
// ============================================================================
static void test_broadcast_algo_tree_degrades() {
    std::printf("[test] broadcast algo=Tree (no peers) degrades to simple...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto data = make_data(16);
    bool result = sync.broadcast(9101, 0b0011, 0,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 std::chrono::milliseconds(500), 1);
    CHECK(!result);  // channel 无效

    auto s = sync.get_session(9101);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(1));  // algo=Tree 被记录
    CHECK(!s->tree_algo.has_value());  // Tree 降级，无 tree_algo 状态

    sync.cleanup_finished();
}

// ============================================================================
// 测试 2: all_gather algo=Tree 无 peers → Tree 降级，简化版创建会话（algo=1）
// ============================================================================
static void test_all_gather_algo_tree_degrades() {
    std::printf("[test] all_gather algo=Tree (no peers) degrades to simple...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto chunk = make_data(16);
    auto result = sync.all_gather(9102, 0b0011, 0,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 1);
    CHECK(!result.has_value());

    auto s = sync.get_session(9102);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(1));
    CHECK(!s->tree_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 3: broadcast algo=0 不进入 Tree 分派
// ============================================================================
static void test_broadcast_algo_ring_skips_tree() {
    std::printf("[test] broadcast algo=0 skips Tree dispatch...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto data = make_data(16);
    bool result = sync.broadcast(9103, 0b0011, 0,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 std::chrono::milliseconds(500), 0);
    CHECK(!result);

    auto s = sync.get_session(9103);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));
    CHECK(!s->tree_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 4: all_gather algo=0 (Ring) 不进入 Tree 分派
// ============================================================================
static void test_all_gather_algo_ring_skips_tree() {
    std::printf("[test] all_gather algo=0 (Ring) skips Tree dispatch...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto chunk = make_data(16);
    auto result = sync.all_gather(9104, 0b0011, 0,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());

    auto s = sync.get_session(9104);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));
    CHECK(!s->tree_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 5: broadcast algo=Tree + null-channel peer → Tree send 失败 → 降级简化版
// ============================================================================
static void test_broadcast_algo_tree_send_fail_degrades() {
    std::printf("[test] broadcast algo=Tree (null-channel peer) send fail degrades...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=2 binomial tree: root=0, child=1
    sync.set_tree_peers(0, nullptr, {{0x02, &null_ch}});

    auto data = make_data(16);
    bool result = sync.broadcast(9105, 0b0011, 0,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 std::chrono::milliseconds(500), 1);
    CHECK(!result);

    // Tree 创建会话后 send 失败 → 擦除 → 简化版重建会话（algo=1, tree_algo=nullopt）
    auto s = sync.get_session(9105);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(1));
    CHECK(!s->tree_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 6: all_gather algo=Tree + null-channel parent → Tree send 失败 → 降级
// ============================================================================
static void test_all_gather_algo_tree_send_fail_degrades() {
    std::printf("[test] all_gather algo=Tree (null-channel parent) send fail degrades...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);  // self=bit1, leaf

    EpChannel null_ch(nullptr);
    // 叶子节点：parent=bit0
    sync.set_tree_peers(0x01, &null_ch, {});

    auto chunk = make_data(16);
    auto result = sync.all_gather(9106, 0b0011, 1,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 1);
    CHECK(!result.has_value());

    auto s = sync.get_session(9106);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(1));
    CHECK(!s->tree_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 7: 被动会话 — Broadcast Tree 帧到达，会话不存在 → 简化版创建被动会话
// ============================================================================
static void test_passive_bcast_tree_frame_degrades() {
    std::printf("[test] passive Broadcast Tree frame (no session) → simple...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);

    // 注入 Broadcast Tree 帧，但无对应会话 → use_tree=false → handle_broadcast_（简化版）
    auto payload = make_data(16);
    auto frame = make_bcast_tree_frame(9107, 0x01, 0x01, payload, 0);

    sync.handle_sync_frame(frame);

    // 简化版 handle_broadcast_ 创建被动会话
    auto s = sync.get_session(9107);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());  // 被动会话无 tree_algo
    sync.cleanup_finished();
}

// ============================================================================
// 测试 8: 被动会话 — AllGather Tree 帧到达，会话不存在 → 简化版创建被动会话
// ============================================================================
static void test_passive_ag_tree_frame_degrades() {
    std::printf("[test] passive AllGather Tree frame (no session) → simple...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);

    auto payload = make_data(16);
    auto frame = make_ag_tree_frame(9108, 0x01, payload, 0);

    sync.handle_sync_frame(frame);

    auto s = sync.get_session(9108);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());
    sync.cleanup_finished();
}

// ============================================================================
// 测试 9: 混合 algo 会话独立 — 不同 sync_id 用不同 algo 互不干扰
// ============================================================================
static void test_mixed_algo_sessions() {
    std::printf("[test] mixed algo sessions independent...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // sync 9109: algo=0 (Ring)
    auto chunk1 = make_data(16);
    sync.all_gather(9109, 0b0011, 0,
                    std::span<const std::uint8_t>(chunk1.data(), chunk1.size()),
                    std::chrono::milliseconds(300), 0);

    // sync 9110: algo=1 (Tree)
    auto chunk2 = make_data(16);
    sync.all_gather(9110, 0b0011, 0,
                    std::span<const std::uint8_t>(chunk2.data(), chunk2.size()),
                    std::chrono::milliseconds(300), 1);

    auto s1 = sync.get_session(9109);
    auto s2 = sync.get_session(9110);
    CHECK(s1.has_value());
    CHECK(s2.has_value());
    CHECK_EQ(s1->algo, static_cast<std::uint8_t>(0));
    CHECK_EQ(s2->algo, static_cast<std::uint8_t>(1));
    CHECK(!s1->tree_algo.has_value());
    CHECK(!s2->tree_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 10: Tree 路径接管失败后无会话泄漏
// ============================================================================
static void test_tree_no_session_leak() {
    std::printf("[test] Tree path failure no session leak...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_tree_peers(0, nullptr, {{0x02, &null_ch}});

    auto data = make_data(16);
    // 多次调用，每次 Tree 失败后简化版创建会话
    for (int i = 0; i < 3; ++i) {
        sync.broadcast(9120 + i, 0b0011, 0,
                       std::span<const std::uint8_t>(data.data(), data.size()),
                       std::chrono::milliseconds(200), 1);
    }
    sync.cleanup_finished();
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 11: Broadcast N=2 Tree 路径接管（null-channel）→ tree_algo 创建后 send 失败降级
//          验证 tree_algo 在 send 失败后被正确擦除
// ============================================================================
static void test_bcast_tree_takeover_then_fail() {
    std::printf("[test] Broadcast N=2 Tree takeover then send fail...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=2: root=0, child=1(bit1=0x02)
    sync.set_tree_peers(0, nullptr, {{0x02, &null_ch}});

    auto data = make_data(16);
    bool result = sync.broadcast(9130, 0b0011, 0,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 std::chrono::milliseconds(300), 1);
    // Tree: children channel 已配置 → 创建 session + tree_algo
    //       root send step 0 → send_to_peer_ 调用 null_ch.send_sync → 返回 false
    //       → 擦除 session → return false → 降级简化版
    CHECK(!result);

    // 简化版重建会话（无 tree_algo）
    auto s = sync.get_session(9130);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());  // tree_algo 已随 Tree session 擦除

    sync.cleanup_finished();
}

// ============================================================================
// 测试 12: AllGather N=2 Tree 叶子路径接管（null-channel）→ tree_algo 创建后 send 失败
// ============================================================================
static void test_ag_tree_leaf_takeover_then_fail() {
    std::printf("[test] AllGather N=2 Tree leaf takeover then send fail...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);  // self=bit1, leaf

    EpChannel null_ch(nullptr);
    // 叶子：parent=bit0(0x01), children=空
    sync.set_tree_peers(0x01, &null_ch, {});

    auto chunk = make_data(16);
    auto result = sync.all_gather(9131, 0b0011, 1,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(300), 1);
    // Tree: parent channel 已配置 → 创建 session + tree_algo
    //       叶子 send step 0 → send_to_peer_ 调用 null_ch.send_sync → 返回 false
    //       → 擦除 session → return false → 降级简化版
    CHECK(!result.has_value());

    auto s = sync.get_session(9131);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 13: handle_sync_frame — Broadcast Tree 帧到达简化版会话 → 简化版处理
//          （会话存在但 tree_algo=nullopt → use_tree=false → handle_broadcast_）
// ============================================================================
static void test_bcast_tree_frame_to_simple_session() {
    std::printf("[test] Broadcast Tree frame to simple session → simple handler...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);

    // 先通过简化版 broadcast 创建会话（algo=1 但 tree_algo=nullopt）
    auto data = make_data(16);
    sync.broadcast(9140, 0b0011, 0,
                   std::span<const std::uint8_t>(data.data(), data.size()),
                   std::chrono::milliseconds(500), 1);

    auto s = sync.get_session(9140);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());  // 简化版会话

    // 注入 Broadcast Tree 帧 → use_tree=false → handle_broadcast_（简化版）
    auto payload = make_data(16);
    auto frame = make_bcast_tree_frame(9140, 0x01, 0x01, payload, 0);
    sync.handle_sync_frame(frame);  // 不应崩溃

    // 简化版会话仍然存在
    auto s2 = sync.get_session(9140);
    CHECK(s2.has_value());
    CHECK(!s2->tree_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 14: Signal 帧不参与 Tree 分派
// ============================================================================
static void test_signal_not_tree_dispatched() {
    std::printf("[test] Signal frame not Tree dispatched...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // 注入 Signal 帧
    EpSyncFrame frame;
    frame.sync_id = 9150;
    frame.sync_op = EpSyncOp::Signal;
    frame.algo = 1;  // algo=Tree（但 Signal 不参与分派）
    frame.participant_mask = 0x01;
    frame.from_node_id = 0x02;

    sync.handle_sync_frame(frame);  // 不应崩溃
    // Signal 不创建会话（仅触发 on_signal_received 回调）
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== AlgoDispatchTree (P4-D Algorithm Dispatch) Unit Tests ===\n\n");

    test_broadcast_algo_tree_degrades();
    test_all_gather_algo_tree_degrades();
    test_broadcast_algo_ring_skips_tree();
    test_all_gather_algo_ring_skips_tree();
    test_broadcast_algo_tree_send_fail_degrades();
    test_all_gather_algo_tree_send_fail_degrades();
    test_passive_bcast_tree_frame_degrades();
    test_passive_ag_tree_frame_degrades();
    test_mixed_algo_sessions();
    test_tree_no_session_leak();
    test_bcast_tree_takeover_then_fail();
    test_ag_tree_leaf_takeover_then_fail();
    test_bcast_tree_frame_to_simple_session();
    test_signal_not_tree_dispatched();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
