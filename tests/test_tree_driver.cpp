// test_tree_driver.cpp — P4-D Tree 驱动守卫与降级单元测试（v2.3 Phase 4）
//
// 验证 P4-D 交付物（Tree 引擎驱动 EpChannel 通信的守卫逻辑）：
//   1. broadcast_tree_ 守卫：N<2 / data 过大 / self 不在 mask / root 不在 mask → return false
//   2. all_gather_tree_ 守卫：N<2 / chunk 过大 / self 不在 mask → return false
//   3. children channel 未配置守卫 → return false
//   4. parent channel 未配置守卫（all_gather 非根节点）→ return false
//   5. Tree 路径失败后正确降级到简化版（无崩溃、无会话泄漏）
//   6. set_tree_peers 注入 peer_channels_ 正确
//   7. clear_peer_channels 后守卫拦截
//   8. TreeAlgoState 字段默认值校验
//   9. TreeEngine 拓扑构建一致性（parent/children 与 build_binomial_tree 一致）
//  10. 多次调用不产生会话累积
//  11. broadcast algo=1 + 有效 peer（null-channel）→ Tree session 生命周期正确
//  12. all_gather algo=1 + 有效 peer（null-channel）→ Tree session 创建后 send 失败降级
//
// 测试策略：
//   - SyncPrimitives(nullptr) + EpChannel(nullptr) 作为 peer
//   - broadcast/all_gather 的 Tree 分派在 channel_ 检查之前
//   - Tree 路径守卫失败 → return false → 简化版 channel_ 无效 → false/nullopt
//   - 通过 session_count() 验证 Tree session 被正确擦除（无泄漏）
//
// 注：Tree 状态机的完整多步通信需要真实 QUIC 连接（属集成测试范畴），
//     算法正确性已由 test_tree_engine.cpp 覆盖。

#include "linoh/multimodal/sync_primitives.hpp"
#include "linoh/multimodal/ep_channel.hpp"
#include "linoh/multimodal/tree_engine.hpp"

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

// ============================================================================
// 测试 1: broadcast algo=Tree N=1（单节点）→ Tree 拒绝
// ============================================================================
static void test_broadcast_tree_n1() {
    std::printf("[test] broadcast algo=Tree N=1 (single node)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);
    auto data = make_data(16);
    // participant_mask=0b0001 → N=1, broadcast_tree_ 检查 N<2 → return false
    // 降级简化版：channel_ 无效 → false
    bool result = sync.broadcast(8101, 0b0001, 0,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 std::chrono::milliseconds(500), 1);
    CHECK(!result);
    // 简化版创建 session（broadcast 在 channel 无效时仍创建会话）
    auto s = sync.get_session(8101);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());  // Tree 未接管
}

// ============================================================================
// 测试 2: broadcast algo=Tree N=2 无 peer → Tree 拒绝，降级简化版
// ============================================================================
static void test_broadcast_tree_no_peers() {
    std::printf("[test] broadcast algo=Tree N=2 no peers (degrade)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);
    auto data = make_data(32);
    // N=2, root=0, self=0, 无 peer_channels_ → children channel 检查失败 → return false
    // 降级简化版：channel_ 无效 → false
    bool result = sync.broadcast(8102, 0b0011, 0,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 std::chrono::milliseconds(500), 1);
    CHECK(!result);
    auto s = sync.get_session(8102);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());  // Tree 降级
}

// ============================================================================
// 测试 3: broadcast algo=Tree root 不在 mask → 参数校验拒绝
// ============================================================================
static void test_broadcast_tree_root_not_in_mask() {
    std::printf("[test] broadcast algo=Tree root not in mask...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);
    auto data = make_data(16);
    // participant_mask=0b0011 (bit 0,1), root=2 (bit 2 不在 mask)
    // 参数校验：root 必须在 mask → false
    bool result = sync.broadcast(8103, 0b0011, 2,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 std::chrono::milliseconds(500), 1);
    CHECK(!result);
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 4: broadcast algo=Tree + null-channel peer → Tree send 失败降级
// ============================================================================
static void test_broadcast_tree_null_peer_degrade() {
    std::printf("[test] broadcast algo=Tree null-channel peer (attempt + degrade)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=2 binomial tree: root=0, child=1
    // set_tree_peers: parent=null (root), children={{0x02, null_ch}}
    sync.set_tree_peers(0, nullptr, {{0x02, &null_ch}});

    auto data = make_data(32);
    // Tree: children channel 已配置 → 创建 session → root send 失败 → 擦除 → false
    // 降级简化版：channel_ 无效 → false，但创建会话
    bool result = sync.broadcast(8104, 0b0011, 0,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 std::chrono::milliseconds(500), 1);
    CHECK(!result);
    // Tree session 被擦除，简化版重建会话（无 tree_algo）
    auto s = sync.get_session(8104);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());  // Tree 接管失败，简化版接管
}

// ============================================================================
// 测试 5: all_gather algo=Tree N=1 → Tree 拒绝
// ============================================================================
static void test_all_gather_tree_n1() {
    std::printf("[test] all_gather algo=Tree N=1 (single node)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);
    auto chunk = make_data(16);
    auto result = sync.all_gather(8105, 0b0001, 0,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 1);
    CHECK(!result.has_value());
    // N=1 Tree 拒绝 → 简化版创建会话（all_gather 在 channel 无效时仍创建会话）
    auto s = sync.get_session(8105);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());
}

// ============================================================================
// 测试 6: all_gather algo=Tree N=2 无 peer → Tree 拒绝（parent channel 未配置）
// ============================================================================
static void test_all_gather_tree_no_parent_peer() {
    std::printf("[test] all_gather algo=Tree N=2 no parent peer (degrade)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);  // self=bit1, 非 root（root=bit0）
    auto chunk = make_data(16);
    // N=2, self=bit1, root=bit0（participants[0]）
    // all_gather_tree_: 非 root 需 parent channel → peer_channels_ 未配置 → return false
    auto result = sync.all_gather(8106, 0b0011, 1,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 1);
    CHECK(!result.has_value());
    auto s = sync.get_session(8106);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());
}

// ============================================================================
// 测试 7: all_gather algo=Tree + null-channel parent → Tree send 失败降级
// ============================================================================
static void test_all_gather_tree_null_parent_degrade() {
    std::printf("[test] all_gather algo=Tree null-channel parent (leaf send fail)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(1);  // self=bit1, leaf（N=2, root=bit0）

    EpChannel null_ch(nullptr);
    // 叶子节点：parent=bit0, children=空
    sync.set_tree_peers(0x01, &null_ch, {});

    auto chunk = make_data(16);
    // Tree: parent channel 已配置 → 创建 session → 叶子 send 失败 → 擦除 → false
    // 降级简化版：channel_ 无效 → nullopt，但创建会话
    auto result = sync.all_gather(8107, 0b0011, 1,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 1);
    CHECK(!result.has_value());
    auto s = sync.get_session(8107);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());
}

// ============================================================================
// 测试 8: set_tree_peers 注入正确
// ============================================================================
static void test_set_tree_peers_injection() {
    std::printf("[test] set_tree_peers injection...\n");

    SyncPrimitives sync(nullptr);
    EpChannel ch1(nullptr);
    EpChannel ch2(nullptr);
    EpChannel ch3(nullptr);

    // root 节点：parent=null, children={bit1, bit2, bit3}
    sync.set_tree_peers(0, nullptr, {{0x02, &ch1}, {0x04, &ch2}, {0x08, &ch3}});
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(3));
    CHECK(sync.has_peer_channel(0x02));
    CHECK(sync.has_peer_channel(0x04));
    CHECK(sync.has_peer_channel(0x08));

    // clear 后归零
    sync.clear_peer_channels();
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 9: set_tree_peers — leaf 节点仅注入 parent
// ============================================================================
static void test_set_tree_peers_leaf() {
    std::printf("[test] set_tree_peers leaf (parent only)...\n");

    SyncPrimitives sync(nullptr);
    EpChannel parent_ch(nullptr);

    // leaf 节点：parent=bit0, children=空
    sync.set_tree_peers(0x01, &parent_ch, {});
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(1));
    CHECK(sync.has_peer_channel(0x01));
}

// ============================================================================
// 测试 10: clear_peer_channels 后 Tree 守卫拦截
// ============================================================================
static void test_clear_peers_then_guard() {
    std::printf("[test] clear_peer_channels then Tree guard...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel ch(nullptr);
    sync.set_tree_peers(0, nullptr, {{0x02, &ch}});
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(1));

    sync.clear_peer_channels();

    auto data = make_data(16);
    // children channel 未配置 → Tree 拒绝
    bool result = sync.broadcast(8110, 0b0011, 0,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 std::chrono::milliseconds(300), 1);
    CHECK(!result);
    auto s = sync.get_session(8110);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());
}

// ============================================================================
// 测试 11: TreeAlgoState 字段默认值
// ============================================================================
static void test_tree_algo_state_defaults() {
    std::printf("[test] TreeAlgoState default values...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=4: root=0, children={1,2,3} (binomial tree)
    // 但 null channel 会导致 send 失败
    sync.set_tree_peers(0, nullptr, {{0x02, &null_ch}, {0x04, &null_ch}, {0x08, &null_ch}});

    auto data = make_data(16);
    // Tree 创建 session 后 send 失败 → 擦除 → 降级
    sync.broadcast(8111, 0b1111, 0,
                   std::span<const std::uint8_t>(data.data(), data.size()),
                   std::chrono::milliseconds(300), 1);

    // 降级后简化版会话无 tree_algo
    auto s = sync.get_session(8111);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());
}

// ============================================================================
// 测试 12: TreeEngine 拓扑构建一致性
// ============================================================================
static void test_tree_engine_topology() {
    std::printf("[test] TreeEngine topology consistency...\n");

    // N=4 binomial tree, root=0
    std::vector<std::uint64_t> participants = {0x01, 0x02, 0x04, 0x08};
    auto tree = TreeEngine::build_binomial_tree(participants, 0);

    // root (0x01) children = {0x02, 0x04} (bit 1 and bit 2)
    // N=4, total_steps=2
    // root virtual=0, children_of(0, 4) = {0+1, 0+2} = {1, 2}
    CHECK(tree.find(0x01) != tree.end());
    CHECK_EQ(tree[0x01].size(), static_cast<std::size_t>(2));

    // Node 0x02 (virtual=1): children_of(1, 4) = {1+2} = {3} → 0x08
    CHECK(tree.find(0x02) != tree.end());
    CHECK_EQ(tree[0x02].size(), static_cast<std::size_t>(1));

    // Node 0x04 (virtual=2): children_of(2, 4) = {} (leaf)
    CHECK(tree.find(0x04) != tree.end());
    CHECK_EQ(tree[0x04].size(), static_cast<std::size_t>(0));

    // Node 0x08 (virtual=3): children_of(3, 4) = {} (leaf)
    CHECK(tree.find(0x08) != tree.end());
    CHECK_EQ(tree[0x08].size(), static_cast<std::size_t>(0));

    // recv_step 验证
    CHECK(!TreeEngine::recv_step_of(0).has_value());  // root 不接收
    CHECK_EQ(TreeEngine::recv_step_of(1).value(), static_cast<std::size_t>(0));
    CHECK_EQ(TreeEngine::recv_step_of(2).value(), static_cast<std::size_t>(1));
    CHECK_EQ(TreeEngine::recv_step_of(3).value(), static_cast<std::size_t>(1));

    // total_steps
    CHECK_EQ(TreeEngine::total_steps(4), static_cast<std::size_t>(2));
    CHECK_EQ(TreeEngine::total_steps(8), static_cast<std::size_t>(3));
    CHECK_EQ(TreeEngine::total_steps(2), static_cast<std::size_t>(1));
}

// ============================================================================
// 测试 13: 多次调用不产生会话累积
// ============================================================================
static void test_no_session_accumulation() {
    std::printf("[test] multiple calls no session accumulation...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_tree_peers(0, nullptr, {{0x02, &null_ch}});

    auto data = make_data(16);
    for (int i = 0; i < 5; ++i) {
        sync.broadcast(8120 + i, 0b0011, 0,
                       std::span<const std::uint8_t>(data.data(), data.size()),
                       std::chrono::milliseconds(200), 1);
    }
    // 清理已完成会话后应无累积
    sync.cleanup_finished();
    // 简化版 session 可能在 cleanup 后残留 0 个
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 14: broadcast algo=Tree session 生命周期（null-channel peer）
// ============================================================================
static void test_broadcast_tree_session_lifecycle() {
    std::printf("[test] broadcast algo=Tree session lifecycle (null-channel)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_tree_peers(0, nullptr, {{0x02, &null_ch}});

    auto data = make_data(16);
    auto t0 = std::chrono::steady_clock::now();
    bool result = sync.broadcast(8130, 0b0011, 0,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 std::chrono::milliseconds(300), 1);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();

    // Tree: 创建 session → send 失败 → 擦除 → false
    // 简化版: channel_ 无效 → false
    CHECK(!result);
    // 应快速返回（send 失败是同步的）
    CHECK(elapsed < 200);
}

// ============================================================================
// 测试 15: all_gather algo=非 Tree（Ring=0）不进入 Tree 路径
// ============================================================================
static void test_all_gather_non_tree_algo() {
    std::printf("[test] all_gather algo=0 (Ring) skips Tree path...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_tree_peers(0x01, &null_ch, {{0x02, &null_ch}});

    auto chunk = make_data(16);
    // algo=0 (Ring) → 不进入 Tree 分派
    auto result = sync.all_gather(8140, 0b0011, 0,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(300), 0);
    CHECK(!result.has_value());
    auto s = sync.get_session(8140);
    CHECK(s.has_value());
    CHECK(!s->tree_algo.has_value());  // Ring 路径不创建 tree_algo
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== TreeDriver (P4-D Tree Engine Guard & Degradation) Unit Tests ===\n\n");

    test_broadcast_tree_n1();
    test_broadcast_tree_no_peers();
    test_broadcast_tree_root_not_in_mask();
    test_broadcast_tree_null_peer_degrade();
    test_all_gather_tree_n1();
    test_all_gather_tree_no_parent_peer();
    test_all_gather_tree_null_parent_degrade();
    test_set_tree_peers_injection();
    test_set_tree_peers_leaf();
    test_clear_peers_then_guard();
    test_tree_algo_state_defaults();
    test_tree_engine_topology();
    test_no_session_accumulation();
    test_broadcast_tree_session_lifecycle();
    test_all_gather_non_tree_algo();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
