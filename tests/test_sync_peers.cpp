// test_sync_peers.cpp — P4-B 多 EpChannel 路由 API 单元测试（v2.3 Phase 4）
//
// 验证 P4-B 交付物：
//   1. peer_channels_ 状态管理：set_peer_channel / has_peer_channel / peer_channel_count
//   2. set_ring_peers 一次性配置 next + prev 邻居
//   3. clear_peer_channels 清除所有 peer 配置
//   4. set_peer_channel(nullptr) 删除单个 peer 条目
//   5. set_self_node_id / self_node_id getter
//   6. peer_channels_ 实例隔离（不同 SyncPrimitives 互不影响）
//   7. all_gather algo=Ring 无 peer channels → Ring 降级，简化版接管
//   8. all_gather algo=Ring 有 peer channels（null-channel EpChannel）→ Ring 尝试后降级
//   9. reduce_scatter algo=Ring 无 peer channels → Ring 降级
//  10. all_reduce algo=Ring 无 peer channels → Ring 降级（channel_ 检查移至 Ring 之后）
//  11. 会话无泄漏（Ring 失败后简化版正确清理）
//
// 测试策略：
//   - SyncPrimitives(nullptr) 构造（channel_ 无效）
//   - EpChannel(nullptr) 作为 peer channel 指针（conn_ 无效，send_sync 返回 false 不崩溃）
//   - all_reduce/all_gather/reduce_scatter 的 Ring 分派在 channel_ 检查之前，
//     可验证 Ring 路径被调用及降级行为
//   - 通过 session_count() 验证无会话泄漏

#include "linoh/multimodal/sync_primitives.hpp"
#include "linoh/multimodal/ep_channel.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
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

// ============================================================================
// 测试 1: peer_channels_ 初始状态
// ============================================================================
static void test_initial_state() {
    std::printf("[test] peer_channels_ initial state...\n");

    SyncPrimitives sync(nullptr);
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(0));
    CHECK(!sync.has_peer_channel(0x01));
    CHECK(!sync.has_peer_channel(0x02));
    CHECK(!sync.has_peer_channel(0));
}

// ============================================================================
// 测试 2: set_peer_channel 增删查
// ============================================================================
static void test_set_peer_channel() {
    std::printf("[test] set_peer_channel add/remove/query...\n");

    SyncPrimitives sync(nullptr);
    EpChannel ch1(nullptr);
    EpChannel ch2(nullptr);

    // 添加 peer 0x01
    sync.set_peer_channel(0x01, &ch1);
    CHECK(sync.has_peer_channel(0x01));
    CHECK(!sync.has_peer_channel(0x02));
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(1));

    // 添加 peer 0x02
    sync.set_peer_channel(0x02, &ch2);
    CHECK(sync.has_peer_channel(0x01));
    CHECK(sync.has_peer_channel(0x02));
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(2));

    // nullptr 删除 peer 0x01
    sync.set_peer_channel(0x01, nullptr);
    CHECK(!sync.has_peer_channel(0x01));
    CHECK(sync.has_peer_channel(0x02));
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(1));

    // 重复删除已不存在的 peer（no-op，count 不变）
    sync.set_peer_channel(0x01, nullptr);
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(1));
}

// ============================================================================
// 测试 3: set_ring_peers 一次性配置 next + prev
// ============================================================================
static void test_set_ring_peers() {
    std::printf("[test] set_ring_peers (next + prev)...\n");

    SyncPrimitives sync(nullptr);
    EpChannel next_ch(nullptr);
    EpChannel prev_ch(nullptr);

    // 4 节点环：本节点 bit=0x02, next=0x04, prev=0x01
    sync.set_ring_peers(0x04, &next_ch, 0x01, &prev_ch);
    CHECK(sync.has_peer_channel(0x04));  // next
    CHECK(sync.has_peer_channel(0x01));  // prev
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(2));

    // 清除后重新配置不同邻居
    sync.clear_peer_channels();
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(0));

    // 2 节点环：next == prev
    sync.set_ring_peers(0x01, &next_ch, 0x01, &prev_ch);
    CHECK(sync.has_peer_channel(0x01));
    // 0x01 只存一个条目（map key 唯一）
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(1));
}

// ============================================================================
// 测试 4: clear_peer_channels
// ============================================================================
static void test_clear_peer_channels() {
    std::printf("[test] clear_peer_channels...\n");

    SyncPrimitives sync(nullptr);
    EpChannel ch1(nullptr), ch2(nullptr), ch3(nullptr);

    sync.set_peer_channel(0x01, &ch1);
    sync.set_peer_channel(0x02, &ch2);
    sync.set_peer_channel(0x04, &ch3);
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(3));

    sync.clear_peer_channels();
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(0));
    CHECK(!sync.has_peer_channel(0x01));
    CHECK(!sync.has_peer_channel(0x02));
    CHECK(!sync.has_peer_channel(0x04));

    // 再次 clear 是 no-op
    sync.clear_peer_channels();
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 5: set_self_node_id / self_node_id
// ============================================================================
static void test_self_node_id() {
    std::printf("[test] set_self_node_id / self_node_id...\n");

    SyncPrimitives sync(nullptr);
    CHECK_EQ(sync.self_node_id(), static_cast<std::uint64_t>(0));  // 默认 0

    sync.set_self_node_id(0x04);
    CHECK_EQ(sync.self_node_id(), static_cast<std::uint64_t>(0x04));

    sync.set_self_node_id(0);
    CHECK_EQ(sync.self_node_id(), static_cast<std::uint64_t>(0));
}

// ============================================================================
// 测试 6: peer_channels_ 实例隔离
// ============================================================================
static void test_instance_isolation() {
    std::printf("[test] peer_channels_ instance isolation...\n");

    SyncPrimitives sync_a(nullptr);
    SyncPrimitives sync_b(nullptr);
    EpChannel ch(nullptr);

    sync_a.set_peer_channel(0x01, &ch);
    CHECK_EQ(sync_a.peer_channel_count(), static_cast<std::size_t>(1));
    CHECK_EQ(sync_b.peer_channel_count(), static_cast<std::size_t>(0));  // b 不受影响

    sync_b.set_peer_channel(0x02, &ch);
    CHECK_EQ(sync_a.peer_channel_count(), static_cast<std::size_t>(1));  // a 不受影响
    CHECK_EQ(sync_b.peer_channel_count(), static_cast<std::size_t>(1));

    sync_a.clear_peer_channels();
    CHECK_EQ(sync_a.peer_channel_count(), static_cast<std::size_t>(0));
    CHECK_EQ(sync_b.peer_channel_count(), static_cast<std::size_t>(1));  // b 不受影响
}

// ============================================================================
// 测试 7: all_gather algo=Ring 无 peer channels → Ring 降级
// ============================================================================
static void test_all_gather_ring_no_peers() {
    std::printf("[test] all_gather algo=Ring without peer channels (degrade)...\n");

    SyncPrimitives sync(nullptr);
    // 不配置 peer_channels_，Ring 路径应直接返回 false
    auto chunk = make_u64({42});
    auto result = sync.all_gather(7001, 0b0011, 0,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 0);  // algo=Ring
    CHECK(!result.has_value());  // Ring 失败 + 简化版 channel 无效 → nullopt
    // all_gather 简化版在 channel 无效时仍创建会话（Waiting 状态，便于被动接收）
    // 验证 Ring 降级：会话存在但 ring_algo 为 nullopt
    auto s = sync.get_session(7001);
    CHECK(s.has_value());
    CHECK(!s->ring_algo.has_value());  // Ring 降级到简化版
}

// ============================================================================
// 测试 8: all_gather algo=Ring 有 peer channels（null-channel）→ Ring 尝试后降级
// ============================================================================
static void test_all_gather_ring_null_channel_peer() {
    std::printf("[test] all_gather algo=Ring with null-channel peer (attempt + degrade)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // 配置 peer channel（EpChannel conn_ 无效，send_sync 返回 false）
    EpChannel peer_ch(nullptr);
    // 2 节点环：本节点 bit 0, next=bit 1, prev=bit 1
    sync.set_ring_peers(/*next=*/0x02, &peer_ch, /*prev=*/0x02, &peer_ch);

    auto chunk = make_u64({42});
    auto result = sync.all_gather(7002, 0b0011, 0,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 0);  // algo=Ring
    // Ring 路径：peer_channels_ 有 next → 创建 Ring session → send 失败 → 擦除 → return false
    // 简化版：channel_ 无效 → 创建会话（Waiting）→ return nullopt
    CHECK(!result.has_value());
    // 验证 Ring 接管失败后简化版接管：会话存在但 ring_algo 为 nullopt
    auto s = sync.get_session(7002);
    CHECK(s.has_value());
    CHECK(!s->ring_algo.has_value());  // Ring session 被擦除，简化版重建（无 ring_algo）
}

// ============================================================================
// 测试 9: reduce_scatter algo=Ring 无 peer channels → Ring 降级
// ============================================================================
static void test_reduce_scatter_ring_no_peers() {
    std::printf("[test] reduce_scatter algo=Ring without peer channels (degrade)...\n");

    SyncPrimitives sync(nullptr);
    // 2 节点，数据 16 字节（2 个 uint64），可被 N=2 整除
    auto data = make_u64({10, 20});
    auto result = sync.reduce_scatter(7003, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(500), 0);  // algo=Ring
    CHECK(!result.has_value());
    // reduce_scatter 简化版在 channel 无效时仍创建会话（Reducing 状态）
    auto s = sync.get_session(7003);
    CHECK(s.has_value());
    CHECK(!s->ring_algo.has_value());  // Ring 降级到简化版
}

// ============================================================================
// 测试 10: all_reduce algo=Ring 无 peer channels → Ring 降级
// ============================================================================
static void test_all_reduce_ring_no_peers() {
    std::printf("[test] all_reduce algo=Ring without peer channels (degrade)...\n");

    SyncPrimitives sync(nullptr);
    auto data = make_u64({100});
    auto result = sync.all_reduce(7004, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 0);  // algo=Ring
    // Ring 路径：无 peer_channels_ → return false
    // 简化版：channel_ 无效 → return nullopt
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 11: all_reduce algo=Ring 有 peer channels（null-channel）→ Ring 尝试后降级
// ============================================================================
static void test_all_reduce_ring_null_channel_peer() {
    std::printf("[test] all_reduce algo=Ring with null-channel peer (attempt + degrade)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    // 2 节点环：本节点 bit 0, next=bit 1, prev=bit 1
    sync.set_ring_peers(0x02, &peer_ch, 0x02, &peer_ch);

    auto data = make_u64({100, 200});  // 16 字节，可被 N=2 整除
    auto result = sync.all_reduce(7005, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 0);  // algo=Ring
    // Ring 路径：peer_channels_ 有 next → 创建 Ring session → send 失败 → 擦除 → return false
    // 简化版：channel_ 无效 → return nullopt
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));  // 关键：Ring session 已擦除
}

// ============================================================================
// 测试 12: algo=非 Ring 不尝试 Ring 路径
// ============================================================================
static void test_non_ring_algo_skips_ring() {
    std::printf("[test] algo=1 (Tree) skips Ring path...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    sync.set_ring_peers(0x02, &peer_ch, 0x02, &peer_ch);

    auto data = make_u64({100, 200});
    // algo=1 (Tree) → 不进入 Ring 分派，直接简化版
    auto result = sync.all_reduce(7006, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 1);  // algo=Tree
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== SyncPeers (P4-B Multi-EpChannel Routing) Unit Tests ===\n\n");

    test_initial_state();
    test_set_peer_channel();
    test_set_ring_peers();
    test_clear_peer_channels();
    test_self_node_id();
    test_instance_isolation();
    test_all_gather_ring_no_peers();
    test_all_gather_ring_null_channel_peer();
    test_reduce_scatter_ring_no_peers();
    test_all_reduce_ring_no_peers();
    test_all_reduce_ring_null_channel_peer();
    test_non_ring_algo_skips_ring();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
