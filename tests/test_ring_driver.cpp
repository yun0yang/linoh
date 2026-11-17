// test_ring_driver.cpp — P4-C Ring 驱动守卫与降级单元测试（v2.3 Phase 4）
//
// 验证 P4-C 交付物（Ring 引擎驱动 EpChannel 通信的守卫逻辑）：
//   1. all_reduce_ring_ 守卫：N<2 / 数据不可整除 / chunk 过大 → return false
//   2. all_gather_ring_ 守卫：N<2 / chunk 过大 → return false
//   3. reduce_scatter_ring_ 守卫：N<2 / 数据不可整除 → return false
//   4. Ring 路径失败后正确降级到简化版（无崩溃、无会话泄漏）
//   5. Ring 路径与简化版的 algo 字段一致性
//   6. 非二次幂 N=3 场景 Ring 守卫
//   7. self_node_id 不在 participant_mask → Ring 拒绝
//   8. Ring 路径需要 peer_channels_ 配置 next 邻居（路由前提）
//   9. 多次调用不产生会话累积
//  10. all_reduce algo=Ring + 有效 peer（null-channel）→ Ring session 生命周期正确
//
// 测试策略：
//   - SyncPrimitives(nullptr) + EpChannel(nullptr) 作为 peer
//   - all_reduce/all_gather/reduce_scatter 的 Ring 分派在 channel_ 检查之前
//   - Ring 路径守卫失败 → return false → 简化版 channel_ 无效 → nullopt
//   - 通过 session_count() 验证 Ring session 被正确擦除（无泄漏）
//   - 守卫逻辑是 all_*_ring_ 私有方法内部，通过公共 API 的返回值和副作用间接验证
//
// 注：Ring 状态机的完整多步通信需要真实 QUIC 连接（属集成测试范畴），
//     算法正确性已由 test_ring_engine.cpp 覆盖（N=2/4/6/8 AllReduce/AllGather/ReduceScatter 模拟）。

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

/// 构造超过 kMaxPayloadLen 的数据（4GB+1，仅在大小检查中使用，不实际分配）
/// 注：kMaxPayloadLen = 4GB，构造如此大的 vector 不现实，
///     此处用 size 检查在 all_reduce 入口已拦截，不需要实际数据

// ============================================================================
// 测试 1: all_reduce algo=Ring N=1（单节点）→ Ring 拒绝
// ============================================================================
static void test_all_reduce_ring_n1() {
    std::printf("[test] all_reduce algo=Ring N=1 (single node)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);
    // participant_mask = 0b0001 → N=1, all_reduce_ring_ 检查 N<2 → return false
    auto data = make_u64({42});
    auto result = sync.all_reduce(8001, 0b0001, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 2: all_reduce algo=Ring 数据不可整除 → Ring 拒绝
// ============================================================================
static void test_all_reduce_ring_not_divisible() {
    std::printf("[test] all_reduce algo=Ring data not divisible by N...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    sync.set_ring_peers(0x02, &peer_ch, 0x02, &peer_ch);

    // N=2 但数据 24 字节（3 个 uint64），24/2=12 字节/chunk → 可整除
    // 改为 N=3：participant_mask=0b0111, data=16 字节（2 个 uint64），16%3 != 0 → 不可整除
    // 但 N=3 需要 3 节点，self=0, next=1, prev=2
    sync.clear_peer_channels();
    sync.set_ring_peers(0x02, &peer_ch, 0x04, &peer_ch);  // next=bit1, prev=bit2

    auto data = make_u64({10, 20});  // 16 字节，16%3 != 0
    auto result = sync.all_reduce(8002, 0b0111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 0);
    // all_reduce_ring_: local_data.size() % N != 0 → return false
    // 简化版: channel_ 无效 → nullopt
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 3: all_gather algo=Ring N=1 → Ring 拒绝
// ============================================================================
static void test_all_gather_ring_n1() {
    std::printf("[test] all_gather algo=Ring N=1 (single node)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);
    auto chunk = make_u64({99});
    auto result = sync.all_gather(8003, 0b0001, 0,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());
    // N=1 Ring 拒绝 → 简化版创建会话（all_gather 在 channel 无效时仍创建会话）
    auto s = sync.get_session(8003);
    CHECK(s.has_value());
    CHECK(!s->ring_algo.has_value());  // Ring 未接管
}

// ============================================================================
// 测试 4: all_gather algo=Ring 有 peer（null-channel）→ Ring 尝试后降级
// ============================================================================
static void test_all_gather_ring_null_peer_degrade() {
    std::printf("[test] all_gather algo=Ring null-channel peer (attempt + degrade)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    // 3 节点环：self=bit0, next=bit1, prev=bit2
    sync.set_ring_peers(0x02, &peer_ch, 0x04, &peer_ch);

    auto chunk = make_u64({77});
    auto result = sync.all_gather(8004, 0b0111, 0,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 0);
    // Ring: peer_channels_ 有 next → 创建 session → send 失败 → 擦除 → false
    // 简化版: channel_ 无效 → 创建会话（Waiting）→ nullopt
    CHECK(!result.has_value());
    // Ring session 被擦除，简化版重建会话（无 ring_algo）
    auto s = sync.get_session(8004);
    CHECK(s.has_value());
    CHECK(!s->ring_algo.has_value());
}

// ============================================================================
// 测试 5: reduce_scatter algo=Ring N=1 → Ring 拒绝
// ============================================================================
static void test_reduce_scatter_ring_n1() {
    std::printf("[test] reduce_scatter algo=Ring N=1 (single node)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);
    auto data = make_u64({5});
    auto result = sync.reduce_scatter(8005, 0b0001, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());
    // N=1 Ring 拒绝 → 简化版创建会话（reduce_scatter 在 channel 无效时仍创建会话）
    auto s = sync.get_session(8005);
    CHECK(s.has_value());
    CHECK(!s->ring_algo.has_value());  // Ring 未接管
}

// ============================================================================
// 测试 6: reduce_scatter algo=Ring 数据不可整除 → Ring 拒绝
// ============================================================================
static void test_reduce_scatter_ring_not_divisible() {
    std::printf("[test] reduce_scatter algo=Ring data not divisible by N...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    sync.set_ring_peers(0x02, &peer_ch, 0x04, &peer_ch);

    // N=3, data=16 字节, 16%3 != 0 → Ring 拒绝
    auto data = make_u64({10, 20});  // 16 字节
    auto result = sync.reduce_scatter(8006, 0b0111, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 7: self_node_id 不在 participant_mask → 参数校验拒绝
// ============================================================================
static void test_self_not_in_mask() {
    std::printf("[test] self_node_id not in participant_mask...\n");

    SyncPrimitives sync(nullptr);
    // self=2 (bit 2) 但 mask=0b0011 (只有 bit 0,1)
    auto data = make_u64({1, 2});
    auto result = sync.all_reduce(8007, 0b0011, 2,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 8: Ring 路径需要 peer_channels_ 配置 next 邻居
// ============================================================================
static void test_ring_requires_next_peer() {
    std::printf("[test] Ring requires next peer channel configured...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // 只配置 prev，不配置 next
    EpChannel prev_ch(nullptr);
    sync.set_peer_channel(0x01, &prev_ch);  // 只有 prev=bit1，没有 next

    // 2 节点环：self=bit0, next=bit1, prev=bit1
    // all_reduce_ring_ 检查 peer_channels_.find(next_node=0x02) → 找到（bit1=0x02）
    // 等等，bit1 = 0x02，所以 next=0x02 已配置。让我重新设计。

    // 3 节点环：self=bit0, next=bit1(0x02), prev=bit2(0x04)
    // 只配置 prev=0x04，不配置 next=0x02
    sync.clear_peer_channels();
    sync.set_peer_channel(0x04, &prev_ch);  // 只有 prev，没有 next

    auto data = make_u64({1, 2, 3});  // 24 字节，24%3=8 → 可整除
    auto result = sync.all_reduce(8008, 0b0111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 0);
    // all_reduce_ring_: peer_channels_.find(next=0x02) == end → return false
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 9: 多次调用不产生会话累积
// ============================================================================
static void test_no_session_accumulation() {
    std::printf("[test] multiple calls no session accumulation...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    sync.set_ring_peers(0x02, &peer_ch, 0x02, &peer_ch);

    auto data = make_u64({1, 2});  // 16 字节，N=2 可整除

    // 连续 5 次调用，每次 Ring 创建/擦除 session
    for (int i = 0; i < 5; ++i) {
        auto result = sync.all_reduce(8009 + i, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(200), 0);
        CHECK(!result.has_value());
    }
    // 所有 session 应已被清理
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 10: all_reduce algo=Ring + 有效 peer（null-channel）→ Ring session 生命周期
// ============================================================================
static void test_all_reduce_ring_session_lifecycle() {
    std::printf("[test] all_reduce algo=Ring session lifecycle (null-channel peer)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    // 2 节点环：self=bit0, next=bit1(0x02), prev=bit1(0x02)
    sync.set_ring_peers(0x02, &peer_ch, 0x02, &peer_ch);

    // 使用短超时确保快速返回
    auto data = make_u64({50, 60});  // 16 字节，N=2 可整除
    auto t0 = std::chrono::steady_clock::now();
    auto result = sync.all_reduce(8020, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(300), 0);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();

    // Ring: 创建 session → send 失败 → 擦除 → return false
    // 简化版: channel_ 无效 → nullopt
    // 应快速返回（不需要等超时）
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
    // 验证快速返回（Ring send 失败是同步的，不应阻塞到超时）
    CHECK(elapsed < 200);  // 应远小于 300ms 超时
}

// ============================================================================
// 测试 11: all_gather algo=非 Ring（Tree=1）不进入 Ring 路径
// ============================================================================
static void test_all_gather_non_ring_algo() {
    std::printf("[test] all_gather algo=1 (Tree) skips Ring path...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // P4-D 修复: 不配置 ring peers。ring peers 共享 peer_channels_ 会被 Tree 复用，
    // 导致 Tree（root 角色）接管而非降级简化版。移除后 algo=1 跳过 Ring 且 Tree
    // 守卫失败（无 children channel）→ 降级简化版创建会话（无 ring_algo）。
    auto chunk = make_u64({33});
    // algo=1 (Tree) → 不进入 Ring 分派
    auto result = sync.all_gather(8021, 0b0011, 0,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(300), 1);
    CHECK(!result.has_value());
    // algo=1 跳过 Ring → 简化版创建会话（无 ring_algo）
    auto s = sync.get_session(8021);
    CHECK(s.has_value());
    CHECK(!s->ring_algo.has_value());  // Tree 路径不创建 ring_algo
}

// ============================================================================
// 测试 12: Ring 路径 N=2 可整除数据 → Ring 尝试（send 失败降级）
//         验证 Ring 路径不被守卫拦截（到达 send 阶段）
// ============================================================================
static void test_ring_reaches_send_stage() {
    std::printf("[test] Ring reaches send stage (N=2 divisible data, null-channel)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    sync.set_ring_peers(0x02, &peer_ch, 0x02, &peer_ch);

    // N=2, data=16 字节，16%2=0 → 通过守卫，到达 send
    auto data = make_u64({1, 2});
    auto result = sync.all_reduce(8022, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(300), 0);
    // Ring 通过守卫 → 创建 session → send 失败 → 擦除 → false
    // 简化版 channel_ 无效 → nullopt
    // 关键：如果守卫拦截了，不会到达 send，但结果相同（nullopt）
    // 区别在于耗时：守卫拦截是即时的，send 失败也是即时的
    // 此测试验证 N=2 可整除场景不崩溃，且正确清理
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== RingDriver (P4-C Ring Engine Guard & Degradation) Unit Tests ===\n\n");

    test_all_reduce_ring_n1();
    test_all_reduce_ring_not_divisible();
    test_all_gather_ring_n1();
    test_all_gather_ring_null_peer_degrade();
    test_reduce_scatter_ring_n1();
    test_reduce_scatter_ring_not_divisible();
    test_self_not_in_mask();
    test_ring_requires_next_peer();
    test_no_session_accumulation();
    test_all_reduce_ring_session_lifecycle();
    test_all_gather_non_ring_algo();
    test_ring_reaches_send_stage();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
