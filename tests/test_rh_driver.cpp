// test_rh_driver.cpp — P4-E RecursiveHalving 驱动守卫与降级单元测试（v2.3 Phase 4）
//
// 验证 P4-E 交付物（RH 引擎驱动 EpChannel 通信的守卫逻辑）：
//   1. all_reduce_rh_ 守卫：N<2 / N 非 2 的幂 / 数据不可整除 / chunk 过大 → return false
//   2. reduce_scatter_rh_ 守卫：N<2 / N 非 2 的幂 / 数据不可整除 → return false
//   3. self_node_id 不在 participant_mask → RH 拒绝
//   4. partner channel 未配置 → RH 拒绝
//   5. RH 路径失败后正确降级到简化版（无崩溃、无会话泄漏）
//   6. set_rh_peers 注入 peer_channels_ 正确
//   7. clear_peer_channels 后守卫拦截
//   8. RhAlgoState 字段默认值校验
//   9. RHEngine 拓扑一致性（partner = rank XOR (1<<s)）
//  10. 多次调用不产生会话累积
//  11. all_reduce algo=RH + null-channel partner → RH session 生命周期正确
//  12. all_reduce algo=0 (Ring) 跳过 RH 路径
//  13. all_reduce algo=1 (Tree) 跳过 RH 路径
//  14. reduce_scatter algo=RH 守卫与降级
//
// 测试策略：
//   - SyncPrimitives(nullptr) + EpChannel(nullptr) 作为 peer
//   - all_reduce/reduce_scatter 的 RH 分派在 channel_ 检查之前
//   - RH 路径守卫失败 → return false → 简化版 channel_ 无效 → nullopt
//   - RH 路径 send 失败 → 擦除 session → return false → 简化版
//   - 通过 session_count() 验证 RH session 被正确擦除（无泄漏）
//
// 注：RH 状态机的完整多步通信需要真实 QUIC 连接（属集成测试范畴），
//     算法正确性已由 test_rh_engine.cpp 覆盖（N=2/4/8 AllReduce/ReduceScatter 模拟）。

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

// ============================================================================
// 测试 1: all_reduce algo=RH N=1（单节点）→ RH 拒绝
// ============================================================================
static void test_all_reduce_rh_n1() {
    std::printf("[test] all_reduce algo=RH N=1 (single node)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);
    auto data = make_u64({42});
    auto result = sync.all_reduce(8201, 0b0001, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 2);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 2: all_reduce algo=RH N=3（非 2 的幂）→ RH 拒绝
// ============================================================================
static void test_all_reduce_rh_not_power_of_two() {
    std::printf("[test] all_reduce algo=RH N=3 (not power of two)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    sync.set_rh_peers({{0x02, &peer_ch}, {0x04, &peer_ch}});

    // N=3, data=24 字节（3 个 u64），24%3=0 可整除
    // 但 N=3 不是 2 的幂 → RH 拒绝
    auto data = make_u64({10, 20, 30});
    auto result = sync.all_reduce(8202, 0b0111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 2);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 3: all_reduce algo=RH 数据不可整除 → RH 拒绝
// ============================================================================
static void test_all_reduce_rh_not_divisible() {
    std::printf("[test] all_reduce algo=RH data not divisible by N...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    sync.set_rh_peers({{0x02, &peer_ch}});

    // N=2, data=24 字节（3 个 u64），24%2=0 可整除
    // 改为 N=4: participant_mask=0b1111, data=24 字节, 24%4=0 → 仍可整除
    // 改为 N=2, data=24 字节但设 elem_size 不匹配 → 但 all_reduce 不检查 elem
    // 用 N=4, data=24 字节, 24%4=6 可整除 → 但需要 4 个 partner
    // 简化：N=2, data=12 字节, 12%2=0 → 可整除。改 data=20 字节, 20%2=0 也可整除
    // 实际上 N=2 时任何偶数长度都可整除。用 N=4, data=24, 24%4=0 → 可整除
    // 要不可整除：N=4, data=18, 18%4 != 0
    sync.clear_peer_channels();
    sync.set_rh_peers({{0x02, &peer_ch}, {0x04, &peer_ch}, {0x08, &peer_ch}});

    auto data = make_u64({10, 20});  // 16 字节，N=4, 16%4=0 → 可整除
    // 改为不可整除：增加 4 字节 → 20 字节, 20%4=0 仍可整除
    // 用 data=24 字节 (3 u64), N=4, 24%4=0 → 可整除
    // 用 data=6 字节, N=4, 6%4 != 0 → 不可整除
    std::vector<std::uint8_t> odd_data(6, 0x01);
    auto result = sync.all_reduce(8203, 0b1111, 0,
                                  std::span<const std::uint8_t>(odd_data.data(), odd_data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 2);
    // all_reduce_rh_: local_data.size() % N != 0 → return false
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 4: all_reduce algo=RH 无 partner → RH 拒绝，降级简化版
// ============================================================================
static void test_all_reduce_rh_no_partner() {
    std::printf("[test] all_reduce algo=RH no partner (degrade)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // N=2, 无 partner channel 配置
    auto data = make_u64({1, 2});
    auto result = sync.all_reduce(8204, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 2);
    // RH: partner channel 未配置 → return false
    // 简化版: channel_ 无效 → nullopt，无会话
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 5: all_reduce algo=RH + null-channel partner → send 失败降级
// ============================================================================
static void test_all_reduce_rh_null_partner_degrade() {
    std::printf("[test] all_reduce algo=RH null-channel partner (attempt + degrade)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=2: self=bit0, partner=bit1(0x02)
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});  // 16 字节，N=2 可整除
    auto result = sync.all_reduce(8205, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(300), 2);
    // RH: partner channel 已配置 → 创建 session → send 失败 → 擦除 → false
    // 简化版: channel_ 无效 → nullopt
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 6: self_node_id 不在 participant_mask → RH 拒绝
// ============================================================================
static void test_self_not_in_mask_rh() {
    std::printf("[test] self_node_id not in participant_mask (RH)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(2);  // self=bit2

    EpChannel peer_ch(nullptr);
    sync.set_rh_peers({{0x01, &peer_ch}});

    // mask=0b0011 (bit 0,1)，self=bit2 不在 mask
    auto data = make_u64({1, 2});
    auto result = sync.all_reduce(8206, 0b0011, 2,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 2);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 7: set_rh_peers 注入 peer_channels_ 正确
// ============================================================================
static void test_set_rh_peers_injection() {
    std::printf("[test] set_rh_peers injection...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel ch1(nullptr), ch2(nullptr), ch3(nullptr);
    sync.set_rh_peers({{0x02, &ch1}, {0x04, &ch2}, {0x08, &ch3}});

    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(3));
    CHECK(sync.has_peer_channel(0x02));
    CHECK(sync.has_peer_channel(0x04));
    CHECK(sync.has_peer_channel(0x08));
    CHECK(!sync.has_peer_channel(0x01));
}

// ============================================================================
// 测试 8: clear_peer_channels 后守卫拦截
// ============================================================================
static void test_clear_then_rh_guard() {
    std::printf("[test] clear_peer_channels then RH guard...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel ch1(nullptr);
    sync.set_rh_peers({{0x02, &ch1}});
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(1));

    sync.clear_peer_channels();
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(0));

    auto data = make_u64({1, 2});
    auto result = sync.all_reduce(8208, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 2);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 9: RhAlgoState 字段默认值
// ============================================================================
static void test_rh_algo_state_defaults() {
    std::printf("[test] RhAlgoState default values...\n");

    SyncSession::RhAlgoState rs;
    CHECK(rs.phase == RHPhase::ReduceScatter);
    CHECK_EQ(rs.current_step, static_cast<std::uint32_t>(0));
    CHECK_EQ(rs.total_steps, static_cast<std::uint32_t>(0));
    CHECK_EQ(rs.self_rank, static_cast<std::size_t>(0));
    CHECK_EQ(rs.N, static_cast<std::size_t>(0));
    CHECK_EQ(rs.msg_size, static_cast<std::size_t>(0));
    CHECK_EQ(rs.chunk_size, static_cast<std::size_t>(0));
    CHECK(!rs.step_send_done);
    CHECK(!rs.step_recv_done);
    CHECK(rs.op == EpSyncOp::AllReduce);
}

// ============================================================================
// 测试 10: RHEngine 拓扑一致性（partner = rank XOR (1<<s)）
// ============================================================================
static void test_rh_engine_topology() {
    std::printf("[test] RHEngine topology consistency...\n");

    // N=4, log₂N=2
    // rank 0: partners at step 0 = 0^1=1, step 1 = 0^2=2
    // rank 1: partners at step 0 = 1^1=0, step 1 = 1^2=3
    // rank 2: partners at step 0 = 2^1=3, step 1 = 2^2=0
    // rank 3: partners at step 0 = 3^1=2, step 1 = 3^2=1

    for (std::size_t rank = 0; rank < 4; ++rank) {
        auto s0 = RHEngine::reduce_scatter_step(rank, 0, 4, 32);
        auto s1 = RHEngine::reduce_scatter_step(rank, 1, 4, 32);
        CHECK(s0.valid);
        CHECK(s1.valid);
        CHECK_EQ(s0.partner_rank, rank ^ 1);
        CHECK_EQ(s1.partner_rank, rank ^ 2);
    }

    // AllGather partners (reverse of ReduceScatter)
    for (std::size_t rank = 0; rank < 4; ++rank) {
        auto ag0 = RHEngine::all_gather_step(rank, 0, 4, 32);
        auto ag1 = RHEngine::all_gather_step(rank, 1, 4, 32);
        // AllGather step 0 → rev_step = log₂N-1-0 = 1 → partner = rank^2
        // AllGather step 1 → rev_step = log₂N-1-1 = 0 → partner = rank^1
        CHECK_EQ(ag0.partner_rank, rank ^ 2);
        CHECK_EQ(ag1.partner_rank, rank ^ 1);
    }
}

// ============================================================================
// 测试 11: 多次调用不产生会话累积
// ============================================================================
static void test_no_session_accumulation_rh() {
    std::printf("[test] multiple RH calls no session accumulation...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});

    for (int i = 0; i < 5; ++i) {
        auto result = sync.all_reduce(8210 + i, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(200), 2);
        CHECK(!result.has_value());
    }
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 12: all_reduce algo=RH session 生命周期（null-channel partner）
// ============================================================================
static void test_all_reduce_rh_session_lifecycle() {
    std::printf("[test] all_reduce algo=RH session lifecycle (null-channel)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({50, 60});
    auto t0 = std::chrono::steady_clock::now();
    auto result = sync.all_reduce(8220, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(300), 2);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();

    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
    // 应快速返回（send 失败是同步的）
    CHECK(elapsed < 200);
}

// ============================================================================
// 测试 13: all_reduce algo=0 (Ring) 跳过 RH 路径
// ============================================================================
static void test_all_reduce_ring_skips_rh() {
    std::printf("[test] all_reduce algo=0 (Ring) skips RH path...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});
    // algo=0 (Ring) → 不进入 RH 分派
    auto result = sync.all_reduce(8221, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(300), 0);
    CHECK(!result.has_value());
    // Ring: ring peers 未配置（只有 RH peers） → return false
    // 简化版: channel_ 无效 → nullopt
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 14: all_reduce algo=1 (Tree) 跳过 RH 路径
// ============================================================================
static void test_all_reduce_tree_skips_rh() {
    std::printf("[test] all_reduce algo=1 (Tree) skips RH path...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});
    // algo=1 (Tree) → 不进入 RH 分派
    // all_reduce 没有 Tree 路径（Tree 仅用于 Broadcast/AllGather）
    auto result = sync.all_reduce(8222, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(300), 1);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 15: reduce_scatter algo=RH N=1 → RH 拒绝
// ============================================================================
static void test_reduce_scatter_rh_n1() {
    std::printf("[test] reduce_scatter algo=RH N=1 (single node)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);
    auto data = make_u64({5});
    auto result = sync.reduce_scatter(8230, 0b0001, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(500), 2);
    CHECK(!result.has_value());
}

// ============================================================================
// 测试 16: reduce_scatter algo=RH N=3（非 2 的幂）→ RH 拒绝
// ============================================================================
static void test_reduce_scatter_rh_not_power_of_two() {
    std::printf("[test] reduce_scatter algo=RH N=3 (not power of two)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    sync.set_rh_peers({{0x02, &peer_ch}, {0x04, &peer_ch}});

    auto data = make_u64({10, 20, 30});  // 24 字节, N=3, 24%3=0 可整除
    auto result = sync.reduce_scatter(8231, 0b0111, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(500), 2);
    CHECK(!result.has_value());
}

// ============================================================================
// 测试 17: reduce_scatter algo=RH 无 partner → RH 拒绝
// ============================================================================
static void test_reduce_scatter_rh_no_partner() {
    std::printf("[test] reduce_scatter algo=RH no partner (degrade)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto data = make_u64({10, 20});
    auto result = sync.reduce_scatter(8232, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(500), 2);
    CHECK(!result.has_value());
}

// ============================================================================
// 测试 18: reduce_scatter algo=RH + null-channel partner → send 失败降级
// ============================================================================
static void test_reduce_scatter_rh_null_partner_degrade() {
    std::printf("[test] reduce_scatter algo=RH null-channel partner (degrade)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({10, 20});
    auto result = sync.reduce_scatter(8233, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(300), 2);
    CHECK(!result.has_value());
}

// ============================================================================
// 测试 19: reduce_scatter algo=0 (Ring) 跳过 RH
// ============================================================================
static void test_reduce_scatter_ring_skips_rh() {
    std::printf("[test] reduce_scatter algo=0 (Ring) skips RH...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({10, 20});
    auto result = sync.reduce_scatter(8234, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(300), 0);
    CHECK(!result.has_value());
}

// ============================================================================
// 测试 20: N=4 all_reduce algo=RH null-channel partners → send 失败降级
// ============================================================================
static void test_all_reduce_rh_n4_null_partners() {
    std::printf("[test] all_reduce algo=RH N=4 null-channel partners...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=4: self=bit0, partners=bit1(0x02), bit2(0x04)
    sync.set_rh_peers({{0x02, &null_ch}, {0x04, &null_ch}});

    // N=4, data=32 字节（4 个 u64），32%4=8 可整除
    auto data = make_u64({1, 2, 3, 4});
    auto result = sync.all_reduce(8240, 0b1111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(300), 2);
    // RH: partners 已配置 → 创建 session → send step 0 失败 → 擦除 → false
    // 简化版: channel_ 无效 → nullopt
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 21: N=4 partner channel 部分缺失 → RH 拒绝
// ============================================================================
static void test_all_reduce_rh_n4_partial_partners() {
    std::printf("[test] all_reduce algo=RH N=4 partial partners (missing)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=4 需要 2 个 partner: bit1(0x02), bit2(0x04)
    // 只配置 bit1，缺 bit2 → RH 拒绝
    sync.set_rh_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2, 3, 4});
    auto result = sync.all_reduce(8241, 0b1111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 2);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::printf("=== RhDriver (P4-E RH Engine Guard & Degradation) Unit Tests ===\n\n");

    test_all_reduce_rh_n1();
    test_all_reduce_rh_not_power_of_two();
    test_all_reduce_rh_not_divisible();
    test_all_reduce_rh_no_partner();
    test_all_reduce_rh_null_partner_degrade();
    test_self_not_in_mask_rh();
    test_set_rh_peers_injection();
    test_clear_then_rh_guard();
    test_rh_algo_state_defaults();
    test_rh_engine_topology();
    test_no_session_accumulation_rh();
    test_all_reduce_rh_session_lifecycle();
    test_all_reduce_ring_skips_rh();
    test_all_reduce_tree_skips_rh();
    test_reduce_scatter_rh_n1();
    test_reduce_scatter_rh_not_power_of_two();
    test_reduce_scatter_rh_no_partner();
    test_reduce_scatter_rh_null_partner_degrade();
    test_reduce_scatter_ring_skips_rh();
    test_all_reduce_rh_n4_null_partners();
    test_all_reduce_rh_n4_partial_partners();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
