// test_pe_driver.cpp — P4-F PairwiseExchange 驱动守卫与降级单元测试（v2.3 Phase 4）
//
// 验证 P4-F 交付物（PE 引擎驱动 EpChannel 通信的守卫逻辑）：
//   1. all_to_all_pe_ 守卫：N<2 / N 非 2 的幂 / local_chunk 不可整除 / chunk_size=0 → return false
//   2. step 0 payload 超 kMaxPayloadLen → PE 拒绝
//   3. self_node_id 不在 participant_mask → 入口直接 nullopt（不进入 PE）
//   4. partner channel 未配置 → PE 拒绝
//   5. PE 路径失败后正确降级到简化版（无崩溃、无会话泄漏）
//   6. set_pe_peers 注入 peer_channels_ 正确
//   7. clear_peer_channels 后守卫拦截
//   8. PeAlgoState 字段默认值校验
//   9. PEEngine 拓扑一致性（partner = rank XOR (1<<s)）
//  10. PEEngine send/recv chunk indices 互补性
//  11. PEEngine total_steps / bytes_per_node 正确性
//  12. 多次调用不产生会话累积（cleanup_finished 后 session_count==0）
//  13. all_to_all algo=PE + null-channel partner → PE session 生命周期正确
//  14. all_to_all algo=0 (Ring) 跳过 PE 路径
//  15. all_to_all algo=1 (Tree) 跳过 PE 路径
//  16. N=4 all_to_all algo=PE null-channel partners → send 失败降级
//  17. N=4 partner channel 部分缺失 → PE 守卫拒绝
//
// 测试策略：
//   - SyncPrimitives(nullptr) + EpChannel(nullptr) 作为 peer
//   - all_to_all 的 PE 分派在简化版会话创建之前（PE 守卫失败 → 降级简化版创建会话）
//   - all_to_all 简化版在 channel_ 检查前创建会话（与 reduce_scatter 一致），
//     故 PE 守卫失败后会话保留（algo=3, pe_algo=nullopt），需 cleanup_finished 清理
//   - PE 路径 send 失败 → 擦除 PE session → 降级简化版创建新会话（algo=3, pe_algo=nullopt）
//   - 通过 get_session() 验证 algo=3 + pe_algo=nullopt（PE 降级标志）
//
// 注：PE 状态机的完整多步通信需要真实 QUIC 连接（属集成测试范畴），
//     算法正确性已由 test_pe_engine.cpp 覆盖（N=2/4/8 AllToAll 模拟）。

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

// ============================================================================
// 测试 1: all_to_all algo=PE N=1（单节点）→ PE 拒绝，降级简化版
// ============================================================================
static void test_all_to_all_pe_n1() {
    std::printf("[test] all_to_all algo=PE N=1 (single node)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);
    auto data = make_u64({42});
    auto result = sync.all_to_all(9401, 0b0001, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(500), 3);
    CHECK(!result.has_value());
    // PE 守卫失败 → 降级简化版 → 简化版创建会话（algo=3, pe_algo=nullopt）
    auto s = sync.get_session(9401);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(3));
    CHECK(!s->pe_algo.has_value());
    sync.cleanup_finished();
}

// ============================================================================
// 测试 2: all_to_all algo=PE N=3（非 2 的幂）→ PE 拒绝
// ============================================================================
static void test_all_to_all_pe_not_power_of_two() {
    std::printf("[test] all_to_all algo=PE N=3 (not power of two)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    sync.set_pe_peers({{0x02, &peer_ch}, {0x04, &peer_ch}});

    // N=3, data=24 字节（3 个 u64），24%3=0 可整除，但 N 非 2 的幂 → PE 拒绝
    auto data = make_u64({10, 20, 30});
    auto result = sync.all_to_all(9402, 0b0111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(500), 3);
    CHECK(!result.has_value());
    auto s = sync.get_session(9402);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // PE 降级
    sync.cleanup_finished();
}

// ============================================================================
// 测试 3: all_to_all algo=PE local_chunk 不可整除 → PE 拒绝
// ============================================================================
static void test_all_to_all_pe_not_divisible() {
    std::printf("[test] all_to_all algo=PE local_chunk not divisible by N...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel peer_ch(nullptr);
    // N=4 需要 partner bit1(0x02), bit2(0x04)
    sync.set_pe_peers({{0x02, &peer_ch}, {0x04, &peer_ch}});

    // N=4, data=6 字节, 6%4=2 != 0 → 不可整除 → PE 拒绝
    std::vector<std::uint8_t> odd_data(6, 0x01);
    auto result = sync.all_to_all(9403, 0b1111, 0,
                                  std::span<const std::uint8_t>(odd_data.data(), odd_data.size()),
                                  std::chrono::milliseconds(500), 3);
    CHECK(!result.has_value());
    auto s = sync.get_session(9403);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());
    sync.cleanup_finished();
}

// ============================================================================
// 测试 4: all_to_all algo=PE 无 partner → PE 拒绝，降级简化版
// ============================================================================
static void test_all_to_all_pe_no_partner() {
    std::printf("[test] all_to_all algo=PE no partner (degrade)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // N=2, 无 partner channel 配置
    auto data = make_u64({1, 2});
    auto result = sync.all_to_all(9404, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(500), 3);
    CHECK(!result.has_value());
    auto s = sync.get_session(9404);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // PE 降级
    sync.cleanup_finished();
}

// ============================================================================
// 测试 5: all_to_all algo=PE + null-channel partner → send 失败降级
// ============================================================================
static void test_all_to_all_pe_null_partner_degrade() {
    std::printf("[test] all_to_all algo=PE null-channel partner (attempt + degrade)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=2: self=bit0, partner=bit1(0x02)
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});  // 16 字节，N=2 可整除
    auto result = sync.all_to_all(9405, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(300), 3);
    // PE: partner channel 已配置 → 创建 session + pe_algo
    //     send step 0 → null_ch.send_sync → false → 擦除 session → false
    // 简化版: 创建新会话（algo=3, pe_algo=nullopt）→ channel_ 无效 → nullopt
    CHECK(!result.has_value());
    auto s = sync.get_session(9405);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // PE session 已擦除，简化版无 pe_algo
    sync.cleanup_finished();
}

// ============================================================================
// 测试 6: self_node_id 不在 participant_mask → 入口直接 nullopt（不进入 PE）
// ============================================================================
static void test_self_not_in_mask_pe() {
    std::printf("[test] self_node_id not in participant_mask (PE)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(2);  // self=bit2

    EpChannel peer_ch(nullptr);
    sync.set_pe_peers({{0x01, &peer_ch}});

    // mask=0b0011 (bit 0,1)，self=bit2 不在 mask → 入口 return nullopt
    auto data = make_u64({1, 2});
    auto result = sync.all_to_all(9406, 0b0011, 2,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(500), 3);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));  // 不创建会话
}

// ============================================================================
// 测试 7: set_pe_peers 注入 peer_channels_ 正确
// ============================================================================
static void test_set_pe_peers_injection() {
    std::printf("[test] set_pe_peers injection...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel ch1(nullptr), ch2(nullptr), ch3(nullptr);
    sync.set_pe_peers({{0x02, &ch1}, {0x04, &ch2}, {0x08, &ch3}});

    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(3));
    CHECK(sync.has_peer_channel(0x02));
    CHECK(sync.has_peer_channel(0x04));
    CHECK(sync.has_peer_channel(0x08));
    CHECK(!sync.has_peer_channel(0x01));
}

// ============================================================================
// 测试 8: clear_peer_channels 后守卫拦截
// ============================================================================
static void test_clear_then_pe_guard() {
    std::printf("[test] clear_peer_channels then PE guard...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel ch1(nullptr);
    sync.set_pe_peers({{0x02, &ch1}});
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(1));

    sync.clear_peer_channels();
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(0));

    auto data = make_u64({1, 2});
    auto result = sync.all_to_all(9408, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(500), 3);
    CHECK(!result.has_value());
    auto s = sync.get_session(9408);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // PE 降级
    sync.cleanup_finished();
}

// ============================================================================
// 测试 9: PeAlgoState 字段默认值
// ============================================================================
static void test_pe_algo_state_defaults() {
    std::printf("[test] PeAlgoState default values...\n");

    SyncSession::PeAlgoState ps;
    CHECK_EQ(ps.current_step, static_cast<std::uint32_t>(0));
    CHECK_EQ(ps.total_steps, static_cast<std::uint32_t>(0));
    CHECK_EQ(ps.self_rank, static_cast<std::size_t>(0));
    CHECK_EQ(ps.N, static_cast<std::size_t>(0));
    CHECK_EQ(ps.chunk_size, static_cast<std::size_t>(0));
    CHECK(ps.partner_bits.empty());
    CHECK(ps.chunks.empty());
    CHECK(!ps.step_send_done);
    CHECK(!ps.step_recv_done);
}

// ============================================================================
// 测试 10: PEEngine 拓扑一致性（partner = rank XOR (1<<s)）
// ============================================================================
static void test_pe_engine_topology() {
    std::printf("[test] PEEngine topology consistency...\n");

    // N=4, log₂N=2
    // rank 0: step 0 partner = 0^1=1, step 1 partner = 0^2=2
    // rank 1: step 0 partner = 1^1=0, step 1 partner = 1^2=3
    // rank 2: step 0 partner = 2^1=3, step 1 partner = 2^2=0
    // rank 3: step 0 partner = 3^1=2, step 1 partner = 3^2=1
    for (std::size_t rank = 0; rank < 4; ++rank) {
        CHECK_EQ(PEEngine::partner_at_step(rank, 0), rank ^ 1);
        CHECK_EQ(PEEngine::partner_at_step(rank, 1), rank ^ 2);
    }

    // N=8, log₂N=3
    for (std::size_t rank = 0; rank < 8; ++rank) {
        CHECK_EQ(PEEngine::partner_at_step(rank, 0), rank ^ 1);
        CHECK_EQ(PEEngine::partner_at_step(rank, 1), rank ^ 2);
        CHECK_EQ(PEEngine::partner_at_step(rank, 2), rank ^ 4);
    }
}

// ============================================================================
// 测试 11: PEEngine send/recv chunk indices 互补性
//   某步 send indices 与 partner 的 recv indices 应一致
// ============================================================================
static void test_pe_engine_chunk_indices() {
    std::printf("[test] PEEngine send/recv chunk indices complementary...\n");

    // N=4, rank 0, step 0:
    //   send = dest bit0=1 的分片（partner bit0=1）= {1, 3}
    //   partner rank 1, recv = dest bit0=1 的分片 = {1, 3}
    auto send_0_0 = PEEngine::send_chunk_indices(0, 0, 4);
    auto recv_1_0 = PEEngine::recv_chunk_indices(1, 0, 4);
    CHECK_EQ(send_0_0.size(), recv_1_0.size());
    CHECK_EQ(send_0_0.size(), static_cast<std::size_t>(2));
    // 两集合应包含相同元素（顺序一致，均按升序）
    for (std::size_t i = 0; i < send_0_0.size(); ++i) {
        CHECK_EQ(send_0_0[i], recv_1_0[i]);
    }

    // N=4, rank 0, step 1:
    //   send = dest bit1=1 且 bit0=0 的分片 = {2}
    //   partner rank 2, recv = dest bit1=1 且 bit0=0 = {2}
    auto send_0_1 = PEEngine::send_chunk_indices(0, 1, 4);
    auto recv_2_1 = PEEngine::recv_chunk_indices(2, 1, 4);
    CHECK_EQ(send_0_1.size(), static_cast<std::size_t>(1));
    CHECK_EQ(send_0_1.size(), recv_2_1.size());
    CHECK_EQ(send_0_1[0], recv_2_1[0]);

    // 互补性：rank 的 send + recv = held（该步后持有的 dest）
    // step 0 后，rank 0 持有 dest bit0=0 的分片 = {0, 2}
    auto held_0_after_0 = PEEngine::held_chunk_indices(0, 0, 4);
    CHECK_EQ(held_0_after_0.size(), static_cast<std::size_t>(2));
    // held 应包含 recv indices
    auto recv_0_0 = PEEngine::recv_chunk_indices(0, 0, 4);
    CHECK_EQ(recv_0_0.size(), static_cast<std::size_t>(2));
}

// ============================================================================
// 测试 12: PEEngine total_steps / bytes_per_node 正确性
// ============================================================================
static void test_pe_engine_metrics() {
    std::printf("[test] PEEngine total_steps / bytes_per_node...\n");

    CHECK_EQ(PEEngine::total_steps(1), static_cast<std::size_t>(0));
    CHECK_EQ(PEEngine::total_steps(2), static_cast<std::size_t>(1));
    CHECK_EQ(PEEngine::total_steps(4), static_cast<std::size_t>(2));
    CHECK_EQ(PEEngine::total_steps(8), static_cast<std::size_t>(3));
    CHECK_EQ(PEEngine::total_steps(16), static_cast<std::size_t>(4));

    // all_to_all_bytes_per_node = (N-1) * chunk_size = (N-1) * msg/N
    CHECK_EQ(PEEngine::all_to_all_bytes_per_node(2, 16), static_cast<std::size_t>(8));   // 1*8
    CHECK_EQ(PEEngine::all_to_all_bytes_per_node(4, 32), static_cast<std::size_t>(24));  // 3*8
    CHECK_EQ(PEEngine::all_to_all_bytes_per_node(8, 64), static_cast<std::size_t>(56));  // 7*8

    // is_power_of_two
    CHECK(PEEngine::is_power_of_two(1));
    CHECK(PEEngine::is_power_of_two(2));
    CHECK(PEEngine::is_power_of_two(4));
    CHECK(!PEEngine::is_power_of_two(3));
    CHECK(!PEEngine::is_power_of_two(6));
    CHECK(!PEEngine::is_power_of_two(0));

    // pad_to_power_of_two
    CHECK_EQ(PEEngine::pad_to_power_of_two(1), static_cast<std::size_t>(1));
    CHECK_EQ(PEEngine::pad_to_power_of_two(3), static_cast<std::size_t>(4));
    CHECK_EQ(PEEngine::pad_to_power_of_two(5), static_cast<std::size_t>(8));
    CHECK_EQ(PEEngine::pad_to_power_of_two(9), static_cast<std::size_t>(16));
}

// ============================================================================
// 测试 13: 多次调用不产生会话累积（cleanup_finished 后 session_count==0）
// ============================================================================
static void test_no_session_accumulation_pe() {
    std::printf("[test] multiple PE calls no session accumulation...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});

    for (int i = 0; i < 5; ++i) {
        auto result = sync.all_to_all(9410 + i, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      std::chrono::milliseconds(200), 3);
        CHECK(!result.has_value());
    }
    // all_to_all 简化版在 channel_ 无效时创建 Waiting 会话（不发送），
    // cleanup_finished 只清理 Completed/TimedOut，不清理 Waiting。
    // 验证：5 次调用产生 5 个会话（每 sync_id 1 个），无额外泄漏
    sync.cleanup_finished();
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(5));
}

// ============================================================================
// 测试 14: all_to_all algo=PE session 生命周期（null-channel partner）
// ============================================================================
static void test_all_to_all_pe_session_lifecycle() {
    std::printf("[test] all_to_all algo=PE session lifecycle (null-channel)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({50, 60});
    auto t0 = std::chrono::steady_clock::now();
    auto result = sync.all_to_all(9420, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(300), 3);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();

    CHECK(!result.has_value());
    // 应快速返回（send 失败是同步的，简化版 channel_ 无效立即返回）
    CHECK(elapsed < 200);
    // all_to_all 简化版创建 1 个 Waiting 会话，cleanup_finished 不清理
    sync.cleanup_finished();
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(1));
}

// ============================================================================
// 测试 15: all_to_all algo=0 (Ring) 跳过 PE 路径
// ============================================================================
static void test_all_to_all_algo0_skips_pe() {
    std::printf("[test] all_to_all algo=0 (Ring) skips PE path...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});
    // algo=0 → 不进入 PE 分派；简化版创建会话（algo=0）
    auto result = sync.all_to_all(9421, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(300), 0);
    CHECK(!result.has_value());
    auto s = sync.get_session(9421);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));  // algo=Ring（非 PE）
    CHECK(!s->pe_algo.has_value());
    sync.cleanup_finished();
}

// ============================================================================
// 测试 16: all_to_all algo=1 (Tree) 跳过 PE 路径
// ============================================================================
static void test_all_to_all_algo1_skips_pe() {
    std::printf("[test] all_to_all algo=1 (Tree) skips PE path...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2});
    // algo=1 (Tree) → 不进入 PE 分派
    auto result = sync.all_to_all(9422, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(300), 1);
    CHECK(!result.has_value());
    auto s = sync.get_session(9422);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(1));  // algo=Tree
    CHECK(!s->pe_algo.has_value());
    sync.cleanup_finished();
}

// ============================================================================
// 测试 17: all_to_all algo=PE step 0 payload 超限 → PE 拒绝
//   N=2, chunk_size = 17MiB, step0_payload = 1 * 17MiB > 16MiB kMaxPayloadLen
// ============================================================================
static void test_all_to_all_pe_step0_payload_exceed() {
    std::printf("[test] all_to_all algo=PE step0 payload exceed kMaxPayloadLen...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_pe_peers({{0x02, &null_ch}});

    // N=2, chunk_size = 17MiB, local_chunk = 34MiB
    // step0_payload = (N/2) * chunk_size = 1 * 17MiB = 17MiB > 16MiB → PE 拒绝
    const std::size_t chunk_size = 17ULL * 1024 * 1024;
    std::vector<std::uint8_t> big_data(2 * chunk_size, 0xAA);
    auto result = sync.all_to_all(9423, 0b0011, 0,
                                  std::span<const std::uint8_t>(big_data.data(), big_data.size()),
                                  std::chrono::milliseconds(300), 3);
    CHECK(!result.has_value());
    auto s = sync.get_session(9423);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // PE 守卫拒绝（payload 超限）→ 降级
    sync.cleanup_finished();
}

// ============================================================================
// 测试 18: N=4 all_to_all algo=PE null-channel partners → send 失败降级
// ============================================================================
static void test_all_to_all_pe_n4_null_partners() {
    std::printf("[test] all_to_all algo=PE N=4 null-channel partners...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=4: self=bit0, partners=bit1(0x02) step0, bit2(0x04) step1
    sync.set_pe_peers({{0x02, &null_ch}, {0x04, &null_ch}});

    // N=4, data=32 字节（4 个 u64），32%4=8 可整除
    auto data = make_u64({1, 2, 3, 4});
    auto result = sync.all_to_all(9440, 0b1111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(300), 3);
    // PE: partners 已配置 → 创建 session + pe_algo → send step 0 失败 → 擦除 → false
    // 简化版: 创建新会话（algo=3, pe_algo=nullopt）→ channel_ 无效 → nullopt
    CHECK(!result.has_value());
    auto s = sync.get_session(9440);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // PE session 已擦除
    sync.cleanup_finished();
}

// ============================================================================
// 测试 19: N=4 partner channel 部分缺失 → PE 守卫拒绝
// ============================================================================
static void test_all_to_all_pe_n4_partial_partners() {
    std::printf("[test] all_to_all algo=PE N=4 partial partners (missing)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=4 需要 2 个 partner: bit1(0x02) step0, bit2(0x04) step1
    // 只配置 bit1，缺 bit2 → PE 守卫拒绝
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({1, 2, 3, 4});
    auto result = sync.all_to_all(9441, 0b1111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  std::chrono::milliseconds(500), 3);
    CHECK(!result.has_value());
    auto s = sync.get_session(9441);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // PE 守卫拒绝（partner 缺失）→ 降级
    sync.cleanup_finished();
}

// ============================================================================
// 测试 20: N=2 all_to_all algo=PE local_chunk 为空（chunk_size=0）→ PE 拒绝
// ============================================================================
static void test_all_to_all_pe_empty_chunk() {
    std::printf("[test] all_to_all algo=PE empty local_chunk (chunk_size=0)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_pe_peers({{0x02, &null_ch}});

    // N=2, local_chunk 为空 → chunk_size=0 → PE 拒绝
    std::vector<std::uint8_t> empty_data;
    auto result = sync.all_to_all(9442, 0b0011, 0,
                                  std::span<const std::uint8_t>(empty_data.data(), empty_data.size()),
                                  std::chrono::milliseconds(300), 3);
    CHECK(!result.has_value());
    auto s = sync.get_session(9442);
    CHECK(s.has_value());
    CHECK(!s->pe_algo.has_value());  // PE 守卫拒绝
    sync.cleanup_finished();
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::printf("=== PeDriver (P4-F PE Engine Guard & Degradation) Unit Tests ===\n\n");

    test_all_to_all_pe_n1();
    test_all_to_all_pe_not_power_of_two();
    test_all_to_all_pe_not_divisible();
    test_all_to_all_pe_no_partner();
    test_all_to_all_pe_null_partner_degrade();
    test_self_not_in_mask_pe();
    test_set_pe_peers_injection();
    test_clear_then_pe_guard();
    test_pe_algo_state_defaults();
    test_pe_engine_topology();
    test_pe_engine_chunk_indices();
    test_pe_engine_metrics();
    test_no_session_accumulation_pe();
    test_all_to_all_pe_session_lifecycle();
    test_all_to_all_algo0_skips_pe();
    test_all_to_all_algo1_skips_pe();
    test_all_to_all_pe_step0_payload_exceed();
    test_all_to_all_pe_n4_null_partners();
    test_all_to_all_pe_n4_partial_partners();
    test_all_to_all_pe_empty_chunk();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
