// test_algo_dispatch_ring.cpp — P4-G 算法分派单元测试（v2.3 Phase 4 / 方向 A）
//
// 验证 P4-G 交付物（handle_sync_frame 的 algo 路由逻辑）：
//   1. algo=0 (Ring) 路径：all_gather/reduce_scatter 在无 peers 时 Ring 降级到简化版
//   2. algo=1 (Tree) 路径：跳过 Ring 分派，直接走简化版
//   3. 被动会话分派：handle_sync_frame 注入帧时，会话不存在 → use_ring=false → 简化版
//   4. 已存在会话分派：会话存在但 ring_algo=nullopt → use_ring=false → 简化版
//   5. 混合 algo 会话独立：不同 sync_id 用不同 algo 互不干扰
//   6. Ring 路径接管失败（send 失败）→ 会话擦除 → 简化版接管（无泄漏）
//   7. Signal/Barrier/未知 op 不参与 algo 分派
//
// 测试策略：
//   - SyncPrimitives(nullptr) 构造（channel_ 无效）
//   - all_gather/reduce_scatter 在 channel 无效时仍创建会话（self chunk 预置），
//     可通过 get_session 观察 algo 字段与 ring_algo 状态
//   - all_reduce 在 channel 无效时简化版不创建会话，用于验证无泄漏
//   - EpChannel(nullptr) 作为 peer channel（conn_ 无效，send_sync 返回 false），
//     触发 all_*_ring_ 的 step 0 发送失败 → 会话擦除 → 降级简化版
//   - 通过 handle_sync_frame 注入 EpSyncFrame 模拟被动接收，验证分派路由
//
// 注：Ring 状态机成功接管（ring_algo.has_value()==true 且多步通信完成）需要
//     真实 QUIC 连接，属集成测试范畴。算法正确性由 test_ring_engine.cpp 覆盖。
//     本测试聚焦于分派逻辑的可观察行为：algo 字段记录、降级路径、无泄漏。

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

/// 构造 AllReduce 帧（用于 handle_sync_frame 注入）
static EpSyncFrame make_ar_frame(std::uint64_t sync_id,
                                  std::uint64_t from_bit,
                                  std::uint64_t participant_mask,
                                  const std::vector<std::uint8_t> &payload,
                                  std::uint8_t algo,
                                  std::uint16_t step = 0) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::AllReduce;
    frame.algo = algo;
    frame.participant_mask = participant_mask;
    frame.reduce_op = static_cast<std::uint8_t>(ReduceOp::SUM);
    frame.shard_idx = 0;
    frame.total_shards = 1;
    frame.payload = payload;
    frame.from_node_id = from_bit;
    frame.step = step;
    return frame;
}

/// 构造 AllGather 帧（用于 handle_sync_frame 注入）
static EpSyncFrame make_ag_frame(std::uint64_t sync_id,
                                  std::uint64_t from_bit,
                                  const std::vector<std::uint8_t> &payload,
                                  std::uint8_t algo,
                                  std::uint16_t step = 0) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::AllGather;
    frame.algo = algo;
    frame.participant_mask = from_bit;  // AllGather: participant_mask = 发送方 bit
    frame.shard_idx = 0;
    frame.total_shards = 1;
    frame.payload = payload;
    frame.from_node_id = from_bit;
    frame.step = step;
    return frame;
}

// ============================================================================
// 测试 1: all_gather algo=Ring 无 peers → Ring 降级，简化版创建会话（algo=0）
// ============================================================================
static void test_all_gather_algo_ring_degrades() {
    std::printf("[test] all_gather algo=Ring (no peers) degrades to simple...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // participant_mask=0b0011 (N=2), self=0, 无 peer_channels_ 配置
    // all_gather_ring_: peer_channels_.find(next) == end → return false
    // 降级简化版：创建会话（algo=0, ring_algo=nullopt），channel 无效 → nullopt
    auto chunk = make_u64({42});
    auto result = sync.all_gather(9001, 0b0011, 0,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());  // channel 无效

    auto s = sync.get_session(9001);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));  // algo=Ring 被记录
    CHECK(!s->ring_algo.has_value());  // Ring 降级，无 ring_algo 状态

    sync.cleanup_finished();
}

// ============================================================================
// 测试 2: all_gather algo=Tree (1) → 跳过 Ring，简化版创建会话（algo=1）
// ============================================================================
static void test_all_gather_algo_tree_skips_ring() {
    std::printf("[test] all_gather algo=Tree skips Ring dispatch...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto chunk = make_u64({42});
    auto result = sync.all_gather(9002, 0b0011, 0,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 1);  // algo=1 Tree
    CHECK(!result.has_value());

    auto s = sync.get_session(9002);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(1));  // algo=Tree 被记录
    CHECK(!s->ring_algo.has_value());  // 跳过 Ring，无 ring_algo

    sync.cleanup_finished();
}

// ============================================================================
// 测试 3: all_gather algo=Ring + null-channel peer → Ring send 失败 → 降级简化版
// ============================================================================
static void test_all_gather_algo_ring_send_fail_degrades() {
    std::printf("[test] all_gather algo=Ring (null-channel peer) send fail degrades...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // 配置 null-channel peer（conn_ 无效，send_sync 返回 false）
    EpChannel null_ch(nullptr);
    sync.set_ring_peers(0x02, &null_ch, 0x02, &null_ch);  // 2 节点环：next=prev=bit1

    auto chunk = make_u64({42});
    auto result = sync.all_gather(9003, 0b0011, 0,
                                  std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                                  std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());

    // Ring 创建会话后 send 失败 → 擦除 → 简化版重建会话（algo=0, ring_algo=nullopt）
    auto s = sync.get_session(9003);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));
    CHECK(!s->ring_algo.has_value());  // Ring 接管失败，简化版接管

    sync.cleanup_finished();
}

// ============================================================================
// 测试 4: reduce_scatter algo=Ring 无 peers → Ring 降级，简化版创建会话（algo=0）
// ============================================================================
static void test_reduce_scatter_algo_ring_degrades() {
    std::printf("[test] reduce_scatter algo=Ring (no peers) degrades...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // N=2, data=16 字节（2 个 u64），16/2=8 可整除
    auto data = make_u64({10, 20});
    auto result = sync.reduce_scatter(9004, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());

    auto s = sync.get_session(9004);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));
    CHECK(!s->ring_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 5: reduce_scatter algo=Tree → 跳过 Ring，简化版创建会话（algo=1）
// ============================================================================
static void test_reduce_scatter_algo_tree_skips_ring() {
    std::printf("[test] reduce_scatter algo=Tree skips Ring...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto data = make_u64({10, 20});
    auto result = sync.reduce_scatter(9005, 0b0011, 0,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      ReduceOp::SUM, ReduceDType::U64,
                                      std::chrono::milliseconds(500), 1);
    CHECK(!result.has_value());

    auto s = sync.get_session(9005);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(1));
    CHECK(!s->ring_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 6: all_reduce algo=Ring 无 peers → Ring 降级 → 简化版 channel 无效 → 无泄漏
// ============================================================================
static void test_all_reduce_algo_ring_no_leak() {
    std::printf("[test] all_reduce algo=Ring (no peers) no session leak...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // all_reduce 简化版在 channel 无效时不创建会话
    auto data = make_u64({1, 2});  // N=2 可整除
    auto result = sync.all_reduce(9006, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));  // 无泄漏
}

// ============================================================================
// 测试 7: all_reduce algo=Tree → 跳过 Ring → 简化版 channel 无效 → 无泄漏
// ============================================================================
static void test_all_reduce_algo_tree_no_leak() {
    std::printf("[test] all_reduce algo=Tree no session leak...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto data = make_u64({1, 2});
    auto result = sync.all_reduce(9007, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 1);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 8: 被动 AllReduce 帧（algo=Ring, from_node_id, step）→ 会话不存在 → 简化版
// ============================================================================
static void test_passive_all_reduce_routes_simple() {
    std::printf("[test] passive AllReduce frame (no session) routes to simple handler...\n");

    SyncPrimitives sync(nullptr);

    // 注入 Ring 帧（algo=0, from_node_id=0x02, step=1）
    // 会话不存在 → use_ring=false → 简化版创建被动会话
    auto payload = make_u64({100});
    sync.handle_sync_frame(make_ar_frame(9008, 0x02, 0b0111, payload, 0, 1));

    auto s = sync.get_session(9008);
    CHECK(s.has_value());  // 简化版创建了被动会话
    CHECK(!s->ring_algo.has_value());  // 被动会话无 ring_algo（无法重建 Ring 状态机）
    // 简化版处理：arrived_mask |= frame.participant_mask
    CHECK_EQ(s->arrived_mask, 0b0111ULL);

    sync.cleanup_finished();
}

// ============================================================================
// 测试 9: 被动 AllGather 帧（algo=Ring, step）→ 会话不存在 → 简化版
// ============================================================================
static void test_passive_all_gather_routes_simple() {
    std::printf("[test] passive AllGather frame (no session) routes to simple handler...\n");

    SyncPrimitives sync(nullptr);

    auto payload = make_u64({200});
    sync.handle_sync_frame(make_ag_frame(9009, 0x02, payload, 0, 1));

    auto s = sync.get_session(9009);
    CHECK(s.has_value());
    CHECK(!s->ring_algo.has_value());
    // AllGather 简化版：arrived_mask |= 发送方 bit
    CHECK_EQ(s->arrived_mask, 0x02ULL);

    sync.cleanup_finished();
}

// ============================================================================
// 测试 10: 已存在会话（algo=Tree, ring_algo=nullopt）→ 注入 Ring 帧 → 仍走简化版
// ============================================================================
static void test_existing_session_no_ring_algo_routes_simple() {
    std::printf("[test] existing session (no ring_algo) routes Ring frame to simple...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // 先 all_gather(algo=1) 创建会话（algo=1, ring_algo=nullopt）
    auto self_chunk = make_u64({42});
    auto result = sync.all_gather(9010, 0b0011, 0,
                                  std::span<const std::uint8_t>(self_chunk.data(), self_chunk.size()),
                                  std::chrono::milliseconds(500), 1);
    CHECK(!result.has_value());

    {
        auto s = sync.get_session(9010);
        CHECK(s.has_value());
        CHECK_EQ(s->algo, static_cast<std::uint8_t>(1));
        CHECK(!s->ring_algo.has_value());
        CHECK_EQ(s->arrived_mask, 0b0001ULL);  // 仅 self
    }

    // 注入 Ring 帧（algo=0, from_node_id=0x02, step=1）到同一 sync_id
    // 会话存在但 ring_algo=nullopt → use_ring=false → 简化版处理器
    auto node1_chunk = make_u64({99});
    sync.handle_sync_frame(make_ag_frame(9010, 0x02, node1_chunk, 0, 1));

    {
        auto s = sync.get_session(9010);
        CHECK(s.has_value());
        CHECK(!s->ring_algo.has_value());  // 仍无 ring_algo（简化版处理）
        CHECK_EQ(s->arrived_mask, 0b0011ULL);  // self + node1 到齐
        // 2 节点全部到齐 → Completed
        CHECK_EQ(s->state, SyncState::Completed);
    }

    sync.cleanup_finished();
}

// ============================================================================
// 测试 11: 混合 algo 会话独立（sync_id=A algo=0, sync_id=B algo=1）
// ============================================================================
static void test_mixed_algo_sessions_independent() {
    std::printf("[test] mixed algo sessions independent...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto chunk = make_u64({42});

    // sync_id=A: all_gather algo=0 (Ring 降级)
    sync.all_gather(9100, 0b0011, 0,
                    std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                    std::chrono::milliseconds(500), 0);
    // sync_id=B: all_gather algo=1 (Tree)
    sync.all_gather(9101, 0b0011, 0,
                    std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                    std::chrono::milliseconds(500), 1);

    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(2));

    auto sa = sync.get_session(9100);
    auto sb = sync.get_session(9101);
    CHECK(sa.has_value());
    CHECK(sb.has_value());
    CHECK_EQ(sa->algo, static_cast<std::uint8_t>(0));  // A: Ring
    CHECK_EQ(sb->algo, static_cast<std::uint8_t>(1));  // B: Tree
    CHECK(!sa->ring_algo.has_value());
    CHECK(!sb->ring_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 12: Signal 帧不参与 algo 分派（正常处理）
// ============================================================================
static void test_signal_ignores_algo_routing() {
    std::printf("[test] Signal frame ignores algo routing...\n");

    SyncPrimitives sync(nullptr);

    // Signal 帧不触发 algo 分派逻辑（use_ring 仅对 AllReduce/AllGather/ReduceScatter 判定）
    EpSyncFrame frame;
    frame.sync_id = 9200;
    frame.sync_op = EpSyncOp::Signal;
    frame.algo = 0;  // 即使 algo=Ring，Signal 也不走 Ring 处理器
    frame.participant_mask = 0b0001;
    frame.from_node_id = 0x02;
    frame.step = 5;

    // 不应崩溃，Signal 走 handle_signal_
    sync.handle_sync_frame(frame);

    // Signal 不创建会话（仅通知），session_count 应为 0
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));

    sync.cleanup_finished();
}

// ============================================================================
// 测试 13: Barrier 帧不参与 algo 分派（正常处理）
// ============================================================================
static void test_barrier_ignores_algo_routing() {
    std::printf("[test] Barrier frame ignores algo routing...\n");

    SyncPrimitives sync(nullptr);

    EpSyncFrame frame;
    frame.sync_id = 9201;
    frame.sync_op = EpSyncOp::Barrier;
    frame.algo = 0;  // Barrier 不走 Ring 分派
    frame.participant_mask = 0b0011;
    frame.from_node_id = 0x02;
    frame.step = 0;

    sync.handle_sync_frame(frame);  // 不应崩溃

    // Barrier 简化版会创建被动会话（等待 release）
    auto s = sync.get_session(9201);
    CHECK(s.has_value());
    CHECK(!s->ring_algo.has_value());  // Barrier 无 ring_algo

    sync.cleanup_finished();
}

// ============================================================================
// 测试 14: 未知 sync_op 被忽略（不创建会话，不崩溃）
// ============================================================================
static void test_unknown_op_ignored() {
    std::printf("[test] unknown sync_op ignored...\n");

    SyncPrimitives sync(nullptr);

    EpSyncFrame frame;
    frame.sync_id = 9202;
    frame.sync_op = static_cast<EpSyncOp>(255);  // 未知 op
    frame.algo = 0;
    frame.participant_mask = 0b0011;
    frame.from_node_id = 0x02;
    frame.step = 1;

    sync.handle_sync_frame(frame);  // default 分支：忽略

    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));  // 无会话创建

    sync.cleanup_finished();
}

// ============================================================================
// 测试 15: all_reduce algo=Ring + null-channel peer → Ring send 失败 → 无泄漏
// ============================================================================
static void test_all_reduce_algo_ring_send_fail_no_leak() {
    std::printf("[test] all_reduce algo=Ring (null-channel peer) send fail no leak...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // 配置 null-channel peer
    EpChannel null_ch(nullptr);
    sync.set_ring_peers(0x02, &null_ch, 0x02, &null_ch);

    // all_reduce_ring_: 守卫通过，创建会话（含 ring_algo），send 失败 → 擦除会话 → return false
    // 降级简化版：channel 无效 → nullopt（不创建会话）
    auto data = make_u64({1, 2});  // N=2, 16 字节可整除
    auto result = sync.all_reduce(9203, 0b0011, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(500), 0);
    CHECK(!result.has_value());
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));  // Ring 擦除 + 简化版未创建 = 无泄漏
}

// ============================================================================
// 测试 16: 连续多次 algo=Ring 调用不产生会话累积（每次都降级清理）
// ============================================================================
static void test_repeated_ring_calls_no_accumulation() {
    std::printf("[test] repeated algo=Ring calls no session accumulation...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    auto chunk = make_u64({42});

    // 连续 5 次 all_gather algo=Ring（不同 sync_id），每次都降级简化版创建会话
    for (std::uint64_t sid = 9300; sid < 9305; ++sid) {
        sync.all_gather(sid, 0b0011, 0,
                        std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                        std::chrono::milliseconds(500), 0);
    }

    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(5));  // 5 个独立会话
    // 全部应为 algo=0, ring_algo=nullopt
    for (std::uint64_t sid = 9300; sid < 9305; ++sid) {
        auto s = sync.get_session(sid);
        CHECK(s.has_value());
        CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));
        CHECK(!s->ring_algo.has_value());
    }
    // 注：会话状态为 Waiting（deadline 未到），cleanup_finished 不清理；
    //     会话随 SyncPrimitives 析构自动释放，无跨测试泄漏
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== test_algo_dispatch_ring (P4-G Direction A) ===\n\n");

    test_all_gather_algo_ring_degrades();
    test_all_gather_algo_tree_skips_ring();
    test_all_gather_algo_ring_send_fail_degrades();
    test_reduce_scatter_algo_ring_degrades();
    test_reduce_scatter_algo_tree_skips_ring();
    test_all_reduce_algo_ring_no_leak();
    test_all_reduce_algo_tree_no_leak();
    test_passive_all_reduce_routes_simple();
    test_passive_all_gather_routes_simple();
    test_existing_session_no_ring_algo_routes_simple();
    test_mixed_algo_sessions_independent();
    test_signal_ignores_algo_routing();
    test_barrier_ignores_algo_routing();
    test_unknown_op_ignored();
    test_all_reduce_algo_ring_send_fail_no_leak();
    test_repeated_ring_calls_no_accumulation();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
