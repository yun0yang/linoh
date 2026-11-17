// test_phase4_e2e.cpp — P4-H 端到端集成测试（v2.3 Phase 4 / 方向 H）
//
// 验证 P4-H 交付物（Ring/Tree/RH/PE 四算法引擎端到端协同）：
//   1. 算法选择矩阵：CommPlannerV2::select_algo 输出与预期算法一致
//   2. 四算法混合会话独立：同一 SyncPrimitives 实例，4 个 sync_id 用 algo=0/1/2/3
//   3. 多 EpChannel 路由协同：set_ring_peers + set_tree_peers + set_rh_peers + set_pe_peers 共享 peer_channels_
//   4. 跨算法降级链：四种算法 null-channel → 降级简化版（algo_state=nullopt）
//   5. EpSyncFrame v3 字段传递：from_node_id/step 编解码保持
//   6. 被动会话跨算法：注入四种 algo 帧 → 简化版创建被动会话
//   7. 算法守卫矩阵 N<2：所有算法拒绝
//   8. 算法守卫矩阵 非 2 的幂：RH/PE 拒绝
//   9. 算法守卫矩阵 不可整除：Ring/RH/PE 拒绝
//  10. 算法引擎拓扑一致性：Ring/Tree/RH/PE 步数与伙伴计算
//  11. 会话生命周期无泄漏：多 sync_id 并发、cleanup_finished、无额外泄漏
//  12. EpSyncFrame v3 向后兼容：from_node_id=0/step=0 条件编码
//
// 测试策略：
//   - SyncPrimitives(nullptr) 构造（channel_ 无效）
//   - EpChannel(nullptr) 作为 peer channel（conn_ 无效，send_sync 返回 false）
//   - 简化版在 channel_ 检查前创建 Waiting 会话，cleanup_finished 不清理 Waiting
//   - 算法路径守卫失败/发送失败 → 降级简化版创建会话（algo_state=nullopt）
//   - 通过 get_session() 验证 algo 字段 + algo_state.has_value()（降级标志）
//   - 通过 encode_sync_frame/decode_sync_frame 验证 v3 字段
//   - 通过 CommPlannerV2::select_algo 验证算法选择矩阵
//
// 注：算法状态机的完整多步通信需要真实 QUIC 连接（属集成测试范畴），
//     算法正确性已由 test_ring/tree/rh/pe_engine.cpp 覆盖。
//     本测试聚焦于端到端协同：四算法共存、降级链、会话独立、帧兼容。

#include "linoh/multimodal/sync_primitives.hpp"
#include "linoh/multimodal/ep_channel.hpp"
#include "linoh/multimodal/ep_frames.hpp"
#include "linoh/multimodal/ring_engine.hpp"
#include "linoh/multimodal/tree_engine.hpp"
#include "linoh/multimodal/rh_engine.hpp"
#include "linoh/multimodal/pe_engine.hpp"
#include "linoh/multimodal/comm_planner_v2.hpp"
#include "linoh/multimodal/collective.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <vector>

using namespace linoh::multimodal::ep;
// CommPlannerV2 / CollectiveOp / CollectiveAlgo 均位于 linoh::multimodal::ep 命名空间，
// 上方 using namespace 已引入，无需额外 using 声明。

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

/// 构造通用 SYNC 帧（用于 handle_sync_frame 注入）
static EpSyncFrame make_sync_frame(std::uint64_t sync_id,
                                   EpSyncOp op,
                                   std::uint8_t algo,
                                   std::uint64_t from_bit,
                                   std::uint64_t participant_mask,
                                   const std::vector<std::uint8_t> &payload,
                                   std::uint16_t step = 0) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = op;
    frame.algo = algo;
    frame.participant_mask = participant_mask;
    frame.shard_idx = 0;
    frame.total_shards = 1;
    frame.payload = payload;
    frame.from_node_id = from_bit;
    frame.step = step;
    return frame;
}

// ============================================================================
// 测试 1: 算法选择矩阵 — CommPlannerV2::select_algo 输出与预期一致
// ============================================================================
static void test_algo_selection_matrix() {
    std::printf("[test] algorithm selection matrix (CommPlannerV2::select_algo)...\n");

    using CA = CollectiveAlgo;

    // AllReduce: <=64KB & <=8 节点 → Ring；否则 RH
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllReduce, 4, 1024), CA::Ring);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllReduce, 8, 65536), CA::Ring);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllReduce, 16, 1024), CA::RecursiveHalving);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllReduce, 4, 65537), CA::RecursiveHalving);

    // AllGather: <=16 节点 → Ring；否则 Tree
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllGather, 8, 1024), CA::Ring);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllGather, 16, 1024), CA::Ring);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllGather, 32, 1024), CA::Tree);

    // Broadcast: <=8 节点 → Tree；否则 Ring
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::Broadcast, 4, 1024), CA::Tree);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::Broadcast, 8, 1024), CA::Tree);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::Broadcast, 16, 1024), CA::Ring);

    // ReduceScatter: 始终 RH
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::ReduceScatter, 4, 1024), CA::RecursiveHalving);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::ReduceScatter, 16, 65536), CA::RecursiveHalving);

    // AllToAll: 始终 PE
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllToAll, 4, 1024), CA::PairwiseExchange);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllToAll, 16, 65536), CA::PairwiseExchange);
}

// ============================================================================
// 测试 2: 四算法混合会话独立 — 同一 SyncPrimitives 实例，4 个 sync_id 用 algo=0/1/2/3
//   all_reduce algo=0 (Ring), all_gather algo=1 (Tree),
//   reduce_scatter algo=2 (RH), all_to_all algo=3 (PE)
// ============================================================================
static void test_four_algos_session_independent() {
    std::printf("[test] four algos mixed sessions independent...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    // 配置全部 peer channels（null-channel，触发各算法守卫/降级）
    EpChannel null_ch(nullptr);
    sync.set_ring_peers(0x02, &null_ch, 0x04, &null_ch);  // Ring: next=bit1, prev=bit2
    sync.set_tree_peers(0x02, &null_ch, {{0x04, &null_ch}, {0x08, &null_ch}});  // Tree: parent + children
    sync.set_rh_peers({{0x02, &null_ch}, {0x04, &null_ch}});  // RH partners
    sync.set_pe_peers({{0x02, &null_ch}, {0x04, &null_ch}});  // PE partners

    auto data = make_u64({1, 2, 3, 4});

    // sync 9601: all_reduce algo=0 (Ring)
    sync.all_reduce(9601, 0b1111, 0x01,
                    std::span<const std::uint8_t>(data.data(), data.size()),
                    ReduceOp::SUM, ReduceDType::U64,
                    std::chrono::milliseconds(200), 0);

    // sync 9602: all_gather algo=1 (Tree)
    sync.all_gather(9602, 0b1111, 0x01,
                    std::span<const std::uint8_t>(data.data(), data.size()),
                    std::chrono::milliseconds(200), 1);

    // sync 9603: reduce_scatter algo=2 (RH)
    sync.reduce_scatter(9603, 0b1111, 0x01,
                        std::span<const std::uint8_t>(data.data(), data.size()),
                        ReduceOp::SUM, ReduceDType::U64,
                        std::chrono::milliseconds(200), 2);

    // sync 9604: all_to_all algo=3 (PE)
    sync.all_to_all(9604, 0b1111, 0x01,
                    std::span<const std::uint8_t>(data.data(), data.size()),
                    std::chrono::milliseconds(200), 3);

    // all_reduce 简化版在 channel_ 无效时不创建会话（与 all_to_all/reduce_scatter 不同），
    // all_gather/reduce_scatter/all_to_all 简化版在 channel_ 检查前创建 Waiting 会话。
    // 验证：all_reduce 无会话泄漏，其他三个算法会话独立存在且 algo 字段正确。
    auto s1 = sync.get_session(9601);  // all_reduce
    auto s2 = sync.get_session(9602);  // all_gather
    auto s3 = sync.get_session(9603);  // reduce_scatter
    auto s4 = sync.get_session(9604);  // all_to_all
    CHECK(!s1.has_value());  // all_reduce 简化版不创建会话（无泄漏）
    CHECK(s2.has_value());
    CHECK(s3.has_value());
    CHECK(s4.has_value());
    CHECK_EQ(s2->algo, static_cast<std::uint8_t>(1));  // Tree
    CHECK_EQ(s3->algo, static_cast<std::uint8_t>(2));  // RH
    CHECK_EQ(s4->algo, static_cast<std::uint8_t>(3));  // PE

    // null-channel → 各算法 send 失败 → 降级简化版 → algo_state=nullopt
    CHECK(!s2->tree_algo.has_value());
    CHECK(!s3->rh_algo.has_value());
    CHECK(!s4->pe_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 3: 多 EpChannel 路由协同 — 四种 set_*_peers 共享 peer_channels_
// ============================================================================
static void test_multi_channel_routing_shared() {
    std::printf("[test] multi EpChannel routing shared peer_channels_...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel ch1(nullptr), ch2(nullptr), ch3(nullptr), ch4(nullptr);

    // Ring: next=bit1, prev=bit2
    sync.set_ring_peers(0x02, &ch1, 0x04, &ch2);
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(2));
    CHECK(sync.has_peer_channel(0x02));
    CHECK(sync.has_peer_channel(0x04));

    // Tree: parent=bit3, children={bit1, bit2}（bit1/bit2 已存在，bit3 新增）
    sync.set_tree_peers(0x08, &ch3, {{0x02, &ch1}, {0x04, &ch2}});
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(3));  // bit1, bit2, bit3
    CHECK(sync.has_peer_channel(0x08));

    // RH: partners={bit4}（新增 bit4）
    sync.set_rh_peers({{0x10, &ch4}});
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(4));
    CHECK(sync.has_peer_channel(0x10));

    // PE: partners={bit1, bit4}（复用已有，无新增）
    sync.set_pe_peers({{0x02, &ch1}, {0x10, &ch4}});
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(4));  // 无新增

    // clear 后全部清除
    sync.clear_peer_channels();
    CHECK_EQ(sync.peer_channel_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// 测试 4: 跨算法降级链 — 四种算法 null-channel → 降级简化版
// ============================================================================
static void test_cross_algo_degradation_chain() {
    std::printf("[test] cross algo degradation chain (null-channel)...\n");

    EpChannel null_ch(nullptr);
    auto data = make_u64({1, 2, 3, 4});

    // --- Ring 降级 ---
    // all_reduce 简化版在 channel_ 无效时不创建会话（与 all_gather/reduce_scatter/all_to_all 不同）
    {
        SyncPrimitives sync(nullptr);
        sync.set_self_node_id(0);
        sync.set_ring_peers(0x02, &null_ch, 0x04, &null_ch);
        auto r = sync.all_reduce(9701, 0b0111, 0x01,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 ReduceOp::SUM, ReduceDType::U64,
                                 std::chrono::milliseconds(200), 0);
        CHECK(!r.has_value());
        // all_reduce 简化版 channel_ 无效 → 不创建会话（session_count==0，无泄漏）
        CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
        sync.cleanup_finished();
    }

    // --- Tree 降级 ---
    {
        SyncPrimitives sync(nullptr);
        sync.set_self_node_id(0);
        sync.set_tree_peers(0x02, &null_ch, {{0x04, &null_ch}});
        auto r = sync.all_gather(9702, 0b0111, 0x01,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 std::chrono::milliseconds(200), 1);
        CHECK(!r.has_value());
        auto s = sync.get_session(9702);
        CHECK(s.has_value());
        CHECK_EQ(s->algo, static_cast<std::uint8_t>(1));
        CHECK(!s->tree_algo.has_value());  // Tree 降级
        sync.cleanup_finished();
    }

    // --- RH 降级 ---
    // N=4 (2 的幂), data=32 字节可整除 → RH 守卫通过 → send 失败 → 降级简化版 → 创建会话
    {
        SyncPrimitives sync(nullptr);
        sync.set_self_node_id(0);
        // N=4 (0b1111), RH 需要 3 个 partner: bit1/bit2/bit3
        sync.set_rh_peers({{0x02, &null_ch}, {0x04, &null_ch}, {0x08, &null_ch}});
        auto r = sync.reduce_scatter(9703, 0b1111, 0x01,
                                     std::span<const std::uint8_t>(data.data(), data.size()),
                                     ReduceOp::SUM, ReduceDType::U64,
                                     std::chrono::milliseconds(200), 2);
        CHECK(!r.has_value());
        auto s = sync.get_session(9703);
        CHECK(s.has_value());
        CHECK_EQ(s->algo, static_cast<std::uint8_t>(2));
        CHECK(!s->rh_algo.has_value());  // RH 降级
        sync.cleanup_finished();
    }

    // --- PE 降级 ---
    {
        SyncPrimitives sync(nullptr);
        sync.set_self_node_id(0);
        sync.set_pe_peers({{0x02, &null_ch}, {0x04, &null_ch}});
        auto r = sync.all_to_all(9704, 0b0111, 0x01,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 std::chrono::milliseconds(200), 3);
        CHECK(!r.has_value());
        auto s = sync.get_session(9704);
        CHECK(s.has_value());
        CHECK_EQ(s->algo, static_cast<std::uint8_t>(3));
        CHECK(!s->pe_algo.has_value());  // PE 降级
        sync.cleanup_finished();
    }
}

// ============================================================================
// 测试 5: EpSyncFrame v3 字段传递 — from_node_id/step 编解码保持
// ============================================================================
static void test_ep_sync_frame_v3_fields_roundtrip() {
    std::printf("[test] EpSyncFrame v3 fields (from_node_id/step) roundtrip...\n");

    EpSyncFrame frame;
    frame.sync_id = 9801;
    frame.sync_op = EpSyncOp::AllReduce;
    frame.algo = 0;  // Ring
    frame.participant_mask = 0b1111;
    frame.from_node_id = 0x04;  // 发送方 bit2
    frame.step = 3;             // Ring 第 3 步
    frame.payload = make_u64({42});

    auto encoded = encode_sync_frame(frame);
    CHECK(!encoded.empty());

    auto decoded = decode_sync_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
    CHECK(decoded.has_value());
    CHECK_EQ(decoded->sync_id, frame.sync_id);
    CHECK_EQ(decoded->sync_op, frame.sync_op);
    CHECK_EQ(decoded->algo, frame.algo);
    CHECK_EQ(decoded->participant_mask, frame.participant_mask);
    CHECK_EQ(decoded->from_node_id, frame.from_node_id);  // v3 字段保持
    CHECK_EQ(decoded->step, frame.step);                  // v3 字段保持
    CHECK_EQ(decoded->payload.size(), frame.payload.size());

    // 不同 algo 帧的 v3 字段保持
    EpSyncFrame pe_frame;
    pe_frame.sync_id = 9802;
    pe_frame.sync_op = EpSyncOp::AllToAll;
    pe_frame.algo = 3;  // PE
    pe_frame.participant_mask = 0b1111;
    pe_frame.from_node_id = 0x08;  // partner bit3
    pe_frame.step = 1;             // PE 第 1 步
    pe_frame.payload = make_u64({100, 200});

    auto pe_enc = encode_sync_frame(pe_frame);
    auto pe_dec = decode_sync_frame(std::span<const std::uint8_t>(pe_enc.data(), pe_enc.size()));
    CHECK(pe_dec.has_value());
    CHECK_EQ(pe_dec->algo, static_cast<std::uint8_t>(3));
    CHECK_EQ(pe_dec->from_node_id, static_cast<std::uint64_t>(0x08));
    CHECK_EQ(pe_dec->step, static_cast<std::uint16_t>(1));
}

// ============================================================================
// 测试 6: 被动会话跨算法 — 注入四种 algo 帧 → 简化版创建被动会话
// ============================================================================
static void test_passive_sessions_cross_algo() {
    std::printf("[test] passive sessions cross algo (frame injection)...\n");

    auto payload = make_u64({10, 20, 30, 40});

    // --- Ring 帧注入 ---
    {
        SyncPrimitives sync(nullptr);
        sync.set_self_node_id(1);
        auto frame = make_sync_frame(9901, EpSyncOp::AllReduce, 0, 0x01, 0b1111, payload, 2);
        sync.handle_sync_frame(frame);
        auto s = sync.get_session(9901);
        CHECK(s.has_value());
        CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));
        CHECK(!s->ring_algo.has_value());  // 被动会话无 Ring 状态
        sync.cleanup_finished();
    }

    // --- Tree 帧注入 ---
    {
        SyncPrimitives sync(nullptr);
        sync.set_self_node_id(1);
        auto frame = make_sync_frame(9902, EpSyncOp::AllGather, 1, 0x01, 0b1111, payload, 1);
        sync.handle_sync_frame(frame);
        auto s = sync.get_session(9902);
        CHECK(s.has_value());
        // 被动会话 algo=0（默认，不从帧复制），tree_algo=nullopt
        CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));
        CHECK(!s->tree_algo.has_value());
        sync.cleanup_finished();
    }

    // --- RH 帧注入 ---
    {
        SyncPrimitives sync(nullptr);
        sync.set_self_node_id(1);
        auto frame = make_sync_frame(9903, EpSyncOp::ReduceScatter, 2, 0x01, 0b1111, payload, 1);
        sync.handle_sync_frame(frame);
        auto s = sync.get_session(9903);
        CHECK(s.has_value());
        // 被动会话 algo=0（默认，不从帧复制），rh_algo=nullopt
        CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));
        CHECK(!s->rh_algo.has_value());
        sync.cleanup_finished();
    }

    // --- PE 帧注入 ---
    {
        SyncPrimitives sync(nullptr);
        sync.set_self_node_id(1);
        auto frame = make_sync_frame(9904, EpSyncOp::AllToAll, 3, 0x01, 0b1111, payload, 0);
        sync.handle_sync_frame(frame);
        auto s = sync.get_session(9904);
        CHECK(s.has_value());
        // 被动会话 algo=0（默认，不从帧复制），pe_algo=nullopt
        CHECK_EQ(s->algo, static_cast<std::uint8_t>(0));
        CHECK(!s->pe_algo.has_value());
        sync.cleanup_finished();
    }
}

// ============================================================================
// 测试 7: 算法守卫矩阵 N<2 — 所有算法拒绝
// ============================================================================
static void test_guard_matrix_n_lt_2() {
    std::printf("[test] guard matrix N<2 (all algos reject)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_ring_peers(0x02, &null_ch, 0, nullptr);
    sync.set_tree_peers(0, nullptr, {});
    sync.set_rh_peers({{0x02, &null_ch}});
    sync.set_pe_peers({{0x02, &null_ch}});

    auto data = make_u64({42});

    // N=1（单节点），所有算法守卫拒绝 → 降级简化版 → channel_ 无效 → nullopt
    // all_reduce algo=0
    auto r1 = sync.all_reduce(10101, 0b0001, 0x01,
                              std::span<const std::uint8_t>(data.data(), data.size()),
                              ReduceOp::SUM, ReduceDType::U64,
                              std::chrono::milliseconds(200), 0);
    CHECK(!r1.has_value());

    // all_gather algo=1
    auto r2 = sync.all_gather(10102, 0b0001, 0x01,
                              std::span<const std::uint8_t>(data.data(), data.size()),
                              std::chrono::milliseconds(200), 1);
    CHECK(!r2.has_value());

    // reduce_scatter algo=2
    auto r3 = sync.reduce_scatter(10103, 0b0001, 0x01,
                                  std::span<const std::uint8_t>(data.data(), data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(200), 2);
    CHECK(!r3.has_value());

    // all_to_all algo=3
    auto r4 = sync.all_to_all(10104, 0b0001, 0x01,
                              std::span<const std::uint8_t>(data.data(), data.size()),
                              std::chrono::milliseconds(200), 3);
    CHECK(!r4.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 8: 算法守卫矩阵 非 2 的幂 — RH/PE 拒绝（Ring/Tree 接受任意 N>=2）
// ============================================================================
static void test_guard_matrix_not_power_of_two() {
    std::printf("[test] guard matrix N not power of two (RH/PE reject)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=3（非 2 的幂），配置 partners
    sync.set_rh_peers({{0x02, &null_ch}, {0x04, &null_ch}});
    sync.set_pe_peers({{0x02, &null_ch}, {0x04, &null_ch}});

    // N=3, data=24 字节（3 个 u64），24%3=0 可整除
    auto data = make_u64({10, 20, 30});

    // RH algo=2 N=3 → 守卫拒绝 → 降级简化版
    auto r = sync.reduce_scatter(10201, 0b0111, 0x01,
                                 std::span<const std::uint8_t>(data.data(), data.size()),
                                 ReduceOp::SUM, ReduceDType::U64,
                                 std::chrono::milliseconds(200), 2);
    CHECK(!r.has_value());
    auto s = sync.get_session(10201);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(2));
    CHECK(!s->rh_algo.has_value());  // RH 守卫拒绝

    // PE algo=3 N=3 → 守卫拒绝 → 降级简化版
    auto r2 = sync.all_to_all(10202, 0b0111, 0x01,
                              std::span<const std::uint8_t>(data.data(), data.size()),
                              std::chrono::milliseconds(200), 3);
    CHECK(!r2.has_value());
    auto s2 = sync.get_session(10202);
    CHECK(s2.has_value());
    CHECK_EQ(s2->algo, static_cast<std::uint8_t>(3));
    CHECK(!s2->pe_algo.has_value());  // PE 守卫拒绝

    sync.cleanup_finished();
}

// ============================================================================
// 测试 9: 算法守卫矩阵 不可整除 — Ring/RH/PE 拒绝
// ============================================================================
static void test_guard_matrix_not_divisible() {
    std::printf("[test] guard matrix local_chunk not divisible (Ring/RH/PE reject)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    // N=4，配置 partners
    sync.set_ring_peers(0x02, &null_ch, 0x04, &null_ch);
    sync.set_rh_peers({{0x02, &null_ch}, {0x04, &null_ch}});
    sync.set_pe_peers({{0x02, &null_ch}, {0x04, &null_ch}});

    // N=4, data=6 字节, 6%4=2 != 0 → 不可整除
    std::vector<std::uint8_t> odd_data(6, 0x01);

    // Ring algo=0 → 守卫拒绝（不可整除）→ all_reduce 简化版不创建会话
    auto r1 = sync.all_reduce(10301, 0b1111, 0x01,
                              std::span<const std::uint8_t>(odd_data.data(), odd_data.size()),
                              ReduceOp::SUM, ReduceDType::U64,
                              std::chrono::milliseconds(200), 0);
    CHECK(!r1.has_value());
    auto s1 = sync.get_session(10301);
    CHECK(!s1.has_value());  // all_reduce 简化版不创建会话

    // RH algo=2 → 守卫拒绝（不可整除）→ reduce_scatter 简化版不可整除不创建会话
    auto r2 = sync.reduce_scatter(10302, 0b1111, 0x01,
                                  std::span<const std::uint8_t>(odd_data.data(), odd_data.size()),
                                  ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(200), 2);
    CHECK(!r2.has_value());
    auto s2 = sync.get_session(10302);
    CHECK(!s2.has_value());  // reduce_scatter 不可整除不创建会话

    // PE algo=3 → 守卫拒绝（不可整除）
    auto r3 = sync.all_to_all(10303, 0b1111, 0x01,
                              std::span<const std::uint8_t>(odd_data.data(), odd_data.size()),
                              std::chrono::milliseconds(200), 3);
    CHECK(!r3.has_value());
    auto s3 = sync.get_session(10303);
    CHECK(s3.has_value());
    CHECK(!s3->pe_algo.has_value());

    sync.cleanup_finished();
}

// ============================================================================
// 测试 10: 算法引擎拓扑一致性 — Ring/Tree/RH/PE 步数与伙伴计算
// ============================================================================
static void test_engine_topology_consistency() {
    std::printf("[test] engine topology consistency (Ring/Tree/RH/PE)...\n");

    // --- Ring: total_steps = 2*(N-1) ---
    CHECK_EQ(RingEngine::total_steps(2), static_cast<std::size_t>(2));
    CHECK_EQ(RingEngine::total_steps(4), static_cast<std::size_t>(6));
    CHECK_EQ(RingEngine::total_steps(8), static_cast<std::size_t>(14));
    CHECK_EQ(RingEngine::reduce_scatter_steps(4), static_cast<std::size_t>(3));
    CHECK_EQ(RingEngine::all_gather_steps(4), static_cast<std::size_t>(3));

    // --- Tree: total_steps = ceil(log2(N)) ---
    CHECK_EQ(TreeEngine::total_steps(2), static_cast<std::size_t>(1));
    CHECK_EQ(TreeEngine::total_steps(4), static_cast<std::size_t>(2));
    CHECK_EQ(TreeEngine::total_steps(8), static_cast<std::size_t>(3));
    CHECK_EQ(TreeEngine::total_steps(16), static_cast<std::size_t>(4));

    // --- RH: total_steps = 2*log2(N) (AllReduce), log2(N) (ReduceScatter) ---
    CHECK_EQ(RHEngine::is_power_of_two(4), true);
    CHECK_EQ(RHEngine::is_power_of_two(6), false);
    CHECK_EQ(RHEngine::pad_to_power_of_two(5), static_cast<std::size_t>(8));
    CHECK_EQ(RHEngine::reduce_scatter_steps(4), static_cast<std::size_t>(2));
    CHECK_EQ(RHEngine::all_gather_steps(4), static_cast<std::size_t>(2));
    CHECK_EQ(RHEngine::total_steps(4), static_cast<std::size_t>(4));   // AllReduce = 2*2
    CHECK_EQ(RHEngine::total_steps(8), static_cast<std::size_t>(6));   // AllReduce = 2*3

    // --- PE: partner = rank XOR (1<<step), total_steps = log2(N) ---
    CHECK_EQ(PEEngine::is_power_of_two(4), true);
    CHECK_EQ(PEEngine::is_power_of_two(3), false);
    CHECK_EQ(PEEngine::pad_to_power_of_two(5), static_cast<std::size_t>(8));
    // N=4, rank 0: step0 partner=1, step1 partner=2
    CHECK_EQ(PEEngine::partner_at_step(0, 0), static_cast<std::size_t>(1));
    CHECK_EQ(PEEngine::partner_at_step(0, 1), static_cast<std::size_t>(2));
    // N=8, rank 5: step0 partner=4, step1 partner=7, step2 partner=1
    CHECK_EQ(PEEngine::partner_at_step(5, 0), static_cast<std::size_t>(4));
    CHECK_EQ(PEEngine::partner_at_step(5, 1), static_cast<std::size_t>(7));
    CHECK_EQ(PEEngine::partner_at_step(5, 2), static_cast<std::size_t>(1));
}

// ============================================================================
// 测试 11: 会话生命周期无泄漏 — 多 sync_id 并发、cleanup_finished、无额外泄漏
// ============================================================================
static void test_session_lifecycle_no_leak() {
    std::printf("[test] session lifecycle no leak...\n");

    SyncPrimitives sync(nullptr);
    sync.set_self_node_id(0);

    EpChannel null_ch(nullptr);
    sync.set_ring_peers(0x02, &null_ch, 0x04, &null_ch);
    sync.set_rh_peers({{0x02, &null_ch}, {0x04, &null_ch}});
    sync.set_pe_peers({{0x02, &null_ch}, {0x04, &null_ch}});

    auto data = make_u64({1, 2, 3, 4});

    // 8 次调用，交替使用四种算法
    // all_reduce 简化版不创建会话，all_gather/reduce_scatter/all_to_all 创建会话
    for (int i = 0; i < 2; ++i) {
        sync.all_reduce(11001 + i * 4, 0b1111, 0x01,
                        std::span<const std::uint8_t>(data.data(), data.size()),
                        ReduceOp::SUM, ReduceDType::U64,
                        std::chrono::milliseconds(100), 0);
        sync.all_gather(11002 + i * 4, 0b1111, 0x01,
                        std::span<const std::uint8_t>(data.data(), data.size()),
                        std::chrono::milliseconds(100), 1);
        sync.reduce_scatter(11003 + i * 4, 0b1111, 0x01,
                            std::span<const std::uint8_t>(data.data(), data.size()),
                            ReduceOp::SUM, ReduceDType::U64,
                            std::chrono::milliseconds(100), 2);
        sync.all_to_all(11004 + i * 4, 0b1111, 0x01,
                        std::span<const std::uint8_t>(data.data(), data.size()),
                        std::chrono::milliseconds(100), 3);
    }

    // 2 轮 × 3 个创建会话的算法 = 6 个 Waiting 会话（cleanup_finished 不清理 Waiting）
    sync.cleanup_finished();
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(6));

    // 验证第二轮的 algo 正确（无交叉污染）
    auto s2 = sync.get_session(11002);  // all_gather
    auto s3 = sync.get_session(11003);  // reduce_scatter
    auto s4 = sync.get_session(11004);  // all_to_all
    CHECK(s2.has_value());
    CHECK(s3.has_value());
    CHECK(s4.has_value());
    CHECK_EQ(s2->algo, static_cast<std::uint8_t>(1));
    CHECK_EQ(s3->algo, static_cast<std::uint8_t>(2));
    CHECK_EQ(s4->algo, static_cast<std::uint8_t>(3));
}

// ============================================================================
// 测试 12: EpSyncFrame v3 向后兼容 — from_node_id=0/step=0 条件编码
// ============================================================================
static void test_ep_sync_frame_v3_backward_compat() {
    std::printf("[test] EpSyncFrame v3 backward compat (conditional encoding)...\n");

    // v3 字段为 0 时不写入尾部（条件编码），与旧帧字节级兼容
    EpSyncFrame legacy_frame;
    legacy_frame.sync_id = 12001;
    legacy_frame.sync_op = EpSyncOp::Barrier;
    legacy_frame.algo = 0;
    legacy_frame.participant_mask = 0b1111;
    legacy_frame.from_node_id = 0;  // 不写入尾部
    legacy_frame.step = 0;          // 不写入尾部
    legacy_frame.payload = {};

    auto legacy_enc = encode_sync_frame(legacy_frame);
    CHECK(!legacy_enc.empty());

    auto legacy_dec = decode_sync_frame(std::span<const std::uint8_t>(legacy_enc.data(), legacy_enc.size()));
    CHECK(legacy_dec.has_value());
    CHECK_EQ(legacy_dec->sync_id, legacy_frame.sync_id);
    CHECK_EQ(legacy_dec->from_node_id, static_cast<std::uint64_t>(0));
    CHECK_EQ(legacy_dec->step, static_cast<std::uint16_t>(0));

    // v3 字段非 0 时写入尾部
    EpSyncFrame v3_frame;
    v3_frame.sync_id = 12002;
    v3_frame.sync_op = EpSyncOp::Barrier;
    v3_frame.algo = 0;
    v3_frame.participant_mask = 0b1111;
    v3_frame.from_node_id = 0x02;  // 写入尾部
    v3_frame.step = 5;             // 写入尾部
    v3_frame.payload = {};

    auto v3_enc = encode_sync_frame(v3_frame);
    CHECK(!v3_enc.empty());

    // v3 帧编码长度应大于 legacy 帧（多了尾部字段）
    CHECK(v3_enc.size() > legacy_enc.size());

    auto v3_dec = decode_sync_frame(std::span<const std::uint8_t>(v3_enc.data(), v3_enc.size()));
    CHECK(v3_dec.has_value());
    CHECK_EQ(v3_dec->from_node_id, static_cast<std::uint64_t>(0x02));
    CHECK_EQ(v3_dec->step, static_cast<std::uint16_t>(5));
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::printf("=== Phase4E2E (P4-H End-to-End Integration) Tests ===\n\n");

    test_algo_selection_matrix();
    test_four_algos_session_independent();
    test_multi_channel_routing_shared();
    test_cross_algo_degradation_chain();
    test_ep_sync_frame_v3_fields_roundtrip();
    test_passive_sessions_cross_algo();
    test_guard_matrix_n_lt_2();
    test_guard_matrix_not_power_of_two();
    test_guard_matrix_not_divisible();
    test_engine_topology_consistency();
    test_session_lifecycle_no_leak();
    test_ep_sync_frame_v3_backward_compat();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
