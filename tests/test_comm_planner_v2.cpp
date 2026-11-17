// test_comm_planner_v2.cpp — v2.1 Phase 2 M3/M4 拓扑感知规划单元测试
//
// 验证 v2.1 Phase 2 M3/M4 交付物（CommPlannerV2 拓扑感知规划 + 异构 chunk 切分）：
//   1. TopologyPlan 构造 + brief + valid
//   2. select_algo 算法选择矩阵（各 op + 边界消息/节点数）
//   3. sort_nodes_by_score 降序 + 同分稳定排序
//   4. build_route 贪心最近邻（RTT 优化）
//   5. split_chunks_by_compute 同构等分
//   6. split_chunks_by_compute 异构加权分配
//   7. split_chunks_by_compute 舍入修正（sum == msg_size）
//   8. split_chunks_by_compute 最小 chunk 保护
//   9. compute_plan_hash 一致性 + 区分性
//  10. plan 完整流程（算法+排序+路由+切分）
//  11. plan 缓存命中（相同输入复用）
//  12. plan 参数校验（空 nodes / msg_size=0 抛异常）
//  13. serialize/deserialize roundtrip
//  14. deserialize 错误格式（坏 magic / 截断）
//  15. CommPlannerV2 构造 + 缓存容量 + 统计
//  16. chunk_imbalance_ratio 计算

#include "linoh/multimodal/comm_planner_v2.hpp"
#include "linoh/multimodal/collective.hpp"
#include "linoh/node_profile.hpp"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

using namespace linoh;
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

#define CHECK_NE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a != _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s != %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ============================================================================
// 辅助函数：构造 NodeProfile
// ============================================================================

/// 构造 NodeProfile（endpoint_id 用 seed 填充，compute 用给定参数）
static NodeProfile make_profile(std::uint8_t seed,
                                 const std::string &node_id,
                                 std::uint32_t vram_mb,
                                 float tflops_fp16,
                                 std::uint32_t rtt_ms = 10) {
    NodeProfile p;
    // endpoint_id: 32 字节，用 seed 填充（保证不同 seed 不同）
    for (int i = 0; i < 32; ++i) {
        p.endpoint_id.data()[i] = static_cast<std::uint8_t>(seed + i);
    }
    p.node_id = node_id;
    p.compute.gpu_model = "TestGPU";
    p.compute.vram_mb = vram_mb;
    p.compute.tflops_fp16 = tflops_fp16;
    p.compute.tflops_int4 = tflops_fp16 * 4.0f;  // INT4 约为 FP16 的 4 倍
    p.compute.cuda_cores = static_cast<std::uint32_t>(tflops_fp16 * 100);
    p.network.uplink_bps = 1'000'000'000;
    p.network.downlink_bps = 1'000'000'000;
    p.network.rtt_ms_avg = rtt_ms;
    p.network.rtt_ms_p99 = rtt_ms * 2;
    p.network.loss_rate = 0.0f;
    p.network.net_class = NetClass::Lan;
    p.stability.score = 0.9f;
    p.stability.uptime_seconds = 86400;
    p.stability.disconnect_count = 0;
    p.stability.task_success_rate = 0.99f;
    p.geo.region = GeoRegion::Unknown;
    return p;
}

/// 构造同构节点列表（N 个相同算力，seed 从 10 开始避免与 heterogeneous 冲突）
static std::vector<NodeProfile> make_homogeneous_nodes(std::size_t n) {
    std::vector<NodeProfile> nodes;
    for (std::size_t i = 0; i < n; ++i) {
        nodes.push_back(make_profile(static_cast<std::uint8_t>(i + 10),
                                      "node-" + std::to_string(i),
                                      24576, 165.0f, 10));  // RTX 4090 同构
    }
    return nodes;
}

/// 构造异构节点列表（算力差异大，rtt 相同使 compute 主导 overall_score）
static std::vector<NodeProfile> make_heterogeneous_nodes() {
    return {
        make_profile(1, "rtx3060", 12288, 30.0f, 10),    // 弱节点
        make_profile(2, "rtx4090", 24576, 165.0f, 10),   // 强节点
        make_profile(3, "rtx4060", 8192, 50.0f, 10),     // 中弱节点
        make_profile(4, "rtx5090", 32768, 210.0f, 10),   // 最强节点
    };
}

/// 构造不同 RTT 的异构节点列表（用于 build_route 测试）
static std::vector<NodeProfile> make_varied_rtt_nodes() {
    return {
        make_profile(1, "rtx3060", 12288, 30.0f, 20),    // rtt=20
        make_profile(2, "rtx4090", 24576, 165.0f, 10),   // rtt=10
        make_profile(3, "rtx4060", 8192, 50.0f, 30),     // rtt=30
        make_profile(4, "rtx5090", 32768, 210.0f, 15),   // rtt=15
    };
}

// ============================================================================
// TEST 1: TopologyPlan 构造 + brief + valid
// ============================================================================

static void test_topology_plan_construction() {
    std::printf("[test] TopologyPlan construction + brief + valid...\n");

    TopologyPlan plan;
    plan.op = CollectiveOp::AllReduce;
    plan.algo = CollectiveAlgo::RecursiveHalving;
    plan.participants = {2, 1, 0, 3};
    plan.route = {0, 1, 2, 3};
    plan.chunk_sizes = {256, 512, 128, 1024};
    plan.plan_id = 100;
    plan.plan_hash = 0xABCDEF;
    plan.msg_size = 1920;
    plan.num_nodes = 4;
    plan.min_chunk = 128;
    plan.max_chunk = 1024;
    plan.chunk_imbalance_ratio = 8.0;

    CHECK(plan.valid());
    CHECK_EQ(plan.num_nodes, static_cast<std::size_t>(4));

    std::string brief = plan.brief();
    // collective_op_name/collective_algo_name 返回 snake_case
    CHECK(brief.find("all_reduce") != std::string::npos);
    CHECK(brief.find("recursive_halving") != std::string::npos);
    CHECK(brief.find("nodes=4") != std::string::npos);
    CHECK(brief.find("msg=1920") != std::string::npos);

    // invalid: participants 与 chunk_sizes 数量不匹配
    TopologyPlan bad;
    bad.participants = {0, 1};
    bad.chunk_sizes = {100};
    bad.num_nodes = 2;
    bad.msg_size = 100;
    CHECK(!bad.valid());
}

// ============================================================================
// TEST 2: select_algo 算法选择矩阵
// ============================================================================

static void test_select_algo() {
    std::printf("[test] select_algo matrix...\n");

    // Barrier 始终 Ring
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::Barrier, 4, 1024),
             CollectiveAlgo::Ring);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::Barrier, 100, 1024 * 1024),
             CollectiveAlgo::Ring);

    // AllReduce: 小消息+少节点 → Ring
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllReduce, 4, 1024),
             CollectiveAlgo::Ring);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllReduce, 8, 64 * 1024),
             CollectiveAlgo::Ring);
    // AllReduce: 大消息 → RecursiveHalving
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllReduce, 4, 64 * 1024 + 1),
             CollectiveAlgo::RecursiveHalving);
    // AllReduce: 多节点 → RecursiveHalving
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllReduce, 9, 1024),
             CollectiveAlgo::RecursiveHalving);

    // AllGather: 少节点(<=16) → Ring
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllGather, 16, 1024),
             CollectiveAlgo::Ring);
    // AllGather: 多节点 → Tree
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllGather, 17, 1024),
             CollectiveAlgo::Tree);

    // Broadcast: 少节点(<=8) → Tree
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::Broadcast, 8, 1024),
             CollectiveAlgo::Tree);
    // Broadcast: 多节点 → Ring
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::Broadcast, 9, 1024),
             CollectiveAlgo::Ring);

    // ReduceScatter 始终 RecursiveHalving
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::ReduceScatter, 4, 1024),
             CollectiveAlgo::RecursiveHalving);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::ReduceScatter, 100, 1024 * 1024),
             CollectiveAlgo::RecursiveHalving);

    // AllToAll 始终 PairwiseExchange
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllToAll, 4, 1024),
             CollectiveAlgo::PairwiseExchange);
    CHECK_EQ(CommPlannerV2::select_algo(CollectiveOp::AllToAll, 100, 1024 * 1024),
             CollectiveAlgo::PairwiseExchange);
}

// ============================================================================
// TEST 3: sort_nodes_by_score 降序 + 同分稳定
// ============================================================================

static void test_sort_nodes_by_score() {
    std::printf("[test] sort_nodes_by_score (desc + tie-break)...\n");

    auto nodes = make_heterogeneous_nodes();
    // nodes[0]=rtx3060(弱), nodes[1]=rtx4090, nodes[2]=rtx4060(中弱), nodes[3]=rtx5090(最强)
    // 预期降序：5090 > 4090 > 4060 > 3060 → 索引 [3, 1, 2, 0]

    auto sorted = CommPlannerV2::sort_nodes_by_score(nodes);
    CHECK_EQ(sorted.size(), static_cast<std::size_t>(4));
    CHECK_EQ(sorted[0], static_cast<std::uint32_t>(3));  // rtx5090 最强
    CHECK_EQ(sorted[1], static_cast<std::uint32_t>(1));  // rtx4090
    CHECK_EQ(sorted[2], static_cast<std::uint32_t>(2));  // rtx4060
    CHECK_EQ(sorted[3], static_cast<std::uint32_t>(0));  // rtx3060 最弱

    // 验证分数确实降序
    float prev = nodes[sorted[0]].overall_score();
    for (std::size_t i = 1; i < sorted.size(); ++i) {
        float cur = nodes[sorted[i]].overall_score();
        CHECK(cur <= prev);
        prev = cur;
    }

    // 同分稳定排序：构造两个完全相同的节点
    std::vector<NodeProfile> same_nodes = {
        make_profile(1, "aaa", 24576, 165.0f, 10),
        make_profile(2, "bbb", 24576, 165.0f, 10),
    };
    auto same_sorted = CommPlannerV2::sort_nodes_by_score(same_nodes);
    // 同分按 node_id 字典序：aaa < bbb → [0, 1]
    CHECK_EQ(same_sorted[0], static_cast<std::uint32_t>(0));
    CHECK_EQ(same_sorted[1], static_cast<std::uint32_t>(1));
}

// ============================================================================
// TEST 4: build_route 贪心最近邻
// ============================================================================

static void test_build_route() {
    std::printf("[test] build_route (greedy nearest neighbor)...\n");

    // 用不同 RTT 的节点集测试贪心最近邻
    auto nodes = make_varied_rtt_nodes();
    // participants 按算力降序：[3, 1, 2, 0]（5090/4090/4060/3060）
    auto participants = CommPlannerV2::sort_nodes_by_score(nodes);

    auto route = CommPlannerV2::build_route(nodes, participants);
    CHECK_EQ(route.size(), static_cast<std::size_t>(4));
    // 起点必须是 participants[0]（最强节点）
    CHECK_EQ(route[0], static_cast<std::uint32_t>(0));
    // 贪心：从 participants[0] 出发，选未访问中 rtt 最小
    // participants = [3, 1, 2, 0]，对应 rtt: 5090=15, 4090=10, 4060=30, 3060=20
    // route[0]=0(5090,rtt15) → 选 rtt 最小：4090(rtt10)=idx1 → 3060(rtt20)=idx3 → 4060(rtt30)=idx2
    CHECK_EQ(route[1], static_cast<std::uint32_t>(1));  // 4090 rtt=10 最小
    CHECK_EQ(route[2], static_cast<std::uint32_t>(3));  // 3060 rtt=20 次小
    CHECK_EQ(route[3], static_cast<std::uint32_t>(2));  // 4060 rtt=30 最后

    // 单节点
    std::vector<NodeProfile> single = {make_profile(1, "n0", 24576, 165.0f, 10)};
    auto single_part = CommPlannerV2::sort_nodes_by_score(single);
    auto single_route = CommPlannerV2::build_route(single, single_part);
    CHECK_EQ(single_route.size(), static_cast<std::size_t>(1));
    CHECK_EQ(single_route[0], static_cast<std::uint32_t>(0));
}

// ============================================================================
// TEST 5: split_chunks_by_compute 同构等分
// ============================================================================

static void test_split_chunks_homogeneous() {
    std::printf("[test] split_chunks_by_compute (homogeneous equal split)...\n");

    auto nodes = make_homogeneous_nodes(4);
    auto participants = CommPlannerV2::sort_nodes_by_score(nodes);

    std::size_t msg = 4096;
    auto chunks = CommPlannerV2::split_chunks_by_compute(nodes, participants, msg);
    CHECK_EQ(chunks.size(), static_cast<std::size_t>(4));

    // 同构应等分：每个 1024
    for (auto c : chunks) {
        CHECK_EQ(c, static_cast<std::size_t>(1024));
    }

    // sum == msg_size
    std::size_t sum = 0;
    for (auto c : chunks) sum += c;
    CHECK_EQ(sum, msg);

    // 不能整除的情况：4096 / 3
    auto nodes3 = make_homogeneous_nodes(3);
    auto part3 = CommPlannerV2::sort_nodes_by_score(nodes3);
    auto chunks3 = CommPlannerV2::split_chunks_by_compute(nodes3, part3, 4096);
    CHECK_EQ(chunks3.size(), static_cast<std::size_t>(3));
    std::size_t sum3 = 0;
    for (auto c : chunks3) sum3 += c;
    CHECK_EQ(sum3, static_cast<std::size_t>(4096));
    // 4096/3 = 1365 余 1，前 1 个多 1：[1366, 1365, 1365]
    CHECK_EQ(chunks3[0], static_cast<std::size_t>(1366));
    CHECK_EQ(chunks3[1], static_cast<std::size_t>(1365));
    CHECK_EQ(chunks3[2], static_cast<std::size_t>(1365));
}

// ============================================================================
// TEST 6: split_chunks_by_compute 异构加权
// ============================================================================

static void test_split_chunks_heterogeneous() {
    std::printf("[test] split_chunks_by_compute (heterogeneous weighted)...\n");

    auto nodes = make_heterogeneous_nodes();
    // 5090(最强) > 4090 > 4060 > 3060(最弱)
    auto participants = CommPlannerV2::sort_nodes_by_score(nodes);

    std::size_t msg = 10000;
    auto chunks = CommPlannerV2::split_chunks_by_compute(nodes, participants, msg);
    CHECK_EQ(chunks.size(), static_cast<std::size_t>(4));

    // 强节点应分到更多 chunk
    // participants=[3,1,2,0] → chunks[0]对应5090(最强)应最大
    CHECK(chunks[0] >= chunks[1]);  // 5090 >= 4090
    CHECK(chunks[1] >= chunks[2]);  // 4090 >= 4060
    CHECK(chunks[2] >= chunks[3]);  // 4060 >= 3060

    // sum == msg_size
    std::size_t sum = 0;
    for (auto c : chunks) sum += c;
    CHECK_EQ(sum, msg);

    // 最弱节点不应分到 0
    CHECK(chunks[3] > static_cast<std::size_t>(0));
}

// ============================================================================
// TEST 7: split_chunks_by_compute 舍入修正（sum == msg_size）
// ============================================================================

static void test_split_chunks_rounding_fix() {
    std::printf("[test] split_chunks_by_compute (rounding fix: sum == msg_size)...\n");

    auto nodes = make_heterogeneous_nodes();
    auto participants = CommPlannerV2::sort_nodes_by_score(nodes);

    // 测试多个 msg_size，确保 sum 始终 == msg_size
    // 注：msg >= n（4）时每个 chunk 可 > 0；msg < n 时物理上无法每节点 >=1
    std::size_t test_sizes[] = {4, 7, 13, 100, 999, 1000, 65535, 1000000, 9999999};
    for (std::size_t msg : test_sizes) {
        auto chunks = CommPlannerV2::split_chunks_by_compute(nodes, participants, msg);
        std::size_t sum = 0;
        for (auto c : chunks) sum += c;
        CHECK_EQ(sum, msg);
        // msg >= n 时每个 chunk > 0
        for (auto c : chunks) {
            CHECK(c > static_cast<std::size_t>(0));
        }
    }
}

// ============================================================================
// TEST 8: split_chunks_by_compute 最小 chunk 保护
// ============================================================================

static void test_split_chunks_min_protection() {
    std::printf("[test] split_chunks_by_compute (min chunk protection)...\n");

    auto nodes = make_heterogeneous_nodes();
    auto participants = CommPlannerV2::sort_nodes_by_score(nodes);

    // 极端异构 + 小消息：弱节点仍应分到 >= 1 字节
    std::size_t msg = 10;
    auto chunks = CommPlannerV2::split_chunks_by_compute(nodes, participants, msg);
    CHECK_EQ(chunks.size(), static_cast<std::size_t>(4));
    for (auto c : chunks) {
        CHECK(c >= static_cast<std::size_t>(1));  // 最小保护
    }
    std::size_t sum = 0;
    for (auto c : chunks) sum += c;
    CHECK_EQ(sum, msg);
}

// ============================================================================
// TEST 9: compute_plan_hash 一致性 + 区分性
// ============================================================================

static void test_compute_plan_hash() {
    std::printf("[test] compute_plan_hash (consistency + distinctness)...\n");

    auto nodes1 = make_heterogeneous_nodes();
    auto nodes2 = make_heterogeneous_nodes();  // 相同内容

    // 相同输入 → 相同 hash
    std::uint64_t h1 = CommPlannerV2::compute_plan_hash(
        CollectiveOp::AllReduce, nodes1, 1024);
    std::uint64_t h2 = CommPlannerV2::compute_plan_hash(
        CollectiveOp::AllReduce, nodes2, 1024);
    CHECK_EQ(h1, h2);

    // 不同 op → 不同 hash
    std::uint64_t h3 = CommPlannerV2::compute_plan_hash(
        CollectiveOp::AllGather, nodes1, 1024);
    CHECK_NE(h1, h3);

    // 不同 msg_size → 不同 hash
    std::uint64_t h4 = CommPlannerV2::compute_plan_hash(
        CollectiveOp::AllReduce, nodes1, 2048);
    CHECK_NE(h1, h4);

    // 不同节点集合 → 不同 hash
    auto nodes3 = make_homogeneous_nodes(4);
    std::uint64_t h5 = CommPlannerV2::compute_plan_hash(
        CollectiveOp::AllReduce, nodes3, 1024);
    CHECK_NE(h1, h5);

    // 不同节点数 → 不同 hash
    auto nodes4 = make_homogeneous_nodes(3);
    std::uint64_t h6 = CommPlannerV2::compute_plan_hash(
        CollectiveOp::AllReduce, nodes4, 1024);
    CHECK_NE(h1, h6);
}

// ============================================================================
// TEST 10: plan 完整流程
// ============================================================================

static void test_plan_full() {
    std::printf("[test] plan full pipeline...\n");

    CommPlannerV2 planner;
    auto nodes = make_heterogeneous_nodes();

    auto plan = planner.plan(CollectiveOp::AllReduce, nodes, 64 * 1024 + 1);
    CHECK(plan.valid());
    CHECK_EQ(plan.op, CollectiveOp::AllReduce);
    // 大消息 → RecursiveHalving
    CHECK_EQ(plan.algo, CollectiveAlgo::RecursiveHalving);
    CHECK_EQ(plan.num_nodes, static_cast<std::size_t>(4));
    CHECK_EQ(plan.msg_size, static_cast<std::size_t>(64 * 1024 + 1));

    // participants 降序
    CHECK_EQ(plan.participants.size(), static_cast<std::size_t>(4));
    // 最强节点(5090=idx3)应在 participants[0]
    CHECK_EQ(plan.participants[0], static_cast<std::uint32_t>(3));

    // route 起点 = 0（participants[0]）
    CHECK_EQ(plan.route.size(), static_cast<std::size_t>(4));
    CHECK_EQ(plan.route[0], static_cast<std::uint32_t>(0));

    // chunk_sizes 与 participants 对齐
    CHECK_EQ(plan.chunk_sizes.size(), plan.participants.size());

    // sum == msg_size
    std::size_t sum = 0;
    for (auto c : plan.chunk_sizes) sum += c;
    CHECK_EQ(sum, plan.msg_size);

    // plan_id > 0
    CHECK(plan.plan_id > 0);
    // plan_hash 非零（除非极端巧合）
    CHECK(plan.plan_hash != 0);

    // imbalance_ratio >= 1.0
    CHECK(plan.chunk_imbalance_ratio >= 1.0);
    // max >= min
    CHECK(plan.max_chunk >= plan.min_chunk);
}

// ============================================================================
// TEST 11: plan 缓存命中
// ============================================================================

static void test_plan_cache_hit() {
    std::printf("[test] plan cache hit...\n");

    CommPlannerV2 planner;
    auto nodes = make_heterogeneous_nodes();

    // 第一次 plan（miss）
    auto plan1 = planner.plan(CollectiveOp::AllGather, nodes, 4096);
    CHECK_EQ(planner.cache_misses(), static_cast<std::uint64_t>(1));
    CHECK_EQ(planner.cache_hits(), static_cast<std::uint64_t>(0));

    // 第二次相同输入（hit）
    auto plan2 = planner.plan(CollectiveOp::AllGather, nodes, 4096);
    CHECK_EQ(planner.cache_hits(), static_cast<std::uint64_t>(1));

    // plan_hash 相同（缓存键一致）
    CHECK_EQ(plan1.plan_hash, plan2.plan_hash);

    // plan_id 不同（每次调用分配新 ID）
    CHECK_NE(plan1.plan_id, plan2.plan_id);

    // try_cache 直接查找
    auto cached = planner.try_cache(plan1.plan_hash);
    CHECK(cached.has_value());

    // 不同输入不命中
    auto plan3 = planner.plan(CollectiveOp::Broadcast, nodes, 4096);
    CHECK_EQ(planner.cache_misses(), static_cast<std::uint64_t>(2));
}

// ============================================================================
// TEST 12: plan 参数校验
// ============================================================================

static void test_plan_validation() {
    std::printf("[test] plan parameter validation...\n");

    CommPlannerV2 planner;
    auto nodes = make_homogeneous_nodes(2);

    // 空 nodes → 抛异常
    bool thrown = false;
    try {
        planner.plan(CollectiveOp::AllReduce, {}, 1024);
    } catch (const std::invalid_argument &) {
        thrown = true;
    }
    CHECK(thrown);

    // msg_size == 0 → 抛异常
    thrown = false;
    try {
        planner.plan(CollectiveOp::AllReduce, nodes, 0);
    } catch (const std::invalid_argument &) {
        thrown = true;
    }
    CHECK(thrown);
}

// ============================================================================
// TEST 13: serialize/deserialize roundtrip
// ============================================================================

static void test_serialize_roundtrip() {
    std::printf("[test] serialize/deserialize roundtrip...\n");

    CommPlannerV2 planner;
    auto nodes = make_heterogeneous_nodes();
    auto plan = planner.plan(CollectiveOp::AllToAll, nodes, 8192);

    // 序列化
    auto bytes = CommPlannerV2::serialize(plan);
    CHECK(!bytes.empty());

    // 反序列
    TopologyPlan restored;
    bool ok = CommPlannerV2::deserialize(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()), restored);
    CHECK(ok);

    // 字段一致
    CHECK_EQ(restored.op, plan.op);
    CHECK_EQ(restored.algo, plan.algo);
    CHECK_EQ(restored.plan_id, plan.plan_id);
    CHECK_EQ(restored.plan_hash, plan.plan_hash);
    CHECK_EQ(restored.msg_size, plan.msg_size);
    CHECK_EQ(restored.num_nodes, plan.num_nodes);
    CHECK_EQ(restored.min_chunk, plan.min_chunk);
    CHECK_EQ(restored.max_chunk, plan.max_chunk);
    // 浮点比较（允许微小误差）
    CHECK(std::abs(restored.chunk_imbalance_ratio - plan.chunk_imbalance_ratio) < 1e-9);

    CHECK_EQ(restored.participants.size(), plan.participants.size());
    for (std::size_t i = 0; i < plan.participants.size(); ++i) {
        CHECK_EQ(restored.participants[i], plan.participants[i]);
    }
    CHECK_EQ(restored.route.size(), plan.route.size());
    for (std::size_t i = 0; i < plan.route.size(); ++i) {
        CHECK_EQ(restored.route[i], plan.route[i]);
    }
    CHECK_EQ(restored.chunk_sizes.size(), plan.chunk_sizes.size());
    for (std::size_t i = 0; i < plan.chunk_sizes.size(); ++i) {
        CHECK_EQ(restored.chunk_sizes[i], plan.chunk_sizes[i]);
    }
}

// ============================================================================
// TEST 14: deserialize 错误格式
// ============================================================================

static void test_deserialize_errors() {
    std::printf("[test] deserialize error formats...\n");

    TopologyPlan out;

    // 空 data
    CHECK(!CommPlannerV2::deserialize({}, out));

    // 坏 magic
    std::vector<std::uint8_t> bad_magic = {'B', 'A', 'D', 'X', 1, 0, 0, 0};
    CHECK(!CommPlannerV2::deserialize(
        std::span<const std::uint8_t>(bad_magic.data(), bad_magic.size()), out));

    // 截断（仅 magic + version）
    std::vector<std::uint8_t> truncated = {'T', 'P', 'N', '1', 1};
    CHECK(!CommPlannerV2::deserialize(
        std::span<const std::uint8_t>(truncated.data(), truncated.size()), out));

    // 版本不匹配
    std::vector<std::uint8_t> bad_ver = {'T', 'P', 'N', '1', 99};
    CHECK(!CommPlannerV2::deserialize(
        std::span<const std::uint8_t>(bad_ver.data(), bad_ver.size()), out));

    // 正确 magic 但后续截断
    CommPlannerV2 planner;
    auto nodes = make_heterogeneous_nodes();
    auto plan = planner.plan(CollectiveOp::AllReduce, nodes, 1024);
    auto full = CommPlannerV2::serialize(plan);
    // 截断到一半
    std::vector<std::uint8_t> half(full.begin(), full.begin() + full.size() / 2);
    CHECK(!CommPlannerV2::deserialize(
        std::span<const std::uint8_t>(half.data(), half.size()), out));
}

// ============================================================================
// TEST 15: CommPlannerV2 构造 + 缓存容量 + 统计
// ============================================================================

static void test_construction_and_cache() {
    std::printf("[test] CommPlannerV2 construction + cache capacity + stats...\n");

    // 默认构造
    CommPlannerV2 planner1;
    CHECK_EQ(planner1.cache_size(), static_cast<std::size_t>(0));
    CHECK_EQ(planner1.cache_hits(), static_cast<std::uint64_t>(0));
    CHECK_EQ(planner1.cache_misses(), static_cast<std::uint64_t>(0));
    CHECK_EQ(planner1.cache_hit_rate(), 0.0);

    // 自定义容量
    CommPlannerV2 planner2(3);
    auto nodes = make_homogeneous_nodes(2);

    // 填满缓存（3 个不同输入）
    planner2.plan(CollectiveOp::AllReduce, nodes, 1024);
    planner2.plan(CollectiveOp::AllReduce, nodes, 2048);
    planner2.plan(CollectiveOp::AllReduce, nodes, 4096);
    CHECK_EQ(planner2.cache_size(), static_cast<std::size_t>(3));

    // 第 4 个应淘汰最久未使用
    planner2.plan(CollectiveOp::AllReduce, nodes, 8192);
    CHECK_EQ(planner2.cache_size(), static_cast<std::size_t>(3));

    // clear_cache
    planner2.clear_cache();
    CHECK_EQ(planner2.cache_size(), static_cast<std::size_t>(0));

    // 容量 0 保护（应至少 1）
    CommPlannerV2 planner3(0);
    planner3.plan(CollectiveOp::AllReduce, nodes, 1024);
    CHECK_EQ(planner3.cache_size(), static_cast<std::size_t>(1));
}

// ============================================================================
// TEST 16: chunk_imbalance_ratio 计算
// ============================================================================

static void test_chunk_imbalance_ratio() {
    std::printf("[test] chunk_imbalance_ratio calculation...\n");

    CommPlannerV2 planner;

    // 同构：imbalance == 1.0
    auto homo = make_homogeneous_nodes(4);
    auto plan_homo = planner.plan(CollectiveOp::AllReduce, homo, 4096);
    CHECK(std::abs(plan_homo.chunk_imbalance_ratio - 1.0) < 1e-9);

    // 异构：imbalance > 1.0
    auto hetero = make_heterogeneous_nodes();
    auto plan_hetero = planner.plan(CollectiveOp::AllReduce, hetero, 100000);
    CHECK(plan_hetero.chunk_imbalance_ratio > 1.0);
    // max/min 应等于 imbalance
    if (plan_hetero.min_chunk > 0) {
        double expected = static_cast<double>(plan_hetero.max_chunk) /
                          static_cast<double>(plan_hetero.min_chunk);
        CHECK(std::abs(plan_hetero.chunk_imbalance_ratio - expected) < 1e-9);
    }
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== v2.1 Phase 2 M3/M4 CommPlannerV2 (Topology-Aware Planning) Unit Tests ===\n\n");

    test_topology_plan_construction();
    test_select_algo();
    test_sort_nodes_by_score();
    test_build_route();
    test_split_chunks_homogeneous();
    test_split_chunks_heterogeneous();
    test_split_chunks_rounding_fix();
    test_split_chunks_min_protection();
    test_compute_plan_hash();
    test_plan_full();
    test_plan_cache_hit();
    test_plan_validation();
    test_serialize_roundtrip();
    test_deserialize_errors();
    test_construction_and_cache();
    test_chunk_imbalance_ratio();

    std::printf("\n=== Test Summary ===\n");
    std::printf("PASS: %d\n", g_pass);
    std::printf("FAIL: %d\n", g_fail);
    std::printf("Total: %d\n", g_pass + g_fail);

    return g_fail == 0 ? 0 : 1;
}
