// test_comm_planner_v1604.cpp — v1.6.0.4 (P3) EP 在线通信规划器单元测试
//
// 测试覆盖：
//   1. compute_routing_hash 一致性 + 区分性
//   2. build_expert_to_node_map 正确性
//   3. LRUHashCache 基础 insert/lookup
//   4. LRUHashCache LRU 淘汰策略
//   5. LRUHashCache 容量边界（0 归一化）
//   6. LRUHashCache clear
//   7. LRUHashCache 命中率统计
//   8. LRUHashCache 移动到头部（命中后顺序更新）
//   9. EpGroupConfig::valid() 校验
//  10. CommPlanner launch_planning 基础流程
//  11. CommPlanner dispatch_bufs + tokens_per_dst 正确
//  12. CommPlanner combine_bufs + zero_fill 正确
//  13. CommPlanner load_imbalance_ratio 统计
//  14. CommPlanner sync_participants 去重
//  15. CommPlanner try_cache 命中复用
//  16. CommPlanner cache 满后 LRU 淘汰
//  17. CommPlanner 多帧规划 plan_id 递增
//  18. CommPlanner routing 为空抛异常
//  19. CommPlanner expert 越界抛异常
//  20. CommPlanner invalid config 抛异常
//  21. serialize/deserialize round-trip
//  22. serialize magic 错误检测
//  23. serialize 截断数据检测
//  24. clear_cache + cache_size
//  25. 4 worker EP 真实场景
//  26. 并发 try_cache 线程安全
//  27. 容量 0 归一化
//  28. 容量 1 边界

#include "linoh/multimodal/comm_planner.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace linoh::multimodal;
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
    else { ++g_fail; std::printf("FAIL: %s == %s -> %lld != %lld (line %d)\n", \
        #a, #b, (long long)_a, (long long)_b, __LINE__); } \
} while (0)

// ----------------------------------------------------------------------------
// 测试辅助
// ----------------------------------------------------------------------------

static ShapeDescriptor make_shape(std::uint32_t max_tokens = 64,
                                  std::uint32_t hidden_dim = 128,
                                  std::uint32_t expert_count = 4) {
    ShapeDescriptor s;
    s.dtype = TensorDType::F16;
    s.max_tokens = max_tokens;
    s.hidden_dim = hidden_dim;
    s.expert_count = expert_count;
    return s;
}

static EpGroupConfig make_config_2workers() {
    EpGroupConfig cfg;
    cfg.ep_master = 0x100;
    cfg.ep_workers = {0x201, 0x202};
    cfg.expert_placement = {{0, 1}, {2, 3}};  // worker 0: 专家 0/1, worker 1: 专家 2/3
    cfg.num_experts = 4;
    cfg.topk = 1;
    cfg.shape = make_shape();
    return cfg;
}

static EpGroupConfig make_config_4workers() {
    EpGroupConfig cfg;
    cfg.ep_master = 0x100;
    cfg.ep_workers = {0x201, 0x202, 0x203, 0x204};
    cfg.expert_placement = {{0}, {1}, {2}, {3}};  // 1:1
    cfg.num_experts = 4;
    cfg.topk = 1;
    cfg.shape = make_shape(32, 64, 4);
    return cfg;
}

// ============================================================================
// TEST 1: compute_routing_hash 一致性 + 区分性
// ============================================================================

static void test_compute_routing_hash_consistency() {
    std::printf("[test] compute_routing_hash consistency...\n");
    std::vector<std::vector<std::uint32_t>> r1 = {{0, 1}, {2}, {3}};
    std::vector<std::vector<std::uint32_t>> r2 = {{0, 1}, {2}, {3}};
    const auto h1 = CommPlanner::compute_routing_hash(r1);
    const auto h2 = CommPlanner::compute_routing_hash(r2);
    CHECK_EQ(h1, h2);

    // 不同 routing 应不同
    std::vector<std::vector<std::uint32_t>> r3 = {{0}, {1}, {2}, {3}};
    const auto h3 = CommPlanner::compute_routing_hash(r3);
    CHECK(h1 != h3);

    // 顺序敏感
    std::vector<std::vector<std::uint32_t>> r4 = {{2}, {0, 1}, {3}};
    const auto h4 = CommPlanner::compute_routing_hash(r4);
    CHECK(h1 != h4);

    // 空 routing -> 非零（hasher 起始常量）
    std::vector<std::vector<std::uint32_t>> r5;
    const auto h5 = CommPlanner::compute_routing_hash(r5);
    CHECK(h5 != 0);
}

// ============================================================================
// TEST 2: build_expert_to_node_map 正确性
// ============================================================================

static void test_build_expert_to_node_map() {
    std::printf("[test] build_expert_to_node_map...\n");
    const auto cfg = make_config_2workers();
    const auto m = CommPlanner::build_expert_to_node_map(cfg);
    CHECK_EQ(m.size(), static_cast<std::size_t>(4));
    CHECK_EQ(m.at(0), static_cast<NodeId>(0x201));
    CHECK_EQ(m.at(1), static_cast<NodeId>(0x201));
    CHECK_EQ(m.at(2), static_cast<NodeId>(0x202));
    CHECK_EQ(m.at(3), static_cast<NodeId>(0x202));
}

// ============================================================================
// TEST 3: LRUHashCache 基础 insert/lookup
// ============================================================================

static void test_lru_basic_insert_lookup() {
    std::printf("[test] LRUHashCache basic insert/lookup...\n");
    LRUHashCache cache(4);
    CHECK_EQ(cache.size(), static_cast<std::size_t>(0));
    CHECK_EQ(cache.hits(), static_cast<std::uint64_t>(0));
    CHECK_EQ(cache.misses(), static_cast<std::uint64_t>(0));

    EpCommPlan plan;
    plan.plan_id = 42;
    plan.routing_hash = 100;
    cache.insert(100, plan);

    CHECK_EQ(cache.size(), static_cast<std::size_t>(1));
    auto got = cache.lookup(100);
    CHECK(got.has_value());
    CHECK_EQ(got->plan_id, static_cast<std::uint64_t>(42));
    CHECK_EQ(cache.hits(), static_cast<std::uint64_t>(1));

    // miss
    auto miss = cache.lookup(999);
    CHECK(!miss.has_value());
    CHECK_EQ(cache.misses(), static_cast<std::uint64_t>(1));
}

// ============================================================================
// TEST 4: LRUHashCache LRU 淘汰
// ============================================================================

static void test_lru_eviction() {
    std::printf("[test] LRUHashCache LRU eviction...\n");
    LRUHashCache cache(2);  // 容量 2

    EpCommPlan p1; p1.plan_id = 1; p1.routing_hash = 1;
    EpCommPlan p2; p2.plan_id = 2; p2.routing_hash = 2;
    EpCommPlan p3; p3.plan_id = 3; p3.routing_hash = 3;
    cache.insert(1, p1);
    cache.insert(2, p2);
    CHECK_EQ(cache.size(), static_cast<std::size_t>(2));

    // 插入第 3 个 -> 淘汰 hash=1
    cache.insert(3, p3);
    CHECK_EQ(cache.size(), static_cast<std::size_t>(2));
    CHECK(!cache.lookup(1).has_value());  // 已淘汰
    CHECK(cache.lookup(2).has_value());
    CHECK(cache.lookup(3).has_value());
}

// ============================================================================
// TEST 5: LRUHashCache 容量 0 归一化
// ============================================================================

static void test_lru_capacity_zero() {
    std::printf("[test] LRUHashCache capacity=0 normalization...\n");
    LRUHashCache cache(0);
    CHECK_EQ(cache.capacity(), static_cast<std::size_t>(1));  // 归一化为 1

    EpCommPlan p; p.plan_id = 1;
    cache.insert(1, p);
    CHECK_EQ(cache.size(), static_cast<std::size_t>(1));

    EpCommPlan p2; p2.plan_id = 2;
    cache.insert(2, p2);
    // 容量 1 -> 旧的被淘汰
    CHECK_EQ(cache.size(), static_cast<std::size_t>(1));
    CHECK(!cache.lookup(1).has_value());
    CHECK(cache.lookup(2).has_value());
}

// ============================================================================
// TEST 6: LRUHashCache 容量 1 边界
// ============================================================================

static void test_lru_capacity_one() {
    std::printf("[test] LRUHashCache capacity=1...\n");
    LRUHashCache cache(1);
    EpCommPlan p1; p1.plan_id = 1; p1.routing_hash = 1;
    EpCommPlan p2; p2.plan_id = 2; p2.routing_hash = 2;
    cache.insert(1, p1);
    cache.insert(2, p2);
    CHECK_EQ(cache.size(), static_cast<std::size_t>(1));
    CHECK(!cache.lookup(1).has_value());
    CHECK(cache.lookup(2).has_value());
}

// ============================================================================
// TEST 7: LRUHashCache clear
// ============================================================================

static void test_lru_clear() {
    std::printf("[test] LRUHashCache clear...\n");
    LRUHashCache cache(4);
    EpCommPlan p; p.plan_id = 1;
    cache.insert(1, p);
    cache.insert(2, p);
    CHECK_EQ(cache.size(), static_cast<std::size_t>(2));
    cache.clear();
    CHECK_EQ(cache.size(), static_cast<std::size_t>(0));
    CHECK(!cache.lookup(1).has_value());
}

// ============================================================================
// TEST 8: LRUHashCache 命中率统计
// ============================================================================

static void test_lru_hit_rate() {
    std::printf("[test] LRUHashCache hit rate stats...\n");
    LRUHashCache cache(4);
    EpCommPlan p; p.plan_id = 1;
    cache.insert(1, p);
    cache.lookup(1);  // hit
    cache.lookup(1);  // hit
    cache.lookup(2);  // miss
    cache.lookup(3);  // miss
    cache.lookup(4);  // miss
    CHECK_EQ(cache.hits(), static_cast<std::uint64_t>(2));
    CHECK_EQ(cache.misses(), static_cast<std::uint64_t>(3));
    // hit_rate = 2 / 5 = 0.4
    const double hr = cache.hit_rate();
    CHECK(hr > 0.39 && hr < 0.41);
}

// ============================================================================
// TEST 9: LRUHashCache 命中后顺序更新（move-to-front）
// ============================================================================

static void test_lru_move_to_front() {
    std::printf("[test] LRUHashCache move-to-front on hit...\n");
    LRUHashCache cache(2);
    EpCommPlan p1; p1.plan_id = 1; p1.routing_hash = 1;
    EpCommPlan p2; p2.plan_id = 2; p2.routing_hash = 2;
    EpCommPlan p3; p3.plan_id = 3; p3.routing_hash = 3;
    cache.insert(1, p1);
    cache.insert(2, p2);

    // 访问 hash=1（移到头部）-> hash=2 现在是 LRU
    cache.lookup(1);

    // 插入 hash=3 -> 淘汰 hash=2（而不是 hash=1）
    cache.insert(3, p3);
    CHECK(cache.lookup(1).has_value());   // 仍存在（被移到了头部）
    CHECK(!cache.lookup(2).has_value());  // 已淘汰
    CHECK(cache.lookup(3).has_value());
}

// ============================================================================
// TEST 10: EpGroupConfig::valid() 校验
// ============================================================================

static void test_epgroup_config_valid() {
    std::printf("[test] EpGroupConfig::valid()...\n");
    EpGroupConfig cfg = make_config_2workers();
    CHECK(cfg.valid());

    // ep_workers 为空
    EpGroupConfig bad = cfg;
    bad.ep_workers.clear();
    bad.expert_placement.clear();
    CHECK(!bad.valid());

    // num_experts = 0
    bad = cfg;
    bad.num_experts = 0;
    CHECK(!bad.valid());

    // topk = 0
    bad = cfg;
    bad.topk = 0;
    CHECK(!bad.valid());

    // expert_placement 数量不匹配
    bad = cfg;
    bad.expert_placement = {{0}};
    CHECK(!bad.valid());

    // shape invalid
    bad = cfg;
    bad.shape = ShapeDescriptor{};
    CHECK(!bad.valid());
}

// ============================================================================
// TEST 11: CommPlanner launch_planning 基础流程
// ============================================================================

static void test_launch_planning_basic() {
    std::printf("[test] launch_planning basic flow...\n");
    CommPlanner planner(4);
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> routing = {
        {0},  // -> worker 0 (0x201)
        {2},  // -> worker 1 (0x202)
        {1},  // -> worker 0
        {3},  // -> worker 1
    };
    const auto plan = planner.launch_planning(routing, cfg);
    CHECK_EQ(plan.dst_nodes.size(), static_cast<std::size_t>(4));
    CHECK_EQ(plan.dst_nodes[0], static_cast<NodeId>(0x201));
    CHECK_EQ(plan.dst_nodes[1], static_cast<NodeId>(0x202));
    CHECK_EQ(plan.dst_nodes[2], static_cast<NodeId>(0x201));
    CHECK_EQ(plan.dst_nodes[3], static_cast<NodeId>(0x202));
    CHECK_EQ(plan.expert_ids.size(), static_cast<std::size_t>(4));
    CHECK_EQ(plan.total_tokens, static_cast<std::uint32_t>(4));
    // plan_id 是原子递增计数器，从 0 开始（首次调用 = 0）
    CHECK(plan.sync_id > 0);
    CHECK(plan.routing_hash != 0);
}

// ============================================================================
// TEST 12: CommPlanner dispatch_bufs + tokens_per_dst 正确
// ============================================================================

static void test_launch_planning_dispatch_bufs() {
    std::printf("[test] launch_planning dispatch_bufs + tokens_per_dst...\n");
    CommPlanner planner;
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> routing = {
        {0}, {1}, {0},  // 3 tokens -> worker 0
        {2}, {3},       // 2 tokens -> worker 1
    };
    const auto plan = planner.launch_planning(routing, cfg);
    CHECK_EQ(plan.dispatch_bufs.size(), static_cast<std::size_t>(2));
    CHECK_EQ(plan.tokens_per_dst.size(), static_cast<std::size_t>(2));
    CHECK_EQ(plan.tokens_per_dst[0], static_cast<std::uint32_t>(3));
    CHECK_EQ(plan.tokens_per_dst[1], static_cast<std::uint32_t>(2));

    // dispatch_bufs[0] 的实际长度应 = 3 * hidden_dim * dtype_size
    // shape: hidden_dim=128, fp16 -> 2 bytes
    const std::uint64_t expected_actual_0 = 3ULL * 128ULL * 2ULL;
    CHECK_EQ(plan.dispatch_bufs[0].length, expected_actual_0);
    // 0 < max_tokens(64) -> 触发 zero_fill
    CHECK(plan.dispatch_bufs[0].zero_fill);
    // offset 1 跟随 offset 0 的 padded 长度
    CHECK_EQ(plan.dispatch_bufs[1].buffer_offset, plan.dispatch_bufs[0].padded_length);
}

// ============================================================================
// TEST 13: CommPlanner combine_bufs + zero_fill 正确
// ============================================================================

static void test_launch_planning_combine_bufs() {
    std::printf("[test] launch_planning combine_bufs + zero_fill...\n");
    CommPlanner planner;
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> routing = {
        {0}, {0},  // 2 tokens -> worker 0
        {2},       // 1 token -> worker 1
    };
    const auto plan = planner.launch_planning(routing, cfg);
    CHECK_EQ(plan.combine_bufs.size(), static_cast<std::size_t>(2));
    CHECK_EQ(plan.combine_bufs[0].length, 2ULL * 128ULL * 2ULL);
    CHECK_EQ(plan.combine_bufs[1].length, 1ULL * 128ULL * 2ULL);
    // worker 0 和 worker 1 都有 padding -> 2 个 zero_fill_range
    CHECK_EQ(plan.zero_fill_ranges.size(), static_cast<std::size_t>(2));
    // zero_fill 区间长度 = padded - actual
    const auto& r0 = plan.zero_fill_ranges[0];
    CHECK_EQ(r0.length, plan.combine_bufs[0].padded_length - plan.combine_bufs[0].length);
}

// ============================================================================
// TEST 14: CommPlanner load_imbalance_ratio 统计
// ============================================================================

static void test_launch_planning_load_stats() {
    std::printf("[test] launch_planning load stats...\n");
    CommPlanner planner;
    const auto cfg = make_config_2workers();
    // 完全均衡：每个专家 1 个 token
    std::vector<std::vector<std::uint32_t>> balanced = {{0}, {1}, {2}, {3}};
    const auto p1 = planner.launch_planning(balanced, cfg);
    CHECK_EQ(p1.max_tokens_per_expert, static_cast<std::uint32_t>(1));
    CHECK_EQ(p1.min_tokens_per_expert, static_cast<std::uint32_t>(1));
    CHECK(p1.load_balanced);
    CHECK(p1.load_imbalance_ratio < 1.01);

    // 不均衡：所有 token 都去专家 0
    std::vector<std::vector<std::uint32_t>> skewed = {{0}, {0}, {0}, {0}};
    const auto p2 = planner.launch_planning(skewed, cfg);
    CHECK_EQ(p2.max_tokens_per_expert, static_cast<std::uint32_t>(4));
    CHECK_EQ(p2.min_tokens_per_expert, static_cast<std::uint32_t>(0));
    CHECK(!p2.load_balanced);
    CHECK(p2.load_imbalance_ratio >= 4.0);
}

// ============================================================================
// TEST 15: CommPlanner sync_participants 去重
// ============================================================================

static void test_launch_planning_sync_participants() {
    std::printf("[test] launch_planning sync_participants dedup...\n");
    CommPlanner planner;
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> routing = {
        {0}, {1}, {0}, {1},  // 全部去 worker 0
    };
    const auto plan = planner.launch_planning(routing, cfg);
    // dst_nodes = [worker 0, worker 0, worker 0, worker 0]
    // sync_participants 去重后只有 1 个
    CHECK_EQ(plan.sync_participants.size(), static_cast<std::size_t>(1));
    CHECK_EQ(plan.sync_participants[0], static_cast<NodeId>(0x201));

    // 混合：worker 0 + worker 1
    std::vector<std::vector<std::uint32_t>> routing2 = {{0}, {2}, {1}, {3}};
    const auto plan2 = planner.launch_planning(routing2, cfg);
    CHECK_EQ(plan2.sync_participants.size(), static_cast<std::size_t>(2));
    std::unordered_set<NodeId> sp(plan2.sync_participants.begin(), plan2.sync_participants.end());
    CHECK(sp.count(0x201) == 1);
    CHECK(sp.count(0x202) == 1);
}

// ============================================================================
// TEST 16: CommPlanner try_cache 命中复用
// ============================================================================

static void test_try_cache_hit() {
    std::printf("[test] try_cache hit & reuse...\n");
    CommPlanner planner(4);
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> routing = {{0}, {2}, {1}, {3}};
    const auto plan1 = planner.launch_planning(routing, cfg);
    const auto plan1_id = plan1.plan_id;
    const auto rh = plan1.routing_hash;

    // 查缓存
    const auto cached = planner.try_cache(rh);
    CHECK(cached.has_value());
    CHECK_EQ(cached->plan_id, plan1_id);
    CHECK_EQ(cached->routing_hash, rh);

    // miss
    const auto miss = planner.try_cache(0xDEADBEEF);
    CHECK(!miss.has_value());
}

// ============================================================================
// TEST 17: CommPlanner cache 满后 LRU 淘汰
// ============================================================================

static void test_cache_eviction() {
    std::printf("[test] CommPlanner cache LRU eviction...\n");
    CommPlanner planner(2);  // 容量 2
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> r1 = {{0}};
    std::vector<std::vector<std::uint32_t>> r2 = {{1}};
    std::vector<std::vector<std::uint32_t>> r3 = {{2}};

    const auto p1 = planner.launch_planning(r1, cfg);
    const auto p2 = planner.launch_planning(r2, cfg);
    CHECK_EQ(planner.cache_size(), static_cast<std::size_t>(2));

    // 第三个 -> 第一个被淘汰
    const auto p3 = planner.launch_planning(r3, cfg);
    CHECK_EQ(planner.cache_size(), static_cast<std::size_t>(2));
    CHECK(!planner.try_cache(p1.routing_hash).has_value());
    CHECK(planner.try_cache(p2.routing_hash).has_value());
    CHECK(planner.try_cache(p3.routing_hash).has_value());
}

// ============================================================================
// TEST 18: CommPlanner 多帧规划 plan_id 递增
// ============================================================================

static void test_plan_id_monotonic() {
    std::printf("[test] plan_id monotonic increasing...\n");
    CommPlanner planner;
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> r = {{0}, {1}};
    const auto p1 = planner.launch_planning(r, cfg);
    const auto p2 = planner.launch_planning(r, cfg);
    const auto p3 = planner.launch_planning(r, cfg);
    CHECK(p2.plan_id > p1.plan_id);
    CHECK(p3.plan_id > p2.plan_id);
    // sync_id 也递增
    CHECK(p2.sync_id > p1.sync_id);
    CHECK(p3.sync_id > p2.sync_id);
}

// ============================================================================
// TEST 19: CommPlanner routing 为空抛异常
// ============================================================================

static void test_launch_planning_empty_routing() {
    std::printf("[test] launch_planning empty routing -> exception...\n");
    CommPlanner planner;
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> bad = {{0}, {}, {1}};  // token 1 为空
    bool caught = false;
    try { (void)planner.launch_planning(bad, cfg); }
    catch (const std::invalid_argument&) { caught = true; }
    CHECK(caught);
}

// ============================================================================
// TEST 20: CommPlanner expert 越界抛异常
// ============================================================================

static void test_launch_planning_expert_oob() {
    std::printf("[test] launch_planning expert OOB -> exception...\n");
    CommPlanner planner;
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> bad = {{0}, {99}};  // 99 >= 4
    bool caught = false;
    try { (void)planner.launch_planning(bad, cfg); }
    catch (const std::invalid_argument&) { caught = true; }
    CHECK(caught);
}

// ============================================================================
// TEST 21: CommPlanner invalid config 抛异常
// ============================================================================

static void test_launch_planning_invalid_config() {
    std::printf("[test] launch_planning invalid config -> exception...\n");
    CommPlanner planner;
    EpGroupConfig bad = make_config_2workers();
    bad.ep_workers.clear();
    bad.expert_placement.clear();
    std::vector<std::vector<std::uint32_t>> r = {{0}};
    bool caught = false;
    try { (void)planner.launch_planning(r, bad); }
    catch (const std::invalid_argument&) { caught = true; }
    CHECK(caught);
}

// ============================================================================
// TEST 22: serialize/deserialize round-trip
// ============================================================================

static void test_serialize_roundtrip() {
    std::printf("[test] serialize/deserialize round-trip...\n");
    CommPlanner planner;
    const auto cfg = make_config_4workers();
    std::vector<std::vector<std::uint32_t>> routing = {
        {0}, {1}, {2}, {3}, {0}, {1},  // 6 tokens, 各专家 1-2 个
    };
    const auto plan = planner.launch_planning(routing, cfg);
    const auto bytes = CommPlanner::serialize(plan);
    CHECK(!bytes.empty());

    // magic 头部（little-endian of 0x45434D50 = 'E','C','M','P'）
    // LE 写入: byte0=0x50='P', byte1=0x4D='M', byte2=0x43='C', byte3=0x45='E'
    CHECK_EQ(bytes[0], static_cast<std::uint8_t>('P'));
    CHECK_EQ(bytes[1], static_cast<std::uint8_t>('M'));
    CHECK_EQ(bytes[2], static_cast<std::uint8_t>('C'));
    CHECK_EQ(bytes[3], static_cast<std::uint8_t>('E'));

    EpCommPlan out;
    const bool ok = CommPlanner::deserialize(bytes, out);
    CHECK(ok);
    CHECK_EQ(out.plan_id, plan.plan_id);
    CHECK_EQ(out.routing_hash, plan.routing_hash);
    CHECK_EQ(out.sync_id, plan.sync_id);
    CHECK_EQ(out.total_tokens, plan.total_tokens);
    CHECK_EQ(out.max_tokens_per_expert, plan.max_tokens_per_expert);
    CHECK_EQ(out.min_tokens_per_expert, plan.min_tokens_per_expert);
    CHECK_EQ(out.load_balanced, plan.load_balanced);
    CHECK_EQ(out.dst_nodes.size(), plan.dst_nodes.size());
    CHECK_EQ(out.expert_ids.size(), plan.expert_ids.size());
    CHECK_EQ(out.dispatch_bufs.size(), plan.dispatch_bufs.size());
    CHECK_EQ(out.combine_bufs.size(), plan.combine_bufs.size());
    CHECK_EQ(out.tokens_per_dst.size(), plan.tokens_per_dst.size());
    CHECK_EQ(out.zero_fill_ranges.size(), plan.zero_fill_ranges.size());
    CHECK_EQ(out.sync_participants.size(), plan.sync_participants.size());

    // 详细字段对比
    for (std::size_t i = 0; i < plan.dst_nodes.size(); ++i) {
        CHECK_EQ(out.dst_nodes[i], plan.dst_nodes[i]);
    }
    for (std::size_t i = 0; i < plan.expert_ids.size(); ++i) {
        CHECK_EQ(out.expert_ids[i], plan.expert_ids[i]);
    }
    for (std::size_t i = 0; i < plan.dispatch_bufs.size(); ++i) {
        CHECK_EQ(out.dispatch_bufs[i].buffer_offset, plan.dispatch_bufs[i].buffer_offset);
        CHECK_EQ(out.dispatch_bufs[i].length, plan.dispatch_bufs[i].length);
        CHECK_EQ(out.dispatch_bufs[i].padded_length, plan.dispatch_bufs[i].padded_length);
        CHECK_EQ(out.dispatch_bufs[i].zero_fill, plan.dispatch_bufs[i].zero_fill);
    }
    CHECK_EQ(out.shape.max_tokens, plan.shape.max_tokens);
    CHECK_EQ(out.shape.hidden_dim, plan.shape.hidden_dim);
    CHECK_EQ(out.shape.expert_count, plan.shape.expert_count);
    CHECK(out.shape.dtype == plan.shape.dtype);
}

// ============================================================================
// TEST 23: serialize magic 错误检测
// ============================================================================

static void test_serialize_bad_magic() {
    std::printf("[test] serialize bad magic -> reject...\n");
    CommPlanner planner;
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> r = {{0}};
    const auto plan = planner.launch_planning(r, cfg);
    auto bytes = CommPlanner::serialize(plan);
    // 篡改 magic
    bytes[0] = 'X';
    EpCommPlan out;
    const bool ok = CommPlanner::deserialize(bytes, out);
    CHECK(!ok);
}

// ============================================================================
// TEST 24: serialize 截断数据检测
// ============================================================================

static void test_serialize_truncated() {
    std::printf("[test] serialize truncated -> reject...\n");
    CommPlanner planner;
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> r = {{0}, {1}, {2}, {3}};
    const auto plan = planner.launch_planning(r, cfg);
    const auto bytes = CommPlanner::serialize(plan);
    // 截断到一半
    const std::vector<std::uint8_t> half(bytes.begin(), bytes.begin() + bytes.size() / 2);
    EpCommPlan out;
    const bool ok = CommPlanner::deserialize(half, out);
    CHECK(!ok);
}

// ============================================================================
// TEST 25: clear_cache + cache_size
// ============================================================================

static void test_clear_cache() {
    std::printf("[test] clear_cache...\n");
    CommPlanner planner(4);
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> r1 = {{0}};
    std::vector<std::vector<std::uint32_t>> r2 = {{1}};
    planner.launch_planning(r1, cfg);
    planner.launch_planning(r2, cfg);
    CHECK_EQ(planner.cache_size(), static_cast<std::size_t>(2));
    planner.clear_cache();
    CHECK_EQ(planner.cache_size(), static_cast<std::size_t>(0));
}

// ============================================================================
// TEST 26: 4 worker EP 真实场景
// ============================================================================

static void test_realistic_4workers() {
    std::printf("[test] realistic 4-worker EP scenario...\n");
    CommPlanner planner(8);
    const auto cfg = make_config_4workers();
    // 32 tokens, 每个 token 选 1 个专家（4 选 1）
    std::vector<std::vector<std::uint32_t>> routing;
    routing.reserve(32);
    for (int i = 0; i < 32; ++i) {
        routing.push_back({static_cast<std::uint32_t>(i % 4)});
    }
    const auto plan = planner.launch_planning(routing, cfg);
    CHECK_EQ(plan.dst_nodes.size(), static_cast<std::size_t>(32));
    CHECK_EQ(plan.total_tokens, static_cast<std::uint32_t>(32));
    // 完全均衡 -> load_balanced
    CHECK(plan.load_balanced);
    CHECK_EQ(plan.max_tokens_per_expert, static_cast<std::uint32_t>(8));
    CHECK_EQ(plan.min_tokens_per_expert, static_cast<std::uint32_t>(8));
    CHECK_EQ(plan.tokens_per_dst.size(), static_cast<std::size_t>(4));
    for (const auto n : plan.tokens_per_dst) {
        CHECK_EQ(n, static_cast<std::uint32_t>(8));
    }
    // 4 个不同的 dst -> 4 个 sync_participants
    CHECK_EQ(plan.sync_participants.size(), static_cast<std::size_t>(4));
}

// ============================================================================
// TEST 27: 并发 try_cache 线程安全
// ============================================================================

static void test_concurrent_try_cache() {
    std::printf("[test] concurrent try_cache thread safety...\n");
    CommPlanner planner(8);
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> r = {{0}, {2}, {1}, {3}};
    const auto plan = planner.launch_planning(r, cfg);
    const auto rh = plan.routing_hash;

    constexpr int N_THREADS = 8;
    constexpr int N_PER_THREAD = 200;
    std::atomic<int> hit_count{0};
    std::vector<std::thread> threads;
    threads.reserve(N_THREADS);
    for (int t = 0; t < N_THREADS; ++t) {
        threads.emplace_back([&planner, &hit_count, rh] {
            for (int i = 0; i < N_PER_THREAD; ++i) {
                const auto p = planner.try_cache(rh);
                if (p.has_value()) ++hit_count;
            }
        });
    }
    for (auto& th : threads) th.join();
    CHECK_EQ(hit_count.load(), N_THREADS * N_PER_THREAD);
    CHECK_EQ(planner.cache_hits(), static_cast<std::uint64_t>(N_THREADS * N_PER_THREAD));
}

// ============================================================================
// TEST 28: 容量 0 归一化
// ============================================================================

static void test_commplanner_capacity_zero() {
    std::printf("[test] CommPlanner capacity=0 normalization...\n");
    CommPlanner planner(0);
    CHECK_EQ(planner.cache_size(), static_cast<std::size_t>(0));
    const auto cfg = make_config_2workers();
    std::vector<std::vector<std::uint32_t>> r = {{0}};
    (void)planner.launch_planning(r, cfg);
    CHECK_EQ(planner.cache_size(), static_cast<std::size_t>(1));  // 归一为 1
}

// ============================================================================
// 主入口
// ============================================================================

int main() {
    std::printf("=== test_comm_planner_v1604 ===\n");
    std::printf("EP online CommPlanner + LRUHashCache + serialize\n\n");

    test_compute_routing_hash_consistency();
    test_build_expert_to_node_map();
    test_lru_basic_insert_lookup();
    test_lru_eviction();
    test_lru_capacity_zero();
    test_lru_capacity_one();
    test_lru_clear();
    test_lru_hit_rate();
    test_lru_move_to_front();
    test_epgroup_config_valid();
    test_launch_planning_basic();
    test_launch_planning_dispatch_bufs();
    test_launch_planning_combine_bufs();
    test_launch_planning_load_stats();
    test_launch_planning_sync_participants();
    test_try_cache_hit();
    test_cache_eviction();
    test_plan_id_monotonic();
    test_launch_planning_empty_routing();
    test_launch_planning_expert_oob();
    test_launch_planning_invalid_config();
    test_serialize_roundtrip();
    test_serialize_bad_magic();
    test_serialize_truncated();
    test_clear_cache();
    test_realistic_4workers();
    test_concurrent_try_cache();
    test_commplanner_capacity_zero();

    std::printf("\n=== SUMMARY ===\n");
    std::printf("PASS: %d\n", g_pass);
    std::printf("FAIL: %d\n", g_fail);
    if (g_fail == 0) {
        std::printf("ALL TESTS PASSED\n");
        return 0;
    }
    std::printf("SOME TESTS FAILED\n");
    return 1;
}
