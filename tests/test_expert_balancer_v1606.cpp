// test_expert_balancer_v1606.cpp - P5 负载均衡与冗余专家单元测试 (v1.6.0.6)
//
// 覆盖：
//   - ExpertAssignment 默认/valid
//   - ExpertBalancer 构造与配置（threshold get/set）
//   - 贪心最佳适应策略（基础均衡 / 热门复制到最轻节点）
//   - 轮询复制策略
//   - 最轻负载优先策略
//   - 零冗余场景（num_redundant=0）
//   - 极端不均场景（1 专家占 90% token）
//   - 完全均匀场景
//   - 单节点场景
//   - 阈值调整（balanced 判定）
//   - compute_imbalance_ratio 静态方法
//   - stats 统计 + reset_stats
//   - 参数校验（invalid_argument）
//   - 三种策略对比
//   - CommPlanner 集成（num_redundant_experts > 0 时 plan 含 redundant_experts）
//   - EpCommPlan 序列化 round-trip（含 P5 字段）

#include "linoh/multimodal/expert_balancer.hpp"
#include "linoh/multimodal/comm_planner.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::cerr << "FAIL: " #cond \
        << " @ line " << __LINE__ << std::endl; } \
} while(0)

#define CHECK_EQ(a, b) do { \
    if ((a) == (b)) { ++g_pass; } \
    else { ++g_fail; std::cerr << "FAIL: " #a " == " #b \
        << " (got " << (a) << " vs " << (b) << ")" \
        << " @ line " << __LINE__ << std::endl; } \
} while(0)

#define CHECK_THROW(expr) do { \
    bool thrown = false; \
    try { (expr); } \
    catch (const std::invalid_argument&) { thrown = true; } \
    catch (...) { } \
    if (thrown) { ++g_pass; } \
    else { ++g_fail; std::cerr << "FAIL: " #expr " did not throw invalid_argument" \
        << " @ line " << __LINE__ << std::endl; } \
} while(0)

using namespace linoh::multimodal::ep;

// ============================================================================
// ExpertAssignment 默认/valid
// ============================================================================

void test_assignment_default() {
    ExpertAssignment a;
    CHECK_EQ(a.num_original, 0u);
    CHECK_EQ(a.num_redundant, 0u);
    CHECK_EQ(a.num_nodes, 0u);
    CHECK(!a.valid());
    CHECK_EQ(a.imbalance_ratio, 1.0);
    CHECK(!a.balanced);
}

void test_assignment_valid() {
    ExpertAssignment a;
    a.expert_to_node = {0, 1, 0, 1};
    a.redundant_experts = {0, 2};
    a.tokens_per_node = {10, 8};
    a.num_original = 2;
    a.num_redundant = 2;
    a.num_nodes = 2;
    CHECK(a.valid());
}

// ============================================================================
// ExpertBalancer 构造与配置
// ============================================================================

void test_balancer_default_threshold() {
    ExpertBalancer b;
    CHECK_EQ(b.balanced_threshold(), ExpertBalancer::kDefaultThreshold);
}

void test_balancer_custom_threshold() {
    ExpertBalancer b(1.2);
    CHECK_EQ(b.balanced_threshold(), 1.2);
}

void test_balancer_threshold_invalid_falls_back() {
    ExpertBalancer b(0.5);  // <= 1.0 should fall back to default
    CHECK_EQ(b.balanced_threshold(), ExpertBalancer::kDefaultThreshold);
}

void test_balancer_set_threshold() {
    ExpertBalancer b;
    b.set_balanced_threshold(1.1);
    CHECK_EQ(b.balanced_threshold(), 1.1);
    b.set_balanced_threshold(0.9);  // invalid, ignored
    CHECK_EQ(b.balanced_threshold(), 1.1);
}

// ============================================================================
// 贪心最佳适应策略
// ============================================================================

void test_greedy_basic() {
    // 6 experts, 3 nodes, 2 redundant
    // tokens_per_expert = [100, 80, 60, 40, 20, 10]
    // base_assignment   = [0, 0, 1, 1, 2, 2]  (每节点 2 专家)
    // 原始负载: 节点0=180, 节点1=100, 节点2=30
    // 贪心动态选最轻节点：
    //   第1次冗余 expert0(100) -> 节点2(30) -> 节点2=130
    //   第2次冗余 expert1(80)  -> 节点1(100) -> 节点1=180  (现在节点1是最轻)
    std::vector<std::uint32_t> tokens = {100, 80, 60, 40, 20, 10};
    std::vector<NodeId> base = {0, 0, 1, 1, 2, 2};

    ExpertBalancer b;
    auto a = b.balance(tokens, base, 3, 2, BalanceStrategy::GREEDY_BEST_FIT);

    CHECK(a.valid());
    CHECK_EQ(a.num_original, 6u);
    CHECK_EQ(a.num_redundant, 2u);
    CHECK_EQ(a.num_nodes, 3u);
    CHECK_EQ(a.expert_to_node.size(), 8u);
    CHECK_EQ(a.redundant_experts.size(), 2u);
    // 冗余专家应是 0 和 1（最热门的两个）
    CHECK_EQ(a.redundant_experts[0], 0u);
    CHECK_EQ(a.redundant_experts[1], 1u);
    // 动态最轻节点选择
    CHECK_EQ(a.expert_to_node[6], 2u);  // expert 0 副本 -> 节点 2 (原始最轻)
    CHECK_EQ(a.expert_to_node[7], 1u);  // expert 1 副本 -> 节点 1 (动态最轻)
    // tokens_per_node: 节点0=180, 节点1=100+80=180, 节点2=30+100=130
    CHECK_EQ(a.tokens_per_node.size(), 3u);
    CHECK_EQ(a.tokens_per_node[0], 180u);
    CHECK_EQ(a.tokens_per_node[1], 180u);
    CHECK_EQ(a.tokens_per_node[2], 130u);
}

void test_greedy_improves_balance() {
    // 极端不均：1 个专家占 90% token
    std::vector<std::uint32_t> tokens = {900, 10, 10, 10, 10, 10};
    std::vector<NodeId> base = {0, 0, 1, 1, 2, 2};
    // 无冗余：节点0=910, 节点1=20, 节点2=20, ratio=45.5
    // 加 3 个冗余：应复制 expert 0 到节点 1/2，大幅改善

    ExpertBalancer b;
    auto a = b.balance(tokens, base, 3, 3, BalanceStrategy::GREEDY_BEST_FIT);

    // 无冗余 ratio
    std::vector<std::uint32_t> base_load = {910, 20, 20};
    double base_ratio = ExpertBalancer::compute_imbalance_ratio(base_load);
    CHECK(base_ratio > 40.0);
    // 有冗余后 ratio 应显著改善
    CHECK(a.imbalance_ratio < base_ratio);
    // expert 0 应被复制到节点 1 或 2
    bool expert0_redundant = (a.redundant_experts[0] == 0);
    CHECK(expert0_redundant);
}

void test_greedy_zero_redundant() {
    std::vector<std::uint32_t> tokens = {50, 30, 20};
    std::vector<NodeId> base = {0, 1, 2};

    ExpertBalancer b;
    auto a = b.balance(tokens, base, 3, 0, BalanceStrategy::GREEDY_BEST_FIT);

    CHECK_EQ(a.num_redundant, 0u);
    CHECK(a.redundant_experts.empty());
    CHECK_EQ(a.expert_to_node.size(), base.size());
    for (std::size_t i = 0; i < base.size(); ++i) {
        CHECK_EQ(a.expert_to_node[i], base[i]);
    }
    CHECK_EQ(a.tokens_per_node.size(), 3u);
    CHECK_EQ(a.tokens_per_node[0], 50u);
    CHECK_EQ(a.tokens_per_node[1], 30u);
    CHECK_EQ(a.tokens_per_node[2], 20u);
    double ratio = static_cast<double>(50) / 20;
    CHECK_EQ(a.imbalance_ratio, ratio);
}

void test_greedy_perfectly_balanced_input() {
    // 完全均匀：3 节点每节点 2 专家各 50 token
    // 加冗余反而会打破均衡（最轻节点接收冗余后变重）
    std::vector<std::uint32_t> tokens = {50, 50, 50, 50, 50, 50};
    std::vector<NodeId> base = {0, 0, 1, 1, 2, 2};

    ExpertBalancer b;
    auto a = b.balance(tokens, base, 3, 2, BalanceStrategy::GREEDY_BEST_FIT);

    // 完全均匀时，冗余会让接收节点变重，ratio=1.5（150/100）
    CHECK(a.imbalance_ratio > 1.0);
    CHECK(!a.balanced);  // 1.5 > 1.05
}

void test_greedy_single_node() {
    std::vector<std::uint32_t> tokens = {100, 50, 30};
    std::vector<NodeId> base = {0, 0, 0};

    ExpertBalancer b;
    auto a = b.balance(tokens, base, 1, 2, BalanceStrategy::GREEDY_BEST_FIT);

    CHECK_EQ(a.num_nodes, 1u);
    CHECK_EQ(a.expert_to_node[3], 0u);
    CHECK_EQ(a.expert_to_node[4], 0u);
    CHECK_EQ(a.tokens_per_node.size(), 1u);
    // 原始 180 + 冗余 expert0(100) + expert1(50) = 330
    CHECK_EQ(a.tokens_per_node[0], 330u);
}

// ============================================================================
// 轮询复制策略
// ============================================================================

void test_round_robin_basic() {
    std::vector<std::uint32_t> tokens = {100, 80, 60, 40, 20, 10};
    std::vector<NodeId> base = {0, 0, 1, 1, 2, 2};

    ExpertBalancer b;
    auto a = b.balance(tokens, base, 3, 3, BalanceStrategy::ROUND_ROBIN_REPL);

    CHECK(a.valid());
    CHECK_EQ(a.redundant_experts.size(), 3u);
    // 轮询分配：冗余 0->node0, 1->node1, 2->node2
    CHECK_EQ(a.expert_to_node[6], 0u);
    CHECK_EQ(a.expert_to_node[7], 1u);
    CHECK_EQ(a.expert_to_node[8], 2u);
    // 冗余专家按热门排序：0, 1, 2
    CHECK_EQ(a.redundant_experts[0], 0u);
    CHECK_EQ(a.redundant_experts[1], 1u);
    CHECK_EQ(a.redundant_experts[2], 2u);
}

void test_round_robin_more_redundant_than_nodes() {
    std::vector<std::uint32_t> tokens = {100, 80, 60};
    std::vector<NodeId> base = {0, 1, 2};

    ExpertBalancer b;
    auto a = b.balance(tokens, base, 3, 6, BalanceStrategy::ROUND_ROBIN_REPL);

    CHECK_EQ(a.expert_to_node.size(), 9u);
    // 轮询：i=0->node0, i=1->node1, i=2->node2, i=3->node0, i=4->node1, i=5->node2
    CHECK_EQ(a.expert_to_node[3], 0u);
    CHECK_EQ(a.expert_to_node[4], 1u);
    CHECK_EQ(a.expert_to_node[5], 2u);
    CHECK_EQ(a.expert_to_node[6], 0u);
    CHECK_EQ(a.expert_to_node[7], 1u);
    CHECK_EQ(a.expert_to_node[8], 2u);
}

// ============================================================================
// 最轻负载优先策略
// ============================================================================

void test_least_loaded_basic() {
    std::vector<std::uint32_t> tokens = {100, 80, 60, 40, 20, 10};
    std::vector<NodeId> base = {0, 0, 1, 1, 2, 2};
    // 原始负载：节点0=180, 节点1=100, 节点2=30
    // 最轻优先：节点2(30) < 节点1(100) < 节点0(180)
    // 冗余 0 -> 节点2, 冗余 1 -> 节点1

    ExpertBalancer b;
    auto a = b.balance(tokens, base, 3, 2, BalanceStrategy::LEAST_LOADED_FIRST);

    CHECK(a.valid());
    CHECK_EQ(a.redundant_experts[0], 0u);  // 最热门
    CHECK_EQ(a.redundant_experts[1], 1u);
    CHECK_EQ(a.expert_to_node[6], 2u);  // 最轻节点
    CHECK_EQ(a.expert_to_node[7], 1u);  // 次轻节点
}

// ============================================================================
// 三种策略对比
// ============================================================================

void test_strategy_comparison() {
    std::vector<std::uint32_t> tokens = {100, 80, 60, 40, 20, 10};
    std::vector<NodeId> base = {0, 0, 1, 1, 2, 2};

    ExpertBalancer b;
    auto greedy = b.balance(tokens, base, 3, 3, BalanceStrategy::GREEDY_BEST_FIT);
    auto rr = b.balance(tokens, base, 3, 3, BalanceStrategy::ROUND_ROBIN_REPL);
    auto ll = b.balance(tokens, base, 3, 3, BalanceStrategy::LEAST_LOADED_FIRST);

    // 所有策略都应改善均衡（相比无冗余）
    std::vector<std::uint32_t> base_load = {180, 100, 30};
    double base_ratio = ExpertBalancer::compute_imbalance_ratio(base_load);
    CHECK(greedy.imbalance_ratio < base_ratio);
    CHECK(rr.imbalance_ratio < base_ratio);
    CHECK(ll.imbalance_ratio < base_ratio);

    // 贪心应产生最优或同等最优的均衡
    CHECK(greedy.imbalance_ratio <= rr.imbalance_ratio + 0.01);
    CHECK(greedy.imbalance_ratio <= ll.imbalance_ratio + 0.01);
}

// ============================================================================
// compute_imbalance_ratio 静态方法
// ============================================================================

void test_compute_imbalance_ratio_empty() {
    std::vector<std::uint32_t> empty;
    CHECK_EQ(ExpertBalancer::compute_imbalance_ratio(empty), 1.0);
}

void test_compute_imbalance_ratio_uniform() {
    std::vector<std::uint32_t> v = {50, 50, 50};
    CHECK_EQ(ExpertBalancer::compute_imbalance_ratio(v), 1.0);
}

void test_compute_imbalance_ratio_skewed() {
    std::vector<std::uint32_t> v = {100, 50, 10};
    CHECK_EQ(ExpertBalancer::compute_imbalance_ratio(v), 10.0);
}

void test_compute_imbalance_ratio_with_zero() {
    std::vector<std::uint32_t> v = {100, 0, 50};
    double r = ExpertBalancer::compute_imbalance_ratio(v);
    CHECK(r == std::numeric_limits<double>::infinity());
}

void test_compute_imbalance_ratio_all_zero() {
    std::vector<std::uint32_t> v = {0, 0, 0};
    CHECK_EQ(ExpertBalancer::compute_imbalance_ratio(v), 1.0);
}

// ============================================================================
// 阈值与 balanced 判定
// ============================================================================

void test_balanced_flag_default_threshold() {
    // ratio=1.0 -> balanced
    std::vector<std::uint32_t> tokens = {50, 50, 50, 50};
    std::vector<NodeId> base = {0, 0, 1, 1};
    ExpertBalancer b;
    auto a = b.balance(tokens, base, 2, 0);
    CHECK(a.balanced);
    CHECK_EQ(a.imbalance_ratio, 1.0);
}

void test_balanced_flag_above_threshold() {
    // ratio=2.0 -> not balanced (default threshold 1.05)
    std::vector<std::uint32_t> tokens = {100, 50, 50, 50};
    std::vector<NodeId> base = {0, 0, 1, 1};
    ExpertBalancer b;
    auto a = b.balance(tokens, base, 2, 0);
    CHECK(!a.balanced);
    CHECK(a.imbalance_ratio > 1.05);
}

void test_balanced_flag_custom_threshold() {
    // ratio=2.0, threshold=3.0 -> balanced
    std::vector<std::uint32_t> tokens = {100, 50, 50, 50};
    std::vector<NodeId> base = {0, 0, 1, 1};
    ExpertBalancer b(3.0);
    auto a = b.balance(tokens, base, 2, 0);
    CHECK(a.balanced);
    CHECK(a.imbalance_ratio <= 3.0);
}

// ============================================================================
// stats 统计
// ============================================================================

void test_stats_initial() {
    ExpertBalancer b;
    auto s = b.stats();
    CHECK_EQ(s.balance_calls, 0u);
    CHECK_EQ(s.balanced_count, 0u);
    CHECK_EQ(s.unbalanced_count, 0u);
    CHECK_EQ(s.total_redundant_used, 0u);
}

void test_stats_after_calls() {
    ExpertBalancer b;
    // 用零冗余 + 完全均匀输入让 balanced=true
    std::vector<std::uint32_t> uniform = {50, 50, 50};
    std::vector<NodeId> base = {0, 1, 2};

    b.balance(uniform, base, 3, 0);  // balanced (ratio=1.0, no redundant)
    b.balance(uniform, base, 3, 0);  // balanced
    std::vector<std::uint32_t> skewed = {100, 10, 10};
    b.balance(skewed, base, 3, 0);  // unbalanced (ratio=10)

    auto s = b.stats();
    CHECK_EQ(s.balance_calls, 3u);
    CHECK_EQ(s.balanced_count, 2u);
    CHECK_EQ(s.unbalanced_count, 1u);
    CHECK_EQ(s.total_redundant_used, 0u);  // 全部 num_redundant=0
}

void test_stats_reset() {
    ExpertBalancer b;
    std::vector<std::uint32_t> tokens = {50, 50};
    std::vector<NodeId> base = {0, 1};
    b.balance(tokens, base, 2, 1);

    b.reset_stats();
    auto s = b.stats();
    CHECK_EQ(s.balance_calls, 0u);
    CHECK_EQ(s.total_redundant_used, 0u);
}

// ============================================================================
// 参数校验
// ============================================================================

void test_validate_empty_tokens() {
    ExpertBalancer b;
    std::vector<std::uint32_t> empty;
    std::vector<NodeId> base;
    CHECK_THROW(b.balance(empty, base, 1, 0));
}

void test_validate_mismatch_size() {
    ExpertBalancer b;
    std::vector<std::uint32_t> tokens = {10, 20};
    std::vector<NodeId> base = {0};  // size mismatch
    CHECK_THROW(b.balance(tokens, base, 1, 0));
}

void test_validate_zero_nodes() {
    ExpertBalancer b;
    std::vector<std::uint32_t> tokens = {10};
    std::vector<NodeId> base = {0};
    CHECK_THROW(b.balance(tokens, base, 0, 0));
}

void test_validate_node_id_out_of_range() {
    ExpertBalancer b;
    std::vector<std::uint32_t> tokens = {10, 20};
    std::vector<NodeId> base = {0, 5};  // 5 >= num_nodes=2
    CHECK_THROW(b.balance(tokens, base, 2, 0));
}

// ============================================================================
// CommPlanner 集成测试
// ============================================================================

ShapeDescriptor make_test_shape() {
    ShapeDescriptor s;
    s.dtype = static_cast<linoh::multimodal::TensorDType>(1);  // BF16
    s.max_tokens = 128;
    s.hidden_dim = 1024;
    s.expert_count = 6;
    return s;
}

EpGroupConfig make_test_config(std::uint32_t num_redundant = 0,
                                std::uint8_t strategy = 0) {
    EpGroupConfig c;
    c.ep_master = 0;
    c.ep_workers = {1, 2, 3};
    c.expert_placement = {{0, 1}, {2, 3}, {4, 5}};
    c.num_experts = 6;
    c.topk = 1;
    c.shape = make_test_shape();
    c.num_redundant_experts = num_redundant;
    c.balance_strategy = strategy;
    return c;
}

void test_commplanner_no_redundant() {
    // num_redundant_experts=0 -> plan.redundant_experts 为空
    CommPlanner planner;
    auto config = make_test_config(0);
    std::vector<std::vector<std::uint32_t>> routing = {{0}, {1}, {2}, {3}, {4}, {5}};
    auto plan = planner.launch_planning(routing, config);

    CHECK(plan.redundant_experts.empty());
    CHECK_EQ(plan.num_redundant, 0u);
}

void test_commplanner_with_redundant() {
    // num_redundant_experts=2 -> plan.redundant_experts 有 2 项
    CommPlanner planner;
    auto config = make_test_config(2);
    // 极端不均路由：expert 0 被选 100 次，其他各 1 次
    std::vector<std::vector<std::uint32_t>> routing;
    for (int i = 0; i < 100; ++i) routing.push_back({0});
    for (int e = 1; e < 6; ++e) routing.push_back({static_cast<std::uint32_t>(e)});

    auto plan = planner.launch_planning(routing, config);

    CHECK_EQ(plan.num_redundant, 2u);
    CHECK_EQ(plan.redundant_experts.size(), 2u);
    // 最热门 expert 0 应在 redundant_experts 中
    bool has_expert0 = false;
    for (auto e : plan.redundant_experts) {
        if (e == 0) has_expert0 = true;
    }
    CHECK(has_expert0);
}

void test_commplanner_balance_strategy_field() {
    // 验证 balance_strategy 字段能正确传递
    CommPlanner planner;
    auto config = make_test_config(1, 2);  // LEAST_LOADED_FIRST
    std::vector<std::vector<std::uint32_t>> routing = {{0}, {1}, {2}};
    auto plan = planner.launch_planning(routing, config);
    CHECK_EQ(plan.num_redundant, 1u);
}

// ============================================================================
// EpCommPlan 序列化 round-trip（含 P5 字段）
// ============================================================================

void test_serialize_roundtrip_with_redundant() {
    CommPlanner planner;
    auto config = make_test_config(2);
    std::vector<std::vector<std::uint32_t>> routing;
    for (int i = 0; i < 50; ++i) routing.push_back({0});
    for (int e = 1; e < 6; ++e) routing.push_back({static_cast<std::uint32_t>(e)});

    auto plan = planner.launch_planning(routing, config);
    CHECK_EQ(plan.num_redundant, 2u);

    auto bytes = CommPlanner::serialize(plan);
    EpCommPlan decoded;
    bool ok = CommPlanner::deserialize(bytes, decoded);
    CHECK(ok);

    CHECK_EQ(decoded.num_redundant, plan.num_redundant);
    CHECK_EQ(decoded.redundant_experts.size(), plan.redundant_experts.size());
    for (std::size_t i = 0; i < plan.redundant_experts.size(); ++i) {
        CHECK_EQ(decoded.redundant_experts[i], plan.redundant_experts[i]);
    }
    CHECK_EQ(decoded.load_imbalance_ratio, plan.load_imbalance_ratio);
    CHECK_EQ(decoded.load_balanced, plan.load_balanced);
}

void test_serialize_roundtrip_without_redundant() {
    // num_redundant=0 -> P5 字段为默认值，round-trip 应保持
    CommPlanner planner;
    auto config = make_test_config(0);
    std::vector<std::vector<std::uint32_t>> routing = {{0}, {1}, {2}};

    auto plan = planner.launch_planning(routing, config);
    CHECK_EQ(plan.num_redundant, 0u);

    auto bytes = CommPlanner::serialize(plan);
    EpCommPlan decoded;
    bool ok = CommPlanner::deserialize(bytes, decoded);
    CHECK(ok);
    CHECK_EQ(decoded.num_redundant, 0u);
    CHECK(decoded.redundant_experts.empty());
}

// ============================================================================
// Main
// ============================================================================

int test_main() {
    // ExpertAssignment
    test_assignment_default();
    test_assignment_valid();

    // Constructor / config
    test_balancer_default_threshold();
    test_balancer_custom_threshold();
    test_balancer_threshold_invalid_falls_back();
    test_balancer_set_threshold();

    // Greedy
    test_greedy_basic();
    test_greedy_improves_balance();
    test_greedy_zero_redundant();
    test_greedy_perfectly_balanced_input();
    test_greedy_single_node();

    // Round robin
    test_round_robin_basic();
    test_round_robin_more_redundant_than_nodes();

    // Least loaded
    test_least_loaded_basic();

    // Strategy comparison
    test_strategy_comparison();

    // compute_imbalance_ratio
    test_compute_imbalance_ratio_empty();
    test_compute_imbalance_ratio_uniform();
    test_compute_imbalance_ratio_skewed();
    test_compute_imbalance_ratio_with_zero();
    test_compute_imbalance_ratio_all_zero();

    // balanced flag
    test_balanced_flag_default_threshold();
    test_balanced_flag_above_threshold();
    test_balanced_flag_custom_threshold();

    // stats
    test_stats_initial();
    test_stats_after_calls();
    test_stats_reset();

    // validation
    test_validate_empty_tokens();
    test_validate_mismatch_size();
    test_validate_zero_nodes();
    test_validate_node_id_out_of_range();

    // CommPlanner integration
    test_commplanner_no_redundant();
    test_commplanner_with_redundant();
    test_commplanner_balance_strategy_field();

    // Serialize round-trip
    test_serialize_roundtrip_with_redundant();
    test_serialize_roundtrip_without_redundant();

    std::cout << "=== Results: " << g_pass << " PASS, "
              << g_fail << " FAIL ===" << std::endl;
    return g_fail == 0 ? 0 : 1;
}

}  // anonymous namespace

int main() {
    return test_main();
}
