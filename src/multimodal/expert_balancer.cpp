// expert_balancer.cpp - EP 负载均衡与冗余专家调度实现（v1.6.0.6 / P5）

#include "linoh/multimodal/expert_balancer.hpp"

#include <algorithm>
#include <numeric>
#include <stdexcept>

namespace linoh::multimodal::ep {

// ============================================================================
// 构造与配置
// ============================================================================

ExpertBalancer::ExpertBalancer(double balanced_threshold)
    : threshold_(balanced_threshold <= 1.0 ? kDefaultThreshold : balanced_threshold) {}

double ExpertBalancer::balanced_threshold() const noexcept {
    return threshold_;
}

void ExpertBalancer::set_balanced_threshold(double t) noexcept {
    if (t > 1.0) {
        threshold_ = t;
    }
}

// ============================================================================
// 公共 API
// ============================================================================

ExpertAssignment ExpertBalancer::balance(
    const std::vector<std::uint32_t>& tokens_per_expert,
    const std::vector<NodeId>& base_assignment,
    std::uint32_t num_nodes,
    std::uint32_t num_redundant,
    BalanceStrategy strategy) {
    validate_inputs_(tokens_per_expert, base_assignment, num_nodes, num_redundant);

    ExpertAssignment result;
    switch (strategy) {
        case BalanceStrategy::GREEDY_BEST_FIT:
            result = balance_greedy_(tokens_per_expert, base_assignment,
                                     num_nodes, num_redundant);
            break;
        case BalanceStrategy::ROUND_ROBIN_REPL:
            result = balance_round_robin_(tokens_per_expert, base_assignment,
                                          num_nodes, num_redundant);
            break;
        case BalanceStrategy::LEAST_LOADED_FIRST:
            result = balance_least_loaded_(tokens_per_expert, base_assignment,
                                           num_nodes, num_redundant);
            break;
        default:
            result = balance_greedy_(tokens_per_expert, base_assignment,
                                     num_nodes, num_redundant);
            break;
    }

    finalize_assignment_(result, tokens_per_expert);

    // 更新统计
    ++stats_.balance_calls;
    stats_.total_redundant_used += num_redundant;
    if (result.balanced) {
        ++stats_.balanced_count;
    } else {
        ++stats_.unbalanced_count;
    }

    return result;
}

double ExpertBalancer::compute_imbalance_ratio(
    const std::vector<std::uint32_t>& tokens_per_node) noexcept {
    if (tokens_per_node.empty()) return 1.0;
    auto it_min = std::min_element(tokens_per_node.begin(), tokens_per_node.end());
    auto it_max = std::max_element(tokens_per_node.begin(), tokens_per_node.end());
    if (*it_min == 0) {
        return *it_max == 0 ? 1.0 : std::numeric_limits<double>::infinity();
    }
    return static_cast<double>(*it_max) / static_cast<double>(*it_min);
}

const ExpertBalancer::Stats& ExpertBalancer::stats() const noexcept {
    return stats_;
}

void ExpertBalancer::reset_stats() noexcept {
    stats_ = Stats{};
}

// ============================================================================
// 私有：贪心最佳适应
// 每轮选最热门专家，复制到当前最轻节点的冗余槽
// ============================================================================

ExpertAssignment ExpertBalancer::balance_greedy_(
    const std::vector<std::uint32_t>& tokens_per_expert,
    const std::vector<NodeId>& base_assignment,
    std::uint32_t num_nodes,
    std::uint32_t num_redundant) {

    const std::uint32_t E = static_cast<std::uint32_t>(tokens_per_expert.size());

    ExpertAssignment result;
    result.num_original = E;
    result.num_redundant = num_redundant;
    result.num_nodes = num_nodes;
    result.expert_to_node = base_assignment;  // 前 E 个
    result.expert_to_node.resize(E + num_redundant);
    result.redundant_experts.reserve(num_redundant);

    // 按专家 token 数降序排序（热门优先）
    std::vector<std::uint32_t> sorted_experts(E);
    std::iota(sorted_experts.begin(), sorted_experts.end(), 0);
    std::sort(sorted_experts.begin(), sorted_experts.end(),
              [&](std::uint32_t a, std::uint32_t b) {
                  return tokens_per_expert[a] > tokens_per_expert[b];
              });

    // 填充冗余槽：每轮选最热门专家复制到最轻节点
    for (std::uint32_t i = 0; i < num_redundant; ++i) {
        const std::uint32_t expert_id = sorted_experts[i % E];

        // 计算当前每节点 token 负载（含已填的冗余专家）
        // 注意：只遍历前 E+i 个（已确定的），避免访问未初始化的冗余槽
        std::vector<std::uint64_t> token_load(num_nodes, 0);
        for (std::uint32_t e = 0; e < E + i; ++e) {
            NodeId node = result.expert_to_node[e];
            if (node < num_nodes) {
                // 对冗余专家（e >= E），累加其复制源专家的 token 数
                std::uint32_t src_expert = (e < E) ? e : result.redundant_experts[e - E];
                token_load[node] += tokens_per_expert[src_expert];
            }
        }

        auto min_it = std::min_element(token_load.begin(), token_load.end());
        NodeId target_node = static_cast<NodeId>(std::distance(token_load.begin(), min_it));

        result.expert_to_node[E + i] = target_node;
        result.redundant_experts.push_back(expert_id);
    }

    return result;
}

// ============================================================================
// 私有：轮询复制
// 冗余专家按节点轮询分配（不考虑负载，简单均匀分布）
// ============================================================================

ExpertAssignment ExpertBalancer::balance_round_robin_(
    const std::vector<std::uint32_t>& tokens_per_expert,
    const std::vector<NodeId>& base_assignment,
    std::uint32_t num_nodes,
    std::uint32_t num_redundant) {

    const std::uint32_t E = static_cast<std::uint32_t>(tokens_per_expert.size());

    ExpertAssignment result;
    result.num_original = E;
    result.num_redundant = num_redundant;
    result.num_nodes = num_nodes;
    result.expert_to_node = base_assignment;
    result.expert_to_node.resize(E + num_redundant);
    result.redundant_experts.reserve(num_redundant);

    // 按专家 token 数降序排序（热门优先复制）
    std::vector<std::uint32_t> sorted_experts(E);
    std::iota(sorted_experts.begin(), sorted_experts.end(), 0);
    std::sort(sorted_experts.begin(), sorted_experts.end(),
              [&](std::uint32_t a, std::uint32_t b) {
                  return tokens_per_expert[a] > tokens_per_expert[b];
              });

    // mp-L5 (v1.7.0.8): ROUND_ROBIN_REPL 策略文档说明
    //   此策略按 token 数降序选择热门专家并轮询分配到各节点，**不考虑节点当前负载**。
    //   适用场景：节点 GPU 同构 + 显存均衡，如刚启动时所有节点负载相近。
    //   不适用场景：节点异构（不同 GPU 型号/显存）或负载已倾斜（某节点
    //   正在处理大 batch）。此时应使用 LEAST_LOAD 策略（见 plan_redundant_experts
    //   重载），按节点负载升序填充冗余专家到最轻节点。
    //   权衡：ROUND_ROBIN 实现简单、无锁、无状态依赖；LEAST_LOAD 更均衡但需
    //   周期性采集 node_load_metric（增加 RPC 开销 + 状态同步复杂度）。
    //   后续如需负载感知，可在此处增加 node_load 入参 + 改用 LEAST_LOAD 逻辑。
    //
    // 轮询分配到各节点（从节点 0 开始）
    for (std::uint32_t i = 0; i < num_redundant; ++i) {
        const std::uint32_t expert_id = sorted_experts[i % E];
        const NodeId target_node = static_cast<NodeId>(i % num_nodes);
        result.expert_to_node[E + i] = target_node;
        result.redundant_experts.push_back(expert_id);
    }

    return result;
}

// ============================================================================
// 私有：最轻负载优先
// 按节点负载升序填充冗余专家
// ============================================================================

ExpertAssignment ExpertBalancer::balance_least_loaded_(
    const std::vector<std::uint32_t>& tokens_per_expert,
    const std::vector<NodeId>& base_assignment,
    std::uint32_t num_nodes,
    std::uint32_t num_redundant) {

    const std::uint32_t E = static_cast<std::uint32_t>(tokens_per_expert.size());

    ExpertAssignment result;
    result.num_original = E;
    result.num_redundant = num_redundant;
    result.num_nodes = num_nodes;
    result.expert_to_node = base_assignment;
    result.expert_to_node.resize(E + num_redundant);
    result.redundant_experts.reserve(num_redundant);

    // 按专家 token 数降序排序
    std::vector<std::uint32_t> sorted_experts(E);
    std::iota(sorted_experts.begin(), sorted_experts.end(), 0);
    std::sort(sorted_experts.begin(), sorted_experts.end(),
              [&](std::uint32_t a, std::uint32_t b) {
                  return tokens_per_expert[a] > tokens_per_expert[b];
              });

    // 计算每节点原始 token 负载
    std::vector<std::uint64_t> token_load(num_nodes, 0);
    for (std::uint32_t e = 0; e < E; ++e) {
        NodeId node = base_assignment[e];
        if (node < num_nodes) {
            token_load[node] += tokens_per_expert[e];
        }
    }

    // 按负载升序排序节点索引
    std::vector<NodeId> node_order(num_nodes);
    std::iota(node_order.begin(), node_order.end(), 0);
    std::sort(node_order.begin(), node_order.end(),
              [&](NodeId a, NodeId b) {
                  return token_load[a] < token_load[b];
              });

    // 按节点负载升序填充冗余专家
    for (std::uint32_t i = 0; i < num_redundant; ++i) {
        const std::uint32_t expert_id = sorted_experts[i % E];
        const NodeId target_node = node_order[i % num_nodes];
        result.expert_to_node[E + i] = target_node;
        result.redundant_experts.push_back(expert_id);
        token_load[target_node] += tokens_per_expert[expert_id];
    }

    return result;
}

// ============================================================================
// 私有：通用收尾
// ============================================================================

void ExpertBalancer::finalize_assignment_(
    ExpertAssignment& assignment,
    const std::vector<std::uint32_t>& tokens_per_expert) const {

    const std::uint32_t E = assignment.num_original;
    const std::uint32_t R = assignment.num_nodes;

    // 计算每节点 token 数
    assignment.tokens_per_node.assign(R, 0);
    for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(assignment.expert_to_node.size()); ++i) {
        NodeId node = assignment.expert_to_node[i];
        if (node < R) {
            std::uint32_t src_expert = (i < E) ? i : assignment.redundant_experts[i - E];
            if (src_expert < tokens_per_expert.size()) {
                assignment.tokens_per_node[node] += tokens_per_expert[src_expert];
            }
        }
    }

    // 计算不均比率
    assignment.imbalance_ratio = compute_imbalance_ratio(assignment.tokens_per_node);
    assignment.balanced = (assignment.imbalance_ratio <= threshold_);
}

// ============================================================================
// 私有：参数校验
// ============================================================================

void ExpertBalancer::validate_inputs_(
    const std::vector<std::uint32_t>& tokens_per_expert,
    const std::vector<NodeId>& base_assignment,
    std::uint32_t num_nodes,
    std::uint32_t num_redundant) const {

    if (tokens_per_expert.empty()) {
        throw std::invalid_argument("tokens_per_expert must not be empty");
    }
    if (base_assignment.size() != tokens_per_expert.size()) {
        throw std::invalid_argument("base_assignment size must match tokens_per_expert size");
    }
    if (num_nodes == 0) {
        throw std::invalid_argument("num_nodes must be > 0");
    }

    // 校验 base_assignment 中的节点 ID 都 < num_nodes
    for (NodeId node : base_assignment) {
        if (node >= num_nodes) {
            throw std::invalid_argument("base_assignment contains node_id >= num_nodes");
        }
    }
}

}  // namespace linoh::multimodal::ep
