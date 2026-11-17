// expert_balancer.hpp - EP 负载均衡与冗余专家调度（v1.6.0.6 / P5）
//
// 借鉴 MoonEP 思想 ①（动态冗余专家实现完美负载均衡）：
//   - 与其精确调度避免不均，不如用少量冗余专家吸收不均
//   - EP 组 E 个专家分布到 R 个节点，每节点 E/R 个专家
//   - 某些专家热门（token 多），某些冷门（token 少）→ 负载不均
//   - 增加 B 个冗余专家（B << E），将热门专家复制到冗余槽位
//   - 目标：min(max(tokens_per_node))，使 max/min ≤ threshold（默认 1.05）
//
// 三种均衡策略：
//   - GREEDY_BEST_FIT：贪心最佳适应（默认，最优解）
//     每轮选最热门专家，复制到当前最轻节点的冗余槽
//   - ROUND_ROBIN_REPL：轮询复制
//     冗余专家按节点轮询分配（简单但不考虑负载）
//   - LEAST_LOADED_FIRST：最轻负载优先
//     按节点负载升序填充冗余专家（贪心变种，按节点而非专家排序）
//
// 集成点：
//   - CommPlanner.launch_planning 内部调用（EpGroupConfig.num_redundant_experts > 0 时）
//   - 独立 API：ExpertBalancer::balance 可单独调用
//   - 结果写入 EpCommPlan.redundant_experts / num_redundant

#ifndef LINOH_MULTIMODAL_EXPERT_BALANCER_HPP
#define LINOH_MULTIMODAL_EXPERT_BALANCER_HPP

#include <cstdint>
#include <mutex>
#include <vector>

#include "linoh/multimodal/comm_planner.hpp"  // NodeId

namespace linoh::multimodal::ep {

/// 冗余专家分配方案
struct ExpertAssignment {
    /// [E+B]：每专家（含冗余）-> 节点映射
    /// 前 E 个等于 base_assignment，后 B 个是冗余专家的副本位置
    std::vector<NodeId> expert_to_node;

    /// [B]：冗余专家对应的原始专家 ID
    /// redundant_experts[i] 表示第 i 个冗余槽位复制的是哪个原始专家
    std::vector<std::uint32_t> redundant_experts;

    /// [R]：每节点最终 token 数（含冗余专家的 token）
    std::vector<std::uint32_t> tokens_per_node;

    std::uint32_t num_original{0};   ///< E：原始专家数
    std::uint32_t num_redundant{0};  ///< B：冗余专家数
    std::uint32_t num_nodes{0};      ///< R：节点数

    /// 负载不均比率 = max(tokens_per_node) / min(tokens_per_node)
    /// 1.0 = 完美均衡；≤ threshold = 达标
    double imbalance_ratio{1.0};

    /// 是否达到均衡（imbalance_ratio <= threshold）
    bool balanced{false};

    /// 有效性检查
    bool valid() const noexcept {
        return num_nodes > 0
            && !expert_to_node.empty()
            && tokens_per_node.size() == num_nodes
            && redundant_experts.size() == num_redundant;
    }
};

/// 负载均衡策略枚举
enum class BalanceStrategy : std::uint8_t {
    GREEDY_BEST_FIT    = 0,  ///< 贪心最佳适应（默认）：热门专家复制到最轻节点
    ROUND_ROBIN_REPL   = 1,  ///< 轮询复制：冗余专家轮询分配到各节点
    LEAST_LOADED_FIRST = 2,  ///< 最轻负载优先：按节点负载升序填充
};

/// ExpertBalancer：冗余专家调度器
///
/// 用法（独立 API）：
///   ExpertBalancer balancer;
///   auto assignment = balancer.balance(
///       tokens_per_expert, base_assignment, R, B, BalanceStrategy::GREEDY_BEST_FIT);
///   if (!assignment.balanced) {
///       // 增加冗余数或调整策略
///   }
///
/// 用法（CommPlanner 集成）：
///   EpGroupConfig config;
///   config.num_redundant_experts = 4;
///   config.balance_strategy = BalanceStrategy::GREEDY_BEST_FIT;
///   auto plan = planner.launch_planning(routing, config);
///   // plan.redundant_experts / plan.num_redundant 已填充
class ExpertBalancer {
public:
    /// 默认均衡阈值 1.05（max/min ≤ 1.05 视为均衡）
    static constexpr double kDefaultThreshold = 1.05;

    ExpertBalancer() = default;
    explicit ExpertBalancer(double balanced_threshold);

    /// 计算冗余专家分配方案
    /// \param tokens_per_expert [E] 每专家 token 数
    /// \param base_assignment [E] 原始专家->节点映射（来自 EpGroupConfig.expert_placement）
    /// \param num_nodes R 节点数
    /// \param num_redundant B 冗余专家数（B << E）
    /// \param strategy 均衡策略（默认贪心最佳适应）
    /// \return ExpertAssignment
    /// \throws std::invalid_argument 若参数不合法
    ExpertAssignment balance(
        const std::vector<std::uint32_t>& tokens_per_expert,
        const std::vector<NodeId>& base_assignment,
        std::uint32_t num_nodes,
        std::uint32_t num_redundant,
        BalanceStrategy strategy = BalanceStrategy::GREEDY_BEST_FIT);

    /// 评估当前分配的负载不均比率
    /// \param tokens_per_node [R] 每节点 token 数
    /// \return max/min（R=0 或 min=0 时返回 1.0）
    static double compute_imbalance_ratio(
        const std::vector<std::uint32_t>& tokens_per_node) noexcept;

    /// 均衡阈值访问器
    double balanced_threshold() const noexcept;
    void set_balanced_threshold(double t) noexcept;

    /// 统计
    struct Stats {
        std::uint64_t balance_calls{0};       ///< balance() 调用总次数
        std::uint64_t balanced_count{0};      ///< 达到均衡的次数
        std::uint64_t unbalanced_count{0};    ///< 未达到均衡的次数
        std::uint64_t total_redundant_used{0};///< 累计使用的冗余专家数
    };
    const Stats& stats() const noexcept;
    void reset_stats() noexcept;

private:
    double threshold_{kDefaultThreshold};
    mutable Stats stats_;

    /// 贪心最佳适应：每轮选最热门专家，复制到最轻节点的冗余槽
    ExpertAssignment balance_greedy_(
        const std::vector<std::uint32_t>& tokens_per_expert,
        const std::vector<NodeId>& base_assignment,
        std::uint32_t num_nodes,
        std::uint32_t num_redundant);

    /// 轮询复制：冗余专家按节点轮询分配
    ExpertAssignment balance_round_robin_(
        const std::vector<std::uint32_t>& tokens_per_expert,
        const std::vector<NodeId>& base_assignment,
        std::uint32_t num_nodes,
        std::uint32_t num_redundant);

    /// 最轻负载优先：按节点负载升序填充冗余专家
    ExpertAssignment balance_least_loaded_(
        const std::vector<std::uint32_t>& tokens_per_expert,
        const std::vector<NodeId>& base_assignment,
        std::uint32_t num_nodes,
        std::uint32_t num_redundant);

    /// 通用：根据 expert_to_node 计算 tokens_per_node + imbalance_ratio + balanced
    void finalize_assignment_(
        ExpertAssignment& assignment,
        const std::vector<std::uint32_t>& tokens_per_expert) const;

    /// 校验输入参数
    void validate_inputs_(
        const std::vector<std::uint32_t>& tokens_per_expert,
        const std::vector<NodeId>& base_assignment,
        std::uint32_t num_nodes,
        std::uint32_t num_redundant) const;
};

}  // namespace linoh::multimodal::ep

#endif  // LINOH_MULTIMODAL_EXPERT_BALANCER_HPP
