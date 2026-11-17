// comm_planner_v2.hpp — 拓扑感知集合通信规划器（v2.1 Phase 2 M3/M4）
//
// 在 CommPlanner（EP 通信规划，P3）基础上，新增 CommPlannerV2 面向 DP/EP 集合通信的
// 拓扑感知规划能力。输入 CollectiveOp + NodeProfile 列表 + 消息大小，输出 TopologyPlan
// 描述算法选择、节点顺序、AllToAll 路由表、异构 chunk 切分。
//
// 设计依据（docs/NATIONAL_COMPUTE_NETWORK_EVOLUTION.md §4.3.4）：
//   - 节点算力（NodeProfile.compute.normalized_score）→ 决定 chunk 切分（M4）
//   - 节点间 RTT（NodeProfile.network.rtt_ms_avg）→ 决定拓扑顺序
//   - 消息大小 + 节点数 → 决定算法选择（ring/tree/recursive_halving/pairwise）
//   - 相同 (op, nodes, msg_size) 复用 plan（LRU 缓存，现有机制）
//
// M3 交付物：
//   1. TopologyPlan 数据结构（op/algo/participants/route/chunk_sizes）
//   2. CommPlannerV2::plan 核心规划 API
//   3. select_algo 算法选择策略（基于 msg_size + num_nodes）
//   4. sort_nodes_by_score 节点排序（按 overall_score 降序）
//   5. build_route AllToAll 路由表生成（按 RTT 优化邻居顺序）
//   6. compute_plan_hash 缓存键计算
//   7. TopologyPlan 序列化/反序列化（用于 ctrl/1 下发）
//
// M4 交付物（合并实现，因 chunk_sizes 是 TopologyPlan 字段）：
//   8. split_chunks_by_compute 异构 chunk 切分（按 compute 加权分配）
//      - 每节点 chunk = msg_size * (compute_score_i / sum(compute_score))
//      - 舍入修正确保 sum(chunk_sizes) == msg_size
//      - 最小 chunk 保护（避免 0 字节分片）
//
// 设计原则：
//   - 纯 C++ 实现，不依赖 PyTorch / 真实网络
//   - TopologyPlan.participants/route 使用输入列表索引（uint32_t），便于测试与节点解耦
//   - 复用现有 LRUHashCache（comm_planner.hpp）做 plan 缓存
//   - 线程安全：LRUHashCache mutex 保护；plan_id 原子递增
//   - 不修改现有 CommPlanner 接口，CommPlannerV2 作为新增模块独立集成

#pragma once

#include <atomic>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "linoh/multimodal/collective.hpp"      // CollectiveOp / CollectiveAlgo
#include "linoh/multimodal/comm_planner.hpp"     // LRUHashCache / NodeId
#include "linoh/node_profile.hpp"                // NodeProfile

namespace linoh::multimodal::ep {

// ============================================================================
// TopologyPlan — 拓扑感知规划结果
// ============================================================================

/// 集合通信拓扑规划结果（一次集合操作的完整通信计划）
///
/// 字段语义：
///   - participants: 参与节点在输入 NodeProfile 列表中的索引，按 overall_score 降序排列。
///                   索引 0 = 最强节点（通常作为 ring/tree 的起点或 root）。
///   - route: AllToAll 通信顺序（participants 索引的排列），按 RTT 优化邻居顺序，
///            使得相邻通信对的 RTT 最小（贪心最近邻）。对 ring 类算法即节点遍历顺序。
///   - chunk_sizes[i]: participants[i] 节点分到的 chunk 字节数（异构按算力加权），
///                     sum(chunk_sizes) == msg_size。
struct TopologyPlan {
    // === 操作与算法 ===
    CollectiveOp    op{CollectiveOp::Barrier};          // 集合操作类型
    CollectiveAlgo  algo{CollectiveAlgo::Ring};         // 选定算法

    // === 节点拓扑 ===
    /// 参与节点索引（输入列表位置），按 overall_score 降序。
    /// 强节点在前，作为 ring 起点 / tree root / broadcast root。
    std::vector<std::uint32_t> participants;

    /// AllToAll / ring 通信顺序（participants 数组的索引序列）。
    /// 按 RTT 贪心最近邻排列，相邻通信对 RTT 最小。
    /// 对 AllToAll：route[i] → route[i+1] 为一轮交换；
    /// 对 ring：route 定义环遍历顺序。
    std::vector<std::uint32_t> route;

    // === 异构 chunk 切分（M4）===
    /// 各节点 chunk 字节数，与 participants 对齐：chunk_sizes[i] 对应 participants[i]。
    /// 按 compute.normalized_score() 加权分配，sum == msg_size。
    std::vector<std::size_t> chunk_sizes;

    // === 元信息 ===
    std::uint64_t   plan_id{0};      // 唯一 ID（原子递增）
    std::uint64_t   plan_hash{0};    // (op, nodes, msg_size) hash，缓存键
    std::size_t     msg_size{0};     // 总消息大小（字节）
    std::size_t     num_nodes{0};    // 参与节点数
    std::size_t     min_chunk{0};    // 最小 chunk（异构切分下限保护）
    std::size_t     max_chunk{0};    // 最大 chunk
    double          chunk_imbalance_ratio{1.0};  // max/min（1.0=同构完美均衡）

    /// 是否有效
    bool valid() const noexcept {
        return !participants.empty()
            && participants.size() == chunk_sizes.size()
            && num_nodes == participants.size()
            && msg_size > 0;
    }

    /// 简要描述（日志用）
    std::string brief() const;
};

// ============================================================================
// CommPlannerV2 — 拓扑感知集合通信规划器
// ============================================================================

/// 拓扑感知集合通信规划器
///
/// 用法（DP/EP master 端）：
///   CommPlannerV2 planner;
///   std::vector<NodeProfile> nodes = store.snapshot();
///   auto plan = planner.plan(CollectiveOp::AllReduce, nodes, 1024 * 1024);
///   // plan.algo      → RecursiveHalving（大消息自动选）
///   // plan.participants → 按算力降序的节点索引
///   // plan.chunk_sizes → 异构切分（强节点多分）
///   // 用 plan 驱动 CollectiveSession 执行
class CommPlannerV2 {
public:
    CommPlannerV2();
    explicit CommPlannerV2(std::size_t cache_capacity);

    // 不可拷贝（cache_ 含 mutex 不可移动）
    CommPlannerV2(const CommPlannerV2&) = delete;
    CommPlannerV2& operator=(const CommPlannerV2&) = delete;

    // 析构函数声明在 header，定义在 .cpp（unique_ptr 删除 PlanCache 完整类型，pimpl 模式）
    ~CommPlannerV2();

    // ====================================================================
    // 核心规划 API
    // ====================================================================

    /// plan：根据操作类型 + 节点画像 + 消息大小生成拓扑规划
    ///
    /// 规划流程：
    ///   1. 计算 plan_hash，查缓存（命中直接返回）
    ///   2. select_algo 选算法（msg_size + num_nodes）
    ///   3. sort_nodes_by_score 节点排序（overall_score 降序）
    ///   4. build_route 路由表（RTT 贪心最近邻）
    ///   5. split_chunks_by_compute 异构切分（compute 加权）
    ///   6. 写入缓存并返回
    ///
    /// \param op 集合操作类型
    /// \param nodes 参与节点画像列表（至少 1 个）
    /// \param msg_size 总消息大小（字节，>0）
    /// \return TopologyPlan（写入缓存）
    /// \throws std::invalid_argument 若 nodes 为空或 msg_size==0
    TopologyPlan plan(CollectiveOp op,
                      const std::vector<NodeProfile>& nodes,
                      std::size_t msg_size);

    /// try_cache：尝试从缓存查找（相同 plan_hash 复用）
    std::optional<TopologyPlan> try_cache(std::uint64_t plan_hash);

    // ====================================================================
    // 规划策略 API（public，便于应用层复用与单元测试）
    // ====================================================================

    /// 算法选择策略（基于操作类型 + 节点数 + 消息大小）
    ///
    /// 规则（docs §4.3.1 算法矩阵）：
    ///   - Barrier:    Ring（始终）
    ///   - AllReduce:  msg<=64KB 且 N<=8 → Ring；否则 RecursiveHalving
    ///   - AllGather:  N<=16 → Ring；否则 Tree
    ///   - Broadcast:  N<=8 → Tree；否则 Ring
    ///   - ReduceScatter: RecursiveHalving（始终，最优）
    ///   - AllToAll:   PairwiseExchange（始终）
    static CollectiveAlgo select_algo(CollectiveOp op,
                                      std::size_t num_nodes,
                                      std::size_t msg_size) noexcept;

    /// 节点排序（按 overall_score 降序）
    ///
    /// 返回排序后的节点在输入列表中的索引序列（强节点在前）。
    /// 同分时按 vram_mb 降序（显存大优先），再按 node_id 字典序稳定排序。
    static std::vector<std::uint32_t> sort_nodes_by_score(
        const std::vector<NodeProfile>& nodes);

    /// AllToAll / ring 路由表生成（按 RTT 贪心最近邻）
    ///
    /// 算法：从最强节点（participants[0]）出发，每步选择未访问节点中 RTT 最小的。
    /// \param nodes 节点画像列表
    /// \param participants 已排序的节点索引
    /// \return route 顺序（participants 数组的索引序列）
    static std::vector<std::uint32_t> build_route(
        const std::vector<NodeProfile>& nodes,
        const std::vector<std::uint32_t>& participants);

    /// 异构 chunk 切分（M4：按 compute 加权分配）
    ///
    /// 算法：
    ///   1. 计算各节点 compute.normalized_score() 权重
    ///   2. 若所有节点权重相同（同构）→ 等分
    ///   3. 异构：chunk_i = round(msg_size * w_i / sum_w)
    ///   4. 舍入修正：差额加到权重最大的节点，确保 sum == msg_size
    ///   5. 最小 chunk 保护：min_chunk = max(1, msg_size / (N * 64))
    ///
    /// \param nodes 节点画像列表
    /// \param participants 已排序的节点索引（chunk_sizes 与此对齐）
    /// \param msg_size 总消息大小
    /// \return chunk_sizes[i] 对应 participants[i] 的字节数
    static std::vector<std::size_t> split_chunks_by_compute(
        const std::vector<NodeProfile>& nodes,
        const std::vector<std::uint32_t>& participants,
        std::size_t msg_size);

    /// 计算 plan_hash（缓存键，FNV-1a 64bit）
    /// 输入：op + 节点 endpoint_id 集合 + msg_size
    static std::uint64_t compute_plan_hash(
        CollectiveOp op,
        const std::vector<NodeProfile>& nodes,
        std::size_t msg_size) noexcept;

    // ====================================================================
    // 序列化（用于通过 ctrl/1 下发到各节点）
    // ====================================================================

    /// 序列化 TopologyPlan 为字节流
    static std::vector<std::uint8_t> serialize(const TopologyPlan& plan);

    /// 反序列化
    /// \return true=成功，false=数据格式错误
    static bool deserialize(std::span<const std::uint8_t> data, TopologyPlan& out);

    // ====================================================================
    // 缓存管理
    // ====================================================================

    std::size_t cache_size() const noexcept;
    void clear_cache() noexcept;
    std::uint64_t cache_hits() const noexcept;
    std::uint64_t cache_misses() const noexcept;
    double cache_hit_rate() const noexcept;

private:
    /// plan 缓存（复用 LRUHashCache，key=plan_hash，value=序列化 bytes）
    /// 注：LRUHashCache 原存 EpCommPlan，此处存 TopologyPlan 的序列化字节，
    ///     为避免改动 LRUHashCache 模板，本类内部用独立 LRU 实现（key→bytes）。
    struct PlanCache;
    std::unique_ptr<PlanCache> cache_;

    /// 生成唯一 plan_id（原子递增）
    static std::uint64_t next_plan_id_() noexcept;
};

// CollectiveOp / CollectiveAlgo 转字符串复用 collective.hpp 中的
// collective_op_name() / collective_algo_name()（已通过 include 引入）

}  // namespace linoh::multimodal::ep
