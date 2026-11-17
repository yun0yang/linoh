// comm_planner.hpp - EP 在线通信规划器（v1.6.0.4 / P3）
//
// 借鉴 MoonEP 思想 ⑤（launch_planning + CommPlan）：
//   - 每次 dispatch 前在线规划通信计划（dst、expert_id、buffer_slice、zero_fill_range）
//   - 规划与执行分离：plan 仅描述，不包含数据
//   - 规划可缓存：相同 routing_hash 复用 plan，避免重复计算
//
// P3 阶段定位：
//   - 实现 CommPlanner 类 + EpCommPlan 数据结构
//   - 实现 LRUHashCache（routing_hash -> EpCommPlan）
//   - 实现 EpCommPlan 序列化（用于通过 ctrl/1 下发到各节点）
//   - 不实现真实负载均衡（P5）：仅记录 load_imbalance_ratio
//   - 不实现真实 EP 端到端推理（P7）
//
// 与 P0-P2 集成点：
//   - EpChannel：plan.dst_nodes + plan.dispatch_bufs 驱动 send_dispatch
//   - SyncPrimitives：plan.sync_participants + plan.sync_id 驱动 barrier
//   - StaticBufferPool：plan.shape.padded_bytes 决定 pool buffer 大小
//   - ZeroCopySender：plan.dispatch_bufs[i].offset/length 决定 buffer 切片
//   - TensorShapeNegotiator：plan.shape 来自协商结果
//
// 设计原则：
//   - 纯 C++ 实现，不依赖 PyTorch
//   - topk>1 简化策略：P3 取第一个专家所在节点（P5 完整冗余专家）
//   - 不修改 P0-P2 现有接口，CommPlanner 作为新增模块独立集成
//   - 线程安全：LRUHashCache mutex 保护；plan_id 原子递增

#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "linoh/multimodal/static_shape.hpp"

namespace linoh::multimodal::ep {

/// NodeId 别名（统一 EP 组节点标识；与 linoh endpoint NodeId 同义）
using NodeId = std::uint64_t;

/// Range 辅助结构（zero_fill 区间）
struct Range {
    std::uint64_t offset{0};
    std::uint64_t length{0};
};

/// Buffer 切片描述（dispatch/combine 各 dst 一个）
struct BufferSlice {
    std::uint64_t buffer_offset{0};   // 在 StaticBufferPool buffer 中的偏移
    std::uint64_t length{0};           // 实际数据长度
    std::uint64_t padded_length{0};    // padding 后长度（静态形状对齐）
    bool zero_fill{false};             // 是否需要零填充（padding 行）
};

/// EP 通信计划（一次 dispatch->compute->combine->sync 的完整规划）
struct EpCommPlan {
    // === dispatch 阶段（EP-master -> N 个 EP-worker）===
    std::vector<NodeId>         dst_nodes;             // 每个 token 的目标节点（size=total_tokens）
    std::vector<std::uint32_t> expert_ids;             // 每个 token 的目标专家（size=total_tokens）
    std::vector<BufferSlice>   dispatch_bufs;          // 每个 dst 节点的发送 buffer 切片
    std::vector<std::uint32_t> tokens_per_dst;         // 每个 dst 节点的 token 数

    // === combine 阶段（N 个 EP-worker -> EP-master）===
    std::vector<BufferSlice>   combine_bufs;           // 每个 src 节点的接收 buffer 切片
    std::vector<Range>         zero_fill_ranges;       // padding 行的清零区间

    // === sync 阶段 ===
    std::vector<NodeId>        sync_participants;      // barrier 参与者（= dst_nodes 去重）
    std::uint64_t              sync_id{0};             // 同步会话 ID

    // === 负载统计 ===
    std::uint32_t              total_tokens{0};
    std::uint32_t              max_tokens_per_expert{0};
    std::uint32_t              min_tokens_per_expert{0};
    double                     load_imbalance_ratio{1.0};  // max/min（P5 用于触发冗余专家）
    bool                       load_balanced{true};

    // === 元信息 ===
    std::uint64_t              routing_hash{0};        // 路由模式 hash（用于缓存键）
    std::uint64_t              plan_id{0};             // plan 唯一 ID
    ShapeDescriptor            shape;                   // 静态形状（来自协商）

    // === P4 transport 提示 ===
    /// EP dispatch/combine 使用的 transport 类型提示（P4 新增）
    enum class TransportHint : std::uint8_t {
        QUIC_UDP    = 0,   // 默认回退（跨节点）
        NVLINK      = 1,   // 同机多 GPU（NVLink 直传）
        CUDA_IPC    = 2,   // 同机进程间（CUDA IPC handle）
    };
    TransportHint              transport_hint{TransportHint::QUIC_UDP};

    // === P5 负载均衡 ===
    /// 冗余专家对应的原始专家 ID 列表
    /// redundant_experts[i] = 第 i 个冗余槽位复制的原始专家 ID
    /// 空表示未启用 P5 负载均衡（config.num_redundant_experts=0）
    std::vector<std::uint32_t> redundant_experts;

    /// 冗余专家数（等于 redundant_experts.size()，冗余字段便于序列化）
    std::uint32_t              num_redundant{0};
};

/// EP 组配置（描述 EP 组拓扑）
struct EpGroupConfig {
    NodeId                     ep_master{0};            // EP-master 节点 ID
    std::vector<NodeId>        ep_workers;              // EP-worker 节点列表（size=num_workers）
    std::vector<std::vector<std::uint32_t>> expert_placement;  // [worker_idx] -> 该节点承载的专家 ID 列表
    std::uint32_t              num_experts{0};          // 总专家数
    std::uint32_t              topk{1};                 // 每 token 选 top-k 专家
    ShapeDescriptor            shape;                    // 静态形状（协商后）

    // === P5 负载均衡配置 ===
    /// 冗余专家数（0=禁用 P5 负载均衡，>0=启用）
    /// B << E（如 E=64, B=4），将热门专家复制到冗余槽位吸收负载不均
    std::uint32_t              num_redundant_experts{0};

    /// 负载均衡策略（0=贪心最佳适应, 1=轮询复制, 2=最轻负载优先）
    /// 对应 BalanceStrategy 枚举（expert_balancer.hpp）
    std::uint8_t               balance_strategy{0};

    /// 是否有效
    bool valid() const noexcept {
        return !ep_workers.empty()
            && num_experts > 0
            && topk > 0
            && expert_placement.size() == ep_workers.size()
            && shape.valid();
    }
};

/// LRU Hash 缓存（routing_hash -> EpCommPlan）
///
/// 借鉴 MoonEP 思想 ⑤：规划可缓存，相同路由模式复用 plan
/// 容量有限（默认 16），LRU 淘汰最久未使用
class LRUHashCache {
public:
    explicit LRUHashCache(std::size_t capacity = 16);

    // 不可拷贝、不可移动（含 mutex 不可移动成员）
    LRUHashCache(const LRUHashCache&) = delete;
    LRUHashCache& operator=(const LRUHashCache&) = delete;
    LRUHashCache(LRUHashCache&&) = delete;
    LRUHashCache& operator=(LRUHashCache&&) = delete;

    /// 查找（命中时移到链表头部）
    std::optional<EpCommPlan> lookup(std::uint64_t routing_hash);

    /// 插入（容量满时淘汰链表尾部）
    void insert(std::uint64_t routing_hash, EpCommPlan plan);

    /// 清空
    void clear() noexcept;

    /// 当前条目数
    std::size_t size() const noexcept;

    /// 容量上限
    std::size_t capacity() const noexcept { return capacity_; }

    /// 统计
    std::uint64_t hits() const noexcept { return hits_.load(); }
    std::uint64_t misses() const noexcept { return misses_.load(); }
    double hit_rate() const noexcept;

private:
    std::size_t capacity_;
    // list: 头=最近使用，尾=最久未使用
    std::list<std::pair<std::uint64_t, EpCommPlan>> list_;
    std::unordered_map<std::uint64_t,
        std::list<std::pair<std::uint64_t, EpCommPlan>>::iterator> map_;
    mutable std::mutex mu_;
    std::atomic<std::uint64_t> hits_{0};
    std::atomic<std::uint64_t> misses_{0};
};

/// 在线通信规划器
///
/// 用法（EP-master 端）：
///   CommPlanner planner;
///   EpGroupConfig config = {ep_master, workers, expert_placement, ...};
///   std::vector<std::vector<std::uint32_t>> routing = {
///       {0, 2},   // token 0: top-2 专家 [0, 2]
///       {1},      // token 1: top-1 专家 [1]
///       ...
///   };
///   auto plan = planner.launch_planning(routing, config);
///   if (!plan.load_balanced) {
///       // P5 阶段触发冗余专家再均衡
///   }
///   // 用 plan 驱动 dispatch/combine/sync
class CommPlanner {
public:
    CommPlanner();
    explicit CommPlanner(std::size_t cache_capacity);

    // 不可拷贝（cache_ 含 mutex 不可移动）
    CommPlanner(const CommPlanner&) = delete;
    CommPlanner& operator=(const CommPlanner&) = delete;

    // ====================================================================
    // 核心规划 API
    // ====================================================================

    /// launch_planning：根据路由结果生成通信计划
    /// \param routing token->expert 路由结果（routing[i] = token i 选中的 top-k 专家列表）
    /// \param config EP 组配置
    /// \return EpCommPlan（写入缓存，可后续 try_cache 复用）
    /// \throws std::invalid_argument 若 routing/config 不合法
    EpCommPlan launch_planning(
        const std::vector<std::vector<std::uint32_t>>& routing,
        const EpGroupConfig& config);

    /// try_cache：尝试从缓存查找（相同 routing_hash 复用）
    /// \return 命中返回 plan，miss 返回 nullopt
    std::optional<EpCommPlan> try_cache(std::uint64_t routing_hash);

    // ====================================================================
    // 路由辅助 API（public，便于应用层复用）
    // ====================================================================

    /// 计算 routing_hash（用于缓存键，FNV-1a 64bit）
    /// 相同 routing 数据返回相同 hash
    static std::uint64_t compute_routing_hash(
        const std::vector<std::vector<std::uint32_t>>& routing);

    /// 根据 expert_placement 反查 expert->node 映射
    /// \return expert_id -> ep_workers[worker_idx]
    static std::unordered_map<std::uint32_t, NodeId> build_expert_to_node_map(
        const EpGroupConfig& config);

    // ====================================================================
    // 序列化（用于通过 ctrl/1 下发到各节点）
    // ====================================================================

    /// 序列化 EpCommPlan 为字节流
    static std::vector<std::uint8_t> serialize(const EpCommPlan& plan);

    /// 反序列化
    /// \return true=成功，false=数据格式错误
    static bool deserialize(std::span<const std::uint8_t> data, EpCommPlan& out);

    // ====================================================================
    // 缓存管理
    // ====================================================================

    /// 缓存条目数
    std::size_t cache_size() const noexcept;

    /// 清空缓存
    void clear_cache() noexcept;

    /// 缓存统计
    std::uint64_t cache_hits() const noexcept;
    std::uint64_t cache_misses() const noexcept;
    double cache_hit_rate() const noexcept;

private:
    LRUHashCache cache_;

    // ====================================================================
    // 内部规划算法
    // ====================================================================

    /// 阶段 1：token->node 映射
    std::vector<NodeId> map_tokens_to_nodes_(
        const std::vector<std::vector<std::uint32_t>>& routing,
        const std::unordered_map<std::uint32_t, NodeId>& expert_to_node);

    /// 阶段 2：按 dst 节点分组 token
    struct GroupedTokens {
        std::vector<std::uint32_t> token_indices;  // 按 dst 分组重排后的 token 索引
        std::vector<std::uint32_t> group_offsets;  // 每 dst 组在 token_indices 中的起始偏移
        std::vector<std::uint32_t> group_sizes;    // 每 dst 组的 token 数
    };
    GroupedTokens group_tokens_by_dst_(
        const std::vector<NodeId>& dst_nodes,
        const EpGroupConfig& config);

    /// 阶段 3：计算 dispatch buffer 切片
    std::vector<BufferSlice> compute_dispatch_bufs_(
        const GroupedTokens& grouped,
        const ShapeDescriptor& shape);

    /// 阶段 4：计算 combine buffer 切片 + zero_fill 区间
    struct CombinePlan {
        std::vector<BufferSlice> combine_bufs;
        std::vector<Range> zero_fill_ranges;
    };
    CombinePlan compute_combine_plan_(
        const GroupedTokens& grouped,
        const ShapeDescriptor& shape);

    /// 阶段 5：负载统计
    struct LoadStats {
        std::uint32_t total_tokens{0};
        std::uint32_t max_tokens_per_expert{0};
        std::uint32_t min_tokens_per_expert{0};
        double imbalance_ratio{1.0};
        bool balanced{true};
    };
    LoadStats compute_load_stats_(
        const std::vector<std::vector<std::uint32_t>>& routing,
        const std::uint32_t num_experts);

    /// 阶段 6：sync 参与者收集（dst_nodes 去重）
    std::vector<NodeId> collect_sync_participants_(const std::vector<NodeId>& dst_nodes);

    /// 生成唯一 plan_id（原子递增）
    static std::uint64_t next_plan_id_();

    /// 生成唯一 sync_id（基于 plan_id，避免冲突）
    static std::uint64_t derive_sync_id_(std::uint64_t plan_id) noexcept;
};

}  // namespace linoh::multimodal::ep
