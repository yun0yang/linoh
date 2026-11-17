// collective.cpp — 集合通信统一接口实现（v2.1 Phase 2）
//
// 实现 CollectiveSession 类，委托 SyncPrimitives 完成实际的集合通信操作。
// 当前 P2 阶段实现：
//   - barrier     → SyncPrimitives::barrier
//   - all_reduce  → SyncPrimitives::all_reduce
//   - all_gather  → SyncPrimitives::all_gather（v2.1 Phase 2 新增）
//   - broadcast   → SyncPrimitives::broadcast（v2.1 Phase 2 新增）
//
// 算法说明：
//   - AllReduce/AllGather 当前为简化实现（SyncPrimitives 内部 tree/ring 混合）
//   - Broadcast 为简化 tree（root 直接发送到所有 participant）
//   - 完整 ring/tree 算法在 P3 阶段实现，届时 CollectiveAlgo 将影响实际算法选择

#include "linoh/multimodal/collective.hpp"

#include "linoh/multimodal/comm_planner_v2.hpp"  // TopologyPlan 定义（execute_plan 使用）

namespace linoh::multimodal::ep {

// ============================================================================
// 构造/析构
// ============================================================================

CollectiveSession::CollectiveSession(SyncPrimitives &sync)
    : sync_(sync), config_() {}

CollectiveSession::CollectiveSession(SyncPrimitives &sync, CollectiveConfig config)
    : sync_(sync), config_(config) {}

// ============================================================================
// 集合通信操作实现
// ============================================================================

bool CollectiveSession::barrier(std::uint64_t sync_id,
                                std::uint64_t participant_mask,
                                std::uint64_t self_node_id,
                                std::chrono::milliseconds timeout) {
    return sync_.barrier(sync_id, participant_mask, self_node_id,
                         resolve_timeout_(timeout));
}

std::optional<std::vector<std::uint8_t>> CollectiveSession::all_reduce(
    std::uint64_t sync_id,
    std::uint64_t participant_mask,
    std::uint64_t self_node_id,
    std::span<const std::uint8_t> local_data,
    ReduceOp op,
    ReduceDType dtype,
    std::chrono::milliseconds timeout,
    CollectiveAlgo algo) {
    // op/dtype 为默认值时使用 config_ 中的配置
    // 注意：C++ 默认参数无法区分"用户传 SUM"和"使用默认值"，这里直接透传
    // 若调用方希望使用 config_.default_reduce_op，应显式传入或修改此逻辑
    // v2.2 Phase 3 (P3-F): 透传 algo 到 SyncPrimitives（uint8_t 编码）
    return sync_.all_reduce(sync_id, participant_mask, self_node_id,
                            local_data, op, dtype, resolve_timeout_(timeout),
                            static_cast<std::uint8_t>(algo));
}

std::optional<std::vector<std::uint8_t>> CollectiveSession::all_gather(
    std::uint64_t sync_id,
    std::uint64_t participant_mask,
    std::uint64_t self_node_id,
    std::span<const std::uint8_t> local_chunk,
    std::chrono::milliseconds timeout,
    CollectiveAlgo algo) {
    // v2.2 Phase 3 (P3-F): 透传 algo 到 SyncPrimitives
    return sync_.all_gather(sync_id, participant_mask, self_node_id,
                            local_chunk, resolve_timeout_(timeout),
                            static_cast<std::uint8_t>(algo));
}

bool CollectiveSession::broadcast(
    std::uint64_t sync_id,
    std::uint64_t participant_mask,
    std::uint64_t root_node_id,
    std::span<const std::uint8_t> data,
    std::chrono::milliseconds timeout,
    CollectiveAlgo algo) {
    // v2.2 Phase 3 (P3-F): 透传 algo 到 SyncPrimitives
    return sync_.broadcast(sync_id, participant_mask, root_node_id,
                           data, resolve_timeout_(timeout),
                           static_cast<std::uint8_t>(algo));
}

// ============================================================================
// v2.1 Phase 2 M2: ReduceScatter / AllToAll 委托实现
// ============================================================================

std::optional<std::vector<std::uint8_t>> CollectiveSession::reduce_scatter(
    std::uint64_t sync_id,
    std::uint64_t participant_mask,
    std::uint64_t self_node_id,
    std::span<const std::uint8_t> local_data,
    ReduceOp op,
    ReduceDType dtype,
    std::chrono::milliseconds timeout,
    CollectiveAlgo algo) {
    // v2.2 Phase 3 (P3-F): 透传 algo 到 SyncPrimitives
    return sync_.reduce_scatter(sync_id, participant_mask, self_node_id,
                                local_data, op, dtype, resolve_timeout_(timeout),
                                static_cast<std::uint8_t>(algo));
}

std::optional<std::vector<std::uint8_t>> CollectiveSession::all_to_all(
    std::uint64_t sync_id,
    std::uint64_t participant_mask,
    std::uint64_t self_node_id,
    std::span<const std::uint8_t> local_chunk,
    std::chrono::milliseconds timeout,
    CollectiveAlgo algo) {
    // v2.2 Phase 3 (P3-F): 透传 algo 到 SyncPrimitives
    return sync_.all_to_all(sync_id, participant_mask, self_node_id,
                            local_chunk, resolve_timeout_(timeout),
                            static_cast<std::uint8_t>(algo));
}

// ============================================================================
// 内部辅助
// ============================================================================

std::chrono::milliseconds CollectiveSession::resolve_timeout_(std::chrono::milliseconds timeout) const noexcept {
    // timeout=0 表示使用默认配置
    if (timeout.count() == 0) {
        return config_.default_timeout;
    }
    return timeout;
}

// ============================================================================
// v2.2 Phase 3 (P3-F): execute_plan 实现
// ============================================================================

std::optional<std::vector<std::uint8_t>> CollectiveSession::execute_plan(
    const TopologyPlan &plan,
    std::uint64_t sync_id,
    std::uint64_t participant_mask,
    std::uint64_t self_node_id,
    std::span<const std::uint8_t> local_data,
    std::span<const std::uint8_t> local_chunk,
    std::uint64_t root_node_id,
    ReduceOp op,
    ReduceDType dtype,
    std::chrono::milliseconds timeout) {
    // 参数校验：plan 必须有效
    if (!plan.valid()) {
        return std::nullopt;
    }

    auto resolved_timeout = resolve_timeout_(timeout);

    // 按 plan.op 分派到对应方法，透传 plan.algo 到 SyncPrimitives
    // 算法标识贯穿调用链：plan.algo → CollectiveSession::xxx → SyncPrimitives::xxx
    // → EpChannel::send_sync → EpSyncFrame.algo 字段
    switch (plan.op) {
        case CollectiveOp::Barrier:
            // Barrier 不需要数据，直接调用
            sync_.barrier(sync_id, participant_mask, self_node_id, resolved_timeout);
            // Barrier 成功返回 true 时返回空 vector 表示"完成但无数据"
            return std::vector<std::uint8_t>{};

        case CollectiveOp::AllReduce:
            // AllReduce 使用 local_data
            return sync_.all_reduce(sync_id, participant_mask, self_node_id,
                                    local_data, op, dtype, resolved_timeout,
                                    static_cast<std::uint8_t>(plan.algo));

        case CollectiveOp::AllGather:
            // AllGather 使用 local_chunk
            return sync_.all_gather(sync_id, participant_mask, self_node_id,
                                    local_chunk, resolved_timeout,
                                    static_cast<std::uint8_t>(plan.algo));

        case CollectiveOp::Broadcast:
            // Broadcast：root 节点发送 data（这里用 local_data），非 root 传空
            sync_.broadcast(sync_id, participant_mask, root_node_id,
                            local_data, resolved_timeout,
                            static_cast<std::uint8_t>(plan.algo));
            // Broadcast 返回 nullopt（非数据返回操作）
            return std::nullopt;

        case CollectiveOp::ReduceScatter:
            // ReduceScatter 使用 local_data
            return sync_.reduce_scatter(sync_id, participant_mask, self_node_id,
                                        local_data, op, dtype, resolved_timeout,
                                        static_cast<std::uint8_t>(plan.algo));

        case CollectiveOp::AllToAll:
            // AllToAll 使用 local_chunk
            return sync_.all_to_all(sync_id, participant_mask, self_node_id,
                                    local_chunk, resolved_timeout,
                                    static_cast<std::uint8_t>(plan.algo));

        default:
            // 未知操作类型
            return std::nullopt;
    }
}

// ============================================================================
// 辅助函数实现
// ============================================================================

const char *collective_op_name(CollectiveOp op) noexcept {
    switch (op) {
        case CollectiveOp::Barrier:       return "barrier";
        case CollectiveOp::AllReduce:     return "all_reduce";
        case CollectiveOp::AllGather:     return "all_gather";
        case CollectiveOp::Broadcast:     return "broadcast";
        case CollectiveOp::ReduceScatter: return "reduce_scatter";
        case CollectiveOp::AllToAll:      return "all_to_all";
    }
    return "unknown";
}

const char *collective_algo_name(CollectiveAlgo algo) noexcept {
    switch (algo) {
        case CollectiveAlgo::Ring:             return "ring";
        case CollectiveAlgo::Tree:             return "tree";
        case CollectiveAlgo::RecursiveHalving: return "recursive_halving";
        case CollectiveAlgo::PairwiseExchange: return "pairwise_exchange";
    }
    return "unknown";
}

}  // namespace linoh::multimodal::ep
