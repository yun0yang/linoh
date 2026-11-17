// tree_engine.cpp — Tree 算法引擎实现（v2.2 Phase 3 / P3-C）
//
// Binomial Tree Broadcast 纯算法逻辑实现。

#include "linoh/multimodal/tree_engine.hpp"

#include <bit>  // std::bit_width (C++20)

namespace linoh::multimodal::ep {

// ========== 拓扑构建 ==========

std::unordered_map<std::uint64_t, std::vector<std::uint64_t>>
TreeEngine::build_binomial_tree(const std::vector<std::uint64_t>& participants,
                                std::size_t root_rank) {
    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> result;
    const std::size_t N = participants.size();
    if (N == 0) return result;

    // root_rank 取模防止越界
    root_rank = root_rank % N;

    result.reserve(N);
    for (std::size_t real_rank = 0; real_rank < N; ++real_rank) {
        std::size_t vrank = to_virtual(real_rank, root_rank);
        auto children_v = children_of(vrank, N);
        std::vector<std::uint64_t> children_bits;
        children_bits.reserve(children_v.size());
        for (std::size_t cv : children_v) {
            std::size_t creal = to_real(cv, root_rank);
            if (creal < N) {
                children_bits.push_back(participants[creal]);
            }
        }
        result[participants[real_rank]] = std::move(children_bits);
    }
    return result;
}

// ========== 步数与阶段 ==========

std::size_t TreeEngine::total_steps(std::size_t N) noexcept {
    if (N <= 1) return 0;
    // ⌈log₂N⌉ = bit_width(N - 1)
    return std::bit_width(N - 1);
}

// ========== 节点角色与关系 ==========

TreeNodeRole TreeEngine::node_role(std::size_t virtual_rank, std::size_t N) noexcept {
    if (virtual_rank == 0) return TreeNodeRole::Root;
    auto children = children_of(virtual_rank, N);
    if (children.empty()) return TreeNodeRole::Leaf;
    return TreeNodeRole::Internal;
}

std::optional<std::size_t>
TreeEngine::parent_of(std::size_t virtual_rank) noexcept {
    if (virtual_rank == 0) return std::nullopt;  // root 无父节点
    // MSB 位置
    std::size_t msb_pos = std::bit_width(virtual_rank) - 1;
    // 父节点 = 清除 MSB
    std::size_t parent = virtual_rank & ~(std::size_t{1} << msb_pos);
    return parent;
}

std::vector<std::size_t>
TreeEngine::children_of(std::size_t virtual_rank, std::size_t N) noexcept {
    std::vector<std::size_t> children;
    if (N <= 1) return children;

    std::size_t steps = total_steps(N);

    // 首个发送步
    std::optional<std::size_t> first_send;
    if (virtual_rank == 0) {
        first_send = 0;
    } else {
        auto recv_step = recv_step_of(virtual_rank);
        if (!recv_step.has_value()) return children;
        first_send = recv_step.value() + 1;
    }

    // 从 first_send 到 total_steps-1，每步发送给 virtual_rank + 2^step
    for (std::size_t s = first_send.value(); s < steps; ++s) {
        std::size_t child = virtual_rank + (std::size_t{1} << s);
        if (child < N) {
            children.push_back(child);
        }
    }
    return children;
}

// ========== 步级调度 ==========

std::optional<std::size_t>
TreeEngine::recv_step_of(std::size_t virtual_rank) noexcept {
    if (virtual_rank == 0) return std::nullopt;  // root 不接收
    // MSB 位置 = 接收步数
    return std::bit_width(virtual_rank) - 1;
}

std::optional<std::size_t>
TreeEngine::first_send_step(std::size_t virtual_rank, std::size_t N) noexcept {
    if (N <= 1) return std::nullopt;

    auto children = children_of(virtual_rank, N);
    if (children.empty()) return std::nullopt;  // 纯叶子，无子节点

    if (virtual_rank == 0) return 0;
    auto recv_step = recv_step_of(virtual_rank);
    if (!recv_step.has_value()) return std::nullopt;
    return recv_step.value() + 1;
}

std::optional<std::size_t>
TreeEngine::send_target_at_step(std::size_t virtual_rank, std::size_t step,
                                 std::size_t N) noexcept {
    if (N <= 1) return std::nullopt;

    // 节点在 step s 发送的条件：
    //   1. virtual_rank < 2^step（已有数据）
    //   2. virtual_rank + 2^step < N（目标存在）
    std::size_t threshold = std::size_t{1} << step;
    if (virtual_rank >= threshold) return std::nullopt;  // 还没有数据

    std::size_t target = virtual_rank + threshold;
    if (target >= N) return std::nullopt;

    return target;
}

std::optional<std::size_t>
TreeEngine::recv_source_at_step(std::size_t virtual_rank, std::size_t step,
                                 std::size_t N) noexcept {
    if (N <= 1 || virtual_rank == 0) return std::nullopt;

    // 节点在 step s 接收的条件：
    //   virtual_rank 的 MSB 位置 = step（仅在这一步接收）
    auto recv_step = recv_step_of(virtual_rank);
    if (!recv_step.has_value() || recv_step.value() != step) return std::nullopt;

    // 发送方 = 父节点
    return parent_of(virtual_rank);
}

// ========== 通信量预估 ==========

std::size_t TreeEngine::broadcast_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept {
    if (N <= 1) return 0;
    // root 发送 log₂N 次，叶子接收 1 次，平均 = (log₂N + 1) / 2 × msg
    // 但更常用的指标是总通信量 / N = (N-1) × msg / N
    if (N == 0) return 0;
    return (N - 1) * msg_size / N;
}

std::size_t TreeEngine::root_send_count(std::size_t N) noexcept {
    return total_steps(N);
}

std::size_t TreeEngine::total_send_count(std::size_t N) noexcept {
    if (N == 0) return 0;
    return N - 1;  // 每个非 root 节点恰好被发送一次
}

}  // namespace linoh::multimodal::ep
