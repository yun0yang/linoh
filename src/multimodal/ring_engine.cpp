// ring_engine.cpp — Ring 算法引擎实现（v2.2 Phase 3 / P3-B）
//
// 纯算法逻辑实现，不依赖网络 IO。

#include "linoh/multimodal/ring_engine.hpp"

#include <algorithm>

namespace linoh::multimodal::ep {

// ============================================================================
// 拓扑构建
// ============================================================================

std::unordered_map<std::uint64_t, RingNeighbors>
RingEngine::build_ring(const std::vector<std::uint64_t>& participants) {
    std::unordered_map<std::uint64_t, RingNeighbors> result;
    const std::size_t N = participants.size();
    if (N == 0) return result;

    result.reserve(N);
    for (std::size_t rank = 0; rank < N; ++rank) {
        RingNeighbors nb;
        nb.next = participants[(rank + 1) % N];
        nb.prev = participants[(rank - 1 + N) % N];
        result[participants[rank]] = nb;
    }
    return result;
}

std::size_t RingEngine::rank_of(const std::vector<std::uint64_t>& participants,
                                std::uint64_t node_bit) noexcept {
    for (std::size_t i = 0; i < participants.size(); ++i) {
        if (participants[i] == node_bit) return i;
    }
    return SIZE_MAX;
}

// ============================================================================
// AllReduce 分片索引计算（核心算法）
// ============================================================================

RingChunkIndex RingEngine::compute_chunk_index(std::size_t self_rank,
                                               std::size_t step,
                                               std::size_t N) noexcept {
    if (N <= 1 || step >= 2 * (N - 1)) {
        return {};
    }

    // 阶段判定
    if (step < N - 1) {
        // 阶段 1：ReduceScatter
        // send_idx = (rank - step - 1 + N) % N
        // recv_idx = (rank - step - 2 + N) % N
        std::size_t send_idx = (self_rank + N - step - 1) % N;
        std::size_t recv_idx = (self_rank + N - step - 2) % N;
        return { send_idx, recv_idx };
    } else {
        // 阶段 2：AllGather，j = step - (N-1)
        // send_idx = (rank - j + N) % N
        // recv_idx = (rank - j - 1 + N) % N
        std::size_t j = step - (N - 1);
        std::size_t send_idx = (self_rank + N - j) % N;
        std::size_t recv_idx = (self_rank + N - j - 1) % N;
        return { send_idx, recv_idx };
    }
}

}  // namespace linoh::multimodal::ep
