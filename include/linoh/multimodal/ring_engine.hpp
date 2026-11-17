// ring_engine.hpp — Ring 算法引擎（v2.2 Phase 3 / P3-B）
//
// 纯算法状态机，计算 Ring AllReduce / AllGather / ReduceScatter 的拓扑与分片索引。
// 不依赖网络 IO，可独立单元测试。SyncPrimitives 调度层（P3-F）根据 EpSyncFrame.algo
// 字段分派到本引擎驱动实际通信。
//
// 算法原理（标准 Ring AllReduce，参考 Gibiansky "Bringing HPC Techniques to Deep Learning"）：
//
// 环拓扑：participants[0] → [1] → ... → [N-1] → [0]
//   - next_node = participants[(rank + 1) % N]  （数据发送方向）
//   - prev_node = participants[(rank - 1 + N) % N]  （数据接收方向）
//
// 阶段 1：Reduce-Scatter（N-1 步）— 每步向 next 发送一个分片，从 prev 接收一个分片并规约。
//   N-1 步后，节点 r 拥有 chunk[r] 的完整规约结果（所有 N 个节点 chunk[r] 的聚合）。
//
//   step i (0..N-2):
//     send_idx = (rank - i - 1 + N) % N   // 本步发送的分片索引
//     recv_idx = (rank - i - 2 + N) % N   // 本步接收并规约的分片索引
//
//   索引匹配验证：节点 r 发送 chunk[(r-i-1+N)%N] 给 next=r+1，
//   节点 r+1 的 recv_idx = (r+1-i-2+N)%N = (r-i-1+N)%N ✓ 匹配
//
// 阶段 2：All-Gather（N-1 步）— 每步向 next 发送已规约的分片，从 prev 接收新分片（覆盖，不规约）。
//   N-1 步后，所有节点拥有全部 N 个分片的规约结果。
//
//   step i (0..N-2):
//     send_idx = (rank - i + N) % N       // 本步发送的分片（上一步接收的或自身规约结果）
//     recv_idx = (rank - i - 1 + N) % N   // 本步接收的分片
//
// 全量 AllReduce 总步数 = 2 × (N - 1)
// 单节点通信量 = 2 × (N-1) × (msg / N) = 2(N-1)msg/N（理论最优）
//
// AllGather-only（无规约）：仅阶段 2 逻辑，N-1 步，每节点发送 own chunk 并沿环传播。
//   step i: send_idx = (rank - i + N) % N, recv_idx = (rank - i - 1 + N) % N
//
// ReduceScatter-only：仅阶段 1 逻辑，N-1 步，结束后节点 r 拥有 chunk[r] 规约结果。
//
// 设计原则：
//   - 纯静态方法，无状态，线程安全
//   - 不依赖 EpChannel / SyncPrimitives / 真实网络
//   - 拓扑计算与数据收发解耦，便于单元测试
//   - 与 CommPlannerV2::TopologyPlan 协同：plan.route 提供环顺序，本引擎计算分片索引

#pragma once

#include <array>
#include <cstdint>
#include <unordered_map>
#include <utility>
#include <vector>

namespace linoh::multimodal::ep {

/// Ring 算法状态机阶段
enum class RingPhase : std::uint8_t {
    ReduceScatter = 0,  // 阶段 1：环形规约（N-1 步）
    AllGather     = 1,  // 阶段 2：环形传播（N-1 步）
    Done          = 2,  // 完成
};

/// Ring 邻居信息（build_ring 返回）
struct RingNeighbors {
    std::uint64_t next{0};  // 右邻居（数据发送目标），环方向 rank+1
    std::uint64_t prev{0};  // 左邻居（数据接收来源），环方向 rank-1
};

/// 单步分片索引（send/recv）
struct RingChunkIndex {
    std::size_t send_idx{0};  // 本步应发送的分片索引
    std::size_t recv_idx{0};  // 本步应接收（并规约/覆盖）的分片索引
};

/// Ring 算法引擎（无状态，纯算法逻辑）
///
/// 用法（与 SyncPrimitives 集成，P3-F）：
///   auto neighbors = RingEngine::build_ring(participants);
///   auto self_rank = index_of(participants, self_bit);
///   for (step = 0; step < RingEngine::total_steps(N); ++step) {
///       auto idx = RingEngine::compute_chunk_index(self_rank, step, N);
///       // 发送 chunks[idx.send_idx] 到 neighbors[self].next
///       // 从 neighbors[self].prev 接收，规约到 chunks[idx.recv_idx]
///   }
class RingEngine {
public:
    // ====================================================================
    // 拓扑构建
    // ====================================================================

    /// 构建环拓扑：participants[0] → [1] → ... → [N-1] → [0]
    /// \param participants 有序节点 bit position 列表（按升序或 CommPlannerV2 排序）
    /// \return map: self_bit -> (next_bit, prev_bit)
    ///         next = participants[(rank+1)%N]，prev = participants[(rank-1+N)%N]
    static std::unordered_map<std::uint64_t, RingNeighbors>
    build_ring(const std::vector<std::uint64_t>& participants);

    /// 获取指定节点的环位置（rank）
    /// \param participants 有序节点列表
    /// \param node_bit 目标节点 bit position
    /// \return rank（0-indexed），若不在列表中返回 SIZE_MAX
    static std::size_t rank_of(const std::vector<std::uint64_t>& participants,
                               std::uint64_t node_bit) noexcept;

    // ====================================================================
    // AllReduce 全量（阶段 1 + 阶段 2）
    // ====================================================================

    /// AllReduce 总步数 = 2 × (N - 1)
    static std::size_t total_steps(std::size_t N) noexcept {
        return N <= 1 ? 0 : 2 * (N - 1);
    }

    /// AllReduce 指定步数的阶段
    /// \param step 0..2N-3
    /// \param N 节点数
    static RingPhase phase_of(std::size_t step, std::size_t N) noexcept {
        if (N <= 1 || step >= 2 * (N - 1)) return RingPhase::Done;
        if (step < N - 1) return RingPhase::ReduceScatter;
        return RingPhase::AllGather;
    }

    /// AllReduce 指定步数的分片索引（核心算法）
    ///
    /// 阶段 1（ReduceScatter，step 0..N-2）：
    ///   send_idx = (rank - step - 1 + N) % N
    ///   recv_idx = (rank - step - 2 + N) % N
    ///
    /// 阶段 2（AllGather，step N-1..2N-3，记 j = step - (N-1)）：
    ///   send_idx = (rank - j + N) % N
    ///   recv_idx = (rank - j - 1 + N) % N
    ///
    /// \param self_rank 本节点在环中的位置（0-indexed）
    /// \param step 当前步数（0..2N-3）
    /// \param N 节点数
    /// \return (send_idx, recv_idx)
    static RingChunkIndex compute_chunk_index(std::size_t self_rank,
                                              std::size_t step,
                                              std::size_t N) noexcept;

    // ====================================================================
    // AllGather-only（仅阶段 2，N-1 步）
    // ====================================================================

    /// AllGather 总步数 = N - 1
    static std::size_t all_gather_steps(std::size_t N) noexcept {
        return N <= 1 ? 0 : N - 1;
    }

    /// AllGather 指定步数的分片索引
    /// step i: send_idx = (rank - i + N) % N, recv_idx = (rank - i - 1 + N) % N
    static RingChunkIndex all_gather_chunk_index(std::size_t self_rank,
                                                 std::size_t step,
                                                 std::size_t N) noexcept {
        if (N == 0) return {};
        return { (self_rank - step + N) % N, (self_rank - step - 1 + N) % N };
    }

    // ====================================================================
    // ReduceScatter-only（仅阶段 1，N-1 步）
    // ====================================================================

    /// ReduceScatter 总步数 = N - 1
    static std::size_t reduce_scatter_steps(std::size_t N) noexcept {
        return N <= 1 ? 0 : N - 1;
    }

    /// ReduceScatter 指定步数的分片索引（= AllReduce 阶段 1）
    /// step i: send_idx = (rank - i - 1 + N) % N, recv_idx = (rank - i - 2 + N) % N
    static RingChunkIndex reduce_scatter_chunk_index(std::size_t self_rank,
                                                     std::size_t step,
                                                     std::size_t N) noexcept {
        if (N == 0) return {};
        return { (self_rank - step - 1 + N) % N, (self_rank - step - 2 + N) % N };
    }

    /// ReduceScatter 完成后，本节点拥有的完整规约分片索引 = self_rank
    /// （节点 r 拥有 chunk[r] 的完整规约结果）
    static std::size_t reduce_scatter_result_idx(std::size_t self_rank) noexcept {
        return self_rank;
    }

    // ====================================================================
    // 通信量预估（性能基准用）
    // ====================================================================

    /// AllReduce 单节点总通信量 = 2 × (N-1) × (msg / N)
    static std::size_t all_reduce_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept {
        if (N <= 1) return 0;
        return 2 * (N - 1) * (msg_size / N);
    }

    /// AllGather 单节点总通信量 = (N-1) × (msg / N)
    static std::size_t all_gather_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept {
        if (N <= 1) return 0;
        return (N - 1) * (msg_size / N);
    }

    /// ReduceScatter 单节点总通信量 = (N-1) × (msg / N)
    static std::size_t reduce_scatter_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept {
        if (N <= 1) return 0;
        return (N - 1) * (msg_size / N);
    }
};

}  // namespace linoh::multimodal::ep
