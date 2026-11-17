// pe_engine.hpp — PairwiseExchange 算法引擎（v2.2 Phase 3 / P3-E）
//
// 纯算法状态机，计算 PairwiseExchange AllToAll 的通信步骤。
// 不依赖网络 IO，可独立单元测试。
//
// 算法原理（Pairwise Exchange AllToAll，要求 N 为 2 的幂）：
//
// AllToAll 语义：每节点 i 有 N 份分片 [C[i][0], ..., C[i][N-1]]，
//   C[i][j] 是节点 i 发给节点 j 的数据。最终节点 j 拥有 [C[0][j], ..., C[N-1][j]]。
//
// PairwiseExchange 通过 log₂N 步完成（而非 N-1 步的全连接）：
//   step s (0..log₂N-1):
//     partner = rank XOR (1 << s)
//     - 发送：当前持有且目标 bit s 与 partner 相同的分片
//     - 接收：partner 发来的、目标 bit s 与自己相同的分片
//
//   每步交换后，节点持有的分片来源翻倍，目标范围减半。
//   log₂N 步后，每节点恰好拥有自己目标的所有 N 份分片。
//
// 示例 N=4, rank 0 (00):
//   初始: 持有 C[0][0..3]
//   step 0: partner=1, 发送 C[0][1],C[0][3] (dest bit0=1), 接收 C[1][0],C[1][2] (dest bit0=0)
//           持有: C[0][0],C[1][0],C[0][2],C[1][2] (dest bit0=0, sources {0,1})
//   step 1: partner=2, 发送 C[0][2],C[1][2] (dest bit1=1), 接收 C[2][0],C[3][0] (dest bit1=0)
//           持有: C[0][0],C[1][0],C[2][0],C[3][0] (dest=0, all sources) ✓
//
// 通信量：
//   - step s 交换 N/2^(s+1) 个分片
//   - 总通信量/节点 = Σ N/2^(s+1) = N-1 个分片 = (N-1) × chunk_size
//   - 远优于全连接的 N×(N-1) 通信量
//
// 非二次幂处理：pad 到最近的 2 的幂，多余虚拟节点的分片置零。

#pragma once

#include <cstdint>
#include <vector>

namespace linoh::multimodal::ep {

/// PairwiseExchange 算法引擎（无状态，纯算法逻辑）
class PEEngine {
public:
    // ========== 工具函数 ==========

    /// 是否为 2 的幂
    static bool is_power_of_two(std::size_t N) noexcept;

    /// 向上 pad 到最近的 2 的幂
    static std::size_t pad_to_power_of_two(std::size_t N) noexcept;

    // ========== 步数计算 ==========

    /// 总步数 = log₂N（N 必须为 2 的幂）
    static std::size_t total_steps(std::size_t N) noexcept;

    /// 通信伙伴 = rank XOR (1 << step)
    static std::size_t partner_at_step(std::size_t rank, std::size_t step) noexcept;

    // ========== 分片索引计算 ==========

    /// 某步需要发送的目标分片索引列表
    /// \param rank 本节点 rank
    /// \param step 当前步数（0..log₂N-1）
    /// \param N 节点数（必须为 2 的幂）
    /// \return 目标分片索引列表（这些分片发给 partner）
    static std::vector<std::size_t>
    send_chunk_indices(std::size_t rank, std::size_t step, std::size_t N) noexcept;

    /// 某步需要接收的目标分片索引列表
    /// \return 目标分片索引列表（这些分片从 partner 接收）
    static std::vector<std::size_t>
    recv_chunk_indices(std::size_t rank, std::size_t step, std::size_t N) noexcept;

    /// 某步后本节点持有的所有目标分片索引
    /// \param step_after 经过 step_after+1 步后（-1 表示初始状态）
    static std::vector<std::size_t>
    held_chunk_indices(std::size_t rank, std::size_t step_after, std::size_t N) noexcept;

    // ========== 通信量预估 ==========

    /// AllToAll 每节点通信量 = (N-1) × chunk_size
    static std::size_t all_to_all_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept;

    /// 某步通信量（字节数）
    /// \param step 步数
    /// \param N 节点数
    /// \param msg_size 总消息大小
    static std::size_t step_bytes(std::size_t step, std::size_t N, std::size_t msg_size) noexcept;
};

}  // namespace linoh::multimodal::ep
