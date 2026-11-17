// rh_engine.hpp — RecursiveHalving 算法引擎（v2.2 Phase 3 / P3-D）
//
// 纯算法状态机，计算 RecursiveHalving AllReduce / ReduceScatter 的通信步骤。
// 不依赖网络 IO，可独立单元测试。
//
// 算法原理（Recursive Halving，要求 N 为 2 的幂）：
//
// ReduceScatter 阶段（log₂N 步）：
//   数据分为 N 份，每步 rank 与 partner = rank XOR (1<<s) 通信：
//     - rank < partner（bit s = 0）：发送上半部分，保留下半部分并规约
//     - rank > partner（bit s = 1）：发送下半部分，保留上半部分并规约
//   log₂N 步后，每节点拥有 1 份 chunk 的完整规约结果。
//   result_idx = bit_reverse(rank, log₂N)
//
// AllGather 阶段（log₂N 步）：
//   ReduceScatter 的逆过程，每步 active range 翻倍：
//     - 与 partner 交换当前 active 数据
//   log₂N 步后，所有节点拥有完整规约结果。
//
// AllReduce = ReduceScatter + AllGather，总步数 = 2 × log₂N
//
// 通信量：
//   - 每步通信量 = msg / 2^(s+1)（递减）
//   - 总通信量/节点 = msg × (1 - 1/N) ≈ msg（远小于 Ring 的 2(N-1)msg/N）
//   - 大消息场景优于 Ring（Ring 通信量随 N 线性增长，RH 近似常数）
//
// 非二次幂处理（padding）：
//   N 非二次幂时，pad 到最近的 2 的幂 N' = 2^⌈log₂N⌉
//   多余的 N'-N 个虚拟节点数据置零，ReduceScatter 后丢弃对应 chunk
//
// 对比 Ring：
//   | 维度        | Ring              | RecursiveHalving   |
//   |------------|-------------------|-------------------|
//   | 步数        | 2(N-1)            | 2 log₂N           |
//   | 通信量/节点 | 2(N-1)msg/N       | msg(1-1/N)        |
//   | 小消息      | ✅ 更优（步数少） | ❌ 延迟高          |
//   | 大消息      | ❌ 通信量大       | ✅ 带宽优          |
//   | N 限制      | 任意              | 必须 2 的幂        |

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace linoh::multimodal::ep {

/// RecursiveHalving 算法阶段
enum class RHPhase : std::uint8_t {
    ReduceScatter = 0,  // 阶段 1：递归减半规约（log₂N 步）
    AllGather     = 1,  // 阶段 2：递归倍增传播（log₂N 步）
    Done          = 2,
};

/// 单步通信信息
struct RHStepInfo {
    std::size_t partner_rank{0};     // 通信伙伴 rank
    std::size_t send_offset{0};      // 发送数据起始偏移（字节）
    std::size_t send_length{0};      // 发送数据长度（字节）
    std::size_t recv_offset{0};      // 接收数据起始偏移（字节，规约到此范围）
    std::size_t recv_length{0};      // 接收数据长度（字节）
    bool keep_lower{false};          // true=保留下半部分，false=保留上半部分
    bool valid{false};               // 是否有效（N<=1 时无效）
};

/// RecursiveHalving 算法引擎（无状态，纯算法逻辑）
class RHEngine {
public:
    // ========== 工具函数 ==========

    /// 是否为 2 的幂
    static bool is_power_of_two(std::size_t N) noexcept;

    /// 向上 pad 到最近的 2 的幂（N=1→1, N=3→4, N=5→8, N=8→8）
    static std::size_t pad_to_power_of_two(std::size_t N) noexcept;

    /// bit 反转（log₂N 位）
    /// \param v 待反转的值
    /// \param bits 位数（log₂N）
    static std::size_t bit_reverse(std::size_t v, std::size_t bits) noexcept;

    // ========== 步数计算 ==========

    /// ReduceScatter 步数 = log₂N（N 必须为 2 的幂）
    static std::size_t reduce_scatter_steps(std::size_t N) noexcept;

    /// AllGather 步数 = log₂N
    static std::size_t all_gather_steps(std::size_t N) noexcept;

    /// AllReduce 总步数 = 2 × log₂N
    static std::size_t total_steps(std::size_t N) noexcept;

    /// 阶段判定（AllReduce 用）
    static RHPhase phase_of(std::size_t step, std::size_t N) noexcept;

    // ========== ReduceScatter 步级计算 ==========

    /// 计算 ReduceScatter 某步的通信信息
    /// \param self_rank 本节点 rank
    /// \param step 当前步数（0..log₂N-1）
    /// \param N 节点数（必须为 2 的幂）
    /// \param msg_size 消息总大小（字节，必须能被 N 整除）
    static RHStepInfo reduce_scatter_step(std::size_t self_rank, std::size_t step,
                                          std::size_t N, std::size_t msg_size) noexcept;

    /// ReduceScatter 结束后本节点拥有的 chunk 索引（= bit_reverse(rank, log₂N)）
    static std::size_t reduce_scatter_result_idx(std::size_t self_rank, std::size_t N) noexcept;

    // ========== AllGather 步级计算 ==========

    /// 计算 AllGather 某步的通信信息
    /// \param self_rank 本节点 rank
    /// \param step 当前步数（0..log₂N-1）
    /// \param N 节点数（必须为 2 的幂）
    /// \param msg_size 消息总大小（字节）
    static RHStepInfo all_gather_step(std::size_t self_rank, std::size_t step,
                                      std::size_t N, std::size_t msg_size) noexcept;

    // ========== AllReduce 步级计算（统一接口）==========

    /// 计算 AllReduce 某步的通信信息（自动分派 ReduceScatter 或 AllGather 阶段）
    /// \param step 0..2×log₂N-1
    static RHStepInfo all_reduce_step(std::size_t self_rank, std::size_t step,
                                      std::size_t N, std::size_t msg_size) noexcept;

    // ========== 通信量预估 ==========

    /// AllReduce 每节点通信量 = msg × (1 - 1/N)
    static std::size_t all_reduce_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept;

    /// ReduceScatter 每节点通信量 = msg × (1 - 1/N) / 2
    static std::size_t reduce_scatter_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept;

    /// AllGather 每节点通信量 = msg × (1 - 1/N) / 2
    static std::size_t all_gather_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept;
};

}  // namespace linoh::multimodal::ep
