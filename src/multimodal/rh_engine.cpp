// rh_engine.cpp — RecursiveHalving 算法引擎实现（v2.2 Phase 3 / P3-D）

#include "linoh/multimodal/rh_engine.hpp"

#include <bit>  // std::bit_width, std::has_single_bit (C++20)

namespace linoh::multimodal::ep {

// ========== 工具函数 ==========

bool RHEngine::is_power_of_two(std::size_t N) noexcept {
    return N > 0 && std::has_single_bit(N);
}

std::size_t RHEngine::pad_to_power_of_two(std::size_t N) noexcept {
    if (N <= 1) return 1;
    return std::size_t{1} << std::bit_width(N - 1);
}

std::size_t RHEngine::bit_reverse(std::size_t v, std::size_t bits) noexcept {
    std::size_t result = 0;
    for (std::size_t i = 0; i < bits; ++i) {
        if ((v >> i) & 1) {
            result |= (std::size_t{1} << (bits - 1 - i));
        }
    }
    return result;
}

// ========== 步数计算 ==========

std::size_t RHEngine::reduce_scatter_steps(std::size_t N) noexcept {
    if (N <= 1) return 0;
    return std::bit_width(N) - 1;  // log₂N
}

std::size_t RHEngine::all_gather_steps(std::size_t N) noexcept {
    return reduce_scatter_steps(N);
}

std::size_t RHEngine::total_steps(std::size_t N) noexcept {
    return 2 * reduce_scatter_steps(N);
}

RHPhase RHEngine::phase_of(std::size_t step, std::size_t N) noexcept {
    std::size_t rs_steps = reduce_scatter_steps(N);
    if (step < rs_steps) return RHPhase::ReduceScatter;
    if (step < 2 * rs_steps) return RHPhase::AllGather;
    return RHPhase::Done;
}

// ========== ReduceScatter 步级计算 ==========

RHStepInfo RHEngine::reduce_scatter_step(std::size_t self_rank, std::size_t step,
                                          std::size_t N, std::size_t msg_size) noexcept {
    RHStepInfo info{};
    if (N <= 1 || !is_power_of_two(N) || step >= reduce_scatter_steps(N)) {
        return info;
    }

    std::size_t chunk_size = msg_size / N;
    std::size_t partner = self_rank ^ (std::size_t{1} << step);

    // 计算 active range 起始（基于前 step 步的决策）
    std::size_t active_start = 0;
    std::size_t active_size = N;
    for (std::size_t s = 0; s < step; ++s) {
        std::size_t half = active_size / 2;
        if ((self_rank >> s) & 1) {
            active_start += half;  // 保留了上半
        }
        active_size = half;
    }

    // 当前步的 active range: [active_start, active_start + active_size)
    std::size_t mid = active_start + active_size / 2;
    bool keep_lower = ((self_rank >> step) & 1) == 0;  // bit step = 0 → 保留下半

    info.partner_rank = partner;
    info.keep_lower = keep_lower;

    if (keep_lower) {
        // 保留下半 [active_start, mid)，发送上半 [mid, active_start + active_size)
        info.send_offset = mid * chunk_size;
        info.send_length = (active_size / 2) * chunk_size;
        // 接收 partner 的下半 [active_start, mid)，规约到本地下半
        info.recv_offset = active_start * chunk_size;
        info.recv_length = (active_size / 2) * chunk_size;
    } else {
        // 保留上半 [mid, active_start + active_size)，发送下半 [active_start, mid)
        info.send_offset = active_start * chunk_size;
        info.send_length = (active_size / 2) * chunk_size;
        // 接收 partner 的上半 [mid, ...)，规约到本地上半
        info.recv_offset = mid * chunk_size;
        info.recv_length = (active_size / 2) * chunk_size;
    }

    info.valid = true;
    return info;
}

std::size_t RHEngine::reduce_scatter_result_idx(std::size_t self_rank, std::size_t N) noexcept {
    if (N <= 1) return 0;
    std::size_t bits = reduce_scatter_steps(N);
    return bit_reverse(self_rank, bits);
}

// ========== AllGather 步级计算 ==========

RHStepInfo RHEngine::all_gather_step(std::size_t self_rank, std::size_t step,
                                      std::size_t N, std::size_t msg_size) noexcept {
    RHStepInfo info{};
    if (N <= 1 || !is_power_of_two(N) || step >= all_gather_steps(N)) {
        return info;
    }

    std::size_t log2N = reduce_scatter_steps(N);
    std::size_t chunk_size = msg_size / N;

    // AllGather step s 对应 ReduceScatter step (log2N - 1 - s)
    std::size_t rev_step = log2N - 1 - step;
    std::size_t partner = self_rank ^ (std::size_t{1} << rev_step);

    // 计算 active range 起始
    // 初始：active_start = reduce_scatter_result_idx(self_rank, N)
    //       active_size = 1
    // 每步 active_size 翻倍
    std::size_t active_start = reduce_scatter_result_idx(self_rank, N);
    std::size_t active_size = 1;
    for (std::size_t s = 0; s < step; ++s) {
        std::size_t bit_pos = log2N - 1 - s;
        if ((self_rank >> bit_pos) & 1) {
            // 本节点在上半，partner 在下半，active_start 下移
            active_start -= active_size;
        }
        active_size *= 2;
    }

    // 当前步：partner = rank XOR (1 << rev_step)
    // bit rev_step 决定本节点在合并后范围的位置
    bool is_upper = ((self_rank >> rev_step) & 1) != 0;

    info.partner_rank = partner;
    info.keep_lower = !is_upper;  // 下半 = lower

    // 发送：当前 active range [active_start, active_start + active_size)
    info.send_offset = active_start * chunk_size;
    info.send_length = active_size * chunk_size;

    // 接收：partner 的 active range，与本节点相邻
    if (is_upper) {
        // 本节点在上半 [active_start, active_start + active_size)
        // partner 在下半 [active_start - active_size, active_start)
        info.recv_offset = (active_start - active_size) * chunk_size;
        info.recv_length = active_size * chunk_size;
    } else {
        // 本节点在下半 [active_start, active_start + active_size)
        // partner 在上半 [active_start + active_size, active_start + 2*active_size)
        info.recv_offset = (active_start + active_size) * chunk_size;
        info.recv_length = active_size * chunk_size;
    }

    info.valid = true;
    return info;
}

// ========== AllReduce 步级计算 ==========

RHStepInfo RHEngine::all_reduce_step(std::size_t self_rank, std::size_t step,
                                      std::size_t N, std::size_t msg_size) noexcept {
    std::size_t rs_steps = reduce_scatter_steps(N);
    if (step < rs_steps) {
        // ReduceScatter 阶段
        return reduce_scatter_step(self_rank, step, N, msg_size);
    } else if (step < 2 * rs_steps) {
        // AllGather 阶段
        return all_gather_step(self_rank, step - rs_steps, N, msg_size);
    }
    return RHStepInfo{};
}

// ========== 通信量预估 ==========

std::size_t RHEngine::all_reduce_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept {
    if (N <= 1) return 0;
    // 每步通信量递减：msg/2 + msg/4 + ... + msg/N = msg(1 - 1/N)
    // ReduceScatter + AllGather = 2 × msg(1 - 1/N)
    // 但通常报告单方向：msg(1 - 1/N)
    return msg_size - msg_size / N;
}

std::size_t RHEngine::reduce_scatter_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept {
    return all_reduce_bytes_per_node(N, msg_size) / 2;
}

std::size_t RHEngine::all_gather_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept {
    return all_reduce_bytes_per_node(N, msg_size) / 2;
}

}  // namespace linoh::multimodal::ep
