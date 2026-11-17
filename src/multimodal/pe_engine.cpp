// pe_engine.cpp — PairwiseExchange 算法引擎实现（v2.2 Phase 3 / P3-E）

#include "linoh/multimodal/pe_engine.hpp"

#include <bit>  // std::bit_width, std::has_single_bit (C++20)

namespace linoh::multimodal::ep {

// ========== 工具函数 ==========

bool PEEngine::is_power_of_two(std::size_t N) noexcept {
    return N > 0 && std::has_single_bit(N);
}

std::size_t PEEngine::pad_to_power_of_two(std::size_t N) noexcept {
    if (N <= 1) return 1;
    return std::size_t{1} << std::bit_width(N - 1);
}

// ========== 步数计算 ==========

std::size_t PEEngine::total_steps(std::size_t N) noexcept {
    if (N <= 1) return 0;
    return std::bit_width(N) - 1;  // log₂N
}

std::size_t PEEngine::partner_at_step(std::size_t rank, std::size_t step) noexcept {
    return rank ^ (std::size_t{1} << step);
}

// ========== 分片索引计算 ==========

std::vector<std::size_t>
PEEngine::send_chunk_indices(std::size_t rank, std::size_t step, std::size_t N) noexcept {
    std::vector<std::size_t> result;
    if (N <= 1 || !is_power_of_two(N) || step >= total_steps(N)) {
        return result;
    }

    // 发送条件：dest 的 bits 0..step-1 = rank 的 bits 0..step-1
    //           AND dest 的 bit step = 1 - rank 的 bit step
    std::size_t base_mask = (std::size_t{1} << step) - 1;  // 低 step 位的掩码
    std::size_t base = rank & base_mask;                    // 匹配的低 step 位
    std::size_t bit_s = (rank >> step) & 1;
    std::size_t partner_bit = 1 - bit_s;

    // 遍历高位（step+1 及以上），构造所有合法 dest
    std::size_t high_shift = step + 1;
    std::size_t high_count = N >> high_shift;  // 高位的组合数
    for (std::size_t high = 0; high < high_count; ++high) {
        std::size_t d = base | (partner_bit << step) | (high << high_shift);
        if (d < N) {
            result.push_back(d);
        }
    }
    return result;
}

std::vector<std::size_t>
PEEngine::recv_chunk_indices(std::size_t rank, std::size_t step, std::size_t N) noexcept {
    std::vector<std::size_t> result;
    if (N <= 1 || !is_power_of_two(N) || step >= total_steps(N)) {
        return result;
    }

    // 接收条件：dest 的 bits 0..step-1 = rank 的 bits 0..step-1
    //           AND dest 的 bit step = rank 的 bit step（与自己相同）
    std::size_t base_mask = (std::size_t{1} << step) - 1;
    std::size_t base = rank & base_mask;
    std::size_t bit_s = (rank >> step) & 1;

    std::size_t high_shift = step + 1;
    std::size_t high_count = N >> high_shift;
    for (std::size_t high = 0; high < high_count; ++high) {
        std::size_t d = base | (bit_s << step) | (high << high_shift);
        if (d < N) {
            result.push_back(d);
        }
    }
    return result;
}

std::vector<std::size_t>
PEEngine::held_chunk_indices(std::size_t rank, std::size_t step_after, std::size_t N) noexcept {
    std::vector<std::size_t> result;
    if (N <= 1) {
        if (N == 1) result.push_back(0);
        return result;
    }

    // 经过 step_after+1 步后，持有的 dest 满足：
    //   bits 0..step_after = rank 的 bits 0..step_after
    // step_after = -1 (用 SIZE_MAX 表示) 时，持有所有 dest（初始状态）
    if (step_after == static_cast<std::size_t>(-1)) {
        for (std::size_t d = 0; d < N; ++d) {
            result.push_back(d);
        }
        return result;
    }

    std::size_t mask = (std::size_t{1} << (step_after + 1)) - 1;  // 低 step_after+1 位的掩码
    std::size_t base = rank & mask;
    std::size_t high_shift = step_after + 1;
    std::size_t high_count = N >> high_shift;
    for (std::size_t high = 0; high < high_count; ++high) {
        std::size_t d = base | (high << high_shift);
        if (d < N) {
            result.push_back(d);
        }
    }
    return result;
}

// ========== 通信量预估 ==========

std::size_t PEEngine::all_to_all_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept {
    if (N <= 1) return 0;
    std::size_t chunk_size = msg_size / N;
    return (N - 1) * chunk_size;
}

std::size_t PEEngine::step_bytes(std::size_t step, std::size_t N, std::size_t msg_size) noexcept {
    if (N <= 1 || step >= total_steps(N)) return 0;
    std::size_t chunk_size = msg_size / N;
    // step s 交换 N/2^(s+1) 个分片
    std::size_t chunks_at_step = N >> (step + 1);
    return chunks_at_step * chunk_size;
}

}  // namespace linoh::multimodal::ep
