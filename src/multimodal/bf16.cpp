// bf16.cpp — v3.9.4 bf16 转换工具实现
//
// 纯位运算实现，跨平台一致（不依赖硬件 bf16 指令如 AVX-512 BF16 / ARMv8.6 BF16）。
// 通过 memcpy 处理 fp32↔uint32_t 别名转换，避免 strict aliasing UB。

#include "linoh/multimodal/bf16.hpp"

#include <cstring>
#include <stdexcept>

namespace linoh::multimodal {

// ============================================================================
// 单元素转换（核心算法）
// ============================================================================

bf16_bits_t fp32_to_bf16_bits(std::uint32_t fp32_bits) noexcept {
    // fp32 布局：[sign(1)][exponent(8)][mantissa(23)]
    // bf16 布局：[sign(1)][exponent(8)][mantissa(7)]
    // 截断位置：fp32 的低 16 位（mantissa 的低 16 位）被丢弃

    const bf16_bits_t bf16_high = static_cast<bf16_bits_t>(fp32_bits >> 16);
    const std::uint16_t truncated_low = static_cast<std::uint16_t>(fp32_bits & 0xFFFF);

    // NaN 传播：若 fp32 是 NaN（exponent=0xFF 且 mantissa!=0），
    // 必须保证 bf16 也是 NaN（exponent=0xFF 且 mantissa!=0）。
    // 截断后 bf16 mantissa 高 7 位可能全 0，导致 NaN→Inf，需强制置位。
    const std::uint32_t exponent = (fp32_bits >> 23) & 0xFF;
    const std::uint32_t mantissa = fp32_bits & 0x7FFFFF;
    if (exponent == 0xFF && mantissa != 0) {
        // 强制 mantissa 最高位为 1（保证 bf16 mantissa != 0，即仍是 NaN）
        // 第 6 位对应 mantissa 的最高位（bf16 mantissa 7 位中的 MSB）
        return static_cast<bf16_bits_t>(bf16_high | 0x0040);
    }

    // Round-to-nearest-even：
    //   - truncated_low > 0x8000：舍入部分 > 0.5 ULP，向上舍入
    //   - truncated_low == 0x8000 且 bf16 最低位为 1：正好 0.5 ULP，向偶数舍入（向上）
    //   - truncated_low == 0x8000 且 bf16 最低位为 0：正好 0.5 ULP，向偶数舍入（向下，不变）
    //   - truncated_low < 0x8000：舍入部分 < 0.5 ULP，向下舍入（不变）
    bf16_bits_t result = bf16_high;
    if (truncated_low > 0x8000 || (truncated_low == 0x8000 && (bf16_high & 1) != 0)) {
        ++result;
    }

    // 注意：舍入可能触发 mantissa 进位到 exponent，甚至 exponent 溢出到 Inf。
    // 这是 IEEE 754 标准行为（如 fp32 最大值舍入后变 Inf），无需特殊处理。
    return result;
}

std::uint32_t bf16_to_fp32_bits(bf16_bits_t bf16_bits) noexcept {
    // bf16 → fp32 仅需左移 16 位，低 16 位补零（无损扩展）
    return static_cast<std::uint32_t>(bf16_bits) << 16;
}

bf16_bits_t fp32_to_bf16(float f) noexcept {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &f, sizeof(bits));
    return fp32_to_bf16_bits(bits);
}

float bf16_to_fp32(bf16_bits_t b) noexcept {
    const std::uint32_t bits = bf16_to_fp32_bits(b);
    float f = 0.0f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

// ============================================================================
// 批量转换
// ============================================================================

std::size_t fp32_array_to_bf16_bytes(const float *src,
                                     std::size_t num_elements,
                                     std::span<std::uint8_t> out) noexcept {
    const std::size_t required = bf16_bytes(num_elements);
    if (out.size() < required) {
        return 0;  // 缓冲区不足，返回 0 表示失败
    }

    for (std::size_t i = 0; i < num_elements; ++i) {
        std::uint32_t fp32_bits = 0;
        std::memcpy(&fp32_bits, src + i, sizeof(fp32_bits));
        const bf16_bits_t bf16 = fp32_to_bf16_bits(fp32_bits);

        // 小端序写入
        out[i * 2] = static_cast<std::uint8_t>(bf16 & 0xFF);
        out[i * 2 + 1] = static_cast<std::uint8_t>((bf16 >> 8) & 0xFF);
    }
    return required;
}

std::size_t bf16_bytes_to_fp32_array(const std::uint8_t *src,
                                     std::size_t num_elements,
                                     std::span<float> out) noexcept {
    const std::size_t required = bf16_bytes(num_elements);
    if (out.size() < num_elements) {
        return 0;  // 输出缓冲区不足
    }

    for (std::size_t i = 0; i < num_elements; ++i) {
        // 小端序读取
        const bf16_bits_t bf16 = static_cast<bf16_bits_t>(src[i * 2]) |
                                 (static_cast<bf16_bits_t>(src[i * 2 + 1]) << 8);
        const std::uint32_t fp32_bits = bf16_to_fp32_bits(bf16);
        std::memcpy(out.data() + i, &fp32_bits, sizeof(fp32_bits));
    }
    return required;
}

std::vector<std::uint8_t> fp32_vec_to_bf16_bytes(const std::vector<float> &fp32_data) {
    std::vector<std::uint8_t> out(bf16_bytes(fp32_data.size()));
    if (fp32_data.empty()) {
        return out;
    }
    const std::size_t written = fp32_array_to_bf16_bytes(
        fp32_data.data(), fp32_data.size(), std::span<std::uint8_t>(out));
    if (written == 0 && !fp32_data.empty()) {
        // 理论不会发生（已预分配足够空间），防御性抛异常
        throw std::runtime_error("fp32_vec_to_bf16_bytes: internal buffer allocation failed");
    }
    return out;
}

std::vector<float> bf16_bytes_to_fp32_vec(const std::vector<std::uint8_t> &bf16_bytes_in) {
    if (bf16_bytes_in.size() % 2 != 0) {
        throw std::runtime_error("bf16_bytes_to_fp32_vec: input byte count must be even");
    }
    const std::size_t num_elements = bf16_bytes_in.size() / 2;
    std::vector<float> out(num_elements);
    if (num_elements == 0) {
        return out;
    }
    const std::size_t read = bf16_bytes_to_fp32_array(
        bf16_bytes_in.data(), num_elements, std::span<float>(out));
    if (read == 0 && num_elements > 0) {
        throw std::runtime_error("bf16_bytes_to_fp32_vec: internal buffer allocation failed");
    }
    return out;
}

}  // namespace linoh::multimodal
