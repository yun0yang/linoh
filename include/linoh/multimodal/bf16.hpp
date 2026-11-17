// bf16.hpp — v3.9.4 bf16 (Brain Float 16) 转换工具
//
// bf16 格式：[sign(1)][exponent(8)][mantissa(7)]，共 16 位
//   - 与 fp32 共享相同的 sign + exponent 字段位置（高 16 位语义对齐）
//   - mantissa 截断到高 7 位（fp32 是 23 位），精度降低但指数范围相同
//   - 适合 LLM hidden_state 传输：精度损失可接受（< 0.4%），带宽节省 50%
//
// 转换算法：round-to-nearest-even（IEEE 754 默认舍入模式）
//   - 取 fp32 高 16 位作为 bf16 基础值
//   - 检查被截断的低 17 位尾数：> 0.5 ULP 向上舍入；== 0.5 ULP 时向偶数舍入
//   - NaN 传播：fp32 NaN 转 bf16 必须保持 NaN（不能变成 Inf），强制 mantissa 高位为 1
//
// 设计要点：
//   - 纯位运算，无浮点指令，跨平台一致（不依赖硬件 bf16 支持）
//   - 通过 memcpy 处理 fp32↔uint32_t 别名（避免 strict aliasing UB）
//   - 批量转换接口（fp32 数组 ↔ bf16 字节流），适合 hidden_state 整体编解码
//   - 与 TensorStream 配合：bf16 数据走 TensorDType::BF16 通道，TensorMeta.dtype=BF16

#ifndef LINOH_MULTIMODAL_BF16_HPP
#define LINOH_MULTIMODAL_BF16_HPP

#include <cstdint>
#include <cstddef>
#include <span>
#include <vector>

namespace linoh::multimodal {

/// bf16 位表示（16 位无符号整数，按 IEEE 754 bf16 布局）
using bf16_bits_t = std::uint16_t;

/// 单个 fp32 → bf16 位转换（round-to-nearest-even）
///
/// 算法：
///   1. 取 fp32 高 16 位作为 bf16 基础
///   2. NaN 传播：若 fp32 是 NaN（exp=0xFF, mantissa!=0），强制 bf16 mantissa 高位=1
///   3. 检查被截断的低 16 位：> 0x8000 或 == 0x8000 且 bf16 低位为 1 时向上舍入
///
/// \param fp32_bits fp32 的位表示（通过 memcpy 从 float 获得）
/// \return bf16 的位表示
bf16_bits_t fp32_to_bf16_bits(std::uint32_t fp32_bits) noexcept;

/// 单个 bf16 位 → fp32 位转换（无损，仅左移 16 位补零）
///
/// \param bf16_bits bf16 的位表示
/// \return fp32 的位表示（通过 memcpy 转为 float）
std::uint32_t bf16_to_fp32_bits(bf16_bits_t bf16_bits) noexcept;

/// 单个 fp32 → bf16 浮点值（便利接口）
/// \note 返回 uint16_t 位表示，因 C++ 无原生 bf16 类型
bf16_bits_t fp32_to_bf16(float f) noexcept;

/// 单个 bf16 位 → fp32 浮点值（便利接口）
float bf16_to_fp32(bf16_bits_t b) noexcept;

// ===== 批量转换接口（hidden_state 整体编解码）=====

/// 批量 fp32 → bf16 字节流
///
/// 将 num_elements 个 fp32 元素转换为 bf16 字节流（小端序）。
/// 输出缓冲区大小必须 >= num_elements * 2 字节。
///
/// \param src fp32 源数组
/// \param num_elements 元素个数
/// \param out 输出字节缓冲区（bf16 字节流，小端序）
/// \return 实际写入的字节数（= num_elements * 2）
std::size_t fp32_array_to_bf16_bytes(const float *src,
                                     std::size_t num_elements,
                                     std::span<std::uint8_t> out) noexcept;

/// 批量 bf16 字节流 → fp32 数组
///
/// 将 bf16 字节流（小端序）转换为 num_elements 个 fp32 元素。
/// 输入字节数必须 >= num_elements * 2。
///
/// \param src bf16 字节流（小端序）
/// \param num_elements 元素个数
/// \param out 输出 fp32 数组
/// \return 实际读取的字节数（= num_elements * 2）
std::size_t bf16_bytes_to_fp32_array(const std::uint8_t *src,
                                     std::size_t num_elements,
                                     std::span<float> out) noexcept;

/// 批量 fp32 → bf16 字节流（vector 便利接口）
///
/// \param fp32_data fp32 数据向量
/// \return bf16 字节流（小端序，大小 = fp32_data.size() * 2）
std::vector<std::uint8_t> fp32_vec_to_bf16_bytes(const std::vector<float> &fp32_data);

/// 批量 bf16 字节流 → fp32 数组（vector 便利接口）
///
/// \param bf16_bytes bf16 字节流（小端序，字节数必须为偶数）
/// \return fp32 数据向量（大小 = bf16_bytes.size() / 2）
std::vector<float> bf16_bytes_to_fp32_vec(const std::vector<std::uint8_t> &bf16_bytes);

// ===== 辅助函数 =====

/// 计算 num_elements 个 bf16 元素所需的字节数
constexpr std::size_t bf16_bytes(std::size_t num_elements) noexcept {
    return num_elements * 2;
}

/// 计算 num_elements 个 fp32 元素所需的字节数
constexpr std::size_t fp32_bytes(std::size_t num_elements) noexcept {
    return num_elements * 4;
}

/// bf16 转换的相对误差上界（理论值，round-to-nearest-even）
/// bf16 mantissa 7 位，ULP = 2^-7 ≈ 0.0078125，最大相对误差 ≈ ULP/2
constexpr double bf16_max_relative_error() noexcept {
    return 1.0 / 256.0;  // 2^-8
}

}  // namespace linoh::multimodal

#endif  // LINOH_MULTIMODAL_BF16_HPP
