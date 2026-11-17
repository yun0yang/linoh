// hidden_state_codec.hpp — v3.9.4 hidden_state 透明传输编解码封装
//
// 上层（node-agent / win-worker）持有 fp32 hidden_state，但希望按需以 bf16 传输节省 50% 带宽。
// HiddenStateCodec 提供"传入 fp32 + 指定 dtype → 输出可传输字节流"的统一接口，
// 接收端按 dtype 自动解码回 fp32，对上层完全透明。
//
// 与 TensorStream 配合：
//   - 编码后的字节流交给 TensorStreamer::shard(tensor_id, bytes, dtype, shape) 分片发送
//   - 接收端 TensorReassembler 重组后，按 TensorMeta.dtype 调用 decode 还原 fp32
//
// 设计要点：
//   - header-only，全部 inline（纯转发到 bf16.hpp 接口）
//   - dtype=F32 时零拷贝（直接 reinterpret_cast 为字节流）
//   - dtype=BF16 时调用 bf16 转换，节省 50% 带宽
//   - 其他 dtype（F16/I32 等）当前不支持编码（返回空，仅作格式预留）

#ifndef LINOH_MULTIMODAL_HIDDEN_STATE_CODEC_HPP
#define LINOH_MULTIMODAL_HIDDEN_STATE_CODEC_HPP

#include "linoh/multimodal/bf16.hpp"
#include "linoh/multimodal/tensor_stream.hpp"  // TensorDType

#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace linoh::multimodal {

/// hidden_state 透明传输编解码器（v3.9.4）
///
/// 用法（发送端）：
/// \code
///   std::vector<float> hidden_state = ...;  // 来自 llama.cpp 的 fp32 输出
///   auto bytes = HiddenStateCodec::encode(hidden_state, TensorDType::BF16);
///   // bytes.size() == hidden_state.size() * 2（节省 50%）
///   auto shards = streamer.shard(tid, bytes, TensorDType::BF16, shape);
/// \endcode
///
/// 用法（接收端）：
/// \code
///   reasm.on_complete([](uint64_t id, vector<uint8_t> data, TensorMeta meta) {
///       auto fp32 = HiddenStateCodec::decode(data, meta.dtype);
///       // fp32.size() == data.size() / element_size(dtype)
///   });
/// \endcode
class HiddenStateCodec {
public:
    /// 编码 fp32 hidden_state 为可传输字节流
    ///
    /// \param fp32_data fp32 hidden_state 数据
    /// \param dtype 目标数据类型（F32=直接拷贝，BF16=转换节省 50%）
    /// \return 编码后的字节流
    static std::vector<std::uint8_t> encode(const std::vector<float> &fp32_data,
                                            TensorDType dtype) {
        switch (dtype) {
            case TensorDType::F32: {
                // fp32 直接拷贝为字节流（零转换）
                std::vector<std::uint8_t> out(fp32_data.size() * sizeof(float));
                if (!fp32_data.empty()) {
                    std::memcpy(out.data(), fp32_data.data(), out.size());
                }
                return out;
            }
            case TensorDType::BF16:
                // fp32 → bf16 字节流（节省 50%）
                return fp32_vec_to_bf16_bytes(fp32_data);
            default:
                // 其他 dtype 暂不支持（F16 需独立转换器，I32/U8 语义不同）
                return {};
        }
    }

    /// 编码 fp32 数组（span 形式，避免 vector 拷贝）
    static std::vector<std::uint8_t> encode(std::span<const float> fp32_data,
                                            TensorDType dtype) {
        switch (dtype) {
            case TensorDType::F32: {
                std::vector<std::uint8_t> out(fp32_data.size() * sizeof(float));
                if (!fp32_data.empty()) {
                    std::memcpy(out.data(), fp32_data.data(), out.size());
                }
                return out;
            }
            case TensorDType::BF16: {
                std::vector<std::uint8_t> out(bf16_bytes(fp32_data.size()));
                if (!fp32_data.empty()) {
                    fp32_array_to_bf16_bytes(fp32_data.data(), fp32_data.size(),
                                             std::span<std::uint8_t>(out));
                }
                return out;
            }
            default:
                return {};
        }
    }

    /// 解码字节流为 fp32 hidden_state
    ///
    /// \param byte_stream 接收到的字节流（由 TensorReassembler 重组得到）
    /// \param dtype 字节流的数据类型（从 TensorMeta.dtype 获取）
    /// \return fp32 hidden_state 数据
    static std::vector<float> decode(const std::vector<std::uint8_t> &byte_stream,
                                     TensorDType dtype) {
        switch (dtype) {
            case TensorDType::F32: {
                // fp32 直接拷贝回 float 数组
                std::vector<float> out(byte_stream.size() / sizeof(float));
                if (!out.empty()) {
                    std::memcpy(out.data(), byte_stream.data(), out.size() * sizeof(float));
                }
                return out;
            }
            case TensorDType::BF16:
                // bf16 字节流 → fp32
                return bf16_bytes_to_fp32_vec(byte_stream);
            default:
                return {};
        }
    }

    /// 估算编码后的字节数（不实际编码）
    ///
    /// \param num_elements fp32 元素个数
    /// \param dtype 目标数据类型
    /// \return 编码后字节数（F32=num*4，BF16=num*2）
    static std::size_t estimate_bytes(std::size_t num_elements,
                                      TensorDType dtype) noexcept {
        switch (dtype) {
            case TensorDType::F32:  return num_elements * 4;
            case TensorDType::BF16: return num_elements * 2;
            case TensorDType::F16:  return num_elements * 2;
            case TensorDType::I32:  return num_elements * 4;
            case TensorDType::U8:   return num_elements * 1;
            case TensorDType::I8:   return num_elements * 1;
            case TensorDType::F64:  return num_elements * 8;
            case TensorDType::I64:  return num_elements * 8;
        }
        return 0;
    }

    /// 计算带宽节省比例（BF16 vs F32）
    ///
    /// \return 节省比例 [0.0, 1.0]，BF16 节省 0.5（50%），F32 节省 0.0
    static constexpr double bandwidth_saving(TensorDType dtype) noexcept {
        switch (dtype) {
            case TensorDType::BF16:
            case TensorDType::F16:
                return 0.5;  // 2 字节 vs 4 字节，节省 50%
            default:
                return 0.0;
        }
    }
};

}  // namespace linoh::multimodal

#endif  // LINOH_MULTIMODAL_HIDDEN_STATE_CODEC_HPP
