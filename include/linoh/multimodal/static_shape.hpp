// static_shape.hpp — 静态形状协商（v1.6.0.3 / P2）
//
// 借鉴 MoonEP 思想 ②（静态形状消除 host 同步）：
//   - EP 组建立时通过 ctrl/1 交换 ShapeDescriptor
//   - 所有 buffer 按协商后的最大形状预分配（padding 填充未使用部分）
//   - 消除运行时动态形状查询的 CPU<->GPU 同步开销
//
// P2 阶段定位：
//   - 仅实现 TensorShapeNegotiator 类（本地协商逻辑）
//   - EP 组建立流程（通过 ctrl/1 交换）留到 P3/P5
//   - 测试通过直接调用 negotiate() 验证
//
// 设计原则：
//   - 协商策略：取双方 max（max_tokens / hidden_dim / expert_count）
//   - dtype 必须一致（不一致返回 false）
//   - padded_bytes = max_tokens * hidden_dim * dtype_size
//   - padding 部分由调用方清零（StaticBufferPool 预分配时已清零）

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "linoh/multimodal/tensor_stream.hpp"  // TensorDType + dtype_size()

namespace linoh::multimodal::ep {

/// 形状描述符（用于 EP 组静态形状协商）
struct ShapeDescriptor {
    TensorDType dtype{TensorDType::F32};  // 数据类型（必须一致）
    std::uint32_t max_tokens{0};           // 最大 token 数（padding 到此值）
    std::uint32_t hidden_dim{0};            // hidden 维度
    std::uint32_t expert_count{1};          // 专家数（EP 场景，默认 1）

    /// 计算 padding 后的字节数
    /// \return max_tokens * hidden_dim * dtype_size，溢出时返回 0
    std::uint64_t padded_bytes() const noexcept;

    /// 是否有效（所有字段 > 0 且在合理上限内）
    /// v1.7.0.7 H7: 增加上限检查，防止恶意对端构造超大值导致 padded_bytes 溢出
    bool valid() const noexcept {
        // v1.7.0.7 H7: 合理上限 — LLM 推理场景实际值远小于此
        //   max_tokens: 122B 模型单次推理 < 32K，上限 1M 留 30x 余量
        //   hidden_dim: 122B 模型约 8192，上限 1M 留 120x 余量
        //   expert_count: 典型 MoE < 256，上限 1024 留 4x 余量
        constexpr std::uint32_t kMaxTokensLimit = 1u << 20;    // 1M tokens
        constexpr std::uint32_t kMaxHiddenDimLimit = 1u << 20; // 1M dim
        constexpr std::uint32_t kMaxExpertLimit = 1u << 10;    // 1024 experts
        return max_tokens > 0 && max_tokens <= kMaxTokensLimit
            && hidden_dim > 0 && hidden_dim <= kMaxHiddenDimLimit
            && expert_count > 0 && expert_count <= kMaxExpertLimit;
    }

    /// 序列化为字节流（用于通过 ctrl/1 传输）
    /// 布局：[0] dtype + [1..4] max_tokens + [5..8] hidden_dim + [9..12] expert_count
    std::array<std::uint8_t, 13> serialize() const;

    /// 从字节流反序列化
    static bool parse(std::span<const std::uint8_t> data, ShapeDescriptor &out);
};

/// 静态形状协商器
///
/// 用法：
///   TensorShapeNegotiator negotiator;
///   ShapeDescriptor local = {TensorDType::F16, 1024, 4096, 8};
///   ShapeDescriptor remote = {TensorDType::F16, 2048, 4096, 8};
///   bool ok = negotiator.negotiate(local, remote);
///   auto desc = negotiator.current();  // 取 max: max_tokens=2048
class TensorShapeNegotiator {
public:
    TensorShapeNegotiator() = default;

    /// 协商
    /// \param local 本端形状描述
    /// \param remote 对端形状描述
    /// \return true=协商成功（dtype 一致且 valid），false=协商失败
    bool negotiate(const ShapeDescriptor &local, const ShapeDescriptor &remote);

    /// 当前协商结果（未协商返回 nullopt）
    const std::optional<ShapeDescriptor> &current() const noexcept {
        return negotiated_;
    }

    /// 协商后的 padded_bytes（未协商返回 0）
    std::uint64_t padded_bytes() const noexcept;

    /// 是否已协商
    bool is_negotiated() const noexcept { return negotiated_.has_value(); }

    /// 清除协商状态
    void reset() noexcept { negotiated_.reset(); }

    /// 填充 padding 部分为零（buffer 尾部未使用区域）
    /// \param data buffer 数据（需清零的 padding 部分在 [used_bytes, padded_bytes)）
    /// \param used_bytes 实际使用的字节数
    /// \param padded_bytes 总字节数（协商后）
    static void fill_padding_zero(std::span<std::uint8_t> data,
                                  std::size_t used_bytes,
                                  std::size_t padded_bytes);

private:
    std::optional<ShapeDescriptor> negotiated_;

    /// 取双方 max
    static ShapeDescriptor merge_max_(const ShapeDescriptor &a,
                                      const ShapeDescriptor &b);
};

}  // namespace linoh::multimodal::ep
