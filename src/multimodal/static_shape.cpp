// static_shape.cpp — 静态形状协商实现（v1.6.0.3 / P2）

#include "linoh/multimodal/static_shape.hpp"

#include <algorithm>
#include <cstring>

namespace linoh::multimodal::ep {

// ============================================================================
// ShapeDescriptor
// ============================================================================

std::uint64_t ShapeDescriptor::padded_bytes() const noexcept {
    std::size_t ds = dtype_size(dtype);
    if (ds == 0) return 0;
    // v1.7.0.7 H7: 溢出检查 — 恶意对端可构造 max_tokens=0xFFFFFFFF, hidden_dim=0xFFFFFFFF
    //   导致乘法溢出回绕为小值，后续 buffer 分配过小引发越界写
    std::uint64_t tokens = static_cast<std::uint64_t>(max_tokens);
    std::uint64_t dim = static_cast<std::uint64_t>(hidden_dim);
    std::uint64_t dsize = static_cast<std::uint64_t>(ds);
    // 检查 tokens * dim 是否溢出
    if (tokens != 0 && dim > UINT64_MAX / tokens) return 0;
    std::uint64_t td = tokens * dim;
    // 检查 td * dsize 是否溢出
    if (td != 0 && dsize > UINT64_MAX / td) return 0;
    return td * dsize;
}

std::array<std::uint8_t, 13> ShapeDescriptor::serialize() const {
    std::array<std::uint8_t, 13> buf{};
    buf[0] = static_cast<std::uint8_t>(dtype);
    std::memcpy(buf.data() + 1, &max_tokens, 4);
    std::memcpy(buf.data() + 5, &hidden_dim, 4);
    std::memcpy(buf.data() + 9, &expert_count, 4);
    return buf;
}

bool ShapeDescriptor::parse(std::span<const std::uint8_t> data,
                            ShapeDescriptor &out) {
    if (data.size() < 13) return false;
    out.dtype = static_cast<TensorDType>(data[0]);
    if (static_cast<std::uint8_t>(out.dtype) > 7) return false;  // 超出枚举范围
    std::memcpy(&out.max_tokens, data.data() + 1, 4);
    std::memcpy(&out.hidden_dim, data.data() + 5, 4);
    std::memcpy(&out.expert_count, data.data() + 9, 4);
    return out.valid();
}

// ============================================================================
// TensorShapeNegotiator
// ============================================================================

bool TensorShapeNegotiator::negotiate(const ShapeDescriptor &local,
                                      const ShapeDescriptor &remote) {
    if (!local.valid() || !remote.valid()) return false;
    if (local.dtype != remote.dtype) return false;
    negotiated_ = merge_max_(local, remote);
    return true;
}

std::uint64_t TensorShapeNegotiator::padded_bytes() const noexcept {
    if (!negotiated_) return 0;
    return negotiated_->padded_bytes();
}

void TensorShapeNegotiator::fill_padding_zero(
    std::span<std::uint8_t> data,
    std::size_t used_bytes,
    std::size_t padded_bytes) {
    if (used_bytes >= padded_bytes) return;
    if (data.size() < padded_bytes) return;
    std::fill(data.begin() + used_bytes,
              data.begin() + padded_bytes,
              std::uint8_t{0});
}

ShapeDescriptor TensorShapeNegotiator::merge_max_(const ShapeDescriptor &a,
                                                  const ShapeDescriptor &b) {
    ShapeDescriptor m;
    m.dtype = a.dtype;  // dtype 已校验一致
    m.max_tokens = (std::max)(a.max_tokens, b.max_tokens);
    m.hidden_dim = (std::max)(a.hidden_dim, b.hidden_dim);
    m.expert_count = (std::max)(a.expert_count, b.expert_count);
    return m;
}

}  // namespace linoh::multimodal::ep
