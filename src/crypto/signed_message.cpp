// =============================================================================
// signed_message.cpp — v3.8.2 控制面 Ed25519 签名信封实现
//
// 依赖：linoh::base::{PublicKey, SecretKey, Signature}（base/key.hpp）
//       linoh::crypto::verify_equal（util/crypto.hpp，常量时间比较）
//
// 外层固定格式（100 + N 字节，小端 LE 编码）：
//   from(32) || signature(64) || data_len(4 LE) || data(N)
// =============================================================================

#include "linoh/crypto/signed_message.hpp"

#include <cstring>  // memcpy

namespace linoh::crypto {

// =============================================================================
// SignedMessage 自验签
// =============================================================================

bool SignedMessage::verify() const noexcept {
    // Signature::verify(message, pub) 内部已用常量时间比较
    return signature.verify(data, from);
}

bool SignedMessage::verify_from(const base::PublicKey &expected_from) const noexcept {
    // 常量时间比较 from == expected_from（防身份伪造探测）
    if (!verify_equal(from.as_span(), expected_from.as_span())) {
        return false;
    }
    return signature.verify(data, from);
}

// =============================================================================
// 构造与序列化
// =============================================================================

SignedMessage sign_message(const base::SecretKey &sk,
                            std::span<const uint8_t> data) {
    SignedMessage sm;
    sm.from = sk.public_key();                         // 32 字节公钥派生
    sm.data.assign(data.begin(), data.end());          // 拷贝内层消息
    auto sig_bytes = sk.sign(data);                    // array<uint8_t,64>
    sm.signature = base::Signature(sig_bytes);         // Ed25519 确定性签名
    return sm;
}

std::vector<uint8_t> encode(const SignedMessage &sm) {
    std::vector<uint8_t> out;
    out.reserve(kSignedMessageHeaderLen + sm.data.size());

    // from (32 字节，公钥原始字节)
    auto from_span = sm.from.as_span();  // span<const uint8_t, 32>
    out.insert(out.end(), from_span.begin(), from_span.end());

    // signature (64 字节，签名原始字节)
    const uint8_t *sig_data = sm.signature.data();
    out.insert(out.end(), sig_data, sig_data + base::Signature::kSize);

    // data_len (4 字节小端 LE)
    const uint32_t len = static_cast<uint32_t>(sm.data.size());
    out.push_back(static_cast<uint8_t>(len & 0xFF));
    out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));

    // data (N 字节)
    out.insert(out.end(), sm.data.begin(), sm.data.end());

    return out;
}

std::optional<SignedMessage> decode(std::span<const uint8_t> bytes) {
    // 校验 1：最小长度（from + signature + data_len = 100）
    if (bytes.size() < kSignedMessageHeaderLen) {
        return std::nullopt;
    }

    // 读取 data_len（小端 LE）
    const uint32_t len = static_cast<uint32_t>(bytes[96])
                       | (static_cast<uint32_t>(bytes[97]) << 8)
                       | (static_cast<uint32_t>(bytes[98]) << 16)
                       | (static_cast<uint32_t>(bytes[99]) << 24);

    // 校验 2：防恶意大包
    if (len > kMaxSignedMessageDataLen) {
        return std::nullopt;
    }

    // 校验 3：data_len 不超过剩余字节（防越界）
    if (bytes.size() < kSignedMessageHeaderLen + len) {
        return std::nullopt;
    }

    SignedMessage sm;
    sm.from = base::PublicKey::from_bytes(bytes.subspan(0, base::PublicKey::kSize));
    sm.signature = base::Signature::from_bytes(
        bytes.subspan(base::PublicKey::kSize, base::Signature::kSize));
    sm.data.assign(bytes.begin() + kSignedMessageHeaderLen,
                   bytes.begin() + kSignedMessageHeaderLen + len);
    return sm;
}

// =============================================================================
// 便捷 API
// =============================================================================

std::vector<uint8_t> sign_and_encode(const base::SecretKey &sk,
                                      std::span<const uint8_t> data) {
    return encode(sign_message(sk, data));
}

VerifyResult decode_and_verify(std::span<const uint8_t> bytes) {
    VerifyResult result;
    auto decoded = decode(bytes);
    if (!decoded) {
        return result;  // valid=false, message=默认
    }
    result.message = std::move(*decoded);
    result.valid = result.message.verify();
    return result;
}

} // namespace linoh::crypto
