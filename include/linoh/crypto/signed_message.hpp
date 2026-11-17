#pragma once

// =============================================================================
// signed_message.hpp — v3.8.2 控制面 Ed25519 签名信封
//
// 设计来源：Psyche shared/network/src/signed_message.rs
//   - 双层序列化：内层 data（调用方自行序列化的消息）+ 外层信封 {from, data, signature}
//   - Ed25519 确定性签名：sign(sk, data) → signature（同 sk+data 产出相同签名）
//   - 验签用常量时间比较（防侧信道），复用 linoh::crypto::verify_equal
//
// 外层固定格式（100 + N 字节，小端 LE 编码）：
//   ┌──────────┬────────────┬────────────┬──────────┐
//   │ from     │ signature  │ data_len   │ data     │
//   │ 32 bytes │ 64 bytes   │ 4 bytes LE │ N bytes  │
//   └──────────┴────────────┴────────────┴──────────┘
//   偏移 0..31   32..95       96..99       100..(100+N-1)
//
// 与 v3.8.3 ReplayProtection 的关系：
//   v3.8.3 在内层 data 中封装 {timestamp + nonce + command_payload}，
//   先 decode_and_verify 验签 → 再查 NonceCache → 重复/过期则丢弃。
//   本模块只负责签名信封，不绑定内层格式（向后兼容，调用方可任意序列化）。
//
// 应用范围：
//   - ✅ ctrl/1 控制面消息（JOIN/FORWARD/RESULT 指令、心跳、状态）
//   - ❌ pp-hidden/1 数据面（已有 TLS 1.3 AKE 加密，不重复签名，性能考虑）
//   - ❌ pp-img/1 / pp-video/1 / pp-audio/1（同上）
//
// v3.8.2 范围：
//   1. SignedMessage 结构（from + data + signature）
//   2. sign_message / encode / decode 基础 API
//   3. sign_and_encode / decode_and_verify 便捷 API
//   4. verify() / verify_from() 自验签
//
// 复用现有 linoh::base::{PublicKey, SecretKey, Signature}（base/key.hpp）
// + linoh::crypto::verify_equal（util/crypto.hpp，常量时间比较）
// =============================================================================

#include "linoh/base/key.hpp"      // PublicKey, SecretKey, Signature
#include "linoh/util/crypto.hpp"   // verify_equal（常量时间比较）

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace linoh::crypto {

// =============================================================================
// SignedMessage — Ed25519 签名信封
// =============================================================================

/// Ed25519 签名信封（Psyche SignedMessage 模式）
///
/// 三字段结构：
/// - `from`：发送者 Ed25519 公钥（32 字节，同时是 EndpointId）
/// - `data`：内层序列化的消息字节（签名覆盖对象，格式由调用方决定）
/// - `signature`：Ed25519 签名（64 字节，对 `data` 签名）
///
/// @note Ed25519 是确定性签名：同一 sk + 同一 data 产出相同 signature（非随机化）。
///       验签使用常量时间比较，防侧信道。
struct SignedMessage {
    base::PublicKey from{};              ///< 发送者公钥（32 字节）
    std::vector<uint8_t> data;           ///< 内层序列化的消息（签名覆盖对象）
    base::Signature signature{};         ///< Ed25519 签名（64 字节）

    /// 自验签：用 `from` 验证 `signature` 对 `data` 的签名
    /// @return true 若签名有效
    bool verify() const noexcept;

    /// 额外校验发送者身份：`from` 必须等于 `expected_from`，且签名有效
    /// @return true 仅当 from==expected_from 且签名有效
    /// @note from 比较用常量时间（verify_equal），防身份伪造探测
    bool verify_from(const base::PublicKey &expected_from) const noexcept;
};

// =============================================================================
// 构造与序列化 API
// =============================================================================

/// 构造签名信封（对 `data` 用 `sk` 签名，自动填入 `from = sk.public_key()`）
///
/// @param sk 发送者私钥（32 字节 Ed25519 seed）
/// @param data 内层消息字节（签名覆盖对象）
/// @return SignedMessage，from/signature 已填好
///
/// @note Ed25519 确定性签名：同 sk+data 产出相同签名。
///       data 为空（size=0）也合法，签名覆盖空消息。
SignedMessage sign_message(const base::SecretKey &sk,
                            std::span<const uint8_t> data);

/// 外层序列化：{from(32) || signature(64) || data_len(LE4) || data(N)}
///
/// @return 100 + data.size() 字节的紧凑二进制
/// @note data_len 用小端编码（postcard 风格），与 application_message 大端不同
std::vector<uint8_t> encode(const SignedMessage &sm);

/// 外层反序列化（仅解码，不验签）
///
/// @param bytes 编码后的字节
/// @return SignedMessage；nullopt 若长度不足 / data_len 越界 / 超过上限
///
/// @note 校验规则：
///   1. bytes.size() >= 100（最小信封：空 data）
///   2. data_len <= bytes.size() - 100（防越界）
///   3. data_len <= kMaxSignedMessageDataLen（防恶意大包）
std::optional<SignedMessage> decode(std::span<const uint8_t> bytes);

// =============================================================================
// 便捷 API（一步到位）
// =============================================================================

/// 一步签名 + 编码：sign_message(sk, data) → encode
std::vector<uint8_t> sign_and_encode(const base::SecretKey &sk,
                                      std::span<const uint8_t> data);

/// 一步解码 + 验签的返回结果
struct VerifyResult {
    bool valid{false};          ///< true 仅当解码成功且验签通过
    SignedMessage message{};    ///< 解码后的信封（valid=false 时为默认值）
};

/// 一步解码 + 验签
///
/// @param bytes 编码后的字节
/// @return VerifyResult；valid=true 仅当 decode 成功且 message.verify() 通过
///
/// @note 典型用法：
///   auto r = decode_and_verify(bytes);
///   if (!r.valid) { /* 丢弃伪造/损坏消息 */ return; }
///   process(r.message.data);
VerifyResult decode_and_verify(std::span<const uint8_t> bytes);

// =============================================================================
// 常量
// =============================================================================

/// 数据长度上限（防恶意大包，16MB；控制面消息远小于此）
constexpr std::uint32_t kMaxSignedMessageDataLen = 16 * 1024 * 1024;

/// 信封固定头长度（from 32 + signature 64 + data_len 4 = 100）
constexpr std::size_t kSignedMessageHeaderLen = 100;

} // namespace linoh::crypto
