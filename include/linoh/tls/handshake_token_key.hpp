#pragma once

#include "crypto_provider.hpp"
#include "linoh/util/secure_buffer.hpp"
#include <array>
#include <cstdint>
#include <span>

namespace linoh::tls {

/// 握手重试令牌的 AEAD 密钥。
///
/// 对应 iroh 的 `n0_watcher::HandshakeTokenKey`。密钥在栈上存储（32 字节），
/// 通过 vtable 引用 AEAD 实现——零堆分配，线程安全的 const 读取。
///
/// 加密格式：`[AEAD(key=master_key, nonce=12B_from_token_nonce, ad=src_addr, data=plaintext)]`
/// plaintext 通常是 `[endpoint_id(32B) | timestamp(8B) | connection_id(N)]`。
class HandshakeTokenKey {
public:
    static constexpr std::size_t kKeyLen = 32;

    /// P1-6: 析构时安全清零密钥
    ~HandshakeTokenKey() {
        util::secure_zero(key_.data(), kKeyLen);
    }

    /// 拷贝：允许（const 语义，密钥不变）
    HandshakeTokenKey(const HandshakeTokenKey &other) {
        std::memcpy(key_.data(), other.key_.data(), kKeyLen);
    }
    HandshakeTokenKey &operator=(const HandshakeTokenKey &other) {
        if (this != &other) {
            util::secure_zero(key_.data(), kKeyLen);
            std::memcpy(key_.data(), other.key_.data(), kKeyLen);
        }
        return *this;
    }

    /// 从加密随机源生成新密钥。
    static HandshakeTokenKey generate();

    /// 从原始字节构造。
    static HandshakeTokenKey from_bytes(std::span<const uint8_t> b);

    /// 加密。返回密文（含 tag）。
    std::vector<uint8_t> seal(uint64_t token_nonce,
                              std::span<const uint8_t> src_addr,
                              std::span<const uint8_t> plaintext) const;

    /// 解密。成功返回 plaintext，失败返回空 vector。
    std::vector<uint8_t> open(uint64_t token_nonce,
                              std::span<const uint8_t> src_addr,
                              std::span<const uint8_t> ciphertext) const;

    /// 从 master_secret 派生 0-RTT 密钥（写入 output，32 字节）。
    void derive_zerortt(const std::array<uint8_t, kKeyLen> &master_secret,
                        std::span<uint8_t> output) const;

    const std::array<uint8_t, kKeyLen> &key() const { return key_; }

private:
    HandshakeTokenKey() = default;
    std::array<uint8_t, kKeyLen> key_{};
};

} // namespace linoh::tls
