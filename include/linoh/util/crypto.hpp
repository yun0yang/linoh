#pragma once

// Custom crypto implementation - no OpenSSL dependency
// Implements: SHA-256, HMAC-SHA256, ChaCha20-Poly1305 AEAD

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace linoh::crypto {

// ============================================================================
// SHA-256
// ============================================================================

class SHA256 {
public:
    static constexpr std::size_t kDigestSize = 32;

    SHA256();
    void update(std::span<const uint8_t> data);
    std::array<uint8_t, kDigestSize> finalize();

    static std::array<uint8_t, kDigestSize> hash(std::span<const uint8_t> data);

private:
    void transform(const uint8_t *block);
    std::array<uint32_t, 8> state_;
    std::array<uint8_t, 64> buffer_;
    std::size_t buffer_len_;
    uint64_t bit_count_;
};

// ============================================================================
// SHA-512 (needed for Ed25519 / RFC 8032)
// ============================================================================

class SHA512 {
public:
    static constexpr std::size_t kDigestSize = 64;
    static constexpr std::size_t kBlockSize = 128;

    SHA512();
    void update(std::span<const uint8_t> data);
    std::array<uint8_t, kDigestSize> finalize();

    static std::array<uint8_t, kDigestSize> hash(std::span<const uint8_t> data);

private:
    void transform(const uint8_t *block);
    std::array<uint64_t, 8> state_;
    std::array<uint8_t, kBlockSize> buffer_;
    std::size_t buffer_len_;
    uint64_t bit_count_lo_;  // low 64 bits of 128-bit counter
    uint64_t bit_count_hi_;  // high 64 bits
};

// ============================================================================
// HMAC-SHA256
// ============================================================================

class HMAC_SHA256 {
public:
    static constexpr std::size_t kDigestSize = 32;

    static std::array<uint8_t, kDigestSize> compute(std::span<const uint8_t> key,
                                                      std::span<const uint8_t> message);
};

// ============================================================================
// ChaCha20 stream cipher
// ============================================================================

class ChaCha20 {
public:
    static constexpr std::size_t kKeySize = 32;
    static constexpr std::size_t kNonceSize = 12;
    static constexpr std::size_t kBlockSize = 64;

    // Encrypt/decrypt in place
    static void process(std::span<const uint8_t> key,
                         std::span<const uint8_t> nonce,
                         std::span<uint8_t> data,
                         uint32_t counter = 0);

    // Encrypt/decrypt into out buffer
    static void process(std::span<const uint8_t> key,
                         std::span<const uint8_t> nonce,
                         std::span<const uint8_t> input,
                         std::span<uint8_t> output,
                         uint32_t counter = 0);

private:
    static void block(std::span<const uint8_t> key,
                       std::span<const uint8_t> nonce,
                       uint32_t counter,
                       std::span<uint8_t> out_block);
};

// ============================================================================
// Poly1305 authenticator
// ============================================================================

class Poly1305 {
public:
    static constexpr std::size_t kKeySize = 32;
    static constexpr std::size_t kTagSize = 16;

    static std::array<uint8_t, kTagSize> compute(std::span<const uint8_t> key,
                                                  std::span<const uint8_t> message);
};

// ============================================================================
// ChaCha20-Poly1305 AEAD (RFC 8439)
// ============================================================================

class ChaCha20Poly1305 {
public:
    static constexpr std::size_t kKeySize = 32;
    static constexpr std::size_t kNonceSize = 12;
    static constexpr std::size_t kTagSize = 16;

    // Encrypt: out = ciphertext || tag
    // Returns total bytes written (plaintext_size + tag_size), 0 on error
    static std::size_t seal(std::span<const uint8_t> key,
                            std::span<const uint8_t> nonce,
                            std::span<const uint8_t> ad,
                            std::span<const uint8_t> plaintext,
                            std::span<uint8_t> out);

    // Decrypt: tag is appended at end of ciphertext
    // Returns plaintext bytes written, 0 on auth failure
    static std::size_t open(std::span<const uint8_t> key,
                            std::span<const uint8_t> nonce,
                            std::span<const uint8_t> ad,
                            std::span<const uint8_t> ciphertext_with_tag,
                            std::span<uint8_t> out);
};

// ============================================================================
// Crypto random source (uses Windows BCrypt or std::random_device)
// ============================================================================

bool crypto_random_bytes(std::span<uint8_t> out);

// ============================================================================
// P1-7: 常量时间比较（防侧信道）
// ============================================================================

/// 常量时间字节比较（防 timing attack）
/// 返回 true 若两缓冲区内容相同且长度相同，否则 false
/// @note 用于签名/MAC/AEAD tag 等敏感数据比较，禁止用于非安全场景
inline bool verify_equal(std::span<const uint8_t> a,
                          std::span<const uint8_t> b) noexcept {
    if (a.size() != b.size()) return false;
    uint8_t diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

/// 32 字节常量时间比较（兼容 TweetNaCl crypto_verify_32 接口）
bool verify_equal_32(const uint8_t *a, const uint8_t *b) noexcept;

// ============================================================================
// tc-M3 (v1.7.0.8): 安全清零内存
// ============================================================================

/// 安全清零内存（防编译器优化，用于敏感密钥材料清零）。
/// 普通 memset 可能被编译器 dead-store 优化移除（变量即将析构时编译器认为写入无意义）。
/// 使用 volatile 指针逐字节写入确保清零不被优化掉。
/// @note 用于 eph_sk_/handshake_secret/master_secret 等敏感密钥的析构期清零，
///       防止进程内存转储/核心转储泄露密钥材料。
inline void secure_zero(void *ptr, std::size_t len) noexcept {
    if (!ptr || len == 0) return;
    volatile uint8_t *p = static_cast<volatile uint8_t *>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

/// 便捷重载：清零 std::array 的固定大小数组
template <typename T, std::size_t N>
inline void secure_zero(std::array<T, N> &arr) noexcept {
    secure_zero(arr.data(), arr.size() * sizeof(T));
}

} // namespace linoh::crypto
