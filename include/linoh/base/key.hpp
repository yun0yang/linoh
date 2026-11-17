#pragma once

#include "linoh/util/secure_buffer.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace linoh::base {

/// Ed25519 公钥（32 字节），同时也作为全网唯一节点标识 `EndpointId`。
class PublicKey {
public:
    static constexpr std::size_t kSize = 32;

    PublicKey() = default;
    explicit PublicKey(std::array<uint8_t, kSize> bytes) : bytes_{std::move(bytes)} {}

    static PublicKey from_bytes(std::span<const uint8_t> b) {
        PublicKey k;
        if (b.size() == kSize) std::memcpy(k.bytes_.data(), b.data(), kSize);
        return k;
    }

    uint8_t *data() { return bytes_.data(); }
    const uint8_t *data() const { return bytes_.data(); }
    std::size_t size() const { return kSize; }
    std::span<const uint8_t> as_span() const { return std::span<const uint8_t>(bytes_.data(), kSize); }
    std::span<uint8_t> as_span() { return std::span<uint8_t>(bytes_.data(), kSize); }

    std::string fmt_short() const;
    std::string to_string() const;

    bool operator==(const PublicKey &other) const { return bytes_ == other.bytes_; }
    bool operator!=(const PublicKey &other) const { return bytes_ != other.bytes_; }
    bool operator<(const PublicKey &other) const { return bytes_ < other.bytes_; }

    bool is_zero() const {
        for (std::size_t i = 0; i < kSize; ++i) if (bytes_[i] != 0) return false;
        return true;
    }

private:
    std::array<uint8_t, kSize> bytes_{};
};

/// EndpointId 是 PublicKey 的同义类型；把对方公钥当成"节点地址"使用。
using EndpointId = PublicKey;

/// Ed25519 私钥（32 字节）。
class SecretKey {
public:
    static constexpr std::size_t kSize = 32;

    SecretKey() = default;

    /// P1-6: 析构时安全清零私钥
    ~SecretKey() {
        util::secure_zero(bytes_.data(), kSize);
    }

    /// 拷贝：允许（密钥不变，源对象保留）
    SecretKey(const SecretKey &other) {
        std::memcpy(bytes_.data(), other.bytes_.data(), kSize);
    }
    SecretKey &operator=(const SecretKey &other) {
        if (this != &other) {
            util::secure_zero(bytes_.data(), kSize);
            std::memcpy(bytes_.data(), other.bytes_.data(), kSize);
        }
        return *this;
    }

    /// 移动：允许（源对象清零）
    SecretKey(SecretKey &&other) noexcept {
        std::memcpy(bytes_.data(), other.bytes_.data(), kSize);
        util::secure_zero(other.bytes_.data(), kSize);
    }
    SecretKey &operator=(SecretKey &&other) noexcept {
        if (this != &other) {
            util::secure_zero(bytes_.data(), kSize);
            std::memcpy(bytes_.data(), other.bytes_.data(), kSize);
            util::secure_zero(other.bytes_.data(), kSize);
        }
        return *this;
    }

    static SecretKey generate();

    static SecretKey from_bytes(std::span<const uint8_t> b) {
        SecretKey k;
        if (b.size() == kSize) std::memcpy(k.bytes_.data(), b.data(), kSize);
        return k;
    }

    uint8_t *data() { return bytes_.data(); }
    const uint8_t *data() const { return bytes_.data(); }
    std::size_t size() const { return kSize; }
    std::span<const uint8_t> as_span() const { return std::span<const uint8_t>(bytes_.data(), kSize); }
    std::span<uint8_t> as_span() { return std::span<uint8_t>(bytes_.data(), kSize); }

    PublicKey public_key() const;
    std::array<uint8_t, 64> sign(std::span<const uint8_t> message) const;

    bool operator==(const SecretKey &other) const { return bytes_ == other.bytes_; }

    bool is_zero() const {
        for (std::size_t i = 0; i < kSize; ++i) if (bytes_[i] != 0) return false;
        return true;
    }

private:
    std::array<uint8_t, kSize> bytes_{};
};

/// Ed25519 签名（64 字节）。
class Signature {
public:
    static constexpr std::size_t kSize = 64;

    Signature() = default;
    explicit Signature(std::array<uint8_t, kSize> s) : bytes_{std::move(s)} {}

    static Signature from_bytes(std::span<const uint8_t> b) {
        Signature s;
        if (b.size() == kSize) std::memcpy(s.bytes_.data(), b.data(), kSize);
        return s;
    }

    const uint8_t *data() const { return bytes_.data(); }
    std::size_t size() const { return kSize; }

    bool verify(std::span<const uint8_t> message, const PublicKey &pub) const;

private:
    std::array<uint8_t, kSize> bytes_{};
};

/// TransportAddr 是一个通用的"对端可达地址"。
/// 对应 iroh 的 `TransportAddr`：可以是 UDP Socket 地址，
/// 也可以是经由某 Relay 的地址，或是用户自定义地址。
enum class TransportKind { Ip, Relay, Custom };

struct TransportAddr {
    TransportKind kind{TransportKind::Ip};
    std::string host;          // IP 字符串或 relay hostname
    uint16_t port{0};
    std::string custom_payload; // for Custom 类型

    bool operator==(const TransportAddr &other) const = default;
};

} // namespace linoh::base

// 允许 std::unordered_map 使用 PublicKey/EndpointId 作为 key
template <>
struct std::hash<linoh::base::PublicKey> {
    std::size_t operator()(const linoh::base::PublicKey &k) const noexcept {
        std::size_t h = 1469598103934665603ULL;
        const uint8_t *p = k.data();
        for (std::size_t i = 0; i < 32; ++i) {
            h ^= static_cast<std::size_t>(p[i]);
            h *= 1099511628211ULL;
        }
        return h;
    }
};
