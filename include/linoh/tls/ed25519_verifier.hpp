#pragma once

#include "linoh/base/key.hpp"
#include <cstdint>
#include <span>

namespace linoh::tls {

/// 把 QUIC TLS 握手中收到的证书公钥与目标 `EndpointId` 进行 constant-time 比较。
/// 对应 iroh 的 `Ed25519Verifier`。
class Ed25519Verifier {
public:
    explicit Ed25519Verifier(base::PublicKey expected) : expected_{std::move(expected)} {}

    /// 直接对裸的 Ed25519 公钥（32 字节）做 constant-time 比较。
    bool verify_raw_key(std::span<const uint8_t> pubkey_bytes) const;

    const base::PublicKey &expected() const { return expected_; }

private:
    base::PublicKey expected_;
};

} // namespace linoh::tls
