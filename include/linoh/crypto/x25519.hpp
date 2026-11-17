#pragma once

// X25519 (Curve25519 ECDH) — RFC 7748.
// Direct port of TweetNaCl.c crypto_scalarmult — public domain, well-tested.
// Self-contained: only needs <cstdint>/<cstddef>. No OpenSSL.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace linoh::crypto::x25519 {

static constexpr std::size_t kKeySize = 32;

/// Compute the shared point: out = scalarmult(scalar, point).
/// `scalar` is a 32-byte secret; `point` is a 32-byte u-coordinate (peer public).
/// Writes 32 bytes to `out`. Returns true (scalar is clamped internally per RFC 7748).
bool scalarmult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

/// Compute the public key: out = scalarmult(scalar, basepoint(9)).
void scalarmult_base(uint8_t out[32], const uint8_t scalar[32]);

/// Generate an ephemeral X25519 keypair from a cryptographically random scalar.
/// `sk` receives the 32-byte secret (already clamped is NOT applied to stored sk;
/// clamping happens inside scalarmult), `pk` receives the 32-byte public key.
/// tc-M1 (v1.7.0.8): 返回 bool 指示 CSPRNG 是否成功。失败时 sk/pk 内容未定义，
///   调用方必须检查返回值并中止握手（返回全零密钥会破坏前向保密）。
bool keygen(uint8_t pk[32], uint8_t sk[32]);

/// Convenience wrappers using std::array.
inline std::array<uint8_t, 32> shared_secret(const std::array<uint8_t, 32> &sk,
                                             const std::array<uint8_t, 32> &peer_pk) {
    std::array<uint8_t, 32> out{};
    scalarmult(out.data(), sk.data(), peer_pk.data());
    return out;
}

inline std::array<uint8_t, 32> public_from_secret(const std::array<uint8_t, 32> &sk) {
    std::array<uint8_t, 32> out{};
    scalarmult_base(out.data(), sk.data());
    return out;
}

} // namespace linoh::crypto::x25519
