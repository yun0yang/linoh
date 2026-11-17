#pragma once

// HKDF (RFC 5869) over HMAC-SHA256, plus TLS 1.3 (RFC 8446 §7.1) helpers:
//   HKDF-Expand-Label and Derive-Secret.
// Depends only on linoh::crypto HMAC-SHA256 / SHA-256. No OpenSSL.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace linoh::crypto {

/// HKDF-Extract(salt, IKM) -> PRK (32 bytes for SHA-256).
/// If salt is empty, a 32-byte zero salt is used (per RFC 5869).
std::array<uint8_t, 32> hkdf_extract(std::span<const uint8_t> salt,
                                     std::span<const uint8_t> ikm);

/// HKDF-Expand(PRK, info, L) -> OKM (L bytes). L must be <= 255*32.
std::vector<uint8_t> hkdf_expand(std::span<const uint8_t> prk,
                                 std::span<const uint8_t> info,
                                 std::size_t length);

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1).
///   HkdfLabel = { uint16 length; opaque label<7..255>="tls13 "+label;
///                 opaque context<0..255>=context }
std::vector<uint8_t> hkdf_expand_label(std::span<const uint8_t> secret,
                                       std::string_view label,
                                       std::span<const uint8_t> context,
                                       std::size_t length);

/// TLS 1.3 Derive-Secret(secret, label, transcript_hash) (RFC 8446 §7.1).
/// transcript_hash is the SHA-256 of the handshake messages (32 bytes).
std::array<uint8_t, 32> derive_secret(std::span<const uint8_t> secret,
                                      std::string_view label,
                                      std::span<const uint8_t> transcript_hash);

} // namespace linoh::crypto
