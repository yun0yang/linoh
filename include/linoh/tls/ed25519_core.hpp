#pragma once

#include <cstdint>
#include <cstddef>

namespace linoh::crypto::ed25519 {

/// Derive Ed25519 public key from a 32-byte seed (RFC 8032).
/// Writes 32-byte public key to `pub`.
void keypair_from_seed(uint8_t pub[32], const uint8_t seed[32]);

/// Sign `message` of `len` bytes using Ed25519 (RFC 8032).
/// Writes 64-byte signature to `sig`.
/// `seed` is the 32-byte private key seed.
void sign(uint8_t sig[64], const uint8_t seed[32],
          const uint8_t *message, size_t len);

/// Verify an Ed25519 signature (RFC 8032).
/// Returns true if valid, false otherwise.
bool verify(const uint8_t sig[64], const uint8_t pub[32],
            const uint8_t *message, size_t len);

} // namespace linoh::crypto::ed25519
