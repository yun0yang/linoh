// 重写 - 不依赖 OpenSSL
#include "linoh/tls/ed25519_verifier.hpp"

#include <cstdint>
#include <cstring>

namespace linoh::tls {

bool Ed25519Verifier::verify_raw_key(std::span<const uint8_t> pubkey_bytes) const {
    if (pubkey_bytes.size() != expected_.size()) return false;
    // constant-time compare
    uint8_t diff = 0;
    for (std::size_t i = 0; i < expected_.size(); ++i) {
        diff |= pubkey_bytes.data()[i] ^ expected_.data()[i];
    }
    return diff == 0;
}

} // namespace linoh::tls
