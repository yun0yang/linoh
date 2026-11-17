// Ed25519 key operations using real cryptographic implementation
#include "linoh/base/key.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/tls/ed25519_core.hpp"

#include <array>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>

namespace linoh::base {

namespace {

std::string to_base32_hex(const uint8_t *data, std::size_t n) {
    static constexpr char kAlphabet[] = "0123456789abcdefghjkmnpqrstvwxyz";
    std::string out;
    std::size_t bits = 0;
    uint32_t acc = 0;
    for (std::size_t i = 0; i < n; ++i) {
        acc = (acc << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(kAlphabet[(acc >> bits) & 0x1F]);
        }
    }
    if (bits > 0) {
        out.push_back(kAlphabet[(acc << (5 - bits)) & 0x1F]);
    }
    return out;
}

} // namespace

std::string PublicKey::fmt_short() const {
    return to_base32_hex(data(), 8);
}

std::string PublicKey::to_string() const {
    return to_base32_hex(data(), kSize);
}

SecretKey SecretKey::generate() {
    SecretKey k;
    // CSPRNG only — no insecure fallback
    crypto::crypto_random_bytes(std::span<uint8_t>(k.data(), kSize));
    return k;
}

PublicKey SecretKey::public_key() const {
    PublicKey pub;
    crypto::ed25519::keypair_from_seed(pub.data(), data());
    return pub;
}

std::array<uint8_t, 64> SecretKey::sign(std::span<const uint8_t> message) const {
    std::array<uint8_t, 64> sig{};
    crypto::ed25519::sign(sig.data(), data(),
                           message.data(), message.size());
    return sig;
}

bool Signature::verify(std::span<const uint8_t> message, const PublicKey &pub) const {
    return crypto::ed25519::verify(data(), pub.data(),
                                   message.data(), message.size());
}

} // namespace linoh::base
