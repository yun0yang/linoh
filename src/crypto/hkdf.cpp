// HKDF (RFC 5869) + TLS 1.3 (RFC 8446 §7.1) key derivation helpers.

#include "linoh/crypto/hkdf.hpp"
#include "linoh/util/crypto.hpp"

#include <cstring>

namespace linoh::crypto {

std::array<uint8_t, 32> hkdf_extract(std::span<const uint8_t> salt,
                                     std::span<const uint8_t> ikm) {
    // PRK = HMAC-Hash(salt, IKM). Empty salt -> 32 zero bytes.
    std::array<uint8_t, 32> zero_salt{};
    std::span<const uint8_t> use_salt =
        salt.empty() ? std::span<const uint8_t>(zero_salt.data(), zero_salt.size()) : salt;
    return HMAC_SHA256::compute(use_salt, ikm);
}

std::vector<uint8_t> hkdf_expand(std::span<const uint8_t> prk,
                                 std::span<const uint8_t> info,
                                 std::size_t length) {
    std::vector<uint8_t> okm;
    okm.reserve(length);
    std::array<uint8_t, 32> t{};
    std::size_t t_len = 0;  // 0 for first iteration (T(0) = empty)
    uint8_t counter = 1;

    while (okm.size() < length) {
        // T(i) = HMAC(PRK, T(i-1) | info | counter)
        std::vector<uint8_t> input;
        input.reserve(t_len + info.size() + 1);
        input.insert(input.end(), t.data(), t.data() + t_len);
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);

        t = HMAC_SHA256::compute(prk, std::span<const uint8_t>(input.data(), input.size()));
        t_len = 32;

        std::size_t take = std::min<std::size_t>(32, length - okm.size());
        okm.insert(okm.end(), t.data(), t.data() + take);
        ++counter;
    }
    return okm;
}

std::vector<uint8_t> hkdf_expand_label(std::span<const uint8_t> secret,
                                       std::string_view label,
                                       std::span<const uint8_t> context,
                                       std::size_t length) {
    // Build HkdfLabel.
    std::string full_label = "tls13 ";
    full_label += label;

    std::vector<uint8_t> hkdf_label;
    hkdf_label.reserve(2 + 1 + full_label.size() + 1 + context.size());
    hkdf_label.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
    hkdf_label.push_back(static_cast<uint8_t>(length & 0xFF));
    hkdf_label.push_back(static_cast<uint8_t>(full_label.size()));
    for (char c : full_label) hkdf_label.push_back(static_cast<uint8_t>(c));
    hkdf_label.push_back(static_cast<uint8_t>(context.size()));
    hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());

    return hkdf_expand(secret,
                       std::span<const uint8_t>(hkdf_label.data(), hkdf_label.size()),
                       length);
}

std::array<uint8_t, 32> derive_secret(std::span<const uint8_t> secret,
                                      std::string_view label,
                                      std::span<const uint8_t> transcript_hash) {
    auto out = hkdf_expand_label(secret, label, transcript_hash, 32);
    std::array<uint8_t, 32> result{};
    std::memcpy(result.data(), out.data(), 32);
    return result;
}

} // namespace linoh::crypto
