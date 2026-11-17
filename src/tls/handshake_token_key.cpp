// 重写 - 不依赖 OpenSSL
#include "linoh/tls/handshake_token_key.hpp"
#include "linoh/util/crypto.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace linoh::tls {

HandshakeTokenKey HandshakeTokenKey::generate() {
    HandshakeTokenKey k;
    // v1.7.0.6 (C11 fix): 检查 CSPRNG 返回值，失败时抛异常而非返回弱密钥
    if (!crypto::crypto_random_bytes(std::span<uint8_t>(k.key_.data(), k.key_.size()))) {
        throw std::runtime_error("CSPRNG failed: cannot generate HandshakeTokenKey");
    }
    return k;
}

HandshakeTokenKey HandshakeTokenKey::from_bytes(std::span<const uint8_t> b) {
    HandshakeTokenKey k;
    if (b.size() >= kKeyLen) {
        std::memcpy(k.key_.data(), b.data(), kKeyLen);
    }
    return k;
}

std::vector<uint8_t> HandshakeTokenKey::seal(uint64_t token_nonce,
                                              std::span<const uint8_t> src_addr,
                                              std::span<const uint8_t> plaintext) const {
    auto cipher = global_provider().default_aead();
    // tc-M5 (v1.7.0.8): 断言 nonce_size >= 12，避免 nonce_size < 12 时
    // token_nonce 低位被截断导致 AEAD nonce 重用（机密性/完整性破坏）。
    // 当前 default_aead() 返回 12 字节 nonce 的 ChaCha20-Poly1305 不触发，
    // 此为防御性检查，防止未来更换 cipher 时引入 nonce 重用。
    if (cipher->nonce_size() < 12) return {};
    std::vector<uint8_t> nonce(cipher->nonce_size(), 0);
    for (std::size_t i = 0; i < 8; ++i) {
        nonce[nonce.size() - 1 - i] = static_cast<uint8_t>((token_nonce >> (i * 8)) & 0xFF);
    }

    std::vector<uint8_t> out(plaintext.size() + cipher->tag_size());
    std::size_t written = cipher->seal(std::span<const uint8_t>(key_.data(), kKeyLen),
                                       std::span<const uint8_t>(nonce.data(), cipher->nonce_size()),
                                       src_addr, plaintext,
                                       std::span<uint8_t>(out.data(), out.size()));
    if (written == 0) return {};
    out.resize(written);
    return out;
}

std::vector<uint8_t> HandshakeTokenKey::open(uint64_t token_nonce,
                                             std::span<const uint8_t> src_addr,
                                             std::span<const uint8_t> ciphertext) const {
    auto cipher = global_provider().default_aead();
    if (ciphertext.size() < cipher->tag_size()) return {};
    // tc-M5 (v1.7.0.8): 同 seal，断言 nonce_size >= 12 防 nonce 重用
    if (cipher->nonce_size() < 12) return {};
    std::vector<uint8_t> nonce(cipher->nonce_size(), 0);
    for (std::size_t i = 0; i < 8; ++i) {
        nonce[nonce.size() - 1 - i] = static_cast<uint8_t>((token_nonce >> (i * 8)) & 0xFF);
    }
    std::vector<uint8_t> out(ciphertext.size() - cipher->tag_size());
    std::size_t written = cipher->open(std::span<const uint8_t>(key_.data(), kKeyLen),
                                       std::span<const uint8_t>(nonce.data(), cipher->nonce_size()),
                                       src_addr, ciphertext,
                                       std::span<uint8_t>(out.data(), out.size()));
    if (written == 0) return {};
    out.resize(written);
    return out;
}

void HandshakeTokenKey::derive_zerortt(const std::array<uint8_t, kKeyLen> &master_secret,
                                       std::span<uint8_t> output) const {
    // 简化 HKDF 风格派生:
    //   zero_rtt_secret = HMAC-SHA256(key=master_secret, msg="zero-rtt" || this->key_)
    if (output.size() < 32) return;
    std::vector<uint8_t> info;
    info.reserve(40);
    const char *label = "zero-rtt";
    for (int i = 0; label[i]; ++i) info.push_back(static_cast<uint8_t>(label[i]));
    info.insert(info.end(), key_.begin(), key_.end());

    auto hmac_result = crypto::HMAC_SHA256::compute(
        std::span<const uint8_t>(master_secret.data(), master_secret.size()),
        std::span<const uint8_t>(info.data(), info.size()));
    std::memcpy(output.data(), hmac_result.data(), 32);
}

} // namespace linoh::tls
