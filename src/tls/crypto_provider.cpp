// 完全重写 - 使用自定义 ChaCha20-Poly1305 AEAD，不依赖 OpenSSL
#include "linoh/tls/crypto_provider.hpp"
#include "linoh/util/crypto.hpp"

#include <memory>
#include <mutex>
#include <vector>
#include <cstdint>
#include <cstring>

namespace linoh::tls {

namespace {

class CustomAead : public AeadCipher {
public:
    std::size_t key_size() const override { return 32; }
    std::size_t nonce_size() const override { return 12; }
    std::size_t tag_size() const override { return 16; }

    std::size_t seal(std::span<const uint8_t> key,
                     std::span<const uint8_t> nonce,
                     std::span<const uint8_t> ad,
                     std::span<const uint8_t> plaintext,
                     std::span<uint8_t> out) const override {
        return crypto::ChaCha20Poly1305::seal(key, nonce, ad, plaintext, out);
    }

    std::size_t open(std::span<const uint8_t> key,
                     std::span<const uint8_t> nonce,
                     std::span<const uint8_t> ad,
                     std::span<const uint8_t> ciphertext,
                     std::span<uint8_t> out) const override {
        return crypto::ChaCha20Poly1305::open(key, nonce, ad, ciphertext, out);
    }
};

} // namespace

std::shared_ptr<AeadCipher> CustomCryptoProvider::default_aead() const {
    static std::shared_ptr<AeadCipher> instance = std::make_shared<CustomAead>();
    return instance;
}

std::shared_ptr<AeadCipher> CustomCryptoProvider::chacha20_poly1305() const {
    static std::shared_ptr<AeadCipher> instance = std::make_shared<CustomAead>();
    return instance;
}

std::shared_ptr<AeadCipher> CustomCryptoProvider::aes_128_gcm() const {
    // tc-M4 (v1.7.0.8): 安全声明一致性修正。
    //   原实现 aes_128_gcm() 直接返回 chacha20_poly1305()，但文档/接口名声称 AES-128-GCM，
    //   安全声明与实现不符（误导安全审计）。
    //   设计决策：linoh 不依赖 OpenSSL AES 硬件加速，统一使用 ChaCha20-Poly1305
    //   （抗时序攻击、纯软件实现性能优于 AES-NI 不可用场景、与 Python 端对齐）。
    //   此处显式注释说明：aes_128_gcm() 返回的实际上是 ChaCha20-Poly1305 实现，
    //   调用方应理解为"AEAD 加密"而非真正的 AES-GCM。
    //   若未来需要真 AES-GCM，需引入 OpenSSL EVP_aes_128_gcm 并实现独立 AeadCipher。
    return chacha20_poly1305();
}

std::shared_ptr<CustomCryptoProvider> CustomCryptoProvider::instance() {
    static std::shared_ptr<CustomCryptoProvider> p = std::make_shared<CustomCryptoProvider>();
    return p;
}

namespace {
std::shared_ptr<CryptoProvider> &global_provider_storage() {
    static std::shared_ptr<CryptoProvider> p = CustomCryptoProvider::instance();
    return p;
}
std::mutex &global_provider_mutex() {
    static std::mutex m;
    return m;
}
} // namespace

void set_global_provider(std::shared_ptr<CryptoProvider> p) {
    if (!p) return;
    std::lock_guard<std::mutex> lk(global_provider_mutex());
    global_provider_storage() = std::move(p);
}

CryptoProvider &global_provider() {
    std::lock_guard<std::mutex> lk(global_provider_mutex());
    return *global_provider_storage();
}

} // namespace linoh::tls
