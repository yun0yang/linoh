#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace linoh::tls {

/// AEAD 加密/解密接口。所有实现必须是线程安全的 stateless 对象。
class AeadCipher {
public:
    virtual ~AeadCipher() = default;

    /// 返回 key 长度（字节）。
    virtual std::size_t key_size() const = 0;
    /// 返回 nonce 长度（字节）。
    virtual std::size_t nonce_size() const = 0;
    /// 返回认证标签长度（字节）。
    virtual std::size_t tag_size() const = 0;

    /// 加密。`out` 应至少有 `plaintext.size() + tag_size()` 空间。返回实际写入字节数。
    virtual std::size_t seal(std::span<const uint8_t> key,
                             std::span<const uint8_t> nonce,
                             std::span<const uint8_t> ad,
                             std::span<const uint8_t> plaintext,
                             std::span<uint8_t> out) const = 0;

    /// 解密。`out` 应至少有 `ciphertext.size() - tag_size()`。成功返回写入字节数，失败 0。
    virtual std::size_t open(std::span<const uint8_t> key,
                             std::span<const uint8_t> nonce,
                             std::span<const uint8_t> ad,
                             std::span<const uint8_t> ciphertext,
                             std::span<uint8_t> out) const = 0;
};

/// 加密提供者抽象：允许在运行时在 OpenSSL / BoringSSL / FIPS 模块之间切换。
class CryptoProvider {
public:
    virtual ~CryptoProvider() = default;

    /// 返回默认 AEAD 实现（AES-128-GCM 或 ChaCha20-Poly1305，取决于编译选项）。
    virtual std::shared_ptr<AeadCipher> default_aead() const = 0;

    /// 返回 ChaCha20-Poly1305。
    virtual std::shared_ptr<AeadCipher> chacha20_poly1305() const = 0;

    /// 返回 AES-128-GCM。
    virtual std::shared_ptr<AeadCipher> aes_128_gcm() const = 0;

    /// 名字，用于日志打印。
    virtual std::string name() const = 0;
};

/// 自定义 ChaCha20-Poly1305 AEAD 实现的默认 CryptoProvider。
/// tc-L1 (v1.7.0.8): 重命名 OpenSSLProvider → CustomCryptoProvider。
///   原命名误导（linoh 不依赖 OpenSSL，纯自定义实现），影响安全审计判断。
class CustomCryptoProvider : public CryptoProvider {
public:
    static std::shared_ptr<CustomCryptoProvider> instance();

    std::shared_ptr<AeadCipher> default_aead() const override;
    std::shared_ptr<AeadCipher> chacha20_poly1305() const override;
    std::shared_ptr<AeadCipher> aes_128_gcm() const override;
    std::string name() const override { return "Custom"; }
};

// tc-L1 (v1.7.0.8): 向后兼容别名（外部代码可能引用 OpenSSLProvider::instance()）
using OpenSSLProvider = CustomCryptoProvider;

/// 设置全局 crypto provider——若未设置，默认使用 `CustomCryptoProvider::instance()`。
void set_global_provider(std::shared_ptr<CryptoProvider> p);
CryptoProvider &global_provider();

} // namespace linoh::tls
