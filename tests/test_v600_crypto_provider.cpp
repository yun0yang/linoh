// test_v600_crypto_provider.cpp — v6.0.0 T-LP5-003 CryptoProvider trait 抽象测试
//
// 验证内容：
//   - AeadCipher 接口契约（key_size/nonce_size/tag_size）
//   - CustomCryptoProvider 默认实现（default_aead/chacha20_poly1305/aes_128_gcm）
//   - seal/open 往返一致性（加密后解密恢复原文）
//   - set_global_provider/global_provider 全局切换
//   - 自定义 CryptoProvider 注入（模拟国密 provider 切换）
//   - AD（附加数据）完整性验证
//   - 错误 nonce/密钥解密失败
//
// 关联任务：T-LP5-003（trait 已存在于 tls/crypto_provider.hpp）

#include "linoh/tls/crypto_provider.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <vector>

using namespace linoh::tls;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 工具函数
// ============================================================================

static std::vector<uint8_t> make_key(std::size_t n, uint8_t seed = 0xAA) {
    std::vector<uint8_t> k(n);
    for (std::size_t i = 0; i < n; ++i) k[i] = static_cast<uint8_t>(seed + i);
    return k;
}

static std::vector<uint8_t> make_nonce(std::size_t n, uint8_t seed = 0xBB) {
    std::vector<uint8_t> nc(n);
    for (std::size_t i = 0; i < n; ++i) nc[i] = static_cast<uint8_t>(seed + i);
    return nc;
}

static std::vector<uint8_t> make_payload(std::size_t n, uint8_t seed = 0xCC) {
    std::vector<uint8_t> p(n);
    for (std::size_t i = 0; i < n; ++i) p[i] = static_cast<uint8_t>(seed + i * 7);
    return p;
}

// ============================================================================
// 测试 1：AeadCipher 接口契约
// ============================================================================

static void test_aead_cipher_contract() {
    std::printf("[test_aead_cipher_contract]\n");

    auto provider = CustomCryptoProvider::instance();
    CHECK(provider != nullptr);

    auto aead = provider->default_aead();
    CHECK(aead != nullptr);

    // ChaCha20-Poly1305 参数契约：key=32B, nonce=12B, tag=16B
    CHECK(aead->key_size() == 32);
    CHECK(aead->nonce_size() == 12);
    CHECK(aead->tag_size() == 16);

    // chacha20_poly1305() 返回有效实例，参数同 default_aead
    auto chacha = provider->chacha20_poly1305();
    CHECK(chacha != nullptr);
    CHECK(chacha->key_size() == 32);
    CHECK(chacha->nonce_size() == 12);
    CHECK(chacha->tag_size() == 16);

    // aes_128_gcm() 返回有效实例（linoh 实现为 ChaCha20-Poly1305 别名，见 crypto_provider.cpp:50-60 注释）
    auto aes = provider->aes_128_gcm();
    CHECK(aes != nullptr);
    CHECK(aes->key_size() == 32);
    CHECK(aes->nonce_size() == 12);
    CHECK(aes->tag_size() == 16);
}

// ============================================================================
// 测试 2：seal/open 往返一致性
// ============================================================================

static void test_seal_open_roundtrip() {
    std::printf("[test_seal_open_roundtrip]\n");

    auto aead = CustomCryptoProvider::instance()->default_aead();

    // 不同大小 payload 往返测试
    std::size_t sizes[] = {0, 1, 16, 64, 256, 1024, 4096, 16384, 65536};
    for (std::size_t sz : sizes) {
        auto key = make_key(aead->key_size());
        auto nonce = make_nonce(aead->nonce_size());
        auto plaintext = make_payload(sz);

        std::vector<uint8_t> ciphertext(plaintext.size() + aead->tag_size());
        std::size_t written = aead->seal(key, nonce, {}, plaintext, ciphertext);
        CHECK(written == plaintext.size() + aead->tag_size());

        std::vector<uint8_t> recovered(plaintext.size());
        std::size_t decrypted = aead->open(key, nonce, {}, ciphertext, recovered);
        CHECK(decrypted == plaintext.size());
        CHECK(recovered == plaintext);
    }
}

// ============================================================================
// 测试 3：AD（附加数据）完整性
// ============================================================================

static void test_ad_integrity() {
    std::printf("[test_ad_integrity]\n");

    auto aead = CustomCryptoProvider::instance()->default_aead();

    auto key = make_key(aead->key_size());
    auto nonce = make_nonce(aead->nonce_size());
    auto plaintext = make_payload(256);
    auto ad = make_payload(64, 0xDD);

    // 带 AD 加密
    std::vector<uint8_t> ciphertext(plaintext.size() + aead->tag_size());
    aead->seal(key, nonce, ad, plaintext, ciphertext);

    // 用相同 AD 解密 — 成功
    std::vector<uint8_t> recovered(plaintext.size());
    std::size_t decrypted = aead->open(key, nonce, ad, ciphertext, recovered);
    CHECK(decrypted == plaintext.size());
    CHECK(recovered == plaintext);

    // 用不同 AD 解密 — 失败（返回 0）
    auto ad_wrong = make_payload(64, 0xEE);
    std::vector<uint8_t> recovered2(plaintext.size());
    std::size_t decrypted2 = aead->open(key, nonce, ad_wrong, ciphertext, recovered2);
    CHECK(decrypted2 == 0);
}

// ============================================================================
// 测试 4：错误密钥/nonce 解密失败
// ============================================================================

static void test_wrong_key_nonce_fails() {
    std::printf("[test_wrong_key_nonce_fails]\n");

    auto aead = CustomCryptoProvider::instance()->default_aead();

    auto key = make_key(aead->key_size());
    auto nonce = make_nonce(aead->nonce_size());
    auto plaintext = make_payload(128);

    std::vector<uint8_t> ciphertext(plaintext.size() + aead->tag_size());
    aead->seal(key, nonce, {}, plaintext, ciphertext);

    // 错误密钥解密 — 失败
    auto key_wrong = make_key(aead->key_size(), 0x99);
    std::vector<uint8_t> recovered(plaintext.size());
    CHECK(aead->open(key_wrong, nonce, {}, ciphertext, recovered) == 0);

    // 错误 nonce 解密 — 失败
    auto nonce_wrong = make_nonce(aead->nonce_size(), 0x88);
    CHECK(aead->open(key, nonce_wrong, {}, ciphertext, recovered) == 0);

    // 篡改密文解密 — 失败
    ciphertext[0] ^= 0xFF;
    CHECK(aead->open(key, nonce, {}, ciphertext, recovered) == 0);
}

// ============================================================================
// 测试 5：set_global_provider / global_provider 切换
// ============================================================================

// 自定义测试 Provider（模拟国密 provider 注入）
class TestCryptoProvider : public CryptoProvider {
public:
    static std::shared_ptr<TestCryptoProvider> instance() {
        static auto p = std::make_shared<TestCryptoProvider>();
        return p;
    }

    std::shared_ptr<AeadCipher> default_aead() const override {
        return CustomCryptoProvider::instance()->default_aead();
    }
    std::shared_ptr<AeadCipher> chacha20_poly1305() const override {
        return CustomCryptoProvider::instance()->chacha20_poly1305();
    }
    std::shared_ptr<AeadCipher> aes_128_gcm() const override {
        return CustomCryptoProvider::instance()->aes_128_gcm();
    }
    std::string name() const override { return "TestProvider"; }
};

static void test_global_provider_switch() {
    std::printf("[test_global_provider_switch]\n");

    // 默认是 CustomCryptoProvider
    CryptoProvider &orig = global_provider();
    CHECK(orig.name() == std::string("Custom"));

    // 切换到 TestProvider
    set_global_provider(TestCryptoProvider::instance());
    CryptoProvider &now = global_provider();
    CHECK(now.name() == std::string("TestProvider"));

    // TestProvider 的 aead 仍可用
    auto aead = now.default_aead();
    CHECK(aead != nullptr);
    CHECK(aead->key_size() == 32);

    // 切换回 CustomCryptoProvider
    set_global_provider(CustomCryptoProvider::instance());
    CryptoProvider &restored = global_provider();
    CHECK(restored.name() == std::string("Custom"));
}

// ============================================================================
// 测试 6：set_global_provider 拒绝 nullptr
// ============================================================================

static void test_set_global_provider_rejects_null() {
    std::printf("[test_set_global_provider_rejects_null]\n");

    CryptoProvider &before = global_provider();
    std::string name_before = before.name();

    set_global_provider(nullptr);  // 应被拒绝，不改变全局 provider

    CryptoProvider &after = global_provider();
    CHECK(after.name() == name_before);  // 未改变
}

// ============================================================================
// 测试 7：CryptoProvider 多实例独立（线程安全单例）
// ============================================================================

static void test_provider_instance_singleton() {
    std::printf("[test_provider_instance_singleton]\n");

    // CustomCryptoProvider::instance() 返回同一单例
    auto p1 = CustomCryptoProvider::instance();
    auto p2 = CustomCryptoProvider::instance();
    CHECK(p1 == p2);  // 同一指针

    // default_aead() 返回同一静态实例
    auto a1 = p1->default_aead();
    auto a2 = p2->default_aead();
    CHECK(a1 == a2);

    // name() 一致
    CHECK(p1->name() == std::string("Custom"));
    CHECK(p1->name() == p2->name());
}

// ============================================================================
// 测试 8：OpenSSLProvider 向后兼容别名
// ============================================================================

static void test_openssl_provider_alias() {
    std::printf("[test_openssl_provider_alias]\n");

    // tc-L1 (v1.7.0.8): OpenSSLProvider 是 CustomCryptoProvider 的别名
    auto p = OpenSSLProvider::instance();
    CHECK(p != nullptr);
    CHECK(p->name() == std::string("Custom"));

    // 与 CustomCryptoProvider::instance() 是同一单例
    CHECK(p == CustomCryptoProvider::instance());
}

// ============================================================================
// 测试 9：大批量 seal/open 性能烟测（无性能断言，仅验证不崩溃）
// ============================================================================

static void test_bulk_seal_open_smoke() {
    std::printf("[test_bulk_seal_open_smoke]\n");

    auto aead = CustomCryptoProvider::instance()->default_aead();
    auto key = make_key(aead->key_size());

    // 模拟 hidden_state 大小（172KB）
    auto plaintext = make_payload(172032);

    // 100 次加密解密循环
    for (int i = 0; i < 100; ++i) {
        auto nonce = make_nonce(aead->nonce_size(), static_cast<uint8_t>(i));

        std::vector<uint8_t> ciphertext(plaintext.size() + aead->tag_size());
        std::size_t w = aead->seal(key, nonce, {}, plaintext, ciphertext);
        CHECK(w == plaintext.size() + aead->tag_size());

        std::vector<uint8_t> recovered(plaintext.size());
        std::size_t d = aead->open(key, nonce, {}, ciphertext, recovered);
        CHECK(d == plaintext.size());
        CHECK(recovered == plaintext);
    }
}

// ============================================================================
// 测试 10：AD 边界（空 AD vs 无 AD）
// ============================================================================

static void test_ad_boundary() {
    std::printf("[test_ad_boundary]\n");

    auto aead = CustomCryptoProvider::instance()->default_aead();
    auto key = make_key(aead->key_size());
    auto nonce = make_nonce(aead->nonce_size());
    auto plaintext = make_payload(64);

    // 空 AD（span 非空但 size=0）
    std::vector<uint8_t> empty_ad;
    std::vector<uint8_t> ciphertext(plaintext.size() + aead->tag_size());
    aead->seal(key, nonce, empty_ad, plaintext, ciphertext);

    // 用空 AD 解密 — 成功
    std::vector<uint8_t> recovered(plaintext.size());
    CHECK(aead->open(key, nonce, empty_ad, ciphertext, recovered) == plaintext.size());
    CHECK(recovered == plaintext);

    // 用默认空 span（{}）解密 — 应与空 AD 等价
    std::vector<uint8_t> recovered2(plaintext.size());
    CHECK(aead->open(key, nonce, {}, ciphertext, recovered2) == plaintext.size());
    CHECK(recovered2 == plaintext);
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== test_v600_crypto_provider ===\n\n");

    test_aead_cipher_contract();
    test_seal_open_roundtrip();
    test_ad_integrity();
    test_wrong_key_nonce_fails();
    test_global_provider_switch();
    test_set_global_provider_rejects_null();
    test_provider_instance_singleton();
    test_openssl_provider_alias();
    test_bulk_seal_open_smoke();
    test_ad_boundary();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
