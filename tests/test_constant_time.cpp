// test_constant_time.cpp — P1-7 常量时间比较单元测试
//
// 验证 linoh::crypto::verify_equal / verify_equal_32 的正确性
// 和现有 AEAD tag / Ed25519 签名验证路径的安全性。
//
// 注：常量时间属性需通过 timing 测量验证，单元测试仅验证功能正确性。
//     常量时间属性的静态保证通过代码审查 + 位运算实现确认。

#include "linoh/util/crypto.hpp"
#include "linoh/tls/ed25519_core.hpp"
#include "linoh/base/key.hpp"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

using namespace linoh::crypto;
using namespace linoh::base;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// verify_equal 测试
// ============================================================================

static void test_verify_equal_same() {
    std::printf("[test] verify_equal: same content returns true...\n");

    std::vector<uint8_t> a = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> b = {0x01, 0x02, 0x03, 0x04, 0x05};

    CHECK(verify_equal(std::span<const uint8_t>(a.data(), a.size()),
                        std::span<const uint8_t>(b.data(), b.size())));
}

static void test_verify_equal_diff() {
    std::printf("[test] verify_equal: different content returns false...\n");

    std::vector<uint8_t> a = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> b = {0x01, 0x02, 0x03, 0x04, 0x06};  // 最后 1 字节不同

    CHECK(!verify_equal(std::span<const uint8_t>(a.data(), a.size()),
                         std::span<const uint8_t>(b.data(), b.size())));
}

static void test_verify_equal_diff_length() {
    std::printf("[test] verify_equal: different length returns false...\n");

    std::vector<uint8_t> a = {0x01, 0x02, 0x03};
    std::vector<uint8_t> b = {0x01, 0x02};

    CHECK(!verify_equal(std::span<const uint8_t>(a.data(), a.size()),
                         std::span<const uint8_t>(b.data(), b.size())));
}

static void test_verify_equal_empty() {
    std::printf("[test] verify_equal: empty buffers are equal...\n");

    CHECK(verify_equal(std::span<const uint8_t>(), std::span<const uint8_t>()));
}

static void test_verify_equal_all_zero() {
    std::printf("[test] verify_equal: all-zero buffers are equal...\n");

    std::vector<uint8_t> a(32, 0);
    std::vector<uint8_t> b(32, 0);

    CHECK(verify_equal(std::span<const uint8_t>(a.data(), a.size()),
                        std::span<const uint8_t>(b.data(), b.size())));
}

static void test_verify_equal_single_byte_diff() {
    std::printf("[test] verify_equal: single byte difference detected...\n");

    // 测试每个字节位置的不同都能被检测
    for (int pos = 0; pos < 16; ++pos) {
        std::vector<uint8_t> a(16, 0xAA);
        std::vector<uint8_t> b(16, 0xAA);
        b[pos] = 0xBB;

        CHECK(!verify_equal(std::span<const uint8_t>(a.data(), a.size()),
                             std::span<const uint8_t>(b.data(), b.size())));
    }
}

// ============================================================================
// verify_equal_32 测试
// ============================================================================

static void test_verify_equal_32_same() {
    std::printf("[test] verify_equal_32: same 32 bytes return true...\n");

    uint8_t a[32], b[32];
    for (int i = 0; i < 32; ++i) {
        a[i] = static_cast<uint8_t>(i);
        b[i] = static_cast<uint8_t>(i);
    }

    CHECK(verify_equal_32(a, b));
}

static void test_verify_equal_32_diff() {
    std::printf("[test] verify_equal_32: different 32 bytes return false...\n");

    uint8_t a[32], b[32];
    for (int i = 0; i < 32; ++i) {
        a[i] = static_cast<uint8_t>(i);
        b[i] = static_cast<uint8_t>(i);
    }
    b[31] = 0xFF;  // 仅最后 1 字节不同

    CHECK(!verify_equal_32(a, b));
}

static void test_verify_equal_32_null_safe() {
    std::printf("[test] verify_equal_32: null pointers return false...\n");

    uint8_t a[32] = {};
    CHECK(!verify_equal_32(nullptr, a));
    CHECK(!verify_equal_32(a, nullptr));
    CHECK(!verify_equal_32(nullptr, nullptr));
}

// ============================================================================
// 现有路径验证：AEAD tag 比较已常量时间
// ============================================================================

static void test_aead_tag_constant_time_path() {
    std::printf("[test] AEAD tag verification uses constant-time path...\n");

    // 加密-解密往返：正常路径
    uint8_t key[32] = {};
    uint8_t nonce[12] = {};
    for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < 12; ++i) nonce[i] = static_cast<uint8_t>(i);

    std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> ciphertext(plaintext.size() + 16);

    std::size_t written = ChaCha20Poly1305::seal(
        std::span<const uint8_t>(key, 32),
        std::span<const uint8_t>(nonce, 12),
        std::span<const uint8_t>(),
        std::span<const uint8_t>(plaintext.data(), plaintext.size()),
        std::span<uint8_t>(ciphertext.data(), ciphertext.size()));
    CHECK(written == plaintext.size() + 16);

    // 篡改密文最后 1 字节（tag 部分），解密应失败
    std::vector<uint8_t> tampered = ciphertext;
    tampered.back() ^= 0x01;

    std::vector<uint8_t> recovered(plaintext.size());
    std::size_t decrypted = ChaCha20Poly1305::open(
        std::span<const uint8_t>(key, 32),
        std::span<const uint8_t>(nonce, 12),
        std::span<const uint8_t>(),
        std::span<const uint8_t>(tampered.data(), tampered.size()),
        std::span<uint8_t>(recovered.data(), recovered.size()));
    CHECK(decrypted == 0);  // 篡改应被检测

    // 正常密文解密应成功
    decrypted = ChaCha20Poly1305::open(
        std::span<const uint8_t>(key, 32),
        std::span<const uint8_t>(nonce, 12),
        std::span<const uint8_t>(),
        std::span<const uint8_t>(ciphertext.data(), ciphertext.size()),
        std::span<uint8_t>(recovered.data(), recovered.size()));
    CHECK(decrypted == plaintext.size());
    CHECK(std::memcmp(recovered.data(), plaintext.data(), plaintext.size()) == 0);
}

// ============================================================================
// 现有路径验证：Ed25519 签名验证已常量时间（TweetNaCl crypto_verify_32）
// ============================================================================

static void test_ed25519_uses_constant_time() {
    std::printf("[test] Ed25519 verify uses constant-time compare...\n");

    SecretKey sk = SecretKey::generate();
    PublicKey pk = sk.public_key();

    std::vector<uint8_t> msg = {'t', 'e', 's', 't', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};
    auto sig = sk.sign(std::span<const uint8_t>(msg.data(), msg.size()));

    // 正常签名验证通过
    bool ok = Signature::from_bytes(std::span<const uint8_t>(sig.data(), sig.size()))
                  .verify(std::span<const uint8_t>(msg.data(), msg.size()), pk);
    CHECK(ok);

    // 篡改签名 1 字节，验证失败
    auto bad_sig = sig;
    bad_sig[0] ^= 0x01;
    bool bad_ok = Signature::from_bytes(std::span<const uint8_t>(bad_sig.data(), bad_sig.size()))
                      .verify(std::span<const uint8_t>(msg.data(), msg.size()), pk);
    CHECK(!bad_ok);

    // 篡改消息 1 字节，验证失败
    std::vector<uint8_t> bad_msg = msg;
    bad_msg[0] ^= 0x01;
    bool bad_msg_ok = Signature::from_bytes(std::span<const uint8_t>(sig.data(), sig.size()))
                          .verify(std::span<const uint8_t>(bad_msg.data(), bad_msg.size()), pk);
    CHECK(!bad_msg_ok);
}

int main() {
    std::printf("=== test_constant_time ===\n");

    test_verify_equal_same();
    test_verify_equal_diff();
    test_verify_equal_diff_length();
    test_verify_equal_empty();
    test_verify_equal_all_zero();
    test_verify_equal_single_byte_diff();
    test_verify_equal_32_same();
    test_verify_equal_32_diff();
    test_verify_equal_32_null_safe();
    test_aead_tag_constant_time_path();
    test_ed25519_uses_constant_time();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
