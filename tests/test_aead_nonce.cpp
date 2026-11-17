// test_aead_nonce.cpp — P1-3 AEAD nonce 方向区分单元测试
//
// 验证 tls13_nonce 在 client/server 方向上产生不同 nonce，
// 即使 iv 相同也能避免 nonce 重用。

#include "linoh/util/crypto.hpp"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>

using namespace linoh::crypto;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// 复制 connection.cpp 内的 tls13_nonce 算法（P1-3 方向位版本）
static std::array<std::uint8_t, 12> tls13_nonce(
    const std::array<std::uint8_t, 12> &iv, std::uint64_t pn, bool is_server) {
    std::array<std::uint8_t, 12> n = iv;
    n[0] = (n[0] & 0x7F) | (is_server ? 0x80 : 0x00);
    for (int i = 0; i < 8; ++i) n[4 + i] ^= static_cast<std::uint8_t>((pn >> (8 * i)) & 0xFF);
    return n;
}

static void test_direction_bit_distinguishes_nonce() {
    std::printf("[test] direction bit distinguishes client/server nonce...\n");

    // 相同 iv 和 pn，仅方向不同
    std::array<std::uint8_t, 12> iv{};
    for (int i = 0; i < 12; ++i) iv[i] = static_cast<std::uint8_t>(0x55);

    auto n_client = tls13_nonce(iv, 42, false);
    auto n_server = tls13_nonce(iv, 42, true);

    // nonce[0] 最高位应不同
    CHECK((n_client[0] & 0x80) == 0x00);
    CHECK((n_server[0] & 0x80) == 0x80);

    // 完整 nonce 应不同
    bool equal = true;
    for (int i = 0; i < 12; ++i) {
        if (n_client[i] != n_server[i]) { equal = false; break; }
    }
    CHECK(!equal);
}

static void test_same_direction_same_nonce() {
    std::printf("[test] same direction + same pn produces same nonce...\n");

    std::array<std::uint8_t, 12> iv{};
    for (int i = 0; i < 12; ++i) iv[i] = static_cast<std::uint8_t>(i);

    auto n1 = tls13_nonce(iv, 100, false);
    auto n2 = tls13_nonce(iv, 100, false);
    CHECK(std::memcmp(n1.data(), n2.data(), 12) == 0);
}

static void test_different_pn_different_nonce() {
    std::printf("[test] different pn produces different nonce...\n");

    std::array<std::uint8_t, 12> iv{};

    auto n1 = tls13_nonce(iv, 1, false);
    auto n2 = tls13_nonce(iv, 2, false);
    CHECK(std::memcmp(n1.data(), n2.data(), 12) != 0);
}

static void test_different_iv_different_nonce() {
    std::printf("[test] different iv produces different nonce...\n");

    std::array<std::uint8_t, 12> iv1{};
    std::array<std::uint8_t, 12> iv2{};
    iv2[0] = 0xFF;

    auto n1 = tls13_nonce(iv1, 0, false);
    auto n2 = tls13_nonce(iv2, 0, false);
    CHECK(std::memcmp(n1.data(), n2.data(), 12) != 0);
}

static void test_pn_xor_in_lower_8_bytes() {
    std::printf("[test] pn XOR is in nonce lower 8 bytes...\n");

    std::array<std::uint8_t, 12> iv{};
    std::uint64_t pn = 0x0102030405060708ULL;

    auto n = tls13_nonce(iv, pn, false);

    // nonce[4..11] 应为 pn 各字节（小端）
    CHECK(n[4] == 0x08);
    CHECK(n[5] == 0x07);
    CHECK(n[6] == 0x06);
    CHECK(n[7] == 0x05);
    CHECK(n[8] == 0x04);
    CHECK(n[9] == 0x03);
    CHECK(n[10] == 0x02);
    CHECK(n[11] == 0x01);
}

static void test_direction_bit_does_not_affect_pn_xor() {
    std::printf("[test] direction bit in byte[0] doesn't affect pn XOR in bytes[4..11]...\n");

    std::array<std::uint8_t, 12> iv{};

    auto n_client = tls13_nonce(iv, 12345, false);
    auto n_server = tls13_nonce(iv, 12345, true);

    // bytes[4..11] 应完全相同（pn XOR 部分）
    CHECK(std::memcmp(n_client.data() + 4, n_server.data() + 4, 8) == 0);

    // bytes[1..3] 也应相同（未参与方向位或 pn XOR）
    CHECK(std::memcmp(n_client.data() + 1, n_server.data() + 1, 3) == 0);

    // 仅 byte[0] 最高位不同
    CHECK((n_client[0] ^ n_server[0]) == 0x80);
}

static void test_roundtrip_with_aead() {
    std::printf("[test] AEAD roundtrip with direction-aware nonce...\n");

    // 模拟 client 发送、server 接收
    uint8_t key[32] = {};
    for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);

    std::array<std::uint8_t, 12> iv{};
    for (int i = 0; i < 12; ++i) iv[i] = 0xAA;

    std::vector<uint8_t> plaintext = {'d', 'a', 't', 'a'};
    std::vector<uint8_t> ciphertext(plaintext.size() + 16);

    // Client 加密：方向位 = 0
    auto n_client = tls13_nonce(iv, 1, false);
    std::size_t written = ChaCha20Poly1305::seal(
        std::span<const uint8_t>(key, 32),
        std::span<const uint8_t>(n_client.data(), 12),
        std::span<const uint8_t>(),
        std::span<const uint8_t>(plaintext.data(), plaintext.size()),
        std::span<uint8_t>(ciphertext.data(), ciphertext.size()));
    CHECK(written == plaintext.size() + 16);

    // Server 解密：方向位 = 0（与发送方一致）
    auto n_server = tls13_nonce(iv, 1, false);  // server 接收 client 数据，用 client 方向位
    std::vector<uint8_t> recovered(plaintext.size());
    std::size_t decrypted = ChaCha20Poly1305::open(
        std::span<const uint8_t>(key, 32),
        std::span<const uint8_t>(n_server.data(), 12),
        std::span<const uint8_t>(),
        std::span<const uint8_t>(ciphertext.data(), ciphertext.size()),
        std::span<uint8_t>(recovered.data(), recovered.size()));
    CHECK(decrypted == plaintext.size());
    CHECK(std::memcmp(recovered.data(), plaintext.data(), plaintext.size()) == 0);

    // 用错误方向位（server 位=1）解密应失败
    auto n_wrong = tls13_nonce(iv, 1, true);
    std::vector<uint8_t> recovered2(plaintext.size());
    std::size_t decrypted2 = ChaCha20Poly1305::open(
        std::span<const uint8_t>(key, 32),
        std::span<const uint8_t>(n_wrong.data(), 12),
        std::span<const uint8_t>(),
        std::span<const uint8_t>(ciphertext.data(), ciphertext.size()),
        std::span<uint8_t>(recovered2.data(), recovered2.size()));
    CHECK(decrypted2 == 0);  // 方向位不匹配导致 nonce 错误，AEAD 验证失败
}

int main() {
    std::printf("=== test_aead_nonce ===\n");

    test_direction_bit_distinguishes_nonce();
    test_same_direction_same_nonce();
    test_different_pn_different_nonce();
    test_different_iv_different_nonce();
    test_pn_xor_in_lower_8_bytes();
    test_direction_bit_does_not_affect_pn_xor();
    test_roundtrip_with_aead();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
