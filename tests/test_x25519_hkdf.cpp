// X25519 (RFC 7748) + HKDF (RFC 5869) + TLS 1.3 HKDF-Expand-Label test vectors.
#include "linoh/crypto/x25519.hpp"
#include "linoh/crypto/hkdf.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

static std::vector<uint8_t> from_hex(const char *hex) {
    std::vector<uint8_t> out;
    for (size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
        auto h2b = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        out.push_back((uint8_t)((h2b(hex[i]) << 4) | h2b(hex[i + 1])));
    }
    return out;
}

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; } \
    else { printf("  [FAIL] %s\n", msg); g_fail++; } \
} while (0)

static bool eq_hex(const uint8_t *data, size_t len, const char *expected_hex) {
    auto expected = from_hex(expected_hex);
    if (expected.size() != len) return false;
    return memcmp(data, expected.data(), len) == 0;
}

// ============================================================================
// RFC 7748 §5.2 — X25519 scalarmult test vectors
// ============================================================================
static void test_x25519_scalarmult() {
    printf("\n=== X25519 RFC 7748 §5.2 scalarmult ===\n");

    // Vector 1
    {
        auto k = from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        auto u = from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        uint8_t out[32];
        linoh::crypto::x25519::scalarmult(out, k.data(), u.data());
        CHECK(eq_hex(out, 32, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
              "scalarmult vector 1");
    }
    // Vector 2
    {
        auto k = from_hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        auto u = from_hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        uint8_t out[32];
        linoh::crypto::x25519::scalarmult(out, k.data(), u.data());
        CHECK(eq_hex(out, 32, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
              "scalarmult vector 2");
    }
}

// ============================================================================
// RFC 7748 §6.1 — X25519 Diffie-Hellman
// ============================================================================
static void test_x25519_dh() {
    printf("\n=== X25519 RFC 7748 §6.1 Diffie-Hellman ===\n");

    auto a_priv = from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    auto b_priv = from_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

    uint8_t a_pub[32], b_pub[32];
    linoh::crypto::x25519::scalarmult_base(a_pub, a_priv.data());
    linoh::crypto::x25519::scalarmult_base(b_pub, b_priv.data());

    CHECK(eq_hex(a_pub, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
          "Alice public key");
    CHECK(eq_hex(b_pub, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
          "Bob public key");

    uint8_t ss_a[32], ss_b[32];
    linoh::crypto::x25519::scalarmult(ss_a, a_priv.data(), b_pub);
    linoh::crypto::x25519::scalarmult(ss_b, b_priv.data(), a_pub);

    CHECK(eq_hex(ss_a, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
          "shared secret (Alice side)");
    CHECK(memcmp(ss_a, ss_b, 32) == 0, "both sides derive identical shared secret");
}

// ============================================================================
// RFC 5869 — HKDF-SHA256 test vectors
// ============================================================================
static void test_hkdf() {
    printf("\n=== HKDF RFC 5869 (SHA-256) ===\n");

    // Test Case 1
    {
        auto ikm  = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        auto salt = from_hex("000102030405060708090a0b0c");
        auto info = from_hex("f0f1f2f3f4f5f6f7f8f9");
        auto prk  = linoh::crypto::hkdf_extract(salt, ikm);
        CHECK(eq_hex(prk.data(), 32,
              "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
              "TC1 PRK");
        auto okm = linoh::crypto::hkdf_expand(
            std::span<const uint8_t>(prk.data(), prk.size()), info, 42);
        CHECK(eq_hex(okm.data(), 42,
              "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
              "TC1 OKM (42 bytes)");
    }

    // Test Case 3 — zero-length salt and info
    {
        auto ikm  = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        auto prk  = linoh::crypto::hkdf_extract(std::span<const uint8_t>(), ikm);
        CHECK(eq_hex(prk.data(), 32,
              "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
              "TC3 PRK (empty salt)");
        auto okm = linoh::crypto::hkdf_expand(
            std::span<const uint8_t>(prk.data(), prk.size()),
            std::span<const uint8_t>(), 42);
        CHECK(eq_hex(okm.data(), 42,
              "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
              "TC3 OKM (empty info)");
    }
}

// ============================================================================
// TLS 1.3 (RFC 8446) — HKDF-Expand-Label / Derive-Secret sanity
// ============================================================================
static void test_tls13_derive() {
    printf("\n=== TLS 1.3 HKDF-Expand-Label / Derive-Secret ===\n");

    // Determinism + length correctness (self-consistency; matches structure of RFC 8448).
    std::array<uint8_t, 32> secret{};
    for (size_t i = 0; i < 32; ++i) secret[i] = static_cast<uint8_t>(i);
    std::array<uint8_t, 32> thash{};
    for (size_t i = 0; i < 32; ++i) thash[i] = static_cast<uint8_t>(0xA0 + i);

    auto k1 = linoh::crypto::hkdf_expand_label(secret, "quic key",
                                               std::span<const uint8_t>(), 32);
    auto k2 = linoh::crypto::hkdf_expand_label(secret, "quic key",
                                               std::span<const uint8_t>(), 32);
    CHECK(k1.size() == 32 && k1 == k2, "expand_label deterministic, len=32");

    auto iv = linoh::crypto::hkdf_expand_label(secret, "quic iv",
                                               std::span<const uint8_t>(), 12);
    CHECK(iv.size() == 12, "expand_label 'quic iv' len=12");
    CHECK(k1 != std::vector<uint8_t>(iv.begin(), iv.end()), "key != iv (different labels)");

    auto ds1 = linoh::crypto::derive_secret(secret, "c hs traffic",
                std::span<const uint8_t>(thash.data(), thash.size()));
    auto ds2 = linoh::crypto::derive_secret(secret, "s hs traffic",
                std::span<const uint8_t>(thash.data(), thash.size()));
    CHECK(ds1 != ds2, "client vs server hs traffic secrets differ");
}

int main() {
    printf("=== X25519 + HKDF Test Vectors ===\n");
    test_x25519_scalarmult();
    test_x25519_dh();
    test_hkdf();
    test_tls13_derive();
    printf("\n=== Results: %d PASSED, %d FAILED ===\n", g_pass, g_fail);
    return g_fail;
}
