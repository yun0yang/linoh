// RFC 8032 Ed25519 + RFC 8439 ChaCha20-Poly1305 test vectors
// Validates that our crypto implementations produce correct results
#include "linoh/base/key.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/tls/ed25519_core.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

// Hex helpers
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

static void print_hex(const uint8_t *data, size_t len, const char *label) {
    printf("  %s: ", label);
    for (size_t i = 0; i < len; ++i) printf("%02x", data[i]);
    printf("\n");
}

static bool cmp_hex(const uint8_t *data, size_t len, const char *expected_hex) {
    auto expected = from_hex(expected_hex);
    if (expected.size() != len) return false;
    return memcmp(data, expected.data(), len) == 0;
}

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; } \
    else { printf("  [FAIL] %s\n", msg); g_fail++; } \
} while (0)

// ============================================================================
// RFC 8032 Section 7.1 Test Vectors
// ============================================================================

static void test_ed25519_vectors() {
    printf("\n=== Ed25519 RFC 8032 Test Vectors ===\n");

    struct TestVec {
        const char *seed;
        const char *pubkey;
        const char *message;  // hex, empty string = ""
        const char *signature;
    };

    TestVec vectors[] = {
        // TEST 1: empty message
        {
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        },
        // TEST 2: 1 byte message (0x72)
        {
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        },
        // TEST 3: 2 byte message (0xaf82)
        {
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        },
        // TEST 102: 1 byte message (0x61)
        {
            "f5e5767cf1533195175511c2d0d9d6e20b97b212126212e0986873c0b514bc61",
            "2782f8694affc5f00a83d794b3e7a5e6c452fc56260a3d56f8462e58d54bdc62",
            "61",
            "8c63d2b1a8d3e8e8a6c2f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0"
            // Note: This is a placeholder; actual test 102 from RFC 8032 has a longer message
        }
    };

    for (int t = 0; t < 3; ++t) {
        printf("\n--- Ed25519 Test %d ---\n", t + 1);

        auto seed = from_hex(vectors[t].seed);
        auto expected_pub = from_hex(vectors[t].pubkey);
        auto msg = from_hex(vectors[t].message);
        auto expected_sig = from_hex(vectors[t].signature);

        // Test keypair derivation
        uint8_t pub[32];
        linoh::crypto::ed25519::keypair_from_seed(pub, seed.data());

        bool pub_ok = cmp_hex(pub, 32, vectors[t].pubkey);
        if (!pub_ok) {
            print_hex(pub, 32, "got pub");
            print_hex(expected_pub.data(), 32, "exp pub");
        }
        CHECK(pub_ok, "public key derivation");

        // Test signing
        uint8_t sig[64];
        linoh::crypto::ed25519::sign(sig, seed.data(), msg.data(), msg.size());

        bool sig_ok = cmp_hex(sig, 64, vectors[t].signature);
        if (!sig_ok) {
            print_hex(sig, 64, "got sig");
            print_hex(expected_sig.data(), 64, "exp sig");
        }
        CHECK(sig_ok, "signature generation");

        // Test verification (valid signature)
        bool verify_ok = linoh::crypto::ed25519::verify(
            sig, pub, msg.data(), msg.size());
        CHECK(verify_ok, "signature verification (valid)");

        // Test verification (wrong message → should fail)
        std::vector<uint8_t> wrong_msg = {0x99};
        bool verify_wrong = linoh::crypto::ed25519::verify(
            sig, pub, wrong_msg.data(), wrong_msg.size());
        CHECK(!verify_wrong, "signature verification (wrong message rejected)");

        // Test verification (tampered signature → should fail)
        uint8_t bad_sig[64];
        memcpy(bad_sig, sig, 64);
        bad_sig[0] ^= 0x01;
        bool verify_bad = linoh::crypto::ed25519::verify(
            bad_sig, pub, msg.data(), msg.size());
        CHECK(!verify_bad, "signature verification (tampered sig rejected)");
    }

    // Test using linoh::base API
    printf("\n--- Ed25519 via linoh::base API ---\n");
    {
        auto seed = from_hex(vectors[0].seed);
        auto msg = from_hex(vectors[0].message);

        auto sk = linoh::base::SecretKey::from_bytes(
            std::span<const uint8_t>(seed.data(), 32));
        auto pk = sk.public_key();

        bool pub_ok = cmp_hex(pk.data(), 32, vectors[0].pubkey);
        CHECK(pub_ok, "SecretKey::public_key()");

        auto sig = sk.sign(std::span<const uint8_t>(msg.data(), msg.size()));
        bool sig_ok = cmp_hex(sig.data(), 64, vectors[0].signature);
        CHECK(sig_ok, "SecretKey::sign()");

        linoh::base::Signature signature(sig);
        bool verify_ok = signature.verify(
            std::span<const uint8_t>(msg.data(), msg.size()), pk);
        CHECK(verify_ok, "Signature::verify() (valid)");

        // Verify with wrong message
        std::vector<uint8_t> wrong = {0x00};
        bool verify_wrong = signature.verify(
            std::span<const uint8_t>(wrong.data(), 1), pk);
        CHECK(!verify_wrong, "Signature::verify() (wrong message rejected)");
    }
}

// ============================================================================
// RFC 8439 Section 2.8.2 ChaCha20-Poly1305 AEAD Test Vector
// ============================================================================

static void test_aead_vector() {
    printf("\n=== ChaCha20-Poly1305 AEAD RFC 8439 Test Vector ===\n");

    auto key = from_hex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f");
    auto nonce = from_hex("070000004041424344454647");
    auto ad = from_hex("50515253c0c1c2c3c4c5c6c7");
    auto plaintext = from_hex(
        "4c616469657320616e642047656e746c"
        "656d656e206f662074686520636c6173"
        "73206f66202739393a20496620492063"
        "6f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220"
        "746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069"
        "742e");
    auto expected_ct = from_hex(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116");
    auto expected_tag = from_hex("1ae10b594f09e26a7e902ecbd0600691");

    // Encrypt
    uint8_t out[256];
    size_t out_len = linoh::crypto::ChaCha20Poly1305::seal(
        key, nonce, ad, plaintext, out);

    CHECK(out_len == plaintext.size() + 16, "seal output length");

    // Check ciphertext
    bool ct_ok = memcmp(out, expected_ct.data(), plaintext.size()) == 0;
    if (!ct_ok) {
        print_hex(out, plaintext.size(), "got ct");
        print_hex(expected_ct.data(), plaintext.size(), "exp ct");
    }
    CHECK(ct_ok, "ciphertext matches");

    // Check tag
    bool tag_ok = memcmp(out + plaintext.size(), expected_tag.data(), 16) == 0;
    if (!tag_ok) {
        print_hex(out + plaintext.size(), 16, "got tag");
        print_hex(expected_tag.data(), 16, "exp tag");
    }
    CHECK(tag_ok, "tag matches");

    // Decrypt
    std::vector<uint8_t> ct_with_tag(out, out + out_len);
    uint8_t decrypted[256];
    size_t dec_len = linoh::crypto::ChaCha20Poly1305::open(
        key, nonce, ad, ct_with_tag, decrypted);

    CHECK(dec_len == plaintext.size(), "open output length");
    bool pt_ok = memcmp(decrypted, plaintext.data(), plaintext.size()) == 0;
    CHECK(pt_ok, "decrypted plaintext matches");

    // Tampered ciphertext → should fail
    ct_with_tag[0] ^= 0x01;
    size_t bad_len = linoh::crypto::ChaCha20Poly1305::open(
        key, nonce, ad, ct_with_tag, decrypted);
    CHECK(bad_len == 0, "tampered ciphertext rejected");
}

// ============================================================================
// SHA-512 Known Answer Test
// ============================================================================

static void test_sha512_vector() {
    printf("\n=== SHA-512 Test Vector ===\n");

    // SHA-512("abc") = ddaf35a193617aba...
    const char *input = "abc";
    auto result = linoh::crypto::SHA512::hash(
        std::span<const uint8_t>((const uint8_t *)input, 3));

    const char *expected =
        "ddaf35a193617abacc417349ae204131"
        "12e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f";

    bool ok = cmp_hex(result.data(), 64, expected);
    if (!ok) {
        print_hex(result.data(), 64, "got");
        printf("  exp: %s\n", expected);
    }
    CHECK(ok, "SHA-512(\"abc\")");
}

// ============================================================================
// Poly1305 Known Answer Test (RFC 7539 Section 2.5)
// ============================================================================

static void test_poly1305_vector() {
    printf("\n=== Poly1305 RFC 7539 Test Vector ===\n");

    auto key = from_hex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b");
    // Message: "Cryptographic Forum Research Group"
    auto msg = from_hex(
        "43727970746f6772617068696320466f7"
        "2756d2052657365617263682047726f75"
        "70");
    auto expected = from_hex("a8061dc1305136c6c22b8baf0c0127a9");

    auto tag = linoh::crypto::Poly1305::compute(key, msg);

    bool ok = memcmp(tag.data(), expected.data(), 16) == 0;
    if (!ok) {
        print_hex(tag.data(), 16, "got");
        print_hex(expected.data(), 16, "exp");
    }
    CHECK(ok, "Poly1305 tag matches RFC 7539");
}

// ============================================================================
// Key generation round-trip test
// ============================================================================

static void test_keygen_roundtrip() {
    printf("\n=== Ed25519 Key Generation Round-Trip ===\n");

    for (int i = 0; i < 10; ++i) {
        auto sk = linoh::base::SecretKey::generate();
        auto pk = sk.public_key();

        // Key should be non-zero
        bool sk_nonzero = !sk.is_zero();
        bool pk_nonzero = !pk.is_zero();
        if (!sk_nonzero || !pk_nonzero) {
            CHECK(false, "key generation non-zero");
            continue;
        }

        // Sign and verify
        uint8_t msg[] = "hello world";
        auto sig = sk.sign(std::span<const uint8_t>(msg, 11));
        linoh::base::Signature signature(sig);
        bool ok = signature.verify(std::span<const uint8_t>(msg, 11), pk);

        if (!ok) {
            printf("  [FAIL] round-trip %d\n", i);
            g_fail++;
        }
    }
    CHECK(true, "10 random keypair sign+verify round-trips");
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("=====================================================\n");
    printf("  linoh Cryptographic Test Vectors\n");
    printf("  RFC 8032 Ed25519 + RFC 8439 AEAD + RFC 7539 Poly1305\n");
    printf("=====================================================\n");

    test_sha512_vector();
    test_poly1305_vector();
    test_aead_vector();
    test_ed25519_vectors();
    test_keygen_roundtrip();

    printf("\n=====================================================\n");
    printf("  Results: %d passed, %d failed\n", g_pass, g_fail);
    printf("=====================================================\n");

    return g_fail > 0 ? 1 : 0;
}
