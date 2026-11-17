// linoh handshake message encode/decode + CertVerify signing round-trip.
#include "linoh/tls/handshake_msg.hpp"
#include "linoh/base/key.hpp"
#include "linoh/util/crypto.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; } \
    else { printf("  [FAIL] %s\n", msg); g_fail++; } \
} while (0)

using namespace linoh;

static void fill(std::array<uint8_t, 32> &a, uint8_t v) { a.fill(v); }

static void test_hello_roundtrip() {
    printf("\n=== Hello round-trip ===\n");
    tls::Hello h;
    fill(h.random, 0x11);
    fill(h.ephemeral, 0x22);
    fill(h.node_pub, 0x33);
    h.alpn = "linoh/echo";

    auto enc = tls::encode_hello(tls::HsType::ClientHello, h);
    CHECK(tls::peek_type(enc).has_value() &&
          *tls::peek_type(enc) == tls::HsType::ClientHello, "peek_type = ClientHello");

    auto dec = tls::decode_hello(enc, tls::HsType::ClientHello);
    CHECK(dec.has_value(), "decode_hello succeeds");
    if (dec) {
        auto &d = dec->first;
        CHECK(d.random == h.random, "random matches");
        CHECK(d.ephemeral == h.ephemeral, "ephemeral matches");
        CHECK(d.node_pub == h.node_pub, "node_pub matches");
        CHECK(d.alpn == h.alpn, "alpn matches");
        CHECK(dec->second == enc.size(), "consumed full buffer");
    }

    // ServerHello with empty alpn.
    tls::Hello sh;
    fill(sh.random, 0xaa); fill(sh.ephemeral, 0xbb); fill(sh.node_pub, 0xcc);
    sh.alpn = "";
    auto senc = tls::encode_hello(tls::HsType::ServerHello, sh);
    auto sdec = tls::decode_hello(senc, tls::HsType::ServerHello);
    CHECK(sdec.has_value() && sdec->first.alpn.empty(), "ServerHello empty alpn round-trip");

    // Type mismatch rejected.
    CHECK(!tls::decode_hello(enc, tls::HsType::ServerHello).has_value(),
          "type mismatch rejected");
}

static void test_finished_certverify() {
    printf("\n=== Finished / CertVerify round-trip ===\n");
    tls::Finished f;
    for (int i = 0; i < 32; ++i) f.verify_data[i] = static_cast<uint8_t>(i);
    auto fenc = tls::encode_finished(f);
    auto fdec = tls::decode_finished(fenc);
    CHECK(fdec.has_value() && fdec->first.verify_data == f.verify_data,
          "Finished round-trip");

    tls::CertVerify cv;
    for (int i = 0; i < 64; ++i) cv.signature[i] = static_cast<uint8_t>(255 - i);
    auto cenc = tls::encode_cert_verify(cv);
    auto cdec = tls::decode_cert_verify(cenc);
    CHECK(cdec.has_value() && cdec->first.signature == cv.signature,
          "CertVerify round-trip");
}

static void test_truncation() {
    printf("\n=== Truncation / malformed rejection ===\n");
    tls::Hello h;
    fill(h.random, 1); fill(h.ephemeral, 2); fill(h.node_pub, 3);
    h.alpn = "x";
    auto enc = tls::encode_hello(tls::HsType::ClientHello, h);

    // Truncate body -> decode must fail.
    std::span<const uint8_t> trunc(enc.data(), enc.size() - 1);
    CHECK(!tls::decode_hello(trunc, tls::HsType::ClientHello).has_value(),
          "truncated Hello rejected");

    // Empty input.
    CHECK(!tls::peek_type(std::span<const uint8_t>{}).has_value(), "empty peek nullopt");
    CHECK(!tls::decode_finished(std::span<const uint8_t>{}).has_value(),
          "empty finished nullopt");
}

static void test_certverify_signing() {
    printf("\n=== CertVerify Ed25519 sign/verify over transcript ===\n");
    // Node identity keypair.
    auto sk = base::SecretKey::generate();
    auto pk = sk.public_key();

    // Fake transcript hash.
    std::array<uint8_t, 32> th;
    for (int i = 0; i < 32; ++i) th[i] = static_cast<uint8_t>(i * 7 + 1);

    auto content = tls::cert_verify_signed_content(
        std::span<const uint8_t>(th.data(), th.size()));
    auto sig = sk.sign(std::span<const uint8_t>(content.data(), content.size()));

    tls::CertVerify cv;
    std::memcpy(cv.signature.data(), sig.data(), 64);
    auto enc = tls::encode_cert_verify(cv);
    auto dec = tls::decode_cert_verify(enc);
    CHECK(dec.has_value(), "CertVerify decode");

    // Verify signature with the identity public key.
    auto content2 = tls::cert_verify_signed_content(
        std::span<const uint8_t>(th.data(), th.size()));
    base::Signature s = base::Signature::from_bytes(
        std::span<const uint8_t>(dec->first.signature.data(), 64));
    CHECK(s.verify(std::span<const uint8_t>(content2.data(), content2.size()), pk),
          "signature verifies with correct identity key");

    // Tampered transcript -> verification fails.
    th[0] ^= 0xff;
    auto content3 = tls::cert_verify_signed_content(
        std::span<const uint8_t>(th.data(), th.size()));
    CHECK(!s.verify(std::span<const uint8_t>(content3.data(), content3.size()), pk),
          "signature fails on tampered transcript");

    // Wrong identity key -> verification fails.
    auto sk2 = base::SecretKey::generate();
    auto pk2 = sk2.public_key();
    CHECK(!s.verify(std::span<const uint8_t>(content2.data(), content2.size()), pk2),
          "signature fails with wrong identity key");
}

int main() {
    printf("=== Handshake Message Tests ===\n");
    test_hello_roundtrip();
    test_finished_certverify();
    test_truncation();
    test_certverify_signing();
    printf("\n=== Results: %d PASSED, %d FAILED ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
