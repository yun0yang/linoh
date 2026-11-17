// TLS 1.3 / QUIC key schedule (RFC 8446 §7.1, RFC 9001 §5.1) tests.
// Validates: ECDHE agreement, deterministic derivation, client/server key
// separation, key!=iv, cross-endpoint key agreement, Finished verify_data.
#include "linoh/tls/key_schedule.hpp"
#include "linoh/crypto/x25519.hpp"

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

static bool eq(const std::array<uint8_t, 32> &a, const std::array<uint8_t, 32> &b) {
    return memcmp(a.data(), b.data(), 32) == 0;
}

// ---------------------------------------------------------------------------
// Simulate a full two-party key schedule and verify both sides agree.
// ---------------------------------------------------------------------------
static void test_two_party_agreement() {
    printf("\n=== Key schedule: two-party ECDHE agreement ===\n");

    // 1. Ephemeral X25519 keypairs.
    uint8_t c_sk[32], c_pk[32], s_sk[32], s_pk[32];
    // tc-M1 (v1.7.0.8): keygen 现返回 bool，检查 CSPRNG 是否成功
    CHECK(crypto::x25519::keygen(c_pk, c_sk), "client keygen CSPRNG ok");
    CHECK(crypto::x25519::keygen(s_pk, s_sk), "server keygen CSPRNG ok");

    // 2. Both derive ECDHE shared secret.
    uint8_t ecdhe_c[32], ecdhe_s[32];
    crypto::x25519::scalarmult(ecdhe_c, c_sk, s_pk);
    crypto::x25519::scalarmult(ecdhe_s, s_sk, c_pk);
    CHECK(memcmp(ecdhe_c, ecdhe_s, 32) == 0, "ECDHE shared secret agrees");

    // 3. Both sides feed the SAME transcript (ClientHello|ServerHello bytes).
    tls::Transcript th_c, th_s;
    std::vector<uint8_t> ch = {0x01, 0x00, 0x00, 0x10, 0xaa, 0xbb, 0xcc};
    std::vector<uint8_t> sh = {0x02, 0x00, 0x00, 0x20, 0xde, 0xad, 0xbe, 0xef};
    th_c.add(ch); th_c.add(sh);
    th_s.add(ch); th_s.add(sh);

    tls::KeySchedule ks_c, ks_s;
    ks_c.init_early();
    ks_s.init_early();
    ks_c.set_handshake(std::span<const uint8_t>(ecdhe_c, 32), th_c);
    ks_s.set_handshake(std::span<const uint8_t>(ecdhe_s, 32), th_s);

    CHECK(eq(ks_c.handshake_secret, ks_s.handshake_secret), "handshake secret agrees");
    CHECK(eq(ks_c.client_handshake.key, ks_s.client_handshake.key),
          "client handshake AEAD key agrees across endpoints");
    CHECK(eq(ks_c.server_handshake.key, ks_s.server_handshake.key),
          "server handshake AEAD key agrees across endpoints");
    CHECK(memcmp(ks_c.client_handshake.iv.data(), ks_s.client_handshake.iv.data(), 12) == 0,
          "client handshake IV agrees across endpoints");

    // 4. Application keys after appending more handshake messages (CertVerify|Finished).
    std::vector<uint8_t> fin = {0x14, 0x00, 0x00, 0x20, 0x11, 0x22};
    th_c.add(fin); th_s.add(fin);
    ks_c.set_master(th_c);
    ks_s.set_master(th_s);
    CHECK(eq(ks_c.master_secret, ks_s.master_secret), "master secret agrees");
    CHECK(eq(ks_c.client_application.key, ks_s.client_application.key),
          "client application AEAD key agrees across endpoints");
    CHECK(eq(ks_c.server_application.key, ks_s.server_application.key),
          "server application AEAD key agrees across endpoints");
}

// ---------------------------------------------------------------------------
// Key separation / structural properties.
// ---------------------------------------------------------------------------
static void test_key_separation() {
    printf("\n=== Key schedule: separation & structure ===\n");

    uint8_t ecdhe[32];
    memset(ecdhe, 0x42, sizeof(ecdhe));
    tls::Transcript th;
    std::vector<uint8_t> m = {0x01, 0x02, 0x03, 0x04};
    th.add(m);

    tls::KeySchedule ks;
    ks.init_early();
    ks.set_handshake(std::span<const uint8_t>(ecdhe, 32), th);
    ks.set_master(th);

    // client vs server secrets differ.
    CHECK(!eq(ks.client_handshake.secret, ks.server_handshake.secret),
          "client vs server handshake secrets differ");
    CHECK(!eq(ks.client_application.secret, ks.server_application.secret),
          "client vs server application secrets differ");
    // handshake vs application differ.
    CHECK(!eq(ks.client_handshake.secret, ks.client_application.secret),
          "handshake vs application traffic secrets differ");
    // key != iv content (compare first 12 bytes).
    CHECK(memcmp(ks.client_handshake.key.data(), ks.client_handshake.iv.data(), 12) != 0,
          "AEAD key != iv (different labels)");
    // early/handshake/master all distinct.
    CHECK(!eq(ks.early_secret, ks.handshake_secret), "early vs handshake secret differ");
    CHECK(!eq(ks.handshake_secret, ks.master_secret), "handshake vs master secret differ");
}

// ---------------------------------------------------------------------------
// Determinism: same inputs -> same outputs.
// ---------------------------------------------------------------------------
static void test_determinism() {
    printf("\n=== Key schedule: determinism ===\n");

    uint8_t ecdhe[32];
    memset(ecdhe, 0x7f, sizeof(ecdhe));
    tls::Transcript th;
    std::vector<uint8_t> m = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    th.add(m);

    tls::KeySchedule a, b;
    a.init_early(); b.init_early();
    a.set_handshake(std::span<const uint8_t>(ecdhe, 32), th);
    b.set_handshake(std::span<const uint8_t>(ecdhe, 32), th);
    CHECK(eq(a.client_handshake.key, b.client_handshake.key),
          "deterministic: identical inputs -> identical keys");
}

// ---------------------------------------------------------------------------
// Finished verify_data agreement + tamper detection.
// ---------------------------------------------------------------------------
static void test_finished() {
    printf("\n=== Finished verify_data ===\n");

    uint8_t ecdhe[32];
    memset(ecdhe, 0x11, sizeof(ecdhe));
    tls::Transcript th;
    std::vector<uint8_t> m = {0x01, 0x00, 0x00, 0x04, 0x09, 0x08, 0x07};
    th.add(m);

    tls::KeySchedule ks;
    ks.init_early();
    ks.set_handshake(std::span<const uint8_t>(ecdhe, 32), th);

    auto vd1 = tls::KeySchedule::finished_verify_data(ks.server_handshake.secret, th);
    auto vd2 = tls::KeySchedule::finished_verify_data(ks.server_handshake.secret, th);
    CHECK(eq(vd1, vd2), "Finished verify_data deterministic");

    // Tamper: appending a byte to transcript changes verify_data.
    tls::Transcript th2 = th;
    std::vector<uint8_t> extra = {0xff};
    th2.add(extra);
    auto vd3 = tls::KeySchedule::finished_verify_data(ks.server_handshake.secret, th2);
    CHECK(!eq(vd1, vd3), "Finished verify_data changes when transcript tampered");

    // Wrong base secret -> different verify_data.
    auto vd4 = tls::KeySchedule::finished_verify_data(ks.client_handshake.secret, th);
    CHECK(!eq(vd1, vd4), "Finished verify_data differs with wrong base secret");
}

int main() {
    printf("=== TLS 1.3 / QUIC Key Schedule Tests ===\n");
    test_two_party_agreement();
    test_key_separation();
    test_determinism();
    test_finished();
    printf("\n=== Results: %d PASSED, %d FAILED ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
