// End-to-end TLS 1.3-style mutual-auth handshake driver test (in-memory).
#include "linoh/tls/handshake.hpp"
#include "linoh/base/key.hpp"

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

static bool same32(const std::array<uint8_t, 32> &a, const std::array<uint8_t, 32> &b) {
    return memcmp(a.data(), b.data(), 32) == 0;
}

static void test_full_handshake() {
    printf("\n=== Full mutual-auth handshake ===\n");
    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    auto c_id = c_sk.public_key();
    auto s_id = s_sk.public_key();

    tls::Handshake client(tls::Role::Client, c_sk, "linoh/echo");
    tls::Handshake server(tls::Role::Server, s_sk, "linoh/echo");

    // Flight 1: CH
    auto ch = client.start();
    CHECK(!ch.empty(), "client produced ClientHello");

    // Flight 2: SH|SCV|SFin
    auto sflight = server.on_message(std::span<const uint8_t>(ch.data(), ch.size()));
    CHECK(!sflight.empty() && !server.is_failed(), "server produced flight 2");

    // Flight 3: CCV|CFin
    auto cflight = client.on_message(std::span<const uint8_t>(sflight.data(), sflight.size()));
    CHECK(client.is_done() && !client.is_failed(), "client reached Done");
    CHECK(!cflight.empty(), "client produced flight 3");

    // Server consumes flight 3.
    server.on_message(std::span<const uint8_t>(cflight.data(), cflight.size()));
    CHECK(server.is_done() && !server.is_failed(), "server reached Done");

    // Mutual authentication: each learned the other's real node identity.
    CHECK(client.peer_node() == s_id, "client authenticated server node id");
    CHECK(server.peer_node() == c_id, "server authenticated client node id");

    // ALPN negotiated.
    CHECK(client.negotiated_alpn() == "linoh/echo", "client alpn");
    CHECK(server.negotiated_alpn() == "linoh/echo", "server alpn");

    // Application keys agree on both sides.
    CHECK(same32(client.keys().client_application.key, server.keys().client_application.key),
          "client app AEAD key agrees");
    CHECK(same32(client.keys().server_application.key, server.keys().server_application.key),
          "server app AEAD key agrees");
    CHECK(same32(client.keys().master_secret, server.keys().master_secret),
          "master secret agrees");
    // Directions differ.
    CHECK(!same32(client.keys().client_application.key, client.keys().server_application.key),
          "client vs server app keys differ");
}

static void test_tamper_certverify() {
    printf("\n=== Tamper: server CertVerify ===\n");
    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    tls::Handshake client(tls::Role::Client, c_sk, "a");
    tls::Handshake server(tls::Role::Server, s_sk, "a");

    auto ch = client.start();
    auto sflight = server.on_message(std::span<const uint8_t>(ch.data(), ch.size()));

    // Flip a byte inside the ServerCertVerify signature region.
    // Layout: SH (1+varint+ (96 + varint(alpn)+alpn)) then SCV(1+varint+64).
    // Just flip a byte near the end (inside SFin/SCV area) to break auth chain.
    sflight[sflight.size() / 2] ^= 0xff;
    client.on_message(std::span<const uint8_t>(sflight.data(), sflight.size()));
    CHECK(client.is_failed(), "client rejects tampered server flight");
}

static void test_tamper_finished() {
    printf("\n=== Tamper: client Finished ===\n");
    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    tls::Handshake client(tls::Role::Client, c_sk, "a");
    tls::Handshake server(tls::Role::Server, s_sk, "a");

    auto ch = client.start();
    auto sflight = server.on_message(std::span<const uint8_t>(ch.data(), ch.size()));
    auto cflight = client.on_message(std::span<const uint8_t>(sflight.data(), sflight.size()));

    // Flip the very last byte (ClientFinished verify_data).
    cflight[cflight.size() - 1] ^= 0xff;
    server.on_message(std::span<const uint8_t>(cflight.data(), cflight.size()));
    CHECK(server.is_failed(), "server rejects tampered client Finished");
}

static void test_alpn_mismatch() {
    printf("\n=== ALPN mismatch ===\n");
    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    tls::Handshake client(tls::Role::Client, c_sk, "proto-A");
    tls::Handshake server(tls::Role::Server, s_sk, "proto-B");

    auto ch = client.start();
    server.on_message(std::span<const uint8_t>(ch.data(), ch.size()));
    CHECK(server.is_failed(), "server rejects mismatched ALPN");
}

int main() {
    printf("=== TLS 1.3 Handshake Driver Tests ===\n");
    test_full_handshake();
    test_tamper_certverify();
    test_tamper_finished();
    test_alpn_mismatch();
    printf("\n=== Results: %d PASSED, %d FAILED ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
