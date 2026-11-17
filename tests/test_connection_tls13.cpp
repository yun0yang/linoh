// 端到端 TLS 1.3 集成测试：Connection 层接入 tls::Handshake（X25519 ECDHE +
// Ed25519 双向认证）+ 1-RTT AEAD 数据面（ChaCha20-Poly1305），并与默认 PSK 路径零回归。
#include "linoh/base/key.hpp"
#include "linoh/endpoint/connection.hpp"
#include "linoh/endpoint/state_machine.hpp"
#include "linoh/util/bytes.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; } \
    else { printf("  [FAIL] %s\n", msg); g_fail++; } \
} while (0)

using namespace linoh;
using namespace linoh::endpoint;

// 在内存中把两个 Connection 的握手指纹相互转发，直到双方都完成。
static void shuttle(std::shared_ptr<Connection> client, std::shared_ptr<Connection> server) {
    // 1) ClientHello
    auto ch = client->take_handshake_flight();
    server->feed_handshake(ch);
    // 2) ServerHello|CertVerify|Finished
    auto sf = server->take_handshake_flight();
    client->feed_handshake(sf);
    // 3) ClientCertVerify|ClientFinished
    auto cf = client->take_handshake_flight();
    server->feed_handshake(cf);
}

static Connection::Config make_cfg(const base::SecretKey &sk, Direction dir,
                                   const protocol::ConnectionId &local,
                                   const protocol::ConnectionId &remote,
                                   bool tls13) {
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = local;
    cfg.remote_cid = remote;
    cfg.direction = dir;
    cfg.alpn = "linoh-tls13";
    if (tls13) cfg.handshake.mode = HandshakeMode::Tls13;
    else cfg.handshake.psk_mode = true;
    return cfg;
}

static void test_full_tls13_handshake_and_data() {
    printf("\n=== TLS 1.3 完整握手 + 1-RTT AEAD 数据面 ===\n");

    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    auto c_cid = protocol::ConnectionId::generate();
    auto s_cid = protocol::ConnectionId::generate();

    auto client = std::make_shared<Connection>(
        make_cfg(c_sk, Direction::Outbound, c_cid, s_cid, true));
    auto server = std::make_shared<Connection>(
        make_cfg(s_sk, Direction::Inbound, s_cid, c_cid, true));

    CHECK(client->state() == ConnState::Initial, "client starts in Initial");
    CHECK(server->state() == ConnState::Initial, "server starts in Initial");
    CHECK(client->tls13_enabled() && client->tls13_active() == false,
          "tls13_enabled true, tls13_active false before handshake");

    // 启动并转发握手指纹
    auto r = client->start_handshake(0.0);
    CHECK(r.is_ok(), "client start_handshake ok");
    CHECK(client->state() == ConnState::Handshake, "client -> Handshake after start");

    shuttle(client, server);

    CHECK(client->state() == ConnState::Established, "client Established after handshake");
    CHECK(server->state() == ConnState::Established, "server Established after handshake");
    CHECK(client->tls13_active() && server->tls13_active(), "tls13_active true after handshake");

    // 双向身份认证：peer_id_ 应为对端公钥
    CHECK(client->peer_id() == s_sk.public_key(), "client peer_id == server pubkey");
    CHECK(server->peer_id() == c_sk.public_key(), "server peer_id == client pubkey");

    // ---- 客户端 -> 服务端 1-RTT AEAD 往返 ----
    std::vector<std::uint8_t> captured;
    server->on_stream([&](std::shared_ptr<Stream> st) {
        // P1-P3 fix(2026-07-20): 用 readable_*() 替代 recv_buffer()
        captured.insert(captured.end(), st->readable_data(), st->readable_data() + st->readable_size());
    });

    const std::string msg = "hello over TLS1.3 AEAD";
    auto st = client->open_stream();
    client->send_stream(st->id(), std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size()));

    std::vector<std::uint8_t> pkt(1280);
    std::size_t n = client->build_1rtt_packet(std::span<std::uint8_t>(pkt));
    CHECK(n > 0, "client built 1-RTT packet (ciphertext)");
    CHECK(n > msg.size(), "ciphertext longer than plaintext (AEAD tag appended)");

    server->handle_packet(util::Bytes(std::span<const std::uint8_t>(pkt.data(), n)));
    CHECK(!captured.empty(), "server received stream data after AEAD decrypt");
    std::string got(reinterpret_cast<const char *>(captured.data()), captured.size());
    CHECK(got == msg, "decrypted payload matches original message");

    // ---- 服务端 -> 客户端 反向 AEAD 往返 ----
    std::vector<std::uint8_t> captured2;
    client->on_stream([&](std::shared_ptr<Stream> st) {
        // P1-P3 fix(2026-07-20): 用 readable_*() 替代 recv_buffer()
        captured2.insert(captured2.end(), st->readable_data(), st->readable_data() + st->readable_size());
    });
    const std::string reply = "pong-secure";
    auto st2 = server->open_stream();
    server->send_stream(st2->id(), std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(reply.data()), reply.size()));
    std::size_t n2 = server->build_1rtt_packet(std::span<std::uint8_t>(pkt));
    CHECK(n2 > 0, "server built 1-RTT reply packet");
    client->handle_packet(util::Bytes(std::span<const std::uint8_t>(pkt.data(), n2)));
    std::string got2(reinterpret_cast<const char *>(captured2.data()), captured2.size());
    CHECK(got2 == reply, "client decrypted server reply correctly");
}

static void test_tampered_ciphertext_rejected() {
    printf("\n=== TLS 1.3 篡改密文应被拒绝 ===\n");
    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    auto c_cid = protocol::ConnectionId::generate();
    auto s_cid = protocol::ConnectionId::generate();
    auto client = std::make_shared<Connection>(
        make_cfg(c_sk, Direction::Outbound, c_cid, s_cid, true));
    auto server = std::make_shared<Connection>(
        make_cfg(s_sk, Direction::Inbound, s_cid, c_cid, true));

    auto r = client->start_handshake(0.0);
    CHECK(r.is_ok(), "start_handshake ok");
    shuttle(client, server);
    CHECK(server->state() == ConnState::Established, "server Established");

    bool got_data = false;
    server->on_stream([&](std::shared_ptr<Stream>) { got_data = true; });

    auto st = client->open_stream();
    std::string msg = "secret-payload";
    client->send_stream(st->id(), std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size()));
    std::vector<std::uint8_t> pkt(1280);
    std::size_t n = client->build_1rtt_packet(std::span<std::uint8_t>(pkt));
    CHECK(n > 0, "built packet");

    // 翻转密文区（跳过短包头 12 字节）的一个字节
    std::size_t hdr_len = 1 + s_cid.len() + 3;  // 短包头 + pn(3)
    pkt[hdr_len] ^= 0xFF;
    server->handle_packet(util::Bytes(std::span<const std::uint8_t>(pkt.data(), n)));
    CHECK(!got_data, "tampered ciphertext rejected (no stream delivered)");
}

static void test_psk_default_unchanged() {
    printf("\n=== PSK 默认路径不回归 ===\n");
    auto sk = base::SecretKey::generate();
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = protocol::ConnectionId::generate();
    cfg.remote_cid = protocol::ConnectionId::generate();
    cfg.direction = Direction::Outbound;
    cfg.alpn = "test";
    // 默认 psk_mode=true, mode=Psk
    auto conn = std::make_shared<Connection>(std::move(cfg));
    CHECK(!conn->tls13_enabled(), "default mode is NOT Tls13 (PSK preserved)");
    auto r = conn->start_handshake(0.0);
    CHECK(r.is_ok() && conn->state() == ConnState::Handshake,
          "PSK start_handshake -> Handshake (unchanged)");
}

int main() {
    printf("=== test_connection_tls13 ===\n");
    test_full_tls13_handshake_and_data();
    test_tampered_ciphertext_rejected();
    test_psk_default_unchanged();
    printf("\nResults: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail;
}
