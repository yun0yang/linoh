// test_endpoint_tls13.cpp — TLS 1.3 握手 + 1-RTT AEAD 数据面的真实 over-the-wire
// 端到端验证。
//
// 与 test_connection_tls13.cpp（内存 shuttle）的区别：本测试用 **真实 Winsock UDP
// 回环 socket** 在两个 Connection 之间传输字节，验证 TLS 1.3 AKE 与 ChaCha20-Poly1305
// 数据面在真实传输层（而非内存指针）上依旧正确——即 4.5 的「生产可用」验证。
//
// 设计要点：
//   - tls::Handshake 产出的握手字节是 transport-agnostic 的裸 TLS 消息，自包含、可在
//     任意通道重放。因此握手阶段直接把 take_handshake_flight() 的字节经 UDP 发送，
//     接收端 feed_handshake() 驱动 AKE。
//   - 1-RTT 数据面用 build_1rtt_packet() 产出真实 QUIC 短包头包，经 UDP 发送，
//     接收端 handle_packet() 解析 + AEAD 解密 + 投递流。
//   - 同一 UDP socket 上既有握手字节又有 1-RTT 包，用 1 字节标签区分：
//       0x00 + 握手字节  /  0x01 + QUIC 短包头包。
//     （仅测试脚手架，不影响任何生产代码路径。）

#include <winsock2.h>
#include <ws2tcpip.h>

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

// ─── 真实 Winsock UDP 助手 ────────────────────────────────────────────────────

static SOCKET udp_bind_local(uint16_t &port) {
    SOCKET s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port = 0;
    if (::bind(s, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0) {
        ::closesocket(s);
        return INVALID_SOCKET;
    }
    sockaddr_in n{};
    int nl = sizeof(n);
    ::getsockname(s, reinterpret_cast<sockaddr *>(&n), &nl);
    port = ntohs(n.sin_port);
    // 接收超时 2s，避免测试因意外挂死
    DWORD t = 2000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char *>(&t), sizeof(t));
    return s;
}

static bool udp_send(SOCKET s, const char *host, uint16_t port,
                     const std::uint8_t *data, std::size_t len) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr(host);
    a.sin_port = htons(port);
    int r = ::sendto(s, reinterpret_cast<const char *>(data),
                     static_cast<int>(len), 0,
                     reinterpret_cast<sockaddr *>(&a), sizeof(a));
    return r == static_cast<int>(len);
}

// 接收一帧，返回字节数（<=0 表示超时/错误）。
static int udp_recv(SOCKET s, std::uint8_t *buf, std::size_t cap) {
    sockaddr_in f{};
    int fl = sizeof(f);
    int n = ::recvfrom(s, reinterpret_cast<char *>(buf),
                       static_cast<int>(cap), 0,
                       reinterpret_cast<sockaddr *>(&f), &fl);
    return n;
}

// 发送带 1 字节标签的帧：tag(0x00=握手字节 / 0x01=QUIC 包) + payload。
static bool send_tagged(SOCKET s, const char *host, uint16_t port,
                        std::uint8_t tag, const std::uint8_t *data, std::size_t len) {
    std::vector<std::uint8_t> frame;
    frame.reserve(len + 1);
    frame.push_back(tag);
    frame.insert(frame.end(), data, data + len);
    return udp_send(s, host, port, frame.data(), frame.size());
}

// ─── 测试主体 ─────────────────────────────────────────────────────────────────

static Connection::Config make_cfg(const base::SecretKey &sk, Direction dir,
                                   const protocol::ConnectionId &local,
                                   const protocol::ConnectionId &remote) {
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = local;
    cfg.remote_cid = remote;
    cfg.direction = dir;
    cfg.alpn = "linoh-tls13";
    cfg.handshake.mode = HandshakeMode::Tls13;  // 关键：启用 TLS 1.3 AKE
    return cfg;
}

static void test_tls13_over_real_udp() {
    printf("\n=== TLS 1.3 完整握手 + 双向 AEAD 数据面（真实 Winsock UDP）===\n");

    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    auto c_cid = protocol::ConnectionId::generate();
    auto s_cid = protocol::ConnectionId::generate();

    auto client = std::make_shared<Connection>(
        make_cfg(c_sk, Direction::Outbound, c_cid, s_cid));
    auto server = std::make_shared<Connection>(
        make_cfg(s_sk, Direction::Inbound, s_cid, c_cid));

    // 两个真实 UDP socket（均绑定 127.0.0.1 临时端口）
    uint16_t cport = 0, sport = 0;
    SOCKET cs = udp_bind_local(cport);
    SOCKET ss = udp_bind_local(sport);
    CHECK(cs != INVALID_SOCKET && ss != INVALID_SOCKET, "two UDP sockets bound on loopback");
    if (cs == INVALID_SOCKET || ss == INVALID_SOCKET) return;

    const char *host = "127.0.0.1";
    std::vector<std::uint8_t> rx(16384);

    // ── 握手：4 次 socket 往返，交替经真实 UDP 传输裸握手字节 ──
    auto r = client->start_handshake(0.0);               // 创建 Client AKE driver + 产出 CH
    CHECK(r.is_ok(), "client start_handshake ok");
    auto f1 = client->take_handshake_flight();           // ClientHello
    CHECK(!f1.empty(), "client produced ClientHello flight");
    CHECK(send_tagged(cs, host, sport, 0x00, f1.data(), f1.size()), "send ClientHello over UDP");

    int n = udp_recv(ss, rx.data(), rx.size());          // server 收 ClientHello
    CHECK(n > 1, "server received ClientHello datagram");
    if (n > 1) {
        server->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));
    }
    auto f2 = server->take_handshake_flight();           // ServerHello|CertVerify|Finished
    CHECK(!f2.empty(), "server produced ServerHello flight");
    CHECK(send_tagged(ss, host, cport, 0x00, f2.data(), f2.size()), "send ServerHello over UDP");

    n = udp_recv(cs, rx.data(), rx.size());              // client 收 ServerHello
    CHECK(n > 1, "client received ServerHello datagram");
    if (n > 1) {
        client->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));
    }
    auto f3 = client->take_handshake_flight();           // ClientCertVerify|ClientFinished
    CHECK(!f3.empty(), "client produced client-finished flight");
    CHECK(send_tagged(cs, host, sport, 0x00, f3.data(), f3.size()), "send client-finished over UDP");

    n = udp_recv(ss, rx.data(), rx.size());              // server 收 client-finished → finalize
    CHECK(n > 1, "server received client-finished datagram");
    if (n > 1) {
        server->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));
    }

    CHECK(client->state() == ConnState::Established, "client Established after over-wire handshake");
    CHECK(server->state() == ConnState::Established, "server Established after over-wire handshake");
    CHECK(client->tls13_active() && server->tls13_active(), "tls13_active true (app AEAD keys ready)");

    // 双向身份认证：peer_id_ 应为对端公钥
    CHECK(client->peer_id() == s_sk.public_key(), "client peer_id == server pubkey (mutual auth)");
    CHECK(server->peer_id() == c_sk.public_key(), "server peer_id == client pubkey (mutual auth)");

    // ── 客户端 → 服务端 1-RTT AEAD（真实 UDP 短包头包）──
    std::vector<std::uint8_t> captured;
    server->on_stream([&](std::shared_ptr<Stream> st) {
        // P1-P3 fix(2026-07-20): 用 readable_*() 替代 recv_buffer()
        captured.insert(captured.end(), st->readable_data(), st->readable_data() + st->readable_size());
    });

    const std::string msg = "hello over real TLS1.3 UDP socket";
    auto st = client->open_stream();
    client->send_stream(st->id(), std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size()));

    std::vector<std::uint8_t> pkt(1280);
    std::size_t pn = client->build_1rtt_packet(std::span<std::uint8_t>(pkt));
    CHECK(pn > 0, "client built 1-RTT QUIC packet (ciphertext)");
    CHECK(send_tagged(cs, host, sport, 0x01, pkt.data(), pn), "send 1-RTT packet over UDP");

    n = udp_recv(ss, rx.data(), rx.size());
    CHECK(n > 1, "server received 1-RTT packet over UDP");
    if (n > 1) {
        std::vector<std::uint8_t> body(rx.begin() + 1, rx.begin() + n);
        server->handle_packet(util::Bytes(std::span<const std::uint8_t>(body.data(), body.size())));
    }
    CHECK(!captured.empty(), "server received stream data after over-wire AEAD decrypt");
    std::string got(reinterpret_cast<const char *>(captured.data()), captured.size());
    CHECK(got == msg, "decrypted payload matches original (over real socket)");

    // ── 服务端 → 客户端 反向 AEAD（真实 UDP）──
    std::vector<std::uint8_t> captured2;
    client->on_stream([&](std::shared_ptr<Stream> st) {
        // P1-P3 fix(2026-07-20): 用 readable_*() 替代 recv_buffer()
        captured2.insert(captured2.end(), st->readable_data(), st->readable_data() + st->readable_size());
    });
    const std::string reply = "pong-secure-over-udp";
    auto st2 = server->open_stream();
    server->send_stream(st2->id(), std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(reply.data()), reply.size()));
    std::size_t pn2 = server->build_1rtt_packet(std::span<std::uint8_t>(pkt));
    CHECK(pn2 > 0, "server built 1-RTT reply packet");
    CHECK(send_tagged(ss, host, cport, 0x01, pkt.data(), pn2), "send 1-RTT reply over UDP");

    n = udp_recv(cs, rx.data(), rx.size());
    CHECK(n > 1, "client received 1-RTT reply over UDP");
    if (n > 1) {
        std::vector<std::uint8_t> body(rx.begin() + 1, rx.begin() + n);
        client->handle_packet(util::Bytes(std::span<const std::uint8_t>(body.data(), body.size())));
    }
    std::string got2(reinterpret_cast<const char *>(captured2.data()), captured2.size());
    CHECK(got2 == reply, "client decrypted server reply correctly (over real socket)");

    ::closesocket(cs);
    ::closesocket(ss);
}

static void test_tampered_ciphertext_over_udp_rejected() {
    printf("\n=== 真实 UDP 上篡改密文应被 AEAD 拒绝 ===\n");
    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    auto c_cid = protocol::ConnectionId::generate();
    auto s_cid = protocol::ConnectionId::generate();
    auto client = std::make_shared<Connection>(
        make_cfg(c_sk, Direction::Outbound, c_cid, s_cid));
    auto server = std::make_shared<Connection>(
        make_cfg(s_sk, Direction::Inbound, s_cid, c_cid));

    uint16_t cport = 0, sport = 0;
    SOCKET cs = udp_bind_local(cport);
    SOCKET ss = udp_bind_local(sport);
    if (cs == INVALID_SOCKET || ss == INVALID_SOCKET) return;
    const char *host = "127.0.0.1";
    std::vector<std::uint8_t> rx(16384);

    auto rs = client->start_handshake(0.0);
    CHECK(rs.is_ok(), "client start_handshake ok (tamper test)");
    auto f1 = client->take_handshake_flight();
    send_tagged(cs, host, sport, 0x00, f1.data(), f1.size());
    int n = udp_recv(ss, rx.data(), rx.size());
    if (n > 1) server->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));
    auto f2 = server->take_handshake_flight();
    send_tagged(ss, host, cport, 0x00, f2.data(), f2.size());
    n = udp_recv(cs, rx.data(), rx.size());
    if (n > 1) client->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));
    auto f3 = client->take_handshake_flight();
    send_tagged(cs, host, sport, 0x00, f3.data(), f3.size());
    n = udp_recv(ss, rx.data(), rx.size());
    if (n > 1) server->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));
    CHECK(server->state() == ConnState::Established, "server Established before tamper test");

    bool got_data = false;
    server->on_stream([&](std::shared_ptr<Stream>) { got_data = true; });

    auto st = client->open_stream();
    std::string msg = "secret-over-udp";
    client->send_stream(st->id(), std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size()));
    std::vector<std::uint8_t> pkt(1280);
    std::size_t pn = client->build_1rtt_packet(std::span<std::uint8_t>(pkt));
    CHECK(pn > 0, "built 1-RTT packet");

    // 真实 UDP 传输途中翻转一个密文字节（跳过 1 字节标签 + 短包头若干字节）
    std::size_t hdr_len = 1 + s_cid.len() + 3;  // tag + 短包头 + pn(3)
    if (hdr_len < pn) pkt[hdr_len] ^= 0xFF;
    send_tagged(cs, host, sport, 0x01, pkt.data(), pn);

    n = udp_recv(ss, rx.data(), rx.size());
    if (n > 1) {
        std::vector<std::uint8_t> body(rx.begin() + 1, rx.begin() + n);
        server->handle_packet(util::Bytes(std::span<const std::uint8_t>(body.data(), body.size())));
    }
    CHECK(!got_data, "tampered ciphertext over real UDP rejected (no stream delivered)");

    ::closesocket(cs);
    ::closesocket(ss);
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);  // 崩溃时也能看到已打印内容
    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("FATAL: WSAStartup failed\n");
        return 2;
    }
    printf("=== test_endpoint_tls13 (real Winsock UDP) ===\n");
    test_tls13_over_real_udp();
    test_tampered_ciphertext_over_udp_rejected();
    ::WSACleanup();
    printf("\nResults: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail;
}
