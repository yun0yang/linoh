// test_integration_e2e.cpp — 端到端集成 PoC：
//   NodeId → Pkarr 地址发现（真实 UDP DNS）→ TLS 1.3 QUIC 加密连接 → 双向应用数据
//
// 缝合 linoh Phase 4 的三大子系统：
//   1. PkarrDnsServer      —— 本地 UDP DNS 服务端（内存发布表，真实 Winsock）
//   2. PkarrPublisher / DnsAddressLookup —— 用 Ed25519 签名发布、经真实 UDP 查询还原地址
//   3. tls::Handshake + 1-RTT AEAD 数据面 —— X25519 ECDHE + Ed25519 双向认证 + ChaCha20-Poly1305
//
// 采用 test_endpoint_tls13.cpp 证明过的「原生 Winsock 在外层代收代发」模式：
//   Endpoint 的 UdpTransport 当前是 asio 桩（无法自主做真实网络 I/O），因此这里直接驱动
//   两个 Connection 对象，用原生 Winsock 在两者之间真实传输字节，验证在真实传输层上
//   地址发现 + TLS 1.3 加密连接的完整闭环。

// NOMINMAX 必须在 <winsock2.h> 之前定义，避免 Windows 的 min/max 宏
// 与 <algorithm>/std::min 冲突（pkarr_dns.hpp 用到 std::min）。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "linoh/address_lookup/lookup.hpp"
#include "linoh/address_lookup/pkarr_server.hpp"
#include "linoh/base/endpoint_addr.hpp"
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
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (cond) {                                                            \
            printf("  [PASS] %s\n", msg);                                      \
            g_pass++;                                                          \
        } else {                                                               \
            printf("  [FAIL] %s\n", msg);                                      \
            g_fail++;                                                          \
        }                                                                      \
    } while (0)

using namespace linoh;
using namespace linoh::endpoint;
using namespace linoh::base;
using namespace linoh::address_lookup;
using namespace linoh::protocol;

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

static int udp_recv(SOCKET s, std::uint8_t *buf, std::size_t cap) {
    sockaddr_in f{};
    int fl = sizeof(f);
    return ::recvfrom(s, reinterpret_cast<char *>(buf),
                      static_cast<int>(cap), 0,
                      reinterpret_cast<sockaddr *>(&f), &fl);
}

// 1 字节标签区分握手字节(0x00)与 QUIC 短包头包(0x01)（仅测试脚手架）。
static bool send_tagged(SOCKET s, const char *host, uint16_t port,
                        std::uint8_t tag, const std::uint8_t *data,
                        std::size_t len) {
    std::vector<std::uint8_t> frame;
    frame.reserve(len + 1);
    frame.push_back(tag);
    frame.insert(frame.end(), data, data + len);
    return udp_send(s, host, port, frame.data(), frame.size());
}

static Connection::Config make_cfg(const SecretKey &sk, Direction dir,
                                   const ConnectionId &local,
                                   const ConnectionId &remote) {
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = local;
    cfg.remote_cid = remote;
    cfg.direction = dir;
    cfg.alpn = "linoh-e2e";
    cfg.handshake.mode = HandshakeMode::Tls13;  // 启用 TLS 1.3 AKE
    return cfg;
}

// ─── 测试主体 ─────────────────────────────────────────────────────────────────

static void test_e2e_pkarr_discovery_then_tls13() {
    printf("\n=== E2E: NodeId → Pkarr 发现 → TLS 1.3 QUIC 加密连接（真实 Winsock UDP）===\n");

    // 1) 启动 Pkarr DNS 服务端（真实 UDP :5333）
    auto server = std::make_shared<PkarrDnsServer>();
    CHECK(server->start("127.0.0.1", 5333).is_ok(), "Pkarr DNS server started on :5333");
    if (!server->running()) return;

    // 2) 服务端节点：生成密钥、绑定真实 wire socket、把「直连地址」签名发布到 Pkarr
    auto s_sk = SecretKey::generate();
    auto s_id = s_sk.public_key();
    uint16_t sport = 0;
    SOCKET ss = udp_bind_local(sport);
    CHECK(ss != INVALID_SOCKET, "server wire UDP socket bound on loopback");
    if (ss == INVALID_SOCKET) { server->stop(); return; }

    base::EndpointAddr server_addr(s_id);
    base::TransportAddr ta;
    ta.kind = TransportKind::Ip;
    ta.host = "127.0.0.1";
    ta.port = sport;
    server_addr.add_direct_address(ta);

    auto publisher = std::make_shared<PkarrPublisher>(s_sk);
    publisher->bind_server(server);          // publish 时零网络直写内存表
    publisher->publish(server_addr);
    CHECK(server->record_count() == 1, "Pkarr server holds 1 signed record");

    // 3) 客户端节点：经**真实 UDP** 向 DNS 服务端查询服务端 NodeId → 还原地址
    auto c_sk = SecretKey::generate();
    uint16_t cport = 0;
    SOCKET cs = udp_bind_local(cport);
    CHECK(cs != INVALID_SOCKET, "client wire UDP socket bound on loopback");
    if (cs == INVALID_SOCKET) { ::closesocket(ss); server->stop(); return; }

    DnsAddressLookup lookup;
    lookup.set_server("127.0.0.1", 5333);
    auto found = lookup.lookup(s_id);
    CHECK(found.has_value(), "DnsAddressLookup resolved a record for server NodeId (real UDP query)");
    if (found) {
        CHECK(!found->direct_addresses().empty(), "discovered EndpointAddr carries a direct address");
        const auto &d = found->direct_addresses()[0];
        CHECK(d.host == "127.0.0.1" && d.port == sport,
              "discovered direct addr == server wire socket (proves Pkarr over real UDP)");
    }

    // 4) 驱动两条 Connection 经真实 Winsock 完成 TLS 1.3 握手（地址来自发现结果）
    auto c_cid = ConnectionId::generate();
    auto s_cid = ConnectionId::generate();
    auto client = std::make_shared<Connection>(
        make_cfg(c_sk, Direction::Outbound, c_cid, s_cid));
    auto sconn = std::make_shared<Connection>(
        make_cfg(s_sk, Direction::Inbound, s_cid, c_cid));

    const char *host = "127.0.0.1";
    std::vector<std::uint8_t> rx(16384);

    auto r = client->start_handshake(0.0);
    CHECK(r.is_ok(), "client start_handshake ok");
    auto f1 = client->take_handshake_flight();
    CHECK(!f1.empty(), "client produced ClientHello flight");
    CHECK(send_tagged(cs, host, sport, 0x00, f1.data(), f1.size()), "send ClientHello to discovered addr");
    int n = udp_recv(ss, rx.data(), rx.size());
    if (n > 1) sconn->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));
    auto f2 = sconn->take_handshake_flight();
    CHECK(!f2.empty(), "server produced ServerHello flight");
    CHECK(send_tagged(ss, host, cport, 0x00, f2.data(), f2.size()), "send ServerHello to client");
    n = udp_recv(cs, rx.data(), rx.size());
    if (n > 1) client->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));
    auto f3 = client->take_handshake_flight();
    CHECK(!f3.empty(), "client produced client-finished flight");
    CHECK(send_tagged(cs, host, sport, 0x00, f3.data(), f3.size()), "send client-finished to server");
    n = udp_recv(ss, rx.data(), rx.size());
    if (n > 1) sconn->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));

    CHECK(client->state() == ConnState::Established,
          "client Established after over-wire handshake");
    CHECK(sconn->state() == ConnState::Established,
          "server Established after over-wire handshake");
    CHECK(client->tls13_active() && sconn->tls13_active(),
          "tls13_active true (app AEAD keys ready)");
    CHECK(client->peer_id() == s_id,
          "client peer_id == server pubkey (mutual auth)");
    CHECK(sconn->peer_id() == c_sk.public_key(),
          "server peer_id == client pubkey (mutual auth)");

    // 5) 客户端 → 服务端 1-RTT AEAD 数据（真实 UDP 短包头包）
    std::vector<std::uint8_t> captured;
    sconn->on_stream([&](std::shared_ptr<Stream> st) {
        // P1-P3 fix(2026-07-20): 用 readable_*() 替代 recv_buffer()
        captured.insert(captured.end(), st->readable_data(), st->readable_data() + st->readable_size());
    });
    const std::string msg = "hello-from-pkarr-discovered-node";
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
        sconn->handle_packet(util::Bytes(std::span<const std::uint8_t>(body.data(), body.size())));
    }
    CHECK(!captured.empty(), "server received stream data after AEAD decrypt");
    std::string got(captured.begin(), captured.end());
    CHECK(got == msg, "decrypted payload matches original (real socket)");

    // 6) 服务端 → 客户端 反向 AEAD 数据
    std::vector<std::uint8_t> captured2;
    client->on_stream([&](std::shared_ptr<Stream> st) {
        // P1-P3 fix(2026-07-20): 用 readable_*() 替代 recv_buffer()
        captured2.insert(captured2.end(), st->readable_data(), st->readable_data() + st->readable_size());
    });
    const std::string reply = "secure-pong-over-e2e";
    auto st2 = sconn->open_stream();
    sconn->send_stream(st2->id(), std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(reply.data()), reply.size()));
    std::size_t pn2 = sconn->build_1rtt_packet(std::span<std::uint8_t>(pkt));
    CHECK(pn2 > 0, "server built 1-RTT reply packet");
    CHECK(send_tagged(ss, host, cport, 0x01, pkt.data(), pn2), "send 1-RTT reply over UDP");
    n = udp_recv(cs, rx.data(), rx.size());
    CHECK(n > 1, "client received 1-RTT reply over UDP");
    if (n > 1) {
        std::vector<std::uint8_t> body(rx.begin() + 1, rx.begin() + n);
        client->handle_packet(util::Bytes(std::span<const std::uint8_t>(body.data(), body.size())));
    }
    std::string got2(captured2.begin(), captured2.end());
    CHECK(got2 == reply, "client decrypted server reply correctly (real socket)");

    // 7) 篡改密文应被 AEAD 拒绝
    bool got_data = false;
    sconn->on_stream([&](std::shared_ptr<Stream>) { got_data = true; });
    auto st3 = client->open_stream();
    std::string secret = "secret-payload";
    client->send_stream(st3->id(), std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(secret.data()), secret.size()));
    std::size_t pn3 = client->build_1rtt_packet(std::span<std::uint8_t>(pkt));
    CHECK(pn3 > 0, "built 1-RTT packet for tamper test");
    std::size_t hdr_len = 1 + s_cid.len() + 3;  // tag + 短包头 + pn(3)
    if (hdr_len < pn3) pkt[hdr_len] ^= 0xFF;
    CHECK(send_tagged(cs, host, sport, 0x01, pkt.data(), pn3), "send tampered 1-RTT packet");
    n = udp_recv(ss, rx.data(), rx.size());
    if (n > 1) {
        std::vector<std::uint8_t> body(rx.begin() + 1, rx.begin() + n);
        sconn->handle_packet(util::Bytes(std::span<const std::uint8_t>(body.data(), body.size())));
    }
    CHECK(!got_data, "tampered ciphertext over real UDP rejected (no stream delivered)");

    ::closesocket(cs);
    ::closesocket(ss);
    server->stop();
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);  // 崩溃时也能看到已打印内容
    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("FATAL: WSAStartup failed\n");
        return 2;
    }
    printf("=== test_integration_e2e (Pkarr discovery + TLS 1.3 QUIC over real UDP) ===\n");
    test_e2e_pkarr_discovery_then_tls13();
    ::WSACleanup();
    printf("\nResults: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail;
}
