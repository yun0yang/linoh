// bench_rtt.cpp — 小消息往返延迟（RTT）基准
//
// 测量不同 payload 大小的单条消息往返延迟：
//   1B / 64B / 256B / 1KB / 4KB
// 真实 Winsock UDP 回环 + TLS 1.3 AEAD 数据面。
//
// 架构：client 发送一条消息 → server echo 回来 → client 收到
//   完整 RTT = send + network + server_recv + echo + network + client_recv

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "linoh/base/key.hpp"
#include "linoh/endpoint/connection.hpp"
#include "linoh/endpoint/state_machine.hpp"
#include "linoh/util/bytes.hpp"
#include "bench_framework.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <memory>
#include <sstream>
#include <span>
#include <vector>

using namespace linoh;
using namespace linoh::endpoint;
using namespace linoh::bench;

// ─── Winsock UDP 助手 ─────────────────────────────────────────────────────────

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

static bool udp_send(SOCKET s, uint16_t port,
                     const std::uint8_t *data, std::size_t len) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port = htons(port);
    return ::sendto(s, reinterpret_cast<const char *>(data),
                     static_cast<int>(len), 0,
                     reinterpret_cast<sockaddr *>(&a), sizeof(a))
           == static_cast<int>(len);
}

static int udp_recv(SOCKET s, std::uint8_t *buf, std::size_t cap) {
    sockaddr_in f{};
    int fl = sizeof(f);
    return ::recvfrom(s, reinterpret_cast<char *>(buf),
                      static_cast<int>(cap), 0,
                      reinterpret_cast<sockaddr *>(&f), &fl);
}

static bool send_tagged(SOCKET s, uint16_t port, std::uint8_t tag,
                        const std::uint8_t *data, std::size_t len) {
    std::vector<std::uint8_t> frame;
    frame.reserve(len + 1);
    frame.push_back(tag);
    frame.insert(frame.end(), data, data + len);
    return udp_send(s, port, frame.data(), frame.size());
}

// ─── TLS 1.3 握手 ────────────────────────────────────────────────────────────

static Connection::Config make_tls13_cfg(const base::SecretKey &sk, Direction dir,
                                          const protocol::ConnectionId &local,
                                          const protocol::ConnectionId &remote) {
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = local;
    cfg.remote_cid = remote;
    cfg.direction = dir;
    cfg.alpn = "bench-rtt";
    cfg.handshake.mode = HandshakeMode::Tls13;
    return cfg;
}

static bool do_tls13_handshake(Connection &client, Connection &server,
                                SOCKET cs, uint16_t sport, SOCKET ss, uint16_t cport) {
    std::vector<std::uint8_t> rx(16384);
    client.start_handshake(0.0);
    auto f1 = client.take_handshake_flight();
    send_tagged(cs, sport, 0x00, f1.data(), f1.size());
    int n = udp_recv(ss, rx.data(), rx.size());
    if (n <= 1) return false;
    server.feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));

    auto f2 = server.take_handshake_flight();
    send_tagged(ss, cport, 0x00, f2.data(), f2.size());
    n = udp_recv(cs, rx.data(), rx.size());
    if (n <= 1) return false;
    client.feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));

    auto f3 = client.take_handshake_flight();
    send_tagged(cs, sport, 0x00, f3.data(), f3.size());
    n = udp_recv(ss, rx.data(), rx.size());
    if (n <= 1) return false;
    server.feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));

    return client.state() == ConnState::Established &&
           server.state() == ConnState::Established;
}

// ─── 小消息 RTT 测量 ──────────────────────────────────────────────────────────

/// 测量一次小消息 RTT（us），失败返回 0。
static std::uint64_t bench_rtt_once(std::size_t payload_size) {
    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    auto c_cid = protocol::ConnectionId::generate();
    auto s_cid = protocol::ConnectionId::generate();

    auto client = std::make_shared<Connection>(
        make_tls13_cfg(c_sk, Direction::Outbound, c_cid, s_cid));
    auto server = std::make_shared<Connection>(
        make_tls13_cfg(s_sk, Direction::Inbound, s_cid, c_cid));

    uint16_t cport = 0, sport = 0;
    SOCKET cs = udp_bind_local(cport);
    SOCKET ss = udp_bind_local(sport);
    if (cs == INVALID_SOCKET || ss == INVALID_SOCKET) {
        if (cs != INVALID_SOCKET) ::closesocket(cs);
        if (ss != INVALID_SOCKET) ::closesocket(ss);
        return 0;
    }

    if (!do_tls13_handshake(*client, *server, cs, sport, ss, cport)) {
        ::closesocket(cs);
        ::closesocket(ss);
        return 0;
    }

    // server: echo 回收到的数据
    server->on_stream([&](std::shared_ptr<Stream> st) {
        // P1-P3 fix(2026-07-20): 用 readable_*() 替代 recv_buffer()
        std::size_t n = st->readable_size();
        if (n > 0) {
            server->send_stream(st->id(), std::span<const std::uint8_t>(
                st->readable_data(), n));
            st->consume(n);
        }
    });

    // client: 接收 echo
    std::atomic<bool> got_echo{false};
    client->on_stream([&](std::shared_ptr<Stream> st) {
        got_echo = true;
        (void)st;
    });

    std::vector<std::uint8_t> payload(payload_size, 0xCD);
    std::vector<std::uint8_t> pkt(1280);
    std::vector<std::uint8_t> rx(16384);

    // ── 计时开始 ──
    std::uint64_t t0 = now_us();

    // client → server
    auto st = client->open_stream();
    client->send_stream(st->id(), std::span<const std::uint8_t>(
        payload.data(), payload_size));
    std::size_t pn = client->build_1rtt_packet(std::span<std::uint8_t>(pkt));
    if (pn == 0) {
        ::closesocket(cs);
        ::closesocket(ss);
        return 0;
    }
    send_tagged(cs, sport, 0x01, pkt.data(), pn);

    // server 收到 → 自动 echo 回 client
    int n = udp_recv(ss, rx.data(), rx.size());
    if (n <= 1) {
        ::closesocket(cs);
        ::closesocket(ss);
        return 0;
    }
    {
        std::vector<std::uint8_t> body(rx.begin() + 1, rx.begin() + n);
        server->handle_packet(util::Bytes(std::span<const std::uint8_t>(
            body.data(), body.size())));
    }

    // server 构建 echo 包并发回
    std::size_t pn2 = server->build_1rtt_packet(std::span<std::uint8_t>(pkt));
    if (pn2 > 0) {
        send_tagged(ss, cport, 0x01, pkt.data(), pn2);
    }

    // client 收到 echo
    n = udp_recv(cs, rx.data(), rx.size());
    if (n <= 1) {
        ::closesocket(cs);
        ::closesocket(ss);
        return 0;
    }
    {
        std::vector<std::uint8_t> body(rx.begin() + 1, rx.begin() + n);
        client->handle_packet(util::Bytes(std::span<const std::uint8_t>(
            body.data(), body.size())));
    }

    std::uint64_t elapsed = now_us() - t0;

    ::closesocket(cs);
    ::closesocket(ss);
    return got_echo ? elapsed : 0;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::printf("FATAL: WSAStartup failed\n");
        return 2;
    }

    constexpr int kRuns = 100;  // 每档运行次数（小消息测多次取分布）

    std::printf("=== bench_rtt: 小消息往返延迟（TLS 1.3 AEAD）===\n");
    std::printf("环境: Windows MSVC Release /O2, 127.0.0.1 UDP loopback, %d runs/bench\n\n", kRuns);

    struct SizeItem { const char *name; std::size_t bytes; };
    SizeItem sizes[] = {
        {"rtt_1B",   1},
        {"rtt_64B",  64},
        {"rtt_256B", 256},
        {"rtt_1KB",  1024},
        {"rtt_4KB",  4096},
    };

    std::vector<Result> all_results;

    for (const auto &s : sizes) {
        Bench b(s.name, "us");
        std::printf("\n[%s] %d runs (%zu bytes payload)\n",
                    s.name, kRuns, s.bytes);
        for (int i = 0; i < kRuns; ++i) {
            auto us = bench_rtt_once(s.bytes);
            if (us > 0) b.record_us(us);
        }
        b.report();
        all_results.push_back(b.to_result());
    }

    // JSON 输出
    std::printf("\n--- JSON ---\n");
    {
        std::ostringstream oss;
        Bench::export_json(oss, all_results);
        std::printf("%s\n", oss.str().c_str());
    }

    ::WSACleanup();
    return 0;
}
