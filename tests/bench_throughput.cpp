// bench_throughput.cpp — 单流大批量数据吞吐量基准
//
// 测量：
//   1MB / 10MB / 100MB 三档数据量下的单向传输吞吐量（MB/s）
//   真实 Winsock UDP 回环 + TLS 1.3 AEAD 数据面
//
// 架构：
//   client → build_1rtt_packet (含 STREAM 帧) → UDP → server handle_packet
//   server 持续接收并统计已接收字节数，client 侧计时
//   数据分批发送（每批 1200B payload），避免单包过大

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

// ─── Winsock UDP 助手（与 test_endpoint_tls13 同模式）─────────────────────────

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
    DWORD t = 5000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char *>(&t), sizeof(t));
    // 增大 UDP 接收缓冲区（避免大批量传输丢包）
    int rcvbuf = 4 * 1024 * 1024;  // 4MB
    ::setsockopt(s, SOL_SOCKET, SO_RCVBUF,
                 reinterpret_cast<const char *>(&rcvbuf), sizeof(rcvbuf));
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

// ─── TLS 1.3 握手辅助 ────────────────────────────────────────────────────────

static Connection::Config make_tls13_cfg(const base::SecretKey &sk, Direction dir,
                                          const protocol::ConnectionId &local,
                                          const protocol::ConnectionId &remote) {
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = local;
    cfg.remote_cid = remote;
    cfg.direction = dir;
    cfg.alpn = "bench-tp";
    cfg.handshake.mode = HandshakeMode::Tls13;
    return cfg;
}

/// 完整 TLS 1.3 握手（3-flight）。
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

// ─── 吞吐量测量 ──────────────────────────────────────────────────────────────

/// 测量发送 total_bytes 字节的吞吐量。
/// 返回耗时（微秒），失败返回 0。
static std::uint64_t bench_throughput_once(std::size_t total_bytes) {
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

    // server 统计已接收字节
    std::atomic<std::size_t> received{0};
    server->on_stream([&](std::shared_ptr<Stream> st) {
        // P1-P3 fix(2026-07-20): 用 readable_size() 替代 recv_buffer().size()
        std::size_t n = st->readable_size();
        received += n;
        st->consume(n);
    });

    // 客户端分批发送，每批 1200B payload（QUIC 包大小限制）
    constexpr std::size_t kBatchPayload = 1200;
    std::vector<std::uint8_t> payload(kBatchPayload, 0xAB);
    std::vector<std::uint8_t> pkt(1280);
    std::vector<std::uint8_t> rx(16384);

    std::uint64_t t0 = now_us();
    std::size_t sent = 0;
    while (sent < total_bytes) {
        std::size_t this_batch = std::min(kBatchPayload, total_bytes - sent);
        auto st = client->open_stream();
        client->send_stream(st->id(), std::span<const std::uint8_t>(
            payload.data(), this_batch));
        std::size_t pn = client->build_1rtt_packet(std::span<std::uint8_t>(pkt));
        if (pn == 0) break;
        send_tagged(cs, sport, 0x01, pkt.data(), pn);
        sent += this_batch;

        // 接收 server 的 ACK（简单阻塞接收）
        int n = udp_recv(ss, rx.data(), rx.size());
        if (n > 1) {
            std::vector<std::uint8_t> body(rx.begin() + 1, rx.begin() + n);
            server->handle_packet(util::Bytes(std::span<const std::uint8_t>(
                body.data(), body.size())));
        }
    }
    std::uint64_t elapsed = now_us() - t0;

    // 等待剩余数据接收完成（最多 1s）
    for (int i = 0; i < 100 && received.load() < sent; ++i) {
        int n = udp_recv(ss, rx.data(), rx.size());
        if (n > 1) {
            std::vector<std::uint8_t> body(rx.begin() + 1, rx.begin() + n);
            server->handle_packet(util::Bytes(std::span<const std::uint8_t>(
                body.data(), body.size())));
        }
    }

    if (received.load() < sent) {
        // 丢包导致未完整接收，标记失败
        elapsed = 0;
    }

    ::closesocket(cs);
    ::closesocket(ss);
    return elapsed;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::printf("FATAL: WSAStartup failed\n");
        return 2;
    }

    constexpr int kRuns = 10;  // 每档运行次数

    std::printf("=== bench_throughput: 单流 TLS 1.3 AEAD 吞吐量 ===\n");
    std::printf("环境: Windows MSVC Release /O2, 127.0.0.1 UDP loopback, %d runs/bench\n\n", kRuns);

    struct BenchItem { const char *name; std::size_t bytes; };
    BenchItem items[] = {
        {"throughput_1MB",   1 * 1024 * 1024},
        {"throughput_10MB",  10 * 1024 * 1024},
        {"throughput_100MB", 100 * 1024 * 1024},
    };

    std::vector<Result> all_results;

    for (const auto &item : items) {
        ThroughputBench b(item.name, item.bytes);
        std::printf("\n[%s] %d runs (%zu bytes/run)\n",
                    item.name, kRuns, item.bytes);
        for (int i = 0; i < kRuns; ++i) {
            std::printf("  run %d/%d...", i + 1, kRuns);
            auto us = bench_throughput_once(item.bytes);
            if (us > 0) {
                b.record_us(us);
                std::printf(" ok (%.2f ms)\n", us_to_ms(us));
            } else {
                std::printf(" FAILED\n");
            }
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
