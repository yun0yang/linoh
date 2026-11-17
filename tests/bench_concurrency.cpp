// bench_concurrency.cpp — 并发流 echo 吞吐量基准
//
// 测量不同并发流数下的总吞吐量：
//   1 / 10 / 100 / 1000 并发流，每流发送 1KB 数据 echo
//   真实 Winsock UDP 回环 + TLS 1.3 AEAD 数据面
//
// 评估：单连接多流复用能力 + FlowController 窗口管理效率

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

#include <atomic>
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
    DWORD t = 5000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char *>(&t), sizeof(t));
    int rcvbuf = 4 * 1024 * 1024;
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

// ─── TLS 1.3 握手 ────────────────────────────────────────────────────────────

static Connection::Config make_tls13_cfg(const base::SecretKey &sk, Direction dir,
                                          const protocol::ConnectionId &local,
                                          const protocol::ConnectionId &remote,
                                          std::uint64_t max_bidi_streams) {
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = local;
    cfg.remote_cid = remote;
    cfg.direction = dir;
    cfg.alpn = "bench-conc";
    cfg.handshake.mode = HandshakeMode::Tls13;
    cfg.max_bidi_streams = max_bidi_streams;  // 允许的并发流数上限
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

// ─── 并发流 echo 测量 ──────────────────────────────────────────────────────────

/// 测量 N 条并发流 echo 的总吞吐量。
/// 每条流发送 1KB 数据，server echo 回来，统计总耗时与总字节。
/// 返回耗时（微秒），失败返回 0。
static std::uint64_t bench_concurrency_once(int num_streams) {
    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    auto c_cid = protocol::ConnectionId::generate();
    auto s_cid = protocol::ConnectionId::generate();

    // 允许足够的并发流
    std::uint64_t max_streams = static_cast<std::uint64_t>(num_streams + 10);

    auto client = std::make_shared<Connection>(
        make_tls13_cfg(c_sk, Direction::Outbound, c_cid, s_cid, max_streams));
    auto server = std::make_shared<Connection>(
        make_tls13_cfg(s_sk, Direction::Inbound, s_cid, c_cid, max_streams));

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

    // server: echo 回数据
    server->on_stream([&](std::shared_ptr<Stream> st) {
        // P1-P3 fix(2026-07-20): 用 readable_*() 替代 recv_buffer()
        std::size_t n = st->readable_size();
        if (n > 0) {
            server->send_stream(st->id(), std::span<const std::uint8_t>(
                st->readable_data(), n));
            st->consume(n);
        }
    });

    // client: 统计已接收 echo 流数
    std::atomic<int> received_streams{0};
    client->on_stream([&](std::shared_ptr<Stream> st) {
        // P1-P3 fix(2026-07-20): 用 readable_size() 替代 recv_buffer().size()
        std::size_t n = st->readable_size();
        if (n > 0) {
            received_streams++;
            st->consume(n);
        }
    });

    constexpr std::size_t kPayloadSize = 1024;
    std::vector<std::uint8_t> payload(kPayloadSize, 0xEE);
    std::vector<std::uint8_t> pkt(1280);
    std::vector<std::uint8_t> rx(16384);

    std::uint64_t t0 = now_us();

    // client 打开 N 条流并发送数据（batch 发送）
    for (int i = 0; i < num_streams; ++i) {
        auto st = client->open_stream();
        client->send_stream(st->id(), std::span<const std::uint8_t>(
            payload.data(), kPayloadSize));
    }

    // 把所有待发数据打包成 1-RTT 包发送
    std::size_t pn = client->build_1rtt_packet(std::span<std::uint8_t>(pkt));
    if (pn > 0) {
        send_tagged(cs, sport, 0x01, pkt.data(), pn);
    }

    // 持续收发直到所有 echo 收到或超时
    int max_iters = num_streams * 4 + 100;  // 防止死循环
    for (int it = 0; it < max_iters && received_streams.load() < num_streams; ++it) {
        // server 收 client 包
        int n = udp_recv(ss, rx.data(), rx.size());
        if (n > 1) {
            std::vector<std::uint8_t> body(rx.begin() + 1, rx.begin() + n);
            server->handle_packet(util::Bytes(std::span<const std::uint8_t>(
                body.data(), body.size())));
        }

        // server 发 echo 包
        std::size_t pn2 = server->build_1rtt_packet(std::span<std::uint8_t>(pkt));
        if (pn2 > 0) {
            send_tagged(ss, cport, 0x01, pkt.data(), pn2);
        }

        // client 收 echo
        n = udp_recv(cs, rx.data(), rx.size());
        if (n > 1) {
            std::vector<std::uint8_t> body(rx.begin() + 1, rx.begin() + n);
            client->handle_packet(util::Bytes(std::span<const std::uint8_t>(
                body.data(), body.size())));
        }
    }

    std::uint64_t elapsed = now_us() - t0;

    // 若未全部收到，标记失败
    if (received_streams.load() < num_streams) {
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

    std::printf("=== bench_concurrency: 并发流 echo 吞吐量 ===\n");
    std::printf("环境: Windows MSVC Release /O2, 127.0.0.1 UDP loopback, %d runs/bench\n", kRuns);
    std::printf("每流 1KB payload, 测量总耗时与总吞吐量\n\n");

    struct ConcItem { const char *name; int streams; };
    ConcItem items[] = {
        {"concurrency_1",    1},
        {"concurrency_10",   10},
        {"concurrency_100",  100},
        {"concurrency_1000", 1000},
    };

    std::vector<Result> all_results;

    for (const auto &item : items) {
        ThroughputBench b(item.name, static_cast<std::size_t>(item.streams) * 1024);
        std::printf("\n[%s] %d runs (%d streams x 1KB)\n",
                    item.name, kRuns, item.streams);
        for (int i = 0; i < kRuns; ++i) {
            std::printf("  run %d/%d...", i + 1, kRuns);
            auto us = bench_concurrency_once(item.streams);
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
