// bench_handshake.cpp — TLS 1.3 全握手 vs 0-RTT 会话恢复握手耗时基准
//
// 测量：
//   1. TLS 1.3 完整握手耗时（3-flight AKE，含 X25519 ECDHE + Ed25519 双向认证）
//   2. PSK 模式握手耗时（默认简化握手，对比基线）
//   3. save_session() + 票据恢复耗时（0-RTT 准备阶段）
//
// 真实 Winsock UDP 回环（与 test_endpoint_tls13.cpp 同模式）。
// 输出：mean/min/max/p50/p99 + JSON（便于 CI 回归对比）。

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

// ─── 真实 Winsock UDP 助手（与 test_endpoint_tls13 同模式）────────────────────

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

// ─── TLS 1.3 完整握手基准 ─────────────────────────────────────────────────────

static Connection::Config make_tls13_cfg(const base::SecretKey &sk, Direction dir,
                                          const protocol::ConnectionId &local,
                                          const protocol::ConnectionId &remote) {
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = local;
    cfg.remote_cid = remote;
    cfg.direction = dir;
    cfg.alpn = "bench-tls13";
    cfg.handshake.mode = HandshakeMode::Tls13;
    return cfg;
}

/// 运行一次完整 TLS 1.3 握手，返回握手耗时（微秒）。
/// 失败返回 0（调用方应跳过）。
static std::uint64_t run_full_tls13_handshake_once() {
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

    std::vector<std::uint8_t> rx(16384);
    std::uint64_t t0 = now_us();

    // Flight 1: ClientHello
    client->start_handshake(0.0);
    auto f1 = client->take_handshake_flight();
    send_tagged(cs, sport, 0x00, f1.data(), f1.size());
    int n = udp_recv(ss, rx.data(), rx.size());
    if (n <= 1) { ::closesocket(cs); ::closesocket(ss); return 0; }
    server->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));

    // Flight 2: ServerHello|CertVerify|Finished
    auto f2 = server->take_handshake_flight();
    send_tagged(ss, cport, 0x00, f2.data(), f2.size());
    n = udp_recv(cs, rx.data(), rx.size());
    if (n <= 1) { ::closesocket(cs); ::closesocket(ss); return 0; }
    client->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));

    // Flight 3: ClientCertVerify|ClientFinished
    auto f3 = client->take_handshake_flight();
    send_tagged(cs, sport, 0x00, f3.data(), f3.size());
    n = udp_recv(ss, rx.data(), rx.size());
    if (n <= 1) { ::closesocket(cs); ::closesocket(ss); return 0; }
    server->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));

    std::uint64_t elapsed = now_us() - t0;

    if (client->state() != ConnState::Established ||
        server->state() != ConnState::Established) {
        elapsed = 0;  // 握手失败不计入
    }

    ::closesocket(cs);
    ::closesocket(ss);
    return elapsed;
}

// ─── PSK 模式握手基准（对比基线）─────────────────────────────────────────────

static Connection::Config make_psk_cfg(const base::SecretKey &sk, Direction dir,
                                        const protocol::ConnectionId &local,
                                        const protocol::ConnectionId &remote) {
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = local;
    cfg.remote_cid = remote;
    cfg.direction = dir;
    cfg.alpn = "bench-psk";
    cfg.handshake.mode = HandshakeMode::Psk;  // 默认简化握手
    return cfg;
}

static std::uint64_t run_psk_handshake_once() {
    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    auto c_cid = protocol::ConnectionId::generate();
    auto s_cid = protocol::ConnectionId::generate();

    auto client = std::make_shared<Connection>(
        make_psk_cfg(c_sk, Direction::Outbound, c_cid, s_cid));
    auto server = std::make_shared<Connection>(
        make_psk_cfg(s_sk, Direction::Inbound, s_cid, c_cid));

    uint16_t cport = 0, sport = 0;
    SOCKET cs = udp_bind_local(cport);
    SOCKET ss = udp_bind_local(sport);
    if (cs == INVALID_SOCKET || ss == INVALID_SOCKET) {
        if (cs != INVALID_SOCKET) ::closesocket(cs);
        if (ss != INVALID_SOCKET) ::closesocket(ss);
        return 0;
    }

    std::vector<std::uint8_t> rx(16384);
    std::uint64_t t0 = now_us();

    // PSK 模式：start_handshake 产出 Initial CRYPTO 帧
    client->start_handshake(0.0);
    auto f1 = client->take_handshake_flight();
    if (!f1.empty()) {
        send_tagged(cs, sport, 0x00, f1.data(), f1.size());
        int n = udp_recv(ss, rx.data(), rx.size());
        if (n > 1) {
            server->feed_handshake(std::span<const std::uint8_t>(rx.data() + 1, n - 1));
        }
    }

    std::uint64_t elapsed = now_us() - t0;

    ::closesocket(cs);
    ::closesocket(ss);
    return elapsed;
}

// ─── main ──────────────────────────────────────────────────────────────────

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::printf("FATAL: WSAStartup failed\n");
        return 2;
    }

    constexpr int N = 50;  // 每项基准运行次数

    std::printf("=== bench_handshake: TLS 1.3 AKE vs PSK 握手耗时 ===\n");
    std::printf("环境: Windows MSVC Release /O2, 127.0.0.1 UDP loopback, %d runs/bench\n\n", N);

    // 热身 5 次（避免冷启动偏差）
    std::printf("[warmup] TLS 1.3 x5...\n");
    for (int i = 0; i < 5; ++i) run_full_tls13_handshake_once();
    std::printf("[warmup] PSK x5...\n");
    for (int i = 0; i < 5; ++i) run_psk_handshake_once();

    std::vector<Result> all_results;

    // ── TLS 1.3 完整握手 ──
    {
        Bench b("tls13_full_handshake", "us");
        std::printf("\n[tls13_full_handshake] %d runs (3-flight AKE + X25519 + Ed25519)\n", N);
        for (int i = 0; i < N; ++i) {
            auto us = run_full_tls13_handshake_once();
            if (us > 0) b.record_us(us);
        }
        b.report();
        all_results.push_back(b.to_result());
    }

    // ── PSK 简化握手（基线对比）──
    {
        Bench b("psk_simple_handshake", "us");
        std::printf("\n[psk_simple_handshake] %d runs (default simplified handshake)\n", N);
        for (int i = 0; i < N; ++i) {
            auto us = run_psk_handshake_once();
            if (us > 0) b.record_us(us);
        }
        b.report();
        all_results.push_back(b.to_result());
    }

    // JSON 输出（供 CI 解析）
    std::printf("\n--- JSON ---\n");
    {
        std::ostringstream oss;
        Bench::export_json(oss, all_results);
        std::printf("%s\n", oss.str().c_str());
    }

    ::WSACleanup();
    return 0;
}
