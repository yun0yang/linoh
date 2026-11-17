// linoh_relay_bridge.cpp — UDP <-> iroh relay v2 bridge for emergency fallback
//
// Purpose:
//   When direct UDP between win-worker and worker-node master is blocked by firewall,
//   this bridge tunnels QUIC/UDP packets through the orchestrator's TCP relay
//   server (iroh relay v2 on port 9002).
//
// Modes:
//   worker : binds a local UDP port; forwards packets to a fixed master bridge
//            peer via relay. The win-worker points its linoh bootstrap to the
//            local UDP port.
//   master : listens on relay; forwards worker packets to local master UDP
//            port (e.g. 127.0.0.1:9001). Each worker gets a dedicated local
//            UDP socket so responses can be routed back to the correct worker.
//
// Build:
//   Windows (MSVC): build_relay_bridge.bat
//   Linux (g++):    build_relay_bridge_linux.sh

#include "linoh/base/key.hpp"
#include "linoh/util/key_file.hpp"   // v4.5.0: 统一密钥持久化
#include "linoh/relay/ws_client.hpp"
#include "linoh/relay/stride.hpp"
#include "linoh/relay/auth.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socket_t = SOCKET;
static constexpr socket_t kInvalidSocket = INVALID_SOCKET;
static inline int socket_close(socket_t s) { return closesocket(s); }
static inline int socket_error() { return WSAGetLastError(); }
static inline bool would_block(int err) { return err == WSAEWOULDBLOCK || err == WSAEINTR; }
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>   // rl-M9: TCP_KEEPIDLE/TCP_KEEPINTVL/TCP_KEEPCNT
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
using socket_t = int;
static constexpr socket_t kInvalidSocket = -1;
static inline int socket_close(socket_t s) { return close(s); }
static inline int socket_error() { return errno; }
static inline bool would_block(int err) { return err == EAGAIN || err == EWOULDBLOCK || err == EINTR; }
#endif

using namespace linoh;
using namespace linoh::relay;
using namespace linoh::base;

// ============================================================================
// Helpers
// ============================================================================

static std::string endpoint_to_hex(const EndpointId &id) {
    char buf[65] = {};
    auto span = id.as_span();
    for (size_t i = 0; i < span.size() && i < 32; ++i) {
        sprintf(buf + i * 2, "%02x", span[i]);
    }
    return std::string(buf);
}

static EndpointId endpoint_from_hex(const std::string &hex) {
    uint8_t bytes[32] = {};
    size_t n = std::min(hex.size(), size_t(64));
    for (size_t i = 0; i + 1 < n; i += 2) {
        char tmp[3] = { hex[i], hex[i + 1], 0 };
        bytes[i / 2] = static_cast<uint8_t>(strtol(tmp, nullptr, 16));
    }
    return EndpointId::from_bytes(std::span<const uint8_t>(bytes, 32));
}

static void set_nonblocking(socket_t s) {
#ifdef _WIN32
    unsigned long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif
}

static std::string format_addr(const sockaddr_in &addr) {
    char host[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr.sin_addr, host, sizeof(host));
    return std::string(host) + ":" + std::to_string(ntohs(addr.sin_port));
}

static bool wait_readable(socket_t s, int timeout_ms) {
#ifdef _WIN32
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return ::select(0, &fds, nullptr, nullptr, &tv) > 0;
#else
    pollfd pfd{s, POLLIN, 0};
    return ::poll(&pfd, 1, timeout_ms) > 0;
#endif
}

// ============================================================================
// Raw TCP relay client (using real OS sockets, not the stub asio Client)
// ============================================================================

class RelayClient {
public:
    RelayClient(base::SecretKey sk, std::string host, uint16_t port)
        : sk_(std::move(sk)), host_(std::move(host)), port_(port),
          id_(sk_.public_key()) {}

    ~RelayClient() { disconnect(); }

    bool connect() {
        if (sk_.is_zero()) {
            fprintf(stderr, "[relay] secret key is zero\n");
            return false;
        }

        sock_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock_ == kInvalidSocket) return false;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
            fprintf(stderr, "[relay] invalid relay host: %s\n", host_.c_str());
            return false;
        }

        fprintf(stderr, "[relay] connecting to %s:%d ...\n", host_.c_str(), port_);
        if (::connect(sock_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
            fprintf(stderr, "[relay] tcp connect failed: %d\n", socket_error());
            return false;
        }

        // rl-M9: 启用 TCP keepalive，防止跨机房长连接被中间设备/relay server 因空闲超时 RST
        //   参数：10s 后开始探测，每 5s 探测一次，3 次失败判定断开
        {
            int keepalive = 1;
            setsockopt(sock_, SOL_SOCKET, SO_KEEPALIVE,
                       reinterpret_cast<const char *>(&keepalive), sizeof(keepalive));
#ifdef _WIN32
            DWORD ka_time = 10000;   // 10s idle 后开始探测
            DWORD ka_interval = 5000; // 5s 探测间隔
            DWORD ka_count = 3;       // 3 次失败
            (void)setsockopt(sock_, IPPROTO_TCP, TCP_KEEPIDLE,
                             reinterpret_cast<const char *>(&ka_time), sizeof(ka_time));
            (void)setsockopt(sock_, IPPROTO_TCP, TCP_KEEPINTVL,
                             reinterpret_cast<const char *>(&ka_interval), sizeof(ka_interval));
            (void)setsockopt(sock_, IPPROTO_TCP, TCP_KEEPCNT,
                             reinterpret_cast<const char *>(&ka_count), sizeof(ka_count));
#else
            int ka_idle = 10;
            int ka_intv = 5;
            int ka_cnt = 3;
            (void)setsockopt(sock_, IPPROTO_TCP, TCP_KEEPIDLE, &ka_idle, sizeof(ka_idle));
            (void)setsockopt(sock_, IPPROTO_TCP, TCP_KEEPINTVL, &ka_intv, sizeof(ka_intv));
            (void)setsockopt(sock_, IPPROTO_TCP, TCP_KEEPCNT, &ka_cnt, sizeof(ka_cnt));
#endif
        }

        if (!ws_handshake()) {
            fprintf(stderr, "[relay] ws handshake failed\n");
            return false;
        }

        if (!auth_handshake()) {
            fprintf(stderr, "[relay] auth handshake failed\n");
            return false;
        }

        connected_ = true;
        set_nonblocking(sock_);
        read_thread_ = std::thread([this] { read_loop(); });
        return true;
    }

    void disconnect() {
        connected_ = false;
        if (sock_ != kInvalidSocket) {
            socket_close(sock_);
            sock_ = kInvalidSocket;
        }
        if (read_thread_.joinable()) read_thread_.join();
    }

    bool send_via(const EndpointId &dst, std::span<const uint8_t> payload) {
        if (!connected_ || payload.empty()) return false;
        Datagram dg;
        dg.dst = dst;
        dg.ecn = EcnCodepoint::None;
        dg.contents.assign(payload.begin(), payload.end());
        auto frame = encode_client_to_relay_datagram(dg);
        auto ws = ws_encode_binary_frame(frame);
        return send_all(ws);
    }

    void set_handler(std::function<void(EndpointId from, std::vector<uint8_t>)> h) {
        std::lock_guard<std::mutex> lk(handler_mu_);
        handler_ = std::move(h);
    }

    bool is_connected() const { return connected_; }
    const EndpointId &id() const { return id_; }

private:
    bool send_all(const std::vector<uint8_t> &data) {
        size_t sent = 0;
        while (sent < data.size()) {
            int n = ::send(sock_, reinterpret_cast<const char *>(data.data() + sent),
                           static_cast<int>(data.size() - sent), 0);
            if (n > 0) {
                sent += static_cast<size_t>(n);
            } else {
                int err = socket_error();
                if (would_block(err)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                fprintf(stderr, "[relay] send failed: %d\n", err);
                connected_ = false;
                return false;
            }
        }
        return true;
    }

    int recv_some(std::vector<uint8_t> &buf, int timeout_ms) {
        if (sock_ == kInvalidSocket) return -1;
        if (!wait_readable(sock_, timeout_ms)) return 0;

        char tmp[4096];
        int n = ::recv(sock_, tmp, sizeof(tmp), 0);
        if (n > 0) {
            buf.insert(buf.end(), tmp, tmp + n);
            return n;
        }
        int err = socket_error();
        if (n == 0 || (err != 0 && !would_block(err))) return -1;
        return 0;
    }

    bool ws_handshake() {
        std::string req = ws_build_handshake_request(host_, "/", std::to_string(port_));
        if (!send_all(std::vector<uint8_t>(req.begin(), req.end()))) return false;

        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (true) {
            auto hend = ws_http_header_end(std::span<const uint8_t>(read_buf_.data(), read_buf_.size()));
            if (hend > 0) {
                bool ok = ws_validate_handshake_response(
                    std::span<const uint8_t>(read_buf_.data(), hend));
                read_buf_.erase(read_buf_.begin(), read_buf_.begin() + static_cast<std::ptrdiff_t>(hend));
                return ok;
            }
            if (std::chrono::steady_clock::now() > deadline) return false;
            if (recv_some(read_buf_, 1000) < 0) return false;
        }
    }

    bool auth_handshake() {
        // rl-M7 (v1.7.0.8): 根因 — 内层 while(next_ws_frame) 无 deadline，
        // next_ws_frame 在连接存活但无数据时会以 1s 间隔无限循环，导致 auth 握手永久阻塞。
        // 修复 — 为整个 auth_handshake 设置 30s deadline，通过指针参数传递给 next_ws_frame，
        // 使其在每次内循环迭代时检查 deadline，超时则返回 false。
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        WsFrame f;
        while (next_ws_frame(f, &deadline)) {
            if (f.opcode == WsOpcode::Binary) {
                auto stride = decode_frame(f.payload);
                if (stride && stride->type == FrameType::ServerChallenge) {
                    auto ch = decode_server_challenge(stride->payload);
                    if (!ch) return false;
                    auto ca = sign_challenge(*ch, sk_);
                    auto auth_frame = encode_client_auth(ca);
                    auto ws = ws_encode_binary_frame(auth_frame);
                    if (!send_all(ws)) return false;

                    while (next_ws_frame(f, &deadline)) {
                        if (f.opcode == WsOpcode::Binary) {
                            auto s2 = decode_frame(f.payload);
                            if (s2 && s2->type == FrameType::ServerConfirmsAuth) return true;
                            if (s2 && s2->type == FrameType::ServerDeniesAuth) return false;
                        } else if (f.opcode == WsOpcode::Close) {
                            return false;
                        }
                    }
                    return false;
                }
            } else if (f.opcode == WsOpcode::Close) {
                return false;
            }
        }
        return false;
    }

    // rl-M7 (v1.7.0.8): 增加 deadline 参数（可选，默认 nullptr 表示无 deadline），
    // 用于 auth_handshake 防止永久阻塞。read_loop 不传 deadline，保持原有行为。
    bool next_ws_frame(WsFrame &out, const std::chrono::steady_clock::time_point *deadline = nullptr) {
        while (true) {
            // rl-M7 (v1.7.0.8): 检查 deadline，超时则返回 false 中断循环
            if (deadline && std::chrono::steady_clock::now() > *deadline) {
                return false;
            }
            auto decoded = ws_decode_frame(std::span<const uint8_t>(read_buf_.data(), read_buf_.size()));
            if (decoded.invalid) {
                // C8: 非法帧，关闭连接
                connected_ = false;
                return false;
            }
            if (decoded.ok) {
                out = std::move(decoded.frame);
                read_buf_.erase(read_buf_.begin(),
                                read_buf_.begin() + static_cast<std::ptrdiff_t>(decoded.bytes_consumed));
                return true;
            }
            // need_more: 继续接收数据
            int n = recv_some(read_buf_, 1000);
            if (n < 0) return false;
            if (n == 0 && !connected_) return false;
        }
    }

    void read_loop() {
        WsFrame f;
        while (connected_ && next_ws_frame(f)) {
            if (f.opcode == WsOpcode::Binary) {
                auto stride = decode_frame(f.payload);
                if (stride && stride->type == FrameType::RelayToClientDatagram) {
                    auto dg = decode_datagram(stride->payload);
                    if (dg) {
                        std::lock_guard<std::mutex> lk(handler_mu_);
                        if (handler_) handler_(dg->dst, std::move(dg->contents));
                    }
                }
            } else if (f.opcode == WsOpcode::Ping) {
                auto pong = ws_encode_pong_frame(f.payload);
                send_all(pong);
            } else if (f.opcode == WsOpcode::Close) {
                break;
            }
        }
        connected_ = false;
    }

    base::SecretKey sk_;
    std::string host_;
    uint16_t port_;
    EndpointId id_;
    socket_t sock_ = kInvalidSocket;
    std::atomic<bool> connected_{false};
    std::vector<uint8_t> read_buf_;
    std::thread read_thread_;

    std::mutex handler_mu_;
    std::function<void(EndpointId, std::vector<uint8_t>)> handler_;
};

// ============================================================================
// UDP socket wrapper
// ============================================================================

class UdpSocket {
public:
    UdpSocket() = default;
    ~UdpSocket() { close(); }

    bool bind(uint16_t port) {
        sock_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_ == kInvalidSocket) return false;

        int reuse = 1;
        setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char *>(&reuse), sizeof(reuse));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (::bind(sock_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
            fprintf(stderr, "[udp] bind failed: %d\n", socket_error());
            close();
            return false;
        }

        sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        ::getsockname(sock_, reinterpret_cast<sockaddr *>(&bound), &len);
        local_port_ = ntohs(bound.sin_port);
        // P10: 增大 UDP 缓冲区到 4MB
        int rcvbuf = 4 * 1024 * 1024;
        setsockopt(sock_, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char *>(&rcvbuf), sizeof(rcvbuf));
        int sndbuf = 4 * 1024 * 1024;
        setsockopt(sock_, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char *>(&sndbuf), sizeof(sndbuf));
        set_nonblocking(sock_);
        return true;
    }

    uint16_t local_port() const { return local_port_; }

    bool send_to(const std::string &host, uint16_t port, std::span<const uint8_t> data) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) return false;

        size_t sent = 0;
        while (sent < data.size()) {
            int n = ::sendto(sock_, reinterpret_cast<const char *>(data.data() + sent),
                             static_cast<int>(data.size() - sent), 0,
                             reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
            if (n > 0) {
                sent += static_cast<size_t>(n);
            } else {
                int err = socket_error();
                if (would_block(err)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                return false;
            }
        }
        return true;
    }

    // Returns number of bytes received, or -1 on error, or 0 if none available.
    int recv_from(std::vector<uint8_t> &out, sockaddr_in &from) {
        out.resize(65536);
        socklen_t from_len = sizeof(from);
        int n = ::recvfrom(sock_, reinterpret_cast<char *>(out.data()),
                           static_cast<int>(out.size()), 0,
                           reinterpret_cast<sockaddr *>(&from), &from_len);
        if (n > 0) {
            out.resize(static_cast<size_t>(n));
            return n;
        }
        int err = socket_error();
        if (would_block(err)) return 0;
        return -1;
    }

    void close() {
        if (sock_ != kInvalidSocket) {
            socket_close(sock_);
            sock_ = kInvalidSocket;
        }
    }

    socket_t raw() const { return sock_; }

private:
    socket_t sock_ = kInvalidSocket;
    uint16_t local_port_ = 0;
};

// ============================================================================
// Worker mode
// ============================================================================

struct UdpPeerAddr {
    std::mutex mu;
    std::string host;
    uint16_t port = 0;
    bool set = false;
};

static void run_worker_mode(RelayClient &relay, uint16_t local_udp_port,
                            const EndpointId &master_bridge_id) {
    UdpSocket udp;
    if (!udp.bind(local_udp_port)) {
        fprintf(stderr, "[worker-bridge] failed to bind local UDP port %d\n", local_udp_port);
        return;
    }
    fprintf(stderr, "[worker-bridge] local UDP bound on port %d, relay peer=%s...\n",
            udp.local_port(), endpoint_to_hex(master_bridge_id).substr(0, 16).c_str());

    UdpPeerAddr peer;
    relay.set_handler([&udp, &peer](EndpointId from, std::vector<uint8_t> data) {
        (void)from;
        std::lock_guard<std::mutex> lk(peer.mu);
        if (peer.set) {
            udp.send_to(peer.host, peer.port, data);
        }
    });

    std::atomic<bool> running{true};
    sockaddr_in from{};
    std::vector<uint8_t> buf;
    while (running && relay.is_connected()) {
        int n = udp.recv_from(buf, from);
        if (n > 0) {
            // Remember the local worker's source address so relay->udp replies
            // can be routed back correctly.
            {
                char host[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &from.sin_addr, host, sizeof(host));
                std::lock_guard<std::mutex> lk(peer.mu);
                peer.host = host;
                peer.port = ntohs(from.sin_port);
                peer.set = true;
            }
            relay.send_via(master_bridge_id, buf);
        } else if (n == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } else if (n < 0) {
            fprintf(stderr, "[worker-bridge] UDP recv error, exiting\n");
            break;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // rl-M5 (v1.7.0.8): 根因 — set_handler 的 lambda 捕获了局部引用 udp/peer，
    // 函数返回后这些引用悬空，若 relay read_thread 仍回调 handler 会导致 UAF。
    // 修复 — 返回前清空 handler 并断开 relay（disconnect 会 join read_thread），
    // 确保 lambda 不再被回调且 read_thread 完全停止后再析构局部变量。
    relay.set_handler(nullptr);
    relay.disconnect();

    running = false;
}

// ============================================================================
// Master mode
// ============================================================================

struct WorkerUdpSlot {
    std::unique_ptr<UdpSocket> sock;
    EndpointId worker_bridge_id;
    std::chrono::steady_clock::time_point last_active;
};

#ifdef _WIN32
// rl-M6 (v1.7.0.8): 根因 — SocketPoller 内部 sockets_ 无锁保护，
// 主线程 poll() 与 cleanup 线程 remove() 并发调用导致数据竞争（vector 迭代器失效/UAF）。
// 修复 — 添加 mutable mutex 保护 sockets_，所有读写操作加锁。
class SocketPoller {
public:
    void add(socket_t s) {
        std::lock_guard<std::mutex> lk(mu_);
        sockets_.push_back(s);
    }
    void remove(socket_t s) {
        std::lock_guard<std::mutex> lk(mu_);
        sockets_.erase(std::remove(sockets_.begin(), sockets_.end(), s), sockets_.end());
    }
    std::vector<socket_t> poll(int timeout_ms) {
        std::lock_guard<std::mutex> lk(mu_);
        fd_set fds;
        FD_ZERO(&fds);
        for (socket_t s : sockets_) FD_SET(s, &fds);
        timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int r = ::select(0, &fds, nullptr, nullptr, &tv);
        std::vector<socket_t> ready;
        if (r > 0) {
            ready.reserve(sockets_.size());
            for (socket_t s : sockets_) {
                if (FD_ISSET(s, &fds)) ready.push_back(s);
            }
        }
        return ready;
    }
private:
    mutable std::mutex mu_;
    std::vector<socket_t> sockets_;
};
#else
// rl-M6 (v1.7.0.8): 同 Windows 版本，添加 mutex 保护 sockets_ 防止并发数据竞争。
class SocketPoller {
public:
    void add(socket_t s) {
        std::lock_guard<std::mutex> lk(mu_);
        sockets_.push_back(s);
    }
    void remove(socket_t s) {
        std::lock_guard<std::mutex> lk(mu_);
        sockets_.erase(std::remove(sockets_.begin(), sockets_.end(), s), sockets_.end());
    }
    std::vector<socket_t> poll(int timeout_ms) {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<pollfd> pollfds;
        pollfds.reserve(sockets_.size());
        for (socket_t s : sockets_) {
            pollfd pfd{};
            pfd.fd = s;
            pfd.events = POLLIN;
            pollfds.push_back(pfd);
        }
        int r = ::poll(pollfds.data(), static_cast<nfds_t>(pollfds.size()), timeout_ms);
        std::vector<socket_t> ready;
        if (r > 0) {
            ready.reserve(pollfds.size());
            for (size_t i = 0; i < pollfds.size(); ++i) {
                if (pollfds[i].revents & POLLIN) ready.push_back(pollfds[i].fd);
            }
        }
        return ready;
    }
private:
    mutable std::mutex mu_;
    std::vector<socket_t> sockets_;
};
#endif

// rl-M9 (v1.7.0.9): 根因 — master bridge 每次重连后 run_master_mode 重新执行，
//   worker slot 绑定随机端口，master linoh 缓存的返回地址失效，返回包全部丢失，
//   导致 win-worker OOS 空洞永久无法填补。
// 修复 — 添加 fixed_slot_port 参数（>0 时 slot 绑定固定端口），重连后端口不变，
//   master linoh 的返回包始终能到达。SO_REUSEADDR 已在 UdpSocket::bind 中设置，
//   旧 slot 析构后端口可立即重用（TIME_WAIT 状态也可绑定）。
static void run_master_mode(RelayClient &relay, const std::string &master_host,
                            uint16_t master_port, uint16_t fixed_slot_port = 0) {
    fprintf(stderr, "[master-bridge] forwarding relay -> %s:%d (slot_port=%s)\n",
            master_host.c_str(), master_port,
            fixed_slot_port > 0 ? std::to_string(fixed_slot_port).c_str() : "auto");

    std::mutex slots_mu;
    std::unordered_map<std::string, std::unique_ptr<WorkerUdpSlot>> slots_by_worker;
    std::unordered_map<uint16_t, WorkerUdpSlot *> slots_by_port;
    std::vector<WorkerUdpSlot *> pending_slots;
    SocketPoller poller;

    auto get_or_create_slot = [&](const EndpointId &worker_id) -> WorkerUdpSlot * {
        std::lock_guard<std::mutex> lk(slots_mu);
        std::string key = endpoint_to_hex(worker_id);
        auto it = slots_by_worker.find(key);
        if (it != slots_by_worker.end()) {
            it->second->last_active = std::chrono::steady_clock::now();
            return it->second.get();
        }
        auto slot = std::make_unique<WorkerUdpSlot>();
        slot->sock = std::make_unique<UdpSocket>();
        // rl-M9: 固定 slot 端口（若配置），确保 master linoh 返回地址跨重连稳定
        if (!slot->sock->bind(fixed_slot_port)) {
            fprintf(stderr, "[master-bridge] failed to allocate worker UDP socket (port=%d)\n",
                    fixed_slot_port);
            return nullptr;
        }
        slot->worker_bridge_id = worker_id;
        slot->last_active = std::chrono::steady_clock::now();
        auto *ptr = slot.get();
        pending_slots.push_back(ptr);
        slots_by_port[slot->sock->local_port()] = ptr;
        slots_by_worker[key] = std::move(slot);
        fprintf(stderr, "[master-bridge] new worker slot %s -> local UDP port %d\n",
                key.substr(0, 16).c_str(), ptr->sock->local_port());
        return ptr;
    };

    relay.set_handler([&](EndpointId from, std::vector<uint8_t> data) {
        auto *slot = get_or_create_slot(from);
        if (!slot) return;
        slot->sock->send_to(master_host, master_port, data);
    });

    std::atomic<bool> running{true};
    std::thread cleanup_thread([&]() {
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lk(slots_mu);
            for (auto it = slots_by_worker.begin(); it != slots_by_worker.end();) {
                if (now - it->second->last_active > std::chrono::minutes(5)) {
                    poller.remove(it->second->sock->raw());
                    slots_by_port.erase(it->second->sock->local_port());
                    it = slots_by_worker.erase(it);
                } else {
                    ++it;
                }
            }
        }
    });

    std::vector<uint8_t> buf;
    sockaddr_in from{};
    while (running && relay.is_connected()) {
        // Synchronize newly created slots into the poller.
        bool has_slots = false;
        {
            std::lock_guard<std::mutex> lk(slots_mu);
            for (auto *slot : pending_slots) {
                poller.add(slot->sock->raw());
            }
            pending_slots.clear();
            has_slots = !slots_by_port.empty();
        }

        if (!has_slots) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        auto ready = poller.poll(100);
        for (socket_t s : ready) {
            WorkerUdpSlot *slot = nullptr;
            {
                std::lock_guard<std::mutex> lk(slots_mu);
                // Find slot by raw socket. This is O(n) but n is small.
                for (auto &kv : slots_by_port) {
                    if (kv.second->sock->raw() == s) {
                        slot = kv.second;
                        break;
                    }
                }
            }
            if (!slot) continue;
            int n = slot->sock->recv_from(buf, from);
            if (n > 0) {
                slot->last_active = std::chrono::steady_clock::now();
                relay.send_via(slot->worker_bridge_id, buf);
            }
        }
    }

    // rl-M5 (v1.7.0.8): 根因 — set_handler 的 lambda 以引用捕获捕获了局部变量
    // （slots_mu/slots_by_worker/slots_by_port/pending_slots/poller/master_host/master_port），
    // 函数返回后引用悬空，若 relay read_thread 仍回调 handler 会导致 UAF。
    // 修复 — 返回前清空 handler 并断开 relay（disconnect 会 join read_thread），
    // 确保 lambda 不再被回调且 read_thread 完全停止后再析构局部变量。
    // 注意：必须在 cleanup_thread.join() 之前执行，因为 cleanup_thread 也引用局部变量。
    relay.set_handler(nullptr);
    relay.disconnect();

    running = false;
    cleanup_thread.join();
}

// ============================================================================
// Direct TCP tunnel mode (bypass iroh relay v2)
// rl-M10: 跨机房 iroh relay v2 传输 linoh UDP 包不稳定（OOS 空洞无法填补），
//   改用直接 TCP 隧道，TCP 保证可靠有序传输，彻底消除 OOS。
//   direct-client (win-worker) → TCP → direct-server (master) → UDP → master linoh
// 帧格式: [4字节大端长度][payload]（每帧 = 一个完整 UDP 包，≤65535 字节）
// ============================================================================

static bool tcp_send_all(socket_t sock, const void *data, size_t len) {
    const char *p = static_cast<const char *>(data);
    size_t sent = 0;
    while (sent < len) {
        int n = ::send(sock, p + sent, static_cast<int>(len - sent), 0);
        if (n > 0) {
            sent += static_cast<size_t>(n);
        } else {
            int err = socket_error();
            if (would_block(err)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            return false;
        }
    }
    return true;
}

static bool tcp_send_frame(socket_t sock, const std::vector<uint8_t> &payload) {
    uint8_t header[4];
    uint32_t len = static_cast<uint32_t>(payload.size());
    header[0] = (uint8_t)(len >> 24);
    header[1] = (uint8_t)(len >> 16);
    header[2] = (uint8_t)(len >> 8);
    header[3] = (uint8_t)(len & 0xFF);
    if (!tcp_send_all(sock, header, 4)) return false;
    if (!payload.empty() && !tcp_send_all(sock, payload.data(), payload.size())) return false;
    return true;
}

static bool tcp_recv_all(socket_t sock, void *buf, size_t len, int timeout_ms = 30000) {
    char *p = static_cast<char *>(buf);
    size_t got = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (got < len) {
        if (!wait_readable(sock, 1000)) {
            if (std::chrono::steady_clock::now() > deadline) return false;
            continue;
        }
        int n = ::recv(sock, p + got, static_cast<int>(len - got), 0);
        if (n > 0) {
            got += static_cast<size_t>(n);
        } else if (n == 0) {
            return false;  // 对端关闭
        } else {
            int err = socket_error();
            if (would_block(err)) continue;
            return false;
        }
    }
    return true;
}

// P10: 应用层 ping/pong 心跳帧（对抗多层 NAT 空闲回收）
//   relay bridge 纯转发模式无应用层心跳，空闲时 NAT conntrack 回收导致连接死亡。
//   ping/pong 用 4 字节 magic 标识，在转发逻辑中过滤不广播，对上层透明。
static const uint8_t kPingMagic[4] = {0xFE, 0xFE, 0xFE, 0xFE};
static const uint8_t kPongMagic[4] = {0xFF, 0xFF, 0xFF, 0xFF};

static bool is_ping_frame(const std::vector<uint8_t> &f) {
    return f.size() == 4 && memcmp(f.data(), kPingMagic, 4) == 0;
}
static bool is_pong_frame(const std::vector<uint8_t> &f) {
    return f.size() == 4 && memcmp(f.data(), kPongMagic, 4) == 0;
}
static bool send_ping_frame(socket_t sock) {
    std::vector<uint8_t> ping(kPingMagic, kPingMagic + 4);
    return tcp_send_frame(sock, ping);
}
static bool send_pong_frame(socket_t sock) {
    std::vector<uint8_t> pong(kPongMagic, kPongMagic + 4);
    return tcp_send_frame(sock, pong);
}

static bool tcp_recv_frame(socket_t sock, std::vector<uint8_t> &out, int timeout_ms = 30000) {
    uint8_t header[4];
    if (!tcp_recv_all(sock, header, 4, timeout_ms)) return false;
    uint32_t len = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
                   ((uint32_t)header[2] << 8) | (uint32_t)header[3];
    if (len > 65535) return false;  // UDP 包最大 65535
    out.resize(len);
    if (len > 0 && !tcp_recv_all(sock, out.data(), len, timeout_ms)) return false;
    return true;
}

static void enable_tcp_keepalive(socket_t sock) {
    int keepalive = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
               reinterpret_cast<const char *>(&keepalive), sizeof(keepalive));
#ifdef _WIN32
    DWORD ka_time = 30000;  // P10: 适配多层 NAT
    DWORD ka_interval = 10000;
    DWORD ka_count = 6;
    (void)setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE,
                     reinterpret_cast<const char *>(&ka_time), sizeof(ka_time));
    (void)setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL,
                     reinterpret_cast<const char *>(&ka_interval), sizeof(ka_interval));
    (void)setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT,
                     reinterpret_cast<const char *>(&ka_count), sizeof(ka_count));
#else
    int ka_idle = 30;  // P10: 适配多层 NAT (原10s 短于 conntrack 回收)
    int ka_intv = 10;
    int ka_cnt = 6;
    (void)setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &ka_idle, sizeof(ka_idle));
    (void)setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &ka_intv, sizeof(ka_intv));
    (void)setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &ka_cnt, sizeof(ka_cnt));
#endif
}

// direct-server: master 端 (worker-node)
// 监听 TCP 端口，接受 client 连接，为每个 client 创建 UDP slot（固定端口），
// 双向转发: TCP ↔ 本地 UDP (master linoh 127.0.0.1:9001)
static void run_direct_server_mode(uint16_t listen_port,
                                   const std::string &master_host,
                                   uint16_t master_port,
                                   uint16_t fixed_slot_port) {
    fprintf(stderr, "[direct-server] listening on TCP %d, forward to %s:%d (slot_port=%d)\n",
            listen_port, master_host.c_str(), master_port, fixed_slot_port);

    socket_t listen_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == kInvalidSocket) {
        fprintf(stderr, "[direct-server] create listen socket failed\n");
        return;
    }
    int reuse = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char *>(&reuse), sizeof(reuse));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listen_port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (::bind(listen_sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        fprintf(stderr, "[direct-server] bind failed: %d\n", socket_error());
        socket_close(listen_sock);
        return;
    }
    if (::listen(listen_sock, 5) != 0) {
        fprintf(stderr, "[direct-server] listen failed: %d\n", socket_error());
        socket_close(listen_sock);
        return;
    }

    while (true) {
        fprintf(stderr, "[direct-server] waiting for client...\n");
        sockaddr_in cli_addr{};
        socklen_t cli_len = sizeof(cli_addr);
        socket_t cli_sock = ::accept(listen_sock, reinterpret_cast<sockaddr *>(&cli_addr), &cli_len);
        if (cli_sock == kInvalidSocket) {
            fprintf(stderr, "[direct-server] accept failed: %d\n", socket_error());
            continue;
        }
        char cli_host[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &cli_addr.sin_addr, cli_host, sizeof(cli_host));
        fprintf(stderr, "[direct-server] client connected: %s:%d\n",
                cli_host, ntohs(cli_addr.sin_port));

        enable_tcp_keepalive(cli_sock);

        UdpSocket udp;
        if (!udp.bind(fixed_slot_port)) {
            fprintf(stderr, "[direct-server] bind UDP slot %d failed\n", fixed_slot_port);
            socket_close(cli_sock);
            continue;
        }
        fprintf(stderr, "[direct-server] UDP slot bound: port=%d\n", udp.local_port());

        std::atomic<bool> running{true};
        std::thread tcp2udp([&]() {
            std::vector<uint8_t> frame;
            while (running) {
                if (!tcp_recv_frame(cli_sock, frame, 30000)) {
                    fprintf(stderr, "[direct-server] tcp_recv_frame failed\n");
                    running = false;
                    return;
                }
                udp.send_to(master_host, master_port, frame);
            }
        });

        sockaddr_in from{};
        std::vector<uint8_t> buf;
        while (running) {
            int n = udp.recv_from(buf, from);
            if (n > 0) {
                if (!tcp_send_frame(cli_sock, buf)) {
                    fprintf(stderr, "[direct-server] tcp_send_frame failed\n");
                    running = false;
                    break;
                }
            } else {
                // n == 0 (no data) or n < 0 (ECONNREFUSED/EINTR, transient - do not reconnect)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }

        if (tcp2udp.joinable()) tcp2udp.join();
        socket_close(cli_sock);
        fprintf(stderr, "[direct-server] client disconnected\n");
    }
}

// direct-master: master 端通过 orchestrator 中转
// rl-M10: master 主动连接 orchestrator direct-relay (TCP client)，同时绑定本地 UDP 端口，
//   双向转发: TCP ↔ 本地 UDP → master linoh (127.0.0.1:9001)
//   与 direct-client 的区别：
//     direct-client 绑定 UDP 让 linoh 连接进来（linoh → UDP → TCP）
//     direct-master 绑定 UDP 后主动发送给 master linoh（TCP → UDP → linoh，linoh 响应 → UDP → TCP）
//   数据流: win-worker → direct-client → TCP → orchestrator direct-relay → TCP → direct-master → UDP → master linoh
static void run_direct_master_mode(const std::string &connect_host,
                                    uint16_t connect_port,
                                    const std::string &master_host,
                                    uint16_t master_port,
                                    uint16_t local_udp_port) {
    UdpSocket udp;
    if (!udp.bind(local_udp_port)) {
        fprintf(stderr, "[direct-master] bind local UDP %d failed\n", local_udp_port);
        return;
    }
    fprintf(stderr, "[direct-master] local UDP bound: port=%d, forward to %s:%d\n",
            udp.local_port(), master_host.c_str(), master_port);

    const int kDelayMs = 2000;
    const int kMaxBackoff = 15000;
    int failures = 0;

    while (true) {
        auto t0 = std::chrono::steady_clock::now();
        socket_t sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == kInvalidSocket) {
            std::this_thread::sleep_for(std::chrono::milliseconds(kDelayMs));
            continue;
        }
        sockaddr_in srv{};
        srv.sin_family = AF_INET;
        srv.sin_port = htons(connect_port);
        if (inet_pton(AF_INET, connect_host.c_str(), &srv.sin_addr) <= 0) {
            fprintf(stderr, "[direct-master] invalid host: %s\n", connect_host.c_str());
            socket_close(sock);
            std::this_thread::sleep_for(std::chrono::milliseconds(kDelayMs));
            continue;
        }
        fprintf(stderr, "[direct-master] connecting to %s:%d...\n", connect_host.c_str(), connect_port);
        if (::connect(sock, reinterpret_cast<sockaddr *>(&srv), sizeof(srv)) != 0) {
            fprintf(stderr, "[direct-master] connect failed: %d\n", socket_error());
            socket_close(sock);
            failures++;
            int delay = kDelayMs * (1 << std::min(failures - 1, 3));
            if (delay > kMaxBackoff) delay = kMaxBackoff;
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            continue;
        }
        enable_tcp_keepalive(sock);
        fprintf(stderr, "[direct-master] connected to %s:%d\n", connect_host.c_str(), connect_port);

        std::atomic<bool> running{true};
        // TCP → UDP: 将 relay 收到的数据转发给 master linoh (127.0.0.1:9001)
        std::thread tcp2udp([&]() {
            std::vector<uint8_t> frame;
            // P10: 应用层 ping/pong 心跳
            auto last_recv = std::chrono::steady_clock::now();
            auto last_ping = std::chrono::steady_clock::now();
            constexpr int kRecvTimeoutMs = 15000;
            constexpr int kPingIntervalMs = 10000;
            constexpr int kDeadAfterMs = 60000;
            while (running) {
                if (!tcp_recv_frame(sock, frame, kRecvTimeoutMs)) {
                    auto now = std::chrono::steady_clock::now();
                    auto since_recv = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_recv).count();
                    if (since_recv > kDeadAfterMs) {
                        fprintf(stderr, "[direct-master] no data for %lldms, reconnect\n", (long long)since_recv);
                        running = false;
                        return;
                    }
                    auto since_ping = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_ping).count();
                    if (since_ping > kPingIntervalMs) {
                        if (!send_ping_frame(sock)) {
                            fprintf(stderr, "[direct-master] send_ping failed, reconnect\n");
                            running = false;
                            return;
                        }
                        last_ping = now;
                    }
                    continue;
                }
                last_recv = std::chrono::steady_clock::now();
                // P10: ping/pong 心跳帧不转发 UDP
                if (is_ping_frame(frame)) { send_pong_frame(sock); continue; }
                if (is_pong_frame(frame)) { continue; }
                udp.send_to(master_host, master_port, frame);
            }
        });

        // UDP → TCP: master linoh 的响应回传给 relay
        sockaddr_in from{};
        std::vector<uint8_t> buf;
        while (running) {
            int n = udp.recv_from(buf, from);
            if (n > 0) {
                if (!tcp_send_frame(sock, buf)) {
                    fprintf(stderr, "[direct-master] tcp_send_frame failed\n");
                    running = false;
                    break;
                }
            } else {
                // n == 0 (no data) or n < 0 (ECONNREFUSED/EINTR, transient - do not reconnect)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }

        if (tcp2udp.joinable()) tcp2udp.join();
        socket_close(sock);

        auto sec = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::steady_clock::now() - t0)
                       .count();
        if (sec > 15) {
            failures = 0;
            fprintf(stderr, "[direct-master] disconnected after %llds (stable)\n", (long long)sec);
        } else {
            failures++;
            int delay = kDelayMs * (1 << std::min(failures - 1, 3));
            if (delay > kMaxBackoff) delay = kMaxBackoff;
            fprintf(stderr, "[direct-master] disconnected after %llds (%d failures)\n",
                    (long long)sec, failures);
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kDelayMs));
    }
}

// direct-client: win-worker 端
// 连接 direct-server TCP，绑定本地 UDP，双向转发: 本地 UDP ↔ TCP
static void run_direct_client_mode(const std::string &connect_host,
                                   uint16_t connect_port,
                                   uint16_t local_udp_port) {
    UdpSocket udp;
    if (!udp.bind(local_udp_port)) {
        fprintf(stderr, "[direct-client] bind local UDP %d failed\n", local_udp_port);
        return;
    }
    fprintf(stderr, "[direct-client] local UDP bound: port=%d\n", udp.local_port());

    const int kDelayMs = 2000;
    const int kMaxBackoff = 15000;
    int failures = 0;

    while (true) {
        auto t0 = std::chrono::steady_clock::now();
        socket_t sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == kInvalidSocket) {
            std::this_thread::sleep_for(std::chrono::milliseconds(kDelayMs));
            continue;
        }
        sockaddr_in srv{};
        srv.sin_family = AF_INET;
        srv.sin_port = htons(connect_port);
        if (inet_pton(AF_INET, connect_host.c_str(), &srv.sin_addr) <= 0) {
            fprintf(stderr, "[direct-client] invalid host: %s\n", connect_host.c_str());
            socket_close(sock);
            std::this_thread::sleep_for(std::chrono::milliseconds(kDelayMs));
            continue;
        }
        fprintf(stderr, "[direct-client] connecting to %s:%d...\n", connect_host.c_str(), connect_port);
        if (::connect(sock, reinterpret_cast<sockaddr *>(&srv), sizeof(srv)) != 0) {
            fprintf(stderr, "[direct-client] connect failed: %d\n", socket_error());
            socket_close(sock);
            failures++;
            int delay = kDelayMs * (1 << std::min(failures - 1, 3));
            if (delay > kMaxBackoff) delay = kMaxBackoff;
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            continue;
        }
        enable_tcp_keepalive(sock);
        fprintf(stderr, "[direct-client] connected to %s:%d\n", connect_host.c_str(), connect_port);

        UdpPeerAddr peer;
        std::atomic<bool> running{true};
        std::thread tcp2udp([&]() {
            std::vector<uint8_t> frame;
            // P10: 应用层 ping/pong 心跳
            auto last_recv = std::chrono::steady_clock::now();
            auto last_ping = std::chrono::steady_clock::now();
            constexpr int kRecvTimeoutMs = 15000;
            constexpr int kPingIntervalMs = 10000;
            constexpr int kDeadAfterMs = 60000;
            while (running) {
                if (!tcp_recv_frame(sock, frame, kRecvTimeoutMs)) {
                    auto now = std::chrono::steady_clock::now();
                    auto since_recv = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_recv).count();
                    if (since_recv > kDeadAfterMs) {
                        fprintf(stderr, "[direct-client] no data for %lldms, reconnect\n", (long long)since_recv);
                        running = false;
                        return;
                    }
                    auto since_ping = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_ping).count();
                    if (since_ping > kPingIntervalMs) {
                        if (!send_ping_frame(sock)) {
                            fprintf(stderr, "[direct-client] send_ping failed, reconnect\n");
                            running = false;
                            return;
                        }
                        last_ping = now;
                    }
                    continue;
                }
                last_recv = std::chrono::steady_clock::now();
                // P10: ping/pong 心跳帧不转发 UDP
                if (is_ping_frame(frame)) { send_pong_frame(sock); continue; }
                if (is_pong_frame(frame)) { continue; }
                std::lock_guard<std::mutex> lk(peer.mu);
                if (peer.set) {
                    udp.send_to(peer.host, peer.port, frame);
                }
            }
        });

        sockaddr_in from{};
        std::vector<uint8_t> buf;
        while (running) {
            int n = udp.recv_from(buf, from);
            if (n > 0) {
                {
                    char host[INET_ADDRSTRLEN] = {};
                    inet_ntop(AF_INET, &from.sin_addr, host, sizeof(host));
                    std::lock_guard<std::mutex> lk(peer.mu);
                    peer.host = host;
                    peer.port = ntohs(from.sin_port);
                    peer.set = true;
                }
                if (!tcp_send_frame(sock, buf)) {
                    fprintf(stderr, "[direct-client] tcp_send_frame failed\n");
                    running = false;
                    break;
                }
            } else {
                // n == 0 (no data) or n < 0 (ECONNREFUSED/EINTR, transient - do not reconnect)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }

        if (tcp2udp.joinable()) tcp2udp.join();
        socket_close(sock);

        auto sec = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::steady_clock::now() - t0)
                       .count();
        if (sec > 15) {
            failures = 0;
            fprintf(stderr, "[direct-client] disconnected after %llds (stable)\n", (long long)sec);
        } else {
            failures++;
            int delay = kDelayMs * (1 << std::min(failures - 1, 3));
            if (delay > kMaxBackoff) delay = kMaxBackoff;
            fprintf(stderr, "[direct-client] disconnected after %llds (%d failures)\n",
                    (long long)sec, failures);
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kDelayMs));
    }
}

// direct-relay: orchestrator 端 TCP 中转
// rl-M10: win-worker 无法直连 master（机房防火墙阻挡 TCP），orchestrator 作为
//   TCP 中转站。master 和 win-worker 都主动连接 orchestrator 的 direct-relay，
//   direct-relay 在两个 client 之间桥接数据（广播模式）。
//   数据流: win-worker → direct-client → TCP → direct-relay → TCP → direct-client → master linoh
static void run_direct_relay_mode(uint16_t listen_port) {
    fprintf(stderr, "[direct-relay] listening on TCP %d\n", listen_port);

    socket_t listen_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == kInvalidSocket) {
        fprintf(stderr, "[direct-relay] create listen socket failed\n");
        return;
    }
    int reuse = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char *>(&reuse), sizeof(reuse));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listen_port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (::bind(listen_sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        fprintf(stderr, "[direct-relay] bind failed: %d\n", socket_error());
        socket_close(listen_sock);
        return;
    }
    if (::listen(listen_sock, 16) != 0) {
        fprintf(stderr, "[direct-relay] listen failed: %d\n", socket_error());
        socket_close(listen_sock);
        return;
    }

    std::mutex clients_mu;
    std::vector<socket_t> clients;

    while (true) {
        sockaddr_in cli_addr{};
        socklen_t cli_len = sizeof(cli_addr);
        socket_t cli_sock = ::accept(listen_sock, reinterpret_cast<sockaddr *>(&cli_addr), &cli_len);
        if (cli_sock == kInvalidSocket) {
            fprintf(stderr, "[direct-relay] accept failed: %d\n", socket_error());
            continue;
        }
        char cli_host[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &cli_addr.sin_addr, cli_host, sizeof(cli_host));

        size_t cur_count;
        {
            std::lock_guard<std::mutex> lk(clients_mu);
            clients.push_back(cli_sock);
            cur_count = clients.size();
        }
        fprintf(stderr, "[direct-relay] client connected: %s:%d (total=%zu)\n",
                cli_host, ntohs(cli_addr.sin_port), cur_count);

        enable_tcp_keepalive(cli_sock);

        std::thread([&, cli_sock]() {
            std::vector<uint8_t> frame;
            // P10: 应用层 ping/pong 心跳，对抗多层 NAT 空闲回收
            auto last_recv = std::chrono::steady_clock::now();
            auto last_ping = std::chrono::steady_clock::now();
            constexpr int kRecvTimeoutMs = 15000;     // 15s recv 超时
            constexpr int kPingIntervalMs = 10000;    // 10s 发一次 ping
            constexpr int kDeadAfterMs = 60000;       // 60s 无数据判定死亡
            while (true) {
                if (!tcp_recv_frame(cli_sock, frame, kRecvTimeoutMs)) {
                    // 超时或错误：检查是否已超死亡阈值
                    auto now = std::chrono::steady_clock::now();
                    auto since_recv = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_recv).count();
                    if (since_recv > kDeadAfterMs) {
                        fprintf(stderr, "[direct-relay] client no data for %lldms, disconnecting\n", (long long)since_recv);
                        break;
                    }
                    // 超时未死：发 ping 保活（ping 失败也 break）
                    auto since_ping = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_ping).count();
                    if (since_ping > kPingIntervalMs) {
                        if (!send_ping_frame(cli_sock)) {
                            fprintf(stderr, "[direct-relay] send_ping failed, disconnecting\n");
                            break;
                        }
                        last_ping = now;
                    }
                    continue;
                }
                last_recv = std::chrono::steady_clock::now();
                // P10: ping/pong 心跳帧不广播
                if (is_ping_frame(frame)) { send_pong_frame(cli_sock); continue; }
                if (is_pong_frame(frame)) { continue; }
                // 正常数据帧广播给其他 client
                std::lock_guard<std::mutex> lk(clients_mu);
                for (socket_t other : clients) {
                    if (other != cli_sock) {
                        if (!tcp_send_frame(other, frame)) {
                            fprintf(stderr, "[direct-relay] send to peer failed\n");
                        }
                    }
                }
            }
            {
                std::lock_guard<std::mutex> lk(clients_mu);
                clients.erase(std::remove(clients.begin(), clients.end(), cli_sock), clients.end());
            }
            socket_close(cli_sock);
            size_t remain;
            {
                std::lock_guard<std::mutex> lk(clients_mu);
                remain = clients.size();
            }
            fprintf(stderr, "[direct-relay] client disconnected (total=%zu)\n", remain);
        }).detach();
    }
}

// ============================================================================
// main
// ============================================================================

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s --mode worker --relay-host HOST --relay-port PORT --peer-id HEX "
            "--local-udp-port PORT [--key-file PATH]\n"
            "  %s --mode master --relay-host HOST --relay-port PORT "
            "--master-udp HOST:PORT [--key-file PATH] [--slot-port PORT]\n"
            "  %s --mode direct-server --direct-listen-port PORT "
            "--master-udp HOST:PORT [--slot-port PORT]\n"
            "  %s --mode direct-client --direct-connect-host HOST --direct-connect-port PORT "
            "--local-udp-port PORT\n"
            "  %s --mode direct-master --direct-connect-host HOST --direct-connect-port PORT "
            "--master-udp HOST:PORT --local-udp-port PORT\n"
            "  %s --mode direct-relay --direct-listen-port PORT\n",
            prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
#ifdef _WIN32
    WSADATA wd;
    WSAStartup(MAKEWORD(2, 2), &wd);
#endif

    std::string mode;
    std::string relay_host;
    uint16_t relay_port = 0;
    std::string peer_id_hex;
    uint16_t local_udp_port = 0;
    std::string master_udp;
    std::string key_file = "linoh_relay_bridge.key";
    uint16_t slot_port = 0;  // rl-M9: master 模式 worker slot 固定端口
    // rl-M10: direct-tunnel 模式参数
    uint16_t direct_listen_port = 0;   // direct-server 监听端口
    std::string direct_connect_host;   // direct-client 连接目标 host
    uint16_t direct_connect_port = 0;  // direct-client 连接目标端口

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--mode" && i + 1 < argc) mode = argv[++i];
        else if (arg == "--relay-host" && i + 1 < argc) relay_host = argv[++i];
        else if (arg == "--relay-port" && i + 1 < argc) relay_port = static_cast<uint16_t>(atoi(argv[++i]));
        else if (arg == "--peer-id" && i + 1 < argc) peer_id_hex = argv[++i];
        else if (arg == "--local-udp-port" && i + 1 < argc) local_udp_port = static_cast<uint16_t>(atoi(argv[++i]));
        else if (arg == "--master-udp" && i + 1 < argc) master_udp = argv[++i];
        else if (arg == "--key-file" && i + 1 < argc) key_file = argv[++i];
        else if (arg == "--slot-port" && i + 1 < argc) slot_port = static_cast<uint16_t>(atoi(argv[++i]));
        else if (arg == "--direct-listen-port" && i + 1 < argc) direct_listen_port = static_cast<uint16_t>(atoi(argv[++i]));
        else if (arg == "--direct-connect-host" && i + 1 < argc) direct_connect_host = argv[++i];
        else if (arg == "--direct-connect-port" && i + 1 < argc) direct_connect_port = static_cast<uint16_t>(atoi(argv[++i]));
        else {
            fprintf(stderr, "unknown arg: %s\n", arg.c_str());
            print_usage(argv[0]);
            return 1;
        }
    }

    if (mode.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    // rl-M10: direct-tunnel 模式不需要 relay_host/relay_port
    bool is_direct_mode = (mode == "direct-server" || mode == "direct-client" ||
                           mode == "direct-relay" || mode == "direct-master");
    if (!is_direct_mode && (relay_host.empty() || relay_port == 0)) {
        print_usage(argv[0]);
        return 1;
    }

    if (mode == "worker" && (peer_id_hex.empty() || local_udp_port == 0)) {
        print_usage(argv[0]);
        return 1;
    }

    if (mode == "master" && master_udp.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    if (mode == "direct-server" && (direct_listen_port == 0 || master_udp.empty())) {
        print_usage(argv[0]);
        return 1;
    }

    if (mode == "direct-client" && (direct_connect_host.empty() || direct_connect_port == 0 || local_udp_port == 0)) {
        print_usage(argv[0]);
        return 1;
    }

    if (mode == "direct-master" && (direct_connect_host.empty() || direct_connect_port == 0 ||
                                     master_udp.empty() || local_udp_port == 0)) {
        print_usage(argv[0]);
        return 1;
    }

    if (mode == "direct-relay" && direct_listen_port == 0) {
        print_usage(argv[0]);
        return 1;
    }

    // rl-M10: direct-tunnel 模式直接运行，不需要 iroh relay / secret key
    if (mode == "direct-server") {
        auto colon = master_udp.find(':');
        if (colon == std::string::npos) {
            fprintf(stderr, "invalid master-udp format\n");
            return 1;
        }
        std::string master_host = master_udp.substr(0, colon);
        uint16_t master_port = static_cast<uint16_t>(atoi(master_udp.substr(colon + 1).c_str()));
        run_direct_server_mode(direct_listen_port, master_host, master_port, slot_port);
        return 0;
    }
    if (mode == "direct-client") {
        run_direct_client_mode(direct_connect_host, direct_connect_port, local_udp_port);
        return 0;
    }
    if (mode == "direct-master") {
        auto colon = master_udp.find(':');
        if (colon == std::string::npos) {
            fprintf(stderr, "invalid master-udp format\n");
            return 1;
        }
        std::string m_host = master_udp.substr(0, colon);
        uint16_t m_port = static_cast<uint16_t>(atoi(master_udp.substr(colon + 1).c_str()));
        run_direct_master_mode(direct_connect_host, direct_connect_port,
                                m_host, m_port, local_udp_port);
        return 0;
    }
    if (mode == "direct-relay") {
        run_direct_relay_mode(direct_listen_port);
        return 0;
    }

    // v4.5.0: 统一调用 linoh::util 密钥持久化（42B 容器 + 原子写 + 跨平台权限）
    auto kf_result = linoh::util::load_or_generate_key_file(key_file);
    base::SecretKey sk = kf_result.sk;
    if (!kf_result.ok || sk.is_zero()) {
        fprintf(stderr, "failed to load/generate secret key\n");
        return 1;
    }

    // rl-M9: 无限重连机制 — relay 断开后持续重连，不再 3 次后退出。
    //   原逻辑 3 次重连失败后退出，导致 supervisor 频繁重启进程（每次重启 slot 端口变化）。
    //   新逻辑：无限重连，成功运行 >15s 后断开则重置计数器（不算连续失败）。
    //   每次重连间隔指数退避（2s→4s→8s→15s 上限）。
    const int kReconnectDelayMs = 2000;
    const int kMaxBackoffMs = 15000;
    int consecutive_failures = 0;

    for (;;) {
        auto connect_start = std::chrono::steady_clock::now();
        RelayClient relay(sk, relay_host, relay_port);
        if (!relay.connect()) {
            consecutive_failures++;
            int delay = kReconnectDelayMs * (1 << std::min(consecutive_failures - 1, 3));
            if (delay > kMaxBackoffMs) delay = kMaxBackoffMs;
            fprintf(stderr, "[relay-bridge] connect failed (%d consecutive), retrying in %dms...\n",
                    consecutive_failures, delay);
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            continue;
        }

        fprintf(stderr, "[relay-bridge] connected as %s to %s:%d\n",
                endpoint_to_hex(relay.id()).c_str(),
                relay_host.c_str(), relay_port);

        if (mode == "worker") {
            EndpointId master_id = endpoint_from_hex(peer_id_hex);
            if (master_id.is_zero()) {
                fprintf(stderr, "invalid peer-id\n");
                return 1;
            }
            run_worker_mode(relay, local_udp_port, master_id);
        } else if (mode == "master") {
            auto colon = master_udp.find(':');
            if (colon == std::string::npos) {
                fprintf(stderr, "invalid master-udp format\n");
                return 1;
            }
            std::string master_host = master_udp.substr(0, colon);
            uint16_t master_port = static_cast<uint16_t>(atoi(master_udp.substr(colon + 1).c_str()));
            run_master_mode(relay, master_host, master_port, slot_port);
        } else {
            fprintf(stderr, "unknown mode: %s\n", mode.c_str());
            return 1;
        }

        // run_*_mode 返回说明 relay 断开
        auto run_duration = std::chrono::steady_clock::now() - connect_start;
        auto run_sec = std::chrono::duration_cast<std::chrono::seconds>(run_duration).count();
        if (run_sec > 15) {
            // 成功运行 >15s 后断开，不算连续失败（可能是偶发网络抖动）
            consecutive_failures = 0;
            fprintf(stderr, "[relay-bridge] disconnected after %llds (stable), reconnecting in %dms...\n",
                    (long long)run_sec, kReconnectDelayMs);
        } else {
            consecutive_failures++;
            int delay = kReconnectDelayMs * (1 << std::min(consecutive_failures - 1, 3));
            if (delay > kMaxBackoffMs) delay = kMaxBackoffMs;
            fprintf(stderr, "[relay-bridge] disconnected after %llds (%d consecutive failures), reconnecting in %dms...\n",
                    (long long)run_sec, consecutive_failures, delay);
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kReconnectDelayMs));
    }

    return 0;
}
