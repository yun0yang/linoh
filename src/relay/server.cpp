// linoh/relay/server.cpp — Self-hosted iroh relay v2 compatible Relay Server
//
// Real Winsock implementation (see server.hpp for rationale — the project's
// `linoh_asio` namespace is a compile-only stub with no real I/O).

#include "linoh/relay/server.hpp"

#include "linoh/util/crypto.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <system_error>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace linoh::relay {

using linoh::crypto::crypto_random_bytes;

namespace {
constexpr int kPingIntervalSec = 15;
constexpr int kAuthTimeoutSec = 30;
constexpr int kReadTimeoutMs = 500;
constexpr int kHandshakeTimeoutMs = 5000;

#ifdef _WIN32
inline int sock_err() { return WSAGetLastError(); }
inline bool would_block() {
    int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK;
}
#else
inline int sock_err() { return errno; }
inline bool would_block() {
    int e = errno;
    return e == EAGAIN || e == EWOULDBLOCK;
}
#endif

/// Send all bytes, looping until complete or an error occurs.
bool sock_send(socket_t s, const uint8_t *data, std::size_t len) {
    std::size_t off = 0;
    while (off < len) {
        int n = ::send(s, reinterpret_cast<const char *>(data + off),
                       static_cast<int>(len - off), 0);
        if (n <= 0) return false;
        off += static_cast<std::size_t>(n);
    }
    return true;
}

/// Recv into buf. Returns:
///   > 0  : bytes read
///     0  : graceful close (peer sent FIN)
///    -1  : error
///    -2  : timeout, no data available within timeout_ms (keep waiting)
int sock_recv(socket_t s, uint8_t *buf, std::size_t len, int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = ::select(static_cast<int>(s) + 1, &fds, nullptr, nullptr, &tv);
    if (r < 0) return -1;
    if (r == 0) return -2;  // timeout, no data available
    int n = ::recv(s, reinterpret_cast<char *>(buf), static_cast<int>(len), 0);
    if (n < 0) return -1;   // recv error
    return n;               // 0 = graceful close, >0 = data
}

void sock_close(socket_t s) {
#ifdef _WIN32
    ::closesocket(s);
#else
    ::close(s);
#endif
}

/// Route a read through the TLS channel when present, else the raw socket.
/// Semantics mirror `sock_recv` (see tls_channel.hpp).
int conn_recv(std::shared_ptr<RelayConn> conn, uint8_t *buf, std::size_t len,
              int timeout_ms) {
    if (conn && conn->tls) return conn->tls->read(buf, len, timeout_ms);
    return sock_recv(conn->sock, buf, len, timeout_ms);
}

/// Route a write through the TLS channel when present, else the raw socket.
bool conn_send(std::shared_ptr<RelayConn> conn, const uint8_t *data,
               std::size_t len) {
    if (conn && conn->tls) return conn->tls->write(data, len);
    return sock_send(conn->sock, data, len);
}
}  // namespace

// ─── Lifecycle ───

RelayServer::RelayServer(unsigned short port) : port_{port} {}

RelayServer::~RelayServer() {
    if (running_.load()) stop();
}

bool RelayServer::start() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        LINOH_ERROR("RelayServer: WSAStartup failed");
        return false;
    }
#endif

    listen_sock_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock_ == kInvalidSocket) {
        LINOH_ERROR("RelayServer: socket() failed");
        return false;
    }

    int yes = 1;
    ::setsockopt(listen_sock_, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char *>(&yes), sizeof(yes));

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port_);
    if (::bind(listen_sock_, reinterpret_cast<struct sockaddr *>(&addr),
               sizeof(addr)) != 0) {
        LINOH_ERROR("RelayServer: bind() failed");
        sock_close(listen_sock_);
        listen_sock_ = kInvalidSocket;
        return false;
    }

    // Determine the actual bound port (for port_ == 0).
    struct sockaddr_in bound {};
    socklen_t blen = sizeof(bound);
    if (::getsockname(listen_sock_,
                      reinterpret_cast<struct sockaddr *>(&bound),
                      &blen) == 0) {
        actual_port_ = ntohs(bound.sin_port);
    } else {
        actual_port_ = port_;
    }

    if (::listen(listen_sock_, SOMAXCONN) != 0) {
        LINOH_ERROR("RelayServer: listen() failed");
        sock_close(listen_sock_);
        listen_sock_ = kInvalidSocket;
        return false;
    }

    running_.store(true);
    accept_thread_ = std::thread([this] { accept_loop(); });
    LINOH_INFO("RelayServer: listening on port", actual_port_);
    return true;
}

void RelayServer::stop() {
    running_.store(false);

    if (listen_sock_ != kInvalidSocket) {
        socket_t ls = listen_sock_;
        listen_sock_ = kInvalidSocket;
        sock_close(ls);
    }
    if (accept_thread_.joinable()) accept_thread_.join();

    // Snapshot connections and force-close their sockets.
    std::vector<std::shared_ptr<RelayConn>> snapshot;
    {
        std::lock_guard<std::mutex> lk(registry_mu_);
        snapshot = conns_;
    }
    for (auto &c : snapshot) {
        c->alive.store(false);
        // Invalidate the socket handle BEFORE closing so any concurrently
        // running read_loop/cleanup_conn skips a second closesocket (which
        // would otherwise race with OS descriptor reuse).
        socket_t s = c->sock;
        c->sock = kInvalidSocket;
        if (s != kInvalidSocket) sock_close(s);
    }
    for (auto &c : snapshot) {
        if (c->supervisor.joinable()) c->supervisor.join();
    }
    {
        std::lock_guard<std::mutex> lk(registry_mu_);
        conns_.clear();
        registry_.clear();
    }

#ifdef _WIN32
    WSACleanup();
#endif
}

std::size_t RelayServer::registered_count() const {
    std::lock_guard<std::mutex> lk(registry_mu_);
    return registry_.size();
}

// v1.7.0.3 P2: 当前是否已达客户端连接上限
bool RelayServer::is_full() const {
    std::size_t limit = max_clients_.load();
    if (limit == 0) return false;  // 0 = 不限制
    std::lock_guard<std::mutex> lk(registry_mu_);
    // 用 conns_ 计数（包含未认证的入站连接），比 registry_ 更严格
    return conns_.size() >= limit;
}

// v1.7.0.3 P2: RelayServerBuilder::build — 应用所有配置构建实例
std::unique_ptr<RelayServer> RelayServerBuilder::build() {
    auto server = std::make_unique<RelayServer>(port_);
    server->set_require_auth(require_auth_);
    server->set_max_clients(max_clients_);
    if (tls_enabled_ && !cert_pem_.empty()) {
        server->set_tls(cert_pem_, key_pem_);
        server->set_tls_enabled(true);
    } else if (tls_enabled_) {
        // tls_enabled=true 但未提供证书：降级为不启用 TLS（不崩溃）
        server->set_tls_enabled(false);
    }
    return server;
}

void RelayServer::set_tls(const std::string &cert_pem,
                          const std::string &key_pem) {
    tls_cfg_.cert_pem = cert_pem;
    tls_cfg_.key_pem = key_pem;
}

// ─── Accept loop ───

void RelayServer::accept_loop() {
    while (running_.load()) {
        struct sockaddr_in peer_addr {};
        socklen_t peer_len = sizeof(peer_addr);
        socket_t cs = ::accept(listen_sock_,
                                reinterpret_cast<struct sockaddr *>(&peer_addr),
                                &peer_len);
        if (cs == kInvalidSocket) {
            if (!running_.load()) break;
            continue;
        }
        // v1.7.0.3 P2: 检查客户端连接上限
        if (is_full()) {
            LINOH_WARN("RelayServer: rejecting connection, max_clients reached");
            sock_close(cs);
            continue;
        }
        auto conn = std::make_shared<RelayConn>();
        conn->sock = cs;
        // v5.0.0 (T-LP4-005): 记录对端公网地址（accept 时获取），
        // 用于 PathChallenge 转发时附加反射地址。
        if (peer_len == sizeof(peer_addr)) {
            char ip_buf[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &peer_addr.sin_addr, ip_buf, sizeof(ip_buf));
            conn->peer_host = ip_buf;
            conn->peer_port = ntohs(peer_addr.sin_port);
        }
        if (tls_enabled_.load()) {
            std::string terr;
            auto tls = TlsChannel::accept(cs, tls_cfg_, &terr);
            if (!tls) {
                LINOH_WARN("RelayServer: TLS accept failed (", terr,
                           "); closing connection");
                sock_close(cs);
                continue;
            }
            conn->tls = tls;
        }
        {
            std::lock_guard<std::mutex> lk(registry_mu_);
            conns_.push_back(conn);
        }
        conn->supervisor = std::thread([this, conn] {
            handle_connection(conn);
        });
    }
}

void RelayServer::handle_connection(std::shared_ptr<RelayConn> conn) {
    try {
        bool hs = do_handshake(conn);
        if (!hs) {
            cleanup_conn(conn);
        } else {
            conn->read_thread = std::thread([this, conn] { read_loop(conn); });
            conn->ping_thread = std::thread([this, conn] { ping_loop(conn); });

            if (conn->read_thread.joinable()) conn->read_thread.join();

            conn->alive.store(false);
            if (conn->ping_thread.joinable()) conn->ping_thread.join();

            cleanup_conn(conn);
        }
    } catch (const std::exception &e) {
        LINOH_ERROR("RelayServer: connection error: ", e.what());
        cleanup_conn(conn);
    } catch (...) {
        LINOH_ERROR("RelayServer: connection error: unknown");
        cleanup_conn(conn);
    }
    // rl-M1 reverted (v1.7.0.8): 原 rl-M1 在此从 conns_ 移除自身，但与 stop() 的
    // snapshot+join 模式存在致命竞态——supervisor 在 stop() snapshot 之后 erase 并退出时，
    // stop() 不会 join 该 supervisor，conn 析构时 std::thread joinable()==true → std::terminate。
    // conns_ 的长期增长问题改由 stop() 统一清理，生产环境如需实时回收应使用
    // 独立的 finished_conns_ 延迟清理列表（确保不破坏 stop() join 闭环）。
}

// ─── Handshake ───

bool RelayServer::do_handshake(std::shared_ptr<RelayConn> conn) {
    // 1. Read the HTTP Upgrade request until headers end.
    std::vector<uint8_t> req_buf(4096);
    std::size_t total = 0;
    std::string client_key, protocol;
    bool got_headers = false;

    while (!got_headers) {
        int n = conn_recv(conn, req_buf.data() + total,
                          req_buf.size() - total, kHandshakeTimeoutMs);
        if (n <= 0) return false;
        total += static_cast<std::size_t>(n);
        auto hend = ws_http_header_end(
            std::span<const uint8_t>(req_buf.data(), total));
        if (hend > 0) {
            if (!ws_parse_handshake_request(
                    std::span<const uint8_t>(req_buf.data(), hend), client_key,
                    protocol)) {
                return false;
            }
            got_headers = true;
        }
        if (total >= req_buf.size() && !got_headers) return false;
    }

    // 2. Respond 101 Switching Protocols.
    std::string resp = ws_build_handshake_response(
        client_key, protocol.empty() ? "iroh-relay-v2" : protocol);
    if (!conn_send(conn,
                   reinterpret_cast<const uint8_t *>(resp.data()),
                   resp.size())) {
        return false;
    }

    LINOH_INFO("RelayServer: WS upgrade complete");

    // 3. Authentication handshake.
    // 【关键修复】即使 --no-auth 模式也必须进行认证握手，以便客户端注册 EndpointId
    // 否则 registry_ 为空，datagram 转发全部被丢弃
    // 在 --no-auth 模式下跳过签名验证，但仍要求客户端发送 ClientAuth 帧
    std::array<uint8_t, kChallengeSize> challenge_bytes{};
    crypto_random_bytes(
        std::span<uint8_t>(challenge_bytes.data(), kChallengeSize));
    ServerChallenge challenge{challenge_bytes};

    auto challenge_frame = encode_frame(
        FrameType::ServerChallenge,
        std::span<const uint8_t>(challenge_bytes.data(), kChallengeSize));
    send_ws_frame(conn, ws_encode_binary_frame_unmasked(challenge_frame));

    AuthResult auth = wait_for_client_auth(conn, challenge);
    if (auth == AuthResult::Confirmed) {
        LINOH_INFO("RelayServer: endpoint authenticated", conn->id.fmt_short());
        return true;
    }
    LINOH_WARN("RelayServer: auth failed (", static_cast<int>(auth), ")");
    return false;
}

AuthResult RelayServer::wait_for_client_auth(std::shared_ptr<RelayConn> conn,
                                             const ServerChallenge &challenge) {
    std::vector<uint8_t> buf;
    std::array<uint8_t, 4096> tmp{};
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(kAuthTimeoutSec);

    while (std::chrono::steady_clock::now() < deadline) {
        int n = conn_recv(conn, tmp.data(), tmp.size(), kReadTimeoutMs);
        if (n == 0) return AuthResult::Error;            // graceful close
        if (n < 0 && n != -2) return AuthResult::Error;  // real error
        if (n > 0) buf.insert(buf.end(), tmp.begin(), tmp.begin() + n);

        while (true) {
            auto dec =
                ws_decode_frame(std::span<const uint8_t>(buf.data(), buf.size()));
            if (dec.invalid) return AuthResult::Error;  // C8: 非法帧关闭连接
            if (dec.need_more) break;                    // 数据不足，继续等待
            auto &frame = dec.frame;
            std::size_t consumed = dec.bytes_consumed;
            buf.erase(buf.begin(), buf.begin() + consumed);

            if (frame.opcode == WsOpcode::Binary) {
                auto stride = decode_frame(frame.payload);
                if (stride && stride->type == FrameType::ClientAuth) {
                    auto ca = decode_client_auth(stride->payload);
                    if (!ca) return AuthResult::Denied;
                    // 【关键修复】--no-auth 模式下跳过签名验证，但仍注册 EndpointId
                    bool auth_ok = false;
                    if (!require_auth_.load()) {
                        auth_ok = true;  // 跳过签名验证
                    } else {
                        auth_ok = verify_client_auth(*ca, challenge);
                    }
                    if (auth_ok) {
                        conn->id = ca->endpoint_id;
                        auto confirm = encode_frame(FrameType::ServerConfirmsAuth,
                                                    std::span<const uint8_t>{});
                        send_ws_frame(conn,
                                      ws_encode_binary_frame_unmasked(confirm));
                        {
                            std::lock_guard<std::mutex> lk(registry_mu_);
                            registry_[conn->id] = conn;
                        }
                        return AuthResult::Confirmed;
                    }
                    auto deny = encode_frame(FrameType::ServerDeniesAuth,
                                             std::span<const uint8_t>{});
                    send_ws_frame(conn, ws_encode_binary_frame_unmasked(deny));
                    return AuthResult::Denied;
                }
            } else if (frame.opcode == WsOpcode::Close) {
                return AuthResult::Error;
            }
        }
    }
    return AuthResult::Timeout;
}

// ─── Read loop ───

void RelayServer::read_loop(std::shared_ptr<RelayConn> conn) {
    std::vector<uint8_t> buf;
    std::array<uint8_t, 4096> tmp{};
    // rl-P1 (v1.7.0.8): read_loop 每帧 buf.erase 头部 O(n) → read_offset 滑动窗口
    //   原实现每消费一帧就 buf.erase(buf.begin(), ...)，O(n) 搬移整个剩余数据。
    //   改为用 read_offset 跟踪已消费位置，ws_decode_frame 传入 buf.data()+offset。
    //   当 read_offset 超过 4KB 阈值时做一次 compact（erase），均摊 O(1)。
    std::size_t read_offset = 0;
    while (conn->alive.load()) {
        int n = conn_recv(conn, tmp.data(), tmp.size(), kReadTimeoutMs);
        if (n == 0) break;                          // graceful close
        if (n < 0 && n != -2) break;               // real error
        if (n > 0) {
            buf.insert(buf.end(), tmp.begin(), tmp.begin() + n);
            while (true) {
                auto dec = ws_decode_frame(
                    std::span<const uint8_t>(buf.data() + read_offset,
                                              buf.size() - read_offset));
                if (dec.invalid) {  // C8: 非法帧关闭连接
                    conn->alive.store(false);
                    break;
                }
                if (dec.need_more) break;  // 数据不足，继续等待
                auto &frame = dec.frame;
                std::size_t consumed = dec.bytes_consumed;
                read_offset += consumed;
                if (!handle_frame(conn, frame)) {
                    conn->alive.store(false);
                    break;
                }
            }
            // rl-P1: 定期 compact，避免 read_offset 无限增长
            if (read_offset > 4096) {
                buf.erase(buf.begin(), buf.begin() + read_offset);
                read_offset = 0;
            }
        }
    }
    cleanup_conn(conn);
}

bool RelayServer::handle_frame(std::shared_ptr<RelayConn> conn,
                               const WsFrame &frame) {
    switch (frame.opcode) {
    case WsOpcode::Binary: {
        auto stride = decode_frame(frame.payload);
        if (!stride) return true;  // ignore malformed
        switch (stride->type) {
        case FrameType::ClientToRelayDatagram:
        case FrameType::ClientToRelayDatagramBatch: {
            if (conn->id.is_zero()) return true;  // not authenticated
            auto dg = decode_datagram(stride->payload);
            if (!dg) return true;
            // v1.7.0.5 P4 (C8+): batch 模式防御性校验（借鉴 iroh #4178）
            // ClientToRelayDatagramBatch 必须 segment_size > 0，否则未来扩展
            // batch 切分逻辑时会触发 0 除法。当前实现整包转发不计算 batch count，
            // 此处提前拒绝非法 batch 帧，避免下游潜在风险。
            if (stride->type == FrameType::ClientToRelayDatagramBatch &&
                dg->segment_size == 0) {
                LINOH_WARN("RelayServer: drop batch datagram with segment_size=0 (iroh #4178)");
                return true;
            }
            forward_datagram(conn, *dg, stride->type);
            break;
        }
        case FrameType::PathChallengeForward: {
            // v5.0.0 (T-LP4-005): relay 转发 PATH_CHALLENGE 路径探测帧
            // 借鉴 iroh 1.0.0-rc.1 noq#672 — Hard-NAT 双向打洞辅助
            if (conn->id.is_zero()) return true;  // not authenticated
            auto probe = decode_path_probe(stride->payload);
            if (!probe) {
                LINOH_WARN("RelayServer: drop malformed PathChallengeForward");
                return true;
            }
            forward_path_probe(conn, *probe);
            break;
        }
        case FrameType::Ping: {
            // rl-M3 (v1.7.0.8): 用 STRIDE Pong 帧（WS Binary 内）响应，而非
            // WS Pong 控制帧。client 只在 WS Binary 内识别 FrameType::Pong，
            // WS Pong 控制帧落入 default 分支被丢弃，keepalive 闭环失效。
            auto pong = encode_frame(
                FrameType::Pong,
                std::span<const uint8_t>(stride->payload.data(),
                                         stride->payload.size()));
            send_ws_frame(conn, ws_encode_binary_frame_unmasked(pong));
            break;
        }
        case FrameType::Pong:
            // rl-M2 (v1.7.0.8): 记录 Pong 到达时间，供 ping_loop 检测半开连接
            conn->last_pong_ms.store(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count());
            break;  // reply to our keepalive ping
        default:
            break;
        }
        break;
    }
    case WsOpcode::Ping:
        send_ws_frame(conn, ws_encode_pong_frame_unmasked(frame.payload));
        break;
    case WsOpcode::Pong:
        // [FIX 2026-08-08] 处理 WS Pong 控制帧，更新 keepalive 时间戳
        // 根因：ping_loop 发送 WS Ping 控制帧(ws_encode_ping_frame_unmasked)，
        //   relay bridge 回复 WS Pong 控制帧(ws_encode_pong_frame)，但原代码
        //   缺少 WsOpcode::Pong 处理，last_pong_ms 永不更新，30s 后超时断开。
        conn->last_pong_ms.store(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch())
                .count());
        break;
    case WsOpcode::Close:
        return false;
    default:
        break;
    }
    return true;
}

void RelayServer::forward_datagram(std::shared_ptr<RelayConn> from,
                                   const Datagram &in, FrameType incoming) {
    // [FIX 2026-08-14] 支持 dst=zero 广播模式
    //
    // 根因：master 和 win-worker 每次启动生成新 keypair，endpoint_id 变化，
    // 导致 relay_peer_id 不匹配，relay_send_thread 使用零 dst 发送（广播）。
    //
    // 修复：当 in.dst 为零时，将数据转发到所有已认证连接（除了发送方）。
    // 对端收到数据后通过动态学习机制更新 relay_peer_id，后续使用单播模式。
    if (in.dst.is_zero()) {
        // 广播模式：转发到所有已认证连接（除了发送方）
        std::vector<std::shared_ptr<RelayConn>> targets;
        {
            std::lock_guard<std::mutex> lk(registry_mu_);
            for (auto &kv : registry_) {
                if (kv.second != from && !kv.first.is_zero()) {
                    targets.push_back(kv.second);
                }
            }
        }

        if (targets.empty()) {
            LINOH_DEBUG("RelayServer: broadcast datagram, no other connected clients");
            return;
        }

        LINOH_INFO("RelayServer: broadcast datagram to ", targets.size(),
                   " client(s), from=", from->id.fmt_short());

        // The 32-byte id field means "dst" on the way in and "src" on the way out.
        Datagram out = in;
        out.dst = from->id;  // mark as the true source for the recipient

        std::vector<uint8_t> stride;
        if (incoming == FrameType::ClientToRelayDatagramBatch) {
            stride = encode_frame(FrameType::RelayToClientDatagramBatch,
                                  encode_datagram(out));
        } else {
            stride = encode_relay_to_client_datagram(out);
        }
        auto ws_frame = ws_encode_binary_frame_unmasked(stride);
        for (auto &t : targets) {
            send_ws_frame(t, ws_frame);
        }
        return;
    }

    // 单播模式：根据 dst 查找目标连接
    std::shared_ptr<RelayConn> dst;
    {
        std::lock_guard<std::mutex> lk(registry_mu_);
        auto it = registry_.find(in.dst);
        if (it != registry_.end()) dst = it->second;
    }
    if (!dst) {
        LINOH_WARN("RelayServer: DROP unicast datagram, dst not connected, size=",
                   in.contents.size(), " dst=", in.dst.fmt_short());
        return;
    }

    // [FIX 2026-08-14] 单播转发日志 — 确认大帧是否被正确转发
    if (in.contents.size() > 100) {
        LINOH_INFO("RelayServer: unicast forward ", in.contents.size(),
                   " bytes to ", in.dst.fmt_short());
    }

    // The 32-byte id field means "dst" on the way in and "src" on the way out.
    Datagram out = in;
    out.dst = from->id;  // mark as the true source for the recipient

    std::vector<uint8_t> stride;
    if (incoming == FrameType::ClientToRelayDatagramBatch) {
        stride = encode_frame(FrameType::RelayToClientDatagramBatch,
                              encode_datagram(out));
    } else {
        stride = encode_relay_to_client_datagram(out);
    }
    send_ws_frame(dst, ws_encode_binary_frame_unmasked(stride));
}

// ─── v5.0.0 (T-LP4-005): Path Challenge Forwarding ───

void RelayServer::forward_path_probe(std::shared_ptr<RelayConn> from,
                                     const PathProbe &probe) {
    std::shared_ptr<RelayConn> dst;
    {
        std::lock_guard<std::mutex> lk(registry_mu_);
        auto it = registry_.find(probe.dst);
        if (it != registry_.end()) dst = it->second;
    }
    if (!dst) {
        LINOH_DEBUG("RelayServer: drop PathChallenge, dst not connected");
        return;
    }

    // 构建 Deliver 帧：源地址标记为发送方，附加 relay 观察到的反射地址
    PathProbe out = probe;
    out.dst = from->id;  // 标记真实来源（与 forward_datagram 一致语义）
    out.observed_host = from->peer_host;
    out.observed_port = from->peer_port;

    LINOH_INFO("RelayServer: forward PathChallenge from ", from->id.fmt_short(),
               " to ", dst->id.fmt_short(),
               " observed=", out.observed_host, ":", out.observed_port);

    auto deliver = encode_path_challenge_deliver(out);
    send_ws_frame(dst, ws_encode_binary_frame_unmasked(deliver));
}

// ─── Keepalive ───

void RelayServer::ping_loop(std::shared_ptr<RelayConn> conn) {
    // rl-M2 (v1.7.0.8): 初始化 last_pong_ms 为当前时间，避免首个 ping 周期误判超时
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now().time_since_epoch())
                      .count();
    conn->last_pong_ms.store(now_ms);

    while (conn->alive.load()) {
        // Sleep in small slices and re-check `alive` so that shutdown
        // (stop() setting alive=false) is observed promptly instead of
        // stalling a full ping interval.
        for (int i = 0; i < kPingIntervalSec * 2 && conn->alive.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (!conn->alive.load()) break;

        // rl-M2 (v1.7.0.8): 检测半开连接 — 若距上次 Pong 超 2×ping 间隔，
        // 视为对端无响应（如进程崩溃但 OS 未发 FIN），断开连接回收资源。
        auto cur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now().time_since_epoch())
                          .count();
        if (conn->last_pong_ms.load() > 0 &&
            cur_ms - conn->last_pong_ms.load() >
                static_cast<long long>(kPingIntervalSec * 2 * 1000)) {
            LINOH_WARN("RelayServer: keepalive timeout (no Pong), closing half-open connection");
            conn->alive.store(false);
            break;
        }

        auto now = cur_ms;
        std::array<uint8_t, 8> p{};
        for (int i = 7; i >= 0; i--) {
            p[i] = static_cast<uint8_t>(now & 0xFF);
            now >>= 8;
        }
        send_ws_frame(conn, ws_encode_ping_frame_unmasked(p));
    }
}

// ─── Write helpers ───

void RelayServer::send_raw(std::shared_ptr<RelayConn> conn, const uint8_t *data,
                           std::size_t len) {
    // v1.7.0.6 (H4-2 fix): sock 读改写纳入 write_mu 保护，
    // 防止与 cleanup_conn / 其他 send_raw 并发导致双重 close 或 use-after-close
    // 调用方（send_ws_frame / cleanup_conn）必须已持有 write_mu
    if (conn->sock == kInvalidSocket || !conn->alive.load()) return;
    if (!conn_send(conn, data, len)) {
        conn->alive.store(false);
        sock_close(conn->sock);
        conn->sock = kInvalidSocket;
    }
}

void RelayServer::send_ws_frame(std::shared_ptr<RelayConn> conn,
                                const std::vector<uint8_t> &frame) {
    std::lock_guard<std::mutex> lk(conn->write_mu);
    send_raw(conn, frame.data(), frame.size());
}

// ─── Cleanup ───

void RelayServer::cleanup_conn(std::shared_ptr<RelayConn> conn) {
    conn->alive.store(false);

    std::vector<std::shared_ptr<RelayConn>> others;
    {
        std::lock_guard<std::mutex> lk(registry_mu_);
        if (!conn->id.is_zero()) {
            registry_.erase(conn->id);
            for (auto &kv : registry_) {
                if (kv.second != conn) others.push_back(kv.second);
            }
        }
        // NOTE: conn stays in `conns_` (the thread-tracking list) until its
        // supervisor thread has fully finished. handle_connection removes it
        // from `conns_` as its last act, so stop() can always join the thread.
        // Removing it here would let a worker thread outlive stop() (and any
        // subsequent WSACleanup), causing a shutdown race.
    }

    if (!others.empty()) {
        auto gone = encode_frame(FrameType::EndpointGone, conn->id.as_span());
        auto ws = ws_encode_binary_frame_unmasked(gone);
        for (auto &c : others) send_ws_frame(c, ws);
    }

    // v1.7.0.6 (H4-2 fix): sock 关闭纳入 write_mu 保护，与 send_raw 互斥
    {
        std::lock_guard<std::mutex> lk(conn->write_mu);
        if (conn->sock != kInvalidSocket) {
            sock_close(conn->sock);
            conn->sock = kInvalidSocket;
        }
    }
}

}  // namespace linoh::relay
