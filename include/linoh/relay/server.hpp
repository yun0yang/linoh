// linoh/relay/server.hpp — Self-hosted iroh relay v2 compatible Relay Server
//
// Implements the relay side of the iroh relay v2 protocol so a relay client can
// connect to it directly (no external iroh server needed):
//
//   1. TCP accept + HTTP Upgrade (Sec-WebSocket-Protocol: iroh-relay-v2)
//   2. Auth handshake: ServerChallenge -> ClientAuth (Ed25519 verify) ->
//      ServerConfirmsAuth / ServerDeniesAuth
//   3. Registry: EndpointId -> connection
//   4. Forwarding: ClientToRelayDatagram -> lookup dst -> RelayToClientDatagram
//   5. Ping/Pong keepalive
//   6. EndpointGone broadcast on disconnect
//
// NOTE: This server uses the real Winsock API directly. The project's
// `linoh_asio` namespace is currently a compile-only stub (no real I/O), so a
// functional relay must bypass it. The wire protocol (WebSocket + STRIDE +
// auth) is identical to what relay::Client produces once its socket layer is
// wired to a real transport, so this server is drop-in compatible.
//
// Threading: one accept thread + one supervisor thread per connection. The
// supervisor spawns a read thread and a ping thread and joins them, so every
// thread is tracked and joinable (no detached threads).

#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/relay/auth.hpp"
#include "linoh/relay/stride.hpp"
#include "linoh/relay/tls_channel.hpp"  // TlsChannel, TlsConfig, socket_t
#include "linoh/relay/ws_client.hpp"  // WsFrame, WsOpcode, ws_decode_frame, ws_http_header_end
#include "linoh/relay/ws_server.hpp"

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace linoh::relay {

// `socket_t` / `kInvalidSocket` are provided by linoh/relay/tls_channel.hpp.

/// A single relayed connection: one authenticated client endpoint.
struct RelayConn {
    socket_t sock{kInvalidSocket};
    std::shared_ptr<TlsChannel> tls;  // non-null only when TLS is enabled
    base::EndpointId id;            // authenticated node id (zero until auth)
    std::atomic<bool> alive{true};
    std::mutex write_mu;            // guards socket writes

    std::thread supervisor;         // owns lifecycle (joins read/ping)
    std::thread read_thread;
    std::thread ping_thread;

    // rl-M2 (v1.7.0.8): 上次收到 Pong 的 steady_clock 毫秒时间戳。
    // ping_loop 据此检测半开连接（Ping 无 Pong 响应超 2×ping 间隔则断开）。
    // 初始化为 start 时刻，避免首个 ping 周期误判超时。
    std::atomic<long long> last_pong_ms{0};

    // v5.0.0 (T-LP4-005): 对端公网地址（accept 时获取），用于 PathChallenge
    // 转发时附加反射地址，使 Hard-NAT 场景下对端能学习到发送方的公网地址。
    std::string peer_host;
    uint16_t peer_port{0};
};

class RelayServer {
public:
    /// @param port  TCP port to bind. 0 = let the OS choose a free port.
    explicit RelayServer(unsigned short port = 0);
    ~RelayServer();

    RelayServer(const RelayServer &) = delete;
    RelayServer &operator=(const RelayServer &) = delete;

    /// Start listening. Returns false on failure.
    bool start();
    /// Stop accepting, close all connections, join all threads.
    void stop();

    bool is_running() const { return running_.load(); }

    /// Require Ed25519 challenge-response auth (default true).
    void set_require_auth(bool r) { require_auth_.store(r); }

    /// Enable wss:// (TLS) using the given in-memory PEM cert/key. Call
    /// set_tls_enabled(true) for it to take effect at accept time.
    void set_tls(const std::string &cert_pem, const std::string &key_pem);
    /// Gate TLS at runtime. Default false => plain ws:// (zero-dependency).
    void set_tls_enabled(bool e) { tls_enabled_.store(e); }

    /// Actual bound port (valid after start()).
    unsigned short local_port() const { return actual_port_; }

    /// Number of currently registered (authenticated) endpoints.
    std::size_t registered_count() const;

    /// v1.7.0.3 P2: 设置最大客户端连接数（0 = 不限制）
    void set_max_clients(std::size_t n) { max_clients_.store(n); }
    std::size_t max_clients() const { return max_clients_.load(); }

    /// v1.7.0.3 P2: 当前是否已达客户端连接上限
    bool is_full() const;

private:
    void accept_loop();
    void handle_connection(std::shared_ptr<RelayConn> conn);

    bool do_handshake(std::shared_ptr<RelayConn> conn);
    AuthResult wait_for_client_auth(std::shared_ptr<RelayConn> conn,
                                    const ServerChallenge &challenge);

    void read_loop(std::shared_ptr<RelayConn> conn);
    void ping_loop(std::shared_ptr<RelayConn> conn);

    /// Returns false if the connection should be closed (e.g. Close frame).
    bool handle_frame(std::shared_ptr<RelayConn> conn, const WsFrame &frame);

    void forward_datagram(std::shared_ptr<RelayConn> from, const Datagram &in,
                          FrameType incoming);

    /// v5.0.0 (T-LP4-005): 转发 PATH_CHALLENGE 路径探测帧（借鉴 iroh noq#672）。
    ///
    /// Hard-NAT 双向打洞场景：双方对称 NAT 直连困难时，通过 relay 中转
    /// PATH_CHALLENGE，relay 附加观察到的源地址（反射地址），使对端能
    /// 学习到发送方的公网 ip:port，从而提升直连成功率。
    ///
    /// @param from  发送方连接（已认证）
    /// @param probe 路径探测载荷（dst=目标 endpoint，challenge_data=8B 探测数据）
    void forward_path_probe(std::shared_ptr<RelayConn> from,
                            const PathProbe &probe);

    /// Write raw bytes to a connection's socket (caller must pass unmasked
    /// server frames). Thread-safe.
    void send_raw(std::shared_ptr<RelayConn> conn, const uint8_t *data,
                  std::size_t len);
    void send_ws_frame(std::shared_ptr<RelayConn> conn,
                       const std::vector<uint8_t> &frame);

    /// Unregister + broadcast EndpointGone + remove from connection list.
    void cleanup_conn(std::shared_ptr<RelayConn> conn);

    unsigned short port_;
    unsigned short actual_port_{0};
    socket_t listen_sock_{kInvalidSocket};
    std::thread accept_thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> require_auth_{true};
    std::atomic<bool> tls_enabled_{false};
    TlsConfig tls_cfg_;

    mutable std::mutex registry_mu_;
    std::map<base::EndpointId, std::shared_ptr<RelayConn>> registry_;
    std::vector<std::shared_ptr<RelayConn>> conns_;

    /// v1.7.0.3 P2: 最大客户端连接数（0 = 不限制）
    std::atomic<std::size_t> max_clients_{0};
};

// ============================================================================
// v1.7.0.3 P2: RelayServerBuilder — 链式配置器（借鉴 iroh-relay ServerConfig）
//
// 用法：
//   auto server = linoh::relay::RelayServerBuilder()
//       .port(9002)
//       .require_auth(true)
//       .max_clients(100)
//       .build();
//   if (server && server->start()) { ... }
// ============================================================================

class RelayServerBuilder {
public:
    RelayServerBuilder() = default;

    /// 设置监听端口（0 = OS 自动选择）
    RelayServerBuilder &port(unsigned short p) { port_ = p; return *this; }

    /// 启用/禁用 Ed25519 认证（默认启用）
    RelayServerBuilder &require_auth(bool r) { require_auth_ = r; return *this; }

    /// 启用 TLS（需配合 tls_cert 设置证书）
    RelayServerBuilder &tls_enabled(bool e) { tls_enabled_ = e; return *this; }

    /// 设置 TLS 证书（PEM 格式）
    RelayServerBuilder &tls_cert(const std::string &cert_pem,
                                  const std::string &key_pem) {
        cert_pem_ = cert_pem; key_pem_ = key_pem; return *this;
    }

    /// 设置最大客户端连接数（0 = 不限制）
    RelayServerBuilder &max_clients(std::size_t n) { max_clients_ = n; return *this; }

    /// 构建 RelayServer 实例（应用所有配置）
    /// @return 非空 unique_ptr（若端口冲突 start() 会失败，build 本身不失败）
    std::unique_ptr<RelayServer> build();

    // 配置读取（用于测试验证）
    unsigned short get_port() const { return port_; }
    bool get_require_auth() const { return require_auth_; }
    bool get_tls_enabled() const { return tls_enabled_; }
    std::size_t get_max_clients() const { return max_clients_; }

private:
    unsigned short port_{0};
    bool require_auth_{true};
    bool tls_enabled_{false};
    std::string cert_pem_;
    std::string key_pem_;
    std::size_t max_clients_{0};
};

}  // namespace linoh::relay
