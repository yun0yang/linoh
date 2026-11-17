#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/net/transport.hpp"
#include "linoh/relay/auth.hpp"
#include "linoh/relay/stride.hpp"
#include "linoh/relay/ws_client.hpp"
#include "linoh/util/bytes.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#ifdef LINOH_WITH_BOOST_ASIO
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
namespace linoh_asio = boost::asio;
#else
#include <asio.hpp>
#ifndef LINOH_USE_STUB_ASIO
namespace linoh_asio = asio;
#endif
#endif

namespace linoh::relay {

/// Relay 客户端：通过 WebSocket 连接到 iroh relay server (v2 协议)。
///
/// 协议流程：
/// 1. TCP 连接到 relay server
/// 2. HTTP Upgrade → WebSocket (Sec-WebSocket-Protocol: iroh-relay-v2)
/// 3. 认证握手：接收 ServerChallenge → 签名 → 发送 ClientAuth → 等待确认
/// 4. 在 WebSocket 连接上发送/接收 STRIDE 帧
/// 5. STRIDE 帧: [VarInt FrameType][Payload]
/// 6. Datagram payload: [EndpointId(32B)][ECN(1B)][SegmentSize(2B)][Contents]
/// 7. Ping/Pong 心跳保活 (15s interval)
///
/// 认证方式：
/// - Challenge-Response：server 发 challenge → client 签名后发 ClientAuth
/// - 域分离前缀: "iroh-relay handshake v1 challenge signature"
class Client : public std::enable_shared_from_this<Client> {
public:
    /// Constructor with secret key for authentication.
    Client(linoh_asio::io_context &ctx, base::RelayUrl url,
           base::SecretKey secret_key = {});
    ~Client();

    /// 连接到 relay server: TCP + WebSocket upgrade + 认证握手.
    bool connect();
    void disconnect();
    bool is_connected() const { return connected_; }
    bool is_authenticated() const { return authenticated_; }

    /// 通过 Relay 向 `dst` 发送 payload (STRIDE ClientToRelayDatagram).
    /// 仅在认证成功后可用。
    std::size_t send_via(const base::EndpointId &dst, std::span<const uint8_t> payload);

    /// v5.0.0 (T-LP4-005): 通过 Relay 向 `dst` 发送 PATH_CHALLENGE 路径探测帧。
    ///
    /// Hard-NAT 双向打洞辅助（借鉴 iroh noq#672）：当双方对称 NAT 直连困难时，
    /// 通过 relay 中转 PATH_CHALLENGE，relay 附加反射地址后转发给对端，
    /// 对端可从中学习到发送方的公网地址，提升直连成功率。
    ///
    /// @param dst            目标 endpoint
    /// @param challenge_data 8 字节 PATH_CHALLENGE 数据
    /// @return true 表示帧已发送（不代表对端收到）
    bool send_path_challenge(const base::EndpointId &dst,
                             std::span<const uint8_t, 8> challenge_data);

    /// v5.0.0 (T-LP4-005): 注册 PathChallengeDeliver 帧处理器。
    ///
    /// 当收到对端通过 relay 转发的 PATH_CHALLENGE 时触发。
    /// 回调参数：
    ///   - from: 发送方 endpoint_id
    ///   - challenge_data: 8 字节 PATH_CHALLENGE 数据
    ///   - observed_host: relay 观察到的发送方公网 IP
    ///   - observed_port: relay 观察到的发送方公网端口
    using PathProbeHandler = std::function<void(
        base::EndpointId from,
        std::array<uint8_t, 8> challenge_data,
        std::string observed_host,
        uint16_t observed_port)>;
    void set_path_probe_handler(PathProbeHandler h) {
        std::lock_guard<std::mutex> lk(path_probe_mu_);
        path_probe_handler_ = std::move(h);
    }

    /// 上层注册的包处理器。收到 RelayToClientDatagram 时触发。
    void set_handler(std::function<void(base::EndpointId from, util::Bytes)> h) {
        std::lock_guard<std::mutex> lk(handler_mu_);
        handler_ = std::move(h);
    }

    const base::RelayUrl &url() const { return url_; }
    const base::EndpointId &local_id() const { return local_id_; }

private:
    /// Perform WebSocket handshake over the TCP socket.
    bool ws_handshake();

    /// Perform authentication handshake after WebSocket upgrade.
    /// Returns AuthResult::Confirmed on success.
    AuthResult auth_handshake();

    /// Wait for ServerConfirmsAuth or ServerDeniesAuth after sending ClientAuth.
    AuthResult wait_for_auth_confirm();

    /// Read WebSocket frames in a loop (async).
    void loop_read_ws();

    /// Handle a decoded WebSocket frame.
    void handle_ws_frame(const WsFrame &frame);

    /// Send a Ping frame (keepalive).
    void send_ping();

    /// Start periodic Ping timer.
    void start_ping_timer();

    linoh_asio::io_context &ctx_;
    base::RelayUrl url_;
    base::SecretKey secret_key_;
    base::EndpointId local_id_;    // derived from secret_key_.public_key()
    std::unique_ptr<linoh_asio::ip::tcp::socket> tcp_;
    std::unique_ptr<linoh_asio::steady_timer> ping_timer_;
    std::atomic<bool> connected_{false};
    std::atomic<bool> ws_upgraded_{false};
    std::atomic<bool> authenticated_{false};
    std::mutex handler_mu_;
    std::function<void(base::EndpointId, util::Bytes)> handler_;

    // v5.0.0 (T-LP4-005): PathChallengeDeliver 帧处理器
    std::mutex path_probe_mu_;
    PathProbeHandler path_probe_handler_;

    /// Read buffer for assembling WebSocket frames.
    std::vector<uint8_t> ws_read_buf_;
};

/// Relay 版 Transport：把 `Client` 包装成 `net::Transport` 接口，
/// 供 Socket 统一调度。
class RelayTransport : public net::Transport {
public:
    explicit RelayTransport(std::shared_ptr<Client> client) : client_{std::move(client)} {
        client_->set_handler([this](base::EndpointId from, util::Bytes data) {
            base::TransportAddr addr;
            addr.kind = base::TransportKind::Relay;
            addr.host = client_->url().host();
            addr.port = client_->url().port();
            addr.custom_payload = from.fmt_short();
            if (handler_) handler_({std::move(data), std::move(addr), 0});
        });
    }

    std::string name() const override { return "relay:" + client_->url().host(); }
    bool is_running() const override { return client_->is_connected(); }

    std::size_t send_to(const base::TransportAddr &dst, std::span<const uint8_t> payload) override {
        return client_->send_via(peer_id_, payload);
    }

    void set_packet_handler(PacketHandler h) override { handler_ = std::move(h); }
    void start() override { client_->connect(); }
    void stop() override { client_->disconnect(); }

    void set_peer(const base::EndpointId &id) { peer_id_ = id; }

private:
    std::shared_ptr<Client> client_;
    PacketHandler handler_;
    base::EndpointId peer_id_;
};

} // namespace linoh::relay
