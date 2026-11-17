#include "linoh/relay/client.hpp"

#include "linoh/util/logging.hpp"

#include <chrono>
#include <cstring>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace linoh::relay {

// ─── Constants ───

constexpr int kPingIntervalSec = 15;
constexpr int kAuthTimeoutSec = 30;

Client::Client(linoh_asio::io_context &ctx, base::RelayUrl url,
               base::SecretKey secret_key)
    : ctx_{ctx}, url_{std::move(url)}, secret_key_{std::move(secret_key)},
      local_id_{secret_key_.is_zero() ? base::EndpointId{} : secret_key_.public_key()} {}

Client::~Client() {
    if (connected_) disconnect();
}

// ─── Connection & WebSocket handshake ───

bool Client::connect() {
    try {
        tcp_ = std::make_unique<linoh_asio::ip::tcp::socket>(ctx_);
        linoh_asio::ip::tcp::resolver res(ctx_);
        auto eps = res.resolve(url_.host(), std::to_string(url_.port()));
        linoh_asio::connect(*tcp_, eps);

        // Perform WebSocket upgrade
        if (!ws_handshake()) {
            LINOH_ERROR("Relay: WebSocket handshake failed");
            connected_ = false;
            return false;
        }

        connected_ = true;
        ws_upgraded_ = true;

        // Perform authentication handshake
        auto auth_result = auth_handshake();
        if (auth_result != AuthResult::Confirmed) {
            LINOH_ERROR("Relay: authentication failed");
            disconnect();
            return false;
        }
        authenticated_ = true;

        LINOH_INFO("Relay: authenticated as", local_id_.fmt_short(),
                   "to", url_.url());

        // Start reading WebSocket frames
        loop_read_ws();

        // Start Ping/Pong keepalive timer
        start_ping_timer();

        LINOH_INFO("Relay: WebSocket connected to", url_.url());
        return true;
    } catch (const std::exception &e) {
        LINOH_ERROR("Relay: connect failed:", e.what());
        connected_ = false;
        return false;
    }
}

bool Client::ws_handshake() {
    // Build HTTP Upgrade request
    std::string req = ws_build_handshake_request(
        url_.host(), "/", std::to_string(url_.port()));

    // Send the request
    std::error_code ec;
    linoh_asio::write(*tcp_, linoh_asio::buffer(req), ec);
    if (ec) {
        LINOH_ERROR("Relay: WS handshake write failed:", ec.message());
        return false;
    }

    // Read response headers (up to \r\n\r\n)
    std::vector<uint8_t> resp_buf;
    resp_buf.resize(4096);  // generous buffer for HTTP headers
    std::size_t total_read = 0;

    while (true) {
        std::size_t n = tcp_->read_some(linoh_asio::buffer(resp_buf.data() + total_read,
                                                              resp_buf.size() - total_read), ec);
        if (ec) {
            LINOH_ERROR("Relay: WS handshake read failed:", ec.message());
            return false;
        }
        total_read += n;

        // Check if we have complete headers (\r\n\r\n)
        auto header_end = ws_http_header_end(
            std::span<const uint8_t>(resp_buf.data(), total_read));
        if (header_end > 0) {
            // Validate handshake response
            if (!ws_validate_handshake_response(
                    std::span<const uint8_t>(resp_buf.data(), header_end))) {
                LINOH_ERROR("Relay: WS handshake response invalid");
                return false;
            }

            // Store any extra bytes (after headers) as initial WebSocket data
            if (header_end < total_read) {
                ws_read_buf_.assign(resp_buf.begin() + header_end,
                                     resp_buf.begin() + total_read);
            }
            return true;
        }

        // Buffer full but no headers found — server misbehaving
        if (total_read >= resp_buf.size()) {
            LINOH_ERROR("Relay: WS handshake response too large, no header end found");
            return false;
        }
    }
}

// ─── Authentication handshake ───

AuthResult Client::auth_handshake() {
    if (secret_key_.is_zero()) {
        LINOH_ERROR("Relay: no secret key provided for authentication");
        return AuthResult::Error;
    }

    // Wait for ServerChallenge frame from the relay server.
    // The challenge arrives as a WebSocket binary frame containing
    // a STRIDE ServerChallenge frame.
    LINOH_INFO("Relay: waiting for server challenge...");

    // Read WebSocket frames until we get the ServerChallenge
    std::vector<uint8_t> auth_buf;
    std::error_code ec;

    while (true) {
        // First check if we already have data in ws_read_buf_
        // from the WebSocket handshake
        if (!ws_read_buf_.empty()) {
            auto decoded = ws_decode_frame(
                std::span<const uint8_t>(ws_read_buf_.data(), ws_read_buf_.size()));
            if (decoded.invalid) {  // C8: 非法帧关闭连接
                LINOH_ERROR("Relay: invalid WebSocket frame during auth handshake");
                return AuthResult::Error;
            }
            if (decoded.ok) {
                auto &frame = decoded.frame;
                auto consumed = decoded.bytes_consumed;
                ws_read_buf_.erase(ws_read_buf_.begin(),
                                    ws_read_buf_.begin() + consumed);

                if (frame.opcode == WsOpcode::Binary) {
                    auto stride = decode_frame(frame.payload);
                    if (stride && stride->type == FrameType::ServerChallenge) {
                        // Got the challenge! Sign it and respond.
                        auto challenge = decode_server_challenge(stride->payload);
                        if (!challenge) {
                            LINOH_ERROR("Relay: invalid ServerChallenge payload");
                            return AuthResult::Error;
                        }

                        LINOH_INFO("Relay: received server challenge, signing...");

                        // Sign the challenge with domain separation
                        auto client_auth = sign_challenge(*challenge, secret_key_);
                        auto auth_frame = encode_client_auth(client_auth);

                        // Send ClientAuth as WebSocket binary frame (masked)
                        auto ws_frame = ws_encode_binary_frame(auth_frame);
                        linoh_asio::write(*tcp_, linoh_asio::buffer(ws_frame), ec);
                        if (ec) {
                            LINOH_ERROR("Relay: ClientAuth write failed:", ec.message());
                            return AuthResult::Error;
                        }

                        LINOH_INFO("Relay: ClientAuth sent, waiting for confirmation...");

                        // Now wait for ServerConfirmsAuth or ServerDeniesAuth
                        return wait_for_auth_confirm();
                    }
                    // Not a ServerChallenge — ignore for now
                }
                // Not a binary frame — ignore
            }
            // need_more: Incomplete frame in buffer — need more data
        }

        // Read more bytes from TCP
        std::vector<uint8_t> read_buf(4096);
        std::size_t n = tcp_->read_some(linoh_asio::buffer(read_buf), ec);
        if (ec) {
            LINOH_ERROR("Relay: auth read failed:", ec.message());
            return AuthResult::Error;
        }
        ws_read_buf_.insert(ws_read_buf_.end(), read_buf.begin(), read_buf.begin() + n);
    }
}

AuthResult Client::wait_for_auth_confirm() {
    // Read WebSocket frames until we get ServerConfirmsAuth or ServerDeniesAuth
    std::error_code ec;

    while (true) {
        if (!ws_read_buf_.empty()) {
            auto decoded = ws_decode_frame(
                std::span<const uint8_t>(ws_read_buf_.data(), ws_read_buf_.size()));
            if (decoded.invalid) {  // C8: 非法帧关闭连接
                LINOH_ERROR("Relay: invalid WebSocket frame during auth confirm");
                return AuthResult::Error;
            }
            if (decoded.ok) {
                auto &frame = decoded.frame;
                auto consumed = decoded.bytes_consumed;
                ws_read_buf_.erase(ws_read_buf_.begin(),
                                    ws_read_buf_.begin() + consumed);

                if (frame.opcode == WsOpcode::Binary) {
                    auto stride = decode_frame(frame.payload);
                    if (stride) {
                        switch (stride->type) {
                        case FrameType::ServerConfirmsAuth:
                            LINOH_INFO("Relay: authentication confirmed!");
                            return AuthResult::Confirmed;
                        case FrameType::ServerDeniesAuth: {
                            auto deny = decode_server_denies(stride->payload);
                            LINOH_ERROR("Relay: authentication denied:", deny.reason);
                            return AuthResult::Denied;
                        }
                        default:
                            // Ignore other frames during auth handshake
                            break;
                        }
                    }
                }
                // Handle Close frame during auth
                if (frame.opcode == WsOpcode::Close) {
                    LINOH_ERROR("Relay: WebSocket close frame during auth");
                    return AuthResult::Error;
                }
            }
            // need_more: Incomplete frame — fall through to read more
        }

        // Read more bytes
        std::vector<uint8_t> read_buf(4096);
        std::size_t n = tcp_->read_some(linoh_asio::buffer(read_buf), ec);
        if (ec) {
            LINOH_ERROR("Relay: auth confirm read failed:", ec.message());
            return AuthResult::Error;
        }
        ws_read_buf_.insert(ws_read_buf_.end(), read_buf.begin(), read_buf.begin() + n);
    }
}

void Client::disconnect() {
    connected_ = false;
    ws_upgraded_ = false;
    authenticated_ = false;
    if (ping_timer_) {
        ping_timer_->cancel();
        ping_timer_.reset();
    }
    std::error_code ec;
    if (tcp_) tcp_->close(ec);
}

// ─── Sending ───

std::size_t Client::send_via(const base::EndpointId &dst, std::span<const uint8_t> payload) {
    if (!connected_ || !ws_upgraded_ || !authenticated_ || payload.empty()) return 0;

    // Build STRIDE ClientToRelayDatagram
    Datagram dg;
    dg.dst = dst;
    dg.ecn = EcnCodepoint::None;
    dg.contents.assign(payload.begin(), payload.end());
    auto stride_frame = encode_client_to_relay_datagram(dg);

    // Wrap in WebSocket binary frame (masked, per RFC 6455)
    auto ws_frame = ws_encode_binary_frame(stride_frame);

    std::error_code ec;
    auto n = linoh_asio::write(*tcp_, linoh_asio::buffer(ws_frame), ec);
    if (ec) {
        LINOH_ERROR("Relay: send_via write failed:", ec.message());
        return 0;
    }
    return payload.size();
}

// ─── v5.0.0 (T-LP4-005): Path Challenge Forwarding ───

bool Client::send_path_challenge(const base::EndpointId &dst,
                                 std::span<const std::uint8_t, 8> challenge_data) {
    if (!connected_ || !ws_upgraded_ || !authenticated_) return false;

    PathProbe probe;
    probe.dst = dst;
    std::memcpy(probe.challenge_data.data(), challenge_data.data(), 8);
    // observed_host / observed_port 留空（Client → Relay 方向）

    auto stride_frame = encode_path_challenge_forward(probe);
    auto ws_frame = ws_encode_binary_frame(stride_frame);

    std::error_code ec;
    linoh_asio::write(*tcp_, linoh_asio::buffer(ws_frame), ec);
    if (ec) {
        LINOH_ERROR("Relay: send_path_challenge write failed:", ec.message());
        return false;
    }
    LINOH_DEBUG("Relay: sent PathChallenge to", dst.fmt_short());
    return true;
}

// ─── Reading WebSocket frames ───

void Client::loop_read_ws() {
    if (!connected_ || !ws_upgraded_) return;

    // Read raw bytes from TCP and try to assemble WebSocket frames
    auto buf = std::make_shared<std::vector<uint8_t>>(4096);
    tcp_->async_read_some(linoh_asio::buffer(buf->data(), buf->size()),
        [this, self = shared_from_this(), buf](std::error_code ec, std::size_t n) {
            if (ec) {
                if (ec != linoh_asio::error::operation_aborted) {
                    LINOH_ERROR("Relay: WS read failed:", ec.message());
                }
                connected_ = false;
                return;
            }

            // Append received bytes to buffer
            ws_read_buf_.insert(ws_read_buf_.end(), buf->begin(), buf->begin() + n);

            // Try to decode complete WebSocket frames from buffer
            while (!ws_read_buf_.empty()) {
                auto decoded = ws_decode_frame(
                    std::span<const uint8_t>(ws_read_buf_.data(), ws_read_buf_.size()));
                if (decoded.invalid) {  // C8: 非法帧关闭连接
                    LINOH_ERROR("Relay: invalid WebSocket frame in read loop");
                    connected_ = false;
                    return;
                }
                if (decoded.need_more) {
                    // Incomplete frame — need more data
                    break;
                }
                auto &frame = decoded.frame;
                auto consumed = decoded.bytes_consumed;

                // Remove consumed bytes from buffer
                ws_read_buf_.erase(ws_read_buf_.begin(),
                                    ws_read_buf_.begin() + consumed);

                // Handle the decoded frame
                handle_ws_frame(frame);
            }

            // Continue reading
            loop_read_ws();
        });
}

void Client::handle_ws_frame(const WsFrame &frame) {
    switch (frame.opcode) {
    case WsOpcode::Binary: {
        // Binary frame contains STRIDE frames
        auto stride = decode_frame(frame.payload);
        if (!stride) {
            LINOH_ERROR("Relay: invalid STRIDE frame in WS binary message");
            return;
        }

        switch (stride->type) {
        case FrameType::RelayToClientDatagram: {
            auto dg = decode_datagram(stride->payload);
            if (!dg) {
                LINOH_ERROR("Relay: invalid datagram payload");
                return;
            }
            std::lock_guard<std::mutex> lk(handler_mu_);
            if (handler_) {
                util::Bytes b(std::span<const uint8_t>(dg->contents.data(), dg->contents.size()));
                handler_(dg->dst, std::move(b));
            }
            break;
        }
        case FrameType::PathChallengeDeliver: {
            // v5.0.0 (T-LP4-005): 收到对端通过 relay 转发的 PATH_CHALLENGE
            auto probe = decode_path_probe(stride->payload);
            if (!probe) {
                LINOH_WARN("Relay: invalid PathChallengeDeliver payload");
                return;
            }
            std::lock_guard<std::mutex> lk(path_probe_mu_);
            if (path_probe_handler_) {
                path_probe_handler_(probe->dst, probe->challenge_data,
                                    probe->observed_host, probe->observed_port);
            }
            break;
        }
        case FrameType::EndpointGone: {
            LINOH_INFO("Relay: received EndpointGone frame");
            break;
        }
        case FrameType::Pong: {
            // Pong received — keepalive successful
            break;
        }
        case FrameType::Restarting: {
            LINOH_INFO("Relay: server restarting, should reconnect");
            connected_ = false;
            break;
        }
        case FrameType::Status: {
            LINOH_INFO("Relay: received Status frame");
            break;
        }
        default: {
            LINOH_INFO("Relay: unknown STRIDE frame type:",
                        static_cast<uint64_t>(stride->type));
            break;
        }
        }
        break;
    }
    case WsOpcode::Ping: {
        // Respond with Pong (unmasked, per RFC 6455 server → client rule)
        // Server Ping frames are unmasked; our Pong must be masked
        auto pong = ws_encode_ping_frame(frame.payload);
        std::error_code ec;
        linoh_asio::write(*tcp_, linoh_asio::buffer(pong), ec);
        if (ec) LINOH_ERROR("Relay: Pong write failed:", ec.message());
        break;
    }
    case WsOpcode::Close: {
        LINOH_INFO("Relay: WebSocket close frame received");
        connected_ = false;
        break;
    }
    default: {
        LINOH_INFO("Relay: unknown WS opcode:", static_cast<int>(frame.opcode));
        break;
    }
    }
}

// ─── Ping/Pong keepalive ───

void Client::send_ping() {
    if (!connected_ || !ws_upgraded_) return;

    // Generate 8-byte ping payload (timestamp)
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    std::array<uint8_t, 8> ping_data;
    for (int i = 7; i >= 0; i--) {
        ping_data[i] = static_cast<uint8_t>(ms & 0xFF);
        ms >>= 8;
    }

    // Send STRIDE Ping frame inside WebSocket binary frame
    auto stride_ping = encode_ping(ping_data);
    auto ws_frame = ws_encode_binary_frame(stride_ping);

    std::error_code ec;
    linoh_asio::write(*tcp_, linoh_asio::buffer(ws_frame), ec);
    if (ec) LINOH_ERROR("Relay: Ping write failed:", ec.message());
}

void Client::start_ping_timer() {
    ping_timer_ = std::make_unique<linoh_asio::steady_timer>(ctx_, std::chrono::seconds(kPingIntervalSec));
    ping_timer_->async_wait(
        [this, self = shared_from_this()](std::error_code ec) {
            if (ec || !connected_) return;
            send_ping();
            // Restart timer
            start_ping_timer();
        });
}

}  // namespace linoh::relay
