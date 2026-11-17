#pragma once

#include "linoh/util/result.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace linoh::endpoint {

using base::EndpointId;
using base::SecretKey;

/// QUIC 连接状态机（RFC 9000 Section 4.1）。
enum class ConnState {
    Initial,
    Handshake,
    Established,
    Closing,
    Draining,
    Closed,
};

/// QUIC 加密级别（RFC 9000 §4.1.1）。
enum class EncryptionLevel : std::uint8_t {
    Initial     = 0,  // 初始握手（使用初始密钥）
    Handshake   = 1,  // 握手阶段（使用握手密钥）
    OneRtt      = 2,  // 1-RTT 数据（使用应用密钥）
    ZeroRtt     = 3,  // 0-RTT 早期数据
};

/// 握手模式。
enum class HandshakeMode {
    /// 简化 PSK 模式：跳过真实 TLS，使用共享密钥完成快速握手（默认）。
    Psk,
    /// TLS 1.3 风格双向认证 AKE：X25519 ECDHE 前向保密 + Ed25519 节点身份签名。
    /// 通过 CRYPTO 帧驱动 tls::Handshake 驱动，派生应用层 AEAD 密钥。
    Tls13,
};

/// 握手配置。
struct HandshakeConfig {
    /// 简化 PSK 模式：跳过真实 TLS，使用共享密钥完成快速握手。
    /// 在 psk_mode 下，握手仍然走 Initial→Handshake→Established 状态转换，
    /// 但 CRYPTO 帧内容为简化的 PSK 握手而非完整 TLS 1.3。
    bool psk_mode{true};

    /// 握手模式选择。默认 Psk（向后兼容）。置为 Tls13 启用真实 TLS 1.3 风格握手。
    HandshakeMode mode{HandshakeMode::Psk};

    /// 握手超时（毫秒），超时后连接进入 Closed 状态。
    std::chrono::milliseconds handshake_timeout{10000};

    /// 最少需要交换的 CRYPTO 帧数才认为握手完成。
    /// PSK 模式：1（仅 ServerHello 确认）
    /// Full TLS：2（ClientHello + ServerHello）
    int min_crypto_frames{1};
};

/// 握手进度跟踪器。
class HandshakeTracker {
public:
    explicit HandshakeTracker(HandshakeConfig cfg = {})
        : cfg_{cfg} {}

    /// 记录收到的 CRYPTO 帧。
    /// @param level 加密级别
    /// @param offset CRYPTO 帧的 offset 字段
    /// @param data CRYPTO 帧数据
    void on_crypto_frame(EncryptionLevel level,
                         std::uint64_t offset,
                         std::span<const std::uint8_t> data) {
        crypto_frames_received_++;
        auto &buf = buffers_[static_cast<size_t>(level)];
        buf.insert(buf.end(), data.begin(), data.end());
    }

    /// 检查握手是否已完成（收到的 CRYPTO 帧数 ≥ min_crypto_frames）。
    bool is_complete() const { return crypto_frames_received_ >= cfg_.min_crypto_frames; }

    /// 获取收到的 CRYPTO 帧数。
    int crypto_frames_received() const { return crypto_frames_received_; }

    /// 获取握手开始时间（毫秒）。
    double start_ms() const { return start_ms_; }

    /// 设置握手开始时间。
    void set_start_ms(double ms) { start_ms_ = ms; }

    /// 检查握手是否超时。
    bool check_timeout(double now_ms) const {
        if (cfg_.handshake_timeout.count() == 0) return false;
        return (now_ms - start_ms_) > static_cast<double>(cfg_.handshake_timeout.count());
    }

    /// 获取配置。
    const HandshakeConfig &config() const { return cfg_; }

    /// 获取某个加密级别已累积的 CRYPTO 数据。
    const std::vector<std::uint8_t> &crypto_buffer(EncryptionLevel level) const {
        return buffers_[static_cast<size_t>(level)];
    }

private:
    HandshakeConfig cfg_;
    int crypto_frames_received_{0};
    double start_ms_{0.0};
    /// 每个加密级别的 CRYPTO 帧数据缓冲。
    std::vector<std::uint8_t> buffers_[4];
};

/// 连接状态机验证器 — 检查操作是否在合法状态下执行。
class StateValidator {
public:
    /// 检查是否可以发送数据（STREAM 帧）。
    static util::ResultVoid can_send_data(ConnState state) {
        if (state == ConnState::Established) return util::ResultVoid();
        return util::ResultVoid(util::ProtocolError::InvalidState,
            "cannot send data in state " + std::to_string(static_cast<int>(state)));
    }

    /// 检查是否可以打开流。
    static util::ResultVoid can_open_stream(ConnState state) {
        if (state == ConnState::Established) return util::ResultVoid();
        return util::ResultVoid(util::ProtocolError::InvalidState,
            "cannot open stream in state " + std::to_string(static_cast<int>(state)));
    }

    /// 检查是否可以接受流。
    static util::ResultVoid can_accept_stream(ConnState state) {
        if (state == ConnState::Established) return util::ResultVoid();
        return util::ResultVoid(util::ProtocolError::InvalidState,
            "cannot accept stream in state " + std::to_string(static_cast<int>(state)));
    }

    /// 检查是否可以处理 1-RTT 包。
    static util::ResultVoid can_handle_1rtt(ConnState state) {
        if (state == ConnState::Established || state == ConnState::Handshake)
            return util::ResultVoid();
        return util::ResultVoid(util::ProtocolError::InvalidState,
            "cannot handle 1-RTT in state " + std::to_string(static_cast<int>(state)));
    }

    /// 验证状态转换是否合法（RFC 9000 §7）。
    static bool is_valid_transition(ConnState from, ConnState to) {
        // Valid transitions:
        // Initial → Handshake (收到/发送 CRYPTO 帧)
        // Initial → Closed (握手超时/拒绝)
        // Handshake → Established (握手完成)
        // Handshake → Closed (握手失败)
        // Established → Closing (主动关闭)
        // Established → Draining (收到 CONNECTION_CLOSE)
        // Closing → Closed (关闭完成)
        // Draining → Closed (draining 完成)

        switch (from) {
            case ConnState::Initial:
                return to == ConnState::Handshake ||
                       to == ConnState::Established ||  // PSK fast path
                       to == ConnState::Closed;
            case ConnState::Handshake:
                return to == ConnState::Established || to == ConnState::Closed;
            case ConnState::Established:
                return to == ConnState::Closing || to == ConnState::Draining;
            case ConnState::Closing:
                return to == ConnState::Closed;
            case ConnState::Draining:
                return to == ConnState::Closed;
            case ConnState::Closed:
                return false;  // 终态
            default:
                return false;
        }
    }
};

} // namespace linoh::endpoint
