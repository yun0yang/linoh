// linoh/relay/stride.hpp — iroh relay v2 STRIDE frame codec
//
// STRIDE frame format: [VarInt FrameType][Payload]
// Datagram payload:    [EndpointId(32B)][ECN(1B)][SegmentSize(2B, big-endian)][Contents]
// SegmentSize is always 2 bytes; 0 means not batched (single datagram).
//
// Reference: iroh relay protocol (v2, WebSocket-based)
// https://deepwiki.com/n0-computer/iroh/6.4-relay-protocol-and-message-flow

#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "linoh/base/key.hpp"       // EndpointId = PublicKey (32B)
#include "linoh/util/varint.hpp"    // QUIC VarInt encode/decode

namespace linoh::relay {

// ─── Frame Types (VarInt-encoded) ───

enum class FrameType : uint64_t {
    /// Server → Client: challenge for authentication (random bytes).
    ServerChallenge = 0,
    /// Client → Server: signed authentication response (EndpointId + Ed25519 signature).
    ClientAuth = 1,
    /// Server → Client: authentication confirmed.
    ServerConfirmsAuth = 2,
    /// Server → Client: authentication denied.
    ServerDeniesAuth = 3,
    /// Client → Relay: forward this datagram to the destination EndpointId.
    ClientToRelayDatagram = 4,
    /// Client → Relay: forward batched datagrams to the destination EndpointId.
    ClientToRelayDatagramBatch = 5,
    /// Relay → Client: deliver a datagram from another endpoint.
    RelayToClientDatagram = 6,
    /// Relay → Client: deliver batched datagrams from another endpoint.
    RelayToClientDatagramBatch = 7,
    /// Relay → Client: the remote endpoint has disconnected.
    EndpointGone = 8,
    /// Client → Relay: keepalive ping.
    Ping = 9,
    /// Relay → Client: keepalive pong response.
    Pong = 10,
    /// Relay → Client: relay server is restarting; client should reconnect.
    Restarting = 12,
    /// Relay → Client: status message (version, uptime, etc.).
    Status = 13,
    /// v5.0.0 (T-LP4-005): Client → Relay — forward a PATH_CHALLENGE to help
    /// peer learn our address. Used for Hard-NAT bidirectional hole punching
    /// (iroh 1.0.0-rc.1 noq#672). Relay appends observed source address.
    PathChallengeForward = 14,
    /// v5.0.0 (T-LP4-005): Relay → Client — deliver a PATH_CHALLENGE from
    /// another endpoint, with relay's observed source address attached.
    PathChallengeDeliver = 15,
};

// ─── ECN Codepoint ───

enum class EcnCodepoint : uint8_t {
    None   = 0,  // no ECN info
    Ect0  = 1,   // ECN Capable Transport(0)
    Ect1  = 2,   // ECN Capable Transport(1)
    Ce    = 3,   // Congestion Experienced
};

// ─── Datagram payload ───

struct Datagram {
    base::EndpointId dst;            // destination (for Client→Relay) or source (for Relay→Client)
    EcnCodepoint     ecn = EcnCodepoint::None;
    std::vector<uint8_t> contents;   // actual payload data

    // Segment size for batched datagrams; 0 means not batched.
    // When > 0, contents contains multiple segments each of this size
    // (except possibly the last).
    uint16_t segment_size = 0;
};

// ─── v5.0.0 (T-LP4-005): Path Probe for Hard-NAT bidirectional hole punching ───

/// PATH_CHALLENGE 转发探测帧载荷。
///
/// 设计借鉴 iroh 1.0.0-rc.1 noq#672：双方对称 NAT 场景下，通过 relay
/// 中转 PATH_CHALLENGE，使对端能学习到发送方的反射地址（relay 观察到的
/// 公网 ip:port），从而提升直连成功率。
///
/// 线格式：
///   [EndpointId(32B)][ChallengeData(8B)][ObservedHostLen(1B)][ObservedHost(?B)][ObservedPort(2B,BE)]
///
/// - Client → Relay 方向：observed_host 为空（ObservedHostLen=0, ObservedPort=0）
/// - Relay → Client 方向：relay 填入观察到的源地址
struct PathProbe {
    base::EndpointId dst;                       ///< 目标 endpoint（Client→Relay）/ 源 endpoint（Relay→Client）
    std::array<uint8_t, 8> challenge_data{};    ///< PATH_CHALLENGE 8 字节数据
    /// Relay 观察到的源地址（仅 Relay→Client 方向填充）
    std::string observed_host;
    uint16_t observed_port{0};

    static constexpr std::size_t kMaxObservedHostLen = 64;
};

// ─── Generic frame ───

struct Frame {
    FrameType type;
    std::vector<uint8_t> payload;  // raw payload after FrameType VarInt
};

// ─── Encoder ───

/// Encode a STRIDE frame: [VarInt(FrameType)][Payload]
inline std::vector<uint8_t> encode_frame(FrameType type, std::span<const uint8_t> payload) {
    std::vector<uint8_t> out;
    auto type_bytes = util::varint_encode_vec(static_cast<uint64_t>(type));
    out.reserve(type_bytes.size() + payload.size());
    out.insert(out.end(), type_bytes.begin(), type_bytes.end());
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

/// Encode a datagram payload: [EndpointId(32B)][ECN(1B)][SegmentSize(2B)][Contents]
inline std::vector<uint8_t> encode_datagram(const Datagram &dg) {
    std::vector<uint8_t> out;
    // EndpointId: 32 bytes, raw copy
    out.insert(out.end(), dg.dst.data(), dg.dst.data() + base::PublicKey::kSize);
    // ECN: 1 byte
    out.push_back(static_cast<uint8_t>(dg.ecn));
    // SegmentSize: always 2 bytes (big-endian); 0 = not batched
    out.push_back(static_cast<uint8_t>((dg.segment_size >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(dg.segment_size & 0xFF));
    // Contents
    out.insert(out.end(), dg.contents.begin(), dg.contents.end());
    return out;
}

/// Encode a complete ClientToRelay datagram frame.
inline std::vector<uint8_t> encode_client_to_relay_datagram(const Datagram &dg) {
    auto payload = encode_datagram(dg);
    return encode_frame(FrameType::ClientToRelayDatagram, payload);
}

/// Encode a complete RelayToClient datagram frame.
inline std::vector<uint8_t> encode_relay_to_client_datagram(const Datagram &dg) {
    auto payload = encode_datagram(dg);
    return encode_frame(FrameType::RelayToClientDatagram, payload);
}

// ─── v5.0.0 (T-LP4-005): Path Probe encode/decode ───

/// Encode a PathProbe payload:
/// [EndpointId(32B)][ChallengeData(8B)][ObservedHostLen(1B)][ObservedHost(?B)][ObservedPort(2B,BE)]
inline std::vector<uint8_t> encode_path_probe(const PathProbe &pp) {
    std::vector<uint8_t> out;
    // EndpointId: 32 bytes
    out.insert(out.end(), pp.dst.data(), pp.dst.data() + base::PublicKey::kSize);
    // ChallengeData: 8 bytes
    out.insert(out.end(), pp.challenge_data.begin(), pp.challenge_data.end());
    // ObservedHostLen: 1 byte (clamped to kMaxObservedHostLen)
    auto host_len = static_cast<uint8_t>(
        (std::min)(pp.observed_host.size(), PathProbe::kMaxObservedHostLen));
    out.push_back(host_len);
    // ObservedHost: variable
    out.insert(out.end(), pp.observed_host.data(),
               pp.observed_host.data() + host_len);
    // ObservedPort: 2 bytes big-endian
    out.push_back(static_cast<uint8_t>((pp.observed_port >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(pp.observed_port & 0xFF));
    return out;
}

/// Decode a PathProbe payload into PathProbe struct.
/// Returns nullopt on malformed input.
inline std::optional<PathProbe> decode_path_probe(std::span<const uint8_t> payload) {
    constexpr std::size_t kFixedHeader = base::PublicKey::kSize + 8 + 1;  // 32 + 8 + 1 = 41
    if (payload.size() < kFixedHeader) return std::nullopt;

    PathProbe pp;
    // EndpointId: 32 bytes
    std::memcpy(pp.dst.data(), payload.data(), base::PublicKey::kSize);
    // ChallengeData: 8 bytes
    std::memcpy(pp.challenge_data.data(),
                payload.data() + base::PublicKey::kSize, 8);
    // ObservedHostLen: 1 byte
    auto host_len = static_cast<std::size_t>(payload[base::PublicKey::kSize + 8]);
    if (host_len > PathProbe::kMaxObservedHostLen) return std::nullopt;
    // Check total size: fixed header + host_len + 2 (port)
    if (payload.size() < kFixedHeader + host_len + 2) return std::nullopt;
    // ObservedHost: variable
    if (host_len > 0) {
        pp.observed_host.assign(
            payload.data() + kFixedHeader,
            payload.data() + kFixedHeader + host_len);
    }
    // ObservedPort: 2 bytes big-endian
    std::size_t port_off = kFixedHeader + host_len;
    pp.observed_port = (static_cast<uint16_t>(payload[port_off]) << 8) |
                       static_cast<uint16_t>(payload[port_off + 1]);
    return pp;
}

/// Encode a complete PathChallengeForward frame (Client → Relay).
inline std::vector<uint8_t> encode_path_challenge_forward(const PathProbe &pp) {
    auto payload = encode_path_probe(pp);
    return encode_frame(FrameType::PathChallengeForward, payload);
}

/// Encode a complete PathChallengeDeliver frame (Relay → Client).
inline std::vector<uint8_t> encode_path_challenge_deliver(const PathProbe &pp) {
    auto payload = encode_path_probe(pp);
    return encode_frame(FrameType::PathChallengeDeliver, payload);
}

/// Encode a Ping frame. Payload is 8 bytes (typically timestamp).
inline std::vector<uint8_t> encode_ping(std::span<const uint8_t, 8> ping_payload) {
    return encode_frame(FrameType::Ping, ping_payload);
}

/// Encode a Pong frame. Payload mirrors the received Ping payload (8 bytes).
inline std::vector<uint8_t> encode_pong(std::span<const uint8_t, 8> pong_payload) {
    return encode_frame(FrameType::Pong, pong_payload);
}

// ─── Decoder ───

/// Decode a STRIDE frame from raw bytes. Returns Frame or nullopt.
///
/// v1.7.0.5 P4 (C8): 加 FrameType 有效性校验（借鉴 iroh #4389 v1.0.2）
/// 未知/非法 FrameType 值会导致 switch 无法匹配，虽不会崩溃但会消耗解析资源。
/// 此处拒绝明显非法的 type_val，避免恶意构造的帧进入处理流程。
inline std::optional<Frame> decode_frame(std::span<const uint8_t> data) {
    auto hdr = util::varint_decode(data);
    if (!hdr) return std::nullopt;
    auto [type_val, consumed] = *hdr;

    // v1.7.0.5 P4 (C8): FrameType 有效性校验
    // 已知 FrameType 范围：0-15（v5.0.0 新增 14=PathChallengeForward, 15=PathChallengeDeliver）
    // 11 是 gap（iroh 协议保留），允许 0-15 范围内的值通过（即使 11 也容忍）
    constexpr uint64_t kMaxKnownFrameType = 15;
    if (type_val > kMaxKnownFrameType) return std::nullopt;

    if (consumed >= data.size()) {
        // Frame with empty payload
        return Frame{static_cast<FrameType>(type_val), {}};
    }
    std::vector<uint8_t> payload(data.begin() + consumed, data.end());
    return Frame{static_cast<FrameType>(type_val), payload};
}

/// Decode a datagram payload into Datagram struct.
/// For Client→Relay: dst is the destination endpoint.
/// For Relay→Client: dst is the source endpoint.
/// Format: [EndpointId(32B)][ECN(1B)][SegmentSize(2B)][Contents]
///
/// v1.7.0.5 P4 (C8): 加 datagram 总大小上限校验（借鉴 iroh #4389 v1.0.2）
/// 防止恶意构造的超大 contents 导致 relay 内存膨胀。
/// 单个 datagram contents 上限 1MB（远超正常推理 hidden_state 单帧大小）。
inline std::optional<Datagram> decode_datagram(std::span<const uint8_t> payload) {
    const std::size_t kFixedHeader = base::PublicKey::kSize + 1 + 2;  // 32B + 1B + 2B = 35
    // v1.7.0.5 P4 (C8): datagram 总大小上限 1MB + 35B header
    constexpr std::size_t kMaxDatagramSize = 1 * 1024 * 1024 + 35;
    if (payload.size() < kFixedHeader) return std::nullopt;
    if (payload.size() > kMaxDatagramSize) return std::nullopt;

    Datagram dg;
    // EndpointId: 32 bytes
    std::memcpy(dg.dst.data(), payload.data(), base::PublicKey::kSize);

    // ECN: 1 byte at offset 32
    dg.ecn = static_cast<EcnCodepoint>(payload[base::PublicKey::kSize]);

    // SegmentSize: 2 bytes (big-endian) at offset 33
    dg.segment_size = (static_cast<uint16_t>(payload[base::PublicKey::kSize + 1]) << 8) |
                       static_cast<uint16_t>(payload[base::PublicKey::kSize + 2]);

    // Contents: remaining bytes after fixed header
    if (kFixedHeader < payload.size()) {
        dg.contents.assign(payload.begin() + kFixedHeader, payload.end());
    }
    return dg;
}

/// Decode a Ping/Pong payload (8 bytes).
inline std::optional<std::array<uint8_t, 8>> decode_ping_pong_payload(std::span<const uint8_t> payload) {
    if (payload.size() != 8) return std::nullopt;
    std::array<uint8_t, 8> arr{};
    std::memcpy(arr.data(), payload.data(), 8);
    return arr;
}

}  // namespace linoh::relay
