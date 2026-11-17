// linoh/relay/ws_client.hpp — Minimal WebSocket client for iroh relay v2
//
// Implements RFC 6455 WebSocket protocol over raw TCP (using linoh's Asio).
// Only supports binary frames (iroh relay uses binary STRIDE frames).
// Does NOT implement TLS — for wss://, wrap in TLS separately (Phase 3).
//
// Handshake: HTTP Upgrade + Sec-WebSocket-Protocol: "iroh-relay-v2"
// Frame format (RFC 6455 §5.2):
//   [FIN(1)][RSV1-3(3)][opcode(4)][MASK(1)][payload_len(7/16/64)][mask_key(0/4B)][payload]

#pragma once

#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <vector>

#include "linoh/util/varint.hpp"

// ws_client.hpp is pure byte-level codec — no Asio dependency.
// Asio is used only in client.hpp / client.cpp for the TCP socket.

namespace linoh::relay {

// ─── WebSocket Frame Opcodes (RFC 6455 §5.2) ───

enum class WsOpcode : uint8_t {
    Continuation = 0x0,
    Text         = 0x1,
    Binary       = 0x2,
    Close        = 0x8,
    Ping         = 0x9,
    Pong         = 0xA,
};

// ─── WebSocket Frame Encoder ───

/// Encode a WebSocket binary frame (FIN=1, no fragmentation).
/// Client frames MUST be masked per RFC 6455 §5.3.
inline std::vector<uint8_t> ws_encode_binary_frame(std::span<const uint8_t> payload) {
    std::vector<uint8_t> frame;

    // Byte 1: FIN=1, RSV1-3=0, opcode=Binary(0x02)
    frame.push_back(0x82);  // 1000 0010

    // Byte 2: MASK=1, payload_len
    const std::size_t len = payload.size();
    if (len < 126) {
        frame.push_back(static_cast<uint8_t>(0x80 | len));  // MASK bit + 7-bit length
    } else if (len < 65536) {
        frame.push_back(0x80 | 126);  // MASK bit + 16-bit length indicator
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        frame.push_back(0x80 | 127);  // MASK bit + 64-bit length indicator
        // 64-bit length (big-endian), but only use lower 32 bits for practicality
        for (int i = 7; i >= 0; i--) {
            frame.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
        }
    }

    // Masking key: 4 random bytes
    std::array<uint8_t, 4> mask_key;
    std::random_device rd;
    for (int i = 0; i < 4; i++) mask_key[i] = static_cast<uint8_t>(rd());

    frame.insert(frame.end(), mask_key.begin(), mask_key.end());

    // Masked payload: payload[i] XOR mask_key[i % 4]
    for (std::size_t i = 0; i < len; i++) {
        frame.push_back(payload[i] ^ mask_key[i % 4]);
    }

    return frame;
}

/// Encode a WebSocket Ping frame (masked, per RFC 6455).
inline std::vector<uint8_t> ws_encode_ping_frame(std::span<const uint8_t> payload = {}) {
    std::vector<uint8_t> frame;

    // FIN=1, opcode=Ping(0x09)
    frame.push_back(0x89);  // 1000 1001

    // MASK=1, payload_len
    const std::size_t len = payload.size();
    frame.push_back(static_cast<uint8_t>(0x80 | len));

    // Masking key
    std::array<uint8_t, 4> mask_key;
    std::random_device rd;
    for (int i = 0; i < 4; i++) mask_key[i] = static_cast<uint8_t>(rd());
    frame.insert(frame.end(), mask_key.begin(), mask_key.end());

    // Masked payload
    for (std::size_t i = 0; i < len; i++) {
        frame.push_back(payload[i] ^ mask_key[i % 4]);
    }

    return frame;
}

/// Encode a WebSocket Pong frame (masked, per RFC 6455).
inline std::vector<uint8_t> ws_encode_pong_frame(std::span<const uint8_t> payload = {}) {
    std::vector<uint8_t> frame;

    // FIN=1, opcode=Pong(0x0A)
    frame.push_back(0x8A);

    // MASK=1, payload_len
    const std::size_t len = payload.size();
    frame.push_back(static_cast<uint8_t>(0x80 | len));

    // Masking key
    std::array<uint8_t, 4> mask_key;
    std::random_device rd;
    for (int i = 0; i < 4; i++) mask_key[i] = static_cast<uint8_t>(rd());
    frame.insert(frame.end(), mask_key.begin(), mask_key.end());

    // Masked payload
    for (std::size_t i = 0; i < len; i++) {
        frame.push_back(payload[i] ^ mask_key[i % 4]);
    }

    return frame;
}

// ─── WebSocket Frame Decoder ───

struct WsFrame {
    WsOpcode opcode;
    bool fin;
    std::vector<uint8_t> payload;  // unmasked
};

/// v1.7.0.6: ws_decode_frame 错误类型
/// 区分"数据不足（继续等待）"与"非法帧（关闭连接）"
enum class WsDecodeError {
    NeedMoreData,      // 数据不足，继续等待更多字节
    InvalidFrame,      // 非法帧（payload 超大 / opcode 非法等），应关闭连接
};

/// v1.7.0.6: ws_decode_frame 返回类型
/// - 成功：{WsFrame, bytes_consumed}
/// - NeedMoreData：数据不足，调用方应继续累积
/// - InvalidFrame：非法帧，调用方应关闭连接（C8 防御生效）
struct WsDecodeResult {
    bool ok = false;
    bool need_more = false;       // true = 数据不足，继续等待
    bool invalid = false;         // true = 非法帧，关闭连接
    WsFrame frame;
    std::size_t bytes_consumed = 0;
};

/// Decode a WebSocket frame from raw bytes.
/// v1.7.0.6: 修复 C5 — 区分"数据不足"与"非法帧"
/// 之前两者都返回 nullopt，导致 C8 防御被绕过（恶意超大 payload 帧被当作数据不足，
/// 缓冲区无限增长）。现在非法帧返回 invalid=true，调用方应关闭连接。
///
/// v1.7.0.5 P4 (C8): 加 payload_len 上限防御
/// 恶意客户端可声明超大 payload_len（最大 2^64-1）导致 frame.payload.resize()
/// 内存耗尽。限制为 16MB 足够所有合法 relay 帧（datagram 最大 ~64KB）。
inline WsDecodeResult ws_decode_frame(std::span<const uint8_t> data) {
    // v1.7.0.5 P4 (C8): 单帧 payload 上限 16MB（防御内存耗尽攻击）
    constexpr uint64_t kMaxWsPayloadLen = 16 * 1024 * 1024;

    WsDecodeResult result;

    if (data.size() < 2) { result.need_more = true; return result; }

    // Byte 1: FIN + RSV1-3 + opcode
    bool fin = (data[0] & 0x80) != 0;
    WsOpcode opcode = static_cast<WsOpcode>(data[0] & 0x0F);

    // Byte 2: MASK + payload_len
    bool masked = (data[1] & 0x80) != 0;
    uint64_t payload_len = data[1] & 0x7F;

    std::size_t header_size = 2;

    if (payload_len == 126) {
        // 16-bit length
        if (data.size() < 4) { result.need_more = true; return result; }
        payload_len = (static_cast<uint64_t>(data[2]) << 8) |
                       static_cast<uint64_t>(data[3]);
        header_size = 4;
    } else if (payload_len == 127) {
        // 64-bit length
        if (data.size() < 10) { result.need_more = true; return result; }
        payload_len = 0;
        for (int i = 0; i < 8; i++) {
            payload_len = (payload_len << 8) | data[2 + i];
        }
        header_size = 10;
    }

    // v1.7.0.5 P4 (C8): 拒绝超大 payload（防御内存耗尽攻击）
    // v1.7.0.6 (C5 fix): 非法帧返回 invalid=true（之前返回 nullopt 被当作数据不足）
    if (payload_len > kMaxWsPayloadLen) { result.invalid = true; return result; }

    // Masking key (4 bytes) if masked
    if (masked) {
        header_size += 4;
    }

    // Check we have enough data
    if (data.size() < header_size + payload_len) { result.need_more = true; return result; }

    // Extract mask key
    std::array<uint8_t, 4> mask_key = {};
    if (masked) {
        std::memcpy(mask_key.data(), data.data() + header_size - 4, 4);
    }

    // Unmask payload
    result.frame.opcode = opcode;
    result.frame.fin = fin;
    result.frame.payload.resize(payload_len);
    for (uint64_t i = 0; i < payload_len; i++) {
        uint8_t raw_byte = data[header_size + i];
        result.frame.payload[i] = masked ? (raw_byte ^ mask_key[i % 4]) : raw_byte;
    }

    result.ok = true;
    result.bytes_consumed = header_size + payload_len;
    return result;
}

// ─── WebSocket HTTP Upgrade Handshake ───

/// Build the HTTP Upgrade request for WebSocket handshake.
/// iroh relay v2 uses Sec-WebSocket-Protocol: "iroh-relay-v2".
inline std::string ws_build_handshake_request(const std::string &host,
                                                const std::string &path = "/",
                                                const std::string &port = "443") {
    // Generate a 16-byte Sec-WebSocket-Key (base64-encoded)
    std::random_device rd;
    std::array<uint8_t, 16> key_bytes;
    for (int i = 0; i < 16; i++) key_bytes[i] = static_cast<uint8_t>(rd());

    // Base64 encode (simple inline implementation). 16 bytes -> 5 full
    // 3-byte groups + 1 trailing byte, emitted with standard '=' padding.
    static constexpr char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string key_b64;
    for (int i = 0; i < 16; i += 3) {
        uint8_t b0 = key_bytes[i];
        uint8_t b1 = (i + 1 < 16) ? key_bytes[i + 1] : 0;
        uint8_t b2 = (i + 2 < 16) ? key_bytes[i + 2] : 0;
        uint32_t n = (static_cast<uint32_t>(b0) << 16) |
                     (static_cast<uint32_t>(b1) << 8) |
                     static_cast<uint32_t>(b2);
        key_b64 += b64[(n >> 18) & 0x3F];
        key_b64 += b64[(n >> 12) & 0x3F];
        if (i + 1 < 16) key_b64 += b64[(n >> 6) & 0x3F];
        else key_b64 += '=';
        if (i + 2 < 16) key_b64 += b64[n & 0x3F];
        else key_b64 += '=';
    }

    std::string req;
    req += "GET " + path + " HTTP/1.1\r\n";
    req += "Host: " + host + ":" + port + "\r\n";
    req += "Upgrade: websocket\r\n";
    req += "Connection: Upgrade\r\n";
    req += "Sec-WebSocket-Key: " + key_b64 + "\r\n";
    req += "Sec-WebSocket-Version: 13\r\n";
    req += "Sec-WebSocket-Protocol: iroh-relay-v2\r\n";
    req += "\r\n";
    return req;
}

/// Validate a WebSocket handshake response from the server.
/// Returns true if the response is a valid 101 Switching Protocols.
inline bool ws_validate_handshake_response(std::span<const uint8_t> response) {
    // Convert to string for header parsing
    std::string resp(response.begin(), response.end());

    // Check HTTP status line: "HTTP/1.1 101"
    if (resp.find("HTTP/1.1 101") == std::string::npos &&
        resp.find("HTTP/1.0 101") == std::string::npos) {
        return false;
    }

    // Check Upgrade: websocket
    if (resp.find("Upgrade: websocket") == std::string::npos &&
        resp.find("Upgrade: WebSocket") == std::string::npos) {
        return false;
    }

    // Check Connection: Upgrade
    if (resp.find("Connection: Upgrade") == std::string::npos &&
        resp.find("Connection: upgrade") == std::string::npos) {
        return false;
    }

    // Check that response ends with \r\n\r\n
    if (resp.find("\r\n\r\n") == std::string::npos) {
        return false;
    }

    return true;
}

/// Extract the size of the HTTP response headers (up to \r\n\r\n).
/// Returns the position after \r\n\r\n, or 0 if headers are incomplete.
inline std::size_t ws_http_header_end(std::span<const uint8_t> data) {
    std::string s(data.begin(), data.end());
    auto pos = s.find("\r\n\r\n");
    if (pos == std::string::npos) return 0;
    return pos + 4;
}

}  // namespace linoh::relay
