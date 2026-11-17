// linoh/relay/ws_server.hpp — Minimal WebSocket SERVER helpers (RFC 6455)
//
// Mirror of ws_client.hpp but for the server side:
//  - Computes Sec-WebSocket-Accept (SHA1 + GUID) for the 101 response.
//  - Encodes UNMASKED frames (server -> client frames must not be masked).
//  - Parses the client's HTTP Upgrade request.
//
// Pure byte-level codec — no Asio dependency.

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace linoh::relay {

// ─── Minimal SHA1 (RFC 3174) ───
// Self-contained so the server does not depend on OpenSSL for the handshake.
inline void ws_sha1(const uint8_t *data, std::size_t len, uint8_t out[20]) {
    auto rol = [](uint32_t x, int n) -> uint32_t {
        return (x << n) | (x >> (32 - n));
    };

    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE,
             h3 = 0x10325476, h4 = 0xC3D2E1F0;

    // Pre-processing: padding
    uint64_t ml = static_cast<uint64_t>(len) * 8;
    std::vector<uint8_t> msg(data, data + len);
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; i--)
        msg.push_back(static_cast<uint8_t>((ml >> (i * 8)) & 0xFF));

    for (std::size_t i = 0; i < msg.size(); i += 64) {
        uint32_t w[80];
        for (int t = 0; t < 16; t++) {
            w[t] = (static_cast<uint32_t>(msg[i + 4 * t]) << 24) |
                   (static_cast<uint32_t>(msg[i + 4 * t + 1]) << 16) |
                   (static_cast<uint32_t>(msg[i + 4 * t + 2]) << 8) |
                   (static_cast<uint32_t>(msg[i + 4 * t + 3]));
        }
        for (int t = 16; t < 80; t++) {
            w[t] = rol(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
        }
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int t = 0; t < 80; t++) {
            uint32_t f, k;
            if (t < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (t < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (t < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t tmp = rol(a, 5) + f + e + k + w[t];
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = tmp;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    uint32_t hs[5] = {h0, h1, h2, h3, h4};
    for (int i = 0; i < 5; i++) {
        out[i * 4 + 0] = static_cast<uint8_t>((hs[i] >> 24) & 0xFF);
        out[i * 4 + 1] = static_cast<uint8_t>((hs[i] >> 16) & 0xFF);
        out[i * 4 + 2] = static_cast<uint8_t>((hs[i] >> 8) & 0xFF);
        out[i * 4 + 3] = static_cast<uint8_t>(hs[i] & 0xFF);
    }
}

/// Base64 encode (RFC 4648) — used for Sec-WebSocket-Accept.
inline std::string ws_base64(const uint8_t *data, std::size_t len) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (std::size_t i = 0; i < len; i += 3) {
        uint32_t n = (i < len ? data[i] : 0) << 16 |
                     (i + 1 < len ? data[i + 1] : 0) << 8 |
                     (i + 2 < len ? data[i + 2] : 0);
        out += tbl[(n >> 18) & 0x3F];
        out += tbl[(n >> 12) & 0x3F];
        out += (i + 1 < len) ? tbl[(n >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? tbl[n & 0x3F] : '=';
    }
    return out;
}

/// Sec-WebSocket-Accept = base64(SHA1(client_key + GUID)).
inline std::string ws_compute_accept_key(const std::string &client_key) {
    constexpr char kGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string concat = client_key + kGuid;
    uint8_t digest[20];
    ws_sha1(reinterpret_cast<const uint8_t *>(concat.data()), concat.size(),
            digest);
    return ws_base64(digest, 20);
}

/// Build the 101 Switching Protocols response.
inline std::string ws_build_handshake_response(
    const std::string &client_key, const std::string &protocol = "iroh-relay-v2") {
    std::string accept = ws_compute_accept_key(client_key);
    std::string resp = "HTTP/1.1 101 Switching Protocols\r\n";
    resp += "Upgrade: websocket\r\n";
    resp += "Connection: Upgrade\r\n";
    resp += "Sec-WebSocket-Accept: " + accept + "\r\n";
    resp += "Sec-WebSocket-Protocol: " + protocol + "\r\n";
    resp += "\r\n";
    return resp;
}

/// Parse a client HTTP Upgrade request.
/// Extracts Sec-WebSocket-Key and Sec-WebSocket-Protocol (if present).
/// Returns false if it is not a recognizable WebSocket upgrade request.
inline bool ws_parse_handshake_request(std::span<const uint8_t> data,
                                       std::string &out_key,
                                       std::string &out_protocol) {
    std::string s(data.begin(), data.end());
    if (s.find("GET ") == std::string::npos) return false;
    if (s.find("Upgrade: websocket") == std::string::npos &&
        s.find("Upgrade: WebSocket") == std::string::npos)
        return false;

    auto extract = [&](const char *header, std::string &out) -> bool {
        auto pos = s.find(header);
        if (pos == std::string::npos) return false;
        auto start = s.find_first_not_of(" \t", pos + std::strlen(header));
        if (start == std::string::npos) return false;
        auto end = s.find("\r\n", start);
        if (end == std::string::npos) end = s.find("\n", start);
        if (end == std::string::npos) end = s.size();
        out = s.substr(start, end - start);
        while (!out.empty() && (out.back() == '\r' || out.back() == '\n' ||
                                out.back() == ' '))
            out.pop_back();
        return true;
    };

    if (!extract("Sec-WebSocket-Key:", out_key)) return false;
    extract("Sec-WebSocket-Protocol:", out_protocol);
    return true;
}

// ─── Server -> Client frame encoders (UNMASKED) ───

inline std::vector<uint8_t> ws_encode_binary_frame_unmasked(
    std::span<const uint8_t> payload) {
    std::vector<uint8_t> frame;
    frame.push_back(0x82);  // FIN=1, opcode=Binary
    const std::size_t len = payload.size();
    if (len < 126) {
        frame.push_back(static_cast<uint8_t>(len));
    } else if (len < 65536) {
        frame.push_back(126);
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; i--)
            frame.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
    }
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

inline std::vector<uint8_t> ws_encode_ping_frame_unmasked(
    std::span<const uint8_t> payload = {}) {
    std::vector<uint8_t> frame;
    frame.push_back(0x89);  // FIN=1, opcode=Ping
    const std::size_t len = payload.size();
    if (len < 126) {
        frame.push_back(static_cast<uint8_t>(len));
    } else {
        frame.push_back(126);
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
    }
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

inline std::vector<uint8_t> ws_encode_pong_frame_unmasked(
    std::span<const uint8_t> payload = {}) {
    std::vector<uint8_t> frame;
    frame.push_back(0x8A);  // FIN=1, opcode=Pong
    const std::size_t len = payload.size();
    if (len < 126) {
        frame.push_back(static_cast<uint8_t>(len));
    } else {
        frame.push_back(126);
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
    }
    frame.insert(frame.end(), payload.begin(), payload.end());
    return frame;
}

inline std::vector<uint8_t> ws_encode_close_frame_unmasked(
    uint16_t code, std::span<const uint8_t> reason = {}) {
    std::vector<uint8_t> frame;
    frame.push_back(0x88);  // FIN=1, opcode=Close
    const std::size_t len = 2 + reason.size();
    if (len < 126) {
        frame.push_back(static_cast<uint8_t>(len));
    } else {
        frame.push_back(126);
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
    }
    frame.push_back(static_cast<uint8_t>((code >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(code & 0xFF));
    frame.insert(frame.end(), reason.begin(), reason.end());
    return frame;
}

}  // namespace linoh::relay
