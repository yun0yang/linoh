#pragma once

// linoh TLS 1.3-style handshake messages (compact, QUIC-framed).
//
// Wire framing per message:  [type:1][varint body_len][body...]
//
// Bodies:
//   ClientHello / ServerHello:
//     random[32] | x25519_ephemeral_pub[32] | node_ed25519_pub[32] |
//     varint(alpn_len) | alpn[alpn_len] | varint(preferred_mtu)?  [v1.5.0.2 Step 3]
//   CertVerify:  signature[64]           (Ed25519 over signed_content(transcript))
//   Finished:    verify_data[32]         (HMAC finished, see key_schedule)
//
// v1.5.0.2 Step 3 changes:
//   - Hello struct added preferred_mtu field (default 1280)
//   - encode_hello appends varint(mtu) after alpn
//   - decode_hello: if alpn_off + alpn_len < blen, the remaining bytes are parsed
//     as a varint preferred_mtu; otherwise preferred_mtu defaults to 1280
//   - Backward compatibility: legacy clients (no mtu field) are accepted
//
// This module is purely structural (encode/decode + bounds checks). The
// "what to sign / verify" convention lives in signed_content(). Header-only.

#include "linoh/multimodal/channel.hpp"
#include "linoh/util/varint.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace linoh::tls {

enum class HsType : uint8_t {
    ClientHello = 1,
    ServerHello = 2,
    CertVerify  = 15,
    Finished    = 20,
};

struct Hello {
    std::array<uint8_t, 32> random{};
    std::array<uint8_t, 32> ephemeral{};  // X25519 ephemeral public key
    std::array<uint8_t, 32> node_pub{};   // Ed25519 node identity public key
    std::string alpn;
    std::uint16_t preferred_mtu{1280};  // v1.5.0.2 Step 3: 客户端期望 MTU
    multimodal::CryptoLevel preferred_crypto_level{  // v1.5.0.2 Step 4: 客户端期望最低 CryptoLevel
        multimodal::CryptoLevel::None};  // None 表示未指定（旧版节点）
};

struct CertVerify {
    std::array<uint8_t, 64> signature{};
};

struct Finished {
    std::array<uint8_t, 32> verify_data{};
};

// ---------------------------------------------------------------------------
// Signed content for CertVerify (TLS 1.3 §4.4.3 style: 64 spaces + label + 0 + TH).
// ---------------------------------------------------------------------------
inline std::vector<uint8_t> cert_verify_signed_content(
    std::span<const uint8_t> transcript_hash) {
    static const char kLabel[] = "linoh handshake node CertificateVerify";
    std::vector<uint8_t> c;
    c.insert(c.end(), 64, 0x20);  // 64 octets of 0x20
    c.insert(c.end(), kLabel, kLabel + (sizeof(kLabel) - 1));
    c.push_back(0x00);
    c.insert(c.end(), transcript_hash.begin(), transcript_hash.end());
    return c;
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------
namespace detail {
inline void put_body(std::vector<uint8_t> &out, HsType type,
                     const std::vector<uint8_t> &body) {
    out.push_back(static_cast<uint8_t>(type));
    auto len = util::varint_encode_vec(static_cast<uint64_t>(body.size()));
    out.insert(out.end(), len.begin(), len.end());
    out.insert(out.end(), body.begin(), body.end());
}
}  // namespace detail

inline std::vector<uint8_t> encode_hello(HsType type, const Hello &h) {
    std::vector<uint8_t> body;
    body.reserve(96 + 2 + h.alpn.size() + 2 + 1);  // +2 varint mtu, +1 crypto_level
    body.insert(body.end(), h.random.begin(), h.random.end());
    body.insert(body.end(), h.ephemeral.begin(), h.ephemeral.end());
    body.insert(body.end(), h.node_pub.begin(), h.node_pub.end());
    auto alpn_len = util::varint_encode_vec(static_cast<uint64_t>(h.alpn.size()));
    body.insert(body.end(), alpn_len.begin(), alpn_len.end());
    body.insert(body.end(), h.alpn.begin(), h.alpn.end());
    // v1.5.0.2 Step 3: 追加 preferred_mtu varint
    auto mtu_bytes = util::varint_encode_vec(static_cast<uint64_t>(h.preferred_mtu));
    body.insert(body.end(), mtu_bytes.begin(), mtu_bytes.end());
    // v1.5.0.2 Step 4: 追加 preferred_crypto_level (1 raw byte, 0-4)
    body.push_back(static_cast<uint8_t>(h.preferred_crypto_level));

    std::vector<uint8_t> out;
    detail::put_body(out, type, body);
    return out;
}

inline std::vector<uint8_t> encode_cert_verify(const CertVerify &cv) {
    std::vector<uint8_t> body(cv.signature.begin(), cv.signature.end());
    std::vector<uint8_t> out;
    detail::put_body(out, HsType::CertVerify, body);
    return out;
}

inline std::vector<uint8_t> encode_finished(const Finished &f) {
    std::vector<uint8_t> body(f.verify_data.begin(), f.verify_data.end());
    std::vector<uint8_t> out;
    detail::put_body(out, HsType::Finished, body);
    return out;
}

// ---------------------------------------------------------------------------
// Decoding — each returns {value, bytes_consumed} or nullopt.
// ---------------------------------------------------------------------------
inline std::optional<HsType> peek_type(std::span<const uint8_t> in) {
    if (in.empty()) return std::nullopt;
    switch (in[0]) {
    case 1:  return HsType::ClientHello;
    case 2:  return HsType::ServerHello;
    case 15: return HsType::CertVerify;
    case 20: return HsType::Finished;
    default: return std::nullopt;
    }
}

namespace detail {
// Parse [type][varint len] header, returning {body_offset, body_len} or nullopt.
inline std::optional<std::pair<std::size_t, std::size_t>> parse_header(
    std::span<const uint8_t> in, HsType expect) {
    if (in.empty() || in[0] != static_cast<uint8_t>(expect)) return std::nullopt;
    auto lv = util::varint_decode(in.subspan(1));
    if (!lv) return std::nullopt;
    std::size_t hdr = 1 + lv->second;
    std::size_t body_len = static_cast<std::size_t>(lv->first);
    if (in.size() < hdr + body_len) return std::nullopt;
    return std::make_pair(hdr, body_len);
}
}  // namespace detail

inline std::optional<std::pair<Hello, std::size_t>> decode_hello(
    std::span<const uint8_t> in, HsType expect) {
    if (expect != HsType::ClientHello && expect != HsType::ServerHello)
        return std::nullopt;
    auto hb = detail::parse_header(in, expect);
    if (!hb) return std::nullopt;
    auto [off, blen] = *hb;
    if (blen < 96) return std::nullopt;  // 3 * 32
    auto body = in.subspan(off, blen);

    Hello h;
    std::memcpy(h.random.data(), body.data() + 0, 32);
    std::memcpy(h.ephemeral.data(), body.data() + 32, 32);
    std::memcpy(h.node_pub.data(), body.data() + 64, 32);
    auto alpn_lv = util::varint_decode(body.subspan(96));
    if (!alpn_lv) return std::nullopt;
    std::size_t alpn_off = 96 + alpn_lv->second;
    std::size_t alpn_len = static_cast<std::size_t>(alpn_lv->first);
    if (alpn_off + alpn_len > blen) return std::nullopt;  // 放宽：≤ 而非 ==
    h.alpn.assign(reinterpret_cast<const char *>(body.data() + alpn_off), alpn_len);

    // v1.5.0.2 Step 3+4: alpn 后先 varint(preferred_mtu)，再可选 1 字节 (preferred_crypto_level)
    h.preferred_mtu = 1280;  // 默认值（向后兼容旧版无 mtu）
    h.preferred_crypto_level = multimodal::CryptoLevel::None;  // 默认未指定
    std::size_t tail_off = alpn_off + alpn_len;
    if (tail_off < blen) {
        // 1) 解析 mtu varint
        auto mtu_lv = util::varint_decode(body.subspan(tail_off));
        if (!mtu_lv) return std::nullopt;
        std::size_t mtu_consumed = mtu_lv->second;
        if (mtu_consumed == 0 || mtu_lv->first == 0 || mtu_lv->first > 9000) {
            return std::nullopt;  // MTU 非法
        }
        // tc-M6 (v1.7.0.8): RFC 9000 §14.1 — QUIC 最小 MTU 为 1280（IPv6 最小链路
        // MTU）。接受 <1280 的 MTU 会导致 PMTUD 失败、分片、或对端按过小 MTU 发包
        // 造成吞吐崩塌。
        if (mtu_lv->first < 1280) {
            return std::nullopt;  // MTU 低于 QUIC 最小值
        }
        h.preferred_mtu = static_cast<std::uint16_t>(mtu_lv->first);
        std::size_t after_mtu = tail_off + mtu_consumed;
        if (after_mtu < blen) {
            // 2) Step 4: 追加 1 字节 crypto_level
            if (after_mtu + 1 != blen) return std::nullopt;  // 残留多余字节
            std::uint8_t lv = body[after_mtu];
            if (lv > 4) return std::nullopt;  // 非法 CryptoLevel
            h.preferred_crypto_level = static_cast<multimodal::CryptoLevel>(lv);
        } else if (after_mtu != blen) {
            return std::nullopt;  // mtu 解析不完整
        }
    }
    return std::make_pair(std::move(h), off + blen);
}

inline std::optional<std::pair<CertVerify, std::size_t>> decode_cert_verify(
    std::span<const uint8_t> in) {
    auto hb = detail::parse_header(in, HsType::CertVerify);
    if (!hb) return std::nullopt;
    auto [off, blen] = *hb;
    if (blen != 64) return std::nullopt;
    CertVerify cv;
    std::memcpy(cv.signature.data(), in.data() + off, 64);
    return std::make_pair(cv, off + blen);
}

inline std::optional<std::pair<Finished, std::size_t>> decode_finished(
    std::span<const uint8_t> in) {
    auto hb = detail::parse_header(in, HsType::Finished);
    if (!hb) return std::nullopt;
    auto [off, blen] = *hb;
    if (blen != 32) return std::nullopt;
    Finished f;
    std::memcpy(f.verify_data.data(), in.data() + off, 32);
    return std::make_pair(f, off + blen);
}

}  // namespace linoh::tls
