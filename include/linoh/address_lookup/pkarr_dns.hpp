// linoh/address_lookup/pkarr_dns.hpp — Pkarr DNS wire format encoding/decoding
//
// Pkarr uses DNS wire format (RFC 1035) to encode node addresses:
// - SRV records for relay servers (priority, weight, port, target)
// - TXT records for direct addresses and metadata
// - The entire DNS packet is signed with Ed25519 (RFC 8032)
//
// Wire format:
//   [DNS Header(12B)][Question section][Answer section]
//   Question: _iroh._tcp.<public-key-hex> IN SRV
//   Answers:  SRV records (relay URLs), TXT records (direct addresses)
//
// Signing:
//   [Ed25519 signature(64B)][DNS packet bytes]
//   The signature covers the DNS packet bytes only.
//
// Reference: iroh-base/src/pkarr.rs, pkarr crate

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "linoh/base/endpoint_addr.hpp"  // EndpointAddr, RelayUrl, TransportAddr
#include "linoh/base/key.hpp"       // EndpointId, SecretKey, PublicKey

namespace linoh::address_lookup::pkarr {

// ─── DNS wire format constants ───

/// DNS record types (RFC 1035)
enum class DnsRecordType : uint16_t {
    A     = 1,     // IPv4 address
    SRV   = 33,    // Service location (RFC 2782)
    TXT   = 16,    // Text strings
};

/// DNS class
enum class DnsClass : uint16_t {
    Internet = 1,  // Internet (avoid clash with Windows IN macro from winsock2.h)
};

/// Pkarr signed packet: [signature(64B)][dns_packet]
struct SignedPacket {
    std::array<uint8_t, 64> signature{};   // Ed25519 signature
    std::vector<uint8_t> dns_packet;       // DNS wire format packet
};

// ─── DNS wire format encoder ───

/// Encode a DNS name in wire format (label sequence).
/// e.g., "example.com" → [7][example][3][com][0]
inline std::vector<uint8_t> encode_dns_name(const std::string &name) {
    std::vector<uint8_t> out;
    std::size_t pos = 0;
    while (pos < name.size()) {
        auto dot = name.find('.', pos);
        auto len = (dot == std::string::npos) ? (name.size() - pos) : (dot - pos);
        if (len > 63) len = 63;  // DNS label max 63 bytes
        out.push_back(static_cast<uint8_t>(len));
        out.insert(out.end(), name.begin() + pos, name.begin() + pos + len);
        pos += len + 1;  // skip the dot
    }
    out.push_back(0);  // root label terminator
    return out;
}

/// Encode a DNS header (12 bytes).
inline std::vector<uint8_t> encode_dns_header(uint16_t id, uint16_t flags,
                                                uint16_t qdcount, uint16_t ancount,
                                                uint16_t nscount = 0, uint16_t arcount = 0) {
    std::vector<uint8_t> hdr(12);
    // ID (2B)
    hdr[0] = static_cast<uint8_t>((id >> 8) & 0xFF);
    hdr[1] = static_cast<uint8_t>(id & 0xFF);
    // Flags (2B)
    hdr[2] = static_cast<uint8_t>((flags >> 8) & 0xFF);
    hdr[3] = static_cast<uint8_t>(flags & 0xFF);
    // Counts (2B each)
    hdr[4] = static_cast<uint8_t>((qdcount >> 8) & 0xFF);
    hdr[5] = static_cast<uint8_t>(qdcount & 0xFF);
    hdr[6] = static_cast<uint8_t>((ancount >> 8) & 0xFF);
    hdr[7] = static_cast<uint8_t>(ancount & 0xFF);
    hdr[8] = static_cast<uint8_t>((nscount >> 8) & 0xFF);
    hdr[9] = static_cast<uint8_t>(nscount & 0xFF);
    hdr[10] = static_cast<uint8_t>((arcount >> 8) & 0xFF);
    hdr[11] = static_cast<uint8_t>(arcount & 0xFF);
    return hdr;
}

/// Encode a DNS SRV record (RFC 2782).
/// Wire format: [priority(2B)][weight(2B)][port(2B)][target DNS name]
inline std::vector<uint8_t> encode_srv_rdata(uint16_t priority, uint16_t weight,
                                               uint16_t port, const std::string &target) {
    std::vector<uint8_t> rdata;
    rdata.push_back(static_cast<uint8_t>((priority >> 8) & 0xFF));
    rdata.push_back(static_cast<uint8_t>(priority & 0xFF));
    rdata.push_back(static_cast<uint8_t>((weight >> 8) & 0xFF));
    rdata.push_back(static_cast<uint8_t>(weight & 0xFF));
    rdata.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    rdata.push_back(static_cast<uint8_t>(port & 0xFF));
    auto name = encode_dns_name(target);
    rdata.insert(rdata.end(), name.begin(), name.end());
    return rdata;
}

/// Encode a DNS TXT record.
/// Wire format: [length byte][text bytes]... (one or more character-string)
inline std::vector<uint8_t> encode_txt_rdata(const std::string &text) {
    std::vector<uint8_t> rdata;
    // Split into 255-byte chunks (DNS TXT character-string limit)
    std::size_t pos = 0;
    while (pos < text.size()) {
        auto chunk_len = std::min(text.size() - pos, static_cast<std::size_t>(255));
        rdata.push_back(static_cast<uint8_t>(chunk_len));
        rdata.insert(rdata.end(), text.begin() + pos, text.begin() + pos + chunk_len);
        pos += chunk_len;
    }
    // Empty TXT record: single empty character-string
    if (rdata.empty()) rdata.push_back(0);
    return rdata;
}

// ─── DNS wire format decoder（新增：查询/响应解析） ───

namespace detail {

/// 读 DNS name（支持压缩指针），返回点分字符串并推进 pos；越界/环回返回 nullopt。
inline std::optional<std::string> read_name(std::span<const uint8_t> pkt, std::size_t &pos) {
    std::string out;
    std::size_t hops = 0;
    std::size_t save = 0;
    std::size_t p = pos;
    bool jumped = false;
    while (true) {
        if (p >= pkt.size()) return std::nullopt;
        uint8_t len = pkt[p];
        if (len == 0) { p++; break; }
        if ((len & 0xC0) == 0xC0) {  // 压缩指针
            if (p + 1 >= pkt.size()) return std::nullopt;
            uint16_t ptr = static_cast<uint16_t>(((len & 0x3F) << 8) | pkt[p + 1]);
            if (!jumped) { save = p + 2; jumped = true; }
            p = ptr;
            if (++hops > 12) return std::nullopt;
            continue;
        }
        if ((len & 0xC0) != 0) return std::nullopt;  // 其它保留类型
        if (p + 1 + len > pkt.size()) return std::nullopt;
        if (!out.empty()) out.push_back('.');
        for (uint8_t i = 0; i < len; i++) out.push_back(static_cast<char>(pkt[p + 1 + i]));
        p += 1 + len;
    }
    pos = jumped ? save : p;
    return out;
}

}  // namespace detail

/// 计算节点的 Pkarr SRV 查询名："_iroh._tcp.<hex>.iroh"（64 hex 拆为 63+1 两标签）。
/// 与 `build_pkarr_dns_packet` 内部使用的 QNAME 完全一致，保证 round-trip。
inline std::string pkarr_srv_qname(const base::EndpointId &node_id) {
    std::string pk_hex;
    char buf[3];
    for (std::size_t i = 0; i < base::PublicKey::kSize; i++) {
        std::snprintf(buf, sizeof(buf), "%02x", node_id.data()[i]);
        pk_hex += buf;
    }
    std::string label1 = pk_hex.substr(0, 63);
    std::string label2 = pk_hex.substr(63);
    return "_iroh._tcp." + label1 + "." + label2 + ".iroh";
}

/// 从 QNAME（"_iroh._tcp.<hex>.iroh" 或 "<hex>.iroh"）还原 NodeId；失败返回 nullopt。
inline std::optional<base::EndpointId> node_id_from_qname(std::string_view qname) {
    std::string s(qname);
    // 去掉末尾 ".iroh"
    const std::string suffix = ".iroh";
    if (s.size() >= suffix.size() &&
        s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0) {
        s = s.substr(0, s.size() - suffix.size());
    } else {
        return std::nullopt;
    }
    // 去掉可选前缀 "_iroh._tcp."
    const std::string prefix = "_iroh._tcp.";
    if (s.compare(0, prefix.size(), prefix) == 0) {
        s = s.substr(prefix.size());
    }
    // 去掉中间的点拼接为 64 hex
    std::string hex;
    for (char c : s) if (c != '.') hex.push_back(c);
    if (hex.size() != 64) return std::nullopt;
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::array<uint8_t, 32> bytes{};
    for (std::size_t i = 0; i < 32; i++) {
        int hi = hexval(hex[i * 2]), lo = hexval(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return base::EndpointId::from_bytes(bytes);
}

/// Build a complete DNS response packet for Pkarr publishing.
/// Includes question section + answer section with SRV and TXT records.
inline std::vector<uint8_t> build_pkarr_dns_packet(
    const base::EndpointId &node_id,
    const std::vector<std::string> &relay_hosts,   // relay server hostnames (e.g., "relay.iroh.link")
    const std::vector<uint16_t> &relay_ports,       // relay server ports
    const std::vector<std::string> &direct_addrs,   // direct addresses (e.g., "1.2.3.4:12345")
    uint16_t dns_id = 0) {

    // Pkarr domain: <public-key-hex>.iroh （与 pkarr_srv_qname 保持一致，保证 round-trip）
    std::string srv_qname = pkarr_srv_qname(node_id);
    std::string qname = srv_qname.substr(std::string("_iroh._tcp.").size());

    // ─── Header ───
    // Flags: QR=1 (response), Opcode=0, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
    uint16_t flags = 0x8000;  // QR=1
    uint16_t ancount = static_cast<uint16_t>(relay_hosts.size() + direct_addrs.size());
    auto header = encode_dns_header(dns_id, flags, 1, ancount);

    // ─── Question section ───
    auto question_name = encode_dns_name(srv_qname);
    // QTYPE = SRV (33), QCLASS = IN (1)
    std::vector<uint8_t> question_type_class(4);
    question_type_class[0] = 0;
    question_type_class[1] = static_cast<uint8_t>(DnsRecordType::SRV);
    question_type_class[2] = 0;
    question_type_class[3] = static_cast<uint8_t>(DnsClass::Internet);

    // ─── Answer section ───
    std::vector<uint8_t> answers;

    // SRV records for relay servers
    for (std::size_t i = 0; i < relay_hosts.size(); i++) {
        auto name_wire = encode_dns_name(srv_qname);
        answers.insert(answers.end(), name_wire.begin(), name_wire.end());
        // Type = SRV (2B), Class = IN (2B), TTL = 60s (2B)
        answers.push_back(0);
        answers.push_back(static_cast<uint8_t>(DnsRecordType::SRV));
        answers.push_back(0);
        answers.push_back(static_cast<uint8_t>(DnsClass::Internet));
        // TTL = 300 (5 minutes) — typical Pkarr TTL
        uint32_t ttl = 300;
        answers.push_back(static_cast<uint8_t>((ttl >> 24) & 0xFF));
        answers.push_back(static_cast<uint8_t>((ttl >> 16) & 0xFF));
        answers.push_back(static_cast<uint8_t>((ttl >> 8) & 0xFF));
        answers.push_back(static_cast<uint8_t>(ttl & 0xFF));
        // RDATA length (2B)
        auto rdata = encode_srv_rdata(10, 10, relay_ports[i], relay_hosts[i]);
        uint16_t rdlength = static_cast<uint16_t>(rdata.size());
        answers.push_back(static_cast<uint8_t>((rdlength >> 8) & 0xFF));
        answers.push_back(static_cast<uint8_t>(rdlength & 0xFF));
        // RDATA
        answers.insert(answers.end(), rdata.begin(), rdata.end());
    }

    // TXT records for direct addresses
    for (const auto &addr : direct_addrs) {
        // TXT record name: <pk_hex>.iroh (same domain, different type)
        auto name_wire = encode_dns_name(qname);
        answers.insert(answers.end(), name_wire.begin(), name_wire.end());
        // Type = TXT (2B), Class = IN (2B), TTL = 300 (4B)
        answers.push_back(0);
        answers.push_back(static_cast<uint8_t>(DnsRecordType::TXT));
        answers.push_back(0);
        answers.push_back(static_cast<uint8_t>(DnsClass::Internet));
        uint32_t ttl = 300;
        answers.push_back(static_cast<uint8_t>((ttl >> 24) & 0xFF));
        answers.push_back(static_cast<uint8_t>((ttl >> 16) & 0xFF));
        answers.push_back(static_cast<uint8_t>((ttl >> 8) & 0xFF));
        answers.push_back(static_cast<uint8_t>(ttl & 0xFF));
        // RDATA
        auto rdata = encode_txt_rdata(addr);
        uint16_t rdlength = static_cast<uint16_t>(rdata.size());
        answers.push_back(static_cast<uint8_t>((rdlength >> 8) & 0xFF));
        answers.push_back(static_cast<uint8_t>(rdlength & 0xFF));
        answers.insert(answers.end(), rdata.begin(), rdata.end());
    }

    // ─── Assemble packet ───
    std::vector<uint8_t> packet;
    packet.reserve(header.size() + question_name.size() + 4 + answers.size());
    packet.insert(packet.end(), header.begin(), header.end());
    packet.insert(packet.end(), question_name.begin(), question_name.end());
    packet.insert(packet.end(), question_type_class.begin(), question_type_class.end());
    packet.insert(packet.end(), answers.begin(), answers.end());
    return packet;
}

/// Sign a DNS packet with Ed25519 for Pkarr publishing.
inline SignedPacket sign_dns_packet(const std::vector<uint8_t> &dns_packet,
                                     const base::SecretKey &secret_key) {
    SignedPacket sp;
    auto sig = secret_key.sign(dns_packet);
    std::memcpy(sp.signature.data(), sig.data(), 64);
    sp.dns_packet = dns_packet;
    return sp;
}

/// Verify a Pkarr signed packet. Returns true if signature is valid.
inline bool verify_signed_packet(const SignedPacket &sp,
                                 const base::EndpointId &expected_id) {
    base::Signature sig(sp.signature);
    return sig.verify(sp.dns_packet, expected_id);
}

/// Serialize a SignedPacket for HTTP publishing.
/// Format: [signature(64B)][dns_packet_bytes]
inline std::vector<uint8_t> serialize_signed_packet(const SignedPacket &sp) {
    std::vector<uint8_t> out;
    out.reserve(64 + sp.dns_packet.size());
    out.insert(out.end(), sp.signature.begin(), sp.signature.end());
    out.insert(out.end(), sp.dns_packet.begin(), sp.dns_packet.end());
    return out;
}

/// Deserialize a SignedPacket from HTTP response bytes.
inline std::optional<SignedPacket> deserialize_signed_packet(
    std::span<const uint8_t> data) {
    if (data.size() < 64 + 12) return std::nullopt;  // 64B sig + at least DNS header
    SignedPacket sp;
    std::memcpy(sp.signature.data(), data.data(), 64);
    sp.dns_packet.assign(data.begin() + 64, data.end());
    return sp;
}

/// DNS 查询包结构（解析结果）。
struct DnsQuery {
    uint16_t id{0};
    base::EndpointId node_id;
    bool is_srv{false};  // true=查 relay(SRV)，false=查 direct(TXT)
};

/// 解析 DNS 查询包：提取 QNAME 对应的 NodeId 与查询类型。非法包返回 nullopt。
inline std::optional<DnsQuery> parse_dns_query(std::span<const uint8_t> pkt) {
    if (pkt.size() < 12) return std::nullopt;
    uint16_t id = static_cast<uint16_t>((pkt[0] << 8) | pkt[1]);
    std::size_t pos = 12;
    auto qname = detail::read_name(pkt, pos);
    if (!qname) return std::nullopt;
    if (pos + 4 > pkt.size()) return std::nullopt;
    uint16_t qtype = static_cast<uint16_t>((pkt[pos] << 8) | pkt[pos + 1]);
    uint16_t qclass = static_cast<uint16_t>((pkt[pos + 2] << 8) | pkt[pos + 3]);
    (void)qclass;
    pos += 4;
    auto nid = node_id_from_qname(*qname);
    if (!nid) return std::nullopt;
    DnsQuery q;
    q.id = id;
    q.node_id = *nid;
    q.is_srv = (qtype == static_cast<uint16_t>(DnsRecordType::SRV));
    return q;
}

/// 构造发往 server 的 DNS 查询包（SRV 问题）。
inline std::vector<uint8_t> build_pkarr_dns_query(const base::EndpointId &node_id,
                                                   uint16_t dns_id = 0x1234) {
    std::string srv_qname = pkarr_srv_qname(node_id);
    auto header = encode_dns_header(dns_id, 0x0100, 1, 0);  // QR=0, RD=1
    auto qname_wire = encode_dns_name(srv_qname);
    std::vector<uint8_t> qtc = {0, static_cast<uint8_t>(DnsRecordType::SRV),
                                0, static_cast<uint8_t>(DnsClass::Internet)};
    std::vector<uint8_t> pkt;
    pkt.insert(pkt.end(), header.begin(), header.end());
    pkt.insert(pkt.end(), qname_wire.begin(), qname_wire.end());
    pkt.insert(pkt.end(), qtc.begin(), qtc.end());
    return pkt;
}

/// 解析服务端返回的 SignedPacket 响应：验签 + 提取 relay/direct 地址。
/// 成功返回已填充的 EndpointAddr；验签失败/解析错误返回 nullopt。
inline std::optional<base::EndpointAddr> parse_dns_response(const SignedPacket &sp) {
    const auto &pkt = sp.dns_packet;
    if (pkt.size() < 12) return std::nullopt;
    std::size_t pos = 12;
    auto qname = detail::read_name(pkt, pos);
    if (!qname) return std::nullopt;
    if (pos + 4 > pkt.size()) return std::nullopt;
    pos += 4;  // 跳过 QTYPE/QCLASS
    auto nid = node_id_from_qname(*qname);
    if (!nid) return std::nullopt;
    if (!verify_signed_packet(sp, *nid)) return std::nullopt;
    uint16_t ancount = static_cast<uint16_t>((pkt[6] << 8) | pkt[7]);
    base::EndpointAddr addr(*nid);
    for (uint16_t i = 0; i < ancount; i++) {
        auto aname = detail::read_name(pkt, pos);
        if (!aname) return std::nullopt;
        if (pos + 10 > pkt.size()) return std::nullopt;
        uint16_t rtype = static_cast<uint16_t>((pkt[pos] << 8) | pkt[pos + 1]);
        pos += 2;  // TYPE
        pos += 2;  // CLASS
        pos += 4;  // TTL
        uint16_t rdlen = static_cast<uint16_t>((pkt[pos] << 8) | pkt[pos + 1]);
        pos += 2;
        if (pos + rdlen > pkt.size()) return std::nullopt;
        std::span<const uint8_t> rdata(pkt.data() + pos, rdlen);
        if (rtype == static_cast<uint16_t>(DnsRecordType::SRV)) {
            if (rdlen < 6) return std::nullopt;
            uint16_t port = static_cast<uint16_t>((rdata[4] << 8) | rdata[5]);
            std::size_t p2 = 6;
            auto target = detail::read_name(rdata, p2);
            if (target && !target->empty()) {
                std::string url = "https://" + *target + ":" + std::to_string(port) + "/";
                addr.add_relay(base::RelayUrl(url));
            }
        } else if (rtype == static_cast<uint16_t>(DnsRecordType::TXT)) {
            std::size_t p2 = 0;
            while (p2 < rdlen) {
                uint8_t slen = rdata[p2++];
                if (p2 + slen > rdlen) return std::nullopt;
                std::string txt(reinterpret_cast<const char *>(rdata.data() + p2), slen);
                p2 += slen;
                auto colon = txt.find(':');
                if (colon != std::string::npos && colon > 0 && colon + 1 < txt.size()) {
                    base::TransportAddr ta;
                    ta.kind = base::TransportKind::Ip;
                    ta.host = txt.substr(0, colon);
                    uint16_t pp = 0;
                    bool ok = true;
                    for (char c : txt.substr(colon + 1)) {
                        if (c < '0' || c > '9') { ok = false; break; }
                        pp = static_cast<uint16_t>(pp * 10 + (c - '0'));
                    }
                    if (ok) { ta.port = pp; addr.add_direct_address(ta); }
                }
            }
        }
        pos += rdlen;
    }
    return addr;
}

}  // namespace linoh::address_lookup::pkarr
