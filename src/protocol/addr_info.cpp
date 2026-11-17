// addr_info.cpp — v4.0.0 M18 地址交换协议分级实现
//
// 实现 DirectAddress 和 AddrInfoPayload 的编解码逻辑。
// 详见 addr_info.hpp 字段布局说明。

#include "linoh/protocol/addr_info.hpp"

#include <cstring>
#include <sstream>

namespace linoh::protocol {

// ============================================================================
// DirectAddress 编码
// ============================================================================

std::vector<std::uint8_t> DirectAddress::encode() const {
    std::vector<std::uint8_t> buf;
    buf.reserve(encoded_size());

    // offset 0: family (1B)
    buf.push_back(static_cast<std::uint8_t>(family));

    // offset 1: ip (F 字节)
    const std::size_t ip_len = static_cast<std::size_t>(family);
    buf.insert(buf.end(), ip.data(), ip.data() + ip_len);

    // offset 1+F: port (2B，大端序)
    buf.push_back(static_cast<std::uint8_t>((port >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(port & 0xFF));

    return buf;
}

bool DirectAddress::decode(std::span<const std::uint8_t> data,
                           DirectAddress &out,
                           std::size_t &consumed) {
    consumed = 0;
    if (data.size() < 1) return false;

    // offset 0: family (1B)
    const std::uint8_t fam = data[0];
    if (fam != static_cast<std::uint8_t>(Family::IPv4) &&
        fam != static_cast<std::uint8_t>(Family::IPv6)) {
        return false;  // 非法 family
    }
    out.family = static_cast<Family>(fam);

    const std::size_t ip_len = static_cast<std::size_t>(fam);
    const std::size_t need = 1 + ip_len + 2;  // family + ip + port
    if (data.size() < need) return false;

    // offset 1: ip (F 字节)
    std::memcpy(out.ip.data(), data.data() + 1, ip_len);

    // offset 1+F: port (2B，大端序)
    const std::size_t port_off = 1 + ip_len;
    out.port =
        (static_cast<std::uint16_t>(data[port_off]) << 8) |
        static_cast<std::uint16_t>(data[port_off + 1]);

    consumed = need;
    return true;
}

std::string DirectAddress::to_string() const {
    std::ostringstream oss;
    if (family == Family::IPv4) {
        oss << static_cast<int>(ip[0]) << "."
            << static_cast<int>(ip[1]) << "."
            << static_cast<int>(ip[2]) << "."
            << static_cast<int>(ip[3]);
    } else {
        oss << "[";
        for (std::size_t i = 0; i < 16; i += 2) {
            if (i > 0) oss << ":";
            oss << std::hex << static_cast<int>((ip[i] << 8) | ip[i + 1]) << std::dec;
        }
        oss << "]";
    }
    oss << ":" << port;
    return oss.str();
}

// ============================================================================
// AddrInfoPayload 编码
// ============================================================================

std::vector<std::uint8_t> AddrInfoPayload::encode() const {
    std::vector<std::uint8_t> buf;

    // 预估容量：固定头 34 + relay_url_len(1) + relay_url + addr_count(1) + addresses
    std::size_t addrs_size = 0;
    for (const auto &addr : addresses) {
        addrs_size += addr.encoded_size();
    }
    buf.reserve(kMinEncodedSize + 1 + relay_url.size() + 1 + addrs_size);

    // offset 0: version (1B)
    buf.push_back(version);

    // offset 1: level (1B)
    buf.push_back(static_cast<std::uint8_t>(level));

    // offset 2: endpoint_id (32B)
    buf.insert(buf.end(), endpoint_id.begin(), endpoint_id.end());

    // offset 34: relay_url_len (1B)
    // relay_url 长度限制 255（uint8 范围）
    const std::size_t url_len = relay_url.size() > kMaxRelayUrlLen
                                    ? kMaxRelayUrlLen
                                    : relay_url.size();
    buf.push_back(static_cast<std::uint8_t>(url_len));

    // offset 35: relay_url (N 字节)
    if (url_len > 0) {
        buf.insert(buf.end(), relay_url.data(), relay_url.data() + url_len);
    }

    // offset 35+N: addr_count (1B)
    const std::size_t addr_count = addresses.size() > kMaxAddresses
                                       ? kMaxAddresses
                                       : addresses.size();
    buf.push_back(static_cast<std::uint8_t>(addr_count));

    // offset 36+N: addresses (M 字节)
    for (std::size_t i = 0; i < addr_count; ++i) {
        auto encoded_addr = addresses[i].encode();
        buf.insert(buf.end(), encoded_addr.begin(), encoded_addr.end());
    }

    return buf;
}

bool AddrInfoPayload::decode(std::span<const std::uint8_t> data,
                              AddrInfoPayload &out) {
    // 最小长度：version(1) + level(1) + endpoint_id(32) = 34
    if (data.size() < kMinEncodedSize) {
        return false;
    }

    std::size_t off = 0;

    // offset 0: version (1B)
    out.version = data[off++];

    // offset 1: level (1B)
    const std::uint8_t level_val = data[off++];
    if (!is_valid_level(level_val)) {
        return false;  // 非法 level
    }
    out.level = static_cast<AddrInfoLevel>(level_val);

    // offset 2: endpoint_id (32B)
    std::memcpy(out.endpoint_id.data(), data.data() + off, 32);
    off += 32;

    // offset 34: relay_url_len (1B)
    if (data.size() < off + 1) return false;
    const std::uint8_t url_len = data[off++];

    // offset 35: relay_url (N 字节)
    if (data.size() < off + url_len) return false;
    out.relay_url.assign(reinterpret_cast<const char *>(data.data() + off), url_len);
    off += url_len;

    // offset 35+N: addr_count (1B)
    if (data.size() < off + 1) return false;
    const std::uint8_t addr_count = data[off++];

    // offset 36+N: addresses (M 字节)
    out.addresses.clear();
    out.addresses.reserve(addr_count);
    for (std::uint8_t i = 0; i < addr_count; ++i) {
        if (off >= data.size()) return false;
        DirectAddress addr;
        std::size_t consumed = 0;
        if (!DirectAddress::decode(data.subspan(off), addr, consumed)) {
            return false;
        }
        out.addresses.push_back(std::move(addr));
        off += consumed;
    }

    return true;
}

std::string AddrInfoPayload::to_string() const {
    std::ostringstream oss;
    oss << "AddrInfoPayload{version=" << static_cast<int>(version)
        << ", level=" << linoh::protocol::to_string(level)
        << ", endpoint_id=<" << (endpoint_id[0]) << "...>";

    if (has_relay() && !relay_url.empty()) {
        oss << ", relay_url=\"" << relay_url << "\"";
    }
    if (has_addresses() && !addresses.empty()) {
        oss << ", addrs=[";
        for (std::size_t i = 0; i < addresses.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << addresses[i].to_string();
        }
        oss << "]";
    }
    oss << "}";
    return oss.str();
}

}  // namespace linoh::protocol
