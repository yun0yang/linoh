// stun.cpp — STUN 协议实现（RFC 5389）
//
// P4-B-1 NetReport 模块的基础组件。

#include "linoh/net/stun.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace linoh::net::stun {

// ============================================================================
// 工具
// ============================================================================

std::uint16_t xor_port(std::uint16_t port) {
    // XOR with the high 16 bits of the magic cookie
    return port ^ static_cast<std::uint16_t>(kMagicCookie >> 16);
}

std::string xor_ipv4(const std::string &ip, const std::array<std::uint8_t, kTransactionIdSize> &tx_id) {
    // IPv4 XOR with magic cookie (4 bytes)
    // tx_id not used for IPv4 (only for IPv6 which XORs with magic+tx_id)
    in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return ip;  // 解析失败，原样返回
    }

    std::uint32_t ip_net = addr.s_addr;  // 网络字节序
    // 转 host 字节序后 XOR
    std::uint32_t ip_host = ntohl(ip_net);
    std::uint32_t xored = ip_host ^ kMagicCookie;
    // 转回网络字节序
    in_addr result;
    result.s_addr = htonl(xored);

    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &result, buf, sizeof(buf));
    return std::string(buf);
}

std::array<std::uint8_t, kTransactionIdSize> generate_transaction_id() {
    std::array<std::uint8_t, kTransactionIdSize> id{};
    // 使用 linoh 的 CSPRNG（与 linoh_c.cpp 一致）
    crypto::crypto_random_bytes(std::span<std::uint8_t>(id.data(), id.size()));
    return id;
}

// ============================================================================
// 编码
// ============================================================================

namespace {

/// 写入 16 位大端
void put_u16_be(std::vector<std::uint8_t> &out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

/// 写入 32 位大端
void put_u32_be(std::vector<std::uint8_t> &out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

/// 读取 16 位大端
std::uint16_t get_u16_be(const std::uint8_t *p) {
    return (static_cast<std::uint16_t>(p[0]) << 8) | static_cast<std::uint16_t>(p[1]);
}

/// 读取 32 位大端
std::uint32_t get_u32_be(const std::uint8_t *p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

} // namespace

std::vector<std::uint8_t> encode_binding_request(
    const std::array<std::uint8_t, kTransactionIdSize> &tx_id) {
    std::vector<std::uint8_t> msg;
    msg.reserve(kHeaderSize);

    // 消息类型 = Binding Request
    put_u16_be(msg, static_cast<std::uint16_t>(MessageType::BindingRequest));
    // 消息长度 = 0（无属性）
    put_u16_be(msg, 0);
    // Magic Cookie
    put_u32_be(msg, kMagicCookie);
    // Transaction ID
    msg.insert(msg.end(), tx_id.begin(), tx_id.end());

    return msg;
}

std::vector<std::uint8_t> encode_xor_mapped_address(
    const std::string &ip,
    std::uint16_t port,
    const std::array<std::uint8_t, kTransactionIdSize> &tx_id) {
    std::vector<std::uint8_t> value;

    // Reserved(1B) + Family(1B) + Port(2B BE) + Address(4B IPv4 / 16B IPv6)
    bool is_v6 = ip.find(':') != std::string::npos;

    // Reserved 字节 + Family
    value.push_back(0x00);
    value.push_back(static_cast<std::uint8_t>(is_v6 ? AddressFamily::IPv6 : AddressFamily::IPv4));

    // XOR Port
    std::uint16_t xport = xor_port(port);
    put_u16_be(value, xport);

    if (is_v6) {
        // IPv6: XOR with magic cookie (4B) || transaction_id (12B)
        in6_addr addr{};
        if (inet_pton(AF_INET6, ip.c_str(), &addr) != 1) {
            return value;  // 解析失败，返回部分编码
        }
        std::array<std::uint8_t, 16> xor_key{};
        // magic cookie 4 字节大端
        xor_key[0] = static_cast<std::uint8_t>((kMagicCookie >> 24) & 0xFF);
        xor_key[1] = static_cast<std::uint8_t>((kMagicCookie >> 16) & 0xFF);
        xor_key[2] = static_cast<std::uint8_t>((kMagicCookie >> 8) & 0xFF);
        xor_key[3] = static_cast<std::uint8_t>(kMagicCookie & 0xFF);
        // tx_id 12 字节
        std::memcpy(xor_key.data() + 4, tx_id.data(), kTransactionIdSize);

        std::array<std::uint8_t, 16> ip_bytes{};
        std::memcpy(ip_bytes.data(), &addr, 16);
        for (int i = 0; i < 16; ++i) {
            value.push_back(ip_bytes[i] ^ xor_key[i]);
        }
    } else {
        // IPv4: XOR with magic cookie (4B)
        in_addr addr{};
        if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
            return value;
        }
        std::uint32_t ip_host = ntohl(addr.s_addr);
        std::uint32_t xored = ip_host ^ kMagicCookie;
        put_u32_be(value, xored);
    }

    return value;
}

std::vector<std::uint8_t> encode_mapped_address(
    const std::string &ip,
    std::uint16_t port) {
    std::vector<std::uint8_t> value;

    bool is_v6 = ip.find(':') != std::string::npos;
    value.push_back(0x00);
    value.push_back(static_cast<std::uint8_t>(is_v6 ? AddressFamily::IPv6 : AddressFamily::IPv4));
    put_u16_be(value, port);

    if (is_v6) {
        in6_addr addr{};
        if (inet_pton(AF_INET6, ip.c_str(), &addr) != 1) return value;
        // 网络字节序，直接按字节写入
        const auto *p = reinterpret_cast<const std::uint8_t *>(&addr);
        for (int i = 0; i < 16; ++i) value.push_back(p[i]);
    } else {
        in_addr addr{};
        if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return value;
        // addr.s_addr 已是网络字节序，直接按字节写入（避免主机字节序移位）
        const auto *p = reinterpret_cast<const std::uint8_t *>(&addr);
        for (int i = 0; i < 4; ++i) value.push_back(p[i]);
    }

    return value;
}

std::vector<std::uint8_t> encode_binding_response(
    const std::array<std::uint8_t, kTransactionIdSize> &tx_id,
    const std::string &mapped_ip,
    std::uint16_t mapped_port) {
    // 先构造属性体
    auto xor_attr_value = encode_xor_mapped_address(mapped_ip, mapped_port, tx_id);

    // 属性 = Type(2B) + Length(2B) + Value
    std::vector<std::uint8_t> body;
    put_u16_be(body, static_cast<std::uint16_t>(AttributeType::XorMappedAddress));
    put_u16_be(body, static_cast<std::uint16_t>(xor_attr_value.size()));
    body.insert(body.end(), xor_attr_value.begin(), xor_attr_value.end());

    // 4 字节对齐 padding
    while (body.size() % 4 != 0) body.push_back(0);

    // 消息头
    std::vector<std::uint8_t> msg;
    msg.reserve(kHeaderSize + body.size());

    put_u16_be(msg, static_cast<std::uint16_t>(MessageType::BindingResponse));
    put_u16_be(msg, static_cast<std::uint16_t>(body.size()));
    put_u32_be(msg, kMagicCookie);
    msg.insert(msg.end(), tx_id.begin(), tx_id.end());

    msg.insert(msg.end(), body.begin(), body.end());
    return msg;
}

// ============================================================================
// 解析
// ============================================================================

std::optional<StunMessage> parse_message(std::span<const std::uint8_t> data) {
    if (data.size() < kHeaderSize) {
        return std::nullopt;
    }

    // 验证前 2 位必须为 00（RFC 5389 §6）
    if ((data[0] & 0xC0) != 0) {
        return std::nullopt;
    }

    StunMessage msg{};
    msg.type = static_cast<MessageType>(get_u16_be(data.data()));
    std::uint16_t length = get_u16_be(data.data() + 2);
    std::uint32_t cookie = get_u32_be(data.data() + 4);

    if (cookie != kMagicCookie) {
        return std::nullopt;
    }

    // 事务 ID
    std::memcpy(msg.transaction_id.data(), data.data() + 8, kTransactionIdSize);

    // 属性
    if (data.size() < kHeaderSize + length) {
        return std::nullopt;
    }

    std::size_t pos = kHeaderSize;
    std::size_t end = kHeaderSize + length;

    while (pos + 4 <= end) {
        StunAttribute attr{};
        attr.type = static_cast<AttributeType>(get_u16_be(data.data() + pos));
        std::uint16_t attr_len = get_u16_be(data.data() + pos + 2);
        pos += 4;

        if (pos + attr_len > end) {
            return std::nullopt;
        }
        attr.value.assign(data.data() + pos, data.data() + pos + attr_len);
        pos += attr_len;

        // 4 字节对齐 padding
        while (pos < end && (pos - kHeaderSize) % 4 != 0) {
            ++pos;
        }

        msg.attributes.push_back(std::move(attr));
    }

    return msg;
}

std::optional<std::pair<std::string, std::uint16_t>> parse_mapped_address(
    const StunAttribute &attr) {
    if (attr.value.size() < 4) return std::nullopt;

    // Reserved(1B) + Family(1B) + Port(2B BE) + Address(4B or 16B)
    std::uint8_t family = attr.value[1];
    std::uint16_t port = get_u16_be(attr.value.data() + 2);

    if (family == static_cast<std::uint8_t>(AddressFamily::IPv4)) {
        if (attr.value.size() < 8) return std::nullopt;
        in_addr addr{};
        // 网络字节序，直接 memcpy
        std::memcpy(&addr, attr.value.data() + 4, 4);
        char buf[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        return std::make_pair(std::string(buf), port);
    } else if (family == static_cast<std::uint8_t>(AddressFamily::IPv6)) {
        if (attr.value.size() < 20) return std::nullopt;
        in6_addr addr{};
        std::memcpy(&addr, attr.value.data() + 4, 16);
        char buf[INET6_ADDRSTRLEN] = {};
        inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
        return std::make_pair(std::string(buf), port);
    }

    return std::nullopt;
}

std::optional<std::pair<std::string, std::uint16_t>> parse_xor_mapped_address(
    const StunAttribute &attr,
    const std::array<std::uint8_t, kTransactionIdSize> &tx_id) {
    if (attr.value.size() < 4) return std::nullopt;

    std::uint8_t family = attr.value[1];
    std::uint16_t xport = get_u16_be(attr.value.data() + 2);
    std::uint16_t port = xor_port(xport);  // XOR 还原

    if (family == static_cast<std::uint8_t>(AddressFamily::IPv4)) {
        if (attr.value.size() < 8) return std::nullopt;
        std::uint32_t xored = get_u32_be(attr.value.data() + 4);
        std::uint32_t ip_host = xored ^ kMagicCookie;
        in_addr addr{};
        addr.s_addr = htonl(ip_host);
        char buf[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        return std::make_pair(std::string(buf), port);
    } else if (family == static_cast<std::uint8_t>(AddressFamily::IPv6)) {
        if (attr.value.size() < 20) return std::nullopt;
        std::array<std::uint8_t, 16> xor_key{};
        xor_key[0] = static_cast<std::uint8_t>((kMagicCookie >> 24) & 0xFF);
        xor_key[1] = static_cast<std::uint8_t>((kMagicCookie >> 16) & 0xFF);
        xor_key[2] = static_cast<std::uint8_t>((kMagicCookie >> 8) & 0xFF);
        xor_key[3] = static_cast<std::uint8_t>(kMagicCookie & 0xFF);
        std::memcpy(xor_key.data() + 4, tx_id.data(), kTransactionIdSize);

        std::array<std::uint8_t, 16> ip_bytes{};
        for (int i = 0; i < 16; ++i) {
            ip_bytes[i] = attr.value[4 + i] ^ xor_key[i];
        }
        in6_addr addr{};
        std::memcpy(&addr, ip_bytes.data(), 16);
        char buf[INET6_ADDRSTRLEN] = {};
        inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
        return std::make_pair(std::string(buf), port);
    }

    return std::nullopt;
}

} // namespace linoh::net::stun
