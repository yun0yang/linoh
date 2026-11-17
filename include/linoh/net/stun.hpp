// stun.hpp — STUN 协议实现（RFC 5389）
//
// P4-B-1 NetReport 模块的基础组件，用于 NAT 类型探测。
//
// 实现范围：
//   - STUN Binding Request / Response 编解码
//   - MAPPED-ADDRESS / XOR-MAPPED-ADDRESS 属性解析
//   - SOFTWARE / FINGERPRINT 属性（可选）
//   - 仅支持 UDP 传输
//
// 不实现的部分（超出 P4-B-1 范围）：
//   - STUN 认证（USERNAME / REALM / NONCE / MESSAGE-INTEGRITY）
//   - TLS over TCP
//   - TURN 扩展

#pragma once

#include "linoh/base/endpoint_addr.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace linoh::net::stun {

// ============================================================================
// STUN 协议常量（RFC 5389 §3 / §15）
// ============================================================================

/// STUN 消息类型（高 2 位固定为 00，故实际为 14 位）
enum class MessageType : std::uint16_t {
    BindingRequest  = 0x0001,
    BindingResponse = 0x0101,
    BindingError    = 0x0111,
};

/// STUN 属性类型
enum class AttributeType : std::uint16_t {
    MappedAddress      = 0x0001,
    ResponseAddress    = 0x0002,  // RFC 5389 已废弃，仅兼容旧客户端
    ChangeRequest      = 0x0003,  // RFC 5389 已废弃
    SourceAddress      = 0x0004,
    ChangedAddress     = 0x0005,
    Username           = 0x0006,
    MessageIntegrity   = 0x0008,
    ErrorCode          = 0x0009,
    UnknownAttributes  = 0x000A,
    Realm              = 0x0014,
    Nonce              = 0x0015,
    XorMappedAddress   = 0x0020,
    Software           = 0x8022,
    AlternateServer    = 0x8023,
    Fingerprint        = 0x8028,
};

/// MAGIC COOKIE（RFC 5389 §6）：固定 0x2112A442
constexpr std::uint32_t kMagicCookie = 0x2112A442;

/// 事务 ID 长度（96 bit = 12 字节）
constexpr std::size_t kTransactionIdSize = 12;

/// STUN 消息头长度（20 字节）
constexpr std::size_t kHeaderSize = 20;

/// MAPPED-ADDRESS 中的地址族
enum class AddressFamily : std::uint8_t {
    IPv4 = 0x01,
    IPv6 = 0x02,
};

// ============================================================================
// STUN 消息结构
// ============================================================================

/// STUN 属性（已解析）
struct StunAttribute {
    AttributeType type;
    std::vector<std::uint8_t> value;
};

/// STUN 消息（请求或响应）
struct StunMessage {
    MessageType type;
    std::array<std::uint8_t, kTransactionIdSize> transaction_id;
    std::vector<StunAttribute> attributes;

    /// 查找指定类型的属性，找不到返回 nullptr。
    const StunAttribute *find(AttributeType t) const {
        for (auto &a : attributes) {
            if (a.type == t) return &a;
        }
        return nullptr;
    }
};

// ============================================================================
// 编解码
// ============================================================================

/// 构造一个 Binding Request 消息（不带任何属性）。
/// @param tx_id 事务 ID（12 字节，调用方负责随机生成）
std::vector<std::uint8_t> encode_binding_request(
    const std::array<std::uint8_t, kTransactionIdSize> &tx_id);

/// 构造一个 Binding Response 消息（带 XOR-MAPPED-ADDRESS）。
std::vector<std::uint8_t> encode_binding_response(
    const std::array<std::uint8_t, kTransactionIdSize> &tx_id,
    const std::string &mapped_ip,
    std::uint16_t mapped_port);

/// 解析 STUN 消息（请求或响应）。
/// @return 解析失败返回 std::nullopt
std::optional<StunMessage> parse_message(std::span<const std::uint8_t> data);

// ============================================================================
// 属性解析
// ============================================================================

/// 解析 MAPPED-ADDRESS 属性，返回 (ip, port)。
/// @return 解析失败返回 nullopt
std::optional<std::pair<std::string, std::uint16_t>> parse_mapped_address(
    const StunAttribute &attr);

/// 解析 XOR-MAPPED-ADDRESS 属性，返回 (ip, port)。
/// @return 解析失败返回 nullopt
std::optional<std::pair<std::string, std::uint16_t>> parse_xor_mapped_address(
    const StunAttribute &attr,
    const std::array<std::uint8_t, kTransactionIdSize> &tx_id);

// ============================================================================
// 工具
// ============================================================================

/// 生成随机事务 ID（使用系统 CSPRNG）。
std::array<std::uint8_t, kTransactionIdSize> generate_transaction_id();

/// 将 IP 字符串和端口编码为 XOR-MAPPED-ADDRESS 属性值。
/// @param tx_id 用于 XOR 计算
std::vector<std::uint8_t> encode_xor_mapped_address(
    const std::string &ip,
    std::uint16_t port,
    const std::array<std::uint8_t, kTransactionIdSize> &tx_id);

/// 将 IP 字符串和端口编码为 MAPPED-ADDRESS 属性值。
std::vector<std::uint8_t> encode_mapped_address(
    const std::string &ip,
    std::uint16_t port);

/// XOR-MAPPED-ADDRESS 的端口/地址 XOR 计算（RFC 5389 §15.2）
///
/// port ^= magic_cookie 高 16 位
/// address ^= magic_cookie (4 字节) || transaction_id (12 字节)
std::uint16_t xor_port(std::uint16_t port);
std::string xor_ipv4(const std::string &ip, const std::array<std::uint8_t, kTransactionIdSize> &tx_id);

} // namespace linoh::net::stun
