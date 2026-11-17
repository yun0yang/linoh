// addr_info.hpp — v4.0.0 M18 地址交换协议分级
//
// 分级地址交换报文，借鉴 sendme AddrInfoOptions 模式。
// 节点通过 ctrl/1 ALPN 发送 AddrInfoAnnounce(0x0064) 携带分级地址信息，
// 对端据此选择最优连接路径。
//
// 设计要点：
//   - 分级交换：AddrInfoLevel 按网络环境选择地址集
//     Id(仅公钥) / RelayAndAddresses(全量,默认) / Relay(仅Relay) / Addresses(仅直连)
//   - 向后兼容：旧节点不识别 AddrInfoAnnounce MethodId，丢弃（等价不交换）
//   - 变长编码：不同 level 报文长度不同，最小 34 字节（Id 级）
//   - 与 orchestrator 协作：linoh 提供分级地址数据，orchestrator 决策最优地址
//
// AddrInfoPayload 编码布局（变长）：
//   offset  size  field
//   0       1     version (当前 1)
//   1       1     level (AddrInfoLevel: 0=Id, 1=RelayAndAddresses, 2=Relay, 3=Addresses)
//   2       32    endpoint_id (Ed25519 公钥)
//   --- level-specific（以下字段根据 level 有无，但编码中始终存在长度字段）---
//   34      1     relay_url_len (0-255，level=Relay/RelayAndAddresses 时 >0，其他 =0)
//   35      N     relay_url (UTF-8, N=relay_url_len)
//   35+N    1     addr_count (0-255，level=Addresses/RelayAndAddresses 时 >0，其他 =0)
//   36+N    M     addresses (M 个 DirectAddress 编码)
//
// DirectAddress 编码布局（变长：7 或 19 字节）：
//   offset  size  field
//   0       1     family (4=IPv4, 16=IPv6)
//   1       F     ip (F=family 字节，IPv4 用前 4 字节，IPv6 用 16 字节)
//   1+F     2     port (大端序)
//   总长度：1+F+2 = 7(IPv4) 或 19(IPv6)
//
// 字节序：port 使用大端（网络）字节序，与 application_message.hpp 一致。
// 向后兼容：version 字段允许未来扩展；旧节点不识别 MethodId 0x0064 → 丢弃。

#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace linoh::protocol {

/// 地址信息分级（sendme AddrInfoOptions 模式）
//
// 按网络环境选择最优地址集：
//   - Id：仅公钥，依赖 DNS/Pkarr 解析（最短 34B）
//   - RelayAndAddresses：全量，公钥 + Relay URL + 直连候选（默认，跨网节点）
//   - Relay：仅公钥 + Relay URL（跨 NAT 节点，无直连候选）
//   - Addresses：仅公钥 + 直连 IP（内网节点，最短最快）
enum class AddrInfoLevel : std::uint8_t {
    Id                = 0,  // 仅公钥（32B），依赖 DNS/Pkarr
    RelayAndAddresses = 1,  // 全量（默认）：公钥 + Relay URL + 直连候选
    Relay             = 2,  // 仅公钥 + Relay URL
    Addresses         = 3,  // 仅公钥 + 直连 IP
};

/// AddrInfoLevel 转字符串（日志用）
inline const char *to_string(AddrInfoLevel level) noexcept {
    switch (level) {
        case AddrInfoLevel::Id:                return "Id";
        case AddrInfoLevel::RelayAndAddresses: return "RelayAndAddresses";
        case AddrInfoLevel::Relay:             return "Relay";
        case AddrInfoLevel::Addresses:         return "Addresses";
    }
    return "Unknown";
}

/// 判定 level 值是否合法
inline bool is_valid_level(std::uint8_t v) noexcept {
    return v <= static_cast<std::uint8_t>(AddrInfoLevel::Addresses);
}

/// 直连地址（IP + port）
//
// 支持 IPv4（4 字节）和 IPv6（16 字节），编码为变长格式。
struct DirectAddress {
    /// 地址族（值 = 地址字节数：4=IPv4, 16=IPv6）
    enum class Family : std::uint8_t {
        IPv4 = 4,   // 4 字节地址
        IPv6 = 16,  // 16 字节地址
    };

    Family family{Family::IPv4};
    std::array<std::uint8_t, 16> ip{};  // IPv4 用前 4 字节，IPv6 用全部 16 字节
    std::uint16_t port{0};

    /// 编码后的字节数（1 + family + 2）
    std::size_t encoded_size() const noexcept {
        return 1 + static_cast<std::size_t>(family) + 2;
    }

    /// 序列化为字节流
    std::vector<std::uint8_t> encode() const;

    /// 从字节流反序列化
    /// @param data 输入数据
    /// @param out 输出结构
    /// @param consumed 消费的字节数（输出）
    /// @return true=成功，false=数据格式错误
    static bool decode(std::span<const std::uint8_t> data,
                       DirectAddress &out,
                       std::size_t &consumed);

    /// 简要描述（日志用）
    std::string to_string() const;

    /// 相等比较（测试用）
    bool operator==(const DirectAddress &other) const noexcept {
        if (family != other.family || port != other.port) return false;
        const std::size_t n = static_cast<std::size_t>(family);
        for (std::size_t i = 0; i < n; ++i) {
            if (ip[i] != other.ip[i]) return false;
        }
        return true;
    }
};

/// 地址交换 payload（MethodId::AddrInfoAnnounce 的 payload）
//
// 节点通过 ctrl/1 ALPN 发送 AddrInfoAnnounce(0x0064) 携带分级地址信息。
// 对端据此选择最优连接路径：内网用 Addresses，跨 NAT 用 Relay，
// 网络不可控用 RelayAndAddresses。
struct AddrInfoPayload {
    static constexpr std::uint8_t kCurrentVersion = 1;
    static constexpr std::size_t kMinEncodedSize = 34;  // version(1) + level(1) + endpoint_id(32)
    static constexpr std::uint8_t kMaxRelayUrlLen = 255;
    static constexpr std::uint8_t kMaxAddresses = 255;

    std::uint8_t version{kCurrentVersion};
    AddrInfoLevel level{AddrInfoLevel::RelayAndAddresses};
    std::array<std::uint8_t, 32> endpoint_id{};

    /// level=Relay/RelayAndAddresses 时有效
    std::string relay_url;

    /// level=Addresses/RelayAndAddresses 时有效
    std::vector<DirectAddress> addresses;

    /// 是否包含 Relay URL
    bool has_relay() const noexcept {
        return level == AddrInfoLevel::Relay || level == AddrInfoLevel::RelayAndAddresses;
    }

    /// 是否包含直连地址
    bool has_addresses() const noexcept {
        return level == AddrInfoLevel::Addresses || level == AddrInfoLevel::RelayAndAddresses;
    }

    /// 序列化为字节流（变长）
    std::vector<std::uint8_t> encode() const;

    /// 从字节流反序列化
    /// @return true=成功，false=数据格式错误（长度不足/字段越界）
    static bool decode(std::span<const std::uint8_t> data, AddrInfoPayload &out);

    /// 简要描述（日志用）
    std::string to_string() const;

    /// 相等比较（测试用，忽略 version 差异）
    bool operator==(const AddrInfoPayload &other) const noexcept {
        if (level != other.level) return false;
        if (endpoint_id != other.endpoint_id) return false;
        if (has_relay() && relay_url != other.relay_url) return false;
        if (has_addresses() && addresses != other.addresses) return false;
        return true;
    }
};

}  // namespace linoh::protocol
