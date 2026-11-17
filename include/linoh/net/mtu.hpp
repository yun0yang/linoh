// mtu.hpp — MTU 协商 + Jumbo Frame（P5-B-4）
//
// 借鉴 Sunshine packetsize 配置项 + RFC 1191 PMTUD：
//   - linoh 默认 MTU 1280（QUIC 最小，RFC 9000）
//   - 局域网可协商到 9000（jumbo frame）提升大流量带宽利用率
//   - PMTUD 探测路径最小 MTU，避免 IP 分片
//
// 协商策略：
//   - 双方都支持 jumbo（>= 9000）+ 网络分级为 Lan → 9000
//   - 任一方 < 9000 → 取 min(local, remote)
//   - 困难网络（Symmetric/Unknown/UDP Blocked）→ 保守用 1280
//
// 不修改现有 kMaxPacketSize 常量（向后兼容），新增运行期 negotiated_mtu_ 字段
// 由 connection.cpp 在握手时调用 MtuNegotiator::negotiate() 协商。

#pragma once

#include "linoh/net/net_report.hpp"  // NatType, UdpFirewall
#include "linoh/net/path.hpp"         // FourTuple

#include <cstdint>
#include <string>

namespace linoh::net {

/// MTU 相关常量
struct MtuConstants {
    static constexpr std::uint16_t kMinMtu      = 1280;  // QUIC 最小 MTU（RFC 9000）
    static constexpr std::uint16_t kStandardMtu = 1500;  // 以太网标准 MTU
    static constexpr std::uint16_t kJumboMtu    = 9000;  // Jumbo frame MTU
    static constexpr std::uint16_t kMaxMtu      = 9000;  // linoh 支持的最大 MTU
};

/// MTU 协商结果
struct MtuNegotiationResult {
    std::uint16_t negotiated_mtu{MtuConstants::kMinMtu};
    bool         jumbo_enabled{false};
    std::string  reason;  // 协商原因（日志用）
};

/// MTU 协商器
class MtuNegotiator {
public:
    /// 握手时协商 MTU
    ///
    /// @param local_mtu  本端期望 MTU
    /// @param remote_mtu 对端期望 MTU
    /// @param nat_type   NAT 类型（影响是否允许 jumbo）
    /// @param fw         UDP 防火墙状态
    /// @return 协商结果
    static MtuNegotiationResult negotiate(
        std::uint16_t local_mtu,
        std::uint16_t remote_mtu,
        NatType nat_type,
        UdpFirewall fw = UdpFirewall::Open) noexcept;

    /// 便捷重载：基于 NetReport
    static MtuNegotiationResult negotiate(
        std::uint16_t local_mtu,
        std::uint16_t remote_mtu,
        const NetReport &report) noexcept;

    /// V3-B: 跨域场景 MTU 协商（协议规范 §6.3）
    ///
    /// 跨域链路特征：中间设备多（骨干路由器、跨运营商网关、ICP 互联点），
    /// jumbo frame 兼容性差，启用 9000 MTU 易触发 IP 分片或 ICMP 不可达被丢弃。
    /// 协商策略（保守）：
    ///   1. 默认上限 1500（以太网标准 MTU），不启用 jumbo
    ///   2. force_jumbo=true 且双方 local/remote 均 >= 9000 时，方启用 9000
    ///   3. 取 min(local, remote, 1500) 作为协商结果
    ///   4. 困难网络（Symmetric/Unknown/UDP Blocked）进一步降至 1280
    ///
    /// @param local_mtu    本端期望 MTU
    /// @param remote_mtu   对端期望 MTU
    /// @param nat_type     NAT 类型（困难网络降级到 1280）
    /// @param fw           UDP 防火墙状态
    /// @param force_jumbo  是否强制启用 jumbo（默认 false，跨域保守不启用）
    /// @return 协商结果（negotiated_mtu / jumbo_enabled / reason）
    static MtuNegotiationResult negotiate_cross_domain(
        std::uint16_t local_mtu,
        std::uint16_t remote_mtu,
        NatType nat_type,
        UdpFirewall fw = UdpFirewall::Open,
        bool force_jumbo = false) noexcept;

    /// V3-B: 跨域便捷重载：基于 NetReport
    static MtuNegotiationResult negotiate_cross_domain(
        std::uint16_t local_mtu,
        std::uint16_t remote_mtu,
        const NetReport &report,
        bool force_jumbo = false) noexcept;
};

/// PMTU Discovery 结果
struct PmtuResult {
    std::uint16_t discovered_mtu{0};
    bool         success{false};
    std::string  failure_reason;
};

/// PMTU Discovery（Path MTU Discovery）
///
/// 借鉴 RFC 1191：通过发送 DF=1 的探测包，观察是否收到 ICMP Fragmentation Needed
/// 当前实现为基于地址推断的简化版本（不发送实际探测包，避免 ICMP 不可达被防火墙丢弃）：
///   - 私网地址（10.x / 192.168.x / 172.16-31.x） → 9000（可能支持 jumbo）
///   - 公网 IPv4 → 1500
///   - IPv6 → 1280
class PmtuDiscovery {
public:
    /// 探测指定路径的 PMTU
    static PmtuResult discover(const FourTuple &path) noexcept;

    /// 基于 IP 推断 MTU（不发送探测包）
    /// @param host IP 地址或主机名（IPv4/IPv6）
    /// @return 推断的 MTU
    static std::uint16_t infer_mtu_from_addr(const std::string &host) noexcept;
};

/// MTU 是否为 jumbo frame（>= 9000）
constexpr bool is_jumbo(std::uint16_t mtu) noexcept {
    return mtu >= MtuConstants::kJumboMtu;
}

/// MTU 是否有效（[1280, 9000]）
constexpr bool is_valid_mtu(std::uint16_t mtu) noexcept {
    return mtu >= MtuConstants::kMinMtu && mtu <= MtuConstants::kMaxMtu;
}

/// 钳制 MTU 到有效范围
constexpr std::uint16_t clamp_mtu(std::uint16_t mtu) noexcept {
    if (mtu < MtuConstants::kMinMtu) return MtuConstants::kMinMtu;
    if (mtu > MtuConstants::kMaxMtu) return MtuConstants::kMaxMtu;
    return mtu;
}

/// MTU 转字符串（日志用）
inline std::string mtu_name(std::uint16_t mtu) {
    if (mtu >= MtuConstants::kJumboMtu) return "jumbo(9000)";
    if (mtu >= MtuConstants::kStandardMtu) return "standard(1500)";
    if (mtu >= MtuConstants::kMinMtu) return "minimum(1280)";
    return "invalid(" + std::to_string(mtu) + ")";
}

}  // namespace linoh::net
