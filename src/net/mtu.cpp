// mtu.cpp — MTU 协商 + Jumbo Frame 实现（P5-B-4）

#include "linoh/net/mtu.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

namespace linoh::net {

// ============================================================================
// 内部辅助：判断是否为私网地址 / IPv6
// ============================================================================

namespace {

/// 判断 IPv4 字符串是否为私网地址（RFC 1918）
bool is_private_ipv4(std::string_view host) noexcept {
    // 10.x.x.x — 需要 "10." + 至少 1 位数字，size >= 4
    if (host.size() >= 4 && host.substr(0, 3) == "10." &&
        std::isdigit(static_cast<unsigned char>(host[3]))) {
        return true;
    }
    // 192.168.x.x
    if (host.size() >= 8 && host.substr(0, 8) == "192.168.") {
        return true;
    }
    // 172.16.x.x ~ 172.31.x.x
    if (host.size() >= 7 && host.substr(0, 4) == "172.") {
        // 提取第二段
        std::size_t pos = 4;
        std::string seg;
        while (pos < host.size() && host[pos] != '.') {
            seg.push_back(host[pos]);
            ++pos;
        }
        if (!seg.empty()) {
            int v = 0;
            for (char c : seg) {
                if (!std::isdigit(static_cast<unsigned char>(c))) return false;
                v = v * 10 + (c - '0');
            }
            if (v >= 16 && v <= 31) return true;
        }
    }
    return false;
}

/// 判断字符串是否为 IPv6 地址（简单启发式：包含 ':'）
bool is_ipv6(std::string_view host) noexcept {
    // 防止误判 "[ipv6]:port" 格式
    if (host.empty()) return false;
    // 去除可能的方括号
    std::string_view h = host;
    if (h.front() == '[') h = h.substr(1);
    return h.find(':') != std::string_view::npos;
}

}  // namespace

// ============================================================================
// MtuNegotiator
// ============================================================================

MtuNegotiationResult MtuNegotiator::negotiate(
    std::uint16_t local_mtu,
    std::uint16_t remote_mtu,
    NatType nat_type,
    UdpFirewall fw) noexcept {
    MtuNegotiationResult result;

    // 钳制输入到有效范围
    std::uint16_t lm = clamp_mtu(local_mtu);
    std::uint16_t rm = clamp_mtu(remote_mtu);

    // 困难网络：UDP blocked 或 Symmetric/Unknown → 保守 1280
    if (fw == UdpFirewall::Blocked) {
        result.negotiated_mtu = MtuConstants::kMinMtu;
        result.jumbo_enabled = false;
        result.reason = "UDP blocked, fallback to minimum MTU";
        return result;
    }
    if (nat_type == NatType::Symmetric || nat_type == NatType::Unknown) {
        result.negotiated_mtu = MtuConstants::kMinMtu;
        result.jumbo_enabled = false;
        result.reason = "Hard NAT (symmetric/unknown), fallback to minimum MTU";
        return result;
    }

    // OpenInternet / FullCone / RestrictedCone / PortRestrictedCone：
    // 取 min(local, remote)，但 RestrictedCone/PortRestrictedCone 不允许 jumbo
    std::uint16_t mtu = std::min(lm, rm);
    bool allow_jumbo = (nat_type == NatType::OpenInternet ||
                         nat_type == NatType::FullCone);

    if (is_jumbo(mtu) && !allow_jumbo) {
        // RestrictedCone/PortRestrictedCone 不允许 jumbo，降级到 1500
        mtu = MtuConstants::kStandardMtu;
        result.reason = "Restricted NAT, downgrade jumbo to standard MTU";
    } else if (is_jumbo(mtu)) {
        result.reason = "Both sides support jumbo frame, LAN class network";
    } else if (mtu >= MtuConstants::kStandardMtu) {
        result.reason = "Standard Ethernet MTU";
    } else {
        result.reason = "Minimum QUIC MTU";
    }

    result.negotiated_mtu = mtu;
    result.jumbo_enabled = is_jumbo(mtu);
    return result;
}

MtuNegotiationResult MtuNegotiator::negotiate(
    std::uint16_t local_mtu,
    std::uint16_t remote_mtu,
    const NetReport &report) noexcept {
    return negotiate(local_mtu, remote_mtu, report.nat_type, report.udp_firewall);
}

// ============================================================================
// V3-B: 跨域 MTU 协商
// ============================================================================

MtuNegotiationResult MtuNegotiator::negotiate_cross_domain(
    std::uint16_t local_mtu,
    std::uint16_t remote_mtu,
    NatType nat_type,
    UdpFirewall fw,
    bool force_jumbo) noexcept {
    MtuNegotiationResult result;

    // 钳制输入到有效范围
    std::uint16_t lm = clamp_mtu(local_mtu);
    std::uint16_t rm = clamp_mtu(remote_mtu);

    // 困难网络：UDP blocked 或 Symmetric/Unknown → 保守 1280
    if (fw == UdpFirewall::Blocked) {
        result.negotiated_mtu = MtuConstants::kMinMtu;
        result.jumbo_enabled = false;
        result.reason = "Cross-domain: UDP blocked, fallback to minimum MTU";
        return result;
    }
    if (nat_type == NatType::Symmetric || nat_type == NatType::Unknown) {
        result.negotiated_mtu = MtuConstants::kMinMtu;
        result.jumbo_enabled = false;
        result.reason = "Cross-domain: Hard NAT (symmetric/unknown), fallback to minimum MTU";
        return result;
    }

    // V3-B 跨域保守策略：默认不启用 jumbo，上限 1500
    // 仅当 force_jumbo=true 且双方均支持 9000 时，方启用 jumbo
    if (force_jumbo && is_jumbo(lm) && is_jumbo(rm)) {
        // 跨域骨干直连场景（如 orchestrator 间专线），允许 jumbo
        result.negotiated_mtu = MtuConstants::kJumboMtu;
        result.jumbo_enabled = true;
        result.reason = "Cross-domain: force_jumbo + both sides support 9000, enable jumbo";
        return result;
    }

    // 默认跨域协商：取 min(local, remote, 1500)
    std::uint16_t mtu = (std::min)(lm, rm);
    if (mtu > MtuConstants::kStandardMtu) {
        mtu = MtuConstants::kStandardMtu;  // 跨域默认上限 1500
    }
    // 下限保护
    if (mtu < MtuConstants::kMinMtu) {
        mtu = MtuConstants::kMinMtu;
    }

    result.negotiated_mtu = mtu;
    result.jumbo_enabled = false;
    if (mtu >= MtuConstants::kStandardMtu) {
        result.reason = "Cross-domain: standard Ethernet MTU (conservative, no jumbo)";
    } else {
        result.reason = "Cross-domain: minimum QUIC MTU (one side < 1500)";
    }
    return result;
}

MtuNegotiationResult MtuNegotiator::negotiate_cross_domain(
    std::uint16_t local_mtu,
    std::uint16_t remote_mtu,
    const NetReport &report,
    bool force_jumbo) noexcept {
    return negotiate_cross_domain(local_mtu, remote_mtu,
                                  report.nat_type, report.udp_firewall,
                                  force_jumbo);
}

// ============================================================================
// PmtuDiscovery
// ============================================================================

std::uint16_t PmtuDiscovery::infer_mtu_from_addr(const std::string &host) noexcept {
    if (host.empty()) return MtuConstants::kMinMtu;

    // IPv6 → 1280
    if (is_ipv6(host)) {
        return MtuConstants::kMinMtu;
    }

    // 私网 IPv4 → 9000
    if (is_private_ipv4(host)) {
        return MtuConstants::kJumboMtu;
    }

    // 公网 IPv4 → 1500
    return MtuConstants::kStandardMtu;
}

PmtuResult PmtuDiscovery::discover(const FourTuple &path) noexcept {
    PmtuResult result;
    // 用对端地址推断（路径瓶颈通常在对端方向）
    std::uint16_t remote_mtu = infer_mtu_from_addr(path.remote_addr.host);
    std::uint16_t local_mtu  = infer_mtu_from_addr(path.local_addr.host);
    // 取较小值作为路径 MTU
    result.discovered_mtu = std::min(remote_mtu, local_mtu);
    result.success = true;
    if (is_jumbo(result.discovered_mtu)) {
        result.failure_reason = "Private network, jumbo frame likely supported";
    } else if (result.discovered_mtu >= MtuConstants::kStandardMtu) {
        result.failure_reason = "Public network, standard MTU";
    } else {
        result.failure_reason = "IPv6 or unknown, minimum MTU";
    }
    return result;
}

}  // namespace linoh::net
