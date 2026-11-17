// tcp_fallback.cpp — TCP 兜底降级编排实现（NAT 穿透优化 P0-G2）

#include "linoh/relay/tcp_fallback.hpp"
#include "linoh/net/udp_probe.hpp"
#include "linoh/util/logging.hpp"

#include <chrono>

namespace linoh::relay {

// ============================================================================
// FallbackResult::to_string
// ============================================================================

std::string FallbackResult::to_string() const {
    std::string s = "FallbackResult{decision=";
    s += std::string(to_string_view(decision));
    s += ", udp=";
    s += std::string(net::to_string_view(udp_probe.availability));
    s += ", loss_rate=";
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%.1f%%", udp_probe.loss_rate * 100.0);
    s += buf;
    if (tcp_attempted) {
        s += ", tcp_attempted=";
        s += (tcp_succeeded ? "success" : "failed");
    }
    if (relay_attempted) {
        s += ", relay_attempted=true";
    }
    s += ", duration=";
    s += std::to_string(total_duration.count());
    s += "ms";
    if (!error_msg.empty()) {
        s += ", error='";
        s += error_msg;
        s += "'";
    }
    s += "}";
    return s;
}

// ============================================================================
// TcpFallback::decide — 纯逻辑决策
// ============================================================================

FallbackDecision TcpFallback::decide(
    net::UdpAvailability availability,
    bool enable_fec_on_bad) {

    switch (availability) {
        case net::UdpAvailability::Available:
            return FallbackDecision::UseUdp;

        case net::UdpAvailability::Bad:
            // Bad 状态：根据配置决定启用 FEC 还是直接降级 TCP
            return enable_fec_on_bad
                ? FallbackDecision::UseUdpWithFec
                : FallbackDecision::UseTcp;

        case net::UdpAvailability::NotAvailable:
            // UDP 不可用，必须降级 TCP
            return FallbackDecision::UseTcp;
    }
    // 不应到达
    return FallbackDecision::UseTcp;
}

// ============================================================================
// TcpFallback::orchestrate_with_providers — mock 路径（测试用）
// ============================================================================

FallbackResult TcpFallback::orchestrate_with_providers(
    const std::string &remote_ip, std::uint16_t remote_port,
    const FallbackConfig &config,
    net::UdpPingProvider udp_provider,
    TcpConnectProvider tcp_provider) {

    auto start = std::chrono::steady_clock::now();
    FallbackResult result;

    // 步骤 1：跳过 UDP 探测直接走 TCP（强制降级场景）
    if (config.skip_udp_probe) {
        LINOH_INFO("TcpFallback: skip_udp_probe=true, directly trying TCP");
        result.decision = FallbackDecision::UseTcp;
        result.tcp_attempted = true;
        if (tcp_provider) {
            result.tcp_succeeded = tcp_provider(
                remote_ip, remote_port, config.tcp_connect_timeout);
            if (result.tcp_succeeded) {
                LINOH_INFO("TcpFallback: TCP connect succeeded, decision=UseTcp");
            } else {
                LINOH_INFO("TcpFallback: TCP connect failed, fallback to Relay");
                result.decision = FallbackDecision::UseRelay;
                result.relay_attempted = true;
            }
        } else {
            // 无 TCP provider，直接 Relay
            result.decision = FallbackDecision::UseRelay;
            result.relay_attempted = true;
        }
        result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    // 步骤 2：UDP 探测
    if (!udp_provider) {
        result.error_msg = "udp_provider is null";
        result.decision = FallbackDecision::UseRelay;
        result.relay_attempted = true;
        result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    result.udp_probe = net::UdpProber::probe_with_provider(
        remote_ip, remote_port, config.udp_probe_config, udp_provider);

    // 步骤 3：根据探测结果决策
    result.decision = decide(result.udp_probe.availability, config.enable_fec_on_bad);

    // UseUdp / UseUdpWithFec：直接返回，无需尝试 TCP
    if (result.decision == FallbackDecision::UseUdp ||
        result.decision == FallbackDecision::UseUdpWithFec) {
        LINOH_INFO("TcpFallback: UDP decision=", to_string_view(result.decision),
                   ", no TCP fallback needed");
        result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    // 步骤 4：UseTcp → 尝试 TCP 连接
    if (result.decision == FallbackDecision::UseTcp) {
        result.tcp_attempted = true;
        if (tcp_provider) {
            result.tcp_succeeded = tcp_provider(
                remote_ip, remote_port, config.tcp_connect_timeout);
            if (result.tcp_succeeded) {
                LINOH_INFO("TcpFallback: TCP connect succeeded, decision=UseTcp");
            } else {
                // 步骤 5：TCP 失败 → Relay 兜底
                LINOH_INFO("TcpFallback: TCP connect failed, fallback to Relay");
                result.decision = FallbackDecision::UseRelay;
                result.relay_attempted = true;
            }
        } else {
            // 无 TCP provider，直接 Relay
            LINOH_INFO("TcpFallback: no tcp_provider, directly fallback to Relay");
            result.decision = FallbackDecision::UseRelay;
            result.relay_attempted = true;
        }
    }

    result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return result;
}

// ============================================================================
// TcpFallback::orchestrate — 真实 socket 路径（生产用）
// ============================================================================

FallbackResult TcpFallback::orchestrate(
    const std::string &local_ip, std::uint16_t local_port,
    const std::string &remote_ip, std::uint16_t remote_port,
    const FallbackConfig &config,
    TcpConnectProvider connect_fn) {

    auto start = std::chrono::steady_clock::now();
    FallbackResult result;

    // 步骤 1：跳过 UDP 探测直接走 TCP（强制降级场景）
    if (config.skip_udp_probe) {
        LINOH_INFO("TcpFallback: skip_udp_probe=true, directly trying TCP");
        result.decision = FallbackDecision::UseTcp;
        result.tcp_attempted = true;
        if (connect_fn) {
            result.tcp_succeeded = connect_fn(
                remote_ip, remote_port, config.tcp_connect_timeout);
            if (result.tcp_succeeded) {
                LINOH_INFO("TcpFallback: TCP connect succeeded, decision=UseTcp");
            } else {
                LINOH_INFO("TcpFallback: TCP connect failed, fallback to Relay");
                result.decision = FallbackDecision::UseRelay;
                result.relay_attempted = true;
            }
        } else {
            result.decision = FallbackDecision::UseRelay;
            result.relay_attempted = true;
        }
        result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    // 步骤 2：UDP 探测（真实 socket）
    result.udp_probe = net::UdpProber::probe(
        local_ip, local_port, remote_ip, remote_port, config.udp_probe_config);

    // 步骤 3：根据探测结果决策
    result.decision = decide(result.udp_probe.availability, config.enable_fec_on_bad);

    // UseUdp / UseUdpWithFec：直接返回
    if (result.decision == FallbackDecision::UseUdp ||
        result.decision == FallbackDecision::UseUdpWithFec) {
        LINOH_INFO("TcpFallback: UDP decision=", to_string_view(result.decision),
                   ", no TCP fallback needed");
        result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    // 步骤 4：UseTcp → 尝试 TCP 连接（由 connect_fn 执行）
    if (result.decision == FallbackDecision::UseTcp) {
        result.tcp_attempted = true;
        if (connect_fn) {
            result.tcp_succeeded = connect_fn(
                remote_ip, remote_port, config.tcp_connect_timeout);
            if (result.tcp_succeeded) {
                LINOH_INFO("TcpFallback: TCP connect succeeded, decision=UseTcp");
            } else {
                // 步骤 5：TCP 失败 → Relay 兜底
                LINOH_INFO("TcpFallback: TCP connect failed, fallback to Relay");
                result.decision = FallbackDecision::UseRelay;
                result.relay_attempted = true;
            }
        } else {
            // 无 connect_fn，直接 Relay
            LINOH_INFO("TcpFallback: no connect_fn, directly fallback to Relay");
            result.decision = FallbackDecision::UseRelay;
            result.relay_attempted = true;
        }
    }

    result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return result;
}

} // namespace linoh::relay
