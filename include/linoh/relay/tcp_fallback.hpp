// tcp_fallback.hpp — TCP 兜底降级编排（NAT 穿透优化 P0-G2）
//
// 借鉴 tdesktop 的 UDP→TCP 降级机制：当 UDP 可用性探测判定为 NotAvailable
// 时，立即降级到 TCP 连接；若 TCP 也失败，再降级到 Relay 中继。
//
// 设计原则：
//   - 纯编排层：只做决策，不直接做 TCP/Relay 连接（避免引入 asio 依赖）
//   - 实际连接由上层 Endpoint 根据 FallbackDecision 执行
//   - 提供 TcpConnectProvider 回调，测试可注入 mock 而不依赖真实网络
//   - 决策逻辑与 I/O 分离：decide 是纯函数，便于单元测试
//
// 决策矩阵：
//   UdpAvailability::Available    → UseUdp（直接打洞）
//   UdpAvailability::Bad          → UseUdpWithFec（打洞 + FEC 增强）或 UseTcp
//                                    （由 enable_fec_on_bad 控制）
//   UdpAvailability::NotAvailable → UseTcp（TCP 连接尝试）
//   TCP 失败                      → UseRelay（Relay 中继兜底）
//
// 与 tdesktop 对比：
//   tdesktop 在 MTPPingDelayDisconnect 中若 UDP ping 超时则立即切换 TCP，
//   无中间态。本实现增加 Bad 中间态（UseUdpWithFec），在 UDP 质量差但非
//   完全不可用时仍走 UDP 但启用 FEC 增强，避免过早降级到 TCP 带来的性能损失。

#pragma once
#ifndef LINOH_RELAY_TCP_FALLBACK_HPP_
#define LINOH_RELAY_TCP_FALLBACK_HPP_

#include "linoh/net/udp_probe.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace linoh::relay {

// ============================================================================
// 降级决策结果
// ============================================================================

enum class FallbackDecision {
    UseUdp,         ///< UDP 可用，直接走打洞
    UseUdpWithFec,  ///< UDP 质量差，走打洞但启用 FEC 增强
    UseTcp,         ///< UDP 不可用，降级到 TCP 直连
    UseRelay,       ///< TCP 也失败，降级到 Relay 中继
};

/// FallbackDecision 转字符串（用于日志和测试断言）
inline std::string_view to_string_view(FallbackDecision d) {
    switch (d) {
        case FallbackDecision::UseUdp:        return "use-udp";
        case FallbackDecision::UseUdpWithFec: return "use-udp-with-fec";
        case FallbackDecision::UseTcp:        return "use-tcp";
        case FallbackDecision::UseRelay:      return "use-relay";
    }
    return "unknown";
}

// ============================================================================
// 降级结果与配置
// ============================================================================

/// 降级编排结果
struct FallbackResult {
    FallbackDecision decision{FallbackDecision::UseUdp};
    net::UdpProbeResult udp_probe;        ///< UDP 探测结果（决策依据）
    bool tcp_attempted{false};            ///< 是否尝试了 TCP
    bool tcp_succeeded{false};            ///< TCP 是否成功
    bool relay_attempted{false};          ///< 是否尝试了 Relay
    std::chrono::milliseconds total_duration{0};
    std::string error_msg;                ///< 错误信息

    /// 结果转字符串（用于日志）
    std::string to_string() const;
};

/// 降级配置
struct FallbackConfig {
    net::UdpProbeConfig udp_probe_config;             ///< UDP 探测配置
    bool enable_fec_on_bad{true};                     ///< Bad 状态时启用 FEC（false 则 Bad 也降级 TCP）
    std::chrono::milliseconds tcp_connect_timeout{3000}; ///< TCP 连接超时
    std::vector<std::string> relay_urls;              ///< Relay URL 列表（TCP 失败后尝试）
    bool skip_udp_probe{false};                       ///< 跳过 UDP 探测直接走 TCP（测试/强制降级用）
};

// ============================================================================
// TcpConnectProvider 回调（用于 mock 测试）
// ============================================================================

/// TCP 连接回调接口：尝试连接到 (host, port) 并返回是否成功。
///
/// 测试时注入 mock provider，避免依赖真实网络。生产代码由 Endpoint 提供
/// 真实的 TCP 连接实现（基于 asio 或阻塞 socket）。
///
/// @param host 目标主机
/// @param port 目标端口
/// @param timeout 连接超时
/// @return true 表示连接成功，false 表示失败
using TcpConnectProvider = std::function<bool(
    const std::string &host,
    std::uint16_t port,
    std::chrono::milliseconds timeout)>;

// ============================================================================
// TcpFallback 编排器
// ============================================================================

/// TCP 兜底降级编排器
class TcpFallback {
public:
    /// 编排降级决策（真实 socket 路径，TCP 连接由调用方提供 connect_fn）
    ///
    /// 流程：
    ///   1. 若 skip_udp_probe → 直接 UseTcp（跳过 UDP 探测）
    ///   2. 否则调用 UdpProber::probe 探测 UDP 可用性
    ///   3. 根据探测结果 decide()：
    ///      - Available → UseUdp，返回
    ///      - Bad + enable_fec_on_bad → UseUdpWithFec，返回
    ///      - Bad + !enable_fec_on_bad → 尝试 TCP
    ///      - NotAvailable → 尝试 TCP
    ///   4. TCP 尝试：调用 connect_fn(remote_ip, remote_port, tcp_timeout)
    ///      - 成功 → UseTcp，返回
    ///      - 失败 → 进入 Relay 兜底
    ///   5. Relay 兜底：返回 UseRelay（实际 Relay 连接由上层执行）
    ///
    /// @param local_ip 本地绑定 IP（UDP 探测用）
    /// @param local_port 本地绑定端口（UDP 探测用）
    /// @param remote_ip 对端 IP
    /// @param remote_port 对端端口
    /// @param config 降级配置
    /// @param connect_fn TCP 连接回调（可为 nullptr，nullptr 时跳过 TCP 直接 Relay）
    static FallbackResult orchestrate(
        const std::string &local_ip, std::uint16_t local_port,
        const std::string &remote_ip, std::uint16_t remote_port,
        const FallbackConfig &config,
        TcpConnectProvider connect_fn);

    /// 编排降级决策（mock 路径，测试用）
    ///
    /// 与 orchestrate 逻辑一致，但 UDP 探测由 udp_provider 模拟，
    /// TCP 连接由 tcp_provider 模拟，不创建真实 socket。
    static FallbackResult orchestrate_with_providers(
        const std::string &remote_ip, std::uint16_t remote_port,
        const FallbackConfig &config,
        net::UdpPingProvider udp_provider,
        TcpConnectProvider tcp_provider);

    /// 根据 UDP 可用性决策（纯逻辑，便于单元测试）
    ///
    /// 决策规则：
    ///   - Available → UseUdp
    ///   - Bad + enable_fec_on_bad=true → UseUdpWithFec
    ///   - Bad + enable_fec_on_bad=false → UseTcp
    ///   - NotAvailable → UseTcp
    ///
    /// @param availability UDP 可用性
    /// @param enable_fec_on_bad Bad 状态时是否启用 FEC
    static FallbackDecision decide(
        net::UdpAvailability availability,
        bool enable_fec_on_bad);

    /// FallbackDecision 转字符串（兼容旧调用）
    static std::string_view decision_name(FallbackDecision d) {
        return to_string_view(d);
    }
};

} // namespace linoh::relay

#endif // LINOH_RELAY_TCP_FALLBACK_HPP_
