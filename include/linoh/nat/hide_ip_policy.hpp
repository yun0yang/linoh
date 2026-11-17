// hide_ip_policy.hpp — P2-G8 隐藏 IP 隐私模式策略（独立纯函数）
//
// 借鉴 tdesktop 隐藏 IP 策略 + WebRTC RTCIceCandidateFilter：
// 通过三重禁用（host/srflx/upnp/mdns candidate + UDP 探测 + 候选过滤兜底）
// 仅保留 Relay 候选，防止本机真实 IP 泄露。
//
// 设计原则：
//   - 纯函数：apply_hide_ip_policy 直接修改传入的配置引用，不依赖 Endpoint 内部状态
//   - 可独立单元测试：无需构造 Endpoint 即可验证策略覆盖正确性
//   - 幂等：多次调用结果一致（覆盖式设置）
//   - Endpoint 集成：Endpoint::Config.hide_real_ip=true 时构造期调用本函数
//
// 三重禁用策略：
//   1. CandidateCollectorConfig: enable_host=false / enable_srflx=false /
//      enable_upnp=false / enable_mdns=false / candidate_filter=CF_RELAY
//      → gather 阶段不收集任何可能暴露本地 IP 的候选
//   2. FallbackConfig: skip_udp_probe=true
//      → 强制跳过 UDP 探测走 TCP Relay（UDP 包源地址会暴露本地 IP）
//   3. IceSessionConfig: presume_writable_when_fully_relayed=true /
//      skip_relay_to_non_relay_connections=true
//      → G5 联动：全 relay 路径跳过 STUN 检查 + 过滤 relay↔direct 候选对
//
// 与 tdesktop 对比：
//   tdesktop 在 MTPConfig 中通过 proxy 选项隐藏 IP，所有流量走 proxy。
//   本实现通过候选过滤 + 强制 Relay 实现等价效果，但保留 P2P Relay 路径
//   的低延迟优势（Relay 间仍可 P2P），仅对端看不到本机真实 IP。

#pragma once
#ifndef LINOH_NAT_HIDE_IP_POLICY_HPP_
#define LINOH_NAT_HIDE_IP_POLICY_HPP_

#include "linoh/nat/ice_candidate.hpp"  // CandidateCollectorConfig, CandidateFilter, CF_RELAY
#include "linoh/relay/tcp_fallback.hpp"  // relay::FallbackConfig
#include "linoh/nat/ice_session.hpp"     // IceSessionConfig

namespace linoh::nat {

/// 应用隐藏 IP 隐私策略到候选收集配置
///
/// 覆盖以下字段（无论原值如何）：
///   - enable_host = false
///   - enable_srflx = false
///   - enable_upnp = false
///   - enable_mdns = false
///   - candidate_filter = CF_RELAY（兜底过滤，确保仅 Relay）
inline void apply_hide_ip_to_collector(CandidateCollectorConfig &cfg) noexcept {
    cfg.enable_host = false;
    cfg.enable_srflx = false;
    cfg.enable_upnp = false;
    cfg.enable_mdns = false;
    cfg.candidate_filter = CF_RELAY;
}

/// 应用隐藏 IP 隐私策略到 TCP 兜底配置
///
/// 覆盖以下字段：
///   - skip_udp_probe = true（强制跳过 UDP 探测，走 TCP Relay）
inline void apply_hide_ip_to_fallback(relay::FallbackConfig &cfg) noexcept {
    cfg.skip_udp_probe = true;
}

/// 应用隐藏 IP 隐私策略到 ICE 会话配置（G5 联动）
///
/// 覆盖以下字段：
///   - presume_writable_when_fully_relayed = true（全 relay 路径跳过 STUN）
///   - skip_relay_to_non_relay_connections = true（过滤 relay↔direct 候选对）
inline void apply_hide_ip_to_ice(IceSessionConfig &cfg) noexcept {
    cfg.presume_writable_when_fully_relayed = true;
    cfg.skip_relay_to_non_relay_connections = true;
}

/// 应用隐藏 IP 隐私策略到全部三组配置（便捷聚合）
///
/// 等价于依次调用三个 apply_hide_ip_to_* 函数。
/// Endpoint::Config.hide_real_ip=true 时构造期调用本函数。
inline void apply_hide_ip_policy(
    CandidateCollectorConfig &collector,
    relay::FallbackConfig &fallback,
    IceSessionConfig &ice) noexcept {
    apply_hide_ip_to_collector(collector);
    apply_hide_ip_to_fallback(fallback);
    apply_hide_ip_to_ice(ice);
}

/// 检查候选收集配置是否符合隐藏 IP 策略（用于测试断言和运行时审计）
inline bool is_hide_ip_collector_config(const CandidateCollectorConfig &cfg) noexcept {
    return cfg.enable_host == false
        && cfg.enable_srflx == false
        && cfg.enable_upnp == false
        && cfg.enable_mdns == false
        && cfg.candidate_filter == CF_RELAY;
}

/// 检查 TCP 兜底配置是否符合隐藏 IP 策略
inline bool is_hide_ip_fallback_config(const relay::FallbackConfig &cfg) noexcept {
    return cfg.skip_udp_probe == true;
}

/// 检查 ICE 会话配置是否符合隐藏 IP 策略
inline bool is_hide_ip_ice_config(const IceSessionConfig &cfg) noexcept {
    return cfg.presume_writable_when_fully_relayed == true
        && cfg.skip_relay_to_non_relay_connections == true;
}

/// 检查全部三组配置是否符合隐藏 IP 策略
inline bool is_hide_ip_policy_applied(
    const CandidateCollectorConfig &collector,
    const relay::FallbackConfig &fallback,
    const IceSessionConfig &ice) noexcept {
    return is_hide_ip_collector_config(collector)
        && is_hide_ip_fallback_config(fallback)
        && is_hide_ip_ice_config(ice);
}

} // namespace linoh::nat

#endif // LINOH_NAT_HIDE_IP_POLICY_HPP_
