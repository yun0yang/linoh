// connect_policy.hpp — v4.0.1 M19 连接策略直连优先
//
// 控制 linoh_endpoint_connect 的连接行为，按 ALPN 通道设置直连要求、
// 超时和 Relay 兜底策略，结合 CGN Detector 置信度优化连接决策。
//
// 设计要点：
//   - 直连优先：hidden_state(pp-hidden/1) 等关键数据强制直连，不走 Relay
//   - CGN 联动：按 CGN Detector 置信度自适应决策
//     高置信度(≥0.7) → DirectOnly（强制直连 + 端口预测打洞）
//     中置信度(0.3-0.7) → DirectWithRelay（直连优先 + Relay 兜底）
//     低置信度(<0.3) → RelayOnly（仅 Relay）
//   - ALPN 级策略：不同 ALPN 通道不同策略
//     pp-hidden/1 → strict_direct（强制直连，无 Relay 兜底）
//     ctrl/1 → control_channel（允许 Relay，控制面必须可达）
//     其他模态 → default_relaxed（默认宽松，允许 Relay 兜底）
//   - 与 M18 衔接：基于 AddrInfo 分级选择最优地址集，ConnectPolicy 决定连接路径
//   - 向后兼容：默认 ConnectPolicy 保持旧行为（允许 Relay 兜底）
//
// ConnectPolicy 编码布局（变长，最小 9 字节）：
//   offset  size  field
//   0       1     version (当前 1)
//   1       1     flags (bit0=require_direct, bit1=relay_fallback, bit2-7 reserved)
//   2       4     direct_timeout_ms (小端序)
//   6       1     alpn_len (0-255)
//   7       N     alpn (UTF-8, N=alpn_len)
//   7+N     2     cgn_confidence_threshold_x100 (置信度×100，小端序，0-10000)
//
// 字节序：direct_timeout_ms 和 cgn_confidence_threshold_x100 使用小端序
// （与 capabilities.hpp 一致，本机序为主）。
// 向后兼容：version 字段允许未来扩展；旧节点忽略 ConnectPolicy 配置走默认策略。

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace linoh::protocol {

/// 连接路径决策结果（CGN Detector 联动）
//
// 由 ConnectPolicy::decide(cgn_confidence) 根据 CGN 置信度返回：
//   - DirectOnly：仅直连（高置信度，端口预测打洞成功率高）
//   - DirectWithRelay：直连优先 + Relay 兜底（中置信度，并行尝试）
//   - RelayOnly：仅 Relay（低置信度，直连几乎必败）
enum class ConnectDecision : std::uint8_t {
    DirectOnly       = 0,  // 仅直连（高置信度 ≥ high_threshold）
    DirectWithRelay  = 1,  // 直连优先 + Relay 兜底（中置信度）
    RelayOnly        = 2,  // 仅 Relay（低置信度 < threshold）
};

/// ConnectDecision 转字符串（日志用）
inline const char *to_string(ConnectDecision d) noexcept {
    switch (d) {
        case ConnectDecision::DirectOnly:      return "DirectOnly";
        case ConnectDecision::DirectWithRelay: return "DirectWithRelay";
        case ConnectDecision::RelayOnly:       return "RelayOnly";
    }
    return "Unknown";
}

/// 连接策略（控制 linoh_endpoint_connect 行为）
//
// 按 ALPN 通道设置直连要求、超时和 Relay 兜底策略。
// 与 CGN Detector 联动，根据置信度自适应决策连接路径。
struct ConnectPolicy {
    static constexpr std::uint8_t kCurrentVersion = 1;
    static constexpr std::size_t kMinEncodedSize = 9;  // version(1)+flags(1)+timeout(4)+alpn_len(1)+threshold(2)
    static constexpr std::uint8_t kMaxAlpnLen = 255;

    /// CGN 置信度阈值常量（M19 默认值）
    /// 高置信度阈值：≥ 此值 → DirectOnly
    static constexpr double kHighConfidenceThreshold = 0.7;
    /// 低置信度阈值：< 此值 → RelayOnly
    static constexpr double kLowConfidenceThreshold = 0.3;

    /// 是否强制直连（true=不走 Relay，false=允许 Relay 兜底）
    bool require_direct{false};

    /// 直连尝试超时（毫秒），超时后根据 relay_fallback 决定是否回退 Relay
    /// 默认 5000ms（与 ICE 默认超时一致）
    std::uint32_t direct_timeout_ms{5000};

    /// 直连失败后是否允许 Relay 兜底
    /// 若 require_direct=true 且 relay_fallback=false，直连失败直接放弃
    bool relay_fallback{true};

    /// 目标 ALPN 通道（决定策略应用范围，空字符串=所有通道）
    std::string alpn;

    /// CGN 置信度阈值（低于此值时强制走 Relay）
    /// 默认 0.3（与 kLowConfidenceThreshold 一致）
    double cgn_confidence_threshold{kLowConfidenceThreshold};

    // -------- 工厂方法 --------

    /// 默认宽松策略（向后兼容：允许 Relay 兜底，5s 超时）
    /// 适用于未知 ALPN 或非关键数据通道
    static ConnectPolicy default_relaxed();

    /// 强制直连策略（hidden_state 等关键数据）
    /// require_direct=true, relay_fallback=false, 10s 超时
    static ConnectPolicy strict_direct(const std::string &alpn);

    /// 控制面策略（允许 Relay，控制面必须可达）
    /// require_direct=false, relay_fallback=true, 3s 超时（控制面要求快速）
    static ConnectPolicy control_channel();

    /// 按 ALPN 推荐策略
    /// pp-hidden/1 → strict_direct
    /// ctrl/1 → control_channel
    /// 其他 → default_relaxed
    static ConnectPolicy for_alpn(const std::string &alpn);

    // -------- 决策函数 --------

    /// 根据 CGN 置信度决策连接路径
    /// @param cgn_confidence CGN Detector 置信度 [0.0, 1.0]
    /// @return 连接路径决策（DirectOnly/DirectWithRelay/RelayOnly）
    ///
    /// 决策逻辑：
    ///   - require_direct=true 时：
    ///     cgn_confidence ≥ kHighConfidenceThreshold(0.7) → DirectOnly
    ///     cgn_confidence ≥ cgn_confidence_threshold → DirectOnly（强制直连）
    ///     cgn_confidence < cgn_confidence_threshold 且 relay_fallback → RelayOnly
    ///     cgn_confidence < cgn_confidence_threshold 且 !relay_fallback → DirectOnly（宁可失败也不走 Relay）
    ///   - require_direct=false 时：
    ///     cgn_confidence ≥ kHighConfidenceThreshold(0.7) → DirectOnly
    ///     cgn_confidence ≥ cgn_confidence_threshold → DirectWithRelay
    ///     cgn_confidence < cgn_confidence_threshold → RelayOnly
    ConnectDecision decide(double cgn_confidence) const;

    // -------- 序列化（用于配置传播） --------

    /// 序列化为字节流（变长，最小 9 字节）
    std::vector<std::uint8_t> encode() const;

    /// 从字节流反序列化
    /// @return true=成功，false=数据格式错误（长度不足/字段越界）
    static bool decode(std::span<const std::uint8_t> data, ConnectPolicy &out);

    /// 简要描述（日志用）
    std::string to_string() const;

    /// 相等比较（测试用）
    bool operator==(const ConnectPolicy &other) const noexcept {
        return require_direct == other.require_direct &&
               direct_timeout_ms == other.direct_timeout_ms &&
               relay_fallback == other.relay_fallback &&
               alpn == other.alpn;
        // cgn_confidence_threshold 是浮点，不参与相等比较（精度问题）
    }
};

}  // namespace linoh::protocol
