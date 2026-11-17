// server_config.hpp — NAT 阈值远端下发（NAT 穿透优化 P2-G6）
//
// 借鉴 tdesktop libtgvoip VoIPServerConfig + tg_voip_jni nativeSetConfig：
// 将 NAT 相关阈值从硬编码提升为运行时可调，通过 ctrl/1 控制通道下发 JSON，
// 覆盖 6 类子配置（UdpProbeConfig / FallbackConfig / CgnDetectorConfig /
// PortPredictorConfig / IceSessionConfig）的关键字段。
//
// 设计原则：
//   - std::optional 字段表示"未下发"（merge 时保留原值），下发后含确定值
//   - from_json / to_json / merge 纯逻辑可测，不依赖网络
//   - ServerConfigManager 线程安全单例（shared_mutex 读写分离）
//   - 默认值兜底：未下发字段 apply_to 返回 base 原值，向后兼容
//   - 手写 JSON 解析（无第三方依赖），字段白名单 + 类型校验 + 容错
//
// 与 tdesktop 对比：
//   tdesktop 通过 MTProto 下发 JSON 到 VoIPServerConfig 单例，覆盖静态阈值。
//   本实现通过 ctrl/1 ALPN 下发 JSON 到 ServerConfigManager 单例，覆盖 6 类子配置，
//   并提供 apply_to 分发 + 热更新回调，比 tdesktop 单字段覆盖粒度更粗但更结构化。

#pragma once
#ifndef LINOH_NAT_SERVER_CONFIG_HPP_
#define LINOH_NAT_SERVER_CONFIG_HPP_

#include "linoh/net/udp_probe.hpp"        // net::UdpProbeConfig
#include "linoh/relay/tcp_fallback.hpp"   // relay::FallbackConfig
#include "linoh/nat/cgn_detector.hpp"     // CgnDetectorConfig
#include "linoh/nat/port_predictor.hpp"   // PortPredictorConfig
#include "linoh/nat/ice_session.hpp"      // IceSessionConfig

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>

namespace linoh::nat {

// ============================================================================
// NatServerConfig — NAT 阈值聚合（可服务器下发，运行时覆盖 6 类子配置）
// ============================================================================

/// NAT 相关阈值聚合结构体。
///
/// 字段使用 std::optional 表示"未下发"（merge 时保留原值），下发后含确定值。
/// 通过 from_json() 从 JSON 解析，merge() 合并覆盖，apply_to() 分发到各子配置。
struct NatServerConfig {
    // ===== 打洞/Relay 切换阈值 =====
    std::optional<double> relay_switch_threshold;              ///< relay 切换评分阈值
    std::optional<double> p2p_to_relay_switch_threshold;       ///< P2P→relay 切换
    std::optional<double> relay_to_p2p_switch_threshold;       ///< relay→P2P 切换
    std::optional<std::chrono::milliseconds> reconnecting_state_timeout;

    // ===== G1 UDP 探测阈值（覆盖 UdpProbeConfig）=====
    std::optional<std::uint32_t> udp_probe_count;              ///< ping 数（默认 5）
    std::optional<double> udp_available_threshold;             ///< 可用阈值（默认 0.7）
    std::optional<double> udp_bad_threshold;                   ///< 不可用阈值（默认 0.3）
    std::optional<std::chrono::milliseconds> udp_probe_recv_timeout;

    // ===== G2 TCP 兜底策略（覆盖 FallbackConfig）=====
    std::optional<bool> enable_fec_on_bad;                     ///< Bad 态启用 FEC
    std::optional<std::chrono::milliseconds> tcp_connect_timeout;
    std::optional<bool> skip_udp_probe;                        ///< 强制 TCP

    // ===== CGN 检测阈值（覆盖 CgnDetectorConfig）=====
    std::optional<double> cgn_port_dispersion_threshold;       ///< 端口离散度（默认 0.5）
    std::optional<double> cgn_confidence_threshold;            ///< 置信度（默认 0.3）

    // ===== 端口预测候选数（覆盖 PortPredictorConfig）=====
    std::optional<std::size_t> port_predict_min_candidates;    ///< 默认 5
    std::optional<std::size_t> port_predict_max_candidates;    ///< 默认 20

    // ===== ICE 优化开关（覆盖 IceSessionConfig G5 字段）=====
    std::optional<bool> ice_presume_writable_when_fully_relayed;
    std::optional<bool> ice_skip_relay_to_non_relay;
    std::optional<bool> ice_gather_continually;
    std::optional<bool> ice_prioritize_most_likely_pairs;

    // ===== 编解码 =====

    /// 从 JSON 解析（对齐 tdesktop ServerConfig::Update，未知字段忽略不报错）
    /// @param json JSON 字符串（字段可选，未提供字段留 nullopt）
    /// @return 解析后的配置（解析失败的字段留 nullopt，不抛异常）
    static NatServerConfig from_json(std::string_view json);

    /// 序列化为 JSON（仅已设置字段，用于日志/调试）
    std::string to_json() const;

    // ===== 合并与分发 =====

    /// 合并覆盖（other 中已设置的字段覆盖本对象，未设置的保留）
    NatServerConfig merge(const NatServerConfig &other) const;

    /// 分发到 G1 UdpProbeConfig（仅覆盖已下发字段）
    net::UdpProbeConfig apply_to(const net::UdpProbeConfig &base) const;
    /// 分发到 G2 FallbackConfig
    relay::FallbackConfig apply_to(const relay::FallbackConfig &base) const;
    /// 分发到 CgnDetectorConfig
    CgnDetectorConfig apply_to(const CgnDetectorConfig &base) const;
    /// 分发到 PortPredictorConfig
    PortPredictorConfig apply_to(const PortPredictorConfig &base) const;
    /// 分发到 IceSessionConfig
    IceSessionConfig apply_to(const IceSessionConfig &base) const;

    /// 已设置字段数（用于日志/测试）
    std::size_t set_field_count() const;
};

// ============================================================================
// ServerConfigManager — ServerConfig 单例（对齐 tdesktop ServerConfig 单例）
// ============================================================================

/// ServerConfig 线程安全单例。
///
/// 通过 update(json) 接收 ctrl/1 通道下发的 JSON，解析+合并+回调通知。
/// 各组件通过 config() 获取快照，或 set_changed_callback() 订阅变更。
class ServerConfigManager {
public:
    /// 单例访问
    static ServerConfigManager &instance();

    /// 更新配置（由 Endpoint 收到 ctrl/1 ServerConfigUpdate 后调用）
    /// @param json JSON 字符串（字段可选，未提供字段保留原值）
    /// @return true=解析+合并成功；false=解析失败（保留旧配置，不应用部分更新）
    bool update(const std::string &json);

    /// 获取当前配置快照（线程安全，返回副本）
    NatServerConfig config() const;

    /// 注册配置变更回调（回调在 update 线程触发，用户不应阻塞）
    using ConfigChangedCallback = std::function<void(const NatServerConfig &)>;
    void set_changed_callback(ConfigChangedCallback cb);

    /// 重置为默认值（清空所有下发字段）
    void reset();

private:
    ServerConfigManager() = default;
    ServerConfigManager(const ServerConfigManager &) = delete;
    ServerConfigManager &operator=(const ServerConfigManager &) = delete;

    mutable std::shared_mutex mu_;
    NatServerConfig config_;
    ConfigChangedCallback callback_;
};

} // namespace linoh::nat

#endif // LINOH_NAT_SERVER_CONFIG_HPP_
