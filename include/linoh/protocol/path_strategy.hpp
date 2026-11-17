// path_strategy.hpp — 可配置路径选择策略（P4-B-3）
//
// 借鉴 iroh PR #4232（Configurable path selection）：
//   - 抽象 PathSelectionStrategy 接口
//   - 默认策略 RttBasedStrategy（保持现有 BiasedRttPathSelector 行为）
//   - PreferDirectStrategy：优先直连地址（非 Relay）
//   - PreferRelayStrategy：优先 Relay 地址（适合 hard NAT）
//   - 应用可通过 EndpointBuilder 注入自定义策略
//
// 与 net::PathSelector 的关系：
//   - net::PathSelector 是低层接口，输入是 vector<shared_ptr<Path>>
//   - protocol::PathSelectionStrategy 是高层接口，输入是 vector<PathQuality>
//   - 两者并行存在，PathSelectionStrategy 用于 PathMigrationManager 决策

#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/protocol/path_migration.hpp"

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace linoh::protocol {

/// 路径选择策略接口（借鉴 iroh Configurable path selection）
///
/// 应用可通过实现此接口定制路径选择逻辑，例如：
///   - 按带宽选路（需要上层提供带宽指标）
///   - 按成本选路（Relay 可能产生流量费用）
///   - 按地理位置选路（延迟优先 vs 国内优先）
class PathSelectionStrategy {
public:
    virtual ~PathSelectionStrategy() = default;

    /// 从候选路径中选择主路径
    ///
    /// @param candidates 候选路径列表（按 path_id 排序）
    /// @return 选中的路径四元组，空列表返回 nullopt
    virtual std::optional<net::FourTuple> select(
        const std::vector<PathMigrationManager::PathQuality> &candidates) = 0;

    /// 策略名称（用于日志和诊断）
    virtual std::string_view name() const = 0;
};

/// 默认策略：按 RTT 选路（保持现有行为）
///
/// - 排除 srtt=0（未测量）的路径
/// - 选 srtt 最小的路径
/// - 全部未测量时返回 nullopt（保守，不切换）
class RttBasedStrategy : public PathSelectionStrategy {
public:
    std::optional<net::FourTuple> select(
        const std::vector<PathMigrationManager::PathQuality> &candidates) override;

    std::string_view name() const override { return "rtt"; }
};

/// 优先直连策略：直连失败才用 Relay
///
/// - 优先选 TransportKind::Ip 的路径
/// - 同类内按 RTT 排序
/// - 直连全失败时才选 Relay
class PreferDirectStrategy : public PathSelectionStrategy {
public:
    std::optional<net::FourTuple> select(
        const std::vector<PathMigrationManager::PathQuality> &candidates) override;

    std::string_view name() const override { return "prefer-direct"; }
};

/// 优先 Relay 策略：始终走 Relay（适合 hard NAT）
///
/// - 优先选 TransportKind::Relay 的路径
/// - 同类内按 RTT 排序
/// - Relay 全失败时才选直连
class PreferRelayStrategy : public PathSelectionStrategy {
public:
    std::optional<net::FourTuple> select(
        const std::vector<PathMigrationManager::PathQuality> &candidates) override;

    std::string_view name() const override { return "prefer-relay"; }
};

/// v4.3.0 M16: 带宽 tier 三键排序策略
///
/// 借鉴 Psyche ConnectionMonitor 带宽反馈闭环，按三键排序选路：
///   1. 带宽 tier 升序（MeasuredPositive > NotMeasured > MeasuredZero）
///   2. 实测带宽降序（带宽大的优先，仅 MeasuredPositive tier 内有效）
///   3. RTT 升序（延迟低的优先，同 tier 同带宽时兜底）
///
/// 设计动机：跨城长肥管场景下，纯 RTT 选路会偏好近距离低带宽路径，
///           而推理 hidden_state 大 tensor 传输更看重带宽。三键排序确保：
///           - 有实测带宽的路径优先于未测量的（数据驱动选路）
///           - 同 tier 内带宽大的优先（吞吐量优先）
///           - 同带宽时延迟低的优先（兜底 RTT 维度）
///
/// 兼容性：未测量路径（NotMeasured）排在 MeasuredPositive 之后，
///         但仍优先于 MeasuredZero，避免新路径被饿死。
class BandwidthTierStrategy : public PathSelectionStrategy {
public:
    std::optional<net::FourTuple> select(
        const std::vector<PathMigrationManager::PathQuality> &candidates) override;

    std::string_view name() const override { return "bandwidth-tier"; }
};

/// v4.7.0: PP 链首节点策略 — 优先低延迟（加快首 token）
///
/// 借鉴 iroh Configurable path selection + PP 优化方案 B 的"首节点延迟敏感"场景。
/// 选路逻辑：
///   - 第一键：srtt 升序（延迟低的优先，srtt=0 未测量排最后）
///   - 第二键：bandwidth_tier 升序（同 RTT 时优选已测量带宽的路径）
///   - 第三键：measured_bandwidth_bps 降序（兜底）
///
/// 与 RttBasedStrategy 的差异：RttBasedStrategy 仅按 srtt 选路，遇到 srtt 相同时
/// 取候选原序；PpFirstStageStrategy 在 srtt 相同时用 bandwidth_tier 打破平局，
/// 确保 PP 首节点在等延迟路径中选带宽更优者（减少 hidden_state 排队时延）。
class PpFirstStageStrategy : public PathSelectionStrategy {
public:
    std::optional<net::FourTuple> select(
        const std::vector<PathMigrationManager::PathQuality> &candidates) override;

    std::string_view name() const override { return "pp-first"; }
};

/// v4.7.0: PP 链末节点策略 — 优先高带宽（加快 hidden_state 回传）
///
/// 借鉴 iroh Configurable path selection + PP 优化方案 B 的"末节点带宽敏感"场景。
/// 选路逻辑：
///   - 第一键：measured_bandwidth_bps 降序（带宽大的优先，hidden_state 回传吞吐优先）
///   - 第二键：bandwidth_tier 升序（MeasuredPositive > NotMeasured > MeasuredZero）
///   - 第三键：srtt 升序（同带宽时延迟低的优先）
///
/// 与 BandwidthTierStrategy 的差异：BandwidthTierStrategy 第一键是 tier（先保证已测量），
/// 第二键才是 bandwidth；PpLastStageStrategy 把 bandwidth 提到第一键，即使 NotMeasured
/// tier 的路径只要有 bandwidth 估值也优先于 MeasuredPositive 但带宽低的路径，
/// 适合末节点 hidden_state 大 tensor 回传的吞吐量优先场景。
class PpLastStageStrategy : public PathSelectionStrategy {
public:
    std::optional<net::FourTuple> select(
        const std::vector<PathMigrationManager::PathQuality> &candidates) override;

    std::string_view name() const override { return "pp-last"; }
};

/// 工厂函数：按名称创建策略
/// @param name "rtt" / "prefer-direct" / "prefer-relay" / "bandwidth-tier" /
///             "pp-first" / "pp-last"（v4.7.0 新增）
/// @return 对应的策略实例，未知名称返回 nullptr
std::shared_ptr<PathSelectionStrategy> create_strategy_by_name(std::string_view name);

} // namespace linoh::protocol
