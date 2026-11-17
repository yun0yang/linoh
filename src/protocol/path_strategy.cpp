// path_strategy.cpp — 可配置路径选择策略实现（P4-B-3）

#include "linoh/protocol/path_strategy.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <chrono>

namespace linoh::protocol {

namespace {

/// 判断 FourTuple 是否为直连（IP 类型）
bool is_direct(const net::FourTuple &t) {
    return t.remote_addr.kind == base::TransportKind::Ip;
}

/// 判断 FourTuple 是否为 Relay
bool is_relay(const net::FourTuple &t) {
    return t.remote_addr.kind == base::TransportKind::Relay;
}

/// 在候选中选 srtt 最小且非零的路径
std::optional<net::FourTuple> select_min_rtt(
    const std::vector<PathMigrationManager::PathQuality> &candidates) {
    auto best = candidates.end();
    std::chrono::microseconds best_rtt{0};

    for (auto it = candidates.begin(); it != candidates.end(); ++it) {
        if (it->srtt.count() == 0) continue;  // 跳过未测量
        if (!it->has_tuple) continue;         // 跳过无 tuple（无法返回地址）
        if (best == candidates.end() || it->srtt < best_rtt) {
            best = it;
            best_rtt = it->srtt;
        }
    }

    if (best == candidates.end()) return std::nullopt;
    return best->four_tuple;
}

} // namespace

// ============================================================================
// RttBasedStrategy
// ============================================================================

std::optional<net::FourTuple> RttBasedStrategy::select(
    const std::vector<PathMigrationManager::PathQuality> &candidates) {
    if (candidates.empty()) {
        LINOH_DEBUG("RttBasedStrategy: no candidates");
        return std::nullopt;
    }
    auto result = select_min_rtt(candidates);
    if (result) {
        LINOH_DEBUG("RttBasedStrategy: selected ", result->to_string());
    } else {
        LINOH_DEBUG("RttBasedStrategy: no valid candidate (all unmeasured)");
    }
    return result;
}

// ============================================================================
// PreferDirectStrategy
// ============================================================================

std::optional<net::FourTuple> PreferDirectStrategy::select(
    const std::vector<PathMigrationManager::PathQuality> &candidates) {
    if (candidates.empty()) return std::nullopt;

    // 先在直连路径中选 RTT 最小的
    std::vector<PathMigrationManager::PathQuality> direct_candidates;
    for (auto &c : candidates) {
        if (c.has_tuple && is_direct(c.four_tuple)) {
            direct_candidates.push_back(c);
        }
    }

    if (!direct_candidates.empty()) {
        auto result = select_min_rtt(direct_candidates);
        if (result) {
            LINOH_DEBUG("PreferDirectStrategy: selected direct ", result->to_string());
            return result;
        }
    }

    // 直连全失败，回退到 Relay
    std::vector<PathMigrationManager::PathQuality> relay_candidates;
    for (auto &c : candidates) {
        if (c.has_tuple && is_relay(c.four_tuple)) {
            relay_candidates.push_back(c);
        }
    }

    if (!relay_candidates.empty()) {
        auto result = select_min_rtt(relay_candidates);
        if (result) {
            LINOH_DEBUG("PreferDirectStrategy: fallback to relay ", result->to_string());
            return result;
        }
    }

    // 最后回退到所有候选中 RTT 最小的（可能是 Custom 类型）
    return select_min_rtt(candidates);
}

// ============================================================================
// PreferRelayStrategy
// ============================================================================

std::optional<net::FourTuple> PreferRelayStrategy::select(
    const std::vector<PathMigrationManager::PathQuality> &candidates) {
    if (candidates.empty()) return std::nullopt;

    // 先在 Relay 路径中选 RTT 最小的
    std::vector<PathMigrationManager::PathQuality> relay_candidates;
    for (auto &c : candidates) {
        if (c.has_tuple && is_relay(c.four_tuple)) {
            relay_candidates.push_back(c);
        }
    }

    if (!relay_candidates.empty()) {
        auto result = select_min_rtt(relay_candidates);
        if (result) {
            LINOH_DEBUG("PreferRelayStrategy: selected relay ", result->to_string());
            return result;
        }
    }

    // [FIX 2026-08-14] prefer-relay 策略禁止回退到 P2P 直连
    // 根因：公网 UDP 直连丢包率极高（>50%），导致大量 packets lost 和 OOS gap。
    //       relay 路径通过 WebSocket(TCP) 传输，无 UDP 丢包问题。
    // 修复：relay 不可用时返回空，强制上层重建 relay 连接，不回退到直连。
    LINOH_WARN("PreferRelayStrategy: no relay path available, refusing direct fallback");
    return std::nullopt;
}

// ============================================================================
// v4.3.0 M16: BandwidthTierStrategy（三键排序）
// ============================================================================

namespace {

/// 三键比较：tier 升序 → bandwidth 降序 → srtt 升序
///
/// 返回 true 表示 a 排在 b 前面（a 更优）。
/// srtt=0（未测量 RTT）视为最差（排最后），因为 RTT 是兜底维度，
/// 未测量 RTT 说明路径尚未完成握手，优先级最低。
bool bandwidth_tier_less(const PathMigrationManager::PathQuality &a,
                          const PathMigrationManager::PathQuality &b) {
    // 第一键：bandwidth_tier 升序（MeasuredPositive=0 > NotMeasured=1 > MeasuredZero=2）
    auto ta = static_cast<std::uint8_t>(a.bandwidth_tier);
    auto tb = static_cast<std::uint8_t>(b.bandwidth_tier);
    if (ta != tb) return ta < tb;

    // 第二键：measured_bandwidth_bps 降序（带宽大的优先）
    // 注意：仅 MeasuredPositive tier 内有意义，但同 tier 比较无副作用
    //       NotMeasured 同 tier bandwidth 都是 0，相等；MeasuredZero 同 tier 都是 0，相等
    if (a.measured_bandwidth_bps != b.measured_bandwidth_bps) {
        return a.measured_bandwidth_bps > b.measured_bandwidth_bps;
    }

    // 第三键：srtt 升序（延迟低的优先）
    // srtt=0 视为"无穷大"（未测量，排最后）
    auto sa = a.srtt.count();
    auto sb = b.srtt.count();
    if (sa == 0 && sb == 0) return false;  // 都未测量，保持原序
    if (sa == 0) return false;              // a 未测量，a 排后
    if (sb == 0) return true;               // b 未测量，a 排前
    return sa < sb;
}

} // namespace

std::optional<net::FourTuple> BandwidthTierStrategy::select(
    const std::vector<PathMigrationManager::PathQuality> &candidates) {
    if (candidates.empty()) {
        LINOH_DEBUG("BandwidthTierStrategy: no candidates");
        return std::nullopt;
    }

    // 过滤掉无 tuple 的候选（无法返回地址）
    std::vector<PathMigrationManager::PathQuality> valid;
    valid.reserve(candidates.size());
    for (const auto &c : candidates) {
        if (c.has_tuple) {
            valid.push_back(c);
        }
    }
    if (valid.empty()) {
        LINOH_DEBUG("BandwidthTierStrategy: no valid candidate (all missing tuple)");
        return std::nullopt;
    }

    // 按三键排序（stable 保证同键候选保持原序）
    std::stable_sort(valid.begin(), valid.end(), bandwidth_tier_less);

    LINOH_DEBUG("BandwidthTierStrategy: selected tier=",
                static_cast<int>(valid[0].bandwidth_tier),
                " bw=", valid[0].measured_bandwidth_bps,
                " srtt=", valid[0].srtt.count());
    return valid[0].four_tuple;
}

// ============================================================================
// v4.7.0: PpFirstStageStrategy（PP 链首节点 — 延迟优先）
// ============================================================================

namespace {

/// PP 首节点三键比较：srtt 升序 → tier 升序 → bandwidth 降序
///
/// 与 BandwidthTierStrategy 的 bandwidth_tier_less 对称：首节点把 srtt 提到第一键，
/// tier 和 bandwidth 依次作 tiebreaker。srtt=0（未测量）排最后。
bool pp_first_less(const PathMigrationManager::PathQuality &a,
                   const PathMigrationManager::PathQuality &b) {
    // 第一键：srtt 升序（srtt=0 视为无穷大排最后）
    auto sa = a.srtt.count();
    auto sb = b.srtt.count();
    if (sa == 0 && sb == 0) {
        // 都未测量，继续后续键
    } else if (sa == 0) {
        return false;  // a 未测量，a 排后
    } else if (sb == 0) {
        return true;   // b 未测量，a 排前
    } else if (sa != sb) {
        return sa < sb;
    }

    // 第二键：bandwidth_tier 升序
    auto ta = static_cast<std::uint8_t>(a.bandwidth_tier);
    auto tb = static_cast<std::uint8_t>(b.bandwidth_tier);
    if (ta != tb) return ta < tb;

    // 第三键：measured_bandwidth_bps 降序
    if (a.measured_bandwidth_bps != b.measured_bandwidth_bps) {
        return a.measured_bandwidth_bps > b.measured_bandwidth_bps;
    }
    return false;  // 完全相等保持原序
}

/// PP 末节点三键比较：bandwidth 降序 → tier 升序 → srtt 升序
///
/// 与 BandwidthTierStrategy 的差异：把 measured_bandwidth_bps 提到第一键，
/// 适合末节点 hidden_state 大 tensor 回传的吞吐量优先场景。
bool pp_last_less(const PathMigrationManager::PathQuality &a,
                  const PathMigrationManager::PathQuality &b) {
    // 第一键：measured_bandwidth_bps 降序（带宽大的优先）
    if (a.measured_bandwidth_bps != b.measured_bandwidth_bps) {
        return a.measured_bandwidth_bps > b.measured_bandwidth_bps;
    }

    // 第二键：bandwidth_tier 升序（同带宽时优选已测量 tier）
    auto ta = static_cast<std::uint8_t>(a.bandwidth_tier);
    auto tb = static_cast<std::uint8_t>(b.bandwidth_tier);
    if (ta != tb) return ta < tb;

    // 第三键：srtt 升序（srtt=0 视为无穷大排最后）
    auto sa = a.srtt.count();
    auto sb = b.srtt.count();
    if (sa == 0 && sb == 0) return false;
    if (sa == 0) return false;
    if (sb == 0) return true;
    return sa < sb;
}

} // namespace

std::optional<net::FourTuple> PpFirstStageStrategy::select(
    const std::vector<PathMigrationManager::PathQuality> &candidates) {
    if (candidates.empty()) {
        LINOH_DEBUG("PpFirstStageStrategy: no candidates");
        return std::nullopt;
    }

    std::vector<PathMigrationManager::PathQuality> valid;
    valid.reserve(candidates.size());
    for (const auto &c : candidates) {
        if (c.has_tuple) valid.push_back(c);
    }
    if (valid.empty()) {
        LINOH_DEBUG("PpFirstStageStrategy: no valid candidate (all missing tuple)");
        return std::nullopt;
    }

    std::stable_sort(valid.begin(), valid.end(), pp_first_less);
    LINOH_DEBUG("PpFirstStageStrategy: selected srtt=", valid[0].srtt.count(),
                " tier=", static_cast<int>(valid[0].bandwidth_tier),
                " bw=", valid[0].measured_bandwidth_bps);
    return valid[0].four_tuple;
}

std::optional<net::FourTuple> PpLastStageStrategy::select(
    const std::vector<PathMigrationManager::PathQuality> &candidates) {
    if (candidates.empty()) {
        LINOH_DEBUG("PpLastStageStrategy: no candidates");
        return std::nullopt;
    }

    std::vector<PathMigrationManager::PathQuality> valid;
    valid.reserve(candidates.size());
    for (const auto &c : candidates) {
        if (c.has_tuple) valid.push_back(c);
    }
    if (valid.empty()) {
        LINOH_DEBUG("PpLastStageStrategy: no valid candidate (all missing tuple)");
        return std::nullopt;
    }

    std::stable_sort(valid.begin(), valid.end(), pp_last_less);
    LINOH_DEBUG("PpLastStageStrategy: selected bw=", valid[0].measured_bandwidth_bps,
                " tier=", static_cast<int>(valid[0].bandwidth_tier),
                " srtt=", valid[0].srtt.count());
    return valid[0].four_tuple;
}

// ============================================================================
// 工厂函数
// ============================================================================

std::shared_ptr<PathSelectionStrategy> create_strategy_by_name(std::string_view name) {
    if (name == "rtt") {
        return std::make_shared<RttBasedStrategy>();
    } else if (name == "prefer-direct") {
        return std::make_shared<PreferDirectStrategy>();
    } else if (name == "prefer-relay") {
        return std::make_shared<PreferRelayStrategy>();
    } else if (name == "bandwidth-tier") {
        return std::make_shared<BandwidthTierStrategy>();
    } else if (name == "pp-first") {
        return std::make_shared<PpFirstStageStrategy>();
    } else if (name == "pp-last") {
        return std::make_shared<PpLastStageStrategy>();
    }
    LINOH_WARN("create_strategy_by_name: unknown strategy '", name, "'");
    return nullptr;
}

} // namespace linoh::protocol
