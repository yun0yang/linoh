// cgn_detector.cpp — P5-D-3 CGN 穿透策略实现

#include "linoh/nat/cgn_detector.hpp"

// P5-D-4: select_dynamic 实现需要完整 NatStats 类型
#include "linoh/nat/nat_stats.hpp"

#include "linoh/util/logging.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <future>
#include <mutex>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <vector>

namespace linoh::nat {

// ============================================================================
// CgnDetectionResult 方法
// ============================================================================

std::string CgnDetectionResult::to_string() const {
    std::ostringstream oss;
    oss << "CgnDetectionResult{is_cgn=" << (is_cgn ? "true" : "false")
        << ", confidence=" << port_prediction_confidence
        << ", port_range=[" << observed_port_range_min << "," << observed_port_range_max << "]"
        << ", ports_count=" << observed_ports.size()
        << ", ips_count=" << observed_ips.size()
        << ", duration=" << detection_duration.count() << "ms"
        << "}";
    return oss.str();
}

// ============================================================================
// CgnDetector 实现
// ============================================================================

CgnDetector::CgnDetector(CgnDetectorConfig config)
    : config_(std::move(config)) {
    provider_ = [this](const std::string &stun, std::chrono::milliseconds timeout) {
        return default_probe(stun, timeout);
    };
}

CgnDetector::CgnDetector(CgnDetectorConfig config, StunProbeProvider provider)
    : config_(std::move(config)),
      provider_(std::move(provider)) {
}

std::future<CgnDetectionResult> CgnDetector::detect_async() {
    return std::async(std::launch::async, [this]() {
        return detect_sync();
    });
}

CgnDetectionResult CgnDetector::detect_sync() {
    auto start = std::chrono::steady_clock::now();
    CgnDetectionResult result;

    if (config_.stun_servers.size() < config_.min_stun_servers) {
        result.is_cgn = false;
        result.port_prediction_confidence = 0.0;
        auto end = std::chrono::steady_clock::now();
        result.detection_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        return result;
    }

    // 并行向所有 STUN 服务器探测
    std::vector<std::future<std::optional<std::pair<std::string, std::uint16_t>>>> futs;
    for (const auto &stun : config_.stun_servers) {
        futs.push_back(provider_(stun, config_.request_timeout));
    }

    // 等待所有探测完成
    auto deadline = start + config_.total_timeout;
    for (auto &fut : futs) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0) break;

        auto status = fut.wait_for(remaining);
        if (status == std::future_status::ready) {
            try {
                auto r = fut.get();
                if (r.has_value()) {
                    result.observed_ips.push_back(r->first);
                    result.observed_ports.push_back(r->second);
                }
            } catch (const std::exception &) {
                // 单个探测失败不影响整体
            }
        }
    }

    // 若探测结果不足，不进行 CGN 判定
    if (result.observed_ports.size() < config_.min_stun_servers) {
        result.is_cgn = false;
        result.port_prediction_confidence = 0.0;
        auto end = std::chrono::steady_clock::now();
        result.detection_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        return result;
    }

    // 计算端口范围
    auto [min_it, max_it] = std::minmax_element(result.observed_ports.begin(),
                                                 result.observed_ports.end());
    result.observed_port_range_min = *min_it;
    result.observed_port_range_max = *max_it;

    // 计算端口离散度和置信度
    double dispersion = compute_port_dispersion(result.observed_ports);
    result.port_prediction_confidence = compute_port_confidence(result.observed_ports);

    // 判定是否 CGN
    result.is_cgn = is_cgn_based_on_observations(
        result.observed_ips, result.observed_ports,
        dispersion, config_.confidence_threshold);

    auto end = std::chrono::steady_clock::now();
    result.detection_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    return result;
}

// ============================================================================
// 默认 STUN 探测实现
// ============================================================================

std::future<std::optional<std::pair<std::string, std::uint16_t>>>
CgnDetector::default_probe(const std::string &stun_server,
                            std::chrono::milliseconds timeout) {
    return std::async(std::launch::async, [stun_server, timeout]() {
        net::NetReporter::Config cfg;
        cfg.request_timeout = timeout;
        auto report = net::NetReporter::probe(cfg, {stun_server});
        if (report.public_ip.empty() || report.public_port == 0) {
            return std::optional<std::pair<std::string, std::uint16_t>>{};
        }
        return std::optional<std::pair<std::string, std::uint16_t>>{
            {report.public_ip, report.public_port}
        };
    });
}

// ============================================================================
// 端口分析工具
// ============================================================================

double CgnDetector::compute_port_dispersion(const std::vector<std::uint16_t> &ports) {
    if (ports.size() < 2) return 0.0;
    double mean = compute_port_mean(ports);
    if (mean == 0.0) return 0.0;
    double stddev = compute_port_stddev(ports);
    return stddev / mean;  // 变异系数（CV）
}

double CgnDetector::compute_port_confidence(const std::vector<std::uint16_t> &ports) {
    if (ports.size() < 2) return 0.0;

    // nn-M2 (v1.7.0.8): 按端口值排序后再计算相邻差值。
    // 原实现依赖探测顺序，但 ports 顺序由 stun_servers 列表顺序决定，不同 STUN
    // 服务器网络延迟导致探测完成顺序与 NAT 实际端口分配顺序不一致，同一 NAT
    // 环境下不同运行得到差异很大的 confidence，CGN 判定不稳定。
    std::vector<std::uint16_t> sorted_ports = ports;
    std::sort(sorted_ports.begin(), sorted_ports.end());

    // 计算相邻端口差值
    std::vector<std::int32_t> diffs;
    diffs.reserve(sorted_ports.size() - 1);
    for (std::size_t i = 1; i < sorted_ports.size(); ++i) {
        diffs.push_back(static_cast<std::int32_t>(sorted_ports[i]) -
                        static_cast<std::int32_t>(sorted_ports[i - 1]));
    }

    // 计算差值的均值和标准差
    double diff_sum = std::accumulate(diffs.begin(), diffs.end(), 0.0);
    double diff_mean = diff_sum / diffs.size();

    double sq_sum = 0.0;
    for (auto d : diffs) {
        sq_sum += (d - diff_mean) * (d - diff_mean);
    }
    double diff_stddev = std::sqrt(sq_sum / diffs.size());

    // 置信度计算：
    //   - 差值标准差越小 → 端口变化越规律 → 置信度越高
    //   - 差值标准差越大 → 端口随机性大 → 置信度越低
    // 归一化：confidence = 1.0 / (1.0 + stddev/mean)
    double abs_diff_mean = std::abs(diff_mean);
    if (abs_diff_mean < 1.0) abs_diff_mean = 1.0;  // 避免除零
    double confidence = 1.0 / (1.0 + diff_stddev / abs_diff_mean);

    // 端口范围过大也降低置信度
    std::uint16_t range = compute_port_range(ports);
    if (range > 1000) {
        confidence *= 0.5;  // 端口范围 >1000，置信度减半
    }

    // 端口完全相同（端口保持稳定）→ 高置信度
    bool all_same = std::all_of(ports.begin(), ports.end(),
                                 [&](std::uint16_t p) { return p == ports[0]; });
    if (all_same) {
        confidence = 1.0;
    }

    return confidence;
}

bool CgnDetector::is_cgn_based_on_observations(
    const std::vector<std::string> &ips,
    const std::vector<std::uint16_t> &ports,
    double port_dispersion,
    double confidence_threshold) {
    // v1.7.0.6 (C7 fix): 修复 CGN 置信度算法失效
    // 之前此函数完全忽略 confidence_threshold，导致 result.is_cgn 几乎总是 false，
    // 后续 CgnStrategySelector::select 直接返回 StandardRfc5389，
    // 跳过 SymmetricNat/ParallelTry/RelayFallback 三种策略，
    // CGN 五级穿透体系的第一级判定失效。
    //
    // v1.7.0.6 (H3-1 fix): 复用 compute_port_confidence() 静态方法，
    // 消除之前在函数内部重复实现 CV 计算且公式不一致的问题
    // （原内部实现未考虑端口范围惩罚和 all_same 短路，与 compute_port_confidence 结果不一致）

    // IP 不一致 → 多 NAT 层，不是单纯 CGN
    if (!is_ip_consistent(ips)) {
        return false;
    }

    // IP 一致但端口离散度高 → CGN
    if (port_dispersion > 0.5) {
        return true;
    }

    // v1.7.0.6: 端口预测置信度低于阈值 → 判定为 CGN
    // 置信度低说明端口离散度虽未到 0.5，但端口预测不可靠，符合 CGN 特征
    // （CGN 环境下端口分配可能呈现中等离散度但不可预测）
    if (!ports.empty() && ports.size() >= 2) {
        // v1.7.0.6 (H3-1 fix): 复用 compute_port_confidence，避免重复实现且公式不一致
        double confidence = compute_port_confidence(ports);
        if (confidence < confidence_threshold) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// CgnStrategySelector 实现
// ============================================================================

CgnStrategy CgnStrategySelector::select(const CgnDetectionResult &result,
                                         double high_threshold,
                                         double low_threshold) {
    if (!result.is_cgn) {
        // 非 CGN，根据 NAT 类型选择
        // 简化：直接 StandardRfc5389
        return CgnStrategy::StandardRfc5389;
    }

    // CGN 场景：根据置信度选择
    if (result.port_prediction_confidence >= high_threshold) {
        // 高置信度：尝试端口预测
        return CgnStrategy::SymmetricNat;
    }
    if (result.port_prediction_confidence < low_threshold) {
        // 低置信度：直接 Relay
        return CgnStrategy::RelayFallback;
    }
    // 中置信度：并行尝试
    return CgnStrategy::ParallelTry;
}

// ============================================================================
// P5-D-4: 动态阈值策略选择
// ============================================================================

CgnStrategy CgnStrategySelector::select_dynamic(const CgnDetectionResult &result,
                                                 const NatStats *stats,
                                                 const StatsKey &key,
                                                 const DynamicThresholdConfig &cfg) {
    // 1. NatStats 不可用 → 用默认阈值
    if (stats == nullptr) {
        return select(result, cfg.default_high, cfg.default_low);
    }

    // 2. 查询维度下各策略统计，找 SymmetricNat 历史样本
    auto strategies = stats->query_strategies(key);
    std::uint64_t sym_total = 0;
    std::uint64_t sym_success = 0;
    for (const auto &s : strategies) {
        if (s.strategy == CgnStrategy::SymmetricNat) {
            sym_total = s.total;
            sym_success = s.success;
            break;
        }
    }

    // 3. 样本不足（冷启动）→ 用默认阈值
    if (sym_total < cfg.min_samples_for_adjust) {
        LINOH_INFO("CgnStrategySelector: cold start, sym_samples=", sym_total,
                   "< min=", cfg.min_samples_for_adjust,
                   "using default high=", cfg.default_high,
                   "low=", cfg.default_low);
        return select(result, cfg.default_high, cfg.default_low);
    }

    // 4. 计算 SymmetricNat 历史成功率，动态调整阈值
    double sym_success_rate = static_cast<double>(sym_success) /
                              static_cast<double>(sym_total);
    double high = cfg.default_high;
    double low = cfg.default_low;

    if (sym_success_rate < cfg.symmetric_nat_low_success_rate) {
        // 低成功率 → 更保守（提高 high，降低 low，让 SymmetricNat 更难触发）
        high = cfg.raised_high;
        low = cfg.lowered_low;
        LINOH_INFO("CgnStrategySelector: low sym success rate=", sym_success_rate,
                   "< ", cfg.symmetric_nat_low_success_rate,
                   "raised high=", high, "lowered low=", low);
    } else if (sym_success_rate > cfg.symmetric_nat_high_success_rate) {
        // 高成功率 → 更激进（降低 high，提高 low，让 SymmetricNat 更易触发）
        high = cfg.lowered_high;
        low = cfg.raised_low;
        LINOH_INFO("CgnStrategySelector: high sym success rate=", sym_success_rate,
                   "> ", cfg.symmetric_nat_high_success_rate,
                   "lowered high=", high, "raised low=", low);
    } else {
        // 中等成功率 → 默认阈值
        LINOH_INFO("CgnStrategySelector: medium sym success rate=", sym_success_rate,
                   "using default high=", high, "low=", low);
    }

    // 5. 调用基础 select
    return select(result, high, low);
}

net::HolepunchStrategy CgnStrategySelector::to_holepunch_strategy(
    CgnStrategy cgn_strategy) {
    switch (cgn_strategy) {
        case CgnStrategy::DirectConnect:
            return net::HolepunchStrategy::None;
        case CgnStrategy::StandardRfc5389:
            return net::HolepunchStrategy::StandardRfc5389;
        case CgnStrategy::SymmetricNat:
            return net::HolepunchStrategy::SymmetricNat;
        case CgnStrategy::RelayFallback:
            return net::HolepunchStrategy::RelayFallback;
        case CgnStrategy::ParallelTry:
            // linoh 现有策略没有 ParallelTry，回退到 SymmetricNat
            // 实际部署时由 Endpoint 同时启动 SymmetricNat 和 Relay
            return net::HolepunchStrategy::SymmetricNat;
    }
    return net::HolepunchStrategy::None;
}

// ============================================================================
// 工具函数实现
// ============================================================================

double compute_port_mean(const std::vector<std::uint16_t> &ports) {
    if (ports.empty()) return 0.0;
    double sum = 0.0;
    for (auto p : ports) sum += p;
    return sum / ports.size();
}

double compute_port_stddev(const std::vector<std::uint16_t> &ports) {
    if (ports.size() < 2) return 0.0;
    double mean = compute_port_mean(ports);
    double sq_sum = 0.0;
    for (auto p : ports) {
        sq_sum += (p - mean) * (p - mean);
    }
    return std::sqrt(sq_sum / ports.size());
}

std::uint16_t compute_port_range(const std::vector<std::uint16_t> &ports) {
    if (ports.empty()) return 0;
    auto [min_it, max_it] = std::minmax_element(ports.begin(), ports.end());
    return *max_it - *min_it;
}

bool is_ip_consistent(const std::vector<std::string> &ips) {
    if (ips.empty()) return true;
    for (const auto &ip : ips) {
        if (ip != ips[0]) return false;
    }
    return true;
}

} // namespace linoh::nat
