// multipath_coordinated_selector.cpp — 多路径协同拥塞控制加权选择器实现（v2.0 Phase 1）

#include "linoh/protocol/multipath_coordinated_selector.hpp"

#include <algorithm>
#include <cmath>
#include <random>

namespace linoh::protocol {

// ============================================================================
// MultipathCoordinatedSelector
// ============================================================================

MultipathCoordinatedSelector::MultipathCoordinatedSelector(std::size_t expected_paths) {
    candidates_.reserve(expected_paths);
    selection_counts_.reserve(expected_paths);
    weights_.reserve(expected_paths);
    health_multipliers_.reserve(expected_paths);
    baseline_srtt_ms_.reserve(expected_paths);
    // 用 random_device 初始化 RNG 状态（与 AdaptiveSelector 一致）
    std::random_device rd;
    rng_state_ = (static_cast<std::uint64_t>(rd()) << 32) | rd();
    if (rng_state_ == 0) rng_state_ = 0x9E3779B97F4A7C15ULL;  // golden ratio 常数
}

void MultipathCoordinatedSelector::update_candidates(std::vector<CoordinatedPathInfo> paths) {
    std::lock_guard<std::mutex> lk(mu_);

    // 1. 先构建旧 tuple → (health, baseline) 映射（在 move 之前）
    //    用于保留已存在路径的健康度和 baseline RTT
    std::vector<std::pair<net::FourTuple, std::pair<double, double>>> old_state;
    old_state.reserve(candidates_.size());
    for (std::size_t i = 0; i < candidates_.size(); ++i) {
        double h = (i < health_multipliers_.size()) ? health_multipliers_[i] : 1.0;
        double b = (i < baseline_srtt_ms_.size()) ? baseline_srtt_ms_[i] : 0.0;
        old_state.emplace_back(candidates_[i].tuple, std::make_pair(h, b));
    }

    // 2. 替换候选列表
    candidates_ = std::move(paths);
    std::size_t n = candidates_.size();
    selection_counts_.assign(n, 0);
    weights_.assign(n, 0.0);
    health_multipliers_.assign(n, 1.0);
    baseline_srtt_ms_.assign(n, 0.0);
    total_selections_ = 0;

    // 3. 按 tuple 匹配恢复旧路径的 health_multiplier 和 baseline_srtt
    for (std::size_t i = 0; i < n; ++i) {
        for (const auto &kv : old_state) {
            if (kv.first == candidates_[i].tuple) {
                health_multipliers_[i] = kv.second.first;
                baseline_srtt_ms_[i] = kv.second.second;
                break;
            }
        }
    }

    // 4. 初始化新路径的 baseline_srtt（首次观测到非零 SRTT 时）
    for (std::size_t i = 0; i < n; ++i) {
        if (baseline_srtt_ms_[i] == 0.0) {
            double srtt_ms = candidates_[i].srtt.count() / 1000.0;
            if (srtt_ms > 0.0) {
                baseline_srtt_ms_[i] = srtt_ms;
            }
        }
    }

    // 5. 重新计算权重（含健康度更新）
    recompute_weights();
}

std::optional<net::FourTuple> MultipathCoordinatedSelector::select_next_for_send() {
    std::lock_guard<std::mutex> lk(mu_);
    if (candidates_.empty()) return std::nullopt;
    if (candidates_.size() == 1) {
        ++selection_counts_[0];
        ++total_selections_;
        return candidates_[0].tuple;
    }

    // CWND cap 检查：总 CWND 超过上限时不再选择新路径
    if (total_cwnd_cap_ > 0) {
        uint64_t total_cwnd = 0;
        for (const auto &c : candidates_) {
            if (c.controller != nullptr) {
                total_cwnd += c.controller->cwnd_bytes();
            }
        }
        if (total_cwnd >= total_cwnd_cap_) {
            return std::nullopt;  // 整体过载，暂停发送
        }
    }

    // 加权随机：生成 [0, 1) 随机数，按累计权重选择
    double r = static_cast<double>(next_random() >> 11) / static_cast<double>(1ULL << 53);
    double cum = 0.0;
    std::size_t idx = 0;
    for (std::size_t i = 0; i < weights_.size(); ++i) {
        cum += weights_[i];
        if (r < cum) {
            idx = i;
            break;
        }
        idx = i;  // 兜底（浮点精度问题）
    }

    ++selection_counts_[idx];
    ++total_selections_;
    return candidates_[idx].tuple;
}

void MultipathCoordinatedSelector::skip_path(const net::FourTuple &tuple) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = std::find_if(candidates_.begin(), candidates_.end(),
                            [&](const CoordinatedPathInfo &p) { return p.tuple == tuple; });
    if (it == candidates_.end()) return;
    std::size_t idx = static_cast<std::size_t>(it - candidates_.begin());
    candidates_.erase(it);
    selection_counts_.erase(selection_counts_.begin() + idx);
    weights_.erase(weights_.begin() + idx);
    health_multipliers_.erase(health_multipliers_.begin() + idx);
    baseline_srtt_ms_.erase(baseline_srtt_ms_.begin() + idx);
    recompute_weights();
}

uint64_t MultipathCoordinatedSelector::total_cwnd_bytes() const {
    std::lock_guard<std::mutex> lk(mu_);
    uint64_t total = 0;
    for (const auto &c : candidates_) {
        if (c.controller != nullptr) {
            total += c.controller->cwnd_bytes();
        }
    }
    return total;
}

std::vector<std::pair<net::FourTuple, uint64_t>>
MultipathCoordinatedSelector::selection_stats() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<std::pair<net::FourTuple, uint64_t>> result;
    result.reserve(candidates_.size());
    for (std::size_t i = 0; i < candidates_.size(); ++i) {
        result.emplace_back(candidates_[i].tuple, selection_counts_[i]);
    }
    return result;
}

std::vector<MultipathCoordinatedSelector::PathHealth>
MultipathCoordinatedSelector::path_health_stats() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<PathHealth> result;
    result.reserve(candidates_.size());
    for (std::size_t i = 0; i < candidates_.size(); ++i) {
        PathHealth h;
        h.tuple = candidates_[i].tuple;
        h.weight = (i < weights_.size()) ? weights_[i] : 0.0;
        h.health_multiplier = (i < health_multipliers_.size()) ? health_multipliers_[i] : 1.0;
        h.pacing_rate_bps = (candidates_[i].controller != nullptr)
                                ? candidates_[i].controller->pacing_rate_bps()
                                : 0;
        h.cwnd_bytes = (candidates_[i].controller != nullptr)
                            ? candidates_[i].controller->cwnd_bytes()
                            : 0;
        h.is_cross_domain = candidates_[i].is_cross_domain;
        h.is_relay_path = candidates_[i].is_relay_path;

        // 退化判定（V3-B: 跨域路径用放宽阈值，与 update_health 保持一致）
        double srtt_ms = candidates_[i].srtt.count() / 1000.0;
        double baseline = (i < baseline_srtt_ms_.size()) ? baseline_srtt_ms_[i] : 0.0;
        double rtt_threshold = candidates_[i].is_cross_domain
                                   ? kCrossDomainRttSpikeThreshold
                                   : kRttSpikeThreshold;
        double loss_threshold = candidates_[i].is_cross_domain
                                    ? kCrossDomainHighLossThreshold
                                    : kHighLossThreshold;
        bool rtt_spike = (baseline > 0.0 && srtt_ms > baseline * rtt_threshold);
        bool high_loss = (candidates_[i].loss_rate > loss_threshold);
        h.is_degraded = rtt_spike || high_loss;
        if (rtt_spike && high_loss) {
            h.degradation_reason = "rtt_spike+high_loss";
        } else if (rtt_spike) {
            h.degradation_reason = "rtt_spike";
        } else if (high_loss) {
            h.degradation_reason = "high_loss";
        }
        result.push_back(std::move(h));
    }
    return result;
}

void MultipathCoordinatedSelector::set_seed(uint64_t seed) {
    std::lock_guard<std::mutex> lk(mu_);
    rng_state_ = seed;
    if (rng_state_ == 0) rng_state_ = 0x9E3779B97F4A7C15ULL;
}

// ============================================================================
// 私有方法
// ============================================================================

void MultipathCoordinatedSelector::recompute_weights() {
    // 调用方持锁，本方法无需再加锁
    if (candidates_.empty()) return;
    if (candidates_.size() == 1) {
        weights_[0] = 1.0;
        return;
    }

    // 1. 更新每路径健康度
    for (std::size_t i = 0; i < candidates_.size(); ++i) {
        update_health(i);
    }

    // 2. 计算 BBR 路径的平均 pacing_rate（用于 NewReno 回退权重）
    double avg_bbr_pacing = 0.0;
    std::size_t bbr_count = 0;
    for (std::size_t i = 0; i < candidates_.size(); ++i) {
        if (candidates_[i].controller != nullptr) {
            uint64_t pr = candidates_[i].controller->pacing_rate_bps();
            if (pr > 0) {
                avg_bbr_pacing += static_cast<double>(pr);
                ++bbr_count;
            }
        }
    }
    if (bbr_count > 0) {
        avg_bbr_pacing /= static_cast<double>(bbr_count);
    } else {
        avg_bbr_pacing = 1.0;  // 无 BBR 路径时用 1.0 作为 NewReno 基准权重
    }

    // 3. 计算原始权重 = pacing_rate * health_multiplier * relay_factor
    //    V3-B: Relay 路径延迟更高（多一跳中转），权重乘以 kRelayPathPenalty=0.7 降基础权重
    //    直连路径优先，Relay 仅在直连全部退化时承担主要流量
    //    v3.9.1: 若设置了 bandwidth_provider_，优先用实测带宽替代 BBR pacing_rate
    constexpr double kRelayPathPenalty = 0.7;
    std::vector<double> raw_weights(candidates_.size(), 0.0);
    double total = 0.0;
    for (std::size_t i = 0; i < candidates_.size(); ++i) {
        double pacing = 0.0;
        // v3.9.1: 优先用实测带宽（如果 bandwidth_provider_ 已设置且返回 > 0）
        if (bandwidth_provider_) {
            uint64_t measured = bandwidth_provider_(candidates_[i].tuple);
            if (measured > 0) {
                pacing = static_cast<double>(measured);
            }
        }
        if (pacing == 0.0) {
            // 回退到 BBR pacing_rate 或 NewReno 平均值
            if (candidates_[i].controller != nullptr) {
                uint64_t pr = candidates_[i].controller->pacing_rate_bps();
                pacing = (pr > 0) ? static_cast<double>(pr) : avg_bbr_pacing;
            } else {
                pacing = avg_bbr_pacing;  // 无控制器按 NewReno 处理
            }
        }
        double health = (i < health_multipliers_.size()) ? health_multipliers_[i] : 1.0;
        double relay_factor = candidates_[i].is_relay_path ? kRelayPathPenalty : 1.0;
        raw_weights[i] = pacing * health * relay_factor;
        total += raw_weights[i];
    }

    // 4. 归一化
    if (total > 0.0) {
        for (std::size_t i = 0; i < weights_.size(); ++i) {
            weights_[i] = raw_weights[i] / total;
        }
    } else {
        // 兜底：均匀分布
        double uniform = 1.0 / static_cast<double>(candidates_.size());
        for (std::size_t i = 0; i < weights_.size(); ++i) {
            weights_[i] = uniform;
        }
    }
}

void MultipathCoordinatedSelector::update_health(std::size_t idx) {
    // 调用方持锁，本方法无需再加锁
    if (idx >= candidates_.size()) return;

    double &health = health_multipliers_[idx];
    double srtt_ms = candidates_[idx].srtt.count() / 1000.0;
    double loss = candidates_[idx].loss_rate;

    // 初始化 baseline（首次观测到非零 SRTT 时）
    if (baseline_srtt_ms_[idx] == 0.0 && srtt_ms > 0.0) {
        baseline_srtt_ms_[idx] = srtt_ms;
    }
    double baseline = baseline_srtt_ms_[idx];

    // V3-B: 跨域路径对 RTT 抖动更宽容（阈值 3.0 → 5.0）
    // 跨域链路 RTT 抖动幅度大（骨干网路由变化、跨运营商），3x baseline 易误判
    double rtt_threshold = candidates_[idx].is_cross_domain
                               ? kCrossDomainRttSpikeThreshold
                               : kRttSpikeThreshold;
    bool rtt_spike = (baseline > 0.0 && srtt_ms > baseline * rtt_threshold);

    // V3-B: 跨域路径对丢包更宽容（阈值 5% → 10%）
    // 跨域链路中间设备更多，瞬时丢包概率高，5% 阈值过于敏感
    double loss_threshold = candidates_[idx].is_cross_domain
                                ? kCrossDomainHighLossThreshold
                                : kHighLossThreshold;
    bool high_loss = (loss > loss_threshold);

    // 3. 计算退化因子
    double penalty = 1.0;
    if (rtt_spike) {
        penalty *= kRttSpikePenalty;
    }
    if (high_loss) {
        // 丢包率 5% → 乘 0.75，10% → 乘 0.5，20%+ → 乘 0.1（下限）
        double loss_penalty = 1.0 - loss * 5.0;
        if (loss_penalty < kMinHealthMultiplier) loss_penalty = kMinHealthMultiplier;
        penalty *= loss_penalty;
    }

    // 4. 应用退化或渐进恢复
    if (penalty < 1.0) {
        // 退化：直接应用惩罚（取较小值，避免退化路径意外回升）
        if (penalty < health) {
            health = penalty;
        }
    } else {
        // 健康：向 1.0 渐进恢复
        health += kRecoveryGain;
        if (health > 1.0) health = 1.0;
    }

    // 确保不低于下限
    if (health < kMinHealthMultiplier) {
        health = kMinHealthMultiplier;
    }
}

uint64_t MultipathCoordinatedSelector::next_random() {
    // 调用方持锁，本方法无需再加锁
    // xorshift64* RNG（与 AdaptiveSelector 一致）
    std::uint64_t x = rng_state_;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state_ = x;
    return x * 0x2545F4914F6CDD1DULL;
}

}  // namespace linoh::protocol
