// multipath_selector.cpp — 多路径 strip/adaptive 选择器实现（P5-B-3）

#include "linoh/protocol/multipath_selector.hpp"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <random>

namespace linoh::protocol {

// ============================================================================
// MultipathStripSelector
// ============================================================================

MultipathStripSelector::MultipathStripSelector(std::size_t expected_paths) {
    candidates_.reserve(expected_paths);
    selection_counts_.reserve(expected_paths);
}

void MultipathStripSelector::update_candidates(std::vector<net::FourTuple> paths) {
    // mp-M3 (v1.7.0.8): 加锁防止与 select_next_for_send 并发
    std::lock_guard<std::mutex> lk(mu_);
    candidates_ = std::move(paths);
    selection_counts_.assign(candidates_.size(), 0);
    next_idx_ = 0;
    total_selections_ = 0;
}

std::optional<net::FourTuple> MultipathStripSelector::select_next_for_send() {
    // mp-M3 (v1.7.0.8): 加锁保护 next_idx_ + selection_counts_ 原子更新
    std::lock_guard<std::mutex> lk(mu_);
    if (candidates_.empty()) return std::nullopt;

    // next_idx_ 已在 update_candidates 中重置为 0；正常 round-robin
    if (next_idx_ >= candidates_.size()) {
        next_idx_ = 0;
    }
    std::size_t idx = next_idx_;
    next_idx_ = (next_idx_ + 1) % candidates_.size();

    ++selection_counts_[idx];
    ++total_selections_;
    return candidates_[idx];
}

void MultipathStripSelector::skip_current() {
    // mp-M3 (v1.7.0.8): 加锁保护 next_idx_ 更新
    std::lock_guard<std::mutex> lk(mu_);
    if (candidates_.empty()) return;
    // 切到下一条
    next_idx_ = (next_idx_ + 1) % candidates_.size();
}

// ============================================================================
// W2.2: FEC 冗余块路径分集（独立项目方案）
// ============================================================================

void MultipathStripSelector::set_policy(StripPolicy p) {
    std::lock_guard<std::mutex> lk(mu_);
    policy_ = p;
}

StripPolicy MultipathStripSelector::policy() const {
    std::lock_guard<std::mutex> lk(mu_);
    return policy_;
}

std::optional<net::FourTuple> MultipathStripSelector::select_for_flow(
    std::uint64_t flow_key, bool is_redundancy) {
    std::lock_guard<std::mutex> lk(mu_);
    if (candidates_.empty()) return std::nullopt;

    // RoundRobin 策略：退化为逐包轮转（与 select_next_for_send 相同逻辑，
    // 保持单一路径语义）
    if (policy_ == StripPolicy::RoundRobin) {
        if (next_idx_ >= candidates_.size()) next_idx_ = 0;
        std::size_t idx = next_idx_;
        next_idx_ = (next_idx_ + 1) % candidates_.size();
        ++selection_counts_[idx];
        ++total_selections_;
        return candidates_[idx];
    }

    // RoleHash：data_idx = h(flow) % n；redundancy 固定走下一轨（n>=2 必异轨）
    std::uint64_t h = flow_key * 0x9E3779B97F4A7C15ULL;  // golden ratio 扰散
    h ^= h >> 32;
    std::size_t idx = static_cast<std::size_t>(h) % candidates_.size();
    if (is_redundancy) {
        idx = (idx + 1) % candidates_.size();
    }
    ++selection_counts_[idx];
    ++total_selections_;
    return candidates_[idx];
}

void MultipathStripSelector::skip_path(const net::FourTuple &tuple) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = std::find_if(candidates_.begin(), candidates_.end(),
                            [&](const net::FourTuple &p) { return p == tuple; });
    if (it == candidates_.end()) return;
    std::size_t idx = static_cast<std::size_t>(it - candidates_.begin());
    candidates_.erase(it);
    selection_counts_.erase(selection_counts_.begin() + idx);
    if (candidates_.empty()) {
        next_idx_ = 0;
    } else if (next_idx_ >= candidates_.size()) {
        next_idx_ = 0;
    }
}

std::vector<std::pair<net::FourTuple, std::uint64_t>>
MultipathStripSelector::selection_stats() const {
    // mp-M3 (v1.7.0.8): 加锁保护遍历 candidates_ 期间不被 update_candidates 重分配
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<std::pair<net::FourTuple, std::uint64_t>> result;
    result.reserve(candidates_.size());
    for (std::size_t i = 0; i < candidates_.size(); ++i) {
        result.emplace_back(candidates_[i], selection_counts_[i]);
    }
    return result;
}

// ============================================================================
// MultipathAdaptiveSelector
// ============================================================================

MultipathAdaptiveSelector::MultipathAdaptiveSelector(std::size_t expected_paths) {
    candidates_.reserve(expected_paths);
    selection_counts_.reserve(expected_paths);
    weights_.reserve(expected_paths);
    // 用 random_device 初始化 RNG 状态
    std::random_device rd;
    rng_state_ = (static_cast<std::uint64_t>(rd()) << 32) | rd();
    if (rng_state_ == 0) rng_state_ = 0x9E3779B97F4A7C15ULL;  // golden ratio 常数
}

void MultipathAdaptiveSelector::update_candidates(std::vector<PathInfo> paths) {
    // mp-M3 (v1.7.0.8): 加锁保护 candidates_/weights_ 重分配
    std::lock_guard<std::mutex> lk(mu_);
    candidates_ = std::move(paths);
    selection_counts_.assign(candidates_.size(), 0);
    weights_.assign(candidates_.size(), 0.0);
    total_selections_ = 0;
    recompute_weights();
}

void MultipathAdaptiveSelector::skip_path(const net::FourTuple &tuple) {
    // mp-M3 (v1.7.0.8): 加锁保护 erase + recompute_weights
    std::lock_guard<std::mutex> lk(mu_);
    auto it = std::find_if(candidates_.begin(), candidates_.end(),
                            [&](const PathInfo &p) { return p.tuple == tuple; });
    if (it == candidates_.end()) return;
    std::size_t idx = static_cast<std::size_t>(it - candidates_.begin());
    candidates_.erase(it);
    selection_counts_.erase(selection_counts_.begin() + idx);
    weights_.erase(weights_.begin() + idx);
    recompute_weights();
}

std::optional<net::FourTuple> MultipathAdaptiveSelector::select_next_for_send() {
    // mp-M3 (v1.7.0.8): 加锁保护加权随机读取 + rng_state_ 更新
    //   并发 select 会导致 rng_state_ 数据竞争（非原子读改写）+ weights_ 读期间被 recompute
    std::lock_guard<std::mutex> lk(mu_);
    if (candidates_.empty()) return std::nullopt;
    if (candidates_.size() == 1) {
        ++selection_counts_[0];
        ++total_selections_;
        return candidates_[0].tuple;
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

std::vector<std::pair<net::FourTuple, std::uint64_t>>
MultipathAdaptiveSelector::selection_stats() const {
    // mp-M3 (v1.7.0.8): 加锁保护遍历期间不被 update_candidates 重分配
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<std::pair<net::FourTuple, std::uint64_t>> result;
    result.reserve(candidates_.size());
    for (std::size_t i = 0; i < candidates_.size(); ++i) {
        result.emplace_back(candidates_[i].tuple, selection_counts_[i]);
    }
    return result;
}

void MultipathAdaptiveSelector::set_seed(std::uint64_t seed) {
    // mp-M3 (v1.7.0.8): 加锁保护 rng_state_ 写入
    std::lock_guard<std::mutex> lk(mu_);
    rng_state_ = seed;
    if (rng_state_ == 0) rng_state_ = 0x9E3779B97F4A7C15ULL;
}

void MultipathAdaptiveSelector::recompute_weights() {
    // mp-M3 (v1.7.0.8): 调用方持锁，本方法无需再加锁
    if (candidates_.empty()) return;
    if (candidates_.size() == 1) {
        weights_[0] = 1.0;
        return;
    }

    // 计算每条路径的权重 = 1 / max(srtt, 1ms)
    // 未测量（srtt=0）的路径按所有已测量路径的平均 RTT 处理
    std::vector<double> raw_weights(candidates_.size(), 0.0);
    double total = 0.0;
    std::uint64_t measured_count = 0;
    double measured_total_us = 0.0;

    for (std::size_t i = 0; i < candidates_.size(); ++i) {
        auto srtt_us = candidates_[i].srtt.count();
        if (srtt_us > 0) {
            ++measured_count;
            measured_total_us += static_cast<double>(srtt_us);
        }
    }
    double avg_us = (measured_count > 0) ? (measured_total_us / measured_count) : 1000.0;
    if (avg_us < 1.0) avg_us = 1.0;

    for (std::size_t i = 0; i < candidates_.size(); ++i) {
        auto srtt_us = candidates_[i].srtt.count();
        double effective_us = (srtt_us > 0) ? static_cast<double>(srtt_us) : avg_us;
        if (effective_us < 1.0) effective_us = 1.0;
        raw_weights[i] = 1.0 / effective_us;
        total += raw_weights[i];
    }

    // 归一化
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

std::uint64_t MultipathAdaptiveSelector::next_random() {
    // mp-M3 (v1.7.0.8): 调用方持锁，本方法无需再加锁
    // xorshift64* RNG
    std::uint64_t x = rng_state_;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state_ = x;
    return x * 0x2545F4914F6CDD1DULL;
}

}  // namespace linoh::protocol
