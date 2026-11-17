// =============================================================================
// peer_error_tracker.cpp — v3.8.0 安全与故障自动化：per-peer 错误计数自动降级实现
//
// 复用 base::EndpointId（PublicKey，已有 std::hash 特化）
// 线程安全：shared_mutex 读写分离（多读单写）
// 滑动窗口：deque<time_point, error_type>，每次操作清理过期条目
// =============================================================================

#include "linoh/endpoint/peer_error_tracker.hpp"

#include <algorithm>
#include <utility>

namespace linoh::endpoint {

// =============================================================================
// ErrorType 辅助
// =============================================================================

const char *error_type_name(ErrorType type) {
    switch (type) {
        case ErrorType::ConnectFailed:    return "ConnectFailed";
        case ErrorType::HandshakeFailed:  return "HandshakeFailed";
        case ErrorType::SendFailed:       return "SendFailed";
        case ErrorType::StreamError:      return "StreamError";
        case ErrorType::Timeout:          return "Timeout";
        default:                          return "Unknown";
    }
}

// =============================================================================
// PeerErrorTracker 构造
// =============================================================================

PeerErrorTracker::PeerErrorTracker(PeerErrorTrackerConfig config)
    : config_(std::move(config)) {}

// =============================================================================
// 核心接口
// =============================================================================

void PeerErrorTracker::record_error(const base::EndpointId &peer, ErrorType type) {
    if (!config_.enabled) return;  // 向后兼容：禁用时 no-op

    const TimePoint now = Clock::now();

    std::unique_lock<std::shared_mutex> lk(mu_);

    auto &state = peers_[peer];  // 不存在则创建默认 PeerState_

    // 清理窗口外过期错误
    prune_expired_locked_(state, now);

    // 添加新错误
    state.recent_errors.emplace_back(now, type);
    ++state.total_errors;
    state.last_error_type = type;
    state.last_error_time = now;
    state.has_last_error = true;

    // 检查是否达到降级阈值
    if (state.recent_errors.size() >= config_.max_errors_per_peer && !state.degraded) {
        state.degraded = true;
        state.degraded_at = now;
    }
}

bool PeerErrorTracker::should_degrade(const base::EndpointId &peer) const {
    if (!config_.enabled) return false;  // 向后兼容：禁用时不降级

    std::shared_lock<std::shared_mutex> lk(mu_);

    auto it = peers_.find(peer);
    if (it == peers_.end()) return false;

    const auto &state = it->second;

    // 已标记降级 → 直接返回 true
    if (state.degraded) return true;

    // 检查窗口内错误数（不清理，仅统计）
    const TimePoint now = Clock::now();
    const TimePoint window_start = now - config_.error_window;

    std::size_t count = 0;
    for (const auto &[tp, et] : state.recent_errors) {
        if (tp >= window_start) ++count;
    }

    return count >= config_.max_errors_per_peer;
}

void PeerErrorTracker::reset(const base::EndpointId &peer) {
    if (!config_.enabled) return;

    std::unique_lock<std::shared_mutex> lk(mu_);

    auto it = peers_.find(peer);
    if (it == peers_.end()) return;

    auto &state = it->second;

    // 清空滑动窗口 + 降级标记（保留 total_errors 用于长期统计）
    state.recent_errors.clear();
    state.degraded = false;
    state.degraded_at = TimePoint{};
}

// =============================================================================
// 查询接口
// =============================================================================

PeerErrorStats PeerErrorTracker::get_stats(const base::EndpointId &peer) const {
    PeerErrorStats stats{};

    if (!config_.enabled) return stats;

    std::shared_lock<std::shared_mutex> lk(mu_);

    auto it = peers_.find(peer);
    if (it == peers_.end()) return stats;

    const auto &state = it->second;

    // 统计窗口内错误数（不清理，仅统计快照）
    const TimePoint now = Clock::now();
    const TimePoint window_start = now - config_.error_window;

    for (const auto &[tp, et] : state.recent_errors) {
        if (tp >= window_start) ++stats.current_window_errors;
    }

    stats.total_errors = state.total_errors;
    stats.last_error_type = state.last_error_type;
    stats.degraded = state.degraded;

    if (state.has_last_error) {
        stats.last_error_time = state.last_error_time;
    }

    return stats;
}

bool PeerErrorTracker::clear_degraded(const base::EndpointId &peer) {
    if (!config_.enabled) return false;

    std::unique_lock<std::shared_mutex> lk(mu_);

    auto it = peers_.find(peer);
    if (it == peers_.end()) return false;

    auto &state = it->second;
    if (!state.degraded) return true;  // 未降级，无需清除

    // 检查冷却时间（直接比较 duration，chrono 自动隐式转换）
    const TimePoint now = Clock::now();
    const auto elapsed = now - state.degraded_at;  // steady_clock duration（通常 nanoseconds）

    if (elapsed < config_.degrade_cooldown) {
        return false;  // 仍在冷却中
    }

    // 冷却已过，清除降级标记 + 清空错误窗口（给 peer 一个干净的重试机会）
    state.degraded = false;
    state.degraded_at = TimePoint{};
    state.recent_errors.clear();

    return true;
}

void PeerErrorTracker::clear_all() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    peers_.clear();
}

std::size_t PeerErrorTracker::peer_count() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return peers_.size();
}

std::size_t PeerErrorTracker::degraded_count() const {
    std::shared_lock<std::shared_mutex> lk(mu_);

    std::size_t count = 0;
    for (const auto &[id, state] : peers_) {
        if (state.degraded) ++count;
    }
    return count;
}

// =============================================================================
// 配置接口
// =============================================================================

void PeerErrorTracker::update_config(PeerErrorTrackerConfig config) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    config_ = std::move(config);
}

// =============================================================================
// 内部辅助
// =============================================================================

void PeerErrorTracker::prune_expired_locked_(PeerState_ &state, TimePoint now) const {
    const TimePoint window_start = now - config_.error_window;

    // deque 前端是最旧的，从前往后清理
    while (!state.recent_errors.empty()) {
        if (state.recent_errors.front().first < window_start) {
            state.recent_errors.pop_front();
        } else {
            break;  // 遇到未过期条目，后面都更新，可停
        }
    }
}

}  // namespace linoh::endpoint
