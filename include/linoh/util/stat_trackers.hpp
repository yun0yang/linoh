// stat_trackers.hpp — min_max_avg_tracker<T> 统计追踪（P5-C-2）
//
// 借鉴 Sunshine src/stat_trackers.h：
//   - 滚动累积 min/max/avg
//   - 按时间间隔回调并重置（用于周期性上报）
//   - 线程安全可选（sync_t 包装）
//
// 用途：
//   - Connection RTT 追踪（替代瞬时 RTT）
//   - PathSelector 选路时使用平滑 RTT
//   - 集群管家调度数据支撑
//   - 多通道带宽/延迟/丢包率统计

#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <type_traits>

namespace linoh::util {

/// @brief min/max/avg 滚动统计追踪器
///
/// 用法示例：
/// @code
///   min_max_avg_tracker<double> rtt_tracker;
///   rtt_tracker.collect(12.5);
///   rtt_tracker.collect(8.3);
///   rtt_tracker.collect(15.7);
///   rtt_tracker.min();   // 8.3
///   rtt_tracker.max();   // 15.7
///   rtt_tracker.avg();   // 12.17
/// @endcode
///
/// @tparam T 数值类型（int/double/long 等）
template <typename T>
class min_max_avg_tracker {
public:
    using value_t = T;

    /// 默认构造：min/max 初始化为类型极限值，count=0
    min_max_avg_tracker() = default;

    /// 收集一个样本
    void collect(T stat) {
        if (count_ == 0) {
            min_ = stat;
            max_ = stat;
            total_ = stat;
        } else {
            min_ = (std::min)(min_, stat);
            max_ = (std::max)(max_, stat);
            total_ += stat;
        }
        ++count_;
    }

    /// @brief 收集样本并按时间间隔回调
    /// @param stat 当前样本
    /// @param callback 回调函数，参数为 (min, max, avg)
    /// @param interval 回调间隔
    /// @return 是否触发了回调（true=已触发并重置）
    ///
    /// 行为：当前样本先加入统计，若达到回调间隔则触发回调并重置；
    /// 重置后当前样本作为新周期第一个样本保留（不会丢失）。
    bool collect_and_callback_on_interval(
        T stat,
        std::function<void(T min, T max, double avg)> callback,
        std::chrono::steady_clock::duration interval) {
        collect(stat);
        auto now = std::chrono::steady_clock::now();
        if (count_ == 1) {
            // 第一次收集，记录起始时间，不触发回调
            last_callback_ = now;
            return false;
        }
        if (now - last_callback_ >= interval) {
            if (callback) {
                callback(min_, max_, avg());
            }
            // 重置后保留当前样本作为新周期起点
            reset();
            collect(stat);
            last_callback_ = now;
            return true;
        }
        return false;
    }

    /// 当前最小值（若无样本返回类型极限值）
    T min() const { return min_; }

    /// 当前最大值（若无样本返回类型极限值）
    T max() const { return max_; }

    /// 当前平均值（若无样本返回 0）
    double avg() const {
        return count_ == 0 ? 0.0 : static_cast<double>(total_) / static_cast<double>(count_);
    }

    /// 累计总和
    T total() const { return total_; }

    /// 已收集样本数
    std::size_t count() const { return count_; }

    /// 是否为空（无样本）
    bool empty() const { return count_ == 0; }

    /// 重置所有统计
    void reset() {
        min_ = kInitMin;
        max_ = kInitMax;
        total_ = T{};
        count_ = 0;
    }

    /// 合并另一个 tracker 到当前（用于多通道聚合）
    void merge(const min_max_avg_tracker<T>& other) {
        if (other.empty()) return;
        if (empty()) {
            *this = other;
            return;
        }
        min_ = (std::min)(min_, other.min_);
        max_ = (std::max)(max_, other.max_);
        total_ += other.total_;
        count_ += other.count_;
    }

private:
    static constexpr T kInitMin = std::numeric_limits<T>::max();
    static constexpr T kInitMax = std::numeric_limits<T>::lowest();

    T min_{kInitMin};
    T max_{kInitMax};
    T total_{};
    std::size_t count_{0};
    std::chrono::steady_clock::time_point last_callback_{};
};

/// @brief 多通道统计聚合器
///
/// 按 ChannelType 分通道维护独立的 tracker，支持聚合查询。
/// 用法：
/// @code
///   channel_stat_tracker<double> rtt_stats;
///   rtt_stats.collect(ChannelType::LLM_HIDDEN, 5.2);
///   rtt_stats.collect(ChannelType::VIDEO_FEATURE, 12.7);
///   rtt_stats.aggregate().avg();  // 所有通道聚合平均
/// @endcode
template <typename T, std::size_t N>
class channel_stat_tracker {
public:
    /// 收集某通道样本
    void collect(std::size_t channel_idx, T stat) {
        if (channel_idx < N) {
            trackers_[channel_idx].collect(stat);
        }
    }

    /// 获取某通道 tracker
    min_max_avg_tracker<T>& channel(std::size_t channel_idx) {
        return trackers_[channel_idx];
    }

    /// 获取某通道 tracker（const 版本）
    const min_max_avg_tracker<T>& channel(std::size_t channel_idx) const {
        return trackers_[channel_idx];
    }

    /// 聚合所有通道
    min_max_avg_tracker<T> aggregate() const {
        min_max_avg_tracker<T> result;
        for (std::size_t i = 0; i < N; ++i) {
            result.merge(trackers_[i]);
        }
        return result;
    }

    /// 重置所有通道
    void reset() {
        for (auto& t : trackers_) t.reset();
    }

    /// 通道数量
    static constexpr std::size_t size() { return N; }

private:
    min_max_avg_tracker<T> trackers_[N]{};
};

/// @brief 线程安全的 min_max_avg_tracker（基于 mutex）
///
/// 用法：
/// @code
///   thread_safe_min_max_avg_tracker<double> rtt;
///   rtt.collect(5.2);     // 多线程安全
///   rtt.with_lock([](min_max_avg_tracker<double>& t) {
///       t.collect(3.1);
///   });
/// @endcode
template <typename T, class M = std::mutex>
class thread_safe_min_max_avg_tracker {
public:
    void collect(T stat) {
        std::lock_guard<M> lk(mutex_);
        tracker_.collect(stat);
    }

    T min() const {
        std::lock_guard<M> lk(mutex_);
        return tracker_.min();
    }

    T max() const {
        std::lock_guard<M> lk(mutex_);
        return tracker_.max();
    }

    double avg() const {
        std::lock_guard<M> lk(mutex_);
        return tracker_.avg();
    }

    T total() const {
        std::lock_guard<M> lk(mutex_);
        return tracker_.total();
    }

    std::size_t count() const {
        std::lock_guard<M> lk(mutex_);
        return tracker_.count();
    }

    bool empty() const {
        std::lock_guard<M> lk(mutex_);
        return tracker_.empty();
    }

    void reset() {
        std::lock_guard<M> lk(mutex_);
        tracker_.reset();
    }

    /// 在持锁状态下执行 callable（用于复合操作）
    template <class F>
    auto with_lock(F&& f) -> decltype(std::forward<F>(f)(std::declval<min_max_avg_tracker<T>&>())) {
        std::lock_guard<M> lk(mutex_);
        return std::forward<F>(f)(tracker_);
    }

    /// 合并另一个线程安全 tracker
    void merge(const thread_safe_min_max_avg_tracker<T, M>& other) {
        std::lock_guard<M> lk1(mutex_);
        std::lock_guard<M> lk2(other.mutex_);
        tracker_.merge(other.tracker_);
    }

private:
    min_max_avg_tracker<T> tracker_;
    mutable M mutex_;
};

}  // namespace linoh::util
