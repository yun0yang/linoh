// event_bus.cpp — 事件总线实现（V3.4 新增）
//
// 实现 Subscriber（双队列 + 分级背压）和 EventBus（多订阅者 fan-out）。
// 设计详见 docs/LINOH_EVENTBUS_BINARY_FRAME_IMPL_PLAN.md §二。

#include "linoh/event_bus.hpp"

#include <algorithm>
#include <chrono>

namespace linoh {

// ============================================================================
// Subscriber 实现
// ============================================================================

Subscriber::Subscriber(SubscriberConfig config, ClockFunc clock)
    : config_(std::move(config))
    , clock_(clock ? std::move(clock)
                   : ClockFunc([]() { return std::chrono::system_clock::now(); })) {}

// FNV-1a 哈希（EndpointId 是 32 字节 PublicKey，无默认 std::hash 特化）
/*static*/ std::size_t Subscriber::event_key(const NodeEvent &event) noexcept {
    auto span = event.endpoint_id.as_span();
    std::size_t h = 14695981039346656037ULL;  // FNV-1a 64-bit offset basis
    for (std::uint8_t b : span) {
        h ^= static_cast<std::size_t>(b);
        h *= 1099511628211ULL;  // FNV-1a 64-bit prime
    }
    return h;
}

bool Subscriber::deliver(const NodeEvent &event) {
    std::unique_lock<std::mutex> lk(mtx_);
    ++counters_.received;

    // 1. 类型过滤
    if (!accepts(event.type)) {
        ++counters_.filtered;
        return true;  // 过滤不算失败
    }

    // 2. 分流：可合并 vs 关键事件
    if (config_.coalesce_enabled && is_coalescable(event.type)) {
        // ===== 可合并事件通道 =====
        auto key = event_key(event);
        if (coalescable_pending_.count(key) > 0) {
            // 同 key 已存在：覆盖版本，不重复入 order（coalesce 核心）
            coalescable_pending_[key] = event;
            ++counters_.coalesced;
            return true;
        }
        // 新 key：背压检查后入队
        if (coalescable_order_.size() >= config_.coalescable_queue_capacity) {
            ++counters_.backpressured;
            if (!apply_coalescable_backpressure(lk)) {
                return false;  // Block 超时或 stop
            }
            if (stopped_) return false;
        }
        coalescable_pending_[key] = event;
        coalescable_order_.push_back(key);
        ++counters_.enqueued;
    } else {
        // ===== 关键事件通道（不可合并） =====
        if (critical_queue_.size() >= config_.critical_queue_capacity) {
            ++counters_.backpressured;
            if (!apply_critical_backpressure(lk)) {
                return false;  // Block 超时或 DropNewest
            }
            if (stopped_) return false;
        }
        critical_queue_.push_back(event);
        ++counters_.enqueued;
    }

    cv_.notify_one();
    return true;
}

std::optional<NodeEvent> Subscriber::poll(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(mtx_);
    if (!cv_.wait_for(lk, timeout, [this] {
            return !critical_queue_.empty() || !coalescable_order_.empty() || stopped_;
        })) {
        return std::nullopt;  // 超时
    }
    if (stopped_ && critical_queue_.empty() && coalescable_order_.empty()) {
        return std::nullopt;
    }

    // 1. 优先消费关键事件（NodeJoined/Left/Stale 不可延迟）
    if (!critical_queue_.empty()) {
        NodeEvent event = std::move(critical_queue_.front());
        critical_queue_.pop_front();
        cv_.notify_one();  // 唤醒可能阻塞在 Block 的 deliver
        return event;
    }

    // 2. 消费可合并事件：从 order 取 key，从 pending 取最新版本
    while (!coalescable_order_.empty()) {
        std::size_t key = coalescable_order_.front();
        coalescable_order_.pop_front();
        auto it = coalescable_pending_.find(key);
        if (it != coalescable_pending_.end()) {
            NodeEvent event = std::move(it->second);
            coalescable_pending_.erase(it);
            return event;  // 总是最新版本（覆盖式合并保证）
        }
        // pending 中无此 key（防御性跳过，理论上不该发生）
    }
    return std::nullopt;
}

std::optional<NodeEvent> Subscriber::try_poll() {
    std::lock_guard<std::mutex> lk(mtx_);

    // 优先关键事件
    if (!critical_queue_.empty()) {
        NodeEvent event = std::move(critical_queue_.front());
        critical_queue_.pop_front();
        cv_.notify_one();
        return event;
    }

    // 其次可合并事件
    while (!coalescable_order_.empty()) {
        std::size_t key = coalescable_order_.front();
        coalescable_order_.pop_front();
        auto it = coalescable_pending_.find(key);
        if (it != coalescable_pending_.end()) {
            NodeEvent event = std::move(it->second);
            coalescable_pending_.erase(it);
            return event;
        }
    }
    return std::nullopt;
}

void Subscriber::stop() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        stopped_ = true;
    }
    cv_.notify_all();  // 唤醒所有阻塞的 poll 和 Block 中的 deliver
}

EventCounters Subscriber::counters() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return counters_;
}

std::size_t Subscriber::queue_size() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return critical_queue_.size() + coalescable_order_.size();
}

// ============================================================================
// 背压处理
// ============================================================================

bool Subscriber::apply_coalescable_backpressure(std::unique_lock<std::mutex> &lk) {
    switch (config_.policy) {
        case BackpressurePolicy::DropOldest: {
            // 弹出最旧 key，从 pending 删除（信息无损：后续新版本会重新入队）
            if (!coalescable_order_.empty()) {
                std::size_t oldest_key = coalescable_order_.front();
                coalescable_order_.pop_front();
                coalescable_pending_.erase(oldest_key);
            }
            return true;  // 腾出了空位
        }
        case BackpressurePolicy::DropNewest:
            // 可合并通道中新版本更重要，DropNewest 回退为 DropOldest（弹出最旧腾位）
            if (!coalescable_order_.empty()) {
                std::size_t oldest_key = coalescable_order_.front();
                coalescable_order_.pop_front();
                coalescable_pending_.erase(oldest_key);
            }
            return true;  // 腾出了空位
        case BackpressurePolicy::Block: {
            // 阻塞等待空位
            if (config_.block_timeout.count() > 0) {
                bool ok = cv_.wait_for(lk, config_.block_timeout, [this] {
                    return coalescable_order_.size() < config_.coalescable_queue_capacity ||
                           stopped_;
                });
                return ok && !stopped_;  // 超时或 stop 返回 false
            }
            cv_.wait(lk, [this] {
                return coalescable_order_.size() < config_.coalescable_queue_capacity ||
                       stopped_;
            });
            return !stopped_;
        }
    }
    return false;
}

bool Subscriber::apply_critical_backpressure(std::unique_lock<std::mutex> &lk) {
    switch (config_.critical_event_policy) {
        case BackpressurePolicy::DropOldest:
            // 极端情况：丢弃最旧关键事件（不推荐，默认不启用）
            if (!critical_queue_.empty()) {
                critical_queue_.pop_front();
            }
            return true;
        case BackpressurePolicy::DropNewest:
            return false;  // 丢弃当前事件
        case BackpressurePolicy::Block:
            return wait_for_critical_space(lk);
    }
    return false;
}

bool Subscriber::wait_for_critical_space(std::unique_lock<std::mutex> &lk) {
    if (config_.block_timeout.count() > 0) {
        bool ok = cv_.wait_for(lk, config_.block_timeout, [this] {
            return critical_queue_.size() < config_.critical_queue_capacity || stopped_;
        });
        return ok && !stopped_;
    }
    cv_.wait(lk, [this] {
        return critical_queue_.size() < config_.critical_queue_capacity || stopped_;
    });
    return !stopped_;
}

// ============================================================================
// EventBus 实现
// ============================================================================

EventBus::EventBus(ClockFunc clock)
    : clock_(clock ? std::move(clock)
                   : ClockFunc([]() { return std::chrono::system_clock::now(); })) {}

std::shared_ptr<Subscriber> EventBus::subscribe(SubscriberConfig config) {
    auto sub = std::make_shared<Subscriber>(std::move(config), clock_);
    std::lock_guard<std::mutex> lk(mtx_);
    subscribers_.push_back(sub);
    return sub;
}

void EventBus::publish(const NodeEvent &event) {
    std::vector<std::shared_ptr<Subscriber>> alive;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        alive.reserve(subscribers_.size());
        // 清理过期 weak_ptr 并收集存活订阅者
        subscribers_.erase(
            std::remove_if(subscribers_.begin(), subscribers_.end(),
                           [&alive](std::weak_ptr<Subscriber> &wp) {
                               auto sp = wp.lock();
                               if (sp) {
                                   alive.push_back(std::move(sp));
                                   return false;  // 保留 weak_ptr
                               }
                               return true;  // 移除过期
                           }),
            subscribers_.end());
    }
    // 在锁外 fan-out（避免长时间持锁，允许订阅者回调中再 publish）
    for (auto &sub : alive) {
        sub->deliver(event);
    }
}

void EventBus::stop_all() {
    std::vector<std::shared_ptr<Subscriber>> alive;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto &wp : subscribers_) {
            if (auto sp = wp.lock()) {
                alive.push_back(std::move(sp));
            }
        }
    }
    for (auto &sub : alive) {
        sub->stop();
    }
}

EventBus::AggregateCounters EventBus::aggregate_counters() const {
    std::vector<std::shared_ptr<Subscriber>> alive;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto &wp : subscribers_) {
            if (auto sp = wp.lock()) {
                alive.push_back(std::move(sp));
            }
        }
    }
    AggregateCounters agg;
    agg.subscriber_count = alive.size();
    for (auto &sub : alive) {
        auto c = sub->counters();
        agg.total.received += c.received;
        agg.total.filtered += c.filtered;
        agg.total.coalesced += c.coalesced;
        agg.total.enqueued += c.enqueued;
        agg.total.backpressured += c.backpressured;
    }
    return agg;
}

std::size_t EventBus::subscriber_count() const {
    std::lock_guard<std::mutex> lk(mtx_);
    // 统计存活订阅者（weak_ptr 未过期）
    std::size_t n = 0;
    for (const auto &wp : subscribers_) {
        if (!wp.expired()) ++n;
    }
    return n;
}

}  // namespace linoh
