// event_bus.hpp — 事件总线（V3.4 新增，借鉴 gpustack server/bus.py 的 coalesce + 背压设计）
//
// 设计要点（详见 docs/LINOH_EVENTBUS_BINARY_FRAME_IMPL_PLAN.md §二）：
//   - 多订阅者：每个 Subscriber 独立双队列，互不影响
//   - coalesce：可合并事件用"字典即队列"设计（pending + order 分离），
//     同 key 覆盖不重复入队，poll 时从 pending 取最新版本
//   - 5 桶计数器：RECEIVED/FILTERED/COALESCED/ENQUEUED/BACKPRESSURED
//   - 分级背压：可合并事件 DropOldest（信息无损）/ 关键事件 Block（保证不丢）
//   - 线程安全：所有接口加锁，publish 并发安全
//   - 注入式时钟：ClockFunc 复用 control_plane 的虚拟时钟机制
//
// 双队列架构：
//   ┌──────────────────────────┬──────────────────────────────────┐
//   │  可合并事件通道            │  关键事件通道（不可合并）          │
//   │  (NodeUpdated/RepChanged) │  (NodeJoined/NodeLeft/NodeStale) │
//   ├──────────────────────────┼──────────────────────────────────┤
//   │  coalescable_pending_     │  critical_queue_                 │
//   │  (key→最新事件版本)        │  (deque<NodeEvent>)              │
//   │  + coalescable_order_     │  背压：critical_event_policy     │
//   │  (deque<key>，去重)        │  默认 Block（保证不丢）           │
//   └──────────────────────────┴──────────────────────────────────┘
//
// 向后兼容：
//   - ControlPlane::subscribe_node_events 内部转为 EventBus 的单订阅者
//   - 旧调用方无感知，行为与 v3.3 一致

#pragma once

#include "linoh/control_plane.hpp"  // NodeEvent, NodeEventType, ClockFunc, TimePoint

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace linoh {

// ============================================================================
// 事件计数桶（对应 gpustack EventCountKind）
// ============================================================================

enum class EventCountKind : std::uint8_t {
    Received      = 0,  // 收到总数
    Filtered      = 1,  // 被 event_types 过滤
    Coalesced     = 2,  // 被合并（相同 key）
    Enqueued      = 3,  // 成功入队
    Backpressured = 4,  // 队列满触发背压
};

constexpr const char *event_count_kind_name(EventCountKind k) noexcept {
    switch (k) {
        case EventCountKind::Received:      return "received";
        case EventCountKind::Filtered:      return "filtered";
        case EventCountKind::Coalesced:     return "coalesced";
        case EventCountKind::Enqueued:      return "enqueued";
        case EventCountKind::Backpressured: return "backpressured";
    }
    return "unknown";
}

/// 计数器快照（5 桶，供指标导出）
struct EventCounters {
    std::uint64_t received{0};
    std::uint64_t filtered{0};
    std::uint64_t coalesced{0};
    std::uint64_t enqueued{0};
    std::uint64_t backpressured{0};

    std::uint64_t get(EventCountKind k) const noexcept {
        switch (k) {
            case EventCountKind::Received:      return received;
            case EventCountKind::Filtered:      return filtered;
            case EventCountKind::Coalesced:     return coalesced;
            case EventCountKind::Enqueued:      return enqueued;
            case EventCountKind::Backpressured: return backpressured;
        }
        return 0;
    }
};

// ============================================================================
// 背压策略
// ============================================================================

enum class BackpressurePolicy : std::uint8_t {
    DropOldest = 0,  // 队列满时丢弃最旧事件（默认，对应 gpustack）
    DropNewest = 1,  // 队列满时丢弃最新事件（保留历史）
    Block      = 2,  // 队列满时阻塞 emit 直到有空位（控制面关键事件用）
};

// ============================================================================
// 订阅者配置
// ============================================================================

struct SubscriberConfig {
    /// 订阅的事件类型集合（空 = 全订阅）
    std::unordered_set<NodeEventType> event_types;

    /// 可合并事件队列容量（NodeUpdated/RegionRepChanged，默认 1000）
    /// 走 DropOldest 策略（信息无损，见 §2.3.4）
    std::size_t coalescable_queue_capacity{1000};

    /// 关键事件队列容量（NodeJoined/NodeLeft/NodeStale，默认 256）
    /// 走 critical_event_policy 策略，默认 Block 保证不丢
    std::size_t critical_queue_capacity{256};

    /// 可合并事件背压策略（默认 DropOldest）
    /// 可合并事件被覆盖的旧版本丢弃无信息损失
    BackpressurePolicy policy{BackpressurePolicy::DropOldest};

    /// 关键事件（不可合并）背压策略（默认 Block）
    /// NodeJoined/NodeLeft/NodeStale 不可丢，强制 Block 保证调度器感知
    /// 高并发下若消费者处理慢，emit 会阻塞而非丢弃
    BackpressurePolicy critical_event_policy{BackpressurePolicy::Block};

    /// Block 策略下的最长等待时间（0 = 无限等待）
    std::chrono::milliseconds block_timeout{0};

    /// 是否启用 coalesce（默认 true）
    bool coalesce_enabled{true};
};

// ============================================================================
// Subscriber — 单订阅者（对应 gpustack bus.py:Subscriber）
// ============================================================================

class Subscriber {
public:
    Subscriber(SubscriberConfig config, ClockFunc clock);

    // 不可拷贝（含 mutex + cv）
    Subscriber(const Subscriber &) = delete;
    Subscriber &operator=(const Subscriber &) = delete;

    /// 投递事件（由 EventBus 调用，线程安全）
    /// @return 是否成功入队（Block 策略下超时返回 false）
    bool deliver(const NodeEvent &event);

    /// 拉取一条事件（阻塞等待，供消费者线程调用）
    /// @return std::nullopt 表示队列空且 stop() 已调用
    std::optional<NodeEvent> poll(std::chrono::milliseconds timeout);

    /// 非阻塞尝试拉取
    std::optional<NodeEvent> try_poll();

    /// 停止订阅（唤醒所有阻塞的 poll / Block 中的 deliver）
    void stop();

    /// 获取计数器快照（线程安全）
    EventCounters counters() const;

    /// 当前队列总大小（可合并 + 关键，线程安全，调试用）
    std::size_t queue_size() const;

private:
    /// 判断事件类型是否被订阅
    bool accepts(NodeEventType type) const noexcept {
        return config_.event_types.empty() ||
               config_.event_types.count(type) > 0;
    }

    /// 判断事件类型是否可合并（同 key 只保留最新）
    static bool is_coalescable(NodeEventType type) noexcept {
        return type == NodeEventType::NodeUpdated ||
               type == NodeEventType::RegionRepChanged;
    }

    /// 事件的合并 key（endpoint_id 的 FNV-1a 哈希）
    static std::size_t event_key(const NodeEvent &event) noexcept;

    /// 可合并事件背压处理
    /// @return true=腾出空位可继续入队，false=Block 超时或 stop
    bool apply_coalescable_backpressure(std::unique_lock<std::mutex> &lk);

    /// 关键事件背压处理
    /// @return true=腾出空位可继续入队，false=丢弃或超时
    bool apply_critical_backpressure(std::unique_lock<std::mutex> &lk);

    /// Block 策略等待关键队列空位
    bool wait_for_critical_space(std::unique_lock<std::mutex> &lk);

    SubscriberConfig config_;
    ClockFunc clock_;

    mutable std::mutex mtx_;
    std::condition_variable cv_;

    // 双队列设计（V3.4 修正：可合并 vs 不可合并事件分离）
    // 可合并事件：字典 + key 顺序队列，同 key 覆盖不重复入队
    std::unordered_map<std::size_t, NodeEvent> coalescable_pending_;  // key→最新事件
    std::deque<std::size_t> coalescable_order_;                       // key 入队顺序（去重）

    // 不可合并事件：独立有界队列，走 critical_event_policy
    std::deque<NodeEvent> critical_queue_;                            // NodeJoined/Left/Stale

    EventCounters counters_{};
    bool stopped_{false};
};

// ============================================================================
// EventBus — 事件总线（多订阅者 fan-out）
// ============================================================================

class EventBus {
public:
    EventBus() = default;
    explicit EventBus(ClockFunc clock);

    /// 订阅事件（返回订阅者句柄，RAII 自动退订）
    /// @param config 订阅配置
    /// @return Subscriber 共享指针，调用方持有期间持续接收事件
    std::shared_ptr<Subscriber> subscribe(SubscriberConfig config = {});

    /// 发布事件（fan-out 到所有匹配订阅者，线程安全）
    void publish(const NodeEvent &event);

    /// 停止所有订阅者
    void stop_all();

    /// 订阅者计数器聚合快照（供指标导出）
    struct AggregateCounters {
        std::size_t subscriber_count{0};
        EventCounters total{};
    };
    AggregateCounters aggregate_counters() const;

    /// 当前活跃订阅者数量
    std::size_t subscriber_count() const;

private:
    ClockFunc clock_{};
    mutable std::mutex mtx_;
    std::vector<std::weak_ptr<Subscriber>> subscribers_;  // weak_ptr 避免悬挂
};

}  // namespace linoh
