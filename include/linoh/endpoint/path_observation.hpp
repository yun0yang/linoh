// path_observation.hpp — v4.7.0 Path Observation API（PathList + PathEventStream）
//
// 借鉴 iroh 1.0.0-rc.0 Path observation API 重设计（iroh#4232）：
//   - PathList：路径快照（不可变视图，借用 Connection，stats 调用 infallible）
//   - PathEventStream：'static 路径事件流（per-stream 有界队列，多消费者独立）
//   - "先订阅后快照"模式消除竞争（auto stream = conn.path_events(); auto snap = conn.paths();）
//
// 与 PathMigrationManager::set_path_event_callback 的关系：
//   - callback 是同步单消费者（仅 closed 事件，PathMigrationManager 级）
//   - PathEventStream 是异步多消费者（Opened/Selected/Closed/Lagged 全事件，Connection 级）
//   - Connection 内部桥接：callback 事件转发到所有 stream
//
// 设计要点：
//   - per-stream 独立有界队列（非 broadcast channel），慢消费者只影响自己
//   - 队列溢出时丢弃最旧事件并投递 kLagged 事件（消费者可感知并恢复）
//   - Connection 持 weak_ptr<Impl>，stream 持 shared_ptr<Impl>，
//     Connection 析构后 stream 仍可读剩余事件，最终 close
//   - PathList 是值类型快照（拷贝构造/赋值），调用方持有期间数据不变

#pragma once

#include "linoh/protocol/path_event.hpp"
#include "linoh/protocol/path_migration.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace linoh::endpoint {

/// PathEventStream 内部实现（per-stream 有界队列 + mutex + cv）
///
/// 每个 PathEventStream 实例持有一个 shared_ptr<Impl>，
/// Connection 持有 weak_ptr<Impl> 做 fan-out。
/// Connection 析构时通过 weak_ptr lock 关闭所有 stream。
struct PathEventStreamImpl {
    mutable std::mutex mu;
    std::condition_variable cv;
    std::deque<protocol::PathEvent> queue;
    std::size_t capacity{64};
    bool closed{false};
    std::uint64_t lagged_count{0};  // 累计溢出计数（诊断用）

    /// 推入事件（调用方必须已持有 mu）
    ///
    /// 若队列满，丢弃最旧事件并累加 lagged_count，同时投递一个 kLagged 事件
    /// 通知消费者（消费者收到 kLagged 后可决定是否重新快照）。
    void push_locked(protocol::PathEvent ev) {
        if (queue.size() >= capacity) {
            queue.pop_front();
            ++lagged_count;
            queue.push_back(protocol::PathEvent::lagged(ev.path_id, lagged_count));
        }
        queue.push_back(std::move(ev));
        cv.notify_one();
    }
};

/// 路径事件流（独立对象，可 'static 持有，不延长 Connection 生命周期）
///
/// 借鉴 iroh PathEventStream。用法：
///   auto stream = conn.path_events();       // 先订阅
///   auto snap = conn.paths();                // 后快照（消除竞争）
///   while (auto ev = stream.try_pop()) { ... }
class PathEventStream {
public:
    static constexpr std::size_t kDefaultCapacity = 64;

    explicit PathEventStream(std::size_t capacity = kDefaultCapacity)
        : impl_(std::make_shared<PathEventStreamImpl>()) {
        impl_->capacity = (capacity == 0) ? kDefaultCapacity : capacity;
    }

    /// 阻塞等待下一个事件（超时返回 nullopt；closed 且队列空时返回 nullopt）
    std::optional<protocol::PathEvent> next(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lk(impl_->mu);
        impl_->cv.wait_for(lk, timeout, [this] {
            return !impl_->queue.empty() || impl_->closed;
        });
        if (impl_->queue.empty()) {
            return std::nullopt;
        }
        protocol::PathEvent ev = std::move(impl_->queue.front());
        impl_->queue.pop_front();
        return ev;
    }

    /// 非阻塞尝试取一个事件
    std::optional<protocol::PathEvent> try_pop() {
        std::lock_guard<std::mutex> lk(impl_->mu);
        if (impl_->queue.empty()) return std::nullopt;
        protocol::PathEvent ev = std::move(impl_->queue.front());
        impl_->queue.pop_front();
        return ev;
    }

    /// 显式关闭流（Connection 析构时也会自动关闭）
    void close() {
        std::lock_guard<std::mutex> lk(impl_->mu);
        impl_->closed = true;
        impl_->cv.notify_all();
    }

    bool is_closed() const {
        std::lock_guard<std::mutex> lk(impl_->mu);
        return impl_->closed;
    }

    /// 累计溢出计数（诊断用，队列溢出次数）
    std::uint64_t lagged_count() const {
        std::lock_guard<std::mutex> lk(impl_->mu);
        return impl_->lagged_count;
    }

private:
    friend class Connection;
    std::shared_ptr<PathEventStreamImpl> impl_;

    /// 供 Connection 获取 weak_ptr（注册 fan-out 用）
    std::weak_ptr<PathEventStreamImpl> weak_impl() const {
        return impl_;
    }
};

// ============================================================================
// v4.7.0: PathList — 路径快照（不可变视图）
// ============================================================================
//
// 借鉴 iroh 1.0.0-rc.0 PathList<'_>（iroh#4232）：
//   - 值类型快照，调用方持有期间数据不变（无并发竞争）
//   - stats 调用 infallible（已拷贝，不依赖 Connection 存活）
//   - "先订阅后快照"模式：auto stream = conn.path_events(); auto snap = conn.paths();
//     流订阅后，快照保证不丢失订阅时刻之后的事件
//
// 与 PathMigrationManager::path_qualities_snapshot() 的关系：
//   - snapshot() 返回 vector<PathQuality>（裸数据）
//   - PathList 包装为不可变视图，提供 current()/current_path_id() 等便捷方法
//   - Connection::paths() 内部调用 snapshot() 后构造 PathList 返回
class PathList {
public:
    PathList() = default;

    /// 路径数量
    std::size_t size() const noexcept { return snapshot_.size(); }
    bool empty() const noexcept { return snapshot_.empty(); }

    /// 按索引访问路径（不检查越界，调用方确保 i < size()）
    const protocol::PathMigrationManager::PathQuality &operator[](std::size_t i) const {
        return snapshot_[i];
    }

    /// 迭代器支持（range-for）
    auto begin() const noexcept { return snapshot_.begin(); }
    auto end() const noexcept { return snapshot_.end(); }

    /// 当前主路径（若 Connection 标记了主路径，返回其快照；否则返回 nullptr）
    const protocol::PathMigrationManager::PathQuality *current() const noexcept {
        if (!current_idx_.has_value() || *current_idx_ >= snapshot_.size()) {
            return nullptr;
        }
        return &snapshot_[*current_idx_];
    }

    /// 当前主路径 ID（若存在）
    std::optional<std::uint64_t> current_path_id() const noexcept {
        const auto *c = current();
        if (c == nullptr) return std::nullopt;
        return c->path_id;
    }

private:
    friend class Connection;
    std::vector<protocol::PathMigrationManager::PathQuality> snapshot_;
    std::optional<std::size_t> current_idx_;  // 主路径在 snapshot_ 中的索引
};

} // namespace linoh::endpoint
