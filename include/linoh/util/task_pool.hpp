// task_pool.hpp — TaskPool 任务池 + 延时调度（P5-C-3）
//
// 借鉴 Sunshine src/task_pool.h：
//   - 统一池化工作线程，避免散落的 std::thread
//   - 支持立即任务 push() 和延时任务 pushDelayed()
//   - 延时任务可 cancel / delay 重新调度
//   - 双队列：立即队列（FIFO）+ 延时队列（按到期时间排序）
//
// 设计要点：
//   - delayed_tasks_ 用 map<id, (expire_at, fn)> 保存有效任务
//   - delayed_queue_ 用 priority_queue<(expire_at, id)> 仅索引
//   - worker 弹出 queue 顶后，检查 map 中是否存在且 expire_at 一致
//     （避免 delay() 重新调度后的旧 queue 条目被执行）
//   - cancel() 直接从 map 删除，queue 中的旧条目会被 worker 跳过

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace linoh::util {

/// @brief 任务池：统一管理工作线程，支持立即/延时任务
class TaskPool {
public:
    using task_id_t = std::uint64_t;
    static constexpr task_id_t kInvalidTaskId = 0;

    /// @brief 构造任务池
    /// @param worker_count 工作线程数（默认 4）
    explicit TaskPool(std::size_t worker_count = 4)
        : stop_{false}, next_task_id_{1} {
        if (worker_count == 0) worker_count = 1;
        workers_.reserve(worker_count);
        for (std::size_t i = 0; i < worker_count; ++i) {
            workers_.emplace_back([this]() { worker_loop(); });
        }
    }

    ~TaskPool() {
        stop_internal();
    }

    TaskPool(const TaskPool&) = delete;
    TaskPool& operator=(const TaskPool&) = delete;
    TaskPool(TaskPool&&) = delete;
    TaskPool& operator=(TaskPool&&) = delete;

    // ------------------------------------------------------------------
    // 立即任务
    // ------------------------------------------------------------------

    /// @brief 提交立即任务
    template <class F>
    auto push(F&& fn) -> std::future<decltype(fn())> {
        using R = decltype(fn());
        auto task = std::make_shared<std::packaged_task<R()>>(std::forward<F>(fn));
        auto fut = task->get_future();
        {
            std::lock_guard<std::mutex> lk(immediate_mutex_);
            immediate_queue_.push_back([task]() { (*task)(); });
        }
        immediate_cv_.notify_one();
        return fut;
    }

    // ------------------------------------------------------------------
    // 延时任务
    // ------------------------------------------------------------------

    /// @brief 提交延时任务
    /// @return (future, task_id)，task_id 用于 cancel/delay
    template <class F>
    auto pushDelayed(F&& fn, std::chrono::milliseconds delay)
        -> std::pair<std::future<decltype(fn())>, task_id_t> {
        using R = decltype(fn());
        auto task = std::make_shared<std::packaged_task<R()>>(std::forward<F>(fn));
        auto fut = task->get_future();
        task_id_t id = next_task_id_.fetch_add(1, std::memory_order_relaxed);
        if (id == kInvalidTaskId) {
            id = next_task_id_.fetch_add(1, std::memory_order_relaxed);
        }
        auto expire_at = std::chrono::steady_clock::now() + delay;
        // 把 shared_ptr<packaged_task> 也存到 DelayedEntry，
        // 这样 cancel 时不会析构 packaged_task（避免 promise 设置 broken_promise）
        {
            std::lock_guard<std::mutex> lk(delayed_mutex_);
            delayed_tasks_.emplace(id, DelayedEntry{
                expire_at,
                [task]() { (*task)(); },
                task  // 保存 shared_ptr 引用
            });
            delayed_queue_.push({expire_at, id});
        }
        delayed_cv_.notify_one();
        return {std::move(fut), id};
    }

    /// @brief 取消延时任务
    /// @return true 若任务未执行且成功取消；false 若任务已执行或不存在
    ///
    /// 注意：为避免 packaged_task 析构触发 broken_promise（让 future 异常 ready），
    /// cancel 时把 task_ref 保留到 cancelled_tasks_，直到 pool 析构。
    bool cancel(task_id_t id) {
        if (id == kInvalidTaskId) return false;
        std::lock_guard<std::mutex> lk(delayed_mutex_);
        auto it = delayed_tasks_.find(id);
        if (it == delayed_tasks_.end()) return false;
        // 保留 task_ref 避免 packaged_task 析构
        if (it->second.task_ref) {
            cancelled_tasks_.push_back(std::move(it->second.task_ref));
        }
        delayed_tasks_.erase(it);
        return true;
    }

    /// @brief 重新设置延时任务的延迟（重新调度）
    /// @param id 任务 ID
    /// @param new_delay 新的延迟时间（从现在起）
    /// @return true 若任务重新调度成功；false 若任务已执行或不存在
    bool delay(task_id_t id, std::chrono::milliseconds new_delay) {
        if (id == kInvalidTaskId) return false;
        std::lock_guard<std::mutex> lk(delayed_mutex_);
        auto it = delayed_tasks_.find(id);
        if (it == delayed_tasks_.end()) return false;
        auto new_expire = std::chrono::steady_clock::now() + new_delay;
        it->second.expire_at = new_expire;
        delayed_queue_.push({new_expire, id});  // 旧 queue 条目会被 worker 跳过（expire_at 不匹配）
        delayed_cv_.notify_one();
        return true;
    }

    /// @brief 立即停止所有任务（未执行的会被丢弃）
    void stop() {
        stop_internal();
    }

    /// @brief 工作线程数
    std::size_t worker_count() const noexcept {
        return workers_.size();
    }

    /// @brief 待执行的立即任务数
    std::size_t immediate_queue_size() const {
        std::lock_guard<std::mutex> lk(immediate_mutex_);
        return immediate_queue_.size();
    }

    /// @brief 待执行的延时任务数（有效任务）
    std::size_t delayed_queue_size() const {
        std::lock_guard<std::mutex> lk(delayed_mutex_);
        return delayed_tasks_.size();
    }

private:
    struct DelayedEntry {
        std::chrono::steady_clock::time_point expire_at;
        std::function<void()> fn;
        std::shared_ptr<void> task_ref;  // 保存 packaged_task 引用，避免 cancel 时析构
    };

    struct QueueEntry {
        std::chrono::steady_clock::time_point expire_at;
        task_id_t id;
        bool operator>(const QueueEntry& other) const {
            return expire_at > other.expire_at;
        }
    };

    void worker_loop() {
        while (true) {
            // 1. 计算下一个延时任务的等待时间
            std::chrono::milliseconds wait_ms{10};
            std::vector<std::function<void()>> ready_tasks;
            {
                std::lock_guard<std::mutex> lk(delayed_mutex_);
                auto now = std::chrono::steady_clock::now();
                // 弹出所有过期条目（含旧的 delay 残留）
                while (!delayed_queue_.empty()) {
                    auto& top = delayed_queue_.top();
                    if (top.expire_at > now) {
                        wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            top.expire_at - now);
                        break;
                    }
                    auto id = top.id;
                    auto expire = top.expire_at;
                    delayed_queue_.pop();
                    // 检查 map 中是否存在且 expire_at 一致
                    auto it = delayed_tasks_.find(id);
                    if (it == delayed_tasks_.end()) continue;  // 已取消
                    if (it->second.expire_at != expire) continue;  // 旧条目（已被 delay 更新）
                    // 任务到期，取出并从 map 删除
                    ready_tasks.push_back(std::move(it->second.fn));
                    delayed_tasks_.erase(it);
                }
            }

            // 2. 把到期任务转移到立即队列
            if (!ready_tasks.empty()) {
                std::lock_guard<std::mutex> lk(immediate_mutex_);
                for (auto& t : ready_tasks) {
                    immediate_queue_.push_back(std::move(t));
                }
                immediate_cv_.notify_all();
            }

            // 3. 等待立即任务或下个延时任务
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lk(immediate_mutex_);
                if (immediate_cv_.wait_for(lk, wait_ms,
                        [this]() { return !immediate_queue_.empty() || stop_; })) {
                    if (!immediate_queue_.empty()) {
                        task = std::move(immediate_queue_.front());
                        immediate_queue_.pop_front();
                    }
                }
            }

            if (task) {
                task();
            } else if (stop_) {
                std::lock_guard<std::mutex> lk1(immediate_mutex_);
                std::lock_guard<std::mutex> lk2(delayed_mutex_);
                if (immediate_queue_.empty() && delayed_tasks_.empty()) return;
            }
        }
    }

    void stop_internal() {
        {
            std::lock_guard<std::mutex> lk1(immediate_mutex_);
            std::lock_guard<std::mutex> lk2(delayed_mutex_);
            stop_ = true;
            // 停止时清空延时任务队列（丢弃未执行任务）
            delayed_tasks_.clear();
        }
        immediate_cv_.notify_all();
        delayed_cv_.notify_all();
        for (auto& w : workers_) {
            if (w.joinable()) w.join();
        }
        workers_.clear();
    }

    std::vector<std::thread> workers_;
    mutable std::mutex immediate_mutex_;
    std::deque<std::function<void()>> immediate_queue_;
    std::condition_variable immediate_cv_;

    mutable std::mutex delayed_mutex_;
    std::unordered_map<task_id_t, DelayedEntry> delayed_tasks_;
    std::priority_queue<QueueEntry, std::vector<QueueEntry>, std::greater<QueueEntry>> delayed_queue_;
    std::condition_variable delayed_cv_;
    std::vector<std::shared_ptr<void>> cancelled_tasks_;  // 已取消任务的 task_ref 保留

    std::atomic<bool> stop_;
    std::atomic<task_id_t> next_task_id_;
};

}  // namespace linoh::util
