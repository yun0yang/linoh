// task_queue.hpp — 线程安全任务队列事件源（v4.3.0 M7）
//
// 模型加载等耗时任务从业务线程 push 到队列，主循环 select 返回后 pop 处理。
// 电平触发语义：队列非空时 ready() 持续返回 true。
//
// 典型用法：
//   TaskQueue<ModelLoadTask> q;
//   loop.register_source(&q, 4);
//   // 业务线程：q.push(task);
//   // 主循环：auto task = q.pop(); if (task) load_model(*task);
#pragma once

#include "linoh/event/event_source.hpp"

#include <condition_variable>
#include <deque>
#include <mutex>
#include <optional>
#include <vector>

namespace linoh::event {

/// 线程安全任务队列（模板，支持任意 Task 类型）
template <typename Task>
class TaskQueue : public EventSource {
public:
    TaskQueue() = default;
    ~TaskQueue() override = default;

    TaskQueue(const TaskQueue&) = delete;
    TaskQueue& operator=(const TaskQueue&) = delete;

    /// 投递任务（跨线程安全）
    void push(Task task) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            queue_.push_back(std::move(task));
        }
        cv_.notify_all();
        wake_loop_();  // 唤醒 EventLoop
    }

    /// 取出一个任务（FIFO），无则返回 nullopt
    std::optional<Task> pop() {
        std::lock_guard<std::mutex> lk(mu_);
        if (queue_.empty()) return std::nullopt;
        Task task = std::move(queue_.front());
        queue_.pop_front();
        return task;
    }

    /// 取出所有任务（批量 drain）
    std::vector<Task> drain() {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<Task> result;
        result.reserve(queue_.size());
        while (!queue_.empty()) {
            result.push_back(std::move(queue_.front()));
            queue_.pop_front();
        }
        return result;
    }

    bool empty() const {
        std::lock_guard<std::mutex> lk(mu_);
        return queue_.empty();
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> lk(mu_);
        return queue_.size();
    }

    // === EventSource 接口（电平触发：队列非空即 ready） ===
    bool ready() const override {
        std::lock_guard<std::mutex> lk(mu_);
        return !queue_.empty();
    }

    bool wait_until(std::chrono::steady_clock::time_point deadline) override {
        std::unique_lock<std::mutex> lk(mu_);
        if (!queue_.empty()) return true;
        cv_.wait_until(lk, deadline);
        return !queue_.empty();
    }

    void clear_ready() override {
        // 电平触发：clear_ready 是 no-op，队列非空时 ready 持续 true
        // 调用方应通过 pop()/drain() 清空队列来使 ready 变 false
    }

private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Task> queue_;
};

}  // namespace linoh::event
