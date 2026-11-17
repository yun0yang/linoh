// shutdown_event.hpp — 优雅退出事件源（v4.3.0 M7）
//
// 最高优先级事件源，trigger() 后 select() 立即返回。
// 典型用法：signal handler / 外部线程触发 → 主循环 select 返回 → 退出
//
// 线程安全：trigger() 可从任意线程调用（含 signal handler，因仅用 atomic + cv notify）
#pragma once

#include "linoh/event/event_source.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>

namespace linoh::event {

/// 优雅退出事件源
class ShutdownEvent : public EventSource {
public:
    ShutdownEvent() = default;
    ~ShutdownEvent() override = default;

    ShutdownEvent(const ShutdownEvent&) = delete;
    ShutdownEvent& operator=(const ShutdownEvent&) = delete;

    /// 触发退出信号（跨线程安全，可从 signal handler 调用）
    ///
    /// 语义：trigger 后 ready() 永久返回 true（不可撤销），
    ///       clear_ready() 不清除 shutdown 标记（幂等，多次 trigger 等效一次）
    void trigger();

    /// 是否已触发
    bool is_triggered() const noexcept;

    // === EventSource 接口 ===
    bool ready() const override;
    bool wait_until(std::chrono::steady_clock::time_point deadline) override;
    void clear_ready() override;  // no-op：shutdown 不可清除

private:
    std::atomic<bool> flag_{false};
    mutable std::mutex mu_;
    std::condition_variable cv_;
};

}  // namespace linoh::event
