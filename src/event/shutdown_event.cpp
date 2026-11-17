// shutdown_event.cpp — ShutdownEvent 实现（v4.3.0 M7）
#include "linoh/event/shutdown_event.hpp"

namespace linoh::event {

void ShutdownEvent::trigger() {
    // 先置 flag（atomic），再 notify（保证 wait_until 不会错过 notify）
    flag_.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(mu_);
    }
    cv_.notify_all();
    // 唤醒 EventLoop（若已注册）
    wake_loop_();
}

bool ShutdownEvent::is_triggered() const noexcept {
    return flag_.load(std::memory_order_acquire);
}

bool ShutdownEvent::ready() const {
    return flag_.load(std::memory_order_acquire);
}

bool ShutdownEvent::wait_until(std::chrono::steady_clock::time_point deadline) {
    if (flag_.load(std::memory_order_acquire)) return true;
    std::unique_lock<std::mutex> lk(mu_);
    return cv_.wait_until(lk, deadline, [this] {
        return flag_.load(std::memory_order_acquire);
    });
}

void ShutdownEvent::clear_ready() {
    // shutdown 不可清除：一旦触发永久 ready
    // no-op by design
}

}  // namespace linoh::event
