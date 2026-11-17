// timer_event.cpp — TimerEvent 实现（v4.3.0 M7）
#include "linoh/event/timer_event.hpp"

namespace linoh::event {

TimerEvent::TimerEvent(std::chrono::milliseconds period)
    : period_(period > std::chrono::milliseconds(0) ? period : std::chrono::milliseconds(1)),
      next_fire_(std::chrono::steady_clock::now() + period_) {
}

void TimerEvent::reset() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        fired_ = false;
        next_fire_ = std::chrono::steady_clock::now() + period_;
    }
    cv_.notify_all();
    // 不需要 wake_loop_：reset 是处理完后调用，此时主循环不在 select 中
}

void TimerEvent::set_period(std::chrono::milliseconds period) {
    if (period <= std::chrono::milliseconds(0)) return;
    {
        std::lock_guard<std::mutex> lk(mu_);
        period_ = period;
        fired_ = false;
        next_fire_ = std::chrono::steady_clock::now() + period_;
    }
    cv_.notify_all();
    wake_loop_();
}

std::chrono::steady_clock::time_point TimerEvent::next_fire() const {
    std::lock_guard<std::mutex> lk(mu_);
    return next_fire_;
}

bool TimerEvent::ready() const {
    std::lock_guard<std::mutex> lk(mu_);
    if (fired_) return true;
    return std::chrono::steady_clock::now() >= next_fire_;
}

bool TimerEvent::wait_until(std::chrono::steady_clock::time_point deadline) {
    std::unique_lock<std::mutex> lk(mu_);
    // 先检查是否已触发
    if (fired_) return true;
    // 取 deadline 和 next_fire_ 的较早者
    auto wait_until_tp = (std::min)(next_fire_, deadline);
    cv_.wait_until(lk, wait_until_tp);
    // 检查是否因 timer 到期而醒来
    if (std::chrono::steady_clock::now() >= next_fire_) {
        fired_ = true;
        // 唤醒 EventLoop
        // 注意：此处持锁调用 wake_loop_ 会有锁顺序问题（wake_loop_ 调 loop_->wake()
        //   获取 EventLoop::mu_）。先释放本锁再 wake。
        lk.unlock();
        wake_loop_();
        return true;
    }
    return fired_;
}

void TimerEvent::clear_ready() {
    reset();
}

}  // namespace linoh::event
