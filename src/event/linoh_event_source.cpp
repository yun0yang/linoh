// linoh_event_source.cpp — LinohEventSource 实现（v4.3.0 M7）
#include "linoh/event/linoh_event_source.hpp"

// C-API：调用 linoh_endpoint_poll 驱动网络事件
#include "linoh/linoh_c.h"

#include <thread>

namespace linoh::event {

LinohEventSource::LinohEventSource(linoh_endpoint_t* ep, Mode mode)
    : ep_(ep), mode_(mode) {
}

LinohEventSource::~LinohEventSource() {
    stop();  // 确保 SelfDriven 模式线程安全退出
}

int LinohEventSource::drive() {
    if (!ep_) return 0;
    // 调用 linoh_endpoint_poll 处理 close/send/accept 事件
    // poll 内部会触发 on_close_cb / on_conn_cb 等回调
    int events = linoh_endpoint_poll(ep_);
    if (events > 0) {
        has_events_.store(true, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(mu_);
        }
        cv_.notify_all();
        wake_loop_();  // 唤醒 EventLoop
    }
    return events;
}

void LinohEventSource::start() {
    if (mode_ != Mode::SelfDriven) return;
    if (started_.load(std::memory_order_acquire)) return;  // 已启动
    if (!ep_) return;

    stop_flag_.store(false, std::memory_order_release);
    started_.store(true, std::memory_order_release);
    poll_thread_ = std::thread([this] { poll_loop_(); });
}

void LinohEventSource::stop() {
    if (!started_.load(std::memory_order_acquire)) return;
    stop_flag_.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(mu_);
    }
    cv_.notify_all();  // 唤醒可能阻塞的 poll_loop_
    if (poll_thread_.joinable()) {
        poll_thread_.join();
    }
    started_.store(false, std::memory_order_release);
}

void LinohEventSource::set_poll_interval(std::chrono::milliseconds interval) {
    if (interval.count() <= 0) return;
    poll_interval_ = interval;
}

bool LinohEventSource::is_running() const noexcept {
    return started_.load(std::memory_order_acquire);
}

bool LinohEventSource::ready() const {
    return has_events_.load(std::memory_order_acquire);
}

bool LinohEventSource::wait_until(std::chrono::steady_clock::time_point deadline) {
    if (has_events_.load(std::memory_order_acquire)) return true;
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait_until(lk, deadline);
    return has_events_.load(std::memory_order_acquire);
}

void LinohEventSource::clear_ready() {
    has_events_.store(false, std::memory_order_release);
}

void LinohEventSource::poll_loop_() {
    // SelfDriven 模式内部线程：周期性调用 linoh_endpoint_poll
    while (!stop_flag_.load(std::memory_order_acquire)) {
        drive();
        // 短暂 sleep 避免 CPU 100%（默认 1ms，可配置）
        std::this_thread::sleep_for(poll_interval_);
    }
}

}  // namespace linoh::event
