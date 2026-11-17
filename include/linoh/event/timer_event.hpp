// timer_event.hpp — 定时触发事件源（v4.3.0 M7）
//
// 周期性触发，用于 heartbeat（5s）/ health_check（30s）等定时任务。
// 触发后 ready() 返回 true，处理完调用 reset() 重置下一周期起点。
//
// 典型用法：
//   auto timer = make_timer(5s);
//   loop.register_source(std::move(timer), 2);
//   // select 返回后：
//   //   send_heartbeat();
//   //   timer->reset();  // 重置 5s 倒计时
#pragma once

#include "linoh/event/event_source.hpp"

#include <chrono>
#include <condition_variable>
#include <mutex>

namespace linoh::event {

/// 周期定时器事件源
class TimerEvent : public EventSource {
public:
    /// @param period 触发周期（必须 > 0）
    explicit TimerEvent(std::chrono::milliseconds period);

    ~TimerEvent() override = default;

    /// 重置周期起点（处理完事件后调用，开始下一轮倒计时）
    /// 也可用于手动重置（如 heartbeat 提前发完后重置）
    void reset();

    /// 修改周期（立即生效，重置起点）
    void set_period(std::chrono::milliseconds period);

    /// 下一次触发时间点（EventLoop::select 据此计算等待上限）
    std::chrono::steady_clock::time_point next_fire() const override;

    // === EventSource 接口 ===
    bool ready() const override;
    bool wait_until(std::chrono::steady_clock::time_point deadline) override;
    void clear_ready() override;  // 等价 reset()

private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::chrono::milliseconds period_;
    std::chrono::steady_clock::time_point next_fire_;
    bool fired_{false};  // 已触发未处理标记
};

}  // namespace linoh::event
