// linoh_event_source.hpp — linoh 网络事件源（v4.3.0 M7）
//
// 包装 linoh_endpoint_poll，支持两种驱动模式：
//
//   Mode::ExternalDriven（默认，win-worker 单线程推荐）：
//     - 调用方在 select 返回后手动调用 drive() 处理 linoh 事件
//     - ready() 返回上次 drive 是否有事件
//     - 不创建额外线程
//
//   Mode::SelfDriven（node-agent 多线程推荐）：
//     - start() 启动内部线程，周期性调用 linoh_endpoint_poll
//     - 有事件时置 ready + wake_loop_，主循环 select 被唤醒
//     - stop() 停止内部线程
//
// 典型用法（ExternalDriven）：
//   LinohEventSource net(ep, Mode::ExternalDriven);
//   loop.register_source(&net, 1);
//   while (running) {
//       auto ready = loop.select(1s);
//       for (auto idx : ready) {
//           if (idx == net_idx) { net.drive(); net.clear_ready(); }
//       }
//   }
//
// 典型用法（SelfDriven）：
//   LinohEventSource net(ep, Mode::SelfDriven);
//   net.start();
//   loop.register_source(&net, 1);
//   while (running) {
//       auto ready = loop.select(1s);
//       for (auto idx : ready) {
//           if (idx == net_idx) { /* linoh 事件已由内部线程 drive 处理 */ net.clear_ready(); }
//       }
//   }
#pragma once

#include "linoh/event/event_source.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

// 前向声明 C-API 类型（避免 header 引入 linoh_c.h）
struct linoh_endpoint;
typedef struct linoh_endpoint linoh_endpoint_t;

namespace linoh::event {

class LinohEventSource : public EventSource {
public:
    enum class Mode : std::uint8_t {
        ExternalDriven = 0,  // 外部驱动：调用方手动 drive()
        SelfDriven     = 1,  // 自驱动：内部线程自动 drive()
    };

    /// @param ep linoh endpoint（不为 nullptr）
    /// @param mode 驱动模式
    explicit LinohEventSource(linoh_endpoint_t* ep, Mode mode = Mode::ExternalDriven);

    ~LinohEventSource() override;

    LinohEventSource(const LinohEventSource&) = delete;
    LinohEventSource& operator=(const LinohEventSource&) = delete;

    /// 主动调用 linoh_endpoint_poll 处理网络事件
    ///
    /// ExternalDriven 模式：由调用方在 select 返回后调用
    /// SelfDriven 模式：由内部线程自动调用，外部无需调用
    ///
    /// @return linoh_endpoint_poll 返回的事件数（> 0 表示有事件被处理）
    int drive();

    /// 启动内部 poll 线程（仅 SelfDriven 模式有效）
    void start();

    /// 停止内部 poll 线程（仅 SelfDriven 模式有效）
    void stop();

    /// 设置 SelfDriven 模式的 poll 间隔（默认 1ms）
    void set_poll_interval(std::chrono::milliseconds interval);

    /// 是否正在运行内部线程（SelfDriven 模式）
    bool is_running() const noexcept;

    // === EventSource 接口 ===
    bool ready() const override;
    bool wait_until(std::chrono::steady_clock::time_point deadline) override;
    void clear_ready() override;

private:
    void poll_loop_();  // SelfDriven 内部线程入口

    linoh_endpoint_t* ep_;
    Mode mode_;
    std::atomic<bool> stop_flag_{true};
    std::atomic<bool> started_{false};
    std::atomic<bool> has_events_{false};
    std::chrono::milliseconds poll_interval_{std::chrono::milliseconds(1)};
    std::thread poll_thread_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
};

}  // namespace linoh::event
