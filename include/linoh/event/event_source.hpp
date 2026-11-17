// event_source.hpp — 事件源抽象基类（v4.3.0 M7 select! 事件驱动）
//
// 设计来源：Psyche client.rs select! 事件循环 + Rust tokio::AsyncReadiness 语义
//
// 痛点：node-agent/win-worker 主循环阻塞式（sleep + poll），linoh 事件 / orchestrator
//       心跳 / 模型加载 / 健康检查混杂在同一线程相互阻塞。模型加载（3 分钟）会
//       阻塞心跳导致节点被误判 INACTIVE。
//
// 方案：linoh 提供 EventSource 抽象 + EventLoop 多路复用器，调用方可阻塞等待
//       任一事件源就绪（select! 语义），就绪后处理再继续等待。
//
// C++ 无 Rust async，用条件变量 + 线程安全队列模拟 channel：
//   - ready() 非阻塞查询是否有待处理事件
//   - wait_until(tp) 阻塞等待直到 ready 或到达 deadline
//   - clear_ready() 处理完后重置就绪状态
//
// 事件源自身不持有业务数据，仅表示"有事件待处理"的信号；具体数据由 source
// 内部队列承载，ready() 后调用方 drain。
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>

namespace linoh::event {

class EventLoop;  // 前向声明

/// 事件源抽象基类
///
/// 所有内置事件源（ShutdownEvent / LinohEventSource / TimerEvent / TaskQueue）
/// 均实现此接口，注册到 EventLoop 后由 select() 统一多路复用等待。
class EventSource {
public:
    virtual ~EventSource() = default;

    /// 是否有待处理事件（非阻塞）
    virtual bool ready() const = 0;

    /// 阻塞等待直到 ready 或到达 deadline
    /// @return true=已 ready，false=到达 deadline 仍未 ready
    virtual bool wait_until(std::chrono::steady_clock::time_point deadline) = 0;

    /// 重置就绪状态（EventLoop 处理完后调用）
    virtual void clear_ready() = 0;

    /// 下一次可能就绪的时间点（用于 EventLoop::select 计算等待上限）
    ///
    /// 默认返回 time_point::max() 表示"无定时约束"（如 ShutdownEvent/TaskQueue
    /// 这类被外部唤醒的 source）。TimerEvent 覆盖此方法返回 next_fire_。
    /// EventLoop::select 会取所有 source 的最早 next_fire 与外部 timeout 比较，
    /// 取较小者作为实际等待上限，避免 TimerEvent 定时精度被外部 timeout 拖累。
    virtual std::chrono::steady_clock::time_point next_fire() const {
        return std::chrono::steady_clock::time_point::max();
    }

    /// 获取已注册的 EventLoop 指针（未注册返回 nullptr）
    /// 用于 source 销毁前从 EventLoop 注销，避免 use-after-free
    EventLoop* registered_loop() const noexcept {
        return loop_.load(std::memory_order_acquire);
    }

protected:
    /// 子类在状态变 ready 时调用，唤醒正在 select 中阻塞的 EventLoop
    /// 线程安全：loop_ 是 atomic 指针，wake() 内部 cv_.notify_one() 线程安全
    void wake_loop_();

private:
    friend class EventLoop;
    /// EventLoop 注册时设置（atomic 保证跨线程读写安全）
    std::atomic<EventLoop*> loop_{nullptr};
};

}  // namespace linoh::event
