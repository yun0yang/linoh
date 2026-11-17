// event_loop.hpp — select! 多路复用器（v4.3.0 M7）
//
// C++ 条件变量模拟 Rust tokio::select! 语义：
//   tokio::select! { biased; _ = shutdown => ..., _ = net => ..., ... }
//
// 注册多个 EventSource，select() 阻塞等待任一就绪，返回就绪 source 的索引列表
// （按 priority 升序，biased 语义）。任一 source 变 ready 时通过 wake_loop_()
// 通知 EventLoop 的 condition_variable，避免轮询。
//
// 使用示例：
//   EventLoop loop;
//   auto sid = loop.register_source(make_shutdown(), 0);  // priority=0 最高
//   while (running) {
//       auto ready = loop.select(1s);
//       for (auto idx : ready) { if (idx == sid) running = false; ... }
//   }
#pragma once

#include "linoh/event/event_source.hpp"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace linoh::event {

class EventLoop;

/// EventLoop 多路复用器
class EventLoop {
public:
    EventLoop() = default;
    ~EventLoop();

    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;
    EventLoop(EventLoop&&) = delete;
    EventLoop& operator=(EventLoop&&) = delete;

    /// 注册事件源（转移所有权）
    ///
    /// @param src 事件源（unique_ptr 所有权转移给 EventLoop）
    /// @param priority 优先级（数字越小越优先，biased 语义；同 priority 按注册顺序）
    /// @return source 索引（用于 select 返回值识别），后续可用 source(index) 取回
    std::size_t register_source(std::unique_ptr<EventSource> src, int priority = 0);

    /// 注册事件源（引用，不转移所有权）
    ///
    /// 调用方负责 source 生命周期管理（source 必须在 EventLoop 析构前保持有效）。
    /// 适用于 C-API 和栈上对象。
    /// @param src 事件源引用
    /// @param priority 优先级
    /// @return source 索引
    std::size_t register_source_ref(EventSource& src, int priority = 0);

    /// select! 语义：等待任一 source 就绪
    ///
    /// @param timeout 最大等待时间：
    ///        - timeout > 0：等待至多 timeout，任一 ready 立即返回
    ///        - timeout == 0：非阻塞轮询一次
    ///        - timeout < 0：永久阻塞直到有 ready
    /// @return 就绪 source 的索引列表（按 priority 升序），空=超时且无就绪
    std::vector<std::size_t> select(std::chrono::milliseconds timeout);

    /// 便捷主循环
    ///
    /// 等价于 while(!stop_predicate()) { for(idx: select(timeout)) handler(idx); }
    /// @param stop_predicate 返回 true 时退出循环
    /// @param handler 每个就绪 source 索引的回调
    /// @param timeout 每次 select 的超时（默认 1s）
    void run(const std::function<bool()>& stop_predicate,
             const std::function<void(std::size_t)>& handler,
             std::chrono::milliseconds timeout = std::chrono::seconds(1));

    /// 取回已注册的 source 指针（不转移所有权，供调用方 drain 数据/重置状态）
    EventSource* source(std::size_t index) const;

    /// 注销事件源（从 sources_ 移除并清空 source 的 loop_ 指针）
    ///
    /// 用于 register_source_ref 注册的 source 在销毁前从 EventLoop 注销，
    /// 避免 EventLoop 析构时访问已释放的 source（use-after-free）。
    /// @param src 要注销的事件源引用
    void unregister_source(EventSource& src);

    /// 已注册 source 数量
    std::size_t size() const noexcept;

    /// 唤醒正在 select 中阻塞的 EventLoop（跨线程安全）
    ///
    /// 供外部强制打断 select（如收到 signal 后唤醒主循环）。
    /// 内部 source 变 ready 时会自动调用，无需手动 wake。
    void wake();

private:
    friend class EventSource;

    /// source 变 ready 时调用（由 EventSource::wake_loop_ 触发）
    void on_source_ready_();

    /// 收集所有 ready source 的索引（按 priority 升序），调用时需持有 mu_
    std::vector<std::size_t> collect_ready_locked_();

    struct Entry {
        std::shared_ptr<EventSource> src;  // owned=正常 shared_ptr，ref=空删除器
        int priority;
        std::size_t idx;
    };

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::vector<Entry> sources_;
    std::atomic<bool> woken_{false};  // wake() 标记，避免虚假唤醒
};

}  // namespace linoh::event
