// event_loop.cpp — EventLoop select! 多路复用器实现（v4.3.0 M7）
#include "linoh/event/event_loop.hpp"

#include <algorithm>

namespace linoh::event {

// === EventSource::wake_loop_ ===
// 子类变 ready 时调用，唤醒正在 select 中阻塞的 EventLoop
void EventSource::wake_loop_() {
    EventLoop* loop = loop_.load(std::memory_order_acquire);
    if (loop != nullptr) {
        loop->wake();
    }
}

// === EventLoop ===
EventLoop::~EventLoop() {
    // 解绑所有 source 的 loop_ 指针，避免 source 析构晚于 EventLoop 时悬空
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& entry : sources_) {
        if (entry.src) {
            entry.src->loop_.store(nullptr, std::memory_order_release);
        }
    }
}

std::size_t EventLoop::register_source(std::unique_ptr<EventSource> src, int priority) {
    if (!src) return static_cast<std::size_t>(-1);
    // 转移所有权：unique_ptr → shared_ptr（EventLoop 持有，析构时 delete）
    auto sp = std::shared_ptr<EventSource>(std::move(src));
    std::lock_guard<std::mutex> lk(mu_);
    std::size_t idx = sources_.size();
    // 设置 source 的 loop_ 指针，使其 wake_loop_ 能回调 EventLoop
    sp->loop_.store(this, std::memory_order_release);
    sources_.push_back(Entry{std::move(sp), priority, idx});
    return idx;
}

std::size_t EventLoop::register_source_ref(EventSource& src, int priority) {
    // 不转移所有权：空删除器 shared_ptr（EventLoop 析构时不 delete）
    auto sp = std::shared_ptr<EventSource>(&src, [](EventSource*) { /* no-op */ });
    std::lock_guard<std::mutex> lk(mu_);
    std::size_t idx = sources_.size();
    sp->loop_.store(this, std::memory_order_release);
    sources_.push_back(Entry{std::move(sp), priority, idx});
    return idx;
}

std::vector<std::size_t> EventLoop::select(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(mu_);

    // 1. 先非阻塞检查是否已有就绪（避免无谓等待）
    std::vector<std::size_t> ready = collect_ready_locked_();
    if (!ready.empty()) {
        return ready;
    }
    // timeout == 0：非阻塞轮询一次，直接返回
    if (timeout.count() == 0) {
        return {};
    }

    // 2. 计算实际等待 deadline：
    //    - 外部 timeout 给出 outer_deadline = now + timeout
    //    - 各 source 的 next_fire() 给出内部定时约束（如 TimerEvent）
    //    取两者较小者作为 cv_.wait_until 的 deadline，避免 TimerEvent 等
    //    定时源精度被外部 timeout 拖累（v4.3.0 M7 fix: 200ms 定时器不再
    //    因 timeout=1000ms 而等待完整 1s）
    auto now = std::chrono::steady_clock::now();
    auto outer_deadline = (timeout.count() < 0)
        ? std::chrono::steady_clock::time_point::max()
        : now + timeout;
    std::chrono::steady_clock::time_point earliest = outer_deadline;
    for (const auto& e : sources_) {
        if (!e.src) continue;
        // next_fire() 是 source 内部查询（获取 source 自己的 mu_），不回调
        // EventLoop，无死锁风险（锁顺序：EventLoop::mu_ → source::mu_）
        auto nf = e.src->next_fire();
        if (nf < earliest) earliest = nf;
    }

    // 3. 在 cv_ 上等待到 earliest deadline，任一 source wake_loop_ → wake() → notify 唤醒
    woken_.store(false, std::memory_order_release);
    if (earliest == std::chrono::steady_clock::time_point::max()) {
        // 永久阻塞直到有 source ready
        cv_.wait(lk, [this] {
            return woken_.load(std::memory_order_acquire);
        });
    } else {
        cv_.wait_until(lk, earliest, [this] {
            return woken_.load(std::memory_order_acquire);
        });
    }
    woken_.store(false, std::memory_order_release);

    // 4. 被 notify 或 deadline 到达后重新检查所有 source
    return collect_ready_locked_();
}

void EventLoop::run(const std::function<bool()>& stop_predicate,
                    const std::function<void(std::size_t)>& handler,
                    std::chrono::milliseconds timeout) {
    while (!stop_predicate()) {
        std::vector<std::size_t> ready = select(timeout);
        for (std::size_t idx : ready) {
            handler(idx);
        }
    }
}

EventSource* EventLoop::source(std::size_t index) const {
    std::lock_guard<std::mutex> lk(mu_);
    if (index >= sources_.size()) return nullptr;
    return sources_[index].src.get();
}

void EventLoop::unregister_source(EventSource& src) {
    // 先清空 source 的 loop_ 指针（防止 wake_loop_ 回调悬空），
    // 再从 sources_ 移除对应的空删除器 shared_ptr entry。
    // owned 注册的 source（unique_ptr 转移所有权）不应通过此方法注销，
    // 因为 EventLoop 才是其所有者；调用方应直接销毁 EventLoop。
    std::lock_guard<std::mutex> lk(mu_);
    // 1. 清空待注销 source 的 loop_ 指针（必须持锁，避免与 wake_loop_ 竞争）
    src.loop_.store(nullptr, std::memory_order_release);
    // 2. 从 sources_ 中移除指向 &src 的 entry（register_source_ref 注册的空删除器 entry）
    //    owned entry 的 shared_ptr.get() 也可能等于 &src，但移除后 EventLoop 不再持有
    //    该 unique_ptr，调用方需自行管理（不应使用此方法注销 owned source）
    for (auto it = sources_.begin(); it != sources_.end(); ++it) {
        if (it->src.get() == &src) {
            sources_.erase(it);
            break;  // 只移除第一个匹配项（register_source_ref 同一 source 多次注册属调用方契约违规）
        }
    }
}

std::size_t EventLoop::size() const noexcept {
    return sources_.size();
}

void EventLoop::wake() {
    // 跨线程安全：atomic store + cv notify
    woken_.store(true, std::memory_order_release);
    cv_.notify_one();
}

void EventLoop::on_source_ready_() {
    // 保留接口供未来扩展（当前 source 直接通过 wake_loop_ → wake）
    wake();
}

std::vector<std::size_t> EventLoop::collect_ready_locked_() {
    // 按 priority 升序构建检查顺序（biased 语义：高优先级先返回）
    // stable 排序保证同 priority 按注册顺序
    std::vector<std::size_t> order;
    order.reserve(sources_.size());
    for (const auto& e : sources_) {
        order.push_back(e.idx);
    }
    std::stable_sort(order.begin(), order.end(),
        [this](std::size_t a, std::size_t b) {
            return sources_[a].priority < sources_[b].priority;
        });

    // 收集所有 ready 的 source 索引（按 priority 升序）
    std::vector<std::size_t> result;
    result.reserve(order.size());
    for (std::size_t idx : order) {
        // ready() 是 source 内部查询，不回调 EventLoop，无死锁风险
        if (sources_[idx].src && sources_[idx].src->ready()) {
            result.push_back(idx);
        }
    }
    return result;
}

}  // namespace linoh::event
