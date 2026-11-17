// concurrent_forwarder.hpp — v3.9.3 FuturesUnordered 并发转发
//
// 多 worker 并发转发：每个转发任务独立执行，慢节点不阻塞其他节点。
// 结果按完成顺序收集（非提交顺序），可配置最大并发数防线程爆炸。
//
// 设计要点：
//   - std::async(std::launch::async) 并发执行转发
//   - ConcurrencyGuard（mutex + condition_variable）控制最大并发数
//   - 共享 results vector（mutex 保护）按完成顺序收集
//   - send_fn 异常 try-catch 兜底，不崩溃
//   - 不可拷贝/移动（内部状态绑定 this），建议用 unique_ptr 传递所有权

#ifndef LINOH_MULTIMODAL_CONCURRENT_FORWARDER_HPP
#define LINOH_MULTIMODAL_CONCURRENT_FORWARDER_HPP

#include <linoh/base/key.hpp>  // EndpointId = PublicKey

#include <cstdint>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace linoh::multimodal {

/// ConcurrentForwarder — 多 worker 并发转发器
///
/// 将多个转发任务并发执行，慢节点不阻塞其他节点。
/// 结果按完成顺序收集（非提交顺序），可配置最大并发数。
class ConcurrentForwarder {
public:
    using TargetId = linoh::base::EndpointId;

    /// 转发任务：目标节点 + 待发数据
    struct ForwardTask {
        TargetId target{};
        std::vector<std::uint8_t> data;
    };

    /// 转发结果：目标节点 + 成功标志 + 错误信息
    struct ForwardResult {
        TargetId target{};
        bool success{false};
        std::string error;
    };

    /// 发送函数签名：返回 true 表示成功，false 或抛异常表示失败
    using SendFn = std::function<bool(const TargetId&, std::span<const std::uint8_t>)>;

    /// 构造函数
    /// @param max_concurrency 最大并发数（默认 8，范围 [1, 1024]）
    explicit ConcurrentForwarder(std::uint32_t max_concurrency = 8);

    ~ConcurrentForwarder();

    // 不可拷贝（内部状态绑定 this）
    ConcurrentForwarder(const ConcurrentForwarder&) = delete;
    ConcurrentForwarder& operator=(const ConcurrentForwarder&) = delete;

    // 不可移动（async 任务可能引用 this）
    ConcurrentForwarder(ConcurrentForwarder&&) = delete;
    ConcurrentForwarder& operator=(ConcurrentForwarder&&) = delete;

    /// 并发转发所有任务
    /// @param tasks 转发任务列表（按提交顺序）
    /// @param send_fn 发送函数（并发调用）
    /// @return 转发结果列表（按完成顺序，非提交顺序）
    ///
    /// 注意：此函数会阻塞直到所有任务完成。如果需要异步，请在独立线程调用。
    std::vector<ForwardResult> forward_all(std::vector<ForwardTask> tasks,
                                           SendFn send_fn);

    /// 并发转发单个任务（便捷接口）
    ForwardResult forward_one(ForwardTask task, SendFn send_fn);

    // ===== 配置 =====

    std::uint32_t max_concurrency() const noexcept { return max_concurrency_; }

    /// 设置最大并发数（影响下一次 forward_all 调用）
    void set_max_concurrency(std::uint32_t n) noexcept;

    // ===== 统计 =====

    /// 上一次 forward_all 的统计信息
    struct Stats {
        std::uint64_t total_tasks{0};       // 总任务数
        std::uint64_t success_count{0};     // 成功数
        std::uint64_t failure_count{0};     // 失败数
        std::uint64_t max_concurrent{0};    // 峰值并发数
        std::uint64_t total_duration_ms{0}; // 总耗时（ms）
    };

    const Stats& last_stats() const noexcept { return last_stats_; }

private:
    /// 并发数控制器（mutex + condition_variable 实现）
    struct ConcurrencyGuard {
        std::mutex mutex;
        std::condition_variable cv;
        std::uint32_t active{0};
        std::uint32_t max{8};
        std::uint32_t peak{0};  // 峰值并发数

        void acquire();
        void release();
    };

    std::uint32_t max_concurrency_;
    mutable ConcurrencyGuard guard_;
    Stats last_stats_;
};

}  // namespace linoh::multimodal

#endif  // LINOH_MULTIMODAL_CONCURRENT_FORWARDER_HPP
