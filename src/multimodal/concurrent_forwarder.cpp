// concurrent_forwarder.cpp — v3.9.3 FuturesUnordered 并发转发实现
//
// 实现 ConcurrentForwarder 的核心逻辑：
//   - std::async(std::launch::async) 并发执行转发
//   - ConcurrencyGuard 控制最大并发数
//   - 共享 results vector 按完成顺序收集
//   - send_fn 异常 try-catch 兜底

#include "linoh/multimodal/concurrent_forwarder.hpp"

#include <algorithm>
#include <chrono>
#include <future>
#include <stdexcept>
#include <utility>

namespace linoh::multimodal {

// ===== ConcurrencyGuard =====

void ConcurrentForwarder::ConcurrencyGuard::acquire() {
    std::unique_lock<std::mutex> lk(mutex);
    cv.wait(lk, [this] { return active < max; });
    ++active;
    if (active > peak) peak = active;
}

void ConcurrentForwarder::ConcurrencyGuard::release() {
    {
        std::lock_guard<std::mutex> lk(mutex);
        --active;
    }
    cv.notify_one();
}

// ===== ConcurrentForwarder =====

ConcurrentForwarder::ConcurrentForwarder(std::uint32_t max_concurrency)
    : max_concurrency_(max_concurrency == 0 ? 1 : max_concurrency) {
    guard_.max = max_concurrency_;
}

ConcurrentForwarder::~ConcurrentForwarder() = default;

void ConcurrentForwarder::set_max_concurrency(std::uint32_t n) noexcept {
    if (n == 0) n = 1;
    max_concurrency_ = n;
    // 注意：guard_.max 在 forward_all 开始时同步，避免并发修改竞争
}

std::vector<ConcurrentForwarder::ForwardResult>
ConcurrentForwarder::forward_all(std::vector<ForwardTask> tasks, SendFn send_fn) {
    // 重置统计
    last_stats_ = Stats{};
    last_stats_.total_tasks = tasks.size();

    if (tasks.empty()) {
        return {};
    }

    // 同步并发上限到 guard
    guard_.max = max_concurrency_;
    guard_.active = 0;
    guard_.peak = 0;

    auto start_time = std::chrono::steady_clock::now();

    // 共享结果收集（按完成顺序）
    std::mutex results_mutex;
    std::vector<ForwardResult> results;
    results.reserve(tasks.size());

    // 启动所有异步任务
    std::vector<std::future<void>> futures;
    futures.reserve(tasks.size());

    for (auto& task : tasks) {
        // 捕获 task 的副本（task.target 可拷贝，task.data 移动）
        ForwardTask task_copy;
        task_copy.target = task.target;
        task_copy.data = std::move(task.data);

        futures.push_back(std::async(
            std::launch::async,
            [&results_mutex, &results, &send_fn, &guard = guard_,
             task = std::move(task_copy)]() mutable {
                // 获取并发许可（阻塞直到有空位）
                guard.acquire();

                ForwardResult result;
                result.target = task.target;

                try {
                    if (send_fn) {
                        result.success = send_fn(task.target, task.data);
                        if (!result.success) {
                            result.error = "send_fn returned false";
                        }
                    } else {
                        result.success = false;
                        result.error = "send_fn is null";
                    }
                } catch (const std::exception& e) {
                    result.success = false;
                    result.error = e.what();
                } catch (...) {
                    result.success = false;
                    result.error = "unknown exception";
                }

                // 释放并发许可
                guard.release();

                // 按完成顺序收集结果
                {
                    std::lock_guard<std::mutex> lk(results_mutex);
                    results.push_back(std::move(result));
                }
            }));
    }

    // 等待所有任务完成（按完成顺序 join，但不影响结果顺序）
    for (auto& f : futures) {
        if (f.valid()) {
            f.wait();
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    last_stats_.total_duration_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time)
            .count());
    last_stats_.max_concurrent = guard_.peak;

    // 统计成功/失败
    for (const auto& r : results) {
        if (r.success) {
            ++last_stats_.success_count;
        } else {
            ++last_stats_.failure_count;
        }
    }

    return results;
}

ConcurrentForwarder::ForwardResult
ConcurrentForwarder::forward_one(ForwardTask task, SendFn send_fn) {
    std::vector<ForwardTask> tasks;
    tasks.push_back(std::move(task));
    auto results = forward_all(std::move(tasks), std::move(send_fn));
    if (results.empty()) {
        ForwardResult r;
        r.success = false;
        r.error = "no result returned";
        return r;
    }
    return std::move(results[0]);
}

}  // namespace linoh::multimodal
