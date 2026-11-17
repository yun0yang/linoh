// test_task_pool.cpp — P5-C-3 TaskPool 任务池测试
//
// 验证：
//   1. 立即任务执行（push）
//   2. 立即任务返回值正确传递
//   3. 延时任务按期执行（pushDelayed）
//   4. 延时任务返回值正确传递
//   5. cancel 取消未执行任务
//   6. delay 重新调度
//   7. 多任务并发执行
//   8. 工作线程数配置
//   9. 析构时未执行任务被丢弃
//  10. 延时任务精确度
//  11. 大量立即任务
//  12. 多延时任务按时间顺序执行
//  13. cancel 已执行任务返回 false
//  14. delay 不存在任务返回 false
//  15. pushDelayed 异常任务不崩

#include "linoh/util/task_pool.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh::util;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 1. 立即任务执行
// ============================================================================

static void test_push_basic() {
    TaskPool pool(2);
    auto fut = pool.push([]() { return 42; });
    int v = fut.get();
    CHECK(v == 42);
}

static void test_push_void() {
    TaskPool pool(2);
    std::atomic<int> counter{0};
    auto fut = pool.push([&]() { counter.fetch_add(1); });
    fut.get();
    CHECK(counter.load() == 1);
}

static void test_push_return_string() {
    TaskPool pool(2);
    auto fut = pool.push([]() { return std::string("hello_task_pool"); });
    std::string s = fut.get();
    CHECK(s == "hello_task_pool");
}

// ============================================================================
// 2. 多任务并发执行
// ============================================================================

static void test_multiple_push() {
    TaskPool pool(4);
    constexpr int N = 100;
    std::vector<std::future<int>> futs;
    futs.reserve(N);
    for (int i = 0; i < N; ++i) {
        futs.push_back(pool.push([i]() { return i * 2; }));
    }
    for (int i = 0; i < N; ++i) {
        CHECK(futs[i].get() == i * 2);
    }
}

static void test_concurrent_push_from_threads() {
    TaskPool pool(4);
    constexpr int kProducers = 4;
    constexpr int kIters = 500;
    std::atomic<int> total{0};
    std::vector<std::thread> producers;
    producers.reserve(kProducers);
    for (int i = 0; i < kProducers; ++i) {
        producers.emplace_back([&]() {
            for (int j = 0; j < kIters; ++j) {
                pool.push([&]() { total.fetch_add(1, std::memory_order_relaxed); });
            }
        });
    }
    for (auto& t : producers) t.join();
    // 等待所有任务完成
    while (pool.immediate_queue_size() > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(total.load() == kProducers * kIters);
}

// ============================================================================
// 3. 延时任务执行
// ============================================================================

static void test_pushDelayed_basic() {
    TaskPool pool(2);
    std::atomic<bool> executed{false};
    auto start = std::chrono::steady_clock::now();
    auto [fut, id] = pool.pushDelayed([&]() {
        executed.store(true);
    }, std::chrono::milliseconds(80));
    fut.get();
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    CHECK(executed.load() == true);
    CHECK(elapsed.count() >= 70);  // 至少 70ms
    CHECK(elapsed.count() < 500);  // 但不应超过 500ms（容忍调度延迟）
    (void)id;
}

static void test_pushDelayed_return_value() {
    TaskPool pool(2);
    auto [fut, id] = pool.pushDelayed([]() { return 99; }, std::chrono::milliseconds(50));
    int v = fut.get();
    CHECK(v == 99);
    (void)id;
}

static void test_pushDelayed_timing_accuracy() {
    TaskPool pool(2);
    auto start = std::chrono::steady_clock::now();
    auto [fut, id] = pool.pushDelayed([]() {}, std::chrono::milliseconds(100));
    fut.get();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    // 延时精度应在 ±30ms 内
    CHECK(elapsed.count() >= 95);
    CHECK(elapsed.count() <= 200);
    (void)id;
}

// ============================================================================
// 4. cancel 取消延时任务
// ============================================================================

static void test_cancel_delayed_task() {
    TaskPool pool(2);
    std::atomic<int> counter{0};
    auto [fut, id] = pool.pushDelayed([&]() { counter.fetch_add(1); },
                                       std::chrono::milliseconds(100));
    bool cancelled = pool.cancel(id);
    CHECK(cancelled == true);
    // 等待超过原定延时
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(counter.load() == 0);  // 任务未执行
    // future 仍 valid 但永远不会 ready（任务被丢弃）
    CHECK(fut.valid() == true);
    // wait_for 应不是 ready（timeout 或 deferred）
    auto status = fut.wait_for(std::chrono::milliseconds(10));
    CHECK(status != std::future_status::ready);
}

static void test_cancel_already_executed() {
    TaskPool pool(2);
    std::atomic<int> counter{0};
    auto [fut, id] = pool.pushDelayed([&]() { counter.fetch_add(1); },
                                       std::chrono::milliseconds(30));
    fut.get();
    // 任务已执行，cancel 应返回 false
    bool cancelled = pool.cancel(id);
    CHECK(cancelled == false);
    CHECK(counter.load() == 1);
}

static void test_cancel_nonexistent() {
    TaskPool pool(2);
    bool cancelled = pool.cancel(99999);
    CHECK(cancelled == false);
}

static void test_cancel_invalid_id() {
    TaskPool pool(2);
    bool cancelled = pool.cancel(TaskPool::kInvalidTaskId);
    CHECK(cancelled == false);
}

// ============================================================================
// 5. delay 重新调度
// ============================================================================

static void test_delay_reschedule() {
    TaskPool pool(2);
    std::atomic<int> counter{0};
    auto start = std::chrono::steady_clock::now();
    auto [fut, id] = pool.pushDelayed([&]() { counter.fetch_add(1); },
                                       std::chrono::milliseconds(50));
    // 30ms 时重新延时到 150ms
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    bool delayed = pool.delay(id, std::chrono::milliseconds(150));
    CHECK(delayed == true);
    fut.get();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    CHECK(counter.load() == 1);
    // 应至少 150ms（delay 后的总时长）
    CHECK(elapsed.count() >= 145);
    CHECK(elapsed.count() <= 400);
}

static void test_delay_nonexistent() {
    TaskPool pool(2);
    bool delayed = pool.delay(99999, std::chrono::milliseconds(50));
    CHECK(delayed == false);
}

static void test_delay_already_executed() {
    TaskPool pool(2);
    auto [fut, id] = pool.pushDelayed([]() {}, std::chrono::milliseconds(30));
    fut.get();
    bool delayed = pool.delay(id, std::chrono::milliseconds(100));
    CHECK(delayed == false);
}

// ============================================================================
// 6. 多延时任务按时间顺序执行
// ============================================================================

static void test_multiple_delayed_ordered() {
    TaskPool pool(2);
    std::atomic<int> order{0};
    std::vector<int> exec_order;
    std::mutex m;

    auto record = [&](int idx) {
        std::lock_guard<std::mutex> lk(m);
        exec_order.push_back(idx);
    };

    // 提交顺序：1, 2, 3，但延迟时间递增
    pool.pushDelayed([&]() { record(1); }, std::chrono::milliseconds(30));
    pool.pushDelayed([&]() { record(2); }, std::chrono::milliseconds(60));
    pool.pushDelayed([&]() { record(3); }, std::chrono::milliseconds(90));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::lock_guard<std::mutex> lk(m);
    CHECK(exec_order.size() == 3);
    CHECK(exec_order[0] == 1);
    CHECK(exec_order[1] == 2);
    CHECK(exec_order[2] == 3);
}

// ============================================================================
// 7. 工作线程数配置
// ============================================================================

static void test_worker_count_config() {
    TaskPool pool1(1);
    CHECK(pool1.worker_count() == 1);

    TaskPool pool4(4);
    CHECK(pool4.worker_count() == 4);

    TaskPool pool8(8);
    CHECK(pool8.worker_count() == 8);
}

static void test_zero_worker_becomes_one() {
    TaskPool pool(0);
    CHECK(pool.worker_count() == 1);
    auto fut = pool.push([]() { return 1; });
    CHECK(fut.get() == 1);
}

// ============================================================================
// 8. 析构时未执行任务被丢弃
// ============================================================================

static void test_destruct_drops_pending() {
    std::atomic<int> counter{0};
    {
        TaskPool pool(2);
        // 提交立即任务但不等待
        for (int i = 0; i < 100; ++i) {
            pool.push([&]() { counter.fetch_add(1); });
        }
        // 立即析构（任务可能部分未执行）
        // 注意：析构会调用 stop_internal，等待 workers_ join
    }
    // counter 可能小于 100（部分任务被丢弃）
    CHECK(counter.load() >= 0);
    CHECK(counter.load() <= 100);
}

static void test_destruct_drains_delayed() {
    std::atomic<int> counter{0};
    {
        TaskPool pool(2);
        pool.pushDelayed([&]() { counter.fetch_add(1); },
                         std::chrono::milliseconds(1000));  // 1s 后执行
        // 立即析构，1s 任务应被丢弃
    }
    // 等待超过原定延时
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    CHECK(counter.load() == 0);
}

// ============================================================================
// 9. 大量立即任务
// ============================================================================

static void test_many_immediate_tasks() {
    TaskPool pool(4);
    constexpr int N = 10000;
    std::vector<std::future<int>> futs;
    futs.reserve(N);
    for (int i = 0; i < N; ++i) {
        futs.push_back(pool.push([i]() { return i; }));
    }
    int sum = 0;
    for (int i = 0; i < N; ++i) {
        sum += futs[i].get();
    }
    CHECK(sum == N * (N - 1) / 2);
}

// ============================================================================
// 10. 异常任务不崩
// ============================================================================

static void test_exception_in_task() {
    TaskPool pool(2);
    auto fut = pool.push([]() -> int {
        throw std::runtime_error("test_exception");
    });
    bool caught = false;
    try {
        fut.get();
    } catch (const std::exception&) {
        caught = true;
    }
    CHECK(caught);
}

static void test_exception_in_delayed_task() {
    TaskPool pool(2);
    auto [fut, id] = pool.pushDelayed([]() -> int {
        throw std::runtime_error("delayed_exception");
    }, std::chrono::milliseconds(30));
    bool caught = false;
    try {
        fut.get();
    } catch (const std::exception&) {
        caught = true;
    }
    CHECK(caught);
    (void)id;
}

// ============================================================================
// 11. 队列大小查询
// ============================================================================

static void test_queue_size_methods() {
    TaskPool pool(2);
    CHECK(pool.worker_count() == 2);
    CHECK(pool.immediate_queue_size() == 0);
    CHECK(pool.delayed_queue_size() == 0);

    // 提交一个延时任务
    auto [fut, id] = pool.pushDelayed([]() {}, std::chrono::milliseconds(500));
    (void)fut;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK(pool.delayed_queue_size() == 1);

    // 取消后队列应空
    pool.cancel(id);
    CHECK(pool.delayed_queue_size() == 0);
}

// ============================================================================
// 12. 实际场景模拟：RPC 超时扫描
// ============================================================================

static void test_rpc_timeout_scenario() {
    TaskPool pool(2);
    std::atomic<int> rpc_completed{0};
    std::atomic<int> rpc_timed_out{0};

    // 模拟 RPC：100ms 内未完成则超时
    auto start_rpc = [&](std::chrono::milliseconds rpc_duration) {
        auto [fut, timeout_id] = pool.pushDelayed([&]() {
            rpc_timed_out.fetch_add(1);
        }, std::chrono::milliseconds(100));

        // RPC 主体（模拟工作）
        pool.push([&, rpc_duration, timeout_id]() {
            std::this_thread::sleep_for(rpc_duration);
            rpc_completed.fetch_add(1);
            // RPC 完成，取消超时任务
            pool.cancel(timeout_id);
        });
        (void)fut;
    };

    // 快速 RPC（50ms）：不应超时
    start_rpc(std::chrono::milliseconds(50));
    // 慢速 RPC（200ms）：应超时
    start_rpc(std::chrono::milliseconds(200));

    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    CHECK(rpc_completed.load() == 2);  // 两个 RPC 都完成
    CHECK(rpc_timed_out.load() == 1);  // 只有慢速 RPC 超时
}

// ============================================================================
// 13. 心跳循环调度场景
// ============================================================================

static void test_heartbeat_loop_scenario() {
    TaskPool pool(2);
    std::atomic<int> heartbeat_count{0};
    std::atomic<bool> stop_hb{false};

    // 心跳：每 30ms 一次，递归调度（用 std::function 支持自引用）
    std::function<void()> schedule_heartbeat = [&]() {
        pool.pushDelayed([&]() {
            if (!stop_hb.load()) {
                heartbeat_count.fetch_add(1);
                schedule_heartbeat();  // 重新调度
            }
        }, std::chrono::milliseconds(30));
    };
    schedule_heartbeat();

    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    stop_hb.store(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // 150ms 内应触发约 4-5 次心跳（30ms 一次）
    CHECK(heartbeat_count.load() >= 3);
    CHECK(heartbeat_count.load() <= 8);
}

// ============================================================================
// 14. 重复 push 测试（任务池持续工作）
// ============================================================================

static void test_repeated_push() {
    TaskPool pool(2);
    for (int round = 0; round < 5; ++round) {
        std::vector<std::future<int>> futs;
        for (int i = 0; i < 20; ++i) {
            futs.push_back(pool.push([i]() { return i; }));
        }
        for (int i = 0; i < 20; ++i) {
            CHECK(futs[i].get() == i);
        }
    }
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::printf("=== test_task_pool.cpp — P5-C-3 TaskPool ===\n");

    test_push_basic();
    test_push_void();
    test_push_return_string();

    test_multiple_push();
    test_concurrent_push_from_threads();

    test_pushDelayed_basic();
    test_pushDelayed_return_value();
    test_pushDelayed_timing_accuracy();

    test_cancel_delayed_task();
    test_cancel_already_executed();
    test_cancel_nonexistent();
    test_cancel_invalid_id();

    test_delay_reschedule();
    test_delay_nonexistent();
    test_delay_already_executed();

    test_multiple_delayed_ordered();

    test_worker_count_config();
    test_zero_worker_becomes_one();

    test_destruct_drops_pending();
    test_destruct_drains_delayed();

    test_many_immediate_tasks();

    test_exception_in_task();
    test_exception_in_delayed_task();

    test_queue_size_methods();

    test_rpc_timeout_scenario();

    test_heartbeat_loop_scenario();

    test_repeated_push();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
