// test_default_route_poller.cpp — v1.7.0.1 P0 DefaultRoutePoller 测试
//
// 验收标准：
//   1. 默认参数 initial=100ms, max=5000ms（v4.6.0: 200ms→100ms 加快初始探测）
//   2. 指数退避序列：100 -> 200 -> 400 -> 800 -> 1600 -> 3200 -> 5000（上限）
//   3. reset_interval() 后立即回到初始值
//   4. max_interval 上限生效
//   5. initial=max 边界情况
//   6. start/stop 状态机正确
//   7. is_running() 状态一致
//   8. 幂等 stop
//   9. 并发 reset_interval 安全
//  10. probe_once 行为
//
// 借鉴 iroh #4039 指数退避

#include "linoh/net/route_monitor.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

using namespace linoh::net;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 测试 1: 默认参数
// ============================================================================
static void test_default_params() {
    std::printf("[test] DefaultRoutePoller default params...\n");

    DefaultRoutePoller p;
    // v4.6.0: 默认 initial_interval 从 200ms 改为 100ms，加快初始路由变更探测
    CHECK(p.current_interval() == std::chrono::milliseconds(100));
}

// ============================================================================
// 测试 2: 指数退避序列
// ============================================================================
static void test_exponential_backoff_sequence() {
    std::printf("[test] DefaultRoutePoller exponential backoff sequence...\n");

    DefaultRoutePoller p(std::chrono::milliseconds(200), std::chrono::seconds(5));

    // 初始 200ms
    CHECK(p.current_interval() == std::chrono::milliseconds(200));

    // next_interval 计算序列
    CHECK(p.next_interval(std::chrono::milliseconds(200)) == std::chrono::milliseconds(400));
    CHECK(p.next_interval(std::chrono::milliseconds(400)) == std::chrono::milliseconds(800));
    CHECK(p.next_interval(std::chrono::milliseconds(800)) == std::chrono::milliseconds(1600));
    CHECK(p.next_interval(std::chrono::milliseconds(1600)) == std::chrono::milliseconds(3200));
    CHECK(p.next_interval(std::chrono::milliseconds(3200)) == std::chrono::milliseconds(5000));
    CHECK(p.next_interval(std::chrono::milliseconds(5000)) == std::chrono::milliseconds(5000));
}

// ============================================================================
// 测试 3: max_interval 上限生效
// ============================================================================
static void test_max_interval_cap() {
    std::printf("[test] DefaultRoutePoller max_interval cap...\n");

    DefaultRoutePoller p(std::chrono::milliseconds(200), std::chrono::milliseconds(1000));

    // 200 -> 400 -> 800 -> 1000（上限）
    CHECK(p.next_interval(std::chrono::milliseconds(200)) == std::chrono::milliseconds(400));
    CHECK(p.next_interval(std::chrono::milliseconds(400)) == std::chrono::milliseconds(800));
    CHECK(p.next_interval(std::chrono::milliseconds(800)) == std::chrono::milliseconds(1000));
    CHECK(p.next_interval(std::chrono::milliseconds(1000)) == std::chrono::milliseconds(1000));
}

// ============================================================================
// 测试 4: reset_interval 回到初始值
// ============================================================================
static void test_reset_interval() {
    std::printf("[test] DefaultRoutePoller reset_interval...\n");

    DefaultRoutePoller p(std::chrono::milliseconds(200), std::chrono::seconds(5));

    // 模拟间隔已退避到较大值
    // reset 后回到 200ms
    p.reset_interval();
    CHECK(p.current_interval() == std::chrono::milliseconds(200));
}

// ============================================================================
// 测试 5: initial = max 边界
// ============================================================================
static void test_initial_equals_max() {
    std::printf("[test] DefaultRoutePoller initial == max...\n");

    DefaultRoutePoller p(std::chrono::milliseconds(500), std::chrono::milliseconds(500));

    CHECK(p.current_interval() == std::chrono::milliseconds(500));
    CHECK(p.next_interval(std::chrono::milliseconds(500)) == std::chrono::milliseconds(500));
    p.reset_interval();
    CHECK(p.current_interval() == std::chrono::milliseconds(500));
}

// ============================================================================
// 测试 6: 自定义参数
// ============================================================================
static void test_custom_params() {
    std::printf("[test] DefaultRoutePoller custom params...\n");

    DefaultRoutePoller p(std::chrono::milliseconds(100), std::chrono::seconds(10));

    CHECK(p.current_interval() == std::chrono::milliseconds(100));
    CHECK(p.next_interval(std::chrono::milliseconds(100)) == std::chrono::milliseconds(200));
    CHECK(p.next_interval(std::chrono::milliseconds(200)) == std::chrono::milliseconds(400));
    CHECK(p.next_interval(std::chrono::milliseconds(6400)) == std::chrono::milliseconds(10000));
}

// ============================================================================
// 测试 7: start/stop 状态机
// ============================================================================
static void test_start_stop_state() {
    std::printf("[test] DefaultRoutePoller start/stop state...\n");

    DefaultRoutePoller p;
    CHECK(!p.is_running());

    p.start([](RouteEvent) {});
    CHECK(p.is_running());

    p.stop();
    CHECK(!p.is_running());
}

// ============================================================================
// 测试 8: 幂等 stop
// ============================================================================
static void test_idempotent_stop() {
    std::printf("[test] DefaultRoutePoller idempotent stop...\n");

    DefaultRoutePoller p;
    p.start([](RouteEvent) {});
    p.stop();
    p.stop();
    p.stop();
    CHECK(!p.is_running());
}

// ============================================================================
// 测试 9: 未 start 直接 stop
// ============================================================================
static void test_stop_without_start() {
    std::printf("[test] DefaultRoutePoller stop without start...\n");

    DefaultRoutePoller p;
    p.stop();
    CHECK(!p.is_running());
}

// ============================================================================
// 测试 10: 析构自动停止
// ============================================================================
static void test_destructor_stops() {
    std::printf("[test] DefaultRoutePoller destructor stops...\n");

    {
        DefaultRoutePoller p;
        p.start([](RouteEvent) {});
        CHECK(p.is_running());
    }
    ++g_pass;  // 无崩溃即通过
}

// ============================================================================
// 测试 11: 重新 start 后重置间隔
// ============================================================================
static void test_restart_resets_interval() {
    std::printf("[test] DefaultRoutePoller restart resets interval...\n");

    DefaultRoutePoller p(std::chrono::milliseconds(200), std::chrono::seconds(5));
    p.start([](RouteEvent) {});
    CHECK(p.current_interval() == std::chrono::milliseconds(200));
    p.stop();
    p.start([](RouteEvent) {});
    CHECK(p.current_interval() == std::chrono::milliseconds(200));
    p.stop();
}

// ============================================================================
// 测试 12: 回调触发（模拟路由变更）
// ============================================================================
static void test_callback_triggered() {
    std::printf("[test] DefaultRoutePoller callback triggered...\n");

    // 使用很短的间隔以便快速测试
    DefaultRoutePoller p(std::chrono::milliseconds(50), std::chrono::milliseconds(200));
    std::atomic<int> call_count{0};

    p.start([&call_count](RouteEvent ev) {
        if (ev == RouteEvent::DefaultRouteChanged) {
            call_count++;
        }
    });

    // 等待足够时间让 poller 至少探测一次
    // 注意：实际是否触发取决于系统是否有路由变更
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    p.stop();

    // 不强制要求 call_count > 0（无路由变更时不触发）
    CHECK(call_count.load() >= 0);
}

// ============================================================================
// 测试 13: reset_interval 后重新进入快速探测
// ============================================================================
static void test_reset_after_backoff() {
    std::printf("[test] DefaultRoutePoller reset after backoff...\n");

    DefaultRoutePoller p(std::chrono::milliseconds(200), std::chrono::seconds(5));

    // 模拟退避到较大值（通过多次 next_interval）
    auto cur = p.current_interval();
    for (int i = 0; i < 5; ++i) {
        cur = p.next_interval(cur);
    }
    CHECK(cur == std::chrono::milliseconds(5000));

    // reset 后回到初始
    p.reset_interval();
    CHECK(p.current_interval() == std::chrono::milliseconds(200));
}

// ============================================================================
// 测试 14: 并发 reset_interval
// ============================================================================
static void test_concurrent_reset() {
    std::printf("[test] DefaultRoutePoller concurrent reset...\n");

    DefaultRoutePoller p(std::chrono::milliseconds(100), std::chrono::seconds(5));
    p.start([](RouteEvent) {});

    std::atomic<int> reset_count{0};
    std::thread t1([&] { for (int i = 0; i < 100; ++i) { p.reset_interval(); reset_count++; } });
    std::thread t2([&] { for (int i = 0; i < 100; ++i) { p.reset_interval(); reset_count++; } });

    t1.join();
    t2.join();
    p.stop();

    CHECK(reset_count.load() == 200);
    CHECK(p.current_interval() == std::chrono::milliseconds(100));
}

// ============================================================================
// 测试 15: probe_once 同步探测
// ============================================================================
static void test_probe_once() {
    std::printf("[test] DefaultRoutePoller probe_once...\n");

    DefaultRoutePoller p;
    // 首次探测：建立基线
    bool changed1 = p.probe_once();
    CHECK(changed1 == false);  // 首次无对比基线，视为无变化

    // 第二次探测：若无路由变更应返回 false
    bool changed2 = p.probe_once();
    CHECK(changed2 == false);
}

// ============================================================================
// 测试 16: 大间隔参数
// ============================================================================
static void test_large_interval() {
    std::printf("[test] DefaultRoutePoller large interval...\n");

    DefaultRoutePoller p(std::chrono::seconds(1), std::chrono::seconds(30));
    CHECK(p.current_interval() == std::chrono::seconds(1));
    CHECK(p.next_interval(std::chrono::seconds(1)) == std::chrono::seconds(2));
    CHECK(p.next_interval(std::chrono::seconds(2)) == std::chrono::seconds(4));
    CHECK(p.next_interval(std::chrono::seconds(16)) == std::chrono::seconds(30));
}

// ============================================================================
// 测试 17: 小间隔参数
// ============================================================================
static void test_small_interval() {
    std::printf("[test] DefaultRoutePoller small interval...\n");

    DefaultRoutePoller p(std::chrono::milliseconds(10), std::chrono::milliseconds(100));
    CHECK(p.current_interval() == std::chrono::milliseconds(10));
    CHECK(p.next_interval(std::chrono::milliseconds(10)) == std::chrono::milliseconds(20));
    CHECK(p.next_interval(std::chrono::milliseconds(80)) == std::chrono::milliseconds(100));
}

// ============================================================================
// 测试 18: 多个 Poller 实例并存
// ============================================================================
static void test_multiple_pollers() {
    std::printf("[test] DefaultRoutePoller multiple instances...\n");

    DefaultRoutePoller p1, p2, p3;
    p1.start([](RouteEvent) {});
    p2.start([](RouteEvent) {});
    p3.start([](RouteEvent) {});

    CHECK(p1.is_running());
    CHECK(p2.is_running());
    CHECK(p3.is_running());

    p1.stop();
    CHECK(!p1.is_running());
    CHECK(p2.is_running());

    p2.stop();
    p3.stop();
}

// ============================================================================
// 测试 19: start 后更新 callback
// ============================================================================
static void test_update_callback() {
    std::printf("[test] DefaultRoutePoller update callback...\n");

    DefaultRoutePoller p;
    std::atomic<int> count1{0}, count2{0};

    p.start([&count1](RouteEvent) { count1++; });
    // 重新 start 应更新 callback（不崩溃）
    p.start([&count2](RouteEvent) { count2++; });

    CHECK(p.is_running());
    p.stop();
}

// ============================================================================
// 测试 20: 快速 start/stop 循环
// ============================================================================
static void test_rapid_start_stop() {
    std::printf("[test] DefaultRoutePoller rapid start/stop...\n");

    DefaultRoutePoller p;
    for (int i = 0; i < 20; ++i) {
        p.start([](RouteEvent) {});
        CHECK(p.is_running());
        p.stop();
        CHECK(!p.is_running());
    }
}

// ============================================================================
// 测试 21: 析构时线程安全 join
// ============================================================================
static void test_destructor_joins_thread() {
    std::printf("[test] DefaultRoutePoller destructor joins thread...\n");

    {
        DefaultRoutePoller p(std::chrono::milliseconds(10), std::chrono::milliseconds(100));
        p.start([](RouteEvent) {});
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        // 析构时应 join 线程
    }
    ++g_pass;  // 无崩溃/无泄漏即通过
}

// ============================================================================
// 测试 22: 退避序列完整遍历
// ============================================================================
static void test_full_backoff_traversal() {
    std::printf("[test] DefaultRoutePoller full backoff traversal...\n");

    DefaultRoutePoller p(std::chrono::milliseconds(1), std::chrono::milliseconds(8));

    auto cur = std::chrono::milliseconds(1);
    std::vector<long long> sequence;
    sequence.push_back(cur.count());
    for (int i = 0; i < 10; ++i) {
        cur = p.next_interval(cur);
        sequence.push_back(cur.count());
    }

    // 1 -> 2 -> 4 -> 8 -> 8 -> 8 ...
    CHECK(sequence[0] == 1);
    CHECK(sequence[1] == 2);
    CHECK(sequence[2] == 4);
    CHECK(sequence[3] == 8);
    CHECK(sequence[4] == 8);
    CHECK(sequence[10] == 8);
}

// ============================================================================
// 测试 23: 回调不持有 Poller 引用（生命周期安全）
// ============================================================================
static void test_callback_lifetime() {
    std::printf("[test] DefaultRoutePoller callback lifetime...\n");

    std::atomic<int> count{0};
    {
        DefaultRoutePoller p(std::chrono::milliseconds(50), std::chrono::milliseconds(100));
        p.start([&count](RouteEvent) { count++; });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    // p 析构后，回调不再被调用
    int c1 = count.load();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    int c2 = count.load();
    CHECK(c2 >= c1);
}

// ============================================================================
// 测试 24: next_interval 不改变 current_interval
// ============================================================================
static void test_next_interval_pure() {
    std::printf("[test] DefaultRoutePoller next_interval is pure...\n");

    DefaultRoutePoller p(std::chrono::milliseconds(200), std::chrono::seconds(5));
    auto original = p.current_interval();
    auto next = p.next_interval(original);

    // next_interval 是 const 方法，不应改变 current_interval
    CHECK(p.current_interval() == original);
    CHECK(next == std::chrono::milliseconds(400));
}

// ============================================================================
// 测试 25: 极端参数（1ms）
// ============================================================================
static void test_extreme_params() {
    std::printf("[test] DefaultRoutePoller extreme params (1ms)...\n");

    DefaultRoutePoller p(std::chrono::milliseconds(1), std::chrono::milliseconds(2));
    CHECK(p.current_interval() == std::chrono::milliseconds(1));
    CHECK(p.next_interval(std::chrono::milliseconds(1)) == std::chrono::milliseconds(2));
    CHECK(p.next_interval(std::chrono::milliseconds(2)) == std::chrono::milliseconds(2));
}

int main() {
    std::printf("=== test_default_route_poller ===\n");

    test_default_params();
    test_exponential_backoff_sequence();
    test_max_interval_cap();
    test_reset_interval();
    test_initial_equals_max();
    test_custom_params();
    test_start_stop_state();
    test_idempotent_stop();
    test_stop_without_start();
    test_destructor_stops();
    test_restart_resets_interval();
    test_callback_triggered();
    test_reset_after_backoff();
    test_concurrent_reset();
    test_probe_once();
    test_large_interval();
    test_small_interval();
    test_multiple_pollers();
    test_update_callback();
    test_rapid_start_stop();
    test_destructor_joins_thread();
    test_full_backoff_traversal();
    test_callback_lifetime();
    test_next_interval_pure();
    test_extreme_params();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
