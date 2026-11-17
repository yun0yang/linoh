// test_event_loop.cpp — v4.3.0 M7 select! 事件循环单元测试
//
// 测试覆盖：
//   ShutdownEvent: trigger/is_triggered/ready/wait_until/clear_ready(不可清除)
//   TimerEvent:    构造/next_fire/短周期触发/reset/set_period/clear_ready/wait_until
//   TaskQueue:     push/pop(FIFO)/drain/empty/size/ready(电平)/clear_ready(no-op)/pop空
//   EventLoop:     register_source/register_source_ref/size/source/select(超时+就绪)
//                  biased优先级/多ready全返回/max_ids截断/跨线程wake/run/析构解绑
//   LinohEventSource: ExternalDriven(nullptr ep, drive=0)/ready/clear_ready
//   C-API:         loop create/destroy/register/select + 工厂函数 + 操作函数 + type dispatch
//
// 设计原则：所有定时测试用 50ms 短周期/100ms 短超时，避免测试过慢；
//           跨线程测试用 std::thread 验证 wake 语义。

#include "linoh/event/event_loop.hpp"
#include "linoh/event/shutdown_event.hpp"
#include "linoh/event/timer_event.hpp"
#include "linoh/event/task_queue.hpp"
#include "linoh/event/linoh_event_source.hpp"
#include "linoh/linoh_c.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace linoh::event;
using namespace std::chrono_literals;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    if ((a) == (b)) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s != %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ========== ShutdownEvent ==========

// 1. ShutdownEvent 基本功能
static void test_shutdown_basic() {
    std::printf("[test] ShutdownEvent basic...\n");
    ShutdownEvent sd;
    CHECK(!sd.is_triggered());
    CHECK(!sd.ready());
    sd.trigger();
    CHECK(sd.is_triggered());
    CHECK(sd.ready());
}

// 2. ShutdownEvent clear_ready 不可清除（幂等）
static void test_shutdown_clear_ready_noop() {
    std::printf("[test] ShutdownEvent clear_ready is no-op...\n");
    ShutdownEvent sd;
    sd.trigger();
    sd.clear_ready();  // 不应清除
    CHECK(sd.ready());
    CHECK(sd.is_triggered());
    sd.trigger();  // 幂等，多次 trigger 等效一次
    CHECK(sd.ready());
}

// 3. ShutdownEvent wait_until 立即返回（已 trigger）
static void test_shutdown_wait_immediate() {
    std::printf("[test] ShutdownEvent wait_until immediate...\n");
    ShutdownEvent sd;
    sd.trigger();
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    CHECK(sd.wait_until(deadline));  // 已 ready，立即返回 true
}

// 4. ShutdownEvent wait_until 超时（未 trigger）
static void test_shutdown_wait_timeout() {
    std::printf("[test] ShutdownEvent wait_until timeout...\n");
    ShutdownEvent sd;
    auto start = std::chrono::steady_clock::now();
    auto deadline = start + std::chrono::milliseconds(50);
    CHECK(!sd.wait_until(deadline));  // 超时返回 false
    auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(elapsed >= std::chrono::milliseconds(40));  // 确实等待了
}

// 5. ShutdownEvent trigger 跨线程唤醒 wait_until
static void test_shutdown_cross_thread_wake() {
    std::printf("[test] ShutdownEvent cross-thread trigger wakes wait_until...\n");
    ShutdownEvent sd;
    std::thread t([&sd] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        sd.trigger();
    });
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    CHECK(sd.wait_until(deadline));  // 被唤醒
    t.join();
}

// ========== TimerEvent ==========

// 6. TimerEvent 构造 + next_fire
static void test_timer_construct() {
    std::printf("[test] TimerEvent construct + next_fire...\n");
    TimerEvent tm(std::chrono::milliseconds(100));
    auto now = std::chrono::steady_clock::now();
    auto nf = tm.next_fire();
    auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(nf - now);
    CHECK(delta >= std::chrono::milliseconds(80));
    CHECK(delta <= std::chrono::milliseconds(120));
    CHECK(!tm.ready());  // 刚构造未到期
}

// 7. TimerEvent 短周期触发
static void test_timer_fire() {
    std::printf("[test] TimerEvent short period fire...\n");
    TimerEvent tm(std::chrono::milliseconds(50));
    CHECK(!tm.ready());
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    CHECK(tm.ready());
}

// 8. TimerEvent reset 重置
static void test_timer_reset() {
    std::printf("[test] TimerEvent reset...\n");
    TimerEvent tm(std::chrono::milliseconds(50));
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    CHECK(tm.ready());
    tm.reset();
    CHECK(!tm.ready());  // reset 后未到期
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    CHECK(tm.ready());
}

// 9. TimerEvent set_period 修改周期
static void test_timer_set_period() {
    std::printf("[test] TimerEvent set_period...\n");
    TimerEvent tm(std::chrono::milliseconds(100));
    tm.set_period(std::chrono::milliseconds(50));
    CHECK(!tm.ready());
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    CHECK(tm.ready());
}

// 10. TimerEvent clear_ready 等价 reset
static void test_timer_clear_ready_eq_reset() {
    std::printf("[test] TimerEvent clear_ready == reset...\n");
    TimerEvent tm(std::chrono::milliseconds(50));
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    CHECK(tm.ready());
    tm.clear_ready();  // 等价 reset
    CHECK(!tm.ready());
}

// 11. TimerEvent wait_until 到期唤醒
static void test_timer_wait_until_fire() {
    std::printf("[test] TimerEvent wait_until fire...\n");
    TimerEvent tm(std::chrono::milliseconds(50));
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    CHECK(tm.wait_until(deadline));  // 50ms 后到期唤醒
}

// 12. TimerEvent 零或负周期 clamp 到 1ms
static void test_timer_zero_period_clamp() {
    std::printf("[test] TimerEvent zero/negative period clamp to 1ms...\n");
    TimerEvent tm(std::chrono::milliseconds(0));
    // 不 crash，周期被 clamp 到 1ms
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK(tm.ready());
}

// ========== TaskQueue ==========

// 13. TaskQueue push + pop FIFO
static void test_taskqueue_push_pop_fifo() {
    std::printf("[test] TaskQueue push + pop FIFO...\n");
    TaskQueue<int> q;
    CHECK(q.empty());
    q.push(10);
    q.push(20);
    q.push(30);
    CHECK_EQ(q.size(), 3u);
    CHECK_EQ(*q.pop(), 10);  // FIFO
    CHECK_EQ(*q.pop(), 20);
    CHECK_EQ(*q.pop(), 30);
    CHECK(q.empty());
}

// 14. TaskQueue drain 批量取出
static void test_taskqueue_drain() {
    std::printf("[test] TaskQueue drain...\n");
    TaskQueue<std::string> q;
    q.push("a");
    q.push("b");
    q.push("c");
    auto all = q.drain();
    CHECK_EQ(all.size(), 3u);
    CHECK_EQ(all[0], "a");
    CHECK_EQ(all[1], "b");
    CHECK_EQ(all[2], "c");
    CHECK(q.empty());
    CHECK_EQ(q.drain().size(), 0u);  // 空队列 drain
}

// 15. TaskQueue pop 空队列返回 nullopt
static void test_taskqueue_pop_empty() {
    std::printf("[test] TaskQueue pop empty returns nullopt...\n");
    TaskQueue<int> q;
    CHECK(!q.pop());
}

// 16. TaskQueue ready 电平触发（非空即 ready）
static void test_taskqueue_ready_level_triggered() {
    std::printf("[test] TaskQueue ready level-triggered...\n");
    TaskQueue<int> q;
    CHECK(!q.ready());
    q.push(1);
    CHECK(q.ready());  // 非空即 ready
    q.pop();
    CHECK(!q.ready());  // 空后 not ready
}

// 17. TaskQueue clear_ready no-op（电平触发）
static void test_taskqueue_clear_ready_noop() {
    std::printf("[test] TaskQueue clear_ready is no-op...\n");
    TaskQueue<int> q;
    q.push(1);
    CHECK(q.ready());
    q.clear_ready();  // no-op
    CHECK(q.ready());  // 仍 ready（队列非空）
}

// 18. TaskQueue 跨线程 push
static void test_taskqueue_cross_thread_push() {
    std::printf("[test] TaskQueue cross-thread push...\n");
    TaskQueue<int> q;
    std::thread t([&q] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        q.push(42);
    });
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    CHECK(q.wait_until(deadline));  // 被唤醒
    CHECK_EQ(*q.pop(), 42);
    t.join();
}

// ========== EventLoop ==========

// 19. EventLoop register_source + size
static void test_loop_register_size() {
    std::printf("[test] EventLoop register_source + size...\n");
    EventLoop loop;
    CHECK_EQ(loop.size(), 0u);
    auto idx1 = loop.register_source(std::make_unique<ShutdownEvent>(), 0);
    CHECK_EQ(loop.size(), 1u);
    auto idx2 = loop.register_source(std::make_unique<ShutdownEvent>(), 1);
    CHECK_EQ(loop.size(), 2u);
    CHECK_EQ(idx1, 0u);
    CHECK_EQ(idx2, 1u);
}

// 20. EventLoop register_source_ref + size
static void test_loop_register_ref() {
    std::printf("[test] EventLoop register_source_ref...\n");
    EventLoop loop;
    ShutdownEvent sd;
    auto idx = loop.register_source_ref(sd, 0);
    CHECK_EQ(loop.size(), 1u);
    CHECK_EQ(idx, 0u);
    // sd 生命周期由调用方管理，loop 析构后 sd 仍有效
    CHECK(!sd.is_triggered());
}

// 21. EventLoop select 非阻塞超时（无 ready 返回空）
static void test_loop_select_timeout_empty() {
    std::printf("[test] EventLoop select timeout (no ready)...\n");
    EventLoop loop;
    ShutdownEvent sd;
    loop.register_source_ref(sd, 0);
    auto start = std::chrono::steady_clock::now();
    auto ready = loop.select(std::chrono::milliseconds(50));
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    CHECK(ready.empty());
    CHECK(elapsed >= std::chrono::milliseconds(40));
}

// 22. EventLoop select 非阻塞轮询（timeout=0）
static void test_loop_select_nonblocking() {
    std::printf("[test] EventLoop select non-blocking (timeout=0)...\n");
    EventLoop loop;
    ShutdownEvent sd;
    loop.register_source_ref(sd, 0);
    auto ready = loop.select(std::chrono::milliseconds(0));  // 非阻塞
    CHECK(ready.empty());  // sd 未 trigger
    sd.trigger();
    ready = loop.select(std::chrono::milliseconds(0));
    CHECK_EQ(ready.size(), 1u);
    CHECK_EQ(ready[0], 0u);
}

// 23. EventLoop select 等待 ShutdownEvent（trigger 后立即返回）
static void test_loop_select_shutdown_ready() {
    std::printf("[test] EventLoop select shutdown ready...\n");
    EventLoop loop;
    ShutdownEvent sd;
    loop.register_source_ref(sd, 0);
    sd.trigger();
    auto ready = loop.select(std::chrono::milliseconds(100));
    CHECK_EQ(ready.size(), 1u);
    CHECK_EQ(ready[0], 0u);
}

// 24. EventLoop select biased 优先级（高优先级先返回）
static void test_loop_select_biased_priority() {
    std::printf("[test] EventLoop select biased priority...\n");
    EventLoop loop;
    ShutdownEvent sd_low;    // priority=10
    ShutdownEvent sd_high;   // priority=0
    TimerEvent    tm(50ms);  // priority=5
    auto idx_low  = loop.register_source_ref(sd_low, 10);
    auto idx_high = loop.register_source_ref(sd_high, 0);
    auto idx_tm   = loop.register_source_ref(tm, 5);
    // 全部 ready
    sd_low.trigger();
    sd_high.trigger();
    std::this_thread::sleep_for(60ms);  // 等 timer 到期
    auto ready = loop.select(std::chrono::milliseconds(100));
    CHECK_EQ(ready.size(), 3u);
    // 按 priority 升序：high(0) < tm(5) < low(10)
    CHECK_EQ(ready[0], idx_high);
    CHECK_EQ(ready[1], idx_tm);
    CHECK_EQ(ready[2], idx_low);
}

// 25. EventLoop select 多个 ready 全部返回
static void test_loop_select_multiple_ready() {
    std::printf("[test] EventLoop select multiple ready...\n");
    EventLoop loop;
    ShutdownEvent sd1, sd2, sd3;
    loop.register_source_ref(sd1, 0);
    loop.register_source_ref(sd2, 0);
    loop.register_source_ref(sd3, 0);
    sd1.trigger();
    sd2.trigger();
    sd3.trigger();
    auto ready = loop.select(std::chrono::milliseconds(100));
    CHECK_EQ(ready.size(), 3u);
}

// 26. EventLoop select 跨线程 wake
static void test_loop_select_cross_thread_wake() {
    std::printf("[test] EventLoop select cross-thread wake...\n");
    EventLoop loop;
    ShutdownEvent sd;
    loop.register_source_ref(sd, 0);
    std::thread t([&sd] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        sd.trigger();
    });
    auto start = std::chrono::steady_clock::now();
    auto ready = loop.select(std::chrono::seconds(5));
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    CHECK_EQ(ready.size(), 1u);
    CHECK(elapsed < std::chrono::seconds(1));  // 不应等满 5s
    t.join();
}

// 27. EventLoop run 主循环
static void test_loop_run() {
    std::printf("[test] EventLoop run main loop...\n");
    EventLoop loop;
    ShutdownEvent sd;
    loop.register_source_ref(sd, 0);
    std::atomic<bool> running{true};
    std::atomic<int> trigger_count{0};
    std::thread t([&sd, &running, &trigger_count] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        sd.trigger();
        trigger_count.store(1, std::memory_order_release);
    });
    loop.run(
        [&running] { return !running.load(std::memory_order_acquire); },
        [&sd, &running](std::size_t idx) {
            if (idx == 0) {
                if (sd.ready()) running.store(false, std::memory_order_release);
            }
        },
        std::chrono::milliseconds(100));
    CHECK_EQ(trigger_count.load(), 1);
    t.join();
}

// 28. EventLoop source 取回
static void test_loop_source_get() {
    std::printf("[test] EventLoop source get...\n");
    EventLoop loop;
    auto idx = loop.register_source(std::make_unique<ShutdownEvent>(), 0);
    auto *src = loop.source(idx);
    CHECK(src != nullptr);
    CHECK(!src->ready());
    auto *bad = loop.source(999);  // 越界
    CHECK(bad == nullptr);
}

// 29. EventLoop 析构解绑 source loop_ 指针（先析构 loop，source 仍可安全析构）
static void test_loop_destruct_unbind() {
    std::printf("[test] EventLoop destruct unbinds source loop_...\n");
    ShutdownEvent sd;
    {
        EventLoop loop;
        loop.register_source_ref(sd, 0);
        // loop 析构时应解绑 sd 的 loop_ 指针
    }
    // sd 在 loop 析构后仍安全（loop_ 已 nullptr）
    sd.trigger();  // 不 crash（wake_loop_ 检查 loop_ 为 nullptr 时跳过）
    CHECK(sd.ready());
}

// 30. EventLoop wake 跨线程强制唤醒
static void test_loop_wake_external() {
    std::printf("[test] EventLoop wake external...\n");
    EventLoop loop;
    std::thread t([&loop] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        loop.wake();  // 外部唤醒
    });
    auto start = std::chrono::steady_clock::now();
    auto ready = loop.select(std::chrono::seconds(5));
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    CHECK(ready.empty());  // wake 但无 source ready
    CHECK(elapsed < std::chrono::seconds(1));
    t.join();
}

// 31. EventLoop select 永久阻塞（timeout<0）+ 跨线程 trigger
static void test_loop_select_infinite() {
    std::printf("[test] EventLoop select infinite (timeout<0)...\n");
    EventLoop loop;
    ShutdownEvent sd;
    loop.register_source_ref(sd, 0);
    std::thread t([&sd] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        sd.trigger();
    });
    auto ready = loop.select(std::chrono::milliseconds(-1));  // 永久阻塞
    CHECK_EQ(ready.size(), 1u);
    t.join();
}

// ========== LinohEventSource ==========

// 32. LinohEventSource ExternalDriven nullptr ep（drive 返回 0）
static void test_linoh_event_nullptr_ep() {
    std::printf("[test] LinohEventSource nullptr ep drive=0...\n");
    LinohEventSource net(nullptr, LinohEventSource::Mode::ExternalDriven);
    CHECK_EQ(net.drive(), 0);  // nullptr ep → 0
    CHECK(!net.ready());       // drive 返回 0，不置 ready
    net.clear_ready();         // no-op，不 crash
    CHECK(!net.is_running());  // ExternalDriven 不启动线程
}

// 33. LinohEventSource SelfDriven nullptr ep 不启动线程
static void test_linoh_event_self_driven_nullptr() {
    std::printf("[test] LinohEventSource SelfDriven nullptr ep no thread...\n");
    LinohEventSource net(nullptr, LinohEventSource::Mode::SelfDriven);
    net.start();  // nullptr ep → 不启动
    CHECK(!net.is_running());
    net.stop();   // no-op
    // set_poll_interval 不 crash
    net.set_poll_interval(std::chrono::milliseconds(5));
}

// 34. LinohEventSource ready/clear_ready 手动控制
static void test_linoh_event_ready_clear() {
    std::printf("[test] LinohEventSource ready/clear_ready manual...\n");
    LinohEventSource net(nullptr, LinohEventSource::Mode::ExternalDriven);
    CHECK(!net.ready());
    // ready 由 drive() 内部设置（events>0 时），nullptr ep 永远 false
    net.clear_ready();
    CHECK(!net.ready());
}

// ========== C-API ==========

// 35. C-API linoh_event_loop_create + destroy
static void test_capi_loop_create_destroy() {
    std::printf("[test] C-API loop create + destroy...\n");
    auto *loop = linoh_event_loop_create();
    CHECK(loop != nullptr);
    linoh_event_loop_destroy(loop);
    // destroy nullptr 应安全（guard 内 delete nullptr 合法）
    linoh_event_loop_destroy(nullptr);
}

// 36. C-API linoh_shutdown_event_create + trigger + destroy
static void test_capi_shutdown_create_trigger() {
    std::printf("[test] C-API shutdown create + trigger...\n");
    auto *sd = linoh_shutdown_event_create();
    CHECK(sd != nullptr);
    CHECK_EQ(linoh_shutdown_event_trigger(sd), 0);
    // 重复 trigger 幂等
    CHECK_EQ(linoh_shutdown_event_trigger(sd), 0);
    linoh_event_source_destroy(sd);
}

// 37. C-API linoh_timer_event_create + reset + destroy
static void test_capi_timer_create_reset() {
    std::printf("[test] C-API timer create + reset...\n");
    auto *tm = linoh_timer_event_create(50);
    CHECK(tm != nullptr);
    CHECK_EQ(linoh_timer_event_reset(tm), 0);
    linoh_event_source_destroy(tm);
}

// 38. C-API linoh_linoh_event_create nullptr ep 返回 nullptr
static void test_capi_linoh_event_nullptr_ep() {
    std::printf("[test] C-API linoh_event nullptr ep returns nullptr...\n");
    auto *net = linoh_linoh_event_create(nullptr, LINOH_EVENT_MODE_EXTERNAL);
    CHECK(net == nullptr);  // nullptr ep → nullptr
}

// 39. C-API linoh_event_loop_register + select（shutdown 就绪）
static void test_capi_register_select() {
    std::printf("[test] C-API register + select (shutdown ready)...\n");
    auto *loop = linoh_event_loop_create();
    std::printf("  [d] loop=%p\n", (void*)loop);
    auto *sd = linoh_shutdown_event_create();
    std::printf("  [d] sd=%p\n", (void*)sd);
    int sid = linoh_event_loop_register(loop, sd, 0);
    std::printf("  [d] sid=%d\n", sid);
    CHECK(sid >= 0);
    linoh_shutdown_event_trigger(sd);
    std::printf("  [d] triggered\n");
    int ids[8];
    int n = linoh_event_loop_select(loop, ids, 8, 100);
    std::printf("  [d] n=%d\n", n);
    CHECK_EQ(n, 1);
    CHECK_EQ(ids[0], sid);
    linoh_event_source_destroy(sd);
    std::printf("  [d] source destroyed\n");
    linoh_event_loop_destroy(loop);
    std::printf("  [d] loop destroyed\n");
}

// 40. C-API linoh_event_loop_select 超时无 ready
static void test_capi_select_timeout() {
    std::printf("[test] C-API select timeout (no ready)...\n");
    auto *loop = linoh_event_loop_create();
    auto *sd = linoh_shutdown_event_create();
    linoh_event_loop_register(loop, sd, 0);
    int ids[8];
    auto start = std::chrono::steady_clock::now();
    int n = linoh_event_loop_select(loop, ids, 8, 50);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    CHECK_EQ(n, 0);  // 无 ready
    CHECK(elapsed >= std::chrono::milliseconds(40));
    linoh_event_source_destroy(sd);
    linoh_event_loop_destroy(loop);
}

// 41. C-API linoh_event_loop_select 非阻塞（timeout_ms=0）
static void test_capi_select_nonblocking() {
    std::printf("[test] C-API select non-blocking (timeout_ms=0)...\n");
    auto *loop = linoh_event_loop_create();
    auto *sd = linoh_shutdown_event_create();
    linoh_event_loop_register(loop, sd, 0);
    int ids[8];
    CHECK_EQ(linoh_event_loop_select(loop, ids, 8, 0), 0);  // 非阻塞，无 ready
    linoh_shutdown_event_trigger(sd);
    CHECK_EQ(linoh_event_loop_select(loop, ids, 8, 0), 1);  // 非阻塞，有 ready
    linoh_event_source_destroy(sd);
    linoh_event_loop_destroy(loop);
}

// 42. C-API linoh_shutdown_event_trigger 跨线程唤醒 select
static void test_capi_cross_thread_wake() {
    std::printf("[test] C-API cross-thread trigger wakes select...\n");
    auto *loop = linoh_event_loop_create();
    auto *sd = linoh_shutdown_event_create();
    linoh_event_loop_register(loop, sd, 0);
    std::thread t([&sd] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        linoh_shutdown_event_trigger(sd);
    });
    int ids[8];
    int n = linoh_event_loop_select(loop, ids, 8, 5000);
    CHECK_EQ(n, 1);
    t.join();
    linoh_event_source_destroy(sd);
    linoh_event_loop_destroy(loop);
}

// 43. C-API type dispatch 错误（trigger 非 ShutdownEvent 返回 -1）
static void test_capi_type_dispatch_error() {
    std::printf("[test] C-API type dispatch error...\n");
    auto *tm = linoh_timer_event_create(50);
    // tm 是 TimerEvent，调用 shutdown trigger 应失败
    CHECK_EQ(linoh_shutdown_event_trigger(tm), -1);
    // tm 调用 linoh_event_drive 应失败
    CHECK_EQ(linoh_linoh_event_drive(tm), -1);
    linoh_event_source_destroy(tm);
}

// 44. C-API register null 参数返回 -1
static void test_capi_register_null() {
    std::printf("[test] C-API register null args...\n");
    auto *loop = linoh_event_loop_create();
    auto *sd = linoh_shutdown_event_create();
    CHECK_EQ(linoh_event_loop_register(nullptr, sd, 0), -1);  // null loop
    CHECK_EQ(linoh_event_loop_register(loop, nullptr, 0), -1);  // null src
    linoh_event_source_destroy(sd);
    linoh_event_loop_destroy(loop);
}

// 45. C-API select null loop 返回 -1
static void test_capi_select_null() {
    std::printf("[test] C-API select null loop...\n");
    int ids[8];
    CHECK_EQ(linoh_event_loop_select(nullptr, ids, 8, 100), -1);
}

// 46. C-API select 截断 max_ids
static void test_capi_select_truncate() {
    std::printf("[test] C-API select truncate max_ids...\n");
    auto *loop = linoh_event_loop_create();
    auto *sd1 = linoh_shutdown_event_create();
    auto *sd2 = linoh_shutdown_event_create();
    auto *sd3 = linoh_shutdown_event_create();
    linoh_event_loop_register(loop, sd1, 0);
    linoh_event_loop_register(loop, sd2, 0);
    linoh_event_loop_register(loop, sd3, 0);
    linoh_shutdown_event_trigger(sd1);
    linoh_shutdown_event_trigger(sd2);
    linoh_shutdown_event_trigger(sd3);
    int ids[2];  // 容量 2，但 3 个 ready
    int n = linoh_event_loop_select(loop, ids, 2, 100);
    CHECK_EQ(n, 2);  // 截断到 2
    linoh_event_source_destroy(sd1);
    linoh_event_source_destroy(sd2);
    linoh_event_source_destroy(sd3);
    linoh_event_loop_destroy(loop);
}

// 47. C-API timer select 到期返回
static void test_capi_timer_select_fire() {
    std::printf("[test] C-API timer select fire...\n");
    auto *loop = linoh_event_loop_create();
    auto *tm = linoh_timer_event_create(50);
    int tid = linoh_event_loop_register(loop, tm, 0);
    CHECK(tid >= 0);
    int ids[8];
    int n = linoh_event_loop_select(loop, ids, 8, 5000);  // 50ms 后 timer 到期
    CHECK_EQ(n, 1);
    CHECK_EQ(ids[0], tid);
    // reset 后再次等待
    CHECK_EQ(linoh_timer_event_reset(tm), 0);
    n = linoh_event_loop_select(loop, ids, 8, 5000);
    CHECK_EQ(n, 1);
    linoh_event_source_destroy(tm);
    linoh_event_loop_destroy(loop);
}

// ========== 综合场景 ==========

// 48. 综合：shutdown + timer + taskqueue 混合 select
static void test_e2e_mixed_sources() {
    std::printf("[test] E2E mixed sources (shutdown + timer + taskqueue)...\n");
    EventLoop loop;
    ShutdownEvent sd;
    TimerEvent tm(50ms);
    TaskQueue<int> q;
    auto sid = loop.register_source_ref(sd, 0);   // 最高优先级
    auto tid = loop.register_source_ref(tm, 1);
    auto qid = loop.register_source_ref(q, 2);

    // 业务线程投递任务
    std::thread t([&q, &sd] {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        q.push(100);
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
        sd.trigger();  // 60ms 后触发 shutdown
    });

    int shutdown_seen = 0;
    int task_seen = 0;
    int timer_seen = 0;

    while (!sd.is_triggered()) {
        auto ready = loop.select(std::chrono::milliseconds(100));
        for (auto idx : ready) {
            if (idx == sid) { ++shutdown_seen; }
            else if (idx == tid) { ++timer_seen; tm.reset(); }
            else if (idx == qid) {
                auto tasks = q.drain();
                for (auto v : tasks) { (void)v; ++task_seen; }
            }
        }
    }
    // 再 select 一次确保 shutdown 被处理
    auto ready = loop.select(std::chrono::milliseconds(0));
    for (auto idx : ready) {
        if (idx == sid) ++shutdown_seen;
    }

    CHECK(task_seen >= 1);     // 至少处理 1 个任务
    CHECK(timer_seen >= 1);    // 至少 1 次 timer 触发
    CHECK(shutdown_seen >= 1); // shutdown 被看到
    t.join();
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);  // 禁用缓冲，崩溃前定位输出
    std::printf("=== test_event_loop ===\n\n");

    // ShutdownEvent
    test_shutdown_basic();
    test_shutdown_clear_ready_noop();
    test_shutdown_wait_immediate();
    test_shutdown_wait_timeout();
    test_shutdown_cross_thread_wake();

    // TimerEvent
    test_timer_construct();
    test_timer_fire();
    test_timer_reset();
    test_timer_set_period();
    test_timer_clear_ready_eq_reset();
    test_timer_wait_until_fire();
    test_timer_zero_period_clamp();

    // TaskQueue
    test_taskqueue_push_pop_fifo();
    test_taskqueue_drain();
    test_taskqueue_pop_empty();
    test_taskqueue_ready_level_triggered();
    test_taskqueue_clear_ready_noop();
    test_taskqueue_cross_thread_push();

    // EventLoop
    test_loop_register_size();
    test_loop_register_ref();
    test_loop_select_timeout_empty();
    test_loop_select_nonblocking();
    test_loop_select_shutdown_ready();
    test_loop_select_biased_priority();
    test_loop_select_multiple_ready();
    test_loop_select_cross_thread_wake();
    test_loop_run();
    test_loop_source_get();
    test_loop_destruct_unbind();
    test_loop_wake_external();
    test_loop_select_infinite();

    // LinohEventSource
    test_linoh_event_nullptr_ep();
    test_linoh_event_self_driven_nullptr();
    test_linoh_event_ready_clear();

    // C-API
    test_capi_loop_create_destroy();
    test_capi_shutdown_create_trigger();
    test_capi_timer_create_reset();
    test_capi_linoh_event_nullptr_ep();
    test_capi_register_select();
    test_capi_select_timeout();
    test_capi_select_nonblocking();
    test_capi_cross_thread_wake();
    test_capi_type_dispatch_error();
    test_capi_register_null();
    test_capi_select_null();
    test_capi_select_truncate();
    test_capi_timer_select_fire();

    // 综合
    test_e2e_mixed_sources();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
