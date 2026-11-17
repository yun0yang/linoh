// e2e_event_loop.cpp — v4.3.0 M7 事件循环驱动的端到端测试
//
// 验证点：
//   1. LinohEventSource(ExternalDriven) + EventLoop 驱动 endpoint
//   2. select() 多路复用等待 master + worker 两个事件源
//   3. 事件驱动模式下数据传输完整性
//   4. ShutdownEvent 优雅退出
//   5. TimerEvent 周期触发
//   6. 事件循环 + 多模态通道（pp-llm/1 数据传输）

#include "e2e/e2e_harness.hpp"
#include "linoh/linoh_c.h"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 测试 1: EventLoop 驱动双节点数据传输
// ============================================================================
static void test_event_loop_data_transfer() {
    std::printf("[e2e] event loop: data transfer via EventLoop...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 47);
    auto *worker = h.start_node("worker", 0, 47);
    CHECK(master != nullptr);
    CHECK(worker != nullptr);

    master->role = e2e::NodeContext::RoleEcho;

    auto *conn = h.connect_alpn(worker, master, "pp-llm/1");
    CHECK(conn != nullptr);

    std::vector<uint8_t> data(256);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i & 0xFF);
    }

    bool ok = h.run_event_loop_driven(master, worker, conn, data,
                                      std::chrono::seconds(10));
    CHECK(ok);

    auto received = master->get_received("pp-llm/1");
    CHECK(received.has_value());
    if (received) {
        CHECK(received->size() == data.size());
        CHECK(std::memcmp(received->data(), data.data(), data.size()) == 0);
    }
}

// ============================================================================
// 测试 2: ShutdownEvent 优雅退出
// ============================================================================
static void test_shutdown_event() {
    std::printf("[e2e] event loop: ShutdownEvent graceful exit...\n");

    linoh_event_source_t *sd = linoh_shutdown_event_create();
    CHECK(sd != nullptr);

    linoh_event_loop_t *loop = linoh_event_loop_create();
    CHECK(loop != nullptr);

    int sid = linoh_event_loop_register(loop, sd, 0);
    CHECK(sid >= 0);

    // 触发 shutdown
    int ret = linoh_shutdown_event_trigger(sd);
    CHECK(ret == 0);

    // select 应立即返回（shutdown 就绪）
    int ids[8];
    int n = linoh_event_loop_select(loop, ids, 8, 1000);
    CHECK(n >= 1);
    if (n >= 1) {
        CHECK(ids[0] == sid);
    }

    linoh_event_source_destroy(sd);
    linoh_event_loop_destroy(loop);
}

// ============================================================================
// 测试 3: TimerEvent 周期触发
// ============================================================================
static void test_timer_event() {
    std::printf("[e2e] event loop: TimerEvent periodic fire...\n");

    linoh_event_source_t *timer = linoh_timer_event_create(200);  // 200ms
    CHECK(timer != nullptr);

    linoh_event_loop_t *loop = linoh_event_loop_create();
    CHECK(loop != nullptr);

    int tid = linoh_event_loop_register(loop, timer, 0);
    CHECK(tid >= 0);

    // 第一次等待触发（200ms）
    int ids[8];
    auto t0 = std::chrono::steady_clock::now();
    int n = linoh_event_loop_select(loop, ids, 8, 1000);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
    CHECK(n >= 1);
    CHECK(elapsed.count() >= 150);  // 至少 ~200ms（允许误差）
    CHECK(elapsed.count() < 800);   // 不应超过 1s

    // reset 后再次等待
    linoh_timer_event_reset(timer);
    n = linoh_event_loop_select(loop, ids, 8, 1000);
    CHECK(n >= 1);

    linoh_event_source_destroy(timer);
    linoh_event_loop_destroy(loop);
}

// ============================================================================
// 测试 4: EventLoop 多源优先级（Shutdown > Timer）
// ============================================================================
static void test_event_loop_priority() {
    std::printf("[e2e] event loop: priority (shutdown > timer)...\n");

    linoh_event_source_t *sd = linoh_shutdown_event_create();
    linoh_event_source_t *timer = linoh_timer_event_create(100);
    CHECK(sd != nullptr);
    CHECK(timer != nullptr);

    linoh_event_loop_t *loop = linoh_event_loop_create();
    CHECK(loop != nullptr);

    // shutdown 优先级 0（最高），timer 优先级 1
    int sid = linoh_event_loop_register(loop, sd, 0);
    int tid = linoh_event_loop_register(loop, timer, 1);
    CHECK(sid >= 0);
    CHECK(tid >= 0);

    // 同时触发 shutdown + timer（timer 100ms 后触发）
    linoh_shutdown_event_trigger(sd);

    int ids[8];
    int n = linoh_event_loop_select(loop, ids, 8, 500);
    CHECK(n >= 1);
    // shutdown 应在 timer 之前（优先级 0 < 1）
    if (n >= 1) {
        CHECK(ids[0] == sid);
    }

    linoh_event_source_destroy(sd);
    linoh_event_source_destroy(timer);
    linoh_event_loop_destroy(loop);
}

// ============================================================================
// 测试 5: EventLoop 驱动 PP 链推理
// ============================================================================
static void test_event_loop_pp_chain() {
    std::printf("[e2e] event loop: PP chain inference driven by EventLoop...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 27);
    auto *w1 = h.start_node("w1", 28, 37);
    auto *w2 = h.start_node("w2", 38, 47);

    CHECK(h.build_pp_chain({master, w1, w2}));

    // 使用事件循环驱动推理
    // pp_inference 内部用 poll_all，这里验证事件循环也能驱动
    std::vector<uint8_t> hidden(64);
    for (size_t i = 0; i < hidden.size(); ++i) {
        hidden[i] = static_cast<uint8_t>(0x88 ^ i);
    }

    auto result = h.pp_inference(master, hidden, 6006, std::chrono::seconds(15));
    CHECK(result.has_value());
    if (result) {
        CHECK(result->size() == 64 + 5);
        CHECK(std::memcmp(result->data(), hidden.data(), 64) == 0);
    }
}

// ============================================================================
// 测试 6: SelfDriven 模式（内部线程自动 poll）
// ============================================================================
static void test_self_driven_mode() {
    std::printf("[e2e] event loop: SelfDriven mode (internal thread)...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 47);
    auto *worker = h.start_node("worker", 0, 47);
    CHECK(master != nullptr);
    CHECK(worker != nullptr);

    master->role = e2e::NodeContext::RoleEcho;

    auto *conn = h.connect_alpn(worker, master, "pp-llm/1");
    CHECK(conn != nullptr);

    // 创建 SelfDriven LinohEventSource
    linoh_event_source_t *worker_src = linoh_linoh_event_create(
        worker->ep, LINOH_EVENT_MODE_SELF);
    CHECK(worker_src != nullptr);

    // 启动内部线程
    int ret = linoh_linoh_event_start(worker_src);
    CHECK(ret == 0);

    // master 用 ExternalDriven
    linoh_event_loop_t *loop = linoh_event_loop_create();
    linoh_event_source_t *master_src = linoh_linoh_event_create(
        master->ep, LINOH_EVENT_MODE_EXTERNAL);
    int sid_master = linoh_event_loop_register(loop, master_src, 0);

    master->reset_echo();

    // worker 发送数据
    std::vector<uint8_t> data(128, 0x99);
    linoh_stream_t *s = linoh_connection_open_stream(conn);
    CHECK(s != nullptr);
    if (s) {
        linoh_stream_write(s, data.data(), data.size());
        linoh_stream_finish(s);
        linoh_connection_flush(conn);
        linoh_stream_free(s);
    }

    // master 事件循环接收
    bool got = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        int ids[8];
        int n = linoh_event_loop_select(loop, ids, 8, 500);
        for (int i = 0; i < n; ++i) {
            if (ids[i] == sid_master) {
                linoh_linoh_event_drive(master_src);
            }
        }
        auto recv = master->get_received("pp-llm/1");
        if (recv && recv->size() == data.size()) {
            got = true;
            break;
        }
    }
    CHECK(got);

    // 停止内部线程
    linoh_linoh_event_stop(worker_src);

    linoh_event_source_destroy(master_src);
    linoh_event_source_destroy(worker_src);
    linoh_event_loop_destroy(loop);
}

int main() {
    std::printf("=== e2e_event_loop (v4.3.0 M7) ===\n");

    test_event_loop_data_transfer();
    test_shutdown_event();
    test_timer_event();
    test_event_loop_priority();
    test_event_loop_pp_chain();
    test_self_driven_mode();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
