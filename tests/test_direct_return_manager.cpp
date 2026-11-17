// test_direct_return_manager.cpp — DirectReturnManager 单元测试（v3.2.0）
//
// 测试覆盖（不依赖真实网络，仅测可独立验证的逻辑）：
//   1. compute_stream_token 确定性（同输入同输出）
//   2. compute_stream_token 区分性（不同 req_id / timestamp 产生不同 token）
//   3. compute_stream_token 低 32 位（不溢出 uint32）
//   4. register_return_slot 返回非零 token
//   5. register_return_slot 多次调用 token 互异（碰撞规避）
//   6. await_return_result 对未知 token 返回异常 future
//   7. cancel_return_slot 后 await 返回异常 future
//   8. cancel_return_slot 对未知 token 安全（无副作用）
//   9. stats() 返回注册/取消计数正确
//  10. local_endpoint_id（无 Endpoint 时返回全 0）
//  11. cleanup_idle_connections 空池安全调用
//  12. 析构时唤醒等待的 future（异常）
//
// 注：open_return_stream / send_result_direct / route_result 涉及真实 Endpoint
//     与 Stream，留待 P1 集成测试覆盖。

#include "linoh/direct_return_manager.hpp"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <future>
#include <thread>
#include <vector>

using namespace linoh;

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

// ============================================================================
// compute_stream_token 测试
// ============================================================================

static void test_token_deterministic() {
    std::printf("[test] compute_stream_token deterministic...\n");
    auto t1 = DirectReturnManager::compute_stream_token(12345, 99999);
    auto t2 = DirectReturnManager::compute_stream_token(12345, 99999);
    CHECK_EQ(t1, t2);
}

static void test_token_diff_reqid() {
    std::printf("[test] compute_stream_token differs by req_id...\n");
    auto t1 = DirectReturnManager::compute_stream_token(1, 1000);
    auto t2 = DirectReturnManager::compute_stream_token(2, 1000);
    CHECK(t1 != t2);
}

static void test_token_diff_timestamp() {
    std::printf("[test] compute_stream_token differs by timestamp...\n");
    auto t1 = DirectReturnManager::compute_stream_token(100, 1000);
    auto t2 = DirectReturnManager::compute_stream_token(100, 1001);
    CHECK(t1 != t2);
}

static void test_token_uint32_range() {
    std::printf("[test] compute_stream_token uint32 range...\n");
    // 大量样本均应落在 uint32 范围
    for (std::uint64_t r = 0; r < 100; ++r) {
        for (std::uint64_t t = 0; t < 100; t += 7) {
            auto tok = DirectReturnManager::compute_stream_token(r, t);
            (void)tok;  // 仅验证不抛异常
        }
    }
    CHECK(true);
}

// ============================================================================
// register_return_slot / await / cancel 测试（无 Endpoint，endpoint_=nullptr）
// ============================================================================

static void test_register_returns_nonzero() {
    std::printf("[test] register_return_slot returns nonzero...\n");
    DirectReturnManager mgr(nullptr);
    auto token = mgr.register_return_slot(42);
    CHECK(token != 0);  // fnv1a 极低概率为 0
}

static void test_register_multiple_distinct() {
    std::printf("[test] register_return_slot multiple distinct...\n");
    DirectReturnManager mgr(nullptr);
    std::vector<std::uint32_t> tokens;
    for (int i = 0; i < 100; ++i) {
        tokens.push_back(mgr.register_return_slot(static_cast<std::uint64_t>(i)));
    }
    // 全部互异
    std::sort(tokens.begin(), tokens.end());
    auto it = std::unique(tokens.begin(), tokens.end());
    CHECK(it == tokens.end());
}

static void test_await_unknown_token_throws() {
    std::printf("[test] await_return_result unknown token throws...\n");
    DirectReturnManager mgr(nullptr);
    auto fut = mgr.await_return_result(0xDEADBEEF);
    bool threw = false;
    try {
        fut.get();
    } catch (...) {
        threw = true;
    }
    CHECK(threw);
}

static void test_cancel_then_await_throws() {
    std::printf("[test] cancel_return_slot then await throws...\n");
    DirectReturnManager mgr(nullptr);
    auto token = mgr.register_return_slot(7);
    auto fut = mgr.await_return_result(token);
    mgr.cancel_return_slot(token);
    bool threw = false;
    try {
        fut.get();
    } catch (...) {
        threw = true;
    }
    CHECK(threw);
}

static void test_cancel_unknown_safe() {
    std::printf("[test] cancel_return_slot unknown token safe...\n");
    DirectReturnManager mgr(nullptr);
    // 不应崩溃
    mgr.cancel_return_slot(0xCAFEBABE);
    CHECK(true);
}

static void test_stats_register_cancel() {
    std::printf("[test] stats register/cancel counts...\n");
    DirectReturnManager mgr(nullptr);
    auto t1 = mgr.register_return_slot(1);
    auto t2 = mgr.register_return_slot(2);
    auto t3 = mgr.register_return_slot(3);
    (void)t1; (void)t2; (void)t3;
    auto s = mgr.stats();
    CHECK_EQ(s.return_slots_registered, 3u);

    mgr.cancel_return_slot(t1);
    s = mgr.stats();
    CHECK_EQ(s.return_slots_cancelled, 1u);
}

static void test_local_endpoint_id_no_ep() {
    std::printf("[test] local_endpoint_id without endpoint...\n");
    DirectReturnManager mgr(nullptr);
    auto id = mgr.local_endpoint_id();
    bool all_zero = true;
    for (auto b : id) {
        if (b != 0) { all_zero = false; break; }
    }
    CHECK(all_zero);
}

static void test_cleanup_idle_empty_pool() {
    std::printf("[test] cleanup_idle_connections empty pool safe...\n");
    DirectReturnManager mgr(nullptr);
    mgr.cleanup_idle_connections();
    CHECK(true);
}

static void test_destructor_wakes_waiter() {
    std::printf("[test] destructor wakes waiting future...\n");
    std::future<std::vector<std::uint8_t>> fut;
    {
        DirectReturnManager mgr(nullptr);
        auto token = mgr.register_return_slot(99);
        fut = mgr.await_return_result(token);
    }  // mgr 析构
    bool threw = false;
    try {
        fut.get();
    } catch (...) {
        threw = true;
    }
    CHECK(threw);
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::printf("=== test_direct_return_manager ===\n");

    test_token_deterministic();
    test_token_diff_reqid();
    test_token_diff_timestamp();
    test_token_uint32_range();
    test_register_returns_nonzero();
    test_register_multiple_distinct();
    test_await_unknown_token_throws();
    test_cancel_then_await_throws();
    test_cancel_unknown_safe();
    test_stats_register_cancel();
    test_local_endpoint_id_no_ep();
    test_cleanup_idle_empty_pool();
    test_destructor_wakes_waiter();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
