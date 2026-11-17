// test_happy_eyeballs.cpp — Happy Eyeballs v2 测试（P4-B-2）
//
// 覆盖：
//   - HappyEyeballsOptions 默认值
//   - resolve_and_sort IPv6 优先 + 交替排列
//   - resolve_and_sort 仅 IPv4
//   - resolve_and_sort 仅 IPv6
//   - resolve_and_sort 不存在的主机
//   - happy_eyeballs_probe 不可达目标优雅降级
//   - happy_eyeballs_probe disabled 模式（顺序尝试）
//   - happy_eyeballs_probe_async 异步返回
//   - HappyEyeballsResult 数据结构完整性

#include "linoh/net/happy_eyeballs.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <future>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

using namespace linoh::net;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 测试 1: HappyEyeballsOptions 默认值
// ============================================================================
static void test_default_options() {
    std::printf("[test] HappyEyeballsOptions default values...\n");

    HappyEyeballsOptions opts;
    CHECK(opts.concurrency == 2);
    CHECK(opts.connection_attempt_delay.count() == 250);
    CHECK(opts.probe_timeout.count() == 2000);
    CHECK(opts.enable_ipv6 == true);
    CHECK(opts.enabled == true);
}

// ============================================================================
// 测试 2: resolve_and_sort - localhost 应返回 127.0.0.1 和/或 ::1
// ============================================================================
static void test_resolve_localhost() {
    std::printf("[test] resolve_and_sort localhost...\n");

    auto candidates = resolve_and_sort("localhost", 19302, true);
    CHECK(!candidates.empty());

    // localhost 应至少解析到 127.0.0.1
    bool has_v4_loopback = false;
    bool has_v6_loopback = false;
    for (auto &c : candidates) {
        if (c.ip == "127.0.0.1") has_v4_loopback = true;
        if (c.ip == "::1") has_v6_loopback = true;
        CHECK(c.port == 19302);
    }
    CHECK(has_v4_loopback);

    // 如果有 IPv6，IPv6 应排在 IPv4 前面（RFC 8305 §4）
    if (has_v6_loopback && has_v4_loopback) {
        // 找到第一个 IPv6 和第一个 IPv4 的位置
        int v6_idx = -1, v4_idx = -1;
        for (int i = 0; i < static_cast<int>(candidates.size()); ++i) {
            if (candidates[i].is_v6 && v6_idx < 0) v6_idx = i;
            if (!candidates[i].is_v6 && v4_idx < 0) v4_idx = i;
        }
        CHECK(v6_idx < v4_idx);  // IPv6 优先
    }
}

// ============================================================================
// 测试 3: resolve_and_sort - 纯 IPv4 模式
// ============================================================================
static void test_resolve_ipv4_only() {
    std::printf("[test] resolve_and_sort IPv4 only...\n");

    auto candidates = resolve_and_sort("127.0.0.1", 19302, true);
    CHECK(candidates.size() == 1);
    CHECK(candidates[0].ip == "127.0.0.1");
    CHECK(candidates[0].is_v6 == false);
    CHECK(candidates[0].port == 19302);
}

// ============================================================================
// 测试 4: resolve_and_sort - 纯 IPv6 地址
// ============================================================================
static void test_resolve_ipv6_address() {
    std::printf("[test] resolve_and_sort IPv6 address...\n");

    auto candidates = resolve_and_sort("::1", 19302, true);
    CHECK(candidates.size() == 1);
    CHECK(candidates[0].is_v6 == true);
    CHECK(candidates[0].port == 19302);
}

// ============================================================================
// 测试 5: resolve_and_sort - enable_ipv6=false 时无 IPv6
// ============================================================================
static void test_resolve_ipv6_disabled() {
    std::printf("[test] resolve_and_sort with IPv6 disabled...\n");

    auto candidates = resolve_and_sort("localhost", 19302, false);
    CHECK(!candidates.empty());
    for (auto &c : candidates) {
        CHECK(c.is_v6 == false);  // 不应有 IPv6
    }
}

// ============================================================================
// 测试 6: resolve_and_sort - 不存在的主机名
// ============================================================================
static void test_resolve_nonexistent_host() {
    std::printf("[test] resolve_and_sort nonexistent host...\n");

    auto candidates = resolve_and_sort("nonexistent.invalid.domain.example", 19302, true);
    CHECK(candidates.empty());
}

// ============================================================================
// 测试 7: happy_eyeballs_probe - 不可达目标优雅降级
// ============================================================================
static void test_probe_unreachable_graceful() {
    std::printf("[test] happy_eyeballs_probe unreachable graceful...\n");

    HappyEyeballsOptions opts;
    opts.probe_timeout = std::chrono::milliseconds(100);
    opts.concurrency = 2;

    // 192.0.2.1 是 TEST-NET-1，不可路由
    auto result = happy_eyeballs_probe("192.0.2.1", 19302, opts);

    // 失败时 result.ip 应为空
    CHECK(result.ip.empty());
    CHECK(result.port == 0);

    // 候选列表应有内容
    CHECK(!result.candidates.empty());
    for (auto &c : result.candidates) {
        CHECK(c.success == false);
        CHECK(!c.error.empty());
    }
}

// ============================================================================
// 测试 8: happy_eyeballs_probe - disabled 模式顺序尝试
// ============================================================================
static void test_probe_disabled_mode() {
    std::printf("[test] happy_eyeballs_probe disabled mode...\n");

    HappyEyeballsOptions opts;
    opts.enabled = false;
    opts.probe_timeout = std::chrono::milliseconds(100);

    auto result = happy_eyeballs_probe("192.0.2.1", 19302, opts);

    // 失败时 result.ip 应为空
    CHECK(result.ip.empty());

    // disabled 模式下候选应按顺序尝试
    CHECK(!result.candidates.empty());
    for (auto &c : result.candidates) {
        CHECK(c.success == false);
    }
}

// ============================================================================
// 测试 9: happy_eyeballs_probe_async - 异步返回
// ============================================================================
static void test_probe_async_returns_future() {
    std::printf("[test] happy_eyeballs_probe_async returns future...\n");

    HappyEyeballsOptions opts;
    opts.probe_timeout = std::chrono::milliseconds(50);

    auto future = happy_eyeballs_probe_async("192.0.2.1", 19302, opts);
    CHECK(future.valid());

    auto status = future.wait_for(std::chrono::seconds(30));
    CHECK(status == std::future_status::ready);

    auto result = future.get();
    CHECK(result.ip.empty());  // 不可达，ip 应为空
}

// ============================================================================
// 测试 10: HappyEyeballsResult 数据结构完整性
// ============================================================================
static void test_result_structure() {
    std::printf("[test] HappyEyeballsResult structure...\n");

    HappyEyeballsResult r;
    CHECK(r.ip.empty());
    CHECK(r.port == 0);
    CHECK(r.is_v6 == false);
    CHECK(r.rtt.count() == 0);
    CHECK(r.candidates.empty());

    // 填充候选
    HappyEyeballsResult::Candidate c;
    c.ip = "1.2.3.4";
    c.port = 5678;
    c.is_v6 = false;
    c.success = true;
    c.rtt = std::chrono::microseconds(10000);
    r.candidates.push_back(c);

    CHECK(r.candidates.size() == 1);
    CHECK(r.candidates[0].ip == "1.2.3.4");
    CHECK(r.candidates[0].port == 5678);
    CHECK(r.candidates[0].success == true);
}

// ============================================================================
// 测试 11: resolve_and_sort 交替排列验证
// ============================================================================
static void test_interleave_order() {
    std::printf("[test] resolve_and_sort interleave order...\n");

    // 用 IP 地址直接测试（避免 DNS 不稳定）
    // 127.0.0.1 和 ::1 都是 loopback，应能解析
    auto candidates = resolve_and_sort("localhost", 19302, true);

    if (candidates.size() >= 2) {
        bool has_v6 = false, has_v4 = false;
        for (auto &c : candidates) {
            if (c.is_v6) has_v6 = true;
            else has_v4 = true;
        }

        if (has_v6 && has_v4) {
            // 第一个应是 IPv6
            CHECK(candidates[0].is_v6 == true);
            // 第二个应是 IPv4（交替）
            CHECK(candidates[1].is_v6 == false);
        }
    }
}

// ============================================================================
// 测试 12: happy_eyeballs_probe - 自定义并发数
// ============================================================================
static void test_probe_custom_concurrency() {
    std::printf("[test] happy_eyeballs_probe custom concurrency...\n");

    HappyEyeballsOptions opts;
    opts.concurrency = 1;  // 单线程并发
    opts.probe_timeout = std::chrono::milliseconds(100);

    auto result = happy_eyeballs_probe("192.0.2.1", 19302, opts);
    CHECK(result.ip.empty());  // 不可达
    CHECK(!result.candidates.empty());
}

// ============================================================================
// 测试 13: happy_eyeballs_probe - 短超时快速失败
// ============================================================================
static void test_probe_short_timeout() {
    std::printf("[test] happy_eyeballs_probe short timeout...\n");

    HappyEyeballsOptions opts;
    opts.probe_timeout = std::chrono::milliseconds(10);
    opts.concurrency = 2;

    auto start = std::chrono::steady_clock::now();
    auto result = happy_eyeballs_probe("192.0.2.1", 19302, opts);
    auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(result.ip.empty());
    // 应在合理时间内返回（短超时）
    CHECK(elapsed < std::chrono::seconds(5));
}

// ============================================================================
// 测试 14: 并发调用 happy_eyeballs_probe
// ============================================================================
static void test_concurrent_probe_calls() {
    std::printf("[test] concurrent happy_eyeballs_probe calls...\n");

    HappyEyeballsOptions opts;
    opts.probe_timeout = std::chrono::milliseconds(50);

    std::atomic<int> success_count{0};
    std::atomic<int> failure_count{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&opts, &success_count, &failure_count]() {
            auto result = happy_eyeballs_probe("192.0.2.1", 19302, opts);
            if (result.ip.empty()) {
                ++failure_count;
            } else {
                ++success_count;
            }
        });
    }
    for (auto &t : threads) t.join();

    // 全部应失败（不可达目标）
    CHECK(success_count.load() == 0);
    CHECK(failure_count.load() == 4);
}

// ============================================================================
// 测试 15: HappyEyeballsOptions 自定义值
// ============================================================================
static void test_custom_options() {
    std::printf("[test] HappyEyeballsOptions custom values...\n");

    HappyEyeballsOptions opts;
    opts.concurrency = 4;
    opts.connection_attempt_delay = std::chrono::milliseconds(500);
    opts.probe_timeout = std::chrono::milliseconds(5000);
    opts.enable_ipv6 = false;
    opts.enabled = false;

    CHECK(opts.concurrency == 4);
    CHECK(opts.connection_attempt_delay.count() == 500);
    CHECK(opts.probe_timeout.count() == 5000);
    CHECK(opts.enable_ipv6 == false);
    CHECK(opts.enabled == false);
}

int main() {
    std::printf("=== test_happy_eyeballs ===\n");

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::printf("WSAStartup failed\n");
        return 1;
    }
#endif

    test_default_options();
    test_resolve_localhost();
    test_resolve_ipv4_only();
    test_resolve_ipv6_address();
    test_resolve_ipv6_disabled();
    test_resolve_nonexistent_host();
    test_probe_unreachable_graceful();
    test_probe_disabled_mode();
    test_probe_async_returns_future();
    test_result_structure();
    test_interleave_order();
    test_probe_custom_concurrency();
    test_probe_short_timeout();
    test_concurrent_probe_calls();
    test_custom_options();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
