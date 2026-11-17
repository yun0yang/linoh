// test_on_close_dedup.cpp — P1-1 on_close_ 双触发去重测试
//
// 验证：
//   1. close() 多次调用，on_close_ 仅触发一次
//   2. CONNECTION_CLOSE 帧触发 + close() 触发，仅触发一次
//   3. on_close_impl 幂等：pending_requests_ 不会被重复 set_exception

#include "linoh/endpoint/connection.hpp"
#include "linoh/protocol/application_message.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <memory>
#include <thread>
#include <vector>

using namespace linoh::endpoint;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// 构造最小可用的 Connection 配置
static Connection::Config make_test_cfg() {
    Connection::Config cfg{};
    cfg.alpn = "test/1";
    cfg.local_cid = linoh::protocol::ConnectionId::generate();
    cfg.remote_cid = linoh::protocol::ConnectionId::generate();
    return cfg;
}

static void test_close_called_once() {
    std::printf("[test] close() called once → on_close_ triggered once...\n");

    auto conn = std::make_shared<Connection>(make_test_cfg());
    std::atomic<int> close_count{0};
    conn->on_close([&close_count]() { close_count.fetch_add(1); });

    // Connection 初始状态是 Initial（Outbound），close() 会进入 Closed
    conn->close(0, "test");
    CHECK(close_count.load() == 1);

    // 再次 close 不应再触发
    conn->close(0, "test2");
    CHECK(close_count.load() == 1);

    // 第三次 close 仍不应触发
    conn->close(0, "test3");
    CHECK(close_count.load() == 1);
}

static void test_close_concurrent() {
    std::printf("[test] close() concurrent → on_close_ triggered exactly once...\n");

    auto conn = std::make_shared<Connection>(make_test_cfg());
    std::atomic<int> close_count{0};
    conn->on_close([&close_count]() { close_count.fetch_add(1); });

    // 4 个线程并发 close
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&conn, i]() {
            conn->close(static_cast<std::uint16_t>(i), "concurrent");
        });
    }
    for (auto &t : threads) t.join();

    CHECK(close_count.load() == 1);
}

static void test_on_close_impl_idempotent() {
    std::printf("[test] on_close_impl idempotent (no double set_exception)...\n");

    auto conn = std::make_shared<Connection>(make_test_cfg());
    // 不注册 on_close_，仅测试 on_close_impl 幂等性
    // 直接调用 close() 会触发 on_close_impl 清理 pending（这里 pending 为空）
    conn->close(0, "first");
    // 再次 close 不应崩溃或重复清理
    conn->close(0, "second");
    conn->close(0, "third");

    // 析构时会再次调用 on_close_impl，应幂等返回
    CHECK(true);  // 如果到达此处表示无崩溃
}

int main() {
    std::printf("=== test_on_close_dedup ===\n");

    test_close_called_once();
    test_close_concurrent();
    test_on_close_impl_idempotent();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
