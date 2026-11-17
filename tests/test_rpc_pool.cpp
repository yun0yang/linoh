// test_rpc_pool.cpp — P1-1 RPC Stream 复用测试
//
// 验证：
//   1. acquire_rpc_stream() 池空时新建 stream
//   2. release_rpc_stream() 归还后池大小递增
//   3. acquire 优先复用池中 stream（不新建）
//   4. 池上限 kRpcStreamPoolMax=32（超过不归还）
//   5. 已 close/fin_sent 的 stream 不归还
//   6. acquire 时若池中 stream 已 close/fin，跳过新建
//   7. register_request_stream / take_request_stream 基本逻辑
//   8. take_request_stream 取出后映射消失（不可重复取）
//   9. on_close 清理池和映射
//  10. 并发 acquire/release 无死锁、无重复

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

// 创建一个处于 Established 状态的 Connection
static std::shared_ptr<Connection> make_established_conn() {
    auto conn = std::make_shared<Connection>(make_test_cfg());
    conn->force_psk_established();
    return conn;
}

// ---------------------------------------------------------------------------
// 1. acquire 池空时新建 stream
// ---------------------------------------------------------------------------
static void test_acquire_new_when_pool_empty() {
    std::printf("[test] acquire_rpc_stream 池空时新建 stream...\n");
    auto conn = make_established_conn();
    CHECK(conn->rpc_stream_pool_size() == 0);

    auto s = conn->acquire_rpc_stream();
    CHECK(s != nullptr);
    CHECK(conn->rpc_stream_pool_size() == 0);  // 取走后池仍空
    CHECK(conn->rpc_in_flight_count() == 0);
}

// ---------------------------------------------------------------------------
// 2. release 归还后池大小递增
// ---------------------------------------------------------------------------
static void test_release_increases_pool() {
    std::printf("[test] release_rpc_stream 归还后池大小递增...\n");
    auto conn = make_established_conn();
    auto s = conn->acquire_rpc_stream();
    CHECK(conn->rpc_stream_pool_size() == 0);

    conn->release_rpc_stream(s);
    CHECK(conn->rpc_stream_pool_size() == 1);
}

// ---------------------------------------------------------------------------
// 3. acquire 优先复用池中 stream
// ---------------------------------------------------------------------------
static void test_acquire_reuses_pooled_stream() {
    std::printf("[test] acquire 优先复用池中 stream...\n");
    auto conn = make_established_conn();
    auto s1 = conn->acquire_rpc_stream();
    auto id1 = s1->id();
    conn->release_rpc_stream(s1);

    auto s2 = conn->acquire_rpc_stream();
    CHECK(s2 != nullptr);
    CHECK(s2->id() == id1);  // 复用同一 stream
    CHECK(conn->rpc_stream_pool_size() == 0);
}

// ---------------------------------------------------------------------------
// 4. 池上限 kRpcStreamPoolMax=32
// ---------------------------------------------------------------------------
static void test_pool_max_limit() {
    std::printf("[test] 池上限 kRpcStreamPoolMax=32...\n");
    auto conn = make_established_conn();

    // 归还 32 个 stream（应全部入池）
    std::vector<std::shared_ptr<Stream>> streams;
    for (std::size_t i = 0; i < Connection::kRpcStreamPoolMax; ++i) {
        streams.push_back(conn->acquire_rpc_stream());
    }
    for (auto &s : streams) {
        conn->release_rpc_stream(s);
    }
    CHECK(conn->rpc_stream_pool_size() == Connection::kRpcStreamPoolMax);

    // 第 33 个 stream 归还应被拒绝（池满）
    auto extra = conn->acquire_rpc_stream();
    conn->release_rpc_stream(extra);
    CHECK(conn->rpc_stream_pool_size() == Connection::kRpcStreamPoolMax);
}

// ---------------------------------------------------------------------------
// 5. 已 close/fin_sent 的 stream 不归还
// ---------------------------------------------------------------------------
static void test_closed_stream_not_returned() {
    std::printf("[test] 已 close/fin_sent 的 stream 不归还...\n");
    auto conn = make_established_conn();

    // 已发 FIN 的 stream 不归还
    auto s1 = conn->acquire_rpc_stream();
    s1->finish_send();  // 模拟已发 FIN
    conn->release_rpc_stream(s1);
    CHECK(conn->rpc_stream_pool_size() == 0);

    // 已 close 的 stream 不归还
    auto s2 = conn->acquire_rpc_stream();
    s2->close();  // 模拟已关闭
    conn->release_rpc_stream(s2);
    CHECK(conn->rpc_stream_pool_size() == 0);
}

// ---------------------------------------------------------------------------
// 6. acquire 时池中 stream 已 close/fin，跳过新建
// ---------------------------------------------------------------------------
static void test_acquire_skips_invalid_pooled_stream() {
    std::printf("[test] acquire 时跳过池中已失效 stream...\n");
    auto conn = make_established_conn();

    // 归还一个 stream，然后标记为已发 FIN
    auto s1 = conn->acquire_rpc_stream();
    auto id1 = s1->id();
    conn->release_rpc_stream(s1);
    s1->finish_send();  // 模拟外部关闭（极端场景）

    // acquire 应跳过失效 stream，新建一个
    auto s2 = conn->acquire_rpc_stream();
    CHECK(s2 != nullptr);
    CHECK(s2->id() != id1);  // 新建了不同的 stream
    CHECK(conn->rpc_stream_pool_size() == 0);
}

// ---------------------------------------------------------------------------
// 7. register_request_stream / take_request_stream 基本逻辑
// ---------------------------------------------------------------------------
static void test_register_and_take_request_stream() {
    std::printf("[test] register_request_stream / take_request_stream 基本逻辑...\n");
    auto conn = make_established_conn();
    auto s = conn->acquire_rpc_stream();

    conn->register_request_stream(42, s);
    auto taken = conn->take_request_stream(42);
    CHECK(taken != nullptr);
    CHECK(taken->id() == s->id());
}

// ---------------------------------------------------------------------------
// 8. take_request_stream 取出后映射消失
// ---------------------------------------------------------------------------
static void test_take_removes_mapping() {
    std::printf("[test] take_request_stream 取出后映射消失...\n");
    auto conn = make_established_conn();
    auto s = conn->acquire_rpc_stream();

    conn->register_request_stream(99, s);
    auto t1 = conn->take_request_stream(99);
    CHECK(t1 != nullptr);

    // 第二次取应返回 nullptr
    auto t2 = conn->take_request_stream(99);
    CHECK(t2 == nullptr);
}

// ---------------------------------------------------------------------------
// 9. take_request_stream 对不存在的 req_id 返回 nullptr
// ---------------------------------------------------------------------------
static void test_take_nonexistent_returns_null() {
    std::printf("[test] take_request_stream 不存在 req_id 返回 nullptr...\n");
    auto conn = make_established_conn();
    auto t = conn->take_request_stream(12345);
    CHECK(t == nullptr);
}

// ---------------------------------------------------------------------------
// 10. register 后 stream 被 close，take 返回 nullptr
// ---------------------------------------------------------------------------
static void test_take_closed_stream_returns_null() {
    std::printf("[test] take_request_stream 已 close 的 stream 返回 nullptr...\n");
    auto conn = make_established_conn();
    auto s = conn->acquire_rpc_stream();

    conn->register_request_stream(7, s);
    s->close();  // 模拟 stream 关闭

    auto t = conn->take_request_stream(7);
    CHECK(t == nullptr);
}

// ---------------------------------------------------------------------------
// 11. on_close 清理池和映射
// ---------------------------------------------------------------------------
static void test_on_close_clears_pool() {
    std::printf("[test] on_close 清理池和映射...\n");
    auto conn = make_established_conn();

    // 攒一些 stream 到池和映射
    auto s1 = conn->acquire_rpc_stream();
    auto s2 = conn->acquire_rpc_stream();
    conn->release_rpc_stream(s1);
    conn->register_request_stream(100, s2);

    CHECK(conn->rpc_stream_pool_size() == 1);

    conn->close(0, "test");

    CHECK(conn->rpc_stream_pool_size() == 0);
    CHECK(conn->rpc_in_flight_count() == 0);
    // take 应返回 nullptr（映射已清理）
    CHECK(conn->take_request_stream(100) == nullptr);
}

// ---------------------------------------------------------------------------
// 12. 并发 acquire/release 无死锁、无重复
// ---------------------------------------------------------------------------
static void test_concurrent_acquire_release() {
    std::printf("[test] 并发 acquire/release 无死锁...\n");
    auto conn = make_established_conn();

    constexpr int kThreads = 4;
    constexpr int kItersPerThread = 100;
    std::atomic<int> acquire_ok{0};
    std::atomic<int> release_ok{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < kItersPerThread; ++i) {
                auto s = conn->acquire_rpc_stream();
                if (s) {
                    acquire_ok.fetch_add(1);
                    conn->release_rpc_stream(s);
                    release_ok.fetch_add(1);
                }
            }
        });
    }
    for (auto &t : threads) t.join();

    CHECK(acquire_ok.load() == kThreads * kItersPerThread);
    CHECK(release_ok.load() == kThreads * kItersPerThread);
    // 池大小不应超过上限
    CHECK(conn->rpc_stream_pool_size() <= Connection::kRpcStreamPoolMax);
}

// ---------------------------------------------------------------------------
// 13. 连续多次 call 后 pool 维持稳定（不无限增长）
//    模拟：acquire → release 循环 N 次，pool 大小应稳定在 1
// ---------------------------------------------------------------------------
static void test_repeated_acquire_release_stable() {
    std::printf("[test] 连续 acquire/release 循环 pool 大小稳定...\n");
    auto conn = make_established_conn();

    for (int i = 0; i < 50; ++i) {
        auto s = conn->acquire_rpc_stream();
        CHECK(s != nullptr);
        conn->release_rpc_stream(s);
    }
    // 50 次循环后，pool 大小应为 1（复用同一 stream）
    CHECK(conn->rpc_stream_pool_size() == 1);
}

int main() {
    std::printf("=== P1-1 RPC Stream 复用测试 ===\n\n");

    test_acquire_new_when_pool_empty();
    test_release_increases_pool();
    test_acquire_reuses_pooled_stream();
    test_pool_max_limit();
    test_closed_stream_not_returned();
    test_acquire_skips_invalid_pooled_stream();
    test_register_and_take_request_stream();
    test_take_removes_mapping();
    test_take_nonexistent_returns_null();
    test_take_closed_stream_returns_null();
    test_on_close_clears_pool();
    test_concurrent_acquire_release();
    test_repeated_acquire_release_stable();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
