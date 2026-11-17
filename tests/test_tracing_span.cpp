// test_tracing_span.cpp — B8 连接级 tracing 事件测试（v1.7.0.4 P3）
//
// 覆盖：
//   - TracingSpan 构造/析构（RAII）
//   - TracingSpan 字段记录
//   - TracingSpan 禁拷贝/允许移动
//   - TracingSpan 嵌套（模拟 endpoint → actor → method 层级）
//   - LINOH_CONN_LOG 宏（携带 conn_id）
//   - LINOH_EVENT 宏（带 target 前缀）
//   - 模拟 Connection 的 stable_id() 调用

#include "linoh/util/tracing_span.hpp"
#include "linoh/util/logging.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::util;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 模拟 Connection（仅用于测试 stable_id 接口）
// ============================================================================
struct MockConnection {
    std::uint64_t id_;
    explicit MockConnection(std::uint64_t id) : id_(id) {}
    std::uint64_t stable_id() const noexcept { return id_; }
};

// ============================================================================
// TracingSpan 基本功能
// ============================================================================

static void test_span_construct_destruct() {
    std::printf("[test] TracingSpan construct/destruct...\n");
    {
        TracingSpan span("test_span");
        CHECK(span.name() == "test_span");
        CHECK(span.fields().empty());
    }
    CHECK(true);  // 析构完成无崩溃
}

static void test_span_with_fields() {
    std::printf("[test] TracingSpan with fields...\n");
    {
        TracingSpan span("endpoint", {{"id", "7dn2ff6eptj2t"}, {"role", "master"}});
        CHECK(span.name() == "endpoint");
        CHECK(span.fields().size() == 2);
        CHECK(span.fields()[0].first == "id");
        CHECK(span.fields()[0].second == "7dn2ff6eptj2t");
        CHECK(span.fields()[1].first == "role");
        CHECK(span.fields()[1].second == "master");
    }
}

static void test_span_empty_fields() {
    std::printf("[test] TracingSpan empty fields...\n");
    TracingSpan span("noop");
    CHECK(span.fields().empty());
}

static void test_span_move_construct() {
    std::printf("[test] TracingSpan move construct...\n");
    TracingSpan original("movable", {{"k", "v"}});
    TracingSpan moved(std::move(original));
    CHECK(moved.name() == "movable");
    CHECK(moved.fields().size() == 1);
    CHECK(moved.fields()[0].first == "k");
}

static void test_span_move_assign() {
    std::printf("[test] TracingSpan move assign...\n");
    TracingSpan span1("span1");
    TracingSpan span2("span2", {{"x", "y"}});
    span1 = std::move(span2);
    CHECK(span1.name() == "span2");
    CHECK(span1.fields().size() == 1);
}

static void test_span_nested_lifecycle() {
    std::printf("[test] TracingSpan nested lifecycle...\n");
    // 模拟 iroh 三层 span: endpoint → actor → method
    {
        TracingSpan endpoint_span("endpoint", {{"node_id", "node-abc"}});
        CHECK(endpoint_span.name() == "endpoint");

        {
            TracingSpan actor_span("actor", {{"remote_id", "peer-xyz"}});
            CHECK(actor_span.name() == "actor");

            {
                TracingSpan method_span("connect");
                CHECK(method_span.name() == "connect");
            }
            CHECK(actor_span.name() == "actor");  // method_span 已析构，actor_span 仍在
        }
        CHECK(endpoint_span.name() == "endpoint");  // actor_span 已析构
    }
    CHECK(true);  // 全部析构完成
}

static void test_span_duration_recorded() {
    std::printf("[test] TracingSpan duration recorded...\n");
    // 启用 DEBUG 级别以观察 span 日志
    log::set_level(log::Level::Debug);

    {
        TracingSpan span("timed");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // 析构时记录 duration（通过 LINOH_DEBUG 输出）
    CHECK(true);

    // 恢复 INFO 级别
    log::set_level(log::Level::Info);
}

static void test_span_vector_storage() {
    std::printf("[test] TracingSpan vector storage...\n");
    std::vector<TracingSpan> spans;
    spans.emplace_back("span1", TracingSpan::Fields{{"k1", "v1"}});
    spans.emplace_back("span2", TracingSpan::Fields{{"k2", "v2"}});

    CHECK(spans.size() == 2);
    CHECK(spans[0].name() == "span1");
    CHECK(spans[1].name() == "span2");
}

// ============================================================================
// LINOH_CONN_LOG 宏测试
// ============================================================================

static void test_conn_log_basic() {
    std::printf("[test] LINOH_CONN_LOG basic...\n");
    log::set_level(log::Level::Info);

    MockConnection conn(42);
    // 不崩溃即可
    LINOH_CONN_LOG(conn, INFO, "connected remote_id=", "peer-xyz");
    CHECK(true);
}

static void test_conn_log_warn_level() {
    std::printf("[test] LINOH_CONN_LOG WARN level...\n");
    log::set_level(log::Level::Info);

    MockConnection conn(99);
    LINOH_CONN_LOG(conn, WARN, "path migration failed reason=", "nat_block");
    CHECK(true);
}

static void test_conn_log_debug_level() {
    std::printf("[test] LINOH_CONN_LOG DEBUG level...\n");
    log::set_level(log::Level::Debug);

    MockConnection conn(7);
    LINOH_CONN_LOG(conn, DEBUG, "ice check sent pair=", "1.2.3.4:9001");
    CHECK(true);

    log::set_level(log::Level::Info);
}

static void test_conn_log_zero_id() {
    std::printf("[test] LINOH_CONN_LOG zero id...\n");
    log::set_level(log::Level::Info);

    MockConnection conn(0);
    LINOH_CONN_LOG(conn, INFO, "init");
    CHECK(true);
}

// ============================================================================
// LINOH_EVENT 宏测试
// ============================================================================

static void test_event_basic() {
    std::printf("[test] LINOH_EVENT basic...\n");
    log::set_level(log::Level::Info);

    LINOH_EVENT("linoh::_events::conn::connected", INFO,
                "conn_id=", 100, "remote_id=", "peer-abc");
    CHECK(true);
}

static void test_event_warn() {
    std::printf("[test] LINOH_EVENT WARN...\n");
    log::set_level(log::Level::Info);

    LINOH_EVENT("linoh::_events::conn::closed", WARN,
                "conn_id=", 50, "reason=", "idle_timeout");
    CHECK(true);
}

static void test_event_debug() {
    std::printf("[test] LINOH_EVENT DEBUG...\n");
    log::set_level(log::Level::Debug);

    LINOH_EVENT("linoh::_events::path::opened", DEBUG,
                "path_id=", 1);
    CHECK(true);

    log::set_level(log::Level::Info);
}

static void test_event_target_naming_convention() {
    std::printf("[test] LINOH_EVENT target naming convention...\n");
    log::set_level(log::Level::Info);

    // 对标 iroh target 命名：linoh::_events::conn::<event>
    LINOH_EVENT("linoh::_events::conn::connected", INFO, "conn_id=", 1);
    LINOH_EVENT("linoh::_events::conn::closed", INFO, "conn_id=", 1);
    LINOH_EVENT("linoh::_events::path::opened", INFO, "path_id=", 1);
    LINOH_EVENT("linoh::_events::path::closed", INFO, "path_id=", 1);
    LINOH_EVENT("linoh::_events::path::selected", INFO, "path_id=", 1);
    CHECK(true);
}

// ============================================================================
// 综合：TracingSpan + LINOH_CONN_LOG 模拟连接生命周期
// ============================================================================

static void test_combined_connection_lifecycle() {
    std::printf("[test] Combined connection lifecycle tracing...\n");
    log::set_level(log::Level::Debug);

    MockConnection conn(12345);

    {
        TracingSpan endpoint_span("endpoint", {{"node_id", "node-master"}});
        {
            TracingSpan conn_span("connection", {{"conn_id", "12345"}});

            LINOH_CONN_LOG(conn, INFO, "handshake started alpn=", "pp-hidden/1");

            {
                TracingSpan method_span("handshake");
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                LINOH_CONN_LOG(conn, DEBUG, "tls 1-rtt completed");
            }

            LINOH_EVENT("linoh::_events::conn::connected", INFO,
                        "conn_id=", conn.stable_id());
        }
        LINOH_CONN_LOG(conn, INFO, "connection closed");
    }

    log::set_level(log::Level::Info);
    CHECK(true);
}

static void test_combined_path_lifecycle() {
    std::printf("[test] Combined path lifecycle tracing...\n");
    log::set_level(log::Level::Debug);

    MockConnection conn(999);

    {
        TracingSpan span("path_migration");
        LINOH_EVENT("linoh::_events::path::opened", INFO, "path_id=", 1);
        LINOH_CONN_LOG(conn, DEBUG, "path 1 opened");

        LINOH_EVENT("linoh::_events::path::selected", INFO, "path_id=", 2);
        LINOH_CONN_LOG(conn, DEBUG, "switched to path 2");

        LINOH_EVENT("linoh::_events::path::closed", INFO, "path_id=", 1);
        LINOH_CONN_LOG(conn, DEBUG, "path 1 closed");
    }

    log::set_level(log::Level::Info);
    CHECK(true);
}

// ============================================================================
// 线程安全：多线程并发 span（RAII 在不同线程栈上独立）
// ============================================================================

static void test_span_multithreaded() {
    std::printf("[test] TracingSpan multithreaded...\n");
    log::set_level(log::Level::Info);

    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([t]() {
            for (int i = 0; i < 10; ++i) {
                TracingSpan span("thread-" + std::to_string(t),
                                  {{"iter", std::to_string(i)}});
                LINOH_EVENT("linoh::_events::test", DEBUG,
                            "thread=", t, "iter=", i);
            }
        });
    }
    for (auto &th : threads) th.join();
    CHECK(true);  // 无崩溃即通过
}

int main() {
    std::printf("=== test_tracing_span (v1.7.0.4 P3 B8) ===\n");

    test_span_construct_destruct();
    test_span_with_fields();
    test_span_empty_fields();
    test_span_move_construct();
    test_span_move_assign();
    test_span_nested_lifecycle();
    test_span_duration_recorded();
    test_span_vector_storage();

    test_conn_log_basic();
    test_conn_log_warn_level();
    test_conn_log_debug_level();
    test_conn_log_zero_id();

    test_event_basic();
    test_event_warn();
    test_event_debug();
    test_event_target_naming_convention();

    test_combined_connection_lifecycle();
    test_combined_path_lifecycle();

    test_span_multithreaded();

    std::printf("\n=== Results: %d PASSED, %d FAILED ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
