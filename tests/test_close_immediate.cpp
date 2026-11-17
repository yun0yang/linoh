// test_close_immediate.cpp — P4-A-3 Immediate Close 测试
//
// 验收标准：
//   1. Immediate 模式下状态机直接到 Closed（跳过 Closing 中间状态）
//   2. C-API linoh_connection_close_immediate 调用后 linoh_connection_state 返回 CLOSED
//   3. 现有 on_close 去重逻辑在 Immediate 模式下保持正确
//
// 借鉴 iroh PR #4270：CloseMode { Graceful, Immediate }

#include "linoh/endpoint/connection.hpp"
#include "linoh/linoh_c.h"

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

// 构造最小可用的 Connection 配置（参考 test_on_close_dedup.cpp）
static Connection::Config make_test_cfg() {
    Connection::Config cfg{};
    cfg.alpn = "test/1";
    cfg.local_cid = linoh::protocol::ConnectionId::generate();
    cfg.remote_cid = linoh::protocol::ConnectionId::generate();
    return cfg;
}

// ============================================================================
// 测试 1: Immediate 模式从 Established 直接跳到 Closed
// ============================================================================
static void test_immediate_from_established() {
    std::printf("[test] Immediate close from Established -> Closed...\n");

    auto conn = std::make_shared<Connection>(make_test_cfg());
    // 强制进入 Established 状态（模拟握手完成）
    conn->force_psk_established();
    CHECK(conn->state() == ConnState::Established);

    // 调用 close_immediate
    conn->close_immediate(0, "test immediate");
    CHECK(conn->state() == ConnState::Closed);
}

// ============================================================================
// 测试 2: Immediate 模式从 Initial 直接跳到 Closed
// ============================================================================
static void test_immediate_from_initial() {
    std::printf("[test] Immediate close from Initial -> Closed...\n");

    auto conn = std::make_shared<Connection>(make_test_cfg());
    // Connection 默认在 Initial 状态
    CHECK(conn->state() == ConnState::Initial);

    conn->close_immediate(0, "initial exit");
    CHECK(conn->state() == ConnState::Closed);
}

// ============================================================================
// 测试 3: Graceful 模式仍能正常工作（保留原有行为）
// ============================================================================
static void test_graceful_close_works() {
    std::printf("[test] Graceful close still works...\n");

    auto conn = std::make_shared<Connection>(make_test_cfg());
    conn->force_psk_established();
    CHECK(conn->state() == ConnState::Established);

    // 无参 close() 走 Graceful 路径
    conn->close(0, "graceful");
    CHECK(conn->state() == ConnState::Closed);

    // 显式指定 Graceful 模式
    auto conn2 = std::make_shared<Connection>(make_test_cfg());
    conn2->force_psk_established();
    conn2->close(0, "explicit graceful", Connection::CloseMode::Graceful);
    CHECK(conn2->state() == ConnState::Closed);
}

// ============================================================================
// 测试 4: Immediate close 触发 on_close_ 仅一次
// ============================================================================
static void test_immediate_triggers_on_close_once() {
    std::printf("[test] Immediate close triggers on_close_ exactly once...\n");

    auto conn = std::make_shared<Connection>(make_test_cfg());
    conn->force_psk_established();
    std::atomic<int> close_count{0};
    conn->on_close([&close_count]() { close_count.fetch_add(1); });

    conn->close_immediate(0, "first");
    CHECK(close_count.load() == 1);

    // 再次调用不应再触发
    conn->close_immediate(0, "second");
    CHECK(close_count.load() == 1);

    // 第三次仍不应触发
    conn->close_immediate(0, "third");
    CHECK(close_count.load() == 1);
}

// ============================================================================
// 测试 5: 多次 close_immediate 幂等（不崩溃，状态稳定）
// ============================================================================
static void test_immediate_idempotent() {
    std::printf("[test] close_immediate idempotent...\n");

    auto conn = std::make_shared<Connection>(make_test_cfg());
    conn->force_psk_established();

    conn->close_immediate(0, "1");
    ConnState s1 = conn->state();
    conn->close_immediate(0, "2");
    ConnState s2 = conn->state();
    conn->close_immediate(0, "3");
    ConnState s3 = conn->state();

    CHECK(s1 == ConnState::Closed);
    CHECK(s2 == ConnState::Closed);
    CHECK(s3 == ConnState::Closed);
}

// ============================================================================
// 测试 6: Immediate + Graceful 混合调用，on_close_ 仅触发一次
// ============================================================================
static void test_mixed_close_calls() {
    std::printf("[test] Mixed Immediate+Graceful close, on_close_ once...\n");

    // 先 Immediate 后 Graceful
    {
        auto conn = std::make_shared<Connection>(make_test_cfg());
        conn->force_psk_established();
        std::atomic<int> close_count{0};
        conn->on_close([&close_count]() { close_count.fetch_add(1); });

        conn->close_immediate(0, "immediate first");
        conn->close(0, "graceful after");
        CHECK(close_count.load() == 1);
        CHECK(conn->state() == ConnState::Closed);
    }

    // 先 Graceful 后 Immediate
    {
        auto conn = std::make_shared<Connection>(make_test_cfg());
        conn->force_psk_established();
        std::atomic<int> close_count{0};
        conn->on_close([&close_count]() { close_count.fetch_add(1); });

        conn->close(0, "graceful first");
        conn->close_immediate(0, "immediate after");
        CHECK(close_count.load() == 1);
        CHECK(conn->state() == ConnState::Closed);
    }
}

// ============================================================================
// 测试 7: 并发 close_immediate，on_close_ 仅触发一次
// ============================================================================
static void test_concurrent_close_immediate() {
    std::printf("[test] Concurrent close_immediate, on_close_ exactly once...\n");

    auto conn = std::make_shared<Connection>(make_test_cfg());
    conn->force_psk_established();
    std::atomic<int> close_count{0};
    conn->on_close([&close_count]() { close_count.fetch_add(1); });

    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&conn, i]() {
            conn->close_immediate(static_cast<std::uint16_t>(i), "concurrent");
        });
    }
    for (auto &t : threads) t.join();

    CHECK(close_count.load() == 1);
    CHECK(conn->state() == ConnState::Closed);
}

// ============================================================================
// 测试 8: 显式 close(code, reason, CloseMode::Immediate)
// ============================================================================
static void test_explicit_close_mode_immediate() {
    std::printf("[test] Explicit close(code, reason, CloseMode::Immediate)...\n");

    auto conn = std::make_shared<Connection>(make_test_cfg());
    conn->force_psk_established();

    // 显式指定 Immediate 模式
    conn->close(1234, "explicit immediate", Connection::CloseMode::Immediate);
    CHECK(conn->state() == ConnState::Closed);
}

// ============================================================================
// 测试 9: C-API linoh_connection_close_immediate → state 返回 CLOSED
// ============================================================================
static void test_c_api_close_immediate() {
    std::printf("[test] C-API linoh_connection_close_immediate -> CLOSED...\n");

    // 1) 创建 endpoint
    linoh_endpoint_config_t cfg{};
    linoh_secret_key_t sk{};
    linoh_public_key_t pk{};
    linoh_generate_keypair(&sk, &pk);
    cfg.secret_key = sk;
    cfg.alpn = "test-close/1";
    cfg.udp_port = 0;  // 随机端口
    cfg.user_data = nullptr;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    CHECK(ep != nullptr);

    // 2) 创建一个 outbound 连接（连不上的目标也无所谓，只测 close 行为）
    linoh_connection_t *lc = linoh_endpoint_connect(ep, "127.0.0.1", 65535);
    CHECK(lc != nullptr);

    // 连接创建后处于 Initial 状态（不是 CLOSED）
    linoh_conn_state_t s_before = linoh_connection_state(lc);
    CHECK(s_before != LINOH_CONN_CLOSED);

    // 3) 调用 linoh_connection_close_immediate
    linoh_connection_close_immediate(lc, 0, "test immediate");

    // 4) 验证状态为 CLOSED
    linoh_conn_state_t s_after = linoh_connection_state(lc);
    CHECK(s_after == LINOH_CONN_CLOSED);

    // 5) 释放资源（linoh_connection_free 会发送 CONNECTION_CLOSE，但已 Closed 应幂等）
    linoh_connection_free(lc);
    linoh_endpoint_free(ep);
}

// ============================================================================
// 测试 10: C-API linoh_connection_close_immediate 多次调用幂等
// ============================================================================
static void test_c_api_close_immediate_idempotent() {
    std::printf("[test] C-API close_immediate idempotent...\n");

    linoh_endpoint_config_t cfg{};
    linoh_secret_key_t sk{};
    linoh_public_key_t pk{};
    linoh_generate_keypair(&sk, &pk);
    cfg.secret_key = sk;
    cfg.alpn = "test-close-idem/1";
    cfg.udp_port = 0;
    cfg.user_data = nullptr;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    CHECK(ep != nullptr);

    linoh_connection_t *lc = linoh_endpoint_connect(ep, "127.0.0.1", 65535);
    CHECK(lc != nullptr);

    // 多次调用 close_immediate，状态应稳定为 CLOSED
    linoh_connection_close_immediate(lc, 0, "first");
    linoh_conn_state_t s1 = linoh_connection_state(lc);
    linoh_connection_close_immediate(lc, 0, "second");
    linoh_conn_state_t s2 = linoh_connection_state(lc);
    linoh_connection_close_immediate(lc, 1, "third");

    CHECK(s1 == LINOH_CONN_CLOSED);
    CHECK(s2 == LINOH_CONN_CLOSED);

    linoh_connection_free(lc);
    linoh_endpoint_free(ep);
}

// ============================================================================
// 测试 11: C-API linoh_connection_close (Graceful) 与 close_immediate 语义对比
// ============================================================================
static void test_c_api_graceful_vs_immediate() {
    std::printf("[test] C-API Graceful close vs Immediate close...\n");

    // Graceful close 也应该最终到 CLOSED（linoh_connection_close 内部调用 close(Graceful)）
    {
        linoh_endpoint_config_t cfg{};
        linoh_secret_key_t sk{};
        linoh_public_key_t pk{};
        linoh_generate_keypair(&sk, &pk);
        cfg.secret_key = sk;
        cfg.alpn = "test-graceful/1";
        cfg.udp_port = 0;
        cfg.user_data = nullptr;

        linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
        CHECK(ep != nullptr);

        linoh_connection_t *lc = linoh_endpoint_connect(ep, "127.0.0.1", 65535);
        CHECK(lc != nullptr);

        linoh_connection_close(lc, 0, "graceful");
        CHECK(linoh_connection_state(lc) == LINOH_CONN_CLOSED);

        linoh_connection_free(lc);
        linoh_endpoint_free(ep);
    }

    // Immediate close 同样到 CLOSED，但路径不同
    {
        linoh_endpoint_config_t cfg{};
        linoh_secret_key_t sk{};
        linoh_public_key_t pk{};
        linoh_generate_keypair(&sk, &pk);
        cfg.secret_key = sk;
        cfg.alpn = "test-immediate/1";
        cfg.udp_port = 0;
        cfg.user_data = nullptr;

        linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
        CHECK(ep != nullptr);

        linoh_connection_t *lc = linoh_endpoint_connect(ep, "127.0.0.1", 65535);
        CHECK(lc != nullptr);

        linoh_connection_close_immediate(lc, 0, "immediate");
        CHECK(linoh_connection_state(lc) == LINOH_CONN_CLOSED);

        linoh_connection_free(lc);
        linoh_endpoint_free(ep);
    }
}

int main() {
    std::printf("=== test_close_immediate ===\n");

    test_immediate_from_established();
    test_immediate_from_initial();
    test_graceful_close_works();
    test_immediate_triggers_on_close_once();
    test_immediate_idempotent();
    test_mixed_close_calls();
    test_concurrent_close_immediate();
    test_explicit_close_mode_immediate();
    test_c_api_close_immediate();
    test_c_api_close_immediate_idempotent();
    test_c_api_graceful_vs_immediate();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
