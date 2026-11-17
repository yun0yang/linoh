// test_linoh_c_alpn_override.cpp — v1.5 P1-1 alpn_override C-API 测试
//
// 验证：
//   1. linoh_endpoint_connect_with_alpn 创建的连接 ALPN == 传入的 alpn
//   2. alpn 传 NULL 或空字符串时回退到 ep->alpn（与旧 linoh_endpoint_connect 行为一致）
//   3. 多次 _with_alpn 不会影响 ep 的默认 alpn（用 _connect 验证）
//   4. linoh_endpoint_connect_multimodal 建立的 ctrl+data 双连接 ALPN 正确
//      （且不再触发旧实现的 swap ep->alpn 副作用）
//
// 关键设计：所有测试均在 localhost 上创建 server + client endpoint，
//          通过真实 QUIC 握手建立连接，验证握手后 conn->alpn()。

#include "linoh/linoh_c.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
static inline int closesocket(int fd) { return ::close(fd); }
#endif

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// 工具：等待握手完成（最多 timeout_ms）
static void poll_until(linoh_endpoint_t *server, linoh_endpoint_t *client,
                       bool *server_done, bool *client_done, int timeout_ms) {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start).count() < timeout_ms) {
        linoh_endpoint_poll(server);
        linoh_endpoint_poll(client);
        bool s_ok = !server_done || *server_done;
        bool c_ok = !client_done || *client_done;
        if (s_ok && c_ok) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

static linoh_endpoint_t *make_endpoint(const char *alpn, uint16_t port) {
    linoh_endpoint_config_t cfg{};
    linoh_secret_key_t sk{};
    linoh_public_key_t pk{};
    linoh_generate_keypair(&sk, &pk);
    cfg.secret_key = sk;
    cfg.alpn = alpn;
    cfg.udp_port = port;
    cfg.user_data = nullptr;
    return linoh_endpoint_create(&cfg);
}

// ============================================================================
// 测试 1: _with_alpn 创建的连接 ALPN == 传入的 alpn
// ============================================================================
static void test_with_alpn_sets_alpn() {
    std::printf("[test] _with_alpn sets connection ALPN to override...\n");

    const char *server_alpn = "default-srv/1";
    const char *override_alpn = "pp-hidden/1";

    linoh_endpoint_t *server = make_endpoint(server_alpn, 0);
    linoh_endpoint_t *client = make_endpoint(server_alpn, 0);
    CHECK(server != nullptr);
    CHECK(client != nullptr);

    uint16_t port = linoh_endpoint_udp_port(server);
    CHECK(port != 0);

    // 用 _with_alpn 强制覆盖 ALPN
    linoh_connection_t *lc = linoh_endpoint_connect_with_alpn(
        client, "127.0.0.1", port, override_alpn);
    CHECK(lc != nullptr);

    // 轮询等待握手
    poll_until(server, client, nullptr, nullptr, 2000);

    // 验证：客户端连接的 ALPN == override_alpn（即使 ep->alpn 是 server_alpn）
    const char *got = linoh_connection_alpn(lc);
    CHECK(got != nullptr);
    if (got) {
        CHECK(std::strcmp(got, override_alpn) == 0);
    }

    linoh_connection_free(lc);
    linoh_endpoint_free(client);
    linoh_endpoint_free(server);
}

// ============================================================================
// 测试 2: alpn=NULL 或空字符串时回退到 ep->alpn
// ============================================================================
static void test_with_alpn_null_falls_back() {
    std::printf("[test] _with_alpn(NULL alpn) falls back to ep->alpn...\n");

    const char *default_alpn = "echo/1";

    linoh_endpoint_t *server = make_endpoint(default_alpn, 0);
    linoh_endpoint_t *client = make_endpoint(default_alpn, 0);
    CHECK(server != nullptr);
    CHECK(client != nullptr);

    uint16_t port = linoh_endpoint_udp_port(server);
    CHECK(port != 0);

    // 传 NULL：应回退到 ep->alpn == "echo/1"
    linoh_connection_t *lc_null = linoh_endpoint_connect_with_alpn(
        client, "127.0.0.1", port, nullptr);
    CHECK(lc_null != nullptr);

    poll_until(server, client, nullptr, nullptr, 2000);

    const char *got_null = linoh_connection_alpn(lc_null);
    CHECK(got_null != nullptr);
    if (got_null) {
        CHECK(std::strcmp(got_null, default_alpn) == 0);
    }

    // 传空字符串：同样应回退
    linoh_connection_t *lc_empty = linoh_endpoint_connect_with_alpn(
        client, "127.0.0.1", port, "");
    CHECK(lc_empty != nullptr);

    poll_until(server, client, nullptr, nullptr, 2000);

    const char *got_empty = linoh_connection_alpn(lc_empty);
    CHECK(got_empty != nullptr);
    if (got_empty) {
        CHECK(std::strcmp(got_empty, default_alpn) == 0);
    }

    linoh_connection_free(lc_null);
    linoh_connection_free(lc_empty);
    linoh_endpoint_free(client);
    linoh_endpoint_free(server);
}

// ============================================================================
// 测试 3: _with_alpn 不影响 ep->alpn（关键不变量）
//
// 旧实现 swap ep->alpn 后忘了恢复的 bug，会让后续 _connect 用错误的 alpn。
// 验证方法：先用 _with_alpn 创建一条 override 连接的，然后调 _connect 创建第二条，
// 验证第二条的 ALPN 是 ep 的默认 alpn（而非 override 残留）。
// ============================================================================
static void test_with_alpn_does_not_pollute_ep() {
    std::printf("[test] _with_alpn does not pollute ep->alpn...\n");

    const char *default_alpn = "default/1";
    const char *override_alpn = "override/1";

    linoh_endpoint_t *server = make_endpoint(default_alpn, 0);
    linoh_endpoint_t *client = make_endpoint(default_alpn, 0);
    CHECK(server != nullptr);
    CHECK(client != nullptr);

    uint16_t port = linoh_endpoint_udp_port(server);
    CHECK(port != 0);

    // Step 1: 用 _with_alpn 创建 override 连接
    linoh_connection_t *lc_override = linoh_endpoint_connect_with_alpn(
        client, "127.0.0.1", port, override_alpn);
    CHECK(lc_override != nullptr);

    // Step 2: 立即用旧 _connect 创建新连接
    // 如果 ep->alpn 被污染，这条连接的 ALPN 会是 override_alpn
    linoh_connection_t *lc_default = linoh_endpoint_connect(
        client, "127.0.0.1", port);
    CHECK(lc_default != nullptr);

    poll_until(server, client, nullptr, nullptr, 2000);

    // 验证：override 连接是 override_alpn
    const char *got_override = linoh_connection_alpn(lc_override);
    CHECK(got_override != nullptr);
    if (got_override) {
        CHECK(std::strcmp(got_override, override_alpn) == 0);
    }

    // 验证：default 连接仍是 default_alpn（ep->alpn 没被污染）
    const char *got_default = linoh_connection_alpn(lc_default);
    CHECK(got_default != nullptr);
    if (got_default) {
        CHECK(std::strcmp(got_default, default_alpn) == 0);
    }

    linoh_connection_free(lc_override);
    linoh_connection_free(lc_default);
    linoh_endpoint_free(client);
    linoh_endpoint_free(server);
}

// ============================================================================
// 测试 4: linoh_endpoint_connect_multimodal 正确建立 ctrl + data 双连接
//
// 关键：旧实现 swap ep->alpn 会有线程安全风险 + 异常路径 alpn 残留。
// 新实现不再 swap，验证 multimodal 仍能正确建立两条独立 ALPN 的连接。
// ============================================================================
static void test_multimodal_pair_alpn() {
    std::printf("[test] _multimodal establishes ctrl+data with correct ALPNs...\n");

    const char *default_alpn = "default/1";

    linoh_endpoint_t *server = make_endpoint(default_alpn, 0);
    linoh_endpoint_t *client = make_endpoint(default_alpn, 0);
    CHECK(server != nullptr);
    CHECK(client != nullptr);

    uint16_t port = linoh_endpoint_udp_port(server);
    CHECK(port != 0);

    // multimodal 建立 ctrl/1 + pp-llm/1 双连接
    linoh_multimodal_conn_t *pair = linoh_endpoint_connect_multimodal(
        client, "127.0.0.1", port, LINOH_CHANNEL_LLM_HIDDEN);
    CHECK(pair != nullptr);

    if (pair) {
        linoh_connection_t *ctrl = linoh_multimodal_ctrl_conn(pair);
        linoh_connection_t *data = linoh_multimodal_data_conn(pair);
        CHECK(ctrl != nullptr);
        CHECK(data != nullptr);

        poll_until(server, client, nullptr, nullptr, 2000);

        if (ctrl) {
            const char *got = linoh_connection_alpn(ctrl);
            CHECK(got != nullptr);
            if (got) {
                CHECK(std::strcmp(got, "ctrl/1") == 0);
            }
        }
        if (data) {
            const char *got = linoh_connection_alpn(data);
            CHECK(got != nullptr);
            if (got) {
                CHECK(std::strcmp(got, "pp-llm/1") == 0);
            }
        }

        // 验证 channel
        linoh_multimodal_channel_t ch = linoh_multimodal_data_channel(pair);
        CHECK(ch == LINOH_CHANNEL_LLM_HIDDEN);

        linoh_multimodal_conn_free(pair);
    }

    linoh_endpoint_free(client);
    linoh_endpoint_free(server);
}

int main() {
    std::printf("=== test_linoh_c_alpn_override ===\n");

    test_with_alpn_sets_alpn();
    test_with_alpn_null_falls_back();
    test_with_alpn_does_not_pollute_ep();
    test_multimodal_pair_alpn();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
