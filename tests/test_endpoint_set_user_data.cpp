// test_endpoint_set_user_data.cpp — P5-C-1 set_user_data API 测试
//
// 验证：
//   1. null endpoint 调用 set_user_data 不崩溃（防御性）
//   2. set_user_data 覆盖 config.user_data，回调中读取的 user_data 为 set 的值
//   3. 多线程并发 set_user_data + 主线程 poll，无崩溃（atomic 线程安全）
//
// 注意：user_data 在 recv_thread 的回调中通过 atomic load() 读取，
//      set_user_data 通过 atomic store() 写入，无锁线程安全。

#include "linoh/linoh_c.h"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

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

// 全局回调上下文（linoh_on_connection_fn 是普通函数指针，不能用捕获 lambda）
static std::atomic<void*> g_captured_ud{nullptr};

static void on_conn_capture_ud(linoh_connection_t *conn, void *ud) {
    (void)conn;
    g_captured_ud.store(ud, std::memory_order_release);
}

// ============================================================================
// 测试 1: null endpoint 调用 set_user_data 不崩溃
// ============================================================================
static void test_set_user_data_null_endpoint() {
    std::printf("[test] set_user_data(NULL, x) - no crash...\n");

    // 应直接 return，不解引用 NULL
    linoh_endpoint_set_user_data(nullptr, nullptr);
    int sentinel = 42;
    linoh_endpoint_set_user_data(nullptr, &sentinel);

    CHECK(true);  // 到达此处表示无崩溃
}

// ============================================================================
// 测试 2: set_user_data 覆盖 config.user_data
//
// 流程：
//   - server: config.user_data = ptr_A，create 后 set_user_data(ptr_B)
//   - server: 注册 on_connection_cb，回调中记录 user_data
//   - client: connect 到 server 的 udp_port
//   - 双方 poll 等待握手
//   - 验证 server on_connection_cb 收到的 user_data == ptr_B（而非 ptr_A）
// ============================================================================
static void test_set_user_data_overrides_config() {
    std::printf("[test] set_user_data overrides config.user_data...\n");

    int config_ud = 100;
    int set_ud = 200;

    // 重置全局回调上下文
    g_captured_ud.store(nullptr, std::memory_order_release);

    // --- 创建 server endpoint ---
    linoh_endpoint_config_t server_cfg{};
    linoh_secret_key_t sk{};
    linoh_public_key_t pk{};
    linoh_generate_keypair(&sk, &pk);
    server_cfg.secret_key = sk;
    server_cfg.alpn = "test-set-ud/1";
    server_cfg.udp_port = 0;  // 随机端口
    server_cfg.user_data = &config_ud;  // 初始值 ptr_A

    linoh_endpoint_t *server = linoh_endpoint_create(&server_cfg);
    CHECK(server != nullptr);

    // 覆盖 config.user_data
    linoh_endpoint_set_user_data(server, &set_ud);  // ptr_B

    // 注册 on_connection 回调（普通函数指针，通过全局变量传递捕获状态）
    linoh_endpoint_on_connection(server, on_conn_capture_ud);

    uint16_t server_port = linoh_endpoint_udp_port(server);
    CHECK(server_port != 0);

    // --- 创建 client endpoint ---
    linoh_endpoint_config_t client_cfg{};
    linoh_secret_key_t csk{};
    linoh_public_key_t cpk{};
    linoh_generate_keypair(&csk, &cpk);
    client_cfg.secret_key = csk;
    client_cfg.alpn = "test-set-ud/1";
    client_cfg.udp_port = 0;
    client_cfg.user_data = nullptr;

    linoh_endpoint_t *client = linoh_endpoint_create(&client_cfg);
    CHECK(client != nullptr);

    // client 连接 server
    linoh_connection_t *lc = linoh_endpoint_connect(client, "127.0.0.1", server_port);
    CHECK(lc != nullptr);

    // --- 双方 poll 等待握手（最多 2 秒） ---
    for (int i = 0; i < 200; ++i) {
        linoh_endpoint_poll(server);
        linoh_endpoint_poll(client);
        if (g_captured_ud.load() != nullptr) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // 验证：on_connection_cb 被触发，且 user_data 是 set_ud（ptr_B）而非 config_ud（ptr_A）
    void *got = g_captured_ud.load();
    CHECK(got == &set_ud);
    CHECK(got != &config_ud);

    linoh_connection_free(lc);
    linoh_endpoint_free(client);
    linoh_endpoint_free(server);
}

// ============================================================================
// 测试 3: 多线程并发 set_user_data + 主线程 poll，无崩溃
//
// 验证 atomic<void*> 的线程安全性：
//   - 4 个线程并发 set_user_data 不同值
//   - 主线程同时 poll
//   - 持续 500ms，验证无崩溃
// ============================================================================
static void test_set_user_data_thread_safety() {
    std::printf("[test] set_user_data thread safety (concurrent set + poll)...\n");

    linoh_endpoint_config_t cfg{};
    linoh_secret_key_t sk{};
    linoh_public_key_t pk{};
    linoh_generate_keypair(&sk, &pk);
    cfg.secret_key = sk;
    cfg.alpn = "test-thread-safety/1";
    cfg.udp_port = 0;
    cfg.user_data = nullptr;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    CHECK(ep != nullptr);

    int vals[4] = {0, 1, 2, 3};
    std::atomic<bool> stop{false};

    // 4 个写线程
    std::vector<std::thread> writers;
    for (int i = 0; i < 4; ++i) {
        writers.emplace_back([ep, &vals, i, &stop]() {
            while (!stop.load()) {
                linoh_endpoint_set_user_data(ep, &vals[i]);
            }
        });
    }

    // 主线程同时 poll 500ms
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start).count() < 500) {
        linoh_endpoint_poll(ep);
    }

    stop.store(true);
    for (auto &t : writers) t.join();

    // 验证：程序正常到达此处表示无崩溃
    // 最终 user_data 应该是 vals[0..3] 之一（或初始 nullptr，取决于调度）
    linoh_endpoint_set_user_data(ep, nullptr);  // 清理

    CHECK(true);

    linoh_endpoint_free(ep);
}

int main() {
    std::printf("=== test_endpoint_set_user_data ===\n");

    test_set_user_data_null_endpoint();
    test_set_user_data_overrides_config();
    test_set_user_data_thread_safety();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
