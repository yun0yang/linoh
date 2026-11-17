// test_linoh_c_lifecycle.cpp — v1.5 P1-2 linoh_connection_retain/release C-API 测试
//
// 验证：
//   1. 新建连接的 refcount 初值 = 1
//   2. retain 后 refcount += 1，release 后 refcount -= 1
//   3. NULL conn 的 retain/release/refcount 不崩溃（防御性）
//   4. 多次 retain/release 计数正确
//   5. refcount 归零不立即释放（仍由 ep->conns 持有）—— 防御性 API 语义
//
// 关键设计：refcount 是防御性 API 暴露，真实释放仍由 linoh_endpoint_free 统一管理。
//          本测试聚焦于计数正确性 + NULL 防御 + 多次 retain/release 配对。

#include "linoh/linoh_c.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>
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

static void poll_loop(linoh_endpoint_t *server, linoh_endpoint_t *client, int ms) {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start).count() < ms) {
        linoh_endpoint_poll(server);
        linoh_endpoint_poll(client);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

// ============================================================================
// 测试 1: NULL conn 的 retain/release/refcount 不崩溃
// ============================================================================
static void test_null_safety() {
    std::printf("[test] NULL conn retain/release/refcount defensive...\n");

    // NULL 应直接 return，不解引用
    linoh_connection_retain(nullptr);
    linoh_connection_release(nullptr);
    int r = linoh_connection_refcount(nullptr);
    CHECK(r == 0);

    CHECK(true);  // 到达此处表示无崩溃
}

// ============================================================================
// 测试 2: 新建连接 refcount 初值 = 1
// ============================================================================
static void test_initial_refcount() {
    std::printf("[test] new connection refcount == 1...\n");

    const char *alpn = "test-lifecycle/1";

    linoh_endpoint_config_t cfg{};
    linoh_secret_key_t sk{};
    linoh_public_key_t pk{};
    linoh_generate_keypair(&sk, &pk);
    cfg.secret_key = sk;
    cfg.alpn = alpn;
    cfg.udp_port = 0;
    cfg.user_data = nullptr;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    CHECK(ep != nullptr);

    // 创建一个空的目标 server endpoint（仅用于连接对象，不必真握手）
    linoh_endpoint_config_t server_cfg{};
    linoh_secret_key_t ssk{};
    linoh_public_key_t spk{};
    linoh_generate_keypair(&ssk, &spk);
    server_cfg.secret_key = ssk;
    server_cfg.alpn = alpn;
    server_cfg.udp_port = 0;
    server_cfg.user_data = nullptr;

    linoh_endpoint_t *server = linoh_endpoint_create(&server_cfg);
    CHECK(server != nullptr);
    uint16_t port = linoh_endpoint_udp_port(server);

    linoh_connection_t *lc = linoh_endpoint_connect(ep, "127.0.0.1", port);
    CHECK(lc != nullptr);

    if (lc) {
        int r = linoh_connection_refcount(lc);
        CHECK(r == 1);
    }

    if (lc) linoh_connection_free(lc);
    linoh_endpoint_free(ep);
    linoh_endpoint_free(server);
}

// ============================================================================
// 测试 3: retain +1 / release -1
// ============================================================================
static void test_retain_release_basic() {
    std::printf("[test] retain/release basic +1/-1...\n");

    const char *alpn = "test-lifecycle/1";

    linoh_endpoint_config_t cfg{};
    linoh_secret_key_t sk{};
    linoh_public_key_t pk{};
    linoh_generate_keypair(&sk, &pk);
    cfg.secret_key = sk;
    cfg.alpn = alpn;
    cfg.udp_port = 0;
    cfg.user_data = nullptr;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    linoh_endpoint_config_t server_cfg{};
    linoh_secret_key_t ssk{};
    linoh_public_key_t spk{};
    linoh_generate_keypair(&ssk, &spk);
    server_cfg.secret_key = ssk;
    server_cfg.alpn = alpn;
    server_cfg.udp_port = 0;
    server_cfg.user_data = nullptr;
    linoh_endpoint_t *server = linoh_endpoint_create(&server_cfg);
    uint16_t port = linoh_endpoint_udp_port(server);

    linoh_connection_t *lc = linoh_endpoint_connect(ep, "127.0.0.1", port);
    CHECK(lc != nullptr);

    if (lc) {
        CHECK(linoh_connection_refcount(lc) == 1);

        linoh_connection_retain(lc);
        CHECK(linoh_connection_refcount(lc) == 2);

        linoh_connection_retain(lc);
        CHECK(linoh_connection_refcount(lc) == 3);

        linoh_connection_release(lc);
        CHECK(linoh_connection_refcount(lc) == 2);

        linoh_connection_release(lc);
        CHECK(linoh_connection_refcount(lc) == 1);

        linoh_connection_release(lc);
        // 归零不立即释放（最低水位 1），但 count 应 == 0
        // 因为 release 不限制下限，让用户明白地掉到底
        int r = linoh_connection_refcount(lc);
        CHECK(r == 0);
    }

    if (lc) linoh_connection_free(lc);
    linoh_endpoint_free(ep);
    linoh_endpoint_free(server);
}

// ============================================================================
// 测试 4: 多次 retain/release 配对计数正确
// ============================================================================
static void test_retain_release_many() {
    std::printf("[test] retain/release 100 cycles balance to 1...\n");

    const char *alpn = "test-lifecycle/1";

    linoh_endpoint_config_t cfg{};
    linoh_secret_key_t sk{};
    linoh_public_key_t pk{};
    linoh_generate_keypair(&sk, &pk);
    cfg.secret_key = sk;
    cfg.alpn = alpn;
    cfg.udp_port = 0;
    cfg.user_data = nullptr;
    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);

    linoh_endpoint_config_t server_cfg{};
    linoh_secret_key_t ssk{};
    linoh_public_key_t spk{};
    linoh_generate_keypair(&ssk, &spk);
    server_cfg.secret_key = ssk;
    server_cfg.alpn = alpn;
    server_cfg.udp_port = 0;
    server_cfg.user_data = nullptr;
    linoh_endpoint_t *server = linoh_endpoint_create(&server_cfg);
    uint16_t port = linoh_endpoint_udp_port(server);

    linoh_connection_t *lc = linoh_endpoint_connect(ep, "127.0.0.1", port);
    CHECK(lc != nullptr);

    if (lc) {
        // 100 次 retain + 100 次 release
        for (int i = 0; i < 100; ++i) {
            linoh_connection_retain(lc);
        }
        CHECK(linoh_connection_refcount(lc) == 101);  // 1 (map) + 100

        for (int i = 0; i < 100; ++i) {
            linoh_connection_release(lc);
        }
        CHECK(linoh_connection_refcount(lc) == 1);
    }

    if (lc) linoh_connection_free(lc);
    linoh_endpoint_free(ep);
    linoh_endpoint_free(server);
}

// ============================================================================
// 测试 5: 多线程并发 retain/release 计数正确（原子操作）
// ============================================================================
static void test_retain_release_thread_safety() {
    std::printf("[test] concurrent retain/release from 4 threads...\n");

    const char *alpn = "test-lifecycle/1";

    linoh_endpoint_config_t cfg{};
    linoh_secret_key_t sk{};
    linoh_public_key_t pk{};
    linoh_generate_keypair(&sk, &pk);
    cfg.secret_key = sk;
    cfg.alpn = alpn;
    cfg.udp_port = 0;
    cfg.user_data = nullptr;
    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);

    linoh_endpoint_config_t server_cfg{};
    linoh_secret_key_t ssk{};
    linoh_public_key_t spk{};
    linoh_generate_keypair(&ssk, &spk);
    server_cfg.secret_key = ssk;
    server_cfg.alpn = alpn;
    server_cfg.udp_port = 0;
    server_cfg.user_data = nullptr;
    linoh_endpoint_t *server = linoh_endpoint_create(&server_cfg);
    uint16_t port = linoh_endpoint_udp_port(server);

    linoh_connection_t *lc = linoh_endpoint_connect(ep, "127.0.0.1", port);
    CHECK(lc != nullptr);

    if (lc) {
        // 4 线程 × 1000 次 retain
        std::vector<std::thread> retainers;
        for (int t = 0; t < 4; ++t) {
            retainers.emplace_back([lc]() {
                for (int i = 0; i < 1000; ++i) {
                    linoh_connection_retain(lc);
                }
            });
        }
        for (auto &t : retainers) t.join();
        // 1 (map) + 4 * 1000
        CHECK(linoh_connection_refcount(lc) == 4001);

        // 4 线程 × 1000 次 release
        std::vector<std::thread> releasers;
        for (int t = 0; t < 4; ++t) {
            releasers.emplace_back([lc]() {
                for (int i = 0; i < 1000; ++i) {
                    linoh_connection_release(lc);
                }
            });
        }
        for (auto &t : releasers) t.join();
        CHECK(linoh_connection_refcount(lc) == 1);
    }

    if (lc) linoh_connection_free(lc);
    linoh_endpoint_free(ep);
    linoh_endpoint_free(server);
}

int main() {
    std::printf("=== test_linoh_c_lifecycle ===\n");

    test_null_safety();
    test_initial_refcount();
    test_retain_release_basic();
    test_retain_release_many();
    test_retain_release_thread_safety();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
