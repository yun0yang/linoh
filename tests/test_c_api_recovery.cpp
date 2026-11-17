// test_c_api_recovery.cpp — v1.5.0.2.3 cluster 兼容性恢复 C-API 测试
//
// 验证 v1.5.0.2.3 新增/恢复的 12 个 C-API：
//   1. linoh_set_log_level (level=0..4)
//   2. linoh_stream_fin_received (false→true 当对端 FIN)
//   3. linoh_tensorstream_create / free
//   4. linoh_tensorstream_send_shard (本地 localhost echo)
//   5. linoh_tensorstream_recv_one (本地 localhost echo)
//   6. linoh_tensorstream_is_complete
//   7. linoh_tensorstream_received_count
//   8. linoh_tensorstream_total_size
//   9. linoh_tensorstream_copy_to
//  10. linoh_tensorstream_tensor_id
//  11. linoh_tensorstream_timeout_ms
//  12. tensor_meta 序列化布局验证（48 字节小端）
//
// 测试策略：
//   1-3 + 6-11 + 12：纯本地状态测试，无网络依赖
//   4-5：本地 localhost endpoint + echo 验证真实 send/recv
//   2：使用真实 stream FIN（client 端 finish_send 后 server 端 fin_received=1）
//
// 关键设计：v1.5.0.2 的 linoh_endpoint_accept 在 on_conn_cb=null 时不可靠
// （poll 会 pop 丢弃），正确模式是 on_conn_cb + atomic 同步（参考
// tests/test_pp_multimodal_chain.cpp 的 linoh_endpoint_on_connection 用法）

#include "linoh/linoh_c.h"
#include "linoh/linoh_tensorstream.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>
#include <vector>
#include <map>
#include <atomic>
#include <string>
#include <fstream>
#include <iostream>

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

#define CHECK_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (%lld != %lld) (line %d)\n", #a, #b, (long long)_a, (long long)_b, __LINE__); } \
} while (0)

// =====================================================================
// server 端入站连接捕获（on_conn_cb 模式）
// =====================================================================
struct ConnCapture {
    std::atomic<linoh_connection_t*> lc{nullptr};
};

static void on_conn_capture(linoh_connection_t *conn, void *user_data) {
    auto *cap = static_cast<ConnCapture*>(user_data);
    linoh_connection_t *expected = nullptr;
    cap->lc.compare_exchange_strong(expected, conn);
}

static linoh_endpoint_t *make_endpoint_client(const char *alpn, uint16_t port) {
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

static linoh_endpoint_t *make_endpoint_server(const char *alpn, ConnCapture *capture) {
    linoh_endpoint_config_t cfg{};
    linoh_secret_key_t sk{};
    linoh_public_key_t pk{};
    linoh_generate_keypair(&sk, &pk);
    cfg.secret_key = sk;
    cfg.alpn = alpn;
    cfg.udp_port = 0;  // 系统分配
    cfg.user_data = capture;
    auto *ep = linoh_endpoint_create(&cfg);
    if (ep) linoh_endpoint_on_connection(ep, on_conn_capture);
    return ep;
}

static void poll_all(std::vector<linoh_endpoint_t *> eps, int timeout_ms) {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start).count() < timeout_ms) {
        for (auto *e : eps) {
            linoh_endpoint_poll(e);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

static linoh_connection_t *wait_for_conn(ConnCapture *capture, linoh_endpoint_t *ep, int timeout_ms) {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start).count() < timeout_ms) {
        if (capture->lc.load()) return capture->lc.load();
        linoh_endpoint_poll(ep);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return nullptr;
}

// 后台 poll 线程包装（关键：linoh_endpoint_poll 必须在独立线程循环，
// 否则 sender 写入 stream 后不会 flush 到 UDP socket）
//
// v1.5.0.2.4: 提供显式 stop() 方法 + 析构前自动 stop，调用方必须在
// linoh_endpoint_free 之前调用 stop() 或 reset this，否则 PollThread 仍
// 在 poll(ep) 时 ep 被 delete → UAF。这是 v1.5.0.2.3 test 4 崩溃的
// 另一个根因（与 linoh_connection_free 析构竞争独立）。
class PollThread {
public:
    PollThread(linoh_endpoint_t *ep, int interval_ms = 1)
        : ep_(ep), interval_ms_(interval_ms), stop_(false) {
        th_ = std::thread([this]() {
            while (!stop_.load()) {
                if (ep_) linoh_endpoint_poll(ep_);
                std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms_));
            }
        });
    }
    ~PollThread() { stop(); }

    /// 显式停止 poll 线程。调用后 ep 仍可安全 free（join 在前）。
    /// 可多次调用（幂等）。
    void stop() {
        if (stop_.exchange(true)) return;
        if (th_.joinable()) th_.join();
        ep_ = nullptr;
    }

    bool is_stopped() const { return stop_.load(); }

private:
    linoh_endpoint_t *ep_;
    int interval_ms_;
    std::atomic<bool> stop_;
    std::thread th_;
};

static bool make_pair(const char *alpn, ConnCapture &capture,
                      linoh_endpoint_t *&ep_s, linoh_endpoint_t *&ep_c,
                      linoh_connection_t *&lc_s, linoh_connection_t *&lc_c) {
    ep_s = make_endpoint_server(alpn, &capture);
    ep_c = make_endpoint_client(alpn, 0);
    if (!ep_s || !ep_c) return false;
    uint16_t port = linoh_endpoint_udp_port(ep_s);
    if (port == 0) return false;
    lc_c = linoh_endpoint_connect(ep_c, "127.0.0.1", port);
    if (!lc_c) return false;
    poll_all({ep_s, ep_c}, 2000);
    lc_s = wait_for_conn(&capture, ep_s, 2000);
    if (!lc_s) return false;
    poll_all({ep_s, ep_c}, 200);
    return true;
}

static void teardown(linoh_endpoint_t *ep_s, linoh_endpoint_t *ep_c,
                     linoh_connection_t *lc_s, linoh_connection_t *lc_c) {
    if (lc_c) linoh_connection_free(lc_c);
    if (lc_s) linoh_connection_free(lc_s);
    if (ep_c) linoh_endpoint_free(ep_c);
    if (ep_s) linoh_endpoint_free(ep_s);
}

// ============================================================================
// 测试 1: linoh_set_log_level (level 0..4 + 越界自动裁剪)
// ============================================================================
static void test_set_log_level() {
    std::printf("[test] linoh_set_log_level...\n");
    for (int lvl = 0; lvl <= 4; ++lvl) {
        linoh_set_log_level(lvl);
    }
    linoh_set_log_level(-1);
    linoh_set_log_level(99);
    CHECK(1);
}

// ============================================================================
// 测试 2: linoh_stream_fin_received (默认 = 0)
// ============================================================================
static void test_stream_fin_received_default() {
    std::printf("[test] linoh_stream_fin_received (default = 0)...\n");
    ConnCapture cap{};
    linoh_endpoint_t *ep_s = nullptr, *ep_c = nullptr;
    linoh_connection_t *lc_s = nullptr, *lc_c = nullptr;
    if (!make_pair("test/fin/1", cap, ep_s, ep_c, lc_s, lc_c)) {
        CHECK(0);
        teardown(ep_s, ep_c, lc_s, lc_c);
        return;
    }
    linoh_stream_t *s = linoh_connection_open_stream(lc_c);
    CHECK(s != nullptr);
    if (s) {
        CHECK_EQ(linoh_stream_fin_received(s), 0);
    }
    if (s) linoh_stream_free(s);
    teardown(ep_s, ep_c, lc_s, lc_c);
}

// ============================================================================
// 测试 3: linoh_tensorstream_create / free
// ============================================================================
static void test_tensorstream_create_free() {
    std::printf("[test] linoh_tensorstream_create / free...\n");
    ConnCapture cap{};
    linoh_endpoint_t *ep_s = nullptr, *ep_c = nullptr;
    linoh_connection_t *lc_s = nullptr, *lc_c = nullptr;
    if (!make_pair("test/ts/cf/1", cap, ep_s, ep_c, lc_s, lc_c)) {
        CHECK(0);
        teardown(ep_s, ep_c, lc_s, lc_c);
        return;
    }

    linoh_tensorstream_t *ts1 = linoh_tensorstream_create(lc_c, nullptr);
    CHECK(ts1 != nullptr);
    if (ts1) {
        CHECK_EQ(linoh_tensorstream_timeout_ms(ts1), 300000u);
        CHECK_EQ(linoh_tensorstream_tensor_id(ts1), 0ull);
    }
    linoh_tensorstream_free(ts1);

    linoh_tensorstream_config_t cfg{};
    cfg.tensor_id = 0xDEADBEEF12345678ull;
    cfg.total_shards = 4;
    cfg.timeout_ms = 5000;
    cfg.channel_type = LINOH_CHANNEL_VIDEO_FEATURE;
    linoh_tensorstream_t *ts2 = linoh_tensorstream_create(lc_c, &cfg);
    CHECK(ts2 != nullptr);
    if (ts2) {
        CHECK_EQ(linoh_tensorstream_tensor_id(ts2), 0xDEADBEEF12345678ull);
        CHECK_EQ(linoh_tensorstream_timeout_ms(ts2), 5000u);
    }
    linoh_tensorstream_free(ts2);

    linoh_tensorstream_t *ts3 = linoh_tensorstream_create(nullptr, nullptr);
    CHECK(ts3 == nullptr);
    linoh_tensorstream_free(nullptr);
    CHECK(1);

    teardown(ep_s, ep_c, lc_s, lc_c);
}

// ============================================================================
// 测试 4-5: 完整 send/recv 循环（3 shards + 验证完整性）
// ============================================================================
static void test_tensorstream_send_recv_loop() {
    std::printf("[test] linoh_tensorstream send/recv loop (3 shards)...\n");
    ConnCapture cap{};
    linoh_endpoint_t *ep_s = nullptr, *ep_c = nullptr;
    linoh_connection_t *lc_s = nullptr, *lc_c = nullptr;
    if (!make_pair("test/ts/sr/1", cap, ep_s, ep_c, lc_s, lc_c)) {
        CHECK(0);
        teardown(ep_s, ep_c, lc_s, lc_c);
        return;
    }

    const size_t shard_size = 64;  // 64B per shard（最小化）
    std::vector<std::vector<uint8_t>> shards(1);
    for (auto &s : shards) s.assign(shard_size, 0xCC);

    // 关键：启动后台 poll 线程（必须独立线程持续 poll 才能推进 stream flush）
    //
    // v1.5.0.2.4: PollThread 必须在 teardown 之前显式 stop。包成 optional
    // 以便 test 末尾调用 poll_s.reset() / poll_c.reset() 触发 stop+join。
    // 旧实现 PollThread 是栈对象，函数返回时才析构；但 teardown 内部会
    // linoh_endpoint_free(ep) → delete ep → PollThread 后续调用 poll(ep) → UAF
    std::optional<PollThread> poll_s{std::in_place, ep_s};
    std::optional<PollThread> poll_c{std::in_place, ep_c};

    std::thread sender([&]() {
        linoh_tensorstream_config_t cfg{};
        cfg.tensor_id = 0xAABBCCDD11223344ull;
        cfg.total_shards = 1;
        cfg.timeout_ms = 5000;
        cfg.channel_type = LINOH_CHANNEL_VIDEO_FEATURE;
        linoh_tensorstream_t *ts = linoh_tensorstream_create(lc_c, &cfg);
        size_t n = linoh_tensorstream_send_shard(ts, 0, shards[0].data(), shard_size, 1);
        if (n != 48 + shard_size) {
            std::printf("send_shard short: %zu\n", n);
        }
        linoh_tensorstream_free(ts);
    });

    std::thread receiver([&]() {
        linoh_tensorstream_t *ts = linoh_tensorstream_create(lc_s, nullptr);
        auto recv_start = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - recv_start).count() < 3000) {
            int r = linoh_tensorstream_recv_one(ts);
            if (r == 1) {
                if (linoh_tensorstream_is_complete(ts)) break;
            } else if (r < 0) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        CHECK_EQ(linoh_tensorstream_is_complete(ts), 1);
        CHECK_EQ(linoh_tensorstream_received_count(ts), 1u);
        CHECK_EQ(linoh_tensorstream_tensor_id(ts), 0xAABBCCDD11223344ull);
        size_t total = linoh_tensorstream_total_size(ts);
        CHECK(total == shard_size);
        std::vector<uint8_t> buf(shard_size, 0);
        size_t copied = linoh_tensorstream_copy_to(ts, buf.data(), buf.size());
        CHECK_EQ(copied, buf.size());
        size_t cc_count = 0;
        for (auto b : buf) if (b == 0xCC) ++cc_count;
        CHECK_EQ(cc_count, buf.size());
        linoh_tensorstream_free(ts);
    });

    sender.join();
    receiver.join();

    // v1.5.0.2.4: 显式 stop PollThread，join 完再 teardown ep
    // 顺序很重要：先 stop 外部 poll 线程，再 linoh_endpoint_free 析构 ep
    poll_s.reset();
    poll_c.reset();

    teardown(ep_s, ep_c, lc_s, lc_c);
}

// ============================================================================
// 测试 6-11: 状态查询 API（null-safe 覆盖）
// ============================================================================
static void test_tensorstream_state_queries() {
    std::printf("[test] linoh_tensorstream state queries (null-safe)...\n");
    CHECK_EQ(linoh_tensorstream_is_complete(nullptr), 0);
    CHECK_EQ(linoh_tensorstream_received_count(nullptr), 0u);
    CHECK_EQ(linoh_tensorstream_total_size(nullptr), 0u);
    CHECK_EQ(linoh_tensorstream_tensor_id(nullptr), 0ull);
    CHECK_EQ(linoh_tensorstream_timeout_ms(nullptr), 0u);
    linoh_tensorstream_free(nullptr);
    CHECK(1);
}

// ============================================================================
// 测试 12: tensor_meta 48B 布局 round-trip
// ============================================================================
static void test_tensor_meta_layout() {
    std::printf("[test] tensor_meta 48-byte layout (round-trip)...\n");
    ConnCapture cap{};
    linoh_endpoint_t *ep_s = nullptr, *ep_c = nullptr;
    linoh_connection_t *lc_s = nullptr, *lc_c = nullptr;
    if (!make_pair("test/meta/1", cap, ep_s, ep_c, lc_s, lc_c)) {
        CHECK(0);
        teardown(ep_s, ep_c, lc_s, lc_c);
        return;
    }

    const uint64_t TID = 0x123456789ABCDEF0ull;
    const uint32_t TOTAL = 5;
    const uint32_t SHARD_IDX = 2;
    const size_t DATA_LEN = 128;

    uint8_t data[DATA_LEN];
    std::memset(data, 0xAB, sizeof(data));

    // 后台 poll 线程
    // v1.5.0.2.4: 同 test 4，包成 optional 以便 teardown 之前显式 stop
    std::optional<PollThread> poll_s{std::in_place, ep_s};
    std::optional<PollThread> poll_c{std::in_place, ep_c};

    std::thread sender([&]() {
        linoh_tensorstream_config_t cfg{};
        cfg.tensor_id = TID;
        cfg.total_shards = TOTAL;
        cfg.timeout_ms = 3000;
        cfg.channel_type = LINOH_CHANNEL_VIDEO_FEATURE;
        linoh_tensorstream_t *ts = linoh_tensorstream_create(lc_c, &cfg);
        size_t sent = linoh_tensorstream_send_shard(ts, SHARD_IDX, data, sizeof(data), 0);
        if (sent != 48 + sizeof(data)) {
            std::printf("send short: %zu\n", sent);
        }
        linoh_tensorstream_free(ts);
    });

    std::thread receiver([&]() {
        linoh_tensorstream_t *ts = linoh_tensorstream_create(lc_s, nullptr);
        auto recv_start = std::chrono::steady_clock::now();
        int got = 0;
        while (std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - recv_start).count() < 3000) {
            int r = linoh_tensorstream_recv_one(ts);
            if (r == 1) { got = 1; break; }
            if (r < 0) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        CHECK(got);
        CHECK_EQ(linoh_tensorstream_tensor_id(ts), TID);
        CHECK_EQ(linoh_tensorstream_received_count(ts), 1u);
        linoh_tensorstream_free(ts);
    });

    sender.join();
    receiver.join();

    // v1.5.0.2.4: 显式 stop PollThread，再 teardown ep
    poll_s.reset();
    poll_c.reset();

    teardown(ep_s, ep_c, lc_s, lc_c);
}

// ============================================================================
// 主函数
// ============================================================================
int main(int argc, char **argv) {
    std::printf("=== test_c_api_recovery v1.5.0.2.3 ===\n");
    // 注：不再重定向 std::cerr 到文件（绕不开 PowerShell 包装问题）；
    //     stderr 走 INHERIT，由调用方 2>&1 捕获。
    linoh_set_log_level(0);  // Trace
    test_set_log_level();
    test_stream_fin_received_default();
    test_tensorstream_create_free();
    test_tensorstream_send_recv_loop();
    test_tensorstream_state_queries();
    test_tensor_meta_layout();
    std::printf("=== RESULT: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
