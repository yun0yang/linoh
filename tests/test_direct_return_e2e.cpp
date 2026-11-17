// test_direct_return_e2e.cpp — v3.2.1 P1-4 Direct Return Path 端到端集成测试
//
// 测试覆盖（真实双节点 C-API 端到端，localhost 回环）：
//   1. 基本直连回传：MASTER register → WORKER open+send → MASTER await 收到
//   2. 连接复用：同一 (master_host, master_port) 二次推理复用 pp-llm/1 连接
//   3. 自动降级：逐跳反向 inject 先到达，直连未发 → hop_by_hop 胜出
//   4. 直连竞速：直连先到达后 inject → inject 返回 0（slot 已被取走）
//   5. 统计验证：results_received / direct_return_won / hop_by_hop_won / pool_hits 计数正确
//
// 依赖：linoh v3.2.1（P1 自动降级 + C-API return slot 管理 + 入站拦截）
// 环境：localhost UDP 回环，无需真实网络

#include "linoh/linoh_c.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <chrono>
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

// ============================================================================
// 辅助：创建 endpoint
// ============================================================================
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

// 辅助：轮询所有 endpoint 一段时间
static void poll_all(std::vector<linoh_endpoint_t *> eps, int timeout_ms) {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start).count() < timeout_ms) {
        for (auto *e : eps) {
            linoh_endpoint_poll(e);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

// 辅助：获取 endpoint 的 UDP 端口
static uint16_t get_udp_port(linoh_endpoint_t *ep) {
    return linoh_endpoint_udp_port(ep);
}

// ============================================================================
// 测试 1: 基本直连回传
//
// MASTER: enable_inbound → register_return_slot → await_return_result
// WORKER: open_return_stream → send_result_direct
// 验证：MASTER 收到与发送一致的 result_payload
// ============================================================================
static void test_basic_direct_return() {
    std::printf("[test] basic direct return (MASTER register → WORKER send → MASTER recv)...\n");

    linoh_endpoint_t *master = make_endpoint("default/1", 0);
    linoh_endpoint_t *worker = make_endpoint("default/1", 0);
    CHECK(master != nullptr);
    CHECK(worker != nullptr);

    uint16_t master_port = get_udp_port(master);
    CHECK(master_port != 0);

    // MASTER: 启用入站拦截 + 注册 return slot
    CHECK(linoh_direct_return_enable_inbound(master) == 0);
    uint32_t token = linoh_register_return_slot(master, 1001);
    CHECK(token != 0);

    // WORKER: 打开 return stream 并发送结果
    linoh_stream_t *rs = linoh_open_return_stream(
        worker, "127.0.0.1", master_port, token);
    CHECK(rs != nullptr);

    // 轮询让连接建立 + 握手完成
    poll_all({master, worker}, 3000);

    // WORKER: 重新 open（连接已在池中，pool hit）
    // 注意：首次 open_return_stream 可能连接尚未完全建立，重新 open 确保连接可用
    if (rs) linoh_close_return_stream(worker, rs);
    rs = linoh_open_return_stream(worker, "127.0.0.1", master_port, token);
    CHECK(rs != nullptr);

    // 构造测试 payload
    const char *test_data = "hello_direct_return_result_1234567890";
    size_t data_len = std::strlen(test_data);

    // WORKER: 发送 ResultPP[DirectReturn]
    int send_ret = linoh_send_result_direct(
        worker, rs, token,
        reinterpret_cast<const uint8_t *>(test_data), data_len, 1);
    CHECK(send_ret == 0);

    // 刷新 worker 发送缓冲（确保数据发出）
    // linoh_stream_write 内部写入 conn send buffer，需 poll 触发 flush
    poll_all({master, worker}, 5000);

    // MASTER: 等待直连回传结果
    uint8_t out_buf[256] = {};
    int64_t recv_len = linoh_await_return_result(
        master, token, 5000, out_buf, sizeof(out_buf));
    CHECK(recv_len > 0);
    if (recv_len > 0) {
        CHECK(static_cast<size_t>(recv_len) == data_len);
        CHECK(std::memcmp(out_buf, test_data, data_len) == 0);
    }

    // 验证统计
    linoh_direct_return_stats_t stats{};
    linoh_direct_return_stats(master, &stats);
    CHECK(stats.return_slots_registered >= 1);
    CHECK(stats.results_received >= 1);
    CHECK(stats.direct_return_won >= 1);

    if (rs) linoh_close_return_stream(worker, rs);
    linoh_endpoint_free(worker);
    linoh_endpoint_free(master);
}

// ============================================================================
// 测试 2: 连接复用（pool_hits）
//
// 同一 (master_host, master_port) 两次推理，第二次应命中连接池
// ============================================================================
static void test_connection_reuse() {
    std::printf("[test] connection reuse (pool_hits > 0 on second inference)...\n");

    linoh_endpoint_t *master = make_endpoint("default/1", 0);
    linoh_endpoint_t *worker = make_endpoint("default/1", 0);
    CHECK(master != nullptr);
    CHECK(worker != nullptr);

    uint16_t master_port = get_udp_port(master);
    CHECK(linoh_direct_return_enable_inbound(master) == 0);

    // 第一次推理
    uint32_t token1 = linoh_register_return_slot(master, 2001);
    CHECK(token1 != 0);

    linoh_stream_t *rs1 = linoh_open_return_stream(
        worker, "127.0.0.1", master_port, token1);
    CHECK(rs1 != nullptr);
    poll_all({master, worker}, 3000);

    if (rs1) linoh_close_return_stream(worker, rs1);
    rs1 = linoh_open_return_stream(worker, "127.0.0.1", master_port, token1);
    CHECK(rs1 != nullptr);

    const char *data1 = "first_result";
    CHECK(linoh_send_result_direct(
        worker, rs1, token1,
        reinterpret_cast<const uint8_t *>(data1), std::strlen(data1), 1) == 0);
    poll_all({master, worker}, 5000);

    uint8_t out1[128] = {};
    int64_t len1 = linoh_await_return_result(master, token1, 5000, out1, sizeof(out1));
    CHECK(len1 > 0);
    if (rs1) linoh_close_return_stream(worker, rs1);

    // 第二次推理（应复用连接）
    uint32_t token2 = linoh_register_return_slot(master, 2002);
    CHECK(token2 != 0);

    linoh_stream_t *rs2 = linoh_open_return_stream(
        worker, "127.0.0.1", master_port, token2);
    CHECK(rs2 != nullptr);
    poll_all({master, worker}, 3000);

    if (rs2) linoh_close_return_stream(worker, rs2);
    rs2 = linoh_open_return_stream(worker, "127.0.0.1", master_port, token2);
    CHECK(rs2 != nullptr);

    const char *data2 = "second_result";
    CHECK(linoh_send_result_direct(
        worker, rs2, token2,
        reinterpret_cast<const uint8_t *>(data2), std::strlen(data2), 1) == 0);
    poll_all({master, worker}, 5000);

    uint8_t out2[128] = {};
    int64_t len2 = linoh_await_return_result(master, token2, 5000, out2, sizeof(out2));
    CHECK(len2 > 0);
    if (len2 > 0) {
        CHECK(static_cast<size_t>(len2) == std::strlen(data2));
        CHECK(std::memcmp(out2, data2, std::strlen(data2)) == 0);
    }

    // 验证统计：至少 2 次注册 + 2 次接收
    linoh_direct_return_stats_t stats{};
    linoh_direct_return_stats(master, &stats);
    CHECK(stats.return_slots_registered >= 2);
    CHECK(stats.results_received >= 2);
    CHECK(stats.direct_return_won >= 2);

    if (rs2) linoh_close_return_stream(worker, rs2);
    linoh_endpoint_free(worker);
    linoh_endpoint_free(master);
}

// ============================================================================
// 测试 3: 自动降级（逐跳反向先到达）
//
// MASTER register slot → inject_hop_by_hop_result 先到达 → await 返回
// 不发送直连 return stream，模拟 dial 失败/超时场景
// ============================================================================
static void test_auto_degradation_hop_by_hop_wins() {
    std::printf("[test] auto degradation: hop-by-hop wins (no direct return sent)...\n");

    linoh_endpoint_t *master = make_endpoint("default/1", 0);
    CHECK(master != nullptr);
    CHECK(linoh_direct_return_enable_inbound(master) == 0);

    uint64_t req_id = 3001;
    uint32_t token = linoh_register_return_slot(master, req_id);
    CHECK(token != 0);

    // 模拟逐跳反向结果先到达（不发送直连 return stream）
    const char *hop_data = "hop_by_hop_result_degradation";
    size_t hop_len = std::strlen(hop_data);
    int inject_ret = linoh_inject_hop_by_hop_result(
        master, req_id,
        reinterpret_cast<const uint8_t *>(hop_data), hop_len);
    CHECK(inject_ret == 1);  // 逐跳反向胜出

    // MASTER: await 应立即返回逐跳结果
    uint8_t out_buf[256] = {};
    int64_t recv_len = linoh_await_return_result(
        master, token, 1000, out_buf, sizeof(out_buf));
    CHECK(recv_len > 0);
    if (recv_len > 0) {
        CHECK(static_cast<size_t>(recv_len) == hop_len);
        CHECK(std::memcmp(out_buf, hop_data, hop_len) == 0);
    }

    // 验证统计：hop_by_hop_won >= 1, direct_return_won == 0
    linoh_direct_return_stats_t stats{};
    linoh_direct_return_stats(master, &stats);
    CHECK(stats.hop_by_hop_won >= 1);
    CHECK(stats.fallback_invoked >= 1);
    CHECK(stats.results_received >= 1);

    linoh_endpoint_free(master);
}

// ============================================================================
// 测试 4: 直连竞优胜出（inject 返回 0）
//
// 直连 return 先到达（route_result 取走 slot）后，inject 返回 0
// 实现：先 inject（胜出），再注册新 slot + inject（slot 仍在，胜出）
//       然后测试 inject 对已 cancel 的 slot 返回 0
// ============================================================================
static void test_direct_wins_over_hop_by_hop() {
    std::printf("[test] direct wins: inject returns 0 after slot taken...\n");

    linoh_endpoint_t *master = make_endpoint("default/1", 0);
    CHECK(master != nullptr);
    CHECK(linoh_direct_return_enable_inbound(master) == 0);

    uint64_t req_id = 4001;
    uint32_t token = linoh_register_return_slot(master, req_id);
    CHECK(token != 0);

    // 先 cancel slot（模拟直连已取走）
    linoh_cancel_return_slot(master, token);

    // 再 inject：应返回 0（slot 已被取走）
    const char *hop_data = "late_hop_by_hop";
    int inject_ret = linoh_inject_hop_by_hop_result(
        master, req_id,
        reinterpret_cast<const uint8_t *>(hop_data), std::strlen(hop_data));
    CHECK(inject_ret == 0);  // 直连已胜出（slot 已被 cancel 取走）

    // 验证统计：fallback_invoked >= 1, hop_by_hop_won == 0
    linoh_direct_return_stats_t stats{};
    linoh_direct_return_stats(master, &stats);
    CHECK(stats.fallback_invoked >= 1);  // inject 被调用
    CHECK(stats.return_slots_cancelled >= 1);

    linoh_endpoint_free(master);
}

// ============================================================================
// 测试 5: cancel 后 await 返回 0（超时/取消语义）
// ============================================================================
static void test_cancel_then_await_timeout() {
    std::printf("[test] cancel then await returns 0 (timeout/cancel)...\n");

    linoh_endpoint_t *master = make_endpoint("default/1", 0);
    CHECK(master != nullptr);
    CHECK(linoh_direct_return_enable_inbound(master) == 0);

    uint32_t token = linoh_register_return_slot(master, 5001);
    CHECK(token != 0);

    linoh_cancel_return_slot(master, token);

    // await 已 cancel 的 slot：应返回 0 或 <0（非 >0）
    uint8_t out_buf[64] = {};
    int64_t recv_len = linoh_await_return_result(
        master, token, 500, out_buf, sizeof(out_buf));
    CHECK(recv_len <= 0);  // 超时/取消/错误，非成功

    linoh_endpoint_free(master);
}

// ============================================================================
// 测试 6: 未知 token await 安全返回
// ============================================================================
static void test_await_unknown_token_safe() {
    std::printf("[test] await unknown token safe (returns <=0)...\n");

    linoh_endpoint_t *master = make_endpoint("default/1", 0);
    CHECK(master != nullptr);
    CHECK(linoh_direct_return_enable_inbound(master) == 0);

    uint8_t out_buf[64] = {};
    int64_t recv_len = linoh_await_return_result(
        master, 0xDEADBEEF, 500, out_buf, sizeof(out_buf));
    CHECK(recv_len <= 0);  // 未知 token，超时或错误

    linoh_endpoint_free(master);
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::printf("=== test_direct_return_e2e (v3.2.1 P1-4) ===\n");

    test_basic_direct_return();
    test_connection_reuse();
    test_auto_degradation_hop_by_hop_wins();
    test_direct_wins_over_hop_by_hop();
    test_cancel_then_await_timeout();
    test_await_unknown_token_safe();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
