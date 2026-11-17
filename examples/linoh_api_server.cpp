/// linoh_api_server.cpp - v1.0 C-API Echo 服务器示例
/// 演示: linoh_endpoint_create/on_stream/flush/free 全流程

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WINSOCKAPI_
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include "linoh/linoh_c.h"

#include <cstdio>
#include <cstring>
#include <atomic>
#include <thread>
#include <chrono>

/// --- 全局统计（用于调试输出）---
static std::atomic<uint32_t> g_total_rx{0};
static std::atomic<uint32_t> g_total_tx{0};

/// --- Stream 回调：收到流数据 -> 回显 ---
static void on_echo_stream(linoh_stream_t *stream, void *user_data) {
    (void)user_data;
    uint8_t buf[2048];

    /// 读取远程流发来的数据
    size_t n = linoh_stream_read(stream, buf, sizeof(buf));
    if (n == 0) {
        printf("[ECHO] empty stream, finish\n");
        linoh_stream_finish(stream);
        return;
    }
    g_total_rx.fetch_add((uint32_t)n);

    /// 打印（可打印字符部分）
    bool printable = true;
    for (size_t i = 0; i < n; i++) {
        if (buf[i] < 32 || buf[i] > 126) { printable = false; break; }
    }
    if (printable) {
        printf("[ECHO] received %zu bytes: %.*s\n", n, (int)n, buf);
    } else {
        printf("[ECHO] received %zu binary bytes (hex)\n", n);
    }

    /// 回显：写回同一条 stream（双方同 ID，对端会收到）
    size_t written = linoh_stream_write(stream, buf, n);
    g_total_tx.fetch_add((uint32_t)written);

    /// 获取连接对象以便 flush
    const linoh_connection_t *c = linoh_stream_connection(stream);
    if (c != nullptr) {
        size_t sent = linoh_connection_flush((linoh_connection_t *)c);
        if (sent > 0) {
            printf("[ECHO] flushed %zu bytes to wire\n", sent);
        } else {
            printf("[ECHO] flush returned 0 (no data or not connected)\n");
        }
    }
}

/// --- Connection 回调：新连接到达 -> 注册 Stream 回调 ---
static void on_echo_connection(linoh_connection_t *conn, void *user_data) {
    (void)user_data;
    printf("[SERVER] new connection arrived, registering stream callback\n");

    /// 注册 stream 回调
    linoh_endpoint_t *ep = (linoh_endpoint_t *)user_data;
    /// 注意：这里通过 Endpoint 注册 stream 回调
    /// 但 stream 回调已经是 per-connection 的，直接调用 on_stream 也可以
    /// 简化：在这里对每个连接独立注册
    (void)ep;

    /// 主动打开一条 stream 用于回显
    linoh_stream_t *echo_s = linoh_connection_open_stream(conn);
    if (echo_s != nullptr) {
        printf("[SERVER] opened echo stream id=%llu\n",
               (unsigned long long)linoh_stream_id(echo_s));
    }

    /// flush 任何初始化数据（空操作，此处仅占位）
    linoh_connection_flush(conn);
}

int main() {
    printf("========================================\n");
    printf("  linoh C-API Echo Server (v1.0)\n");
    printf("  Listening on UDP port 54321\n");
    printf("========================================\n");

    /// 生成密钥对
    linoh_secret_key_t sk{};
    linoh_public_key_t  pk{};
    if (linoh_generate_keypair(&sk, &pk) != 0) {
        printf("[ERROR] failed to generate keypair\n");
        return 1;
    }

    /// 配置 Endpoint
    linoh_endpoint_config_t cfg{};
    memcpy(&cfg.secret_key, &sk, sizeof(sk));
    cfg.alpn        = "echo/1";
    cfg.udp_port   = 54321;
    cfg.user_data  = nullptr;

    /// 创建 Endpoint
    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    if (ep == nullptr) {
        printf("[ERROR] linoh_endpoint_create failed: %s\n", linoh_error_str());
        return 1;
    }
    printf("[SERVER] endpoint created, local port=%u\n",
           (unsigned)linoh_endpoint_udp_port(ep));

    /// 打印节点公钥
    char pk_buf[128];
    size_t pn = linoh_public_key_fmt_short(&pk, pk_buf, sizeof(pk_buf));
    printf("[SERVER] node id: %.*s\n", (int)pn, pk_buf);

    /// 注册 connection & stream 回调
    linoh_endpoint_on_connection(ep, on_echo_connection);
    linoh_endpoint_on_stream(ep, on_echo_stream);

    printf("[SERVER] ready to accept connections... (press Ctrl+C to exit)\n");

    /// 主循环：poll + 休眠
    uint32_t tick = 0;
    while (true) {
        int events = linoh_endpoint_poll(ep);
        if (events > 0) {
            printf("[SERVER] poll events: %d\n", events);
        }

        /// 每 5 秒打印一次统计
        tick++;
        if ((tick % 50) == 0) {
            uint32_t rx = g_total_rx.load();
            uint32_t tx = g_total_tx.load();
            if (rx > 0 || tx > 0) {
                printf("[SERVER] stats rx=%u tx=%u\n", rx, tx);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    /// 正常退出（不会到达）
    linoh_endpoint_free(ep);
    printf("[SERVER] done\n");
    return 0;
}
