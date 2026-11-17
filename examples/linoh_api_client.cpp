/// linoh_api_client.cpp - v1.0 C-API Echo 客户端示例
/// 演示: linoh_endpoint_create / linoh_endpoint_connect / linoh_stream_write / linoh_stream_read

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
#include <thread>
#include <chrono>
#include <atomic>

static std::atomic<bool> g_received_echo{false};

/// Stream 回调：收到服务器回显
static void on_client_stream(linoh_stream_t *stream, void *user_data) {
    (void)user_data;
    uint8_t buf[2048];
    size_t n = linoh_stream_read(stream, buf, sizeof(buf));
    if (n > 0) {
        bool printable = true;
        for (size_t i = 0; i < n; i++) {
            if (buf[i] < 32 || buf[i] > 126) { printable = false; break; }
        }
        if (printable) {
            printf("[CLIENT] echo received %zu bytes: %.*s\n", n, (int)n, buf);
        } else {
            printf("[CLIENT] echo received %zu binary bytes\n", n);
        }
        g_received_echo.store(true);
    }
}

int main() {
    printf("========================================\n");
    printf("  linoh C-API Echo Client (v1.0)\n");
    printf("  Connecting to 127.0.0.1:54321\n");
    printf("========================================\n");

    /// 生成密钥对
    linoh_secret_key_t sk{};
    linoh_public_key_t  pk{};
    if (linoh_generate_keypair(&sk, &pk) != 0) {
        printf("[ERROR] failed to generate keypair\n");
        return 1;
    }

    /// 配置 Endpoint（客户端：端口 0，让 OS 分配）
    linoh_endpoint_config_t cfg{};
    memcpy(&cfg.secret_key, &sk, sizeof(sk));
    cfg.alpn        = "echo/1";
    cfg.udp_port   = 0;
    cfg.user_data  = nullptr;

    /// 创建 Endpoint
    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    if (ep == nullptr) {
        printf("[ERROR] linoh_endpoint_create failed: %s\n", linoh_error_str());
        return 1;
    }
    printf("[CLIENT] endpoint created, local port=%u\n",
           (unsigned)linoh_endpoint_udp_port(ep));

    /// 注册 stream 回调
    linoh_endpoint_on_stream(ep, on_client_stream);

    /// 连接到服务器
    linoh_connection_t *conn = linoh_endpoint_connect(ep, "127.0.0.1", 54321);
    if (conn == nullptr) {
        printf("[ERROR] linoh_endpoint_connect failed\n");
        return 1;
    }
    printf("[CLIENT] connected, opening stream...\n");

    /// 等待一下让服务器处理 Initial 包
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    /// 打开流并发送数据
    linoh_stream_t *stream = linoh_connection_open_stream(conn);
    if (stream == nullptr) {
        printf("[ERROR] linoh_connection_open_stream failed\n");
        return 1;
    }
    printf("[CLIENT] opened stream id=%llu\n",
           (unsigned long long)linoh_stream_id(stream));

    const char *msg = "Hello, linoh via C-API!";
    size_t written = linoh_stream_write(stream, (const uint8_t*)msg, strlen(msg));
    printf("[CLIENT] wrote %zu bytes to stream\n", written);

    /// flush 实际发送
    size_t flushed = linoh_connection_flush(conn);
    printf("[CLIENT] flushed %zu bytes to wire\n", flushed);

    /// 等待回显（最多 3 秒）
    for (int i = 0; i < 30; i++) {
        if (g_received_echo.load()) break;
        linoh_endpoint_poll(ep);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    /// 报告结果
    if (g_received_echo.load()) {
        printf("[CLIENT] echo test PASSED\n");
    } else {
        printf("[CLIENT] echo test FAILED (no echo received)\n");
    }

    /// 清理
    linoh_endpoint_free(ep);
    printf("[CLIENT] done\n");
    return 0;
}
