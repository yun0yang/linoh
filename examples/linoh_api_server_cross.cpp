/// linoh_api_server_cross.cpp - 跨平台 C-API Echo Server
/// PoC 用：验证 win-worker linoh P2P 连接建立与 stream 双向通信
/// Linux/macOS/Windows 通用

#include "linoh/linoh_c.h"

#include <cstdio>
#include <cstring>
#include <atomic>
#include <thread>
#include <chrono>
#include <vector>
#include <mutex>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

static std::atomic<uint32_t> g_total_rx{0};
static std::atomic<uint32_t> g_total_tx{0};
static std::mutex g_stream_mu;

// 简单的 stream 回调：收到数据后回显（让 worker 看到握手成功）
static void on_echo_stream(linoh_stream_t *stream, void *user_data) {
    (void)user_data;
    uint8_t buf[4096];
    size_t n = linoh_stream_read(stream, buf, sizeof(buf));
    if (n == 0) {
        printf("[ECHO] empty stream, finish\n");
        linoh_stream_finish(stream);
        return;
    }
    g_total_rx.fetch_add((uint32_t)n);

    bool printable = (n > 0);
    for (size_t i = 0; i < n && i < 64; i++) {
        if (buf[i] < 32 || buf[i] > 126) { printable = false; break; }
    }
    if (printable) {
        printf("[ECHO] recv %zu bytes: %.*s\n", n, (int)n, buf);
    } else {
        printf("[ECHO] recv %zu binary bytes\n", n);
    }

    // 回显
    size_t written = linoh_stream_write(stream, buf, n);
    g_total_tx.fetch_add((uint32_t)written);

    const linoh_connection_t *c = linoh_stream_connection(stream);
    if (c != nullptr) {
        linoh_connection_flush((linoh_connection_t *)c);
    }
}

static void on_echo_connection(linoh_connection_t *conn, void *user_data) {
    (void)user_data;
    printf("[SERVER] new connection arrived\n");

    // 主动打开一条 stream
    linoh_stream_t *echo_s = linoh_connection_open_stream(conn);
    if (echo_s != nullptr) {
        printf("[SERVER] opened echo stream id=%llu\n",
               (unsigned long long)linoh_stream_id(echo_s));
    }
    linoh_connection_flush(conn);
}

int main(int argc, char *argv[]) {
    uint16_t port = 9001;
    if (argc >= 2) port = (uint16_t)atoi(argv[1]);

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[ERROR] WSAStartup failed\n");
        return 1;
    }
#endif

    printf("========================================\n");
    printf("  linoh C-API Echo Server (PoC)\n");
    printf("  UDP port: %u\n", (unsigned)port);
    printf("========================================\n");

    linoh_secret_key_t sk{};
    linoh_public_key_t  pk{};
    if (linoh_generate_keypair(&sk, &pk) != 0) {
        printf("[ERROR] failed to generate keypair\n");
        return 1;
    }

    linoh_endpoint_config_t cfg{};
    memcpy(&cfg.secret_key, &sk, sizeof(sk));
    cfg.alpn       = "pp-inference/1";
    cfg.udp_port   = port;
    cfg.user_data  = nullptr;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    if (ep == nullptr) {
        printf("[ERROR] linoh_endpoint_create failed: %s\n", linoh_error_str());
        return 1;
    }

    printf("[SERVER] endpoint created, port=%u\n",
           (unsigned)linoh_endpoint_udp_port(ep));

    char pk_buf[128];
    size_t pn = linoh_public_key_fmt_short(&pk, pk_buf, sizeof(pk_buf));
    printf("[SERVER] node id: %.*s\n", (int)pn, pk_buf);

    linoh_endpoint_on_connection(ep, on_echo_connection);
    linoh_endpoint_on_stream(ep, on_echo_stream);

    printf("[SERVER] ready (Ctrl+C to exit)\n");

    uint32_t tick = 0;
    while (true) {
        int events = linoh_endpoint_poll(ep);
        if (events > 0) {
            printf("[SERVER] poll events: %d\n", events);
        }
        tick++;
        if ((tick % 100) == 0) {
            uint32_t rx = g_total_rx.load();
            uint32_t tx = g_total_tx.load();
            if (rx > 0 || tx > 0) {
                printf("[SERVER] stats rx=%u tx=%u\n", rx, tx);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    linoh_endpoint_free(ep);
    return 0;
}
