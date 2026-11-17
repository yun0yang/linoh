// test_e2e_stress_client_linux.cpp
//
// linoh e2e stress test client (Linux, C-API).
// 与 test_e2e_stress_server.cpp 配套使用，ALPN: "e2e-stress/1"
//
// v1.5.0.1 P1 协议：1 round = 1 个 stream + 一次性 write total_bytes 字节
// server 端主动轮询 stream readable_size 等待数据到齐（非 RPC 模式）

#include "linoh/linoh_c.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

// v1.5.0.1 P1: OpenSSL EVP API（worker-node 老 OpenSSL 用 EVP_MD_CTX_create/destroy）
#include <openssl/evp.h>

// 全局状态
static struct {
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int             hs_done;          // handshake 完成标志
    linoh_conn_state_t hs_state;
    int             ack_received;
    uint8_t         ack_byte;
} g_ctx;

static void on_conn_state(linoh_connection_t *conn, linoh_conn_state_t state, void *ud) {
    (void)conn; (void)ud;
    pthread_mutex_lock(&g_ctx.mu);
    g_ctx.hs_state = state;
    if (state == LINOH_CONN_ESTABLISHED) {
        g_ctx.hs_done = 1;
        printf("[CLIENT] HANDSHAKE DONE state=%d\n", (int)state);
    } else {
        printf("[CLIENT] state change: %d\n", (int)state);
    }
    fflush(stdout);
    pthread_cond_broadcast(&g_ctx.cv);
    pthread_mutex_unlock(&g_ctx.mu);
}

static void on_close(linoh_connection_t *conn, void *ud) {
    (void)conn; (void)ud;
    printf("[CLIENT] conn closed\n"); fflush(stdout);
}

static void on_stream(linoh_stream_t *stream, void *ud) {
    (void)ud;
    // 1B ACK
    uint8_t buf[16];
    size_t n = linoh_stream_read(stream, buf, sizeof(buf));
    printf("[CLIENT] on_stream sid=%llu readable=%d n=%zu\n",
           (unsigned long long)linoh_stream_id(stream),
           linoh_stream_has_readable(stream), n);
    fflush(stdout);
    if (n > 0) {
        pthread_mutex_lock(&g_ctx.mu);
        g_ctx.ack_byte = buf[0];
        g_ctx.ack_received = 1;
        pthread_cond_broadcast(&g_ctx.cv);
        pthread_mutex_unlock(&g_ctx.mu);
    }
    linoh_stream_free(stream);
}

static double now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void fill_random(uint8_t *buf, size_t len) {
    static uint64_t seed = 0xCAFEBABEDEADBEEFULL;
    for (size_t i = 0; i < len; i += 8) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        size_t remain = (i + 8 <= len) ? 8 : (len - i);
        memcpy(buf + i, &seed, remain);
    }
}

static void *poll_thread_fn(void *arg) {
    linoh_endpoint_t *ep = (linoh_endpoint_t *)arg;
    while (1) {
        linoh_endpoint_poll(ep);
        usleep(1000);  // 1ms
    }
    return nullptr;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <server_ip> <server_port> --size-mb N --rounds N --audit-dir PATH\n", argv[0]);
        return 1;
    }
    const char *server_ip = argv[1];
    int server_port = atoi(argv[2]);
    int size_mb = 32;
    int rounds = 5;
    const char *audit_dir = ".";
    for (int i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--size-mb") == 0 && i+1 < argc) size_mb = atoi(argv[++i]);
        else if (strcmp(argv[i], "--rounds") == 0 && i+1 < argc) rounds = atoi(argv[++i]);
        else if (strcmp(argv[i], "--audit-dir") == 0 && i+1 < argc) audit_dir = argv[++i];
    }

    printf("========================================================\n");
    printf("  linoh E2E Stress Client (v1.5.0.1 P1)\n");
    printf("  Server: %s:%d, size=%dMB, rounds=%d, audit-dir=%s\n",
           server_ip, server_port, size_mb, rounds, audit_dir);
    printf("  Protocol: 1 round = 1 stream + %dMB write + wait ACK\n", size_mb);
    printf("========================================================\n\n");
    fflush(stdout);

    setenv("LINOH_AUDIT", "1", 1);
    setenv("LINOH_AUDIT_DIR", audit_dir, 1);

    pthread_mutex_init(&g_ctx.mu, nullptr);
    pthread_cond_init(&g_ctx.cv, nullptr);
    g_ctx.hs_done = 0;
    g_ctx.hs_state = LINOH_CONN_INITIAL;
    g_ctx.ack_received = 0;
    g_ctx.ack_byte = 0xFF;

    // 1) 创建 endpoint
    linoh_endpoint_config_t cfg{};
    cfg.alpn = "e2e-stress/1";
    cfg.user_data = nullptr;
    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    if (!ep) { fprintf(stderr, "linoh_endpoint_create failed\n"); return 1; }
    char id_buf[32];
    linoh_public_key_fmt_short(linoh_endpoint_id(ep), id_buf, sizeof(id_buf));
    printf("[CLIENT] endpoint created, local_id=%s\n", id_buf);
    fflush(stdout);

    linoh_endpoint_on_conn_state(ep, on_conn_state);
    linoh_endpoint_on_stream(ep, on_stream);

    // 2) 主动连接 server
    linoh_connection_t *conn = linoh_endpoint_connect_with_alpn(
        ep, server_ip, (uint16_t)server_port, "e2e-stress/1");
    if (!conn) { fprintf(stderr, "connect failed\n"); return 1; }
    printf("[CLIENT] outbound conn created, server=%s:%d\n", server_ip, server_port);
    fflush(stdout);

    // 3) 启动 poll 线程
    pthread_t poll_thread;
    pthread_create(&poll_thread, nullptr, poll_thread_fn, ep);

    // 4) 等待 handshake
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 30;
    pthread_mutex_lock(&g_ctx.mu);
    while (!g_ctx.hs_done) {
        int rc = pthread_cond_timedwait(&g_ctx.cv, &g_ctx.mu, &deadline);
        if (rc != 0) {
            fprintf(stderr, "[CLIENT] handshake timeout (30s)\n");
            pthread_mutex_unlock(&g_ctx.mu);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_ctx.mu);
    printf("[CLIENT] handshake complete, starting data xfer\n");
    fflush(stdout);

    // 5) 跑 rounds
    size_t total_bytes = (size_t)size_mb * 1024 * 1024;
    uint8_t *payload = (uint8_t *)malloc(total_bytes);
    if (!payload) { fprintf(stderr, "malloc %zu failed\n", total_bytes); return 1; }
    fill_random(payload, total_bytes);

    // v1.5.0.1 P1: 打印 payload 真实 SHA256 头 16 字节用于与 server log 对比验证
    // （fill_random 是确定性 LCG，相同代码/seed 总是生成相同 payload）
    {
        unsigned char sha[32];
        EVP_MD_CTX* ctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, payload, total_bytes);
        unsigned int outlen = 32;
        EVP_DigestFinal_ex(ctx, sha, &outlen);
        EVP_MD_CTX_destroy(ctx);
        printf("[CLIENT] payload_sha256=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x total_bytes=%zu\n",
               sha[0],sha[1],sha[2],sha[3],sha[4],sha[5],sha[6],sha[7],
               sha[8],sha[9],sha[10],sha[11],sha[12],sha[13],sha[14],sha[15],
               total_bytes);
        fflush(stdout);
    }

    double t_total = now_ms();
    for (int round = 1; round <= rounds; ++round) {
        printf("\n[CLIENT] ===== Round %d/%d =====\n", round, rounds);
        fflush(stdout);
        pthread_mutex_lock(&g_ctx.mu);
        g_ctx.ack_received = 0;
        g_ctx.ack_byte = 0xFF;
        pthread_mutex_unlock(&g_ctx.mu);

        linoh_stream_t *st = linoh_connection_open_stream(conn);
        if (!st) { fprintf(stderr, "open_stream failed\n"); break; }

        double round_start = now_ms();
        // v1.5.0.1 P1: 1 round = 1 stream + 一次性 write total_bytes
        // server 端主动轮询 stream readable_size 等数据到齐
        size_t written = linoh_stream_write(st, payload, total_bytes);
        printf("[CLIENT] round=%d st=%p sid=%llu wrote %zu/%zu bytes\n",
               round, (void*)st, (unsigned long long)linoh_stream_id(st),
               written, total_bytes);
        fflush(stdout);
        linoh_stream_finish(st);
        linoh_connection_flush(conn);
        printf("[CLIENT] round=%d finish+flush done\n", round);
        fflush(stdout);
        linoh_stream_free(st);

        // 等 ACK（最多 120s，给 32MB 大数据足够时间）
        struct timespec ack_deadline;
        clock_gettime(CLOCK_REALTIME, &ack_deadline);
        ack_deadline.tv_sec += 120;
        pthread_mutex_lock(&g_ctx.mu);
        while (!g_ctx.ack_received) {
            int rc = pthread_cond_timedwait(&g_ctx.cv, &g_ctx.mu, &ack_deadline);
            if (rc != 0) break;
        }
        pthread_mutex_unlock(&g_ctx.mu);
        double round_ms = now_ms() - round_start;
        double throughput = (double)total_bytes / round_ms * 1000.0 / 1024.0 / 1024.0;
        pthread_mutex_lock(&g_ctx.mu);
        if (g_ctx.ack_received) {
            printf("[CLIENT] round=%d sent=%zu in %.1fms ack=0x%02x throughput=%.2fMB/s\n",
                   round, total_bytes, round_ms, g_ctx.ack_byte, throughput);
        } else {
            printf("[CLIENT] round=%d TIMEOUT after %.1fms\n", round, round_ms);
        }
        pthread_mutex_unlock(&g_ctx.mu);
        fflush(stdout);
        usleep(200 * 1000);
    }

    double total_ms = now_ms() - t_total;
    printf("\n[CLIENT] ===== All %d rounds done in %.1fms =====\n", rounds, total_ms);
    fflush(stdout);

    linoh_connection_close(conn, 0, "done");
    sleep(1);
    free(payload);
    return 0;
}
