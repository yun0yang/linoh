/// linoh_e2e_stress_client.c
///
/// 端到端 linoh 通信压测客户端（Windows MSVC / C-API）。
///
/// 用法:
///   linoh_e2e_stress_client.exe <server_ip> <server_port> --size-mb 32 --rounds 5 --audit-dir .
///
/// 协议:
///   - ALPN: "e2e-stress/1"
///   - 每轮: open_stream -> write 4B size(BE) + 32MB data -> flush (循环) -> 等待 1B ACK
///   - 流式分片: 每次 write 64KB，多次 flush 直到写完
///
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <direct.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

#include "linoh/linoh_c.h"

#define CHUNK_BYTES  (64 * 1024)        // 64KB 每片
#define DEFAULT_SIZE_MB 32
#define DEFAULT_ROUNDS 5

typedef struct {
    HANDLE   ack_received;   // signal: ACK arrived
    uint8_t  ack_byte;       // 0x01=OK, 0x00=NAK
    int      state_changes;  // ESTABLISHED 计数
    linoh_connection_t *conn;  // 反向引用
} client_ctx_t;

static void on_state(linoh_connection_t *c, linoh_conn_state_t state, void *ud) {
    client_ctx_t *ctx = (client_ctx_t*)ud;
    ctx->state_changes++;
    printf("[CLIENT] state -> %d (changes=%d)\n", state, ctx->state_changes);
    fflush(stdout);
    if (state == LINOH_CONN_ESTABLISHED) {
        // ready
    }
}

static void on_close(linoh_connection_t *c, void *ud) {
    (void)c; (void)ud;
    printf("[CLIENT] connection closed\n");
    fflush(stdout);
}

static void on_stream(linoh_stream_t *s, void *ud) {
    client_ctx_t *ctx = (client_ctx_t*)ud;
    if (!ctx) return;
    uint8_t buf[256];
    size_t n = linoh_stream_read(s, buf, sizeof(buf));
    if (n > 0) {
        ctx->ack_byte = buf[0];
        printf("[CLIENT] received %zu bytes, ack=0x%02x\n", n, buf[0]);
        fflush(stdout);
        SetEvent(ctx->ack_received);
    }
    linoh_stream_free(s);
}

static double now_ms(void) {
    LARGE_INTEGER freq, c;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart * 1000.0 / (double)freq.QuadPart;
}

static void fill_random(uint8_t *buf, size_t len) {
    // 用 BCryptGenRandom 填充
    NTSTATUS s = BCryptGenRandom(NULL, buf, (ULONG)len,
                                 BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (s != 0) {
        fprintf(stderr, "BCryptGenRandom failed: 0x%08lx\n", s);
        // fallback: 用 rand()
        for (size_t i = 0; i < len; ++i) buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <server_ip> <server_port> [--size-mb N] [--rounds N] [--audit-dir PATH]\n", argv[0]);
        return 1;
    }
    const char *server_ip = argv[1];
    int server_port = atoi(argv[2]);
    int size_mb = DEFAULT_SIZE_MB;
    int rounds = DEFAULT_ROUNDS;
    const char *audit_dir = ".";

    for (int i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--size-mb") == 0 && i+1 < argc) {
            size_mb = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--rounds") == 0 && i+1 < argc) {
            rounds = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--audit-dir") == 0 && i+1 < argc) {
            audit_dir = argv[++i];
        }
    }

    printf("========================================================\n");
    printf("  linoh E2E Stress Client (v1.5.0.1, MSVC C-API)\n");
    printf("  Server: %s:%d, size=%dMB, rounds=%d, audit-dir=%s\n",
           server_ip, server_port, size_mb, rounds, audit_dir);
    printf("========================================================\n\n");

    // 让 audit 落指定目录（先 chdir 让 payload_audit 用 cwd 落盘）
    if (_chdir(audit_dir) != 0) {
        // 不致命，log 会落到默认 cwd
        fprintf(stderr, "warn: chdir to %s failed\n", audit_dir);
    }
    _putenv_s("LINOH_AUDIT", "1");
    _putenv_s("LINOH_AUDIT_DIR", audit_dir);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    // 1. 生成密钥对
    linoh_secret_key_t sk;
    linoh_public_key_t pk;
    if (linoh_generate_keypair(&sk, &pk) != LINOH_OK) {
        fprintf(stderr, "linoh_generate_keypair failed: %s\n", linoh_error_str());
        WSACleanup();
        return 1;
    }
    char pk_hex[64] = {0};
    linoh_public_key_fmt_short(&pk, pk_hex, sizeof(pk_hex));
    printf("[CLIENT] local node_id=%s\n", pk_hex);

    // 2. 创建 endpoint
    linoh_endpoint_config_t cfg = {0};
    cfg.secret_key = sk;
    cfg.alpn = "e2e-stress/1";
    cfg.udp_port = 0;  // 随机分配
    cfg.user_data = NULL;

    client_ctx_t ctx = {0};
    ctx.ack_received = CreateEvent(NULL, FALSE, FALSE, NULL);
    ctx.ack_byte = 0xFF;
    cfg.user_data = &ctx;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    if (!ep) {
        fprintf(stderr, "linoh_endpoint_create failed: %s\n", linoh_error_str());
        CloseHandle(ctx.ack_received);
        WSACleanup();
        return 1;
    }

    // 注册回调
    linoh_endpoint_on_conn_state(ep, on_state);
    linoh_endpoint_on_close(ep, on_close);
    linoh_endpoint_on_stream(ep, on_stream);
    linoh_endpoint_set_user_data(ep, &ctx);

    const linoh_endpoint_id_t *my_id = linoh_endpoint_id(ep);
    char my_hex[64] = {0};
    linoh_public_key_fmt_short((const linoh_public_key_t*)my_id, my_hex, sizeof(my_hex));
    printf("[CLIENT] endpoint node_id=%s udp_port=%u\n", my_hex, linoh_endpoint_udp_port(ep));

    // 3. 连接到 server
    printf("[CLIENT] connecting to %s:%d ...\n", server_ip, server_port);
    fflush(stdout);
    linoh_connection_t *conn = linoh_endpoint_connect_with_alpn(ep, server_ip, (uint16_t)server_port, "e2e-stress/1");
    if (!conn) {
        fprintf(stderr, "linoh_endpoint_connect_with_alpn failed: %s\n", linoh_error_str());
        linoh_endpoint_free(ep);
        CloseHandle(ctx.ack_received);
        WSACleanup();
        return 1;
    }
    ctx.conn = conn;
    printf("[CLIENT] connection initiated, waiting ESTABLISHED...\n");
    fflush(stdout);

    // 4. 等待 ESTABLISHED（最多 30s）
    double t0 = now_ms();
    while (linoh_connection_state(conn) != LINOH_CONN_ESTABLISHED) {
        linoh_endpoint_poll(ep);
        Sleep(20);
        if (now_ms() - t0 > 30000.0) {
            fprintf(stderr, "[CLIENT] handshake timeout\n");
            linoh_connection_free(conn);
            linoh_endpoint_free(ep);
            CloseHandle(ctx.ack_received);
            WSACleanup();
            return 1;
        }
    }
    double handshake_ms = now_ms() - t0;
    printf("[CLIENT] ESTABLISHED in %.1fms\n", handshake_ms);
    fflush(stdout);

    // 5. 跑 N 轮
    size_t total_bytes = (size_t)size_mb * 1024 * 1024;
    size_t chunks = (total_bytes + CHUNK_BYTES - 1) / CHUNK_BYTES;
    uint8_t *payload = (uint8_t*)malloc(CHUNK_BYTES);
    if (!payload) {
        fprintf(stderr, "malloc %d failed\n", CHUNK_BYTES);
        return 1;
    }
    fill_random(payload, CHUNK_BYTES);

    double total_send_start = now_ms();
    for (int round = 1; round <= rounds; ++round) {
        printf("\n[CLIENT] ===== Round %d/%d: open_stream =====\n", round, rounds);
        fflush(stdout);

        ResetEvent(ctx.ack_received);
        ctx.ack_byte = 0xFF;

        linoh_stream_t *stream = linoh_connection_open_stream(conn);
        if (!stream) {
            fprintf(stderr, "[CLIENT] open_stream failed\n");
            free(payload);
            return 1;
        }

        // 写 4B size(BE)
        uint8_t size_hdr[4];
        uint32_t sz_be = (uint32_t)total_bytes;
        size_hdr[0] = (sz_be >> 24) & 0xFF;
        size_hdr[1] = (sz_be >> 16) & 0xFF;
        size_hdr[2] = (sz_be >>  8) & 0xFF;
        size_hdr[3] = (sz_be      ) & 0xFF;
        linoh_stream_write(stream, size_hdr, 4);

        double round_start = now_ms();
        for (size_t i = 0; i < chunks; ++i) {
            size_t remaining = total_bytes - i * CHUNK_BYTES;
            size_t this_chunk = (remaining < CHUNK_BYTES) ? remaining : CHUNK_BYTES;
            size_t w = linoh_stream_write(stream, payload, this_chunk);
            if (w < this_chunk) {
                fprintf(stderr, "[CLIENT] short write %zu/%zu at chunk %zu/%zu\n",
                        w, this_chunk, i+1, chunks);
            }
            // 每 4 chunks flush 一次
            if ((i & 3) == 3 || i + 1 == chunks) {
                linoh_connection_flush(conn);
            }
        }
        // 收尾
        linoh_stream_finish(stream);
        linoh_connection_flush(conn);

        // 等待 ACK（最多 240s） 6-3 retx 调优: 60s->240s, 5% drop 下 32MB retx 完成需 200s+ 充分余量
        double t_round_flush = now_ms();
        DWORD wait_ret = WaitForSingleObject(ctx.ack_received, 240000);
        double round_elapsed = now_ms() - round_start;
        if (wait_ret == WAIT_OBJECT_0) {
            double ack_after = now_ms() - t_round_flush;
            double throughput = (double)total_bytes / round_elapsed * 1000.0 / 1024.0 / 1024.0;
            printf("[CLIENT] round=%d sent=%zu in %.1fms (ack_after=%.1fms) ack=0x%02x throughput=%.2fMB/s\n",
                   round, total_bytes, round_elapsed, ack_after, ctx.ack_byte, throughput);
        } else {
            fprintf(stderr, "[CLIENT] round=%d timeout (no ACK in 60s) elapsed=%.1fms\n",
                    round, round_elapsed);
        }
        fflush(stdout);

        linoh_stream_free(stream);

        // 轮间暂停
        Sleep(200);
    }
    double total_ms = now_ms() - total_send_start;
    printf("\n[CLIENT] ===== All %d rounds done in %.1fms =====\n", rounds, total_ms);
    fflush(stdout);

    // 6. 关闭
    linoh_connection_close(conn, 0, "done");
    Sleep(200);
    linoh_connection_free(conn);
    linoh_endpoint_free(ep);
    CloseHandle(ctx.ack_received);
    free(payload);
    WSACleanup();
    return 0;
}
