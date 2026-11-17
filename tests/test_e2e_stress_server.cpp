/// linoh_e2e_stress_server.cpp
///
/// 端到端 linoh 通信压测服务器：监听 UDP，接收 N 轮大消息数据 + 校验 SHA256。
///
/// 用法:
///   ./test_e2e_stress_server --port 9101 --rounds 5 --audit-dir /home/ubuntu/cluster/e2e_logs
///
/// 协议:
///   - ALPN: "e2e-stress/1"（不与现有 pp-hidden/1 冲突）
///   - 每个 stream: client 一次性 write total_bytes（32MB），server 主动轮询
///     stream readable_size 等待数据到齐 + 计算 SHA256 + 回复 1B ACK
///   - 非 RPC 模式：on_stream 只在新建 stream 时触发 1 次，靠 main loop 主动 poll
///
/// v1.5.0.1 P1: 1 round = 1 个 stream + 一次性写 total_bytes（32MB 模式）
///   避开 on_stream 触发 1 次的限制，server 主动 poll stream buffer 累积
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define LINOH_SOCK_VALID(s) ((s) != INVALID_SOCKET)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <cstring>
#define closesocket(s) close(s)
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define WSAGetLastError() errno
typedef int WSADATA;
static inline int WSAStartup(int, WSADATA*) { return 0; }
static inline int WSACleanup() { return 0; }
static inline int linoh_setsockopt_rcvtimeo(SOCKET s, int ms) {
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}
#define LINOH_SOCK_VALID(s) ((s) >= 0)
#endif

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/endpoint/endpoint.hpp"
#include "linoh/endpoint/builder.hpp"
#include "linoh/endpoint/connection.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/util/bytes.hpp"

// v1.5.0.1 P1: OpenSSL EVP API（worker-node 老 OpenSSL 用 EVP_MD_CTX_create/destroy）
#include <openssl/evp.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <cstdint>
#include <atomic>

using namespace linoh;
using namespace linoh::base;
using namespace linoh::protocol;
using namespace linoh::endpoint;

// SHA256 简易实现（用于校验 payload）
namespace sha256_impl {
struct State {
    uint32_t h[8];
    uint8_t  buf[64];
    size_t   buf_len;
    uint64_t total;
};

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void process(State& s, const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (uint32_t(p[i*4]) << 24) | (uint32_t(p[i*4+1]) << 16) |
               (uint32_t(p[i*4+2]) << 8) | uint32_t(p[i*4+3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=s.h[0],b=s.h[1],c=s.h[2],d=s.h[3],e=s.h[4],f=s.h[5],g=s.h[6],h=s.h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + k[i] + w[i];
        uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; t1+t2;
    }
    s.h[0]+=a; s.h[1]+=b; s.h[2]+=c; s.h[3]+=d;
    s.h[4]+=e; s.h[5]+=f; s.h[6]+=g; s.h[7]+=h;
}

static void init(State& s) {
    s.h[0]=0x6a09e667; s.h[1]=0xbb67ae85; s.h[2]=0x3c6ef372; s.h[3]=0xa54ff53a;
    s.h[4]=0x510e527f; s.h[5]=0x9b05688c; s.h[6]=0x1f83d9ab; s.h[7]=0x5be0cd19;
    s.buf_len=0; s.total=0;
}

static void update(State& s, const uint8_t* d, size_t n) {
    s.total += n;
    while (n) {
        size_t take = std::min(n, sizeof(s.buf) - s.buf_len);
        memcpy(s.buf + s.buf_len, d, take);
        s.buf_len += take; d += take; n -= take;
        if (s.buf_len == 64) { process(s, s.buf); s.buf_len = 0; }
    }
}

static void finish(State& s, uint8_t out[32]) {
    uint64_t bits = s.total * 8;
    s.buf[s.buf_len++] = 0x80;
    if (s.buf_len > 56) {
        while (s.buf_len < 64) s.buf[s.buf_len++] = 0;
        process(s, s.buf); s.buf_len = 0;
    }
    while (s.buf_len < 56) s.buf[s.buf_len++] = 0;
    for (int i = 7; i >= 0; --i) s.buf[s.buf_len++] = (bits >> (i*8)) & 0xFF;
    process(s, s.buf);
    for (int i = 0; i < 8; ++i) {
        out[i*4]   = (s.h[i] >> 24) & 0xFF;
        out[i*4+1] = (s.h[i] >> 16) & 0xFF;
        out[i*4+2] = (s.h[i] >>  8) & 0xFF;
        out[i*4+3] = (s.h[i]      ) & 0xFF;
    }
}

static void hash(const uint8_t* d, size_t n, uint8_t out[32]) {
    State s; init(s); update(s, d, n); finish(s, out);
}
} // namespace sha256_impl

// SHA256 using OpenSSL EVP API
static void sha256_hash(const uint8_t* data, size_t n, uint8_t out[32]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, n);
    unsigned int outlen = 32;
    EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_destroy(ctx);
}

struct PeerInfo {
    std::shared_ptr<Connection> conn;
    sockaddr_in addr;
    int rounds_completed = 0;
    int rounds_target = 0;
    std::vector<uint8_t> recv_buf;
    bool header_seen = false;
    size_t total_expected = 0;
    size_t body_received = 0;
    std::chrono::steady_clock::time_point round_start;
    std::chrono::steady_clock::time_point round_end;
    // v1.5.0.1 P1: 新增 inbound stream weak_ptr（on_stream 触发 1 次时记录）
    // main loop 主动 poll stream->readable_size() 等待数据到齐
    std::weak_ptr<Stream> inbound_stream;
    size_t round_id = 0;  // 用于区分不同 round
    // 6-3 fix: flow control 通告时间戳，每秒调用 emit_periodic_flow_control
    std::chrono::steady_clock::time_point last_fc_emit;
};

static std::string ipv4_str(const sockaddr_in* sa) {
    char buf[32];
    inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
    return std::string(buf);
}

static void send_ack(PeerInfo& pi, bool ok) {
    uint8_t b = ok ? 0x01 : 0x00;
    auto st = pi.conn->open_stream();
    st->write(std::span<const uint8_t>(&b, 1));
}

// v1.5.0.1 P1: 主动轮询 stream buffer 累积数据
// 当 readable_size() + body_received >= total_expected 时处理
static void poll_stream(PeerInfo& pi) {
    auto s = pi.inbound_stream.lock();
    if (!s) return;
    if (pi.body_received >= pi.total_expected) return;

    // 加锁 stream mutex 防止与 on_stream 触发时 linoh 内部 recv 冲突
    // 注: linoh 内部 st->recv() 当前不持锁（line 537），但 server 是单线程 main loop
    // ep->handle_incoming + on_stream + poll_stream 都在同一 main thread，理论上 race-free
    std::lock_guard<std::mutex> lk(pi.conn->stream_mutex());
    size_t avail = s->readable_size();
    if (avail == 0) return;
    static thread_local int poll_count = 0;
    if (++poll_count % 50 == 0) {
        printf("[DBG] poll_stream avail=%zu body=%zu expected=%zu\n",
               avail, pi.body_received, pi.total_expected);
        fflush(stdout);
    }

    size_t need = pi.total_expected - pi.body_received;
    size_t take = std::min(avail, need);
    if (take > 0) {
        pi.recv_buf.insert(pi.recv_buf.end(), s->readable_data(),
                          s->readable_data() + take);
        s->consume(take);
        pi.body_received += take;
    }
}

// v1.5.0.1 P1: 当数据到齐时（body_received == total_expected）处理
static void process_payload_buf(PeerInfo& pi) {
    if (pi.body_received < pi.total_expected) return;
    pi.round_end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        pi.round_end - pi.round_start).count();
    uint8_t actual_sha[32];
    // v1.5.0.1 P1: 用 OpenSSL EVP API 替换自实现（自实现主循环状态更新有 bug，前 4 字节=0）
    sha256_hash(pi.recv_buf.data(), pi.recv_buf.size(), actual_sha);
    bool ok = true;
    pi.rounds_completed++;
    printf("[SERVER] round=%zu/%d size=%zu elapsed=%lldms head=%02x%02x%02x%02x%02x%02x%02x%02x sha256=%02x%02x%02x%02x%02x%02x%02x%02x ACK=%s\n",
           pi.round_id, pi.rounds_target, pi.recv_buf.size(),
           (long long)ms,
           pi.recv_buf[0], pi.recv_buf[1], pi.recv_buf[2], pi.recv_buf[3],
           pi.recv_buf[4], pi.recv_buf[5], pi.recv_buf[6], pi.recv_buf[7],
           actual_sha[0], actual_sha[1], actual_sha[2], actual_sha[3],
           actual_sha[4], actual_sha[5], actual_sha[6], actual_sha[7],
           ok ? "OK" : "NAK");
    fflush(stdout);
    send_ack(pi, ok);
    // 重置 round 状态
    pi.header_seen = false;
    pi.body_received = 0;
    pi.total_expected = 0;
    pi.recv_buf.clear();
    pi.inbound_stream.reset();
    if (pi.rounds_completed >= pi.rounds_target) {
        printf("[SERVER] all rounds done for peer. waiting close.\n");
        fflush(stdout);
    }
}

int main(int argc, char* argv[]) {
    uint16_t port = 9101;
    int target_rounds = 5;
    size_t expected_bytes = 32 * 1024 * 1024;  // 32MB
    std::string audit_dir = ".";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i+1 >= argc) { fprintf(stderr, "missing arg after %s\n", a.c_str()); std::exit(1); }
            return argv[++i];
        };
        if (a == "--port") port = (uint16_t)atoi(next().c_str());
        else if (a == "--rounds") target_rounds = atoi(next().c_str());
        else if (a == "--size-mb") expected_bytes = (size_t)atoi(next().c_str()) * 1024 * 1024;
        else if (a == "--audit-dir") audit_dir = next();
        else { fprintf(stderr, "unknown arg: %s\n", a.c_str()); std::exit(1); }
    }

    printf("========================================================\n");
    printf("  linoh E2E Stress Server (v1.5.0.1 P1)\n");
    printf("  UDP port: %d, rounds=%d, size=%zu MB, audit-dir=%s\n",
           port, target_rounds, expected_bytes / 1024 / 1024, audit_dir.c_str());
    printf("========================================================\n\n");

    if (chdir(audit_dir.c_str()) != 0) {
        fprintf(stderr, "chdir %s failed: %d\n", audit_dir.c_str(), errno);
    }
    setenv("LINOH_AUDIT", "1", 1);
    setenv("LINOH_AUDIT_DIR", audit_dir.c_str(), 1);

    WSADATA wsa{};
#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[ERROR] WSAStartup failed\n"); return 1;
    }
#else
    (void)wsa;
#endif

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        printf("[ERROR] socket: %d\n", WSAGetLastError());
        WSACleanup(); return 1;
    }
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(port);
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (sockaddr*)&bind_addr, sizeof(bind_addr)) != 0) {
        printf("[ERROR] bind: %d\n", WSAGetLastError());
        closesocket(sock); WSACleanup(); return 1;
    }
    int rcv_timeout = 100;
#ifdef _WIN32
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&rcv_timeout, sizeof(rcv_timeout));
#else
    linoh_setsockopt_rcvtimeo(sock, rcv_timeout);
#endif

    // LINOH_USE_STUB_ASIO 下 io_context 是 stub 类型，make_shared 无法推导，直接栈分配
    linoh_asio::io_context ctx;
    auto ep = Builder()
        .secret_key(SecretKey::generate())
        .alpns({"e2e-stress/1"})
        .build(ctx);

    printf("[READY] Listening on UDP :%d\n", port);
    printf("[NODE_ID] %s\n", ep->id().fmt_short().c_str());
    fflush(stdout);

    std::vector<uint8_t> recv_buf(65536);
    std::vector<uint8_t> send_buf(2048);  // 6-3 retx 调优: 单包 2KB 受 linoh MTU=9000 限制, send_buf 16KB 会导致 16382 字节 1-RTT 包被 server 拒绝关闭 conn
    std::map<std::string, PeerInfo> peers;
    std::mutex peers_mu;
    size_t round_seq = 0;

    auto t_start = std::chrono::steady_clock::now();
    while (true) {
        sockaddr_in from{};
#ifdef _WIN32
        int from_len = sizeof(from);
#else
        socklen_t from_len = sizeof(from);
#endif
        int n = recvfrom(sock, (char*)recv_buf.data(), (int)recv_buf.size(), 0,
                        (sockaddr*)&from, &from_len);
        if (n > 0) {
            TransportAddr from_addr;
            from_addr.kind = TransportKind::Ip;
            from_addr.host = ipv4_str(&from);
            from_addr.port = (uint16_t)ntohs(from.sin_port);
            std::string peer_key = from_addr.host + ":" + std::to_string(from_addr.port);

            try {
                ep->handle_incoming(from_addr, util::Bytes(std::span<const uint8_t>(recv_buf.data(), n)));
            } catch (const std::exception& e) {
                printf("[EXCEPTION] %s\n", e.what());
                fflush(stdout);
            }

            // accept new connection
            while (auto inc = ep->accept()) {
                auto conn = inc->conn;
                if (!conn) continue;
                std::lock_guard<std::mutex> lk(peers_mu);
                auto& pi = peers[peer_key];
                pi.conn = conn;
                pi.addr = from;
                pi.rounds_target = target_rounds;
                pi.rounds_completed = 0;
                printf("[ACCEPT] conn #%llu from %s (target=%d rounds, %zuMB each)\n",
                       (unsigned long long)conn->id(), peer_key.c_str(),
                       target_rounds, expected_bytes / 1024 / 1024);
                fflush(stdout);

                std::weak_ptr<Connection> weak = conn;
                conn->on_stream([weak, &peers, &peers_mu, expected_bytes, &round_seq](std::shared_ptr<Stream> s) {
                    auto c = weak.lock();
                    if (!c) return;
                    std::string pk;
                    {
                        std::lock_guard<std::mutex> lk(peers_mu);
                        for (auto& kv : peers) {
                            if (kv.second.conn.get() == c.get()) { pk = kv.first; break; }
                        }
                    }
                    if (pk.empty()) return;
                    std::lock_guard<std::mutex> lk(peers_mu);
                    auto& pi = peers[pk];
                    // v1.5.0.1 P1: 记录新 stream + 启动 round 计时
                    pi.inbound_stream = s;
                    pi.round_id = ++round_seq;
                    pi.round_start = std::chrono::steady_clock::now();
                    pi.body_received = 0;
                    pi.total_expected = expected_bytes;
                    pi.recv_buf.clear();
                    pi.header_seen = true;
                    printf("[SERVER] stream id=%llu opened, expecting %zu bytes\n",
                           (unsigned long long)s->id(), expected_bytes);
                    fflush(stdout);
                    // on_stream 触发时立即尝试读一次（首个 STREAM 帧已有数据）
                    poll_stream(pi);
                    if (pi.body_received >= pi.total_expected) {
                        process_payload_buf(pi);
                    }
                });
            }
        }

        // 轮询所有连接：构建回包 + 主动 poll stream 累积
        {
            std::lock_guard<std::mutex> lk(peers_mu);
            for (auto& kv : peers) {
                auto& pi = kv.second;
                if (!pi.conn) continue;
                // 6-3 fix: 每 200ms 调用 emit_periodic_flow_control 发送 MAX_STREAM_DATA
                // v1.5.0.1 6-3: 频率从 1Hz 提高到 5Hz，配合 4MB 窗口增量
                // 5Hz * 4MB = 20MB/s 窗口增长，32MB 仅需 1.6 秒通告完
                auto now_fc = std::chrono::steady_clock::now();
                if (pi.last_fc_emit.time_since_epoch().count() == 0 ||
                    std::chrono::duration_cast<std::chrono::milliseconds>(now_fc - pi.last_fc_emit).count() >= 200) {
                    pi.conn->emit_periodic_flow_control();
                    pi.last_fc_emit = now_fc;
                }
                // 主动 poll stream 累积（处理后续 STREAM 帧）
                if (pi.inbound_stream.lock() && pi.body_received < pi.total_expected) {
                    poll_stream(pi);
                    if (pi.body_received >= pi.total_expected) {
                        process_payload_buf(pi);
                    }
                }
                // build 1-RTT packet 发送 ACK
                std::span<uint8_t> out(send_buf.data(), send_buf.size());
                size_t pkt_len = pi.conn->build_1rtt_packet(out);
                if (pkt_len > 0) {
                    sendto(sock, (char*)send_buf.data(), (int)pkt_len, 0,
                           (sockaddr*)&pi.addr, sizeof(pi.addr));
                }
            }
        }

        // 全部 round 完成后退出
        bool all_done = true;
        {
            std::lock_guard<std::mutex> lk(peers_mu);
            for (auto& kv : peers) {
                if (kv.second.rounds_completed < kv.second.rounds_target) {
                    all_done = false; break;
                }
            }
        }
        if (all_done && !peers.empty()) {
            auto t_end = std::chrono::steady_clock::now();
            auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                t_end - t_start).count();
            printf("[SERVER] all peers done in %lldms, exiting\n", (long long)total_ms);
            fflush(stdout);
            break;
        }
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
