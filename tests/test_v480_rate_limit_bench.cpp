// test_v480_rate_limit_bench.cpp — T-LP3-007 限流基准测试
//
// 验证 RateLimitFilter 拒绝路径性能优势（借鉴 iroh#3951 设计目标）
//
// 基准对比：
//   场景 A (accept-then-close): 模拟完整接受路径 — mutex lock + queue push +
//                                connection alloc + state transition + close +
//                                queue pop + connection destruct
//   场景 B (rate-limit-reject): 仅 RateLimitFilter::filter() 调用
//
// 设计说明：
//   - 实际部署中 IncomingFilter 的价值在于避免 TLS 握手 + 连接创建开销
//   - 单元测试中用 MockConnection 近似模拟，ratio 会小于生产环境的 20x
//   - 重点关注：拒绝路径正确性 + 拒绝路径吞吐不低于接受路径 + 内存有界

#include "linoh/endpoint/incoming_filter.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

using namespace linoh::endpoint;
using namespace linoh::base;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
    } while (0)

// ============================================================================
// 场景 A: 模拟"接受后关闭"路径
// 包含：mutex lock + queue push + 模拟 connection 创建 + close + queue pop + destruct
// ============================================================================

struct MockConnection {
    char padding[256];  // 模拟 connection 对象的内存占用
    int state = 0;
    MockConnection() { state = 1; }
    ~MockConnection() { state = 0; }
};

struct AcceptThenClosePath {
    std::mutex mu;
    std::queue<std::unique_ptr<MockConnection>> pending;

    void accept_and_close() {
        auto conn = std::make_unique<MockConnection>();
        {
            std::lock_guard<std::mutex> lk(mu);
            pending.push(std::move(conn));
        }
        {
            std::lock_guard<std::mutex> lk(mu);
            if (!pending.empty()) {
                auto &c = pending.front();
                c->state = 2;
            }
        }
        {
            std::lock_guard<std::mutex> lk(mu);
            if (!pending.empty()) {
                pending.front()->state = 3;
                pending.pop();
            }
        }
    }
};

// ============================================================================
// 辅助函数
// ============================================================================

static TransportAddr make_addr(const std::string &host, uint16_t port) {
    TransportAddr a;
    a.kind = TransportKind::Ip;
    a.host = host;
    a.port = port;
    return a;
}

/// 预生成 IP 地址列表（避免在热循环中调用 std::to_string）
static std::vector<std::string> generate_ips(int n) {
    std::vector<std::string> ips;
    ips.reserve(n);
    for (int i = 0; i < n; ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "10.%d.%d.%d",
                      (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
        ips.emplace_back(buf);
    }
    return ips;
}

// ============================================================================
// 基准测试函数
// ============================================================================

/// 单线程吞吐量基准
static void bench_single_thread() {
    std::printf("\n[bench] T-LP3-007: Single-thread throughput comparison\n");

    const int N = 50000;
    auto ips = generate_ips(N);

    // 场景 A: accept-then-close
    AcceptThenClosePath path_a;
    auto start_a = std::chrono::steady_clock::now();
    for (int i = 0; i < N; ++i) {
        path_a.accept_and_close();
    }
    auto end_a = std::chrono::steady_clock::now();
    double ms_a = std::chrono::duration<double, std::milli>(end_a - start_a).count();
    double ops_a = N / (ms_a / 1000.0);
    std::printf("  Scenario A (accept-then-close): %d ops in %.2f ms = %.0f ops/sec\n",
                N, ms_a, ops_a);

    // 场景 B: rate-limit-reject（max_per_window=1，所有请求除第一个外都被拒绝）
    // 使用同一 IP 反复请求，模拟单一来源的高频攻击
    RateLimitFilter filter_b(std::chrono::seconds(60), 1);
    TransportAddr attacker_addr = make_addr("203.0.113.1", 9000);
    IncomingRequest req_b;
    req_b.remote_addr = attacker_addr;

    auto start_b = std::chrono::steady_clock::now();
    int rejected = 0;
    for (int i = 0; i < N; ++i) {
        if (filter_b.filter(req_b) == IncomingFilterOutcome::kReject) {
            ++rejected;
        }
    }
    auto end_b = std::chrono::steady_clock::now();
    double ms_b = std::chrono::duration<double, std::milli>(end_b - start_b).count();
    double ops_b = N / (ms_b / 1000.0);
    std::printf("  Scenario B (rate-limit-reject): %d ops in %.2f ms = %.0f ops/sec (rejected=%d)\n",
                N, ms_b, ops_b, rejected);

    double ratio = ops_b / ops_a;
    std::printf("  Throughput ratio (B/A): %.2fx\n", ratio);

    // 拒绝路径吞吐应显著高于接受后关闭路径
    // MockConnection 开销远小于真实 TLS 连接，但 ratio 仍应 > 1
    CHECK(ops_b > 0);
    CHECK(rejected == N - 1);  // 第一个 accept，其余都 reject
    CHECK(ratio > 1.0);  // 拒绝路径应更快
    std::printf("  [PASS] Rate limit reject path faster than accept-then-close\n");
}

/// 多 IP 限流正确性基准
static void bench_multi_ip_rate_limiting() {
    std::printf("\n[bench] T-LP3-007: Multi-IP rate limiting correctness\n");

    const int NUM_IPS = 1000;
    const int REQ_PER_IP = 5;
    const int MAX_PER_WINDOW = 3;

    auto ips = generate_ips(NUM_IPS);
    RateLimitFilter filter(std::chrono::seconds(1), MAX_PER_WINDOW);

    int accepted = 0;
    int rejected = 0;

    auto start = std::chrono::steady_clock::now();
    for (int ip = 0; ip < NUM_IPS; ++ip) {
        IncomingRequest req;
        req.remote_addr = make_addr(ips[ip], 9000);
        for (int r = 0; r < REQ_PER_IP; ++r) {
            if (filter.filter(req) == IncomingFilterOutcome::kAccept) {
                ++accepted;
            } else {
                ++rejected;
            }
        }
    }
    auto end = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    int expected_accepted = NUM_IPS * MAX_PER_WINDOW;
    int expected_rejected = NUM_IPS * (REQ_PER_IP - MAX_PER_WINDOW);

    std::printf("  %d IPs x %d reqs (max=%d/window): accepted=%d, rejected=%d in %.2f ms\n",
                NUM_IPS, REQ_PER_IP, MAX_PER_WINDOW, accepted, rejected, ms);
    std::printf("  Expected: accepted=%d, rejected=%d\n", expected_accepted, expected_rejected);

    CHECK(accepted == expected_accepted);
    CHECK(rejected == expected_rejected);
    CHECK(filter.tracked_ip_count() == static_cast<std::size_t>(NUM_IPS));
    std::printf("  [PASS] Multi-IP rate limiting correct\n");
}

/// 大量不同 IP 的吞吐量测试（验证定期清理优化效果）
static void bench_many_unique_ips() {
    std::printf("\n[bench] T-LP3-007: Many unique IPs throughput (periodic cleanup)\n");

    const int N = 50000;
    auto ips = generate_ips(N);

    // 使用 60s 窗口确保测试期间不过期
    RateLimitFilter filter(std::chrono::seconds(60), 10);

    auto start = std::chrono::steady_clock::now();
    int accepted = 0;
    for (int i = 0; i < N; ++i) {
        IncomingRequest req;
        req.remote_addr = make_addr(ips[i], 9000);
        if (filter.filter(req) == IncomingFilterOutcome::kAccept) {
            ++accepted;
        }
    }
    auto end = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    double ops = N / (ms / 1000.0);

    std::printf("  %d unique-IP requests in %.2f ms = %.0f ops/sec\n", N, ms, ops);
    std::printf("  Tracked IPs: %zu, Accepted: %d\n", filter.tracked_ip_count(), accepted);

    CHECK(accepted == N);  // 每个IP第一次都应 accept
    CHECK(filter.tracked_ip_count() == static_cast<std::size_t>(N));
    CHECK(ops > 50000);  // 至少 5万 ops/sec（优化后应远高于此）
    std::printf("  [PASS] Many unique IPs throughput OK (periodic cleanup effective)\n");
}

/// 内存增长验证：大量不同 IP 后 tracked_ip_count 不应无限增长
static void bench_memory_growth_bounded() {
    std::printf("\n[bench] T-LP3-007: Memory growth bounded (cleanup_expired)\n");

    auto ips1 = generate_ips(1000);
    RateLimitFilter filter(std::chrono::milliseconds(50), 1);  // 短窗口

    // 第一批：1000 个 IP
    for (int i = 0; i < 1000; ++i) {
        IncomingRequest req;
        req.remote_addr = make_addr(ips1[i], 9000);
        filter.filter(req);
    }
    std::size_t count_after_batch1 = filter.tracked_ip_count();
    std::printf("  After batch1 (1000 IPs): tracked=%zu\n", count_after_batch1);
    CHECK(count_after_batch1 >= 1000);

    // 等待窗口过期
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    // 第二批：1000 个新 IP（触发惰性清理）
    auto ips2 = generate_ips(2000);
    for (int i = 1000; i < 2000; ++i) {
        IncomingRequest req;
        req.remote_addr = make_addr(ips2[i], 9000);
        filter.filter(req);
    }
    std::size_t count_after_batch2 = filter.tracked_ip_count();
    std::printf("  After batch2 (1000 new IPs, post-expiry): tracked=%zu\n", count_after_batch2);

    // 清理后 batch1 的条目应被回收，tracked_count 不应 = 2000
    CHECK(count_after_batch2 < 2000);
    std::printf("  [PASS] Memory growth bounded by cleanup_expired\n");
}

/// 拒绝路径延迟测试（单一 IP 高频拒绝）
static void bench_reject_latency() {
    std::printf("\n[bench] T-LP3-007: Reject path latency (single attacker)\n");

    const int N = 1000000;  // 100万次拒绝
    RateLimitFilter filter(std::chrono::seconds(60), 1);
    IncomingRequest req;
    req.remote_addr = make_addr("203.0.113.1", 9000);

    // 第一次 accept，后续全部 reject
    filter.filter(req);

    auto start = std::chrono::steady_clock::now();
    int rejected = 0;
    for (int i = 0; i < N; ++i) {
        if (filter.filter(req) == IncomingFilterOutcome::kReject) {
            ++rejected;
        }
    }
    auto end = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    double ops = N / (ms / 1000.0);
    double us_per_op = ms * 1000.0 / N;

    std::printf("  %d rejections in %.2f ms = %.0f ops/sec (%.3f us/op)\n",
                N, ms, ops, us_per_op);

    CHECK(rejected == N);
    CHECK(ops > 1000000);  // 拒绝路径应达到百万级 ops/sec
    std::printf("  [PASS] Reject path latency < 1 us/op\n");
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== test_v480_rate_limit_bench ===\n");
    std::printf("T-LP3-007: RateLimitFilter benchmark\n");

    bench_single_thread();
    bench_multi_ip_rate_limiting();
    bench_many_unique_ips();
    bench_memory_growth_bounded();
    bench_reject_latency();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
