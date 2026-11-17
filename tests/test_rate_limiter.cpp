// test_rate_limiter.cpp — 令牌桶速率限制器测试（P4-C-2）
//
// 覆盖：
//   - TokenBucket 容量与补充速率
//   - try_consume 成功/失败
//   - 时间补充正确性
//   - reset / available / last_access
//   - RateLimiter per-client 隔离
//   - 字节桶 + 请求桶独立
//   - idle 清理
//   - 多线程并发

#include "linoh/util/rate_limiter.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::util;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 测试 1: TokenBucket 初始满桶
// ============================================================================
static void test_token_bucket_initial_full() {
    std::printf("[test] TokenBucket initial full...\n");

    TokenBucket b(100, 10);
    CHECK(b.available() == 100);
    CHECK(b.capacity() == 100);
    CHECK(b.refill_rate() == 10);
}

// ============================================================================
// 测试 2: try_consume 成功
// ============================================================================
static void test_try_consume_success() {
    std::printf("[test] try_consume success...\n");

    TokenBucket b(100, 10);
    CHECK(b.try_consume(50));
    CHECK(b.available() == 50);
    CHECK(b.try_consume(50));
    CHECK(b.available() == 0);
}

// ============================================================================
// 测试 3: try_consume 失败（令牌不足）
// ============================================================================
static void test_try_consume_insufficient() {
    std::printf("[test] try_consume insufficient...\n");

    TokenBucket b(100, 10);
    CHECK(b.try_consume(50));
    CHECK(!b.try_consume(60));  // 只有 50，不够 60
    CHECK(b.available() == 50);  // 失败时桶状态不变
}

// ============================================================================
// 测试 4: try_consume(0) 始终成功
// ============================================================================
static void test_try_consume_zero() {
    std::printf("[test] try_consume(0)...\n");

    TokenBucket b(0, 0);  // 容量 0 会被强制改为 1
    CHECK(b.try_consume(0));
}

// ============================================================================
// 测试 5: 时间补充令牌
// ============================================================================
static void test_refill_over_time() {
    std::printf("[test] refill over time...\n");

    TokenBucket b(100, 1000);  // 1000 tokens/sec = 1 token/ms
    CHECK(b.try_consume(100));  // 清空
    CHECK(b.available() == 0);

    // 等待 50ms，应补充约 50 个令牌
    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    // refill 在下次 try_consume/available 调用时触发
    std::uint64_t avail = b.available();
    CHECK(avail >= 40);  // 至少 40（保守下限）
    CHECK(avail <= 100);  // 不超过容量
}

// ============================================================================
// 测试 6: 容量上限
// ============================================================================
static void test_capacity_ceiling() {
    std::printf("[test] capacity ceiling...\n");

    TokenBucket b(50, 10000);  // 高补充速率，小容量
    CHECK(b.try_consume(50));  // 清空

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    // 补充应被容量截断到 50
    CHECK(b.available() <= 50);
    CHECK(b.available() == 50);  // 满桶后不再增加
}

// ============================================================================
// 测试 7: reset 重置到满桶
// ============================================================================
static void test_reset() {
    std::printf("[test] reset...\n");

    TokenBucket b(100, 10);
    CHECK(b.try_consume(80));
    CHECK(b.available() == 20);

    b.reset();
    CHECK(b.available() == 100);
}

// ============================================================================
// 测试 8: last_access 更新
// ============================================================================
static void test_last_access() {
    std::printf("[test] last_access...\n");

    TokenBucket b(100, 10);
    auto t1 = b.last_access();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK(b.try_consume(1));
    auto t2 = b.last_access();
    CHECK(t2 > t1);
}

// ============================================================================
// 测试 9: RateLimiter per-client 隔离
// ============================================================================
static void test_per_client_isolation() {
    std::printf("[test] per-client isolation...\n");

    RateLimiter rl(100, 10);  // 100 bytes/sec, 10 req/sec per client

    // client A 消费 80 bytes
    CHECK(rl.try_consume_bytes("client-A", 80));
    CHECK(rl.try_consume_bytes("client-A", 30) == false);  // A 只剩 20

    // client B 独立，仍然满桶
    CHECK(rl.try_consume_bytes("client-B", 80));
    CHECK(rl.try_consume_bytes("client-B", 20));  // B 还有 20

    CHECK(rl.client_count() == 2);
}

// ============================================================================
// 测试 10: RateLimiter 请求桶独立于字节桶
// ============================================================================
static void test_bytes_and_requests_independent() {
    std::printf("[test] bytes and requests independent...\n");

    RateLimiter rl(1000, 5);  // 1000 bytes/sec, 5 req/sec

    // 消费 5 个请求
    for (int i = 0; i < 5; ++i) {
        CHECK(rl.try_consume_request("client"));
    }
    // 第 6 个请求被拒绝
    CHECK(!rl.try_consume_request("client"));

    // 但字节桶仍然满
    CHECK(rl.try_consume_bytes("client", 500));
}

// ============================================================================
// 测试 11: get_bytes_bucket / get_requests_bucket 返回引用
// ============================================================================
static void test_get_bucket_returns_ref() {
    std::printf("[test] get_bucket returns ref...\n");

    RateLimiter rl(100, 10);
    TokenBucket &b1 = rl.get_bytes_bucket("client");
    TokenBucket &b2 = rl.get_bytes_bucket("client");
    CHECK(&b1 == &b2);  // 同一客户端应返回同一桶引用

    b1.try_consume(50);
    CHECK(b2.available() == 50);  // 状态共享
}

// ============================================================================
// 测试 12: cleanup_idle 清理空闲客户端
// ============================================================================
static void test_cleanup_idle() {
    std::printf("[test] cleanup_idle...\n");

    RateLimiter rl(100, 10);

    rl.try_consume_bytes("active", 10);
    rl.try_consume_bytes("idle-1", 10);
    rl.try_consume_bytes("idle-2", 10);
    CHECK(rl.client_count() == 3);

    // 等待 idle-1 和 idle-2 超时
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 活跃 active 保持
    rl.try_consume_bytes("active", 1);

    // 清理 50ms 以上的空闲客户端
    std::size_t removed = rl.cleanup_idle(std::chrono::milliseconds(50));
    CHECK(removed == 2);  // idle-1, idle-2 被清理
    CHECK(rl.client_count() == 1);
}

// ============================================================================
// 测试 13: cleanup_idle 默认参数（5 分钟）
// ============================================================================
static void test_cleanup_idle_default() {
    std::printf("[test] cleanup_idle default...\n");

    RateLimiter rl(100, 10);
    rl.try_consume_bytes("client", 10);

    // 立即清理（默认 5 分钟），不应清理任何客户端
    std::size_t removed = rl.cleanup_idle();
    CHECK(removed == 0);
    CHECK(rl.client_count() == 1);
}

// ============================================================================
// 测试 14: 配置参数查询
// ============================================================================
static void test_config_params() {
    std::printf("[test] config params...\n");

    RateLimiter rl(1024, 100);
    CHECK(rl.bytes_per_second() == 1024);
    CHECK(rl.requests_per_second() == 100);
}

// ============================================================================
// 测试 15: 高频 refill 不丢失令牌
// ============================================================================
static void test_high_frequency_refill() {
    std::printf("[test] high frequency refill...\n");

    TokenBucket b(1000, 100);  // 100 tokens/sec
    CHECK(b.try_consume(1000));  // 清空

    // 高频调用 try_consume(0)，不应导致令牌负增长
    for (int i = 0; i < 100; ++i) {
        CHECK(b.try_consume(0));
    }

    // 等待补充
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    std::uint64_t avail = b.available();
    CHECK(avail > 0);  // 应有补充
    CHECK(avail <= 1000);
}

// ============================================================================
// 测试 16: 并发 try_consume（线程安全）
// ============================================================================
static void test_concurrent_consume() {
    std::printf("[test] concurrent consume...\n");

    TokenBucket b(10000, 1000);
    std::atomic<int> success_count{0};
    std::atomic<int> total_count{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < 100; ++i) {
                if (b.try_consume(1)) {
                    ++success_count;
                }
                ++total_count;
            }
        });
    }
    for (auto &t : threads) t.join();

    CHECK(total_count.load() == 800);
    CHECK(success_count.load() == 800);  // 10000 容量足够 800 次消费
    CHECK(b.available() == 10000 - 800);
}

// ============================================================================
// 测试 17: RateLimiter 多客户端并发
// ============================================================================
static void test_concurrent_clients() {
    std::printf("[test] concurrent clients...\n");

    RateLimiter rl(100, 100);

    std::atomic<int> total_success{0};
    std::vector<std::thread> threads;

    for (int t = 0; t < 10; ++t) {
        threads.emplace_back([&, t]() {
            std::string key = "client-" + std::to_string(t);
            int local = 0;
            for (int i = 0; i < 100; ++i) {
                if (rl.try_consume_request(key)) ++local;
            }
            total_success += local;
        });
    }
    for (auto &t : threads) t.join();

    // 每客户端容量 100，10 客户端总共最多 1000 次成功
    CHECK(total_success.load() <= 1000);
    CHECK(rl.client_count() == 10);
}

// ============================================================================
// 测试 18: 容量 0 防御
// ============================================================================
static void test_zero_capacity_defense() {
    std::printf("[test] zero capacity defense...\n");

    TokenBucket b(0, 0);  // 容量 0 被强制改为 1
    CHECK(b.capacity() == 1);
    CHECK(b.try_consume(1));  // 初始 1 个令牌
    CHECK(!b.try_consume(1));  // 用完后无补充（rate=0）
}

int main() {
    std::printf("=== test_rate_limiter ===\n");

    test_token_bucket_initial_full();
    test_try_consume_success();
    test_try_consume_insufficient();
    test_try_consume_zero();
    test_refill_over_time();
    test_capacity_ceiling();
    test_reset();
    test_last_access();
    test_per_client_isolation();
    test_bytes_and_requests_independent();
    test_get_bucket_returns_ref();
    test_cleanup_idle();
    test_cleanup_idle_default();
    test_config_params();
    test_high_frequency_refill();
    test_concurrent_consume();
    test_concurrent_clients();
    test_zero_capacity_defense();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
