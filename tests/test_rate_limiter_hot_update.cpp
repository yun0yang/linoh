// test_rate_limiter_hot_update.cpp — B3 速率限制热更新测试（v1.7.0.2 P1）
//
// 覆盖：
//   - TokenBucket::set_rate 基本功能
//   - set_rate 后 try_consume 行为
//   - set_rate 令牌截断（tokens > new_capacity）
//   - set_rate 后 refill_rate 生效
//   - set_rate 线程安全（并发 try_consume + set_rate）
//   - RateLimiter::set_rates 全量更新
//   - set_rates(update_existing_buckets=false) 仅影响新桶
//   - set_rates 后新客户端用新配置
//   - set_rates 线程安全
//   - 热更新后 cleanup_idle 正常工作

#include "linoh/util/rate_limiter.hpp"

#include <atomic>
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
// 测试 1: set_rate 基本功能（容量和速率更新）
// ============================================================================
static void test_set_rate_basic() {
    std::printf("[test] set_rate basic...\n");

    TokenBucket b(100, 10);
    CHECK(b.capacity() == 100);
    CHECK(b.refill_rate() == 10);

    b.set_rate(200, 20);
    CHECK(b.capacity() == 200);
    CHECK(b.refill_rate() == 20);
}

// ============================================================================
// 测试 2: set_rate 后 try_consume 行为（令牌保留不重置）
// ============================================================================
static void test_set_rate_preserves_tokens() {
    std::printf("[test] set_rate preserves tokens...\n");

    TokenBucket b(100, 10);
    CHECK(b.try_consume(40));
    CHECK(b.available() == 60);  // 剩余 60

    b.set_rate(200, 20);
    // 令牌不重置，仍为 60（< new_capacity=200，不截断）
    CHECK(b.available() == 60);
    CHECK(b.try_consume(60));  // 可消费剩余的 60
    CHECK(b.available() == 0);
}

// ============================================================================
// 测试 3: set_rate 令牌截断（tokens > new_capacity）
// ============================================================================
static void test_set_rate_truncates_tokens() {
    std::printf("[test] set_rate truncates tokens...\n");

    TokenBucket b(100, 10);
    CHECK(b.available() == 100);  // 满桶

    // 容量从 100 降到 50，当前 100 个令牌应被截断到 50
    b.set_rate(50, 5);
    CHECK(b.capacity() == 50);
    CHECK(b.available() == 50);  // 截断
    CHECK(b.try_consume(50));    // 恰好可消费 50
}

// ============================================================================
// 测试 4: set_rate(0, x) 容量 0 被强制改为 1
// ============================================================================
static void test_set_rate_zero_capacity_defense() {
    std::printf("[test] set_rate zero capacity defense...\n");

    TokenBucket b(100, 10);
    b.set_rate(0, 5);
    CHECK(b.capacity() == 1);  // 0 被强制改为 1
    CHECK(b.refill_rate() == 5);
}

// ============================================================================
// 测试 5: set_rate 后 refill_rate 立即生效
// ============================================================================
static void test_set_rate_refill_rate_effective() {
    std::printf("[test] set_rate refill_rate effective...\n");

    TokenBucket b(1000, 0);  // 初始 refill_rate=0，不补充
    CHECK(b.try_consume(1000));  // 清空
    CHECK(b.available() == 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(b.available() == 0);  // rate=0 仍无补充

    // 热更新为 1000 tokens/sec = 1 token/ms
    b.set_rate(1000, 1000);

    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    std::uint64_t avail = b.available();
    CHECK(avail >= 40);  // 至少补充 40 个
    CHECK(avail <= 1000);
}

// ============================================================================
// 测试 6: set_rate 重置补充时间基准（避免旧时间戳一次性补满）
// ============================================================================
static void test_set_rate_resets_refill_time() {
    std::printf("[test] set_rate resets refill time...\n");

    TokenBucket b(100, 0);  // rate=0 不补充
    CHECK(b.try_consume(100));  // 清空

    // 等待一段时间，rate=0 期间不补充
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 热更新为高补充速率，若不重置时间基准会一次性补满
    b.set_rate(100, 10000);  // 10000 tokens/sec

    // 立即检查（无额外等待），应只有少量补充
    std::uint64_t avail = b.available();
    CHECK(avail < 100);  // 不应立即补满
}

// ============================================================================
// 测试 7: set_rate 多次热更新
// ============================================================================
static void test_set_rate_multiple_updates() {
    std::printf("[test] set_rate multiple updates...\n");

    TokenBucket b(100, 10);
    b.set_rate(200, 20);
    CHECK(b.capacity() == 200);
    b.set_rate(300, 30);
    CHECK(b.capacity() == 300);
    b.set_rate(50, 5);
    CHECK(b.capacity() == 50);
    CHECK(b.available() <= 50);  // 截断到 50
}

// ============================================================================
// 测试 8: set_rate 与 reset 交互
// ============================================================================
static void test_set_rate_then_reset() {
    std::printf("[test] set_rate then reset...\n");

    TokenBucket b(100, 10);
    b.set_rate(200, 20);
    // set_rate 不改变 tokens_（除非超过新 capacity 才截断），tokens_ 仍为 100
    b.reset();  // reset 用当前 capacity_ 填满到 200
    CHECK(b.available() == 200);  // 用新容量 200 填满
    CHECK(b.try_consume(50));
    CHECK(b.available() == 150);  // 200 - 50
}

// ============================================================================
// 测试 9: RateLimiter::set_rates 全量更新已有桶
// ============================================================================
static void test_set_rates_updates_existing() {
    std::printf("[test] set_rates updates existing buckets...\n");

    RateLimiter rl(100, 10);  // 100 bps, 10 rps
    rl.try_consume_bytes("client-A", 50);

    // 热更新
    rl.set_rates(200, 20, true);

    // client-A 的字节桶应被更新到 200 容量
    auto &bucket = rl.get_bytes_bucket("client-A");
    CHECK(bucket.capacity() == 200);
    CHECK(bucket.refill_rate() == 200);

    // 配置参数也应更新
    CHECK(rl.bytes_per_second() == 200);
    CHECK(rl.requests_per_second() == 20);
}

// ============================================================================
// 测试 10: set_rates(update_existing_buckets=false) 仅影响新桶
// ============================================================================
static void test_set_rates_no_update_existing() {
    std::printf("[test] set_rates no update existing buckets...\n");

    RateLimiter rl(100, 10);
    rl.try_consume_bytes("client-A", 50);
    auto &old_bucket = rl.get_bytes_bucket("client-A");
    CHECK(old_bucket.capacity() == 100);

    // 热更新但不更新已有桶
    rl.set_rates(200, 20, false);

    // client-A 仍用旧配置
    auto &bucket_a = rl.get_bytes_bucket("client-A");
    CHECK(bucket_a.capacity() == 100);
    CHECK(bucket_a.refill_rate() == 100);

    // 新 client-B 用新配置
    rl.try_consume_bytes("client-B", 1);
    auto &bucket_b = rl.get_bytes_bucket("client-B");
    CHECK(bucket_b.capacity() == 200);
    CHECK(bucket_b.refill_rate() == 200);
}

// ============================================================================
// 测试 11: set_rates 后新客户端用新配置
// ============================================================================
static void test_set_rates_new_client_uses_new() {
    std::printf("[test] set_rates new client uses new config...\n");

    RateLimiter rl(100, 10);
    rl.try_consume_bytes("old-client", 10);

    rl.set_rates(500, 50, true);

    rl.try_consume_bytes("new-client", 1);
    auto &bucket = rl.get_bytes_bucket("new-client");
    CHECK(bucket.capacity() == 500);
    CHECK(bucket.refill_rate() == 500);
}

// ============================================================================
// 测试 12: set_rates 同时更新请求桶
// ============================================================================
static void test_set_rates_updates_request_bucket() {
    std::printf("[test] set_rates updates request bucket...\n");

    RateLimiter rl(100, 10);
    rl.try_consume_request("client");

    rl.set_rates(200, 20, true);

    auto &req_bucket = rl.get_requests_bucket("client");
    CHECK(req_bucket.capacity() == 20);
    CHECK(req_bucket.refill_rate() == 20);
}

// ============================================================================
// 测试 13: set_rates 热更新后字节桶与请求桶独立
// ============================================================================
static void test_set_rates_buckets_independent() {
    std::printf("[test] set_rates buckets independent...\n");

    RateLimiter rl(1000, 5);
    rl.set_rates(2000, 10, true);

    auto &bytes_bucket = rl.get_bytes_bucket("client");
    auto &req_bucket = rl.get_requests_bucket("client");

    CHECK(bytes_bucket.capacity() == 2000);
    CHECK(req_bucket.capacity() == 10);  // 请求桶用 rps 配置
}

// ============================================================================
// 测试 14: set_rates(0, 0) 防御
// ============================================================================
static void test_set_rates_zero_defense() {
    std::printf("[test] set_rates zero defense...\n");

    RateLimiter rl(100, 10);
    rl.set_rates(0, 0, true);

    rl.try_consume_bytes("client", 1);
    auto &bucket = rl.get_bytes_bucket("client");
    CHECK(bucket.capacity() == 1);  // 0 被强制改为 1
    CHECK(bucket.refill_rate() == 0);  // rate 不强制改
}

// ============================================================================
// 测试 15: 热更新后 cleanup_idle 正常工作
// ============================================================================
static void test_set_rates_then_cleanup_idle() {
    std::printf("[test] set_rates then cleanup_idle...\n");

    RateLimiter rl(100, 10);
    rl.try_consume_bytes("active", 10);
    rl.try_consume_bytes("idle-1", 10);
    rl.try_consume_bytes("idle-2", 10);

    rl.set_rates(200, 20, true);  // 热更新

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    rl.try_consume_bytes("active", 1);  // active 保持活跃

    std::size_t removed = rl.cleanup_idle(std::chrono::milliseconds(50));
    CHECK(removed == 2);  // idle-1, idle-2 被清理
    CHECK(rl.client_count() == 1);
}

// ============================================================================
// 测试 16: TokenBucket 并发 try_consume + set_rate（线程安全）
// ============================================================================
static void test_concurrent_set_rate_and_consume() {
    std::printf("[test] concurrent set_rate and consume...\n");

    TokenBucket b(10000, 1000);
    std::atomic<bool> stop{false};
    std::atomic<int> errors{0};

    std::thread setter([&]() {
        for (int i = 0; i < 100; ++i) {
            // 在 5000-15000 之间切换容量
            std::uint64_t cap = (i % 2 == 0) ? 5000 : 15000;
            b.set_rate(cap, 1000);
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        stop = true;
    });

    std::thread consumer([&]() {
        while (!stop.load()) {
            // 并发消费不应崩溃
            b.try_consume(1);
        }
    });

    std::thread reader([&]() {
        while (!stop.load()) {
            // 并发读取不应崩溃
            volatile auto cap = b.capacity();
            volatile auto rate = b.refill_rate();
            volatile auto avail = b.available();
            (void)cap; (void)rate; (void)avail;
        }
    });

    setter.join();
    consumer.join();
    reader.join();

    CHECK(errors.load() == 0);  // 无错误即通过
}

// ============================================================================
// 测试 17: RateLimiter 并发 set_rates + try_consume_bytes（线程安全）
// ============================================================================
static void test_concurrent_set_rates_and_consume() {
    std::printf("[test] concurrent set_rates and consume...\n");

    RateLimiter rl(1000, 100);
    std::atomic<bool> stop{false};
    std::atomic<int> total_success{0};

    std::thread setter([&]() {
        for (int i = 0; i < 50; ++i) {
            rl.set_rates(500 + i * 10, 50 + i, true);
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
        stop = true;
    });

    std::vector<std::thread> consumers;
    for (int t = 0; t < 4; ++t) {
        consumers.emplace_back([&, t]() {
            std::string key = "client-" + std::to_string(t);
            while (!stop.load()) {
                if (rl.try_consume_bytes(key, 1)) {
                    ++total_success;
                }
            }
        });
    }

    setter.join();
    for (auto &t : consumers) t.join();

    // 无崩溃即通过，成功次数 > 0 说明限流器在工作
    CHECK(total_success.load() > 0);
    CHECK(rl.client_count() == 4);
}

// ============================================================================
// 测试 18: set_rate 不影响 last_access（仍用于 idle 清理）
// ============================================================================
static void test_set_rate_updates_last_access() {
    std::printf("[test] set_rate updates last_access...\n");

    TokenBucket b(100, 10);
    auto t1 = b.last_access();

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    b.set_rate(200, 20);
    auto t2 = b.last_access();

    CHECK(t2 > t1);  // last_access 应被 set_rate 更新
}

// ============================================================================
// 测试 19: 频繁 set_rate 不丢失令牌
// ============================================================================
static void test_frequent_set_rate_no_token_loss() {
    std::printf("[test] frequent set_rate no token loss...\n");

    TokenBucket b(1000, 1000);
    CHECK(b.try_consume(500));  // 剩余 500

    // 频繁热更新（容量保持 1000 不变）
    for (int i = 0; i < 100; ++i) {
        b.set_rate(1000, 1000);
    }

    // 令牌数应保持 500（不重置）
    CHECK(b.available() == 500);
}

// ============================================================================
// 测试 20: set_rate 降容量后再升容量（令牌不立即恢复）
// ============================================================================
static void test_set_rate_down_then_up() {
    std::printf("[test] set_rate down then up...\n");

    TokenBucket b(1000, 0);  // rate=0 不补充
    CHECK(b.available() == 1000);

    // 降到 100
    b.set_rate(100, 0);
    CHECK(b.available() == 100);

    // 再升回 1000，令牌不立即恢复到 1000
    b.set_rate(1000, 0);
    CHECK(b.available() == 100);  // 仍为 100（不重置）
}

// ============================================================================
// 测试 21: set_rates 多客户端场景
// ============================================================================
static void test_set_rates_multi_client() {
    std::printf("[test] set_rates multi client...\n");

    RateLimiter rl(100, 10);
    for (int i = 0; i < 5; ++i) {
        rl.try_consume_bytes("client-" + std::to_string(i), 10);
    }
    CHECK(rl.client_count() == 5);

    rl.set_rates(500, 50, true);

    // 所有 5 个客户端的字节桶都应被更新
    for (int i = 0; i < 5; ++i) {
        auto &bucket = rl.get_bytes_bucket("client-" + std::to_string(i));
        CHECK(bucket.capacity() == 500);
    }
}

// ============================================================================
// 测试 22: set_rate 默认参数行为验证
// ============================================================================
static void test_set_rates_default_param() {
    std::printf("[test] set_rates default param...\n");

    RateLimiter rl(100, 10);
    rl.try_consume_bytes("client", 10);

    // 不传第三参数，默认 update_existing_buckets=true
    rl.set_rates(300, 30);

    auto &bucket = rl.get_bytes_bucket("client");
    CHECK(bucket.capacity() == 300);
}

// ============================================================================
// 测试 23: 热更新后 try_consume 仍正确拒绝超限请求
// ============================================================================
static void test_set_rate_rejects_after_update() {
    std::printf("[test] set_rate rejects after update...\n");

    TokenBucket b(100, 0);  // rate=0 不补充
    b.set_rate(50, 0);       // 降到 50

    CHECK(b.try_consume(50));   // 恰好 50
    CHECK(!b.try_consume(1));   // 拒绝
}

// ============================================================================
// 测试 24: set_rate 线程安全（多线程交替 set_rate）
// ============================================================================
static void test_concurrent_set_rate_only() {
    std::printf("[test] concurrent set_rate only...\n");

    TokenBucket b(1000, 100);
    std::vector<std::thread> threads;

    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&b, t]() {
            for (int i = 0; i < 1000; ++i) {
                std::uint64_t cap = 100 + (t * 100) + (i % 100);
                b.set_rate(cap, 100);
            }
        });
    }
    for (auto &t : threads) t.join();

    // 最终容量应为某个线程最后设置的值，且无崩溃
    CHECK(b.capacity() >= 100);
}

// ============================================================================
// 测试 25: set_rates 后 get_bytes_bucket 返回新引用仍有效
// ============================================================================
static void test_set_rates_bucket_ref_valid() {
    std::printf("[test] set_rates bucket ref valid...\n");

    RateLimiter rl(100, 10);
    auto &bucket1 = rl.get_bytes_bucket("client");
    bucket1.try_consume(50);

    rl.set_rates(200, 20, true);

    // 引用应仍有效（桶对象未销毁，仅内部状态更新）
    CHECK(bucket1.capacity() == 200);
    CHECK(bucket1.available() <= 200);
}

int main() {
    std::printf("=== test_rate_limiter_hot_update (v1.7.0.2 P1 B3) ===\n");

    test_set_rate_basic();
    test_set_rate_preserves_tokens();
    test_set_rate_truncates_tokens();
    test_set_rate_zero_capacity_defense();
    test_set_rate_refill_rate_effective();
    test_set_rate_resets_refill_time();
    test_set_rate_multiple_updates();
    test_set_rate_then_reset();
    test_set_rates_updates_existing();
    test_set_rates_no_update_existing();
    test_set_rates_new_client_uses_new();
    test_set_rates_updates_request_bucket();
    test_set_rates_buckets_independent();
    test_set_rates_zero_defense();
    test_set_rates_then_cleanup_idle();
    test_concurrent_set_rate_and_consume();
    test_concurrent_set_rates_and_consume();
    test_set_rate_updates_last_access();
    test_frequent_set_rate_no_token_loss();
    test_set_rate_down_then_up();
    test_set_rates_multi_client();
    test_set_rates_default_param();
    test_set_rate_rejects_after_update();
    test_concurrent_set_rate_only();
    test_set_rates_bucket_ref_valid();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
