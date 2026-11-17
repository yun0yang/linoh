// =============================================================================
// test_replay_protection.cpp — v3.8.6 控制面指令防重放单元测试
//
// 覆盖场景：
//   1. 正常首次 nonce 通过
//   2. 重复 nonce 被拒绝（重放攻击）
//   3. nonce 长度不足被拒绝
//   4. TTL 过期内重复被拒绝
//   5. TTL 过期后同一 nonce 可再用（模拟时间推进 61s）
//   6. LRU 淘汰：超容量最旧被淘汰
//   7. LRU 淘汰后旧 nonce 可重新接受
//   8. evict_expired 手动清理
//   9. evict_expired 未过期条目保留
//  10. stats 统计准确性（accepts/hits/evicted/expired/size）
//  11. clear 清空缓存
//  12. 不同 nonce 独立性
//  13. ReplayProtection timestamp 过期拒绝
//  14. ReplayProtection timestamp 未来偏移拒绝
//  15. ReplayProtection 正常通过
//  16. ReplayProtection 重复 nonce 拒绝
//  17. 并发安全：4 线程并发 check_and_insert
// =============================================================================

#include "linoh/protocol/replay_protection.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

using namespace linoh::protocol;
using namespace std::chrono_literals;

namespace {

/// 生成确定性 nonce（按 seed 填充 32 字节）
NonceCache::NonceArray make_nonce(std::uint64_t seed) {
    NonceCache::NonceArray n{};
    for (std::size_t i = 0; i < kNonceSize; ++i) {
        n[i] = static_cast<std::uint8_t>((seed >> (i % 8 * 8)) & 0xFF);
    }
    return n;
}

/// 生成指定大小和 seed 的 nonce（用于测试短 nonce）
std::vector<std::uint8_t> make_short_nonce(std::size_t size, std::uint8_t seed) {
    std::vector<std::uint8_t> n(size);
    for (std::size_t i = 0; i < size; ++i) {
        n[i] = static_cast<std::uint8_t>(seed + i);
    }
    return n;
}

int test_count = 0;
int test_passed = 0;

#define RUN_TEST(name)                                                        \
    do {                                                                      \
        ++test_count;                                                         \
        std::cout << "  [test] " #name " ... ";                               \
        name();                                                               \
        ++test_passed;                                                        \
        std::cout << "OK\n";                                                  \
    } while (0)

} // namespace

// =============================================================================
// 1. 正常首次 nonce 通过
// =============================================================================

void test_first_nonce_accepted() {
    NonceCache cache(10000, 60s);
    auto n = make_nonce(1);
    assert(cache.check_and_insert(n));
    assert(cache.size() == 1);
}

// =============================================================================
// 2. 重复 nonce 被拒绝（重放攻击）
// =============================================================================

void test_duplicate_nonce_rejected() {
    NonceCache cache(10000, 60s);
    auto n = make_nonce(42);
    assert(cache.check_and_insert(n));    // 首次 → true
    assert(!cache.check_and_insert(n));   // 重复 → false
    assert(cache.size() == 1);            // 重复不增加 size
}

// =============================================================================
// 3. nonce 长度不足被拒绝
// =============================================================================

void test_short_nonce_rejected() {
    NonceCache cache(10000, 60s);
    auto short_n = make_short_nonce(16, 0xAB);  // 16 字节，不足 32
    assert(!cache.check_and_insert(short_n));
    assert(cache.size() == 0);
}

// =============================================================================
// 4. TTL 过期内重复被拒绝
// =============================================================================

void test_within_ttl_duplicate_rejected() {
    NonceCache cache(10000, 60s);
    auto n = make_nonce(7);
    auto t0 = std::chrono::steady_clock::now();

    assert(cache.check_and_insert(n, t0));              // t=0 首次
    assert(!cache.check_and_insert(n, t0 + 30s));       // t=30 重复（未过期）
    assert(!cache.check_and_insert(n, t0 + 59s));       // t=59 重复（仍未过期）
    assert(cache.size() == 1);
}

// =============================================================================
// 5. TTL 过期后同一 nonce 可再用（模拟时间推进 61s）
// =============================================================================

void test_expired_nonce_reusable() {
    NonceCache cache(10000, 60s);
    auto n = make_nonce(99);
    auto t0 = std::chrono::steady_clock::now();

    assert(cache.check_and_insert(n, t0));              // t=0 首次
    assert(!cache.check_and_insert(n, t0 + 30s));       // t=30 重复
    assert(cache.check_and_insert(n, t0 + 61s));        // t=61 过期，可重用
    assert(cache.size() == 1);

    auto s = cache.stats();
    assert(s.expired == 1);  // 1 次过期清理
}

// =============================================================================
// 6. LRU 淘汰：超容量最旧被淘汰
// =============================================================================

void test_lru_eviction() {
    NonceCache cache(3, 60s);  // 容量 3
    auto n1 = make_nonce(1);
    auto n2 = make_nonce(2);
    auto n3 = make_nonce(3);
    auto n4 = make_nonce(4);
    auto t0 = std::chrono::steady_clock::now();

    assert(cache.check_and_insert(n1, t0));   // [n1]
    assert(cache.check_and_insert(n2, t0));   // [n2, n1]
    assert(cache.check_and_insert(n3, t0));   // [n3, n2, n1]，满
    assert(cache.check_and_insert(n4, t0));   // [n4, n3, n2]，淘汰 n1
    assert(cache.size() == 3);

    auto s = cache.stats();
    assert(s.evicted == 1);  // 淘汰 1 个
}

// =============================================================================
// 7. LRU 淘汰后旧 nonce 可重新接受
// =============================================================================

void test_evicted_nonce_reaccepted() {
    NonceCache cache(2, 60s);  // 容量 2
    auto n1 = make_nonce(10);
    auto n2 = make_nonce(20);
    auto n3 = make_nonce(30);
    auto t0 = std::chrono::steady_clock::now();

    assert(cache.check_and_insert(n1, t0));   // [n1]
    assert(cache.check_and_insert(n2, t0));   // [n2, n1]，满
    assert(cache.check_and_insert(n3, t0));   // [n3, n2]，淘汰 n1

    // n1 被淘汰后，再次插入应接受（不在缓存中）
    assert(cache.check_and_insert(n1, t0));   // n1 重新接受
}

// =============================================================================
// 8. evict_expired 手动清理
// =============================================================================

void test_evict_expired_manual() {
    NonceCache cache(10000, 60s);
    auto n1 = make_nonce(1);
    auto n2 = make_nonce(2);
    auto n3 = make_nonce(3);
    auto t0 = std::chrono::steady_clock::now();

    cache.check_and_insert(n1, t0);
    cache.check_and_insert(n2, t0);
    cache.check_and_insert(n3, t0);
    assert(cache.size() == 3);

    // 推进 61s，全部过期
    std::size_t cleaned = cache.evict_expired(t0 + 61s);
    assert(cleaned == 3);
    assert(cache.size() == 0);

    auto s = cache.stats();
    assert(s.expired == 3);
}

// =============================================================================
// 9. evict_expired 未过期条目保留
// =============================================================================

void test_evict_expired_keeps_fresh() {
    NonceCache cache(10000, 60s);
    auto n1 = make_nonce(1);
    auto n2 = make_nonce(2);
    auto t0 = std::chrono::steady_clock::now();

    cache.check_and_insert(n1, t0);              // t=0
    cache.check_and_insert(n2, t0 + 30s);        // t=30

    // t=40：n1(40s) 未过期，n2(10s) 未过期
    std::size_t cleaned = cache.evict_expired(t0 + 40s);
    assert(cleaned == 0);
    assert(cache.size() == 2);

    // t=61：n1(61s) 过期，n2(31s) 未过期
    cleaned = cache.evict_expired(t0 + 61s);
    assert(cleaned == 1);
    assert(cache.size() == 1);

    // n2 仍可重复拒绝
    assert(!cache.check_and_insert(n2, t0 + 61s));
}

// =============================================================================
// 10. stats 统计准确性
// =============================================================================

void test_stats_accuracy() {
    NonceCache cache(10000, 60s);
    auto n1 = make_nonce(1);
    auto n2 = make_nonce(2);
    auto n3 = make_nonce(1);  // 与 n1 相同

    cache.check_and_insert(n1);   // accepts=1
    cache.check_and_insert(n2);   // accepts=2
    cache.check_and_insert(n3);   // hits=1（重复）

    auto s = cache.stats();
    assert(s.accepts == 2);
    assert(s.hits == 1);
    assert(s.evicted == 0);
    assert(s.expired == 0);
    assert(s.size == 2);
}

// =============================================================================
// 11. clear 清空缓存
// =============================================================================

void test_clear_cache() {
    NonceCache cache(10000, 60s);
    cache.check_and_insert(make_nonce(1));
    cache.check_and_insert(make_nonce(2));
    assert(cache.size() == 2);

    cache.clear();
    assert(cache.size() == 0);

    // clear 后统计也重置
    auto s = cache.stats();
    assert(s.accepts == 0);
    assert(s.hits == 0);

    // clear 后同一 nonce 可重新接受
    assert(cache.check_and_insert(make_nonce(1)));
}

// =============================================================================
// 12. 不同 nonce 独立性
// =============================================================================

void test_different_nonce_independent() {
    NonceCache cache(10000, 60s);
    auto n1 = make_nonce(100);
    auto n2 = make_nonce(200);
    auto n3 = make_nonce(300);

    assert(cache.check_and_insert(n1));   // 首次
    assert(cache.check_and_insert(n2));   // 首次（不同 nonce）
    assert(cache.check_and_insert(n3));   // 首次（不同 nonce）
    assert(!cache.check_and_insert(n1));  // n1 重复
    assert(!cache.check_and_insert(n2));  // n2 重复
    assert(cache.check_and_insert(make_nonce(400)));  // 新 nonce 首次
    assert(cache.size() == 4);
}

// =============================================================================
// 13. ReplayProtection timestamp 过期拒绝
// =============================================================================

void test_replay_timestamp_expired() {
    ReplayProtection rp(10000, 60s);
    auto n = make_nonce(1);

    // 120s 前的时间戳 → 过期拒绝
    auto now = std::chrono::system_clock::now();
    auto now_secs = std::chrono::duration_cast<std::chrono::seconds>(
                        now.time_since_epoch()).count();
    std::uint64_t old_timestamp = static_cast<std::uint64_t>(now_secs) - 120;

    assert(!rp.check(old_timestamp, n));
}

// =============================================================================
// 14. ReplayProtection timestamp 未来偏移拒绝
// =============================================================================

void test_replay_timestamp_future() {
    ReplayProtection rp(10000, 60s);
    auto n = make_nonce(1);

    // 120s 后的时间戳 → 未来偏移过大拒绝
    auto now = std::chrono::system_clock::now();
    auto now_secs = std::chrono::duration_cast<std::chrono::seconds>(
                        now.time_since_epoch()).count();
    std::uint64_t future_timestamp = static_cast<std::uint64_t>(now_secs) + 120;

    assert(!rp.check(future_timestamp, n));
}

// =============================================================================
// 15. ReplayProtection 正常通过
// =============================================================================

void test_replay_normal_pass() {
    ReplayProtection rp(10000, 60s);
    auto n = make_nonce(1);

    // 当前时间戳 → 通过
    auto now = std::chrono::system_clock::now();
    auto now_secs = std::chrono::duration_cast<std::chrono::seconds>(
                        now.time_since_epoch()).count();

    assert(rp.check(static_cast<std::uint64_t>(now_secs), n));
    assert(rp.size() == 1);
}

// =============================================================================
// 16. ReplayProtection 重复 nonce 拒绝
// =============================================================================

void test_replay_duplicate_rejected() {
    ReplayProtection rp(10000, 60s);
    auto n = make_nonce(42);

    auto now = std::chrono::system_clock::now();
    auto now_secs = std::chrono::duration_cast<std::chrono::seconds>(
                        now.time_since_epoch()).count();
    auto ts = static_cast<std::uint64_t>(now_secs);

    assert(rp.check(ts, n));     // 首次通过
    assert(!rp.check(ts, n));    // 重复拒绝

    auto s = rp.stats();
    assert(s.accepts == 1);
    assert(s.hits == 1);
}

// =============================================================================
// 17. 并发安全：4 线程并发 check_and_insert
// =============================================================================

void test_concurrent_check_and_insert() {
    NonceCache cache(100000, 60s);
    constexpr int kThreads = 4;
    constexpr int kPerThread = 500;
    std::atomic<int> total_accepts{0};
    std::atomic<int> total_hits{0};

    auto worker = [&](int tid) {
        int local_accepts = 0;
        int local_hits = 0;
        for (int i = 0; i < kPerThread; ++i) {
            // 每个线程用不同的 nonce 范围（tid * 1000 + i）
            auto n = make_nonce(static_cast<std::uint64_t>(tid) * 1000 + i);
            if (cache.check_and_insert(n)) {
                ++local_accepts;
            } else {
                ++local_hits;
            }
        }
        total_accepts += local_accepts;
        total_hits += local_hits;
    };

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back(worker, t);
    }
    for (auto &th : threads) {
        th.join();
    }

    // 4 线程 × 500 个不同 nonce = 2000 个首次接受，0 重复
    assert(total_accepts == kThreads * kPerThread);
    assert(total_hits == 0);
    assert(cache.size() == static_cast<std::size_t>(kThreads * kPerThread));
}

// =============================================================================
// 18. 并发：多线程竞争同一 nonce（仅 1 个接受）
// =============================================================================

void test_concurrent_same_nonce() {
    NonceCache cache(10000, 60s);
    auto n = make_nonce(777);
    constexpr int kThreads = 8;
    std::atomic<int> accepts{0};
    std::atomic<int> hits{0};

    auto worker = [&]() {
        if (cache.check_and_insert(n)) {
            ++accepts;
        } else {
            ++hits;
        }
    };

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back(worker);
    }
    for (auto &th : threads) {
        th.join();
    }

    // 仅 1 个线程接受，其余 7 个命中重复
    assert(accepts == 1);
    assert(hits == kThreads - 1);
    assert(cache.size() == 1);
}

// =============================================================================
// 19. max_size 和 ttl 访问器
// =============================================================================

void test_accessors() {
    NonceCache cache(5000, 30s);
    assert(cache.max_size() == 5000);
    assert(cache.ttl() == 30s);

    NonceCache default_cache;
    assert(default_cache.max_size() == kDefaultNonceCacheSize);
    assert(default_cache.ttl() == kDefaultReplayTtl);
}

// =============================================================================
// 20. ReplayProtection clear
// =============================================================================

void test_replay_clear() {
    ReplayProtection rp(10000, 60s);
    auto n = make_nonce(1);

    auto now = std::chrono::system_clock::now();
    auto now_secs = std::chrono::duration_cast<std::chrono::seconds>(
                        now.time_since_epoch()).count();

    assert(rp.check(static_cast<std::uint64_t>(now_secs), n));
    assert(rp.size() == 1);

    rp.clear();
    assert(rp.size() == 0);

    // clear 后同一 nonce 可重新接受
    assert(rp.check(static_cast<std::uint64_t>(now_secs), n));
}

int main() {
    std::cout << "=== test_replay_protection (v3.8.6 nonce + timestamp 防重放) ===\n";

    RUN_TEST(test_first_nonce_accepted);
    RUN_TEST(test_duplicate_nonce_rejected);
    RUN_TEST(test_short_nonce_rejected);
    RUN_TEST(test_within_ttl_duplicate_rejected);
    RUN_TEST(test_expired_nonce_reusable);
    RUN_TEST(test_lru_eviction);
    RUN_TEST(test_evicted_nonce_reaccepted);
    RUN_TEST(test_evict_expired_manual);
    RUN_TEST(test_evict_expired_keeps_fresh);
    RUN_TEST(test_stats_accuracy);
    RUN_TEST(test_clear_cache);
    RUN_TEST(test_different_nonce_independent);
    RUN_TEST(test_replay_timestamp_expired);
    RUN_TEST(test_replay_timestamp_future);
    RUN_TEST(test_replay_normal_pass);
    RUN_TEST(test_replay_duplicate_rejected);
    RUN_TEST(test_concurrent_check_and_insert);
    RUN_TEST(test_concurrent_same_nonce);
    RUN_TEST(test_accessors);
    RUN_TEST(test_replay_clear);

    std::cout << "\n=== Result: " << test_passed << "/" << test_count
              << " tests passed ===\n";
    return (test_passed == test_count) ? 0 : 1;
}
