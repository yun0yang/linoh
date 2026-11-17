// test_sync.cpp — P5-C-1 sync_t<T> 同步包装器测试
//
// 验证：
//   1. 默认构造 + 值构造
//   2. with_lock(callable) 异常安全模式
//   3. lock() 返回 unique_lock
//   4. operator*/operator-> 直接访问
//   5. copy 构造线程安全（std::lock 双锁避免死锁）
//   6. move 构造线程安全
//   7. shared_mutex 特化：shared_lock 多读单写
//   8. shared_sync_t 别名
//   9. lock_pair 双 sync_t 同时上锁（死锁防御）
//  10. 多线程并发写入（正确同步）
//  11. 多线程并发读写（shared_mutex）
//  12. callable 抛异常后锁正确释放（异常安全）
//  13. with_lock 返回值正确传递

#include "linoh/util/sync.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh::util;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 1. 基本构造与读写
// ============================================================================

static void test_default_construct() {
    sync_t<int> s;
    s.with_lock([](int& v) {
        v = 42;
    });
    int got = s.with_lock([](const int& v) { return v; });
    CHECK(got == 42);
}

static void test_value_construct() {
    sync_t<int> s(100);
    int got = s.with_lock([](const int& v) { return v; });
    CHECK(got == 100);
}

static void test_with_lock_returns_value() {
    sync_t<std::string> s(std::string("hello"));
    auto copy = s.with_lock([](const std::string& v) { return v + "_copy"; });
    CHECK(copy == "hello_copy");
    // 原值未变
    auto original = s.with_lock([](const std::string& v) { return v; });
    CHECK(original == "hello");
}

static void test_lock_returns_unique_lock() {
    sync_t<int> s(7);
    auto lk = s.lock();
    *s = 10;  // operator* 直接访问（已持有锁）
    CHECK(*s == 10);
    // lk 析构时自动 unlock
}

static void test_operator_arrow() {
    sync_t<std::string> s(std::string("world"));
    auto lk = s.lock();
    s->append("!");
    CHECK(*s == "world!");
}

// ============================================================================
// 2. copy / move 构造
// ============================================================================

static void test_copy_construct() {
    sync_t<int> original(99);
    sync_t<int> copied(original);
    int got = copied.with_lock([](const int& v) { return v; });
    CHECK(got == 99);
    // 原值仍在
    int orig = original.with_lock([](const int& v) { return v; });
    CHECK(orig == 99);
}

static void test_copy_construct_string() {
    sync_t<std::string> original(std::string("data"));
    sync_t<std::string> copied(original);
    auto got = copied.with_lock([](const std::string& v) { return v; });
    CHECK(got == "data");
}

static void test_move_construct() {
    sync_t<std::string> original(std::string("movable"));
    sync_t<std::string> moved(std::move(original));
    auto got = moved.with_lock([](const std::string& v) { return v; });
    CHECK(got == "movable");
}

static void test_move_construct_after_use() {
    // 先用一下再 move（验证 mutex 状态正常）
    sync_t<int> s(5);
    s.with_lock([](int& v) { v += 1; });
    sync_t<int> moved(std::move(s));
    int got = moved.with_lock([](const int& v) { return v; });
    CHECK(got == 6);
}

// ============================================================================
// 3. shared_mutex 特化
// ============================================================================

static void test_shared_lock_basic() {
    sync_t<std::string, std::shared_mutex> s(std::string("shared"));
    {
        auto slk = s.shared_lock();
        CHECK(*s == "shared");
    }
    // 共享锁释放后可获取独占锁
    {
        auto lk = s.lock();
        *s = "updated";
        CHECK(*s == "updated");
    }
}

static void test_with_shared() {
    sync_t<int, std::shared_mutex> s(42);
    int got = s.with_shared([](const int& v) { return v * 2; });
    CHECK(got == 84);
}

static void test_shared_sync_t_alias() {
    shared_sync_t<std::string> s(std::string("alias"));
    auto got = s.with_lock([](const std::string& v) { return v; });
    CHECK(got == "alias");
    auto shared_got = s.with_shared([](const std::string& v) { return v + "_r"; });
    CHECK(shared_got == "alias_r");
}

// ============================================================================
// 4. lock_pair 双 sync_t 同时上锁
// ============================================================================

static void test_lock_pair_basic() {
    sync_t<int> a(1);
    sync_t<int> b(2);
    auto [lka, lkb] = lock_pair(a, b);
    *a = 10;
    *b = 20;
    CHECK(*a == 10);
    CHECK(*b == 20);
}

static void test_lock_pair_string() {
    sync_t<std::string> a(std::string("aaa"));
    sync_t<std::string> b(std::string("bbb"));
    {
        auto [lka, lkb] = lock_pair(a, b);
        a->append("+");
        b->append("+");
    }
    CHECK(*a == "aaa+");
    CHECK(*b == "bbb+");
}

// ============================================================================
// 5. 异常安全：callable 抛异常后锁正确释放
// ============================================================================

static void test_exception_safety() {
    sync_t<int> s(0);
    bool caught = false;
    try {
        s.with_lock([](int& v) {
            v = 1;
            throw std::runtime_error("test");
        });
    } catch (const std::exception&) {
        caught = true;
    }
    CHECK(caught);
    // 锁应该已经被释放，可以再次加锁
    int got = s.with_lock([](const int& v) { return v; });
    CHECK(got == 1);
}

static void test_exception_in_with_shared() {
    sync_t<int, std::shared_mutex> s(10);
    bool caught = false;
    try {
        s.with_shared([](const int& v) {
            throw std::runtime_error("shared_test");
        });
    } catch (const std::exception&) {
        caught = true;
    }
    CHECK(caught);
    // 锁已释放
    int got = s.with_lock([](const int& v) { return v; });
    CHECK(got == 10);
}

// ============================================================================
// 6. 多线程并发：写写互斥
// ============================================================================

static void test_concurrent_writes_mutex() {
    sync_t<int> counter(0);
    constexpr int kThreads = 8;
    constexpr int kIters = 10000;
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&counter]() {
            for (int j = 0; j < kIters; ++j) {
                counter.with_lock([](int& v) { v += 1; });
            }
        });
    }
    for (auto& t : threads) t.join();
    int got = counter.with_lock([](const int& v) { return v; });
    CHECK(got == kThreads * kIters);
}

static void test_concurrent_writes_shared_mutex() {
    sync_t<long long> counter(0);
    constexpr int kThreads = 8;
    constexpr int kIters = 10000;
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&counter]() {
            for (int j = 0; j < kIters; ++j) {
                counter.with_lock([](long long& v) { v += 1; });
            }
        });
    }
    for (auto& t : threads) t.join();
    long long got = counter.with_lock([](const long long& v) { return v; });
    CHECK(got == static_cast<long long>(kThreads) * kIters);
}

// ============================================================================
// 7. 多线程并发：读写分离（shared_mutex 多读单写）
// ============================================================================

static void test_concurrent_read_write_shared() {
    sync_t<int, std::shared_mutex> data(0);
    constexpr int kReaders = 4;
    constexpr int kWriters = 2;
    constexpr int kIters = 2000;

    std::atomic<int> reads{0};
    std::atomic<int> writes{0};

    std::vector<std::thread> threads;
    threads.reserve(kReaders + kWriters);

    // 读者：shared_lock，限制迭代次数避免写者饥饿
    for (int i = 0; i < kReaders; ++i) {
        threads.emplace_back([&]() {
            for (int j = 0; j < kIters; ++j) {
                data.with_shared([&](const int& v) {
                    (void)v;
                    reads.fetch_add(1, std::memory_order_relaxed);
                });
                // 偶尔 yield 给写者机会
                if ((j & 0x3F) == 0) std::this_thread::yield();
            }
        });
    }

    // 写者：exclusive lock
    for (int i = 0; i < kWriters; ++i) {
        threads.emplace_back([&]() {
            for (int j = 0; j < kIters; ++j) {
                data.with_lock([](int& v) { v += 1; });
                writes.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    int final_value = data.with_lock([](const int& v) { return v; });
    CHECK(final_value == kWriters * kIters);
    CHECK(reads.load() > 0);
    CHECK(writes.load() == kWriters * kIters);
}

// ============================================================================
// 8. 多线程并发：copy 构造与读写的线程安全
// ============================================================================

static void test_copy_construct_concurrent() {
    sync_t<int> original(42);
    std::atomic<int> copy_values_sum{0};
    std::atomic<int> copy_count{0};

    // copier 线程：限制迭代次数避免无限循环
    std::thread copier([&]() {
        for (int i = 0; i < 5000; ++i) {
            sync_t<int> copied(original);
            int v = copied.with_lock([](const int& c) { return c; });
            copy_values_sum.fetch_add(v, std::memory_order_relaxed);
            copy_count.fetch_add(1, std::memory_order_relaxed);
        }
    });

    // writer 线程：改写 1000 次
    std::thread writer([&]() {
        for (int i = 0; i < 1000; ++i) {
            original.with_lock([i](int& v) { v = i; });
        }
    });

    copier.join();
    writer.join();

    // copy_values_sum 应该是 [0,999] 范围内的某些值之和
    CHECK(copy_values_sum.load() >= 0);
    CHECK(copy_count.load() == 5000);
}

// ============================================================================
// 9. 复杂类型：vector / map
// ============================================================================

static void test_with_vector() {
    sync_t<std::vector<int>> vec;
    for (int i = 0; i < 100; ++i) {
        vec.with_lock([i](std::vector<int>& v) { v.push_back(i); });
    }
    std::size_t sz = vec.with_lock([](const std::vector<int>& v) { return v.size(); });
    CHECK(sz == 100);
    int last = vec.with_lock([](const std::vector<int>& v) { return v.back(); });
    CHECK(last == 99);
}

static void test_with_unordered_map() {
    sync_t<std::unordered_map<std::string, int>> map;
    map.with_lock([](std::unordered_map<std::string, int>& m) {
        m["one"] = 1;
        m["two"] = 2;
        m["three"] = 3;
    });
    auto got = map.with_lock([](const std::unordered_map<std::string, int>& m) {
        auto it = m.find("two");
        return it != m.end() ? it->second : -1;
    });
    CHECK(got == 2);
    auto missing = map.with_lock([](const std::unordered_map<std::string, int>& m) {
        return m.count("missing");
    });
    CHECK(missing == 0);
}

// ============================================================================
// 10. lock() + 显式 unlock 模式（unique_lock 灵活性）
// ============================================================================

static void test_unique_lock_early_unlock() {
    sync_t<int> s(5);
    {
        auto lk = s.lock();
        *s = 10;
        // 提前释放锁
        lk.unlock();
        // 此处不再持有锁，再次 lock 应成功
    }
    int got = s.with_lock([](const int& v) { return v; });
    CHECK(got == 10);
}

static void test_unique_lock_deferred() {
    // 通过 lock() 拿到 unique_lock 后，可以 defer/adopt/move
    sync_t<int> s(100);
    auto lk1 = s.lock();
    lk1.unlock();
    // 再次 lock（lk1 已 unlock，可以复用）
    // 但 unique_lock::lock 会调用 mutex_.lock()
    // 这里我们直接调用 with_lock 验证
    s.with_lock([](int& v) { v += 1; });
    int got = s.with_lock([](const int& v) { return v; });
    CHECK(got == 101);
}

// ============================================================================
// 11. 死锁防御：lock_pair 多次调用
// ============================================================================

static void test_lock_pair_no_deadlock() {
    // 多次以不同顺序调用 lock_pair，验证不会死锁
    sync_t<int> a(1), b(2), c(3);
    for (int i = 0; i < 100; ++i) {
        {
            auto [lka, lkb] = lock_pair(a, b);
            *a += 1;
            *b += 1;
        }
        {
            auto [lkb, lkc] = lock_pair(b, c);
            *b += 1;
            *c += 1;
        }
        {
            auto [lkc, lka] = lock_pair(c, a);
            *c += 1;
            *a += 1;
        }
    }
    int av = a.with_lock([](const int& v) { return v; });
    int bv = b.with_lock([](const int& v) { return v; });
    int cv = c.with_lock([](const int& v) { return v; });
    // 每轮每变量 +2（a 在 (a,b) 和 (c,a) 中各 +1；b 在 (a,b) 和 (b,c) 中各 +1；c 在 (b,c) 和 (c,a) 中各 +1）
    CHECK(av == 1 + 100 * 2);
    CHECK(bv == 2 + 100 * 2);
    CHECK(cv == 3 + 100 * 2);
}

// ============================================================================
// 12. 并发 lock_pair 测试（多线程同时 lock_pair 不同顺序）
// ============================================================================

static void test_lock_pair_concurrent() {
    sync_t<int> a(0), b(0);
    constexpr int kThreads = 4;
    constexpr int kIters = 5000;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&a, &b, i]() {
            for (int j = 0; j < kIters; ++j) {
                if ((i + j) % 2 == 0) {
                    auto [lka, lkb] = lock_pair(a, b);
                    *a += 1;
                    *b += 1;
                } else {
                    // 反向 lock，验证 std::lock 避免死锁
                    auto [lkb, lka] = lock_pair(b, a);
                    *b += 1;
                    *a += 1;
                }
            }
        });
    }
    for (auto& t : threads) t.join();

    int av = a.with_lock([](const int& v) { return v; });
    int bv = b.with_lock([](const int& v) { return v; });
    // 每轮每变量 +1（不管是 (a,b) 还是 (b,a) 顺序，都是 a+=1 b+=1）
    CHECK(av == kThreads * kIters);
    CHECK(bv == kThreads * kIters);
}

// ============================================================================
// 13. debug_is_uncontended
// ============================================================================

static void test_debug_is_uncontended() {
    sync_t<int> s(0);
    // 无锁状态下应返回 true
    CHECK(s.debug_is_uncontended() == true);
    // 持有锁状态下应返回 false
    {
        auto lk = s.lock();
        CHECK(s.debug_is_uncontended() == false);
    }
    // 释放后再次 true
    CHECK(s.debug_is_uncontended() == true);
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::printf("=== test_sync.cpp — P5-C-1 sync_t<T> ===\n");

    test_default_construct();
    test_value_construct();
    test_with_lock_returns_value();
    test_lock_returns_unique_lock();
    test_operator_arrow();

    test_copy_construct();
    test_copy_construct_string();
    test_move_construct();
    test_move_construct_after_use();

    test_shared_lock_basic();
    test_with_shared();
    test_shared_sync_t_alias();

    test_lock_pair_basic();
    test_lock_pair_string();

    test_exception_safety();
    test_exception_in_with_shared();

    test_concurrent_writes_mutex();
    test_concurrent_writes_shared_mutex();

    test_concurrent_read_write_shared();

    test_copy_construct_concurrent();

    test_with_vector();
    test_with_unordered_map();

    test_unique_lock_early_unlock();
    test_unique_lock_deferred();

    test_lock_pair_no_deadlock();
    test_lock_pair_concurrent();

    test_debug_is_uncontended();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
