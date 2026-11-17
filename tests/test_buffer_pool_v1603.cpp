// test_buffer_pool_v1603.cpp — v1.6.0.3 (P2) StaticBufferPool 单元测试
//
// 测试覆盖：
//   1. 构造 + 预分配验证
//   2. acquire/release 基础流程
//   3. BorrowedBuffer RAII 析构自动归还
//   4. 池耗尽处理
//   5. 并发 acquire（多线程）
//   6. stats 统计正确性
//   7. try_acquire 行为
//   8. 移动语义
//   9. 手动 release()
//  10. buffer_at 访问器
//  11. 零字节 buffer 边界
//  12. 重复 release 安全性
//  13. 大容量 pool（1000 buffer）
//  14. BufferLocation 枚举值

#include "linoh/multimodal/buffer_pool.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

using namespace linoh::multimodal::ep;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ============================================================================
// TEST 1: 构造 + 预分配
// ============================================================================

static void test_construction() {
    std::printf("[test] construction + pre-allocation...\n");
    StaticBufferPool pool(8, 4096);
    CHECK_EQ(pool.total_count(), static_cast<std::size_t>(8));
    CHECK_EQ(pool.free_count(), static_cast<std::size_t>(8));
    CHECK_EQ(pool.in_use_count(), static_cast<std::size_t>(0));
    CHECK_EQ(pool.buffer_size(), static_cast<std::size_t>(4096));
    CHECK(pool.location() == BufferLocation::REGULAR_HOST);
}

// ============================================================================
// TEST 2: acquire/release 基础
// ============================================================================

static void test_acquire_release() {
    std::printf("[test] acquire/release basic...\n");
    StaticBufferPool pool(4, 1024);
    auto buf = pool.acquire();
    CHECK(buf.valid());
    CHECK_EQ(buf.size(), static_cast<std::size_t>(1024));
    CHECK_EQ(pool.free_count(), static_cast<std::size_t>(3));
    CHECK_EQ(pool.in_use_count(), static_cast<std::size_t>(1));
    buf.release();
    CHECK_EQ(pool.free_count(), static_cast<std::size_t>(4));
    CHECK_EQ(pool.in_use_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// TEST 3: BorrowedBuffer RAII 析构自动归还
// ============================================================================

static void test_raii_destructor() {
    std::printf("[test] BorrowedBuffer RAII destructor...\n");
    StaticBufferPool pool(2, 512);
    {
        auto buf = pool.acquire();
        CHECK(buf.valid());
        CHECK_EQ(pool.free_count(), static_cast<std::size_t>(1));
        // 析构自动归还
    }
    CHECK_EQ(pool.free_count(), static_cast<std::size_t>(2));
}

// ============================================================================
// TEST 4: 池耗尽处理
// ============================================================================

static void test_exhaustion() {
    std::printf("[test] pool exhaustion...\n");
    StaticBufferPool pool(2, 256);
    auto buf1 = pool.acquire();
    auto buf2 = pool.acquire();
    CHECK(buf1.valid());
    CHECK(buf2.valid());
    CHECK_EQ(pool.free_count(), static_cast<std::size_t>(0));

    auto buf3 = pool.acquire();
    CHECK(!buf3.valid());
    CHECK(!buf3);

    auto stats = pool.stats();
    CHECK_EQ(stats.exhaust_total, static_cast<std::uint64_t>(1));
}

// ============================================================================
// TEST 5: 并发 acquire（多线程）
// ============================================================================

static void test_concurrent_acquire() {
    std::printf("[test] concurrent acquire (multi-thread)...\n");
    StaticBufferPool pool(100, 1024);
    std::atomic<int> acquire_count{0};
    std::atomic<int> exhaust_count{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < 10; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < 20; ++i) {
                auto buf = pool.acquire();
                if (buf.valid()) {
                    ++acquire_count;
                    // 模拟使用
                    std::this_thread::sleep_for(std::chrono::microseconds(10));
                    buf.release();
                } else {
                    ++exhaust_count;
                }
            }
        });
    }
    for (auto &t : threads) t.join();

    CHECK_EQ(pool.total_count(), static_cast<std::size_t>(100));
    CHECK_EQ(pool.free_count(), static_cast<std::size_t>(100));
    CHECK_EQ(pool.in_use_count(), static_cast<std::size_t>(0));
    CHECK(acquire_count.load() > 0);
}

// ============================================================================
// TEST 6: stats 统计
// ============================================================================

static void test_stats() {
    std::printf("[test] stats counters...\n");
    StaticBufferPool pool(3, 512);
    auto b1 = pool.acquire();
    auto b2 = pool.acquire();
    auto stats = pool.stats();
    CHECK_EQ(stats.acquire_total, static_cast<std::uint64_t>(2));
    CHECK_EQ(stats.in_use_buffers, static_cast<std::size_t>(2));
    CHECK_EQ(stats.free_buffers, static_cast<std::size_t>(1));

    b1.release();
    stats = pool.stats();
    CHECK_EQ(stats.release_total, static_cast<std::uint64_t>(1));
    CHECK_EQ(stats.in_use_buffers, static_cast<std::size_t>(1));

    b2.release();
    stats = pool.stats();
    CHECK_EQ(stats.release_total, static_cast<std::uint64_t>(2));
    CHECK_EQ(stats.in_use_buffers, static_cast<std::size_t>(0));
}

// ============================================================================
// TEST 7: try_acquire
// ============================================================================

static void test_try_acquire() {
    std::printf("[test] try_acquire...\n");
    StaticBufferPool pool(1, 256);
    auto b1 = pool.try_acquire();
    CHECK(b1.has_value());
    CHECK(b1->valid());

    auto b2 = pool.try_acquire();
    CHECK(!b2.has_value());
}

// ============================================================================
// TEST 8: 移动语义
// ============================================================================

static void test_move_semantics() {
    std::printf("[test] BorrowedBuffer move semantics...\n");
    StaticBufferPool pool(2, 1024);
    auto b1 = pool.acquire();
    CHECK(b1.valid());
    auto *orig_ptr = b1.data_ptr();

    BorrowedBuffer b2(std::move(b1));
    CHECK(b2.valid());
    CHECK(!b1.valid());
    CHECK_EQ(b2.data_ptr(), orig_ptr);

    CHECK_EQ(pool.in_use_count(), static_cast<std::size_t>(1));
    b2.release();
    CHECK_EQ(pool.free_count(), static_cast<std::size_t>(2));
}

// ============================================================================
// TEST 9: 手动 release
// ============================================================================

static void test_manual_release() {
    std::printf("[test] manual release...\n");
    StaticBufferPool pool(1, 128);
    auto b = pool.acquire();
    CHECK(b.valid());
    b.release();
    CHECK(!b.valid());
    CHECK_EQ(pool.free_count(), static_cast<std::size_t>(1));

    // 重复 release 安全（已置空）
    b.release();
    CHECK_EQ(pool.free_count(), static_cast<std::size_t>(1));
}

// ============================================================================
// TEST 10: buffer_at 访问器
// ============================================================================

static void test_buffer_at() {
    std::printf("[test] buffer_at accessor...\n");
    StaticBufferPool pool(2, 256);
    auto b = pool.acquire();
    std::memset(b.data_ptr(), 0xAB, 100);
    b.release();

    auto buf0 = pool.buffer_at(0);
    auto buf1 = pool.buffer_at(1);
    CHECK_EQ(buf0.size(), static_cast<std::size_t>(256));
    CHECK_EQ(buf1.size(), static_cast<std::size_t>(256));

    // 其中一个 buffer 应该有 0xAB 数据（取决于 acquire 取哪个索引）
    bool found = false;
    for (std::size_t i = 0; i < 2; ++i) {
        auto buf = pool.buffer_at(i);
        if (buf[0] == 0xAB) {
            found = true;
            break;
        }
    }
    CHECK(found);
}

// ============================================================================
// TEST 11: 零字节 buffer 边界
// ============================================================================

static void test_zero_byte_buffer() {
    std::printf("[test] zero-byte buffer boundary...\n");
    StaticBufferPool pool(1, 0);
    auto b = pool.acquire();
    CHECK(b.valid());
    CHECK_EQ(b.size(), static_cast<std::size_t>(0));
    b.release();
}

// ============================================================================
// TEST 12: 大容量 pool
// ============================================================================

static void test_large_pool() {
    std::printf("[test] large pool (1000 buffers)...\n");
    StaticBufferPool pool(1000, 1024);
    CHECK_EQ(pool.total_count(), static_cast<std::size_t>(1000));
    std::vector<BorrowedBuffer> bufs;
    for (int i = 0; i < 500; ++i) {
        bufs.push_back(pool.acquire());
    }
    CHECK_EQ(pool.in_use_count(), static_cast<std::size_t>(500));
    bufs.clear();
    CHECK_EQ(pool.free_count(), static_cast<std::size_t>(1000));
}

// ============================================================================
// TEST 13: BufferLocation 枚举值
// ============================================================================

static void test_buffer_location_enum() {
    std::printf("[test] BufferLocation enum values...\n");
    CHECK(static_cast<int>(BufferLocation::REGULAR_HOST) == 0);
    CHECK(static_cast<int>(BufferLocation::PINNED_HOST) == 1);
    CHECK(static_cast<int>(BufferLocation::DEVICE) == 2);
}

// ============================================================================
// TEST 14: 预分配清零验证
// ============================================================================

static void test_preallocated_zero() {
    std::printf("[test] pre-allocated buffers zeroed...\n");
    StaticBufferPool pool(2, 512);
    auto b = pool.acquire();
    bool all_zero = true;
    for (std::size_t i = 0; i < b.size(); ++i) {
        if (b.data()[i] != 0) {
            all_zero = false;
            break;
        }
    }
    CHECK(all_zero);
}

int main() {
    std::printf("=== test_buffer_pool_v1603 ===\n");
    test_construction();
    test_acquire_release();
    test_raii_destructor();
    test_exhaustion();
    test_concurrent_acquire();
    test_stats();
    test_try_acquire();
    test_move_semantics();
    test_manual_release();
    test_buffer_at();
    test_zero_byte_buffer();
    test_large_pool();
    test_buffer_location_enum();
    test_preallocated_zero();
    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
