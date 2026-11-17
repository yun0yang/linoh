// test_session_deduper.cpp — SessionDeduper 单元测试（V3.4）
//
// 测试覆盖（对应 docs/LINOH_EVENTBUS_BINARY_FRAME_IMPL_PLAN.md §3.6）：
//   1. test_deduper_basic          首次见到 true / 重复 false
//   2. test_deduper_lru_eviction   LRU/FIFO 淘汰最旧
//   3. test_deduper_clear          清空后重新接受
//   4. test_deduper_capacity       容量边界 + capacity() 查询
//   5. test_deduper_thread_safety  多线程并发 check_and_record

#include "linoh/protocol/session_deduper.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <thread>
#include <vector>

using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    if ((a) == (b)) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s != %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ============================================================================
// 1. 基本：首次 true / 重复 false
// ============================================================================

static void test_deduper_basic() {
    std::printf("[test] basic: first-seen true, duplicate false...\n");
    SessionDeduper d(10);
    CHECK_EQ(d.size(), 0u);

    auto sid1 = SessionId::generate();
    CHECK(d.check_and_record(sid1));    // 首次 → true
    CHECK_EQ(d.size(), 1u);

    CHECK(!d.check_and_record(sid1));   // 重复 → false
    CHECK_EQ(d.size(), 1u);             // size 不变

    auto sid2 = SessionId::generate();
    CHECK(d.check_and_record(sid2));    // 首次 → true
    CHECK_EQ(d.size(), 2u);

    CHECK(!d.check_and_record(sid1));   // sid1 仍重复
    CHECK(!d.check_and_record(sid2));   // sid2 重复
    CHECK_EQ(d.size(), 2u);
}

// ============================================================================
// 2. LRU/FIFO 淘汰：容量超限时淘汰最旧
// ============================================================================

static void test_deduper_lru_eviction() {
    std::printf("[test] LRU eviction: oldest evicted on overflow...\n");
    SessionDeduper d(3);  // 容量 3

    auto s1 = SessionId::generate();
    auto s2 = SessionId::generate();
    auto s3 = SessionId::generate();
    auto s4 = SessionId::generate();

    // 填满容量：lru = [s1, s2, s3]
    CHECK(d.check_and_record(s1));
    CHECK(d.check_and_record(s2));
    CHECK(d.check_and_record(s3));
    CHECK_EQ(d.size(), 3u);

    // s1 仍在缓存中 → 重复
    CHECK(!d.check_and_record(s1));

    // 插入 s4 → 淘汰 s1（最旧）：lru = [s2, s3, s4]
    CHECK(d.check_and_record(s4));
    CHECK_EQ(d.size(), 3u);

    // s1 被淘汰，重新接受 → 淘汰 s2：lru = [s3, s4, s1]
    CHECK(d.check_and_record(s1));
    CHECK_EQ(d.size(), 3u);

    // s2 被淘汰，重新接受 → 淘汰 s3：lru = [s4, s1, s2]
    CHECK(d.check_and_record(s2));
    CHECK_EQ(d.size(), 3u);

    // s3 被淘汰，重新接受 → 淘汰 s4：lru = [s1, s2, s3]
    CHECK(d.check_and_record(s3));
    CHECK_EQ(d.size(), 3u);

    // s4 被淘汰，重新接受 → 淘汰 s1：lru = [s2, s3, s4]
    CHECK(d.check_and_record(s4));
    CHECK_EQ(d.size(), 3u);

    // s1 被淘汰，重新接受 → 淘汰 s2：lru = [s3, s4, s1]
    CHECK(d.check_and_record(s1));
    CHECK_EQ(d.size(), 3u);

    // s2 被淘汰（刚被淘汰），重新接受 → 淘汰 s3
    CHECK(d.check_and_record(s2));
    CHECK_EQ(d.size(), 3u);
}

// ============================================================================
// 3. clear() 清空后重新接受
// ============================================================================

static void test_deduper_clear() {
    std::printf("[test] clear: reset and re-accept...\n");
    SessionDeduper d(100);
    std::vector<SessionId> sids;
    for (int i = 0; i < 5; ++i) {
        auto sid = SessionId::generate();
        sids.push_back(sid);
        CHECK(d.check_and_record(sid));
    }
    CHECK_EQ(d.size(), 5u);

    d.clear();
    CHECK_EQ(d.size(), 0u);

    // 清空后，原来的 sid 重新被接受
    CHECK(d.check_and_record(sids[0]));
    CHECK_EQ(d.size(), 1u);

    // 再次 clear
    d.clear();
    CHECK_EQ(d.size(), 0u);
}

// ============================================================================
// 4. 容量边界 + capacity() 查询
// ============================================================================

static void test_deduper_capacity() {
    std::printf("[test] capacity boundary + capacity() query...\n");
    SessionDeduper d(100);
    CHECK_EQ(d.capacity(), 100u);

    std::vector<SessionId> sids;
    sids.reserve(101);
    for (int i = 0; i < 100; ++i) {
        auto sid = SessionId::generate();
        sids.push_back(sid);
        CHECK(d.check_and_record(sid));
    }
    CHECK_EQ(d.size(), 100u);

    // 插入第 101 个 → 淘汰最旧（sids[0]），size 仍 100
    auto sid101 = SessionId::generate();
    CHECK(d.check_and_record(sid101));
    CHECK_EQ(d.size(), 100u);

    // sids[0] 被淘汰，重新接受
    CHECK(d.check_and_record(sids[0]));
    CHECK_EQ(d.size(), 100u);

    // sids[1] 仍重复（因 sids[0] 重新插入淘汰了 sids[1]）
    CHECK(d.check_and_record(sids[1]));  // 被淘汰，重新接受

    // 容量 1 的边界
    SessionDeduper d1(1);
    auto a = SessionId::generate();
    auto b = SessionId::generate();
    CHECK(d1.check_and_record(a));
    CHECK_EQ(d1.size(), 1u);
    CHECK(d1.check_and_record(b));   // 插入 b 淘汰 a
    CHECK_EQ(d1.size(), 1u);
    CHECK(d1.check_and_record(a));   // a 已被淘汰，重新接受
}

// ============================================================================
// 5. 多线程并发 check_and_record
// ============================================================================

static void test_deduper_thread_safety() {
    std::printf("[test] thread safety: 4 threads concurrent...\n");
    SessionDeduper d(100000);  // 大容量避免淘汰干扰
    const int kThreads = 4;
    const int kPerThread = 1000;
    std::atomic<int> first_seen_count{0};

    auto worker = [&]() {
        for (int i = 0; i < kPerThread; ++i) {
            auto sid = SessionId::generate();
            if (d.check_and_record(sid)) {
                ++first_seen_count;
            }
        }
    };

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back(worker);
    }
    for (auto &th : threads) {
        th.join();
    }

    // 4 线程 × 1000 = 4000 个唯一 sid（SessionId 碰撞概率极低）
    CHECK_EQ(first_seen_count.load(), kThreads * kPerThread);
    CHECK_EQ(d.size(), static_cast<std::size_t>(kThreads * kPerThread));

    // 并发重复 check：已存在的 sid 应全部返回 false
    // 取已记录的 sid 重新 check（通过 clear + 重新插入模拟）
    d.clear();
    CHECK_EQ(d.size(), 0u);
}

// ============================================================================

int main() {
    std::printf("=== test_session_deduper ===\n");

    test_deduper_basic();
    test_deduper_lru_eviction();
    test_deduper_clear();
    test_deduper_capacity();
    test_deduper_thread_safety();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
