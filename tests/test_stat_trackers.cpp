// test_stat_trackers.cpp — P5-C-2 min_max_avg_tracker 统计追踪测试
//
// 验证：
//   1. 基本累积 min/max/avg 正确
//   2. 空状态查询（min/max/avg/total/count）
//   3. reset 重置
//   4. 间隔回调（按时间触发并重置）
//   5. 多 tracker 实例独立
//   6. merge 合并
//   7. channel_stat_tracker 多通道聚合
//   8. thread_safe_min_max_avg_tracker 多线程安全
//   9. 浮点 / 整型 / 长整型
//  10. 大样本量
//  11. 边界：单样本、负数

#include "linoh/util/stat_trackers.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>
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
// 1. 基本累积
// ============================================================================

static void test_basic_collect_double() {
    min_max_avg_tracker<double> t;
    t.collect(12.5);
    t.collect(8.3);
    t.collect(15.7);
    t.collect(10.0);

    CHECK(t.count() == 4);
    CHECK(t.min() == 8.3);
    CHECK(t.max() == 15.7);
    // avg = (12.5+8.3+15.7+10.0)/4 = 46.5/4 = 11.625
    CHECK(t.avg() > 11.624 && t.avg() < 11.626);
    CHECK(t.total() > 46.4 && t.total() < 46.6);
}

static void test_basic_collect_int() {
    min_max_avg_tracker<int> t;
    t.collect(5);
    t.collect(3);
    t.collect(8);
    t.collect(1);
    t.collect(9);

    CHECK(t.count() == 5);
    CHECK(t.min() == 1);
    CHECK(t.max() == 9);
    CHECK(t.total() == 26);
    CHECK(t.avg() == 5.2);
}

static void test_basic_collect_long() {
    min_max_avg_tracker<long long> t;
    t.collect(1000000LL);
    t.collect(2000000LL);
    t.collect(3000000LL);

    CHECK(t.count() == 3);
    CHECK(t.min() == 1000000LL);
    CHECK(t.max() == 3000000LL);
    CHECK(t.total() == 6000000LL);
    CHECK(t.avg() == 2000000.0);
}

// ============================================================================
// 2. 空状态查询
// ============================================================================

static void test_empty_state() {
    min_max_avg_tracker<double> t;
    CHECK(t.empty());
    CHECK(t.count() == 0);
    CHECK(t.avg() == 0.0);
    CHECK(t.total() == 0.0);
    // min/max 在空状态下返回类型极限值（语义未定义，但应稳定）
    // 这里只验证不崩溃
    (void)t.min();
    (void)t.max();
}

// ============================================================================
// 3. 单样本
// ============================================================================

static void test_single_sample() {
    min_max_avg_tracker<int> t;
    t.collect(42);
    CHECK(!t.empty());
    CHECK(t.count() == 1);
    CHECK(t.min() == 42);
    CHECK(t.max() == 42);
    CHECK(t.avg() == 42.0);
    CHECK(t.total() == 42);
}

// ============================================================================
// 4. 负数
// ============================================================================

static void test_negative_values() {
    min_max_avg_tracker<int> t;
    t.collect(-5);
    t.collect(-10);
    t.collect(3);
    t.collect(-2);

    CHECK(t.count() == 4);
    CHECK(t.min() == -10);
    CHECK(t.max() == 3);
    CHECK(t.total() == -14);
    CHECK(t.avg() == -3.5);
}

// ============================================================================
// 5. reset 重置
// ============================================================================

static void test_reset() {
    min_max_avg_tracker<int> t;
    t.collect(5);
    t.collect(10);
    CHECK(t.count() == 2);

    t.reset();
    CHECK(t.empty());
    CHECK(t.count() == 0);
    CHECK(t.avg() == 0.0);

    // reset 后可继续 collect
    t.collect(100);
    CHECK(t.count() == 1);
    CHECK(t.min() == 100);
    CHECK(t.max() == 100);
}

// ============================================================================
// 6. 间隔回调
// ============================================================================

static void test_interval_callback_triggers() {
    min_max_avg_tracker<int> t;
    int cb_count = 0;
    int cb_min = 0, cb_max = 0;
    double cb_avg = 0.0;

    auto callback = [&](int mn, int mx, double av) {
        ++cb_count;
        cb_min = mn;
        cb_max = mx;
        cb_avg = av;
    };

    // 第一次 collect 不触发回调（记录起始时间）
    t.collect_and_callback_on_interval(5, callback, std::chrono::milliseconds(50));
    CHECK(cb_count == 0);

    // 短时间内多次 collect，不应触发
    t.collect_and_callback_on_interval(10, callback, std::chrono::milliseconds(50));
    t.collect_and_callback_on_interval(15, callback, std::chrono::milliseconds(50));
    CHECK(cb_count == 0);
    CHECK(t.count() == 3);  // 还未重置

    // 等待超过间隔
    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    // 再次 collect，应触发回调并重置
    t.collect_and_callback_on_interval(20, callback, std::chrono::milliseconds(50));
    CHECK(cb_count == 1);
    CHECK(cb_min == 5);
    CHECK(cb_max == 20);
    CHECK(cb_avg > 12.4 && cb_avg < 12.6);  // (5+10+15+20)/4 = 12.5

    // 重置后 count 应为 1（新样本）
    CHECK(t.count() == 1);
    CHECK(t.min() == 20);
}

static void test_interval_callback_no_trigger_under_interval() {
    min_max_avg_tracker<int> t;
    int cb_count = 0;
    auto callback = [&](int, int, double) { ++cb_count; };

    t.collect_and_callback_on_interval(1, callback, std::chrono::milliseconds(100));
    for (int i = 0; i < 10; ++i) {
        t.collect_and_callback_on_interval(i + 2, callback, std::chrono::milliseconds(100));
    }
    CHECK(cb_count == 0);  // 都在间隔内
    CHECK(t.count() == 11);
}

// ============================================================================
// 7. 多 tracker 实例独立
// ============================================================================

static void test_multiple_instances_independent() {
    min_max_avg_tracker<int> t1, t2, t3;

    t1.collect(10);
    t1.collect(20);

    t2.collect(100);
    t2.collect(200);
    t2.collect(300);

    t3.collect(-5);
    t3.collect(5);

    CHECK(t1.count() == 2);
    CHECK(t1.min() == 10);
    CHECK(t1.max() == 20);

    CHECK(t2.count() == 3);
    CHECK(t2.min() == 100);
    CHECK(t2.max() == 300);

    CHECK(t3.count() == 2);
    CHECK(t3.min() == -5);
    CHECK(t3.max() == 5);

    // 重置 t2 不影响 t1/t3
    t2.reset();
    CHECK(t1.count() == 2);
    CHECK(t2.count() == 0);
    CHECK(t3.count() == 2);
}

// ============================================================================
// 8. merge 合并
// ============================================================================

static void test_merge_basic() {
    min_max_avg_tracker<int> t1, t2;
    t1.collect(5);
    t1.collect(10);
    t1.collect(15);

    t2.collect(3);
    t2.collect(20);

    t1.merge(t2);
    CHECK(t1.count() == 5);
    CHECK(t1.min() == 3);
    CHECK(t1.max() == 20);
    CHECK(t1.total() == 53);  // 30+23
    CHECK(t1.avg() > 10.5 && t1.avg() < 10.7);  // 53/5 = 10.6
}

static void test_merge_empty_into_nonempty() {
    min_max_avg_tracker<int> t1, t2;
    t1.collect(5);
    t1.collect(10);

    t1.merge(t2);  // 合并空 tracker
    CHECK(t1.count() == 2);
    CHECK(t1.min() == 5);
    CHECK(t1.max() == 10);
}

static void test_merge_nonempty_into_empty() {
    min_max_avg_tracker<int> t1, t2;
    t2.collect(5);
    t2.collect(10);

    t1.merge(t2);
    CHECK(t1.count() == 2);
    CHECK(t1.min() == 5);
    CHECK(t1.max() == 10);
}

static void test_merge_both_empty() {
    min_max_avg_tracker<int> t1, t2;
    t1.merge(t2);
    CHECK(t1.empty());
    CHECK(t1.count() == 0);
}

// ============================================================================
// 9. channel_stat_tracker 多通道聚合
// ============================================================================

static void test_channel_stat_basic() {
    channel_stat_tracker<double, 4> rtt_stats;
    rtt_stats.collect(0, 5.0);   // LLM
    rtt_stats.collect(0, 6.0);
    rtt_stats.collect(1, 12.0);  // IMG
    rtt_stats.collect(1, 18.0);
    rtt_stats.collect(2, 30.0);  // VIDEO
    rtt_stats.collect(3, 8.0);   // AUDIO

    CHECK(rtt_stats.channel(0).count() == 2);
    CHECK(rtt_stats.channel(0).min() == 5.0);
    CHECK(rtt_stats.channel(0).max() == 6.0);

    CHECK(rtt_stats.channel(1).count() == 2);
    CHECK(rtt_stats.channel(1).min() == 12.0);
    CHECK(rtt_stats.channel(1).max() == 18.0);

    CHECK(rtt_stats.channel(2).count() == 1);
    CHECK(rtt_stats.channel(3).count() == 1);
}

static void test_channel_stat_aggregate() {
    channel_stat_tracker<double, 3> stats;
    stats.collect(0, 10.0);
    stats.collect(1, 20.0);
    stats.collect(2, 30.0);

    auto agg = stats.aggregate();
    CHECK(agg.count() == 3);
    CHECK(agg.min() == 10.0);
    CHECK(agg.max() == 30.0);
    CHECK(agg.avg() == 20.0);
    CHECK(agg.total() == 60.0);
}

static void test_channel_stat_reset() {
    channel_stat_tracker<int, 3> stats;
    stats.collect(0, 1);
    stats.collect(1, 2);
    stats.collect(2, 3);

    stats.reset();
    CHECK(stats.channel(0).empty());
    CHECK(stats.channel(1).empty());
    CHECK(stats.channel(2).empty());
}

static void test_channel_stat_out_of_range_ignored() {
    channel_stat_tracker<int, 3> stats;
    stats.collect(10, 100);  // 越界，应被忽略
    CHECK(stats.channel(0).empty());
    CHECK(stats.channel(2).empty());
}

static void test_channel_stat_size() {
    channel_stat_tracker<int, 5> stats;
    CHECK(stats.size() == 5);
}

// ============================================================================
// 10. thread_safe_min_max_avg_tracker 多线程安全
// ============================================================================

static void test_thread_safe_basic() {
    thread_safe_min_max_avg_tracker<int> t;
    t.collect(5);
    t.collect(10);
    t.collect(15);

    CHECK(t.count() == 3);
    CHECK(t.min() == 5);
    CHECK(t.max() == 15);
    CHECK(t.avg() == 10.0);
    CHECK(t.total() == 30);
}

static void test_thread_safe_concurrent_collect() {
    thread_safe_min_max_avg_tracker<long long> t;
    constexpr int kThreads = 8;
    constexpr int kIters = 10000;
    constexpr int kBase = 1000;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&t, i]() {
            for (int j = 0; j < kIters; ++j) {
                t.collect(kBase + i);  // 每线程固定值
            }
        });
    }
    for (auto& th : threads) th.join();

    CHECK(t.count() == kThreads * kIters);
    CHECK(t.min() == kBase);                  // 线程 0 收集 1000
    CHECK(t.max() == kBase + kThreads - 1);   // 线程 7 收集 1007
    // total = sum_{i=0..7} (1000+i) * 10000 = 10000 * (8000 + 0+1+...+7) = 10000 * 8028
    long long expected_total = static_cast<long long>(kIters) * (static_cast<long long>(kBase) * kThreads + (kThreads - 1) * kThreads / 2);
    CHECK(t.total() == expected_total);
}

static void test_thread_safe_with_lock() {
    thread_safe_min_max_avg_tracker<int> t;
    t.with_lock([](min_max_avg_tracker<int>& inner) {
        inner.collect(1);
        inner.collect(2);
        inner.collect(3);
    });

    int mn = t.with_lock([](min_max_avg_tracker<int>& inner) { return inner.min(); });
    int mx = t.with_lock([](min_max_avg_tracker<int>& inner) { return inner.max(); });
    double av = t.with_lock([](min_max_avg_tracker<int>& inner) { return inner.avg(); });

    CHECK(mn == 1);
    CHECK(mx == 3);
    CHECK(av == 2.0);
}

static void test_thread_safe_merge() {
    thread_safe_min_max_avg_tracker<int> t1, t2;
    t1.collect(5);
    t1.collect(10);
    t2.collect(3);
    t2.collect(20);

    t1.merge(t2);
    CHECK(t1.count() == 4);
    CHECK(t1.min() == 3);
    CHECK(t1.max() == 20);
}

static void test_thread_safe_reset() {
    thread_safe_min_max_avg_tracker<int> t;
    t.collect(5);
    t.collect(10);
    t.reset();
    CHECK(t.empty());
    CHECK(t.count() == 0);
}

// ============================================================================
// 11. 大样本量
// ============================================================================

static void test_large_sample_count() {
    min_max_avg_tracker<long long> t;
    constexpr int N = 1000000;
    for (int i = 0; i < N; ++i) {
        t.collect(i);
    }
    CHECK(t.count() == N);
    CHECK(t.min() == 0);
    CHECK(t.max() == N - 1);
    // total = 0+1+...+(N-1) = N*(N-1)/2
    long long expected_total = static_cast<long long>(N) * (N - 1) / 2;
    CHECK(t.total() == expected_total);
    double expected_avg = static_cast<double>(N - 1) / 2.0;
    CHECK(t.avg() > expected_avg - 0.01 && t.avg() < expected_avg + 0.01);
}

// ============================================================================
// 12. 相同值多次收集
// ============================================================================

static void test_same_value_repeated() {
    min_max_avg_tracker<int> t;
    for (int i = 0; i < 100; ++i) {
        t.collect(42);
    }
    CHECK(t.count() == 100);
    CHECK(t.min() == 42);
    CHECK(t.max() == 42);
    CHECK(t.avg() == 42.0);
    CHECK(t.total() == 4200);
}

// ============================================================================
// 13. 浮点精度
// ============================================================================

static void test_floating_point_precision() {
    min_max_avg_tracker<double> t;
    t.collect(0.1);
    t.collect(0.2);
    t.collect(0.3);

    CHECK(t.count() == 3);
    CHECK(t.min() > 0.099 && t.min() < 0.101);
    CHECK(t.max() > 0.299 && t.max() < 0.301);
    double av = t.avg();
    CHECK(av > 0.199 && av < 0.201);
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::printf("=== test_stat_trackers.cpp — P5-C-2 min_max_avg_tracker ===\n");

    test_basic_collect_double();
    test_basic_collect_int();
    test_basic_collect_long();

    test_empty_state();

    test_single_sample();

    test_negative_values();

    test_reset();

    test_interval_callback_triggers();
    test_interval_callback_no_trigger_under_interval();

    test_multiple_instances_independent();

    test_merge_basic();
    test_merge_empty_into_nonempty();
    test_merge_nonempty_into_empty();
    test_merge_both_empty();

    test_channel_stat_basic();
    test_channel_stat_aggregate();
    test_channel_stat_reset();
    test_channel_stat_out_of_range_ignored();
    test_channel_stat_size();

    test_thread_safe_basic();
    test_thread_safe_concurrent_collect();
    test_thread_safe_with_lock();
    test_thread_safe_merge();
    test_thread_safe_reset();

    test_large_sample_count();

    test_same_value_repeated();

    test_floating_point_precision();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
