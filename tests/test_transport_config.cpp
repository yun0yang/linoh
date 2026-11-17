// =============================================================================
// test_transport_config.cpp — v3.9.0 QUIC 传输参数 + BBR v2 pacing 限速单元测试
//
// 覆盖场景：
//   PacingLimiter（令牌桶限速器）:
//   1.  默认状态 enabled=false
//   2.  configure(0, rtt) 后 enabled=false（速率 0 禁用）
//   3.  configure(rate, rtt) 后 enabled=true
//   4.  桶容量 = 2 * pacing_rate * rtt（精确计算）
//   5.  try_consume 首包放行（初始令牌 = 桶容量）
//   6.  令牌耗尽后拒绝
//   7.  时间推进后令牌补充再放行
//   8.  pacing_rate=0 时 try_consume 始终放行
//   9.  reset 后 enabled=false
//  10.  桶容量上限 64MB（防溢出）
//  11.  configure 多次调用更新桶容量
//  12.  并发 try_consume 安全（多线程令牌守恒）
//  13.  诊断访问器 tokens_available/bucket_capacity/pacing_rate_bps
//
//   BBR v2 pacing 集成:
//  14.  BBR 初始 pacing_limiter disabled
//  15.  on_ack 后 pacing_limiter enabled
//  16.  pacing_rate_bps 传播到 pacing_limiter
//  17.  can_send 受 pacing 限速（令牌耗尽后 false，cwnd 仍够）
//  18.  reset 后 pacing_limiter disabled
// =============================================================================

#include "linoh/protocol/pacing_limiter.hpp"
#include "linoh/protocol/bbr_v2.hpp"
#include "linoh/protocol/loss_recovery.hpp"  // RttEstimator, kInitialCwndBytes

#include <atomic>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <thread>
#include <vector>

using namespace linoh::protocol;

namespace {

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

// =============================================================================
// PacingLimiter 测试
// =============================================================================

// 1. 默认状态 enabled=false
void test_default_disabled() {
    PacingLimiter pl;
    assert(!pl.enabled());
    assert(pl.tokens_available() == 0);
    assert(pl.bucket_capacity() == 0);
    assert(pl.pacing_rate_bps() == 0);
}

// 2. configure(0, rtt) 后 enabled=false（速率 0 禁用）
void test_configure_zero_rate_disabled() {
    PacingLimiter pl;
    pl.configure(0, 10.0);
    assert(!pl.enabled());
    assert(pl.bucket_capacity() == 0);
}

// 3. configure(rate, rtt) 后 enabled=true
void test_configure_enables() {
    PacingLimiter pl;
    pl.configure(1000000, 10.0);  // 1MB/s, 10ms
    assert(pl.enabled());
    assert(pl.pacing_rate_bps() == 1000000);
}

// 4. 桶容量 = 2 * pacing_rate * rtt
void test_bucket_capacity_formula() {
    PacingLimiter pl;
    // rate=1MB/s, rtt=10ms → 2 * 1000000 * 0.01 = 20000
    pl.configure(1000000, 10.0);
    assert(pl.bucket_capacity() == 20000);

    // rate=1MB/s, rtt=1000ms → 2 * 1000000 * 1.0 = 2000000
    pl.configure(1000000, 1000.0);
    assert(pl.bucket_capacity() == 2000000);

    // rate=500KB/s, rtt=20ms → 2 * 500000 * 0.02 = 20000
    pl.configure(500000, 20.0);
    assert(pl.bucket_capacity() == 20000);
}

// 5. try_consume 首包放行（初始令牌 = 桶容量）
void test_first_consume_allowed() {
    PacingLimiter pl;
    pl.configure(1000000, 1000.0);  // 桶容量 = 2000000
    assert(pl.try_consume(2000000, 100.0));  // 全桶消耗
    assert(pl.tokens_available() == 0);
}

// 6. 令牌耗尽后拒绝
void test_consume_exhausted_rejected() {
    PacingLimiter pl;
    pl.configure(1000000, 1000.0);  // 桶容量 = 2000000
    assert(pl.try_consume(2000000, 100.0));   // 耗尽
    assert(!pl.try_consume(1, 100.0));        // 同一时刻无补充，拒绝
    assert(!pl.try_consume(1000, 100.0));     // 仍拒绝
}

// 7. 时间推进后令牌补充再放行
void test_refill_after_time_advance() {
    PacingLimiter pl;
    pl.configure(1000000, 1000.0);  // rate=1MB/s, 桶容量=2000000
    assert(pl.try_consume(2000000, 100.0));  // 耗尽，last_refill=100
    assert(!pl.try_consume(1, 100.0));       // 无补充

    // 推进 1 秒 → 补充 1MB/s * 1s = 1000000 令牌
    assert(pl.try_consume(1000000, 1100.0));  // 消耗 1000000，剩 0
    assert(!pl.try_consume(1, 1100.0));       // 再次耗尽

    // 推进 0.5 秒 → 补充 500000 令牌
    assert(pl.try_consume(500000, 1600.0));   // 消耗 500000，剩 0
    assert(pl.tokens_available() == 0);
}

// 8. pacing_rate=0 时 try_consume 始终放行
void test_zero_rate_passthrough() {
    PacingLimiter pl;
    // 未 configure，pacing_rate=0
    assert(pl.try_consume(999999, 100.0));
    assert(pl.try_consume(999999, 100.0));

    // configure(0, rtt) 后仍放行
    pl.configure(0, 10.0);
    assert(!pl.enabled());
    assert(pl.try_consume(999999, 100.0));
}

// 9. reset 后 enabled=false
void test_reset_disables() {
    PacingLimiter pl;
    pl.configure(1000000, 10.0);
    assert(pl.enabled());
    pl.reset();
    assert(!pl.enabled());
    assert(pl.tokens_available() == 0);
    assert(pl.bucket_capacity() == 0);
    assert(pl.pacing_rate_bps() == 0);
}

// 10. 桶容量上限 64MB（防溢出）
void test_bucket_capacity_cap() {
    PacingLimiter pl;
    // rate=100MB/s, rtt=100s → 2*100000000*100 = 20GB → 截断 64MB
    pl.configure(100000000, 100000.0);
    assert(pl.bucket_capacity() == 67108864);  // 64 * 1024 * 1024

    // 初始令牌也被截断到 64MB
    assert(pl.tokens_available() == 67108864);
}

// 11. configure 多次调用更新桶容量
void test_reconfigure_updates() {
    PacingLimiter pl;
    pl.configure(1000000, 10.0);       // 桶=20000
    assert(pl.bucket_capacity() == 20000);

    pl.configure(2000000, 20.0);       // 桶=2*2000000*0.02=80000
    assert(pl.bucket_capacity() == 80000);
    assert(pl.pacing_rate_bps() == 2000000);

    // 重新 configure 后令牌不超过新桶容量
    pl.configure(1000, 1.0);           // 桶=2*1000*0.001=2
    assert(pl.bucket_capacity() == 2);
    assert(pl.tokens_available() <= 2);
}

// 12. 并发 try_consume 安全（多线程令牌守恒）
void test_concurrent_try_consume() {
    PacingLimiter pl;
    // 桶容量 = 2 * 1000000 * 1.0 = 2000000
    pl.configure(1000000, 1000.0);
    const std::uint64_t bucket = pl.bucket_capacity();
    assert(bucket == 2000000);

    constexpr int kThreads = 8;
    constexpr int kIters = 100;
    const std::uint64_t per_consume = 1000;
    // 总请求 = 8 * 100 * 1000 = 800000 < 桶容量 2000000，固定时间无补充
    std::atomic<int> successes{0};

    auto worker = [&]() {
        for (int i = 0; i < kIters; ++i) {
            if (pl.try_consume(per_consume, 500.0)) {  // 固定 now，无时间推进补充
                ++successes;
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) threads.emplace_back(worker);
    for (auto &th : threads) th.join();

    // 所有请求都应成功（总消耗 800000 < 桶容量 2000000）
    assert(successes.load() == kThreads * kIters);
    // 令牌守恒：剩余 = 2000000 - 800000 = 1200000
    assert(pl.tokens_available() == 1200000);
}

// 13. 诊断访问器
void test_diagnostic_accessors() {
    PacingLimiter pl;
    pl.configure(2000000, 50.0);  // 桶=2*2000000*0.05=200000
    assert(pl.pacing_rate_bps() == 2000000);
    assert(pl.bucket_capacity() == 200000);
    assert(pl.tokens_available() == 200000);  // 初始满桶

    pl.try_consume(50000, 100.0);
    assert(pl.tokens_available() == 150000);
}

// =============================================================================
// BBR v2 pacing 集成测试
// =============================================================================

// 14. BBR 初始 pacing_limiter disabled
void test_bbr_initial_pacing_disabled() {
    BbrV2Controller bbr;
    assert(!bbr.pacing_limiter().enabled());
    assert(bbr.pacing_rate_bps() == 0);
}

// 15. on_ack 后 pacing_limiter enabled
void test_bbr_on_ack_enables_pacing() {
    RttEstimator rtt;
    rtt.update(10.0, 0.0);  // SRTT=10ms

    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);
    bbr.on_ack(100000, 1);  // delivery_rate = 100000/0.01 = 10MB/s

    assert(bbr.pacing_rate_bps() > 0);
    assert(bbr.pacing_limiter().enabled());
}

// 16. pacing_rate_bps 传播到 pacing_limiter
void test_bbr_pacing_rate_propagated() {
    RttEstimator rtt;
    rtt.update(10.0, 0.0);

    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);
    bbr.on_ack(100000, 1);

    // BBR pacing_rate_bps == pacing_limiter 内部速率
    assert(bbr.pacing_limiter().pacing_rate_bps() == bbr.pacing_rate_bps());
    assert(bbr.pacing_limiter().pacing_rate_bps() > 0);
}

// 17. can_send 受 pacing 限速（令牌耗尽后 false，cwnd 仍够）
void test_bbr_can_send_pacing_limit() {
    RttEstimator rtt;
    rtt.update(10.0, 0.0);  // SRTT=10ms

    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);
    // 极小 ACK：delivery_rate = 100/0.01 = 10000 bytes/s
    // pacing_rate = 10000 * 2.77(Startup gain) = 27700 bytes/s
    // 桶容量 = 2 * 27700 * 0.01 = 554 bytes
    // cwnd = max(14600, BDP*2.77) = max(14600, 100*2.77) = 14600（BDP 太小，cwnd 保持初始）
    bbr.on_ack(100, 1);

    const std::uint64_t bucket = bbr.pacing_limiter().bucket_capacity();
    assert(bucket == 554);  // 2 * 27700 * 0.01

    // 首次 can_send(bucket) 通过（桶满），cwnd=14600 远够
    assert(bbr.can_send(bucket));
    // 耗尽后剩余令牌极少（微秒级补充可忽略，远小于 1000）
    assert(bbr.pacing_limiter().tokens_available() < 1000);
    // can_send(1000) 应被 pacing 拒绝：桶空 + 微秒级补充远不足 1000
    // （pacing_rate=27700 bytes/s，补充 1000 字节需 36ms，两次 can_send 间隔不可能那么长）
    // cwnd 仍够（1000 < 14600），所以 false 只能是 pacing 拒绝（验证限速生效）
    assert(!bbr.can_send(1000));
}

// 18. reset 后 pacing_limiter disabled
void test_bbr_reset_disables_pacing() {
    RttEstimator rtt;
    rtt.update(10.0, 0.0);

    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);
    bbr.on_ack(100000, 1);
    assert(bbr.pacing_limiter().enabled());

    bbr.reset();
    assert(!bbr.pacing_limiter().enabled());
    assert(bbr.pacing_rate_bps() == 0);
}

} // namespace

int main() {
    std::cout << "=== v3.9.0 transport config + BBR pacing tests ===\n";

    // PacingLimiter
    RUN_TEST(test_default_disabled);
    RUN_TEST(test_configure_zero_rate_disabled);
    RUN_TEST(test_configure_enables);
    RUN_TEST(test_bucket_capacity_formula);
    RUN_TEST(test_first_consume_allowed);
    RUN_TEST(test_consume_exhausted_rejected);
    RUN_TEST(test_refill_after_time_advance);
    RUN_TEST(test_zero_rate_passthrough);
    RUN_TEST(test_reset_disables);
    RUN_TEST(test_bucket_capacity_cap);
    RUN_TEST(test_reconfigure_updates);
    RUN_TEST(test_concurrent_try_consume);
    RUN_TEST(test_diagnostic_accessors);

    // BBR pacing 集成
    RUN_TEST(test_bbr_initial_pacing_disabled);
    RUN_TEST(test_bbr_on_ack_enables_pacing);
    RUN_TEST(test_bbr_pacing_rate_propagated);
    RUN_TEST(test_bbr_can_send_pacing_limit);
    RUN_TEST(test_bbr_reset_disables_pacing);

    std::cout << "\n=== " << test_passed << "/" << test_count << " tests passed ===\n";
    return (test_passed == test_count) ? 0 : 1;
}
