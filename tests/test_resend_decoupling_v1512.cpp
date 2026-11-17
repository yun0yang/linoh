// test_resend_decoupling_v1512.cpp — v1.5.0.12 resend 节拍解耦测试
//
// 验证 v1.5.0.11 ISSUE T11 反馈（LINOH_V1511_T11_FEEDBACK.md）：
//   v1.5.0.11 build_oos_pn_data 每 50ms 重置 send_time_ms，导致
//   resend_oos_pn_if_needed 中 now - send_time_ms < 100ms 永远成立，
//   resend 永不触发，high_priority 队列始终为空。
//
// v1.5.0.12 修复方案（ISSUE T11 P0 决策）：
//   1. resend 触发条件改为基于 last_resend_check_ms_ 节拍时间追踪
//   2. 与 build_oos_pn_data 的 send_time_ms 重置完全解耦
//   3. 新增 3 个可观测性计数器：call_total / skipped_rhythm_total / triggered_total
//
// 测试矩阵（6 用例）：
//   1. kOosPnResendTimeoutMs = 100.0 编译期验证（继承 v1.5.0.11）
//   2. last_resend_check_ms_ 初值 0.0（确保首次调用必触发）
//   3. 3 个节拍计数器初值 0
//   4. 默认 Connection 上 resend 返回 0（空队列，但节拍满足）
//   5. 节拍矩阵验证：skipped_rhythm + triggered <= call_total
//   6. 测试访问器签名编译期验证
//
// 测试基线：v1.5.0.11 (commit ffbe036, tag v1.5.0.11)
// 目标版本：v1.5.0.12 (ISSUE T11 节拍解耦)

#include "linoh/base/key.hpp"
#include "linoh/endpoint/connection.hpp"
#include "linoh/endpoint/state_machine.hpp"
#include "linoh/protocol/loss_recovery.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/util/bytes.hpp"
#include "linoh/util/logging.hpp"

#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <span>
#include <string>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::endpoint;
using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (%lld != %lld) (line %d)\n", \
        #a, #b, (long long)_a, (long long)_b, __LINE__); } \
} while (0)

#define CHECK_GE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a >= _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s >= %s (%lld < %lld) (line %d)\n", \
        #a, #b, (long long)_a, (long long)_b, __LINE__); } \
} while (0)

#define NEAR(a, b, eps) (std::fabs((double)(a) - (double)(b)) < (eps))

// ============================================================================
// TEST 1: kOosPnResendTimeoutMs = 100.0 编译期验证（继承 v1.5.0.11）
//   v1.5.0.12 未改变此参数，保持 100ms 超时
// ============================================================================
static void test_v1512_resend_timeout_compile_time() {
    std::printf("[test] v1.5.0.12 kOosPnResendTimeoutMs = 100.0 (inherited)...\n");

    constexpr double expected = 100.0;
    constexpr double actual = Connection::kOosPnResendTimeoutMs;
    CHECK(NEAR(actual, expected, 1e-6));

    std::printf("    kOosPnResendTimeoutMs verified (100.0 ms)\n");
}

// ============================================================================
// TEST 2: last_resend_check_ms_ 初值 0.0
//   v1.5.0.12 核心修复：初值 0 确保首次调用 resend 时 now - 0 = now > 100ms
//   必触发，无初值陷阱（对比 v1.5.0.11 send_time_ms 被 build 重置的耦合问题）
// ============================================================================
static void test_v1512_last_resend_check_initial_zero() {
    std::printf("[test] v1.5.0.12 last_resend_check_ms_ initial = 0.0...\n");

    auto conn = std::make_shared<Connection>(Connection::Config{});

    // v1.5.0.12: last_resend_check_ms_ 初值 0.0，首次调用必触发节拍检查
    double initial = conn->last_resend_check_ms_for_test();
    CHECK(NEAR(initial, 0.0, 1e-6));

    std::printf("    last_resend_check_ms_ initial = 0.0 verified (no cold-start trap)\n");
}

// ============================================================================
// TEST 3: 3 个节拍计数器初值 0
//   v1.5.0.12 P2 可观测性：call_total / skipped_rhythm_total / triggered_total
// ============================================================================
static void test_v1512_rhythm_counters_initial_zero() {
    std::printf("[test] v1.5.0.12 rhythm counters initial = 0...\n");

    auto conn = std::make_shared<Connection>(Connection::Config{});

    CHECK_EQ(conn->resend_oos_pn_call_total_for_test(), 0ull);
    CHECK_EQ(conn->resend_oos_pn_skipped_rhythm_total_for_test(), 0ull);
    CHECK_EQ(conn->resend_oos_pn_triggered_total_for_test(), 0ull);

    std::printf("    rhythm counters (call/skipped/triggered) all = 0 verified\n");
}

// ============================================================================
// TEST 4: 默认 Connection 上 resend 返回 0（空队列）
//   v1.5.0.12: 即使节拍满足（首次调用 last_resend_check_ms_=0 → now > 100ms），
//   空 pending 队列仍返回 0，但 call_total 应 +1
// ============================================================================
static void test_v1512_resend_empty_queue_increments_call_total() {
    std::printf("[test] v1.5.0.12 resend on empty queue increments call_total...\n");

    auto conn = std::make_shared<Connection>(Connection::Config{});

    // 首次调用：节拍满足（now - 0 > 100ms），但空队列返回 0
    auto result = conn->resend_oos_pn_if_needed();
    CHECK_EQ(result, 0ull);

    // call_total 应 +1（无论是否有超时条目）
    CHECK_EQ(conn->resend_oos_pn_call_total_for_test(), 1ull);

    // triggered_total 应保持 0（无超时条目可触发）
    CHECK_EQ(conn->resend_oos_pn_triggered_total_for_test(), 0ull);

    // skipped_rhythm_total 应保持 0（节拍满足，未跳过）
    CHECK_EQ(conn->resend_oos_pn_skipped_rhythm_total_for_test(), 0ull);

    // last_resend_check_ms_ 应更新为 now（非 0）
    double updated = conn->last_resend_check_ms_for_test();
    CHECK(updated > 0.0);

    std::printf("    call_total=1, triggered=0, skipped_rhythm=0, last_check updated verified\n");
}

// ============================================================================
// TEST 5: 节拍矩阵验证 — 连续调用 resend 验证节拍跳过
//   v1.5.0.12: 首次调用节拍满足（triggered 或 empty），第二次调用节拍未到跳过
//   矩阵：skipped_rhythm + triggered <= call_total
// ============================================================================
static void test_v1512_rhythm_matrix_skip_on_second_call() {
    std::printf("[test] v1.5.0.12 rhythm matrix: second call skipped (100ms not elapsed)...\n");

    auto conn = std::make_shared<Connection>(Connection::Config{});

    // 第一次调用：节拍满足（last_resend_check_ms_=0 → now > 100ms）
    conn->resend_oos_pn_if_needed();
    CHECK_EQ(conn->resend_oos_pn_call_total_for_test(), 1ull);
    CHECK_EQ(conn->resend_oos_pn_skipped_rhythm_total_for_test(), 0ull);

    // 第二次调用：节拍未到（now - last_resend_check_ms_ < 100ms）
    conn->resend_oos_pn_if_needed();
    CHECK_EQ(conn->resend_oos_pn_call_total_for_test(), 2ull);
    CHECK_EQ(conn->resend_oos_pn_skipped_rhythm_total_for_test(), 1ull);

    // 矩阵验证：skipped_rhythm + triggered <= call_total
    auto call_total = conn->resend_oos_pn_call_total_for_test();
    auto skipped = conn->resend_oos_pn_skipped_rhythm_total_for_test();
    auto triggered = conn->resend_oos_pn_triggered_total_for_test();
    CHECK_GE(call_total, skipped + triggered);

    std::printf("    rhythm matrix verified: call=%llu skipped=%llu triggered=%llu\n",
                (unsigned long long)call_total, (unsigned long long)skipped,
                (unsigned long long)triggered);
}

// ============================================================================
// TEST 6: 测试访问器签名编译期验证
//   v1.5.0.12: 4 个新增访问器签名正确声明为 public
// ============================================================================
static void test_v1512_test_accessor_signatures() {
    std::printf("[test] v1.5.0.12 P2 test accessor signatures...\n");

    // 编译期验证：访问器方法签名正确
    using AccCallTotal = std::uint64_t (Connection::*)() const;
    AccCallTotal acc_call = &Connection::resend_oos_pn_call_total_for_test;
    CHECK(acc_call != nullptr);

    using AccSkipped = std::uint64_t (Connection::*)() const;
    AccSkipped acc_skipped = &Connection::resend_oos_pn_skipped_rhythm_total_for_test;
    CHECK(acc_skipped != nullptr);

    using AccTriggered = std::uint64_t (Connection::*)() const;
    AccTriggered acc_triggered = &Connection::resend_oos_pn_triggered_total_for_test;
    CHECK(acc_triggered != nullptr);

    using AccLastCheck = double (Connection::*)() const;
    AccLastCheck acc_last = &Connection::last_resend_check_ms_for_test;
    CHECK(acc_last != nullptr);

    std::printf("    P2 accessor signatures verified (compile-time)\n");
}

int main() {
    std::printf("=== test_resend_decoupling_v1512 ===\n");
    std::printf("v1.5.0.12 resend-build decoupling: last_resend_check_ms_ rhythm tracking (ISSUE T11)\n\n");

    test_v1512_resend_timeout_compile_time();
    test_v1512_last_resend_check_initial_zero();
    test_v1512_rhythm_counters_initial_zero();
    test_v1512_resend_empty_queue_increments_call_total();
    test_v1512_rhythm_matrix_skip_on_second_call();
    test_v1512_test_accessor_signatures();

    std::printf("\n=== Result: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
