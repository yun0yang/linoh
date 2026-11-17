// test_path_abandon.cpp — P4-A-4 路径放弃策略精细化测试
//
// 验收标准（来自 P4 阶段优化方案文档）：
//   1. 新路径 RTT 比老路径差 30%（在阈值内）：放弃老路径（切换到新路径）
//   2. 新路径 RTT 比老路径差 60%（超出阈值）：保留老路径
//   3. abandon_path 只影响当前 manager（iroh PR #4284 修复点）
//   4. 现有 test_phase4_integration.cpp 回归通过
//
// 借鉴 iroh PR #4296（Correctly abandon paths when new are opened with worse RTT）
//      iroh PR #4284（Do not close abandoned paths on all connections）

#include "linoh/protocol/path_migration.hpp"
#include "linoh/base/endpoint_addr.hpp"
#include "linoh/net/path.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <memory>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 测试 1: AbandonPolicy 默认值
// ============================================================================
static void test_default_policy() {
    std::printf("[test] AbandonPolicy default values...\n");

    PathMigrationManager mgr;
    const auto &policy = mgr.abandon_policy();
    CHECK(policy.rtt_worse_threshold == 1.5);
    CHECK(policy.idle_timeout.count() == 30);
}

// ============================================================================
// 测试 2: set_abandon_policy 自定义策略
// ============================================================================
static void test_set_custom_policy() {
    std::printf("[test] Set custom AbandonPolicy...\n");

    PathMigrationManager mgr;
    PathMigrationManager::AbandonPolicy custom;
    custom.rtt_worse_threshold = 2.0;
    custom.idle_timeout = std::chrono::seconds(60);
    mgr.set_abandon_policy(custom);

    const auto &policy = mgr.abandon_policy();
    CHECK(policy.rtt_worse_threshold == 2.0);
    CHECK(policy.idle_timeout.count() == 60);
}

// ============================================================================
// 测试 3: should_abandon_old_path - 新路径 RTT 差 30%（在阈值内）→ 放弃老路径
// ============================================================================
static void test_abandon_old_path_rtt_within_threshold() {
    std::printf("[test] should_abandon_old_path: new RTT 30%% worse (within threshold)...\n");

    PathMigrationManager mgr;
    // 默认 threshold=1.5
    PathMigrationManager::PathQuality old_q;
    old_q.srtt = std::chrono::microseconds(10000);  // 10ms

    PathMigrationManager::PathQuality new_q;
    new_q.srtt = std::chrono::microseconds(13000);  // 13ms，比老路径差 30%

    // 13000 <= 10000 * 1.5 = 15000，应放弃老路径
    CHECK(mgr.should_abandon_old_path(old_q, new_q) == true);
}

// ============================================================================
// 测试 4: should_abandon_old_path - 新路径 RTT 差 60%（超出阈值）→ 保留老路径
// ============================================================================
static void test_abandon_old_path_rtt_exceeds_threshold() {
    std::printf("[test] should_abandon_old_path: new RTT 60%% worse (exceeds threshold)...\n");

    PathMigrationManager mgr;
    // 默认 threshold=1.5
    PathMigrationManager::PathQuality old_q;
    old_q.srtt = std::chrono::microseconds(10000);  // 10ms

    PathMigrationManager::PathQuality new_q;
    new_q.srtt = std::chrono::microseconds(16000);  // 16ms，比老路径差 60%

    // 16000 > 10000 * 1.5 = 15000，应保留老路径
    CHECK(mgr.should_abandon_old_path(old_q, new_q) == false);
}

// ============================================================================
// 测试 5: should_abandon_old_path - 新路径 RTT 相同 → 放弃老路径
// ============================================================================
static void test_abandon_old_path_same_rtt() {
    std::printf("[test] should_abandon_old_path: same RTT...\n");

    PathMigrationManager mgr;
    PathMigrationManager::PathQuality old_q;
    old_q.srtt = std::chrono::microseconds(10000);

    PathMigrationManager::PathQuality new_q;
    new_q.srtt = std::chrono::microseconds(10000);

    // 10000 <= 10000 * 1.5 = 15000，应放弃老路径
    CHECK(mgr.should_abandon_old_path(old_q, new_q) == true);
}

// ============================================================================
// 测试 6: should_abandon_old_path - 新路径 RTT 更好 → 放弃老路径
// ============================================================================
static void test_abandon_old_path_better_rtt() {
    std::printf("[test] should_abandon_old_path: new RTT better...\n");

    PathMigrationManager mgr;
    PathMigrationManager::PathQuality old_q;
    old_q.srtt = std::chrono::microseconds(10000);

    PathMigrationManager::PathQuality new_q;
    new_q.srtt = std::chrono::microseconds(8000);  // 比 old 好 20%

    CHECK(mgr.should_abandon_old_path(old_q, new_q) == true);
}

// ============================================================================
// 测试 7: should_abandon_old_path - srtt 为 0 时保守返回 false
// ============================================================================
static void test_abandon_old_path_zero_srtt() {
    std::printf("[test] should_abandon_old_path: zero srtt conservative false...\n");

    PathMigrationManager mgr;
    PathMigrationManager::PathQuality old_q;
    old_q.srtt = std::chrono::microseconds(0);  // 未测量

    PathMigrationManager::PathQuality new_q;
    new_q.srtt = std::chrono::microseconds(10000);

    CHECK(mgr.should_abandon_old_path(old_q, new_q) == false);

    // 反过来
    old_q.srtt = std::chrono::microseconds(10000);
    new_q.srtt = std::chrono::microseconds(0);
    CHECK(mgr.should_abandon_old_path(old_q, new_q) == false);
}

// ============================================================================
// 测试 8: should_abandon_old_path - 自定义 threshold
// ============================================================================
static void test_abandon_old_path_custom_threshold() {
    std::printf("[test] should_abandon_old_path: custom threshold...\n");

    PathMigrationManager mgr;
    PathMigrationManager::AbandonPolicy policy;
    policy.rtt_worse_threshold = 2.0;  // 允许新路径差 100%
    mgr.set_abandon_policy(policy);

    PathMigrationManager::PathQuality old_q;
    old_q.srtt = std::chrono::microseconds(10000);

    PathMigrationManager::PathQuality new_q;
    new_q.srtt = std::chrono::microseconds(16000);  // 差 60%

    // 16000 <= 10000 * 2.0 = 20000，应放弃老路径
    CHECK(mgr.should_abandon_old_path(old_q, new_q) == true);

    // 差 110%，超过自定义阈值
    new_q.srtt = std::chrono::microseconds(21000);
    CHECK(mgr.should_abandon_old_path(old_q, new_q) == false);
}

// ============================================================================
// 测试 9: update_path_quality 新建路径条目
// ============================================================================
static void test_update_path_quality_create() {
    std::printf("[test] update_path_quality creates new entry...\n");

    PathMigrationManager mgr;
    auto now = std::chrono::steady_clock::now();

    mgr.update_path_quality(1, std::chrono::microseconds(5000), 0, now);

    auto q = mgr.path_quality(1);
    CHECK(q.has_value());
    CHECK(q->path_id == 1);
    CHECK(q->srtt.count() == 5000);
    CHECK(q->loss_count == 0);
    CHECK(q->has_tuple == false);
}

// ============================================================================
// 测试 10: update_path_quality 多次更新覆盖
// ============================================================================
static void test_update_path_quality_overwrite() {
    std::printf("[test] update_path_quality overwrites...\n");

    PathMigrationManager mgr;
    auto t1 = std::chrono::steady_clock::now();
    mgr.update_path_quality(1, std::chrono::microseconds(5000), 0, t1);

    auto t2 = t1 + std::chrono::milliseconds(100);
    mgr.update_path_quality(1, std::chrono::microseconds(8000), 2, t2);

    auto q = mgr.path_quality(1);
    CHECK(q.has_value());
    CHECK(q->srtt.count() == 8000);
    CHECK(q->loss_count == 2);
    CHECK(q->last_seen == t2);
}

// ============================================================================
// 测试 11: update_path_quality 带 FourTuple 重载
// ============================================================================
static void test_update_path_quality_with_tuple() {
    std::printf("[test] update_path_quality with FourTuple...\n");

    PathMigrationManager mgr;
    auto now = std::chrono::steady_clock::now();

    base::TransportAddr local_addr;
    local_addr.kind = base::TransportKind::Ip;
    local_addr.host = "127.0.0.1";
    local_addr.port = 8000;

    base::TransportAddr remote_addr;
    remote_addr.kind = base::TransportKind::Ip;
    remote_addr.host = "127.0.0.1";
    remote_addr.port = 9000;

    net::FourTuple tuple{local_addr, remote_addr};

    mgr.update_path_quality(1, std::chrono::microseconds(5000), 0, now, tuple);

    auto q = mgr.path_quality(1);
    CHECK(q.has_value());
    CHECK(q->has_tuple == true);
    CHECK(q->four_tuple.to_string() == tuple.to_string());
}

// ============================================================================
// 测试 12: path_quality 查询不存在的路径返回 nullopt
// ============================================================================
static void test_path_quality_nonexistent() {
    std::printf("[test] path_quality nonexistent returns nullopt...\n");

    PathMigrationManager mgr;
    auto q = mgr.path_quality(999);
    CHECK(!q.has_value());
}

// ============================================================================
// 测试 13: abandon_path 移除指定路径
// ============================================================================
static void test_abandon_path_removes() {
    std::printf("[test] abandon_path removes specified path...\n");

    PathMigrationManager mgr;
    auto now = std::chrono::steady_clock::now();
    mgr.update_path_quality(1, std::chrono::microseconds(5000), 0, now);
    mgr.update_path_quality(2, std::chrono::microseconds(6000), 1, now);

    CHECK(mgr.active_path_count() == 2);

    mgr.abandon_path(1);
    CHECK(mgr.active_path_count() == 1);
    CHECK(!mgr.path_quality(1).has_value());
    CHECK(mgr.path_quality(2).has_value());  // 路径 2 保留
}

// ============================================================================
// 测试 14: abandon_path 幂等
// ============================================================================
static void test_abandon_path_idempotent() {
    std::printf("[test] abandon_path idempotent...\n");

    PathMigrationManager mgr;
    auto now = std::chrono::steady_clock::now();
    mgr.update_path_quality(1, std::chrono::microseconds(5000), 0, now);

    mgr.abandon_path(1);
    mgr.abandon_path(1);  // 再次调用不应崩溃
    mgr.abandon_path(1);

    CHECK(mgr.active_path_count() == 0);
}

// ============================================================================
// 测试 15: abandon_path 不存在的路径（静默返回）
// ============================================================================
static void test_abandon_path_nonexistent() {
    std::printf("[test] abandon_path nonexistent path silent...\n");

    PathMigrationManager mgr;
    mgr.abandon_path(999);  // 不存在，静默返回
    CHECK(mgr.active_path_count() == 0);
}

// ============================================================================
// 测试 16: P4-A-4 PR #4284 - abandon_path 只影响当前 manager
// ============================================================================
static void test_abandon_path_isolation() {
    std::printf("[test] abandon_path isolation (iroh PR #4284)...\n");

    // 两个独立的 manager（模拟两个 Connection）
    PathMigrationManager mgr_a;
    PathMigrationManager mgr_b;

    auto now = std::chrono::steady_clock::now();
    mgr_a.update_path_quality(1, std::chrono::microseconds(5000), 0, now);
    mgr_b.update_path_quality(1, std::chrono::microseconds(5000), 0, now);

    CHECK(mgr_a.active_path_count() == 1);
    CHECK(mgr_b.active_path_count() == 1);

    // 在 mgr_a 放弃路径 1，不应影响 mgr_b
    mgr_a.abandon_path(1);

    CHECK(mgr_a.active_path_count() == 0);
    CHECK(mgr_b.active_path_count() == 1);  // mgr_b 的路径 1 仍存在
    CHECK(!mgr_a.path_quality(1).has_value());
    CHECK(mgr_b.path_quality(1).has_value());
}

// ============================================================================
// 测试 17: abandon_idle_paths 放弃超时路径
// ============================================================================
static void test_abandon_idle_paths_timeout() {
    std::printf("[test] abandon_idle_paths abandons timed-out paths...\n");

    PathMigrationManager mgr;
    // 默认 idle_timeout=30s

    auto t_old = std::chrono::steady_clock::now() - std::chrono::seconds(60);
    auto t_recent = std::chrono::steady_clock::now();

    mgr.update_path_quality(1, std::chrono::microseconds(5000), 0, t_old);  // 60s 前
    mgr.update_path_quality(2, std::chrono::microseconds(6000), 0, t_recent);  // 刚刚

    auto now = std::chrono::steady_clock::now();
    auto abandoned = mgr.abandon_idle_paths(now);

    CHECK(abandoned.size() == 1);
    CHECK(abandoned[0] == 1);
    CHECK(mgr.active_path_count() == 1);
    CHECK(mgr.path_quality(2).has_value());
}

// ============================================================================
// 测试 18: abandon_idle_paths 未超时路径保留
// ============================================================================
static void test_abandon_idle_paths_keep_recent() {
    std::printf("[test] abandon_idle_paths keeps recent paths...\n");

    PathMigrationManager mgr;
    auto now = std::chrono::steady_clock::now();

    mgr.update_path_quality(1, std::chrono::microseconds(5000), 0, now);
    mgr.update_path_quality(2, std::chrono::microseconds(6000), 0, now);

    auto abandoned = mgr.abandon_idle_paths(now);
    CHECK(abandoned.empty());
    CHECK(mgr.active_path_count() == 2);
}

// ============================================================================
// 测试 19: abandon_idle_paths 自定义 idle_timeout
// ============================================================================
static void test_abandon_idle_paths_custom_timeout() {
    std::printf("[test] abandon_idle_paths with custom idle_timeout...\n");

    PathMigrationManager mgr;
    PathMigrationManager::AbandonPolicy policy;
    policy.idle_timeout = std::chrono::seconds(10);
    mgr.set_abandon_policy(policy);

    auto t_old = std::chrono::steady_clock::now() - std::chrono::seconds(15);
    auto now = std::chrono::steady_clock::now();

    mgr.update_path_quality(1, std::chrono::microseconds(5000), 0, t_old);

    auto abandoned = mgr.abandon_idle_paths(now);
    CHECK(abandoned.size() == 1);
    CHECK(abandoned[0] == 1);
}

// ============================================================================
// 测试 20: is_path_abandoned
// ============================================================================
static void test_is_path_abandoned() {
    std::printf("[test] is_path_abandoned...\n");

    PathMigrationManager mgr;
    auto now = std::chrono::steady_clock::now();
    mgr.update_path_quality(1, std::chrono::microseconds(5000), 0, now);

    CHECK(mgr.is_path_abandoned(1) == false);  // 存在，未放弃
    CHECK(mgr.is_path_abandoned(2) == true);   // 不存在，视为已放弃

    mgr.abandon_path(1);
    CHECK(mgr.is_path_abandoned(1) == true);   // 放弃后视为已放弃
}

// ============================================================================
// 测试 21: active_path_count 初始为 0
// ============================================================================
static void test_active_path_count_initial() {
    std::printf("[test] active_path_count initial zero...\n");

    PathMigrationManager mgr;
    CHECK(mgr.active_path_count() == 0);
}

// ============================================================================
// 测试 22: 综合场景 - 多路径质量监控与放弃
// ============================================================================
static void test_comprehensive_multi_path() {
    std::printf("[test] Comprehensive multi-path monitoring...\n");

    PathMigrationManager mgr;
    auto now = std::chrono::steady_clock::now();

    // 添加 3 条路径
    mgr.update_path_quality(1, std::chrono::microseconds(10000), 0, now);
    mgr.update_path_quality(2, std::chrono::microseconds(15000), 1, now);
    mgr.update_path_quality(3, std::chrono::microseconds(20000), 2, now);

    CHECK(mgr.active_path_count() == 3);

    // 评估：新路径 2 vs 老路径 1
    auto q1 = mgr.path_quality(1);
    auto q2 = mgr.path_quality(2);
    CHECK(q1.has_value());
    CHECK(q2.has_value());
    // 15000 <= 10000 * 1.5 = 15000，应放弃老路径 1
    CHECK(mgr.should_abandon_old_path(*q1, *q2) == true);

    // 评估：新路径 3 vs 老路径 1
    auto q3 = mgr.path_quality(3);
    // 20000 > 10000 * 1.5 = 15000，应保留老路径 1
    CHECK(mgr.should_abandon_old_path(*q1, *q3) == false);

    // 放弃路径 1（模拟切换到路径 2）
    mgr.abandon_path(1);
    CHECK(mgr.active_path_count() == 2);
    CHECK(!mgr.path_quality(1).has_value());
}

// ============================================================================
// 测试 23: 旧 API 兼容 - generate_challenge/validate_response 仍工作
// ============================================================================
static void test_legacy_api_compat() {
    std::printf("[test] Legacy API compatibility (generate_challenge etc)...\n");

    PathMigrationManager mgr;

    // 旧的 challenge API 仍正常工作
    auto challenge = mgr.generate_challenge();
    double now_ms = 1000.0;
    mgr.record_challenge_sent(challenge, now_ms);

    PathResponseFrame response;
    response.data = challenge.data;
    int idx = mgr.validate_response(response);
    CHECK(idx == 0);

    mgr.mark_path_validated(0);

    // P4-A-4 新 API 不影响旧 API
    CHECK(mgr.active_path_count() == 0);
    CHECK(mgr.active_cid_count() == 0);
}

// ============================================================================
// 测试 24: 并发安全 - 多线程 update_path_quality
// ============================================================================
static void test_concurrent_update() {
    std::printf("[test] Concurrent update_path_quality...\n");

    PathMigrationManager mgr;
    auto now = std::chrono::steady_clock::now();

    // 4 个线程并发更新不同路径
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&mgr, t, now]() {
            for (int i = 0; i < 50; ++i) {
                std::uint64_t path_id = static_cast<std::uint64_t>(t * 100 + i);
                mgr.update_path_quality(path_id,
                                         std::chrono::microseconds(5000 + i * 100),
                                         static_cast<std::uint32_t>(i),
                                         now);
            }
        });
    }
    for (auto &th : threads) th.join();

    // 应有 200 条路径
    CHECK(mgr.active_path_count() == 200);

    // 放弃部分路径
    mgr.abandon_path(0);
    mgr.abandon_path(100);
    mgr.abandon_path(200);
    mgr.abandon_path(300);

    CHECK(mgr.active_path_count() == 196);
}

int main() {
    std::printf("=== test_path_abandon ===\n");

    test_default_policy();
    test_set_custom_policy();
    test_abandon_old_path_rtt_within_threshold();
    test_abandon_old_path_rtt_exceeds_threshold();
    test_abandon_old_path_same_rtt();
    test_abandon_old_path_better_rtt();
    test_abandon_old_path_zero_srtt();
    test_abandon_old_path_custom_threshold();
    test_update_path_quality_create();
    test_update_path_quality_overwrite();
    test_update_path_quality_with_tuple();
    test_path_quality_nonexistent();
    test_abandon_path_removes();
    test_abandon_path_idempotent();
    test_abandon_path_nonexistent();
    test_abandon_path_isolation();
    test_abandon_idle_paths_timeout();
    test_abandon_idle_paths_keep_recent();
    test_abandon_idle_paths_custom_timeout();
    test_is_path_abandoned();
    test_active_path_count_initial();
    test_comprehensive_multi_path();
    test_legacy_api_compat();
    test_concurrent_update();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
