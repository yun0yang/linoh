// test_connection_stability.cpp — v3.3.0 突破4 连接稳定性自适应增强
//
// 覆盖三个改进点：
//   1. 跨域 idle_timeout / keepalive_interval 自适应（Config 字段 + 默认值）
//   2. 多路径主动健康迁移（PathMigrationManager::detect_degraded_paths）
//   3. Relay 熔断器 cooldown 指数退避（CircuitBreaker consecutive_opens + effective_cooldown）

#include "linoh/endpoint/connection.hpp"
#include "linoh/nat/relay_pool.hpp"
#include "linoh/protocol/path_migration.hpp"

#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            printf("FAIL [%s:%d] %s\n", __FILE__, __LINE__, #cond);          \
            ++failures;                                                      \
        } else {                                                             \
            ++passed;                                                        \
        }                                                                    \
    } while (0)

static int passed = 0;
static int failures = 0;

// ============================================================================
// 改进点1: 跨域 idle_timeout / keepalive_interval 自适应
// ============================================================================

static void test_cross_domain_config_defaults() {
    printf("[test] cross-domain Config default values...\n");
    linoh::endpoint::Connection::Config cfg;
    // 本域默认值
    CHECK(cfg.idle_timeout.count() == 30000);
    CHECK(cfg.keepalive_interval.count() == 15000);
    // v3.3.0 突破4: 跨域覆盖默认值
    CHECK(cfg.cross_domain_idle_timeout.count() == 60000);
    CHECK(cfg.cross_domain_keepalive_interval.count() == 8000);
    // is_cross_domain 默认 false
    CHECK(cfg.is_cross_domain == false);
}

static void test_cross_domain_config_override_semantics() {
    printf("[test] cross-domain Config override semantics (0=disabled)...\n");
    linoh::endpoint::Connection::Config cfg;
    // 设为 0 表示不覆盖
    cfg.cross_domain_idle_timeout = std::chrono::milliseconds(0);
    cfg.cross_domain_keepalive_interval = std::chrono::milliseconds(0);
    // 原值不受影响
    CHECK(cfg.idle_timeout.count() == 30000);
    CHECK(cfg.keepalive_interval.count() == 15000);
    // 自定义覆盖值
    cfg.cross_domain_idle_timeout = std::chrono::milliseconds(120000);
    cfg.cross_domain_keepalive_interval = std::chrono::milliseconds(5000);
    CHECK(cfg.cross_domain_idle_timeout.count() == 120000);
    CHECK(cfg.cross_domain_keepalive_interval.count() == 5000);
}

// ============================================================================
// 改进点2: 多路径主动健康迁移 — 路径退化检测
// ============================================================================

using namespace linoh::protocol;
using namespace linoh::nat;
using namespace std::chrono;

static void test_degradation_no_paths() {
    printf("[test] detect_degraded_paths: empty manager returns empty...\n");
    PathMigrationManager mgr;
    auto now = steady_clock::now();
    auto degraded = mgr.detect_degraded_paths(now);
    CHECK(degraded.empty());
}

static void test_degradation_normal_path_not_degraded() {
    printf("[test] detect_degraded_paths: normal RTT not degraded...\n");
    PathMigrationManager mgr;
    auto now = steady_clock::now();
    // 建立 10 次稳定 RTT=50ms 的基线
    for (int i = 0; i < 10; ++i) {
        mgr.update_path_quality(1, microseconds(50000), 0, now);
    }
    auto degraded = mgr.detect_degraded_paths(now);
    CHECK(degraded.empty());
}

static void test_degradation_rtt_spike_detected() {
    printf("[test] detect_degraded_paths: RTT spike triggers degradation...\n");
    PathMigrationManager mgr;
    auto now = steady_clock::now();
    // 建立基线：10 次 RTT=50ms
    for (int i = 0; i < 10; ++i) {
        mgr.update_path_quality(1, microseconds(50000), 0, now);
    }
    // 验证基线已建立
    auto q = mgr.path_quality(1);
    CHECK(q.has_value());
    CHECK(q->srtt_baseline.count() > 0);

    // RTT 突增到 500ms（基线 ~50ms * 3.0 = ~150ms 阈值，500ms 远超阈值）
    mgr.update_path_quality(1, microseconds(500000), 0, now);
    auto degraded = mgr.detect_degraded_paths(now);
    CHECK(degraded.size() == 1);
    CHECK(degraded[0] == 1);
}

static void test_degradation_rtt_jitter_not_false_positive() {
    printf("[test] detect_degraded_paths: short RTT jitter no false positive...\n");
    PathMigrationManager mgr;
    auto now = steady_clock::now();
    // 建立基线：10 次 RTT=50ms
    for (int i = 0; i < 10; ++i) {
        mgr.update_path_quality(1, microseconds(50000), 0, now);
    }
    // 单次轻微突增到 100ms（基线 ~50ms * 3.0 = ~150ms，100ms 未超阈值）
    mgr.update_path_quality(1, microseconds(100000), 0, now);
    auto degraded = mgr.detect_degraded_paths(now);
    CHECK(degraded.empty());
}

static void test_degradation_custom_ratio() {
    printf("[test] detect_degraded_paths: custom rtt_degradation_ratio=2.0...\n");
    PathMigrationManager mgr;
    PathMigrationManager::AbandonPolicy policy;
    policy.rtt_degradation_ratio = 2.0;  // 更敏感：2 倍即触发
    mgr.set_abandon_policy(policy);

    auto now = steady_clock::now();
    for (int i = 0; i < 10; ++i) {
        mgr.update_path_quality(1, microseconds(50000), 0, now);
    }
    // RTT 突增到 120ms（基线 ~50ms * 2.0 = ~100ms，120ms 超过）
    mgr.update_path_quality(1, microseconds(120000), 0, now);
    auto degraded = mgr.detect_degraded_paths(now);
    CHECK(degraded.size() == 1);
}

static void test_degradation_multiple_paths() {
    printf("[test] detect_degraded_paths: multiple paths, only degraded ones returned...\n");
    PathMigrationManager mgr;
    auto now = steady_clock::now();
    // path 1: 正常（50ms）
    for (int i = 0; i < 10; ++i) {
        mgr.update_path_quality(1, microseconds(50000), 0, now);
    }
    // path 2: 正常基线（30ms）
    for (int i = 0; i < 10; ++i) {
        mgr.update_path_quality(2, microseconds(30000), 0, now);
    }
    // path 2 突增到 200ms（基线 ~30ms * 3.0 = ~90ms，200ms 超过）
    mgr.update_path_quality(2, microseconds(200000), 0, now);
    auto degraded = mgr.detect_degraded_paths(now);
    CHECK(degraded.size() == 1);
    CHECK(degraded[0] == 2);
}

static void test_degradation_idle_path_excluded() {
    printf("[test] detect_degraded_paths: idle paths excluded (handled by abandon)...\n");
    PathMigrationManager::AbandonPolicy policy;
    policy.idle_timeout = seconds(5);  // 5s idle timeout

    auto now = steady_clock::now();
    // 模拟路径已 idle 10s：所有更新用 old_now（now-10s），超过 idle_timeout=5s
    auto old_now = now - seconds(10);
    PathMigrationManager mgr;
    mgr.set_abandon_policy(policy);
    for (int i = 0; i < 10; ++i) {
        mgr.update_path_quality(1, microseconds(50000), 0, old_now);
    }
    // 突增 RTT（也在 old_now 时刻，last_seen=old_now）
    mgr.update_path_quality(1, microseconds(500000), 0, old_now);
    // now 时刻检测，路径 last_seen 在 10s 前，超过 idle_timeout=5s → 不参与退化检测
    auto degraded = mgr.detect_degraded_paths(now);
    CHECK(degraded.empty());  // idle 路径不参与退化检测

    // 对照组：last_seen 在 1s 前（未超 idle_timeout=5s），突增 RTT 应被检测到
    PathMigrationManager mgr2;
    mgr2.set_abandon_policy(policy);
    auto recent_now = now - seconds(1);
    for (int i = 0; i < 10; ++i) {
        mgr2.update_path_quality(1, microseconds(50000), 0, recent_now);
    }
    mgr2.update_path_quality(1, microseconds(500000), 0, recent_now);
    auto degraded2 = mgr2.detect_degraded_paths(now);
    CHECK(degraded2.size() == 1);  // 非 idle 路径参与退化检测
}

static void test_srtt_baseline_ema_update() {
    printf("[test] srtt_baseline EMA update (alpha=0.125)...\n");
    PathMigrationManager mgr;
    auto now = steady_clock::now();
    // 首次采样：baseline = srtt = 100ms
    mgr.update_path_quality(1, microseconds(100000), 0, now);
    auto q = mgr.path_quality(1);
    CHECK(q.has_value());
    CHECK(q->srtt_baseline.count() == 100000);  // 首次 baseline = srtt

    // 第二次采样 srtt=200ms：baseline = 100*0.875 + 200*0.125 = 87.5 + 25 = 112.5ms
    mgr.update_path_quality(1, microseconds(200000), 0, now);
    q = mgr.path_quality(1);
    CHECK(q.has_value());
    CHECK(q->srtt_baseline.count() == 112500);  // 112.5ms
}

// ============================================================================
// 改进点3: Relay 熔断器 cooldown 指数退避
// ============================================================================

static void test_breaker_initial_state() {
    printf("[test] CircuitBreaker initial state (Closed, no opens)...\n");
    CircuitBreaker cb;
    CHECK(cb.state() == CircuitState::Closed);
    CHECK(cb.consecutive_opens() == 0);
    CHECK(cb.effective_cooldown().count() == 30000);  // 默认 cooldown
}

static void test_breaker_first_open_cooldown() {
    printf("[test] CircuitBreaker first open: cooldown=30s (no backoff)...\n");
    CircuitBreakerConfig cfg;
    cfg.failure_threshold = 2;
    CircuitBreaker cb(cfg);
    // 触发首次熔断
    cb.record_failure();
    cb.record_failure();
    CHECK(cb.state() == CircuitState::Open);
    CHECK(cb.consecutive_opens() == 1);
    // 首次熔断 cooldown = base cooldown = 30s
    CHECK(cb.effective_cooldown().count() == 30000);
}

static void test_breaker_second_open_backoff() {
    printf("[test] CircuitBreaker recovery resets opens, new open starts fresh...\n");
    CircuitBreakerConfig cfg;
    cfg.failure_threshold = 1;
    cfg.cooldown = milliseconds(50);
    cfg.max_cooldown = milliseconds(300000);
    cfg.backoff_factor = 2.0;
    cfg.close_threshold = 1;
    cfg.half_open_max_probes = 1;
    CircuitBreaker cb(cfg);

    // 第一次熔断
    cb.record_failure();
    CHECK(cb.state() == CircuitState::Open);
    CHECK(cb.consecutive_opens() == 1);
    CHECK(cb.effective_cooldown().count() == 50);

    // 等 cooldown，HalfOpen，探测失败 → Open（consecutive_opens=2，HalfOpen→Open 递增）
    std::this_thread::sleep_for(milliseconds(60));
    CHECK(cb.allow_request());
    cb.record_failure();
    CHECK(cb.state() == CircuitState::Open);
    CHECK(cb.consecutive_opens() == 2);
    CHECK(cb.effective_cooldown().count() == 100);  // 50 * 2^1 = 100

    // 等 cooldown=100ms，HalfOpen，探测成功 → Closed（consecutive_opens=0 重置）
    std::this_thread::sleep_for(milliseconds(110));
    CHECK(cb.allow_request());
    cb.record_success();
    CHECK(cb.state() == CircuitState::Closed);
    CHECK(cb.consecutive_opens() == 0);
    CHECK(cb.effective_cooldown().count() == 50);  // 恢复 base cooldown

    // 新的 Closed→Open（重新从 1 开始）
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 1);
    CHECK(cb.effective_cooldown().count() == 50);
}

static void test_breaker_consecutive_opens_backoff() {
    printf("[test] CircuitBreaker consecutive opens backoff (100/200/400/800/1000)...\n");
    // 验证连续探测失败的指数退避序列
    // 设计：HalfOpen→Open 也递增 consecutive_opens，实现真正的指数退避
    CircuitBreakerConfig cfg;
    cfg.failure_threshold = 1;
    cfg.cooldown = milliseconds(100);
    cfg.max_cooldown = milliseconds(1000);
    cfg.backoff_factor = 2.0;
    cfg.close_threshold = 1;
    cfg.half_open_max_probes = 1;
    CircuitBreaker cb(cfg);

    // Closed→Open (第1次)
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 1);
    CHECK(cb.effective_cooldown().count() == 100);

    // HalfOpen→Open (第2次)
    std::this_thread::sleep_for(milliseconds(110));
    cb.allow_request();
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 2);
    CHECK(cb.effective_cooldown().count() == 200);

    // HalfOpen→Open (第3次)
    std::this_thread::sleep_for(milliseconds(210));
    cb.allow_request();
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 3);
    CHECK(cb.effective_cooldown().count() == 400);

    // HalfOpen→Open (第4次)
    std::this_thread::sleep_for(milliseconds(410));
    cb.allow_request();
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 4);
    CHECK(cb.effective_cooldown().count() == 800);

    // HalfOpen→Open (第5次，触及上限)
    std::this_thread::sleep_for(milliseconds(810));
    cb.allow_request();
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 5);
    CHECK(cb.effective_cooldown().count() == 1000);  // 100*2^4=1600 > max 1000
}

static void test_breaker_halfopen_fail_increments_backoff() {
    printf("[test] CircuitBreaker HalfOpen->Open fail increments backoff...\n");
    // 此测试验证修正后的设计：HalfOpen 探测失败重新 Open 时，consecutive_opens 递增
    // 这样实现真正的指数退避：
    //   Closed→Open(1): cooldown=30s
    //   HalfOpen→Open(2): cooldown=60s
    //   HalfOpen→Open(3): cooldown=120s
    //   HalfOpen→Open(4): cooldown=240s
    //   HalfOpen→Open(5+): cooldown=300s (max)
    CircuitBreakerConfig cfg;
    cfg.failure_threshold = 1;
    cfg.cooldown = milliseconds(100);
    cfg.max_cooldown = milliseconds(1000);
    cfg.backoff_factor = 2.0;
    cfg.close_threshold = 1;
    cfg.half_open_max_probes = 1;
    CircuitBreaker cb(cfg);

    // Closed → Open (第1次)
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 1);
    CHECK(cb.effective_cooldown().count() == 100);

    // 等 cooldown，进入 HalfOpen
    std::this_thread::sleep_for(milliseconds(150));
    CHECK(cb.allow_request());
    CHECK(cb.state() == CircuitState::HalfOpen);

    // HalfOpen 探测失败 → Open (第2次)
    cb.record_failure();
    CHECK(cb.state() == CircuitState::Open);
    CHECK(cb.consecutive_opens() == 2);
    CHECK(cb.effective_cooldown().count() == 200);  // 100 * 2^1 = 200

    // 等 cooldown=200ms，进入 HalfOpen
    std::this_thread::sleep_for(milliseconds(250));
    CHECK(cb.allow_request());
    CHECK(cb.state() == CircuitState::HalfOpen);

    // HalfOpen 探测失败 → Open (第3次)
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 3);
    CHECK(cb.effective_cooldown().count() == 400);  // 100 * 2^2 = 400

    // 等 cooldown=400ms，进入 HalfOpen
    std::this_thread::sleep_for(milliseconds(450));
    CHECK(cb.allow_request());

    // HalfOpen 探测失败 → Open (第4次)
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 4);
    CHECK(cb.effective_cooldown().count() == 800);  // 100 * 2^3 = 800

    // 等 cooldown=800ms，进入 HalfOpen
    std::this_thread::sleep_for(milliseconds(850));
    CHECK(cb.allow_request());

    // HalfOpen 探测失败 → Open (第5次，触及上限)
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 5);
    CHECK(cb.effective_cooldown().count() == 1000);  // 100 * 2^4 = 1600 > max 1000
}

static void test_breaker_success_resets_opens() {
    printf("[test] CircuitBreaker success resets consecutive_opens to 0...\n");
    CircuitBreakerConfig cfg;
    cfg.failure_threshold = 1;
    cfg.cooldown = milliseconds(50);
    cfg.close_threshold = 1;
    cfg.half_open_max_probes = 1;
    CircuitBreaker cb(cfg);

    // 熔断 + 退避到 consecutive_opens=3
    cb.record_failure();
    std::this_thread::sleep_for(milliseconds(60));
    cb.allow_request();
    cb.record_failure();
    std::this_thread::sleep_for(milliseconds(120));
    cb.allow_request();
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 3);

    // 等 cooldown，进入 HalfOpen，探测成功 → Closed
    std::this_thread::sleep_for(milliseconds(400));  // 等 effective_cooldown=400ms
    CHECK(cb.allow_request());
    cb.record_success();
    CHECK(cb.state() == CircuitState::Closed);
    CHECK(cb.consecutive_opens() == 0);  // 重置
    CHECK(cb.effective_cooldown().count() == 50);  // 恢复 base cooldown
}

static void test_breaker_custom_backoff_factor() {
    printf("[test] CircuitBreaker custom backoff_factor=3.0...\n");
    CircuitBreakerConfig cfg;
    cfg.failure_threshold = 1;
    cfg.cooldown = milliseconds(100);
    cfg.max_cooldown = milliseconds(10000);
    cfg.backoff_factor = 3.0;  // 3 倍退避
    cfg.close_threshold = 1;
    cfg.half_open_max_probes = 1;
    CircuitBreaker cb(cfg);

    cb.record_failure();
    CHECK(cb.consecutive_opens() == 1);
    CHECK(cb.effective_cooldown().count() == 100);

    std::this_thread::sleep_for(milliseconds(110));
    cb.allow_request();
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 2);
    CHECK(cb.effective_cooldown().count() == 300);  // 100 * 3^1 = 300

    std::this_thread::sleep_for(milliseconds(310));
    cb.allow_request();
    cb.record_failure();
    CHECK(cb.consecutive_opens() == 3);
    CHECK(cb.effective_cooldown().count() == 900);  // 100 * 3^2 = 900
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("=== test_connection_stability (v3.3.0 突破4) ===\n\n");

    test_cross_domain_config_defaults();
    test_cross_domain_config_override_semantics();

    test_degradation_no_paths();
    test_degradation_normal_path_not_degraded();
    test_degradation_rtt_spike_detected();
    test_degradation_rtt_jitter_not_false_positive();
    test_degradation_custom_ratio();
    test_degradation_multiple_paths();
    test_degradation_idle_path_excluded();
    test_srtt_baseline_ema_update();

    test_breaker_initial_state();
    test_breaker_first_open_cooldown();
    test_breaker_second_open_backoff();
    test_breaker_consecutive_opens_backoff();
    test_breaker_halfopen_fail_increments_backoff();
    test_breaker_success_resets_opens();
    test_breaker_custom_backoff_factor();

    printf("\n=== Summary: %d passed, %d failed ===\n", passed, failures);
    return failures == 0 ? 0 : 1;
}
