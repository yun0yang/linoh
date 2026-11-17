// test_relay_pool.cpp — P5-D-5 Relay 自动 fallback 测试

#include "linoh/nat/relay_pool.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#define CHECK(cond) do { \
    ++total; \
    if (!(cond)) { \
        std::cerr << "FAIL: " << #cond << " (line " << __LINE__ << ")" << std::endl; \
        ++failed; \
    } \
} while(0)

static int total = 0;
static int failed = 0;

using namespace linoh;
using namespace linoh::nat;

// ============================================================================
// 辅助：mock 探测器
// ============================================================================

/// 可编程的 mock 探测器
class MockProbe {
public:
    HealthProbeResult operator()(const base::RelayUrl &url) {
        call_count_++;
        std::string url_str = url.url();
        if (results_.count(url_str)) {
            return results_[url_str];
        }
        HealthProbeResult r;
        r.success = true;
        r.rtt = std::chrono::milliseconds(50);
        return r;
    }

    void set_result(const std::string &url, bool success, int rtt_ms = 50) {
        HealthProbeResult r;
        r.success = success;
        r.rtt = std::chrono::milliseconds(rtt_ms);
        if (!success) r.error_message = "mock fail";
        results_[url] = r;
    }

    // v2.0 Phase 1：支持设置负载/带宽元数据
    void set_result_with_metrics(const std::string &url, bool success, int rtt_ms,
                                 int load_percent, int uplink_bps) {
        HealthProbeResult r;
        r.success = success;
        r.rtt = std::chrono::milliseconds(rtt_ms);
        r.load_percent = load_percent;
        r.uplink_bps = uplink_bps;
        if (!success) r.error_message = "mock fail";
        results_[url] = r;
    }

    int call_count() const { return call_count_; }

private:
    std::atomic<int> call_count_{0};
    std::unordered_map<std::string, HealthProbeResult> results_;
};

static base::RelayUrl make_url(const std::string &s) {
    return base::RelayUrl(s);
}

// ============================================================================
// 1. 枚举测试
// ============================================================================

void test_relay_health_name() {
    std::cout << "[test] relay_health_name" << std::endl;
    CHECK(std::string(relay_health_name(RelayHealth::Unknown)) == "unknown");
    CHECK(std::string(relay_health_name(RelayHealth::Healthy)) == "healthy");
    CHECK(std::string(relay_health_name(RelayHealth::Degraded)) == "degraded");
    CHECK(std::string(relay_health_name(RelayHealth::Unhealthy)) == "unhealthy");
    CHECK(std::string(relay_health_name(RelayHealth::CircuitOpen)) == "circuit-open");
}

void test_circuit_state_name() {
    std::cout << "[test] circuit_state_name" << std::endl;
    CHECK(std::string(circuit_state_name(CircuitState::Closed)) == "closed");
    CHECK(std::string(circuit_state_name(CircuitState::Open)) == "open");
    CHECK(std::string(circuit_state_name(CircuitState::HalfOpen)) == "half-open");
}

// ============================================================================
// 2. CircuitBreaker 测试
// ============================================================================

void test_circuit_breaker_initial() {
    std::cout << "[test] CircuitBreaker initial" << std::endl;
    CircuitBreaker b;
    CHECK(b.state() == CircuitState::Closed);
    CHECK(b.consecutive_failures() == 0);
    CHECK(b.consecutive_successes() == 0);
    CHECK(b.allow_request() == true);
}

void test_circuit_breaker_stays_closed_on_success() {
    std::cout << "[test] CircuitBreaker stays closed on success" << std::endl;
    CircuitBreaker b;
    for (int i = 0; i < 10; ++i) {
        b.record_success();
    }
    CHECK(b.state() == CircuitState::Closed);
    CHECK(b.consecutive_successes() == 10);
}

void test_circuit_breaker_opens_after_threshold() {
    std::cout << "[test] CircuitBreaker opens after threshold" << std::endl;
    CircuitBreakerConfig cfg;
    cfg.failure_threshold = 3;
    CircuitBreaker b(cfg);

    for (int i = 0; i < 3; ++i) {
        b.record_failure();
    }
    CHECK(b.state() == CircuitState::Open);
    CHECK(b.consecutive_failures() == 3);
    CHECK(b.allow_request() == false);  // Open 状态不允许
}

void test_circuit_breaker_resets_on_success() {
    std::cout << "[test] CircuitBreaker resets on success" << std::endl;
    CircuitBreakerConfig cfg;
    cfg.failure_threshold = 3;
    CircuitBreaker b(cfg);

    b.record_failure();
    b.record_failure();
    CHECK(b.state() == CircuitState::Closed);
    b.record_success();
    CHECK(b.consecutive_failures() == 0);
    CHECK(b.consecutive_successes() == 1);
}

void test_circuit_breaker_half_open_after_cooldown() {
    std::cout << "[test] CircuitBreaker half-open after cooldown" << std::endl;
    CircuitBreakerConfig cfg;
    cfg.failure_threshold = 2;
    cfg.cooldown = std::chrono::milliseconds(50);
    cfg.half_open_max_probes = 3;
    cfg.close_threshold = 2;
    CircuitBreaker b(cfg);

    b.record_failure();
    b.record_failure();
    CHECK(b.state() == CircuitState::Open);

    // 等待冷却
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    CHECK(b.allow_request() == true);  // 转 HalfOpen
    CHECK(b.state() == CircuitState::HalfOpen);
}

void test_circuit_breaker_closes_after_half_open_success() {
    std::cout << "[test] CircuitBreaker closes after half-open success" << std::endl;
    CircuitBreakerConfig cfg;
    cfg.failure_threshold = 2;
    cfg.cooldown = std::chrono::milliseconds(20);
    cfg.close_threshold = 2;
    CircuitBreaker b(cfg);

    b.record_failure();
    b.record_failure();
    CHECK(b.state() == CircuitState::Open);

    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    CHECK(b.allow_request() == true);
    CHECK(b.state() == CircuitState::HalfOpen);

    b.record_success();
    b.record_success();
    CHECK(b.state() == CircuitState::Closed);
}

void test_circuit_breaker_reopens_on_half_open_failure() {
    std::cout << "[test] CircuitBreaker reopens on half-open failure" << std::endl;
    CircuitBreakerConfig cfg;
    cfg.failure_threshold = 2;
    cfg.cooldown = std::chrono::milliseconds(20);
    CircuitBreaker b(cfg);

    b.record_failure();
    b.record_failure();
    CHECK(b.state() == CircuitState::Open);

    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    CHECK(b.allow_request() == true);
    CHECK(b.state() == CircuitState::HalfOpen);

    b.record_failure();
    CHECK(b.state() == CircuitState::Open);
}

// ============================================================================
// 3. RelayEntry 测试
// ============================================================================

void test_relay_entry_score() {
    std::cout << "[test] RelayEntry score" << std::endl;

    base::RelayUrl url("https://relay1.example.com/");
    RelayEntry e1(url);
    e1.health = RelayHealth::Healthy;
    e1.last_rtt = std::chrono::milliseconds(50);

    RelayEntry e2(url);
    e2.health = RelayHealth::Healthy;
    e2.last_rtt = std::chrono::milliseconds(100);

    // 同健康度，RTT 高分高
    CHECK(e1.score() < e2.score());

    RelayEntry e3(url);
    e3.health = RelayHealth::Degraded;
    e3.last_rtt = std::chrono::milliseconds(50);

    // 健康度差，分数高
    CHECK(e1.score() < e3.score());

    RelayEntry e4(url);
    e4.health = RelayHealth::Unhealthy;

    CHECK(e3.score() < e4.score());
}

void test_relay_entry_is_usable() {
    std::cout << "[test] RelayEntry is_usable" << std::endl;

    RelayEntry e(base::RelayUrl("https://relay1.example.com/"));

    e.health = RelayHealth::Healthy;
    CHECK(e.is_usable());

    e.health = RelayHealth::Degraded;
    CHECK(e.is_usable());

    e.health = RelayHealth::Unknown;
    CHECK(!e.is_usable());

    e.health = RelayHealth::Unhealthy;
    CHECK(!e.is_usable());

    e.health = RelayHealth::CircuitOpen;
    CHECK(!e.is_usable());
}

// ============================================================================
// 4. RelayPool 基础测试
// ============================================================================

void test_relay_pool_empty() {
    std::cout << "[test] RelayPool empty" << std::endl;
    RelayPool pool;
    CHECK(pool.empty());
    CHECK(pool.size() == 0);
    CHECK(!pool.select_best().has_value());
    CHECK(!pool.select_best_url().has_value());
    CHECK(!pool.current_primary().has_value());
}

void test_relay_pool_add_and_get() {
    std::cout << "[test] RelayPool add and get" << std::endl;
    RelayPool pool;
    pool.add_relay(make_url("https://relay1.example.com/"));
    pool.add_relay(make_url("https://relay2.example.com/"));

    CHECK(pool.size() == 2);
    CHECK(!pool.empty());

    auto all = pool.get_all_relays();
    CHECK(all.size() == 2);
}

void test_relay_pool_remove() {
    std::cout << "[test] RelayPool remove" << std::endl;
    RelayPool pool;
    auto url1 = make_url("https://relay1.example.com/");
    auto url2 = make_url("https://relay2.example.com/");
    pool.add_relay(url1);
    pool.add_relay(url2);

    CHECK(pool.remove_relay(url1));
    CHECK(pool.size() == 1);

    // 移除不存在的
    CHECK(!pool.remove_relay(url1));
}

void test_relay_pool_remove_pinned() {
    std::cout << "[test] RelayPool remove pinned" << std::endl;
    RelayPool pool;
    auto url = make_url("https://relay1.example.com/");
    pool.add_relay(url, /*pinned=*/true);

    // pinned 不可移除
    CHECK(!pool.remove_relay(url));
    CHECK(pool.size() == 1);
}

void test_relay_pool_select_best_initial() {
    std::cout << "[test] RelayPool select_best initial" << std::endl;
    RelayPool pool;
    pool.add_relay(make_url("https://relay1.example.com/"));
    pool.add_relay(make_url("https://relay2.example.com/"));

    auto best = pool.select_best();
    CHECK(best.has_value());
    // 初始都是 Unknown，按 URL 顺序选第一个
    CHECK(best->url.url() == "https://relay1.example.com/" ||
          best->url.url() == "https://relay2.example.com/");
}

// ============================================================================
// 5. RelayPool 健康检查测试（mock 探测器）
// ============================================================================

void test_relay_pool_check_one_success() {
    std::cout << "[test] RelayPool check_one success" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.probe_timeout = std::chrono::milliseconds(100);
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    auto url1 = make_url("https://relay1.example.com/");
    pool.add_relay(url1);
    probe.set_result("https://relay1.example.com/", true, 30);

    auto result = pool.check_one(url1);
    CHECK(result.success);
    CHECK(result.rtt == std::chrono::milliseconds(30));

    auto all = pool.get_all_relays();
    CHECK(all.size() == 1);
    CHECK(all[0].health == RelayHealth::Healthy);
    CHECK(all[0].last_rtt == std::chrono::milliseconds(30));
    CHECK(all[0].consecutive_successes == 1);
}

void test_relay_pool_check_one_failure() {
    std::cout << "[test] RelayPool check_one failure" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.breaker_config.failure_threshold = 3;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    auto url1 = make_url("https://relay1.example.com/");
    pool.add_relay(url1);
    probe.set_result("https://relay1.example.com/", false);

    auto result = pool.check_one(url1);
    CHECK(!result.success);

    auto all = pool.get_all_relays();
    CHECK(all[0].health == RelayHealth::Unknown);  // 单次失败不会变 Degraded
    CHECK(all[0].consecutive_failures == 1);

    // 再失败一次 → Degraded
    pool.check_one(url1);
    all = pool.get_all_relays();
    CHECK(all[0].health == RelayHealth::Degraded);
    CHECK(all[0].consecutive_failures == 2);
}

void test_relay_pool_check_all() {
    std::cout << "[test] RelayPool check_all" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://relay1.example.com/"));
    pool.add_relay(make_url("https://relay2.example.com/"));
    pool.add_relay(make_url("https://relay3.example.com/"));

    probe.set_result("https://relay1.example.com/", true, 30);
    probe.set_result("https://relay2.example.com/", true, 60);
    probe.set_result("https://relay3.example.com/", true, 40);

    pool.check_all_sync();

    auto all = pool.get_all_relays();
    CHECK(all.size() == 3);
    for (const auto &e : all) {
        CHECK(e.health == RelayHealth::Healthy);
    }

    // 选最佳应是 relay1 (RTT 最小)
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://relay1.example.com/");
}

void test_relay_pool_select_best_by_health() {
    std::cout << "[test] RelayPool select_best by health" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(200);
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://relay1.example.com/"));
    pool.add_relay(make_url("https://relay2.example.com/"));

    // relay1 健康 RTT 30
    probe.set_result("https://relay1.example.com/", true, 30);
    // relay2 高 RTT 600 → Degraded
    probe.set_result("https://relay2.example.com/", true, 600);

    pool.check_all_sync();

    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://relay1.example.com/");
    CHECK(best->health == RelayHealth::Healthy);
}

void test_relay_pool_degraded_threshold() {
    std::cout << "[test] RelayPool degraded threshold" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(100);
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://relay1.example.com/"));
    probe.set_result("https://relay1.example.com/", true, 50);
    pool.check_one(make_url("https://relay1.example.com/"));
    auto all = pool.get_all_relays();
    CHECK(all[0].health == RelayHealth::Healthy);

    probe.set_result("https://relay1.example.com/", true, 200);
    pool.check_one(make_url("https://relay1.example.com/"));
    all = pool.get_all_relays();
    CHECK(all[0].health == RelayHealth::Degraded);
}

// ============================================================================
// 6. record_success / record_failure 测试
// ============================================================================

void test_relay_pool_record_success() {
    std::cout << "[test] RelayPool record_success" << std::endl;
    MockProbe probe;
    RelayPool pool(RelayPoolConfig{}, [&probe](const base::RelayUrl &url) { return probe(url); });
    pool.add_relay(make_url("https://relay1.example.com/"));

    // 先标记失败
    probe.set_result("https://relay1.example.com/", false);
    pool.check_one(make_url("https://relay1.example.com/"));
    pool.check_one(make_url("https://relay1.example.com/"));
    auto all = pool.get_all_relays();
    CHECK(all[0].consecutive_failures == 2);

    // 记录成功
    pool.record_success(make_url("https://relay1.example.com/"));
    all = pool.get_all_relays();
    CHECK(all[0].consecutive_failures == 0);
    CHECK(all[0].consecutive_successes == 1);
}

void test_relay_pool_record_failure_to_unhealthy() {
    std::cout << "[test] RelayPool record_failure to unhealthy" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.breaker_config.failure_threshold = 3;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });
    pool.add_relay(make_url("https://relay1.example.com/"));

    pool.record_failure(make_url("https://relay1.example.com/"));
    pool.record_failure(make_url("https://relay1.example.com/"));
    auto all = pool.get_all_relays();
    CHECK(all[0].health == RelayHealth::Degraded);

    pool.record_failure(make_url("https://relay1.example.com/"));
    all = pool.get_all_relays();
    CHECK(all[0].health == RelayHealth::Unhealthy);
    CHECK(all[0].consecutive_failures == 3);
}

// ============================================================================
// 7. FailoverController 测试
// ============================================================================

void test_failover_controller_initial() {
    std::cout << "[test] FailoverController initial" << std::endl;
    auto pool = std::make_shared<RelayPool>();
    FailoverController fc(pool);

    CHECK(fc.is_enabled());
    CHECK(fc.get_history().empty());
}

void test_failover_controller_trigger_no_relay() {
    std::cout << "[test] FailoverController trigger no relay" << std::endl;
    auto pool = std::make_shared<RelayPool>();
    FailoverController fc(pool);

    auto r = fc.trigger_failover("test");
    CHECK(!r.has_value());
    CHECK(fc.get_history().empty());
}

void test_failover_controller_trigger_first() {
    std::cout << "[test] FailoverController trigger first" << std::endl;
    auto pool = std::make_shared<RelayPool>();
    pool->add_relay(make_url("https://relay1.example.com/"));
    FailoverController fc(pool);

    auto r = fc.trigger_failover("initial");
    CHECK(r.has_value());
    // 第一次故障切换（从无主到有主），应记录事件
    auto history = fc.get_history();
    CHECK(history.size() == 1);
    CHECK(history[0].reason == "initial");
}

void test_failover_controller_switch_on_change() {
    std::cout << "[test] FailoverController switch on change" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(100);
    auto pool = std::make_shared<RelayPool>(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });
    pool->add_relay(make_url("https://relay1.example.com/"));
    pool->add_relay(make_url("https://relay2.example.com/"));

    // 初始：relay1 健康 RTT 30, relay2 健康 RTT 50 → relay1 最佳
    probe.set_result("https://relay1.example.com/", true, 30);
    probe.set_result("https://relay2.example.com/", true, 50);
    pool->check_all_sync();

    FailoverController fc(pool);
    auto r1 = fc.trigger_failover("initial");
    CHECK(r1.has_value());
    CHECK(r1->url() == "https://relay1.example.com/");
    CHECK(fc.get_history().size() == 1);

    // 现在 relay1 失败 → relay2 最佳
    probe.set_result("https://relay1.example.com/", false);
    probe.set_result("https://relay2.example.com/", true, 50);
    pool->check_all_sync();
    pool->check_all_sync();

    auto r2 = fc.trigger_failover("relay1 down");
    CHECK(r2.has_value());
    CHECK(r2->url() == "https://relay2.example.com/");
    auto history = fc.get_history();
    CHECK(history.size() == 2);
    CHECK(history[1].reason == "relay1 down");
}

void test_failover_controller_callback() {
    std::cout << "[test] FailoverController callback" << std::endl;
    auto pool = std::make_shared<RelayPool>();
    pool->add_relay(make_url("https://relay1.example.com/"));

    bool called = false;
    std::string captured_reason;
    FailoverController fc(pool, [&](const FailoverEvent &event) {
        called = true;
        captured_reason = event.reason;
    });

    fc.trigger_failover("test callback");
    CHECK(called);
    CHECK(captured_reason == "test callback");
}

void test_failover_controller_disabled() {
    std::cout << "[test] FailoverController disabled" << std::endl;
    auto pool = std::make_shared<RelayPool>();
    pool->add_relay(make_url("https://relay1.example.com/"));
    FailoverController fc(pool);
    fc.set_enabled(false);

    auto r = fc.trigger_failover("test");
    CHECK(!r.has_value());
    CHECK(fc.get_history().empty());
}

void test_failover_controller_clear_history() {
    std::cout << "[test] FailoverController clear_history" << std::endl;
    auto pool = std::make_shared<RelayPool>();
    pool->add_relay(make_url("https://relay1.example.com/"));
    FailoverController fc(pool);

    fc.trigger_failover("event1");
    CHECK(fc.get_history().size() == 1);

    fc.clear_history();
    CHECK(fc.get_history().empty());
}

// ============================================================================
// 8. 综合 round-trip 测试
// ============================================================================

void test_relay_pool_failover_scenario() {
    std::cout << "[test] RelayPool failover scenario" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(100);
    cfg.breaker_config.failure_threshold = 3;
    auto pool = std::make_shared<RelayPool>(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool->add_relay(make_url("https://relay1.example.com/"));
    pool->add_relay(make_url("https://relay2.example.com/"));
    pool->add_relay(make_url("https://relay3.example.com/"));

    // 初始所有健康，relay1 RTT 最低
    probe.set_result("https://relay1.example.com/", true, 30);
    probe.set_result("https://relay2.example.com/", true, 60);
    probe.set_result("https://relay3.example.com/", true, 100);
    pool->check_all_sync();

    auto primary = pool->current_primary();
    CHECK(primary.has_value());
    CHECK(primary->url() == "https://relay1.example.com/");

    // relay1 故障，触发故障切换
    probe.set_result("https://relay1.example.com/", false);
    pool->check_all_sync();
    // relay1 持续失败
    pool->check_all_sync();
    pool->check_all_sync();
    // 现在 relay1 应为 Unhealthy
    auto all = pool->get_all_relays();
    bool relay1_unhealthy = false;
    for (const auto &e : all) {
        if (e.url.url() == "https://relay1.example.com/") {
            if (e.health == RelayHealth::Unhealthy || e.health == RelayHealth::Degraded) {
                relay1_unhealthy = true;
            }
        }
    }
    CHECK(relay1_unhealthy);

    // 主 Relay 应切到 relay2
    primary = pool->current_primary();
    CHECK(primary.has_value());
    CHECK(primary->url() == "https://relay2.example.com/");
}

// ============================================================================
// 9. 配置测试
// ============================================================================

void test_relay_pool_config_defaults() {
    std::cout << "[test] RelayPoolConfig defaults" << std::endl;
    RelayPoolConfig cfg;
    CHECK(cfg.check_interval == std::chrono::milliseconds(60000));
    CHECK(cfg.probe_timeout == std::chrono::milliseconds(5000));
    CHECK(cfg.degraded_rtt_threshold == std::chrono::milliseconds(500));
    CHECK(cfg.max_relays == 10);
    CHECK(cfg.enable_auto_failover == true);
}

void test_circuit_breaker_config_defaults() {
    std::cout << "[test] CircuitBreakerConfig defaults" << std::endl;
    CircuitBreakerConfig cfg;
    CHECK(cfg.failure_threshold == 5);
    CHECK(cfg.cooldown == std::chrono::milliseconds(30000));
    CHECK(cfg.half_open_max_probes == 3);
    CHECK(cfg.close_threshold == 2);
}

// ============================================================================
// 10. v2.0 Phase 1：多维选择测试（geo + load + uplink）
// ============================================================================

void test_geo_region_name() {
    std::cout << "[test] geo_region_name" << std::endl;
    CHECK(std::string(geo_region_name(GeoRegion::Unknown)) == "unknown");
    CHECK(std::string(geo_region_name(GeoRegion::North)) == "north");
    CHECK(std::string(geo_region_name(GeoRegion::East)) == "east");
    CHECK(std::string(geo_region_name(GeoRegion::South)) == "south");
    CHECK(std::string(geo_region_name(GeoRegion::Central)) == "central");
    CHECK(std::string(geo_region_name(GeoRegion::Southwest)) == "southwest");
    CHECK(std::string(geo_region_name(GeoRegion::Northwest)) == "northwest");
    CHECK(std::string(geo_region_name(GeoRegion::Northeast)) == "northeast");
    CHECK(std::string(geo_region_name(GeoRegion::Backbone)) == "backbone");
}

void test_is_cross_region() {
    std::cout << "[test] is_cross_region" << std::endl;
    // 同区域不算跨区域
    CHECK(!is_cross_region(GeoRegion::North, GeoRegion::North));
    CHECK(!is_cross_region(GeoRegion::East, GeoRegion::East));
    // 不同区域算跨区域
    CHECK(is_cross_region(GeoRegion::North, GeoRegion::East));
    CHECK(is_cross_region(GeoRegion::South, GeoRegion::Northwest));
    // Unknown 不算跨区域（向后兼容，不惩罚）
    CHECK(!is_cross_region(GeoRegion::Unknown, GeoRegion::North));
    CHECK(!is_cross_region(GeoRegion::North, GeoRegion::Unknown));
    // Backbone 与任意区域都不算跨区域
    CHECK(!is_cross_region(GeoRegion::Backbone, GeoRegion::North));
    CHECK(!is_cross_region(GeoRegion::North, GeoRegion::Backbone));
}

void test_relay_score_weights_defaults() {
    std::cout << "[test] RelayScoreWeights defaults" << std::endl;
    RelayScoreWeights w;
    CHECK(w.weight_health == 1.0);
    CHECK(w.weight_rtt == 1.0);
    CHECK(w.weight_load == 2.0);
    CHECK(w.weight_geo_distance == 5.0);
    CHECK(w.cross_region_penalty == 200.0);
}

void test_relay_entry_score_backward_compat() {
    std::cout << "[test] RelayEntry score backward compat" << std::endl;
    // 无参 score() 向后兼容：新增字段默认 0，结果与旧版一致
    base::RelayUrl url("https://relay1.example.com/");
    RelayEntry e1(url);
    e1.health = RelayHealth::Healthy;
    e1.last_rtt = std::chrono::milliseconds(50);
    // 旧版：0 (health) + 50 (rtt) = 50
    CHECK(e1.score() == 50.0);

    RelayEntry e2(url);
    e2.health = RelayHealth::Degraded;
    e2.last_rtt = std::chrono::milliseconds(200);
    // 旧版：100 (health) + 200 (rtt) = 300
    CHECK(e2.score() == 300.0);
}

void test_relay_entry_score_multi_dim() {
    std::cout << "[test] RelayEntry score multi-dim" << std::endl;
    base::RelayUrl url("https://relay1.example.com/");
    RelayScoreWeights w;

    // 健康 + RTT 50ms + load 0% + distance 0km
    RelayEntry e1(url);
    e1.health = RelayHealth::Healthy;
    e1.last_rtt = std::chrono::milliseconds(50);
    // score = 0*1 + 50*1 + 0*2 + 0*5 = 50
    CHECK(e1.score(GeoRegion::Unknown, w) == 50.0);

    // 同上但 load=30%
    RelayEntry e2(url);
    e2.health = RelayHealth::Healthy;
    e2.last_rtt = std::chrono::milliseconds(50);
    e2.load_percent = 30;
    // score = 0 + 50 + 30*2 + 0 = 110
    CHECK(e2.score(GeoRegion::Unknown, w) == 110.0);

    // 同上但 distance=500km
    RelayEntry e3(url);
    e3.health = RelayHealth::Healthy;
    e3.last_rtt = std::chrono::milliseconds(50);
    e3.geo_distance_km = 500;
    // score = 0 + 50 + 0 + (500/100)*5 = 75
    CHECK(e3.score(GeoRegion::Unknown, w) == 75.0);

    // load + distance 叠加
    RelayEntry e4(url);
    e4.health = RelayHealth::Healthy;
    e4.last_rtt = std::chrono::milliseconds(50);
    e4.load_percent = 30;
    e4.geo_distance_km = 500;
    // score = 0 + 50 + 60 + 25 = 135
    CHECK(e4.score(GeoRegion::Unknown, w) == 135.0);
}

void test_relay_entry_score_cross_region() {
    std::cout << "[test] RelayEntry score cross_region penalty" << std::endl;
    base::RelayUrl url("https://relay1.example.com/");
    RelayScoreWeights w;

    // 本地=North, relay=North → 同区域，无惩罚
    RelayEntry same_region(url);
    same_region.health = RelayHealth::Healthy;
    same_region.last_rtt = std::chrono::milliseconds(50);
    same_region.region = GeoRegion::North;
    double same_score = same_region.score(GeoRegion::North, w);

    // 本地=North, relay=East → 跨区域，+200
    RelayEntry cross_region(url);
    cross_region.health = RelayHealth::Healthy;
    cross_region.last_rtt = std::chrono::milliseconds(50);
    cross_region.region = GeoRegion::East;
    double cross_score = cross_region.score(GeoRegion::North, w);

    CHECK(same_score == 50.0);
    CHECK(cross_score == 250.0);  // 50 + 200
    CHECK(cross_score - same_score == w.cross_region_penalty);

    // Backbone relay 不受跨区域惩罚
    RelayEntry backbone(url);
    backbone.health = RelayHealth::Healthy;
    backbone.last_rtt = std::chrono::milliseconds(50);
    backbone.region = GeoRegion::Backbone;
    CHECK(backbone.score(GeoRegion::North, w) == 50.0);

    // relay region=Unknown 不惩罚
    RelayEntry unknown_region(url);
    unknown_region.health = RelayHealth::Healthy;
    unknown_region.last_rtt = std::chrono::milliseconds(50);
    unknown_region.region = GeoRegion::Unknown;
    CHECK(unknown_region.score(GeoRegion::North, w) == 50.0);
}

void test_relay_pool_config_multi_dim_defaults() {
    std::cout << "[test] RelayPoolConfig multi-dim defaults" << std::endl;
    RelayPoolConfig cfg;
    CHECK(cfg.local_region == GeoRegion::Unknown);
    CHECK(cfg.load_filter_threshold == 80);
    CHECK(cfg.active_set_size == 3);
    CHECK(cfg.score_weights.weight_load == 2.0);
    CHECK(cfg.score_weights.cross_region_penalty == 200.0);
}

void test_relay_pool_set_local_region() {
    std::cout << "[test] RelayPool set_local_region" << std::endl;
    RelayPool pool;
    CHECK(pool.local_region() == GeoRegion::Unknown);
    pool.set_local_region(GeoRegion::North);
    CHECK(pool.local_region() == GeoRegion::North);
    pool.set_local_region(GeoRegion::East);
    CHECK(pool.local_region() == GeoRegion::East);
}

void test_relay_pool_set_relay_metrics() {
    std::cout << "[test] RelayPool set_relay_metrics" << std::endl;
    RelayPool pool;
    auto url1 = make_url("https://relay1.example.com/");
    pool.add_relay(url1);

    // 设置 metrics
    CHECK(pool.set_relay_metrics(url1, /*load=*/50, /*uplink=*/100000000,
                                 GeoRegion::North, /*distance=*/300));
    auto all = pool.get_all_relays();
    CHECK(all.size() == 1);
    CHECK(all[0].load_percent == 50);
    CHECK(all[0].uplink_bps == 100000000);
    CHECK(all[0].region == GeoRegion::North);
    CHECK(all[0].geo_distance_km == 300);

    // 部分更新：只更新 load，其他保持
    CHECK(pool.set_relay_metrics(url1, /*load=*/80, /*uplink=*/-1,
                                 GeoRegion::Unknown, /*distance=*/-1));
    all = pool.get_all_relays();
    CHECK(all[0].load_percent == 80);
    CHECK(all[0].uplink_bps == 100000000);   // 未更新
    CHECK(all[0].region == GeoRegion::North); // 未更新
    CHECK(all[0].geo_distance_km == 300);     // 未更新

    // 不存在的 URL
    CHECK(!pool.set_relay_metrics(make_url("https://nonexistent/"), 10, 1000));
}

void test_relay_pool_select_best_by_geo() {
    std::cout << "[test] RelayPool select_best by geo (cross-region penalty)" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://relay-north.example.com/"));
    pool.add_relay(make_url("https://relay-east.example.com/"));

    // 两个 relay 健康、RTT 相同
    probe.set_result("https://relay-north.example.com/", true, 50);
    probe.set_result("https://relay-east.example.com/", true, 50);

    // 设置 region
    pool.set_relay_metrics(make_url("https://relay-north.example.com/"), 0, 0, GeoRegion::North, 0);
    pool.set_relay_metrics(make_url("https://relay-east.example.com/"), 0, 0, GeoRegion::East, 0);

    pool.check_all_sync();

    // 本地=North，relay-north 同区域 score=50，relay-east 跨区域 score=250
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://relay-north.example.com/");
}

void test_relay_pool_select_best_by_geo_distance() {
    std::cout << "[test] RelayPool select_best by geo_distance" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://relay-near.example.com/"));
    pool.add_relay(make_url("https://relay-far.example.com/"));

    // 同区域，RTT 相同，距离不同
    probe.set_result("https://relay-near.example.com/", true, 50);
    probe.set_result("https://relay-far.example.com/", true, 50);

    pool.set_relay_metrics(make_url("https://relay-near.example.com/"), 0, 0, GeoRegion::North, 100);
    pool.set_relay_metrics(make_url("https://relay-far.example.com/"), 0, 0, GeoRegion::North, 1500);

    pool.check_all_sync();

    // near: 0+50+0+(100/100)*5 = 55
    // far:  0+50+0+(1500/100)*5 = 125
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://relay-near.example.com/");
}

void test_relay_pool_select_best_by_load() {
    std::cout << "[test] RelayPool select_best by load" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://relay-idle.example.com/"));
    pool.add_relay(make_url("https://relay-busy.example.com/"));

    // 同区域，RTT 相同，负载不同
    probe.set_result("https://relay-idle.example.com/", true, 50);
    probe.set_result("https://relay-busy.example.com/", true, 50);

    pool.set_relay_metrics(make_url("https://relay-idle.example.com/"), 10, 0, GeoRegion::North, 0);
    pool.set_relay_metrics(make_url("https://relay-busy.example.com/"), 70, 0, GeoRegion::North, 0);

    pool.check_all_sync();

    // idle: 0+50+10*2+0 = 70
    // busy: 0+50+70*2+0 = 190
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://relay-idle.example.com/");
}

void test_relay_pool_load_filter() {
    std::cout << "[test] RelayPool load_filter (overloaded relay excluded)" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    cfg.load_filter_threshold = 80;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://relay-overload.example.com/"));
    pool.add_relay(make_url("https://relay-normal.example.com/"));

    // overload RTT 更低（若无 load 过滤，overload 会胜出）
    probe.set_result("https://relay-overload.example.com/", true, 30);
    probe.set_result("https://relay-normal.example.com/", true, 80);

    pool.set_relay_metrics(make_url("https://relay-overload.example.com/"), 95, 0, GeoRegion::North, 0);
    pool.set_relay_metrics(make_url("https://relay-normal.example.com/"), 20, 0, GeoRegion::North, 0);

    pool.check_all_sync();

    // overload: load=95 > 80 → 被第一级过滤排除
    // normal: load=20 → 通过过滤
    // 虽然 overload score(30+95*2=220) < normal score(80+20*2=120) 不成立
    // 实际 normal=120 < overload=220，但即使 overload 分数更低也会被过滤
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://relay-normal.example.com/");
}

void test_relay_pool_load_filter_degrade_when_all_overloaded() {
    std::cout << "[test] RelayPool load_filter degrade when all overloaded" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    cfg.load_filter_threshold = 80;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://relay-a.example.com/"));
    pool.add_relay(make_url("https://relay-b.example.com/"));

    probe.set_result("https://relay-a.example.com/", true, 50);
    probe.set_result("https://relay-b.example.com/", true, 80);

    // 两个都过载
    pool.set_relay_metrics(make_url("https://relay-a.example.com/"), 90, 0, GeoRegion::North, 0);
    pool.set_relay_metrics(make_url("https://relay-b.example.com/"), 95, 0, GeoRegion::North, 0);

    pool.check_all_sync();

    // 全池过载 → 降级到第二级（usable，忽略 load）
    // relay-a: 0+50+90*2 = 230
    // relay-b: 0+80+95*2 = 270
    // 选 relay-a
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://relay-a.example.com/");
}

void test_relay_pool_probe_carries_metrics() {
    std::cout << "[test] RelayPool probe carries load/uplink metrics" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://relay1.example.com/"));
    probe.set_result_with_metrics("https://relay1.example.com/", true, 50,
                                  /*load=*/42, /*uplink=*/50000000);

    pool.check_one(make_url("https://relay1.example.com/"));

    auto all = pool.get_all_relays();
    CHECK(all.size() == 1);
    CHECK(all[0].health == RelayHealth::Healthy);
    CHECK(all[0].last_rtt == std::chrono::milliseconds(50));
    CHECK(all[0].load_percent == 42);
    CHECK(all[0].uplink_bps == 50000000);
}

void test_relay_pool_active_set() {
    std::cout << "[test] RelayPool active_set" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    cfg.active_set_size = 3;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://r1.example.com/"));
    pool.add_relay(make_url("https://r2.example.com/"));
    pool.add_relay(make_url("https://r3.example.com/"));
    pool.add_relay(make_url("https://r4.example.com/"));
    pool.add_relay(make_url("https://r5.example.com/"));

    // 所有 relay 健康，RTT 递增
    probe.set_result("https://r1.example.com/", true, 10);
    probe.set_result("https://r2.example.com/", true, 20);
    probe.set_result("https://r3.example.com/", true, 30);
    probe.set_result("https://r4.example.com/", true, 40);
    probe.set_result("https://r5.example.com/", true, 50);

    pool.check_all_sync();

    auto active = pool.get_active_set();
    CHECK(active.size() == 3);
    // 按 score 升序，前 3 个应是 r1, r2, r3
    CHECK(active[0].url.url() == "https://r1.example.com/");
    CHECK(active[1].url.url() == "https://r2.example.com/");
    CHECK(active[2].url.url() == "https://r3.example.com/");
}

void test_relay_pool_active_set_size_clamped() {
    std::cout << "[test] RelayPool active_set size clamped" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.active_set_size = 5;  // 大于池大小
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://r1.example.com/"));
    pool.add_relay(make_url("https://r2.example.com/"));

    probe.set_result("https://r1.example.com/", true, 10);
    probe.set_result("https://r2.example.com/", true, 20);
    pool.check_all_sync();

    auto active = pool.get_active_set();
    CHECK(active.size() == 2);  // 不会超过池大小
}

void test_relay_pool_geo_overrides_rtt() {
    std::cout << "[test] RelayPool geo penalty can override RTT advantage" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://relay-far-fast.example.com/"));
    pool.add_relay(make_url("https://relay-near-slow.example.com/"));

    // far-fast: 跨区域但 RTT 低
    probe.set_result("https://relay-far-fast.example.com/", true, 20);
    pool.set_relay_metrics(make_url("https://relay-far-fast.example.com/"), 0, 0, GeoRegion::East, 0);

    // near-slow: 同区域但 RTT 高
    probe.set_result("https://relay-near-slow.example.com/", true, 100);
    pool.set_relay_metrics(make_url("https://relay-near-slow.example.com/"), 0, 0, GeoRegion::North, 0);

    pool.check_all_sync();

    // far-fast: 0+20+0+0+200(跨区域) = 220
    // near-slow: 0+100+0+0+0(同区域) = 100
    // 同区域 RTT 高的反而胜出
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://relay-near-slow.example.com/");
}

// ============================================================================
// 11. 边界情况测试
// ============================================================================

void test_relay_pool_max_relays() {
    std::cout << "[test] RelayPool max_relays" << std::endl;
    RelayPoolConfig cfg;
    cfg.max_relays = 3;
    RelayPool pool(cfg);
    pool.add_relay(make_url("https://relay1.example.com/"));
    pool.add_relay(make_url("https://relay2.example.com/"));
    pool.add_relay(make_url("https://relay3.example.com/"));
    pool.add_relay(make_url("https://relay4.example.com/"));

    // 不应超过 max_relays（虽然实现可能宽松，但至少不超过太多）
    CHECK(pool.size() <= 4);
}

void test_relay_pool_empty_check_all() {
    std::cout << "[test] RelayPool empty check_all" << std::endl;
    RelayPool pool;
    pool.check_all_sync();  // 不应崩溃
    CHECK(pool.empty());
}

void test_relay_pool_record_nonexistent() {
    std::cout << "[test] RelayPool record nonexistent" << std::endl;
    RelayPool pool;
    // 记录不存在的 URL，不应崩溃
    pool.record_success(make_url("https://nonexistent.example.com/"));
    pool.record_failure(make_url("https://nonexistent.example.com/"));
    CHECK(pool.empty());
}

// ============================================================================
// 12. v2.0 Phase 1 交付物 5：层级化 Relay 架构测试
// ============================================================================

void test_relay_role_name() {
    std::cout << "[test] relay_role_name enum" << std::endl;
    CHECK(relay_role_name(RelayRole::Region) == std::string("region"));
    CHECK(relay_role_name(RelayRole::Backbone) == std::string("backbone"));
}

void test_relay_entry_default_role() {
    std::cout << "[test] RelayEntry default role is Region" << std::endl;
    RelayEntry e(make_url("https://r.example.com/"));
    CHECK(e.role == RelayRole::Region);
}

void test_set_relay_role_success() {
    std::cout << "[test] set_relay_role success" << std::endl;
    RelayPool pool;
    pool.add_relay(make_url("https://backbone.example.com/"));
    CHECK(pool.set_relay_role(make_url("https://backbone.example.com/"), RelayRole::Backbone));
    auto all = pool.get_all_relays();
    CHECK(all.size() == 1);
    CHECK(all[0].role == RelayRole::Backbone);
}

void test_set_relay_role_nonexistent() {
    std::cout << "[test] set_relay_role returns false for nonexistent URL" << std::endl;
    RelayPool pool;
    pool.add_relay(make_url("https://r1.example.com/"));
    CHECK(!pool.set_relay_role(make_url("https://nonexistent.example.com/"), RelayRole::Backbone));
}

void test_relay_load_report_defaults() {
    std::cout << "[test] RelayLoadReport default values" << std::endl;
    RelayLoadReport rpt;
    CHECK(rpt.role == RelayRole::Region);
    CHECK(rpt.region == GeoRegion::Unknown);
    CHECK(rpt.connections == 0);
    CHECK(rpt.bytes_in == 0);
    CHECK(rpt.bytes_out == 0);
    CHECK(rpt.load_percent == 0);
    CHECK(rpt.uplink_bps == 0);
}

void test_update_load_reports_updates_fields() {
    std::cout << "[test] update_load_reports updates fields" << std::endl;
    RelayPool pool;
    pool.add_relay(make_url("https://r1.example.com/"));
    pool.add_relay(make_url("https://r2.example.com/"));

    std::vector<RelayLoadReport> reports;
    RelayLoadReport r1;
    r1.url = make_url("https://r1.example.com/");
    r1.role = RelayRole::Backbone;
    r1.region = GeoRegion::Backbone;
    r1.load_percent = 65;
    r1.uplink_bps = 100000000;
    r1.connections = 42;
    reports.push_back(r1);

    std::size_t updated = pool.update_load_reports(reports);
    CHECK(updated == 1);

    auto all = pool.get_all_relays();
    CHECK(all.size() == 2);
    // 找到 r1
    bool found = false;
    for (const auto &e : all) {
        if (e.url.url() == "https://r1.example.com/") {
            CHECK(e.role == RelayRole::Backbone);
            CHECK(e.region == GeoRegion::Backbone);
            CHECK(e.load_percent == 65);
            CHECK(e.uplink_bps == 100000000);
            found = true;
        }
    }
    CHECK(found);
}

void test_update_load_reports_ignores_unmatched() {
    std::cout << "[test] update_load_reports ignores unmatched URLs" << std::endl;
    RelayPool pool;
    pool.add_relay(make_url("https://r1.example.com/"));

    std::vector<RelayLoadReport> reports;
    RelayLoadReport r1;
    r1.url = make_url("https://r1.example.com/");
    r1.load_percent = 50;
    reports.push_back(r1);
    RelayLoadReport r2;
    r2.url = make_url("https://nonexistent.example.com/");
    r2.load_percent = 99;
    reports.push_back(r2);

    std::size_t updated = pool.update_load_reports(reports);
    CHECK(updated == 1);  // 仅 r1 更新成功
}

void test_cascading_prefers_local_region() {
    std::cout << "[test] cascading select prefers local Region relay" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    cfg.enable_cascading_select = true;
    cfg.active_set_size = 1;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://backbone-fast.example.com/"));
    pool.add_relay(make_url("https://local-slow.example.com/"));

    // backbone-fast: Backbone 角色,RTT 更低
    probe.set_result("https://backbone-fast.example.com/", true, 10);
    pool.set_relay_metrics(make_url("https://backbone-fast.example.com/"), 0, 0, GeoRegion::Backbone, 0);
    pool.set_relay_role(make_url("https://backbone-fast.example.com/"), RelayRole::Backbone);

    // local-slow: Region 角色,同区域,RTT 更高
    probe.set_result("https://local-slow.example.com/", true, 100);
    pool.set_relay_metrics(make_url("https://local-slow.example.com/"), 0, 0, GeoRegion::North, 0);

    pool.check_all_sync();

    // 级联第一级:本区域 Region 命中,即使 RTT 高也优先
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://local-slow.example.com/");
}

void test_cascading_falls_back_to_backbone() {
    std::cout << "[test] cascading select falls back to Backbone when local Region unavailable" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    cfg.enable_cascading_select = true;
    cfg.active_set_size = 1;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://local-dead.example.com/"));
    pool.add_relay(make_url("https://backbone-good.example.com/"));

    // local-dead: Region 角色,同区域,但探测失败(Unhealthy)
    probe.set_result("https://local-dead.example.com/", false);
    pool.set_relay_metrics(make_url("https://local-dead.example.com/"), 0, 0, GeoRegion::North, 0);

    // backbone-good: Backbone 角色,健康
    probe.set_result("https://backbone-good.example.com/", true, 30);
    pool.set_relay_metrics(make_url("https://backbone-good.example.com/"), 0, 0, GeoRegion::Backbone, 0);
    pool.set_relay_role(make_url("https://backbone-good.example.com/"), RelayRole::Backbone);

    pool.check_all_sync();

    // 第一级本区域 Region 无可用(local-dead 不可用) → 第二级 Backbone 命中
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://backbone-good.example.com/");
}

void test_cascading_falls_back_to_global_region() {
    std::cout << "[test] cascading select falls back to global Region when Backbone unavailable" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    cfg.enable_cascading_select = true;
    cfg.active_set_size = 1;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://backbone-dead.example.com/"));
    pool.add_relay(make_url("https://east-relay.example.com/"));

    // backbone-dead: Backbone 角色,但不可用
    probe.set_result("https://backbone-dead.example.com/", false);
    pool.set_relay_metrics(make_url("https://backbone-dead.example.com/"), 0, 0, GeoRegion::Backbone, 0);
    pool.set_relay_role(make_url("https://backbone-dead.example.com/"), RelayRole::Backbone);

    // east-relay: Region 角色,跨区域(East),健康
    probe.set_result("https://east-relay.example.com/", true, 80);
    pool.set_relay_metrics(make_url("https://east-relay.example.com/"), 0, 0, GeoRegion::East, 0);

    pool.check_all_sync();

    // 第一级(本区域 Region)空 → 第二级 Backbone 不可用 → 第三级全局 Region 命中
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://east-relay.example.com/");
}

void test_cascading_degrades_when_all_overloaded() {
    std::cout << "[test] cascading select degrades when all relays overloaded" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    cfg.enable_cascading_select = true;
    cfg.load_filter_threshold = 80;
    cfg.active_set_size = 1;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://local-overload.example.com/"));
    pool.add_relay(make_url("https://backbone-overload.example.com/"));

    // 两个 relay 都健康但过载(load > 80)
    probe.set_result("https://local-overload.example.com/", true, 50);
    pool.set_relay_metrics(make_url("https://local-overload.example.com/"), 95, 0, GeoRegion::North, 0);

    probe.set_result("https://backbone-overload.example.com/", true, 30);
    pool.set_relay_metrics(make_url("https://backbone-overload.example.com/"), 90, 0, GeoRegion::Backbone, 0);
    pool.set_relay_role(make_url("https://backbone-overload.example.com/"), RelayRole::Backbone);

    pool.check_all_sync();

    // 第一/二/三级(load<=80 过滤)都空 → 第四级 usable(忽略 load) 命中
    // local-overload: 0+50+95*2 = 240
    // backbone-overload: 0+30+90*2 = 210 (Backbone 不算跨区域)
    // 选 backbone-overload (score 更低)
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://backbone-overload.example.com/");
}

void test_cascading_disabled_falls_back_to_global() {
    std::cout << "[test] cascading disabled falls back to global score strategy" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    cfg.enable_cascading_select = false;  // 关闭级联
    cfg.active_set_size = 1;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://local-slow.example.com/"));
    pool.add_relay(make_url("https://backbone-fast.example.com/"));

    // local-slow: Region,同区域,RTT 高
    probe.set_result("https://local-slow.example.com/", true, 100);
    pool.set_relay_metrics(make_url("https://local-slow.example.com/"), 0, 0, GeoRegion::North, 0);

    // backbone-fast: Backbone,RTT 低
    probe.set_result("https://backbone-fast.example.com/", true, 10);
    pool.set_relay_metrics(make_url("https://backbone-fast.example.com/"), 0, 0, GeoRegion::Backbone, 0);
    pool.set_relay_role(make_url("https://backbone-fast.example.com/"), RelayRole::Backbone);

    pool.check_all_sync();

    // 关闭级联后,按全局 score 选择:
    // local-slow: 0+100+0+0+0(同区域) = 100
    // backbone-fast: 0+10+0+0+0(Backbone 不算跨区域) = 10
    // 选 backbone-fast
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://backbone-fast.example.com/");
}

void test_cascading_unknown_region_disables_cascading() {
    std::cout << "[test] local_region=Unknown disables cascading (backward compat)" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::Unknown;  // 未知区域,不启用级联
    cfg.enable_cascading_select = true;     // 即使开启也无效
    cfg.active_set_size = 1;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    pool.add_relay(make_url("https://local-slow.example.com/"));
    pool.add_relay(make_url("https://backbone-fast.example.com/"));

    probe.set_result("https://local-slow.example.com/", true, 100);
    pool.set_relay_metrics(make_url("https://local-slow.example.com/"), 0, 0, GeoRegion::North, 0);

    probe.set_result("https://backbone-fast.example.com/", true, 10);
    pool.set_relay_metrics(make_url("https://backbone-fast.example.com/"), 0, 0, GeoRegion::Backbone, 0);
    pool.set_relay_role(make_url("https://backbone-fast.example.com/"), RelayRole::Backbone);

    pool.check_all_sync();

    // local_region=Unknown → 级联不生效,走原全局策略
    // local-slow: 0+100+0+0+0(Unknown 不算跨区域) = 100
    // backbone-fast: 0+10+0+0+0 = 10
    // 选 backbone-fast
    auto best = pool.select_best();
    CHECK(best.has_value());
    CHECK(best->url.url() == "https://backbone-fast.example.com/");
}

void test_failover_callback_triggered_on_threshold() {
    std::cout << "[test] failover callback triggered on failure threshold" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    cfg.enable_cascading_select = true;
    cfg.active_set_size = 3;
    cfg.failover_failure_threshold = 3;
    cfg.breaker_config.failure_threshold = 10;  // 拉高熔断阈值,避免干扰
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    // 三个本区域 Region relay:r1(主用), r2, r3
    pool.add_relay(make_url("https://r1.example.com/"));
    pool.add_relay(make_url("https://r2.example.com/"));
    pool.add_relay(make_url("https://r3.example.com/"));

    probe.set_result("https://r1.example.com/", true, 10);
    probe.set_result("https://r2.example.com/", true, 20);
    probe.set_result("https://r3.example.com/", true, 30);
    pool.set_relay_metrics(make_url("https://r1.example.com/"), 0, 0, GeoRegion::North, 0);
    pool.set_relay_metrics(make_url("https://r2.example.com/"), 0, 0, GeoRegion::North, 0);
    pool.set_relay_metrics(make_url("https://r3.example.com/"), 0, 0, GeoRegion::North, 0);
    pool.check_all_sync();

    // 先调用 select_best 选定主用并填充活跃集缓存
    // （failover 依赖缓存中按原始 score 排序的活跃集，r1<r2<r3）
    auto primary = pool.select_best();
    CHECK(primary.has_value());
    CHECK(primary->url.url() == "https://r1.example.com/");

    // 注册 failover 回调
    std::atomic<int> fo_count{0};
    std::string from_url, to_url, reason;
    pool.set_failover_callback([&](const base::RelayUrl &from,
                                   const base::RelayUrl &to,
                                   const std::string &r) {
        ++fo_count;
        from_url = from.url();
        to_url = to.url();
        reason = r;
    });

    // 主用是 r1(score 最低)。连续失败 3 次 → 触发 failover
    pool.record_failure(make_url("https://r1.example.com/"));
    CHECK(fo_count.load() == 0);  // 第 1 次,未触发
    pool.record_failure(make_url("https://r1.example.com/"));
    CHECK(fo_count.load() == 0);  // 第 2 次,未触发
    pool.record_failure(make_url("https://r1.example.com/"));
    CHECK(fo_count.load() == 1);  // 第 3 次,触发

    CHECK(from_url == "https://r1.example.com/");
    CHECK(to_url == "https://r2.example.com/");  // 活跃集次优
    CHECK(reason == "failover_failure_threshold_reached");
}

void test_exhausted_callback_triggered() {
    std::cout << "[test] exhausted callback triggered when active set depleted" << std::endl;
    MockProbe probe;
    RelayPoolConfig cfg;
    cfg.degraded_rtt_threshold = std::chrono::milliseconds(1000);
    cfg.local_region = GeoRegion::North;
    cfg.enable_cascading_select = true;
    cfg.active_set_size = 2;
    cfg.failover_failure_threshold = 2;
    cfg.breaker_config.failure_threshold = 10;
    RelayPool pool(cfg, [&probe](const base::RelayUrl &url) { return probe(url); });

    // 两个本区域 Region relay
    pool.add_relay(make_url("https://r1.example.com/"));
    pool.add_relay(make_url("https://r2.example.com/"));

    probe.set_result("https://r1.example.com/", true, 10);
    probe.set_result("https://r2.example.com/", true, 20);
    pool.set_relay_metrics(make_url("https://r1.example.com/"), 0, 0, GeoRegion::North, 0);
    pool.set_relay_metrics(make_url("https://r2.example.com/"), 0, 0, GeoRegion::North, 0);
    pool.check_all_sync();

    // 先调用 select_best 选定主用并填充活跃集缓存
    // （failover 依赖缓存中按原始 score 排序的活跃集，r1<r2）
    auto primary = pool.select_best();
    CHECK(primary.has_value());
    CHECK(primary->url.url() == "https://r1.example.com/");

    std::atomic<int> fo_count{0};
    std::atomic<int> ex_count{0};
    pool.set_failover_callback([&](const base::RelayUrl &,
                                   const base::RelayUrl &,
                                   const std::string &) { ++fo_count; });
    pool.set_active_set_exhausted_callback([&]() { ++ex_count; });

    // r1 主用,失败 2 次 → failover 到 r2
    pool.record_failure(make_url("https://r1.example.com/"));
    pool.record_failure(make_url("https://r1.example.com/"));
    CHECK(fo_count.load() == 1);
    CHECK(ex_count.load() == 0);

    // 重置 r1 的失败计数(模拟新主用 r2 开始失败)
    // 注意:advance_active_idx_locked 推进到 r2 后,再失败 r2 会触发新一轮 failover
    // r2 是活跃集最后一个(idx=1),再推进就耗尽
    pool.record_failure(make_url("https://r2.example.com/"));
    pool.record_failure(make_url("https://r2.example.com/"));
    // r2 失败 2 次触发 advance,但活跃集已耗尽 → 触发 exhausted
    CHECK(ex_count.load() == 1);
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << " test_relay_pool (P5-D-5)" << std::endl;
    std::cout << "========================================" << std::endl;

    // 1. 枚举
    test_relay_health_name();
    test_circuit_state_name();

    // 2. CircuitBreaker
    test_circuit_breaker_initial();
    test_circuit_breaker_stays_closed_on_success();
    test_circuit_breaker_opens_after_threshold();
    test_circuit_breaker_resets_on_success();
    test_circuit_breaker_half_open_after_cooldown();
    test_circuit_breaker_closes_after_half_open_success();
    test_circuit_breaker_reopens_on_half_open_failure();

    // 3. RelayEntry
    test_relay_entry_score();
    test_relay_entry_is_usable();

    // 4. RelayPool 基础
    test_relay_pool_empty();
    test_relay_pool_add_and_get();
    test_relay_pool_remove();
    test_relay_pool_remove_pinned();
    test_relay_pool_select_best_initial();

    // 5. 健康检查
    test_relay_pool_check_one_success();
    test_relay_pool_check_one_failure();
    test_relay_pool_check_all();
    test_relay_pool_select_best_by_health();
    test_relay_pool_degraded_threshold();

    // 6. record_success/failure
    test_relay_pool_record_success();
    test_relay_pool_record_failure_to_unhealthy();

    // 7. FailoverController
    test_failover_controller_initial();
    test_failover_controller_trigger_no_relay();
    test_failover_controller_trigger_first();
    test_failover_controller_switch_on_change();
    test_failover_controller_callback();
    test_failover_controller_disabled();
    test_failover_controller_clear_history();

    // 8. 综合
    test_relay_pool_failover_scenario();

    // 9. 配置
    test_relay_pool_config_defaults();
    test_circuit_breaker_config_defaults();

    // 10. v2.0 Phase 1：多维选择
    test_geo_region_name();
    test_is_cross_region();
    test_relay_score_weights_defaults();
    test_relay_entry_score_backward_compat();
    test_relay_entry_score_multi_dim();
    test_relay_entry_score_cross_region();
    test_relay_pool_config_multi_dim_defaults();
    test_relay_pool_set_local_region();
    test_relay_pool_set_relay_metrics();
    test_relay_pool_select_best_by_geo();
    test_relay_pool_select_best_by_geo_distance();
    test_relay_pool_select_best_by_load();
    test_relay_pool_load_filter();
    test_relay_pool_load_filter_degrade_when_all_overloaded();
    test_relay_pool_probe_carries_metrics();
    test_relay_pool_active_set();
    test_relay_pool_active_set_size_clamped();
    test_relay_pool_geo_overrides_rtt();

    // 11. 边界
    test_relay_pool_max_relays();
    test_relay_pool_empty_check_all();
    test_relay_pool_record_nonexistent();

    // 12. v2.0 Phase 1 交付物 5：层级化 Relay 架构
    test_relay_role_name();
    test_relay_entry_default_role();
    test_set_relay_role_success();
    test_set_relay_role_nonexistent();
    test_relay_load_report_defaults();
    test_update_load_reports_updates_fields();
    test_update_load_reports_ignores_unmatched();
    test_cascading_prefers_local_region();
    test_cascading_falls_back_to_backbone();
    test_cascading_falls_back_to_global_region();
    test_cascading_degrades_when_all_overloaded();
    test_cascading_disabled_falls_back_to_global();
    test_cascading_unknown_region_disables_cascading();
    test_failover_callback_triggered_on_threshold();
    test_exhausted_callback_triggered();

    std::cout << "========================================" << std::endl;
    std::cout << " Total: " << total << ", Failed: " << failed << std::endl;
    std::cout << "========================================" << std::endl;

    return failed == 0 ? 0 : 1;
}
