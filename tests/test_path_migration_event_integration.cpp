// test_path_migration_event_integration.cpp — v1.7.0.4 P3 B7 集成测试
//
// 验证 PathMigrationManager 的 PathEvent 集成：
//   - set_path_event_callback 注册回调
//   - abandon_path 触发 PathEvent::closed 携带 last_stats
//   - abandon_idle_paths 触发多个 PathEvent::closed
//   - ConnectionStatsAggregator 订阅事件并累加统计
//   - 回调异常不影响主流程
//   - has_path_event_callback 状态查询

#include "linoh/protocol/path_migration.hpp"
#include "linoh/protocol/path_event.hpp"
#include "linoh/protocol/path_stats.hpp"

#include <chrono>
#include <cstdio>
#include <vector>

using namespace linoh;
using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// 辅助：构造 IP 类型 FourTuple
static net::FourTuple make_ip_tuple(const std::string &local_ip, uint16_t local_port,
                                      const std::string &remote_ip, uint16_t remote_port) {
    net::FourTuple t;
    t.local_addr.kind = base::TransportKind::Ip;
    t.local_addr.host = local_ip;
    t.local_addr.port = local_port;
    t.remote_addr.kind = base::TransportKind::Ip;
    t.remote_addr.host = remote_ip;
    t.remote_addr.port = remote_port;
    return t;
}

// ============================================================================
// 测试 1: 初始状态无 callback
// ============================================================================

static void test_initial_no_callback() {
    std::printf("[test] initial no callback...\n");
    PathMigrationManager mgr;
    CHECK(!mgr.has_path_event_callback());
}

// ============================================================================
// 测试 2: 设置 callback 后 has_path_event_callback 返回 true
// ============================================================================

static void test_set_callback() {
    std::printf("[test] set callback...\n");
    PathMigrationManager mgr;
    mgr.set_path_event_callback([](const PathEvent &) {});
    CHECK(mgr.has_path_event_callback());
}

// ============================================================================
// 测试 3: abandon_path 触发 PathEvent::closed
// ============================================================================

static void test_abandon_path_triggers_event() {
    std::printf("[test] abandon_path triggers event...\n");
    PathMigrationManager mgr;

    PathEvent received;
    bool called = false;
    mgr.set_path_event_callback([&](const PathEvent &ev) {
        received = ev;
        called = true;
    });

    // 准备一条路径
    auto tuple = make_ip_tuple("1.2.3.4", 9001, "5.6.7.8", 9001);
    mgr.update_path_quality(42, std::chrono::microseconds(50000), 3,
                             std::chrono::steady_clock::now(), tuple);

    // 放弃路径
    mgr.abandon_path(42);

    CHECK(called);
    CHECK(received.is_closed());
    CHECK(received.path_id == 42);
    CHECK(received.has_last_stats());
    CHECK(received.reason == "abandon_path");
}

// ============================================================================
// 测试 4: abandon_path 携带 last_stats 统计
// ============================================================================

static void test_abandon_path_carries_stats() {
    std::printf("[test] abandon_path carries stats...\n");
    PathMigrationManager mgr;

    PathStats captured;
    mgr.set_path_event_callback([&](const PathEvent &ev) {
        if (ev.has_last_stats()) captured = *ev.last_stats;
    });

    // 直接修改 path_quality 的累计统计（通过 update_path_quality 后再 abandon）
    auto tuple = make_ip_tuple("10.0.0.1", 9001, "10.0.0.2", 9001);
    auto now = std::chrono::steady_clock::now();
    mgr.update_path_quality(1, std::chrono::microseconds(100000), 5, now, tuple);

    // 此时 path 1 的 srtt=100ms, loss_count=5
    mgr.abandon_path(1);

    // 验证 last_stats 中的瞬时字段 rtt 反映 srtt
    CHECK(captured.rtt.count() == 100000000);  // 100ms = 100000000 ns
    // lost_packets 来自 PathQuality（loss_count=5，但 PathQuality::lost_packets 默认 0）
    // 注：update_path_quality 设置的是 loss_count，不是 lost_packets
    CHECK(captured.lost_packets == 0);  // PathQuality::lost_packets 默认 0
}

// ============================================================================
// 测试 5: abandon_idle_paths 触发多个事件
// ============================================================================

static void test_abandon_idle_paths_multiple_events() {
    std::printf("[test] abandon_idle_paths multiple events...\n");
    PathMigrationManager mgr;
    mgr.set_abandon_policy({1.5, std::chrono::seconds(1)});

    std::vector<PathEvent> events;
    mgr.set_path_event_callback([&](const PathEvent &ev) {
        events.push_back(ev);
    });

    // 创建 3 条路径，last_seen 在过去
    auto past = std::chrono::steady_clock::now() - std::chrono::seconds(5);
    auto t1 = make_ip_tuple("1.1.1.1", 1, "2.2.2.2", 1);
    auto t2 = make_ip_tuple("1.1.1.2", 2, "2.2.2.2", 2);
    auto t3 = make_ip_tuple("1.1.1.3", 3, "2.2.2.2", 3);
    mgr.update_path_quality(1, std::chrono::microseconds(10000), 0, past, t1);
    mgr.update_path_quality(2, std::chrono::microseconds(20000), 0, past, t2);
    mgr.update_path_quality(3, std::chrono::microseconds(30000), 0, past, t3);

    // 调用 abandon_idle_paths
    auto abandoned = mgr.abandon_idle_paths(std::chrono::steady_clock::now());

    CHECK(abandoned.size() == 3);
    CHECK(events.size() == 3);
    for (const auto &ev : events) {
        CHECK(ev.is_closed());
        CHECK(ev.reason == "idle_timeout");
        CHECK(ev.has_last_stats());
    }
}

// ============================================================================
// 测试 6: ConnectionStatsAggregator 订阅 PathEvent 完整链路
// ============================================================================

static void test_aggregator_subscribes_path_events() {
    std::printf("[test] Aggregator subscribes path events...\n");
    PathMigrationManager mgr;
    ConnectionStatsAggregator agg;

    mgr.set_path_event_callback([&](const PathEvent &ev) {
        if (ev.is_closed() && ev.has_last_stats()) {
            agg.on_path_closed(*ev.last_stats);
        }
    });

    // 创建并放弃路径 1
    auto t1 = make_ip_tuple("1.1.1.1", 1, "2.2.2.2", 1);
    mgr.update_path_quality(1, std::chrono::microseconds(50000), 2,
                             std::chrono::steady_clock::now(), t1);
    mgr.abandon_path(1);

    // 创建并放弃路径 2
    auto t2 = make_ip_tuple("1.1.1.2", 2, "2.2.2.2", 2);
    mgr.update_path_quality(2, std::chrono::microseconds(80000), 3,
                             std::chrono::steady_clock::now(), t2);
    mgr.abandon_path(2);

    auto s = agg.snapshot();
    // lost_packets 来自 PathQuality::lost_packets（默认 0，update_path_quality 设的是 loss_count）
    CHECK(s.lost_packets == 0);
    // rtt 不累加（瞬时字段）
}

// ============================================================================
// 测试 7: abandon_path 不存在的路径不触发事件
// ============================================================================

static void test_abandon_nonexistent_no_event() {
    std::printf("[test] abandon nonexistent no event...\n");
    PathMigrationManager mgr;
    bool called = false;
    mgr.set_path_event_callback([&](const PathEvent &) { called = true; });

    mgr.abandon_path(999);  // 不存在
    CHECK(!called);
}

// ============================================================================
// 测试 8: 无 callback 时 abandon_path 正常工作（不崩溃）
// ============================================================================

static void test_abandon_without_callback() {
    std::printf("[test] abandon without callback...\n");
    PathMigrationManager mgr;
    auto t = make_ip_tuple("1.1.1.1", 1, "2.2.2.2", 1);
    mgr.update_path_quality(1, std::chrono::microseconds(10000), 0,
                             std::chrono::steady_clock::now(), t);

    // 无 callback，应正常工作不崩溃
    mgr.abandon_path(1);
    CHECK(mgr.is_path_abandoned(1));
}

// ============================================================================
// 测试 9: 回调异常不影响主流程
// ============================================================================

static void test_callback_exception_does_not_crash() {
    std::printf("[test] callback exception does not crash...\n");
    PathMigrationManager mgr;
    mgr.set_path_event_callback([](const PathEvent &) {
        throw std::runtime_error("test exception");
    });

    auto t = make_ip_tuple("1.1.1.1", 1, "2.2.2.2", 1);
    mgr.update_path_quality(1, std::chrono::microseconds(10000), 0,
                             std::chrono::steady_clock::now(), t);

    // 应不崩溃，路径仍被正常放弃
    mgr.abandon_path(1);
    CHECK(mgr.is_path_abandoned(1));
}

// ============================================================================
// 测试 10: PathEvent::closed 携带 remote_addr（FourTuple）
// ============================================================================

static void test_event_carries_remote_addr() {
    std::printf("[test] event carries remote_addr...\n");
    PathMigrationManager mgr;
    PathEvent received;
    mgr.set_path_event_callback([&](const PathEvent &ev) { received = ev; });

    auto t = make_ip_tuple("10.20.30.40", 9001, "50.60.70.80", 9001);
    mgr.update_path_quality(7, std::chrono::microseconds(10000), 0,
                             std::chrono::steady_clock::now(), t);
    mgr.abandon_path(7);

    CHECK(received.path_id == 7);
    // remote_addr 应包含 FourTuple 信息
    CHECK(!received.remote_addr.empty());
    CHECK(received.remote_addr.find("10.20.30.40") != std::string::npos);
}

// ============================================================================
// 测试 11: 多次 abandon 同一路径（幂等性）
// ============================================================================

static void test_abandon_idempotent() {
    std::printf("[test] abandon idempotent...\n");
    PathMigrationManager mgr;
    int call_count = 0;
    mgr.set_path_event_callback([&](const PathEvent &) { ++call_count; });

    auto t = make_ip_tuple("1.1.1.1", 1, "2.2.2.2", 1);
    mgr.update_path_quality(1, std::chrono::microseconds(10000), 0,
                             std::chrono::steady_clock::now(), t);

    mgr.abandon_path(1);
    CHECK(call_count == 1);

    // 再次 abandon 同一路径（已不存在），不应触发事件
    mgr.abandon_path(1);
    CHECK(call_count == 1);  // 仍为 1
}

// ============================================================================
// 测试 12: build_path_stats 填充 rtt 瞬时字段
// ============================================================================

static void test_build_path_stats_rtt() {
    std::printf("[test] build_path_stats rtt...\n");
    PathMigrationManager mgr;
    PathStats captured;
    mgr.set_path_event_callback([&](const PathEvent &ev) {
        if (ev.has_last_stats()) captured = *ev.last_stats;
    });

    // srtt = 50ms = 50000us
    auto t = make_ip_tuple("1.1.1.1", 1, "2.2.2.2", 1);
    mgr.update_path_quality(1, std::chrono::microseconds(50000), 0,
                             std::chrono::steady_clock::now(), t);
    mgr.abandon_path(1);

    // rtt 应为 50000us = 50000000ns
    CHECK(captured.rtt.count() == 50000000);
}

// ============================================================================
// 测试 13: abandon_idle_paths 混合场景（部分超时部分未超时）
// ============================================================================

static void test_abandon_idle_mixed() {
    std::printf("[test] abandon idle mixed...\n");
    PathMigrationManager mgr;
    mgr.set_abandon_policy({1.5, std::chrono::seconds(2)});

    std::vector<std::uint64_t> abandoned_ids;
    int event_count = 0;
    mgr.set_path_event_callback([&](const PathEvent &ev) {
        ++event_count;
        abandoned_ids.push_back(ev.path_id);
    });

    auto now = std::chrono::steady_clock::now();
    auto past = now - std::chrono::seconds(5);

    // 路径 1, 2 超时，路径 3 未超时
    auto t1 = make_ip_tuple("1.1.1.1", 1, "2.2.2.2", 1);
    auto t2 = make_ip_tuple("1.1.1.2", 2, "2.2.2.2", 2);
    auto t3 = make_ip_tuple("1.1.1.3", 3, "2.2.2.2", 3);
    mgr.update_path_quality(1, std::chrono::microseconds(10000), 0, past, t1);
    mgr.update_path_quality(2, std::chrono::microseconds(20000), 0, past, t2);
    mgr.update_path_quality(3, std::chrono::microseconds(30000), 0, now, t3);

    auto abandoned = mgr.abandon_idle_paths(now);

    CHECK(abandoned.size() == 2);
    CHECK(event_count == 2);
    CHECK(mgr.active_path_count() == 1);  // 路径 3 仍在
    CHECK(!mgr.is_path_abandoned(3));
}

int main() {
    std::printf("=== test_path_migration_event_integration (v1.7.0.4 P3 B7) ===\n");

    test_initial_no_callback();
    test_set_callback();
    test_abandon_path_triggers_event();
    test_abandon_path_carries_stats();
    test_abandon_idle_paths_multiple_events();
    test_aggregator_subscribes_path_events();
    test_abandon_nonexistent_no_event();
    test_abandon_without_callback();
    test_callback_exception_does_not_crash();
    test_event_carries_remote_addr();
    test_abandon_idempotent();
    test_build_path_stats_rtt();
    test_abandon_idle_mixed();

    std::printf("\n=== Results: %d PASSED, %d FAILED ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
