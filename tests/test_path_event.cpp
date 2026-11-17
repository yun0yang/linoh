// test_path_event.cpp — B7/B8 路径事件枚举测试（v1.7.0.4 P3）
//
// 覆盖：
//   - PathEvent::Type 枚举（kOpened/kClosed/kSelected）
//   - PathEvent::opened 工厂方法
//   - PathEvent::closed 工厂方法（携带 last_stats）
//   - PathEvent::selected 工厂方法
//   - is_opened/is_closed/is_selected/has_last_stats 判断
//   - type_str 转字符串
//   - PathEventCallback 分发
//   - last_stats 携带与访问

#include "linoh/protocol/path_event.hpp"

#include <chrono>
#include <cstdio>
#include <functional>
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
// PathEvent::opened 测试
// ============================================================================

static void test_opened_basic() {
    std::printf("[test] PathEvent::opened basic...\n");
    auto ev = PathEvent::opened(42, "1.2.3.4:9001", "0.0.0.0:9001");
    CHECK(ev.type == PathEvent::Type::kOpened);
    CHECK(ev.path_id == 42);
    CHECK(ev.remote_addr == "1.2.3.4:9001");
    CHECK(ev.local_addr == "0.0.0.0:9001");
    CHECK(ev.reason.empty());
    CHECK(!ev.has_last_stats());
}

static void test_opened_is_methods() {
    std::printf("[test] PathEvent::opened is_* methods...\n");
    auto ev = PathEvent::opened(1, "remote", "local");
    CHECK(ev.is_opened());
    CHECK(!ev.is_closed());
    CHECK(!ev.is_selected());
    CHECK(!ev.has_last_stats());
}

static void test_opened_zero_path_id() {
    std::printf("[test] PathEvent::opened zero path_id...\n");
    auto ev = PathEvent::opened(0, "r", "l");
    CHECK(ev.path_id == 0);
    CHECK(ev.is_opened());
}

static void test_opened_empty_addrs() {
    std::printf("[test] PathEvent::opened empty addrs...\n");
    auto ev = PathEvent::opened(5, "", "");
    CHECK(ev.remote_addr.empty());
    CHECK(ev.local_addr.empty());
    CHECK(ev.is_opened());
}

// ============================================================================
// PathEvent::closed 测试
// ============================================================================

static void test_closed_basic() {
    std::printf("[test] PathEvent::closed basic...\n");
    PathStats stats;
    stats.udp_tx.packets_sent = 100;
    stats.lost_packets = 5;
    stats.rtt = std::chrono::nanoseconds(50000);

    auto ev = PathEvent::closed(7, "1.2.3.4:9001", "0.0.0.0:9001", stats, "idle timeout");
    CHECK(ev.type == PathEvent::Type::kClosed);
    CHECK(ev.path_id == 7);
    CHECK(ev.remote_addr == "1.2.3.4:9001");
    CHECK(ev.local_addr == "0.0.0.0:9001");
    CHECK(ev.reason == "idle timeout");
    CHECK(ev.has_last_stats());
    CHECK(ev.last_stats.has_value());
    CHECK(ev.last_stats->udp_tx.packets_sent == 100);
    CHECK(ev.last_stats->lost_packets == 5);
    CHECK(ev.last_stats->rtt.count() == 50000);
}

static void test_closed_is_methods() {
    std::printf("[test] PathEvent::closed is_* methods...\n");
    PathStats stats;
    auto ev = PathEvent::closed(1, "r", "l", stats);
    CHECK(!ev.is_opened());
    CHECK(ev.is_closed());
    CHECK(!ev.is_selected());
    CHECK(ev.has_last_stats());
}

static void test_closed_default_reason() {
    std::printf("[test] PathEvent::closed default reason...\n");
    PathStats stats;
    auto ev = PathEvent::closed(1, "r", "l", stats);
    CHECK(ev.reason.empty());
}

static void test_closed_carries_stats_snapshot() {
    std::printf("[test] PathEvent::closed carries stats snapshot...\n");
    PathStats stats;
    stats.udp_tx.bytes_sent = 99999;
    stats.frame_tx.stream_sent = 50;
    stats.congestion_events = 3;
    stats.cwnd = 8000;

    auto ev = PathEvent::closed(1, "r", "l", stats);

    // 修改原 stats 不影响 event 中的副本
    stats.udp_tx.bytes_sent = 0;
    stats.congestion_events = 0;

    CHECK(ev.last_stats->udp_tx.bytes_sent == 99999);
    CHECK(ev.last_stats->frame_tx.stream_sent == 50);
    CHECK(ev.last_stats->congestion_events == 3);
    CHECK(ev.last_stats->cwnd == 8000);
}

static void test_closed_moved_stats() {
    std::printf("[test] PathEvent::closed moved stats...\n");
    PathStats stats;
    stats.udp_rx.bytes_received = 12345;

    auto ev = PathEvent::closed(1, "r", "l", std::move(stats));
    CHECK(ev.last_stats->udp_rx.bytes_received == 12345);
}

// ============================================================================
// PathEvent::selected 测试
// ============================================================================

static void test_selected_basic() {
    std::printf("[test] PathEvent::selected basic...\n");
    auto ev = PathEvent::selected(3, "1.2.3.4:9001", "0.0.0.0:9001", "better RTT");
    CHECK(ev.type == PathEvent::Type::kSelected);
    CHECK(ev.path_id == 3);
    CHECK(ev.remote_addr == "1.2.3.4:9001");
    CHECK(ev.local_addr == "0.0.0.0:9001");
    CHECK(ev.reason == "better RTT");
    CHECK(!ev.has_last_stats());
}

static void test_selected_is_methods() {
    std::printf("[test] PathEvent::selected is_* methods...\n");
    auto ev = PathEvent::selected(1, "r", "l");
    CHECK(!ev.is_opened());
    CHECK(!ev.is_closed());
    CHECK(ev.is_selected());
    CHECK(!ev.has_last_stats());
}

static void test_selected_default_reason() {
    std::printf("[test] PathEvent::selected default reason...\n");
    auto ev = PathEvent::selected(1, "r", "l");
    CHECK(ev.reason.empty());
}

// ============================================================================
// type_str 测试
// ============================================================================

static void test_type_str() {
    std::printf("[test] PathEvent::type_str...\n");
    CHECK(std::string(PathEvent::type_str(PathEvent::Type::kOpened)) == "Opened");
    CHECK(std::string(PathEvent::type_str(PathEvent::Type::kClosed)) == "Closed");
    CHECK(std::string(PathEvent::type_str(PathEvent::Type::kSelected)) == "Selected");
}

// ============================================================================
// PathEventCallback 分发测试
// ============================================================================

static void test_callback_single_dispatch() {
    std::printf("[test] PathEventCallback single dispatch...\n");
    PathEvent received;
    PathEventCallback cb = [&](const PathEvent &ev) { received = ev; };

    auto orig = PathEvent::opened(5, "remote:1234", "local:5678");
    cb(orig);

    CHECK(received.type == PathEvent::Type::kOpened);
    CHECK(received.path_id == 5);
    CHECK(received.remote_addr == "remote:1234");
}

static void test_callback_multiple_dispatch() {
    std::printf("[test] PathEventCallback multiple dispatch...\n");
    std::vector<PathEvent> received;
    PathEventCallback cb = [&](const PathEvent &ev) { received.push_back(ev); };

    cb(PathEvent::opened(1, "r1", "l1"));
    PathStats stats; stats.lost_packets = 99;
    cb(PathEvent::closed(1, "r1", "l1", stats, "timeout"));
    cb(PathEvent::selected(2, "r2", "l2", "better path"));

    CHECK(received.size() == 3);
    CHECK(received[0].is_opened());
    CHECK(received[1].is_closed());
    CHECK(received[1].last_stats->lost_packets == 99);
    CHECK(received[2].is_selected());
}

static void test_callback_stats_preserved_through_dispatch() {
    std::printf("[test] PathEventCallback stats preserved...\n");
    PathStats stats;
    stats.udp_tx.packets_sent = 777;
    stats.lost_bytes = 88888;

    PathEvent received;
    PathEventCallback cb = [&](const PathEvent &ev) { received = ev; };

    cb(PathEvent::closed(42, "r", "l", stats, "test"));

    CHECK(received.has_last_stats());
    CHECK(received.last_stats->udp_tx.packets_sent == 777);
    CHECK(received.last_stats->lost_bytes == 88888);
}

static void test_callback_empty_function() {
    std::printf("[test] PathEventCallback empty function...\n");
    PathEventCallback cb;
    // 空 callback 调用应安全（不崩溃）
    auto ev = PathEvent::opened(1, "r", "l");
    if (cb) {
        cb(ev);
    }
    CHECK(true);  // 到达此行说明无崩溃
}

static void test_callback_reassign() {
    std::printf("[test] PathEventCallback reassign...\n");
    int count_a = 0, count_b = 0;
    PathEventCallback cb = [&](const PathEvent &) { ++count_a; };

    cb(PathEvent::opened(1, "r", "l"));
    CHECK(count_a == 1);

    cb = [&](const PathEvent &) { ++count_b; };
    cb(PathEvent::opened(2, "r", "l"));
    CHECK(count_a == 1);
    CHECK(count_b == 1);
}

// ============================================================================
// 模拟 PathMigrator → Aggregator 集成场景
// ============================================================================

static void test_integration_with_aggregator() {
    std::printf("[test] Integration with ConnectionStatsAggregator...\n");
    ConnectionStatsAggregator agg;

    // 模拟 PathMigrator 的事件分发
    PathEventCallback dispatcher = [&](const PathEvent &ev) {
        if (ev.is_closed() && ev.has_last_stats()) {
            agg.on_path_closed(*ev.last_stats);
        }
    };

    // 路径 1 打开
    dispatcher(PathEvent::opened(1, "r1", "l1"));

    // 路径 1 关闭，携带统计
    PathStats p1_stats;
    p1_stats.udp_tx.packets_sent = 100;
    p1_stats.lost_packets = 3;
    dispatcher(PathEvent::closed(1, "r1", "l1", p1_stats, "idle"));

    // 路径 2 打开
    dispatcher(PathEvent::opened(2, "r2", "l2"));

    // 路径 2 关闭，携带统计
    PathStats p2_stats;
    p2_stats.udp_tx.packets_sent = 200;
    p2_stats.lost_packets = 5;
    dispatcher(PathEvent::closed(2, "r2", "l2", p2_stats, "migrate"));

    auto s = agg.snapshot();
    CHECK(s.udp_tx.packets_sent == 300);
    CHECK(s.lost_packets == 8);
}

static void test_integration_opened_event_no_aggregator_change() {
    std::printf("[test] Integration: opened event no aggregator change...\n");
    ConnectionStatsAggregator agg;
    PathEventCallback dispatcher = [&](const PathEvent &ev) {
        if (ev.is_closed() && ev.has_last_stats()) {
            agg.on_path_closed(*ev.last_stats);
        }
    };

    // 仅 opened 事件，不应改变 aggregator
    dispatcher(PathEvent::opened(1, "r", "l"));
    dispatcher(PathEvent::selected(1, "r", "l"));

    auto s = agg.snapshot();
    CHECK(s.udp_tx.packets_sent == 0);
    CHECK(s.lost_packets == 0);
}

static void test_integration_closed_without_stats_ignored() {
    std::printf("[test] Integration: closed without stats ignored...\n");
    ConnectionStatsAggregator agg;
    int dispatch_count = 0;
    PathEventCallback dispatcher = [&](const PathEvent &ev) {
        ++dispatch_count;
        if (ev.is_closed() && ev.has_last_stats()) {
            agg.on_path_closed(*ev.last_stats);
        }
    };

    // closed 但无 stats（理论上不会发生，但测试防御）
    PathEvent ev;
    ev.type = PathEvent::Type::kClosed;
    ev.path_id = 1;
    // last_stats 不设置
    dispatcher(ev);

    CHECK(dispatch_count == 1);
    CHECK(agg.snapshot().lost_packets == 0);
}

int main() {
    std::printf("=== test_path_event (v1.7.0.4 P3 B7/B8) ===\n");

    test_opened_basic();
    test_opened_is_methods();
    test_opened_zero_path_id();
    test_opened_empty_addrs();

    test_closed_basic();
    test_closed_is_methods();
    test_closed_default_reason();
    test_closed_carries_stats_snapshot();
    test_closed_moved_stats();

    test_selected_basic();
    test_selected_is_methods();
    test_selected_default_reason();

    test_type_str();

    test_callback_single_dispatch();
    test_callback_multiple_dispatch();
    test_callback_stats_preserved_through_dispatch();
    test_callback_empty_function();
    test_callback_reassign();

    test_integration_with_aggregator();
    test_integration_opened_event_no_aggregator_change();
    test_integration_closed_without_stats_ignored();

    std::printf("\n=== Results: %d PASSED, %d FAILED ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
