// test_path_stats.cpp — B7 路径统计保留测试（v1.7.0.4 P3）
//
// 覆盖：
//   - UdpStats operator+= / operator+ / operator==
//   - FrameStats operator+= / operator+ / operator==
//   - PathStats 默认值与字段类型
//   - ConnectionStats::operator+= (PathStats) 忽略瞬时字段
//   - ConnectionStats::operator+= (ConnectionStats)
//   - ConnectionStatsAggregator: on_path_closed 累加 / snapshot / reset
//   - 多路径累加场景

#include "linoh/protocol/path_stats.hpp"

#include <chrono>
#include <cstdio>

using namespace linoh;
using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// UdpStats 测试
// ============================================================================

static void test_udp_stats_default() {
    std::printf("[test] UdpStats default values...\n");
    UdpStats s;
    CHECK(s.packets_sent == 0);
    CHECK(s.bytes_sent == 0);
    CHECK(s.packets_received == 0);
    CHECK(s.bytes_received == 0);
}

static void test_udp_stats_add_assign() {
    std::printf("[test] UdpStats operator+= ...\n");
    UdpStats a;
    a.packets_sent = 10;
    a.bytes_sent = 1000;
    a.packets_received = 8;
    a.bytes_received = 800;

    UdpStats b;
    b.packets_sent = 5;
    b.bytes_sent = 500;
    b.packets_received = 4;
    b.bytes_received = 400;

    a += b;
    CHECK(a.packets_sent == 15);
    CHECK(a.bytes_sent == 1500);
    CHECK(a.packets_received == 12);
    CHECK(a.bytes_received == 1200);
}

static void test_udp_stats_add() {
    std::printf("[test] UdpStats operator+ ...\n");
    UdpStats a;
    a.packets_sent = 3;
    a.bytes_sent = 300;
    UdpStats b;
    b.packets_sent = 7;
    b.bytes_sent = 700;

    UdpStats c = a + b;
    CHECK(c.packets_sent == 10);
    CHECK(c.bytes_sent == 1000);
    // a 不被修改
    CHECK(a.packets_sent == 3);
}

static void test_udp_stats_eq() {
    std::printf("[test] UdpStats operator== ...\n");
    UdpStats a, b;
    a.packets_sent = 1;
    a.bytes_sent = 100;
    b.packets_sent = 1;
    b.bytes_sent = 100;
    CHECK(a == b);

    b.bytes_sent = 200;
    CHECK(!(a == b));
}

static void test_udp_stats_chained_add() {
    std::printf("[test] UdpStats chained += ...\n");
    UdpStats total;
    UdpStats p1; p1.packets_sent = 5; p1.bytes_sent = 500;
    UdpStats p2; p2.packets_sent = 3; p2.bytes_sent = 300;
    UdpStats p3; p3.packets_sent = 2; p3.bytes_sent = 200;

    total += p1;
    total += p2;
    total += p3;
    CHECK(total.packets_sent == 10);
    CHECK(total.bytes_sent == 1000);
}

// ============================================================================
// FrameStats 测试
// ============================================================================

static void test_frame_stats_default() {
    std::printf("[test] FrameStats default values...\n");
    FrameStats s;
    CHECK(s.ack_sent == 0);
    CHECK(s.ack_received == 0);
    CHECK(s.stream_sent == 0);
    CHECK(s.stream_received == 0);
    CHECK(s.crypto_sent == 0);
    CHECK(s.crypto_received == 0);
    CHECK(s.ping_sent == 0);
    CHECK(s.pong_received == 0);
}

static void test_frame_stats_add_assign() {
    std::printf("[test] FrameStats operator+= ...\n");
    FrameStats a;
    a.ack_sent = 10;
    a.stream_sent = 5;
    a.crypto_received = 3;

    FrameStats b;
    b.ack_sent = 5;
    b.stream_sent = 2;
    b.crypto_received = 1;

    a += b;
    CHECK(a.ack_sent == 15);
    CHECK(a.stream_sent == 7);
    CHECK(a.crypto_received == 4);
}

static void test_frame_stats_eq() {
    std::printf("[test] FrameStats operator== ...\n");
    FrameStats a, b;
    a.ack_sent = 1;
    b.ack_sent = 1;
    CHECK(a == b);
    b.stream_sent = 1;
    CHECK(!(a == b));
}

// ============================================================================
// PathStats 测试
// ============================================================================

static void test_path_stats_default() {
    std::printf("[test] PathStats default values...\n");
    PathStats s;
    CHECK(s.rtt.count() == 0);
    CHECK(s.cwnd == 0);
    CHECK(s.current_mtu == 0);
    CHECK(s.congestion_events == 0);
    CHECK(s.lost_packets == 0);
    CHECK(s.lost_bytes == 0);
    CHECK(s.sent_plpmtud_probes == 0);
    CHECK(s.lost_plpmtud_probes == 0);
    CHECK(s.black_holes_detected == 0);
}

static void test_path_stats_field_types() {
    std::printf("[test] PathStats field types...\n");
    PathStats s;
    s.rtt = std::chrono::nanoseconds(50000);
    s.cwnd = 10000;
    s.current_mtu = 1500;
    s.congestion_events = 3;
    s.lost_packets = 5;

    CHECK(s.rtt.count() == 50000);
    CHECK(s.cwnd == 10000);
    CHECK(s.current_mtu == 1500);
    CHECK(s.congestion_events == 3);
    CHECK(s.lost_packets == 5);
}

// ============================================================================
// ConnectionStats::operator+=(PathStats) — 核心测试：忽略瞬时字段
// ============================================================================

static void test_conn_stats_add_path_ignores_gauge() {
    std::printf("[test] ConnectionStats += PathStats ignores gauge...\n");
    ConnectionStats cs;
    PathStats ps;
    ps.rtt = std::chrono::nanoseconds(50000);
    ps.cwnd = 10000;
    ps.current_mtu = 1500;
    ps.udp_tx.packets_sent = 100;
    ps.udp_tx.bytes_sent = 10000;
    ps.lost_packets = 5;
    ps.congestion_events = 2;

    cs += ps;

    // 累计字段已累加
    CHECK(cs.udp_tx.packets_sent == 100);
    CHECK(cs.udp_tx.bytes_sent == 10000);
    CHECK(cs.lost_packets == 5);
    CHECK(cs.congestion_events == 2);
    // 瞬时字段不存在于 ConnectionStats（编译期保证）
}

static void test_conn_stats_add_path_multiple() {
    std::printf("[test] ConnectionStats += multiple PathStats...\n");
    ConnectionStats cs;

    PathStats p1;
    p1.udp_tx.packets_sent = 100;
    p1.lost_packets = 5;

    PathStats p2;
    p2.udp_tx.packets_sent = 200;
    p2.lost_packets = 3;

    cs += p1;
    cs += p2;

    CHECK(cs.udp_tx.packets_sent == 300);
    CHECK(cs.lost_packets == 8);
}

static void test_conn_stats_add_path_chained() {
    std::printf("[test] ConnectionStats chained += PathStats...\n");
    ConnectionStats cs;
    PathStats p1; p1.udp_rx.bytes_received = 1000;
    PathStats p2; p2.udp_rx.bytes_received = 2000;
    PathStats p3; p3.udp_rx.bytes_received = 3000;

    cs += p1;
    cs += p2;
    cs += p3;

    CHECK(cs.udp_rx.bytes_received == 6000);
}

static void test_conn_stats_add_path_with_frames() {
    std::printf("[test] ConnectionStats += PathStats with frames...\n");
    ConnectionStats cs;
    PathStats ps;
    ps.frame_tx.stream_sent = 50;
    ps.frame_rx.ack_received = 30;
    ps.frame_tx.crypto_sent = 5;

    cs += ps;
    CHECK(cs.frame_tx.stream_sent == 50);
    CHECK(cs.frame_rx.ack_received == 30);
    CHECK(cs.frame_tx.crypto_sent == 5);
}

static void test_conn_stats_add_self() {
    std::printf("[test] ConnectionStats += ConnectionStats...\n");
    ConnectionStats a, b;
    a.udp_tx.packets_sent = 100;
    a.lost_packets = 5;
    b.udp_tx.packets_sent = 200;
    b.lost_packets = 3;

    a += b;
    CHECK(a.udp_tx.packets_sent == 300);
    CHECK(a.lost_packets == 8);
}

static void test_conn_stats_eq() {
    std::printf("[test] ConnectionStats operator== ...\n");
    ConnectionStats a, b;
    a.udp_tx.packets_sent = 100;
    b.udp_tx.packets_sent = 100;
    CHECK(a == b);

    b.lost_packets = 1;
    CHECK(!(a == b));
}

static void test_conn_stats_add_path_operator_plus() {
    std::printf("[test] ConnectionStats operator+ PathStats...\n");
    ConnectionStats cs;
    cs.lost_packets = 10;

    PathStats ps;
    ps.lost_packets = 5;

    ConnectionStats result = cs + ps;
    CHECK(result.lost_packets == 15);
    // cs 不被修改
    CHECK(cs.lost_packets == 10);
}

// ============================================================================
// ConnectionStatsAggregator 测试
// ============================================================================

static void test_aggregator_initial_empty() {
    std::printf("[test] ConnectionStatsAggregator initial empty...\n");
    ConnectionStatsAggregator agg;
    auto s = agg.snapshot();
    CHECK(s.udp_tx.packets_sent == 0);
    CHECK(s.lost_packets == 0);
}

static void test_aggregator_on_path_closed_accumulates() {
    std::printf("[test] Aggregator on_path_closed accumulates...\n");
    ConnectionStatsAggregator agg;

    PathStats p1;
    p1.udp_tx.packets_sent = 100;
    p1.lost_packets = 5;

    agg.on_path_closed(p1);

    auto s = agg.snapshot();
    CHECK(s.udp_tx.packets_sent == 100);
    CHECK(s.lost_packets == 5);
}

static void test_aggregator_multiple_paths() {
    std::printf("[test] Aggregator multiple paths...\n");
    ConnectionStatsAggregator agg;

    PathStats p1; p1.udp_tx.packets_sent = 100; p1.lost_packets = 5;
    PathStats p2; p2.udp_tx.packets_sent = 200; p2.lost_packets = 3;
    PathStats p3; p3.udp_tx.packets_sent = 50;  p3.lost_packets = 1;

    agg.on_path_closed(p1);
    agg.on_path_closed(p2);
    agg.on_path_closed(p3);

    auto s = agg.snapshot();
    CHECK(s.udp_tx.packets_sent == 350);
    CHECK(s.lost_packets == 9);
}

static void test_aggregator_reset() {
    std::printf("[test] Aggregator reset...\n");
    ConnectionStatsAggregator agg;

    PathStats p;
    p.udp_tx.packets_sent = 100;
    agg.on_path_closed(p);

    CHECK(agg.snapshot().udp_tx.packets_sent == 100);

    agg.reset();
    CHECK(agg.snapshot().udp_tx.packets_sent == 0);
    CHECK(agg.snapshot().lost_packets == 0);
}

static void test_aggregator_ignores_gauge() {
    std::printf("[test] Aggregator ignores gauge fields...\n");
    ConnectionStatsAggregator agg;

    PathStats p;
    p.rtt = std::chrono::nanoseconds(999999);
    p.cwnd = 99999;
    p.current_mtu = 9000;
    p.udp_tx.packets_sent = 10;

    agg.on_path_closed(p);

    auto s = agg.snapshot();
    // 累计字段已累加
    CHECK(s.udp_tx.packets_sent == 10);
    // 瞬时字段不存在于 ConnectionStats
}

static void test_aggregator_accumulates_all_counter_fields() {
    std::printf("[test] Aggregator accumulates all counter fields...\n");
    ConnectionStatsAggregator agg;

    PathStats p;
    p.udp_tx.packets_sent = 1;
    p.udp_tx.bytes_sent = 100;
    p.udp_rx.packets_received = 2;
    p.udp_rx.bytes_received = 200;
    p.frame_tx.ack_sent = 3;
    p.frame_rx.ack_received = 4;
    p.congestion_events = 5;
    p.spurious_congestion_events = 6;
    p.lost_packets = 7;
    p.lost_bytes = 800;
    p.sent_plpmtud_probes = 8;
    p.lost_plpmtud_probes = 9;
    p.black_holes_detected = 10;

    agg.on_path_closed(p);

    auto s = agg.snapshot();
    CHECK(s.udp_tx.packets_sent == 1);
    CHECK(s.udp_tx.bytes_sent == 100);
    CHECK(s.udp_rx.packets_received == 2);
    CHECK(s.udp_rx.bytes_received == 200);
    CHECK(s.frame_tx.ack_sent == 3);
    CHECK(s.frame_rx.ack_received == 4);
    CHECK(s.congestion_events == 5);
    CHECK(s.spurious_congestion_events == 6);
    CHECK(s.lost_packets == 7);
    CHECK(s.lost_bytes == 800);
    CHECK(s.sent_plpmtud_probes == 8);
    CHECK(s.lost_plpmtud_probes == 9);
    CHECK(s.black_holes_detected == 10);
}

static void test_aggregator_snapshot_returns_copy() {
    std::printf("[test] Aggregator snapshot returns copy...\n");
    ConnectionStatsAggregator agg;

    PathStats p;
    p.lost_packets = 5;
    agg.on_path_closed(p);

    auto s1 = agg.snapshot();
    CHECK(s1.lost_packets == 5);

    // 修改 snapshot 不影响 aggregator
    s1.lost_packets = 999;
    auto s2 = agg.snapshot();
    CHECK(s2.lost_packets == 5);
}

static void test_aggregator_mixed_paths() {
    std::printf("[test] Aggregator mixed paths (gauge + counter)...\n");
    ConnectionStatsAggregator agg;

    PathStats p1;
    p1.rtt = std::chrono::nanoseconds(100000);
    p1.cwnd = 5000;
    p1.udp_tx.packets_sent = 100;

    PathStats p2;
    p2.rtt = std::chrono::nanoseconds(200000);
    p2.cwnd = 8000;
    p2.udp_tx.packets_sent = 200;

    agg.on_path_closed(p1);
    agg.on_path_closed(p2);

    auto s = agg.snapshot();
    // counter 字段累加
    CHECK(s.udp_tx.packets_sent == 300);
    // gauge 字段不存在于 ConnectionStats
}

// ============================================================================
// 模拟多路径生命周期场景
// ============================================================================

static void test_multi_path_lifecycle() {
    std::printf("[test] Multi-path lifecycle simulation...\n");
    ConnectionStatsAggregator agg;

    // 路径 1: 短路径，少量数据
    PathStats p1;
    p1.udp_tx.packets_sent = 100;
    p1.udp_tx.bytes_sent = 12000;
    p1.lost_packets = 2;
    p1.frame_tx.stream_sent = 30;
    agg.on_path_closed(p1);

    // 路径 2: 长路径，大量数据
    PathStats p2;
    p2.udp_tx.packets_sent = 500;
    p2.udp_tx.bytes_sent = 60000;
    p2.lost_packets = 10;
    p2.frame_tx.stream_sent = 150;
    agg.on_path_closed(p2);

    // 路径 3: 中等路径
    PathStats p3;
    p3.udp_tx.packets_sent = 200;
    p3.udp_tx.bytes_sent = 24000;
    p3.lost_packets = 5;
    p3.frame_tx.stream_sent = 60;
    agg.on_path_closed(p3);

    auto s = agg.snapshot();
    CHECK(s.udp_tx.packets_sent == 800);
    CHECK(s.udp_tx.bytes_sent == 96000);
    CHECK(s.lost_packets == 17);
    CHECK(s.frame_tx.stream_sent == 240);
}

int main() {
    std::printf("=== test_path_stats (v1.7.0.4 P3 B7) ===\n");

    test_udp_stats_default();
    test_udp_stats_add_assign();
    test_udp_stats_add();
    test_udp_stats_eq();
    test_udp_stats_chained_add();

    test_frame_stats_default();
    test_frame_stats_add_assign();
    test_frame_stats_eq();

    test_path_stats_default();
    test_path_stats_field_types();

    test_conn_stats_add_path_ignores_gauge();
    test_conn_stats_add_path_multiple();
    test_conn_stats_add_path_chained();
    test_conn_stats_add_path_with_frames();
    test_conn_stats_add_self();
    test_conn_stats_eq();
    test_conn_stats_add_path_operator_plus();

    test_aggregator_initial_empty();
    test_aggregator_on_path_closed_accumulates();
    test_aggregator_multiple_paths();
    test_aggregator_reset();
    test_aggregator_ignores_gauge();
    test_aggregator_accumulates_all_counter_fields();
    test_aggregator_snapshot_returns_copy();
    test_aggregator_mixed_paths();

    test_multi_path_lifecycle();

    std::printf("\n=== Results: %d PASSED, %d FAILED ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
