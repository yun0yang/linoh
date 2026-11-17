// test_passive_endpoint_update.cpp — P0-G3 被动端点更新测试
//
// 验证：
//   1. PassiveEndpointUpdaterConfig 默认构造（cooldown=30s, address_check=true, stats=true）
//   2. address_differs: 完全相同地址 → false
//   3. address_differs: 仅 host 不同 → true
//   4. address_differs: 仅 port 不同 → true
//   5. address_differs: kind 不同但 host/port 相同 → false（仅比 host+port）
//   6. maybe_update: 地址一致 → nullopt，total_packets_checked+1
//   7. maybe_update: 地址不同且无历史 → 返回 actual_src，updates_performed+1
//   8. maybe_update: 限频窗口内 → nullopt，updates_suppressed+1
//   9. maybe_update: 窗口外（>= cooldown）→ 返回新地址
//  10. maybe_update: enable_address_check=false → 总是返回 actual_src
//  11. maybe_update: 不同 peer 独立限频，互不影响
//  12. maybe_update: enable_stats=false → 统计不递增
//  13. stats() 快照正确性
//  14. reset_stats() 清零统计但不影响 per-peer 限频状态
//  15. cooldown=0 → 每次都允许更新（无限频）
//  16. maybe_update: 返回的地址字段与 actual_src 完全一致

#include "linoh/nat/passive_endpoint_updater.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh;
using namespace linoh::nat;
using namespace linoh::base;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 辅助函数
// ============================================================================

/// 构造测试用 EndpointId（PublicKey）：填充可辨识字节模式
static EndpointId make_peer(std::uint8_t seed) {
    std::array<std::uint8_t, PublicKey::kSize> bytes{};
    bytes[0] = seed;
    bytes[31] = static_cast<std::uint8_t>(~seed);
    return PublicKey(bytes);
}

/// 构造 IP 类型 TransportAddr
static TransportAddr make_addr(const std::string &host, std::uint16_t port) {
    TransportAddr a;
    a.kind = TransportKind::Ip;
    a.host = host;
    a.port = port;
    return a;
}

/// 稳定时间基线（避免 steady_clock 抖动影响断言）
static auto T0 = std::chrono::steady_clock::time_point{};

// ============================================================================
// 测试用例
// ============================================================================

// 1. PassiveEndpointUpdaterConfig 默认构造
static void test_config_defaults() {
    PassiveEndpointUpdaterConfig cfg;
    CHECK(cfg.cooldown == std::chrono::seconds(30));
    CHECK(cfg.enable_address_check == true);
    CHECK(cfg.enable_stats == true);
}

// 2-5. address_differs 工具函数
static void test_address_differs_same() {
    auto a = make_addr("1.2.3.4", 5000);
    auto b = make_addr("1.2.3.4", 5000);
    CHECK(address_differs(a, b) == false);
}

static void test_address_differs_host_only() {
    auto a = make_addr("1.2.3.4", 5000);
    auto b = make_addr("1.2.3.5", 5000);
    CHECK(address_differs(a, b) == true);
}

static void test_address_differs_port_only() {
    auto a = make_addr("1.2.3.4", 5000);
    auto b = make_addr("1.2.3.4", 5001);
    CHECK(address_differs(a, b) == true);
}

static void test_address_differs_kind_ignored() {
    // kind 不同但 host/port 相同 → 仅比较 host+port，应返回 false
    auto a = make_addr("1.2.3.4", 5000);
    TransportAddr b;
    b.kind = TransportKind::Relay;
    b.host = "1.2.3.4";
    b.port = 5000;
    CHECK(address_differs(a, b) == false);
}

// 6. maybe_update: 地址一致 → nullopt
static void test_maybe_update_same_address() {
    PassiveEndpointUpdater updater;
    auto peer = make_peer(1);
    auto addr = make_addr("10.0.0.1", 9000);

    auto r = updater.maybe_update(peer, addr, addr, T0);
    CHECK(!r.has_value());

    auto s = updater.stats();
    CHECK(s.total_packets_checked == 1);
    CHECK(s.address_mismatches == 0);
    CHECK(s.updates_performed == 0);
    CHECK(s.updates_suppressed == 0);
}

// 7. maybe_update: 地址不同且无历史 → 返回 actual_src
static void test_maybe_update_different_address() {
    PassiveEndpointUpdater updater;
    auto peer = make_peer(2);
    auto recorded = make_addr("10.0.0.1", 9000);
    auto actual = make_addr("10.0.0.1", 9500);  // 端口跳跃

    auto r = updater.maybe_update(peer, recorded, actual, T0);
    CHECK(r.has_value());
    CHECK(r->host == actual.host);
    CHECK(r->port == actual.port);

    auto s = updater.stats();
    CHECK(s.total_packets_checked == 1);
    CHECK(s.address_mismatches == 1);
    CHECK(s.updates_performed == 1);
    CHECK(s.updates_suppressed == 0);
}

// 8. maybe_update: 限频窗口内 → nullopt + updates_suppressed
static void test_maybe_update_cooldown_suppress() {
    PassiveEndpointUpdater updater;
    auto peer = make_peer(3);
    auto recorded = make_addr("10.0.0.1", 9000);
    auto actual1 = make_addr("10.0.0.1", 9100);
    auto actual2 = make_addr("10.0.0.1", 9200);

    // 首次：T0 更新成功
    auto r1 = updater.maybe_update(peer, recorded, actual1, T0);
    CHECK(r1.has_value());

    // 限频窗口内（T0 + 10s < 30s cooldown）→ 抑制
    auto r2 = updater.maybe_update(peer, actual1, actual2, T0 + std::chrono::seconds(10));
    CHECK(!r2.has_value());

    auto s = updater.stats();
    CHECK(s.total_packets_checked == 2);
    CHECK(s.address_mismatches == 2);
    CHECK(s.updates_performed == 1);
    CHECK(s.updates_suppressed == 1);
}

// 9. maybe_update: 窗口外（>= cooldown）→ 返回新地址
static void test_maybe_update_cooldown_expired() {
    PassiveEndpointUpdater updater;
    auto peer = make_peer(4);
    auto recorded = make_addr("10.0.0.1", 9000);
    auto actual1 = make_addr("10.0.0.1", 9100);
    auto actual2 = make_addr("10.0.0.1", 9200);

    // 首次：T0 更新成功
    auto r1 = updater.maybe_update(peer, recorded, actual1, T0);
    CHECK(r1.has_value());

    // 窗口外（T0 + 30s == cooldown）→ 允许更新
    auto r2 = updater.maybe_update(peer, actual1, actual2, T0 + std::chrono::seconds(30));
    CHECK(r2.has_value());
    CHECK(r2->port == 9200);

    auto s = updater.stats();
    CHECK(s.updates_performed == 2);
    CHECK(s.updates_suppressed == 0);
}

// 10. maybe_update: enable_address_check=false → 总是返回 actual_src
static void test_maybe_update_disable_address_check() {
    PassiveEndpointUpdaterConfig cfg;
    cfg.enable_address_check = false;
    PassiveEndpointUpdater updater(cfg);

    auto peer = make_peer(5);
    auto addr = make_addr("10.0.0.1", 9000);

    // 即使地址一致，也返回 actual_src
    auto r = updater.maybe_update(peer, addr, addr, T0);
    CHECK(r.has_value());
    CHECK(r->port == 9000);

    auto s = updater.stats();
    CHECK(s.total_packets_checked == 1);
    CHECK(s.address_mismatches == 1);  // 跳过地址比较也计入 mismatch
    CHECK(s.updates_performed == 1);
}

// 11. maybe_update: 不同 peer 独立限频
static void test_maybe_update_different_peers() {
    PassiveEndpointUpdater updater;
    auto peerA = make_peer(6);
    auto peerB = make_peer(7);
    auto recorded = make_addr("10.0.0.1", 9000);
    auto actualA = make_addr("10.0.0.1", 9100);
    auto actualB = make_addr("10.0.0.1", 9200);

    // peerA 在 T0 更新
    auto rA1 = updater.maybe_update(peerA, recorded, actualA, T0);
    CHECK(rA1.has_value());

    // peerB 在 T0+5s 更新（独立限频，不受 peerA 影响）
    auto rB1 = updater.maybe_update(peerB, recorded, actualB, T0 + std::chrono::seconds(5));
    CHECK(rB1.has_value());

    // peerA 在 T0+10s 再次更新 → 被 peerA 自身的限频抑制
    auto rA2 = updater.maybe_update(peerA, actualA, make_addr("10.0.0.1", 9300),
                                    T0 + std::chrono::seconds(10));
    CHECK(!rA2.has_value());

    // peerB 在 T0+10s 再次更新 → 被 peerB 自身的限频抑制
    auto rB2 = updater.maybe_update(peerB, actualB, make_addr("10.0.0.1", 9400),
                                    T0 + std::chrono::seconds(10));
    CHECK(!rB2.has_value());

    auto s = updater.stats();
    CHECK(s.updates_performed == 2);
    CHECK(s.updates_suppressed == 2);
}

// 12. maybe_update: enable_stats=false → 统计不递增
static void test_maybe_update_disable_stats() {
    PassiveEndpointUpdaterConfig cfg;
    cfg.enable_stats = false;
    PassiveEndpointUpdater updater(cfg);

    auto peer = make_peer(8);
    auto recorded = make_addr("10.0.0.1", 9000);
    auto actual = make_addr("10.0.0.1", 9100);

    auto r = updater.maybe_update(peer, recorded, actual, T0);
    CHECK(r.has_value());

    auto s = updater.stats();
    CHECK(s.total_packets_checked == 0);
    CHECK(s.address_mismatches == 0);
    CHECK(s.updates_performed == 0);
    CHECK(s.updates_suppressed == 0);
}

// 13. stats() 快照正确性（多次操作后累计）
static void test_stats_snapshot() {
    PassiveEndpointUpdater updater;
    auto peer = make_peer(9);

    // 包1：地址一致 → checked+1
    updater.maybe_update(peer, make_addr("1.1.1.1", 100),
                         make_addr("1.1.1.1", 100), T0);
    // 包2：地址不同，首次更新 → checked+1, mismatch+1, performed+1
    updater.maybe_update(peer, make_addr("1.1.1.1", 100),
                         make_addr("1.1.1.1", 200), T0 + std::chrono::seconds(1));
    // 包3：地址不同，限频窗口内 → checked+1, mismatch+1, suppressed+1
    updater.maybe_update(peer, make_addr("1.1.1.1", 200),
                         make_addr("1.1.1.1", 300), T0 + std::chrono::seconds(2));

    auto s = updater.stats();
    CHECK(s.total_packets_checked == 3);
    CHECK(s.address_mismatches == 2);
    CHECK(s.updates_performed == 1);
    CHECK(s.updates_suppressed == 1);
}

// 14. reset_stats() 清零统计但不影响 per-peer 限频状态
static void test_reset_stats() {
    PassiveEndpointUpdater updater;
    auto peer = make_peer(10);
    auto recorded = make_addr("10.0.0.1", 9000);
    auto actual1 = make_addr("10.0.0.1", 9100);

    // 首次更新建立限频基线
    updater.maybe_update(peer, recorded, actual1, T0);
    CHECK(updater.stats().updates_performed == 1);

    // 重置统计
    updater.reset_stats();
    auto s = updater.stats();
    CHECK(s.total_packets_checked == 0);
    CHECK(s.address_mismatches == 0);
    CHECK(s.updates_performed == 0);
    CHECK(s.updates_suppressed == 0);

    // 限频状态仍生效：T0+5s 仍被抑制（per-peer last_update 未清）
    auto r = updater.maybe_update(peer, actual1, make_addr("10.0.0.1", 9200),
                                  T0 + std::chrono::seconds(5));
    CHECK(!r.has_value());
    CHECK(updater.stats().updates_suppressed == 1);
}

// 15. cooldown=0 → 每次都允许更新（无限频）
static void test_cooldown_zero() {
    PassiveEndpointUpdaterConfig cfg;
    cfg.cooldown = std::chrono::milliseconds(0);
    PassiveEndpointUpdater updater(cfg);

    auto peer = make_peer(11);
    auto recorded = make_addr("10.0.0.1", 9000);

    // 连续三次更新（同一时间点 T0）均应成功
    auto r1 = updater.maybe_update(peer, recorded, make_addr("10.0.0.1", 9100), T0);
    auto r2 = updater.maybe_update(peer, make_addr("10.0.0.1", 9100),
                                   make_addr("10.0.0.1", 9200), T0);
    auto r3 = updater.maybe_update(peer, make_addr("10.0.0.1", 9200),
                                   make_addr("10.0.0.1", 9300), T0);

    CHECK(r1.has_value());
    CHECK(r2.has_value());
    CHECK(r3.has_value());
    CHECK(r1->port == 9100);
    CHECK(r2->port == 9200);
    CHECK(r3->port == 9300);

    auto s = updater.stats();
    CHECK(s.updates_performed == 3);
    CHECK(s.updates_suppressed == 0);
}

// 16. maybe_update: 返回的地址字段与 actual_src 完全一致
static void test_maybe_update_preserves_actual_src() {
    PassiveEndpointUpdater updater;
    auto peer = make_peer(12);
    auto recorded = make_addr("10.0.0.1", 9000);
    TransportAddr actual;
    actual.kind = TransportKind::Ip;
    actual.host = "203.0.113.42";
    actual.port = 65000;
    actual.custom_payload = "marker";  // 非默认值，验证整体复制

    auto r = updater.maybe_update(peer, recorded, actual, T0);
    CHECK(r.has_value());
    CHECK(r->kind == actual.kind);
    CHECK(r->host == actual.host);
    CHECK(r->port == actual.port);
    CHECK(r->custom_payload == actual.custom_payload);
}

int main() {
    test_config_defaults();
    test_address_differs_same();
    test_address_differs_host_only();
    test_address_differs_port_only();
    test_address_differs_kind_ignored();
    test_maybe_update_same_address();
    test_maybe_update_different_address();
    test_maybe_update_cooldown_suppress();
    test_maybe_update_cooldown_expired();
    test_maybe_update_disable_address_check();
    test_maybe_update_different_peers();
    test_maybe_update_disable_stats();
    test_stats_snapshot();
    test_reset_stats();
    test_cooldown_zero();
    test_maybe_update_preserves_actual_src();

    std::printf("test_passive_endpoint_update: %d passed, %d failed\n",
                pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
