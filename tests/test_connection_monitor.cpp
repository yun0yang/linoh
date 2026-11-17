// test_connection_monitor.cpp — v3.9.1 ConnectionMonitor 带宽反馈闭环测试
//
// 覆盖场景：
//   ConnectionMonitor 基本功能（12 个）：
//   1. 基本带宽上报/查询
//   2. 基本 RTT 上报/查询
//   3. 握手完成上报
//   4. 综合上报 on_metrics_measured
//   5. 不存在的 peer 返回默认值
//   6. remove_connection
//   7. clear
//   8. connection_count
//   9. 数据过期判断 is_expired
//   10. purge_expired 清理过期数据
//   11. 统计信息正确性
//   12. 多线程并发安全
//
//   bandwidth_provider 接入 MultipathCoordinatedSelector（6 个）：
//   13. 未设置 provider 时行为不变
//   14. 设置 provider 后权重用实测带宽
//   15. provider 返回 0 时回退到 pacing_rate
//   16. 清除 provider 后回退
//   17. has_bandwidth_provider 查询
//   18. 慢路径权重降低、快路径权重提升

#include "linoh/endpoint/connection_monitor.hpp"
#include "linoh/protocol/congestion_controller.hpp"
#include "linoh/protocol/multipath_coordinated_selector.hpp"
#include "linoh/net/path.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

using namespace linoh::base;
using namespace linoh::endpoint;
using namespace linoh::net;
using namespace linoh::protocol;

// ===== Mock CongestionController =====

class MockController : public CongestionController {
public:
    MockController(uint64_t pacing_bps, uint64_t cwnd)
        : pacing_bps_(pacing_bps), cwnd_(cwnd) {}
    void on_ack(uint64_t, uint64_t) override {}
    void on_loss(uint64_t) override {}
    void on_rto() override {}
    bool can_send(uint64_t) const override { return true; }
    uint64_t cwnd_bytes() const override { return cwnd_; }
    void reset() override {}
    std::string_view algo_name() const override { return "mock"; }
    uint64_t pacing_rate_bps() const override { return pacing_bps_; }
private:
    uint64_t pacing_bps_;
    uint64_t cwnd_;
};

// ===== 辅助函数 =====

static EndpointId make_peer(std::uint8_t seed) {
    std::array<std::uint8_t, 32> bytes{};
    bytes[0] = seed;
    bytes[31] = seed;
    return EndpointId(bytes);
}

static FourTuple make_tuple(const std::string& local_ip, std::uint16_t local_port,
                            const std::string& remote_ip, std::uint16_t remote_port) {
    FourTuple t;
    t.local_addr.kind = TransportKind::Ip;
    t.local_addr.host = local_ip;
    t.local_addr.port = local_port;
    t.remote_addr.kind = TransportKind::Ip;
    t.remote_addr.host = remote_ip;
    t.remote_addr.port = remote_port;
    return t;
}

static CoordinatedPathInfo make_path(FourTuple tuple, MockController* ctrl,
                                     double srtt_ms, double loss_rate = 0.0) {
    CoordinatedPathInfo p;
    p.tuple = tuple;
    p.controller = ctrl;
    p.srtt = std::chrono::microseconds(static_cast<int64_t>(srtt_ms * 1000));
    p.loss_rate = loss_rate;
    return p;
}

// ===== ConnectionMonitor 基本功能测试 =====

// 1. 基本带宽上报/查询
static void test_bandwidth_report() {
    ConnectionMonitor monitor;
    auto peer = make_peer(1);

    monitor.on_bandwidth_measured(peer, 10'000'000);  // 10 Mbps
    auto data = monitor.get_connection_data(peer);

    assert(data.bandwidth_bps == 10'000'000);
    assert(data.last_updated != std::chrono::steady_clock::time_point{});
    printf("  [PASS] test_bandwidth_report\n");
}

// 2. 基本 RTT 上报/查询
static void test_rtt_report() {
    ConnectionMonitor monitor;
    auto peer = make_peer(2);

    monitor.on_rtt_measured(peer, 50);  // 50ms
    auto data = monitor.get_connection_data(peer);

    assert(data.rtt_ms == 50);
    printf("  [PASS] test_rtt_report\n");
}

// 3. 握手完成上报
static void test_handshake_completed() {
    ConnectionMonitor monitor;
    auto peer = make_peer(3);

    monitor.on_handshake_completed(peer, 30);  // 30ms RTT
    auto data = monitor.get_connection_data(peer);

    assert(data.rtt_ms == 30);
    assert(monitor.stats().total_handshake_reports == 1);
    printf("  [PASS] test_handshake_completed\n");
}

// 4. 综合上报 on_metrics_measured
static void test_metrics_measured() {
    ConnectionMonitor monitor;
    auto peer = make_peer(4);

    monitor.on_metrics_measured(peer, 50'000'000, 25);  // 50 Mbps, 25ms RTT
    auto data = monitor.get_connection_data(peer);

    assert(data.bandwidth_bps == 50'000'000);
    assert(data.rtt_ms == 25);
    assert(monitor.stats().total_bandwidth_reports == 1);
    assert(monitor.stats().total_rtt_reports == 1);
    printf("  [PASS] test_metrics_measured\n");
}

// 5. 不存在的 peer 返回默认值
static void test_nonexistent_peer() {
    ConnectionMonitor monitor;
    auto peer = make_peer(99);

    auto data = monitor.get_connection_data(peer);
    assert(data.bandwidth_bps == 0);
    assert(data.rtt_ms == 0);

    assert(monitor.get_bandwidth_bps(peer) == 0);
    assert(monitor.get_rtt_ms(peer) == 0);
    printf("  [PASS] test_nonexistent_peer\n");
}

// 6. remove_connection
static void test_remove_connection() {
    ConnectionMonitor monitor;
    auto peer1 = make_peer(10);
    auto peer2 = make_peer(20);

    monitor.on_bandwidth_measured(peer1, 1000);
    monitor.on_bandwidth_measured(peer2, 2000);
    assert(monitor.connection_count() == 2);

    monitor.remove_connection(peer1);
    assert(monitor.connection_count() == 1);
    assert(monitor.get_bandwidth_bps(peer1) == 0);
    assert(monitor.get_bandwidth_bps(peer2) == 2000);
    printf("  [PASS] test_remove_connection\n");
}

// 7. clear
static void test_clear() {
    ConnectionMonitor monitor;
    for (int i = 0; i < 5; ++i) {
        monitor.on_bandwidth_measured(make_peer(static_cast<std::uint8_t>(i)), 1000 * i);
    }
    assert(monitor.connection_count() == 5);

    monitor.clear();
    assert(monitor.connection_count() == 0);
    printf("  [PASS] test_clear\n");
}

// 8. connection_count
static void test_connection_count() {
    ConnectionMonitor monitor;
    assert(monitor.connection_count() == 0);

    monitor.on_bandwidth_measured(make_peer(1), 1000);
    assert(monitor.connection_count() == 1);

    monitor.on_rtt_measured(make_peer(2), 10);
    assert(monitor.connection_count() == 2);

    // 同一 peer 多次上报不增加计数
    monitor.on_bandwidth_measured(make_peer(1), 2000);
    assert(monitor.connection_count() == 2);
    printf("  [PASS] test_connection_count\n");
}

// 9. 数据过期判断 is_expired
static void test_is_expired() {
    ConnectionMonitor::ConnectionData data;
    assert(data.is_expired(30));  // 未设置数据，过期

    data.bandwidth_bps = 1000;
    data.last_updated = std::chrono::steady_clock::now();
    assert(!data.is_expired(30));  // 刚更新，未过期

    // 模拟过期：last_updated 设为 60 秒前
    data.last_updated = std::chrono::steady_clock::now() - std::chrono::seconds(60);
    assert(data.is_expired(30));  // 60s > 30s ttl，过期
    assert(!data.is_expired(120));  // 60s < 120s ttl，未过期
    printf("  [PASS] test_is_expired\n");
}

// 10. purge_expired 清理过期数据
static void test_purge_expired() {
    ConnectionMonitor monitor;
    auto peer1 = make_peer(1);
    auto peer2 = make_peer(2);

    // peer1 上报（刚更新，未过期）
    monitor.on_bandwidth_measured(peer1, 1000);

    // peer2 手动设置过期数据
    {
        // 直接通过 on_bandwidth_measured 上报，然后等待过期
        monitor.on_bandwidth_measured(peer2, 2000);
    }

    // 立即 purge，应该清除 0 个（都未过期）
    std::size_t purged = monitor.purge_expired(30);
    assert(purged == 0);
    assert(monitor.connection_count() == 2);

    // 等待 100ms 后 purge（ttl=0 会清除所有）
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    purged = monitor.purge_expired(0);  // ttl=0 秒，立即过期
    assert(purged == 2);
    assert(monitor.connection_count() == 0);
    assert(monitor.stats().total_purged == 2);
    printf("  [PASS] test_purge_expired\n");
}

// 11. 统计信息正确性
static void test_stats() {
    ConnectionMonitor monitor;
    auto peer = make_peer(42);

    monitor.on_bandwidth_measured(peer, 1000);
    monitor.on_rtt_measured(peer, 10);
    monitor.on_handshake_completed(peer, 15);
    monitor.on_metrics_measured(peer, 2000, 20);

    const auto& stats = monitor.stats();
    assert(stats.total_bandwidth_reports == 2);  // on_bandwidth + on_metrics
    assert(stats.total_rtt_reports == 2);        // on_rtt + on_metrics
    assert(stats.total_handshake_reports == 1);
    assert(stats.total_purged == 0);
    printf("  [PASS] test_stats\n");
}

// 12. 多线程并发安全
static void test_concurrent_safety() {
    ConnectionMonitor monitor;
    constexpr int N = 50;
    std::atomic<int> reported{0};

    // 多线程并发上报
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&monitor, &reported, t]() {
            for (int i = 0; i < N; ++i) {
                auto peer = make_peer(static_cast<std::uint8_t>(t * N + i));
                monitor.on_bandwidth_measured(peer, 1000 * (i + 1));
                monitor.on_rtt_measured(peer, static_cast<std::uint32_t>(i + 1));
                reported.fetch_add(1);
            }
        });
    }

    // 同时有读线程
    std::atomic<bool> stop{false};
    std::thread reader([&monitor, &stop]() {
        while (!stop.load()) {
            monitor.get_connection_data(make_peer(0));
            monitor.connection_count();
        }
    });

    for (auto& t : threads) t.join();
    stop.store(true);
    reader.join();

    assert(reported.load() == 4 * N);
    assert(monitor.connection_count() == static_cast<std::size_t>(4 * N));
    printf("  [PASS] test_concurrent_safety (%d writes + concurrent reads)\n", 4 * N);
}

// ===== bandwidth_provider 接入 MultipathCoordinatedSelector 测试 =====

// 13. 未设置 provider 时行为不变（用 pacing_rate）
static void test_no_provider_uses_pacing_rate() {
    MultipathCoordinatedSelector selector(2);
    MockController ctrl1(10'000'000, 65536);  // 10 Mbps
    MockController ctrl2(20'000'000, 65536);  // 20 Mbps

    auto t1 = make_tuple("10.0.0.1", 9001, "10.0.0.2", 9001);
    auto t2 = make_tuple("10.0.0.1", 9002, "10.0.0.3", 9002);

    selector.update_candidates({make_path(t1, &ctrl1, 10), make_path(t2, &ctrl2, 10)});

    assert(!selector.has_bandwidth_provider());

    auto health = selector.path_health_stats();
    assert(health.size() == 2);
    // 权重应基于 pacing_rate（20M > 10M，路径2 权重更高）
    assert(health[1].weight > health[0].weight);
    printf("  [PASS] test_no_provider_uses_pacing_rate\n");
}

// 14. 设置 provider 后权重用实测带宽
static void test_provider_overrides_pacing_rate() {
    MultipathCoordinatedSelector selector(2);
    MockController ctrl1(10'000'000, 65536);   // pacing 10 Mbps
    MockController ctrl2(20'000'000, 65536);   // pacing 20 Mbps

    auto t1 = make_tuple("10.0.0.1", 9001, "10.0.0.2", 9001);
    auto t2 = make_tuple("10.0.0.1", 9002, "10.0.0.3", 9002);

    selector.update_candidates({make_path(t1, &ctrl1, 10), make_path(t2, &ctrl2, 10)});

    // 设置 bandwidth_provider：路径1 实测带宽更高（30M vs 5M）
    // 与 pacing_rate 相反（pacing: 10M vs 20M）
    selector.set_bandwidth_provider([](const FourTuple& t) -> uint64_t {
        if (t.local_addr.port == 9001) return 30'000'000;  // 路径1 实测 30 Mbps
        if (t.local_addr.port == 9002) return 5'000'000;   // 路径2 实测 5 Mbps
        return 0;
    });

    assert(selector.has_bandwidth_provider());

    // 重新触发 recompute_weights（通过再次 update_candidates 或 select）
    selector.update_candidates({make_path(t1, &ctrl1, 10), make_path(t2, &ctrl2, 10)});

    auto health = selector.path_health_stats();
    assert(health.size() == 2);
    // 权重应基于实测带宽（30M > 5M，路径1 权重更高，与 pacing 相反）
    assert(health[0].weight > health[1].weight);
    printf("  [PASS] test_provider_overrides_pacing_rate\n");
}

// 15. provider 返回 0 时回退到 pacing_rate
static void test_provider_zero_falls_back() {
    MultipathCoordinatedSelector selector(2);
    MockController ctrl1(10'000'000, 65536);
    MockController ctrl2(20'000'000, 65536);

    auto t1 = make_tuple("10.0.0.1", 9001, "10.0.0.2", 9001);
    auto t2 = make_tuple("10.0.0.1", 9002, "10.0.0.3", 9002);

    selector.update_candidates({make_path(t1, &ctrl1, 10), make_path(t2, &ctrl2, 10)});

    // provider 总是返回 0（无实测数据）
    selector.set_bandwidth_provider([](const FourTuple&) -> uint64_t { return 0; });

    selector.update_candidates({make_path(t1, &ctrl1, 10), make_path(t2, &ctrl2, 10)});

    auto health = selector.path_health_stats();
    // 应回退到 pacing_rate（路径2 权重更高）
    assert(health[1].weight > health[0].weight);
    printf("  [PASS] test_provider_zero_falls_back\n");
}

// 16. 清除 provider 后回退
static void test_clear_provider_falls_back() {
    MultipathCoordinatedSelector selector(2);
    MockController ctrl1(10'000'000, 65536);
    MockController ctrl2(20'000'000, 65536);

    auto t1 = make_tuple("10.0.0.1", 9001, "10.0.0.2", 9001);
    auto t2 = make_tuple("10.0.0.1", 9002, "10.0.0.3", 9002);

    selector.update_candidates({make_path(t1, &ctrl1, 10), make_path(t2, &ctrl2, 10)});

    // 设置 provider
    selector.set_bandwidth_provider([](const FourTuple& t) -> uint64_t {
        if (t.local_addr.port == 9001) return 30'000'000;
        return 5'000'000;
    });
    assert(selector.has_bandwidth_provider());

    // 清除 provider
    selector.set_bandwidth_provider(nullptr);
    assert(!selector.has_bandwidth_provider());

    selector.update_candidates({make_path(t1, &ctrl1, 10), make_path(t2, &ctrl2, 10)});

    auto health = selector.path_health_stats();
    // 应回退到 pacing_rate（路径2 权重更高）
    assert(health[1].weight > health[0].weight);
    printf("  [PASS] test_clear_provider_falls_back\n");
}

// 17. has_bandwidth_provider 查询
static void test_has_bandwidth_provider() {
    MultipathCoordinatedSelector selector(1);
    assert(!selector.has_bandwidth_provider());

    selector.set_bandwidth_provider([](const FourTuple&) -> uint64_t { return 1000; });
    assert(selector.has_bandwidth_provider());

    selector.set_bandwidth_provider(nullptr);
    assert(!selector.has_bandwidth_provider());
    printf("  [PASS] test_has_bandwidth_provider\n");
}

// 18. 慢路径权重降低、快路径权重提升
static void test_slow_path_weight_decreases() {
    MultipathCoordinatedSelector selector(2);
    MockController ctrl1(10'000'000, 65536);
    MockController ctrl2(10'000'000, 65536);  // 相同 pacing_rate

    auto t1 = make_tuple("10.0.0.1", 9001, "10.0.0.2", 9001);
    auto t2 = make_tuple("10.0.0.1", 9002, "10.0.0.3", 9002);

    selector.update_candidates({make_path(t1, &ctrl1, 10), make_path(t2, &ctrl2, 10)});

    // 初始权重相等（相同 pacing_rate）
    auto health0 = selector.path_health_stats();
    double diff0 = std::abs(health0[0].weight - health0[1].weight);
    assert(diff0 < 0.01);  // 近似相等

    // 设置 provider：路径1 快（100M），路径2 慢（1M）
    selector.set_bandwidth_provider([](const FourTuple& t) -> uint64_t {
        if (t.local_addr.port == 9001) return 100'000'000;  // 100 Mbps
        return 1'000'000;                                    // 1 Mbps
    });

    selector.update_candidates({make_path(t1, &ctrl1, 10), make_path(t2, &ctrl2, 10)});

    auto health1 = selector.path_health_stats();
    // 路径1 权重应显著高于路径2
    assert(health1[0].weight > health1[1].weight);
    assert(health1[0].weight > 0.9);  // 100/(100+1) ≈ 0.99
    assert(health1[1].weight < 0.1);  // 1/(100+1) ≈ 0.01
    printf("  [PASS] test_slow_path_weight_decreases (fast=%.2f%% slow=%.2f%%)\n",
           health1[0].weight * 100, health1[1].weight * 100);
}

// ===== main =====

int main() {
    printf("=== v3.9.1 ConnectionMonitor 带宽反馈闭环测试 ===\n\n");

    // ConnectionMonitor 基本功能
    test_bandwidth_report();
    test_rtt_report();
    test_handshake_completed();
    test_metrics_measured();
    test_nonexistent_peer();
    test_remove_connection();
    test_clear();
    test_connection_count();
    test_is_expired();
    test_purge_expired();
    test_stats();
    test_concurrent_safety();

    // bandwidth_provider 接入
    test_no_provider_uses_pacing_rate();
    test_provider_overrides_pacing_rate();
    test_provider_zero_falls_back();
    test_clear_provider_falls_back();
    test_has_bandwidth_provider();
    test_slow_path_weight_decreases();

    printf("\n=== All 18 tests PASSED ===\n");
    return 0;
}
