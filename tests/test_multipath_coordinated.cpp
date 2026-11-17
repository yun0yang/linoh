// test_multipath_coordinated.cpp — v2.0 Phase 1 多路径协同拥塞控制加权选择器测试
//
// 验证目标：
//   1. MultipathMode::Coordinated 枚举值与名称
//   2. 空候选 / 单候选 / 多候选基础选择
//   3. BBR pacing_rate 加权分配（高 pacing 路径分配更多包）
//   4. NewReno 回退（pacing_rate=0 时按平均权重）
//   5. RTT 飙升检测（>3x baseline 时权重降低）
//   6. 高丢包率检测（>5% 时权重降低）
//   7. 健康度渐进恢复（退化路径恢复时权重回升）
//   8. skip_path 移除路径后重新归一化
//   9. 总 CWND 上限（超过 cap 时暂停选择）
//  10. update_candidates 保留已存在路径的健康度
//  11. path_health_stats 诊断输出
//  12. selection_stats / total_selections 统计
//  13. 线程安全（并发 select 不崩溃）

#include "linoh/protocol/multipath_coordinated_selector.hpp"
#include "linoh/protocol/congestion_controller.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace linoh;
using protocol::MultipathMode;
using protocol::MultipathCoordinatedSelector;
using protocol::CoordinatedPathInfo;
using protocol::CongestionController;
using protocol::CongestionAlgo;
using net::FourTuple;
using base::TransportAddr;
using base::TransportKind;

static int g_pass = 0;
static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; } \
    else { printf("  [FAIL] %s (line %d)\n", msg, __LINE__); g_fail++; } \
} while (0)

// ============================================================================
// Mock CongestionController — 可配置 pacing_rate / cwnd
// ============================================================================

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

    void set_pacing_bps(uint64_t v) { pacing_bps_ = v; }
    void set_cwnd(uint64_t v) { cwnd_ = v; }

private:
    uint64_t pacing_bps_;
    uint64_t cwnd_;
};

// ============================================================================
// 辅助：构造测试用 FourTuple
// ============================================================================

static FourTuple make_tuple(const std::string &local_ip, uint16_t local_port,
                             const std::string &remote_ip, uint16_t remote_port) {
    FourTuple t;
    t.local_addr.kind = TransportKind::Ip;
    t.local_addr.host = local_ip;
    t.local_addr.port = local_port;
    t.remote_addr.kind = TransportKind::Ip;
    t.remote_addr.host = remote_ip;
    t.remote_addr.port = remote_port;
    return t;
}

static CoordinatedPathInfo make_path(FourTuple tuple, MockController *ctrl,
                                      double srtt_ms, double loss_rate = 0.0) {
    CoordinatedPathInfo p;
    p.tuple = tuple;
    p.controller = ctrl;
    p.srtt = std::chrono::microseconds(static_cast<int64_t>(srtt_ms * 1000));
    p.loss_rate = loss_rate;
    return p;
}

// ============================================================================
// 1. MultipathMode::Coordinated 枚举测试
// ============================================================================

static void test_mode_enum() {
    printf("\n[test_mode_enum]\n");
    CHECK(std::string(protocol::multipath_mode_name(MultipathMode::Coordinated)) == "coordinated",
          "Coordinated mode name = 'coordinated'");
    CHECK(static_cast<int>(MultipathMode::Coordinated) == 3, "Coordinated enum value = 3");
}

// ============================================================================
// 2. 空候选 / 单候选基础测试
// ============================================================================

static void test_empty_and_single() {
    printf("\n[test_empty_and_single]\n");
    MultipathCoordinatedSelector s;

    // 空候选
    CHECK(s.candidate_count() == 0, "Empty: candidate_count == 0");
    CHECK(!s.select_next_for_send().has_value(), "Empty: select returns nullopt");
    CHECK(s.total_selections() == 0, "Empty: total_selections == 0");

    // 单候选
    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    MockController c1(1'000'000, 14600);
    s.update_candidates({make_path(t1, &c1, 10.0)});
    CHECK(s.candidate_count() == 1, "Single: candidate_count == 1");
    for (int i = 0; i < 5; ++i) {
        auto sel = s.select_next_for_send();
        CHECK(sel.has_value() && *sel == t1, "Single: always returns the only path");
    }
    CHECK(s.total_selections() == 5, "Single: total_selections == 5");
}

// ============================================================================
// 3. BBR pacing_rate 加权分配
// ============================================================================

static void test_pacing_rate_weighting() {
    printf("\n[test_pacing_rate_weighting]\n");
    MultipathCoordinatedSelector s;
    s.set_seed(42);  // 固定种子保证可重现

    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.3", 3000, "10.0.0.4", 4000);

    // 路径1: pacing=10Mbps, 路径2: pacing=1Mbps → 路径1 应分配 ~10x
    MockController c1(10'000'000, 14600);
    MockController c2(1'000'000, 14600);
    s.update_candidates({
        make_path(t1, &c1, 10.0),
        make_path(t2, &c2, 10.0),
    });

    // 检查权重
    auto health = s.path_health_stats();
    CHECK(health.size() == 2, "Two paths in health stats");
    CHECK(health[0].weight > 0.8, "High pacing path weight > 0.8");
    CHECK(health[1].weight < 0.2, "Low pacing path weight < 0.2");
    CHECK(health[0].pacing_rate_bps == 10'000'000, "Path1 pacing = 10Mbps");

    // 大量采样验证分配比例
    std::unordered_map<std::string, int> counts;
    for (int i = 0; i < 10000; ++i) {
        auto sel = s.select_next_for_send();
        if (sel.has_value()) {
            counts[sel->to_string()]++;
        }
    }
    // 路径1 应占 ~90%
    double ratio = static_cast<double>(counts[t1.to_string()]) / 10000.0;
    printf("    path1 ratio = %.4f (expect ~0.91)\n", ratio);
    CHECK(ratio > 0.85, "High pacing path gets >85% traffic");
    CHECK(ratio < 0.95, "High pacing path gets <95% traffic");
}

// ============================================================================
// 4. NewReno 回退（pacing_rate=0）
// ============================================================================

static void test_newreno_fallback() {
    printf("\n[test_newreno_fallback]\n");
    MultipathCoordinatedSelector s;
    s.set_seed(123);

    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.3", 3000, "10.0.0.4", 4000);

    // 两条 NewReno 路径（pacing=0）→ 应均匀分配
    MockController c1(0, 14600);
    MockController c2(0, 14600);
    s.update_candidates({
        make_path(t1, &c1, 10.0),
        make_path(t2, &c2, 10.0),
    });

    auto health = s.path_health_stats();
    CHECK(health[0].weight > 0.45 && health[0].weight < 0.55, "NewReno uniform weight ~0.5");
    CHECK(health[1].weight > 0.45 && health[1].weight < 0.55, "NewReno uniform weight ~0.5");

    // 采样验证
    std::unordered_map<std::string, int> counts;
    for (int i = 0; i < 10000; ++i) {
        auto sel = s.select_next_for_send();
        if (sel.has_value()) counts[sel->to_string()]++;
    }
    double ratio1 = static_cast<double>(counts[t1.to_string()]) / 10000.0;
    printf("    path1 ratio = %.4f (expect ~0.50)\n", ratio1);
    CHECK(ratio1 > 0.4 && ratio1 < 0.6, "NewReno paths get ~50% each");
}

// ============================================================================
// 5. NewReno + BBR 混合（NewReno 按 BBR 平均 pacing 分配）
// ============================================================================

static void test_mixed_bbr_newreno() {
    printf("\n[test_mixed_bbr_newreno]\n");
    MultipathCoordinatedSelector s;
    s.set_seed(456);

    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.3", 3000, "10.0.0.4", 4000);
    auto t3 = make_tuple("10.0.0.5", 5000, "10.0.0.6", 6000);

    // BBR 10Mbps + BBR 20Mbps + NewReno（pacing=0）
    // avg_bbr = 15Mbps → NewReno 权重 = 15Mbps
    // total = 10+20+15 = 45 → 权重 = 10/45, 20/45, 15/45
    MockController c1(10'000'000, 14600);
    MockController c2(20'000'000, 14600);
    MockController c3(0, 14600);  // NewReno
    s.update_candidates({
        make_path(t1, &c1, 10.0),
        make_path(t2, &c2, 10.0),
        make_path(t3, &c3, 10.0),
    });

    auto health = s.path_health_stats();
    CHECK(health.size() == 3, "Three paths");
    // path2 (20Mbps) 应有最高权重
    CHECK(health[1].weight > health[0].weight, "20Mbps > 10Mbps weight");
    CHECK(health[1].weight > health[2].weight, "20Mbps > NewReno weight");
    // NewReno 权重应在 BBR 之间
    CHECK(health[2].weight > health[0].weight, "NewReno(avg=15Mbps) > 10Mbps weight");
    CHECK(health[2].weight < health[1].weight, "NewReno(avg=15Mbps) < 20Mbps weight");
}

// ============================================================================
// 6. RTT 飙升检测
// ============================================================================

static void test_rtt_spike_detection() {
    printf("\n[test_rtt_spike_detection]\n");
    MultipathCoordinatedSelector s;
    s.set_seed(789);

    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.3", 3000, "10.0.0.4", 4000);

    MockController c1(10'000'000, 14600);
    MockController c2(10'000'000, 14600);

    // 初始：两条路径 RTT 均为 10ms
    s.update_candidates({
        make_path(t1, &c1, 10.0),
        make_path(t2, &c2, 10.0),
    });

    auto health_before = s.path_health_stats();
    CHECK(health_before[0].weight > 0.45 && health_before[0].weight < 0.55,
          "Before spike: ~50/50 split");
    CHECK(!health_before[0].is_degraded, "Path1 healthy before spike");

    // 路径1 RTT 飙升到 50ms（5x baseline）
    s.update_candidates({
        make_path(t1, &c1, 50.0),
        make_path(t2, &c2, 10.0),
    });

    auto health_after = s.path_health_stats();
    CHECK(health_after[0].is_degraded, "Path1 degraded after RTT spike");
    CHECK(health_after[0].degradation_reason.find("rtt_spike") != std::string::npos,
          "Degradation reason contains 'rtt_spike'");
    CHECK(health_after[0].health_multiplier < 0.6, "Health multiplier reduced < 0.6");
    CHECK(health_after[0].weight < health_after[1].weight,
          "Spiked path weight < healthy path");

    // 路径1 应分配更少流量
    std::unordered_map<std::string, int> counts;
    for (int i = 0; i < 10000; ++i) {
        auto sel = s.select_next_for_send();
        if (sel.has_value()) counts[sel->to_string()]++;
    }
    double ratio_spike = static_cast<double>(counts[t1.to_string()]) / 10000.0;
    printf("    spiked path ratio = %.4f (expect < 0.4)\n", ratio_spike);
    CHECK(ratio_spike < 0.4, "Spiked path gets <40% traffic");
}

// ============================================================================
// 7. 高丢包率检测
// ============================================================================

static void test_high_loss_detection() {
    printf("\n[test_high_loss_detection]\n");
    MultipathCoordinatedSelector s;
    s.set_seed(321);

    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.3", 3000, "10.0.0.4", 4000);

    MockController c1(10'000'000, 14600);
    MockController c2(10'000'000, 14600);

    // 路径1 丢包率 10%（>5% 阈值）
    s.update_candidates({
        make_path(t1, &c1, 10.0, 0.10),
        make_path(t2, &c2, 10.0, 0.0),
    });

    auto health = s.path_health_stats();
    CHECK(health[0].is_degraded, "Path1 degraded by high loss");
    CHECK(health[0].degradation_reason.find("high_loss") != std::string::npos,
          "Degradation reason contains 'high_loss'");
    CHECK(health[0].health_multiplier < 0.6, "Loss penalty: health < 0.6");
    CHECK(health[1].health_multiplier > 0.9, "Healthy path health > 0.9");
    CHECK(health[0].weight < health[1].weight, "Lossy path weight < clean path");
}

// ============================================================================
// 8. 健康度渐进恢复
// ============================================================================

static void test_health_recovery() {
    printf("\n[test_health_recovery]\n");
    MultipathCoordinatedSelector s;
    s.set_seed(654);

    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.3", 3000, "10.0.0.4", 4000);

    MockController c1(10'000'000, 14600);
    MockController c2(10'000'000, 14600);

    // 阶段0：建立正常 baseline（RTT=10ms）
    s.update_candidates({
        make_path(t1, &c1, 10.0),
        make_path(t2, &c2, 10.0),
    });

    // 阶段1：路径1 RTT 飙升到 50ms（5x baseline=10ms）
    s.update_candidates({
        make_path(t1, &c1, 50.0),
        make_path(t2, &c2, 10.0),
    });
    auto h1 = s.path_health_stats();
    CHECK(h1[0].health_multiplier < 0.6, "Phase1: spiked path health < 0.6");
    double degraded_health = h1[0].health_multiplier;

    // 阶段2：路径1 RTT 恢复正常（update_candidates 触发 recompute_weights → update_health）
    // update_health 在无退化时应向 1.0 渐进恢复 kRecoveryGain=0.1
    s.update_candidates({
        make_path(t1, &c1, 10.0),  // 恢复正常
        make_path(t2, &c2, 10.0),
    });
    auto h2 = s.path_health_stats();
    CHECK(h2[0].health_multiplier > degraded_health,
          "Phase2: health recovered > degraded value");
    CHECK(h2[0].health_multiplier < 1.0, "Phase2: health not fully recovered yet (gradual)");

    // 阶段3：多次更新后完全恢复
    for (int i = 0; i < 10; ++i) {
        s.update_candidates({
            make_path(t1, &c1, 10.0),
            make_path(t2, &c2, 10.0),
        });
    }
    auto h3 = s.path_health_stats();
    CHECK(h3[0].health_multiplier > 0.95, "Phase3: health fully recovered > 0.95");
    CHECK(!h3[0].is_degraded, "Phase3: path no longer degraded");
}

// ============================================================================
// 9. skip_path 移除路径
// ============================================================================

static void test_skip_path() {
    printf("\n[test_skip_path]\n");
    MultipathCoordinatedSelector s;
    s.set_seed(987);

    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.3", 3000, "10.0.0.4", 4000);
    auto t3 = make_tuple("10.0.0.5", 5000, "10.0.0.6", 6000);

    MockController c1(5'000'000, 14600);
    MockController c2(10'000'000, 14600);
    MockController c3(15'000'000, 14600);

    s.update_candidates({
        make_path(t1, &c1, 10.0),
        make_path(t2, &c2, 10.0),
        make_path(t3, &c3, 10.0),
    });
    CHECK(s.candidate_count() == 3, "Initial: 3 candidates");

    // 移除路径2
    s.skip_path(t2);
    CHECK(s.candidate_count() == 2, "After skip: 2 candidates");

    // 剩余路径权重应重新归一化（总和 = 1.0）
    auto health = s.path_health_stats();
    double total_weight = 0.0;
    for (const auto &h : health) total_weight += h.weight;
    CHECK(total_weight > 0.99 && total_weight < 1.01, "Weights renormalized sum=1.0");

    // 选择不再返回已移除的路径
    for (int i = 0; i < 100; ++i) {
        auto sel = s.select_next_for_send();
        if (sel.has_value()) {
            CHECK(*sel != t2, "Skipped path not selected");
        }
    }
}

// ============================================================================
// 10. 总 CWND 上限
// ============================================================================

static void test_total_cwnd_cap() {
    printf("\n[test_total_cwnd_cap]\n");
    MultipathCoordinatedSelector s;
    s.set_seed(111);

    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.3", 3000, "10.0.0.4", 4000);

    // 路径1 cwnd=10000, 路径2 cwnd=10000 → total=20000
    MockController c1(10'000'000, 10000);
    MockController c2(10'000'000, 10000);
    s.update_candidates({
        make_path(t1, &c1, 10.0),
        make_path(t2, &c2, 10.0),
    });

    CHECK(s.total_cwnd_bytes() == 20000, "Total CWND = 20000");

    // 设置 cap=15000 → total(20000) > cap → 选择被阻塞
    s.set_total_cwnd_cap(15000);
    CHECK(s.total_cwnd_cap() == 15000, "CWND cap = 15000");
    CHECK(s.total_cwnd_bytes() == 20000, "Total CWND still 20000 (cap doesn't change actual)");

    auto sel = s.select_next_for_send();
    CHECK(!sel.has_value(), "Select blocked when total_cwnd > cap");

    // 提高 cap=30000 → total(20000) < cap → 选择恢复
    s.set_total_cwnd_cap(30000);
    sel = s.select_next_for_send();
    CHECK(sel.has_value(), "Select resumes when cap raised");

    // cap=0 表示不限制
    s.set_total_cwnd_cap(0);
    sel = s.select_next_for_send();
    CHECK(sel.has_value(), "Select works when cap=0 (unlimited)");
}

// ============================================================================
// 11. update_candidates 保留健康度
// ============================================================================

static void test_preserve_health_on_update() {
    printf("\n[test_preserve_health_on_update]\n");
    MultipathCoordinatedSelector s;
    s.set_seed(222);

    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.3", 3000, "10.0.0.4", 4000);

    MockController c1(10'000'000, 14600);
    MockController c2(10'000'000, 14600);

    // 阶段0：建立正常 baseline（RTT=10ms）
    s.update_candidates({
        make_path(t1, &c1, 10.0),
        make_path(t2, &c2, 10.0),
    });

    // 阶段1：路径1 RTT 飙升到 50ms（5x baseline=10ms）
    s.update_candidates({
        make_path(t1, &c1, 50.0),
        make_path(t2, &c2, 10.0),
    });
    auto h1 = s.path_health_stats();
    double degraded = h1[0].health_multiplier;
    CHECK(degraded < 0.6, "Path1 degraded initially");

    // 阶段2：路径1 仍然退化（RTT 保持 50ms），验证 health_multiplier 被保留
    s.update_candidates({
        make_path(t1, &c1, 50.0),
        make_path(t2, &c2, 10.0),
    });
    auto h2 = s.path_health_stats();
    // health_multiplier 应保持在退化水平附近（不重置为 1.0）
    CHECK(h2[0].health_multiplier < 0.7, "Path1 still degraded after update (health preserved)");
}

// ============================================================================
// 12. selection_stats / total_selections 统计
// ============================================================================

static void test_selection_stats() {
    printf("\n[test_selection_stats]\n");
    MultipathCoordinatedSelector s;
    s.set_seed(333);

    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.3", 3000, "10.0.0.4", 4000);

    MockController c1(10'000'000, 14600);
    MockController c2(10'000'000, 14600);
    s.update_candidates({
        make_path(t1, &c1, 10.0),
        make_path(t2, &c2, 10.0),
    });

    for (int i = 0; i < 100; ++i) {
        s.select_next_for_send();
    }

    auto stats = s.selection_stats();
    CHECK(stats.size() == 2, "selection_stats has 2 entries");
    uint64_t total = 0;
    for (const auto &[tuple, count] : stats) {
        total += count;
    }
    CHECK(total == 100, "Total selections = 100");
    CHECK(s.total_selections() == 100, "total_selections() = 100");
}

// ============================================================================
// 13. 线程安全（并发 select 不崩溃）
// ============================================================================

static void test_thread_safety() {
    printf("\n[test_thread_safety]\n");
    MultipathCoordinatedSelector s;
    s.set_seed(444);

    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.3", 3000, "10.0.0.4", 4000);
    auto t3 = make_tuple("10.0.0.5", 5000, "10.0.0.6", 6000);

    MockController c1(5'000'000, 14600);
    MockController c2(10'000'000, 14600);
    MockController c3(15'000'000, 14600);

    s.update_candidates({
        make_path(t1, &c1, 10.0),
        make_path(t2, &c2, 10.0),
        make_path(t3, &c3, 10.0),
    });

    std::atomic<int> total{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < 1000; ++i) {
                auto sel = s.select_next_for_send();
                if (sel.has_value()) {
                    total.fetch_add(1);
                }
            }
        });
    }
    for (auto &t : threads) t.join();

    CHECK(total.load() == 4000, "Concurrent: 4000 total selections");
    CHECK(s.total_selections() == 4000, "total_selections matches concurrent count");
}

// ============================================================================
// 14. 无控制器路径（controller=nullptr）
// ============================================================================

static void test_null_controller() {
    printf("\n[test_null_controller]\n");
    MultipathCoordinatedSelector s;
    s.set_seed(555);

    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.3", 3000, "10.0.0.4", 4000);

    // 路径1 有控制器，路径2 无控制器
    MockController c1(10'000'000, 14600);
    s.update_candidates({
        make_path(t1, &c1, 10.0),
        make_path(t2, nullptr, 10.0),  // null controller
    });

    auto health = s.path_health_stats();
    CHECK(health[1].pacing_rate_bps == 0, "Null controller pacing = 0");
    CHECK(health[1].cwnd_bytes == 0, "Null controller cwnd = 0");
    // null controller 按 NewReno 处理，用 avg_bbr_pacing 作为权重
    // avg = 10Mbps → 两条路径权重各 50%
    CHECK(health[0].weight > 0.4 && health[0].weight < 0.6, "Null ctrl: path1 ~50%");
    CHECK(health[1].weight > 0.4 && health[1].weight < 0.6, "Null ctrl: path2 ~50%");

    // total_cwnd_bytes 只计算有控制器的路径
    CHECK(s.total_cwnd_bytes() == 14600, "total_cwnd only counts non-null controllers");
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    printf("=== test_multipath_coordinated ===\n");

    test_mode_enum();
    test_empty_and_single();
    test_pacing_rate_weighting();
    test_newreno_fallback();
    test_mixed_bbr_newreno();
    test_rtt_spike_detection();
    test_high_loss_detection();
    test_health_recovery();
    test_skip_path();
    test_total_cwnd_cap();
    test_preserve_health_on_update();
    test_selection_stats();
    test_thread_safety();
    test_null_controller();

    printf("\n=== Summary: %d PASS / %d FAIL ===\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
