// test_multipath_selector.cpp — P5-B-3 多路径 strip/adaptive 选择器测试
//
// 验证：
//   - MultipathMode 枚举与 multipath_mode_name
//   - MultipathStripSelector：空候选、单候选、round-robin 循环、skip_current、
//     update_candidates 重置、selection_stats、负载均衡（4 路径 ±5%）
//   - MultipathAdaptiveSelector：空候选、单候选、加权分配（RTT 反比）、
//     skip_path 移除、selection_stats、加权比例验证（RTT=10ms 与 100ms ~10x）
//   - 故障切换：路径故障时自动切换到其他路径

#include "linoh/protocol/multipath_selector.hpp"

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <unordered_map>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh;
using protocol::MultipathMode;
using protocol::MultipathStripSelector;
using protocol::MultipathAdaptiveSelector;
using net::FourTuple;
using base::TransportAddr;
using base::TransportKind;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 辅助：构造测试用 FourTuple
// ============================================================================

static FourTuple make_tuple(const std::string &local_ip, std::uint16_t local_port,
                              const std::string &remote_ip, std::uint16_t remote_port) {
    FourTuple t;
    t.local_addr.kind = TransportKind::Ip;
    t.local_addr.host = local_ip;
    t.local_addr.port = local_port;
    t.remote_addr.kind = TransportKind::Ip;
    t.remote_addr.host = remote_ip;
    t.remote_addr.port = remote_port;
    return t;
}

// ============================================================================
// MultipathMode 枚举测试
// ============================================================================

static void test_mode_name() {
    CHECK(std::string(protocol::multipath_mode_name(MultipathMode::Backup))   == "backup");
    CHECK(std::string(protocol::multipath_mode_name(MultipathMode::Strip))    == "strip");
    CHECK(std::string(protocol::multipath_mode_name(MultipathMode::Adaptive)) == "adaptive");
}

// ============================================================================
// MultipathStripSelector 测试
// ============================================================================

static void test_strip_empty() {
    MultipathStripSelector s;
    CHECK(s.candidate_count() == 0);
    CHECK(!s.select_next_for_send().has_value());
    CHECK(s.total_selections() == 0);
}

static void test_strip_single_candidate() {
    MultipathStripSelector s;
    auto t = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    s.update_candidates({t});

    CHECK(s.candidate_count() == 1);
    for (int i = 0; i < 10; ++i) {
        auto sel = s.select_next_for_send();
        CHECK(sel.has_value());
        CHECK(sel.value() == t);
    }
    CHECK(s.total_selections() == 10);
}

static void test_strip_round_robin() {
    MultipathStripSelector s;
    std::vector<FourTuple> paths = {
        make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1002, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1003, "10.0.0.2", 2000),
    };
    s.update_candidates(paths);

    CHECK(s.candidate_count() == 4);
    // round-robin: 0, 1, 2, 3, 0, 1, 2, 3, ...
    for (int round = 0; round < 3; ++round) {
        for (int i = 0; i < 4; ++i) {
            auto sel = s.select_next_for_send();
            CHECK(sel.has_value());
            CHECK(sel.value() == paths[i]);
        }
    }
    CHECK(s.total_selections() == 12);
}

static void test_strip_skip_current() {
    MultipathStripSelector s;
    std::vector<FourTuple> paths = {
        make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1002, "10.0.0.2", 2000),
    };
    s.update_candidates(paths);

    // 第一条
    auto s1 = s.select_next_for_send();
    CHECK(s1.value() == paths[0]);
    // skip_current 跳过 paths[1]，下一条应该是 paths[2]
    s.skip_current();
    auto s2 = s.select_next_for_send();
    CHECK(s2.value() == paths[2]);
}

static void test_strip_update_resets() {
    MultipathStripSelector s;
    std::vector<FourTuple> paths1 = {
        make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000),
    };
    s.update_candidates(paths1);
    s.select_next_for_send();  // idx 0
    s.select_next_for_send();  // idx 1
    CHECK(s.total_selections() == 2);

    // 更新候选会重置计数和索引
    std::vector<FourTuple> paths2 = {
        make_tuple("10.0.0.1", 2000, "10.0.0.3", 3000),
    };
    s.update_candidates(paths2);
    CHECK(s.candidate_count() == 1);
    CHECK(s.total_selections() == 0);

    auto sel = s.select_next_for_send();
    CHECK(sel.value() == paths2[0]);
}

static void test_strip_selection_stats() {
    MultipathStripSelector s;
    std::vector<FourTuple> paths = {
        make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000),
    };
    s.update_candidates(paths);

    // 选择 5 次：idx 0 三次，idx 1 两次（0,1,0,1,0）
    for (int i = 0; i < 5; ++i) s.select_next_for_send();

    auto stats = s.selection_stats();
    CHECK(stats.size() == 2);
    CHECK(stats[0].first == paths[0]);
    CHECK(stats[0].second == 3);
    CHECK(stats[1].first == paths[1]);
    CHECK(stats[1].second == 2);
}

static void test_strip_load_balance() {
    // 4 路径 round-robin 1000 次选择，每条应分配 250 次（±5%）
    MultipathStripSelector s;
    std::vector<FourTuple> paths = {
        make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1002, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1003, "10.0.0.2", 2000),
    };
    s.update_candidates(paths);

    const int N = 1000;
    for (int i = 0; i < N; ++i) s.select_next_for_send();

    auto stats = s.selection_stats();
    CHECK(stats.size() == 4);
    // round-robin 严格均衡，每条 N/4 = 250
    for (auto &p : stats) {
        CHECK(p.second == 250);
    }
    CHECK(s.total_selections() == 1000);
}

// ============================================================================
// MultipathAdaptiveSelector 测试
// ============================================================================

static void test_adaptive_empty() {
    MultipathAdaptiveSelector s;
    CHECK(s.candidate_count() == 0);
    CHECK(!s.select_next_for_send().has_value());
    CHECK(s.total_selections() == 0);
}

static void test_adaptive_single_candidate() {
    MultipathAdaptiveSelector s;
    auto t = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    s.update_candidates({MultipathAdaptiveSelector::PathInfo{t, std::chrono::microseconds(10000)}});

    CHECK(s.candidate_count() == 1);
    for (int i = 0; i < 10; ++i) {
        auto sel = s.select_next_for_send();
        CHECK(sel.has_value());
        CHECK(sel.value() == t);
    }
    CHECK(s.total_selections() == 10);
}

static void test_adaptive_weighted_distribution() {
    // RTT=10ms 与 RTT=100ms 的两条路径，前者应分配约 10 倍
    MultipathAdaptiveSelector s;
    s.set_seed(42);  // 固定种子确保可重现
    std::vector<MultipathAdaptiveSelector::PathInfo> paths = {
        {make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000), std::chrono::microseconds(10000)},   // 10ms
        {make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000), std::chrono::microseconds(100000)},  // 100ms
    };
    s.update_candidates(paths);

    const int N = 10000;
    for (int i = 0; i < N; ++i) s.select_next_for_send();

    auto stats = s.selection_stats();
    CHECK(stats.size() == 2);
    CHECK(s.total_selections() == N);

    // RTT=10ms 应分配 ~90.9%（10/(10+1)），RTT=100ms ~9.1%
    // 允许 ±5% 偏差
    double ratio_fast = static_cast<double>(stats[0].second) / N;
    double ratio_slow = static_cast<double>(stats[1].second) / N;
    std::printf("  Adaptive ratio: fast=%.3f slow=%.3f\n", ratio_fast, ratio_slow);
    CHECK(ratio_fast > 0.85);  // 快路径占比 > 85%
    CHECK(ratio_slow < 0.15);  // 慢路径占比 < 15%
}

static void test_adaptive_equal_rtt() {
    // 相同 RTT 的两条路径应接近 50/50 分配
    MultipathAdaptiveSelector s;
    s.set_seed(123);
    std::vector<MultipathAdaptiveSelector::PathInfo> paths = {
        {make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000), std::chrono::microseconds(50000)},
        {make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000), std::chrono::microseconds(50000)},
    };
    s.update_candidates(paths);

    const int N = 10000;
    for (int i = 0; i < N; ++i) s.select_next_for_send();

    auto stats = s.selection_stats();
    CHECK(stats.size() == 2);
    // 允许 ±10% 偏差
    double r0 = static_cast<double>(stats[0].second) / N;
    double r1 = static_cast<double>(stats[1].second) / N;
    std::printf("  Adaptive equal-RTT ratio: p0=%.3f p1=%.3f\n", r0, r1);
    CHECK(r0 > 0.40);
    CHECK(r0 < 0.60);
    CHECK(r1 > 0.40);
    CHECK(r1 < 0.60);
}

static void test_adaptive_skip_path() {
    MultipathAdaptiveSelector s;
    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000);
    auto t3 = make_tuple("10.0.0.1", 1002, "10.0.0.2", 2000);
    s.update_candidates({
        {t1, std::chrono::microseconds(10000)},
        {t2, std::chrono::microseconds(20000)},
        {t3, std::chrono::microseconds(30000)},
    });

    CHECK(s.candidate_count() == 3);
    s.skip_path(t2);
    CHECK(s.candidate_count() == 2);

    // 剩余两条都应能被选中
    std::unordered_map<FourTuple, int, FourTuple::Hash> hits;
    for (int i = 0; i < 1000; ++i) {
        auto sel = s.select_next_for_send();
        CHECK(sel.has_value());
        hits[sel.value()]++;
    }
    CHECK(hits.size() == 2);
    CHECK(hits.count(t1) > 0);
    CHECK(hits.count(t3) > 0);
    CHECK(hits.count(t2) == 0);
}

static void test_adaptive_unmeasured_rtt() {
    // srtt=0 的路径按平均处理
    MultipathAdaptiveSelector s;
    s.set_seed(999);
    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000);
    s.update_candidates({
        {t1, std::chrono::microseconds(10000)},  // 已测量 10ms
        {t2, std::chrono::microseconds(0)},        // 未测量
    });

    // 未测量路径按已测量路径的平均 RTT 处理 = 10ms，两条路径权重相等
    const int N = 1000;
    for (int i = 0; i < N; ++i) s.select_next_for_send();

    auto stats = s.selection_stats();
    CHECK(stats.size() == 2);
    // 两条路径权重相等，应接近 50/50（允许 ±15% 偏差）
    double r0 = static_cast<double>(stats[0].second) / N;
    double r1 = static_cast<double>(stats[1].second) / N;
    std::printf("  Adaptive unmeasured ratio: p0=%.3f p1=%.3f\n", r0, r1);
    CHECK(r0 > 0.35);
    CHECK(r0 < 0.65);
    CHECK(r1 > 0.35);
    CHECK(r1 < 0.65);
}

static void test_adaptive_selection_stats() {
    MultipathAdaptiveSelector s;
    s.set_seed(7);
    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000);
    s.update_candidates({
        {t1, std::chrono::microseconds(10000)},
        {t2, std::chrono::microseconds(20000)},
    });

    for (int i = 0; i < 100; ++i) s.select_next_for_send();

    auto stats = s.selection_stats();
    CHECK(stats.size() == 2);
    std::uint64_t total = stats[0].second + stats[1].second;
    CHECK(total == 100);
    CHECK(s.total_selections() == 100);
}

// ============================================================================
// 故障切换测试
// ============================================================================

static void test_strip_failover() {
    // 4 路径 round-robin，模拟一条故障后剩余 3 条仍能正常分发
    MultipathStripSelector s;
    std::vector<FourTuple> paths = {
        make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1002, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1003, "10.0.0.2", 2000),
    };
    s.update_candidates(paths);

    // 选 3 次：0, 1, 2
    s.select_next_for_send();  // paths[0]
    s.select_next_for_send();  // paths[1]
    s.select_next_for_send();  // paths[2]

    // paths[3] 故障，从候选中移除
    std::vector<FourTuple> remaining(paths.begin(), paths.begin() + 3);
    s.update_candidates(remaining);
    CHECK(s.candidate_count() == 3);

    // 后续分发只在剩余 3 条
    for (int i = 0; i < 30; ++i) {
        auto sel = s.select_next_for_send();
        CHECK(sel.has_value());
        CHECK(sel.value() != paths[3]);
    }
}

static void test_adaptive_failover() {
    // 自适应选择器，一条路径故障后剩余路径仍能正常分发
    MultipathAdaptiveSelector s;
    s.set_seed(2024);
    auto t1 = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto t2 = make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000);
    auto t3 = make_tuple("10.0.0.1", 1002, "10.0.0.2", 2000);
    s.update_candidates({
        {t1, std::chrono::microseconds(10000)},
        {t2, std::chrono::microseconds(20000)},
        {t3, std::chrono::microseconds(30000)},
    });

    // 选 100 次
    for (int i = 0; i < 100; ++i) s.select_next_for_send();
    CHECK(s.total_selections() == 100);

    // t2 故障，移除
    s.skip_path(t2);
    CHECK(s.candidate_count() == 2);

    // 后续分发只在 t1, t3
    for (int i = 0; i < 100; ++i) {
        auto sel = s.select_next_for_send();
        CHECK(sel.has_value());
        CHECK(sel.value() != t2);
    }
}

// ============================================================================
// 三种模式对比测试
// ============================================================================

static void test_three_modes_consistent() {
    // 三种模式都应能处理 3 路径候选
    std::vector<FourTuple> paths = {
        make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1001, "10.0.0.2", 2000),
        make_tuple("10.0.0.1", 1002, "10.0.0.2", 2000),
    };

    // Backup 模式：通过现有 PathSelectionStrategy（此处不验证）
    // Strip 模式
    MultipathStripSelector strip;
    strip.update_candidates(paths);
    CHECK(strip.candidate_count() == 3);

    // Adaptive 模式
    MultipathAdaptiveSelector adaptive;
    std::vector<MultipathAdaptiveSelector::PathInfo> info;
    for (auto &p : paths) info.push_back({p, std::chrono::microseconds(10000)});
    adaptive.update_candidates(info);
    CHECK(adaptive.candidate_count() == 3);
}

int main() {
    std::printf("=== test_multipath_selector ===\n");

    test_mode_name();

    test_strip_empty();
    test_strip_single_candidate();
    test_strip_round_robin();
    test_strip_skip_current();
    test_strip_update_resets();
    test_strip_selection_stats();
    test_strip_load_balance();

    test_adaptive_empty();
    test_adaptive_single_candidate();
    test_adaptive_weighted_distribution();
    test_adaptive_equal_rtt();
    test_adaptive_skip_path();
    test_adaptive_unmeasured_rtt();
    test_adaptive_selection_stats();

    test_strip_failover();
    test_adaptive_failover();

    test_three_modes_consistent();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
