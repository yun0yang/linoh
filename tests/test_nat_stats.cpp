// test_nat_stats.cpp — P5-D-2 NAT 穿透统计模型单元测试
//
// 测试覆盖：
//   1. record_and_query — 记录 + 查询统计快照
//   2. success_rate_calc — 成功率计算正确
//   3. cold_start_fallback — 样本 <10 回退（recommend 返回 nullopt）
//   4. recommend_strategy — 策略推荐排序
//   5. per_carrier_stats — 按运营商分维度统计
//   6. per_region_stats — 按区域分维度统计
//   7. lru_records_limit — 单维度 max_records_per_key 上限
//   8. concurrent_record — 多线程并发记录线程安全
//   9. global_success_rate — 全局命中率监控
//  10. persistence_roundtrip — 持久化往返（save/load）
//  11. query_strategies — 各策略统计查询
//  12. default_candidates — 默认候选策略列表
//  13. key_count_total_records — 监控接口
//  14. geo_region_parse — GeoRegion 解析
//  15. stats_key_equality — StatsKey 相等性
//  16. strategy_stats_score — StrategyStats 评分公式

#include "linoh/nat/nat_stats.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <thread>
#include <vector>

using namespace linoh::nat;
using namespace linoh::net;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    if ((a) == (b)) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s != %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

#define CHECK_NE(a, b) do { \
    if ((a) != (b)) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ========== 测试用例 ==========

// 1. record_and_query — 记录 + 查询统计快照
static void test_record_and_query() {
    std::printf("[test] record_and_query...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};

    // 记录 5 次成功 + 5 次失败
    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }
    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, false,
                                        std::chrono::milliseconds(300)));
    }

    StatsSnapshot snap = stats.query(key);
    CHECK_EQ(snap.total, std::uint64_t(10));
    CHECK_EQ(snap.success, std::uint64_t(5));
    CHECK_EQ(snap.success_rate, 0.5);
}

// 2. success_rate_calc — 成功率计算正确
static void test_success_rate_calc() {
    std::printf("[test] success_rate_calc...\n");
    NatStats stats;
    StatsKey key{NatType::FullCone, "电信", GeoRegion::South};

    // 3 成功 / 7 失败 = 0.3
    for (int i = 0; i < 3; ++i) {
        stats.record(PenetrationRecord(NatType::FullCone, "电信", GeoRegion::South,
                                        CgnStrategy::StandardRfc5389, true,
                                        std::chrono::milliseconds(100)));
    }
    for (int i = 0; i < 7; ++i) {
        stats.record(PenetrationRecord(NatType::FullCone, "电信", GeoRegion::South,
                                        CgnStrategy::StandardRfc5389, false,
                                        std::chrono::milliseconds(100)));
    }

    StatsSnapshot snap = stats.query(key);
    CHECK_EQ(snap.total, std::uint64_t(10));
    CHECK_EQ(snap.success, std::uint64_t(3));
    // 成功率 0.3（允许浮点误差）
    CHECK(snap.success_rate > 0.29 && snap.success_rate < 0.31);
}

// 3. cold_start_fallback — 样本 <10 回退
static void test_cold_start_fallback() {
    std::printf("[test] cold_start_fallback...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "联通", GeoRegion::North};

    // 仅 5 条记录（< cold_start_threshold=10）
    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "联通", GeoRegion::North,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }

    auto candidates = default_candidates(NatType::Symmetric);
    auto rec = stats.recommend_strategy(key, candidates);
    // 冷启动应返回 nullopt（调用方回退 CGN 规则）
    CHECK(!rec.has_value());

    // 但 query 仍可返回统计快照
    StatsSnapshot snap = stats.query(key);
    CHECK_EQ(snap.total, std::uint64_t(5));
    CHECK(snap.is_cold_start());  // 5 < 10
}

// 4. recommend_strategy — 策略推荐排序
static void test_recommend_strategy() {
    std::printf("[test] recommend_strategy...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};

    // SymmetricNat 策略：8 成功 / 2 失败 = 0.8
    for (int i = 0; i < 8; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }
    for (int i = 0; i < 2; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, false,
                                        std::chrono::milliseconds(200)));
    }
    // RelayFallback 策略：3 成功 / 7 失败 = 0.3
    for (int i = 0; i < 3; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::RelayFallback, true,
                                        std::chrono::milliseconds(300)));
    }
    for (int i = 0; i < 7; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::RelayFallback, false,
                                        std::chrono::milliseconds(300)));
    }

    auto candidates = default_candidates(NatType::Symmetric);
    auto rec = stats.recommend_strategy(key, candidates);
    CHECK(rec.has_value());
    // SymmetricNat(0.8) 应优于 RelayFallback(0.3)
    CHECK_EQ(rec->first, CgnStrategy::SymmetricNat);
    CHECK(rec->second > 0.79 && rec->second < 0.81);
}

// 5. per_carrier_stats — 按运营商分维度统计
static void test_per_carrier_stats() {
    std::printf("[test] per_carrier_stats...\n");
    NatStats stats;

    // 移动：10 条
    for (int i = 0; i < 10; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }
    // 电信：5 条
    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "电信", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }

    StatsSnapshot mobile = stats.query({NatType::Symmetric, "移动", GeoRegion::East});
    StatsSnapshot telecom = stats.query({NatType::Symmetric, "电信", GeoRegion::East});
    CHECK_EQ(mobile.total, std::uint64_t(10));
    CHECK_EQ(telecom.total, std::uint64_t(5));
    CHECK_EQ(stats.key_count(), std::size_t(2));
}

// 6. per_region_stats — 按区域分维度统计
static void test_per_region_stats() {
    std::printf("[test] per_region_stats...\n");
    NatStats stats;

    for (int i = 0; i < 10; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }
    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::South,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }

    StatsSnapshot east = stats.query({NatType::Symmetric, "移动", GeoRegion::East});
    StatsSnapshot south = stats.query({NatType::Symmetric, "移动", GeoRegion::South});
    CHECK_EQ(east.total, std::uint64_t(10));
    CHECK_EQ(south.total, std::uint64_t(5));
}

// 7. lru_records_limit — 单维度 max_records_per_key 上限
static void test_lru_records_limit() {
    std::printf("[test] lru_records_limit...\n");
    NatStatsConfig cfg;
    cfg.max_records_per_key = 100;  // 小上限便于测试
    NatStats stats(cfg);
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};

    // 插入 200 条
    for (int i = 0; i < 200; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, i % 2 == 0,
                                        std::chrono::milliseconds(200)));
    }

    StatsSnapshot snap = stats.query(key);
    // total 维护的是累计计数（不受 LRU 影响），records deque 才受 LRU 限制
    CHECK_EQ(snap.total, std::uint64_t(200));
    // global_success_rate 反映累计统计
    double rate = stats.global_success_rate();
    CHECK(rate > 0.49 && rate < 0.51);  // 100/200 = 0.5
}

// 8. concurrent_record — 多线程并发记录线程安全
static void test_concurrent_record() {
    std::printf("[test] concurrent_record...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};

    constexpr int kThreads = 8;
    constexpr int kPerThread = 50;
    std::vector<std::thread> threads;
    std::atomic<int> ok_count{0};

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&stats, &ok_count, t]() {
            for (int i = 0; i < kPerThread; ++i) {
                stats.record(PenetrationRecord(
                    NatType::Symmetric, "移动", GeoRegion::East,
                    CgnStrategy::SymmetricNat, (t + i) % 2 == 0,
                    std::chrono::milliseconds(200)));
                ++ok_count;
            }
        });
    }
    for (auto &th : threads) th.join();

    CHECK_EQ(ok_count.load(), kThreads * kPerThread);
    StatsSnapshot snap = stats.query(key);
    CHECK_EQ(snap.total, std::uint64_t(kThreads * kPerThread));
}

// 9. global_success_rate — 全局命中率监控
static void test_global_success_rate() {
    std::printf("[test] global_success_rate...\n");
    NatStats stats;

    // 维度1：5 成功 / 5 失败
    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }
    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, false,
                                        std::chrono::milliseconds(200)));
    }
    // 维度2：3 成功 / 0 失败
    for (int i = 0; i < 3; ++i) {
        stats.record(PenetrationRecord(NatType::FullCone, "电信", GeoRegion::South,
                                        CgnStrategy::StandardRfc5389, true,
                                        std::chrono::milliseconds(100)));
    }

    double rate = stats.global_success_rate();
    // (5+3) / (5+5+3) = 8/13 ≈ 0.615
    CHECK(rate > 0.60 && rate < 0.63);
}

// 10. persistence_roundtrip — 持久化往返
static void test_persistence_roundtrip() {
    std::printf("[test] persistence_roundtrip...\n");
    NatStatsConfig cfg;
    cfg.persistence_path = "build/test_nat_stats_persistence.tsv";
    // 清理残留文件（方案 A 下 NatStats 构造函数会自动 load，若不清理残留数据会被加载）
    std::remove(cfg.persistence_path.c_str());
    NatStats stats(cfg);

    for (int i = 0; i < 15; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, i % 2 == 0,
                                        std::chrono::milliseconds(200 + i)));
    }
    for (int i = 0; i < 10; ++i) {
        stats.record(PenetrationRecord(NatType::FullCone, "电信", GeoRegion::South,
                                        CgnStrategy::StandardRfc5389, true,
                                        std::chrono::milliseconds(100)));
    }

    bool saved = stats.save_to_file();
    CHECK(saved);

    NatStats stats2(cfg);
    int loaded = stats2.load_from_file();
    CHECK_EQ(loaded, 25);

    // 验证统计一致
    StatsKey key1{NatType::Symmetric, "移动", GeoRegion::East};
    StatsKey key2{NatType::FullCone, "电信", GeoRegion::South};
    StatsSnapshot s1_new = stats.query(key1);
    StatsSnapshot s1_loaded = stats2.query(key1);
    StatsSnapshot s2_new = stats.query(key2);
    StatsSnapshot s2_loaded = stats2.query(key2);

    CHECK_EQ(s1_new.total, s1_loaded.total);
    CHECK_EQ(s1_new.success, s1_loaded.success);
    CHECK_EQ(s2_new.total, s2_loaded.total);
    CHECK_EQ(s2_new.success, s2_loaded.success);
}

// 11. query_strategies — 各策略统计查询
static void test_query_strategies() {
    std::printf("[test] query_strategies...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};

    // SymmetricNat: 8/10 = 0.8
    for (int i = 0; i < 8; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }
    for (int i = 0; i < 2; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, false,
                                        std::chrono::milliseconds(200)));
    }
    // RelayFallback: 3/10 = 0.3
    for (int i = 0; i < 3; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::RelayFallback, true,
                                        std::chrono::milliseconds(300)));
    }
    for (int i = 0; i < 7; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::RelayFallback, false,
                                        std::chrono::milliseconds(300)));
    }

    auto strats = stats.query_strategies(key);
    CHECK_EQ(strats.size(), std::size_t(2));
    // 按成功率降序：SymmetricNat(0.8) 在前
    CHECK_EQ(strats[0].strategy, CgnStrategy::SymmetricNat);
    CHECK_EQ(strats[1].strategy, CgnStrategy::RelayFallback);
    CHECK(strats[0].success_rate > strats[1].success_rate);
}

// 12. default_candidates — 默认候选策略列表
static void test_default_candidates() {
    std::printf("[test] default_candidates...\n");

    auto sym = default_candidates(NatType::Symmetric);
    CHECK(!sym.empty());
    CHECK_EQ(sym[0], CgnStrategy::SymmetricNat);  // 对称 NAT 首选端口预测

    auto cone = default_candidates(NatType::FullCone);
    CHECK(!cone.empty());
    CHECK_EQ(cone[0], CgnStrategy::StandardRfc5389);  // Cone NAT 首选标准打洞

    auto open = default_candidates(NatType::OpenInternet);
    CHECK(!open.empty());
    CHECK_EQ(open[0], CgnStrategy::DirectConnect);  // 公网直连

    auto unknown = default_candidates(NatType::Unknown);
    CHECK(unknown.size() >= 3);  // 未知情况全策略候选
}

// 13. key_count_total_records — 监控接口
static void test_key_count_total_records() {
    std::printf("[test] key_count_total_records...\n");
    NatStats stats;

    CHECK_EQ(stats.key_count(), std::size_t(0));
    CHECK_EQ(stats.total_records(), std::uint64_t(0));

    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }
    for (int i = 0; i < 3; ++i) {
        stats.record(PenetrationRecord(NatType::FullCone, "电信", GeoRegion::South,
                                        CgnStrategy::StandardRfc5389, true,
                                        std::chrono::milliseconds(100)));
    }

    CHECK_EQ(stats.key_count(), std::size_t(2));
    CHECK_EQ(stats.total_records(), std::uint64_t(8));
}

// 14. geo_region_parse — GeoRegion 解析
static void test_geo_region_parse() {
    std::printf("[test] geo_region_parse...\n");
    CHECK_EQ(parse_geo_region("north"), GeoRegion::North);
    CHECK_EQ(parse_geo_region("south"), GeoRegion::South);
    CHECK_EQ(parse_geo_region("east"), GeoRegion::East);
    CHECK_EQ(parse_geo_region("central"), GeoRegion::Central);
    CHECK_EQ(parse_geo_region("overseas"), GeoRegion::Overseas);
    CHECK_EQ(parse_geo_region("invalid"), GeoRegion::Unknown);
    CHECK_EQ(parse_geo_region(""), GeoRegion::Unknown);

    // name 往返
    CHECK_EQ(geo_region_name(GeoRegion::North), "north");
    CHECK_EQ(geo_region_name(GeoRegion::Overseas), "overseas");
    CHECK_EQ(geo_region_name(GeoRegion::Unknown), "unknown");
}

// 15. stats_key_equality — StatsKey 相等性
static void test_stats_key_equality() {
    std::printf("[test] stats_key_equality...\n");
    StatsKey k1{NatType::Symmetric, "移动", GeoRegion::East};
    StatsKey k2{NatType::Symmetric, "移动", GeoRegion::East};
    StatsKey k3{NatType::Symmetric, "电信", GeoRegion::East};
    StatsKey k4{NatType::Symmetric, "移动", GeoRegion::South};
    StatsKey k5{NatType::FullCone, "移动", GeoRegion::East};

    CHECK(k1 == k2);
    CHECK(k1 != k3);
    CHECK(k1 != k4);
    CHECK(k1 != k5);
}

// 16. strategy_stats_score — StrategyStats 评分公式
static void test_strategy_stats_score() {
    std::printf("[test] strategy_stats_score...\n");
    StrategyStats ss;
    ss.success_rate = 0.8;
    ss.total = 50;

    // score = 0.8 * 0.7 + sample_confidence * 0.3
    // sample_confidence = min(50/100, 1.0) = 0.5
    // score = 0.56 + 0.15 = 0.71
    double score = ss.score(0.5);
    CHECK(score > 0.70 && score < 0.72);

    // 高样本置信度
    ss.total = 200;
    // score = 0.8 * 0.7 + 1.0 * 0.3 = 0.56 + 0.3 = 0.86
    double score2 = ss.score(1.0);
    CHECK(score2 > 0.85 && score2 < 0.87);
}

// 17. PenetrationRecord::to_string — 序列化格式
static void test_record_to_string() {
    std::printf("[test] record_to_string...\n");
    PenetrationRecord r(NatType::Symmetric, "移动", GeoRegion::East,
                         CgnStrategy::SymmetricNat, true,
                         std::chrono::milliseconds(250));
    std::string s = r.to_string();
    CHECK(s.find("Symmetric") != std::string::npos);
    CHECK(s.find("移动") != std::string::npos);
    CHECK(s.find("east") != std::string::npos);
    CHECK(s.find("symmetric") != std::string::npos);
    CHECK(s.find("|1|") != std::string::npos);
    CHECK(s.find("|250|") != std::string::npos);
}

// 18. clear — 清空统计
static void test_clear() {
    std::printf("[test] clear...\n");
    NatStats stats;
    for (int i = 0; i < 10; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }
    CHECK_EQ(stats.key_count(), std::size_t(1));
    CHECK_EQ(stats.total_records(), std::uint64_t(10));

    stats.clear();
    CHECK_EQ(stats.key_count(), std::size_t(0));
    CHECK_EQ(stats.total_records(), std::uint64_t(0));
}

// ========== main ==========

int main() {
    std::printf("=== test_nat_stats (V3.6.0 P5-D-2) ===\n");

    test_record_and_query();
    test_success_rate_calc();
    test_cold_start_fallback();
    test_recommend_strategy();
    test_per_carrier_stats();
    test_per_region_stats();
    test_lru_records_limit();
    test_concurrent_record();
    test_global_success_rate();
    test_persistence_roundtrip();
    test_query_strategies();
    test_default_candidates();
    test_key_count_total_records();
    test_geo_region_parse();
    test_stats_key_equality();
    test_strategy_stats_score();
    test_record_to_string();
    test_clear();

    std::printf("\n=== test_nat_stats: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
