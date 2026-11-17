// test_cgn_dynamic_threshold.cpp — P5-D-4 CGN 动态阈值策略选择单元测试
//
// 测试覆盖：
//   1. config_defaults — DynamicThresholdConfig 默认值
//   2. stats_nullptr_fallback — stats 为 nullptr 回退默认阈值
//   3. cold_start_fallback — 样本 < min_samples_for_adjust 回退默认阈值
//   4. low_success_rate_raises_threshold — 低成功率提高 high 阈值
//   5. high_success_rate_lowers_threshold — 高成功率降低 high 阈值
//   6. medium_success_rate_default — 中等成功率用默认阈值
//   7. non_cgn_returns_standard — 非 CGN 返回 StandardRfc5389
//   8. raised_high_blocks_symmetric — 提高后 high 阻断 SymmetricNat
//   9. lowered_high_enables_symmetric — 降低后 high 启用 SymmetricNat
//  10. lowered_low_enables_relay_early — 降低后 low 提前降级 Relay
//  11. raised_low_delays_relay — 提高后 low 延迟降级 Relay
//  12. min_samples_boundary — 样本数边界（阈值-1 vs 阈值）
//  13. custom_config — 自定义配置生效
//  14. per_dimension_isolation — 不同维度独立调整
//  15. feedback_loop — 失败记录后阈值变保守

#include "linoh/nat/cgn_detector.hpp"
#include "linoh/nat/nat_stats.hpp"

#include <cassert>
#include <cstdio>

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

// ========== 辅助函数 ==========

/// 构造 CGN 检测结果
static CgnDetectionResult make_cgn_result(bool is_cgn, double confidence) {
    CgnDetectionResult r;
    r.is_cgn = is_cgn;
    r.port_prediction_confidence = confidence;
    return r;
}

/// 向 NatStats 记录 N 次 SymmetricNat 穿透结果
static void record_symmetric_attempts(NatStats &stats, const StatsKey &key,
                                       std::size_t total, std::size_t success) {
    for (std::size_t i = 0; i < success; ++i) {
        stats.record(PenetrationRecord(key.nat_type, key.carrier, key.region,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }
    for (std::size_t i = success; i < total; ++i) {
        stats.record(PenetrationRecord(key.nat_type, key.carrier, key.region,
                                        CgnStrategy::SymmetricNat, false,
                                        std::chrono::milliseconds(300)));
    }
}

// ========== 测试用例 ==========

// 1. config_defaults — DynamicThresholdConfig 默认值
static void test_config_defaults() {
    std::printf("[test] config_defaults...\n");
    DynamicThresholdConfig cfg;

    CHECK_EQ(cfg.default_high, 0.7);
    CHECK_EQ(cfg.default_low, 0.3);
    CHECK_EQ(cfg.symmetric_nat_low_success_rate, 0.3);
    CHECK_EQ(cfg.raised_high, 0.85);
    CHECK_EQ(cfg.lowered_low, 0.2);
    CHECK_EQ(cfg.symmetric_nat_high_success_rate, 0.6);
    CHECK_EQ(cfg.lowered_high, 0.55);
    CHECK_EQ(cfg.raised_low, 0.4);
    CHECK_EQ(cfg.min_samples_for_adjust, std::size_t(20));
}

// 2. stats_nullptr_fallback — stats 为 nullptr 回退默认阈值
static void test_stats_nullptr_fallback() {
    std::printf("[test] stats_nullptr_fallback...\n");
    CgnDetectionResult result = make_cgn_result(true, 0.8);  // 高置信度
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};

    // stats=nullptr 应等同于 select(result, 0.7, 0.3)
    auto strategy_dyn = CgnStrategySelector::select_dynamic(result, nullptr, key);
    auto strategy_base = CgnStrategySelector::select(result, 0.7, 0.3);
    CHECK_EQ(strategy_dyn, strategy_base);
    CHECK_EQ(strategy_dyn, CgnStrategy::SymmetricNat);  // 0.8 >= 0.7
}

// 3. cold_start_fallback — 样本 < min_samples_for_adjust 回退默认阈值
static void test_cold_start_fallback() {
    std::printf("[test] cold_start_fallback...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};

    // 只记录 10 次（< 默认 min_samples_for_adjust=20）
    record_symmetric_attempts(stats, key, 10, 1);  // 10% 成功率

    CgnDetectionResult result = make_cgn_result(true, 0.8);
    auto strategy_dyn = CgnStrategySelector::select_dynamic(result, &stats, key);
    auto strategy_base = CgnStrategySelector::select(result, 0.7, 0.3);
    CHECK_EQ(strategy_dyn, strategy_base);  // 冷启动回退默认
    CHECK_EQ(strategy_dyn, CgnStrategy::SymmetricNat);
}

// 4. low_success_rate_raises_threshold — 低成功率提高 high 阈值
static void test_low_success_rate_raises_threshold() {
    std::printf("[test] low_success_rate_raises_threshold...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};

    // 25 次尝试，5 次成功 = 20% 成功率（< 0.3）
    record_symmetric_attempts(stats, key, 25, 5);

    // 置信度 0.8：默认 high=0.7 → SymmetricNat；raised_high=0.85 → ParallelTry
    CgnDetectionResult result_08 = make_cgn_result(true, 0.8);
    auto strategy_default = CgnStrategySelector::select(result_08, 0.7, 0.3);
    auto strategy_dynamic = CgnStrategySelector::select_dynamic(result_08, &stats, key);
    CHECK_EQ(strategy_default, CgnStrategy::SymmetricNat);   // 默认会触发
    CHECK_EQ(strategy_dynamic, CgnStrategy::ParallelTry);     // 动态阈值阻断
}

// 5. high_success_rate_lowers_threshold — 高成功率降低 high 阈值
static void test_high_success_rate_lowers_threshold() {
    std::printf("[test] high_success_rate_lowers_threshold...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "电信", GeoRegion::South};

    // 30 次尝试，21 次成功 = 70% 成功率（> 0.6）
    record_symmetric_attempts(stats, key, 30, 21);

    // 置信度 0.6：默认 high=0.7 → ParallelTry；lowered_high=0.55 → SymmetricNat
    CgnDetectionResult result_06 = make_cgn_result(true, 0.6);
    auto strategy_default = CgnStrategySelector::select(result_06, 0.7, 0.3);
    auto strategy_dynamic = CgnStrategySelector::select_dynamic(result_06, &stats, key);
    CHECK_EQ(strategy_default, CgnStrategy::ParallelTry);     // 默认中置信度
    CHECK_EQ(strategy_dynamic, CgnStrategy::SymmetricNat);    // 动态阈值启用
}

// 6. medium_success_rate_default — 中等成功率用默认阈值
static void test_medium_success_rate_default() {
    std::printf("[test] medium_success_rate_default...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "联通", GeoRegion::North};

    // 40 次尝试，20 次成功 = 50% 成功率（0.3 < rate < 0.6）
    record_symmetric_attempts(stats, key, 40, 20);

    CgnDetectionResult result = make_cgn_result(true, 0.8);
    auto strategy_dyn = CgnStrategySelector::select_dynamic(result, &stats, key);
    auto strategy_base = CgnStrategySelector::select(result, 0.7, 0.3);
    CHECK_EQ(strategy_dyn, strategy_base);  // 中等成功率用默认
    CHECK_EQ(strategy_dyn, CgnStrategy::SymmetricNat);
}

// 7. non_cgn_returns_standard — 非 CGN 返回 StandardRfc5389
static void test_non_cgn_returns_standard() {
    std::printf("[test] non_cgn_returns_standard...\n");
    NatStats stats;
    StatsKey key{NatType::FullCone, "移动", GeoRegion::East};
    record_symmetric_attempts(stats, key, 25, 5);  // 低成功率

    CgnDetectionResult result = make_cgn_result(false, 0.9);  // 非 CGN
    auto strategy = CgnStrategySelector::select_dynamic(result, &stats, key);
    CHECK_EQ(strategy, CgnStrategy::StandardRfc5389);
}

// 8. raised_high_blocks_symmetric — 提高后 high 阻断 SymmetricNat
static void test_raised_high_blocks_symmetric() {
    std::printf("[test] raised_high_blocks_symmetric...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};
    record_symmetric_attempts(stats, key, 25, 5);  // 20% < 0.3 → raised_high=0.85

    // 置信度 0.8：0.8 < 0.85 → ParallelTry（非 SymmetricNat）
    CgnDetectionResult r_08 = make_cgn_result(true, 0.8);
    CHECK_EQ(CgnStrategySelector::select_dynamic(r_08, &stats, key),
             CgnStrategy::ParallelTry);

    // 置信度 0.9：0.9 >= 0.85 → SymmetricNat（仍可触发）
    CgnDetectionResult r_09 = make_cgn_result(true, 0.9);
    CHECK_EQ(CgnStrategySelector::select_dynamic(r_09, &stats, key),
             CgnStrategy::SymmetricNat);
}

// 9. lowered_high_enables_symmetric — 降低后 high 启用 SymmetricNat
static void test_lowered_high_enables_symmetric() {
    std::printf("[test] lowered_high_enables_symmetric...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "电信", GeoRegion::South};
    record_symmetric_attempts(stats, key, 30, 21);  // 70% > 0.6 → lowered_high=0.55

    // 置信度 0.6：0.6 >= 0.55 → SymmetricNat
    CgnDetectionResult r_06 = make_cgn_result(true, 0.6);
    CHECK_EQ(CgnStrategySelector::select_dynamic(r_06, &stats, key),
             CgnStrategy::SymmetricNat);

    // 置信度 0.5：0.5 < 0.55 → ParallelTry
    CgnDetectionResult r_05 = make_cgn_result(true, 0.5);
    CHECK_EQ(CgnStrategySelector::select_dynamic(r_05, &stats, key),
             CgnStrategy::ParallelTry);
}

// 10. lowered_low_enables_relay_early — 降低后 low 提前降级 Relay
static void test_lowered_low_enables_relay_early() {
    std::printf("[test] lowered_low_enables_relay_early...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};
    record_symmetric_attempts(stats, key, 25, 5);  // 20% < 0.3 → lowered_low=0.2

    // 置信度 0.25：默认 low=0.3 → RelayFallback；lowered_low=0.2 → ParallelTry
    CgnDetectionResult r_025 = make_cgn_result(true, 0.25);
    auto strategy_default = CgnStrategySelector::select(r_025, 0.7, 0.3);
    auto strategy_dynamic = CgnStrategySelector::select_dynamic(r_025, &stats, key);
    CHECK_EQ(strategy_default, CgnStrategy::RelayFallback);
    CHECK_EQ(strategy_dynamic, CgnStrategy::ParallelTry);  // 0.25 >= 0.2

    // 置信度 0.15：0.15 < 0.2 → RelayFallback
    CgnDetectionResult r_015 = make_cgn_result(true, 0.15);
    CHECK_EQ(CgnStrategySelector::select_dynamic(r_015, &stats, key),
             CgnStrategy::RelayFallback);
}

// 11. raised_low_delays_relay — 提高后 low 延迟降级 Relay
static void test_raised_low_delays_relay() {
    std::printf("[test] raised_low_delays_relay...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "电信", GeoRegion::South};
    record_symmetric_attempts(stats, key, 30, 21);  // 70% > 0.6 → raised_low=0.4

    // 置信度 0.35：默认 low=0.3 → ParallelTry；raised_low=0.4 → RelayFallback
    CgnDetectionResult r_035 = make_cgn_result(true, 0.35);
    auto strategy_default = CgnStrategySelector::select(r_035, 0.7, 0.3);
    auto strategy_dynamic = CgnStrategySelector::select_dynamic(r_035, &stats, key);
    CHECK_EQ(strategy_default, CgnStrategy::ParallelTry);
    CHECK_EQ(strategy_dynamic, CgnStrategy::RelayFallback);  // 0.35 < 0.4
}

// 12. min_samples_boundary — 样本数边界（阈值-1 vs 阈值）
static void test_min_samples_boundary() {
    std::printf("[test] min_samples_boundary...\n");
    DynamicThresholdConfig cfg;
    cfg.min_samples_for_adjust = 20;

    // 样本数 = 19（< 20）→ 冷启动回退默认
    {
        NatStats stats;
        StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};
        record_symmetric_attempts(stats, key, 19, 1);  // ~5% 成功率

        CgnDetectionResult result = make_cgn_result(true, 0.8);
        auto strategy_dyn = CgnStrategySelector::select_dynamic(result, &stats, key, cfg);
        CHECK_EQ(strategy_dyn, CgnStrategy::SymmetricNat);  // 默认阈值，0.8>=0.7
    }

    // 样本数 = 20（== 20）→ 触发动态调整
    {
        NatStats stats;
        StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};
        record_symmetric_attempts(stats, key, 20, 1);  // 5% < 0.3

        CgnDetectionResult result = make_cgn_result(true, 0.8);
        auto strategy_dyn = CgnStrategySelector::select_dynamic(result, &stats, key, cfg);
        CHECK_EQ(strategy_dyn, CgnStrategy::ParallelTry);  // raised_high=0.85, 0.8<0.85
    }
}

// 13. custom_config — 自定义配置生效
static void test_custom_config() {
    std::printf("[test] custom_config...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};
    record_symmetric_attempts(stats, key, 30, 6);  // 20% < 0.3

    // 自定义更激进的阈值
    DynamicThresholdConfig cfg;
    cfg.raised_high = 0.95;  // 极高门槛
    cfg.lowered_low = 0.1;

    CgnDetectionResult result = make_cgn_result(true, 0.9);
    // 默认 high=0.7 → SymmetricNat；自定义 raised_high=0.95 → ParallelTry
    auto strategy_default = CgnStrategySelector::select(result, 0.7, 0.3);
    auto strategy_custom = CgnStrategySelector::select_dynamic(result, &stats, key, cfg);
    CHECK_EQ(strategy_default, CgnStrategy::SymmetricNat);
    CHECK_EQ(strategy_custom, CgnStrategy::ParallelTry);  // 0.9 < 0.95
}

// 14. per_dimension_isolation — 不同维度独立调整
static void test_per_dimension_isolation() {
    std::printf("[test] per_dimension_isolation...\n");
    NatStats stats;

    // 维度 A：移动/华东，低成功率
    StatsKey key_a{NatType::Symmetric, "移动", GeoRegion::East};
    record_symmetric_attempts(stats, key_a, 25, 5);  // 20% < 0.3

    // 维度 B：电信/华南，高成功率
    StatsKey key_b{NatType::Symmetric, "电信", GeoRegion::South};
    record_symmetric_attempts(stats, key_b, 30, 21);  // 70% > 0.6

    CgnDetectionResult result = make_cgn_result(true, 0.6);

    // 维度 A：raised_high=0.85, 0.6 < 0.85 → ParallelTry
    auto strategy_a = CgnStrategySelector::select_dynamic(result, &stats, key_a);
    CHECK_EQ(strategy_a, CgnStrategy::ParallelTry);

    // 维度 B：lowered_high=0.55, 0.6 >= 0.55 → SymmetricNat
    auto strategy_b = CgnStrategySelector::select_dynamic(result, &stats, key_b);
    CHECK_EQ(strategy_b, CgnStrategy::SymmetricNat);
}

// 15. feedback_loop — 失败记录后阈值变保守
static void test_feedback_loop() {
    std::printf("[test] feedback_loop...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};

    // 初始 20 次成功 → 高成功率 → 激进阈值
    record_symmetric_attempts(stats, key, 20, 18);  // 90% > 0.6

    CgnDetectionResult result_06 = make_cgn_result(true, 0.6);
    auto strategy_initial = CgnStrategySelector::select_dynamic(result_06, &stats, key);
    CHECK_EQ(strategy_initial, CgnStrategy::SymmetricNat);  // lowered_high=0.55

    // 后续 20 次失败 → 成功率降至 47%（18/40 = 0.45）→ 中等 → 默认阈值
    for (int i = 0; i < 20; ++i) {
        stats.record(PenetrationRecord(key.nat_type, key.carrier, key.region,
                                        CgnStrategy::SymmetricNat, false,
                                        std::chrono::milliseconds(300)));
    }
    auto strategy_after_fail = CgnStrategySelector::select_dynamic(result_06, &stats, key);
    // 0.45 在 [0.3, 0.6] → 默认阈值 0.7/0.3, 0.6 < 0.7 → ParallelTry
    CHECK_EQ(strategy_after_fail, CgnStrategy::ParallelTry);
}

// ========== main ==========

int main() {
    std::printf("=== test_cgn_dynamic_threshold (V3.6.1 P5-D-4) ===\n");

    test_config_defaults();
    test_stats_nullptr_fallback();
    test_cold_start_fallback();
    test_low_success_rate_raises_threshold();
    test_high_success_rate_lowers_threshold();
    test_medium_success_rate_default();
    test_non_cgn_returns_standard();
    test_raised_high_blocks_symmetric();
    test_lowered_high_enables_symmetric();
    test_lowered_low_enables_relay_early();
    test_raised_low_delays_relay();
    test_min_samples_boundary();
    test_custom_config();
    test_per_dimension_isolation();
    test_feedback_loop();

    std::printf("\n=== test_cgn_dynamic_threshold: %d pass, %d fail ===\n",
                g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
