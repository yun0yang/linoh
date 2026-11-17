// test_bandwidth_tier_strategy.cpp — v4.3.0 M16 带宽 tier 三键排序策略单元测试
//
// 测试覆盖：
//   BandwidthTier 枚举值 + PathQuality 默认值
//   空候选 / 全无 tuple 返回 nullopt
//   单候选直接返回
//   tier 优先级：MeasuredPositive > NotMeasured > MeasuredZero（含跨级）
//   同 MeasuredPositive 内带宽降序
//   同 tier 同带宽内 RTT 升序
//   srtt=0 排最后
//   混合三键综合场景
//   工厂函数 create_strategy_by_name + name()

#include "linoh/protocol/path_strategy.hpp"
#include "linoh/protocol/path_migration.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

using namespace linoh::protocol;
using namespace linoh::net;
using PMM = PathMigrationManager;

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

// ========== 辅助函数 ==========

/// 构造 PathQuality，用 remote_addr.port 作为候选标识（测试验证用）
static PMM::PathQuality make_quality(std::uint16_t port,
                                       PMM::BandwidthTier tier,
                                       std::uint64_t bandwidth_bps,
                                       std::chrono::microseconds srtt) {
    PMM::PathQuality q;
    q.path_id = port;  // port 同时作为 path_id
    q.has_tuple = true;
    q.four_tuple.remote_addr.kind = linoh::base::TransportKind::Ip;
    q.four_tuple.remote_addr.host = "10.0.0.1";
    q.four_tuple.remote_addr.port = port;
    q.srtt = srtt;
    q.bandwidth_tier = tier;
    q.measured_bandwidth_bps = bandwidth_bps;
    return q;
}

/// 验证 select 返回的 FourTuple 的 remote_port 是否等于预期 port
static bool select_returns_port(BandwidthTierStrategy &strategy,
                                  const std::vector<PMM::PathQuality> &candidates,
                                  std::uint16_t expected_port) {
    auto result = strategy.select(candidates);
    if (!result) return false;
    return result->remote_addr.port == expected_port;
}

// ========== BandwidthTier 枚举 ==========

// 1. BandwidthTier 枚举值（排序权重）
static void test_tier_enum_values() {
    std::printf("[test] BandwidthTier enum values...\n");
    CHECK_EQ(static_cast<std::uint8_t>(PMM::BandwidthTier::MeasuredPositive), 0u);
    CHECK_EQ(static_cast<std::uint8_t>(PMM::BandwidthTier::NotMeasured), 1u);
    CHECK_EQ(static_cast<std::uint8_t>(PMM::BandwidthTier::MeasuredZero), 2u);
    // MeasuredPositive < NotMeasured < MeasuredZero（升序排序权重）
    CHECK(static_cast<std::uint8_t>(PMM::BandwidthTier::MeasuredPositive) <
          static_cast<std::uint8_t>(PMM::BandwidthTier::NotMeasured));
    CHECK(static_cast<std::uint8_t>(PMM::BandwidthTier::NotMeasured) <
          static_cast<std::uint8_t>(PMM::BandwidthTier::MeasuredZero));
}

// 2. PathQuality 默认值
static void test_path_quality_defaults() {
    std::printf("[test] PathQuality default values...\n");
    PMM::PathQuality q;
    CHECK(q.bandwidth_tier == PMM::BandwidthTier::NotMeasured);
    CHECK_EQ(q.measured_bandwidth_bps, 0u);
}

// ========== 边界条件 ==========

// 3. 空候选返回 nullopt
static void test_empty_candidates() {
    std::printf("[test] empty candidates returns nullopt...\n");
    BandwidthTierStrategy s;
    std::vector<PMM::PathQuality> empty;
    CHECK(!s.select(empty));
}

// 4. 全部无 tuple 返回 nullopt
static void test_all_missing_tuple() {
    std::printf("[test] all missing tuple returns nullopt...\n");
    BandwidthTierStrategy s;
    PMM::PathQuality q;
    q.has_tuple = false;  // 无 tuple
    q.bandwidth_tier = PMM::BandwidthTier::MeasuredPositive;
    q.measured_bandwidth_bps = 1000000;
    std::vector<PMM::PathQuality> candidates = {q};
    CHECK(!s.select(candidates));
}

// 5. 单个候选直接返回
static void test_single_candidate() {
    std::printf("[test] single candidate returned directly...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(1000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(0)),
    };
    CHECK(select_returns_port(s, candidates, 1000));
}

// ========== tier 优先级 ==========

// 6. MeasuredPositive 优先于 NotMeasured
static void test_positive_over_not_measured() {
    std::printf("[test] MeasuredPositive > NotMeasured...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(2000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(1000)),
        make_quality(1000, PMM::BandwidthTier::MeasuredPositive, 500000, std::chrono::microseconds(50000)),
    };
    // 即使 Positive 的 RTT 更高，tier 优先
    CHECK(select_returns_port(s, candidates, 1000));
}

// 7. NotMeasured 优先于 MeasuredZero
static void test_not_measured_over_zero() {
    std::printf("[test] NotMeasured > MeasuredZero...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(3000, PMM::BandwidthTier::MeasuredZero, 0, std::chrono::microseconds(1000)),
        make_quality(2000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(50000)),
    };
    // 即使 NotMeasured 的 RTT 更高，tier 优先
    CHECK(select_returns_port(s, candidates, 2000));
}

// 8. MeasuredPositive 优先于 MeasuredZero（跨级）
static void test_positive_over_zero() {
    std::printf("[test] MeasuredPositive > MeasuredZero (cross-tier)...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(3000, PMM::BandwidthTier::MeasuredZero, 0, std::chrono::microseconds(1000)),
        make_quality(1000, PMM::BandwidthTier::MeasuredPositive, 500000, std::chrono::microseconds(50000)),
    };
    CHECK(select_returns_port(s, candidates, 1000));
}

// 9. 三 tier 混合，MeasuredPositive 胜出
static void test_three_tier_mixed() {
    std::printf("[test] three-tier mixed, MeasuredPositive wins...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(3000, PMM::BandwidthTier::MeasuredZero, 0, std::chrono::microseconds(1000)),
        make_quality(2000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(2000)),
        make_quality(1000, PMM::BandwidthTier::MeasuredPositive, 500000, std::chrono::microseconds(3000)),
    };
    CHECK(select_returns_port(s, candidates, 1000));
}

// ========== 带宽降序 ==========

// 10. 同 MeasuredPositive tier 内带宽降序
static void test_bandwidth_descending() {
    std::printf("[test] same MeasuredPositive tier, bandwidth descending...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(1000, PMM::BandwidthTier::MeasuredPositive, 100000, std::chrono::microseconds(1000)),
        make_quality(2000, PMM::BandwidthTier::MeasuredPositive, 500000, std::chrono::microseconds(1000)),
        make_quality(3000, PMM::BandwidthTier::MeasuredPositive, 300000, std::chrono::microseconds(1000)),
    };
    // 500000 > 300000 > 100000，port 2000 胜出
    CHECK(select_returns_port(s, candidates, 2000));
}

// 11. 多个 MeasuredPositive 按带宽降序（RTT 相同）
static void test_multiple_positive_bandwidth_order() {
    std::printf("[test] multiple MeasuredPositive, bandwidth descending...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(100, PMM::BandwidthTier::MeasuredPositive, 1000000, std::chrono::microseconds(5000)),
        make_quality(200, PMM::BandwidthTier::MeasuredPositive, 2000000, std::chrono::microseconds(5000)),
        make_quality(300, PMM::BandwidthTier::MeasuredPositive, 500000, std::chrono::microseconds(5000)),
        make_quality(400, PMM::BandwidthTier::MeasuredPositive, 3000000, std::chrono::microseconds(5000)),
    };
    // 3000000 > 2000000 > 1000000 > 500000，port 400 胜出
    CHECK(select_returns_port(s, candidates, 400));
}

// ========== RTT 升序兜底 ==========

// 12. 同 tier 同带宽内 RTT 升序
static void test_rtt_ascending_tiebreak() {
    std::printf("[test] same tier+bandwidth, RTT ascending tiebreak...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(1000, PMM::BandwidthTier::MeasuredPositive, 500000, std::chrono::microseconds(30000)),
        make_quality(2000, PMM::BandwidthTier::MeasuredPositive, 500000, std::chrono::microseconds(10000)),
        make_quality(3000, PMM::BandwidthTier::MeasuredPositive, 500000, std::chrono::microseconds(20000)),
    };
    // 同 tier 同带宽，RTT 最小的 port 2000 胜出
    CHECK(select_returns_port(s, candidates, 2000));
}

// 13. NotMeasured 内 srtt 升序兜底
static void test_not_measured_rtt_tiebreak() {
    std::printf("[test] NotMeasured tier, RTT ascending tiebreak...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(1000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(30000)),
        make_quality(2000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(10000)),
    };
    CHECK(select_returns_port(s, candidates, 2000));
}

// 14. srtt=0 排最后
static void test_srtt_zero_last() {
    std::printf("[test] srtt=0 ranks last...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(1000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(0)),      // 未测量 RTT
        make_quality(2000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(50000)),  // 有 RTT
    };
    // srtt=0 排最后，port 2000 胜出
    CHECK(select_returns_port(s, candidates, 2000));
}

// 15. 两个 srtt=0 保持原序
static void test_both_srtt_zero_keep_order() {
    std::printf("[test] both srtt=0, keep original order...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(1000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(0)),
        make_quality(2000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(0)),
    };
    // 都未测量 RTT，保持原序，port 1000 胜出
    CHECK(select_returns_port(s, candidates, 1000));
}

// ========== 混合三键综合场景 ==========

// 16. 综合：tier + bandwidth + RTT 三键交互
static void test_e2e_three_keys_interaction() {
    std::printf("[test] E2E three keys interaction...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        // MeasuredZero, RTT 最低但 tier 最差
        make_quality(1000, PMM::BandwidthTier::MeasuredZero, 0, std::chrono::microseconds(1000)),
        // NotMeasured, RTT 中等
        make_quality(2000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(20000)),
        // MeasuredPositive, 带宽中等, RTT 最高
        make_quality(3000, PMM::BandwidthTier::MeasuredPositive, 500000, std::chrono::microseconds(50000)),
        // MeasuredPositive, 带宽最高, RTT 最高
        make_quality(4000, PMM::BandwidthTier::MeasuredPositive, 2000000, std::chrono::microseconds(80000)),
        // MeasuredPositive, 带宽最低, RTT 最低
        make_quality(5000, PMM::BandwidthTier::MeasuredPositive, 100000, std::chrono::microseconds(5000)),
    };
    // 第一键 tier：3 个 MeasuredPositive 胜出（3000/4000/5000）
    // 第二键 bandwidth：4000(2000000) > 3000(500000) > 5000(100000)
    // port 4000 胜出
    CHECK(select_returns_port(s, candidates, 4000));
}

// 17. 同带宽不同 tier（tier 优先）
static void test_same_bandwidth_different_tier() {
    std::printf("[test] same bandwidth, different tier...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        // MeasuredZero 带宽 0
        make_quality(1000, PMM::BandwidthTier::MeasuredZero, 0, std::chrono::microseconds(1000)),
        // NotMeasured 带宽 0（默认）
        make_quality(2000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(50000)),
    };
    // 同 bandwidth(0)，但 tier 不同：NotMeasured > MeasuredZero
    CHECK(select_returns_port(s, candidates, 2000));
}

// 18. 无 tuple 候选被过滤，有效候选正常排序
static void test_filter_missing_tuple() {
    std::printf("[test] filter missing tuple, valid candidates sorted...\n");
    BandwidthTierStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(1000, PMM::BandwidthTier::MeasuredPositive, 1000000, std::chrono::microseconds(1000)),
        // 无 tuple 的 MeasuredPositive（更高带宽，应被过滤）
        []() {
            auto q = make_quality(9999, PMM::BandwidthTier::MeasuredPositive, 9999999, std::chrono::microseconds(1));
            q.has_tuple = false;
            return q;
        }(),
        make_quality(2000, PMM::BandwidthTier::MeasuredPositive, 2000000, std::chrono::microseconds(1000)),
    };
    // 无 tuple 的被过滤，有效中 2000000 > 1000000，port 2000 胜出
    CHECK(select_returns_port(s, candidates, 2000));
}

// ========== 工厂函数 + name() ==========

// 19. create_strategy_by_name("bandwidth-tier") 返回非 null
static void test_factory_bandwidth_tier() {
    std::printf("[test] factory create 'bandwidth-tier'...\n");
    auto s = create_strategy_by_name("bandwidth-tier");
    CHECK(s != nullptr);
    CHECK(s->name() == "bandwidth-tier");
}

// 20. create_strategy_by_name 未知名称返回 nullptr
static void test_factory_unknown() {
    std::printf("[test] factory unknown name returns nullptr...\n");
    CHECK(create_strategy_by_name("unknown") == nullptr);
    CHECK(create_strategy_by_name("") == nullptr);
}

// 21. create_strategy_by_name 各已知策略
static void test_factory_all_known() {
    std::printf("[test] factory all known strategies...\n");
    CHECK(create_strategy_by_name("rtt") != nullptr);
    CHECK(create_strategy_by_name("prefer-direct") != nullptr);
    CHECK(create_strategy_by_name("prefer-relay") != nullptr);
    CHECK(create_strategy_by_name("bandwidth-tier") != nullptr);
}

// 22. name() 返回正确
static void test_name() {
    std::printf("[test] name() returns 'bandwidth-tier'...\n");
    BandwidthTierStrategy s;
    CHECK(s.name() == "bandwidth-tier");
}

// 辅助：RttBasedStrategy 版本的 select_returns_port
static bool select_returns_port_by_rtt(RttBasedStrategy &strategy,
                                          const std::vector<PMM::PathQuality> &candidates,
                                          std::uint16_t expected_port) {
    auto result = strategy.select(candidates);
    if (!result) return false;
    return result->remote_addr.port == expected_port;
}

// 23. RttBasedStrategy 仍正常工作（回归测试）
static void test_rtt_strategy_regression() {
    std::printf("[test] RttBasedStrategy regression...\n");
    RttBasedStrategy s;
    auto candidates = std::vector<PMM::PathQuality>{
        make_quality(1000, PMM::BandwidthTier::MeasuredPositive, 1000000, std::chrono::microseconds(30000)),
        make_quality(2000, PMM::BandwidthTier::NotMeasured, 0, std::chrono::microseconds(10000)),
    };
    // RttBasedStrategy 忽略 tier/bandwidth，选 RTT 最小（port 2000）
    CHECK(select_returns_port_by_rtt(s, candidates, 2000));
}

int main() {
    std::printf("=== test_bandwidth_tier_strategy ===\n\n");

    // 枚举 + 默认值
    test_tier_enum_values();
    test_path_quality_defaults();

    // 边界条件
    test_empty_candidates();
    test_all_missing_tuple();
    test_single_candidate();

    // tier 优先级
    test_positive_over_not_measured();
    test_not_measured_over_zero();
    test_positive_over_zero();
    test_three_tier_mixed();

    // 带宽降序
    test_bandwidth_descending();
    test_multiple_positive_bandwidth_order();

    // RTT 升序兜底
    test_rtt_ascending_tiebreak();
    test_not_measured_rtt_tiebreak();
    test_srtt_zero_last();
    test_both_srtt_zero_keep_order();

    // 综合
    test_e2e_three_keys_interaction();
    test_same_bandwidth_different_tier();
    test_filter_missing_tuple();

    // 工厂 + name
    test_factory_bandwidth_tier();
    test_factory_unknown();
    test_factory_all_known();
    test_name();

    // 回归
    test_rtt_strategy_regression();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
