// test_nat_prediction_model.cpp — P5-D-2 端到端 NAT 穿透预测模型测试
//
// 集成测试：CGN 检测 → 策略推荐 → 端口预测 → 结果反馈
// 模拟真实场景：移动网络 Symmetric NAT 节点的多次穿透学习过程
//
// 测试覆盖：
//   1. e2e_symmetric_nat_high_confidence — 高置信度 Symmetric NAT 穿透流程
//   2. e2e_cold_start_fallback — 冷启动回退 CGN 规则
//   3. e2e_stats_driven_recommendation — 统计驱动的策略推荐
//   4. e2e_port_predictor_feedback — 端口预测命中反馈修正
//   5. e2e_relay_fallback_after_failures — 多次失败后降级 Relay
//   6. e2e_persistence_across_restart — 持久化跨重启保留学习数据
//   7. e2e_multi_peer_learning — 多 peer 独立学习
//   8. e2e_default_candidates_vs_stats — 默认候选 vs 统计推荐

#include "linoh/nat/cgn_detector.hpp"
#include "linoh/nat/nat_stats.hpp"
#include "linoh/nat/port_predictor.hpp"

#include <cassert>
#include <cstdio>
#include <random>
#include <vector>

using namespace linoh::nat;
using namespace linoh::net;
using namespace linoh::base;

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

static EndpointId make_peer(std::uint8_t seed) {
    EndpointId id{};
    for (std::size_t i = 0; i < id.size(); ++i) {
        id.data()[i] = static_cast<std::uint8_t>(seed + i);
    }
    return id;
}

static PortPredictTimePoint make_tp(long long ms) {
    return PortPredictTimePoint(std::chrono::milliseconds(ms));
}

/// 模拟一次 NAT 穿透尝试
/// @param predictor 端口预测器
/// @param peer 对端 EndpointId
/// @param actual_port 对端实际端口（模拟真实端口）
/// @param predicted_candidates 预测候选端口
/// @return 是否命中（候选中包含实际端口）
static bool simulate_penetration(PortPredictor &predictor,
                                  const EndpointId &peer,
                                  std::uint16_t actual_port,
                                  const std::vector<std::uint16_t> &predicted_candidates) {
    bool hit = false;
    for (std::uint16_t p : predicted_candidates) {
        if (p == actual_port) { hit = true; break; }
    }
    // 反馈预测结果
    std::uint16_t predicted = predicted_candidates.empty() ? 0 : predicted_candidates[0];
    predictor.feedback(peer, predicted, actual_port, hit);
    // 记录观测（用于下次预测）
    predictor.record_observation(peer, actual_port);
    return hit;
}

// ========== 端到端测试用例 ==========

// 1. 高置信度 Symmetric NAT 穿透流程
static void test_e2e_symmetric_nat_high_confidence() {
    std::printf("[test] e2e symmetric NAT high confidence...\n");
    PortPredictor predictor;
    NatStats stats;
    EndpointId peer = make_peer(0x07);

    // 模拟 CGN 检测结果：高置信度（0.85）
    CgnDetectionResult cgn_result;
    cgn_result.is_cgn = true;
    cgn_result.carrier_name = "移动";
    cgn_result.port_prediction_confidence = 0.85;
    cgn_result.observed_ports = {30000, 30010, 30020};

    // 策略选择：高置信度 → SymmetricNat
    CgnStrategy strategy = CgnStrategySelector::select(cgn_result, 0.7, 0.3);
    CHECK_EQ(strategy, CgnStrategy::SymmetricNat);

    // 端口预测：先记录观测
    predictor.record_observation(peer, 30000, make_tp(0));
    predictor.record_observation(peer, 30010, make_tp(1000));
    predictor.record_observation(peer, 30020, make_tp(2000));

    // 预测下一次端口
    PortPrediction pred = predictor.predict(peer);
    CHECK(!pred.candidates.empty());
    CHECK(pred.confidence > 0.5);

    // 模拟实际端口（应该落在预测候选中）
    std::uint16_t actual_port = 30030;
    bool hit = simulate_penetration(predictor, peer, actual_port, pred.candidates);
    CHECK(hit);  // 等差序列应命中

    // 记录到统计
    stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                    strategy, hit, std::chrono::milliseconds(200)));
    CHECK_EQ(stats.total_records(), std::uint64_t(1));
}

// 2. 冷启动回退 CGN 规则
static void test_e2e_cold_start_fallback() {
    std::printf("[test] e2e cold start fallback...\n");
    NatStats stats;
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};

    // 仅 3 条记录（< cold_start_threshold=10）
    for (int i = 0; i < 3; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, true,
                                        std::chrono::milliseconds(200)));
    }

    // 冷启动：recommend_strategy 返回 nullopt
    auto candidates = default_candidates(NatType::Symmetric);
    auto rec = stats.recommend_strategy(key, candidates);
    CHECK(!rec.has_value());

    // 调用方应回退到 CGN 规则（使用 default_candidates[0]）
    CgnStrategy fallback = candidates[0];
    CHECK_EQ(fallback, CgnStrategy::SymmetricNat);
}

// 3. 统计驱动的策略推荐
static void test_e2e_stats_driven_recommendation() {
    std::printf("[test] e2e stats driven recommendation...\n");
    PortPredictor predictor;
    NatStats stats;
    EndpointId peer = make_peer(0x08);
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};

    // 阶段1：冷启动期，使用 CGN 规则选择 SymmetricNat，但命中率低
    // 模拟 5 次尝试，2 成功 3 失败
    for (int i = 0; i < 5; ++i) {
        bool ok = (i < 2);
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, ok,
                                        std::chrono::milliseconds(200)));
    }

    // 冷启动：recommend 返回 nullopt
    auto candidates = default_candidates(NatType::Symmetric);
    CHECK(!stats.recommend_strategy(key, candidates).has_value());

    // 阶段2：继续记录，达到样本阈值后启用统计推荐
    // 再记录 5 次 SymmetricNat（1 成功 4 失败）+ 5 次 RelayFallback（5 成功 0 失败）
    for (int i = 0; i < 4; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, false,
                                        std::chrono::milliseconds(200)));
    }
    stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                    CgnStrategy::SymmetricNat, true,
                                    std::chrono::milliseconds(200)));
    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::RelayFallback, true,
                                        std::chrono::milliseconds(300)));
    }

    // 现在 SymmetricNat: 3/10 = 0.3, RelayFallback: 5/5 = 1.0
    auto rec = stats.recommend_strategy(key, candidates);
    CHECK(rec.has_value());
    // RelayFallback(1.0) 应优于 SymmetricNat(0.3)
    CHECK_EQ(rec->first, CgnStrategy::RelayFallback);
    CHECK(rec->second > 0.99);
}

// 4. 端口预测命中反馈修正
static void test_e2e_port_predictor_feedback() {
    std::printf("[test] e2e port predictor feedback...\n");
    PortPredictor predictor;
    EndpointId peer = make_peer(0x09);

    // 记录 5 次等差观测
    for (int i = 0; i < 5; ++i) {
        predictor.record_observation(peer, static_cast<std::uint16_t>(40000 + i * 10),
                                      make_tp(1000LL * i));
    }

    // 预测
    PortPrediction pred = predictor.predict(peer);
    CHECK(!pred.candidates.empty());

    // 模拟命中
    predictor.feedback(peer, pred.candidates[0], pred.candidates[0], true);
    // 模拟未命中
    predictor.feedback(peer, pred.candidates[0], 50000, false);

    // 再次预测（模型应基于反馈调整）
    PortPrediction pred2 = predictor.predict(peer);
    CHECK(!pred2.candidates.empty());
}

// 5. 多次失败后降级 Relay
static void test_e2e_relay_fallback_after_failures() {
    std::printf("[test] e2e relay fallback after failures...\n");
    PortPredictor predictor;
    NatStats stats;
    EndpointId peer = make_peer(0x0A);
    StatsKey key{NatType::Symmetric, "电信", GeoRegion::North};

    // 模拟 10 次 SymmetricNat 策略全部失败
    for (int i = 0; i < 10; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "电信", GeoRegion::North,
                                        CgnStrategy::SymmetricNat, false,
                                        std::chrono::milliseconds(200)));
    }
    // 模拟 5 次 RelayFallback 全部成功
    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "电信", GeoRegion::North,
                                        CgnStrategy::RelayFallback, true,
                                        std::chrono::milliseconds(300)));
    }

    auto candidates = default_candidates(NatType::Symmetric);
    auto rec = stats.recommend_strategy(key, candidates);
    CHECK(rec.has_value());
    // SymmetricNat: 0/10 = 0.0, RelayFallback: 5/5 = 1.0
    CHECK_EQ(rec->first, CgnStrategy::RelayFallback);
}

// 6. 持久化跨重启保留学习数据
static void test_e2e_persistence_across_restart() {
    std::printf("[test] e2e persistence across restart...\n");
    // PortPredictor 持久化
    PortPredictor predictor;
    EndpointId peer = make_peer(0x0B);
    for (int i = 0; i < 5; ++i) {
        predictor.record_observation(peer, static_cast<std::uint16_t>(50000 + i * 5),
                                      make_tp(1000LL * i));
    }
    bool pp_saved = predictor.save_to_file("build/test_e2e_port_predictor.tsv");
    CHECK(pp_saved);

    PortPredictor predictor2;
    int pp_loaded = predictor2.load_from_file("build/test_e2e_port_predictor.tsv");
    CHECK(pp_loaded > 0);

    // 两个 predictor 应给出相同预测
    PortPrediction pred1 = predictor.predict(peer);
    PortPrediction pred2 = predictor2.predict(peer);
    CHECK_EQ(pred1.candidates.size(), pred2.candidates.size());
    if (!pred1.candidates.empty()) {
        CHECK_EQ(pred1.candidates[0], pred2.candidates[0]);
    }

    // NatStats 持久化
    NatStatsConfig cfg;
    cfg.persistence_path = "build/test_e2e_nat_stats.tsv";
    // 清理残留文件（方案 A 下 NatStats 构造函数会自动 load，若不清理残留数据会被加载）
    std::remove(cfg.persistence_path.c_str());
    NatStats stats(cfg);
    for (int i = 0; i < 12; ++i) {
        stats.record(PenetrationRecord(NatType::Symmetric, "移动", GeoRegion::East,
                                        CgnStrategy::SymmetricNat, i % 2 == 0,
                                        std::chrono::milliseconds(200)));
    }
    bool ns_saved = stats.save_to_file();
    CHECK(ns_saved);

    NatStats stats2(cfg);
    int ns_loaded = stats2.load_from_file();
    CHECK_EQ(ns_loaded, 12);

    // 验证推荐一致
    StatsKey key{NatType::Symmetric, "移动", GeoRegion::East};
    auto candidates = default_candidates(NatType::Symmetric);
    auto rec1 = stats.recommend_strategy(key, candidates);
    auto rec2 = stats2.recommend_strategy(key, candidates);
    CHECK(rec1.has_value());
    CHECK(rec2.has_value());
    if (rec1.has_value() && rec2.has_value()) {
        CHECK_EQ(rec1->first, rec2->first);
    }
}

// 7. 多 peer 独立学习
static void test_e2e_multi_peer_learning() {
    std::printf("[test] e2e multi peer learning...\n");
    PortPredictor predictor;
    EndpointId peer1 = make_peer(0x01);
    EndpointId peer2 = make_peer(0x02);

    // peer1：等差 +10，起始 30000
    for (int i = 0; i < 5; ++i) {
        predictor.record_observation(peer1, static_cast<std::uint16_t>(30000 + i * 10),
                                      make_tp(1000LL * i));
    }
    // peer2：等差 +20，起始 40000
    for (int i = 0; i < 5; ++i) {
        predictor.record_observation(peer2, static_cast<std::uint16_t>(40000 + i * 20),
                                      make_tp(1000LL * i));
    }

    PortPrediction pred1 = predictor.predict(peer1);
    PortPrediction pred2 = predictor.predict(peer2);
    CHECK(!pred1.candidates.empty());
    CHECK(!pred2.candidates.empty());

    // peer1 预测应基于 +10 增量，peer2 基于 +20 增量
    // peer1 下一个应在 30050 附近，peer2 在 40100 附近
    bool peer1_hit = false;
    for (auto p : pred1.candidates) {
        if (p == 30050 || p == 30060 || p == 30040) { peer1_hit = true; break; }
    }
    CHECK(peer1_hit);

    bool peer2_hit = false;
    for (auto p : pred2.candidates) {
        if (p == 40100 || p == 40120 || p == 40080) { peer2_hit = true; break; }
    }
    CHECK(peer2_hit);
}

// 8. 默认候选 vs 统计推荐
static void test_e2e_default_candidates_vs_stats() {
    std::printf("[test] e2e default candidates vs stats...\n");
    NatStats stats;
    StatsKey key{NatType::FullCone, "联通", GeoRegion::Central};

    // FullCone 默认首选 StandardRfc5389
    auto candidates = default_candidates(NatType::FullCone);
    CHECK_EQ(candidates[0], CgnStrategy::StandardRfc5389);

    // 记录 15 次：StandardRfc5389 5/10, RelayFallback 5/5
    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::FullCone, "联通", GeoRegion::Central,
                                        CgnStrategy::StandardRfc5389, true,
                                        std::chrono::milliseconds(100)));
    }
    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::FullCone, "联通", GeoRegion::Central,
                                        CgnStrategy::StandardRfc5389, false,
                                        std::chrono::milliseconds(100)));
    }
    for (int i = 0; i < 5; ++i) {
        stats.record(PenetrationRecord(NatType::FullCone, "联通", GeoRegion::Central,
                                        CgnStrategy::RelayFallback, true,
                                        std::chrono::milliseconds(300)));
    }

    // 统计推荐应优先 RelayFallback（1.0 > 0.5）
    auto rec = stats.recommend_strategy(key, candidates);
    CHECK(rec.has_value());
    CHECK_EQ(rec->first, CgnStrategy::RelayFallback);

    // 但冷启动时仍用默认候选[0]
    StatsKey cold_key{NatType::FullCone, "新运营商", GeoRegion::Central};
    auto cold_rec = stats.recommend_strategy(cold_key, candidates);
    CHECK(!cold_rec.has_value());  // 冷启动回退
}

// ========== main ==========

int main() {
    std::printf("=== test_nat_prediction_model (V3.6.0 P5-D-2 E2E) ===\n");

    test_e2e_symmetric_nat_high_confidence();
    test_e2e_cold_start_fallback();
    test_e2e_stats_driven_recommendation();
    test_e2e_port_predictor_feedback();
    test_e2e_relay_fallback_after_failures();
    test_e2e_persistence_across_restart();
    test_e2e_multi_peer_learning();
    test_e2e_default_candidates_vs_stats();

    std::printf("\n=== test_nat_prediction_model: %d pass, %d fail ===\n",
                g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
