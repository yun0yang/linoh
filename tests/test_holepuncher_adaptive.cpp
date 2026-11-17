// test_holepuncher_adaptive.cpp — P5-D-4 Holepuncher 自适应候选数单元测试
//
// 测试覆盖：
//   1. build_candidates_predictor_nullptr — predictor=nullptr 回退固定 10
//   2. build_candidates_cold_start — predictor 无历史回退固定 10
//   3. build_candidates_with_history — predictor 有历史使用其候选
//   4. build_candidates_used_predictor_flag — used_predictor_out 标志正确
//   5. build_candidates_model_used — model_used_out 反映预测模型
//   6. build_candidates_confidence — confidence_out 反映置信度
//   7. build_candidates_dedup_observed_ports — 观测端口去重
//   8. build_candidates_observed_appended — 观测端口追加兜底
//   9. build_candidates_adaptive_count_range — predictor 候选数 5-20 范围
//  10. attempt_adaptive_nullptr_no_crash — nullptr 不崩溃
//  11. attempt_adaptive_cold_start_no_crash — 冷启动不崩溃
//  12. attempt_adaptive_with_history_no_crash — 有历史不崩溃

#include "linoh/net/holepuncher.hpp"
#include "linoh/nat/port_predictor.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>

using namespace linoh::net;
using namespace linoh::nat;
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

// ========== 测试辅助 ==========

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

/// 向 predictor 记录 N 次等差端口观测（模拟对端 NAT 端口序列）
static void record_port_sequence(PortPredictor &pp, const EndpointId &peer,
                                 std::uint16_t start_port, std::uint16_t delta,
                                 std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) {
        pp.record_observation(peer, static_cast<std::uint16_t>(start_port + i * delta),
                              make_tp(1000LL * i));
    }
}

// ========== 测试用例 ==========

// 1. build_candidates_predictor_nullptr — predictor=nullptr 回退固定 10
static void test_build_candidates_predictor_nullptr() {
    std::printf("[test] build_candidates_predictor_nullptr...\n");
    EndpointId peer = make_peer(0x01);
    bool used = true;
    PortPredictModel model = PortPredictModel::Hybrid;
    double conf = 1.0;

    auto candidates = Holepuncher::build_adaptive_candidates(
        40000, 40010, nullptr, peer, used, model, conf);

    CHECK(!used);                                      // nullptr 不使用 predictor
    CHECK_EQ(model, PortPredictModel::TwoPoint);       // 回退模型
    CHECK_EQ(conf, 0.0);                               // 无置信度
    CHECK(candidates.size() >= 10);                    // 固定 10 + 观测端口
    CHECK(candidates.size() <= 12);                    // 最多 10 + 2 观测
}

// 2. build_candidates_cold_start — predictor 无历史回退固定 10
static void test_build_candidates_cold_start() {
    std::printf("[test] build_candidates_cold_start...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x02);  // 无历史观测
    bool used = true;
    PortPredictModel model = PortPredictModel::Hybrid;
    double conf = 1.0;

    auto candidates = Holepuncher::build_adaptive_candidates(
        40000, 40010, &pp, peer, used, model, conf);

    CHECK(!used);  // 冷启动不使用 predictor
    CHECK_EQ(conf, 0.0);
    CHECK(candidates.size() >= 10);
}

// 3. build_candidates_with_history — predictor 有历史使用其候选
static void test_build_candidates_with_history() {
    std::printf("[test] build_candidates_with_history...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x03);
    // 记录 5 次等差观测：40000, 40010, 40020, 40030, 40040
    record_port_sequence(pp, peer, 40000, 10, 5);

    bool used = false;
    PortPredictModel model = PortPredictModel::TwoPoint;
    double conf = 0.0;

    auto candidates = Holepuncher::build_adaptive_candidates(
        40000, 40010, &pp, peer, used, model, conf);

    CHECK(used);                            // 有历史 → 使用 predictor
    CHECK(conf > 0.0);                      // 有置信度
    CHECK(!candidates.empty());
    // predictor 候选应包含 40050（40040 + 10）
    bool has_40050 = std::find(candidates.begin(), candidates.end(),
                               std::uint16_t(40050)) != candidates.end();
    CHECK(has_40050);
}

// 4. build_candidates_used_predictor_flag — used_predictor_out 标志正确
static void test_build_candidates_used_predictor_flag() {
    std::printf("[test] build_candidates_used_predictor_flag...\n");
    EndpointId peer = make_peer(0x04);

    // nullptr → false
    {
        bool used = true;
        PortPredictModel model;
        double conf;
        Holepuncher::build_adaptive_candidates(40000, 40010, nullptr, peer,
                                               used, model, conf);
        CHECK(!used);
    }

    // 冷启动 → false
    {
        PortPredictor pp;
        bool used = true;
        PortPredictModel model;
        double conf;
        Holepuncher::build_adaptive_candidates(40000, 40010, &pp, peer,
                                               used, model, conf);
        CHECK(!used);
    }

    // 有历史 → true
    {
        PortPredictor pp;
        record_port_sequence(pp, peer, 40000, 10, 5);
        bool used = false;
        PortPredictModel model;
        double conf;
        Holepuncher::build_adaptive_candidates(40000, 40010, &pp, peer,
                                               used, model, conf);
        CHECK(used);
    }
}

// 5. build_candidates_model_used — model_used_out 反映预测模型
static void test_build_candidates_model_used() {
    std::printf("[test] build_candidates_model_used...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x05);
    // 2 点观测 → TwoPoint 模型
    pp.record_observation(peer, 40000, make_tp(1000));
    pp.record_observation(peer, 40010, make_tp(2000));

    bool used;
    PortPredictModel model = PortPredictModel::Hybrid;
    double conf;

    Holepuncher::build_adaptive_candidates(40000, 40010, &pp, peer,
                                           used, model, conf);
    CHECK(used);
    CHECK_EQ(model, PortPredictModel::TwoPoint);  // 2 点用 TwoPoint
}

// 6. build_candidates_confidence — confidence_out 反映置信度
static void test_build_candidates_confidence() {
    std::printf("[test] build_candidates_confidence...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x06);
    // 2 点稳定 delta → 置信度 0.5
    pp.record_observation(peer, 40000, make_tp(1000));
    pp.record_observation(peer, 40010, make_tp(2000));

    bool used;
    PortPredictModel model;
    double conf = 0.0;

    Holepuncher::build_adaptive_candidates(40000, 40010, &pp, peer,
                                           used, model, conf);
    CHECK(used);
    CHECK_EQ(conf, 0.5);  // 2 点 TwoPoint 置信度 0.5
}

// 7. build_candidates_dedup_observed_ports — 观测端口去重
static void test_build_candidates_dedup_observed_ports() {
    std::printf("[test] build_candidates_dedup_observed_ports...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x07);
    // predictor 预测的候选中已包含 40000
    record_port_sequence(pp, peer, 40000, 10, 5);  // 候选含 40050, 40060...
    // 注：predictor 候选可能不含 40000，但让我们用 predictor 预测的端口作为观测值
    auto pred = pp.predict(peer);
    std::uint16_t predicted_first = pred.candidates.empty() ? 0 : pred.candidates[0];

    bool used;
    PortPredictModel model;
    double conf;
    // 用 predicted_first 作为观测端口，应被去重
    auto candidates = Holepuncher::build_adaptive_candidates(
        predicted_first, predicted_first, &pp, peer, used, model, conf);

    // 统计 predicted_first 出现次数
    std::size_t count = std::count(candidates.begin(), candidates.end(), predicted_first);
    CHECK_EQ(count, std::size_t(1));  // 只出现一次（去重）
}

// 8. build_candidates_observed_appended — 观测端口追加兜底
static void test_build_candidates_observed_appended() {
    std::printf("[test] build_candidates_observed_appended...\n");
    EndpointId peer = make_peer(0x08);
    bool used;
    PortPredictModel model;
    double conf;

    // 用独特端口 50000/50010 作为观测值
    auto candidates = Holepuncher::build_adaptive_candidates(
        50000, 50010, nullptr, peer, used, model, conf);

    // 观测端口应在候选列表中（兜底）
    bool has_50000 = std::find(candidates.begin(), candidates.end(),
                               std::uint16_t(50000)) != candidates.end();
    bool has_50010 = std::find(candidates.begin(), candidates.end(),
                               std::uint16_t(50010)) != candidates.end();
    CHECK(has_50000);
    CHECK(has_50010);
}

// 9. build_candidates_adaptive_count_range — predictor 候选数 5-20 范围
static void test_build_candidates_adaptive_count_range() {
    std::printf("[test] build_candidates_adaptive_count_range...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x09);
    // 记录充足观测（>= min_observations_for_advanced=3）
    record_port_sequence(pp, peer, 40000, 10, 10);

    bool used;
    PortPredictModel model;
    double conf;
    auto candidates = Holepuncher::build_adaptive_candidates(
        40000, 40010, &pp, peer, used, model, conf);

    CHECK(used);
    // predictor 候选数（不含追加的观测端口）应在 5-20 范围
    // 由于追加 2 个观测端口可能去重，总数 >= 5
    CHECK(candidates.size() >= 5);
    CHECK(candidates.size() <= 22);  // 20 + 2 观测
}

// 10. attempt_adaptive_nullptr_no_crash — nullptr 不崩溃
static void test_attempt_adaptive_nullptr_no_crash() {
    std::printf("[test] attempt_adaptive_nullptr_no_crash...\n");
    EndpointId peer = make_peer(0x0A);

    // 短超时 50ms，避免测试变慢；无对端 → 必然失败但不崩溃
    auto result = Holepuncher::attempt_symmetric_adaptive(
        "127.0.0.1", 0, "127.0.0.1", 9999,
        40000, 40010, nullptr, peer,
        std::chrono::milliseconds(50));

    CHECK(!result.success);  // 无对端响应
    CHECK_EQ(result.strategy_used, HolepunchStrategy::SymmetricNat);
}

// 11. attempt_adaptive_cold_start_no_crash — 冷启动不崩溃
static void test_attempt_adaptive_cold_start_no_crash() {
    std::printf("[test] attempt_adaptive_cold_start_no_crash...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x0B);  // 无历史

    auto result = Holepuncher::attempt_symmetric_adaptive(
        "127.0.0.1", 0, "127.0.0.1", 9999,
        40000, 40010, &pp, peer,
        std::chrono::milliseconds(50));

    CHECK(!result.success);
    CHECK_EQ(result.strategy_used, HolepunchStrategy::SymmetricNat);
}

// 12. attempt_adaptive_with_history_no_crash — 有历史不崩溃
static void test_attempt_adaptive_with_history_no_crash() {
    std::printf("[test] attempt_adaptive_with_history_no_crash...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x0C);
    record_port_sequence(pp, peer, 40000, 10, 5);

    auto result = Holepuncher::attempt_symmetric_adaptive(
        "127.0.0.1", 0, "127.0.0.1", 9999,
        40000, 40010, &pp, peer,
        std::chrono::milliseconds(50));

    CHECK(!result.success);  // 无对端响应，但不应崩溃
    CHECK_EQ(result.strategy_used, HolepunchStrategy::SymmetricNat);
}

// ========== main ==========

int main() {
    std::printf("=== test_holepuncher_adaptive (V3.6.1 P5-D-4) ===\n");

    test_build_candidates_predictor_nullptr();
    test_build_candidates_cold_start();
    test_build_candidates_with_history();
    test_build_candidates_used_predictor_flag();
    test_build_candidates_model_used();
    test_build_candidates_confidence();
    test_build_candidates_dedup_observed_ports();
    test_build_candidates_observed_appended();
    test_build_candidates_adaptive_count_range();
    test_attempt_adaptive_nullptr_no_crash();
    test_attempt_adaptive_cold_start_no_crash();
    test_attempt_adaptive_with_history_no_crash();

    std::printf("\n=== test_holepuncher_adaptive: %d pass, %d fail ===\n",
                g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
