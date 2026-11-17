// test_port_predictor.cpp — P5-D-1 Symmetric NAT 端口预测引擎单元测试
//
// 测试覆盖：
//   1. PortObservation 序列化往返
//   2. linear_fit 线性回归工具
//   3. compute_delta_stats 增量统计
//   4. 冷启动（无历史 / 1 点观测）
//   5. TwoPoint 模型（2 点，兼容 v3.5）
//   6. LinearRegression 模型（5 点等差/带噪）
//   7. WeightedRecent 模型（旧观测权重衰减）
//   8. Hybrid 模型融合
//   9. 置信度自适应候选数
//  10. 命中/未命中反馈
//  11. LRU 淘汰（32 条上限）
//  12. 持久化往返（save/load）
//  13. 多线程并发 record/predict
//  14. 监控计数（peer_count / total_observations）

#include "linoh/nat/port_predictor.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

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

// ========== 测试用例 ==========

// 1. PortObservation 序列化往返
static void test_observation_parse_to_string() {
    std::printf("[test] PortObservation parse/to_string roundtrip...\n");
    PortObservation obs;
    obs.peer_endpoint = make_peer(0x10);
    obs.observed_port = 12345;
    obs.timestamp = make_tp(1700000000000LL);  // 固定 epoch

    std::string s = obs.to_string();
    CHECK_EQ(s.size() > 66u, true);  // 64 hex + '|' + port + '|' + epoch

    PortObservation parsed;
    bool ok = PortObservation::parse(s, parsed);
    CHECK(ok);
    CHECK_EQ(parsed.observed_port, std::uint16_t{12345});
    // peer 字节一致
    CHECK(std::memcmp(parsed.peer_endpoint.data(), obs.peer_endpoint.data(), 32) == 0);
    // 时间戳一致
    auto ms_orig = std::chrono::duration_cast<std::chrono::milliseconds>(
        obs.timestamp.time_since_epoch()).count();
    auto ms_parsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        parsed.timestamp.time_since_epoch()).count();
    CHECK_EQ(ms_orig, ms_parsed);

    // 非法输入
    PortObservation bad;
    CHECK(!PortObservation::parse("short", bad));
    CHECK(!PortObservation::parse("", bad));
}

// 2. linear_fit 线性回归工具
static void test_linear_fit_util() {
    std::printf("[test] linear_fit utility...\n");
    // 完美线性 y = 2x + 1
    std::vector<double> xs = {0, 1, 2, 3, 4};
    std::vector<double> ys = {1, 3, 5, 7, 9};
    LinearFit fit = linear_fit(xs, ys);
    CHECK(fit.valid);
    CHECK_EQ(static_cast<int>(std::round(fit.slope * 100)), 200);       // 2.0
    CHECK_EQ(static_cast<int>(std::round(fit.intercept * 100)), 100);   // 1.0
    CHECK_EQ(fit.residual_stddev < 1e-9, true);

    // 样本不足
    LinearFit bad = linear_fit({1.0}, {2.0});
    CHECK(!bad.valid);

    // 空样本
    LinearFit empty = linear_fit({}, {});
    CHECK(!empty.valid);

    // 垂直线（x 全相同）→ invalid
    LinearFit vert = linear_fit({5.0, 5.0, 5.0}, {1.0, 2.0, 3.0});
    CHECK(!vert.valid);
}

// 3. compute_delta_stats 增量统计
static void test_delta_stats_util() {
    std::printf("[test] compute_delta_stats utility...\n");
    std::vector<std::int32_t> deltas = {10, 10, 10, 10};
    DeltaStats stats = compute_delta_stats(deltas);
    CHECK(stats.valid);
    CHECK_EQ(static_cast<int>(std::round(stats.mean * 100)), 1000);  // 10.0
    CHECK(stats.stddev < 1e-9);  // 完全稳定

    // 带波动
    std::vector<std::int32_t> noisy = {10, 20, 5, 15};
    DeltaStats noisy_stats = compute_delta_stats(noisy);
    CHECK(noisy_stats.valid);
    CHECK(noisy_stats.stddev > 0.0);

    // 空输入
    DeltaStats empty = compute_delta_stats({});
    CHECK(!empty.valid);
}

// 4. 冷启动（无历史）
static void test_cold_start_no_history() {
    std::printf("[test] cold start (no history)...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x01);
    PortPrediction pred = pp.predict(peer);
    CHECK(pred.is_cold_start());
    CHECK_EQ(pred.observation_count, std::size_t{0});
    CHECK_EQ(pred.confidence, 0.0);
    CHECK_EQ(pred.candidates.empty(), true);
    CHECK_EQ(pp.observation_count(peer), std::size_t{0});
    CHECK_EQ(pp.peer_count(), std::size_t{0});
}

// 5. 冷启动（1 点观测）
static void test_cold_start_one_observation() {
    std::printf("[test] cold start (1 observation)...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x02);
    pp.record_observation(peer, 50000, make_tp(1000));
    PortPrediction pred = pp.predict(peer);
    // 1 点 < min_observations_for_advanced(3)，TwoPoint 需 2 点，置信度 0
    CHECK(pred.is_cold_start());  // observation_count < 2
    CHECK_EQ(pred.observation_count, std::size_t{1});
}

// 6. TwoPoint 模型（2 点，兼容 v3.5）
static void test_two_point_compat() {
    std::printf("[test] TwoPoint model (2 points, v3.5 compat)...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x03);
    pp.record_observation(peer, 40000, make_tp(1000));
    pp.record_observation(peer, 40010, make_tp(2000));
    PortPrediction pred = pp.predict(peer);
    // 2 点 < min_observations_for_advanced(3)，用 TwoPoint
    CHECK_EQ(pred.model_used, PortPredictModel::TwoPoint);
    CHECK_EQ(pred.observation_count, std::size_t{2});
    CHECK(!pred.candidates.empty());
    // delta=10，首个候选应为 40010 + 10 = 40020
    CHECK_EQ(pred.candidates[0], std::uint16_t{40020});
    // 第二候选 40010 + 20 = 40030
    CHECK_EQ(pred.candidates[1], std::uint16_t{40030});
    // 2 点置信度 0.5
    CHECK_EQ(pred.confidence, 0.5);
}

// 7. LinearRegression 模型（5 点等差）
static void test_linear_regression_stable() {
    std::printf("[test] LinearRegression model (5 points stable)...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x04);
    // 等差序列：50000, 50010, 50020, 50030, 50040（delta=10）
    for (int i = 0; i < 5; ++i) {
        pp.record_observation(peer, static_cast<std::uint16_t>(50000 + i * 10),
                              make_tp(1000LL * i));
    }
    PortPrediction pred = pp.predict(peer);
    // 5 点 >= 3，用 Hybrid（融合包含 LR）
    CHECK_EQ(pred.model_used, PortPredictModel::Hybrid);
    CHECK(!pred.candidates.empty());
    // 预测下一个应在 50050 附近（首候选）
    CHECK_EQ(pred.candidates[0], std::uint16_t{50050});
    // 等差序列置信度高
    CHECK(pred.confidence > 0.5);
}

// 8. LinearRegression 带噪序列
static void test_linear_regression_noisy() {
    std::printf("[test] LinearRegression model (noisy)...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x05);
    // 带噪序列：50000, 50020, 50005, 50035, 50015
    std::uint16_t ports[] = {50000, 50020, 50005, 50035, 50015};
    for (int i = 0; i < 5; ++i) {
        pp.record_observation(peer, ports[i], make_tp(1000LL * i));
    }
    PortPrediction pred = pp.predict(peer);
    CHECK(!pred.candidates.empty());
    // 带噪置信度低于等差
    PortPredictor pp2;
    EndpointId peer2 = make_peer(0x44);
    for (int i = 0; i < 5; ++i) {
        pp2.record_observation(peer2, static_cast<std::uint16_t>(50000 + i * 10),
                               make_tp(1000LL * i));
    }
    PortPrediction pred_stable = pp2.predict(peer2);
    CHECK(pred_stable.confidence > pred.confidence);
}

// 9. WeightedRecent 旧观测权重衰减
static void test_weighted_recent_decay() {
    std::printf("[test] WeightedRecent decay...\n");
    // 直接测试 predict_weighted_recent 的行为：近期端口主导
    PortPredictor pp;
    EndpointId peer = make_peer(0x06);
    // 旧观测端口低，新观测端口高，增量递增
    pp.record_observation(peer, 30000, make_tp(0));       // 很旧
    pp.record_observation(peer, 31000, make_tp(1000));    // 旧
    pp.record_observation(peer, 33000, make_tp(2000));    // 较新
    pp.record_observation(peer, 36000, make_tp(3000));    // 新
    pp.record_observation(peer, 40000, make_tp(4000));    // 最新
    PortPrediction pred = pp.predict(peer);
    CHECK(!pred.candidates.empty());
    // 最新增量 4000，预测应偏向大幅增长（>40000）
    CHECK(pred.candidates[0] > 40000);
}

// 10. Hybrid 模型融合
static void test_hybrid_model_fusion() {
    std::printf("[test] Hybrid model fusion...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x07);
    for (int i = 0; i < 6; ++i) {
        pp.record_observation(peer, static_cast<std::uint16_t>(20000 + i * 5),
                              make_tp(1000LL * i));
    }
    PortPrediction pred = pp.predict(peer);
    CHECK_EQ(pred.model_used, PortPredictModel::Hybrid);
    CHECK(!pred.candidates.empty());
    // 候选去重（无重复端口）
    std::vector<std::uint16_t> sorted = pred.candidates;
    std::sort(sorted.begin(), sorted.end());
    auto last = std::unique(sorted.begin(), sorted.end());
    CHECK(last == sorted.end());  // 无重复
}

// 11. 置信度自适应候选数
static void test_confidence_adaptive_count() {
    std::printf("[test] confidence adaptive count...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x08);
    // 等差序列（高置信度）
    for (int i = 0; i < 5; ++i) {
        pp.record_observation(peer, static_cast<std::uint16_t>(10000 + i * 3),
                              make_tp(1000LL * i));
    }
    PortPrediction pred = pp.predict(peer);  // count=0 自适应
    CHECK(!pred.candidates.empty());
    // 高置信度 → 候选数较少（接近 min_candidates=5）
    CHECK(pred.candidates.size() <= 20u);
    CHECK(pred.candidates.size() >= 5u);
}

// 12. 命中/未命中反馈
static void test_feedback_hit_miss() {
    std::printf("[test] feedback hit/miss...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x09);
    pp.record_observation(peer, 30000, make_tp(0));
    pp.record_observation(peer, 30010, make_tp(1000));

    PeerHitStats stats0 = pp.hit_stats(peer);
    CHECK_EQ(stats0.hit_count, std::uint64_t{0});
    CHECK_EQ(stats0.miss_count, std::uint64_t{0});
    CHECK_EQ(stats0.hit_rate(), 0.0);

    pp.feedback(peer, 30020, 30020, true, PortPredictModel::TwoPoint);
    pp.feedback(peer, 30030, 30099, false, PortPredictModel::TwoPoint);

    PeerHitStats stats1 = pp.hit_stats(peer);
    CHECK_EQ(stats1.hit_count, std::uint64_t{1});
    CHECK_EQ(stats1.miss_count, std::uint64_t{1});
    CHECK_EQ(stats1.hit_rate(), 0.5);
}

// 13. LRU 淘汰（32 条上限）
static void test_lru_eviction() {
    std::printf("[test] LRU eviction (32 cap)...\n");
    PortPredictorConfig cfg;
    cfg.max_observations_per_peer = 8;  // 小上限便于测试
    PortPredictor pp(std::move(cfg));
    EndpointId peer = make_peer(0x0A);
    for (int i = 0; i < 20; ++i) {
        pp.record_observation(peer, static_cast<std::uint16_t>(10000 + i),
                              make_tp(1000LL * i));
    }
    CHECK_EQ(pp.observation_count(peer), std::size_t{8});  // 被限制到 8
    // 最旧的被淘汰，最新的是 10019
    PortPrediction pred = pp.predict(peer);
    CHECK_EQ(pred.observation_count, std::size_t{8});
}

// 14. 持久化往返
static void test_persistence_roundtrip() {
    std::printf("[test] persistence roundtrip...\n");
    const std::string path = "test_port_predictor_history.tmp";
    {
        PortPredictorConfig cfg;
        cfg.persistence_path = path;
        PortPredictor pp(std::move(cfg));
        EndpointId peer = make_peer(0x0B);
        pp.record_observation(peer, 11111, make_tp(1000));
        pp.record_observation(peer, 11121, make_tp(2000));
        pp.record_observation(peer, 11131, make_tp(3000));
        pp.feedback(peer, 11141, 11141, true, PortPredictModel::TwoPoint);
        CHECK(pp.save_to_file());
    }
    // 重新加载
    {
        PortPredictorConfig cfg;
        cfg.persistence_path = path;
        PortPredictor pp(std::move(cfg));  // 构造时自动 load
        EndpointId peer = make_peer(0x0B);
        CHECK_EQ(pp.observation_count(peer), std::size_t{3});
        PortPrediction pred = pp.predict(peer);
        CHECK(!pred.candidates.empty());
        CHECK_EQ(pred.observation_count, std::size_t{3});
    }
    // 清理
    std::remove(path.c_str());
}

// 15. 多线程并发 record/predict
static void test_concurrent_record_predict() {
    std::printf("[test] concurrent record/predict...\n");
    PortPredictor pp;
    EndpointId peer = make_peer(0x0C);

    std::atomic<int> done{0};
    std::vector<std::thread> threads;
    // 4 写线程 + 4 读线程
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&pp, peer, t, &done]() {
            for (int i = 0; i < 100; ++i) {
                pp.record_observation(peer,
                    static_cast<std::uint16_t>(20000 + t * 100 + i),
                    make_tp(1000LL * (t * 100 + i)));
            }
            ++done;
        });
    }
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&pp, peer, &done]() {
            for (int i = 0; i < 100; ++i) {
                PortPrediction pred = pp.predict(peer);
                (void)pred;
            }
            ++done;
        });
    }
    for (auto &th : threads) th.join();
    CHECK_EQ(done.load(), 8);
    // 最终观测数受 LRU 限制（32）
    CHECK(pp.observation_count(peer) <= 32u);
    CHECK(pp.observation_count(peer) > 0u);
}

// 16. 监控计数
static void test_monitoring_counts() {
    std::printf("[test] monitoring counts...\n");
    PortPredictor pp;
    CHECK_EQ(pp.peer_count(), std::size_t{0});
    CHECK_EQ(pp.total_observations(), std::size_t{0});

    EndpointId peer1 = make_peer(0x10);
    EndpointId peer2 = make_peer(0x20);
    pp.record_observation(peer1, 1000, make_tp(0));
    pp.record_observation(peer1, 1010, make_tp(1000));
    pp.record_observation(peer2, 2000, make_tp(0));

    CHECK_EQ(pp.peer_count(), std::size_t{2});
    CHECK_EQ(pp.total_observations(), std::size_t{3});
    CHECK_EQ(pp.observation_count(peer1), std::size_t{2});
    CHECK_EQ(pp.observation_count(peer2), std::size_t{1});

    pp.clear();
    CHECK_EQ(pp.peer_count(), std::size_t{0});
    CHECK_EQ(pp.total_observations(), std::size_t{0});
}

// ========== main ==========

int main() {
    std::printf("=== test_port_predictor ===\n");
    test_observation_parse_to_string();
    test_linear_fit_util();
    test_delta_stats_util();
    test_cold_start_no_history();
    test_cold_start_one_observation();
    test_two_point_compat();
    test_linear_regression_stable();
    test_linear_regression_noisy();
    test_weighted_recent_decay();
    test_hybrid_model_fusion();
    test_confidence_adaptive_count();
    test_feedback_hit_miss();
    test_lru_eviction();
    test_persistence_roundtrip();
    test_concurrent_record_predict();
    test_monitoring_counts();

    std::printf("\n=== test_port_predictor: %d pass, %d fail ===\n",
                g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
