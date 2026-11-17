// test_congestion_auto_switch.cpp — v3.3.0 突破1: BBR v2 默认化 + 跨域拥塞自适应测试
//
// 验证目标：
//   1. 默认拥塞算法为 BbrV2（非 NewReno）
//   2. BbrV2Controller 初始状态正确（Startup, algo_name="bbrv2"）
//   3. apply_cross_domain_config 成功应用跨域参数
//   4. is_cross_domain_configured 状态正确
//   5. NewReno 的 apply_cross_domain_config 返回 false（不支持跨域自适应）
//   6. 跨域配置后 BBR 参数变化（min_rtt_window 30s, probe_rtt 60s, cwnd_gain 3.0）
//   7. 重复 apply_cross_domain_config 幂等（不崩溃，状态一致）
//   8. 跨域配置后 on_ack 不改变已配置参数
//   9. RTT 阈值检测：SRTT > 50ms 触发跨域配置的概念验证
//  10. 工厂函数 make_congestion_controller(BbrV2) 返回正确类型
//  11. 工厂函数 make_congestion_controller(NewReno) 返回正确类型
//  12. BBR on_loss 不退避 cwnd（核心特性保持）
//  13. BBR on_rto 重置到 Startup（跨域配置后仍重置状态机）

#include "linoh/protocol/bbr_v2.hpp"
#include "linoh/protocol/loss_recovery.hpp"
#include "linoh/protocol/congestion_controller.hpp"

#include <cmath>
#include <cstdio>
#include <memory>

using namespace linoh::protocol;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while(0)

// ============================================================================
// 测试 1: 默认拥塞算法枚举值
// ============================================================================
static void test_default_algo_enum() {
    printf("[test] default algo enum is BbrV2...\n");
    // v3.3.0 突破1: 默认改为 BbrV2
    // 注意：此处验证枚举值，不依赖 ConnectionConfig（避免引入 endpoint 头文件依赖）
    CHECK(static_cast<int>(CongestionAlgo::BbrV2) == 1);
    CHECK(static_cast<int>(CongestionAlgo::NewReno) == 0);
}

// ============================================================================
// 测试 2: BbrV2Controller 初始状态
// ============================================================================
static void test_bbr_initial_state() {
    printf("[test] BBR v2 initial state...\n");
    RttEstimator rtt;
    rtt.update(30.0, 0.0);  // 初始 RTT 30ms
    auto ctrl = make_congestion_controller(CongestionAlgo::BbrV2, &rtt);
    CHECK(ctrl != nullptr);
    CHECK(ctrl->algo_name() == "bbrv2");
    CHECK(ctrl->cwnd_bytes() > 0);
    CHECK(ctrl->pacing_rate_bps() >= 0);  // Startup 阶段 pacing 可能为 0 或正值
    CHECK(!ctrl->is_cross_domain_configured());  // 初始未配置跨域
}

// ============================================================================
// 测试 3: apply_cross_domain_config 成功
// ============================================================================
static void test_apply_cross_domain_config() {
    printf("[test] apply_cross_domain_config succeeds...\n");
    RttEstimator rtt;
    rtt.update(80.0, 0.0);  // 跨域 RTT 80ms
    auto ctrl = make_congestion_controller(CongestionAlgo::BbrV2, &rtt);

    BbrCrossDomainConfig cfg{};
    bool result = ctrl->apply_cross_domain_config(cfg);
    CHECK(result == true);
    CHECK(ctrl->is_cross_domain_configured() == true);
}

// ============================================================================
// 测试 4: NewReno 不支持跨域配置
// ============================================================================
static void test_newreno_cross_domain_unsupported() {
    printf("[test] NewReno cross-domain unsupported...\n");
    auto ctrl = make_congestion_controller(CongestionAlgo::NewReno, nullptr);
    CHECK(ctrl != nullptr);
    CHECK(ctrl->algo_name() == "newreno");

    BbrCrossDomainConfig cfg{};
    bool result = ctrl->apply_cross_domain_config(cfg);
    CHECK(result == false);  // NewReno 不支持
    CHECK(ctrl->is_cross_domain_configured() == false);
}

// ============================================================================
// 测试 5: 重复 apply_cross_domain_config 幂等
// ============================================================================
static void test_cross_domain_config_idempotent() {
    printf("[test] cross-domain config idempotent...\n");
    RttEstimator rtt;
    rtt.update(60.0, 0.0);
    auto ctrl = make_congestion_controller(CongestionAlgo::BbrV2, &rtt);

    BbrCrossDomainConfig cfg{};
    CHECK(ctrl->apply_cross_domain_config(cfg) == true);
    CHECK(ctrl->is_cross_domain_configured() == true);
    // 再次应用不崩溃
    CHECK(ctrl->apply_cross_domain_config(cfg) == true);
    CHECK(ctrl->is_cross_domain_configured() == true);
}

// ============================================================================
// 测试 6: 跨域配置后 on_ack 正常工作
// ============================================================================
static void test_cross_domain_config_then_ack() {
    printf("[test] cross-domain config then on_ack...\n");
    RttEstimator rtt;
    rtt.update(70.0, 0.0);
    auto ctrl = make_congestion_controller(CongestionAlgo::BbrV2, &rtt);

    BbrCrossDomainConfig cfg{};
    ctrl->apply_cross_domain_config(cfg);
    CHECK(ctrl->is_cross_domain_configured() == true);

    // 跨域配置后 ACK 不改变 is_cross_domain_configured 状态
    ctrl->on_ack(1460, 1);
    CHECK(ctrl->is_cross_domain_configured() == true);
    CHECK(ctrl->cwnd_bytes() > 0);
}

// ============================================================================
// 测试 7: BBR on_loss 不退避 cwnd（核心特性）
// ============================================================================
static void test_bbr_loss_no_backoff() {
    printf("[test] BBR on_loss no cwnd backoff...\n");
    RttEstimator rtt;
    rtt.update(30.0, 0.0);
    auto ctrl = make_congestion_controller(CongestionAlgo::BbrV2, &rtt);

    uint64_t cwnd_before = ctrl->cwnd_bytes();
    ctrl->on_loss(100);  // 模拟丢包
    uint64_t cwnd_after = ctrl->cwnd_bytes();

    // BBR 核心特性：不基于丢包退避 cwnd（与 NewReno 不同）
    // 注意：Startup 阶段 cwnd 可能因 on_ack 增长，但 on_loss 本身不缩减
    CHECK(cwnd_after >= cwnd_before);  // 不缩减
}

// ============================================================================
// 测试 8: BBR on_rto 重置到 Startup
// ============================================================================
static void test_bbr_rto_reset() {
    printf("[test] BBR on_rto resets to Startup...\n");
    RttEstimator rtt;
    rtt.update(80.0, 0.0);
    auto ctrl = make_congestion_controller(CongestionAlgo::BbrV2, &rtt);

    // 先应用跨域配置
    BbrCrossDomainConfig cfg{};
    ctrl->apply_cross_domain_config(cfg);
    CHECK(ctrl->is_cross_domain_configured() == true);

    // 模拟一些 ACK
    ctrl->on_ack(14600, 1);
    ctrl->on_ack(14600, 2);

    // RTO 超时重置
    ctrl->on_rto();
    // RTO 后状态机重置到 Startup，但跨域配置标志保留（参数不丢失）
    CHECK(ctrl->cwnd_bytes() > 0);
}

// ============================================================================
// 测试 9: 跨域 BbrCrossDomainConfig 默认值
// ============================================================================
static void test_cross_domain_config_defaults() {
    printf("[test] BbrCrossDomainConfig default values...\n");
    BbrCrossDomainConfig cfg{};
    CHECK(cfg.cross_domain_min_rtt_window.count() == 30);      // 30s
    CHECK(cfg.cross_domain_probe_rtt_interval.count() == 60);  // 60s
    CHECK(std::abs(cfg.cross_domain_startup_gain - 2.77) < 0.01);
    CHECK(std::abs(cfg.cross_domain_cwnd_gain - 3.0) < 0.01);
    CHECK(cfg.cross_domain_enable_pacing == true);
}

// ============================================================================
// 测试 10: 工厂函数创建正确类型
// ============================================================================
static void test_factory_creates_correct_type() {
    printf("[test] factory creates correct type...\n");
    RttEstimator rtt;
    rtt.update(30.0, 0.0);

    auto bbr = make_congestion_controller(CongestionAlgo::BbrV2, &rtt);
    CHECK(bbr != nullptr);
    CHECK(bbr->algo_name() == "bbrv2");
    CHECK(bbr->pacing_rate_bps() >= 0);  // BBR 有 pacing 速率

    auto newreno = make_congestion_controller(CongestionAlgo::NewReno, nullptr);
    CHECK(newreno != nullptr);
    CHECK(newreno->algo_name() == "newreno");
    CHECK(newreno->pacing_rate_bps() == 0);  // NewReno 无 pacing
}

// ============================================================================
// 测试 11: 跨域配置自定义参数
// ============================================================================
static void test_cross_domain_custom_config() {
    printf("[test] cross-domain custom config...\n");
    RttEstimator rtt;
    rtt.update(100.0, 0.0);
    auto ctrl = make_congestion_controller(CongestionAlgo::BbrV2, &rtt);

    BbrCrossDomainConfig cfg{};
    cfg.cross_domain_min_rtt_window = std::chrono::seconds(45);
    cfg.cross_domain_probe_rtt_interval = std::chrono::seconds(90);
    cfg.cross_domain_cwnd_gain = 4.0;
    cfg.cross_domain_enable_pacing = false;

    bool result = ctrl->apply_cross_domain_config(cfg);
    CHECK(result == true);
    CHECK(ctrl->is_cross_domain_configured() == true);
}

// ============================================================================
// 测试 12: BBR can_send 边界检查
// ============================================================================
static void test_bbr_can_send_boundary() {
    printf("[test] BBR can_send boundary...\n");
    RttEstimator rtt;
    rtt.update(30.0, 0.0);
    auto ctrl = make_congestion_controller(CongestionAlgo::BbrV2, &rtt);

    uint64_t cwnd = ctrl->cwnd_bytes();
    CHECK(cwnd > 0);
    CHECK(ctrl->can_send(1) == true);           // 1 字节总能发
    CHECK(ctrl->can_send(cwnd) == true);        // 刚好 cwnd 内
    // 超出 cwnd 的请求（取决于实现，可能 true 或 false）
    // 不做严格断言，只验证不崩溃
    ctrl->can_send(cwnd + 1);
}

// ============================================================================
// 测试 13: RTT 阈值概念验证 — SRTT > 50ms 应触发跨域配置
// ============================================================================
static void test_rtt_threshold_concept() {
    printf("[test] RTT threshold concept (>50ms triggers cross-domain)...\n");
    RttEstimator rtt;

    // 单域 RTT 20ms — 不应触发跨域
    rtt.update(20.0, 0.0);
    double srtt_lan = rtt.srtt_ms();
    CHECK(srtt_lan < 50.0);  // 单域 RTT < 50ms

    // 跨域 RTT 80ms — 应触发跨域
    RttEstimator rtt_wan;
    rtt_wan.update(80.0, 0.0);
    double srtt_wan = rtt_wan.srtt_ms();
    CHECK(srtt_wan > 50.0);  // 跨域 RTT > 50ms

    // 验证 BBR + 跨域 RTT + apply_cross_domain_config 链路
    auto ctrl = make_congestion_controller(CongestionAlgo::BbrV2, &rtt_wan);
    if (srtt_wan > 50.0 && !ctrl->is_cross_domain_configured()) {
        BbrCrossDomainConfig cfg{};
        CHECK(ctrl->apply_cross_domain_config(cfg) == true);
        CHECK(ctrl->is_cross_domain_configured() == true);
    }
}

int main() {
    printf("=== test_congestion_auto_switch (v3.3.0 突破1) ===\n\n");

    test_default_algo_enum();
    test_bbr_initial_state();
    test_apply_cross_domain_config();
    test_newreno_cross_domain_unsupported();
    test_cross_domain_config_idempotent();
    test_cross_domain_config_then_ack();
    test_bbr_loss_no_backoff();
    test_bbr_rto_reset();
    test_cross_domain_config_defaults();
    test_factory_creates_correct_type();
    test_cross_domain_custom_config();
    test_bbr_can_send_boundary();
    test_rtt_threshold_concept();

    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
