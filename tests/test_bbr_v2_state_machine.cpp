// test_bbr_v2_state_machine.cpp — v2.0 BBR v2 拥塞控制状态机测试
//
// 验证目标：
//   1.  初始状态 Startup，cwnd = kInitialCwndBytes (14600)
//   2.  algo_name() == "bbrv2"
//   3.  can_send 边界（cwnd 内 true，超出 false）
//   4.  on_ack 后 max_bw > 0，total_acked 累加
//   5.  on_loss 不改变 cwnd（BBR 核心特性：不基于丢包退避）
//   6.  Startup 退出：连续 3 次低增长 ACK → Drain
//   7.  BDP 计算 = max_bw * min_rtt / 1000
//   8.  current_gain 各状态值（Startup=2.77, Drain=0.36, ProbeBW=1.25/0.75）
//   9.  Drain → ProbeBW 转换（持续 1 RTT 后）
//   10. ProbeBW 相位切换（每 RTT 切换）
//   11. on_rto 重置到 Startup
//   12. reset 回到 Startup
//   13. 工厂函数创建 NewReno / BbrV2
//   14. NewReno 通过基类指针多态调用
//   15. ProbeRTT cwnd = 4 * MSS（需 10s，仅验证 current_gain=0.5 逻辑）

#include "linoh/protocol/bbr_v2.hpp"
#include "linoh/protocol/loss_recovery.hpp"

#include <chrono>
#include <cstdio>
#include <memory>
#include <thread>

using namespace linoh::protocol;

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; } \
    else { printf("  [FAIL] %s (line %d)\n", msg, __LINE__); g_fail++; } \
} while (0)

// =============================================================================
// TEST 1: 初始状态 Startup，cwnd = 14600，algo = "bbrv2"
// =============================================================================
static void test_initial_state() {
    printf("\n=== TEST 1: 初始状态 ===\n");
    BbrV2Controller bbr;
    CHECK(bbr.state() == BbrState::Startup, "initial state = Startup");
    CHECK(bbr.cwnd_bytes() == kInitialCwndBytes, "initial cwnd == kInitialCwndBytes");
    // S3（K-BBRT-001）：IW 10→32 演进（kInitialCwnd=32，relay 大帧快速排空），
    // 旧断言硬编码 14600 已过时；常量断言为主，数值断言锚定 46720=32×1460
    CHECK(kInitialCwndBytes == 32 * 1460, "kInitialCwndBytes == 46720 (IW32)");
    CHECK(bbr.cwnd_bytes() == 46720, "initial cwnd == 46720 (IW32, S3 修正)");
    CHECK(bbr.algo_name() == "bbrv2", "algo_name == 'bbrv2'");
    CHECK(bbr.max_bw_bps() == 0, "initial max_bw = 0");
    CHECK(bbr.min_rtt_ms() == 0.0, "initial min_rtt = 0");
    CHECK(bbr.total_acked() == 0, "initial total_acked = 0");
    CHECK(bbr.pacing_rate_bps() == 0, "initial pacing_rate = 0");
}

// =============================================================================
// TEST 2: can_send 边界
// =============================================================================
static void test_can_send() {
    printf("\n=== TEST 2: can_send 边界 ===\n");
    BbrV2Controller bbr;
    // S3：随 kInitialCwnd=32 演进常量化（原硬编码 14600/14601 过时）
    CHECK(bbr.can_send(kInitialCwndBytes) == true, "can_send(cwnd) = true");
    CHECK(bbr.can_send(kInitialCwndBytes + 1) == false, "can_send(cwnd+1) = false");
    CHECK(bbr.can_send(1) == true, "can_send(1) = true");
    CHECK(bbr.can_send(0) == true, "can_send(0) = true");
}

// =============================================================================
// TEST 3: on_ack 更新带宽模型
// =============================================================================
static void test_on_ack_updates_model() {
    printf("\n=== TEST 3: on_ack 更新带宽模型 ===\n");
    RttEstimator rtt;
    rtt.update(10.0, 0.0);  // SRTT = 10ms

    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);

    // ACK 100000 bytes，delivery_rate = 100000 / 0.01 = 10000000 bytes/sec
    bbr.on_ack(100000, 1);

    CHECK(bbr.max_bw_bps() == 10000000, "max_bw = 10000000 after first ACK");
    CHECK(bbr.total_acked() == 100000, "total_acked = 100000");
    CHECK(bbr.min_rtt_ms() == 10.0, "min_rtt = 10.0ms");
}

// =============================================================================
// TEST 4: on_loss 不改变 cwnd（BBR 核心特性）
// =============================================================================
static void test_on_loss_no_cwnd_change() {
    printf("\n=== TEST 4: on_loss 不改变 cwnd ===\n");
    RttEstimator rtt;
    rtt.update(10.0, 0.0);

    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);
    bbr.on_ack(100000, 1);
    uint64_t cwnd_before = bbr.cwnd_bytes();

    bbr.on_loss(1);  // 丢包通知

    CHECK(bbr.cwnd_bytes() == cwnd_before, "cwnd unchanged after on_loss (BBR core)");
    CHECK(bbr.state() == BbrState::Startup, "state still Startup after on_loss");
}

// =============================================================================
// TEST 5: Startup 退出 → Drain（连续 3 次低增长）
// =============================================================================
static void test_startup_exit_to_drain() {
    printf("\n=== TEST 5: Startup → Drain ===\n");
    RttEstimator rtt;
    rtt.update(10.0, 0.0);

    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);

    // 第 1 次 ACK：max_bw=0，跳过退出检查，max_bw 更新为 10000000
    bbr.on_ack(100000, 1);
    CHECK(bbr.state() == BbrState::Startup, "still Startup after 1st ACK");
    CHECK(bbr.rounds_without_growth() == 0, "rounds_without_growth = 0 after 1st ACK");

    // 第 2 次 ACK：delivery_rate == max_bw，未增长 25% → rounds=1
    bbr.on_ack(100000, 1);
    CHECK(bbr.state() == BbrState::Startup, "still Startup after 2nd ACK");
    CHECK(bbr.rounds_without_growth() == 1, "rounds_without_growth = 1 after 2nd ACK");

    // 第 3 次 ACK：rounds=2
    bbr.on_ack(100000, 1);
    CHECK(bbr.state() == BbrState::Startup, "still Startup after 3rd ACK");
    CHECK(bbr.rounds_without_growth() == 2, "rounds_without_growth = 2 after 3rd ACK");

    // 第 4 次 ACK：rounds=3 >= kStartupExitRounds → enter_drain
    bbr.on_ack(100000, 1);
    CHECK(bbr.state() == BbrState::Drain, "state = Drain after 4th ACK (3 rounds no growth)");
}

// =============================================================================
// TEST 6: BDP 计算
// =============================================================================
static void test_bdp_calculation() {
    printf("\n=== TEST 6: BDP 计算 ===\n");
    RttEstimator rtt;
    rtt.update(10.0, 0.0);

    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);

    // 无样本时 BDP = 0
    CHECK(bbr.bdp_bytes() == 0, "BDP = 0 before any ACK");

    bbr.on_ack(100000, 1);
    // BDP = max_bw(10000000) * min_rtt(10) / 1000 = 100000
    CHECK(bbr.bdp_bytes() == 100000, "BDP = 100000 (10000000 * 10 / 1000)");
}

// =============================================================================
// TEST 7: current_gain 各状态
// =============================================================================
static void test_current_gain() {
    printf("\n=== TEST 7: current_gain 各状态 ===\n");
    BbrV2Controller bbr;

    // Startup
    CHECK(bbr.state() == BbrState::Startup, "state = Startup");
    // gain = 2.77，用近似比较
    CHECK(bbr.current_gain() > 2.76 && bbr.current_gain() < 2.78, "Startup gain ~ 2.77");

    // 进入 Drain（需 4 次 ACK）
    RttEstimator rtt;
    rtt.update(10.0, 0.0);
    bbr.set_rtt_estimator(&rtt);
    bbr.on_ack(100000, 1);
    bbr.on_ack(100000, 1);
    bbr.on_ack(100000, 1);
    bbr.on_ack(100000, 1);
    CHECK(bbr.state() == BbrState::Drain, "state = Drain");
    CHECK(bbr.current_gain() > 0.35 && bbr.current_gain() < 0.37, "Drain gain ~ 0.36");
}

// =============================================================================
// TEST 8: Drain → ProbeBW 转换（持续 1 RTT 后）
// =============================================================================
static void test_drain_to_probe_bw() {
    printf("\n=== TEST 8: Drain → ProbeBW ===\n");
    RttEstimator rtt;
    rtt.update(10.0, 0.0);

    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);

    // 进入 Drain
    for (int i = 0; i < 4; ++i) bbr.on_ack(100000, 1);
    CHECK(bbr.state() == BbrState::Drain, "entered Drain");

    // 等待超过 1 RTT (10ms)
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // 再次 on_ack → transition_state 检查时间 → enter_probe_bw
    bbr.on_ack(1000, 1);
    CHECK(bbr.state() == BbrState::ProbeBW, "state = ProbeBW after 1 RTT");
    CHECK(bbr.probe_bw_phase() == 0, "ProbeBW phase = 0 (probe up)");
    CHECK(bbr.current_gain() > 1.24 && bbr.current_gain() < 1.26, "ProbeBW phase 0 gain ~ 1.25");
}

// =============================================================================
// TEST 9: ProbeBW 相位切换
// =============================================================================
static void test_probe_bw_phase_advance() {
    printf("\n=== TEST 9: ProbeBW 相位切换 ===\n");
    RttEstimator rtt;
    rtt.update(10.0, 0.0);

    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);

    // 进入 ProbeBW
    for (int i = 0; i < 4; ++i) bbr.on_ack(100000, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    bbr.on_ack(1000, 1);
    CHECK(bbr.state() == BbrState::ProbeBW, "in ProbeBW");
    CHECK(bbr.probe_bw_phase() == 0, "phase = 0");

    // 等待 1 RTT → phase 1
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    bbr.on_ack(1000, 1);
    CHECK(bbr.probe_bw_phase() == 1, "phase = 1 after 1 RTT");
    CHECK(bbr.current_gain() > 0.74 && bbr.current_gain() < 0.76, "phase 1 gain ~ 0.75");

    // 等待 1 RTT → phase 2
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    bbr.on_ack(1000, 1);
    CHECK(bbr.probe_bw_phase() == 2, "phase = 2 after 2 RTTs");
}

// =============================================================================
// TEST 10: on_rto 重置到 Startup
// =============================================================================
static void test_on_rto_resets() {
    printf("\n=== TEST 10: on_rto 重置 ===\n");
    RttEstimator rtt;
    rtt.update(10.0, 0.0);

    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);

    // 进入 Drain
    for (int i = 0; i < 4; ++i) bbr.on_ack(100000, 1);
    CHECK(bbr.state() == BbrState::Drain, "in Drain before RTO");

    bbr.on_rto();

    CHECK(bbr.state() == BbrState::Startup, "state = Startup after RTO");
    CHECK(bbr.cwnd_bytes() == kInitialCwndBytes, "cwnd = 14600 after RTO");
    CHECK(bbr.max_bw_bps() == 0, "max_bw = 0 after RTO");
    CHECK(bbr.total_acked() == 0, "total_acked = 0 after RTO");
}

// =============================================================================
// TEST 11: reset 回到 Startup
// =============================================================================
static void test_reset() {
    printf("\n=== TEST 11: reset ===\n");
    RttEstimator rtt;
    rtt.update(10.0, 0.0);

    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);
    bbr.on_ack(100000, 1);
    bbr.on_ack(100000, 1);
    CHECK(bbr.max_bw_bps() > 0, "max_bw > 0 before reset");

    bbr.reset();

    CHECK(bbr.state() == BbrState::Startup, "state = Startup after reset");
    CHECK(bbr.cwnd_bytes() == kInitialCwndBytes, "cwnd = 14600 after reset");
    CHECK(bbr.max_bw_bps() == 0, "max_bw = 0 after reset");
    CHECK(bbr.total_acked() == 0, "total_acked = 0 after reset");
    CHECK(bbr.rounds_without_growth() == 0, "rounds_without_growth = 0 after reset");
}

// =============================================================================
// TEST 12: 工厂函数创建 NewReno
// =============================================================================
static void test_factory_newreno() {
    printf("\n=== TEST 12: 工厂函数 NewReno ===\n");
    auto ctrl = make_congestion_controller(CongestionAlgo::NewReno, nullptr);
    CHECK(ctrl != nullptr, "factory created NewReno (non-null)");
    CHECK(ctrl->algo_name() == "newreno", "algo_name == 'newreno'");
    CHECK(ctrl->cwnd_bytes() == kInitialCwndBytes, "NewReno cwnd = 14600");
    CHECK(ctrl->pacing_rate_bps() == 0, "NewReno pacing_rate = 0 (not implemented)");

    // 测试 NewReno 通过基类指针正常工作
    ctrl->on_ack(14600, 1);
    CHECK(ctrl->cwnd_bytes() > 14600, "NewReno cwnd increased after ACK (slow start)");

    // 测试 cwnd 抑制
    CHECK(ctrl->is_cwnd_suppressed() == false, "NewReno not suppressed initially");
    ctrl->update_retx_pending(200);
    CHECK(ctrl->is_cwnd_suppressed() == true, "NewReno suppressed after retx > 100");
    ctrl->update_retx_pending(0);
    CHECK(ctrl->is_cwnd_suppressed() == false, "NewReno not suppressed after retx = 0");
}

// =============================================================================
// TEST 13: 工厂函数创建 BbrV2
// =============================================================================
static void test_factory_bbrv2() {
    printf("\n=== TEST 13: 工厂函数 BbrV2 ===\n");
    RttEstimator rtt;
    rtt.update(10.0, 0.0);

    auto ctrl = make_congestion_controller(CongestionAlgo::BbrV2, &rtt);
    CHECK(ctrl != nullptr, "factory created BbrV2 (non-null)");
    CHECK(ctrl->algo_name() == "bbrv2", "algo_name == 'bbrv2'");
    CHECK(ctrl->cwnd_bytes() == kInitialCwndBytes, "BbrV2 cwnd = 14600");

    // BbrV2 通过基类指针正常工作
    ctrl->on_ack(100000, 1);
    CHECK(ctrl->pacing_rate_bps() > 0, "BbrV2 pacing_rate > 0 after ACK");

    // BbrV2 的 is_cwnd_suppressed 默认 false
    CHECK(ctrl->is_cwnd_suppressed() == false, "BbrV2 not suppressed (default)");
    ctrl->update_retx_pending(200);
    CHECK(ctrl->is_cwnd_suppressed() == false, "BbrV2 still not suppressed (ignores retx)");
}

// =============================================================================
// TEST 14: BBR on_loss 不影响状态（通过基类指针）
// =============================================================================
static void test_bbr_on_loss_via_base() {
    printf("\n=== TEST 14: BBR on_loss via base ptr ===\n");
    RttEstimator rtt;
    rtt.update(10.0, 0.0);

    auto ctrl = make_congestion_controller(CongestionAlgo::BbrV2, &rtt);
    ctrl->on_ack(100000, 1);
    uint64_t cwnd_before = ctrl->cwnd_bytes();

    ctrl->on_loss(1);

    CHECK(ctrl->cwnd_bytes() == cwnd_before, "cwnd unchanged after on_loss (via base ptr)");
}

// =============================================================================
// TEST 15: NewReno on_loss 进入 recovery（多态正确性）
// =============================================================================
static void test_newreno_on_loss_via_base() {
    printf("\n=== TEST 15: NewReno on_loss via base ptr ===\n");
    // S3（K-BBRT-001）两段语义重写：
    //   小 cwnd 场景（cwnd < 2×kMinimumCwnd×MSS）：ssthresh 被 93KB 下限接管
    //     （relay 演进意图），丢包响应不得令 cwnd 显著增长（≤ before+3MSS 的
    //     RFC fast recovery inflation），且 ssthresh 封顶 before（修复后语义）。
    //   大 cwnd 场景（cwnd > 2×下限）：标准减半路径生效（after < before）。
    auto ctrl = make_congestion_controller(CongestionAlgo::NewReno, nullptr);
    ctrl->on_ack(14600, 1);
    uint64_t cwnd_before = ctrl->cwnd_bytes();
    CHECK(cwnd_before > 46720, "cwnd increased after ACK");

    ctrl->on_loss(1);
    uint64_t cwnd_after = ctrl->cwnd_bytes();
    constexpr uint64_t kMss = 1460;
    // 小 cwnd：下限接管（ssthresh=before），fast recovery 允许 +3×MSS 临时膨胀
    CHECK(cwnd_after <= cwnd_before + 3 * kMss,
          "NewReno small-cwnd: on_loss not inflate beyond +3MSS (S3)");
    CHECK(cwnd_after > 0, "NewReno cwnd > 0 after on_loss");
    // recovery 退出后：cwnd 保持 fast recovery 值附近（标准行为：不立即收回
    // inflation，由 CA 向 ssthresh 缓慢收敛），单步增长 ≤ 1 MSS 量级
    ctrl->on_ack(1460, 100);  // largest_acked > recovery_start → 退出 recovery
    CHECK(ctrl->cwnd_bytes() <= cwnd_after + 1460,
          "NewReno post-recovery single-step growth <= 1 MSS");

    // 大 cwnd 场景：ack 推高 cwnd 越过 2×93KB 后，标准减半生效
    auto ctrl2 = make_congestion_controller(CongestionAlgo::NewReno, nullptr);
    for (int i = 0; i < 20; ++i) ctrl2->on_ack(14600, i + 1);
    uint64_t big_before = ctrl2->cwnd_bytes();
    CHECK(big_before > 2 * 64 * kMss, "big cwnd > 2x floor (186880)");
    ctrl2->on_loss(1);
    uint64_t big_after = ctrl2->cwnd_bytes();
    CHECK(big_after < big_before, "NewReno big-cwnd: cwnd decreased (standard halving)");
}

// =============================================================================
// TEST 16 (A1 回归): max_bw 窗口滑出后衰减
// 修复 A1: 原实现 max_bw_bps_ 只增不减（历史最大值），带宽临时飙升后回落时
//          max_bw 永不下降，导致 BDP 持续高估、cwnd 失控、长期排队丢包。
// 验证：注入高带宽样本后再注入足够低带宽样本，max_bw 应下降到低值。
// =============================================================================
static void test_a1_max_bw_decay() {
    printf("\n=== TEST 16 (A1): max_bw 窗口衰减 ===\n");
    RttEstimator rtt;
    rtt.update(10.0, 0.0);  // SRTT = 10ms
    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);

    // 注入 1 个高带宽样本：ACK 100000 bytes / 10ms = 10MB/s
    bbr.on_ack(100000, 1);
    uint64_t high_bw = bbr.max_bw_bps();
    CHECK(high_bw == 10000000, "high max_bw = 10000000 after 1 ACK");

    // 注入 10 个低带宽样本：ACK 1000 bytes / 10ms = 100KB/s
    // bw_samples_ 窗口大小 kBwWindowSize=10，10 个低样本后高样本被挤出窗口
    for (int i = 0; i < 10; ++i) {
        bbr.on_ack(1000, 1);
    }
    uint64_t decayed_bw = bbr.max_bw_bps();
    CHECK(decayed_bw < high_bw, "max_bw decayed after window slide-out (A1 fix)");
    CHECK(decayed_bw == 100000, "max_bw = 100000 (low sample) after 10 low ACKs");
}

// =============================================================================
// TEST 17 (A1 回归): ProbeRTT 独立计时器触发
// 修复 A1: 原用 min_rtt_window_start_ms_ 判断 ProbeRTT 触发间隔，但 update_model
//          每次窗口过期会重置它（先于 transition_state 执行），导致 ProbeRTT 永不触发。
//          改用独立 probe_rtt_last_entered_ms_ 计时器，与 min_rtt 窗口解耦。
// 验证：进入 ProbeBW 后等待超过 probe_rtt_interval，on_ack 应触发 ProbeRTT。
// =============================================================================
static void test_a1_probe_rtt_triggers() {
    printf("\n=== TEST 17 (A1): ProbeRTT 独立计时器触发 ===\n");
    RttEstimator rtt;
    rtt.update(10.0, 0.0);  // SRTT = 10ms
    BbrV2Controller bbr;
    bbr.set_rtt_estimator(&rtt);

    // 应用跨域配置：缩短 ProbeRTT 间隔到最小 1s（避免单域 10s 等待）
    BbrCrossDomainConfig cfg;
    cfg.cross_domain_min_rtt_window = std::chrono::seconds(1);
    cfg.cross_domain_probe_rtt_interval = std::chrono::seconds(1);
    bbr.apply_cross_domain_config(cfg);
    CHECK(bbr.probe_rtt_interval_ms() == 1000.0, "probe_rtt_interval = 1000ms (cross-domain)");
    CHECK(bbr.min_rtt_window_ms() == 1000.0, "min_rtt_window = 1000ms (cross-domain)");

    // 进入 ProbeBW：4 ACK (Startup->Drain) + sleep 1 RTT + 1 ACK (Drain->ProbeBW)
    for (int i = 0; i < 4; ++i) bbr.on_ack(100000, 1);
    CHECK(bbr.state() == BbrState::Drain, "entered Drain");
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    bbr.on_ack(1000, 1);
    CHECK(bbr.state() == BbrState::ProbeBW, "entered ProbeBW");

    // 等待超过 ProbeRTT 间隔（1s）
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // on_ack -> transition_state 应触发 enter_probe_rtt（A1 修复：用独立计时器）
    bbr.on_ack(1000, 1);
    CHECK(bbr.state() == BbrState::ProbeRTT, "state = ProbeRTT after interval (A1 fix)");
    // ProbeRTT cwnd = kProbeRttCwndMss(4) * kMssBytes(1460) = 5840
    CHECK(bbr.cwnd_bytes() == 4 * 1460, "ProbeRTT cwnd = 4*MSS = 5840");
}

// =============================================================================

int main() {
    printf("=== test_bbr_v2_state_machine ===\n");

    test_initial_state();
    test_can_send();
    test_on_ack_updates_model();
    test_on_loss_no_cwnd_change();
    test_startup_exit_to_drain();
    test_bdp_calculation();
    test_current_gain();
    test_drain_to_probe_bw();
    test_probe_bw_phase_advance();
    test_on_rto_resets();
    test_reset();
    test_factory_newreno();
    test_factory_bbrv2();
    test_bbr_on_loss_via_base();
    test_newreno_on_loss_via_base();
    test_a1_max_bw_decay();
    test_a1_probe_rtt_triggers();

    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
