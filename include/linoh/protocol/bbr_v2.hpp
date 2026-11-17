// linoh/protocol/bbr_v2.hpp — BBR v2 拥塞控制算法
//
// v2.0 Phase 1: 基于 Google BBR v2 draft 的简化实现，适配 linoh QUIC 数据面。
//
// 设计目标：
//   1. 跨城长肥管高吞吐 — 基于带宽估计而非丢包退避，避免 NewReno 在
//      高 BDP 链路下利用率 <30% 的问题
//   2. 消费级宽带抖动鲁棒 — ProbeBW 周期性探测带宽变化，自适应增益
//   3. 不破坏 NewReno 兼容 — 通过 CongestionController 接口切换，默认 NewReno
//
// 四状态机：
//   Startup  (gain=2.77) → 快速探测可用带宽，cwnd 翻倍增长
//   Drain    (gain=0.36) → 排空 Startup 积压的 inflight 队列
//   ProbeBW  (8 相位循环) → 周期性探测带宽变化，gain 在 1.25/0.75 间切换
//   ProbeRTT (cwnd=4*MSS) → 定期刷新 min_rtt，持续 200ms
//
// 状态转换：
//   Startup → Drain      : 连续 3 轮 RTT 内 max_bw 增长 < 25%
//   Drain → ProbeBW      : inflight 降到 BDP 以下
//   ProbeBW → ProbeRTT   : 10s 未探测 min_rtt
//   ProbeRTT → ProbeBW   : 持续 200ms 后恢复
//
// 简化说明（v2.0 第一版）：
//   - 带宽估计用 newly_acked_bytes / srtt 估算 delivery_rate（非精确 packet-level 采样）
//   - min_rtt 用 RttEstimator.srtt 的 10s 滑动最小值近似
//   - pacing 已于 v3.9.0 落地：PacingLimiter 令牌桶在 can_send() 中
//     try_consume 限速（桶容量 2×BDP 允许突发；pacing_rate=0 时放行）
//     ——本行旧注释"仅诊断/日志"已于 2026-08-24 修正（避免再误判为债务）
//   - 后续 v2.5 可增强为精确 delivery rate 采样
//
// 线程安全：依赖 Connection 外层锁串行化 on_ack/on_loss 调用，
//           内部不加锁（与 NewRenoController 一致）。

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string_view>

#include "linoh/protocol/congestion_controller.hpp"
#include "linoh/protocol/pacing_limiter.hpp"  // v3.9.0: pacing 令牌桶限速器

namespace linoh::protocol {

// 前向声明（congestion_controller.hpp 已声明，此处重复声明无害）
class RttEstimator;

/// BBR v2 状态机状态。
enum class BbrState : uint8_t {
    Startup  = 0,  // 初始探测，gain=2.77，cwnd 翻倍增长
    Drain    = 1,  // 排空积压，gain=0.36
    ProbeBW  = 2,  // 带宽探测，8 相位循环
    ProbeRTT = 3,  // RTT 探测，cwnd 降到 4*MSS
};

/// BBR v2 拥塞控制器。
class BbrV2Controller : public CongestionController {
public:
    BbrV2Controller();

    // ===== 核心 API =====

    void on_ack(uint64_t newly_acked_bytes,
                uint64_t largest_acked_pn = UINT64_MAX) override;
    void on_loss(uint64_t current_largest_acked = 0) override;
    void on_rto() override;
    bool can_send(uint64_t bytes) const override;
    uint64_t cwnd_bytes() const override;
    void reset() override;
    std::string_view algo_name() const override { return "bbrv2"; }

    // ===== 可选 API =====

    uint64_t pacing_rate_bps() const override;
    void set_rtt_estimator(const RttEstimator* rtt) override { rtt_ = rtt; }

    // ===== V3-B: 跨域参数自适应 =====

    /// 应用跨域 BBR 参数（override）。
    /// 将 min_rtt_window / probe_rtt_interval / cwnd_gain 乘子等写入实例成员，
    /// 后续 update_model / transition_state / recalculate 使用实例成员而非 static 常量。
    /// @return 始终 true（BbrV2 支持跨域自适应）
    bool apply_cross_domain_config(const BbrCrossDomainConfig &cfg) override;

    /// 查询是否已应用跨域参数。
    bool is_cross_domain_configured() const noexcept override { return cross_domain_configured_; }

    // ===== 测试访问器 =====

    BbrState state() const { return state_; }
    uint64_t max_bw_bps() const { return max_bw_bps_; }
    double min_rtt_ms() const { return min_rtt_ms_; }
    int probe_bw_phase() const { return probe_bw_phase_; }
    uint64_t total_acked() const { return total_acked_; }
    int rounds_without_growth() const { return rounds_without_growth_; }

    /// v3.9.0: pacing 限速器访问器（测试/诊断用）
    PacingLimiter& pacing_limiter() { return pacing_limiter_; }
    const PacingLimiter& pacing_limiter() const { return pacing_limiter_; }

    /// V3-B: 当前 min_rtt 窗口长度（毫秒）。单域=10s，跨域=30s。
    double min_rtt_window_ms() const noexcept { return min_rtt_window_ms_; }

    /// V3-B: 当前 ProbeRTT 触发间隔（毫秒）。单域=10s，跨域=60s。
    double probe_rtt_interval_ms() const noexcept { return probe_rtt_interval_ms_; }

    /// V3-B: 当前 cwnd 增益乘子（单域=1.0，跨域=cfg.cross_domain_cwnd_gain/2.0）。
    double cwnd_gain_multiplier() const noexcept { return cwnd_gain_multiplier_; }

    /// BDP（Bandwidth-Delay Product）字节数 = max_bw * min_rtt。
    uint64_t bdp_bytes() const;

    /// 当前状态的 cwnd 增益。
    double current_gain() const;

private:
    /// 更新带宽和 RTT 模型。
    void update_model(uint64_t newly_acked_bytes, double rtt_ms, double now_ms);

    /// 状态转换检查与执行。
    void transition_state(double now_ms, uint64_t in_flight_bytes);

    /// 进入各状态的初始化。
    void enter_startup();
    void enter_drain(double now_ms);
    void enter_probe_bw(double now_ms);
    void enter_probe_rtt(double now_ms);

    /// 重新计算 cwnd 和 pacing_rate。
    void recalculate();

    /// 获取当前单调时钟（毫秒）。
    static double now_ms();

    // ===== 状态机 =====
    BbrState state_;

    // ===== 带宽模型 =====
    uint64_t max_bw_bps_;               // 滑动窗口内最大交付速率 (bytes/sec)
    std::deque<uint64_t> bw_samples_;   // 带宽样本窗口（每个 RTT 一个样本）
    uint64_t round_start_acked_;        // 当前轮起始时的累计已确认字节
    uint64_t total_acked_;              // 累计已确认字节
    int rounds_without_growth_;         // Startup 阶段连续未增长轮数

    // ===== RTT 模型 =====
    double min_rtt_ms_;                 // 10s 窗口内最小 RTT
    double min_rtt_window_start_ms_;    // min_rtt 窗口起始时间
    double probe_rtt_start_ms_;         // ProbeRTT 阶段起始时间
    double probe_rtt_last_entered_ms_{0.0}; // 上次进入 ProbeRTT 时间（独立计时，与 min_rtt 窗口解耦，修复 A1）
    bool probe_rtt_done_;               // ProbeRTT 是否已收到至少一个 ACK

    // ===== ProbeBW 相位 =====
    int probe_bw_phase_;                // 0-7（相位 0 = probe up，1-7 = drain down）
    double probe_bw_phase_start_ms_;    // 当前相位起始时间
    double state_enter_ms_;             // 进入当前状态的时间（Drain/通用计时）

    // ===== cwnd / pacing =====
    uint64_t cwnd_bytes_;
    uint64_t pacing_rate_bps_;
    /// v3.9.0: pacing 令牌桶限速器（mutable，因 can_send 是 const 但需修改令牌桶状态）
    mutable PacingLimiter pacing_limiter_;

    // ===== RTT 估算器引用 =====
    const RttEstimator* rtt_;

    // ===== V3-B: 跨域参数实例成员（默认 = 单域 static 常量值，向后兼容）=====
    /// min_rtt 滑动窗口长度（毫秒）。单域 kMinRttWindowMs=10000，跨域 30000。
    /// 用于 update_model 重置 min_rtt 窗口（line 137 等价点）。
    double min_rtt_window_ms_{kMinRttWindowMs};
    /// ProbeRTT 触发间隔（毫秒）。单域 kMinRttWindowMs=10000，跨域 60000。
    /// 用于 transition_state 判断是否进入 ProbeRTT（line 209 等价点）。
    /// 拆分自 kMinRttWindowMs：跨域时 min_rtt 窗口与 ProbeRTT 间隔解耦。
    double probe_rtt_interval_ms_{kMinRttWindowMs};
    /// cwnd 增益乘子（单域 1.0，跨域 cfg.cross_domain_cwnd_gain/2.0）。
    /// recalculate 时 cwnd = original_cwnd * cwnd_gain_multiplier_。
    double cwnd_gain_multiplier_{1.0};
    /// 是否已应用跨域参数（诊断用）
    bool cross_domain_configured_{false};

    // ===== BBR v2 常量 =====
    // Startup 增益 = 2/ln(2) ≈ 2.77，确保每轮 RTT 翻倍探测
    static constexpr double kStartupGain = 2.77;
    // Drain 增益 = 1/StartupGain ≈ 0.36，快速排空积压
    static constexpr double kDrainGain = 0.36;
    // ProbeBW 探测增益（probe up 相位）
    static constexpr double kProbeBwUpGain = 1.25;
    // ProbeBW 排空增益（drain down 相位）
    static constexpr double kProbeBwDownGain = 0.75;
    // ProbeRTT 持续时间（毫秒）
    static constexpr double kProbeRttDurationMs = 200.0;
    // min_rtt 窗口长度（毫秒，10 秒）
    static constexpr double kMinRttWindowMs = 10000.0;
    // 带宽样本窗口大小（轮数）
    static constexpr size_t kBwWindowSize = 10;
    // Startup 退出阈值：连续 3 轮增长 < 25%
    static constexpr int kStartupExitRounds = 3;
    static constexpr double kStartupGrowthTarget = 1.25;  // 25%
    // ProbeRTT 期间 cwnd = 4 * MSS
    static constexpr uint64_t kProbeRttCwndMss = 4;
    // ProbeBW 相位数（8 相位循环）
    static constexpr int kProbeBwPhases = 8;
};

} // namespace linoh::protocol
