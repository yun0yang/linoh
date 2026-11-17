// linoh/protocol/bbr_v2.cpp — BBR v2 拥塞控制算法实现
//
// v2.0 Phase 1: 基于 Google BBR v2 draft 的简化实现。
// 详见 bbr_v2.hpp 头文件注释。

#include "linoh/protocol/bbr_v2.hpp"
#include "linoh/protocol/loss_recovery.hpp"  // RttEstimator, kMssBytes, kInitialCwndBytes, kMinimumCwnd
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <chrono>

namespace linoh::protocol {

// ============================================================================
// BbrV2Controller
// ============================================================================

BbrV2Controller::BbrV2Controller()
    : state_{BbrState::Startup}
    , max_bw_bps_{0}
    , round_start_acked_{0}
    , total_acked_{0}
    , rounds_without_growth_{0}
    , min_rtt_ms_{0.0}
    , min_rtt_window_start_ms_{0.0}
    , probe_rtt_start_ms_{0.0}
    , probe_rtt_done_{false}
    , probe_bw_phase_{0}
    , probe_bw_phase_start_ms_{0.0}
    , state_enter_ms_{0.0}
    , cwnd_bytes_{kInitialCwndBytes}   // 初始 cwnd = 10 * MSS = 14600（与 NewReno 一致）
    , pacing_rate_bps_{0}
    , rtt_{nullptr} {
    double now = now_ms();
    min_rtt_window_start_ms_ = now;
    state_enter_ms_ = now;
    probe_rtt_last_entered_ms_ = now;  // 修复 A1: 初始化为当前时间，避免首次 on_ack 立即触发 ProbeRTT
    LINOH_INFO("BBR: initialized, state=Startup, cwnd=", cwnd_bytes_);
}

double BbrV2Controller::now_ms() {
    auto tp = std::chrono::steady_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        tp.time_since_epoch()).count();
    return static_cast<double>(us) / 1000.0;
}

// ----------------------------------------------------------------------------

void BbrV2Controller::on_ack(uint64_t newly_acked_bytes, uint64_t largest_acked_pn) {
    (void)largest_acked_pn;  // BBR 不依赖 PN

    total_acked_ += newly_acked_bytes;

    double now = now_ms();
    // 从 RTT 估算器获取 SRTT（未注入时用默认 100ms）
    double rtt = (rtt_ != nullptr) ? rtt_->srtt_ms() : kInitialRttMs;

    // ProbeRTT 期间收到 ACK → 标记完成
    if (state_ == BbrState::ProbeRTT) {
        probe_rtt_done_ = true;
    }

    update_model(newly_acked_bytes, rtt, now);
    transition_state(now, 0);  // 简化版不传 in_flight_bytes
    recalculate();

    LINOH_DEBUG("BBR::on_ack: newly_acked=", newly_acked_bytes,
                " total_acked=", total_acked_,
                " rtt=", rtt,
                " max_bw=", max_bw_bps_,
                " min_rtt=", min_rtt_ms_,
                " BDP=", bdp_bytes(),
                " cwnd=", cwnd_bytes_,
                " state=", static_cast<int>(state_),
                " phase=", probe_bw_phase_);
}

void BbrV2Controller::on_loss(uint64_t current_largest_acked) {
    (void)current_largest_acked;
    // BBR v2 核心设计：不基于丢包退避 cwnd（与 NewReno 的根本区别）
    // 丢包仅用于诊断日志，不影响状态机
    LINOH_DEBUG("BBR::on_loss: ignored (loss-based backoff disabled), state=",
                static_cast<int>(state_), " cwnd=", cwnd_bytes_);
}

void BbrV2Controller::on_rto() {
    // RTO 超时：链路可能严重劣化，重置到 Startup 重新探测
    LINOH_INFO("BBR::on_rto: resetting to Startup (link degradation suspected)");
    reset();
}

bool BbrV2Controller::can_send(uint64_t bytes) const {
    // v3.9.0: cwnd 检查 + pacing 令牌桶限速双重检查
    // 1) cwnd 检查（原有逻辑）：待发送字节不得超过拥塞窗口
    if (bytes > cwnd_bytes_) return false;
    // 2) pacing 限速（v3.9.0 新增）：令牌桶控制发送速率不超过 pacing_rate_bps
    //    防 burst 丢包（跨域长肥管道收益显著），桶容量=2×BDP 允许突发
    if (pacing_limiter_.enabled()) {
        return pacing_limiter_.try_consume(bytes, now_ms());
    }
    return true;
}

uint64_t BbrV2Controller::cwnd_bytes() const {
    return cwnd_bytes_;
}

void BbrV2Controller::reset() {
    double now = now_ms();
    state_ = BbrState::Startup;
    max_bw_bps_ = 0;
    bw_samples_.clear();
    round_start_acked_ = 0;
    total_acked_ = 0;
    rounds_without_growth_ = 0;
    min_rtt_ms_ = 0.0;
    min_rtt_window_start_ms_ = now;
    probe_rtt_start_ms_ = 0.0;
    probe_rtt_done_ = false;
    probe_bw_phase_ = 0;
    probe_bw_phase_start_ms_ = now;
    state_enter_ms_ = now;
    cwnd_bytes_ = kInitialCwndBytes;
    pacing_rate_bps_ = 0;
    pacing_limiter_.reset();  // v3.9.0: 清理令牌桶状态

    LINOH_INFO("BBR::reset: state=Startup, cwnd=", cwnd_bytes_);
}

uint64_t BbrV2Controller::pacing_rate_bps() const {
    return pacing_rate_bps_;
}

// ============================================================================
// V3-B: 跨域参数自适应
// ============================================================================

bool BbrV2Controller::apply_cross_domain_config(const BbrCrossDomainConfig &cfg) {
    // 跨域 min_rtt 窗口（默认 30s，比单域 10s 长，适应跨域 RTT 抖动）
    min_rtt_window_ms_ = static_cast<double>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            cfg.cross_domain_min_rtt_window).count());
    if (min_rtt_window_ms_ < 1000.0) {
        // 安全下限：跨域窗口不得低于 1s（避免无意义频繁重置）
        min_rtt_window_ms_ = 1000.0;
    }

    // 跨域 ProbeRTT 间隔（默认 60s，比单域 10s 长，减少跨域带宽浪费）
    probe_rtt_interval_ms_ = static_cast<double>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            cfg.cross_domain_probe_rtt_interval).count());
    if (probe_rtt_interval_ms_ < min_rtt_window_ms_) {
        // ProbeRTT 间隔不得小于 min_rtt 窗口（否则频繁进入 ProbeRTT 降速）
        probe_rtt_interval_ms_ = min_rtt_window_ms_;
    }

    // 跨域 cwnd 增益乘子：cfg.cross_domain_cwnd_gain / 2.0
    // 语义：单域 BBR ProbeBW cwnd_gain 基准为 2.0；跨域 cfg 默认 3.0 → 乘子=1.5
    // recalculate 时 cwnd = bdp * gain * cwnd_gain_multiplier_
    if (cfg.cross_domain_cwnd_gain > 0.0) {
        cwnd_gain_multiplier_ = cfg.cross_domain_cwnd_gain / 2.0;
        // 乘子合理范围 [0.5, 3.0]：低于 0.5 等于关闭 BDP 利用，高于 3.0 过度放大易丢包
        if (cwnd_gain_multiplier_ < 0.5) cwnd_gain_multiplier_ = 0.5;
        if (cwnd_gain_multiplier_ > 3.0) cwnd_gain_multiplier_ = 3.0;
    }

    cross_domain_configured_ = true;

    LINOH_INFO("BBR: applied cross-domain config, "
               "min_rtt_window_ms=", min_rtt_window_ms_,
               " probe_rtt_interval_ms=", probe_rtt_interval_ms_,
               " cwnd_gain_multiplier=", cwnd_gain_multiplier_,
               " pacing_enabled=", cfg.cross_domain_enable_pacing,
               " startup_gain=", cfg.cross_domain_startup_gain);

    return true;
}

// ============================================================================
// 模型更新
// ============================================================================

void BbrV2Controller::update_model(uint64_t newly_acked_bytes,
                                    double rtt_ms, double now_ms) {
    // --- 1. 更新 min_rtt（10s 滑动窗口） ---
    if (min_rtt_ms_ <= 0.0 || rtt_ms < min_rtt_ms_) {
        min_rtt_ms_ = rtt_ms;
    }
    // min_rtt 窗口过期 → 重置（触发 ProbeRTT 重新探测）
    // V3-B: 使用实例成员 min_rtt_window_ms_（单域 10s，跨域 30s）
    if (now_ms - min_rtt_window_start_ms_ > min_rtt_window_ms_) {
        min_rtt_ms_ = rtt_ms;
        min_rtt_window_start_ms_ = now_ms;
    }

    // --- 2. 计算交付速率 (bytes/sec) ---
    if (rtt_ms < 1.0) rtt_ms = 1.0;  // 防除零，最小 1ms
    uint64_t delivery_rate = static_cast<uint64_t>(
        static_cast<double>(newly_acked_bytes) / (rtt_ms / 1000.0));

    // --- 3. 更新带宽样本窗口（10 轮滑动窗口） ---
    bw_samples_.push_back(delivery_rate);
    if (bw_samples_.size() > kBwWindowSize) {
        bw_samples_.pop_front();
    }

    // --- 4. Startup 退出检查 ---
    // 连续 kStartupExitRounds 次 ACK 的 delivery_rate 未超过 max_bw * 1.25
    // 说明带宽已收敛，退出 Startup 进入 Drain
    if (state_ == BbrState::Startup && max_bw_bps_ > 0) {
        if (delivery_rate >= static_cast<uint64_t>(
                static_cast<double>(max_bw_bps_) * kStartupGrowthTarget)) {
            rounds_without_growth_ = 0;  // 仍有显著增长
        } else {
            rounds_without_growth_++;
            LINOH_DEBUG("BBR: Startup rounds_without_growth=", rounds_without_growth_,
                        " delivery_rate=", delivery_rate,
                        " threshold=", static_cast<uint64_t>(max_bw_bps_ * kStartupGrowthTarget));
            if (rounds_without_growth_ >= kStartupExitRounds) {
                enter_drain(now_ms);
            }
        }
    }

    // --- 5. 更新 max_bw（取窗口内最大值，窗口滑出即衰减） ---
    // 修复 A1: 原实现只增不减（历史最大值），带宽临时飙升后回落时 max_bw 永不下降，
    // 导致 BDP 持续高估、cwnd 失控、长期排队丢包。改为每次重新计算窗口最大值。
    max_bw_bps_ = 0;
    for (auto bw : bw_samples_) {
        if (bw > max_bw_bps_) max_bw_bps_ = bw;
    }
}

// ============================================================================
// 状态转换
// ============================================================================

void BbrV2Controller::transition_state(double now_ms, uint64_t in_flight_bytes) {
    (void)in_flight_bytes;  // 简化版不使用 inflight 判断

    double rtt = (rtt_ != nullptr) ? rtt_->srtt_ms() : kInitialRttMs;
    if (rtt < 1.0) rtt = 1.0;

    switch (state_) {
        case BbrState::Startup:
            // 退出条件在 update_model 中处理
            break;

        case BbrState::Drain:
            // 简化：持续 1 个 RTT 后转 ProbeBW
            // （精确版应检查 inflight <= BDP，但 on_ack 无 inflight 参数）
            if (now_ms - state_enter_ms_ >= rtt) {
                enter_probe_bw(now_ms);
            }
            break;

        case BbrState::ProbeBW: {
            // 每 1 个 RTT 切换相位（8 相位循环）
            if (now_ms - probe_bw_phase_start_ms_ >= rtt) {
                probe_bw_phase_ = (probe_bw_phase_ + 1) % kProbeBwPhases;
                probe_bw_phase_start_ms_ = now_ms;
                LINOH_DEBUG("BBR: ProbeBW phase=", probe_bw_phase_,
                            " gain=", current_gain());
            }
            // V3-B: ProbeRTT 触发间隔（单域 10s，跨域 60s，由 probe_rtt_interval_ms_ 决定）
            // 修复 A1: 原用 min_rtt_window_start_ms_ 判断，但 update_model 每次窗口过期
            // 会重置它（先于 transition_state 执行），导致 ProbeRTT 永不触发；
            // 改用独立 probe_rtt_last_entered_ms_ 计时器，与 min_rtt 窗口解耦。
            if (now_ms - probe_rtt_last_entered_ms_ >= probe_rtt_interval_ms_) {
                enter_probe_rtt(now_ms);
            }
            break;
        }

        case BbrState::ProbeRTT:
            // 持续 200ms + 收到至少一个 ACK → 恢复 ProbeBW
            if (now_ms - probe_rtt_start_ms_ >= kProbeRttDurationMs && probe_rtt_done_) {
                // 刷新 min_rtt 窗口
                min_rtt_window_start_ms_ = now_ms;
                enter_probe_bw(now_ms);
            }
            break;
    }
}

// ============================================================================
// 状态进入
// ============================================================================

void BbrV2Controller::enter_startup() {
    state_ = BbrState::Startup;
    state_enter_ms_ = now_ms();
    rounds_without_growth_ = 0;
    LINOH_INFO("BBR: -> Startup");
}

void BbrV2Controller::enter_drain(double now_ms) {
    state_ = BbrState::Drain;
    state_enter_ms_ = now_ms;
    LINOH_INFO("BBR: Startup -> Drain, max_bw_bps=", max_bw_bps_,
               " min_rtt_ms=", min_rtt_ms_,
               " BDP_bytes=", bdp_bytes());
}

void BbrV2Controller::enter_probe_bw(double now_ms) {
    state_ = BbrState::ProbeBW;
    probe_bw_phase_ = 0;  // 从 probe up 相位开始
    probe_bw_phase_start_ms_ = now_ms;
    state_enter_ms_ = now_ms;
    LINOH_INFO("BBR: -> ProbeBW, phase=0, max_bw_bps=", max_bw_bps_);
}

void BbrV2Controller::enter_probe_rtt(double now_ms) {
    state_ = BbrState::ProbeRTT;
    probe_rtt_start_ms_ = now_ms;
    probe_rtt_last_entered_ms_ = now_ms;  // 修复 A1: 记录本次进入时间，供下次触发判断
    probe_rtt_done_ = false;
    state_enter_ms_ = now_ms;
    LINOH_INFO("BBR: ProbeBW -> ProbeRTT (min_rtt refresh), cwnd=",
               kProbeRttCwndMss * kMssBytes);
}

// ============================================================================
// cwnd / pacing 计算
// ============================================================================

uint64_t BbrV2Controller::bdp_bytes() const {
    if (max_bw_bps_ == 0 || min_rtt_ms_ <= 0.0) return 0;
    // BDP = bandwidth (bytes/sec) * rtt (sec)
    //     = max_bw_bps_ * min_rtt_ms_ / 1000
    return static_cast<uint64_t>(
        static_cast<double>(max_bw_bps_) * min_rtt_ms_ / 1000.0);
}

double BbrV2Controller::current_gain() const {
    switch (state_) {
        case BbrState::Startup:  return kStartupGain;      // 2.77
        case BbrState::Drain:    return kDrainGain;         // 0.36
        case BbrState::ProbeBW:
            // 相位 0 = probe up (gain=1.25)，相位 1-7 = drain down (gain=0.75)
            return (probe_bw_phase_ == 0) ? kProbeBwUpGain : kProbeBwDownGain;
        case BbrState::ProbeRTT: return 0.5;                // 临时降速
    }
    return 1.0;
}

void BbrV2Controller::recalculate() {
    uint64_t bdp = bdp_bytes();
    double gain = current_gain();

    switch (state_) {
        case BbrState::Startup:
            // cwnd = max(当前 cwnd, BDP * gain)
            // Startup 阶段 cwnd 只增不减，随 BDP 估计增长而放大
            if (bdp > 0) {
                uint64_t target = static_cast<uint64_t>(
                    static_cast<double>(bdp) * gain);
                cwnd_bytes_ = (std::max)(cwnd_bytes_, target);
            }
            // 无 BDP 估计时保持初始 cwnd
            break;

        case BbrState::Drain:
            // cwnd = BDP * drain_gain（排空积压）
            // V3-B: 跨域链路应用 cwnd_gain_multiplier_（单域=1.0 不影响，跨域=1.5 提升 BDP 利用率）
            if (bdp > 0) {
                cwnd_bytes_ = static_cast<uint64_t>(
                    static_cast<double>(bdp) * gain * cwnd_gain_multiplier_);
            }
            break;

        case BbrState::ProbeBW:
            // cwnd = BDP * gain（probe up 时放大，drain down 时缩小）
            // V3-B: 跨域链路应用 cwnd_gain_multiplier_（应对跨域高 BDP，提升吞吐）
            if (bdp > 0) {
                cwnd_bytes_ = static_cast<uint64_t>(
                    static_cast<double>(bdp) * gain * cwnd_gain_multiplier_);
            }
            break;

        case BbrState::ProbeRTT:
            // cwnd = 4 * MSS（临时降到最小，刷新 min_rtt）
            cwnd_bytes_ = kProbeRttCwndMss * kMssBytes;
            break;
    }

    // cwnd 下限保护：kMinimumCwnd(64) × MSS = 93KB（relay 大帧一轮发完的演进；
    // 注释原写"最小 2*MSS"已过时）。S3（K-BBRT-001）修复：ProbeRTT 豁免——
    // 其语义就是临时压到 4×MSS 排空 inflight 以刷新 min_rtt，统一地板会
    // 把 5840 抬回 93440 使探测失效（实测）。
    if (state_ != BbrState::ProbeRTT) {
        cwnd_bytes_ = (std::max)(cwnd_bytes_, kMinimumCwnd * kMssBytes);
    }

    // pacing rate = max_bw * gain
    if (max_bw_bps_ > 0) {
        pacing_rate_bps_ = static_cast<uint64_t>(
            static_cast<double>(max_bw_bps_) * gain);
    }

    // v3.9.0: 配置 pacing 令牌桶（将 pacing_rate_bps 落地为实际发送限速）
    // RTT 用 min_rtt（无估计时用默认 kInitialRttMs 防护，避免桶容量为 0）
    double rtt_for_pacing = (min_rtt_ms_ > 0.0) ? min_rtt_ms_ : kInitialRttMs;
    pacing_limiter_.configure(pacing_rate_bps_, rtt_for_pacing);
}

// ============================================================================
// 工厂函数
// ============================================================================

std::unique_ptr<CongestionController> make_congestion_controller(
    CongestionAlgo algo, const RttEstimator* rtt) {
    switch (algo) {
        case CongestionAlgo::BbrV2: {
            auto ctrl = std::make_unique<BbrV2Controller>();
            ctrl->set_rtt_estimator(rtt);
            return ctrl;
        }
        case CongestionAlgo::NewReno:
        default:
            return std::make_unique<NewRenoController>();
    }
}

} // namespace linoh::protocol
