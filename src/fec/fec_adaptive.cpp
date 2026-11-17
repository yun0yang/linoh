// fec_adaptive.cpp — O3 FEC 自适应控制器实现
//（cluster 优化总体方案 v1.0 / linoh 编码层方案 O3 / 灵衢 Q2 迟滞思想）

#include "linoh/fec/fec_adaptive.hpp"

namespace linoh::fec {

namespace {

// 档位表（tier → M 与分档边界）
//   tier 0: M=1，p ∈ (0, 0.5%]
//   tier 1: M=2，p ∈ (0.5%, 2%]
//   tier 2: M=4，p ∈ (2%, ∞)
constexpr int kTierM[3] = {1, 2, 4};
constexpr double kTierUpper[2] = {0.005, 0.02};  // tier0 上界 / tier1 上界

int tier_for_rate(double p) {
    if (p <= kTierUpper[0]) return 0;
    if (p <= kTierUpper[1]) return 1;
    return 2;
}

}  // namespace

FecAdaptiveController::FecAdaptiveController(const Options &opts) : opts_(opts) {
    if (opts_.window_pkts == 0) opts_.window_pkts = 500;
    if (opts_.ema_alpha <= 0.0 || opts_.ema_alpha > 1.0) opts_.ema_alpha = 0.3;
    if (opts_.up_stable_windows < 1) opts_.up_stable_windows = 1;
    if (opts_.down_stable_windows < 1) opts_.down_stable_windows = 1;
    if (opts_.k_blocks == 0) opts_.k_blocks = 16;
    if (opts_.block_size == 0) opts_.block_size = 1024;
}

bool FecAdaptiveController::update(std::uint64_t sent_total,
                                   std::uint64_t lost_total) {
    // 计数器回退（连接重置/对端重连）→ 重新基线，本样本作废
    if (!has_baseline_) {
        base_sent_ = sent_total;
        base_lost_ = lost_total;
        has_baseline_ = true;
        pend_sent_ = 0;
        pend_lost_ = 0;
        return false;
    }
    if (sent_total < base_sent_ + pend_sent_ ||
        lost_total < base_lost_ + pend_lost_) {
        // 任一累计计数回退：重置基线（视为统计重置），避免无符号下溢
        base_sent_ = sent_total;
        base_lost_ = lost_total;
        pend_sent_ = 0;
        pend_lost_ = 0;
        return false;
    }

    const std::uint64_t d_sent = sent_total - base_sent_ - pend_sent_;
    const std::uint64_t d_lost = lost_total - base_lost_ - pend_lost_;

    pend_sent_ += d_sent;
    pend_lost_ += d_lost;

    if (pend_sent_ < opts_.window_pkts) {
        return false;  // 样本不足，不评估
    }

    // 窗口丢包率（lost 可能滞后于 sent，钳到 [0,1]）
    double rate = static_cast<double>(pend_lost_) /
                  static_cast<double>(pend_sent_);
    if (rate < 0.0) rate = 0.0;
    if (rate > 1.0) rate = 1.0;

    // 差分清零（保留累计基线）
    base_sent_ += pend_sent_;
    base_lost_ += pend_lost_;
    pend_sent_ = 0;
    pend_lost_ = 0;

    evaluate_(rate);
    return true;
}

void FecAdaptiveController::evaluate_(double window_loss_rate) {
    // EMA 更新
    if (ema_ < 0.0) {
        ema_ = window_loss_rate;  // 首窗直接取值
    } else {
        ema_ = opts_.ema_alpha * window_loss_rate +
               (1.0 - opts_.ema_alpha) * ema_;
    }
    ++windows_;

    const int target = tier_for_rate(ema_);

    if (target > tier_) {
        ++up_streak_;
        down_streak_ = 0;
        if (up_streak_ >= opts_.up_stable_windows) {
            ++tier_;
            ++switches_;
            up_streak_ = 0;
        }
    } else if (target < tier_) {
        ++down_streak_;
        up_streak_ = 0;
        if (down_streak_ >= opts_.down_stable_windows) {
            --tier_;
            ++switches_;
            down_streak_ = 0;
        }
    } else {
        // 落在当前档区间：清计数（迟滞要求"连续"越界）
        up_streak_ = 0;
        down_streak_ = 0;
    }
}

FecConfig FecAdaptiveController::current_config() const {
    FecConfig cfg;
    cfg.type = opts_.type;
    cfg.data_blocks = opts_.k_blocks;
    cfg.recovery_blocks = static_cast<std::size_t>(kTierM[tier_]);
    cfg.block_size = opts_.block_size;
    return cfg;
}

int FecAdaptiveController::current_recovery_blocks() const noexcept {
    return kTierM[tier_];
}

}  // namespace linoh::fec
