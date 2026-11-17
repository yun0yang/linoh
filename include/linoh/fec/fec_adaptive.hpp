// fec_adaptive.hpp — O3 FEC 自适应控制器（cluster 优化总体方案 v1.0 / 编码层方案 O3）
//
// 问题：FecConfig 静态配置无法匹配公网丢包率的时变特性——
//   冗余不足时重传长尾放大（LLMPP per-token 同步链路每 2.4-6 个 token
//   一次停顿，见编码层方案 §6.3）；冗余过度时带宽浪费最高 +25%。
//
// 机制：滑动窗口丢包率估计（EWMA 平滑）+ 迟滞分档：
//   | 实测 p（EMA） | 档位 | 冗余 |
//   | <= 0.5%       | M=1  | +6.25% |
//   | 0.5% - 2%     | M=2  | +12.5% |
//   | > 2%          | M=4  | +25% |
//   RS K=16 固定，block_size=1024（1 包/块，块丢失率=包丢失率，
//   避免大块放大 p_blk，编码层方案 §1.6 推论 2）。
//
// 迟滞（借鉴灵衢 ubs-engine QoS 心跳/超时参数体系，Q2）：
//   升档需连续 up_stable_windows 个窗口越上界（快速加保护），
//   降档需连续 down_stable_windows 个窗口低于下界（保守降档，
//   防止丢包率短暂回落导致保护撤除→再次丢包的振荡）。
//
// 数据源：Connection::stats() 的 packets_sent / lost_packets 累计值，
// 调用方周期性（如每秒）喂入 update()；控制器只做差分与分档，
// 不持有连接引用，无锁（单线程或调用方自锁）。
//
// 数学依据：组内触发重传概率 P = 1-(1-p)^K（无 FEC）/ P(Bin(K+M,p)>M)
// （RS）。p=3% 时 M=0/1/2/4 对应 38.6%/9.1%/1.6%/0.04%（编码层方案 §5.2）。

#pragma once

#include "linoh/fec/fec.hpp"

#include <cstdint>

namespace linoh::fec {

/// FEC 自适应控制器（无锁；调用方保证 update 串行）
class FecAdaptiveController {
public:
    struct Options {
        /// 每评估窗口的最小发送包数（差分累计值达到才评估一次）
        std::uint64_t window_pkts = 500;
        /// 丢包率 EWMA 平滑系数（0-1，越大越跟随当前窗口）
        double ema_alpha = 0.3;
        /// 升档需连续越上界的窗口数
        int up_stable_windows = 2;
        /// 降档需连续低于下界的窗口数（> 升档数，保守降档）
        int down_stable_windows = 4;
        /// RS 数据块数 K（固定 16；分档仅调 M）
        std::size_t k_blocks = 16;
        /// 块大小（字节）。保持 1024 = 单包/块
        std::size_t block_size = 1024;
        /// 编码类型（默认 RS；Xor 仅支持 M=1，不参与分档）
        FecType type = FecType::ReedSolomon;
    };

    /// @param opts 配置（可选，默认档位表如上）
    explicit FecAdaptiveController(const Options &opts = {});

    /// 喂入连接级累计统计（Connection::stats() 的 packets_sent/lost_packets）
    /// 差分累计满 window_pkts 时评估一次窗口丢包率并更新 EMA/档位。
    /// @return true=本次调用触发了窗口评估（loss_rate_ema()/档位可能变化）
    /// @note 计数器回退（对端重连/重置）自动重新基线，不产生负样本
    bool update(std::uint64_t sent_total, std::uint64_t lost_total);

    /// 当前建议 FecConfig（冷启动默认中档 M=2——公网未知丢包率下的
    /// 保守起点；内网可由调用方首喂低丢包样本快速降档）
    FecConfig current_config() const;

    /// 平滑丢包率（0-1）；尚无窗口样本时返回 -1
    double loss_rate_ema() const noexcept { return ema_; }

    /// 当前 M 档位（1 / 2 / 4）
    int current_recovery_blocks() const noexcept;

    /// 档位切换累计次数（监控：频繁切换=迟滞参数需调）
    std::uint32_t switch_count() const noexcept { return switches_; }

    /// 完成评估的窗口数（监控/测试）
    std::uint32_t windows_evaluated() const noexcept { return windows_; }

private:
    void evaluate_(double window_loss_rate);

    Options opts_;
    std::uint64_t base_sent_{0};   // 窗口起点（差分基线）
    std::uint64_t base_lost_{0};
    bool has_baseline_{false};
    std::uint64_t pend_sent_{0};   // 当前窗口累计差分
    std::uint64_t pend_lost_{0};
    double ema_{-1.0};             // -1 = 无样本
    int tier_{1};                  // 0:M=1  1:M=2  2:M=4
    int up_streak_{0};
    int down_streak_{0};
    std::uint32_t switches_{0};
    std::uint32_t windows_{0};
};

}  // namespace linoh::fec
