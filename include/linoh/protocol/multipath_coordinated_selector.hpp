// multipath_coordinated_selector.hpp — 多路径协同拥塞控制加权选择器（v2.0 Phase 1）
//
// 设计目标：
//   1. 基于拥塞控制器指标（BBR pacing_rate）动态分配路径权重
//   2. 健康度感知 — RTT 飙升 / 高丢包率时自动降低权重，恢复时渐进回升
//   3. 总 CWND 上限 — 聚合所有路径的 cwnd，防止整体网络过载
//   4. 向后兼容 — NewReno 路径（pacing_rate=0）回退到平均权重
//
// 与现有选择器的关系：
//   - MultipathStripSelector    : 纯 round-robin，不考虑路径质量
//   - MultipathAdaptiveSelector : 按 RTT 反比加权，不考虑拥塞窗口
//   - MultipathCoordinatedSelector : 综合 pacing_rate + health + CWND cap，
//                                    适合 BBR 启用后的高吞吐场景
//
// 权重计算：
//   BBR 路径:  raw_weight = pacing_rate_bps * health_multiplier
//   NewReno 路径: raw_weight = avg_bbr_pacing_rate * health_multiplier（无 BBR 时用 1.0）
//   归一化:    weight[i] = raw_weight[i] / sum(raw_weight)
//
// 健康度计算：
//   health_multiplier 起始 1.0，按以下规则调整：
//     - RTT > 3x baseline  → 乘 0.5（显著退化）
//     - loss_rate > 5%     → 乘 (1 - loss_rate*5)，裁剪到 [0.1, 1.0]
//     - 每次更新向 1.0 渐进恢复 kRecoveryGain=0.1
//   baseline_srtt 在 update_candidates 时初始化为首次观测 SRTT
//
// 线程安全：与 MultipathAdaptiveSelector 一致，mutable mutex 保护内部状态。
//           调用方（Connection）保证 CongestionController 指针有效期。

#pragma once

#include "linoh/net/path.hpp"                     // net::FourTuple
#include "linoh/protocol/congestion_controller.hpp"  // CongestionController
#include "linoh/protocol/multipath_selector.hpp"     // MultipathMode

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace linoh::protocol {

/// 协同选择器路径信息（update_candidates 输入）
struct CoordinatedPathInfo {
    net::FourTuple tuple{};
    CongestionController *controller{nullptr};  ///< 非拥有指针，可为 nullptr（NewReno 或未注入）
    std::chrono::microseconds srtt{0};          ///< 平滑 RTT，0 表示未测量
    double loss_rate{0.0};                      ///< [0.0, 1.0]，0 表示无丢包
    bool is_cross_domain{false};                ///< V3-B: 是否为跨域路径（影响退化阈值，跨域对 RTT 飙升更宽容）
    bool is_relay_path{false};                  ///< V3-B: 是否为 Relay 中继路径（延迟更高，权重计算时降基础权重）
};

/// 多路径协同拥塞控制加权选择器
///
/// 每次 STREAM 帧发送时调用 select_next_for_send()，
/// 按 pacing_rate * health_multiplier 加权随机选择路径。
class MultipathCoordinatedSelector {
public:
    /// 路径健康度快照（诊断/日志用）
    struct PathHealth {
        net::FourTuple tuple{};
        double weight{0.0};              ///< 当前归一化权重 [0, 1]
        double health_multiplier{1.0};   ///< 健康度乘子 [0.1, 1.0]
        uint64_t pacing_rate_bps{0};     ///< 当前 pacing 速率
        uint64_t cwnd_bytes{0};          ///< 当前拥塞窗口
        bool is_degraded{false};         ///< 是否处于退化态
        std::string degradation_reason;  ///< 退化原因（空=健康）
        bool is_cross_domain{false};     ///< V3-B: 是否为跨域路径
        bool is_relay_path{false};       ///< V3-B: 是否为 Relay 中继路径
    };

    /// 构造
    /// @param expected_paths 预期候选数量（仅用于 reserve）
    explicit MultipathCoordinatedSelector(std::size_t expected_paths = 4);

    /// 更新候选路径列表（带拥塞控制器和 RTT 信息）
    /// - 首次调用时初始化 baseline_srtt
    /// - 后续调用保留已存在路径的 health_multiplier（按 tuple 匹配）
    /// - 新路径 health_multiplier 初始化为 1.0
    void update_candidates(std::vector<CoordinatedPathInfo> paths);

    /// 选择下一个发送路径（加权随机）
    /// @return 候选路径，空候选时返回 nullopt
    std::optional<net::FourTuple> select_next_for_send();

    /// 跳过指定路径（路径故障时调用，从候选中移除）
    void skip_path(const net::FourTuple &tuple);

    /// 设置总 CWND 上限（0 = 不限制）
    /// 选择器在 total_cwnd_bytes() 超过 cap 时不再选择新路径
    void set_total_cwnd_cap(uint64_t cap_bytes) {
        std::lock_guard<std::mutex> lk(mu_);
        total_cwnd_cap_ = cap_bytes;
    }

    /// 当前所有路径的 CWND 总和
    uint64_t total_cwnd_bytes() const;

    /// 当前总 CWND 上限
    uint64_t total_cwnd_cap() const {
        std::lock_guard<std::mutex> lk(mu_);
        return total_cwnd_cap_;
    }

    /// 当前候选数量
    std::size_t candidate_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return candidates_.size();
    }

    /// 每条路径被选中的次数（测试负载均衡用）
    std::vector<std::pair<net::FourTuple, uint64_t>> selection_stats() const;

    /// 总选择次数
    uint64_t total_selections() const {
        std::lock_guard<std::mutex> lk(mu_);
        return total_selections_;
    }

    /// 所有路径的健康度快照（诊断用）
    std::vector<PathHealth> path_health_stats() const;

    /// 设置随机种子（测试用，默认从 random_device 初始化）
    void set_seed(uint64_t seed);

    // ===== v3.9.1: 带宽反馈闭环 =====

    /// 带宽提供者函数：给定路径 FourTuple，返回实测带宽 bps（0 = 无数据）
    /// 设置后 recompute_weights 优先用实测带宽替代 BBR pacing_rate
    using BandwidthProvider = std::function<uint64_t(const net::FourTuple&)>;

    /// 设置带宽提供者（传入 nullptr 清除，回退到 pacing_rate）
    void set_bandwidth_provider(BandwidthProvider fn) {
        std::lock_guard<std::mutex> lk(mu_);
        bandwidth_provider_ = std::move(fn);
    }

    /// 当前是否设置了带宽提供者
    bool has_bandwidth_provider() const {
        std::lock_guard<std::mutex> lk(mu_);
        return static_cast<bool>(bandwidth_provider_);
    }

private:
    mutable std::mutex mu_;
    std::vector<CoordinatedPathInfo> candidates_;
    std::vector<uint64_t> selection_counts_;
    std::vector<double> weights_;            ///< 归一化权重
    std::vector<double> health_multipliers_;  ///< 每路径健康度乘子 [0.1, 1.0]
    std::vector<double> baseline_srtt_ms_;   ///< 每路径 baseline RTT（退化检测基准）
    uint64_t total_selections_{0};
    uint64_t rng_state_{0};
    uint64_t total_cwnd_cap_{0};  ///< 0 = 不限制
    BandwidthProvider bandwidth_provider_;  ///< v3.9.1: 实测带宽提供者（可选）

    /// 重新计算归一化权重（pacing_rate * health_multiplier）
    void recompute_weights();

    /// 更新指定路径的健康度乘子（基于 RTT 飙升和丢包率）
    void update_health(std::size_t idx);

    /// 简单线性同余 RNG（保证可重现，与 AdaptiveSelector 一致）
    uint64_t next_random();

    // ===== 健康度检测常量 =====
    static constexpr double kRttSpikeThreshold = 3.0;   ///< RTT > 3x baseline = 飙升
    static constexpr double kHighLossThreshold = 0.05;   ///< 丢包率 > 5% = 退化
    static constexpr double kMinHealthMultiplier = 0.1;  ///< 健康度乘子下限
    static constexpr double kRecoveryGain = 0.1;         ///< 每次更新向 1.0 恢复的步长
    static constexpr double kRttSpikePenalty = 0.5;      ///< RTT 飙升时的惩罚因子

    // ===== V3-B: 跨域路径放宽阈值（跨域链路 RTT 抖动与瞬时丢包更常见）=====
    /// 跨域路径 RTT 飙升阈值（5x baseline，比单域 3.0 宽松）
    static constexpr double kCrossDomainRttSpikeThreshold = 5.0;
    /// 跨域路径高丢包阈值（10%，比单域 5% 宽松）
    static constexpr double kCrossDomainHighLossThreshold = 0.10;
};

}  // namespace linoh::protocol
