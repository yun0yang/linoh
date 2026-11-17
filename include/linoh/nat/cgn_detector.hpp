// cgn_detector.hpp — P5-D-3 CGN（Carrier-Grade NAT）穿透策略
//
// 借鉴 iroh Relay-first 策略 + TURN 强制中转
//
// 设计原则：
//   - CGN 检测通过多次 STUN 探测 + 端口离散度分析
//   - 检测结果驱动策略选择（StandardRfc5389 / SymmetricNat / RelayFallback）
//   - 置信度阈值可配置（默认 0.3）
//   - 检测过程异步并行（多 STUN 服务器同时探测）
//
// 检测算法：
//   1. 向 3+ 个不同 STUN 服务器探测
//   2. 若返回的映射 IP 一致但端口离散度高 → CGN
//   3. 若端口预测置信度 <0.3 → CGN
//   4. 若多个 STUN 返回不同 IP → 非 CGN（多 NAT 层）

#pragma once

#include "linoh/net/holepuncher.hpp"
#include "linoh/net/net_report.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace linoh::nat {

// ============================================================================
// 前向声明（避免与 nat_stats.hpp 循环依赖）
// ============================================================================

class NatStats;        // 定义于 nat_stats.hpp
struct StatsKey;       // 定义于 nat_stats.hpp

// ============================================================================
// CGN 检测结果
// ============================================================================

/// CGN 检测结果
struct CgnDetectionResult {
    bool is_cgn{false};                          ///< 是否检测到 CGN
    std::string carrier_name;                    ///< 运营商名称（可选，从 STUN 响应或 IP 归属推断）
    std::uint16_t observed_port_range_min{0};    ///< 观察到的端口范围最小值
    std::uint16_t observed_port_range_max{0};    ///< 观察到的端口范围最大值
    double port_prediction_confidence{0.0};      ///< 端口预测置信度 0.0-1.0
    std::vector<std::uint16_t> observed_ports;   ///< 观察到的所有外部端口
    std::vector<std::string> observed_ips;       ///< 观察到的所有外部 IP
    std::chrono::milliseconds detection_duration{0};  ///< 检测耗时

    /// 默认构造
    CgnDetectionResult() = default;

    /// 是否应该使用 Relay（CGN 且置信度低）
    bool should_use_relay(double threshold = 0.3) const {
        return is_cgn && port_prediction_confidence < threshold;
    }

    /// 转字符串
    std::string to_string() const;
};

// ============================================================================
// CGN 检测配置
// ============================================================================

/// CGN 检测配置
struct CgnDetectorConfig {
    /// STUN 服务器列表（至少 3 个，越多越准确）
    std::vector<std::string> stun_servers;

    /// 单次 STUN 请求超时
    std::chrono::milliseconds request_timeout{std::chrono::milliseconds(2000)};

    /// 总检测超时
    std::chrono::milliseconds total_timeout{std::chrono::seconds(10)};

    /// 端口离散度判定阈值（标准差/均值，>0.5 视为离散度高）
    double port_dispersion_threshold{0.5};

    /// 置信度判定阈值（<0.3 视为低置信度）
    double confidence_threshold{0.3};

    /// 最小 STUN 服务器数量（少于该值不进行 CGN 判定）
    std::size_t min_stun_servers{3};
};

// ============================================================================
// CGN 检测器
// ============================================================================

/// STUN 探测回调（注入式，便于测试）
///
/// @param stun_server STUN 服务器地址 (host:port)
/// @param timeout 超时
/// @return (映射IP, 映射端口)；失败返回 nullopt
using StunProbeProvider = std::function<
    std::future<std::optional<std::pair<std::string, std::uint16_t>>>(
        const std::string &stun_server,
        std::chrono::milliseconds timeout)>;

/// CGN 检测器
class CgnDetector {
public:
    /// 默认构造（使用内置 STUN 探测）
    explicit CgnDetector(CgnDetectorConfig config = {});

    /// 注入式构造（用于测试）
    CgnDetector(CgnDetectorConfig config, StunProbeProvider provider);

    /// 检测 CGN（异步）
    ///
    /// 算法：
    ///   1. 向所有 STUN 服务器并行探测
    ///   2. 收集所有 (IP, port) 对
    ///   3. 分析 IP 一致性 + 端口离散度
    ///   4. 计算端口预测置信度
    ///   5. 综合判定是否 CGN
    std::future<CgnDetectionResult> detect_async();

    /// 同步版检测
    CgnDetectionResult detect_sync();

    /// 获取配置
    const CgnDetectorConfig &config() const { return config_; }

    /// 计算端口离散度（标准差/均值，变异系数 CV）
    /// 公开静态方法，便于单元测试和外部复用
    static double compute_port_dispersion(const std::vector<std::uint16_t> &ports);

    /// 计算端口预测置信度
    ///
    /// 算法：基于端口差值的稳定性
    ///   - 端口差值稳定（变化小）→ 高置信度
    ///   - 端口差值大或无规律 → 低置信度
    static double compute_port_confidence(const std::vector<std::uint16_t> &ports);

private:
    CgnDetectorConfig config_;
    StunProbeProvider provider_;

    /// 默认 STUN 探测实现（基于 NetReporter）
    static std::future<std::optional<std::pair<std::string, std::uint16_t>>>
    default_probe(const std::string &stun_server,
                  std::chrono::milliseconds timeout);

    /// 判断是否 CGN
    static bool is_cgn_based_on_observations(
        const std::vector<std::string> &ips,
        const std::vector<std::uint16_t> &ports,
        double port_dispersion,
        double confidence_threshold);
};

// ============================================================================
// CGN 穿透策略选择器
// ============================================================================

/// CGN 穿透策略
enum class CgnStrategy : std::uint8_t {
    DirectConnect,      // 非 CGN，直接连接
    StandardRfc5389,    // 标准 STUN 打洞
    SymmetricNat,       // 对称 NAT 端口预测
    RelayFallback,      // 强制 Relay 中转
    ParallelTry,        // 并行尝试（端口预测 + Relay）
};

/// 策略转字符串
constexpr const char *cgn_strategy_name(CgnStrategy s) {
    switch (s) {
        case CgnStrategy::DirectConnect:   return "direct";
        case CgnStrategy::StandardRfc5389: return "standard";
        case CgnStrategy::SymmetricNat:    return "symmetric";
        case CgnStrategy::RelayFallback:   return "relay-fallback";
        case CgnStrategy::ParallelTry:     return "parallel-try";
    }
    return "unknown";
}

// ============================================================================
// P5-D-4: 动态阈值配置
// ============================================================================

/// P5-D-4: CGN 策略选择动态阈值配置
///
/// 默认阈值固定 0.7/0.3；当 NatStats 历史样本充足时，按某维度 SymmetricNat
/// 历史成功率调整 high/low 阈值，让策略选择更贴合实际网络环境。
struct DynamicThresholdConfig {
    /// 默认高置信度阈值（冷启动 / NatStats 不可用时使用）
    double default_high{0.7};
    /// 默认低置信度阈值
    double default_low{0.3};

    /// 当某维度 SymmetricNat 历史成功率 < 此值时，提高 high 阈值
    /// （让 SymmetricNat 更难触发，避免低成功率维度浪费时间）
    double symmetric_nat_low_success_rate{0.3};
    /// 提高后的 high 阈值（更保守）
    double raised_high{0.85};
    /// 降低后的 low 阈值（更早降级 Relay）
    double lowered_low{0.2};

    /// 当某维度 SymmetricNat 历史成功率 > 此值时，降低 high 阈值
    /// （让 SymmetricNat 更易触发，抓住高成功率维度）
    double symmetric_nat_high_success_rate{0.6};
    /// 降低后的 high 阈值（更激进）
    double lowered_high{0.55};
    /// 提高后的 low 阈值（更晚降级 Relay）
    double raised_low{0.4};

    /// 阈值调整所需的最小样本数（低于此值用默认阈值，避免冷启动误判）
    std::size_t min_samples_for_adjust{20};
};

/// CGN 策略选择器
class CgnStrategySelector {
public:
    /// 根据检测结果选择穿透策略
    ///
    /// 决策逻辑：
    ///   1. 非 CGN → DirectConnect 或 StandardRfc5389
    ///   2. CGN + 高置信度（>=0.7）→ SymmetricNat（端口预测）
    ///   3. CGN + 中置信度（0.3-0.7）→ ParallelTry（端口预测 + Relay 并行）
    ///   4. CGN + 低置信度（<0.3）→ RelayFallback（强制 Relay）
    static CgnStrategy select(const CgnDetectionResult &result,
                              double high_threshold = 0.7,
                              double low_threshold = 0.3);

    /// P5-D-4: 根据 NatStats 历史成功率动态调整阈值的策略选择
    ///
    /// 决策逻辑：
    ///   1. stats 为空 → 用默认阈值调用 select()
    ///   2. 维度冷启动（样本 < cfg.min_samples_for_adjust）→ 用默认阈值
    ///   3. 查询维度下 SymmetricNat 策略历史成功率：
    ///      - 成功率 < cfg.symmetric_nat_low_success_rate →
    ///        high=cfg.raised_high, low=cfg.lowered_low（更保守，少尝试 SymmetricNat）
    ///      - 成功率 > cfg.symmetric_nat_high_success_rate →
    ///        high=cfg.lowered_high, low=cfg.raised_low（更激进，多尝试 SymmetricNat）
    ///      - 否则 → 默认阈值
    ///   4. 调用 select(result, high, low)
    ///
    /// @param result CGN 检测结果
    /// @param stats NAT 统计模型（可为 nullptr，表示未启用 NAT 强化）
    /// @param key 统计维度键 (NAT 类型, 运营商, 区域)
    /// @param cfg 动态阈值配置
    /// @return 推荐的 CGN 策略
    static CgnStrategy select_dynamic(const CgnDetectionResult &result,
                                      const NatStats *stats,
                                      const StatsKey &key,
                                      const DynamicThresholdConfig &cfg = {});

    /// 将 CGN 策略转换为 linoh 现有的 HolepunchStrategy
    static net::HolepunchStrategy to_holepunch_strategy(CgnStrategy cgn_strategy);
};

// ============================================================================
// 工具函数
// ============================================================================

/// 计算端口的均值
double compute_port_mean(const std::vector<std::uint16_t> &ports);

/// 计算端口的标准差
double compute_port_stddev(const std::vector<std::uint16_t> &ports);

/// 计算端口范围（max - min）
std::uint16_t compute_port_range(const std::vector<std::uint16_t> &ports);

/// 判断 IP 列表是否一致（所有 IP 相同）
bool is_ip_consistent(const std::vector<std::string> &ips);

} // namespace linoh::nat
