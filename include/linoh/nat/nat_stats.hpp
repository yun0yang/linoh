// nat_stats.hpp — P5-D-2 NAT 穿透统计模型与策略推荐
//
// 借鉴 iroh Relay-first 策略 + 历史成功率反馈
//
// 设计原则：
//   - 按 (NAT 类型, 运营商, 区域) 三维统计穿透成功率
//   - 样本不足时回退 CGN 规则（冷启动）
//   - 样本充足时按 score = success_rate * 0.7 + sample_confidence * 0.3 推荐策略
//   - 线程安全（shared_mutex 读写分离）
//   - per-key LRU 上限 1000 条，避免内存膨胀
//   - 可选磁盘持久化（跨重启保留历史数据）
//
// 与 CGN Detector 的关系：
//   - CgnDetector 负责"当前环境"的实时检测（端口离散度 + 置信度）
//   - NatStats 负责"历史经验"的统计反馈（成功率 + 策略推荐）
//   - 两者融合：CGN 检测提供候选策略，NatStats 按历史成功率排序推荐

#pragma once

#include "linoh/nat/cgn_detector.hpp"   // CgnStrategy
#include "linoh/net/net_report.hpp"     // NatType

#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace linoh::nat {

// ============================================================================
// 地理区域枚举（中国主要区域 + Unknown）
// ============================================================================

/// 地理区域（用于统计维度）
enum class GeoRegion : std::uint8_t {
    Unknown = 0,    // 未知/未指定
    North,          // 华北（北京、天津、河北、山西、内蒙古）
    South,          // 华南（广东、广西、海南）
    East,           // 华东（上海、江苏、浙江、安徽、福建、江西、山东）
    Central,        // 华中（河南、湖北、湖南）
    Southwest,      // 西南（重庆、四川、贵州、云南、西藏）
    Northwest,      // 西北（陕西、甘肃、青海、宁夏、新疆）
    Northeast,      // 东北（辽宁、吉林、黑龙江）
    Overseas,       // 海外（境外节点）
};

/// GeoRegion 转字符串
constexpr const char *geo_region_name(GeoRegion r) {
    switch (r) {
        case GeoRegion::Unknown:    return "unknown";
        case GeoRegion::North:      return "north";
        case GeoRegion::South:      return "south";
        case GeoRegion::East:       return "east";
        case GeoRegion::Central:    return "central";
        case GeoRegion::Southwest:  return "southwest";
        case GeoRegion::Northwest:  return "northwest";
        case GeoRegion::Northeast:  return "northeast";
        case GeoRegion::Overseas:   return "overseas";
    }
    return "unknown";
}

/// 字符串转 GeoRegion（不匹配返回 Unknown）
GeoRegion parse_geo_region(const std::string &s);

// ============================================================================
// NAT 穿透结果记录
// ============================================================================

/// 单次 NAT 穿透结果记录
struct PenetrationRecord {
    net::NatType                nat_type{net::NatType::Unknown};  ///< NAT 类型
    std::string                 carrier;                          ///< 运营商（"移动"/"电信"/"联通"/""）
    GeoRegion                   region{GeoRegion::Unknown};       ///< 地理区域
    CgnStrategy                 strategy_used{CgnStrategy::DirectConnect};  ///< 使用的策略
    bool                        success{false};                   ///< 是否成功
    std::chrono::milliseconds   duration{0};                      ///< 耗时
    std::int64_t                timestamp_ms{0};                   ///< 记录时间戳（epoch ms）

    /// 默认构造
    PenetrationRecord() = default;

    /// 便捷构造
    PenetrationRecord(net::NatType nt, std::string cr, GeoRegion r,
                      CgnStrategy s, bool ok, std::chrono::milliseconds d)
        : nat_type(nt), carrier(std::move(cr)), region(r),
          strategy_used(s), success(ok), duration(d),
          timestamp_ms(std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch()).count()) {}

    /// 转字符串（用于日志/持久化）
    std::string to_string() const;
};

// ============================================================================
// 统计维度键
// ============================================================================

/// 统计维度键：(NAT 类型, 运营商, 区域)
struct StatsKey {
    net::NatType    nat_type{net::NatType::Unknown};
    std::string     carrier;
    GeoRegion       region{GeoRegion::Unknown};

    bool operator==(const StatsKey &) const = default;

    /// 转字符串（用于日志/持久化）
    std::string to_string() const;
};

/// StatsKey 哈希函数
struct StatsKeyHash {
    std::size_t operator()(const StatsKey &k) const noexcept {
        std::size_t h = static_cast<std::size_t>(k.nat_type);
        h ^= std::hash<std::string>{}(k.carrier) << 1;
        h ^= static_cast<std::size_t>(k.region) << 6;
        return h;
    }
};

// ============================================================================
// 统计快照
// ============================================================================

/// 单维度统计快照
struct StatsSnapshot {
    std::uint64_t   total{0};               ///< 总尝试次数
    std::uint64_t   success{0};             ///< 成功次数
    double          success_rate{0.0};      ///< 成功率 [0.0, 1.0]
    std::chrono::milliseconds avg_duration{0};  ///< 平均耗时
    std::uint64_t   sample_confidence{0};   ///< 样本置信度 [0, 100]（samples/100*100）

    /// 默认构造
    StatsSnapshot() = default;

    /// 是否冷启动（样本不足）
    bool is_cold_start(std::size_t threshold = 10) const {
        return total < threshold;
    }
};

/// 单策略统计
struct StrategyStats {
    CgnStrategy             strategy{CgnStrategy::DirectConnect};
    std::uint64_t           total{0};
    std::uint64_t           success{0};
    double                  success_rate{0.0};
    std::chrono::milliseconds avg_duration{0};

    /// 综合评分：success_rate * 0.7 + sample_confidence * 0.3
    /// @param sample_confidence 样本置信度 [0.0, 1.0]（samples / 100，上限 1.0）
    double score(double sample_confidence) const {
        return success_rate * 0.7 + sample_confidence * 0.3;
    }
};

// ============================================================================
// NAT 穿透统计模型
// ============================================================================

/// NAT 穿透统计模型配置
struct NatStatsConfig {
    /// 单维度最大记录数（LRU 上限）
    std::size_t max_records_per_key{1000};

    /// 冷启动阈值（样本 < 该值时回退 CGN 规则）
    std::size_t cold_start_threshold{10};

    /// 样本置信度饱和上限（samples / saturation_limit，上限 1.0）
    std::size_t sample_saturation_limit{100};

    /// 策略推荐评分权重：score = success_rate * w_rate + sample_confidence * w_conf
    double weight_success_rate{0.7};
    double weight_sample_confidence{0.3};

    /// 持久化文件路径（空表示不持久化）
    std::string persistence_path;

    /// 自动保存间隔（记录数达到该值时触发保存，0 表示不自动保存）
    std::size_t autosave_interval{0};
};

/// NAT 穿透统计模型
///
/// 线程安全：使用 shared_mutex 读写分离，多线程并发 record/query/recommend
class NatStats {
public:
    /// 默认构造
    NatStats() = default;

    /// 带配置构造
    explicit NatStats(NatStatsConfig config);

    // --- 不可移动/拷贝（含 shared_mutex）---
    NatStats(const NatStats &) = delete;
    NatStats &operator=(const NatStats &) = delete;
    NatStats(NatStats &&) = delete;
    NatStats &operator=(NatStats &&) = delete;

    /// 记录一次穿透结果（线程安全）
    void record(const PenetrationRecord &r);

    /// 查询维度统计快照
    StatsSnapshot query(const StatsKey &key) const;

    /// 查询维度下各策略统计
    std::vector<StrategyStats> query_strategies(const StatsKey &key) const;

    /// 策略推荐：基于历史成功率推荐最优策略
    ///
    /// @param key 统计维度键
    /// @param candidates 候选策略（按 CGN 置信度预筛后的可行策略列表）
    /// @return (推荐策略, 预期成功率)；冷启动或无候选返回 nullopt
    std::optional<std::pair<CgnStrategy, double>> recommend_strategy(
        const StatsKey &key,
        std::span<const CgnStrategy> candidates) const;

    /// 全局命中率（所有维度的总成功率，用于监控）
    double global_success_rate() const;

    /// 获取配置
    const NatStatsConfig &config() const { return config_; }

    /// 获取维度数量
    std::size_t key_count() const;

    /// 获取所有维度的总记录数
    std::uint64_t total_records() const;

    // --- 持久化 ---

    /// 保存到文件
    /// @param path 文件路径（空则用 config_.persistence_path）
    /// @return true 成功
    bool save_to_file(const std::string &path = "") const;

    /// 从文件加载
    /// @param path 文件路径（空则用 config_.persistence_path）
    /// @return 加载的记录数，-1 表示失败
    int load_from_file(const std::string &path = "");

    /// 清空所有统计
    void clear();

private:
    /// per-key 历史记录（时序，LRU 淘汰）
    struct KeyBucket {
        std::deque<PenetrationRecord> records;
        std::uint64_t total{0};
        std::uint64_t success{0};
        std::chrono::milliseconds total_duration{0};
        std::unordered_map<CgnStrategy, std::pair<std::uint64_t, std::uint64_t>>
            per_strategy;  // strategy -> (total, success)
    };

    mutable std::shared_mutex mu_;
    std::unordered_map<StatsKey, KeyBucket, StatsKeyHash> buckets_;
    NatStatsConfig config_;
    mutable std::atomic<std::uint64_t> unsaved_count_{0};

    /// 计算样本置信度 [0.0, 1.0]
    double compute_sample_confidence(std::uint64_t samples) const;

    /// LRU 淘汰（超过 max_records_per_key 时删除最旧记录）
    void evict_lru_(KeyBucket &bucket);

    /// 自动保存检查
    void maybe_autosave_() const;
};

// ============================================================================
// 策略推荐辅助函数
// ============================================================================

/// 默认候选策略列表（按 CGN 规则优先级排序）
/// @param nat_type NAT 类型
/// @return 候选策略列表
std::vector<CgnStrategy> default_candidates(net::NatType nat_type);

/// 将 CgnStrategy 转换为 std::uint8_t（用于 std::hash/unordered_map key）
constexpr std::uint8_t to_underlying(CgnStrategy s) {
    return static_cast<std::uint8_t>(s);
}

} // namespace linoh::nat

// 注意：CgnStrategy 是 enum class，C++14 起 std::hash 对枚举类型有默认特化，
// 无需（也不能）显式特化 std::hash<CgnStrategy>。
