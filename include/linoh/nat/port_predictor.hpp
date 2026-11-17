// port_predictor.hpp — P5-D-1 Symmetric NAT 端口预测引擎
//
// 在 v3.5 predict_symmetric_nat_ports（2 点线性外推）基础上升级为：
//   - per-peer 历史端口序列管理（上限 32 条 LRU）
//   - 4 种预测模型：TwoPoint / LinearRegression / WeightedRecent / Hybrid
//   - 置信区间 + 自适应候选数（5-20）
//   - 命中/未命中反馈修正模型权重
//   - 线程安全（shared_mutex 读写分离）
//   - 持久化接口（save_to_file / load_from_file，跨重启保留）
//
// 设计原则：
//   - 观测 <3 点回退 TwoPoint（兼容 v3.5 predict_symmetric_nat_ports 算法）
//   - 观测 >=3 点启用 LinearRegression / WeightedRecent / Hybrid
//   - Hybrid 融合多模型候选，按历史命中率加权排序去重
//   - 冷启动（无历史）由调用方回退 CGN 静态规则
//
// 集成点：
//   - Holepuncher SymmetricNat 路径调用 PortPredictor::predict() 获取候选端口
//   - Endpoint 连接成功/失败时调用 record_observation() / feedback()
//   - Endpoint 持有 shared_ptr<PortPredictor>（P5-D-3 深度集成）

#pragma once

#include "linoh/base/key.hpp"  // EndpointId = PublicKey, std::hash<PublicKey>

#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace linoh::nat {

// ============================================================================
// 基础类型
// ============================================================================

using PortPredictClock = std::chrono::system_clock;
using PortPredictTimePoint = PortPredictClock::time_point;

/// 端口预测模型枚举
enum class PortPredictModel : std::uint8_t {
    TwoPoint = 0,           // v3.5 兼容：2 点线性外推（predict_symmetric_nat_ports 原算法）
    LinearRegression = 1,   // 多点线性回归（最小二乘）
    WeightedRecent = 2,     // 加权近期（近期观测权重指数衰减）
    Hybrid = 3,             // 多模型融合 + 残差分析 + 命中率加权
};

/// 模型转字符串
constexpr const char *port_predict_model_name(PortPredictModel m) {
    switch (m) {
        case PortPredictModel::TwoPoint:         return "two-point";
        case PortPredictModel::LinearRegression: return "linear-regression";
        case PortPredictModel::WeightedRecent:   return "weighted-recent";
        case PortPredictModel::Hybrid:           return "hybrid";
    }
    return "unknown";
}

// ============================================================================
// 观测记录与预测结果
// ============================================================================

/// 单次端口观测记录
struct PortObservation {
    base::EndpointId peer_endpoint;       ///< 对端节点 EndpointId
    std::uint16_t    observed_port{0};    ///< STUN 观测到的外部映射端口
    PortPredictTimePoint timestamp;       ///< 观测时间

    PortObservation() = default;
    PortObservation(base::EndpointId peer, std::uint16_t port, PortPredictTimePoint ts)
        : peer_endpoint(peer), observed_port(port), timestamp(ts) {}

    /// 序列化为字符串（持久化用，格式：peer_hex|port|epoch_ms）
    std::string to_string() const;

    /// 从字符串反序列化
    static bool parse(std::string_view line, PortObservation &out);
};

/// 端口预测结果
struct PortPrediction {
    std::vector<std::uint16_t> candidates;       ///< 候选端口列表（按可能性降序，去重）
    double                     confidence{0.0};  ///< 预测置信度 0.0-1.0
    PortPredictModel           model_used{PortPredictModel::TwoPoint};  ///< 使用的模型
    std::size_t                observation_count{0};  ///< 历史观测数

    /// 是否为冷启动（观测不足，调用方应回退 CGN 规则）
    bool is_cold_start() const { return observation_count < 2; }
};

// ============================================================================
// per-peer 历史统计
// ============================================================================

/// 单个 peer 的预测命中统计（用于 Hybrid 模型加权）
struct PeerHitStats {
    std::uint64_t hit_count{0};       ///< 预测命中次数
    std::uint64_t miss_count{0};      ///< 预测未命中次数
    std::uint64_t last_hit_model{0};  ///< 最近命中的模型（bit0=TwoPoint, bit1=LR, bit2=WR）

    /// 命中率
    double hit_rate() const {
        std::uint64_t total = hit_count + miss_count;
        return total == 0 ? 0.0 : static_cast<double>(hit_count) / static_cast<double>(total);
    }

    /// 总样本数
    std::uint64_t total() const { return hit_count + miss_count; }
};

// ============================================================================
// 端口预测器
// ============================================================================

/// PortPredictor 配置
struct PortPredictorConfig {
    /// per-peer 历史观测上限（LRU 淘汰）
    std::size_t max_observations_per_peer{32};

    /// 最小观测数（<此值用 TwoPoint，>=此值可用高级模型）
    std::size_t min_observations_for_advanced{3};

    /// 最小候选数（置信度高时）
    std::size_t min_candidates{5};

    /// 最大候选数（置信度低时）
    std::size_t max_candidates{20};

    /// WeightedRecent 模型衰减时间常数（秒，近期观测权重高）
    double weighted_decay_tau_sec{300.0};

    /// 持久化文件路径（空=不持久化）
    std::string persistence_path;

    /// 持久化自动保存间隔（观测数达到此值倍数时触发，0=不自动保存）
    std::size_t autosave_every_observations{50};
};

/// 端口预测器（管理 per-peer 历史序列 + 多模型预测 + 命中反馈）
///
/// 线程安全：内部 shared_mutex 读写分离，record/feedback 写锁，predict 读锁。
/// 持久化：save_to_file / load_from_file，跨重启保留历史。
class PortPredictor {
public:
    /// 默认配置构造
    explicit PortPredictor(PortPredictorConfig config = {});

    /// 析构（若配置了 autosave，析构时自动保存）
    ~PortPredictor();

    // 不可拷贝/移动（含 shared_mutex，不可移动）
    PortPredictor(const PortPredictor &) = delete;
    PortPredictor &operator=(const PortPredictor &) = delete;
    PortPredictor(PortPredictor &&) = delete;
    PortPredictor &operator=(PortPredictor &&) = delete;

    // ------------------------------------------------------------------
    // 观测记录与反馈（写操作）
    // ------------------------------------------------------------------

    /// 记录一次对端端口观测（线程安全，写锁）
    /// @param peer 对端 EndpointId
    /// @param observed_port STUN 观测到的外部端口
    /// @param ts 观测时间（默认 now）
    void record_observation(const base::EndpointId &peer,
                            std::uint16_t observed_port,
                            PortPredictTimePoint ts = PortPredictClock::now());

    /// 反馈预测命中/未命中（修正 Hybrid 模型权重，线程安全，写锁）
    /// @param peer 对端 EndpointId
    /// @param predicted 预测的端口（命中时=actual，未命中时为预测候选之一）
    /// @param actual 实际端口
    /// @param hit 是否命中
    /// @param model 产生该预测的模型（用于 last_hit_model 统计）
    void feedback(const base::EndpointId &peer,
                  std::uint16_t predicted,
                  std::uint16_t actual,
                  bool hit,
                  PortPredictModel model = PortPredictModel::Hybrid);

    // ------------------------------------------------------------------
    // 预测（读操作）
    // ------------------------------------------------------------------

    /// 预测对端下一次端口（基于历史序列，线程安全，读锁）
    /// @param peer 对端 EndpointId
    /// @param count 候选数（0=按置信度自适应 min_candidates..max_candidates）
    /// @return 预测结果（冷启动时 confidence=0, candidates 为空）
    PortPrediction predict(const base::EndpointId &peer,
                           std::size_t count = 0) const;

    /// 获取对端历史观测数（线程安全，读锁）
    std::size_t observation_count(const base::EndpointId &peer) const;

    /// 获取对端命中统计（线程安全，读锁）
    PeerHitStats hit_stats(const base::EndpointId &peer) const;

    /// 获取 per-peer 总数（监控用，线程安全，读锁）
    std::size_t peer_count() const;

    /// 获取全局总观测数（监控用，线程安全，读锁）
    std::size_t total_observations() const;

    // ------------------------------------------------------------------
    // 持久化
    // ------------------------------------------------------------------

    /// 保存到文件（线程安全，写锁后文件写）
    /// 格式：每行一条 PortObservation.to_string()，行首 # 为注释
    /// @param path 文件路径（空=用 config_.persistence_path）
    /// @return true=成功
    bool save_to_file(const std::string &path = "") const;

    /// 从文件加载（线程安全，写锁，合并到现有历史）
    /// @param path 文件路径（空=用 config_.persistence_path）
    /// @return 加载的记录数，-1=失败
    int load_from_file(const std::string &path = "");

    /// 清空所有历史（线程安全，写锁）
    void clear();

    /// 获取配置
    const PortPredictorConfig &config() const { return config_; }

private:
    // ------------------------------------------------------------------
    // per-peer 历史
    // ------------------------------------------------------------------

    struct PeerHistory {
        std::deque<PortObservation> observations;  ///< 时序观测（front=最旧，back=最新）
        PeerHitStats                hit_stats;
    };

    mutable std::shared_mutex mu_;
    std::unordered_map<base::EndpointId, PeerHistory> histories_;  // std::hash<PublicKey> 已特化
    PortPredictorConfig config_;
    std::size_t          total_observations_{0};
    std::size_t          autosave_counter_{0};

    // ------------------------------------------------------------------
    // 内部预测模型实现（纯函数，操作 observations 序列）
    // ------------------------------------------------------------------

    /// TwoPoint 模型：兼容 v3.5 predict_symmetric_nat_ports（2 点线性外推）
    static PortPrediction predict_two_point(
        const std::deque<PortObservation> &obs,
        std::size_t count);

    /// LinearRegression 模型：多点最小二乘拟合 port = a*t + b
    static PortPrediction predict_linear_regression(
        const std::deque<PortObservation> &obs,
        std::size_t count);

    /// WeightedRecent 模型：近期观测权重指数衰减，加权预测增量
    static PortPrediction predict_weighted_recent(
        const std::deque<PortObservation> &obs,
        std::size_t count,
        double decay_tau_sec);

    /// Hybrid 模型：多模型并行预测 + 命中率加权融合 + 去重排序
    static PortPrediction predict_hybrid(
        const std::deque<PortObservation> &obs,
        std::size_t count,
        double decay_tau_sec,
        const PeerHitStats &stats);

    /// 自适应候选数：按置信度调整 count 到 [min, max]
    std::size_t adaptive_count(double confidence, std::size_t requested) const;

    /// 去重并截断候选列表到 count 个
    static std::vector<std::uint16_t> dedup_and_truncate(
        std::vector<std::uint16_t> candidates, std::size_t count);

    /// LRU 淘汰：若 observations 超过上限，删除最旧
    void evict_if_needed_(PeerHistory &h);

    /// 自动保存检查（写锁内调用，仅计数标记，不直接 save 避免锁升级死锁）
    /// 实际持久化由析构 + 手动 save_to_file 触发
    void maybe_autosave_();

    /// peer EndpointId 转 hex 字符串（持久化 stats 行用，static，不访问成员）
    static std::string peer_to_hex_(const base::EndpointId &peer);
};

// ============================================================================
// 工具函数（公开，便于单测）
// ============================================================================

/// 最小二乘线性回归：y = a*x + b
/// @return (a, b, residual_stddev)；样本 <2 返回 nullopt
struct LinearFit {
    double slope{0.0};        ///< a
    double intercept{0.0};    ///< b
    double residual_stddev{0.0};  ///< 残差标准差
    bool   valid{false};      ///< 是否有效（样本 >=2）
};
LinearFit linear_fit(const std::vector<double> &xs, const std::vector<double> &ys);

/// 端口增量序列分析（相邻观测的端口差值）
/// @return 增量列表（obs[i+1].port - obs[i].port）
std::vector<std::int32_t> compute_port_deltas(
    const std::deque<PortObservation> &obs);

/// 增量序列的均值与标准差（用于判断增量稳定性）
struct DeltaStats {
    double mean{0.0};
    double stddev{0.0};
    bool   valid{false};  ///< 增量数 >=1
};
DeltaStats compute_delta_stats(const std::vector<std::int32_t> &deltas);

}  // namespace linoh::nat
