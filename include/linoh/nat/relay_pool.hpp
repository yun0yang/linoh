// relay_pool.hpp — P5-D-5 Relay 自动 fallback
//
// 多 Relay 服务器池 + 健康检查 + 故障切换
//
// 借鉴 iroh relay-discovery + Circuit Breaker 模式
//
// 设计原则：
//   - 维护多个 Relay 服务器，按 RTT/健康度排序
//   - 定期健康检查（ping），失败累计超过阈值标记为 UNHEALTHY
//   - 主 Relay 故障时自动切换到备用 Relay（FailoverController）
//   - 熔断器（Circuit Breaker）防止持续尝试不可达的 Relay
//   - 注入式 HealthProbe 便于测试

#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/geo_region.hpp"  // v2.0: GeoRegion 提取到 linoh 顶层

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace linoh::nat {

// ============================================================================
// Relay 健康状态
// ============================================================================

/// Relay 服务器健康状态
enum class RelayHealth : std::uint8_t {
    Unknown,      // 未探测
    Healthy,      // 健康
    Degraded,     // 降级（高 RTT 或少量失败）
    Unhealthy,    // 不健康（多次失败）
    CircuitOpen,  // 熔断器开启（暂停探测）
};

/// 健康状态转字符串
constexpr const char *relay_health_name(RelayHealth h) {
    switch (h) {
        case RelayHealth::Unknown:      return "unknown";
        case RelayHealth::Healthy:      return "healthy";
        case RelayHealth::Degraded:     return "degraded";
        case RelayHealth::Unhealthy:    return "unhealthy";
        case RelayHealth::CircuitOpen:  return "circuit-open";
    }
    return "unknown";
}

// ============================================================================
// Relay 角色层级（v2.0 Phase 1 交付物 5：层级化 Relay 架构）
// ============================================================================

/// Relay 角色层级
/// - Region：区域 Relay，服务本区域节点（每区域 2-3 个主备 + 负载均衡）
/// - Backbone：骨干 Relay，仅承担跨区域中转，不直接服务节点
enum class RelayRole : std::uint8_t {
    Region,    // 区域 Relay（默认）
    Backbone,  // 骨干 Relay
};

constexpr const char *relay_role_name(RelayRole r) {
    switch (r) {
        case RelayRole::Region:    return "region";
        case RelayRole::Backbone:  return "backbone";
    }
    return "unknown";
}

// GeoRegion / geo_region_name / is_cross_region 已提取到 linoh/geo_region.hpp
// （linoh 顶层命名空间，nat 内部引用仍可见）

// ============================================================================
// Relay 评分权重（v2.0 Phase 1）
// ============================================================================

/// Relay 多维评分权重（score 越低越优）
struct RelayScoreWeights {
    double weight_health{1.0};           // 健康度惩罚系数
    double weight_rtt{1.0};              // 每 1ms RTT 计 1 分
    double weight_load{2.0};             // 每 1% 负载计 2 分
    double weight_geo_distance{5.0};     // 每 100km 距离计 5 分
    double cross_region_penalty{200.0};  // 跨区域一次性惩罚
};

// ============================================================================
// Relay 服务器条目
// ============================================================================

/// Relay 服务器条目（含健康度 + 地理 + 负载 + 带宽信息）
struct RelayEntry {
    base::RelayUrl url;
    RelayHealth health{RelayHealth::Unknown};
    std::chrono::milliseconds last_rtt{0};
    std::chrono::system_clock::time_point last_check;
    std::uint32_t consecutive_failures{0};
    std::uint32_t consecutive_successes{0};
    std::uint64_t total_checks{0};
    std::uint64_t total_failures{0};
    bool pinned{false};  // 是否固定（不可淘汰）

    // v2.0 Phase 1：多维选择字段
    GeoRegion region{GeoRegion::Unknown};  // Relay 所在地理区域
    int load_percent{0};                   // 当前负载百分比 [0,100]
    int uplink_bps{0};                     // 上行带宽估计（bps）
    int geo_distance_km{0};                // 与本地节点的地理距离（km）

    // v2.0 Phase 1 交付物 5：层级化 Relay 角色
    RelayRole role{RelayRole::Region};  // 区域 vs 骨干

    /// 构造
    explicit RelayEntry(base::RelayUrl u) : url(std::move(u)) {}

    /// 基础分数（用于排序，越低越好）
    /// - 健康度优先：Healthy < Degraded < Unknown < Unhealthy < CircuitOpen
    /// - 同健康度内按 RTT 排序
    /// - v2.0：叠加 load / geo_distance 维度（使用默认权重）
    ///
    /// 注：此无参版本不计算跨区域惩罚（不知道本地 region），向后兼容。
    double score() const {
        return score(GeoRegion::Unknown, RelayScoreWeights{});
    }

    /// 多维分数（带本地 region 与权重）
    /// score = health_penalty * w.weight_health
    ///       + rtt_ms * w.weight_rtt
    ///       + load_percent * w.weight_load
    ///       + (geo_distance_km / 100) * w.weight_geo_distance
    ///       + (cross_region ? w.cross_region_penalty : 0)
    double score(GeoRegion local_region, const RelayScoreWeights &w) const {
        double health_score = 0;
        switch (health) {
            case RelayHealth::Healthy:      health_score = 0;    break;
            case RelayHealth::Degraded:     health_score = 100;  break;
            case RelayHealth::Unknown:      health_score = 200;  break;
            case RelayHealth::Unhealthy:    health_score = 500;  break;
            case RelayHealth::CircuitOpen:  health_score = 1000; break;
        }
        double s = 0;
        s += health_score * w.weight_health;
        s += static_cast<double>(last_rtt.count()) * w.weight_rtt;
        s += static_cast<double>(load_percent) * w.weight_load;
        s += (static_cast<double>(geo_distance_km) / 100.0) * w.weight_geo_distance;
        if (is_cross_region(local_region, region)) {
            s += w.cross_region_penalty;
        }
        return s;
    }

    /// 是否可用（健康或降级）
    bool is_usable() const {
        return health == RelayHealth::Healthy || health == RelayHealth::Degraded;
    }
};

// ============================================================================
// 熔断器（Circuit Breaker）
// ============================================================================

/// 熔断器配置
struct CircuitBreakerConfig {
    /// 触发熔断的连续失败次数
    std::uint32_t failure_threshold{5};

    /// 熔断后冷却时间（探测前等待）
    std::chrono::milliseconds cooldown{std::chrono::milliseconds(30000)};

    /// 半开状态允许的探测次数
    std::uint32_t half_open_max_probes{3};

    /// 关闭熔断需要的连续成功次数
    std::uint32_t close_threshold{2};

    /// v3.3.0 突破4: 指数退避上限（连续熔断时 cooldown 翻倍，至上限为止）
    ///
    /// 实际 cooldown = min(cooldown * backoff_factor^(consecutive_opens-1), max_cooldown)
    ///   第1次熔断：cooldown = 30s
    ///   第2次熔断：cooldown = 60s
    ///   第3次熔断：cooldown = 120s
    ///   第4次熔断：cooldown = 240s
    ///   第5次及以后：cooldown = 300s（上限）
    /// 设计意图：Relay 不稳定时避免频繁打洞探测，给 Relay 足够恢复时间。
    /// consecutive_opens 在 HalfOpen→Closed 成功恢复时重置为 0。
    std::chrono::milliseconds max_cooldown{std::chrono::milliseconds(300000)};

    /// v3.3.0 突破4: 退避因子（每次连续熔断 cooldown 乘以此因子）
    double backoff_factor{2.0};
};

/// 熔断器状态
enum class CircuitState : std::uint8_t {
    Closed,    // 正常（允许请求）
    Open,      // 熔断（拒绝请求）
    HalfOpen,  // 半开（允许少量探测）
};

constexpr const char *circuit_state_name(CircuitState s) {
    switch (s) {
        case CircuitState::Closed:    return "closed";
        case CircuitState::Open:      return "open";
        case CircuitState::HalfOpen:  return "half-open";
    }
    return "unknown";
}

/// 熔断器
class CircuitBreaker {
public:
    explicit CircuitBreaker(CircuitBreakerConfig cfg = {});

    /// 是否允许请求
    bool allow_request();

    /// 记录成功
    void record_success();

    /// 记录失败
    void record_failure();

    /// 当前状态
    // nn-M6 (v1.7.0.8): 所有 getter 加锁，避免与 record_success/record_failure 并发竞争。
    CircuitState state() const;

    /// 当前连续失败次数
    std::uint32_t consecutive_failures() const;

    /// 当前连续成功次数
    std::uint32_t consecutive_successes() const;

    /// 总检查次数（成功）
    std::uint64_t total_checks() const;

    /// 总失败次数
    std::uint64_t total_failures() const;

    /// v3.3.0 突破4: 当前连续熔断次数（每次 Closed→Open +1，HalfOpen→Closed 重置为 0）
    std::uint32_t consecutive_opens() const;

    /// v3.3.0 突破4: 当前实际生效的 cooldown（含指数退避）
    ///
    /// 计算：min(config_.cooldown * backoff_factor^(consecutive_opens_-1), config_.max_cooldown)
    /// consecutive_opens_=0 时返回 config_.cooldown（未熔断过）。
    std::chrono::milliseconds effective_cooldown() const;

    /// 配置
    const CircuitBreakerConfig &config() const { return config_; }

private:
    // nn-M6 (v1.7.0.8): 原实现 state_/consecutive_failures_/opened_at_ 等成员
    // 既非 atomic 也无锁保护。RelayPool::record_success/record_failure 在 mutex_
    // 下调用 breaker->record_*()，但 CircuitBreaker 自身也被其他路径访问
    // （如 select_best 间接读取 state），存在 data race。加 mutex_ 统一保护。
    mutable std::mutex mutex_;
    CircuitBreakerConfig config_;
    CircuitState state_{CircuitState::Closed};
    std::uint32_t consecutive_failures_{0};
    std::uint32_t consecutive_successes_{0};
    std::uint64_t total_checks_{0};
    std::uint64_t total_failures_{0};
    std::chrono::system_clock::time_point opened_at_;
    std::uint32_t half_open_probes_{0};

    /// v3.3.0 突破4: 连续熔断计数器（用于指数退避）
    ///   Closed→Open 时 ++（record_failure 首次触发熔断）
    ///   HalfOpen→Open 时 ++（探测失败重新熔断，也算连续熔断）
    ///   HalfOpen→Closed 时 = 0（record_success 成功恢复时重置）
    std::uint32_t consecutive_opens_{0};

    /// 检查是否应该从 Open 转为 HalfOpen（调用方已持锁）
    void maybe_transition_to_half_open_locked();

    /// v3.3.0 突破4: 计算实际 cooldown（含指数退避，调用方已持锁）
    std::chrono::milliseconds effective_cooldown_locked() const;
};

// ============================================================================
// 健康探测器（注入式）
// ============================================================================

/// 健康探测结果
struct HealthProbeResult {
    bool success{false};
    std::chrono::milliseconds rtt{0};
    std::string error_message;

    // v2.0 Phase 1：探测时携带的负载/带宽元数据
    // 由增强型探测回调填充（如向 Relay HTTP /metrics 端点拉取），
    // 默认探测（TCP connect）不填充，保持 0。
    int load_percent{0};   // Relay 当前负载百分比 [0,100]；0 表示未知
    int uplink_bps{0};     // Relay 上行带宽估计（bps）；0 表示未知
};

/// 健康探测回调（注入式，便于测试）
/// @param relay_url Relay 服务器 URL
/// @return 探测结果
using HealthProbeCallback = std::function<HealthProbeResult(const base::RelayUrl &relay_url)>;

/// 默认探测回调（实际网络 ping）
HealthProbeResult default_health_probe(const base::RelayUrl &relay_url);

// ============================================================================
// Relay 负载上报（v2.0 Phase 1 交付物 5：层级化 Relay 架构）
// ============================================================================

/// Relay 负载上报数据结构
/// Relay 服务定期（5s）向 orchestrator 上报，节点拉取时下发到本地 RelayPool。
/// linoh 侧先定义数据契约，orchestrator 集成留待交付物 7。
struct RelayLoadReport {
    base::RelayUrl url;
    RelayRole role{RelayRole::Region};
    GeoRegion region{GeoRegion::Unknown};
    std::uint32_t connections{0};       // 当前连接数
    std::uint64_t bytes_in{0};          // 入站字节累计
    std::uint64_t bytes_out{0};         // 出站字节累计
    int load_percent{0};                // load = connections / capacity * 100
    int uplink_bps{0};                  // 上行带宽估计
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Relay 池配置
// ============================================================================

struct RelayPoolConfig {
    /// 健康检查间隔
    std::chrono::milliseconds check_interval{std::chrono::milliseconds(60000)};

    /// 探测超时
    std::chrono::milliseconds probe_timeout{std::chrono::milliseconds(5000)};

    /// 降级 RTT 阈值（超过此值标记为 Degraded）
    std::chrono::milliseconds degraded_rtt_threshold{std::chrono::milliseconds(500)};

    /// 熔断器配置
    CircuitBreakerConfig breaker_config{};

    /// 最大保留的 Relay 数量
    std::size_t max_relays{10};

    /// 是否启用自动故障切换
    bool enable_auto_failover{true};

    /// 主 Relay 切换的最小间隔（防止抖动）
    std::chrono::milliseconds failover_min_interval{std::chrono::milliseconds(10000)};

    // v2.0 Phase 1：多维选择配置
    /// 本地节点所在地理区域（用于跨区域惩罚计算）
    GeoRegion local_region{GeoRegion::Unknown};

    /// 负载过滤阈值：load_percent 超过此值的 Relay 不进入活跃集候选
    /// （全池过载时降级使用，见 select_best 实现）
    int load_filter_threshold{80};

    /// 多维评分权重
    RelayScoreWeights score_weights{};

    /// 活跃集大小：select_best 排序后保留的候选数量
    /// （主用 score 最小者，故障切换时按序取下一个）
    std::size_t active_set_size{3};

    // v2.0 Phase 1 交付物 5：层级化 Relay 架构配置
    /// 是否启用区域→骨干级联选择（local_region != Unknown 时生效）
    /// false 或 local_region==Unknown 时退回原全局策略，保证向后兼容
    bool enable_cascading_select{true};

    /// 主用 Relay 连续失败次数达到阈值后自动切换到活跃集次优
    /// （由 record_failure 触发 do_failover_with_index）
    std::uint32_t failover_failure_threshold{3};
};

// ============================================================================
// Relay 池
// ============================================================================

/// Relay 池：管理多个 Relay 服务器，自动健康检查和故障切换
class RelayPool {
public:
    /// 默认构造（使用默认探测回调）
    explicit RelayPool(RelayPoolConfig config = {});

    /// 注入式构造（用于测试）
    RelayPool(RelayPoolConfig config, HealthProbeCallback probe);

    /// v1.7.0.6 (H2-2 fix): 析构时停止后台健康检查线程
    ~RelayPool();

    /// 添加 Relay 服务器
    /// @param url Relay URL
    /// @param pinned 是否固定（不可淘汰）
    void add_relay(base::RelayUrl url, bool pinned = false);

    /// 移除 Relay 服务器（pinned 的不可移除）
    /// @return 是否移除成功
    bool remove_relay(const base::RelayUrl &url);

    /// 获取所有 Relay 条目
    std::vector<RelayEntry> get_all_relays() const;

    /// 获取可用的 Relay 条目（健康或降级）
    std::vector<RelayEntry> get_usable_relays() const;

    /// 选择最佳 Relay（按多维 score 排序）
    /// v2.0 Phase 1：filter(is_usable, load<=threshold) → sort(score) → take best
    /// 全池过载或全池不可用时降级使用，保证总能返回最优候选（除非池空）。
    /// @return 最佳 Relay 条目；池空返回 nullopt
    std::optional<RelayEntry> select_best() const;

    /// 选择最佳 Relay URL（便捷方法）
    std::optional<base::RelayUrl> select_best_url() const;

    /// v2.0 Phase 1：获取活跃集（按多维 score 升序排序的前 N 个候选）
    /// N = config_.active_set_size。主用 [0]，故障切换按序取下一个。
    /// 过滤逻辑同 select_best：先过滤 usable+load，全池过载时降级。
    std::vector<RelayEntry> get_active_set() const;

    /// v2.0 Phase 1：设置本地节点地理区域（影响跨区域惩罚计算）
    void set_local_region(GeoRegion region);

    /// v2.0 Phase 1：获取本地节点地理区域
    GeoRegion local_region() const { return config_.local_region; }

    /// v2.0 Phase 1：外部设置 Relay 的多维指标
    /// 用于 orchestrator 下发 region/load/uplink/distance 的场景
    /// （探针无法获取的静态/半静态信息）
    /// @param url Relay URL
    /// @param load_percent 负载百分比 [0,100]；<0 表示不更新
    /// @param uplink_bps 上行带宽 bps；<0 表示不更新
    /// @param region 地理区域；GeoRegion::Unknown 表示不更新（需显式设置）
    /// @param geo_distance_km 地理距离 km；<0 表示不更新
    /// @return 是否设置成功（URL 存在）
    bool set_relay_metrics(const base::RelayUrl &url,
                           int load_percent,
                           int uplink_bps,
                           GeoRegion region = GeoRegion::Unknown,
                           int geo_distance_km = -1);

    // v2.0 Phase 1 交付物 5：层级化 Relay 架构 API ----------------------------

    /// 设置 Relay 角色层级（区域 / 骨干）
    /// @return 是否设置成功（URL 存在）
    bool set_relay_role(const base::RelayUrl &url, RelayRole role);

    /// 批量更新 Relay 负载上报（来自 orchestrator 下发）
    /// 匹配 URL 的条目更新 load/connections/bytes/uplink 等字段；
    /// 未匹配的 URL 忽略（不新增条目，新增需走 add_relay）。
    /// @return 实际更新成功的条目数
    std::size_t update_load_reports(const std::vector<RelayLoadReport> &reports);

    // === V3-B: 跨域感知选择 ================================================

    /// 跨域连接场景选择最佳 Relay
    /// 行为（V3-B 协议规范 §5.2.2）：
    ///   - 优先选 role=Backbone 的骨干 Relay（跨域可达）
    ///   - 跳过本区域 Relay（跨域穿透通常失败）
    ///   - 按 score(local_region, weights) 升序排序，取最优
    /// 降级链：骨干(usable+load) → 区域(usable) → 全局(usable, 忽略 load)
    /// @return 最佳跨域 Relay；无可用返回 nullopt
    std::optional<RelayEntry> select_for_cross_domain() const;

    /// 设置跨域骨干 Relay 列表（由 orchestrator 下发）
    /// @param backbone_urls 跨域骨干 Relay URL 列表
    /// @note 自动设置 role=Backbone 并 pin（不可淘汰）；
    ///       已存在的 URL 仅更新 role/pinned，不重复入池
    void set_cross_domain_backbone_relays(const std::vector<base::RelayUrl> &backbone_urls);

    /// 故障切换回调类型：from_url 旧主用，to_url 新主用，reason 触发原因
    using FailoverCallback = std::function<void(const base::RelayUrl &from_url,
                                                const base::RelayUrl &to_url,
                                                const std::string &reason)>;

    /// 活跃集耗尽回调类型：所有活跃集候选均不可用，触发全量刷新
    using ActiveSetExhaustedCallback = std::function<void()>;

    /// 注册故障切换回调（主用切换到活跃集次优时触发）
    void set_failover_callback(FailoverCallback cb);

    /// 注册活跃集耗尽回调（活跃集全部不可用时触发，上层应拉取最新 Relay 列表）
    void set_active_set_exhausted_callback(ActiveSetExhaustedCallback cb);

    /// 主动触发健康检查（同步）
    /// 检查所有 Relay 的健康状态
    void check_all_sync();

    /// 主动触发健康检查（异步）
    /// @return future，完成后可获取
    std::future<void> check_all_async();

    /// 单个 Relay 健康检查
    /// @param url Relay URL
    /// @return 探测结果
    HealthProbeResult check_one(const base::RelayUrl &url);

    /// 记录请求成功
    void record_success(const base::RelayUrl &url);

    /// 记录请求失败
    void record_failure(const base::RelayUrl &url);

    /// 获取当前主 Relay（最佳可用）
    std::optional<base::RelayUrl> current_primary() const;

    /// 获取 Relay 数量
    std::size_t size() const;

    /// 是否为空
    bool empty() const { return size() == 0; }

    /// v1.7.0.6 (H2-2 fix): 启动后台周期性健康检查线程
    /// 线程按 config_.check_interval 周期调用 check_all_sync()，
    /// 池为空时自动退出，再次调用 start_health_check_thread() 重启
    void start_health_check_thread();

    /// v1.7.0.6 (H2-2 fix): 停止后台健康检查线程
    void stop_health_check_thread();

    /// 配置
    const RelayPoolConfig &config() const { return config_; }

private:
    mutable std::mutex mutex_;
    RelayPoolConfig config_;
    HealthProbeCallback probe_;
    std::vector<std::unique_ptr<RelayEntry>> entries_;
    std::vector<std::unique_ptr<CircuitBreaker>> breakers_;
    base::RelayUrl last_primary_;
    std::chrono::system_clock::time_point last_failover_time_;

    // v1.7.0.6 (H2-2 fix): 后台周期性健康检查
    std::thread health_thread_;
    std::atomic<bool> health_thread_running_{false};
    std::condition_variable_any health_cv_;
    std::mutex health_mu_;

    // v2.0 Phase 1 交付物 5：层级化 Relay 状态
    /// 当前活跃集索引（主用 = cached_active_set_[current_active_idx_]）
    /// mutable 因 select_best 等 const 方法可能间接读取（do_failover_with_index 内部修改）
    mutable std::size_t current_active_idx_{0};
    /// 缓存的活跃集（在 select_best/get_active_set 时填充，advance 时复用）
    /// 避免失败后 score 变化导致活跃集重排，保证 failover 按原始排序推进
    mutable std::vector<RelayEntry> cached_active_set_;
    /// 故障切换回调（主用切换时触发，锁外调用防重入）
    FailoverCallback failover_callback_;
    /// 活跃集耗尽回调（全部候选不可用时触发，锁外调用）
    ActiveSetExhaustedCallback exhausted_callback_;

    /// 内部：查找条目（不加锁）
    RelayEntry *find_entry(const base::RelayUrl &url);
    const RelayEntry *find_entry(const base::RelayUrl &url) const;

    /// 内部：查找熔断器
    CircuitBreaker *find_breaker(const base::RelayUrl &url);

    /// 内部：应用探测结果到条目
    void apply_probe_result(RelayEntry &entry, const HealthProbeResult &result);

    /// 内部：执行故障切换
    /// @return 新的主 Relay；无可用返回 nullopt
    std::optional<base::RelayUrl> do_failover();

    /// v2.0 Phase 1 交付物 5：内部级联选择实现
    /// 按 区域 Region → 骨干 Backbone → 全局降级 顺序选择
    /// @param want_count 返回的活跃集大小（取 min(want_count, active_set_size)）
    std::vector<RelayEntry> select_cascading_locked(std::size_t want_count) const;

    /// v2.0 Phase 1 交付物 5：主用连续失败超阈值时推进活跃集索引
    /// @param failed_url 失败的主用 URL
    /// @return 新主用 URL；活跃集耗尽返回 nullopt 并触发 exhausted_callback_
    std::optional<base::RelayUrl> advance_active_idx_locked(const base::RelayUrl &failed_url);
};

// ============================================================================
// 故障切换控制器
// ============================================================================

/// 故障切换事件
struct FailoverEvent {
    base::RelayUrl from_url;
    base::RelayUrl to_url;
    std::chrono::system_clock::time_point timestamp;
    std::string reason;
};

/// 故障切换控制器
class FailoverController {
public:
    using FailoverCallback = std::function<void(const FailoverEvent &)>;

    /// 构造
    /// @param pool Relay 池
    /// @param callback 故障切换回调（可选）
    explicit FailoverController(std::shared_ptr<RelayPool> pool,
                                FailoverCallback callback = nullptr);

    /// 触发故障切换
    /// @param reason 触发原因
    /// @return 新的主 Relay；无可用返回 nullopt
    std::optional<base::RelayUrl> trigger_failover(const std::string &reason);

    /// 获取历史故障切换事件
    std::vector<FailoverEvent> get_history() const;

    /// 清空历史
    void clear_history();

    /// 启用/禁用
    void set_enabled(bool enabled) { enabled_ = enabled; }
    bool is_enabled() const { return enabled_; }

private:
    std::shared_ptr<RelayPool> pool_;
    FailoverCallback callback_;
    std::vector<FailoverEvent> history_;
    mutable std::mutex mutex_;
    bool enabled_{true};
    base::RelayUrl last_primary_;
    bool has_last_primary_{false};
};

} // namespace linoh::nat
