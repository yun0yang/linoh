#pragma once

// =============================================================================
// peer_error_tracker.hpp — v3.8.0 安全与故障自动化：per-peer 错误计数自动降级
//
// 设计来源：Psyche PeerErrorTracker + linoh 硬约束 17（linoh 故障直接降级节点）
//
// 核心能力：
//   - per-peer 错误计数器（滑动窗口，60s 内 max_errors 次错误自动降级）
//   - 成功通信后 reset 重置计数（恢复健康）
//   - 不驱逐节点（硬约束 1），仅标记 should_degrade 供上层决策
//   - 线程安全（shared_mutex 读写分离，多读单写）
//   - 可配置（max_errors_per_peer / error_window / enabled）
//   - 可禁用（enabled=false 回退旧行为，向后兼容）
//
// 降级策略（上层集成，本模块不直接执行）：
//   - should_degrade=true → 上层设置 linoh_connected=false
//   - orchestrator 检测到 linoh_connected=false → 重新调度（不驱逐）
//   - 降级后定期 clear_degraded 尝试恢复（orchestrator 决策）
//
// 与 v3.7 的关系：
//   - 复用 v3.7.0 的 sha256（无直接依赖，但同属可靠性强化体系）
//   - PeerErrorTracker 放入 linoh-base.lib（仅依赖 base::EndpointId，无 asio 依赖）
//
// 硬约束遵守：
//   - 硬约束 1：不驱逐节点，仅标记降级状态
//   - 硬约束 17：linoh 故障直接降级（本模块提供数据支撑，上层执行降级）
//   - 向后兼容：enabled=false 时所有方法 no-op，行为同 v3.7
// =============================================================================

#include <linoh/base/key.hpp>  // EndpointId = PublicKey

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <unordered_map>

namespace linoh::endpoint {

// =============================================================================
// ErrorType — peer 通信错误类型
// =============================================================================

enum class ErrorType : std::uint8_t {
    ConnectFailed = 0,    // 连接建立失败（dial 失败/超时）
    HandshakeFailed = 1,  // TLS 1.3 AKE 握手失败
    SendFailed = 2,       // 发送数据失败（sendto 错误/stream 写入失败）
    StreamError = 3,      // Stream 读写错误（reset/帧解析失败）
    Timeout = 4,          // 超时（心跳超时/握手超时/数据超时）
};

/// 错误类型转字符串（日志/诊断用）
const char *error_type_name(ErrorType type);

// =============================================================================
// PeerErrorTrackerConfig — 配置
// =============================================================================

struct PeerErrorTrackerConfig {
    /// 滑动窗口内最大错误数，超过则标记降级（Psyche 默认 5）
    std::size_t max_errors_per_peer = 5;

    /// 滑动窗口时长（默认 60s，仅统计窗口内的错误）
    /// 用 milliseconds 以支持测试场景的亚秒窗口（生产用 60000ms = 60s）
    std::chrono::milliseconds error_window{std::chrono::seconds{60}};

    /// 是否启用（默认 true；false 时所有方法 no-op，向后兼容）
    bool enabled = true;

    /// 降级后自动恢复冷却时间（默认 300s，冷却后 clear_degraded 可重试）
    std::chrono::milliseconds degrade_cooldown{std::chrono::seconds{300}};
};

// =============================================================================
// PeerErrorStats — peer 错误统计快照（值类型，线程安全拷贝）
// =============================================================================

struct PeerErrorStats {
    std::size_t current_window_errors = 0;  ///< 当前滑动窗口内错误数
    std::size_t total_errors = 0;           ///< 累计错误总数（不随窗口清理）
    std::optional<ErrorType> last_error_type;  ///< 最后一次错误类型
    std::optional<std::chrono::steady_clock::time_point> last_error_time;  ///< 最后错误时间点
    bool degraded = false;                  ///< 是否已降级
};

// =============================================================================
// PeerErrorTracker — per-peer 错误计数与自动降级判定
// =============================================================================

class PeerErrorTracker {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    /// 构造（默认配置或自定义配置）
    explicit PeerErrorTracker(PeerErrorTrackerConfig config = {});

    // -------------------------------------------------------------------------
    // 核心接口
    // -------------------------------------------------------------------------

    /// 记录一次 peer 通信错误
    /// @param peer peer 的 EndpointId（Ed25519 公钥）
    /// @param type 错误类型
    /// @note 自动清理窗口外过期错误；错误数达到 max_errors 时标记 degraded=true
    /// @note enabled=false 时 no-op
    void record_error(const base::EndpointId &peer, ErrorType type);

    /// 判断 peer 是否应该降级
    /// @return true 若窗口内错误数 >= max_errors 或已标记 degraded
    /// @note enabled=false 时返回 false（不降级，向后兼容）
    bool should_degrade(const base::EndpointId &peer) const;

    /// 重置 peer 的错误计数（成功通信后调用）
    /// @param peer peer 的 EndpointId
    /// @note 清除滑动窗口 + 降级标记 + total_errors 保留（用于长期统计）
    /// @note enabled=false 时 no-op
    void reset(const base::EndpointId &peer);

    // -------------------------------------------------------------------------
    // 查询接口
    // -------------------------------------------------------------------------

    /// 获取 peer 的错误统计快照
    /// @return 统计快照；peer 不存在时返回默认值（全 0）
    PeerErrorStats get_stats(const base::EndpointId &peer) const;

    /// 清除 peer 的降级标记（冷却时间过后尝试恢复）
    /// @param peer peer 的 EndpointId
    /// @return true 若降级标记已清除（冷却已过）；false 仍在冷却中
    /// @note 不清除错误计数，仅清除 degraded 标记
    bool clear_degraded(const base::EndpointId &peer);

    /// 清除所有 peer 的统计（重置跟踪器）
    void clear_all();

    /// 获取被跟踪的 peer 数量
    std::size_t peer_count() const;

    /// 获取已降级 peer 数量
    std::size_t degraded_count() const;

    // -------------------------------------------------------------------------
    // 配置接口
    // -------------------------------------------------------------------------

    const PeerErrorTrackerConfig &config() const { return config_; }

    /// 更新配置（运行时可调，不影响已有统计）
    void update_config(PeerErrorTrackerConfig config);

private:
    /// 内部 peer 状态（需在 prune_expired_locked_ 声明前定义，避免前向声明歧义）
    struct PeerState_ {
        std::deque<std::pair<TimePoint, ErrorType>> recent_errors;  ///< 滑动窗口（时间点 + 错误类型）
        std::size_t total_errors = 0;                               ///< 累计错误总数
        TimePoint degraded_at{};                                    ///< 降级时间点（用于冷却）
        bool degraded = false;                                      ///< 是否已降级
        std::optional<ErrorType> last_error_type;                   ///< 最后错误类型
        TimePoint last_error_time{};                                ///< 最后错误时间
        bool has_last_error = false;                                ///< last_error_time 是否有效
    };

    /// 清理 peer 窗口内过期错误（调用方持写锁）
    void prune_expired_locked_(PeerState_ &state, TimePoint now) const;

    mutable std::shared_mutex mu_;                                   ///< 读写锁（多读单写）
    std::unordered_map<base::EndpointId, PeerState_> peers_;        ///< per-peer 状态表
    PeerErrorTrackerConfig config_;                                  ///< 配置
};

}  // namespace linoh::endpoint
