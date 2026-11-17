// connection_migration.hpp — v4.0.4 M22 连接迁移协调器（RFC 9000 §9）
//
// 设计来源：linoh 进化路线图 §10.2.5（M22 子任务）
//   - 跨网节点（如移动 worker）切换网络时 IP 变化，当前连接断开需重建，中断推理链路
//   - 利用 QUIC 原生 Connection Migration，检测本地 IP 变化 → PATH_CHALLENGE →
//     PATH_RESPONSE → 迁移完成，IP 切换不断连
//
// 与现有 PathMigrationManager（protocol/path_migration.hpp）的关系：
//   - PathMigrationManager 提供底层路径验证原语（challenge/response 生成+验证、CID 管理、
//     路径质量监控、路径放弃策略）
//   - ConnectionMigrationCoordinator 是更高层的协调器，管理迁移生命周期：
//     ① IP 变化检测决策 ② 迁移状态机 ③ 旧路径清理定时 ④ 统计和事件追踪
//   - 协调器调用 PathMigrationManager 的原语执行实际验证，自身不直接操作网络
//
// 迁移状态机：
//   Idle ──(detect IP change)──> Validating ──(PATH_RESPONSE ok)──> Migrating
//      │                              │                                │
//      │                              │ (timeout/retry exhausted)      │
//      │                              v                                v
//      │                           Failed                          Completed
//      │                                                              │
//      <──────────(cleanup old path)──────────────────────────────────┘
//
// v4.0.4 范围：
//   1. MigrationConfig 配置结构（enable_migration / path_validation_timeout /
//      max_path_id / old_path_cleanup_grace / fec_fallback_during_migration）
//   2. MigrationState 状态机枚举（Idle / Validating / Migrating / Completed / Failed）
//   3. MigrationEvent 事件记录（timestamp / state / old_addr / new_addr / reason）
//   4. MigrationStats 统计（total / successful / failed / validations_sent /
//      validations_received / old_paths_cleaned / last_duration）
//   5. ConnectionMigrationCoordinator 协调器类（线程安全 shared_mutex 多读单写）
//      - should_migrate：决策是否应发起迁移
//      - initiate_migration：生成 PATH_CHALLENGE，进入 Validating 状态
//      - on_challenge_sent：记录挑战发送时间（用于超时重试）
//      - on_response_received：验证 PATH_RESPONSE 匹配，进入 Migrating 状态
//      - complete_migration：完成迁移，进入 Completed 状态
//      - fail_migration：迁移失败，进入 Failed 状态
//      - should_cleanup_old_path：旧路径清理决策
//      - needs_retry / is_validation_expired：超时和重试逻辑
//      - reset：重置到 Idle 状态
//      - stats / events：统计和事件查询

#pragma once

#include "linoh/protocol/path_migration.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace linoh::endpoint {

// ============================================================================
// 常量
// ============================================================================

/// 默认路径验证超时（3 秒，RFC 9000 §9 建议值）
constexpr std::chrono::seconds kDefaultPathValidationTimeout{3};

/// 默认旧路径清理宽限期（2 秒，验证成功后保留旧路径的时间）
constexpr std::chrono::seconds kDefaultOldPathCleanupGrace{2};

/// 最大 PATH_CHALLENGE 重试次数（与 PathMigrationManager::kMaxChallengeAttempts 对齐）
constexpr std::uint8_t kMaxMigrationRetries = 3;

/// 最大事件历史记录数（防内存无限增长）
constexpr std::size_t kMaxMigrationEvents = 64;

// ============================================================================
// MigrationConfig — 迁移配置
// ============================================================================

/// 连接迁移配置（RFC 9000 §9）
///
/// 配置迁移行为，包括是否启用、路径验证超时、旧路径清理等。
struct MigrationConfig {
    /// 是否启用连接迁移（默认 true）
    /// 禁用时 IP 变化不触发迁移，等价旧行为（连接断开重建）
    bool enable_migration{true};

    /// 路径验证超时（秒，默认 3）
    /// PATH_CHALLENGE 发送后等待 PATH_RESPONSE 的最长时间
    /// 超时后重试，超过 kMaxMigrationRetries 次则迁移失败
    std::chrono::seconds path_validation_timeout{kDefaultPathValidationTimeout};

    /// 最大路径 ID（默认 4）
    /// 限制同时活跃的路径数量，防止路径爆炸
    std::uint8_t max_path_id{4};

    /// 旧路径清理宽限期（秒，默认 2）
    /// 迁移完成后保留旧路径的时间，确保在途包到达
    std::chrono::seconds old_path_cleanup_grace{kDefaultOldPathCleanupGrace};

    /// 迁移期间是否启用 FEC 兜底（默认 true）
    /// 路径验证期间启用 FEC 防丢包
    bool fec_fallback_during_migration{true};

    // --- 工厂方法 ---

    /// worker 节点默认配置（启用迁移，3s 超时，2s 清理宽限）
    static MigrationConfig default_for_worker() {
        return MigrationConfig{};
    }

    /// master 节点默认配置（启用迁移，更长超时 5s，更长清理 3s）
    static MigrationConfig default_for_master() {
        MigrationConfig cfg;
        cfg.path_validation_timeout = std::chrono::seconds{5};
        cfg.old_path_cleanup_grace = std::chrono::seconds{3};
        return cfg;
    }

    /// 禁用迁移（向后兼容，等价旧行为）
    static MigrationConfig disabled() {
        MigrationConfig cfg;
        cfg.enable_migration = false;
        return cfg;
    }
};

// ============================================================================
// MigrationState — 迁移状态机
// ============================================================================

/// 连接迁移状态机
///
/// 状态转换：
///   Idle ──(initiate_migration)──> Validating
///   Validating ──(on_response_received ok)──> Migrating
///   Validating ──(timeout/retry exhausted)──> Failed
///   Migrating ──(complete_migration)──> Completed
///   Completed ──(cleanup/reset)──> Idle
///   Failed ──(reset)──> Idle
enum class MigrationState : std::uint8_t {
    Idle       = 0,  // 无迁移活动
    Validating = 1,  // 已发送 PATH_CHALLENGE，等待 PATH_RESPONSE
    Migrating  = 2,  // 路径验证成功，正在切换到新路径
    Completed  = 3,  // 迁移完成，旧路径清理中
    Failed     = 4,  // 迁移失败（验证超时/重试耗尽）
};

/// MigrationState 转字符串
std::string_view to_string(MigrationState state);

/// 迁移是否处于活跃状态（Validating / Migrating）
constexpr bool is_active_state(MigrationState state) {
    return state == MigrationState::Validating || state == MigrationState::Migrating;
}

// ============================================================================
// MigrationEvent — 迁移事件记录
// ============================================================================

/// 迁移事件记录（用于诊断和审计）
struct MigrationEvent {
    std::uint64_t event_id{0};                          ///< 事件 ID（递增）
    std::chrono::steady_clock::time_point timestamp;    ///< 事件时间
    MigrationState state{MigrationState::Idle};          ///< 触发时的状态
    std::string old_address;                            ///< 旧地址描述
    std::string new_address;                            ///< 新地址描述
    std::string reason;                                 ///< 触发原因
};

// ============================================================================
// MigrationStats — 迁移统计
// ============================================================================

/// 迁移统计
struct MigrationStats {
    std::uint64_t total_migrations{0};              ///< 总迁移次数（含失败）
    std::uint64_t successful_migrations{0};         ///< 成功迁移次数
    std::uint64_t failed_migrations{0};             ///< 失败迁移次数
    std::uint64_t path_validations_sent{0};         ///< 发送的 PATH_CHALLENGE 数
    std::uint64_t path_validations_received{0};     ///< 收到的 PATH_RESPONSE 数
    std::uint64_t old_paths_cleaned{0};             ///< 清理的旧路径数
    std::chrono::microseconds last_migration_duration{0};  ///< 上次迁移耗时
};

// ============================================================================
// ConnectionMigrationCoordinator — 连接迁移协调器
// ============================================================================

/// 连接迁移协调器（per-Connection 单例）
///
/// 管理 QUIC 连接迁移的完整生命周期，基于 RFC 9000 §9。
/// 与 PathMigrationManager 配合：
///   - 协调器负责状态机和决策
///   - PathMigrationManager 负责底层路径验证原语
///
/// 线程安全：shared_mutex 多读单写。
///   - 写操作（initiate_migration / on_response_received / complete_migration 等）用独占锁
///   - 读操作（state / stats / events）用共享锁
///
/// 使用流程：
///   1. 检测到本地 IP 变化时调用 should_migrate() 决策
///   2. should_migrate() 返回 true 后调用 initiate_migration() 生成 PATH_CHALLENGE
///   3. 发送 PATH_CHALLENGE 后调用 on_challenge_sent() 记录发送时间
///   4. 收到 PATH_RESPONSE 时调用 on_response_received() 验证
///   5. 验证成功后调用 complete_migration() 完成迁移
///   6. 迁移完成后等待 old_path_cleanup_grace，再清理旧路径
///   7. 若验证超时，调用 needs_retry() 决策是否重试，超过上限则 fail_migration()
class ConnectionMigrationCoordinator {
public:
    /// 时间源类型（便于测试注入）
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    /// 构造迁移协调器
    ///
    /// @param config 迁移配置
    explicit ConnectionMigrationCoordinator(MigrationConfig config = MigrationConfig{});

    // --- 配置 ---

    /// 获取当前配置
    MigrationConfig config() const;

    /// 更新配置（仅在 Idle 状态允许更新）
    /// @return true 表示更新成功，false 表示当前处于活跃迁移状态不允许更新
    bool set_config(const MigrationConfig &config);

    // --- 状态查询 ---

    /// 当前迁移状态
    MigrationState state() const;

    /// 是否正在迁移（Validating / Migrating）
    bool is_migrating() const;

    /// 是否启用迁移
    bool is_migration_enabled() const;

    // --- 迁移决策 ---

    /// 决策是否应发起迁移
    ///
    /// @param old_local_addr 旧本地地址描述（如 "192.168.1.100:9001"）
    /// @param new_local_addr 新本地地址描述
    /// @return true 表示应发起迁移（迁移已启用 + 地址确实变化 + 当前非活跃状态）
    bool should_migrate(const std::string &old_local_addr,
                        const std::string &new_local_addr) const;

    // --- 迁移流程 ---

    /// 发起迁移：生成 PATH_CHALLENGE，进入 Validating 状态
    ///
    /// @param old_addr 旧地址描述
    /// @param new_addr 新地址描述
    /// @param reason   迁移原因（如 "WiFi→LTE"、"NAT rebinding"）
    /// @param now      当前时间点（默认 Clock::now()）
    /// @return PATH_CHALLENGE 帧（调用方负责发送到对端），nullopt 表示无法发起
    std::optional<protocol::PathChallengeFrame> initiate_migration(
        const std::string &old_addr,
        const std::string &new_addr,
        const std::string &reason,
        TimePoint now = Clock::now());

    /// 记录 PATH_CHALLENGE 已发送（用于超时重试计时）
    ///
    /// @param challenge 发送的挑战帧
    /// @param now       发送时间（默认 Clock::now()）
    void on_challenge_sent(const protocol::PathChallengeFrame &challenge,
                           TimePoint now = Clock::now());

    /// 收到 PATH_RESPONSE 时调用，验证匹配
    ///
    /// @param response 收到的响应帧
    /// @return true 表示验证成功（数据匹配 + 处于 Validating 状态），自动进入 Migrating 状态
    bool on_response_received(const protocol::PathResponseFrame &response,
                              TimePoint now = Clock::now());

    /// 完成迁移：切换到新路径，进入 Completed 状态
    ///
    /// @param now 当前时间点（默认 Clock::now()）
    void complete_migration(TimePoint now = Clock::now());

    /// 迁移失败：回退到旧路径或断开
    ///
    /// @param reason 失败原因
    void fail_migration(const std::string &reason);

    // --- 旧路径清理 ---

    /// 决策是否应清理旧路径
    ///
    /// @param now 当前时间点（默认 Clock::now()）
    /// @return true 表示已完成迁移且超过 old_path_cleanup_grace
    bool should_cleanup_old_path(TimePoint now = Clock::now()) const;

    /// 清理旧路径完成，重置到 Idle 状态
    void cleanup_completed();

    // --- 超时和重试 ---

    /// 检查是否需要重试 PATH_CHALLENGE
    ///
    /// @param now 当前时间点（默认 Clock::now()）
    /// @return true 表示处于 Validating 状态且超时且重试次数未耗尽
    bool needs_retry(TimePoint now = Clock::now()) const;

    /// 获取当前重试次数
    std::uint8_t retry_count() const;

    /// 检查路径验证是否超时
    ///
    /// @param now 当前时间点（默认 Clock::now()）
    /// @return true 表示处于 Validating 状态且超过 path_validation_timeout
    bool is_validation_expired(TimePoint now = Clock::now()) const;

    /// 执行重试：生成新的 PATH_CHALLENGE
    ///
    /// @param now 当前时间点（默认 Clock::now()）
    /// @return 新的 PATH_CHALLENGE 帧，nullopt 表示无法重试（非 Validating 状态或重试耗尽）
    std::optional<protocol::PathChallengeFrame> retry(TimePoint now = Clock::now());

    // --- 重置 ---

    /// 重置到 Idle 状态（清除当前迁移上下文，保留统计和历史事件）
    void reset();

    // --- 统计和事件 ---

    /// 获取统计快照
    MigrationStats stats() const;

    /// 获取事件历史（最新在前，最多 kMaxMigrationEvents 条）
    std::vector<MigrationEvent> events() const;

    /// 获取当前迁移上下文（用于诊断）
    struct MigrationContext {
        std::string old_address;
        std::string new_address;
        std::string reason;
        std::uint8_t retry_count{0};
        TimePoint migration_start_time{};
        TimePoint challenge_sent_time{};
        std::array<std::uint8_t, 8> current_challenge_data{};
    };
    std::optional<MigrationContext> current_context() const;

private:
    /// 状态转换（内部，调用方已持锁）
    void transition_to(MigrationState new_state, const std::string &reason, TimePoint now);

    /// 记录事件（内部，调用方已持锁）
    void record_event(MigrationState state,
                      const std::string &old_addr,
                      const std::string &new_addr,
                      const std::string &reason,
                      TimePoint now);

    /// 生成随机 8 字节挑战数据
    static std::array<std::uint8_t, 8> generate_challenge_data();

    mutable std::mutex mu_;  // 简化：用 mutex（协调器操作不频繁，不需要读写锁）

    MigrationConfig config_;
    MigrationState state_{MigrationState::Idle};
    MigrationStats stats_;
    std::vector<MigrationEvent> events_;
    std::uint64_t next_event_id_{0};

    // 当前迁移上下文（仅 Validating/Migrating/Completed/Failed 状态有效）
    MigrationContext context_{};
};

} // namespace linoh::endpoint
