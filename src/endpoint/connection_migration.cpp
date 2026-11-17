/// @file connection_migration.cpp
/// v4.0.4 M22 连接迁移协调器实现（RFC 9000 §9）

#include "linoh/endpoint/connection_migration.hpp"
#include "linoh/util/crypto.hpp"

#include <algorithm>
#include <cstring>

namespace linoh::endpoint {

// ============================================================================
// MigrationState 辅助函数
// ============================================================================

std::string_view to_string(MigrationState state) {
    switch (state) {
        case MigrationState::Idle:       return "Idle";
        case MigrationState::Validating: return "Validating";
        case MigrationState::Migrating:  return "Migrating";
        case MigrationState::Completed:  return "Completed";
        case MigrationState::Failed:     return "Failed";
        default:                          return "Unknown";
    }
}

// ============================================================================
// ConnectionMigrationCoordinator
// ============================================================================

ConnectionMigrationCoordinator::ConnectionMigrationCoordinator(MigrationConfig config)
    : config_(config) {
}

// --- 配置 ---

MigrationConfig ConnectionMigrationCoordinator::config() const {
    std::lock_guard<std::mutex> lk(mu_);
    return config_;
}

bool ConnectionMigrationCoordinator::set_config(const MigrationConfig &config) {
    std::lock_guard<std::mutex> lk(mu_);
    // 仅在 Idle 状态允许更新配置
    if (is_active_state(state_) || state_ == MigrationState::Completed) {
        return false;
    }
    config_ = config;
    return true;
}

// --- 状态查询 ---

MigrationState ConnectionMigrationCoordinator::state() const {
    std::lock_guard<std::mutex> lk(mu_);
    return state_;
}

bool ConnectionMigrationCoordinator::is_migrating() const {
    std::lock_guard<std::mutex> lk(mu_);
    return is_active_state(state_);
}

bool ConnectionMigrationCoordinator::is_migration_enabled() const {
    std::lock_guard<std::mutex> lk(mu_);
    return config_.enable_migration;
}

// --- 迁移决策 ---

bool ConnectionMigrationCoordinator::should_migrate(
    const std::string &old_local_addr,
    const std::string &new_local_addr) const {
    std::lock_guard<std::mutex> lk(mu_);
    // 条件 1：迁移已启用
    if (!config_.enable_migration) return false;
    // 条件 2：地址确实变化
    if (old_local_addr == new_local_addr) return false;
    // 条件 3：当前非活跃迁移状态
    if (is_active_state(state_)) return false;
    return true;
}

// --- 迁移流程 ---

std::optional<protocol::PathChallengeFrame>
ConnectionMigrationCoordinator::initiate_migration(
    const std::string &old_addr,
    const std::string &new_addr,
    const std::string &reason,
    TimePoint now) {
    std::lock_guard<std::mutex> lk(mu_);

    // 前置校验：迁移已启用 + 当前非活跃状态
    if (!config_.enable_migration) return std::nullopt;
    if (is_active_state(state_)) return std::nullopt;

    // 初始化迁移上下文
    context_.old_address = old_addr;
    context_.new_address = new_addr;
    context_.reason = reason;
    context_.retry_count = 0;
    context_.migration_start_time = now;
    context_.challenge_sent_time = now;
    context_.current_challenge_data = generate_challenge_data();

    // 状态转换：Idle → Validating
    transition_to(MigrationState::Validating, reason, now);

    // 构造 PATH_CHALLENGE 帧
    protocol::PathChallengeFrame frame;
    frame.data = context_.current_challenge_data;
    return frame;
}

void ConnectionMigrationCoordinator::on_challenge_sent(
    const protocol::PathChallengeFrame &challenge,
    TimePoint now) {
    std::lock_guard<std::mutex> lk(mu_);

    // 记录发送时间（用于超时重试计时）
    context_.challenge_sent_time = now;

    // 统计
    ++stats_.path_validations_sent;
}

bool ConnectionMigrationCoordinator::on_response_received(
    const protocol::PathResponseFrame &response,
    TimePoint now) {
    std::lock_guard<std::mutex> lk(mu_);

    // 仅在 Validating 状态处理响应
    if (state_ != MigrationState::Validating) return false;

    // 统计
    ++stats_.path_validations_received;

    // 验证响应数据匹配
    if (std::memcmp(response.data.data(),
                    context_.current_challenge_data.data(),
                    8) != 0) {
        // 数据不匹配，可能是旧挑战的响应或伪造
        return false;
    }

    // 验证成功，进入 Migrating 状态
    transition_to(MigrationState::Migrating, "path validated", now);
    return true;
}

void ConnectionMigrationCoordinator::complete_migration(TimePoint now) {
    std::lock_guard<std::mutex> lk(mu_);

    // 仅在 Migrating 状态允许完成
    if (state_ != MigrationState::Migrating) return;

    // 计算迁移耗时
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        now - context_.migration_start_time);
    stats_.last_migration_duration = duration;

    // 统计
    ++stats_.successful_migrations;

    // 状态转换：Migrating → Completed
    transition_to(MigrationState::Completed, "migration completed", now);
}

void ConnectionMigrationCoordinator::fail_migration(const std::string &reason) {
    std::lock_guard<std::mutex> lk(mu_);

    // 仅在活跃状态允许失败
    if (!is_active_state(state_)) return;

    // 统计
    ++stats_.failed_migrations;

    // 状态转换 → Failed
    transition_to(MigrationState::Failed, reason, Clock::now());
}

// --- 旧路径清理 ---

bool ConnectionMigrationCoordinator::should_cleanup_old_path(TimePoint now) const {
    std::lock_guard<std::mutex> lk(mu_);

    // 仅在 Completed 状态检查清理
    if (state_ != MigrationState::Completed) return false;

    // 检查是否超过清理宽限期
    // 完成时间 = 进入 Completed 状态的时间（记录在最近事件的 timestamp 中）
    // 这里用 last_migration_duration 的结束时间近似：migration_start + duration + grace
    // 更精确的做法是记录 complete_time，但为简化用 events_ 中最后一条 Completed 事件的时间
    if (events_.empty()) return false;

    const auto &last_event = events_.back();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_event.timestamp);
    return elapsed >= config_.old_path_cleanup_grace;
}

void ConnectionMigrationCoordinator::cleanup_completed() {
    std::lock_guard<std::mutex> lk(mu_);

    // 仅在 Completed/Failed 状态允许清理重置
    if (state_ != MigrationState::Completed && state_ != MigrationState::Failed) return;

    if (state_ == MigrationState::Completed) {
        ++stats_.old_paths_cleaned;
    }

    // 重置到 Idle（保留统计和历史事件）
    state_ = MigrationState::Idle;
    context_ = MigrationContext{};
}

// --- 超时和重试 ---

bool ConnectionMigrationCoordinator::needs_retry(TimePoint now) const {
    std::lock_guard<std::mutex> lk(mu_);

    // 仅在 Validating 状态检查重试
    if (state_ != MigrationState::Validating) return false;

    // 检查重试次数未耗尽
    if (context_.retry_count >= kMaxMigrationRetries) return false;

    // 检查是否超时
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - context_.challenge_sent_time);
    return elapsed >= config_.path_validation_timeout;
}

std::uint8_t ConnectionMigrationCoordinator::retry_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return context_.retry_count;
}

bool ConnectionMigrationCoordinator::is_validation_expired(TimePoint now) const {
    std::lock_guard<std::mutex> lk(mu_);

    // 仅在 Validating 状态检查超时
    if (state_ != MigrationState::Validating) return false;

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - context_.challenge_sent_time);
    return elapsed >= config_.path_validation_timeout;
}

std::optional<protocol::PathChallengeFrame>
ConnectionMigrationCoordinator::retry(TimePoint now) {
    std::lock_guard<std::mutex> lk(mu_);

    // 仅在 Validating 状态允许重试
    if (state_ != MigrationState::Validating) return std::nullopt;

    // 检查重试次数
    if (context_.retry_count >= kMaxMigrationRetries) return std::nullopt;

    // 检查是否确实超时（防止过早重试）
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - context_.challenge_sent_time);
    if (elapsed < config_.path_validation_timeout) return std::nullopt;

    // 生成新挑战
    context_.current_challenge_data = generate_challenge_data();
    context_.challenge_sent_time = now;
    ++context_.retry_count;
    // 注意：path_validations_sent 由 on_challenge_sent 统计（与 initiate_migration 一致）

    // 构造 PATH_CHALLENGE 帧
    protocol::PathChallengeFrame frame;
    frame.data = context_.current_challenge_data;
    return frame;
}

// --- 重置 ---

void ConnectionMigrationCoordinator::reset() {
    std::lock_guard<std::mutex> lk(mu_);
    state_ = MigrationState::Idle;
    context_ = MigrationContext{};
}

// --- 统计和事件 ---

MigrationStats ConnectionMigrationCoordinator::stats() const {
    std::lock_guard<std::mutex> lk(mu_);
    return stats_;
}

std::vector<MigrationEvent> ConnectionMigrationCoordinator::events() const {
    std::lock_guard<std::mutex> lk(mu_);
    // 返回最新在前（events_ 内部是时间顺序，反转使最新在前）
    std::vector<MigrationEvent> result(events_.rbegin(), events_.rend());
    return result;
}

std::optional<ConnectionMigrationCoordinator::MigrationContext>
ConnectionMigrationCoordinator::current_context() const {
    std::lock_guard<std::mutex> lk(mu_);
    if (state_ == MigrationState::Idle) return std::nullopt;
    return context_;
}

// --- 内部方法 ---

void ConnectionMigrationCoordinator::transition_to(
    MigrationState new_state,
    const std::string &reason,
    TimePoint now) {
    // 调用方已持锁
    MigrationState old_state = state_;
    state_ = new_state;

    // 统计：仅 Idle→Validating 计为一次新迁移
    if (old_state == MigrationState::Idle && new_state == MigrationState::Validating) {
        ++stats_.total_migrations;
    }

    // 记录事件
    record_event(new_state, context_.old_address, context_.new_address, reason, now);
}

void ConnectionMigrationCoordinator::record_event(
    MigrationState state,
    const std::string &old_addr,
    const std::string &new_addr,
    const std::string &reason,
    TimePoint now) {
    // 调用方已持锁

    // 容量管理：超过上限删除最旧条目
    if (events_.size() >= kMaxMigrationEvents) {
        events_.erase(events_.begin());
    }

    MigrationEvent event;
    event.event_id = next_event_id_++;
    event.timestamp = now;
    event.state = state;
    event.old_address = old_addr;
    event.new_address = new_addr;
    event.reason = reason;
    events_.push_back(std::move(event));
}

std::array<std::uint8_t, 8>
ConnectionMigrationCoordinator::generate_challenge_data() {
    std::array<std::uint8_t, 8> data{};
    crypto::crypto_random_bytes(std::span<std::uint8_t>(data.data(), 8));
    return data;
}

} // namespace linoh::endpoint
