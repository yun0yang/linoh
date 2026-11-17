/// @file path_migration.cpp
/// QUIC 连接迁移与路径验证实现。

#include "linoh/protocol/path_migration.hpp"
#include "linoh/protocol/path_strategy.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <cstring>

namespace linoh::protocol {

// ============================================================================
// PathMigrationManager
// ============================================================================

PathMigrationManager::PathMigrationManager(std::uint64_t initial_cid_seq)
    : next_cid_seq_(initial_cid_seq) {
}

PathChallengeFrame PathMigrationManager::generate_challenge() {
    PathChallengeFrame frame;
    crypto::crypto_random_bytes(std::span<uint8_t>(frame.data.data(), 8));
    return frame;
}

PathChallengeFrame PathMigrationManager::generate_challenge_with_tuple(const net::FourTuple &tuple) {
    PathChallengeFrame frame = generate_challenge();
    // 关联在 record_challenge_sent_with_tuple 中设置
    (void)tuple;
    return frame;
}

int PathMigrationManager::validate_response(const PathResponseFrame &response) const {
    // v1.7.0.7 H9: 加锁防止 pending_validations_ 在遍历期间被 push_back 导致 TOCTOU
    std::lock_guard<std::mutex> lk(mu_);
    for (int i = 0; i < static_cast<int>(pending_validations_.size()); ++i) {
        if (pending_validations_[i].challenge_data == response.data) {
            return i;
        }
    }
    return -1;  // 不匹配任何 pending challenge
}

void PathMigrationManager::mark_path_validated(int index) {
    // v1.7.0.7 H9: 加锁防止 validate_response 返回 index 后 pending_validations_ 重分配
    //   导致 index 失效或越界
    std::lock_guard<std::mutex> lk(mu_);
    if (index >= 0 && index < static_cast<int>(pending_validations_.size())) {
        pending_validations_[index].validated = true;
        LINOH_INFO("PathMigration: path validated at index=", index);
    }
}

std::optional<net::FourTuple> PathMigrationManager::mark_path_validated_with_tuple(int index) {
    // v1.7.0.7 H9: 加锁保护
    std::lock_guard<std::mutex> lk(mu_);
    if (index < 0 || index >= static_cast<int>(pending_validations_.size())) {
        return std::nullopt;
    }
    pending_validations_[index].validated = true;
    if (pending_validations_[index].has_four_tuple) {
        auto tuple = pending_validations_[index].four_tuple;
        LINOH_INFO("PathMigration: path validated at index=", index,
                   " tuple=", tuple.to_string());
        return tuple;
    }
    LINOH_INFO("PathMigration: path validated at index=", index, " (no tuple associated)");
    return std::nullopt;
}

void PathMigrationManager::record_challenge_sent(const PathChallengeFrame &challenge,
                                                   double now_ms) {
    std::lock_guard<std::mutex> lk(mu_);
    // mp-M5 (v1.7.0.8): 清理已验证条目（validated=true），防止 pending_validations_ 无限增长
    //   mark_path_validated 仅置标志不 erase，已验证条目在后续诊断读取（validated_tuples）
    //   后即无价值，下次发新 challenge 时清理。使用 erase-remove 惯用法。
    pending_validations_.erase(
        std::remove_if(pending_validations_.begin(), pending_validations_.end(),
                       [](const PathValidationState &v) { return v.validated; }),
        pending_validations_.end());
    PathValidationState state;
    state.challenge_data = challenge.data;
    state.challenge_count = 1;
    state.challenge_sent_ms = now_ms;
    pending_validations_.push_back(state);
    // mp-M5: 硬上限兜底，超限时清理最旧未验证条目（极端场景：大量并发路径验证）
    while (pending_validations_.size() > kMaxPendingValidations) {
        LINOH_WARN("PathMigration: pending_validations_ overflow, evicting oldest entry");
        pending_validations_.erase(pending_validations_.begin());
    }
    LINOH_DEBUG("PathMigration: challenge sent, count=", pending_validations_.size());
}

void PathMigrationManager::record_challenge_sent_with_tuple(const PathChallengeFrame &challenge,
                                                              double now_ms,
                                                              const net::FourTuple &tuple) {
    std::lock_guard<std::mutex> lk(mu_);
    // mp-M5 (v1.7.0.8): 同 record_challenge_sent，清理已验证条目
    pending_validations_.erase(
        std::remove_if(pending_validations_.begin(), pending_validations_.end(),
                       [](const PathValidationState &v) { return v.validated; }),
        pending_validations_.end());
    PathValidationState state;
    state.challenge_data = challenge.data;
    state.challenge_count = 1;
    state.challenge_sent_ms = now_ms;
    state.four_tuple = tuple;
    state.has_four_tuple = true;
    pending_validations_.push_back(state);
    while (pending_validations_.size() > kMaxPendingValidations) {
        LINOH_WARN("PathMigration: pending_validations_ overflow, evicting oldest entry");
        pending_validations_.erase(pending_validations_.begin());
    }
    LINOH_DEBUG("PathMigration: challenge sent with tuple ", tuple.to_string(),
                " count=", pending_validations_.size());
}

bool PathMigrationManager::has_challenge_for_tuple(const net::FourTuple &tuple) const {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto &v : pending_validations_) {
        if (v.has_four_tuple && !v.validated && v.four_tuple == tuple) {
            return true;
        }
    }
    return false;
}

std::vector<net::FourTuple> PathMigrationManager::validated_tuples() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<net::FourTuple> result;
    for (const auto &v : pending_validations_) {
        if (v.validated && v.has_four_tuple) {
            result.push_back(v.four_tuple);
        }
    }
    return result;
}

bool PathMigrationManager::has_expired_challenges(double now_ms) const {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto &v : pending_validations_) {
        if (!v.validated &&
            v.challenge_count < kMaxChallengeAttempts &&
            (now_ms - v.challenge_sent_ms) > kChallengeTimeoutMs) {
            return true;
        }
    }
    return false;
}

std::vector<PathChallengeFrame> PathMigrationManager::pending_challenges() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<PathChallengeFrame> result;
    for (auto &v : pending_validations_) {
        if (!v.validated) {
            PathChallengeFrame f;
            f.data = v.challenge_data;
            result.push_back(f);
        }
    }
    return result;
}

void PathMigrationManager::add_cid(const ConnectionIdEntry &entry) {
    std::lock_guard<std::mutex> lk(mu_);
    // 检查是否已存在
    for (auto &e : cid_entries_) {
        if (e.sequence_number == entry.sequence_number) {
            e = entry;  // 更新
            return;
        }
    }
    cid_entries_.push_back(entry);
    LINOH_DEBUG("PathMigration: added CID seq=", entry.sequence_number);
}

void PathMigrationManager::retire_cid(std::uint64_t sequence_number) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto &e : cid_entries_) {
        if (e.sequence_number == sequence_number) {
            e.retired = true;
            LINOH_DEBUG("PathMigration: retired CID seq=", sequence_number);
            return;
        }
    }
}

std::vector<ConnectionIdEntry> PathMigrationManager::active_cids() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<ConnectionIdEntry> result;
    for (auto &e : cid_entries_) {
        if (!e.retired) result.push_back(e);
    }
    return result;
}

std::optional<ConnectionIdEntry> PathMigrationManager::next_available_cid() const {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto &e : cid_entries_) {
        if (!e.retired) return e;
    }
    return std::nullopt;
}

std::size_t PathMigrationManager::active_cid_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::size_t count = 0;
    for (auto &e : cid_entries_) {
        if (!e.retired) ++count;
    }
    return count;
}

// ============================================================================
// P4-A-4: 路径质量监控与放弃策略（借鉴 iroh PR #4296 / #4284）
// ============================================================================

void PathMigrationManager::update_path_quality(std::uint64_t path_id,
                                                 std::chrono::microseconds srtt,
                                                 std::uint32_t loss_count,
                                                 std::chrono::steady_clock::time_point now) {
    // v4.7.0: 检测新路径（用于 emit Opened 事件）
    // 必须在锁内检测、锁外 emit（H10 模式：回调可能反向调用 public 方法）
    bool is_new_path = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        is_new_path = (path_qualities_.find(path_id) == path_qualities_.end());
        auto &q = path_qualities_[path_id];
        q.path_id = path_id;
        q.srtt = srtt;
        q.loss_count = loss_count;
        q.last_seen = now;
        // v3.3.0 突破4: 更新 RTT 基线（EMA, alpha=0.125），用于退化检测
        //   首次采样 baseline=srtt；后续 baseline = baseline*0.875 + srtt*0.125
        //   慢速 EMA 能过滤短期抖动，只在持续 RTT 上涨时触发退化告警
        if (q.srtt_baseline.count() == 0) {
            q.srtt_baseline = srtt;
        } else {
            double base_us = static_cast<double>(q.srtt_baseline.count());
            double srtt_us = static_cast<double>(srtt.count());
            base_us = base_us * 0.875 + srtt_us * 0.125;
            q.srtt_baseline = std::chrono::microseconds(static_cast<std::int64_t>(base_us));
        }
        // has_tuple / four_tuple 保持不变（若之前已设置则保留）
    }
    // v4.7.0: 锁外 emit Opened 事件（回调可能反向调用 public 方法）
    if (is_new_path) {
        emit_path_opened_event(path_id, std::nullopt);
    }
}

void PathMigrationManager::update_path_quality(std::uint64_t path_id,
                                                 std::chrono::microseconds srtt,
                                                 std::uint32_t loss_count,
                                                 std::chrono::steady_clock::time_point now,
                                                 const net::FourTuple &tuple) {
    // v4.7.0: 检测新路径（用于 emit Opened 事件）
    bool is_new_path = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        is_new_path = (path_qualities_.find(path_id) == path_qualities_.end());
        auto &q = path_qualities_[path_id];
        q.path_id = path_id;
        q.srtt = srtt;
        q.loss_count = loss_count;
        q.last_seen = now;
        q.four_tuple = tuple;
        q.has_tuple = true;
        // v3.3.0 突破4: 更新 RTT 基线（EMA, alpha=0.125）
        if (q.srtt_baseline.count() == 0) {
            q.srtt_baseline = srtt;
        } else {
            double base_us = static_cast<double>(q.srtt_baseline.count());
            double srtt_us = static_cast<double>(srtt.count());
            base_us = base_us * 0.875 + srtt_us * 0.125;
            q.srtt_baseline = std::chrono::microseconds(static_cast<std::int64_t>(base_us));
        }
    }
    // v4.7.0: 锁外 emit Opened 事件
    if (is_new_path) {
        emit_path_opened_event(path_id, tuple);
    }
}

std::optional<PathMigrationManager::PathQuality>
PathMigrationManager::path_quality(std::uint64_t path_id) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = path_qualities_.find(path_id);
    if (it == path_qualities_.end()) return std::nullopt;
    return it->second;
}

bool PathMigrationManager::should_abandon_old_path(
    const PathQuality &old_q, const PathQuality &new_q) const {
    // 参数为副本，无共享状态访问，无需加锁
    // 任一路径 srtt 未测量时保守返回 false（不放弃老路径）
    if (old_q.srtt.count() == 0 || new_q.srtt.count() == 0) {
        return false;
    }
    AbandonPolicy policy_copy;
    {
        std::lock_guard<std::mutex> lk(mu_);
        policy_copy = policy_;
    }
    // 新路径 RTT 不超过老路径的 rtt_worse_threshold 倍时放弃老路径
    double old_us = static_cast<double>(old_q.srtt.count());
    double new_us = static_cast<double>(new_q.srtt.count());
    return new_us <= old_us * policy_copy.rtt_worse_threshold;
}

void PathMigrationManager::abandon_path(std::uint64_t path_id) {
    // v1.7.0.7 H10: 先在锁内拷贝 PathQuality + erase，锁外调用回调
    //   根因：原实现在 emit_path_closed_event（含用户回调 path_event_cb_）后 erase，
    //   回调若反向调用 update_path_quality / abandon_path 修改 path_qualities_，
    //   则 it 已失效，erase(it) 是 UB
    PathQuality q_copy;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = path_qualities_.find(path_id);
        if (it == path_qualities_.end()) return;  // 幂等：路径不存在时静默返回
        q_copy = it->second;
        found = true;
        LINOH_INFO("PathMigration: abandon path id=", path_id,
                   " tuple=", it->second.has_tuple ? it->second.four_tuple.to_string() : "(none)");
        path_qualities_.erase(it);
    }
    // 锁外触发 PathEvent::closed（回调可能反向调用 public 方法）
    if (found) {
        emit_path_closed_event(q_copy, "abandon_path");
    }
}

std::vector<std::uint64_t> PathMigrationManager::abandon_idle_paths(
    std::chrono::steady_clock::time_point now) {
    // v1.7.0.7 H10: 先在锁内收集待放弃的 (path_id, PathQuality) 副本 + 统一 erase，
    //   锁外对每个副本调用回调。根因：原实现在 while 循环内调用 emit_path_closed_event
    //   （含用户回调），回调若修改 path_qualities_（update_path_quality rehash /
    //   abandon_path erase），迭代器 it 立即失效，it = erase(it) 是 UB。
    std::vector<std::uint64_t> abandoned;
    std::vector<std::pair<std::uint64_t, PathQuality>> to_emit;
    {
        std::lock_guard<std::mutex> lk(mu_);
        AbandonPolicy policy_copy = policy_;
        for (auto it = path_qualities_.begin(); it != path_qualities_.end(); ) {
            auto idle = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.last_seen);
            if (idle > policy_copy.idle_timeout) {
                LINOH_INFO("PathMigration: abandon idle path id=", it->first,
                           " idle_sec=", idle.count(),
                           " tuple=", it->second.has_tuple ? it->second.four_tuple.to_string() : "(none)");
                to_emit.emplace_back(it->first, it->second);
                abandoned.push_back(it->first);
                it = path_qualities_.erase(it);
            } else {
                ++it;
            }
        }
    }
    // 锁外触发 PathEvent::closed（回调可能反向调用 public 方法）
    for (auto &[pid, q] : to_emit) {
        emit_path_closed_event(q, "idle_timeout");
    }
    return abandoned;
}

// ============================================================================
// v3.3.0 突破4: 主动健康检测 — 路径退化检测
// ============================================================================

std::vector<std::uint64_t> PathMigrationManager::detect_degraded_paths(
    std::chrono::steady_clock::time_point now) const {
    std::vector<std::uint64_t> degraded;
    std::lock_guard<std::mutex> lk(mu_);
    AbandonPolicy policy_copy = policy_;
    for (const auto &[pid, q] : path_qualities_) {
        // 跳过过老路径（超过 idle_timeout 无活动，应由 abandon_idle_paths 处理）
        auto idle = std::chrono::duration_cast<std::chrono::seconds>(now - q.last_seen);
        if (idle > policy_copy.idle_timeout) continue;

        bool is_degraded = false;

        // 检测1: RTT 突增 — srtt > baseline * rtt_degradation_ratio
        //   baseline > 0 保证已建立基线（至少一次采样）
        if (q.srtt_baseline.count() > 0 && q.srtt.count() > 0) {
            double srtt_us = static_cast<double>(q.srtt.count());
            double base_us = static_cast<double>(q.srtt_baseline.count());
            if (srtt_us > base_us * policy_copy.rtt_degradation_ratio) {
                is_degraded = true;
            }
        }

        // 检测2: 丢包率突增 — lost_packets / max(total_packets, 1) > loss_rate_threshold
        //   total_packets = udp_tx.packets_sent（若上层填充了 udp_tx）
        //   未填充 udp_tx（packets_sent==0）时跳过此检测，避免除零
        if (!is_degraded && q.lost_packets > 0) {
            std::uint64_t total = q.udp_tx.packets_sent;
            if (total > 0) {
                double loss_rate = static_cast<double>(q.lost_packets) /
                                   static_cast<double>(total);
                if (loss_rate > policy_copy.loss_rate_threshold) {
                    is_degraded = true;
                }
            }
        }

        if (is_degraded) {
            degraded.push_back(pid);
            LINOH_INFO("PathMigration: path id=", pid, " degraded "
                       "(srtt=", q.srtt.count(), "us baseline=", q.srtt_baseline.count(),
                       "us lost=", q.lost_packets, " sent=", q.udp_tx.packets_sent,
                       " tuple=", q.has_tuple ? q.four_tuple.to_string() : "(none)");
        }
    }
    return degraded;
}

std::size_t PathMigrationManager::active_path_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return path_qualities_.size();
}

bool PathMigrationManager::is_path_abandoned(std::uint64_t path_id) const {
    std::lock_guard<std::mutex> lk(mu_);
    return path_qualities_.find(path_id) == path_qualities_.end();
}

// ============================================================================
// v1.7.0.4 P3 (B7): PathEvent 集成实现
// ============================================================================

PathStats PathMigrationManager::build_path_stats(const PathQuality &q) const {
    // 参数 q 为副本，无共享状态访问，无需加锁
    PathStats stats;
    // 瞬时状态（gauge）— 用当前 srtt 填充 rtt，cwnd/current_mtu 无数据置 0
    stats.rtt = std::chrono::duration_cast<std::chrono::nanoseconds>(q.srtt);
    stats.cwnd = 0;
    stats.current_mtu = 0;
    // 累计计数器 — 从 PathQuality 拷贝
    stats.udp_tx = q.udp_tx;
    stats.udp_rx = q.udp_rx;
    stats.lost_packets = q.lost_packets;
    stats.lost_bytes = q.lost_bytes;
    stats.congestion_events = q.congestion_events;
    return stats;
}

void PathMigrationManager::emit_path_closed_event(const PathQuality &q,
                                                   const std::string &reason) {
    // v1.7.0.7 H10: 调用方须保证未持有 mu_（回调可能反向调用 public 方法导致死锁）
    PathEventCallback cb_copy;
    {
        std::lock_guard<std::mutex> lk(mu_);
        cb_copy = path_event_cb_;
    }
    if (!cb_copy) return;

    PathStats last_stats = build_path_stats(q);
    std::string remote = q.has_tuple ? q.four_tuple.to_string() : "(unknown)";
    std::string local = "(local)";
    auto ev = PathEvent::closed(q.path_id, std::move(remote), std::move(local),
                                 std::move(last_stats), reason);
    try {
        cb_copy(ev);
    } catch (...) {
        // 回调异常不应影响路径迁移主流程（path_event.hpp 约定）
        LINOH_WARN("PathMigration: path_event_cb_ threw exception, ignored");
    }
}

// ============================================================================
// v4.7.0: PathEvent::Opened 事件 emit（新路径首次见到时触发）
// ============================================================================

void PathMigrationManager::emit_path_opened_event(
    std::uint64_t path_id,
    const std::optional<net::FourTuple> &tuple) {
    // v4.7.0: 调用方须保证未持有 mu_（H10 模式）
    PathEventCallback cb_copy;
    {
        std::lock_guard<std::mutex> lk(mu_);
        cb_copy = path_event_cb_;
    }
    if (!cb_copy) return;

    std::string remote = tuple.has_value() ? tuple->to_string() : "(unknown)";
    std::string local = "(local)";
    auto ev = PathEvent::opened(path_id, std::move(remote), std::move(local));
    try {
        cb_copy(ev);
    } catch (...) {
        LINOH_WARN("PathMigration: path_event_cb_ threw exception (opened), ignored");
    }
}

// ============================================================================
// Frame encoding
// ============================================================================

std::vector<std::uint8_t> encode_path_challenge(const PathChallengeFrame &frame) {
    std::vector<std::uint8_t> buf;
    buf.push_back(0x1a);  // type
    buf.insert(buf.end(), frame.data.begin(), frame.data.end());
    return buf;
}

std::optional<PathChallengeFrame> decode_path_challenge(std::span<const std::uint8_t> payload) {
    if (payload.size() < 8) return std::nullopt;
    PathChallengeFrame frame;
    std::memcpy(frame.data.data(), payload.data(), 8);
    return frame;
}

std::vector<std::uint8_t> encode_path_response(const PathResponseFrame &frame) {
    std::vector<std::uint8_t> buf;
    buf.push_back(0x1b);  // type
    buf.insert(buf.end(), frame.data.begin(), frame.data.end());
    return buf;
}

std::optional<PathResponseFrame> decode_path_response(std::span<const std::uint8_t> payload) {
    if (payload.size() < 8) return std::nullopt;
    PathResponseFrame frame;
    std::memcpy(frame.data.data(), payload.data(), 8);
    return frame;
}

std::vector<std::uint8_t> encode_new_connection_id(const NewConnectionIdFrame &frame) {
    std::vector<std::uint8_t> buf;
    buf.push_back(0x18);  // type

    auto seq = util::varint_encode_vec(frame.sequence_number);
    buf.insert(buf.end(), seq.begin(), seq.end());

    auto retire = util::varint_encode_vec(frame.retire_prior_to);
    buf.insert(buf.end(), retire.begin(), retire.end());

    buf.push_back(frame.connection_id_length);
    buf.insert(buf.end(), frame.connection_id.begin(), frame.connection_id.end());
    buf.insert(buf.end(), frame.stateless_reset_token.begin(),
               frame.stateless_reset_token.end());

    return buf;
}

std::optional<NewConnectionIdFrame> decode_new_connection_id(std::span<const std::uint8_t> payload) {
    std::size_t pos = 0;

    auto r1 = util::varint_decode(payload);
    if (!r1) return std::nullopt;
    std::uint64_t seq = r1->first;
    pos += r1->second;

    if (payload.size() < pos) return std::nullopt;
    auto r2 = util::varint_decode(payload.subspan(pos));
    if (!r2) return std::nullopt;
    std::uint64_t retire = r2->first;
    pos += r2->second;

    if (payload.size() < pos + 1) return std::nullopt;
    std::uint8_t cid_len = payload[pos++];
    if (cid_len > ConnectionId::kMaxSize) return std::nullopt;

    if (payload.size() < pos + cid_len) return std::nullopt;
    std::vector<std::uint8_t> cid(payload.data() + pos, payload.data() + pos + cid_len);
    pos += cid_len;

    if (payload.size() < pos + 16) return std::nullopt;
    NewConnectionIdFrame frame;
    frame.sequence_number = seq;
    frame.retire_prior_to = retire;
    frame.connection_id_length = cid_len;
    frame.connection_id = cid;
    std::memcpy(frame.stateless_reset_token.data(), payload.data() + pos, 16);

    return frame;
}

std::vector<std::uint8_t> encode_retire_connection_id(const RetireConnectionIdFrame &frame) {
    std::vector<std::uint8_t> buf;
    buf.push_back(0x19);  // type
    auto enc = util::varint_encode_vec(frame.sequence_number);
    buf.insert(buf.end(), enc.begin(), enc.end());
    return buf;
}

std::optional<RetireConnectionIdFrame> decode_retire_connection_id(std::span<const std::uint8_t> payload) {
    auto result = util::varint_decode(payload);
    if (!result) return std::nullopt;
    return RetireConnectionIdFrame{result->first};
}

// ============================================================================
// v4.7.0: PathSelectionStrategy 集成
// ============================================================================

std::optional<net::FourTuple> PathMigrationManager::select_primary_path() const {
    // 锁内拷贝策略和候选列表（锁外调用 strategy，避免持锁调复杂选路逻辑，复用 H10 模式）
    std::shared_ptr<PathSelectionStrategy> strat;
    std::vector<PathQuality> candidates;
    {
        std::lock_guard<std::mutex> lk(mu_);
        strat = strategy_;
        candidates.reserve(path_qualities_.size());
        for (const auto &kv : path_qualities_) {
            candidates.push_back(kv.second);
        }
    }
    if (!strat || candidates.empty()) {
        LINOH_DEBUG("select_primary_path: no strategy or no candidates");
        return std::nullopt;
    }
    return strat->select(candidates);
}

} // namespace linoh::protocol
