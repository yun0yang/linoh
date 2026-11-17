// sync_primitives.cpp — EP 跨节点同步原语实现（v1.6.0.2 / P1）
//
// 实现 SyncPrimitives 类的 barrier / signal / all_reduce 三种同步原语。
// 核心逻辑：
//   - signal：直接发送 EP_SYNC_FRAME(sync_op=Signal)
//   - barrier：master 收集所有 participant signal -> 广播 release
//   - all_reduce：ring all-reduce（reduce-scatter + all-gather）
//
// 会话管理：
//   - sessions_ map 按 sync_id 索引
//   - arrived_mask 跟踪已到达节点
//   - deadline 超时检测 + cv_ 条件变量唤醒阻塞调用

#include "linoh/multimodal/sync_primitives.hpp"

#include <algorithm>
#include <cstring>
#include <bit>
#include <utility>  // std::pair（A6: signal 回调参数锁内收集）

namespace linoh::multimodal::ep {

// ============================================================================
// 构造/析构
// ============================================================================

SyncPrimitives::SyncPrimitives(EpChannel *channel)
    : channel_(channel) {}

SyncPrimitives::~SyncPrimitives() {
    // 唤醒所有阻塞等待
    cv_.notify_all();
}

// ============================================================================
// 同步原语 API
// ============================================================================

bool SyncPrimitives::signal(std::uint64_t sync_id, std::uint64_t to_mask) {
    if (!channel_ || !channel_->is_valid()) {
        return false;
    }
    return send_sync_frame_(sync_id, EpSyncOp::Signal, to_mask);
}

bool SyncPrimitives::barrier(std::uint64_t sync_id,
                             std::uint64_t participant_mask,
                             std::uint64_t self_node_id,
                             std::chrono::milliseconds timeout) {
    if (!channel_ || !channel_->is_valid()) {
        return false;
    }
    if (participant_mask == 0) {
        return false;  // 无参与节点
    }

    auto deadline = std::chrono::steady_clock::now() + timeout;

    // 创建会话
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;
        session.state = SyncState::Waiting;
        session.deadline = deadline;
        sessions_[sync_id] = std::move(session);
    }

    // 广播 barrier 开始（通知所有 participant）
    // participant_mask 作为目标，让所有节点知道 barrier 启动
    if (!send_sync_frame_(sync_id, EpSyncOp::Barrier, participant_mask)) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(sync_id);
        return false;
    }

    // 发送自己的 signal（本节点已就绪）
    if (!send_sync_frame_(sync_id, EpSyncOp::Signal, participant_mask)) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(sync_id);
        return false;
    }

    // 等待完成或超时
    std::unique_lock<std::mutex> lk(mu_);
    bool ok = cv_.wait_until(lk, deadline, [&] {
        auto it = sessions_.find(sync_id);
        if (it == sessions_.end()) return false;
        return it->second.state == SyncState::Completed || it->second.state == SyncState::TimedOut;
    });

    if (!ok) {
        // 超时
        auto it = sessions_.find(sync_id);
        if (it != sessions_.end()) {
            it->second.state = SyncState::TimedOut;

            // P6 部分降级：若允许且已有部分 participant 到齐，触发回调
            if (allow_partial_combine_ && it->second.arrived_mask != 0) {
                std::uint64_t arrived = it->second.arrived_mask;
                std::uint64_t expected = it->second.participant_mask;
                sessions_.erase(it);
                lk.unlock();  // 锁外调用回调，避免死锁
                if (callbacks_.on_barrier_partial) {
                    callbacks_.on_barrier_partial(sync_id, arrived, expected);
                }
                // 部分降级语义：返回 true 表示"已处理"（业务层基于回调决策）
                return true;
            }
        }
        notify_timeout_(sync_id);
        sessions_.erase(sync_id);
        return false;
    }

    auto it = sessions_.find(sync_id);
    if (it != sessions_.end()) {
        bool success = (it->second.state == SyncState::Completed);
        sessions_.erase(it);
        return success;
    }

    return false;
}

std::optional<std::vector<std::uint8_t>> SyncPrimitives::all_reduce(
    std::uint64_t sync_id,
    std::uint64_t participant_mask,
    std::uint64_t self_node_id,
    std::span<const std::uint8_t> local_data,
    ReduceOp op,
    ReduceDType dtype,
    std::chrono::milliseconds timeout,
    std::uint8_t algo) {
    if (participant_mask == 0 || local_data.empty()) {
        return std::nullopt;
    }

    // P1 阶段限制：单 chunk <= 4KB
    if (local_data.size() > EpSyncFrame::kMaxPayloadLen) {
        return std::nullopt;
    }

    // v1.7.0.7 C11: 校验数据长度与 dtype 匹配，避免 apply_reduce_ 越界
    std::size_t elem_size = 0;
    switch (dtype) {
        case ReduceDType::U64:
        case ReduceDType::F64: elem_size = 8; break;
        case ReduceDType::U32:
        case ReduceDType::F32: elem_size = 4; break;
        case ReduceDType::U16:
        case ReduceDType::F16:
        case ReduceDType::BF16: elem_size = 2; break;
        default: elem_size = 8; break;
    }
    if (local_data.size() % elem_size != 0) {
        return std::nullopt;
    }

    auto deadline = std::chrono::steady_clock::now() + timeout;

    // v2.3 Phase 4 (P4-G): algo=Ring 时优先尝试 Ring 路径
    // Ring 路径仅依赖 peer_channels_（不依赖默认 channel_），失败则降级简化版
    if (algo == 0) {  // algo=Ring
        if (all_reduce_ring_(sync_id, participant_mask, self_node_id,
                             local_data, op, dtype, timeout)) {
            // Ring 路径已接管，跳到统一等待逻辑
            std::unique_lock<std::mutex> lk(mu_);
            bool ok = cv_.wait_until(lk, deadline, [&] {
                auto it = sessions_.find(sync_id);
                if (it == sessions_.end()) return false;
                return it->second.state == SyncState::Completed ||
                       it->second.state == SyncState::TimedOut;
            });
            if (!ok) {
                auto it = sessions_.find(sync_id);
                if (it != sessions_.end()) {
                    it->second.state = SyncState::TimedOut;
                }
                notify_timeout_(sync_id);
                sessions_.erase(sync_id);
                return std::nullopt;
            }
            auto it = sessions_.find(sync_id);
            if (it != sessions_.end()) {
                bool success = (it->second.state == SyncState::Completed);
                std::vector<std::uint8_t> result = std::move(it->second.reduced_data);
                sessions_.erase(it);
                if (success) return result;
            }
            return std::nullopt;
        }
        // Ring 路径未接管（peer_channels_ 未配置或条件不满足），降级简化版
    }

    // v2.3 Phase 4 (P4-E): algo=RH 时优先尝试 RH 路径
    // RH 路径要求 N 为 2 的幂 + 全部 partner channel 已配置，失败则降级简化版
    if (algo == 2) {  // algo=RH
        if (all_reduce_rh_(sync_id, participant_mask, self_node_id,
                           local_data, op, dtype, timeout)) {
            // RH 路径已接管，跳到统一等待逻辑
            std::unique_lock<std::mutex> lk(mu_);
            bool ok = cv_.wait_until(lk, deadline, [&] {
                auto it = sessions_.find(sync_id);
                if (it == sessions_.end()) return false;
                return it->second.state == SyncState::Completed ||
                       it->second.state == SyncState::TimedOut;
            });
            if (!ok) {
                auto it = sessions_.find(sync_id);
                if (it != sessions_.end()) {
                    it->second.state = SyncState::TimedOut;
                }
                notify_timeout_(sync_id);
                sessions_.erase(sync_id);
                return std::nullopt;
            }
            auto it = sessions_.find(sync_id);
            if (it != sessions_.end()) {
                bool success = (it->second.state == SyncState::Completed);
                std::vector<std::uint8_t> result = std::move(it->second.reduced_data);
                sessions_.erase(it);
                if (success) return result;
            }
            return std::nullopt;
        }
        // RH 路径未接管（守卫失败），降级简化版
    }

    // 简化版路径需要默认 channel_ 有效
    if (!channel_ || !channel_->is_valid()) {
        return std::nullopt;
    }

    // 创建会话
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;
        session.state = SyncState::Reducing;
        session.deadline = deadline;
        session.reduce_op = op;
        session.reduce_dtype = dtype;  // v1.7.0.7 C11: 记录 dtype
        session.algo = algo;           // v2.2 Phase 3 (P3-F): 记录算法
        session.local_data.assign(local_data.begin(), local_data.end());
        session.reduced_data.assign(local_data.begin(), local_data.end());
        session.ring_round = 0;
        session.total_rings = 2 * (popcount_(participant_mask) - 1);
        sessions_[sync_id] = std::move(session);
    }

    // 发送 AllReduce 启动帧（携带本地数据）
    // 在 P1 简化实现中：所有节点将本地数据发送给 master（bit 0），
    // master 执行规约后广播结果（tree 模式简化，完整 ring 在 P2 实现）
    // mp-M2 (v1.7.0.8): 在帧中携带 reduce_op，被动会话不再硬编码 SUM
    // v2.2 Phase 3 (P3-F): 在帧中携带 algo，便于接收方记录和对端诊断
    if (!send_sync_frame_(sync_id, EpSyncOp::AllReduce, participant_mask,
                          std::span<const std::uint8_t>(local_data.data(), local_data.size()),
                          static_cast<std::uint8_t>(op), algo)) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(sync_id);
        return std::nullopt;
    }

    // 等待完成或超时
    std::unique_lock<std::mutex> lk(mu_);
    bool ok = cv_.wait_until(lk, deadline, [&] {
        auto it = sessions_.find(sync_id);
        if (it == sessions_.end()) return false;
        return it->second.state == SyncState::Completed || it->second.state == SyncState::TimedOut;
    });

    if (!ok) {
        auto it = sessions_.find(sync_id);
        if (it != sessions_.end()) {
            it->second.state = SyncState::TimedOut;
        }
        notify_timeout_(sync_id);
        sessions_.erase(sync_id);
        return std::nullopt;
    }

    auto it = sessions_.find(sync_id);
    if (it != sessions_.end()) {
        if (it->second.state == SyncState::Completed) {
            auto result = std::move(it->second.reduced_data);
            sessions_.erase(it);
            return result;
        }
        sessions_.erase(it);
    }

    return std::nullopt;
}

// ============================================================================
// v2.1 Phase 2: all_gather 实现
// ============================================================================

std::optional<std::vector<std::uint8_t>> SyncPrimitives::all_gather(
    std::uint64_t sync_id,
    std::uint64_t participant_mask,
    std::uint64_t self_node_id,
    std::span<const std::uint8_t> local_chunk,
    std::chrono::milliseconds timeout,
    std::uint8_t algo) {
    // 参数校验（不依赖 channel，确保测试场景可创建会话）
    if (participant_mask == 0) {
        return std::nullopt;  // 无参与节点
    }
    // v2.2 Phase 3 (P3-G): 超过 shard_size_ 的 chunk 自动分片传输，
    // 单帧 payload 不再受 4KB 限制；此处仅保留 4GB 绝对上限保护
    if (local_chunk.size() > EpSyncFrame::kMaxPayloadLen) {
        return std::nullopt;
    }
    // self_node_id 必须在 participant_mask 中
    if ((participant_mask & (static_cast<std::uint64_t>(1) << self_node_id)) == 0) {
        return std::nullopt;
    }

    auto deadline = std::chrono::steady_clock::now() + timeout;

    // v2.3 Phase 4 (P4-G): algo=Ring 时优先尝试 Ring 路径
    // Ring 路径要求 peer_channels_ 已配置 next 邻居，失败则降级简化版
    if (algo == 0) {  // algo=Ring
        if (all_gather_ring_(sync_id, participant_mask, self_node_id,
                             local_chunk, timeout)) {
            // Ring 路径已接管，统一等待逻辑
            std::unique_lock<std::mutex> lk(mu_);
            bool ok = cv_.wait_until(lk, deadline, [&] {
                auto it = sessions_.find(sync_id);
                if (it == sessions_.end()) return false;
                return it->second.state == SyncState::Completed ||
                       it->second.state == SyncState::TimedOut;
            });
            if (!ok) {
                auto it = sessions_.find(sync_id);
                if (it != sessions_.end()) {
                    it->second.state = SyncState::TimedOut;
                }
                notify_timeout_(sync_id);
                sessions_.erase(sync_id);
                return std::nullopt;
            }
            auto it = sessions_.find(sync_id);
            if (it != sessions_.end()) {
                bool success = (it->second.state == SyncState::Completed);
                std::vector<std::uint8_t> result = std::move(it->second.reduced_data);
                sessions_.erase(it);
                if (success) return result;
            }
            return std::nullopt;
        }
        // Ring 路径未接管（peer_channels_ 未配置或条件不满足），降级简化版
    }

    // v2.3 Phase 4 (P4-D): algo=Tree (1) 优先尝试 Tree 路径
    // Tree 路径要求 peer_channels_ 已配置 parent（非 root）/children，失败则降级简化版
    if (algo == 1) {  // algo=Tree
        if (all_gather_tree_(sync_id, participant_mask, self_node_id,
                             local_chunk, timeout)) {
            // Tree 路径已接管，统一等待逻辑
            std::unique_lock<std::mutex> lk(mu_);
            bool ok = cv_.wait_until(lk, deadline, [&] {
                auto it = sessions_.find(sync_id);
                if (it == sessions_.end()) return false;
                return it->second.state == SyncState::Completed ||
                       it->second.state == SyncState::TimedOut;
            });
            if (!ok) {
                auto it = sessions_.find(sync_id);
                if (it != sessions_.end()) {
                    it->second.state = SyncState::TimedOut;
                }
                notify_timeout_(sync_id);
                sessions_.erase(sync_id);
                return std::nullopt;
            }
            auto it = sessions_.find(sync_id);
            if (it != sessions_.end()) {
                bool success = (it->second.state == SyncState::Completed);
                std::vector<std::uint8_t> result = std::move(it->second.reduced_data);
                sessions_.erase(it);
                if (success) return result;
            }
            return std::nullopt;
        }
        // Tree 路径未接管（守卫失败），降级简化版
    }

    bool channel_valid = (channel_ && channel_->is_valid());

    // 创建会话（即使 channel 无效也创建，便于测试场景通过 handle_sync_frame 模拟接收）
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;
        session.state = SyncState::Waiting;  // 复用 Waiting 状态表示收集阶段
        session.deadline = deadline;
        session.algo = algo;  // v2.2 Phase 3 (P3-F): 记录算法
        session.gather_chunk_size = local_chunk.size();
        // 预置自身 chunk
        session.gather_chunks[self_node_id].assign(local_chunk.begin(), local_chunk.end());
        // arrived_mask 标记自身已到达
        session.arrived_mask = (static_cast<std::uint64_t>(1) << self_node_id);
        sessions_[sync_id] = std::move(session);
    }

    // channel 无效：会话已创建但不发送，立即返回 nullopt
    // 测试场景可通过 handle_sync_frame 模拟接收帧，会话由 check_timeouts 超时清理
    if (!channel_valid) {
        return std::nullopt;
    }

    // v2.2 Phase 3 (P3-G): 大 chunk 自动分片发送（小 chunk 退化为单帧 total_shards=1）
    if (!send_sharded_(sync_id, EpSyncOp::AllGather,
                       static_cast<std::uint64_t>(1) << self_node_id,
                       std::span<const std::uint8_t>(local_chunk.data(), local_chunk.size()),
                       0, algo)) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(sync_id);
        return std::nullopt;
    }

    // 等待完成或超时
    std::unique_lock<std::mutex> lk(mu_);
    bool ok = cv_.wait_until(lk, deadline, [&] {
        auto it = sessions_.find(sync_id);
        if (it == sessions_.end()) return false;
        return it->second.state == SyncState::Completed || it->second.state == SyncState::TimedOut;
    });

    if (!ok) {
        auto it = sessions_.find(sync_id);
        if (it != sessions_.end()) {
            it->second.state = SyncState::TimedOut;
        }
        notify_timeout_(sync_id);
        sessions_.erase(sync_id);
        return std::nullopt;
    }

    auto it = sessions_.find(sync_id);
    if (it != sessions_.end()) {
        if (it->second.state == SyncState::Completed) {
            // 按 participant bit 升序拼接 chunks
            std::vector<std::uint8_t> result;
            std::uint64_t mask = it->second.participant_mask;
            std::uint64_t bit = 0;
            while (mask) {
                if (mask & 1) {
                    auto chunk_it = it->second.gather_chunks.find(bit);
                    if (chunk_it != it->second.gather_chunks.end()) {
                        result.insert(result.end(), chunk_it->second.begin(), chunk_it->second.end());
                    }
                }
                mask >>= 1;
                ++bit;
            }
            sessions_.erase(it);
            return result;
        }
        sessions_.erase(it);
    }

    return std::nullopt;
}

// ============================================================================
// v2.1 Phase 2: broadcast 实现
// ============================================================================

bool SyncPrimitives::broadcast(
    std::uint64_t sync_id,
    std::uint64_t participant_mask,
    std::uint64_t root_node_id,
    std::span<const std::uint8_t> data,
    std::chrono::milliseconds timeout,
    std::uint8_t algo) {
    (void)timeout;  // broadcast 发送不阻塞等待（异步），timeout 仅用于日志
    // 参数校验（不依赖 channel，确保测试场景可创建会话）
    if (participant_mask == 0) {
        return false;  // 无参与节点
    }
    // root 必须在 participant_mask 中
    if ((participant_mask & (static_cast<std::uint64_t>(1) << root_node_id)) == 0) {
        return false;
    }
    // v2.2 Phase 3 (P3-G): 超过 shard_size_ 自动分片，仅保留 4GB 绝对上限
    if (data.size() > EpSyncFrame::kMaxPayloadLen) {
        return false;
    }

    // v2.3 Phase 4 (P4-D): algo=Tree (1) 优先尝试 Tree 路径
    // Tree 路径仅依赖 peer_channels_（parent/children），失败则降级简化版
    if (algo == 1) {
        if (broadcast_tree_(sync_id, participant_mask, root_node_id,
                            self_node_id_, data, timeout)) {
            // Tree 路径已接管（root 发完即完成，非 root 等待回调）
            return true;
        }
        // Tree 路径未接管（守卫失败），降级简化版
    }

    // 创建本地会话记录（即使 channel 无效也创建，便于测试场景）
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.root_node_id = root_node_id;
        session.state = SyncState::Completed;  // root 端直接标记完成（不等待 ack）
        session.deadline = std::chrono::steady_clock::now() + timeout;
        session.algo = algo;  // v2.2 Phase 3 (P3-F): 记录算法
        session.local_data.assign(data.begin(), data.end());
        sessions_[sync_id] = std::move(session);
    }

    // channel 无效：会话已创建但不发送，返回 false
    if (!channel_ || !channel_->is_valid()) {
        return false;
    }

    // v2.2 Phase 3 (P3-G): 大 chunk 自动分片广播（小 chunk 退化为单帧）
    // participant_mask 字段携带 root_node_id 的 bit，payload 携带广播数据（分片）
    return send_sharded_(sync_id, EpSyncOp::Broadcast,
                         static_cast<std::uint64_t>(1) << root_node_id,
                         std::span<const std::uint8_t>(data.data(), data.size()),
                         0, algo);
}

// ============================================================================
// v2.1 Phase 2 M2: reduce_scatter 实现
// ============================================================================

std::optional<std::vector<std::uint8_t>> SyncPrimitives::reduce_scatter(
    std::uint64_t sync_id,
    std::uint64_t participant_mask,
    std::uint64_t self_node_id,
    std::span<const std::uint8_t> local_data,
    ReduceOp op,
    ReduceDType dtype,
    std::chrono::milliseconds timeout,
    std::uint8_t algo) {
    // 参数校验（不依赖 channel，确保测试场景可创建会话）
    if (participant_mask == 0 || local_data.empty()) {
        return std::nullopt;  // 无参与节点或空数据
    }
    // v2.2 Phase 3 (P3-G): 超过 shard_size_ 自动分片，仅保留 4GB 绝对上限
    if (local_data.size() > EpSyncFrame::kMaxPayloadLen) {
        return std::nullopt;
    }
    // self 必须在 participant_mask 中
    if ((participant_mask & (static_cast<std::uint64_t>(1) << self_node_id)) == 0) {
        return std::nullopt;
    }
    // 数据长度必须能被 participant 数整除（规约后等分 N 份）
    std::uint32_t n = popcount_(participant_mask);
    if (n == 0 || local_data.size() % n != 0) {
        return std::nullopt;
    }

    auto deadline = std::chrono::steady_clock::now() + timeout;

    // v2.3 Phase 4 (P4-G): algo=Ring 时优先尝试 Ring 路径
    // Ring 路径要求 peer_channels_ 已配置 next 邻居，失败则降级简化版
    if (algo == 0) {  // algo=Ring
        if (reduce_scatter_ring_(sync_id, participant_mask, self_node_id,
                                 local_data, op, dtype, timeout)) {
            // Ring 路径已接管，统一等待逻辑
            std::unique_lock<std::mutex> lk(mu_);
            bool ok = cv_.wait_until(lk, deadline, [&] {
                auto it = sessions_.find(sync_id);
                if (it == sessions_.end()) return false;
                return it->second.state == SyncState::Completed ||
                       it->second.state == SyncState::TimedOut;
            });
            if (!ok) {
                auto it = sessions_.find(sync_id);
                if (it != sessions_.end()) {
                    it->second.state = SyncState::TimedOut;
                }
                notify_timeout_(sync_id);
                sessions_.erase(sync_id);
                return std::nullopt;
            }
            auto it = sessions_.find(sync_id);
            if (it != sessions_.end()) {
                bool success = (it->second.state == SyncState::Completed);
                std::vector<std::uint8_t> result = std::move(it->second.reduced_data);
                sessions_.erase(it);
                if (success) return result;
            }
            return std::nullopt;
        }
        // Ring 路径未接管（peer_channels_ 未配置或条件不满足），降级简化版
    }

    // v2.3 Phase 4 (P4-E): algo=RH 时优先尝试 RH 路径
    // RH 路径要求 N 为 2 的幂 + 全部 partner channel 已配置，失败则降级简化版
    if (algo == 2) {  // algo=RH
        if (reduce_scatter_rh_(sync_id, participant_mask, self_node_id,
                               local_data, op, dtype, timeout)) {
            // RH 路径已接管，统一等待逻辑
            std::unique_lock<std::mutex> lk(mu_);
            bool ok = cv_.wait_until(lk, deadline, [&] {
                auto it = sessions_.find(sync_id);
                if (it == sessions_.end()) return false;
                return it->second.state == SyncState::Completed ||
                       it->second.state == SyncState::TimedOut;
            });
            if (!ok) {
                auto it = sessions_.find(sync_id);
                if (it != sessions_.end()) {
                    it->second.state = SyncState::TimedOut;
                }
                notify_timeout_(sync_id);
                sessions_.erase(sync_id);
                return std::nullopt;
            }
            auto it = sessions_.find(sync_id);
            if (it != sessions_.end()) {
                bool success = (it->second.state == SyncState::Completed);
                std::vector<std::uint8_t> result = std::move(it->second.reduced_data);
                sessions_.erase(it);
                if (success) return result;
            }
            return std::nullopt;
        }
        // RH 路径未接管（守卫失败），降级简化版
    }

    bool channel_valid = (channel_ && channel_->is_valid());

    // 计算本节点在有序 participant 列表中的索引（用于提取规约后的分片）
    std::uint32_t scatter_idx = 0;
    {
        std::uint64_t mask = participant_mask;
        std::uint64_t bit = 0;
        while (bit < self_node_id && mask) {
            if (mask & 1) ++scatter_idx;
            mask >>= 1;
            ++bit;
        }
    }

    // 创建会话（预置自身数据到 reduced_data，arrived_mask 标记自身）
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;
        session.state = SyncState::Reducing;
        session.deadline = deadline;
        session.reduce_op = op;
        session.reduce_dtype = dtype;
        session.algo = algo;  // v2.2 Phase 3 (P3-F): 记录算法
        session.local_data.assign(local_data.begin(), local_data.end());
        session.reduced_data.assign(local_data.begin(), local_data.end());
        session.scatter_chunk_index = scatter_idx;
        session.arrived_mask = (static_cast<std::uint64_t>(1) << self_node_id);
        sessions_[sync_id] = std::move(session);
    }

    // channel 无效：会话已创建但不发送，立即返回 nullopt
    if (!channel_valid) {
        return std::nullopt;
    }

    // v2.2 Phase 3 (P3-G): 大 chunk 自动分片发送（小 chunk 退化为单帧）
    // participant_mask 设为自身 bit，reduce_op 透传
    if (!send_sharded_(sync_id, EpSyncOp::ReduceScatter,
                       static_cast<std::uint64_t>(1) << self_node_id,
                       std::span<const std::uint8_t>(local_data.data(), local_data.size()),
                       static_cast<std::uint8_t>(op), algo)) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(sync_id);
        return std::nullopt;
    }

    // 等待完成或超时
    std::unique_lock<std::mutex> lk(mu_);
    bool ok = cv_.wait_until(lk, deadline, [&] {
        auto it = sessions_.find(sync_id);
        if (it == sessions_.end()) return false;
        return it->second.state == SyncState::Completed || it->second.state == SyncState::TimedOut;
    });

    if (!ok) {
        auto it = sessions_.find(sync_id);
        if (it != sessions_.end()) {
            it->second.state = SyncState::TimedOut;
        }
        notify_timeout_(sync_id);
        sessions_.erase(sync_id);
        return std::nullopt;
    }

    auto it = sessions_.find(sync_id);
    if (it != sessions_.end()) {
        if (it->second.state == SyncState::Completed) {
            // 从规约结果中提取本节点对应的分片（按 bit 升序第 scatter_idx 份）
            const auto &reduced = it->second.reduced_data;
            std::size_t chunk_size = reduced.size() / n;
            std::size_t offset = static_cast<std::size_t>(scatter_idx) * chunk_size;
            std::vector<std::uint8_t> result(reduced.begin() + offset,
                                             reduced.begin() + offset + chunk_size);
            sessions_.erase(it);
            return result;
        }
        sessions_.erase(it);
    }

    return std::nullopt;
}

// ============================================================================
// v2.1 Phase 2 M2: all_to_all 实现
// ============================================================================

std::optional<std::vector<std::uint8_t>> SyncPrimitives::all_to_all(
    std::uint64_t sync_id,
    std::uint64_t participant_mask,
    std::uint64_t self_node_id,
    std::span<const std::uint8_t> local_chunk,
    std::chrono::milliseconds timeout,
    std::uint8_t algo) {
    // 参数校验（不依赖 channel，确保测试场景可创建会话）
    if (participant_mask == 0) {
        return std::nullopt;  // 无参与节点
    }
    // v2.2 Phase 3 (P3-G): 超过 shard_size_ 自动分片，仅保留 4GB 绝对上限
    if (local_chunk.size() > EpSyncFrame::kMaxPayloadLen) {
        return std::nullopt;
    }
    // self 必须在 participant_mask 中
    if ((participant_mask & (static_cast<std::uint64_t>(1) << self_node_id)) == 0) {
        return std::nullopt;
    }

    auto deadline = std::chrono::steady_clock::now() + timeout;

    // v2.3 Phase 4 (P4-F): algo=PE 时优先尝试 PE 路径
    // PE 路径要求 N 为 2 的幂 + 全部 partner channel 已配置，失败则降级简化版
    if (algo == 3) {  // algo=PE
        if (all_to_all_pe_(sync_id, participant_mask, self_node_id,
                           local_chunk, timeout)) {
            // PE 路径已接管，统一等待逻辑
            std::unique_lock<std::mutex> lk(mu_);
            bool ok = cv_.wait_until(lk, deadline, [&] {
                auto it = sessions_.find(sync_id);
                if (it == sessions_.end()) return false;
                return it->second.state == SyncState::Completed ||
                       it->second.state == SyncState::TimedOut;
            });
            if (!ok) {
                auto it = sessions_.find(sync_id);
                if (it != sessions_.end()) {
                    it->second.state = SyncState::TimedOut;
                }
                notify_timeout_(sync_id);
                sessions_.erase(sync_id);
                return std::nullopt;
            }
            auto it = sessions_.find(sync_id);
            if (it != sessions_.end()) {
                bool success = (it->second.state == SyncState::Completed);
                std::vector<std::uint8_t> result = std::move(it->second.reduced_data);
                sessions_.erase(it);
                if (success) return result;
            }
            return std::nullopt;
        }
        // PE 路径未接管（守卫失败），降级简化版
    }

    bool channel_valid = (channel_ && channel_->is_valid());

    // 创建会话（预置自身 chunk 到 all_to_all_received）
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;
        session.state = SyncState::Waiting;
        session.deadline = deadline;
        session.algo = algo;  // v2.2 Phase 3 (P3-F): 记录算法
        session.all_to_all_received[self_node_id].assign(local_chunk.begin(), local_chunk.end());
        session.arrived_mask = (static_cast<std::uint64_t>(1) << self_node_id);
        sessions_[sync_id] = std::move(session);
    }

    // channel 无效：会话已创建但不发送，立即返回 nullopt
    if (!channel_valid) {
        return std::nullopt;
    }

    // v2.2 Phase 3 (P3-G): 大 chunk 自动分片发送（小 chunk 退化为单帧）
    // participant_mask 设为自身 bit
    if (!send_sharded_(sync_id, EpSyncOp::AllToAll,
                       static_cast<std::uint64_t>(1) << self_node_id,
                       std::span<const std::uint8_t>(local_chunk.data(), local_chunk.size()),
                       0, algo)) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(sync_id);
        return std::nullopt;
    }

    // 等待完成或超时
    std::unique_lock<std::mutex> lk(mu_);
    bool ok = cv_.wait_until(lk, deadline, [&] {
        auto it = sessions_.find(sync_id);
        if (it == sessions_.end()) return false;
        return it->second.state == SyncState::Completed || it->second.state == SyncState::TimedOut;
    });

    if (!ok) {
        auto it = sessions_.find(sync_id);
        if (it != sessions_.end()) {
            it->second.state = SyncState::TimedOut;
        }
        notify_timeout_(sync_id);
        sessions_.erase(sync_id);
        return std::nullopt;
    }

    auto it = sessions_.find(sync_id);
    if (it != sessions_.end()) {
        if (it->second.state == SyncState::Completed) {
            // 按发送方 bit 升序拼接 chunks
            std::vector<std::uint8_t> result;
            std::uint64_t mask = it->second.participant_mask;
            std::uint64_t bit = 0;
            while (mask) {
                if (mask & 1) {
                    auto chunk_it = it->second.all_to_all_received.find(bit);
                    if (chunk_it != it->second.all_to_all_received.end()) {
                        result.insert(result.end(), chunk_it->second.begin(), chunk_it->second.end());
                    }
                }
                mask >>= 1;
                ++bit;
            }
            sessions_.erase(it);
            return result;
        }
        sessions_.erase(it);
    }

    return std::nullopt;
}

// ============================================================================
// 回调注册
// ============================================================================

void SyncPrimitives::set_callbacks(SyncCallbacks callbacks) {
    std::lock_guard<std::mutex> lk(mu_);
    callbacks_ = std::move(callbacks);
}

// ============================================================================
// 帧路由入口
// ============================================================================

void SyncPrimitives::handle_sync_frame(const EpSyncFrame &frame) {
    // v2.3 Phase 4 (P4-G/P4-D/P4-E/P4-F): 按 algo 路由
    // 如果会话存在且有 ring_algo（本节点已通过 all_reduce_ring_ 等发起 Ring 会话），
    // 走 Ring 专用处理器；否则检查 tree_algo（P4-D），走 Tree 处理器；
    // 再检查 rh_algo（P4-E），走 RH 处理器；
    // 再检查 pe_algo（P4-F），走 PE 处理器；
    // 都没有则降级到简化版（向后兼容，含被动会话创建）。
    // Ring 帧特征：from_node_id != 0 或 step != 0（P4-A 扩展字段）
    bool use_ring = false;
    bool use_tree = false;
    bool use_rh = false;
    bool use_pe = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(frame.sync_id);
        if (it != sessions_.end()) {
            if (it->second.ring_algo.has_value()) use_ring = true;
            if (it->second.tree_algo.has_value()) use_tree = true;
            if (it->second.rh_algo.has_value()) use_rh = true;
            if (it->second.pe_algo.has_value()) use_pe = true;
        }
    }

    switch (frame.sync_op) {
        case EpSyncOp::Signal:
            handle_signal_(frame);
            break;
        case EpSyncOp::Barrier:
            handle_barrier_(frame);
            break;
        case EpSyncOp::Ack:
            handle_ack_(frame);
            break;
        case EpSyncOp::AllReduce:
            // P4-G: Ring 优先；P4-E: RH 次之；最后简化版
            if (use_ring) {
                handle_all_reduce_ring_(frame);
            } else if (use_rh) {
                handle_all_reduce_rh_(frame);
            } else {
                handle_all_reduce_(frame);
            }
            break;
        case EpSyncOp::Release:
            handle_release_(frame);
            break;
        // v2.1 Phase 2: 集合通信原语路由
        case EpSyncOp::AllGather:
            // P4-G: Ring 优先；P4-D: Tree 次之；最后简化版
            if (use_ring) {
                handle_all_gather_ring_(frame);
            } else if (use_tree) {
                handle_all_gather_tree_(frame);
            } else {
                handle_all_gather_(frame);
            }
            break;
        case EpSyncOp::Broadcast:
            // P4-D: Tree 会话走 Tree 处理器，否则简化版
            if (use_tree) {
                handle_broadcast_tree_(frame);
            } else {
                handle_broadcast_(frame);
            }
            break;
        // v2.1 Phase 2 M2: ReduceScatter / AllToAll 路由
        case EpSyncOp::ReduceScatter:
            // P4-G: Ring 优先；P4-E: RH 次之；最后简化版
            if (use_ring) {
                handle_reduce_scatter_ring_(frame);
            } else if (use_rh) {
                handle_all_reduce_rh_(frame);  // RH 复用同一 handler
            } else {
                handle_reduce_scatter_(frame);
            }
            break;
        case EpSyncOp::AllToAll:
            // P4-F: PE 会话走 PE 处理器，否则简化版
            if (use_pe) {
                handle_all_to_all_pe_(frame);
            } else {
                handle_all_to_all_(frame);
            }
            break;
        default:
            // 未知 sync_op，忽略
            break;
    }
}

// ============================================================================
// 超时清理
// ============================================================================

void SyncPrimitives::check_timeouts() {
    auto now = std::chrono::steady_clock::now();
    // v1.7.0.7 H4: 锁内收集超时 sync_id，锁外调用回调，避免锁内回调死锁
    std::vector<std::uint64_t> timed_out_ids;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto &kv : sessions_) {
            auto &session = kv.second;
            if (session.state == SyncState::Waiting || session.state == SyncState::Reducing) {
                if (now >= session.deadline) {
                    session.state = SyncState::TimedOut;
                    timed_out_ids.push_back(session.sync_id);
                }
            }
        }
    }
    // 锁外触发回调（用户回调可能调用 signal/barrier 等会再次获取 mu_）
    for (auto sid : timed_out_ids) {
        notify_timeout_(sid);
    }
    cv_.notify_all();
}

// ============================================================================
// 状态查询
// ============================================================================

std::optional<SyncSession> SyncPrimitives::get_session(std::uint64_t sync_id) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = sessions_.find(sync_id);
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::size_t SyncPrimitives::session_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return sessions_.size();
}

void SyncPrimitives::cleanup_finished() {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (it->second.state == SyncState::Completed || it->second.state == SyncState::TimedOut) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// 内部辅助：发送 SYNC 帧
// ============================================================================

bool SyncPrimitives::send_sync_frame_(std::uint64_t sync_id,
                                      EpSyncOp op,
                                      std::uint64_t participant_mask,
                                      std::span<const std::uint8_t> payload,
                                      std::uint8_t reduce_op,
                                      std::uint8_t algo,
                                      std::uint16_t shard_idx,
                                      std::uint16_t total_shards,
                                      std::uint64_t from_node_id,
                                      std::uint16_t step) {
    if (!channel_) return false;
    // v2.2 Phase 3 (P3-F/P3-G): 透传 algo / shard_idx / total_shards 到 EpChannel
    // v2.3 Phase 4 (P4-A): 透传 from_node_id / step 支持多步通信状态机
    return channel_->send_sync(sync_id, op, participant_mask, payload, reduce_op,
                               algo, shard_idx, total_shards, from_node_id, step);
}

// ============================================================================
// v2.3 Phase 4 (P4-B): 多 EpChannel 注入实现
// ============================================================================

void SyncPrimitives::set_peer_channel(std::uint64_t peer_bit, EpChannel *channel) {
    std::lock_guard<std::mutex> lk(mu_);
    if (channel) {
        peer_channels_[peer_bit] = channel;
    } else {
        peer_channels_.erase(peer_bit);
    }
}

void SyncPrimitives::set_ring_peers(std::uint64_t next_bit, EpChannel *next_channel,
                                    std::uint64_t prev_bit, EpChannel *prev_channel) {
    std::lock_guard<std::mutex> lk(mu_);
    if (next_channel) {
        peer_channels_[next_bit] = next_channel;
    }
    if (prev_channel) {
        peer_channels_[prev_bit] = prev_channel;
    }
}

// v2.3 Phase 4 (P4-D): Tree 拓扑邻居配置
// 一次性注入 parent + children 的 EpChannel 到 peer_channels_。
// root 节点 parent_channel=nullptr（跳过 parent 注入），仅注入 children。
// leaf 节点 children 为空，仅注入 parent。
void SyncPrimitives::set_tree_peers(std::uint64_t parent_bit, EpChannel *parent_channel,
                                    const std::vector<std::pair<std::uint64_t, EpChannel *>> &children) {
    std::lock_guard<std::mutex> lk(mu_);
    if (parent_channel) {
        peer_channels_[parent_bit] = parent_channel;
    }
    for (const auto &child : children) {
        if (child.second) {
            peer_channels_[child.first] = child.second;
        }
    }
}

// v2.3 Phase 4 (P4-E): RH 拓扑邻居配置
void SyncPrimitives::set_rh_peers(const std::vector<std::pair<std::uint64_t, EpChannel *>> &partners) {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto &p : partners) {
        if (p.second) {
            peer_channels_[p.first] = p.second;
        }
    }
}

// v2.3 Phase 4 (P4-F): set_pe_peers — 配置 PairwiseExchange 全部 partner channel
void SyncPrimitives::set_pe_peers(const std::vector<std::pair<std::uint64_t, EpChannel *>> &partners) {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto &p : partners) {
        if (p.second) {
            peer_channels_[p.first] = p.second;
        }
    }
}

bool SyncPrimitives::send_to_peer_(std::uint64_t peer_bit,
                                   std::uint64_t sync_id,
                                   EpSyncOp op,
                                   std::uint64_t participant_mask,
                                   std::span<const std::uint8_t> payload,
                                   std::uint8_t reduce_op,
                                   std::uint8_t algo,
                                   std::uint16_t shard_idx,
                                   std::uint16_t total_shards,
                                   std::uint64_t from_node_id,
                                   std::uint16_t step) {
    // 优先查 peer_channels_ 路由表
    EpChannel *ch = nullptr;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = peer_channels_.find(peer_bit);
        if (it != peer_channels_.end()) {
            ch = it->second;
        } else {
            ch = channel_;  // 回退到默认通道
        }
    }
    if (!ch) return false;
    return ch->send_sync(sync_id, op, participant_mask, payload, reduce_op,
                         algo, shard_idx, total_shards, from_node_id, step);
}

// ============================================================================
// v2.2 Phase 3 (P3-G): 大 chunk 自动分片发送
// ============================================================================

bool SyncPrimitives::send_sharded_(std::uint64_t sync_id,
                                    EpSyncOp op,
                                    std::uint64_t target_mask,
                                    std::span<const std::uint8_t> data,
                                    std::uint8_t reduce_op,
                                    std::uint8_t algo) {
    std::size_t total = data.size();
    // 计算分片数：shard_size_ = 0 表示禁用分片（单帧）；total <= shard_size_ 也单帧
    std::size_t limit = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        limit = shard_size_;
    }
    std::uint16_t total_shards = 1;
    if (limit > 0 && total > limit) {
        // 向上取整，保护 limit > 0 的前提避免除零
        std::size_t shards = (total + limit - 1) / limit;
        if (shards > 65535) shards = 65535;  // uint16_t 上限保护
        total_shards = static_cast<std::uint16_t>(shards);
    }

    // 逐片发送：每片 payload = data[offset, offset+len)
    for (std::uint16_t idx = 0; idx < total_shards; ++idx) {
        std::size_t offset = (limit > 0)
                                 ? static_cast<std::size_t>(idx) * limit
                                 : 0;
        std::size_t remain = (total > offset) ? (total - offset) : 0;
        std::size_t len = (limit > 0)
                              ? (std::min)(limit, remain)
                              : total;
        if (len == 0) len = remain;  // 兜底
        std::span<const std::uint8_t> shard(data.data() + offset, len);
        if (!send_sync_frame_(sync_id, op, target_mask, shard, reduce_op, algo,
                              idx, total_shards)) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// v2.2 Phase 3 (P3-G): 分片缓冲与乱序重组
// ============================================================================

bool SyncPrimitives::buffer_shard_(SyncSession &session,
                                    std::uint64_t from_bit,
                                    const EpSyncFrame &frame,
                                    std::vector<std::uint8_t> &reassembled) {
    // 单分片路径（total_shards <= 1）：直接返回 payload，行为与改造前完全一致
    if (frame.total_shards <= 1) {
        reassembled.assign(frame.payload.begin(), frame.payload.end());
        return true;
    }

    // 多分片路径：按 (from_bit << 16) | shard_idx 缓冲，支持乱序到达
    // from_bit 为发送方 bit position（0-63），shard_idx 为 0-65535，无键冲突
    std::uint64_t key = (from_bit << 16) | frame.shard_idx;
    // 幂等处理重复分片（重传）：仅当该 shard_idx 首次到达才递增计数，
    // 避免重复分片虚增 received_count 导致未收齐即过早触发重组。
    // 重复分片仍覆盖缓冲（保证重传数据最新），但不改变完成判定。
    bool is_new = (session.shard_buffer.find(key) == session.shard_buffer.end());
    session.shard_buffer[key].assign(frame.payload.begin(), frame.payload.end());
    session.shard_total[from_bit] = frame.total_shards;
    if (is_new) {
        session.shard_received_count[from_bit]++;
    }

    // 检查该发送方的分片是否全部到齐（按唯一 shard_idx 计数）
    if (session.shard_received_count[from_bit] >= session.shard_total[from_bit]) {
        // 按 shard_idx 升序重组完整数据
        reassembled.clear();
        for (std::uint16_t i = 0; i < frame.total_shards; ++i) {
            auto it = session.shard_buffer.find((from_bit << 16) | i);
            if (it != session.shard_buffer.end()) {
                reassembled.insert(reassembled.end(),
                                   it->second.begin(), it->second.end());
            }
        }
        // 清理该发送方的分片缓冲，释放内存
        for (std::uint16_t i = 0; i < frame.total_shards; ++i) {
            session.shard_buffer.erase((from_bit << 16) | i);
        }
        return true;
    }
    return false;  // 分片尚未到齐，继续等待
}

// ============================================================================
// 内部辅助：处理各类 sync_op
// ============================================================================

void SyncPrimitives::handle_signal_(const EpSyncFrame &frame) {
    // signal 帧到达：在对应会话的 arrived_mask 中标记
    // 修复 A6: 锁内收集状态，锁外触发回调 + 发送 release（原锁内调用
    // callbacks_.on_signal_received 和 send_sync_frame_，回调内再调 SyncPrimitives
    // 方法会死锁）。参照 handle_all_reduce_ 的"锁内收集、锁外回调"模式。
    std::vector<std::uint64_t> release_ids;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> signal_callbacks;  // (sync_id, from_mask)

    {
        std::lock_guard<std::mutex> lk(mu_);

        // signal 帧的 participant_mask 表示发送方节点位图（bit i = 节点 i 发送了 signal）
        std::uint64_t from_mask = frame.participant_mask;

        auto it = sessions_.find(frame.sync_id);
        if (it != sessions_.end()) {
            auto &session = it->second;
            session.arrived_mask |= from_mask;

            // 收集回调参数，锁外触发（A6 修复）
            if (callbacks_.on_signal_received) {
                signal_callbacks.emplace_back(frame.sync_id, from_mask);
            }

            // 检查是否全部到齐
            if ((session.arrived_mask & session.participant_mask) == session.participant_mask) {
                // 所有 participant 到齐
                // 如果是 barrier 会话，广播 release
                if (session.state == SyncState::Waiting) {
                    session.state = SyncState::Releasing;
                    release_ids.push_back(frame.sync_id);
                }
            }
        } else {
            // 会话不存在，可能是收到的 signal 但本节点未发起 barrier
            // 仍触发回调
            if (callbacks_.on_signal_received) {
                signal_callbacks.emplace_back(frame.sync_id, from_mask);
            }
        }
    }

    // 锁外触发回调（A6 修复）
    for (auto &sc : signal_callbacks) {
        callbacks_.on_signal_received(sc.first, sc.second);
    }

    // 锁外发送 release 帧，避免 send_sync 内部回调时再次获取 mu_ 导致死锁
    for (auto sid : release_ids) {
        send_sync_frame_(sid, EpSyncOp::Release, 0xFFFFFFFFFFFFFFFFULL, {});
    }
}

void SyncPrimitives::handle_barrier_(const EpSyncFrame &frame) {
    // barrier 帧到达：表示有节点发起了一个 barrier
    // 本节点如果参与，需要回复 signal
    std::lock_guard<std::mutex> lk(mu_);

    // 检查本节点是否在 participant_mask 中
    // 注意：这里无法知道"本节点的 bit 位置"，简化处理：收到 barrier 帧即回复 signal
    // 在实际部署中，每个节点知道自己的 node_id

    // 如果已有对应会话，更新状态
    auto it = sessions_.find(frame.sync_id);
    if (it == sessions_.end()) {
        // 本节点未发起此 barrier，但需要参与
        // 创建被动参与会话
        SyncSession session;
        session.sync_id = frame.sync_id;
        session.participant_mask = frame.participant_mask;
        session.state = SyncState::Waiting;
        session.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        sessions_[frame.sync_id] = std::move(session);
    }
}

void SyncPrimitives::handle_ack_(const EpSyncFrame &frame) {
    // ACK 帧：对 signal 的确认（P1 阶段暂不处理，预留扩展）
    (void)frame;
}

void SyncPrimitives::handle_release_(const EpSyncFrame &frame) {
    // release 帧到达：barrier 完成，解除阻塞
    // 修复 A6: 锁内收集状态，锁外触发回调（原锁内调用 on_release_received /
    // on_barrier_complete，回调内再调 SyncPrimitives 方法会死锁）。参照 handle_all_reduce_ 模式。
    bool need_release_cb = false;
    bool need_barrier_cb = false;

    {
        std::lock_guard<std::mutex> lk(mu_);

        auto it = sessions_.find(frame.sync_id);
        if (it != sessions_.end()) {
            auto &session = it->second;
            session.state = SyncState::Completed;

            need_release_cb = static_cast<bool>(callbacks_.on_release_received);
            need_barrier_cb = static_cast<bool>(callbacks_.on_barrier_complete);
        } else {
            // 会话不存在，仅触发 release 回调
            need_release_cb = static_cast<bool>(callbacks_.on_release_received);
        }
    }

    // 锁外触发回调（A6 修复）
    if (need_release_cb) {
        callbacks_.on_release_received(frame.sync_id);
    }
    if (need_barrier_cb) {
        callbacks_.on_barrier_complete(frame.sync_id);
    }

    cv_.notify_all();
}

void SyncPrimitives::handle_all_reduce_(const EpSyncFrame &frame) {
    // all_reduce 帧到达：携带某节点的本地数据
    // 修复 A3: 锁内收集状态，锁外触发回调（原锁内调用 notify_all_reduce_complete_，
    // 回调内再调 SyncPrimitives 方法会死锁）。参照 handle_all_gather_ 模式。
    bool completed = false;
    std::vector<std::uint8_t> completed_result;

    {
    std::lock_guard<std::mutex> lk(mu_);

    auto it = sessions_.find(frame.sync_id);
    if (it == sessions_.end()) {
        // 会话不存在，创建被动参与会话
        SyncSession session;
        session.sync_id = frame.sync_id;
        session.participant_mask = frame.participant_mask;
        session.state = SyncState::Reducing;
        session.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        // mp-M2 (v1.7.0.8): 从帧中读取 reduce_op，替代硬编码 SUM
        //   原实现被动会话固定 SUM，发起方用 MAX/MIN 时被动方按 SUM 处理导致结果错误
        session.reduce_op = (frame.reduce_op <= 3)
                                ? static_cast<ReduceOp>(frame.reduce_op)
                                : ReduceOp::SUM;
        session.reduced_data.clear();
        session.arrived_mask = 0;
        sessions_[frame.sync_id] = std::move(session);
        it = sessions_.find(frame.sync_id);
    }

    if (it != sessions_.end()) {
        auto &session = it->second;
        // 合并 payload 到 reduced_data
        if (session.reduced_data.empty()) {
            session.reduced_data.assign(frame.payload.begin(), frame.payload.end());
        } else {
            session.reduced_data = apply_reduce_(
                std::span<const std::uint8_t>(session.reduced_data.data(), session.reduced_data.size()),
                std::span<const std::uint8_t>(frame.payload.data(), frame.payload.size()),
                session.reduce_op,
                session.reduce_dtype);
        }
        session.arrived_mask |= frame.participant_mask;

        // 检查是否全部到齐
        if ((session.arrived_mask & session.participant_mask) == session.participant_mask) {
            // 如果是 AVG，除以 N
            if (session.reduce_op == ReduceOp::AVG) {
                std::uint32_t n = popcount_(session.participant_mask);
                if (n > 0 && !session.reduced_data.empty()) {
                    // v1.7.0.7 C11: 按 reduce_dtype 处理元素宽度，避免硬编码 uint64 导致 F32/F16 数据破坏
                    std::size_t esize = 0;
                    switch (session.reduce_dtype) {
                        case ReduceDType::U64:
                        case ReduceDType::F64: esize = 8; break;
                        case ReduceDType::U32:
                        case ReduceDType::F32: esize = 4; break;
                        case ReduceDType::U16:
                        case ReduceDType::F16:
                        case ReduceDType::BF16: esize = 2; break;
                        default: esize = 8; break;
                    }
                    if (session.reduced_data.size() % esize == 0) {
                        std::size_t cnt = session.reduced_data.size() / esize;
                        bool is_float = (session.reduce_dtype == ReduceDType::F64 ||
                                         session.reduce_dtype == ReduceDType::F32 ||
                                         session.reduce_dtype == ReduceDType::F16 ||
                                         session.reduce_dtype == ReduceDType::BF16);
                        for (std::size_t i = 0; i < cnt; ++i) {
                            if (is_float) {
                                double val = 0.0;
                                if (session.reduce_dtype == ReduceDType::F64) {
                                    std::memcpy(&val, session.reduced_data.data() + i * 8, 8);
                                } else if (session.reduce_dtype == ReduceDType::F32) {
                                    float fval;
                                    std::memcpy(&fval, session.reduced_data.data() + i * 4, 4);
                                    val = fval;
                                } else if (session.reduce_dtype == ReduceDType::F16) {
                                    std::uint16_t h;
                                    std::memcpy(&h, session.reduced_data.data() + i * 2, 2);
                                    val = half_to_float_(h);
                                } else {  // BF16
                                    std::uint16_t b;
                                    std::memcpy(&b, session.reduced_data.data() + i * 2, 2);
                                    val = bf16_to_float_(b);
                                }
                                val /= static_cast<double>(n);
                                // 写回
                                if (session.reduce_dtype == ReduceDType::F64) {
                                    std::memcpy(session.reduced_data.data() + i * 8, &val, 8);
                                } else if (session.reduce_dtype == ReduceDType::F32) {
                                    float fval = static_cast<float>(val);
                                    std::memcpy(session.reduced_data.data() + i * 4, &fval, 4);
                                } else if (session.reduce_dtype == ReduceDType::F16) {
                                    std::uint16_t h = float_to_half_(static_cast<float>(val));
                                    std::memcpy(session.reduced_data.data() + i * 2, &h, 2);
                                } else {  // BF16
                                    std::uint16_t b = float_to_bf16_(static_cast<float>(val));
                                    std::memcpy(session.reduced_data.data() + i * 2, &b, 2);
                                }
                            } else {
                                // 整数类型：按 elem_size 提升到 uint64_t 后除法再截断
                                std::uint64_t val = 0;
                                std::memcpy(reinterpret_cast<std::uint8_t *>(&val),
                                            session.reduced_data.data() + i * esize, esize);
                                val /= n;
                                std::memcpy(session.reduced_data.data() + i * esize, &val, esize);
                            }
                        }
                    }
                }
            }

            session.state = SyncState::Completed;
            completed = true;
            completed_result = session.reduced_data;  // 拷贝结果出锁，供锁外回调使用
        }
    }
    }  // 锁作用域结束（A3 修复）

    // 锁外触发回调（A3 修复：原在锁内调用，回调内再调 SyncPrimitives 方法会死锁）
    if (completed) {
        notify_all_reduce_complete_(frame.sync_id,
            std::span<const std::uint8_t>(completed_result.data(), completed_result.size()));
        std::lock_guard<std::mutex> lk(mu_);
        cv_.notify_all();
    }
}

// ============================================================================
// v2.1 Phase 2: handle_all_gather_ 实现
// ============================================================================

void SyncPrimitives::handle_all_gather_(const EpSyncFrame &frame) {
    // AllGather 帧到达：携带某节点的 chunk（可能为分片）
    // frame.participant_mask 表示发送方 bit position（单 bit）
    // v2.2 Phase 3 (P3-G): 支持 shard_idx/total_shards 分片重组，乱序到达
    // 锁内收集 chunk + 检查完成条件，锁外触发回调避免死锁
    bool completed = false;
    std::vector<std::uint8_t> completed_result;

    // 提取发送方 bit position（单 bit）
    std::uint64_t from_bit = 0;
    {
        std::uint64_t tmp = frame.participant_mask;
        while (tmp) {
            if (tmp & 1) break;
            tmp >>= 1;
            ++from_bit;
        }
    }

    {
        std::lock_guard<std::mutex> lk(mu_);

        auto it = sessions_.find(frame.sync_id);
        if (it == sessions_.end()) {
            // 会话不存在，创建被动参与会话
            // 注意：被动会话无法知道完整的 participant_mask，
            // 这里用 frame.participant_mask 作为已知参与节点（后续帧到达时累积）
            SyncSession session;
            session.sync_id = frame.sync_id;
            session.participant_mask = frame.participant_mask;  // 初始为发送方，后续无法扩展
            session.state = SyncState::Waiting;
            session.deadline = std::chrono::steady_clock::now() + passive_session_timeout_;
            session.gather_chunk_size = frame.payload.size();
            // v2.2 Phase 3 (P3-G): 分片缓冲重组，全部分片到齐才记录 chunk 和 arrived_mask
            std::vector<std::uint8_t> reassembled;
            if (buffer_shard_(session, from_bit, frame, reassembled)) {
                session.gather_chunks[from_bit] = std::move(reassembled);
                session.arrived_mask = frame.participant_mask;
            }
            sessions_[frame.sync_id] = std::move(session);
            // 被动会话无法判定完成（participant_mask 不完整），仅收集数据
            return;
        }

        auto &session = it->second;
        // v2.2 Phase 3 (P3-G): 分片缓冲重组，全部分片到齐才更新 chunk 和 arrived_mask
        std::vector<std::uint8_t> reassembled;
        if (buffer_shard_(session, from_bit, frame, reassembled)) {
            // 收集 chunk（覆盖更新，支持重传/分片重发）
            session.gather_chunks[from_bit] = std::move(reassembled);
            session.arrived_mask |= frame.participant_mask;
        }
        // 分片未到齐时 arrived_mask 不更新，完成检查自然推迟

        // 检查是否所有 participant 的 chunk 已到齐
        if ((session.arrived_mask & session.participant_mask) == session.participant_mask) {
            session.state = SyncState::Completed;
            completed = true;
            // 按 participant bit 升序拼接 chunks
            std::uint64_t mask = session.participant_mask;
            std::uint64_t bit = 0;
            while (mask) {
                if (mask & 1) {
                    auto chunk_it = session.gather_chunks.find(bit);
                    if (chunk_it != session.gather_chunks.end()) {
                        completed_result.insert(completed_result.end(),
                                                chunk_it->second.begin(), chunk_it->second.end());
                    }
                }
                mask >>= 1;
                ++bit;
            }
        }
    }

    // 锁外触发回调（避免锁内回调死锁）
    if (completed) {
        notify_all_gather_complete_(frame.sync_id,
            std::span<const std::uint8_t>(completed_result.data(), completed_result.size()));
        std::lock_guard<std::mutex> lk(mu_);
        cv_.notify_all();
    }
}

// ============================================================================
// v2.1 Phase 2: handle_broadcast_ 实现
// ============================================================================

void SyncPrimitives::handle_broadcast_(const EpSyncFrame &frame) {
    // Broadcast 帧到达：root 节点分发数据（可能为分片）
    // frame.participant_mask 表示 root 节点 bit position（单 bit）
    // v2.2 Phase 3 (P3-G): 支持 shard_idx/total_shards 分片重组，全部分片到齐才触发回调
    std::uint64_t root_bit = 0;
    std::uint64_t tmp = frame.participant_mask;
    while (tmp) {
        if (tmp & 1) break;
        tmp >>= 1;
        ++root_bit;
    }

    // reassembled_ready=true 表示分片已到齐，reassembled_data 为完整广播数据
    bool reassembled_ready = false;
    std::vector<std::uint8_t> reassembled_data;

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(frame.sync_id);
        if (it == sessions_.end()) {
            // 被动接收广播：创建会话记录
            SyncSession session;
            session.sync_id = frame.sync_id;
            session.participant_mask = frame.participant_mask;
            session.root_node_id = root_bit;
            session.state = SyncState::Waiting;  // 分片未到齐前保持 Waiting
            session.deadline = std::chrono::steady_clock::now() + passive_session_timeout_;
            // v2.2 Phase 3 (P3-G): 分片缓冲重组
            if (buffer_shard_(session, root_bit, frame, reassembled_data)) {
                session.local_data = reassembled_data;
                session.state = SyncState::Completed;
                reassembled_ready = true;
            }
            sessions_[frame.sync_id] = std::move(session);
        } else {
            // 更新已有会话
            auto &session = it->second;
            session.root_node_id = root_bit;
            if (buffer_shard_(session, root_bit, frame, reassembled_data)) {
                session.local_data = reassembled_data;
                session.state = SyncState::Completed;
                reassembled_ready = true;
            }
        }
    }

    // 锁外触发回调（仅当分片到齐，避免部分数据触发回调）
    if (reassembled_ready) {
        notify_broadcast_received_(frame.sync_id, root_bit,
            std::span<const std::uint8_t>(reassembled_data.data(), reassembled_data.size()));
    }
}

// ============================================================================
// v2.1 Phase 2 M2: handle_reduce_scatter_ 实现
// ============================================================================

void SyncPrimitives::handle_reduce_scatter_(const EpSyncFrame &frame) {
    // ReduceScatter 帧到达：携带某节点的本地数据（可能为分片）
    // frame.participant_mask 表示发送方 bit position（单 bit）
    // frame.reduce_op 携带规约操作
    // v2.2 Phase 3 (P3-G): 分片重组后再规约，避免对部分数据执行 apply_reduce_
    // 锁内合并数据 + 检查完成条件，锁外触发回调避免死锁
    bool completed = false;
    std::vector<std::uint8_t> completed_result;

    // 提取发送方 bit position（单 bit）
    std::uint64_t from_bit = 0;
    {
        std::uint64_t tmp = frame.participant_mask;
        while (tmp) {
            if (tmp & 1) break;
            tmp >>= 1;
            ++from_bit;
        }
    }

    {
        std::lock_guard<std::mutex> lk(mu_);

        auto it = sessions_.find(frame.sync_id);
        if (it == sessions_.end()) {
            // 创建被动参与会话
            SyncSession session;
            session.sync_id = frame.sync_id;
            session.participant_mask = frame.participant_mask;
            session.state = SyncState::Reducing;
            session.deadline = std::chrono::steady_clock::now() + passive_session_timeout_;
            // mp-M2 兼容：从帧中读取 reduce_op
            session.reduce_op = (frame.reduce_op <= 3)
                                    ? static_cast<ReduceOp>(frame.reduce_op)
                                    : ReduceOp::SUM;
            // v2.2 Phase 3 (P3-G): 分片缓冲重组，全部分片到齐才写入 reduced_data
            std::vector<std::uint8_t> reassembled;
            if (buffer_shard_(session, from_bit, frame, reassembled)) {
                session.reduced_data = std::move(reassembled);
                session.arrived_mask = (static_cast<std::uint64_t>(1) << from_bit);
            }
            sessions_[frame.sync_id] = std::move(session);
            // 被动会话无法判定完成（participant_mask 不完整），仅累积数据
            return;
        }

        auto &session = it->second;
        // v2.2 Phase 3 (P3-G): 分片缓冲重组，全部分片到齐才执行规约
        std::vector<std::uint8_t> reassembled;
        if (buffer_shard_(session, from_bit, frame, reassembled)) {
            // 合并重组后的完整数据到 reduced_data（apply_reduce_ 按 dtype 处理元素宽度）
            if (session.reduced_data.empty()) {
                session.reduced_data = std::move(reassembled);
            } else {
                session.reduced_data = apply_reduce_(
                    std::span<const std::uint8_t>(session.reduced_data.data(), session.reduced_data.size()),
                    std::span<const std::uint8_t>(reassembled.data(), reassembled.size()),
                    session.reduce_op,
                    session.reduce_dtype);
            }
            session.arrived_mask |= frame.participant_mask;
        }
        // 分片未到齐时不更新 arrived_mask，完成检查自然推迟

        // 检查是否全部到齐
        if ((session.arrived_mask & session.participant_mask) == session.participant_mask) {
            session.state = SyncState::Completed;
            completed = true;
            completed_result = session.reduced_data;
        }
    }

    // 锁外触发回调（避免锁内回调死锁）
    if (completed) {
        notify_reduce_scatter_complete_(frame.sync_id,
            std::span<const std::uint8_t>(completed_result.data(), completed_result.size()));
        std::lock_guard<std::mutex> lk(mu_);
        cv_.notify_all();
    }
}

// ============================================================================
// v2.1 Phase 2 M2: handle_all_to_all_ 实现
// ============================================================================

void SyncPrimitives::handle_all_to_all_(const EpSyncFrame &frame) {
    // AllToAll 帧到达：携带某节点发给本节点的数据（可能为分片）
    // frame.participant_mask 表示发送方 bit position（单 bit）
    // v2.2 Phase 3 (P3-G): 支持 shard_idx/total_shards 分片重组，乱序到达
    // 锁内收集 chunk + 检查完成条件，锁外触发回调避免死锁
    bool completed = false;
    std::vector<std::uint8_t> completed_result;
    std::uint64_t completed_from_mask = 0;

    // 提取发送方 bit position（单 bit）
    std::uint64_t from_bit = 0;
    {
        std::uint64_t tmp = frame.participant_mask;
        while (tmp) {
            if (tmp & 1) break;
            tmp >>= 1;
            ++from_bit;
        }
    }

    {
        std::lock_guard<std::mutex> lk(mu_);

        auto it = sessions_.find(frame.sync_id);
        if (it == sessions_.end()) {
            // 创建被动参与会话
            SyncSession session;
            session.sync_id = frame.sync_id;
            session.participant_mask = frame.participant_mask;
            session.state = SyncState::Waiting;
            session.deadline = std::chrono::steady_clock::now() + passive_session_timeout_;
            // v2.2 Phase 3 (P3-G): 分片缓冲重组，全部分片到齐才记录 chunk 和 arrived_mask
            std::vector<std::uint8_t> reassembled;
            if (buffer_shard_(session, from_bit, frame, reassembled)) {
                session.all_to_all_received[from_bit] = std::move(reassembled);
                session.arrived_mask = frame.participant_mask;
            }
            sessions_[frame.sync_id] = std::move(session);
            // 被动会话无法判定完成（participant_mask 不完整），仅收集数据
            return;
        }

        auto &session = it->second;
        // v2.2 Phase 3 (P3-G): 分片缓冲重组，全部分片到齐才更新 chunk 和 arrived_mask
        std::vector<std::uint8_t> reassembled;
        if (buffer_shard_(session, from_bit, frame, reassembled)) {
            // 收集 chunk（覆盖更新，支持重传/分片重发）
            session.all_to_all_received[from_bit] = std::move(reassembled);
            session.arrived_mask |= frame.participant_mask;
        }
        // 分片未到齐时 arrived_mask 不更新，完成检查自然推迟

        // 检查是否所有 participant 的数据已到齐
        if ((session.arrived_mask & session.participant_mask) == session.participant_mask) {
            session.state = SyncState::Completed;
            completed = true;
            completed_from_mask = session.arrived_mask;
            // 按发送方 bit 升序拼接 chunks
            std::uint64_t mask = session.participant_mask;
            std::uint64_t bit = 0;
            while (mask) {
                if (mask & 1) {
                    auto chunk_it = session.all_to_all_received.find(bit);
                    if (chunk_it != session.all_to_all_received.end()) {
                        completed_result.insert(completed_result.end(),
                                                chunk_it->second.begin(), chunk_it->second.end());
                    }
                }
                mask >>= 1;
                ++bit;
            }
        }
    }

    // 锁外触发回调（避免锁内回调死锁）
    if (completed) {
        notify_all_to_all_complete_(frame.sync_id, completed_from_mask,
            std::span<const std::uint8_t>(completed_result.data(), completed_result.size()));
        std::lock_guard<std::mutex> lk(mu_);
        cv_.notify_all();
    }
}

// ============================================================================
// 内部辅助：通知回调
// ============================================================================

void SyncPrimitives::notify_barrier_complete_(std::uint64_t sync_id) {
    if (callbacks_.on_barrier_complete) {
        callbacks_.on_barrier_complete(sync_id);
    }
}

void SyncPrimitives::notify_timeout_(std::uint64_t sync_id) {
    if (callbacks_.on_sync_timeout) {
        callbacks_.on_sync_timeout(sync_id);
    }
}

void SyncPrimitives::notify_all_reduce_complete_(std::uint64_t sync_id, std::span<const std::uint8_t> result) {
    if (callbacks_.on_all_reduce_complete) {
        callbacks_.on_all_reduce_complete(sync_id, result);
    }
}

void SyncPrimitives::notify_release_(std::uint64_t sync_id) {
    if (callbacks_.on_release_received) {
        callbacks_.on_release_received(sync_id);
    }
}

// v2.1 Phase 2: 集合通信完成通知
void SyncPrimitives::notify_all_gather_complete_(std::uint64_t sync_id, std::span<const std::uint8_t> result) {
    if (callbacks_.on_all_gather_complete) {
        callbacks_.on_all_gather_complete(sync_id, result);
    }
}

void SyncPrimitives::notify_broadcast_received_(std::uint64_t sync_id, std::uint64_t root_node_id,
                                                std::span<const std::uint8_t> data) {
    if (callbacks_.on_broadcast_received) {
        callbacks_.on_broadcast_received(sync_id, root_node_id, data);
    }
}

// v2.1 Phase 2 M2: ReduceScatter / AllToAll 完成通知
void SyncPrimitives::notify_reduce_scatter_complete_(std::uint64_t sync_id,
                                                      std::span<const std::uint8_t> result) {
    if (callbacks_.on_reduce_scatter_complete) {
        callbacks_.on_reduce_scatter_complete(sync_id, result);
    }
}

void SyncPrimitives::notify_all_to_all_complete_(std::uint64_t sync_id, std::uint64_t from_mask,
                                                   std::span<const std::uint8_t> data) {
    if (callbacks_.on_all_to_all_complete) {
        callbacks_.on_all_to_all_complete(sync_id, from_mask, data);
    }
}

// ============================================================================
// 内部辅助：ring all-reduce 算法
// ============================================================================

std::vector<std::uint8_t> SyncPrimitives::apply_reduce_(std::span<const std::uint8_t> a,
                                                        std::span<const std::uint8_t> b,
                                                        ReduceOp op,
                                                        ReduceDType dtype) {
    // v1.7.0.7 C11: 按 dtype 处理不同元素宽度，避免硬编码 uint64 导致 F32/F16 数据破坏
    if (a.size() != b.size() || a.empty()) {
        // 长度不匹配或空数据，返回 a 的副本
        return std::vector<std::uint8_t>(a.begin(), a.end());
    }

    std::size_t elem_size = 0;
    switch (dtype) {
        case ReduceDType::U64:
        case ReduceDType::F64: elem_size = 8; break;
        case ReduceDType::U32:
        case ReduceDType::F32: elem_size = 4; break;
        case ReduceDType::U16:
        case ReduceDType::F16:
        case ReduceDType::BF16: elem_size = 2; break;
        default: elem_size = 8; break;
    }
    if (a.size() % elem_size != 0) {
        return std::vector<std::uint8_t>(a.begin(), a.end());
    }

    std::vector<std::uint8_t> result(a.size());
    std::size_t cnt = a.size() / elem_size;

    // 整数类型（U64/U32/U16）按无符号整数累加
    if (dtype == ReduceDType::U64 || dtype == ReduceDType::U32 || dtype == ReduceDType::U16) {
        for (std::size_t i = 0; i < cnt; ++i) {
            std::uint64_t va = 0, vb = 0;
            std::memcpy(reinterpret_cast<std::uint8_t *>(&va), a.data() + i * elem_size, elem_size);
            std::memcpy(reinterpret_cast<std::uint8_t *>(&vb), b.data() + i * elem_size, elem_size);

            std::uint64_t vr;
            switch (op) {
                case ReduceOp::SUM:
                case ReduceOp::AVG:  // AVG 在最终结果中除以 N，此处按 SUM 处理
                    vr = va + vb;
                    break;
                case ReduceOp::MAX:
                    vr = (va > vb) ? va : vb;
                    break;
                case ReduceOp::MIN:
                    vr = (va < vb) ? va : vb;
                    break;
                default:
                    vr = va + vb;
                    break;
            }

            // 按原始宽度写回（截断到 elem_size 字节）
            std::memcpy(result.data() + i * elem_size, &vr, elem_size);
        }
        return result;
    }

    // 浮点类型（F64/F32/F16/BF16）按 double 累加后按 dtype 截断
    // 注意：F16/BF16 没有 C++ 标准类型，按 float 累加后截断
    for (std::size_t i = 0; i < cnt; ++i) {
        double va = 0.0, vb = 0.0;

        if (dtype == ReduceDType::F64) {
            std::memcpy(&va, a.data() + i * 8, 8);
            std::memcpy(&vb, b.data() + i * 8, 8);
        } else if (dtype == ReduceDType::F32) {
            float fa = 0.0f, fb = 0.0f;
            std::memcpy(&fa, a.data() + i * 4, 4);
            std::memcpy(&fb, b.data() + i * 4, 4);
            va = fa;
            vb = fb;
        } else if (dtype == ReduceDType::F16) {
            // IEEE 754 half: 提取符号/指数/尾数转 float
            std::uint16_t ha, hb;
            std::memcpy(&ha, a.data() + i * 2, 2);
            std::memcpy(&hb, b.data() + i * 2, 2);
            va = half_to_float_(ha);
            vb = half_to_float_(hb);
        } else if (dtype == ReduceDType::BF16) {
            // bfloat16: 高 16 位为 float 的高 16 位（低 16 位为 0）
            std::uint16_t ba, bb;
            std::memcpy(&ba, a.data() + i * 2, 2);
            std::memcpy(&bb, b.data() + i * 2, 2);
            va = bf16_to_float_(ba);
            vb = bf16_to_float_(bb);
        }

        double vr;
        switch (op) {
            case ReduceOp::SUM:
            case ReduceOp::AVG:  // AVG 在最终结果中除以 N
                vr = va + vb;
                break;
            case ReduceOp::MAX:
                vr = (va > vb) ? va : vb;
                break;
            case ReduceOp::MIN:
                vr = (va < vb) ? va : vb;
                break;
            default:
                vr = va + vb;
                break;
        }

        // 按 dtype 截断写回
        if (dtype == ReduceDType::F64) {
            std::memcpy(result.data() + i * 8, &vr, 8);
        } else if (dtype == ReduceDType::F32) {
            float fr = static_cast<float>(vr);
            std::memcpy(result.data() + i * 4, &fr, 4);
        } else if (dtype == ReduceDType::F16) {
            std::uint16_t hr = float_to_half_(static_cast<float>(vr));
            std::memcpy(result.data() + i * 2, &hr, 2);
        } else if (dtype == ReduceDType::BF16) {
            std::uint16_t br = float_to_bf16_(static_cast<float>(vr));
            std::memcpy(result.data() + i * 2, &br, 2);
        }
    }

    return result;
}

std::uint32_t SyncPrimitives::popcount_(std::uint64_t mask) {
    // mp-P8 (v1.7.0.8): 逐位循环 64 次 → std::popcount 单指令（POPCNT/CNTB）
    return static_cast<std::uint32_t>(std::popcount(mask));
}

std::vector<std::uint64_t> SyncPrimitives::mask_to_nodes_(std::uint64_t mask) {
    // v2.3 Phase 4 (P4-D 修复): 返回 bit position（1<<bit），与 peer_channels_ key
    // 及 Ring/Tree 函数中 self_bit=(1<<self_node_id) 比较保持一致。
    // 早期版本误返回 bit index（0,1,2...），导致 self_rank 永不匹配：
    //   - Ring 靠 rank_of==SIZE_MAX 守卫降级掩盖了 bug（真实 P2P 通信从未触发）
    //   - Tree 的 self_rank 默认 0 → is_root 错误为 true → 跳过 parent channel 守卫
    // 修复后 participants 元素为 bit position，与 set_peer_channel/set_ring_peers/
    // set_tree_peers 注入的 peer_channels_ key 类型一致。
    std::vector<std::uint64_t> nodes;
    std::uint64_t bit = 0;
    while (mask) {
        if (mask & 1) {
            nodes.push_back(static_cast<std::uint64_t>(1) << bit);
        }
        mask >>= 1;
        ++bit;
    }
    return nodes;
}

// ============================================================================
// v1.7.0.7 C11: F16/BF16 与 float 互转辅助实现
// ============================================================================

float SyncPrimitives::half_to_float_(std::uint16_t h) noexcept {
    // IEEE 754 half-precision (binary16) 转 float (binary32)
    std::uint32_t sign = static_cast<std::uint32_t>(h & 0x8000) << 16;
    std::uint32_t exp = (h >> 10) & 0x1F;
    std::uint32_t mant = h & 0x3FF;

    float result;
    if (exp == 0) {
        if (mant == 0) {
            // 零
            std::uint32_t bits = sign;
            std::memcpy(&result, &bits, 4);
        } else {
            // 非规格化数：调整指数
            exp = 1;
            while ((mant & 0x400) == 0) {
                mant <<= 1;
                --exp;
            }
            mant &= 0x3FF;
            std::uint32_t f_exp = 127 - 15 + exp;
            std::uint32_t bits = sign | (f_exp << 23) | (mant << 13);
            std::memcpy(&result, &bits, 4);
        }
    } else if (exp == 0x1F) {
        // Inf / NaN
        std::uint32_t bits = sign | 0x7F800000u | (mant << 13);
        std::memcpy(&result, &bits, 4);
    } else {
        // 规格化数
        std::uint32_t f_exp = 127 - 15 + exp;
        std::uint32_t bits = sign | (f_exp << 23) | (mant << 13);
        std::memcpy(&result, &bits, 4);
    }
    return result;
}

std::uint16_t SyncPrimitives::float_to_half_(float f) noexcept {
    // float (binary32) 转 IEEE 754 half-precision (binary16)
    std::uint32_t bits;
    std::memcpy(&bits, &f, 4);
    std::uint32_t sign = (bits >> 16) & 0x8000;
    std::int32_t exp = static_cast<std::int32_t>((bits >> 23) & 0xFF) - 127 + 15;
    std::uint32_t mant = (bits >> 13) & 0x3FF;

    if (exp <= 0) {
        // 下溢出（包括非规格化）
        if (exp < -10) {
            // 太小，直接返回 0
            return static_cast<std::uint16_t>(sign);
        }
        // 非规格化数
        mant |= 0x400;
        std::uint32_t shift = static_cast<std::uint32_t>(14 - exp);
        mant >>= shift;
        return static_cast<std::uint16_t>(sign | mant);
    } else if (exp >= 0x1F) {
        // 上溢出：Inf 或 NaN
        if (exp == 0x1F && mant == 0 && (bits & 0x7FFFFF) == 0) {
            // Inf
            return static_cast<std::uint16_t>(sign | 0x7C00);
        }
        // NaN
        return static_cast<std::uint16_t>(sign | 0x7C00 | mant);
    } else {
        return static_cast<std::uint16_t>(sign | (exp << 10) | mant);
    }
}

float SyncPrimitives::bf16_to_float_(std::uint16_t b) noexcept {
    // bfloat16: 高 16 位为 float 的高 16 位，低 16 位为 0
    std::uint32_t bits = static_cast<std::uint32_t>(b) << 16;
    float result;
    std::memcpy(&result, &bits, 4);
    return result;
}

std::uint16_t SyncPrimitives::float_to_bf16_(float f) noexcept {
    // float 转 bfloat16: 截断 float 的低 16 位（round-to-nearest-even 可选，这里用截断）
    std::uint32_t bits;
    std::memcpy(&bits, &f, 4);
    // round-to-nearest-even
    std::uint32_t lsb = (bits >> 16) & 1;
    std::uint32_t rounding_bias = 0x7FFF + lsb;
    bits += rounding_bias;
    return static_cast<std::uint16_t>(bits >> 16);
}

// ============================================================================
// 辅助函数实现
// ============================================================================

const char *reduce_op_name(ReduceOp op) noexcept {
    switch (op) {
        case ReduceOp::SUM: return "SUM";
        case ReduceOp::MAX: return "MAX";
        case ReduceOp::MIN: return "MIN";
        case ReduceOp::AVG: return "AVG";
        default: return "UNKNOWN";
    }
}

const char *sync_state_name(SyncState state) noexcept {
    switch (state) {
        case SyncState::Waiting:   return "Waiting";
        case SyncState::Reducing:  return "Reducing";
        case SyncState::Releasing:return "Releasing";
        case SyncState::Completed: return "Completed";
        case SyncState::TimedOut:  return "TimedOut";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// v2.3 Phase 4 (P4-C): Ring 算法驱动实现
// ============================================================================
//
// Ring AllReduce 状态机流程（N 节点环）：
//
// 发起方（all_reduce_ring_）：
//   1. 校验 algo=Ring + peer_channels_ 已配置 next/prev
//   2. 将 local_data 分成 N 个 chunks（chunk_size = msg/N）
//   3. 初始化 RingAlgoState，执行 step 0：发送 chunks[send_idx] 到 next
//   4. 返回 true，调用方阻塞等待 cv_
//
// 接收方（handle_all_reduce_ring_）：
//   1. 收到 prev 的 step N 帧，校验 step + from_node_id 匹配
//   2. 阶段 1（ReduceScatter）：apply_reduce_ 到 chunks[recv_idx]
//      阶段 2（AllGather）：覆盖 chunks[recv_idx]
//   3. ring_advance_step_：推进 current_step
//   4. 若未完成，发送下一步 chunks[send_idx] 到 next
//   5. 若全部完成，组装 result（N chunks 拼接），标记 Completed
//
// 降级保护（P4-G）：
//   - all_reduce 入口先尝试 all_reduce_ring_，返回 false 则降级简化版
//   - handle_sync_frame 按 algo 路由：Ring 帧且会话有 ring_algo → handle_*_ring_
//     否则 → 简化版 handle_*_（向后兼容）

bool SyncPrimitives::all_reduce_ring_(std::uint64_t sync_id,
                                      std::uint64_t participant_mask,
                                      std::uint64_t self_node_id,
                                      std::span<const std::uint8_t> local_data,
                                      ReduceOp op,
                                      ReduceDType dtype,
                                      std::chrono::milliseconds timeout) {
    // 1. 校验 Ring 路径前提条件
    std::size_t N = popcount_(participant_mask);
    if (N < 2) return false;  // 单节点无需 Ring

    // local_data 必须能被 N 整除（每节点 chunk 等长）
    if (local_data.size() % N != 0) return false;

    std::size_t chunk_size = local_data.size() / N;
    // 单 chunk 不超过 EpSyncFrame payload 上限（Ring 每步发一个 chunk）
    if (chunk_size > EpSyncFrame::kMaxPayloadLen) return false;

    // self_node_id 是 bit index (0-63)，转换为 bit position 用于 RingEngine
    std::uint64_t self_bit = static_cast<std::uint64_t>(1) << self_node_id;

    // 构建 ring 拓扑
    auto participants = mask_to_nodes_(participant_mask);
    if (participants.size() != N) return false;
    auto ring = RingEngine::build_ring(participants);
    auto self_rank = RingEngine::rank_of(participants, self_bit);
    if (self_rank == SIZE_MAX) return false;

    auto nit = ring.find(self_bit);
    if (nit == ring.end()) return false;
    std::uint64_t next_node = nit->second.next;  // bit position
    std::uint64_t prev_node = nit->second.prev;  // bit position

    // 检查 next/prev 的 peer channel 是否已配置
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (peer_channels_.find(next_node) == peer_channels_.end()) return false;
        // prev channel 可以回退到默认 channel_，不强求配置
    }

    // 2. 初始化会话 + RingAlgoState
    auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<std::uint8_t> send_data;  // step 0 要发送的数据（锁外发送）
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;  // 存储 bit index（与简化版一致）
        session.state = SyncState::Reducing;
        session.deadline = deadline;
        session.reduce_op = op;
        session.reduce_dtype = dtype;
        session.algo = 0;  // Ring
        session.local_data.assign(local_data.begin(), local_data.end());
        session.reduced_data.assign(local_data.begin(), local_data.end());
        session.ring_round = 0;
        session.total_rings = static_cast<std::uint32_t>(2 * (N - 1));

        SyncSession::RingAlgoState rs;
        rs.phase = RingPhase::ReduceScatter;
        rs.current_step = 0;
        rs.total_steps = static_cast<std::uint32_t>(2 * (N - 1));
        rs.self_rank = self_rank;
        rs.N = N;
        rs.next_node = next_node;  // bit position
        rs.prev_node = prev_node;  // bit position
        rs.chunk_size = chunk_size;
        rs.op = EpSyncOp::AllReduce;
        rs.chunks.resize(N);
        for (std::size_t i = 0; i < N; ++i) {
            rs.chunks[i].assign(
                local_data.data() + i * chunk_size,
                local_data.data() + (i + 1) * chunk_size);
        }
        rs.step_send_done = false;
        rs.step_recv_done = false;
        session.ring_algo = std::move(rs);

        // 准备 step 0 发送数据
        auto idx = RingEngine::compute_chunk_index(self_rank, 0, N);
        send_data = session.ring_algo->chunks[idx.send_idx];
        session.ring_algo->step_send_done = true;  // 标记即将发送

        sessions_[sync_id] = std::move(session);
    }

    // 3. 锁外发送 step 0（携带 from_node_id=bit position + step=0）
    bool sent = send_to_peer_(next_node, sync_id, EpSyncOp::AllReduce,
                              participant_mask,
                              std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                              static_cast<std::uint8_t>(op),
                              0,    // algo = Ring
                              0, 1, // shard_idx=0, total_shards=1
                              self_bit,  // from_node_id = bit position
                              0);   // step = 0
    if (!sent) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(sync_id);
        return false;
    }

    return true;  // Ring 路径已接管
}

bool SyncPrimitives::all_gather_ring_(std::uint64_t sync_id,
                                      std::uint64_t participant_mask,
                                      std::uint64_t self_node_id,
                                      std::span<const std::uint8_t> local_chunk,
                                      std::chrono::milliseconds timeout) {
    // AllGather-only：仅阶段 2，N-1 步
    std::size_t N = popcount_(participant_mask);
    if (N < 2) return false;

    // AllGather 的 local_chunk 是本节点完整 chunk，不需要均分
    // 结果 = N 个 chunk 拼接（按 rank 升序）
    if (local_chunk.size() > EpSyncFrame::kMaxPayloadLen) return false;

    // self_node_id 是 bit index，转换为 bit position
    std::uint64_t self_bit = static_cast<std::uint64_t>(1) << self_node_id;

    auto participants = mask_to_nodes_(participant_mask);
    auto ring = RingEngine::build_ring(participants);
    auto self_rank = RingEngine::rank_of(participants, self_bit);
    if (self_rank == SIZE_MAX) return false;

    auto nit = ring.find(self_bit);
    if (nit == ring.end()) return false;
    std::uint64_t next_node = nit->second.next;
    std::uint64_t prev_node = nit->second.prev;

    {
        std::lock_guard<std::mutex> lk(mu_);
        if (peer_channels_.find(next_node) == peer_channels_.end()) return false;
    }

    auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<std::uint8_t> send_data;
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;  // bit index
        session.state = SyncState::Reducing;
        session.deadline = deadline;
        session.algo = 0;  // Ring
        session.local_data.assign(local_chunk.begin(), local_chunk.end());
        session.gather_chunk_size = local_chunk.size();

        SyncSession::RingAlgoState rs;
        rs.phase = RingPhase::AllGather;  // 直接进入阶段 2
        rs.current_step = 0;
        rs.total_steps = static_cast<std::uint32_t>(N - 1);
        rs.self_rank = self_rank;
        rs.N = N;
        rs.next_node = next_node;  // bit position
        rs.prev_node = prev_node;  // bit position
        rs.chunk_size = local_chunk.size();
        rs.op = EpSyncOp::AllGather;
        rs.chunks.resize(N);
        // 本节点 chunk 放在 self_rank 位置，其余位置为空（等待接收填充）
        rs.chunks[self_rank].assign(local_chunk.begin(), local_chunk.end());
        rs.step_send_done = false;
        rs.step_recv_done = false;
        session.ring_algo = std::move(rs);

        // step 0：send_idx = (rank - 0 + N) % N = rank，即发送自己的 chunk
        auto idx = RingEngine::all_gather_chunk_index(self_rank, 0, N);
        send_data = session.ring_algo->chunks[idx.send_idx];
        session.ring_algo->step_send_done = true;

        sessions_[sync_id] = std::move(session);
    }

    bool sent = send_to_peer_(next_node, sync_id, EpSyncOp::AllGather,
                              participant_mask,
                              std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                              0,    // reduce_op 不适用
                              0,    // algo = Ring
                              0, 1, // shard_idx=0, total_shards=1
                              self_bit,  // from_node_id = bit position
                              0);
    if (!sent) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(sync_id);
        return false;
    }
    return true;
}

bool SyncPrimitives::reduce_scatter_ring_(std::uint64_t sync_id,
                                          std::uint64_t participant_mask,
                                          std::uint64_t self_node_id,
                                          std::span<const std::uint8_t> local_data,
                                          ReduceOp op,
                                          ReduceDType dtype,
                                          std::chrono::milliseconds timeout) {
    // ReduceScatter-only：仅阶段 1，N-1 步，结束后本节点拥有 chunk[self_rank] 规约结果
    std::size_t N = popcount_(participant_mask);
    if (N < 2) return false;
    if (local_data.size() % N != 0) return false;

    std::size_t chunk_size = local_data.size() / N;
    if (chunk_size > EpSyncFrame::kMaxPayloadLen) return false;

    // self_node_id 是 bit index，转换为 bit position
    std::uint64_t self_bit = static_cast<std::uint64_t>(1) << self_node_id;

    auto participants = mask_to_nodes_(participant_mask);
    auto ring = RingEngine::build_ring(participants);
    auto self_rank = RingEngine::rank_of(participants, self_bit);
    if (self_rank == SIZE_MAX) return false;

    auto nit = ring.find(self_bit);
    if (nit == ring.end()) return false;
    std::uint64_t next_node = nit->second.next;
    std::uint64_t prev_node = nit->second.prev;

    {
        std::lock_guard<std::mutex> lk(mu_);
        if (peer_channels_.find(next_node) == peer_channels_.end()) return false;
    }

    auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<std::uint8_t> send_data;
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;  // bit index
        session.state = SyncState::Reducing;
        session.deadline = deadline;
        session.reduce_op = op;
        session.reduce_dtype = dtype;
        session.algo = 0;  // Ring
        session.local_data.assign(local_data.begin(), local_data.end());
        session.scatter_chunk_index = static_cast<std::uint32_t>(self_rank);

        SyncSession::RingAlgoState rs;
        rs.phase = RingPhase::ReduceScatter;  // 仅阶段 1
        rs.current_step = 0;
        rs.total_steps = static_cast<std::uint32_t>(N - 1);
        rs.self_rank = self_rank;
        rs.N = N;
        rs.next_node = next_node;  // bit position
        rs.prev_node = prev_node;  // bit position
        rs.chunk_size = chunk_size;
        rs.op = EpSyncOp::ReduceScatter;
        rs.chunks.resize(N);
        for (std::size_t i = 0; i < N; ++i) {
            rs.chunks[i].assign(
                local_data.data() + i * chunk_size,
                local_data.data() + (i + 1) * chunk_size);
        }
        rs.step_send_done = false;
        rs.step_recv_done = false;
        session.ring_algo = std::move(rs);

        auto idx = RingEngine::reduce_scatter_chunk_index(self_rank, 0, N);
        send_data = session.ring_algo->chunks[idx.send_idx];
        session.ring_algo->step_send_done = true;

        sessions_[sync_id] = std::move(session);
    }

    bool sent = send_to_peer_(next_node, sync_id, EpSyncOp::ReduceScatter,
                              participant_mask,
                              std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                              static_cast<std::uint8_t>(op),
                              0, 0, 1, self_bit, 0);
    if (!sent) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(sync_id);
        return false;
    }
    return true;
}

// ============================================================================
// P4-C: Ring 状态机步进推进（锁内调用，不发数据）
// ============================================================================

bool SyncPrimitives::ring_advance_step_(SyncSession &session) {
    // 前提：调用方持锁，session.ring_algo 有值
    auto &rs = session.ring_algo.value();
    if (!rs.step_send_done || !rs.step_recv_done) {
        return false;  // 当前步未完成，继续等待
    }

    rs.current_step++;
    rs.step_send_done = false;
    rs.step_recv_done = false;

    if (rs.current_step >= rs.total_steps) {
        // 全部步数完成，组装最终结果
        rs.result.clear();
        if (rs.op == EpSyncOp::ReduceScatter) {
            // ReduceScatter 结果：仅本节点的 chunk[self_rank]
            rs.result = rs.chunks[rs.self_rank];
        } else {
            // AllReduce / AllGather 结果：N 个 chunks 拼接（按 rank 升序）
            for (std::size_t i = 0; i < rs.N; ++i) {
                rs.result.insert(rs.result.end(),
                                 rs.chunks[i].begin(), rs.chunks[i].end());
            }
        }
        session.reduced_data = rs.result;
        session.state = SyncState::Completed;
        return true;  // 全部完成
    }
    return false;  // 还有剩余步数
}

// ============================================================================
// P4-C: Ring 接收方帧处理
// ============================================================================

void SyncPrimitives::handle_all_reduce_ring_(const EpSyncFrame &frame) {
    bool completed = false;
    std::vector<std::uint8_t> completed_result;
    // 锁外发送准备
    bool need_send = false;
    std::vector<std::uint8_t> send_data;
    std::uint64_t send_target = 0;
    std::uint64_t send_sid = 0;
    std::uint8_t send_reduce_op = 0;
    std::uint16_t send_step = 0;
    std::uint64_t send_from = 0;
    std::uint64_t send_pmask = 0;

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(frame.sync_id);
        if (it == sessions_.end() || !it->second.ring_algo.has_value()) {
            return;  // 非 Ring 会话或会话不存在，降级路径处理
        }

        auto &session = it->second;
        auto &rs = session.ring_algo.value();

        // 校验 step 匹配（防止乱序/重复帧）
        if (frame.step != rs.current_step) return;
        // 校验来源是 prev_node
        if (frame.from_node_id != rs.prev_node) return;

        rs.step_recv_done = true;

        // 按阶段处理接收数据
        auto idx = RingEngine::compute_chunk_index(rs.self_rank, rs.current_step, rs.N);
        auto phase = RingEngine::phase_of(rs.current_step, rs.N);

        if (phase == RingPhase::ReduceScatter) {
            // 阶段 1：规约到 chunks[recv_idx]
            rs.chunks[idx.recv_idx] = apply_reduce_(
                std::span<const std::uint8_t>(rs.chunks[idx.recv_idx].data(),
                                              rs.chunks[idx.recv_idx].size()),
                std::span<const std::uint8_t>(frame.payload.data(), frame.payload.size()),
                session.reduce_op, session.reduce_dtype);
        } else if (phase == RingPhase::AllGather) {
            // 阶段 2：覆盖 chunks[recv_idx]
            rs.chunks[idx.recv_idx].assign(frame.payload.begin(), frame.payload.end());
        }

        // 推进步进
        bool done = ring_advance_step_(session);
        if (done) {
            completed = true;
            completed_result = rs.result;
        } else if (rs.step_send_done == false) {
            // 需要发送下一步
            auto next_idx = RingEngine::compute_chunk_index(rs.self_rank, rs.current_step, rs.N);
            send_data = rs.chunks[next_idx.send_idx];
            send_target = rs.next_node;
            send_sid = frame.sync_id;
            send_reduce_op = frame.reduce_op;
            send_step = static_cast<std::uint16_t>(rs.current_step);
            send_from = static_cast<std::uint64_t>(1) << session.self_node_id;  // bit position
            send_pmask = session.participant_mask;
            need_send = true;
            rs.step_send_done = true;  // 标记即将发送
        }
    }

    // 锁外发送下一步
    if (need_send) {
        send_to_peer_(send_target, send_sid, EpSyncOp::AllReduce, send_pmask,
                      std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                      send_reduce_op, 0, 0, 1, send_from, send_step);
    }

    if (completed) {
        notify_all_reduce_complete_(frame.sync_id,
            std::span<const std::uint8_t>(completed_result.data(), completed_result.size()));
        cv_.notify_all();
    }
}

void SyncPrimitives::handle_all_gather_ring_(const EpSyncFrame &frame) {
    bool completed = false;
    std::vector<std::uint8_t> completed_result;
    bool need_send = false;
    std::vector<std::uint8_t> send_data;
    std::uint64_t send_target = 0;
    std::uint64_t send_sid = 0;
    std::uint16_t send_step = 0;
    std::uint64_t send_from = 0;
    std::uint64_t send_pmask = 0;

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(frame.sync_id);
        if (it == sessions_.end() || !it->second.ring_algo.has_value()) {
            return;
        }

        auto &session = it->second;
        auto &rs = session.ring_algo.value();

        if (frame.step != rs.current_step) return;
        if (frame.from_node_id != rs.prev_node) return;

        rs.step_recv_done = true;

        // AllGather：覆盖 chunks[recv_idx]
        auto idx = RingEngine::all_gather_chunk_index(rs.self_rank, rs.current_step, rs.N);
        rs.chunks[idx.recv_idx].assign(frame.payload.begin(), frame.payload.end());

        bool done = ring_advance_step_(session);
        if (done) {
            completed = true;
            completed_result = rs.result;
        } else if (rs.step_send_done == false) {
            auto next_idx = RingEngine::all_gather_chunk_index(rs.self_rank, rs.current_step, rs.N);
            send_data = rs.chunks[next_idx.send_idx];
            send_target = rs.next_node;
            send_sid = frame.sync_id;
            send_step = static_cast<std::uint16_t>(rs.current_step);
            send_from = static_cast<std::uint64_t>(1) << session.self_node_id;  // bit position
            send_pmask = session.participant_mask;
            need_send = true;
            rs.step_send_done = true;
        }
    }

    if (need_send) {
        send_to_peer_(send_target, send_sid, EpSyncOp::AllGather, send_pmask,
                      std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                      0, 0, 0, 1, send_from, send_step);
    }

    if (completed) {
        notify_all_gather_complete_(frame.sync_id,
            std::span<const std::uint8_t>(completed_result.data(), completed_result.size()));
        cv_.notify_all();
    }
}

void SyncPrimitives::handle_reduce_scatter_ring_(const EpSyncFrame &frame) {
    bool completed = false;
    std::vector<std::uint8_t> completed_result;
    bool need_send = false;
    std::vector<std::uint8_t> send_data;
    std::uint64_t send_target = 0;
    std::uint64_t send_sid = 0;
    std::uint8_t send_reduce_op = 0;
    std::uint16_t send_step = 0;
    std::uint64_t send_from = 0;
    std::uint64_t send_pmask = 0;

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(frame.sync_id);
        if (it == sessions_.end() || !it->second.ring_algo.has_value()) {
            return;
        }

        auto &session = it->second;
        auto &rs = session.ring_algo.value();

        if (frame.step != rs.current_step) return;
        if (frame.from_node_id != rs.prev_node) return;

        rs.step_recv_done = true;

        // ReduceScatter：规约到 chunks[recv_idx]
        auto idx = RingEngine::reduce_scatter_chunk_index(rs.self_rank, rs.current_step, rs.N);
        rs.chunks[idx.recv_idx] = apply_reduce_(
            std::span<const std::uint8_t>(rs.chunks[idx.recv_idx].data(),
                                          rs.chunks[idx.recv_idx].size()),
            std::span<const std::uint8_t>(frame.payload.data(), frame.payload.size()),
            session.reduce_op, session.reduce_dtype);

        bool done = ring_advance_step_(session);
        if (done) {
            completed = true;
            completed_result = rs.result;  // 仅 chunks[self_rank]
        } else if (rs.step_send_done == false) {
            auto next_idx = RingEngine::reduce_scatter_chunk_index(rs.self_rank, rs.current_step, rs.N);
            send_data = rs.chunks[next_idx.send_idx];
            send_target = rs.next_node;
            send_sid = frame.sync_id;
            send_reduce_op = frame.reduce_op;
            send_step = static_cast<std::uint16_t>(rs.current_step);
            send_from = static_cast<std::uint64_t>(1) << session.self_node_id;  // bit position
            send_pmask = session.participant_mask;
            need_send = true;
            rs.step_send_done = true;
        }
    }

    if (need_send) {
        send_to_peer_(send_target, send_sid, EpSyncOp::ReduceScatter, send_pmask,
                      std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                      send_reduce_op, 0, 0, 1, send_from, send_step);
    }

    if (completed) {
        notify_reduce_scatter_complete_(frame.sync_id,
            std::span<const std::uint8_t>(completed_result.data(), completed_result.size()));
        cv_.notify_all();
    }
}

// ============================================================================
// v2.3 Phase 4 (P4-D): Tree 算法驱动 — 发起方
// ============================================================================
//
// Tree Broadcast/AllGather 状态机流程：
//
// Broadcast（binomial tree 向下扩散，log₂N 步）：
//   发起方（broadcast_tree_）：
//     - root：同步循环发送 log₂N 步，每步向一个 child 扩散，发完即完成
//     - 非 root：初始化 tree_algo 状态，等待 recv_step 接收父数据
//   接收方（handle_broadcast_tree_）：
//     - 收到父数据后，向所有 children 转发（循环发送后续步），标记完成
//
// AllGather（两阶段：GatherUp + BroadcastDown，2×log₂N 步）：
//   发起方（all_gather_tree_）：
//     - 叶子：向 parent 发送自身 chunk
//     - internal/root：等待所有 children 数据到齐
//   接收方（handle_all_gather_tree_）：
//     - GatherUp：累积 children chunk，全到齐后向 parent 发送（root 转 BroadcastDown）
//     - BroadcastDown：接收完整 result，向 children 转发，标记完成
//
// 降级保护（与 Ring 一致）：
//   - broadcast/all_gather 入口先尝试 *_tree_，返回 false 则降级简化版
//   - handle_sync_frame 按 algo 路由：Tree 帧且会话有 tree_algo → handle_*_tree_
//     否则 → 简化版 handle_*_（向后兼容）

bool SyncPrimitives::broadcast_tree_(std::uint64_t sync_id,
                                     std::uint64_t participant_mask,
                                     std::uint64_t root_node_id,
                                     std::uint64_t self_node_id,
                                     std::span<const std::uint8_t> data,
                                     std::chrono::milliseconds timeout) {
    // 1. 守卫校验
    std::size_t N = popcount_(participant_mask);
    if (N < 2) return false;  // 单节点无需 Tree
    if (data.size() > EpSyncFrame::kMaxPayloadLen) return false;

    std::uint64_t self_bit = static_cast<std::uint64_t>(1) << self_node_id;
    std::uint64_t root_bit = static_cast<std::uint64_t>(1) << root_node_id;
    if ((participant_mask & self_bit) == 0) return false;
    if ((participant_mask & root_bit) == 0) return false;

    // 2. 构建 binomial tree
    auto participants = mask_to_nodes_(participant_mask);
    std::size_t root_rank = 0, self_rank = 0;
    for (std::size_t i = 0; i < participants.size(); ++i) {
        if (participants[i] == root_bit) root_rank = i;
        if (participants[i] == self_bit) self_rank = i;
    }

    std::size_t self_virtual = TreeEngine::to_virtual(self_rank, root_rank);
    bool is_root = (self_rank == root_rank);
    std::size_t steps = TreeEngine::total_steps(N);

    // 3. 推导 parent/children/recv_step
    auto parent_opt = TreeEngine::parent_of(self_virtual);
    auto children_virtual = TreeEngine::children_of(self_virtual, N);

    std::uint64_t parent_bit = 0;
    if (parent_opt.has_value()) {
        parent_bit = participants[TreeEngine::to_real(parent_opt.value(), root_rank)];
    }
    std::vector<std::uint64_t> children_bits;
    for (auto cv : children_virtual) {
        children_bits.push_back(participants[TreeEngine::to_real(cv, root_rank)]);
    }

    std::uint32_t recv_step = UINT32_MAX;  // root 不接收
    if (!is_root) {
        auto rs = TreeEngine::recv_step_of(self_virtual);
        recv_step = rs.has_value() ? static_cast<std::uint32_t>(rs.value()) : UINT32_MAX;
    }

    // 4. 检查 parent channel（非 root 的 BroadcastDown 需从 parent 接收数据）
    //    P4-D 修复: 即使 leaf 无 children 不需发送，也必须注册 parent channel
    //    以保证 Tree 拓扑完整。否则 leaf 会创建 TreeAlgoState 后无限等待
    //    父数据（永不到达）→ 超时擦除会话，与 all_gather_tree_ 行为不一致。
    if (!is_root) {
        std::lock_guard<std::mutex> lk(mu_);
        if (peer_channels_.find(parent_bit) == peer_channels_.end()) return false;
    }
    // 4b. 检查 children channel（root/internal 需要；leaf 无 children 跳过）
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto cb : children_bits) {
            if (peer_channels_.find(cb) == peer_channels_.end()) return false;
        }
    }

    // 5. 初始化会话 + TreeAlgoState
    auto deadline = std::chrono::steady_clock::now() + timeout;
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;
        session.root_node_id = root_node_id;
        session.state = is_root ? SyncState::Releasing : SyncState::Waiting;
        session.deadline = deadline;
        session.algo = 1;  // Tree

        SyncSession::TreeAlgoState ts;
        ts.phase = SyncSession::TreePhase::BroadcastDown;
        ts.current_step = 0;
        ts.total_steps = static_cast<std::uint32_t>(steps);
        ts.recv_step = recv_step;
        ts.children_received = 0;
        ts.self_virtual = self_virtual;
        ts.root_rank = root_rank;
        ts.N = N;
        ts.parent_bit = parent_bit;
        ts.children_bits = children_bits;
        ts.is_root = is_root;
        ts.data.assign(data.begin(), data.end());
        ts.op = EpSyncOp::Broadcast;
        ts.step_send_done = false;
        ts.step_recv_done = false;
        session.tree_algo = std::move(ts);
        sessions_[sync_id] = std::move(session);
    }

    // 6. root 同步循环发送所有步（锁外）
    if (is_root) {
        for (std::size_t step = 0; step < steps; ++step) {
            auto target_opt = TreeEngine::send_target_at_step(self_virtual, step, N);
            if (!target_opt.has_value()) continue;
            std::uint64_t target_bit = participants[TreeEngine::to_real(target_opt.value(), root_rank)];
            bool sent = send_to_peer_(target_bit, sync_id, EpSyncOp::Broadcast,
                                      participant_mask,
                                      std::span<const std::uint8_t>(data.data(), data.size()),
                                      0,    // reduce_op
                                      1,    // algo = Tree
                                      0, 1, // shard_idx=0, total_shards=1
                                      self_bit,
                                      static_cast<std::uint16_t>(step));
            if (!sent) {
                std::lock_guard<std::mutex> lk(mu_);
                sessions_.erase(sync_id);
                return false;
            }
        }
        // root 发完即完成
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(sync_id);
        if (it != sessions_.end()) {
            it->second.state = SyncState::Completed;
            it->second.tree_algo->result.assign(data.begin(), data.end());
        }
    }
    // 非 root：等待 handle_broadcast_tree_ 接收父数据

    return true;  // Tree 路径已接管
}

bool SyncPrimitives::all_gather_tree_(std::uint64_t sync_id,
                                      std::uint64_t participant_mask,
                                      std::uint64_t self_node_id,
                                      std::span<const std::uint8_t> local_chunk,
                                      std::chrono::milliseconds timeout) {
    // 1. 守卫校验
    std::size_t N = popcount_(participant_mask);
    if (N < 2) return false;
    if (local_chunk.size() > EpSyncFrame::kMaxPayloadLen) return false;

    std::uint64_t self_bit = static_cast<std::uint64_t>(1) << self_node_id;
    if ((participant_mask & self_bit) == 0) return false;

    // 2. 构建 binomial tree（root_rank=0，即 participants[0] 为收集 root）
    auto participants = mask_to_nodes_(participant_mask);
    std::size_t root_rank = 0, self_rank = 0;
    for (std::size_t i = 0; i < participants.size(); ++i) {
        if (participants[i] == self_bit) self_rank = i;
    }

    std::size_t self_virtual = TreeEngine::to_virtual(self_rank, root_rank);
    bool is_root = (self_rank == root_rank);
    std::size_t steps = TreeEngine::total_steps(N);

    // 3. 推导 parent/children
    auto parent_opt = TreeEngine::parent_of(self_virtual);
    auto children_virtual = TreeEngine::children_of(self_virtual, N);

    std::uint64_t parent_bit = 0;
    if (parent_opt.has_value()) {
        parent_bit = participants[TreeEngine::to_real(parent_opt.value(), root_rank)];
    }
    std::vector<std::uint64_t> children_bits;
    for (auto cv : children_virtual) {
        children_bits.push_back(participants[TreeEngine::to_real(cv, root_rank)]);
    }

    // 4. 检查 parent channel（非 root 的 GatherUp 需向 parent 发送）
    if (!is_root) {
        std::lock_guard<std::mutex> lk(mu_);
        if (peer_channels_.find(parent_bit) == peer_channels_.end()) return false;
    }
    // 4b. 检查 children channel（root/internal 的 GatherUp 收 children + BroadcastDown 发 children）
    //     leaf 无 children 跳过；root/internal 必须为每个 child 配置 channel，否则降级
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto cb : children_bits) {
            if (peer_channels_.find(cb) == peer_channels_.end()) return false;
        }
    }

    // 5. 初始化会话 + TreeAlgoState
    auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<std::uint8_t> leaf_send_data;  // 叶子 step 0 发送数据
    bool leaf_need_send = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;
        session.state = SyncState::Waiting;
        session.deadline = deadline;
        session.algo = 1;  // Tree
        session.gather_chunk_size = local_chunk.size();

        SyncSession::TreeAlgoState ts;
        ts.phase = SyncSession::TreePhase::GatherUp;
        ts.current_step = 0;
        ts.total_steps = static_cast<std::uint32_t>(steps);
        ts.recv_step = is_root ? UINT32_MAX : static_cast<std::uint32_t>(
                            TreeEngine::recv_step_of(self_virtual).value_or(0));
        ts.children_received = 0;
        ts.self_virtual = self_virtual;
        ts.root_rank = root_rank;
        ts.N = N;
        ts.parent_bit = parent_bit;
        ts.children_bits = children_bits;
        ts.is_root = is_root;
        ts.chunk_size = local_chunk.size();
        ts.op = EpSyncOp::AllGather;
        ts.step_send_done = false;
        ts.step_recv_done = false;

        // 初始化 chunks：本节点 chunk 放在 self_virtual 位置
        ts.chunks.resize(N);
        ts.chunks[self_virtual].assign(local_chunk.begin(), local_chunk.end());

        // 叶子节点（无 children）：立即向 parent 发送自身 chunk
        if (!is_root && children_bits.empty()) {
            leaf_send_data = ts.chunks[self_virtual];
            leaf_need_send = true;
            ts.step_send_done = true;
        }

        session.tree_algo = std::move(ts);
        sessions_[sync_id] = std::move(session);
    }

    // 6. 叶子节点锁外发送 step 0（向 parent 发送自身 chunk）
    if (leaf_need_send) {
        bool sent = send_to_peer_(parent_bit, sync_id, EpSyncOp::AllGather,
                                  participant_mask,
                                  std::span<const std::uint8_t>(leaf_send_data.data(), leaf_send_data.size()),
                                  0,    // reduce_op
                                  1,    // algo = Tree
                                  0, 1, // shard
                                  self_bit,
                                  0);   // step = 0
        if (!sent) {
            std::lock_guard<std::mutex> lk(mu_);
            sessions_.erase(sync_id);
            return false;
        }
    }
    // 非 root 非叶子：等待 children 数据到齐后向 parent 发送
    // root：等待所有 children 数据到齐后转 BroadcastDown

    return true;  // Tree 路径已接管
}

// ============================================================================
// v2.3 Phase 4 (P4-D): Tree 状态机步进推进（锁内调用，不发数据）
// ============================================================================

bool SyncPrimitives::tree_advance_step_(SyncSession &session) {
    auto &ts = session.tree_algo.value();

    if (ts.op == EpSyncOp::Broadcast) {
        // Broadcast：收到父数据即完成（转发由 handle 函数锁外执行）
        ts.phase = SyncSession::TreePhase::Done;
        ts.result = ts.data;
        session.state = SyncState::Completed;
        return true;
    }

    // AllGather
    if (ts.phase == SyncSession::TreePhase::GatherUp) {
        // 检查所有 children 是否已到齐
        if (ts.children_received < ts.children_bits.size()) {
            return false;  // 继续等待
        }
        // children 全到齐
        if (ts.is_root) {
            // root：组装完整 result，转 BroadcastDown
            ts.result.clear();
            for (std::size_t i = 0; i < ts.N; ++i) {
                if (!ts.chunks[i].empty()) {
                    ts.result.insert(ts.result.end(), ts.chunks[i].begin(), ts.chunks[i].end());
                }
            }
            ts.phase = SyncSession::TreePhase::BroadcastDown;
            ts.current_step = 0;
            ts.step_send_done = false;
            ts.step_recv_done = true;  // root 在 BroadcastDown 不接收
            return false;  // 转 BroadcastDown 但未完成
        } else {
            // 非 root：合并 chunks 向 parent 发送（由 handle 函数执行发送）
            ts.step_send_done = true;
            return false;  // 等待发送后不在此标记完成
        }
    }

    if (ts.phase == SyncSession::TreePhase::BroadcastDown) {
        // 收到父数据即完成
        ts.phase = SyncSession::TreePhase::Done;
        if (ts.result.empty()) {
            ts.result = ts.data;
        }
        session.state = SyncState::Completed;
        return true;
    }

    return false;
}

// ============================================================================
// v2.3 Phase 4 (P4-D): Tree 接收方帧处理
// ============================================================================

void SyncPrimitives::handle_broadcast_tree_(const EpSyncFrame &frame) {
    bool completed = false;
    std::vector<std::uint8_t> completed_data;
    std::uint64_t completed_root = 0;

    // 锁外发送准备
    bool need_send = false;
    std::vector<std::uint8_t> send_data;
    std::vector<std::pair<std::uint64_t, std::uint16_t>> sends;  // (target_bit, step)
    std::uint64_t send_sid = 0;
    std::uint64_t send_pmask = 0;
    std::uint64_t send_from = 0;

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(frame.sync_id);
        if (it == sessions_.end() || !it->second.tree_algo.has_value()) {
            return;  // 非 Tree 会话或会话不存在
        }

        auto &session = it->second;
        auto &ts = session.tree_algo.value();

        // 校验：非 root 且 step 匹配 recv_step 且 from_node_id 匹配 parent
        if (ts.is_root) return;
        if (frame.step != ts.recv_step) return;
        if (frame.from_node_id != ts.parent_bit) return;

        // 存储数据
        ts.data.assign(frame.payload.begin(), frame.payload.end());
        ts.step_recv_done = true;

        // 准备向 children 转发
        if (!ts.children_bits.empty()) {
            auto participants = mask_to_nodes_(session.participant_mask);
            send_data = ts.data;
            send_sid = frame.sync_id;
            send_pmask = session.participant_mask;
            send_from = static_cast<std::uint64_t>(1) << session.self_node_id;
            for (std::size_t step = ts.recv_step + 1; step < ts.total_steps; ++step) {
                auto target_opt = TreeEngine::send_target_at_step(ts.self_virtual, step, ts.N);
                if (target_opt.has_value()) {
                    std::uint64_t tb = participants[TreeEngine::to_real(target_opt.value(), ts.root_rank)];
                    sends.push_back({tb, static_cast<std::uint16_t>(step)});
                }
            }
            need_send = !sends.empty();
            ts.step_send_done = true;
        }

        // 标记完成
        tree_advance_step_(session);
        completed = (session.state == SyncState::Completed);
        if (completed) {
            completed_data = ts.result;
            completed_root = session.root_node_id;
        }
    }

    // 锁外向 children 转发
    if (need_send) {
        for (const auto &s : sends) {
            send_to_peer_(s.first, send_sid, EpSyncOp::Broadcast, send_pmask,
                          std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                          0, 1, 0, 1, send_from, s.second);
        }
    }

    if (completed) {
        notify_broadcast_received_(frame.sync_id, completed_root,
            std::span<const std::uint8_t>(completed_data.data(), completed_data.size()));
        cv_.notify_all();
    }
}

void SyncPrimitives::handle_all_gather_tree_(const EpSyncFrame &frame) {
    bool completed = false;
    std::vector<std::uint8_t> completed_result;

    // 锁外发送准备
    bool need_send = false;
    std::vector<std::uint8_t> send_data;
    std::uint64_t send_target = 0;
    std::uint64_t send_sid = 0;
    std::uint64_t send_pmask = 0;
    std::uint64_t send_from = 0;
    std::uint16_t send_step = 0;

    // BroadcastDown 转发准备
    bool need_bcast_send = false;
    std::vector<std::uint8_t> bcast_data;
    std::vector<std::uint64_t> bcast_targets;
    std::uint64_t bcast_sid = 0;
    std::uint64_t bcast_pmask = 0;
    std::uint64_t bcast_from = 0;

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(frame.sync_id);
        if (it == sessions_.end() || !it->second.tree_algo.has_value()) {
            return;
        }

        auto &session = it->second;
        auto &ts = session.tree_algo.value();

        if (ts.phase == SyncSession::TreePhase::GatherUp) {
            // GatherUp 阶段：从 child 接收累积 chunk
            // 校验 from_node_id 是某 child bit
            bool valid_child = false;
            std::size_t child_virtual = 0;
            auto participants = mask_to_nodes_(session.participant_mask);
            for (auto cv : TreeEngine::children_of(ts.self_virtual, ts.N)) {
                std::uint64_t cb = participants[TreeEngine::to_real(cv, ts.root_rank)];
                if (frame.from_node_id == cb) {
                    valid_child = true;
                    child_virtual = cv;
                    break;
                }
            }
            if (!valid_child) return;

            // 将 payload 存入 chunks[child_virtual]
            // payload 包含 child 已收集的所有 chunk（按 virtual rank 升序）
            // 简化策略：按 chunk_size 拆分 payload 到对应 chunks 位置
            if (ts.chunk_size > 0) {
                std::size_t n_chunks = frame.payload.size() / ts.chunk_size;
                for (std::size_t i = 0; i < n_chunks; ++i) {
                    // child 发来的数据按 virtual rank 升序，起始 virtual = child_virtual - 已收集范围
                    // 简化：直接按 child 的 virtual rank 附近存储
                    // 实际上 child 发来的 chunks 覆盖以 child_virtual 为根的子树
                    // 首版简化：用 child_virtual 作为基准，逐 chunk 存储
                    std::size_t offset = i * ts.chunk_size;
                    // child 发送的 chunks 按 virtual rank 升序，
                    // child 的子树范围 = [child_virtual, child_virtual + 2^step - 1]
                    // 但简化版直接按顺序追加到 result
                }
            }
            // 简化存储：直接追加到 chunks[child_virtual]
            ts.chunks[child_virtual].assign(frame.payload.begin(), frame.payload.end());

            ts.children_received++;

            // 检查是否所有 children 已到齐
            if (ts.children_received >= ts.children_bits.size()) {
                if (ts.is_root) {
                    // root：组装完整 result，转 BroadcastDown
                    ts.result.clear();
                    for (std::size_t i = 0; i < ts.N; ++i) {
                        ts.result.insert(ts.result.end(), ts.chunks[i].begin(), ts.chunks[i].end());
                    }
                    ts.phase = SyncSession::TreePhase::BroadcastDown;
                    ts.current_step = 0;
                    ts.step_recv_done = true;

                    // root 向所有 children 分发完整 result
                    if (!ts.children_bits.empty()) {
                        bcast_data = ts.result;
                        bcast_targets = ts.children_bits;
                        bcast_sid = frame.sync_id;
                        bcast_pmask = session.participant_mask;
                        bcast_from = static_cast<std::uint64_t>(1) << session.self_node_id;
                        need_bcast_send = true;
                        ts.step_send_done = true;
                    }
                    // root 在 BroadcastDown 不接收，直接标记完成
                    ts.phase = SyncSession::TreePhase::Done;
                    session.state = SyncState::Completed;
                    session.reduced_data = ts.result;
                    completed = true;
                    completed_result = ts.result;
                } else {
                    // 非 root：合并自身 + children chunks，向 parent 发送
                    send_data.clear();
                    for (std::size_t i = 0; i < ts.N; ++i) {
                        if (!ts.chunks[i].empty()) {
                            send_data.insert(send_data.end(), ts.chunks[i].begin(), ts.chunks[i].end());
                        }
                    }
                    send_target = ts.parent_bit;
                    send_sid = frame.sync_id;
                    send_pmask = session.participant_mask;
                    send_from = static_cast<std::uint64_t>(1) << session.self_node_id;
                    send_step = static_cast<std::uint16_t>(ts.recv_step);
                    need_send = true;
                    ts.step_send_done = true;
                    // 非 root GatherUp 发送后不标记完成，等待 BroadcastDown 接收
                }
            }
        } else if (ts.phase == SyncSession::TreePhase::BroadcastDown) {
            // BroadcastDown 阶段：从 parent 接收完整 result
            if (frame.from_node_id != ts.parent_bit) return;

            ts.result.assign(frame.payload.begin(), frame.payload.end());
            ts.step_recv_done = true;

            // 向 children 转发
            if (!ts.children_bits.empty()) {
                bcast_data = ts.result;
                bcast_targets = ts.children_bits;
                bcast_sid = frame.sync_id;
                bcast_pmask = session.participant_mask;
                bcast_from = static_cast<std::uint64_t>(1) << session.self_node_id;
                need_bcast_send = true;
                ts.step_send_done = true;
            }

            // 标记完成
            ts.phase = SyncSession::TreePhase::Done;
            session.state = SyncState::Completed;
            session.reduced_data = ts.result;
            completed = true;
            completed_result = ts.result;
        }
    }

    // 锁外发送：GatherUp 向 parent
    if (need_send) {
        send_to_peer_(send_target, send_sid, EpSyncOp::AllGather, send_pmask,
                      std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                      0, 1, 0, 1, send_from, send_step);
    }

    // 锁外发送：BroadcastDown 向 children
    if (need_bcast_send) {
        for (std::uint64_t target : bcast_targets) {
            send_to_peer_(target, bcast_sid, EpSyncOp::AllGather, bcast_pmask,
                          std::span<const std::uint8_t>(bcast_data.data(), bcast_data.size()),
                          0, 1, 0, 1, bcast_from, 0);
        }
    }

    if (completed) {
        notify_all_gather_complete_(frame.sync_id,
            std::span<const std::uint8_t>(completed_result.data(), completed_result.size()));
        cv_.notify_all();
    }
}

// ============================================================================
// v2.3 Phase 4 (P4-E): RecursiveHalving 引擎接入
// ============================================================================

bool SyncPrimitives::all_reduce_rh_(std::uint64_t sync_id,
                                     std::uint64_t participant_mask,
                                     std::uint64_t self_node_id,
                                     std::span<const std::uint8_t> local_data,
                                     ReduceOp op,
                                     ReduceDType dtype,
                                     std::chrono::milliseconds timeout) {
    // 1. 守卫校验
    std::size_t N = popcount_(participant_mask);
    if (N < 2) return false;
    if (!RHEngine::is_power_of_two(N)) return false;  // RH 要求 N 为 2 的幂
    if (local_data.size() % N != 0) return false;

    std::size_t chunk_size = local_data.size() / N;
    if (chunk_size > EpSyncFrame::kMaxPayloadLen) return false;

    std::uint64_t self_bit = static_cast<std::uint64_t>(1) << self_node_id;
    if ((participant_mask & self_bit) == 0) return false;

    // 2. 构建 participants，计算 self_rank
    auto participants = mask_to_nodes_(participant_mask);
    std::size_t self_rank = 0;
    bool found = false;
    for (std::size_t i = 0; i < participants.size(); ++i) {
        if (participants[i] == self_bit) { self_rank = i; found = true; break; }
    }
    if (!found) return false;

    // 3. 计算 log₂N 个 partner 并检查 channel
    std::size_t log2N = RHEngine::reduce_scatter_steps(N);
    std::vector<std::uint64_t> partner_bits_all;  // 所有步的 partner（含 AllGather 阶段）
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (std::size_t step = 0; step < 2 * log2N; ++step) {
            auto info = RHEngine::all_reduce_step(self_rank, step, N, local_data.size());
            if (!info.valid) return false;
            std::uint64_t pbit = participants[info.partner_rank];
            partner_bits_all.push_back(pbit);
            if (peer_channels_.find(pbit) == peer_channels_.end()) return false;
        }
    }

    // 4. 初始化会话 + RhAlgoState
    auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<std::uint8_t> send_data;
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;
        session.state = SyncState::Reducing;
        session.deadline = deadline;
        session.reduce_op = op;
        session.reduce_dtype = dtype;
        session.algo = 2;  // RH
        session.local_data.assign(local_data.begin(), local_data.end());

        SyncSession::RhAlgoState rs;
        rs.phase = RHPhase::ReduceScatter;
        rs.current_step = 0;
        rs.total_steps = static_cast<std::uint32_t>(2 * log2N);
        rs.self_rank = self_rank;
        rs.N = N;
        rs.msg_size = local_data.size();
        rs.chunk_size = chunk_size;
        rs.partner_bits = partner_bits_all;
        rs.work_buf.assign(local_data.begin(), local_data.end());
        rs.op = EpSyncOp::AllReduce;
        rs.step_send_done = false;
        rs.step_recv_done = false;

        // 准备 step 0 发送数据
        auto step_info = RHEngine::all_reduce_step(self_rank, 0, N, local_data.size());
        send_data.assign(
            rs.work_buf.data() + step_info.send_offset,
            rs.work_buf.data() + step_info.send_offset + step_info.send_length);
        rs.step_send_done = true;

        session.rh_algo = std::move(rs);
        sessions_[sync_id] = std::move(session);
    }

    // 5. 锁外发送 step 0
    bool sent = send_to_peer_(partner_bits_all[0], sync_id, EpSyncOp::AllReduce,
                              participant_mask,
                              std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                              static_cast<std::uint8_t>(op),
                              2,    // algo = RH
                              0, 1, // shard_idx=0, total_shards=1
                              self_bit,
                              0);   // step = 0
    if (!sent) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(sync_id);
        return false;
    }

    return true;
}

bool SyncPrimitives::reduce_scatter_rh_(std::uint64_t sync_id,
                                         std::uint64_t participant_mask,
                                         std::uint64_t self_node_id,
                                         std::span<const std::uint8_t> local_data,
                                         ReduceOp op,
                                         ReduceDType dtype,
                                         std::chrono::milliseconds timeout) {
    // 1. 守卫校验
    std::size_t N = popcount_(participant_mask);
    if (N < 2) return false;
    if (!RHEngine::is_power_of_two(N)) return false;
    if (local_data.size() % N != 0) return false;

    std::size_t chunk_size = local_data.size() / N;
    if (chunk_size > EpSyncFrame::kMaxPayloadLen) return false;

    std::uint64_t self_bit = static_cast<std::uint64_t>(1) << self_node_id;
    if ((participant_mask & self_bit) == 0) return false;

    // 2. 构建 participants，计算 self_rank
    auto participants = mask_to_nodes_(participant_mask);
    std::size_t self_rank = 0;
    bool found = false;
    for (std::size_t i = 0; i < participants.size(); ++i) {
        if (participants[i] == self_bit) { self_rank = i; found = true; break; }
    }
    if (!found) return false;

    // 3. 计算 partner 并检查 channel（仅 ReduceScatter 阶段，log₂N 步）
    std::size_t log2N = RHEngine::reduce_scatter_steps(N);
    std::vector<std::uint64_t> partner_bits_all;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (std::size_t step = 0; step < log2N; ++step) {
            auto info = RHEngine::reduce_scatter_step(self_rank, step, N, local_data.size());
            if (!info.valid) return false;
            std::uint64_t pbit = participants[info.partner_rank];
            partner_bits_all.push_back(pbit);
            if (peer_channels_.find(pbit) == peer_channels_.end()) return false;
        }
    }

    // 4. 初始化会话 + RhAlgoState
    auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<std::uint8_t> send_data;
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;
        session.state = SyncState::Reducing;
        session.deadline = deadline;
        session.reduce_op = op;
        session.reduce_dtype = dtype;
        session.algo = 2;  // RH
        session.local_data.assign(local_data.begin(), local_data.end());

        SyncSession::RhAlgoState rs;
        rs.phase = RHPhase::ReduceScatter;
        rs.current_step = 0;
        rs.total_steps = static_cast<std::uint32_t>(log2N);  // 仅 RS 阶段
        rs.self_rank = self_rank;
        rs.N = N;
        rs.msg_size = local_data.size();
        rs.chunk_size = chunk_size;
        rs.partner_bits = partner_bits_all;
        rs.work_buf.assign(local_data.begin(), local_data.end());
        rs.op = EpSyncOp::ReduceScatter;
        rs.step_send_done = false;
        rs.step_recv_done = false;

        // 准备 step 0 发送数据
        auto step_info = RHEngine::reduce_scatter_step(self_rank, 0, N, local_data.size());
        send_data.assign(
            rs.work_buf.data() + step_info.send_offset,
            rs.work_buf.data() + step_info.send_offset + step_info.send_length);
        rs.step_send_done = true;

        session.rh_algo = std::move(rs);
        sessions_[sync_id] = std::move(session);
    }

    // 5. 锁外发送 step 0
    bool sent = send_to_peer_(partner_bits_all[0], sync_id, EpSyncOp::ReduceScatter,
                              participant_mask,
                              std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                              static_cast<std::uint8_t>(op),
                              2,    // algo = RH
                              0, 1, // shard
                              self_bit,
                              0);   // step = 0
    if (!sent) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(sync_id);
        return false;
    }

    return true;
}

void SyncPrimitives::handle_all_reduce_rh_(const EpSyncFrame &frame) {
    bool completed = false;
    std::vector<std::uint8_t> completed_result;
    bool need_send = false;
    std::vector<std::uint8_t> send_data;
    std::uint64_t send_target = 0;
    std::uint64_t send_sid = 0;
    std::uint8_t send_reduce_op = 0;
    std::uint16_t send_step = 0;
    std::uint64_t send_from = 0;
    std::uint64_t send_pmask = 0;
    EpSyncOp send_op = EpSyncOp::AllReduce;

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(frame.sync_id);
        if (it == sessions_.end() || !it->second.rh_algo.has_value()) {
            return;  // 非 RH 会话或会话不存在
        }

        auto &session = it->second;
        auto &rs = session.rh_algo.value();

        // 校验 step 匹配
        if (frame.step != rs.current_step) return;
        // 校验来源是当前步 partner
        if (rs.current_step >= rs.partner_bits.size()) return;
        if (frame.from_node_id != rs.partner_bits[rs.current_step]) return;

        rs.step_recv_done = true;

        // 按阶段处理接收数据
        auto step_info = RHEngine::all_reduce_step(rs.self_rank, rs.current_step,
                                                    rs.N, rs.msg_size);
        if (!step_info.valid) return;

        if (rs.phase == RHPhase::ReduceScatter) {
            // 规约 partner 数据到 work_buf[recv_offset..]
            auto reduced = apply_reduce_(
                std::span<const std::uint8_t>(
                    rs.work_buf.data() + step_info.recv_offset,
                    step_info.recv_length),
                std::span<const std::uint8_t>(frame.payload.data(), frame.payload.size()),
                session.reduce_op, session.reduce_dtype);
            std::memcpy(rs.work_buf.data() + step_info.recv_offset,
                        reduced.data(), step_info.recv_length);
        } else if (rs.phase == RHPhase::AllGather) {
            // 覆盖 work_buf[recv_offset..]
            if (frame.payload.size() == step_info.recv_length) {
                std::memcpy(rs.work_buf.data() + step_info.recv_offset,
                            frame.payload.data(), step_info.recv_length);
            }
        }

        // 推进步进
        bool done = rh_advance_step_(session);
        if (done) {
            completed = true;
            completed_result = rs.result;
        } else if (!rs.step_send_done) {
            // 准备下一步发送
            auto next_info = RHEngine::all_reduce_step(rs.self_rank, rs.current_step,
                                                        rs.N, rs.msg_size);
            if (next_info.valid) {
                send_data.assign(
                    rs.work_buf.data() + next_info.send_offset,
                    rs.work_buf.data() + next_info.send_offset + next_info.send_length);
                send_target = rs.partner_bits[rs.current_step];
                send_sid = frame.sync_id;
                send_reduce_op = frame.reduce_op;
                send_step = static_cast<std::uint16_t>(rs.current_step);
                send_from = static_cast<std::uint64_t>(1) << session.self_node_id;
                send_pmask = session.participant_mask;
                send_op = rs.op;
                need_send = true;
                rs.step_send_done = true;
            }
        }
    }

    // 锁外发送下一步
    if (need_send) {
        send_to_peer_(send_target, send_sid, send_op, send_pmask,
                      std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                      send_reduce_op, 2, 0, 1, send_from, send_step);
    }

    if (completed) {
        notify_all_reduce_complete_(frame.sync_id,
            std::span<const std::uint8_t>(completed_result.data(), completed_result.size()));
        cv_.notify_all();
    }
}

bool SyncPrimitives::rh_advance_step_(SyncSession &session) {
    auto &rs = session.rh_algo.value();
    if (!rs.step_send_done || !rs.step_recv_done) return false;

    rs.current_step++;

    std::size_t log2N = RHEngine::reduce_scatter_steps(rs.N);

    // 阶段切换：ReduceScatter → AllGather（仅 AllReduce）
    if (rs.current_step == log2N && rs.op == EpSyncOp::AllReduce) {
        rs.phase = RHPhase::AllGather;
    }

    // 完成检查
    if (rs.current_step >= rs.total_steps) {
        rs.phase = RHPhase::Done;
        if (rs.op == EpSyncOp::AllReduce) {
            // AllReduce: result 是完整 work_buf
            rs.result = rs.work_buf;
        } else {
            // ReduceScatter: result 是 result_idx 对应的 chunk
            std::size_t result_idx = RHEngine::reduce_scatter_result_idx(rs.self_rank, rs.N);
            rs.result.assign(
                rs.work_buf.data() + result_idx * rs.chunk_size,
                rs.work_buf.data() + (result_idx + 1) * rs.chunk_size);
        }
        session.state = SyncState::Completed;
        session.reduced_data = rs.result;
        return true;
    }

    // 重置步进标志
    rs.step_send_done = false;
    rs.step_recv_done = false;
    return false;
}

// ============================================================================
// v2.3 Phase 4 (P4-F): PairwiseExchange AllToAll 实现
// ============================================================================

bool SyncPrimitives::all_to_all_pe_(std::uint64_t sync_id,
                                     std::uint64_t participant_mask,
                                     std::uint64_t self_node_id,
                                     std::span<const std::uint8_t> local_chunk,
                                     std::chrono::milliseconds timeout) {
    // 1. 守卫校验
    std::size_t N = popcount_(participant_mask);
    if (N < 2) return false;
    if (!PEEngine::is_power_of_two(N)) return false;  // PE 要求 N 为 2 的幂
    if (local_chunk.size() % N != 0) return false;    // 必须可整除为 N 段

    std::size_t chunk_size = local_chunk.size() / N;
    if (chunk_size == 0) return false;

    // step 0 单帧 payload = |send_chunk_indices(self_rank, 0, N)| × chunk_size
    // |send_chunk_indices| at step 0 = N/2
    std::size_t step0_payload = (N / 2) * chunk_size;
    if (step0_payload > EpSyncFrame::kMaxPayloadLen) return false;

    std::uint64_t self_bit = static_cast<std::uint64_t>(1) << self_node_id;
    if ((participant_mask & self_bit) == 0) return false;

    // 2. 构建 participants，计算 self_rank
    auto participants = mask_to_nodes_(participant_mask);
    std::size_t self_rank = 0;
    bool found = false;
    for (std::size_t i = 0; i < participants.size(); ++i) {
        if (participants[i] == self_bit) { self_rank = i; found = true; break; }
    }
    if (!found) return false;

    // 3. 计算 log₂N 个 partner 并检查 channel
    std::size_t log2N = PEEngine::total_steps(N);
    std::vector<std::uint64_t> partner_bits;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (std::size_t step = 0; step < log2N; ++step) {
            std::size_t partner_rank = PEEngine::partner_at_step(self_rank, step);
            if (partner_rank >= participants.size()) return false;
            std::uint64_t pbit = participants[partner_rank];
            partner_bits.push_back(pbit);
            if (peer_channels_.find(pbit) == peer_channels_.end()) return false;
        }
    }

    // 4. 初始化会话 + PeAlgoState
    auto deadline = std::chrono::steady_clock::now() + timeout;
    std::vector<std::uint8_t> send_data;
    {
        std::lock_guard<std::mutex> lk(mu_);
        SyncSession session;
        session.sync_id = sync_id;
        session.participant_mask = participant_mask;
        session.self_node_id = self_node_id;
        session.state = SyncState::Waiting;
        session.deadline = deadline;
        session.algo = 3;  // PE

        SyncSession::PeAlgoState ps;
        ps.current_step = 0;
        ps.total_steps = static_cast<std::uint32_t>(log2N);
        ps.self_rank = self_rank;
        ps.N = N;
        ps.chunk_size = chunk_size;
        ps.partner_bits = partner_bits;
        ps.step_send_done = false;
        ps.step_recv_done = false;

        // 拆分 local_chunk 为 N 段，填入 chunks[0..N-1]
        for (std::size_t j = 0; j < N; ++j) {
            ps.chunks[j].assign(
                local_chunk.data() + j * chunk_size,
                local_chunk.data() + (j + 1) * chunk_size);
        }

        // 准备 step 0 发送数据
        auto send_indices = PEEngine::send_chunk_indices(self_rank, 0, N);
        for (std::size_t idx : send_indices) {
            auto it = ps.chunks.find(idx);
            if (it != ps.chunks.end()) {
                send_data.insert(send_data.end(), it->second.begin(), it->second.end());
            }
        }
        ps.step_send_done = true;

        session.pe_algo = std::move(ps);
        sessions_[sync_id] = std::move(session);
    }

    // 5. 锁外发送 step 0
    bool sent = send_to_peer_(partner_bits[0], sync_id, EpSyncOp::AllToAll,
                              participant_mask,
                              std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                              0,    // reduce_op unused
                              3,    // algo = PE
                              0, 1, // shard_idx=0, total_shards=1
                              self_bit,
                              0);   // step = 0
    if (!sent) {
        std::lock_guard<std::mutex> lk(mu_);
        sessions_.erase(sync_id);
        return false;
    }

    return true;
}

void SyncPrimitives::handle_all_to_all_pe_(const EpSyncFrame &frame) {
    // PE 接收方：拆包 frame.payload，更新 chunks，推进状态机
    bool completed = false;
    std::vector<std::uint8_t> completed_result;
    std::uint64_t completed_from_mask = 0;

    // 锁外准备发送数据
    bool need_send = false;
    std::vector<std::uint8_t> send_data;
    std::uint64_t send_target = 0;
    std::uint64_t send_sid = 0;
    std::uint16_t send_step = 0;
    std::uint64_t send_from = 0;
    std::uint64_t send_pmask = 0;

    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(frame.sync_id);
        if (it == sessions_.end() || !it->second.pe_algo.has_value()) {
            return;  // 会话不存在或非 PE 会话，忽略
        }

        auto &session = it->second;
        auto &ps = session.pe_algo.value();

        // 校验 from_node_id 和 step
        if (frame.step != ps.current_step) return;
        std::uint64_t expected_partner = ps.partner_bits[ps.current_step];
        if (frame.from_node_id != expected_partner) return;

        // 拆包 payload：按 recv_chunk_indices 顺序提取
        auto recv_indices = PEEngine::recv_chunk_indices(ps.self_rank, ps.current_step, ps.N);
        std::size_t sources_per_dest = static_cast<std::size_t>(1) << ps.current_step;
        std::size_t recv_chunk_total = sources_per_dest * ps.chunk_size;

        // 判断 prepend 或 append：rank bit s = 0 → append（partner sources 更大），
        //                                rank bit s = 1 → prepend（partner sources 更小）
        bool rank_bit_s = (ps.self_rank >> ps.current_step) & 1;
        bool prepend = rank_bit_s;  // bit s = 1 → partner 的 sources 更小 → prepend

        std::size_t offset = 0;
        for (std::size_t dest : recv_indices) {
            if (offset + recv_chunk_total > frame.payload.size()) break;

            std::vector<std::uint8_t> recv_part(
                frame.payload.data() + offset,
                frame.payload.data() + offset + recv_chunk_total);

            auto &chunk = ps.chunks[dest];
            if (prepend) {
                // partner 的 sources 更小，插入到前面
                chunk.insert(chunk.begin(), recv_part.begin(), recv_part.end());
            } else {
                // partner 的 sources 更大，追加到后面
                chunk.insert(chunk.end(), recv_part.begin(), recv_part.end());
            }

            offset += recv_chunk_total;
        }

        ps.step_recv_done = true;

        // 推进状态机
        bool done = pe_advance_step_(session);

        if (done) {
            completed = true;
            completed_result = session.reduced_data;
            completed_from_mask = session.participant_mask;
        } else if (!ps.step_send_done) {
            // 准备下一步发送数据
            auto send_indices = PEEngine::send_chunk_indices(
                ps.self_rank, ps.current_step, ps.N);
            for (std::size_t idx : send_indices) {
                auto cit = ps.chunks.find(idx);
                if (cit != ps.chunks.end()) {
                    send_data.insert(send_data.end(), cit->second.begin(), cit->second.end());
                }
            }
            send_target = ps.partner_bits[ps.current_step];
            send_sid = frame.sync_id;
            send_step = static_cast<std::uint16_t>(ps.current_step);
            send_from = static_cast<std::uint64_t>(1) << session.self_node_id;
            send_pmask = session.participant_mask;
            need_send = true;
            ps.step_send_done = true;
        }
    }

    // 锁外发送下一步
    if (need_send) {
        send_to_peer_(send_target, send_sid, EpSyncOp::AllToAll, send_pmask,
                      std::span<const std::uint8_t>(send_data.data(), send_data.size()),
                      0, 3, 0, 1, send_from, send_step);
    }

    if (completed) {
        notify_all_to_all_complete_(frame.sync_id, completed_from_mask,
            std::span<const std::uint8_t>(completed_result.data(), completed_result.size()));
        cv_.notify_all();
    }
}

bool SyncPrimitives::pe_advance_step_(SyncSession &session) {
    auto &ps = session.pe_algo.value();
    if (!ps.step_send_done || !ps.step_recv_done) return false;

    ps.current_step++;

    // 完成检查
    if (ps.current_step >= ps.total_steps) {
        // 组装 result：chunks[self_rank] 包含所有 N 个 source 的数据（按 source 升序拼接）
        auto it = ps.chunks.find(ps.self_rank);
        if (it != ps.chunks.end()) {
            session.reduced_data = it->second;
        }
        session.state = SyncState::Completed;
        return true;
    }

    // 重置步进标志
    ps.step_send_done = false;
    ps.step_recv_done = false;
    return false;
}

}  // namespace linoh::multimodal::ep
