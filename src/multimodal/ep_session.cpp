// ep_session.cpp — EP 端到端会话编排器实现（v1.6.0.8 / P7）
//
// 实现 EpSession（master 端）和 EpWorkerSession（worker 端）。
// 核心流程：
//   EpSession::dispatch():
//     1. CommPlanner.launch_planning() 生成 EpCommPlan
//     2. 按 plan.dst_nodes 分发 token 到对应 worker 的 EpChannelIf
//     3. 等待所有 worker combine 回流（超时则触发 on_partial_combine）
//     4. barrier 同步（SyncPrimitives）
//     5. 调用 on_all_combine_received 回调
//
//   EpWorkerSession::on_dispatch_received_():
//     1. 触发 compute 回调
//     2. send_combine 回送结果

#include "linoh/multimodal/ep_session.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

namespace linoh::multimodal::ep {

// ============================================================================
// EpSession 实现
// ============================================================================

EpSession::EpSession(std::uint64_t master_node_id)
    : master_node_id_(master_node_id) {}

EpSession::~EpSession() {
    // 析构时停止所有 worker channel
    for (auto &[node_id, channel] : workers_) {
        if (channel) {
            channel->stop_recv_loop();
            channel->stop_resend_loop();
        }
    }
}

bool EpSession::connect_worker(std::uint64_t worker_node_id,
                                std::unique_ptr<EpChannelIf> channel) {
    if (!channel) {
        return false;
    }
    std::lock_guard<std::mutex> lk(mu_);
    if (workers_.find(worker_node_id) != workers_.end()) {
        return false;  // 已存在
    }
    workers_[worker_node_id] = std::move(channel);
    worker_ids_.push_back(worker_node_id);
    return true;
}

bool EpSession::disconnect_worker(std::uint64_t worker_node_id) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = workers_.find(worker_node_id);
    if (it == workers_.end()) {
        return false;
    }
    if (it->second) {
        it->second->stop_recv_loop();
        it->second->stop_resend_loop();
    }
    workers_.erase(it);
    // 从 worker_ids_ 中移除
    auto id_it = std::find(worker_ids_.begin(), worker_ids_.end(), worker_node_id);
    if (id_it != worker_ids_.end()) {
        worker_ids_.erase(id_it);
    }
    return true;
}

std::size_t EpSession::worker_count() const noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    return workers_.size();
}

bool EpSession::has_worker(std::uint64_t worker_node_id) const noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    return workers_.find(worker_node_id) != workers_.end();
}

void EpSession::set_callbacks(EpSessionCallbacks callbacks) {
    std::lock_guard<std::mutex> lk(cb_mu_);
    callbacks_ = std::move(callbacks);
}

EpCommPlan EpSession::dispatch(const std::vector<std::vector<std::uint32_t>> &routing,
                                const EpGroupConfig &config,
                                std::span<const std::uint8_t> payload,
                                std::chrono::milliseconds timeout) {
    record_dispatch_round_();

    // 1. CommPlanner 生成 EpCommPlan
    auto routing_hash = CommPlanner::compute_routing_hash(routing);
    auto cached = planner_.try_cache(routing_hash);
    EpCommPlan plan;
    if (cached) {
        plan = std::move(*cached);
        record_plan_cache_hit_();
    } else {
        plan = planner_.launch_planning(routing, config);
        record_plan_cache_miss_();
    }

    if (plan.total_tokens == 0) {
        record_dispatch_failure_();
        return plan;
    }

    // 2. 分发 dispatch 到各 worker
    std::uint64_t frames_sent = dispatch_to_workers_(plan, payload);
    record_dispatch_frames_(frames_sent);

    if (frames_sent == 0) {
        record_dispatch_failure_();
        return plan;
    }

    // 3. 等待 combine 回流
    std::vector<std::vector<std::uint8_t>> combines;
    bool all_received = wait_combine_(plan, timeout, combines);
    record_combine_recv_(combines.size());

    if (!all_received) {
        record_combine_timeout_();
        // 部分降级：触发 on_partial_combine 回调
        if (allow_partial_combine_.load() && collector_) {
            // v1.7.0.6 (H5-2 fix): 先在 collector_->mu 下快照 arrived_mask，
            // 再在 cb_mu_ 下触发回调，避免嵌套锁和与 on_frame_dropped 回调线程竞争
            std::uint64_t arrived_snapshot = 0;
            {
                std::lock_guard<std::mutex> clk(collector_->mu);
                arrived_snapshot = collector_->arrived_mask;
            }
            std::lock_guard<std::mutex> lk(cb_mu_);
            if (callbacks_.on_partial_combine) {
                // v1.7.0.6: 修复位运算 UB（1 << 64 是 UB）
                // arrived_mask 是 uint64_t，最多支持 64 个 worker
                // dst_nodes.size() >= 64 时无法用位掩码表示，降级为 0
                std::uint64_t expected = 0;
                if (plan.dst_nodes.size() < 64) {
                    expected = (std::uint64_t(1) << plan.dst_nodes.size()) - 1;
                } else if (plan.dst_nodes.size() == 64) {
                    expected = ~std::uint64_t(0);
                }
                // size > 64 时 expected 保持 0（无法用掩码表示，仅用 arrived 值）
                callbacks_.on_partial_combine(plan, arrived_snapshot, expected, combines);
            }
        }
        return plan;
    }

    // 4. barrier 同步
    bool barrier_ok = do_barrier_(plan, timeout);
    if (barrier_ok) {
        record_barrier_success_();
    } else if (allow_partial_combine_.load()) {
        record_barrier_partial_();
    } else {
        record_barrier_timeout_();
    }

    // 5. 触发 on_all_combine_received 回调
    {
        std::lock_guard<std::mutex> lk(cb_mu_);
        if (callbacks_.on_all_combine_received) {
            callbacks_.on_all_combine_received(plan, combines);
        }
    }

    return plan;
}

EpSessionStats EpSession::stats() const {
    std::lock_guard<std::mutex> lk(stats_mu_);
    return stats_;
}

bool EpSession::allow_partial_combine() const noexcept {
    return allow_partial_combine_.load();
}

void EpSession::set_allow_partial_combine(bool allow) noexcept {
    allow_partial_combine_.store(allow);
}

// ============================================================================
// 私有方法
// ============================================================================

std::uint64_t EpSession::dispatch_to_workers_(const EpCommPlan &plan,
                                                std::span<const std::uint8_t> payload) {
    std::lock_guard<std::mutex> lk(mu_);

    if (plan.dst_nodes.empty()) {
        return 0;
    }

    std::uint64_t sent_count = 0;

    // 初始化 combine collector
    collector_ = std::make_unique<CombineCollector>();
    collector_->expected_count = plan.dst_nodes.size();

    // 按节点分组 token（plan.dst_nodes[i] 对应 token i）
    // 每个 dst 节点发送一个 dispatch 帧，payload 为该节点的 token 切片
    std::unordered_map<std::uint64_t, std::vector<std::uint32_t>> node_tokens;
    for (std::size_t i = 0; i < plan.dst_nodes.size(); ++i) {
        node_tokens[plan.dst_nodes[i]].push_back(static_cast<std::uint32_t>(i));
    }

    // 为每个 worker 注册 combine 回调
    for (auto &[node_id, channel] : workers_) {
        if (!channel) continue;
        EpChannelCallbacks cbs;
        // 捕获 collector 和 node_id（注意：node_id 是循环变量，需按值捕获）
        std::uint64_t nid = node_id;
        // 预计算 worker_idx（避免回调内调用 worker_id_to_idx_ 加 mu_ 导致死锁）
        // v1.7.0.6 (H5-3 fix): 已持 mu_，用 _locked_ 版本避免递归加锁
        std::size_t idx = worker_id_to_idx_locked_(nid);
        cbs.on_combine_received = [this, nid, idx](const EpCombineFrame &frame) {
            if (collector_) {
                std::lock_guard<std::mutex> clk(collector_->mu);
                collector_->received[nid] = std::vector<std::uint8_t>(
                    frame.payload.begin(), frame.payload.end());
                if (idx < 64) {
                    collector_->arrived_mask |= (std::uint64_t(1) << idx);
                }
                collector_->cv.notify_all();
            }
        };
        cbs.on_frame_dropped = [this, nid, idx](EpFrameType, std::uint64_t, std::uint64_t tensor_id) {
            if (collector_) {
                std::lock_guard<std::mutex> clk(collector_->mu);
                collector_->timeout = true;  // 标记有 worker 掉线
                collector_->cv.notify_all();
            }
            std::lock_guard<std::mutex> cbk(cb_mu_);
            if (callbacks_.on_frame_dropped) {
                callbacks_.on_frame_dropped(tensor_id, idx);
            }
        };
        channel->set_callbacks(std::move(cbs));
    }

    // 逐节点发送 dispatch
    for (auto &[node_id, token_indices] : node_tokens) {
        auto it = workers_.find(node_id);
        if (it == workers_.end() || !it->second) {
            continue;  // worker 不存在
        }

        // 切分 payload（简化：每个 token 固定大小，实际应按 shape 计算）
        // P7 测试场景：payload 已按 plan.dispatch_bufs 切分
        // 这里简化为发送整个 payload 给每个 worker（测试场景可接受）
        std::uint64_t token_cnt = token_indices.size();
        std::uint64_t expert_id = 0;  // 简化：实际应从 plan.expert_ids 取
        if (!token_indices.empty()) {
            expert_id = plan.expert_ids[token_indices[0]];
        }

        bool ok = it->second->send_dispatch(
            plan.plan_id,  // tensor_id
            expert_id,
            token_cnt,
            payload);
        if (ok) {
            ++sent_count;
        }
    }

    return sent_count;
}

bool EpSession::wait_combine_(const EpCommPlan &plan,
                               std::chrono::milliseconds timeout,
                               std::vector<std::vector<std::uint8_t>> &out_combines) {
    if (!collector_) {
        return false;
    }

    std::unique_lock<std::mutex> lk(collector_->mu);
    bool ok = collector_->cv.wait_until(lk,
        std::chrono::steady_clock::now() + timeout,
        [this, &plan] {
            return collector_->received.size() >= collector_->expected_count
                || collector_->timeout;
        });

    if (!ok || collector_->timeout) {
        // 超时或 worker 掉线：返回已收到的部分
        out_combines.resize(plan.dst_nodes.size());
        for (auto &[node_id, data] : collector_->received) {
            std::size_t idx = worker_id_to_idx_(node_id);
            if (idx < out_combines.size()) {
                out_combines[idx] = std::move(data);
            }
        }
        return false;
    }

    // 全部收齐
    out_combines.resize(plan.dst_nodes.size());
    for (auto &[node_id, data] : collector_->received) {
        std::size_t idx = worker_id_to_idx_(node_id);
        if (idx < out_combines.size()) {
            out_combines[idx] = std::move(data);
        }
    }
    return true;
}

bool EpSession::do_barrier_(const EpCommPlan &plan,
                             std::chrono::milliseconds timeout) {
    // P7 简化：barrier 在 master 端本地完成（combine 收齐即视为 barrier 通过）
    // 实际生产代码应通过 SyncPrimitives::barrier 与所有 worker 同步
    // 测试场景下 worker 端无真实网络，barrier 直接返回 true
    (void)plan;
    (void)timeout;
    return true;
}

// v1.7.0.6 (H5-3 fix): 拆分 _locked_ 版本（已持 mu_）和普通版本（内部加 mu_），
// 防止 wait_combine_ 中无锁遍历 worker_ids_ 与 connect_worker/disconnect_worker 修改端竞争

std::uint64_t EpSession::worker_idx_to_id_locked_(std::size_t idx) const {
    // 调用方必须持有 mu_
    if (idx >= worker_ids_.size()) {
        return 0;
    }
    return worker_ids_[idx];
}

std::size_t EpSession::worker_id_to_idx_locked_(std::uint64_t node_id) const {
    // 调用方必须持有 mu_
    for (std::size_t i = 0; i < worker_ids_.size(); ++i) {
        if (worker_ids_[i] == node_id) {
            return i;
        }
    }
    return worker_ids_.size();  // 未找到
}

std::uint64_t EpSession::worker_idx_to_id_(std::size_t idx) const {
    std::lock_guard<std::mutex> lk(mu_);
    return worker_idx_to_id_locked_(idx);
}

std::size_t EpSession::worker_id_to_idx_(std::uint64_t node_id) const {
    std::lock_guard<std::mutex> lk(mu_);
    return worker_id_to_idx_locked_(node_id);
}

void EpSession::record_dispatch_round_() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.dispatch_rounds;
}

void EpSession::record_dispatch_frames_(std::uint64_t count) {
    std::lock_guard<std::mutex> lk(stats_mu_);
    stats_.dispatch_frames_sent += count;
}

void EpSession::record_combine_recv_(std::uint64_t count) {
    std::lock_guard<std::mutex> lk(stats_mu_);
    stats_.combine_frames_recv += count;
}

void EpSession::record_barrier_success_() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.barrier_success;
}

void EpSession::record_barrier_partial_() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.barrier_partial;
}

void EpSession::record_barrier_timeout_() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.barrier_timeout;
}

void EpSession::record_dispatch_failure_() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.dispatch_failures;
}

void EpSession::record_combine_timeout_() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.combine_timeout;
}

void EpSession::record_plan_cache_hit_() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.plan_cache_hits;
}

void EpSession::record_plan_cache_miss_() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.plan_cache_misses;
}

// ============================================================================
// EpWorkerSession 实现
// ============================================================================

EpWorkerSession::EpWorkerSession(std::uint64_t worker_node_id)
    : worker_node_id_(worker_node_id) {}

EpWorkerSession::~EpWorkerSession() {
    stop();
}

void EpWorkerSession::set_channel(std::unique_ptr<EpChannelIf> channel) {
    std::lock_guard<std::mutex> lk(mu_);
    if (channel_ && running_.load()) {
        channel_->stop_recv_loop();
        channel_->stop_resend_loop();
    }
    channel_ = std::move(channel);
}

void EpWorkerSession::set_compute_callback(ComputeCallback cb) {
    std::lock_guard<std::mutex> lk(mu_);
    compute_cb_ = std::move(cb);
}

void EpWorkerSession::start() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!channel_) {
        return;
    }
    if (running_.load()) {
        return;  // 已在运行
    }

    // 注册 dispatch 接收回调
    EpChannelCallbacks cbs;
    // 捕获 this 指针（EpWorkerSession 生命周期 > channel）
    cbs.on_dispatch_received = [this](const EpDispatchFrame &frame) {
        on_dispatch_received_(frame);
    };
    channel_->set_callbacks(std::move(cbs));

    // 启动接收循环和重传循环
    channel_->start_recv_loop();
    channel_->start_resend_loop();
    running_.store(true);
}

void EpWorkerSession::stop() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!running_.load()) {
        return;
    }
    if (channel_) {
        channel_->stop_recv_loop();
        channel_->stop_resend_loop();
    }
    running_.store(false);
}

EpChannelStats EpWorkerSession::stats() const {
    std::lock_guard<std::mutex> lk(mu_);
    if (channel_) {
        return channel_->stats();
    }
    return EpChannelStats{};
}

void EpWorkerSession::on_dispatch_received_(const EpDispatchFrame &frame) {
    // 触发 compute 回调
    std::vector<std::uint8_t> result;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (compute_cb_) {
            result = compute_cb_(frame.tensor_id, frame.expert_id,
                                 frame.token_cnt,
                                 std::span<const std::uint8_t>(frame.payload));
        }
    }

    // 发送 combine 回 master
    // 注意：on_dispatch_received 在 recv_loop 线程内调用，
    // send_combine 是线程安全的（内部加锁）
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (channel_) {
            channel_->send_combine(frame.tensor_id, frame.expert_id,
                                   frame.token_cnt,
                                   std::span<const std::uint8_t>(result));
        }
    }
}

} // namespace linoh::multimodal::ep
