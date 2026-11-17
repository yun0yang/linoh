// ep_session.hpp — EP 端到端会话编排器（v1.6.0.8 / P7）
//
// 将 P0-P6 分散交付的独立模块组装为可端到端运行的 EP 推理通信底座：
//   - EpSession（master 端）：管理多 worker 连接池 + CommPlanner 规划 + dispatch 分发 + combine 收集 + barrier 同步
//   - EpWorkerSession（worker 端）：接收 dispatch → 触发 compute 回调 → 发送 combine
//
// 设计原则：
//   - 编排层与传输层解耦：通过 EpChannelIf 抽象接口依赖 EpChannel，便于测试注入 mock
//   - 同步语义：dispatch() 阻塞等待所有 worker ACK combine（业务层无需关心重试）
//   - 冗余专家支持：redundant_experts 非空时复制 dispatch 到冗余节点
//
// 线程模型：
//   - dispatch() 调用方线程同步执行
//   - worker 端 compute 回调在 EpChannel recv_loop 线程内触发
//   - barrier 同步阻塞调用方线程

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "linoh/multimodal/comm_planner.hpp"
#include "linoh/multimodal/ep_channel.hpp"
#include "linoh/multimodal/ep_frames.hpp"
#include "linoh/multimodal/sync_primitives.hpp"

namespace linoh::multimodal::ep {

// ============================================================================
// EpChannelIf — EpChannel 抽象接口（用于 EpSession 解耦 + 测试 mock）
// ============================================================================
//
// EpSession 通过此接口操作 EpChannel，不直接依赖具体实现。
// 生产代码中 EpChannel 实现此接口；测试代码中可注入 mock 实现。
class EpChannelIf {
public:
    virtual ~EpChannelIf() = default;

    /// 发送 EP_DISPATCH_FRAME
    virtual bool send_dispatch(std::uint64_t tensor_id,
                               std::uint64_t expert_id,
                               std::uint64_t token_cnt,
                               std::span<const std::uint8_t> payload,
                               std::span<const std::uint8_t> padding = {}) = 0;

    /// 发送 EP_COMBINE_FRAME
    virtual bool send_combine(std::uint64_t tensor_id,
                              std::uint64_t expert_id,
                              std::uint64_t token_cnt,
                              std::span<const std::uint8_t> payload) = 0;

    /// 发送 EP_SYNC_FRAME
    virtual bool send_sync(std::uint64_t sync_id,
                           EpSyncOp sync_op,
                           std::uint64_t participant_mask,
                           std::span<const std::uint8_t> payload = {}) = 0;

    /// 设置回调集合
    virtual void set_callbacks(EpChannelCallbacks callbacks) = 0;

    /// 获取统计
    virtual EpChannelStats stats() const = 0;

    /// 是否有效
    virtual bool is_valid() const noexcept = 0;

    /// 启动接收循环
    virtual void start_recv_loop() = 0;

    /// 停止接收循环
    virtual void stop_recv_loop() = 0;

    /// 启动重传检查线程
    virtual void start_resend_loop() = 0;

    /// 停止重传检查线程
    virtual void stop_resend_loop() = 0;
};

// ============================================================================
// EpChannelAdapter — EpChannelIf 的 EpChannel 适配器（生产代码使用）
// ============================================================================
//
// 将 EpChannel 适配为 EpChannelIf 接口。
// EpSession 通过 EpChannelIf 操作，生产代码传入 EpChannelAdapter。
class EpChannelAdapter : public EpChannelIf {
public:
    explicit EpChannelAdapter(std::shared_ptr<endpoint::Connection> conn)
        : channel_(std::move(conn)) {}

    bool send_dispatch(std::uint64_t tensor_id,
                       std::uint64_t expert_id,
                       std::uint64_t token_cnt,
                       std::span<const std::uint8_t> payload,
                       std::span<const std::uint8_t> padding = {}) override {
        return channel_.send_dispatch(tensor_id, expert_id, token_cnt, payload, padding);
    }

    bool send_combine(std::uint64_t tensor_id,
                      std::uint64_t expert_id,
                      std::uint64_t token_cnt,
                      std::span<const std::uint8_t> payload) override {
        return channel_.send_combine(tensor_id, expert_id, token_cnt, payload);
    }

    bool send_sync(std::uint64_t sync_id,
                   EpSyncOp sync_op,
                   std::uint64_t participant_mask,
                   std::span<const std::uint8_t> payload = {}) override {
        return channel_.send_sync(sync_id, sync_op, participant_mask, payload);
    }

    void set_callbacks(EpChannelCallbacks callbacks) override {
        channel_.set_callbacks(std::move(callbacks));
    }

    EpChannelStats stats() const override { return channel_.stats(); }

    bool is_valid() const noexcept override { return channel_.is_valid(); }

    void start_recv_loop() override { channel_.start_recv_loop(); }
    void stop_recv_loop() override { channel_.stop_recv_loop(); }
    void start_resend_loop() override { channel_.start_resend_loop(); }
    void stop_resend_loop() override { channel_.stop_resend_loop(); }

    /// 底层 EpChannel（用于 SyncPrimitives 构造等需要 EpChannel* 的场景）
    EpChannel *channel_ptr() noexcept { return &channel_; }

private:
    EpChannel channel_;
};

// ============================================================================
// EpSessionStats — EP 会话级统计
// ============================================================================
struct EpSessionStats {
    std::uint64_t dispatch_rounds{0};        // dispatch() 调用次数
    std::uint64_t dispatch_frames_sent{0};   // 总 dispatch 帧发送数（含冗余）
    std::uint64_t combine_frames_recv{0};    // 总 combine 帧接收数
    std::uint64_t barrier_success{0};        // barrier 成功次数
    std::uint64_t barrier_partial{0};       // barrier 部分降级次数
    std::uint64_t barrier_timeout{0};        // barrier 超时失败次数
    std::uint64_t dispatch_failures{0};      // dispatch 发送失败次数
    std::uint64_t combine_timeout{0};        // 等待 combine 超时次数
    std::uint64_t plan_cache_hits{0};        // CommPlanner 缓存命中次数
    std::uint64_t plan_cache_misses{0};      // CommPlanner 缓存未命中次数
};

// ============================================================================
// EpSessionCallbacks — EP 会话回调（master 端）
// ============================================================================
struct EpSessionCallbacks {
    /// 所有 worker combine 收齐后调用（业务层在此合并结果）
    /// \param plan 本次 dispatch 使用的 EpCommPlan
    /// \param combines 每个 worker 返回的 combine 数据（按 worker_idx 索引）
    std::function<void(const EpCommPlan &plan,
                       const std::vector<std::vector<std::uint8_t>> &combines)> on_all_combine_received;

    /// barrier 部分降级时调用
    /// \param plan 本次 dispatch 使用的 EpCommPlan
    /// \param arrived_mask 已到齐的 worker 位图
    /// \param participant_mask 应到齐的 worker 位图
    /// \param combines 已收到的 combine 数据（未到齐的 worker 位置为空）
    std::function<void(const EpCommPlan &plan,
                       std::uint64_t arrived_mask,
                       std::uint64_t participant_mask,
                       const std::vector<std::vector<std::uint8_t>> &combines)> on_partial_combine;

    /// 帧丢弃时调用（worker 掉线 / 重传达上限）
    std::function<void(std::uint64_t tensor_id, std::uint64_t worker_idx)> on_frame_dropped;
};

// ============================================================================
// EpSession — EP-master 端会话编排器
// ============================================================================
//
// 管理 EP-master 到 N 个 EP-worker 的多连接池，对外暴露 dispatch() 高层 API：
//   1. CommPlanner.launch_planning() 生成 EpCommPlan
//   2. 按 plan.dst_nodes 分发 token 到对应 worker 的 EpChannelIf
//   3. 等待所有 worker combine 回流
//   4. 触发 barrier 同步（SyncPrimitives）
//   5. 调用 on_all_combine_received 回调
//
// 用法（EP-master 端）：
//   EpSession session(master_node_id);
//   session.connect_worker(worker0_id, channel0);
//   session.connect_worker(worker1_id, channel1);
//   session.set_callbacks({...});
//   auto plan = session.dispatch(routing, config, payload);
//   // session 内部等待 combine + barrier，触发回调
//
class EpSession {
public:
    /// 构造 EpSession
    /// \param master_node_id EP-master 节点 ID
    explicit EpSession(std::uint64_t master_node_id);

    ~EpSession();

    // 不可拷贝、不可移动（含 mutex 不可移动成员）
    EpSession(const EpSession &) = delete;
    EpSession &operator=(const EpSession &) = delete;
    EpSession(EpSession &&) = delete;
    EpSession &operator=(EpSession &&) = delete;

    // ====================================================================
    // 连接池管理
    // ====================================================================

    /// 连接一个 worker（EpSession 持有 channel 所有权）
    /// \param worker_node_id worker 节点 ID
    /// \param channel EpChannelIf 实例（通常为 EpChannelAdapter）
    /// \return true=成功，false=已存在相同 worker_node_id
    bool connect_worker(std::uint64_t worker_node_id,
                        std::unique_ptr<EpChannelIf> channel);

    /// 断开 worker 连接
    /// \return true=成功，false=不存在
    bool disconnect_worker(std::uint64_t worker_node_id);

    /// 当前连接的 worker 数量
    std::size_t worker_count() const noexcept;

    /// worker 是否已连接
    bool has_worker(std::uint64_t worker_node_id) const noexcept;

    // ====================================================================
    // 回调注册
    // ====================================================================

    /// 设置回调集合
    void set_callbacks(EpSessionCallbacks callbacks);

    // ====================================================================
    // dispatch / combine / sync 编排
    // ====================================================================

    /// 执行一次完整的 dispatch → compute → combine → sync 流程
    ///
    /// \param routing 路由结果（每个 token 的目标专家列表）
    /// \param config EP 组配置
    /// \param payload 每个 token 的 embedding 数据（size=total_tokens × hidden_dim）
    /// \param timeout combine 等待超时（默认 30s）
    /// \return EpCommPlan 本次使用的通信计划（失败时 plan.valid()=false）
    ///
    /// 流程：
    ///   1. CommPlanner.launch_planning(routing, config) 生成 plan
    ///   2. 按 plan.dst_nodes 分发 token 到对应 worker
    ///   3. 等待所有 worker combine 回流（超时则触发 on_partial_combine）
    ///   4. barrier 同步（SyncPrimitives）
    ///   5. 调用 on_all_combine_received 回调
    EpCommPlan dispatch(const std::vector<std::vector<std::uint32_t>> &routing,
                        const EpGroupConfig &config,
                        std::span<const std::uint8_t> payload,
                        std::chrono::milliseconds timeout = std::chrono::seconds(30));

    // ====================================================================
    // 状态查询
    // ====================================================================

    /// 获取统计
    EpSessionStats stats() const;

    /// 获取 CommPlanner（用于高级用法，如手动缓存管理）
    CommPlanner &planner() noexcept { return planner_; }

    /// 是否允许 barrier 部分降级
    bool allow_partial_combine() const noexcept;

    /// 设置是否允许 barrier 部分降级
    void set_allow_partial_combine(bool allow) noexcept;

private:
    std::uint64_t master_node_id_;
    mutable std::mutex mu_;

    /// worker 连接池（worker_node_id -> EpChannelIf）
    std::unordered_map<std::uint64_t, std::unique_ptr<EpChannelIf>> workers_;

    /// worker 节点 ID 列表（按连接顺序，用于位图映射）
    std::vector<std::uint64_t> worker_ids_;

    /// CommPlanner 实例
    CommPlanner planner_;

    /// SyncPrimitives 实例（延迟初始化，需要 EpChannel*）
    std::unique_ptr<SyncPrimitives> sync_;

    /// 回调
    mutable std::mutex cb_mu_;
    EpSessionCallbacks callbacks_;

    /// 统计
    mutable std::mutex stats_mu_;
    EpSessionStats stats_;

    /// 是否允许 barrier 部分降级
    std::atomic<bool> allow_partial_combine_{false};

    /// combine 收集状态（dispatch 过程中临时持有）
    struct CombineCollector {
        std::mutex mu;
        std::condition_variable cv;
        std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> received;  // worker_idx -> combine data
        std::uint64_t expected_count{0};
        std::uint64_t arrived_mask{0};
        bool timeout{false};
    };
    std::unique_ptr<CombineCollector> collector_;

    /// 内部：根据 plan 分发 dispatch 到各 worker
    /// \return 成功分发的 worker 数
    std::uint64_t dispatch_to_workers_(const EpCommPlan &plan,
                                        std::span<const std::uint8_t> payload);

    /// 内部：等待所有 worker combine 回流
    /// \return true=全部收齐，false=超时或部分缺失
    bool wait_combine_(const EpCommPlan &plan,
                       std::chrono::milliseconds timeout,
                       std::vector<std::vector<std::uint8_t>> &out_combines);

    /// 内部：执行 barrier 同步
    /// \return true=成功，false=超时
    bool do_barrier_(const EpCommPlan &plan,
                     std::chrono::milliseconds timeout);

    /// 内部：worker_idx 到 worker_node_id 的映射（调用方需持 mu_）
    std::uint64_t worker_idx_to_id_locked_(std::size_t idx) const;
    /// 内部：worker_node_id 到 worker_idx 的映射（调用方需持 mu_）
    std::size_t worker_id_to_idx_locked_(std::uint64_t node_id) const;

    /// 内部：worker_idx 到 worker_node_id 的映射（内部加 mu_）
    std::uint64_t worker_idx_to_id_(std::size_t idx) const;

    /// 内部：worker_node_id 到 worker_idx 的映射（内部加 mu_）
    std::size_t worker_id_to_idx_(std::uint64_t node_id) const;

    /// 内部：更新统计
    void record_dispatch_round_();
    void record_dispatch_frames_(std::uint64_t count);
    void record_combine_recv_(std::uint64_t count);
    void record_barrier_success_();
    void record_barrier_partial_();
    void record_barrier_timeout_();
    void record_dispatch_failure_();
    void record_combine_timeout_();
    void record_plan_cache_hit_();
    void record_plan_cache_miss_();
};

// ============================================================================
// EpWorkerSession — EP-worker 端会话
// ============================================================================
//
// Worker 端接收 dispatch → 触发 compute 回调 → 发送 combine。
// 持有单个 EpChannelIf（与 master 的连接）。
//
// 用法（EP-worker 端）：
//   EpWorkerSession worker(worker_node_id);
//   worker.set_channel(std::make_unique<EpChannelAdapter>(conn));
//   worker.set_compute_callback([](tensor_id, expert_id, token_payload) {
//       // 业务层计算
//       return result_payload;
//   });
//   worker.start();  // 启动接收循环
//
class EpWorkerSession {
public:
    using ComputeCallback = std::function<std::vector<std::uint8_t>(
        std::uint64_t tensor_id,
        std::uint64_t expert_id,
        std::uint64_t token_cnt,
        std::span<const std::uint8_t> payload)>;

    /// 构造 EpWorkerSession
    /// \param worker_node_id worker 节点 ID
    explicit EpWorkerSession(std::uint64_t worker_node_id);

    ~EpWorkerSession();

    // 不可拷贝、不可移动
    EpWorkerSession(const EpWorkerSession &) = delete;
    EpWorkerSession &operator=(const EpWorkerSession &) = delete;
    EpWorkerSession(EpWorkerSession &&) = delete;
    EpWorkerSession &operator=(EpWorkerSession &&) = delete;

    /// 设置 channel（EpWorkerSession 持有所有权）
    void set_channel(std::unique_ptr<EpChannelIf> channel);

    /// 设置 compute 回调
    void set_compute_callback(ComputeCallback cb);

    /// 启动 worker（启动接收循环 + 注册 dispatch 回调）
    void start();

    /// 停止 worker
    void stop();

    /// 是否在运行
    bool is_running() const noexcept { return running_.load(); }

    /// 获取统计
    EpChannelStats stats() const;

private:
    std::uint64_t worker_node_id_;
    std::unique_ptr<EpChannelIf> channel_;
    ComputeCallback compute_cb_;
    std::atomic<bool> running_{false};
    mutable std::mutex mu_;

    /// 内部：dispatch 接收回调
    void on_dispatch_received_(const EpDispatchFrame &frame);
};

} // namespace linoh::multimodal::ep
