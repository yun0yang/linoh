// ep_channel.hpp — EP 通道收发封装（v1.6.0.1 / P0 + v1.6.0.7 / P6 可靠性增强）
//
// 借鉴 control_channel.hpp 的高层封装思想：
//   - 持有一条 EP 数据连接（已通过 connect_multimodal 建立）
//   - 提供 send_dispatch / send_combine / send_sync 三个高层 API
//   - 内部接收循环线程：accept_stream → read → decode → 路由到回调
//   - 统计计数（按帧类型分桶）
//
// P0 阶段定位：基础收发能力，不实现完整 EP 调度逻辑
//   - 不实现 CommPlan 在线规划（P2 阶段）
//   - 不实现静态 Buffer 池 / 零拷贝（P3 阶段）
//   - 不实现 NVLink transport（P4 阶段）
//   - 不实现负载均衡 / 冗余专家（P5 阶段）
//
// P6（v1.6.0.7）可靠性增强：
//   - EP 专属重传参数：dispatch 50ms×12 / combine 100ms×8
//   - 应用层 ACK 确认机制（EpAckFrame，type=0x23）
//   - 独立 resend_thread_（25ms 节拍）周期检查 pending 队列
//   - ACK 走 data_conn（与 EP 帧同通道）
//
// 线程模型：
//   - 发送：调用方线程同步调用 send_xxx，内部 open_stream + write + finish_send
//   - 接收：内部 recv_loop_ 线程循环 accept_stream + read + decode + 回调
//   - 重传：独立 resend_thread_（25ms 节拍），超时未 ACK 则重传
//   - 回调在 recv_loop_ 线程内同步调用，调用方需避免阻塞操作

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "linoh/endpoint/connection.hpp"
#include "linoh/multimodal/ep_frames.hpp"
#include "linoh/net/cuda_buffer.hpp"
#include "linoh/net/transport_selector.hpp"

namespace linoh::multimodal::ep {

// ============================================================================
// P6 可靠性参数常量（v1.6.0.7）
// ============================================================================

/// dispatch 帧重传超时（ms）。dispatch 对延迟敏感，超时较短。
constexpr double kEpDispatchResendTimeoutMs = 50.0;

/// dispatch 帧最大重传次数。
constexpr std::uint32_t kEpDispatchMaxResendCount = 12;

/// combine 帧重传超时（ms）。combine 数据量较大，超时略宽松。
constexpr double kEpCombineResendTimeoutMs = 100.0;

/// combine 帧最大重传次数。
constexpr std::uint32_t kEpCombineMaxResendCount = 8;

/// resend_thread_ 检查节拍（ms）。
constexpr double kEpResendCheckIntervalMs = 25.0;

/// mp-M1 (v1.7.0.8): 接收累积缓冲上限（字节）。
///   recv_loop_ 维护 per-stream 累积缓冲，半帧到达时保留等待更多数据。
///   超此上限仍无法解码视为垃圾数据/攻击，清空缓冲防止内存爆炸。
///   32 MiB 覆盖单个 DISPATCH 帧（kMaxPayloadLen=16MiB + 头部 + padding）。
constexpr std::size_t kEpMaxAccumBuffer = 32 * 1024 * 1024;

/// EP 通道统计（按帧类型分桶）
struct EpChannelStats {
    std::uint64_t dispatch_sent{0};      // 发送的 EP_DISPATCH_FRAME 数
    std::uint64_t combine_sent{0};       // 发送的 EP_COMBINE_FRAME 数
    std::uint64_t sync_sent{0};          // 发送的 EP_SYNC_FRAME 数
    std::uint64_t dispatch_recv{0};      // 接收的 EP_DISPATCH_FRAME 数
    std::uint64_t combine_recv{0};       // 接收的 EP_COMBINE_FRAME 数
    std::uint64_t sync_recv{0};          // 接收的 EP_SYNC_FRAME 数
    std::uint64_t send_failures{0};      // 发送失败次数
    std::uint64_t decode_failures{0};    // 解码失败次数
    std::uint64_t bytes_sent{0};         // 发送总字节数
    std::uint64_t bytes_recv{0};         // 接收总字节数
    // === P4 hardware accel 统计 ===
    std::uint64_t hw_dispatch_sent{0};       // 走 HwAccelTransport 的 dispatch 次数
    std::uint64_t hw_combine_sent{0};        // 走 HwAccelTransport 的 combine 次数
    std::uint64_t hw_bytes_sent{0};          // HwAccelTransport 发送字节数
    std::uint64_t hw_failures{0};            // HwAccelTransport 失败次数（已回退到 QUIC）
    std::uint64_t hw_fallback_to_quic{0};    // HwAccelTransport 不可用回退 QUIC 次数
    // === P6 可靠性统计（v1.6.0.7） ===
    std::uint64_t dispatch_resent{0};        // dispatch 帧重传次数
    std::uint64_t combine_resent{0};         // combine 帧重传次数
    std::uint64_t ack_sent{0};               // 发送的 ACK 帧数
    std::uint64_t ack_recv{0};               // 接收的 ACK 帧数
    std::uint64_t resend_dropped{0};         // 达到最大重传次数后丢弃的帧数
    std::uint64_t combine_partial_total{0};  // 触发 partial_combine 降级的总次数
};

/// EP 待确认帧条目（P6 / v1.6.0.7）
/// 发送方将每个 dispatch/combine 帧入队 pending 队列，等待对端 ACK。
/// 超时未收到 ACK 则重传，达到最大重传次数后丢弃。
struct EpPendingFrame {
    EpFrameType type{EpFrameType::DISPATCH};  // 帧类型（DISPATCH / COMBINE）
    std::uint64_t frame_seq{0};               // 全局递增序列号
    std::uint64_t tensor_id{0};               // 业务关联
    std::uint64_t expert_id{0};               // 专家 ID
    std::uint64_t token_cnt{0};               // token 数
    std::vector<std::uint8_t> payload;        // 已编码的完整帧字节（含 type 前缀）
    std::vector<std::uint8_t> padding;        // dispatch 的对齐填充（combine 无）
    double send_time_ms{0.0};                 // 首次发送时间（steady_clock ms）
    std::uint32_t resent_count{0};            // 已重传次数
    std::atomic<bool> acked{false};           // 是否已收到 ACK（原子，便于多线程检查）
};

/// EP 通道回调集合（接收端注册）
struct EpChannelCallbacks {
    /// 收到 EP_DISPATCH_FRAME 时调用
    std::function<void(const EpDispatchFrame &)> on_dispatch_received;
    /// 收到 EP_COMBINE_FRAME 时调用
    std::function<void(const EpCombineFrame &)> on_combine_received;
    /// 收到 EP_SYNC_FRAME 时调用
    std::function<void(const EpSyncFrame &)> on_sync_received;
    /// 解码失败时调用（数据损坏 / 帧格式错误）
    std::function<void(std::span<const std::uint8_t>)> on_decode_error;
    // === P6 可靠性回调（v1.6.0.7） ===
    /// 帧达到最大重传次数被丢弃时调用（业务层可降级处理）
    /// \param type 帧类型，frame_seq 序列号，tensor_id 业务关联
    std::function<void(EpFrameType type, std::uint64_t frame_seq, std::uint64_t tensor_id)> on_frame_dropped;
};

/// EP 通道（单连接收发封装）
///
/// 用法（EP-master 端）：
///   auto pair = endpoint.connect_multimodal(addr, ChannelType::EP_DISPATCH).get();
///   EpChannel channel(pair.data_conn);
///   channel.start_recv_loop();
///   channel.set_callbacks({...});
///   channel.send_dispatch(tensor_id, expert_id, token_cnt, payload);
///
/// 用法（EP-worker 端）：
///   auto pair = endpoint.connect_multimodal(addr, ChannelType::EP_COMBINE).get();
///   EpChannel channel(pair.data_conn);
///   channel.start_recv_loop();
///   channel.send_combine(tensor_id, expert_id, token_cnt, payload);
class EpChannel {
public:
    /// 构造 EpChannel
    /// \param data_conn EP 数据连接（必须已 Established）
    explicit EpChannel(std::shared_ptr<endpoint::Connection> data_conn);

    ~EpChannel();

    // 不可拷贝、不可移动（内部含 std::mutex / std::atomic 不可移动成员）
    // 如需移动语义，使用 std::unique_ptr<EpChannel> 间接实现
    EpChannel(const EpChannel &) = delete;
    EpChannel &operator=(const EpChannel &) = delete;
    EpChannel(EpChannel &&) = delete;
    EpChannel &operator=(EpChannel &&) = delete;

    // ====================================================================
    // 发送 API
    // ====================================================================

    /// 发送 EP_DISPATCH_FRAME
    /// \param tensor_id tensor 全局唯一 ID
    /// \param expert_id 目标专家 ID
    /// \param token_cnt 本帧携带的 token 数
    /// \param payload token embedding 字节流
    /// \param padding 对齐填充（可选，传空表示无 padding）
    /// \return true=发送成功，false=发送失败（连接关闭 / stream 打开失败）
    bool send_dispatch(std::uint64_t tensor_id,
                       std::uint64_t expert_id,
                       std::uint64_t token_cnt,
                       std::span<const std::uint8_t> payload,
                       std::span<const std::uint8_t> padding = {});

    /// 发送 EP_COMBINE_FRAME
    bool send_combine(std::uint64_t tensor_id,
                      std::uint64_t expert_id,
                      std::uint64_t token_cnt,
                      std::span<const std::uint8_t> payload);

    /// 发送 EP_SYNC_FRAME
    /// \param sync_id 同步会话 ID
    /// \param sync_op 同步操作类型
    /// \param participant_mask 参与节点位图
    /// \param payload 同步 payload（AllReduce 时携带标量）
    /// \param reduce_op mp-M2 (v1.7.0.8): AllReduce 规约操作（0=SUM 1=MAX 2=MIN 3=AVG），
    ///                  仅 sync_op==AllReduce 时有意义，其他 sync_op 传 0
    /// \param algo v2.2 Phase 3 (P3-F): CollectiveAlgo 枚举值（0=Ring 1=Tree 2=RH 3=PE），
    ///              仅 sync_op==AllReduce/AllGather/Broadcast/ReduceScatter/AllToAll 时有意义。
    ///              默认 0=Ring 与 P2 行为一致（向后兼容）。
    /// \param shard_idx v2.2 Phase 3 (P3-G): 大 chunk 分片序号（0-indexed），单 chunk 场景为 0
    /// \param total_shards v2.2 Phase 3 (P3-G): 总分片数，单 chunk 场景为 1
    /// \param from_node_id v2.3 Phase 4 (P4-A): 发送方 bit position（多 EpChannel 来源识别），默认 0
    /// \param step v2.3 Phase 4 (P4-A): 集合通信步数（状态机对齐），默认 0
    bool send_sync(std::uint64_t sync_id,
                   EpSyncOp sync_op,
                   std::uint64_t participant_mask,
                   std::span<const std::uint8_t> payload = {},
                   std::uint8_t reduce_op = 0,
                   std::uint8_t algo = 0,
                   std::uint16_t shard_idx = 0,
                   std::uint16_t total_shards = 1,
                   std::uint64_t from_node_id = 0,
                   std::uint16_t step = 0);

    // ====================================================================
    // P4 硬件加速 API
    // ====================================================================

    /// 绑定 TransportSelector（用于按 peer 选择 HwAccelTransport）。
    /// \param selector 选择器实例（生命周期由调用方保证，EpChannel 不持有）
    /// \note 不持有所有权；selector 可为 nullptr 表示禁用 hw 加速
    void set_hw_accel(net::TransportSelector *selector) noexcept;

    /// 当前是否绑定了 TransportSelector。
    bool has_hw_accel() const noexcept;

    /// 硬件加速发送 EP_DISPATCH_FRAME。
    /// 优先走 TransportSelector->select(peer) 返回的 HwAccelTransport，
    /// 失败时自动回退到普通 send_dispatch（QUIC UDP）。
    /// \param peer 目标节点 ID（用于 hw transport 选择）
    /// \param tensor_id tensor 全局唯一 ID
    /// \param expert_id 目标专家 ID
    /// \param token_cnt 本帧携带的 token 数
    /// \param buf GPU/Host buffer（CudaBuffer 句柄）
    /// \return true=发送成功（hw 或 fallback），false=两者均失败
    bool send_dispatch_hw(net::NodeId peer,
                          std::uint64_t tensor_id,
                          std::uint64_t expert_id,
                          std::uint64_t token_cnt,
                          const net::CudaBuffer &buf);

    /// 硬件加速发送 EP_COMBINE_FRAME（语义同 send_dispatch_hw）。
    bool send_combine_hw(net::NodeId peer,
                         std::uint64_t tensor_id,
                         std::uint64_t expert_id,
                         std::uint64_t token_cnt,
                         const net::CudaBuffer &buf);

    // ====================================================================
    // 接收回调注册
    // ====================================================================

    /// 设置回调集合（线程安全，可在 recv_loop 启动前或运行中调用）
    void set_callbacks(EpChannelCallbacks callbacks);

    // ====================================================================
    // 接收循环管理
    // ====================================================================

    /// 启动接收循环线程
    void start_recv_loop();

    /// 停止接收循环线程
    void stop_recv_loop();

    /// 接收循环是否在运行
    bool is_recv_running() const noexcept { return recv_running_.load(); }

    // ====================================================================
    // P6 可靠性 API（v1.6.0.7）
    // ====================================================================

    /// 启动重传检查线程（25ms 节拍）。
    /// 必须在 start_recv_loop 之后调用。
    /// 已在运行则 no-op。
    void start_resend_loop();

    /// 停止重传检查线程。
    /// 析构函数会自动调用。
    void stop_resend_loop();

    /// 重传线程是否在运行
    bool is_resend_running() const noexcept { return resend_running_.load(); }

    /// 当前 pending 队列长度（待 ACK 的 dispatch/combine 帧数）
    std::size_t pending_size() const;

    /// 清空 pending 队列（用于紧急恢复，如对端确认已重启）
    void clear_pending();

    // ====================================================================
    // 状态查询
    // ====================================================================

    /// 获取统计
    EpChannelStats stats() const;

    /// 当前 data_conn 是否有效（非空且未关闭）
    bool is_valid() const noexcept;

    /// 底层 Connection（用于高级用法）
    std::shared_ptr<endpoint::Connection> connection() const noexcept { return conn_; }

private:
    std::shared_ptr<endpoint::Connection> conn_;
    mutable std::mutex mu_;

    // 接收循环线程
    std::thread recv_thread_;
    std::atomic<bool> recv_running_{false};
    std::atomic<bool> recv_stop_{false};

    // 回调
    mutable std::mutex cb_mu_;
    EpChannelCallbacks callbacks_;

    // 统计
    mutable std::mutex stats_mu_;
    EpChannelStats stats_;

    // === P4 硬件加速 ===
    /// TransportSelector 指针（非拥有，由调用方管理生命周期）
    net::TransportSelector *hw_selector_{nullptr};

    // === P6 可靠性 ===
    /// 待 ACK 的帧队列（dispatch / combine）
    /// v1.7.0.7 multimodal H1: 改为 shared_ptr 管理。
    ///   根因：原实现用 unique_ptr，resend_ep_if_needed_ 锁内收集 to_resend 存裸指针，
    ///         锁外调用 resend_frame_ 期间若另一线程调用 clear_pending() 释放 unique_ptr，
    ///         裸指针立即悬空 → UAF。
    ///   修复：改用 shared_ptr，to_resend 存 shared_ptr 拷贝，即使 clear_pending 清空队列，
    ///         to_resend 中的 shared_ptr 仍持有引用，resend_frame_ 安全访问。
    ///   注：EpPendingFrame 含 std::atomic<bool> 不可拷贝不可移动，
    ///       但 shared_ptr 包裹后只需拷贝 shared_ptr（指针语义），无需拷贝 EpPendingFrame 本身。
    mutable std::mutex pending_mu_;
    std::deque<std::shared_ptr<EpPendingFrame>> pending_frames_;
    std::atomic<std::uint64_t> next_frame_seq_{1};  // 全局递增序列号

    /// 重传检查线程
    std::thread resend_thread_;
    std::atomic<bool> resend_running_{false};
    std::atomic<bool> resend_stop_{false};
    std::condition_variable resend_cv_;  // 用于 stop 时立即唤醒

    /// 接收主循环
    void recv_loop_();

    /// 处理一帧接收数据
    /// mp-M1 (v1.7.0.8): 返回消费的字节数。
    ///   >0: 成功解码并处理一帧，从累积缓冲移除对应字节
    ///   0: 数据不完整（半帧），保留累积缓冲等待更多数据
    ///   1（首字节非法时）: 丢弃 1 字节垃圾数据继续
    std::size_t handle_frame_(std::span<const std::uint8_t> data);

    /// 内部：发送一帧（编码 + open_stream + write + finish_send）
    bool send_frame_(const std::vector<std::uint8_t> &encoded);

    /// 内部：尝试用 HwAccelTransport 发送，返回发送字节数（0 表示未走 hw）
    std::size_t try_send_hw_(net::NodeId peer, const net::CudaBuffer &buf);

    // === P6 内部方法（v1.6.0.7） ===

    /// 入队 pending 并发送帧（dispatch / combine 共用）
    /// \param type 帧类型（DISPATCH / COMBINE）
    /// \param tensor_id 业务关联
    /// \param expert_id 专家 ID
    /// \param token_cnt token 数
    /// \param encoded 已编码的完整帧字节（含 type 前缀）
    /// \param padding dispatch 的对齐填充（combine 传空）
    /// \return true=入队 + 首次发送成功
    bool enqueue_and_send_(EpFrameType type,
                           std::uint64_t tensor_id,
                           std::uint64_t expert_id,
                           std::uint64_t token_cnt,
                           std::vector<std::uint8_t> encoded,
                           std::vector<std::uint8_t> padding);

    /// 发送 ACK 帧给对端（接收方调用）
    bool send_ack_(std::uint64_t frame_seq, std::uint64_t tensor_id, EpFrameType frame_type);

    /// 处理收到的 ACK 帧（标记对应 pending 为 acked）
    void handle_ack_(const EpAckFrame &ack);

    /// 重传检查主循环（resend_thread_ 入口）
    void resend_loop_();

    /// 单次检查 pending 队列，超时则重传，达到上限则丢弃
    void resend_ep_if_needed_();

    /// 重传单个帧
    void resend_frame_(EpPendingFrame &pf);

    /// 标记帧已丢弃（达到最大重传次数）
    /// v1.7.0.7 multimodal H1: 参数改为 shared_ptr 与 pending_frames_ 元素类型一致
    void drop_frame_(std::shared_ptr<EpPendingFrame> pf);

    /// 记录 partial_combine 降级（仅统计累加，业务逻辑由上层 SyncPrimitives 处理）
    void record_partial_combine_() noexcept;

    /// 统计更新
    void record_sent_(EpFrameType type, std::size_t bytes);
    void record_recv_(EpFrameType type, std::size_t bytes);
    void record_send_failure_();
    void record_decode_failure_();
    void record_hw_sent_(EpFrameType type, std::size_t bytes);
    void record_hw_failure_() noexcept;
    void record_hw_fallback_() noexcept;
    /// P6：记录重传统计
    void record_resent_(EpFrameType type) noexcept;
    /// P6：记录 ACK 收发统计
    void record_ack_sent_() noexcept;
    void record_ack_recv_() noexcept;
    /// P6：记录丢弃帧统计
    void record_resend_dropped_() noexcept;
};

}  // namespace linoh::multimodal::ep
