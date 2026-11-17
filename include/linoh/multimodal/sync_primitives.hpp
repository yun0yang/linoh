// sync_primitives.hpp — EP 跨节点同步原语（v1.6.0.2 / P1）
//
// 在 ep-sync/1 ALPN 通道上实现三种同步原语，支撑 EP combine 阶段的多专家结果同步：
//   - signal  : 单向通知（EP-worker -> EP-master，计算完成通知）
//   - barrier : 屏障（EP-master 收集所有 participant signal 后广播 release）
//   - all_reduce : 跨节点张量规约（sum/max/min/avg，ring all-reduce 算法）
//
// 设计原则：
//   - 不修改 EpChannel，独立 SyncPrimitives 类通过 EpChannel* 发送 SYNC 帧
//   - 通过 EpChannel 的 on_sync_received 回调将 SYNC 帧路由到 handle_sync_frame
//   - 会话状态由 sync_id 索引，participant_mask 跟踪参与节点（最多 64 节点）
//   - 超时机制：steady_clock deadline + 周期 check_timeouts 触发回调
//   - all_reduce P1 阶段假设单 chunk (<=4KB)，大 tensor 分片在 P2 阶段实现
//
// 与 v1.5.0.12 OOS_PN 重传关系：
//   - EP_SYNC 已在 P0 标记为 is_reliable_channel=true
//   - SYNC 帧通过 EpChannel::send_sync 发送，复用底层 Connection 的 OOS_PN 重传
//   - 100ms x 8 次重传，保证 SYNC 帧在高丢包下可达
//
// 线程模型：
//   - 发送：调用方线程同步调用 signal/barrier/all_reduce
//   - 接收：EpChannel 的 recv_loop_ 线程调用 handle_sync_frame
//   - 超时检查：上层周期调用 check_timeouts（建议 10ms 周期）
//   - 回调在 recv_loop_ 线程内同步调用，调用方需避免阻塞

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "linoh/multimodal/ep_channel.hpp"
#include "linoh/multimodal/ep_frames.hpp"
#include "linoh/multimodal/ring_engine.hpp"
#include "linoh/multimodal/tree_engine.hpp"
#include "linoh/multimodal/rh_engine.hpp"
#include "linoh/multimodal/pe_engine.hpp"

namespace linoh::multimodal::ep {

/// 规约操作类型（all_reduce 使用）
enum class ReduceOp : std::uint8_t {
    SUM = 0,  // 求和
    MAX = 1,  // 最大值
    MIN = 2,  // 最小值
    AVG = 3,  // 平均值（= SUM / N）
};

/// 规约数据类型（决定 apply_reduce_ 的元素宽度）
/// 修复 v1.7.0.7 C11: 原实现硬编码假设 uint64，F32/F16 等被当作 uint64 累加导致数据破坏
enum class ReduceDType : std::uint8_t {
    U64 = 0,  // uint64_t（8 字节，向后兼容默认值）
    U32 = 1,  // uint32_t（4 字节）
    U16 = 2,  // uint16_t（2 字节）
    F64 = 3,  // double（8 字节）
    F32 = 4,  // float（4 字节）
    F16 = 5,  // half（2 字节，按 float 累加后截断）
    BF16 = 6, // bfloat16（2 字节，按 float 累加后截断）
};

/// 同步会话状态
enum class SyncState : std::uint8_t {
    Waiting    = 0,  // 等待 participant 到齐
    Reducing   = 1,  // all_reduce 进行中（ring 阶段）
    Releasing  = 2,  // 正在广播 release
    Completed  = 3,  // 正常完成
    TimedOut   = 4,  // 超时
};

/// 同步会话（内部状态）
struct SyncSession {
    std::uint64_t sync_id{0};
    std::uint64_t participant_mask{0};  // 期望参与节点位图（bit i = 节点 i 参与）
    std::uint64_t arrived_mask{0};      // 已到达节点位图
    SyncState state{SyncState::Waiting};
    std::chrono::steady_clock::time_point deadline;
    ReduceOp reduce_op{ReduceOp::SUM};       // all_reduce 操作类型
    ReduceDType reduce_dtype{ReduceDType::U64}; // all_reduce 数据类型（v1.7.0.7 C11）
    std::vector<std::uint8_t> local_data;   // 本地数据
    std::vector<std::uint8_t> reduced_data;  // 规约结果
    std::uint32_t ring_round{0};            // 当前 ring 轮次
    std::uint32_t total_rings{0};           // 总 ring 轮数（= 2*(N-1)）
    std::uint64_t self_node_id{0};          // 本节点在 ring 中的位置（0-indexed）

    // === v2.1 Phase 2: AllGather ===
    /// 已收集 chunk：key = 发送方 bit position，value = chunk 数据
    std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> gather_chunks;
    /// chunk 大小（所有节点等长，用于预分配结果 buffer）
    std::size_t gather_chunk_size{0};

    // === v2.1 Phase 2: Broadcast ===
    /// Broadcast root 节点（bit position）
    std::uint64_t root_node_id{0};

    // === v2.1 Phase 2 M2: ReduceScatter ===
    /// ReduceScatter 结果分片索引（本节点应获取的结果片段序号，= self_node_id 在有序列表中的位置）
    std::uint32_t scatter_chunk_index{0};

    // === v2.1 Phase 2 M2: AllToAll ===
    /// AllToAll 已接收数据：key = 发送方 bit position，value = 该发送方发给本节点的数据
    std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> all_to_all_received;

    // === v2.2 Phase 3 (P3-F): 算法标识 ===
    /// 集合通信算法（CollectiveAlgo 枚举值，0=Ring 1=Tree 2=RH 3=PE）
    /// 用于诊断和未来 P4 真实算法分派，当前 P3-F 阶段仅记录不改变传输逻辑
    std::uint8_t algo{0};

    // === v2.2 Phase 3 (P3-G): 大 chunk 分片重组状态 ===
    /// 已接收分片：key = (sender_bit << 16) | shard_idx，value = 分片数据
    /// 用于 AllGather/AllToAll/ReduceScatter 等需要重组分片的操作
    std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> shard_buffer;
    /// 各发送方的已接收分片计数：key = sender_bit，value = 已接收分片数
    std::unordered_map<std::uint64_t, std::uint16_t> shard_received_count;
    /// 各发送方的期望分片总数：key = sender_bit，value = total_shards
    std::unordered_map<std::uint64_t, std::uint16_t> shard_total;
    /// 各发送方的已重组完整数据：key = sender_bit，value = 完整数据
    std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> reassembled_data;

    // === v2.3 Phase 4 (P4-C): Ring 算法状态机 ===
    /// Ring AllReduce/AllGather/ReduceScatter 多步通信状态
    /// 仅当 algo=0 (Ring) 且 peer_channels_ 已配置时启用
    struct RingAlgoState {
        RingPhase phase{RingPhase::ReduceScatter};   // 当前阶段
        std::uint32_t current_step{0};                // 当前步数 (0..total_steps-1)
        std::uint32_t total_steps{0};                 // 总步数 = 2*(N-1) 或 N-1
        std::size_t self_rank{0};                     // 本节点在环中的 rank
        std::size_t N{0};                             // 环节点数
        std::uint64_t next_node{0};                   // 右邻居 bit position（发送目标）
        std::uint64_t prev_node{0};                   // 左邻居 bit position（接收来源）
        std::size_t chunk_size{0};                    // 每个 chunk 字节数 = msg / N
        std::vector<std::vector<std::uint8_t>> chunks; ///< N 个 chunk（规约中累积）
        std::vector<std::uint8_t> result;             // 最终结果（AllGather 结束后）
        bool step_send_done{false};                   // 当前步已发送
        bool step_recv_done{false};                   // 当前步已接收 prev 数据
        EpSyncOp op{EpSyncOp::AllReduce};             // 操作类型（AllReduce/AllGather/ReduceScatter）
    };
    std::optional<RingAlgoState> ring_algo;  ///< P4-C: Ring 状态（非 Ring 算法时为 nullopt）

    // === v2.3 Phase 4 (P4-D): Tree 算法状态机 ===
    /// Tree Broadcast/AllGather 多步通信状态
    /// 仅当 algo=1 (Tree) 且 peer_channels_ 已配置 parent/children 时启用
    enum class TreePhase : std::uint8_t {
        GatherUp      = 0,  // AllGather 阶段 1：向上收集（叶子→root）
        BroadcastDown = 1,  // Broadcast / AllGather 阶段 2：向下分发（root→叶子）
        Done          = 2,
    };
    struct TreeAlgoState {
        TreePhase phase{TreePhase::BroadcastDown};   // 当前阶段
        std::uint32_t current_step{0};                // 当前步数 (0..total_steps-1)
        std::uint32_t total_steps{0};                 // 总步数 = log₂N（Broadcast）或 2×log₂N（AllGather）
        std::uint32_t recv_step{0};                   // 本节点接收步（= MSB(virtual_rank)，root=UINT32_MAX 表示不接收）
        std::uint32_t children_received{0};           // GatherUp 阶段已收 children 数据计数

        // 拓扑信息（基于 virtual_rank）
        std::size_t self_virtual{0};                  // 本节点虚拟 rank（real XOR root）
        std::size_t root_rank{0};                     // root 在 participants 中的 real rank
        std::size_t N{0};                             // 节点数
        std::uint64_t parent_bit{0};                  // 父节点 bit position（root 为 0）
        std::vector<std::uint64_t> children_bits;     // 子节点 bit position 列表（按 virtual 升序）
        bool is_root{false};                          // 本节点是否为 root

        // 数据
        std::size_t chunk_size{0};                    // 单 chunk 字节数（AllGather 用）
        std::vector<std::vector<std::uint8_t>> chunks; ///< N 个 chunk（AllGather 收集/分发）
        std::vector<std::uint8_t> data;               // Broadcast 单包数据
        std::vector<std::uint8_t> result;             // 最终结果

        // 步进标志（与 Ring 一致）
        bool step_send_done{false};                   // 当前步已发送
        bool step_recv_done{false};                   // 当前步已接收
        EpSyncOp op{EpSyncOp::Broadcast};             // 操作类型（Broadcast/AllGather）
    };
    std::optional<TreeAlgoState> tree_algo;  ///< P4-D: Tree 状态（非 Tree 算法时为 nullopt）

    // === v2.3 Phase 4 (P4-E): RH 算法状态机 ===
    /// RecursiveHalving AllReduce/ReduceScatter 多步通信状态
    /// 仅当 algo=2 (RH) 且 peer_channels_ 已配置全部 partner 时启用
    struct RhAlgoState {
        RHPhase phase{RHPhase::ReduceScatter};   // 当前阶段
        std::uint32_t current_step{0};            // 当前步数 (0..total_steps-1)
        std::uint32_t total_steps{0};             // 总步数 = log₂N (RS) 或 2×log₂N (AR)
        std::size_t self_rank{0};                 // 本节点 rank
        std::size_t N{0};                         // 节点数（必须 2 的幂）
        std::size_t msg_size{0};                  // 消息总大小（字节）
        std::size_t chunk_size{0};                // msg_size / N

        // 通信伙伴（每步不同，precomputed）
        std::vector<std::uint64_t> partner_bits;  // log₂N 个 partner 的 bit position

        // 数据
        std::vector<std::uint8_t> work_buf;       // 工作缓冲（ReduceScatter 原地缩减）
        std::vector<std::uint8_t> result;         // 最终结果

        // 步进标志（与 Ring/Tree 一致）
        bool step_send_done{false};               // 当前步已发送
        bool step_recv_done{false};               // 当前步已接收 partner 数据
        EpSyncOp op{EpSyncOp::AllReduce};         // 操作类型（AllReduce/ReduceScatter）
    };
    std::optional<RhAlgoState> rh_algo;  ///< P4-E: RH 状态（非 RH 算法时为 nullopt）

    // === v2.3 Phase 4 (P4-F): PE 算法状态机 ===
    /// PairwiseExchange AllToAll 多步通信状态
    /// 仅当 algo=3 (PE) 且 peer_channels_ 已配置全部 partner 时启用
    struct PeAlgoState {
        std::uint32_t current_step{0};            // 当前步数 (0..log₂N-1)
        std::uint32_t total_steps{0};             // 总步数 = log₂N
        std::size_t self_rank{0};                 // 本节点 rank
        std::size_t N{0};                         // 节点数（必须 2 的幂）
        std::size_t chunk_size{0};                // 单分片字节数 = local_chunk.size() / N

        // 通信伙伴（每步不同，precomputed）
        std::vector<std::uint64_t> partner_bits;  // log₂N 个 partner 的 bit position

        // 数据缓冲：key = dest 索引（0..N-1），value = 该 dest 的分片数据
        // 初始：本节点持有的 N 个分片（C[self_rank][0..N-1]）
        // 完成后：key = self_rank 的分片被填满（来自所有 source 的该 dest 数据）
        std::unordered_map<std::size_t, std::vector<std::uint8_t>> chunks;

        // 步进标志（与 Ring/Tree/RH 一致）
        bool step_send_done{false};               // 当前步已发送
        bool step_recv_done{false};               // 当前步已接收 partner 数据
    };
    std::optional<PeAlgoState> pe_algo;  ///< P4-F: PE 状态（非 PE 算法时为 nullopt）
};

/// 同步回调集合
struct SyncCallbacks {
    /// barrier 完成（所有 participant 到齐，release 已广播）
    std::function<void(std::uint64_t sync_id)> on_barrier_complete;
    /// 同步超时
    std::function<void(std::uint64_t sync_id)> on_sync_timeout;
    /// 收到 signal
    std::function<void(std::uint64_t sync_id, std::uint64_t from_mask)> on_signal_received;
    /// all_reduce 完成（结果可用）
    std::function<void(std::uint64_t sync_id, std::span<const std::uint8_t> result)> on_all_reduce_complete;
    /// 收到 release（解除阻塞）
    std::function<void(std::uint64_t sync_id)> on_release_received;
    // === P6 部分降级回调（v1.6.0.7） ===
    /// barrier 超时但已有部分 participant 到齐（allow_partial_combine=true 时触发）
    /// \param sync_id 会话 ID
    /// \param arrived_mask 已到齐节点位图
    /// \param participant_mask 期望参与节点位图
    /// \note 业务层可基于此回调决定是否使用部分 combine 结果
    std::function<void(std::uint64_t sync_id, std::uint64_t arrived_mask, std::uint64_t participant_mask)> on_barrier_partial;
    // === v2.1 Phase 2: 集合通信回调 ===
    /// all_gather 完成（所有 participant 的 chunk 已收集并拼接）
    /// \param sync_id 会话 ID
    /// \param result 拼接结果（按 participant bit 升序排列各 chunk）
    std::function<void(std::uint64_t sync_id, std::span<const std::uint8_t> result)> on_all_gather_complete;
    /// 收到 broadcast 数据（root 节点分发的数据已到达）
    /// \param sync_id 会话 ID
    /// \param root_node_id 广播源节点的 bit position
    /// \param data 广播数据
    std::function<void(std::uint64_t sync_id, std::uint64_t root_node_id, std::span<const std::uint8_t> data)> on_broadcast_received;
    // === v2.1 Phase 2 M2: ReduceScatter / AllToAll 回调 ===
    /// reduce_scatter 完成（本节点获取到规约后属于自己的分片）
    /// \param sync_id 会话 ID
    /// \param result 本节点的结果分片
    std::function<void(std::uint64_t sync_id, std::span<const std::uint8_t> result)> on_reduce_scatter_complete;
    /// all_to_all 完成（所有发送方的数据已到达本节点）
    /// \param sync_id 会话 ID
    /// \param from_mask 已接收数据的发送方位图
    /// \param data 拼接结果（按发送方 bit 升序排列各 chunk）
    std::function<void(std::uint64_t sync_id, std::uint64_t from_mask, std::span<const std::uint8_t> data)> on_all_to_all_complete;
};

/// 同步原语管理器
///
/// 用法（EP-master 端）：
///   EpChannel channel(data_conn);
///   channel.start_recv_loop();
///   SyncPrimitives sync(&channel);
///   channel.set_callbacks({.on_sync_received = [&](const EpSyncFrame& f){ sync.handle_sync_frame(f); }});
///   sync.set_callbacks({...});
///   sync.barrier(1001, 0b1111, 30s);  // 4 节点 barrier
///
/// 用法（EP-worker 端）：
///   sync.signal(1001, 0b0001);  // 通知 master（bit 0）
class SyncPrimitives {
public:
    /// 构造 SyncPrimitives
    /// \param channel EP 通道指针（非拥有，调用方需保证生命周期长于 SyncPrimitives）
    explicit SyncPrimitives(EpChannel *channel);

    ~SyncPrimitives();

    // 不可拷贝、不可移动（内部含 mutex + session map）
    SyncPrimitives(const SyncPrimitives &) = delete;
    SyncPrimitives &operator=(const SyncPrimitives &) = delete;
    SyncPrimitives(SyncPrimitives &&) = delete;
    SyncPrimitives &operator=(SyncPrimitives &&) = delete;

    // ====================================================================
    // 同步原语 API
    // ====================================================================

    /// signal：单向通知（worker -> master）
    /// \param sync_id 同步会话 ID
    /// \param to_mask 目标节点位图（通常为 master 单点）
    /// \return true=发送成功
    bool signal(std::uint64_t sync_id, std::uint64_t to_mask);

    /// barrier：阻塞直到所有 participant 到齐
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图
    /// \param self_node_id 本节点在 participant 中的位置（bit index，0-indexed）
    /// \param timeout 超时（默认 30s）
    /// \return true=成功完成，false=超时或失败
    /// 注意：调用方线程会阻塞直到完成或超时
    bool barrier(std::uint64_t sync_id,
                 std::uint64_t participant_mask,
                 std::uint64_t self_node_id,
                 std::chrono::milliseconds timeout = std::chrono::seconds(30));

    /// all_reduce：跨节点张量规约（ring all-reduce）
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图
    /// \param self_node_id 本节点在 ring 中的位置（bit index，0-indexed）
    /// \param local_data 本地数据（P1 阶段限制 <=4KB，大 tensor 在 P2 实现）
    /// \param op 规约操作（SUM/MAX/MIN/AVG）
    /// \param dtype 数据类型（U64/U32/U16/F64/F32/F16/BF16），默认 U64 向后兼容
    /// \param timeout 超时
    /// \param algo v2.2 Phase 3 (P3-F): 集合通信算法（0=Ring 1=Tree 2=RH 3=PE），默认 0 向后兼容
    /// \return 规约结果（成功），nullopt（失败/超时）
    std::optional<std::vector<std::uint8_t>> all_reduce(
        std::uint64_t sync_id,
        std::uint64_t participant_mask,
        std::uint64_t self_node_id,
        std::span<const std::uint8_t> local_data,
        ReduceOp op = ReduceOp::SUM,
        ReduceDType dtype = ReduceDType::U64,
        std::chrono::milliseconds timeout = std::chrono::seconds(30),
        std::uint8_t algo = 0);

    // ====================================================================
    // v2.1 Phase 2: 集合通信原语（AllGather / Broadcast）
    // ====================================================================

    /// all_gather：跨节点全收集（每个 participant 的 chunk 拼接为完整结果）
    ///
    /// 算法（简化 ring）：每个 participant 将本地 chunk 通过 EP_SYNC_FRAME(AllGather)
    /// 发送给其他所有 participant，接收方按发送方 bit position 收集到 gather_chunks，
    /// 当所有 participant 的 chunk 到齐后按 bit 升序拼接结果并触发完成回调。
    ///
    /// P2 阶段限制：单 chunk <= 4KB（EpSyncFrame::kMaxPayloadLen），大 tensor 分片留待后续。
    ///
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图
    /// \param self_node_id 本节点 bit position（用于在结果中定位自身 chunk）
    /// \param local_chunk 本节点 chunk 数据（<=4KB）
    /// \param timeout 超时
    /// \param algo v2.2 Phase 3 (P3-F): 集合通信算法（0=Ring 1=Tree 2=RH 3=PE），默认 0 向后兼容
    /// \return 拼接结果（成功，按 participant bit 升序），nullopt（失败/超时）
    std::optional<std::vector<std::uint8_t>> all_gather(
        std::uint64_t sync_id,
        std::uint64_t participant_mask,
        std::uint64_t self_node_id,
        std::span<const std::uint8_t> local_chunk,
        std::chrono::milliseconds timeout = std::chrono::seconds(30),
        std::uint8_t algo = 0);

    /// broadcast：root 节点数据广播到所有 participant
    ///
    /// 算法（简化 tree）：root 节点通过 EP_SYNC_FRAME(Broadcast) 发送数据到所有 participant，
    /// 接收方记录 root_node_id 并触发 on_broadcast_received 回调。
    /// root 节点本身不等待（直接返回 true），非 root 节点通过回调接收数据。
    ///
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图
    /// \param root_node_id root 节点 bit position（必须在 participant_mask 中）
    /// \param data 广播数据（仅 root 节点提供，非 root 传空 span）
    /// \param timeout 超时（仅 root 节点用于发送等待，非 root 通过回调异步接收）
    /// \param algo v2.2 Phase 3 (P3-F): 集合通信算法（0=Ring 1=Tree 2=RH 3=PE），默认 0 向后兼容
    /// \return true=发送/接收成功，false=失败（channel 无效 / root 非法 / 发送失败）
    bool broadcast(
        std::uint64_t sync_id,
        std::uint64_t participant_mask,
        std::uint64_t root_node_id,
        std::span<const std::uint8_t> data,
        std::chrono::milliseconds timeout = std::chrono::seconds(30),
        std::uint8_t algo = 0);

    // ====================================================================
    // v2.1 Phase 2 M2: 集合通信原语（ReduceScatter / AllToAll）
    // ====================================================================

    /// reduce_scatter：跨节点规约后按 chunk 分散结果
    ///
    /// 算法（简化 ring）：每个 participant 将本地数据通过 EP_SYNC_FRAME(ReduceScatter)
    /// 发送给其他所有 participant。接收方收集所有 participant 数据后执行规约（SUM/MAX/MIN），
    /// 将结果等分为 N 份，每个 participant 获取自己对应的一份（按 bit 升序索引）。
    ///
    /// P2 阶段限制：单 participant 数据 <= 4KB，数据长度必须能被 participant 数整除。
    ///
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图
    /// \param self_node_id 本节点 bit position
    /// \param local_data 本节点数据（<=4KB，长度必须能被 participant 数整除）
    /// \param op 规约操作（SUM/MAX/MIN）
    /// \param dtype 数据类型
    /// \param timeout 超时
    /// \param algo v2.2 Phase 3 (P3-F): 集合通信算法（0=Ring 1=Tree 2=RH 3=PE），默认 0 向后兼容
    /// \return 本节点的结果分片（成功），nullopt（失败/超时）
    std::optional<std::vector<std::uint8_t>> reduce_scatter(
        std::uint64_t sync_id,
        std::uint64_t participant_mask,
        std::uint64_t self_node_id,
        std::span<const std::uint8_t> local_data,
        ReduceOp op = ReduceOp::SUM,
        ReduceDType dtype = ReduceDType::U64,
        std::chrono::milliseconds timeout = std::chrono::seconds(30),
        std::uint8_t algo = 0);

    /// all_to_all：全交换（每个节点向其他节点发送不同数据）
    ///
    /// 算法（PairwiseExchange）：每个节点通过 EP_SYNC_FRAME(AllToAll) 向其他 participant
    /// 发送数据。帧的 participant_mask 字段表示目标节点 bit（单 bit）。
    /// 接收方按发送方 bit position 收集数据，当所有 participant 的数据到齐后
    /// 按 bit 升序拼接结果并触发完成回调。
    ///
    /// P2 阶段限制：单 chunk <= 4KB。本节点向每个目标发送的数据需分别调用此方法
    /// （每次 participant_mask 指定一个目标 bit）。
    ///
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图（所有参与 AllToAll 的节点）
    /// \param self_node_id 本节点 bit position
    /// \param local_chunk 本节点要发送给"所有其他 participant"的拼接数据
    ///        （每个 participant 的数据等长，按 bit 升序拼接，含自身位置的空占位）
    /// \param timeout 超时
    /// \param algo v2.2 Phase 3 (P3-F): 集合通信算法（0=Ring 1=Tree 2=RH 3=PE），默认 0 向后兼容
    /// \return 拼接结果（按发送方 bit 升序），nullopt（失败/超时）
    std::optional<std::vector<std::uint8_t>> all_to_all(
        std::uint64_t sync_id,
        std::uint64_t participant_mask,
        std::uint64_t self_node_id,
        std::span<const std::uint8_t> local_chunk,
        std::chrono::milliseconds timeout = std::chrono::seconds(30),
        std::uint8_t algo = 0);

    // ====================================================================
    // v2.3 Phase 4 (P4-B): 多 EpChannel 注入（Ring/Tree 等拓扑通信）
    // ====================================================================
    //
    // Ring AllReduce 需要与 next/prev 两个邻居分别通信，单 EpChannel 只能
    // 连接单个对端。通过 peer_channels_ 注入多个 EpChannel，每个对应一个
    // 邻居节点（按 bit position 索引），send_to_peer_ 根据目标 bit 路由
    // 到对应 channel。若 peer_channels_ 未配置某 bit，回退到默认 channel_。
    //
    // 典型用法（Ring 4 节点，本节点 bit=0x02）：
    //   sync.set_self_node_id(0x02);
    //   sync.set_ring_peers(
    //       /*next_bit=*/0x04, &next_channel,
    //       /*prev_bit=*/0x01, &prev_channel);
    //   sync.all_reduce(sid, 0x0F, 0x02, data, ..., /*algo=*/0);

    /// 设置本节点 bit position（Ring/Tree 算法需要，用于推导 rank）
    /// \param self_bit 本节点在 participant_mask 中的 bit position
    /// \note 必须在 all_reduce/all_gather 等（algo=Ring）之前设置
    void set_self_node_id(std::uint64_t self_bit) noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        self_node_id_ = self_bit;
    }
    std::uint64_t self_node_id() const noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        return self_node_id_;
    }

    /// 注入单个 peer 的 EpChannel
    /// \param peer_bit 对端节点 bit position
    /// \param channel  对端 EpChannel 指针（非拥有，调用方保证生命周期）
    void set_peer_channel(std::uint64_t peer_bit, EpChannel *channel);

    /// 一次性配置 Ring 环邻居（next + prev）
    /// \param next_bit 右邻居 bit（数据发送方向 rank+1）
    /// \param next_channel 右邻居 channel
    /// \param prev_bit 左邻居 bit（数据接收方向 rank-1）
    /// \param prev_channel 左邻居 channel
    void set_ring_peers(std::uint64_t next_bit, EpChannel *next_channel,
                        std::uint64_t prev_bit, EpChannel *prev_channel);

    /// 清除所有 peer channel 配置（回退到单 channel 模式）
    void clear_peer_channels() noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        peer_channels_.clear();
    }

    /// 已配置的 peer channel 数量
    std::size_t peer_channel_count() const noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        return peer_channels_.size();
    }

    /// 查询某 peer bit 是否已配置专用 channel
    bool has_peer_channel(std::uint64_t peer_bit) const noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        return peer_channels_.find(peer_bit) != peer_channels_.end();
    }

    // ====================================================================
    // v2.3 Phase 4 (P4-D): Tree 拓扑邻居配置
    // ====================================================================
    //
    // Tree Broadcast/AllGather 需要与 parent 和 children 分别通信：
    //   - 非 root 节点从 parent 接收数据（需 parent channel）
    //   - internal 节点向 children 转发数据（需 children channel）
    //   - leaf 节点仅从 parent 接收，无 children
    //   - root 节点仅向 children 发送，无 parent
    //
    // 典型用法（N=4 binomial tree，root=bit0，self=bit2）：
    //   sync.set_self_node_id(0x02);
    //   sync.set_tree_peers(
    //       /*parent_bit=*/0x01, &parent_channel,
    //       /*children=*/{{0x04, &child_channel}});

    /// 一次性配置 Tree 拓扑邻居（parent + children）
    /// \param parent_bit 父节点 bit position（root 传 0 且 parent_channel=nullptr）
    /// \param parent_channel 父节点 channel（root 传 nullptr）
    /// \param children 子节点列表（bit + channel 配对，root/internal 提供，leaf 传空）
    /// \note 内部循环调用 set_peer_channel 注入 peer_channels_。
    ///       parent_channel=nullptr 时跳过 parent 注入（root 场景）。
    void set_tree_peers(std::uint64_t parent_bit, EpChannel *parent_channel,
                        const std::vector<std::pair<std::uint64_t, EpChannel *>> &children);

    // ====================================================================
    // v2.3 Phase 4 (P4-E): RH 拓扑邻居配置
    // ====================================================================
    //
    // RecursiveHalving AllReduce/ReduceScatter 需要与 log₂N 个 partner 通信：
    //   每步 s 的 partner = self_rank XOR (1<<s)，s = 0..log₂N-1
    //   所有 partner 的 channel 必须预先注入 peer_channels_
    //
    // 典型用法（N=4, self=bit0, partners=bit1/bit2）：
    //   sync.set_self_node_id(0);
    //   sync.set_rh_peers({{0x02, &ch1}, {0x04, &ch2}});
    //   sync.all_reduce(sid, 0x0F, 0, data, ..., /*algo=*/2);

    /// 一次性配置 RH 全部 partner（log₂N 个）
    /// \param partners partner 列表（bit + channel 配对，每步一个 partner）
    /// \note 内部循环调用 set_peer_channel 注入 peer_channels_。
    ///       与 set_ring_peers/set_tree_peers 风格一致，可混用（共享 peer_channels_）。
    void set_rh_peers(const std::vector<std::pair<std::uint64_t, EpChannel *>> &partners);

    // ====================================================================
    // v2.3 Phase 4 (P4-F): PairwiseExchange 拓扑邻居配置
    // ====================================================================
    //
    // PairwiseExchange AllToAll 需要与 log₂N 个 partner 通信：
    //   每步 s 的 partner = self_rank XOR (1<<s)，s = 0..log₂N-1
    //   所有 partner 的 channel 必须预先注入 peer_channels_
    //
    // 典型用法（N=4, self=bit0, partners=bit1/bit2）：
    //   sync.set_self_node_id(0);
    //   sync.set_pe_peers({{0x02, &ch1}, {0x04, &ch2}});
    //   sync.all_to_all(sid, 0x0F, 0, data, ..., /*algo=*/3);

    /// 一次性配置 PE 全部 partner（log₂N 个）
    /// \param partners partner 列表（bit + channel 配对，每步一个 partner）
    /// \note 内部循环调用 set_peer_channel 注入 peer_channels_。
    ///       与 set_rh_peers 风格一致，可混用（共享 peer_channels_）。
    void set_pe_peers(const std::vector<std::pair<std::uint64_t, EpChannel *>> &partners);

    // ====================================================================
    // 回调注册
    // ====================================================================

    void set_callbacks(SyncCallbacks callbacks);

    // ====================================================================
    // P6 部分降级配置（v1.6.0.7）
    // ====================================================================

    /// 设置是否允许 barrier 超时时使用部分 combine 结果。
    /// \param allow true=允许（超时且有部分 participant 到齐时触发 on_barrier_partial 回调）
    ///              false=禁止（超时直接返回 false，默认值）
    void set_allow_partial_combine(bool allow) noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        allow_partial_combine_ = allow;
    }

    /// 当前是否允许部分降级
    bool allow_partial_combine() const noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        return allow_partial_combine_;
    }

    // ====================================================================
    // 帧路由入口（由 EpChannel 的 on_sync_received 调用）
    // ====================================================================

    /// 处理收到的 EP_SYNC_FRAME
    /// \param frame 解码后的 SYNC 帧
    void handle_sync_frame(const EpSyncFrame &frame);

    // ====================================================================
    // 超时清理（周期调用，由上层 timer 驱动，建议 10ms 周期）
    // ====================================================================

    void check_timeouts();

    // ====================================================================
    // 状态查询（主要用于测试）
    // ====================================================================

    /// 获取指定会话状态
    std::optional<SyncSession> get_session(std::uint64_t sync_id) const;

    /// 当前活跃会话数
    std::size_t session_count() const;

    /// 清理已完成/超时的会话（可手动调用释放内存）
    void cleanup_finished();

    // mp-L3 (v1.7.0.8): 被动会话超时可配置（原硬编码 30s）
    //   场景：被动参与会话（barrier/all_reduce）由对端 SYNC 帧触发创建，
    //   原硬编码 30s 超时在某些场景过短（如大 tensor all_reduce 慢）或过长
    //   （如快速 barrier 测试）。现提供 setter 供上层按场景调整。
    //   注意：发起方会话仍使用 barrier()/all_reduce() 入参 timeout，此设置
    //   仅影响被动会话（对端发起、本节点参与）。
    void set_passive_session_timeout(std::chrono::milliseconds timeout) {
        // 修复 A4: 加锁保护，与 handle_* 函数的锁内读取同步（原实现未加锁 → 数据竞争 UB）
        std::lock_guard<std::mutex> lk(mu_);
        passive_session_timeout_ = timeout;
    }
    std::chrono::milliseconds passive_session_timeout() const {
        // 修复 A4: 加锁保护（mu_ 为 mutable，const 方法可加锁）
        std::lock_guard<std::mutex> lk(mu_);
        return passive_session_timeout_;
    }

    // ====================================================================
    // v2.2 Phase 3 (P3-G): 大 chunk 分片配置
    // ====================================================================
    //
    // 当单次发送的数据（all_gather/all_to_all/broadcast/reduce_scatter 的本地
    // chunk/local_data/data）超过 shard_size_ 时，自动拆分为多个 EP_SYNC_FRAME
    // 分片传输，每片携带 shard_idx / total_shards 字段。接收方按发送方缓冲分片，
    // 全部分片到齐后按 shard_idx 升序重组为完整数据，支持乱序到达。
    //
    // 默认 64KB：兼顾单帧效率与内存占用。测试场景可调小（如 8/16/32 字节）以
    // 用小数据量验证分片路径。设为 0 表示禁用分片（始终单帧，向后兼容）。

    /// 设置分片阈值（单帧 payload 上限），0=禁用分片
    void set_shard_size(std::size_t size) noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        shard_size_ = size;
    }
    /// 当前分片阈值
    std::size_t shard_size() const noexcept {
        std::lock_guard<std::mutex> lk(mu_);
        return shard_size_;
    }

private:
    EpChannel *channel_;  // 非拥有，默认通道（向后兼容）

    // v2.3 Phase 4 (P4-B): 多 EpChannel 路由表
    // key = peer bit position，value = 对端 EpChannel*
    // send_to_peer_ 优先查此表，未命中回退到 channel_
    std::unordered_map<std::uint64_t, EpChannel *> peer_channels_;
    // v2.3 Phase 4 (P4-B): 本节点 bit position（Ring/Tree 算法推导 rank 用）
    std::uint64_t self_node_id_{0};

    mutable std::mutex mu_;
    std::unordered_map<std::uint64_t, SyncSession> sessions_;
    SyncCallbacks callbacks_;
    bool allow_partial_combine_{false};  // P6：默认禁止部分降级
    // mp-L3 (v1.7.0.8): 被动会话超时，默认 30s 兼容原行为
    std::chrono::milliseconds passive_session_timeout_{std::chrono::seconds(30)};
    // v2.2 Phase 3 (P3-G): 分片阈值，默认 64KB，0=禁用分片
    std::size_t shard_size_{64 * 1024};

    // 完成会话的条件变量（barrier/all_reduce 阻塞等待）
    std::condition_variable cv_;

    // 内部辅助：发送 SYNC 帧（默认通道）
    // mp-M2 (v1.7.0.8): reduce_op 传递 AllReduce 规约操作到 EpSyncFrame
    // v2.2 Phase 3 (P3-F): algo 传递集合通信算法（0=Ring 1=Tree 2=RH 3=PE）
    // v2.2 Phase 3 (P3-G): shard_idx/total_shards 支持大 chunk 分片传输
    // v2.3 Phase 4 (P4-A): from_node_id/step 支持多步通信状态机对齐
    bool send_sync_frame_(std::uint64_t sync_id,
                          EpSyncOp op,
                          std::uint64_t participant_mask,
                          std::span<const std::uint8_t> payload = {},
                          std::uint8_t reduce_op = 0,
                          std::uint8_t algo = 0,
                          std::uint16_t shard_idx = 0,
                          std::uint16_t total_shards = 1,
                          std::uint64_t from_node_id = 0,
                          std::uint16_t step = 0);

    // v2.3 Phase 4 (P4-B): 按目标 peer bit 路由发送 SYNC 帧
    // 优先查 peer_channels_，未命中回退到默认 channel_
    // \param peer_bit 目标节点 bit position（用于路由选择）
    // \param sync_id 会话 ID
    // \param op SYNC 操作类型
    // \param participant_mask 帧的 participant_mask 字段
    // \param payload 负载
    // \param reduce_op 规约操作
    // \param algo 算法标识
    // \param shard_idx 分片序号
    // \param total_shards 总分片数
    // \param from_node_id 发送方 bit position（多 EpChannel 来源识别）
    // \param step 集合通信步数
    // \return true=发送成功，false=无可用 channel 或发送失败
    bool send_to_peer_(std::uint64_t peer_bit,
                       std::uint64_t sync_id,
                       EpSyncOp op,
                       std::uint64_t participant_mask,
                       std::span<const std::uint8_t> payload = {},
                       std::uint8_t reduce_op = 0,
                       std::uint8_t algo = 0,
                       std::uint16_t shard_idx = 0,
                       std::uint16_t total_shards = 1,
                       std::uint64_t from_node_id = 0,
                       std::uint16_t step = 0);

    // v2.2 Phase 3 (P3-G): 大 chunk 自动分片发送
    // 当 data.size() > shard_size_ 时拆分为多个分片帧依次发送，每片携带
    // shard_idx / total_shards。shard_size_ = 0 或 data 较小时退化为单帧（total_shards=1）。
    // \param sync_id 会话 ID
    // \param op SYNC 操作类型
    // \param target_mask 帧的 participant_mask 字段（发送方 bit / root bit / 目标集合）
    // \param data 待发送完整数据
    // \param reduce_op 规约操作（reduce_scatter/all_reduce 用，其他传 0）
    // \param algo 集合通信算法标识
    // \return true=所有分片发送成功，false=任一分片发送失败
    bool send_sharded_(std::uint64_t sync_id,
                       EpSyncOp op,
                       std::uint64_t target_mask,
                       std::span<const std::uint8_t> data,
                       std::uint8_t reduce_op,
                       std::uint8_t algo);

    // v2.2 Phase 3 (P3-G): 分片缓冲与乱序重组
    // 将到达的分片缓冲到 session.shard_buffer，当某发送方的全部分片到齐时按
    // shard_idx 升序重组为完整数据并通过 reassembled 输出。
    // \param session 当前会话（调用方持锁）
    // \param from_bit 发送方 bit position（用于分片键隔离不同发送方）
    // \param frame 到达的 SYNC 帧（携带 shard_idx/total_shards/payload）
    // \param reassembled [out] 重组完成的完整数据（仅当返回 true 时有效）
    // \return true=该发送方的全部分片已到齐并完成重组，false=尚未到齐（继续等待）
    bool buffer_shard_(SyncSession &session,
                       std::uint64_t from_bit,
                       const EpSyncFrame &frame,
                       std::vector<std::uint8_t> &reassembled);

    // 内部辅助：处理各类 sync_op
    void handle_signal_(const EpSyncFrame &frame);
    void handle_barrier_(const EpSyncFrame &frame);
    void handle_ack_(const EpSyncFrame &frame);
    void handle_release_(const EpSyncFrame &frame);
    void handle_all_reduce_(const EpSyncFrame &frame);
    // v2.1 Phase 2: 集合通信帧处理
    void handle_all_gather_(const EpSyncFrame &frame);
    void handle_broadcast_(const EpSyncFrame &frame);
    // v2.1 Phase 2 M2: ReduceScatter / AllToAll 帧处理
    void handle_reduce_scatter_(const EpSyncFrame &frame);
    void handle_all_to_all_(const EpSyncFrame &frame);

    // v2.3 Phase 4 (P4-C): Ring 算法驱动 — 发起方
    // 所有节点主动调用，初始化 RingAlgoState 并执行 step 0 发送。
    // 后续步进由 handle_*_ring_ 在收到 prev 数据后自动推进。
    // \return true=Ring 路径已接管（调用方应跳过简化版逻辑），false=降级到简化版
    bool all_reduce_ring_(std::uint64_t sync_id,
                          std::uint64_t participant_mask,
                          std::uint64_t self_node_id,
                          std::span<const std::uint8_t> local_data,
                          ReduceOp op,
                          ReduceDType dtype,
                          std::chrono::milliseconds timeout);
    bool all_gather_ring_(std::uint64_t sync_id,
                          std::uint64_t participant_mask,
                          std::uint64_t self_node_id,
                          std::span<const std::uint8_t> local_chunk,
                          std::chrono::milliseconds timeout);
    bool reduce_scatter_ring_(std::uint64_t sync_id,
                              std::uint64_t participant_mask,
                              std::uint64_t self_node_id,
                              std::span<const std::uint8_t> local_data,
                              ReduceOp op,
                              ReduceDType dtype,
                              std::chrono::milliseconds timeout);

    // v2.3 Phase 4 (P4-C): Ring 算法驱动 — 接收方帧处理
    // 收到 Ring 帧后，根据 step 和 self_rank 计算 recv_idx，
    // 规约/覆盖到 chunks[recv_idx]，然后推进到下一步并发送。
    void handle_all_reduce_ring_(const EpSyncFrame &frame);
    void handle_all_gather_ring_(const EpSyncFrame &frame);
    void handle_reduce_scatter_ring_(const EpSyncFrame &frame);

    // v2.3 Phase 4 (P4-C): Ring 状态机步进推进
    // 当前步 send + recv 均完成后，推进 current_step，执行下一步发送。
    // 若全部步数完成，组装 result 并标记 session 完成。
    // \param session 当前会话（调用方持锁）
    // \return true=全部步数完成（session 已标记 Completed），false=继续等待
    bool ring_advance_step_(SyncSession &session);

    // v2.3 Phase 4 (P4-D): Tree 算法驱动 — 发起方
    // broadcast_tree_ 由 root 调用，同步循环发送 log₂N 步沿 binomial tree 扩散。
    //   root 发完即完成（不等待 ack），非 root 通过 handle_broadcast_tree_ 被动接收。
    // all_gather_tree_ 由所有节点调用，两阶段（GatherUp + BroadcastDown）。
    //   GatherUp：叶子向 parent 发送，internal 收齐 children 后向 parent 发送，root 收齐全部。
    //   BroadcastDown：root 向 children 分发完整结果，各节点向自己 children 转发。
    // \return true=Tree 路径已接管（调用方应跳过简化版逻辑），false=降级到简化版
    bool broadcast_tree_(std::uint64_t sync_id,
                         std::uint64_t participant_mask,
                         std::uint64_t root_node_id,
                         std::uint64_t self_node_id,
                         std::span<const std::uint8_t> data,
                         std::chrono::milliseconds timeout);
    bool all_gather_tree_(std::uint64_t sync_id,
                          std::uint64_t participant_mask,
                          std::uint64_t self_node_id,
                          std::span<const std::uint8_t> local_chunk,
                          std::chrono::milliseconds timeout);

    // v2.3 Phase 4 (P4-D): Tree 算法驱动 — 接收方帧处理
    // 收到 Tree 帧后，按 phase（GatherUp/BroadcastDown）处理：
    //   - BroadcastDown：接收父数据，转发给 children，完成触发回调
    //   - GatherUp：累积 children chunk，全到齐后向 parent 发送（root 转 BroadcastDown）
    // 若 session 不存在且本地已配置 tree 拓扑，创建被动 Tree 会话。
    void handle_broadcast_tree_(const EpSyncFrame &frame);
    void handle_all_gather_tree_(const EpSyncFrame &frame);

    // v2.3 Phase 4 (P4-D): Tree 状态机步进推进（锁内调用，不发数据）
    // BroadcastDown：非 root 接收父数据后，向所有 children 转发，标记完成。
    // AllGather GatherUp：children 全到齐后向 parent 发送，root 转 BroadcastDown。
    // AllGather BroadcastDown：接收完整 result 后向 children 转发，标记完成。
    // \param session 当前会话（调用方持锁）
    // \return true=全部完成（session 已标记 Completed），false=继续等待
    bool tree_advance_step_(SyncSession &session);

    // v2.3 Phase 4 (P4-E): RH 算法驱动 — 发起方
    // all_reduce_rh_ 由所有节点调用，两阶段（ReduceScatter + AllGather），2×log₂N 步。
    //   ReduceScatter：每步与 partner = rank XOR (1<<s) 交换半数数据并规约。
    //   AllGather：每步与 partner 交换当前 active 数据（覆盖，不规约）。
    // reduce_scatter_rh_ 仅 ReduceScatter 阶段（log₂N 步），结果为 1 个 chunk。
    // \return true=RH 路径已接管（调用方应跳过简化版逻辑），false=降级到简化版
    bool all_reduce_rh_(std::uint64_t sync_id,
                        std::uint64_t participant_mask,
                        std::uint64_t self_node_id,
                        std::span<const std::uint8_t> local_data,
                        ReduceOp op,
                        ReduceDType dtype,
                        std::chrono::milliseconds timeout);
    bool reduce_scatter_rh_(std::uint64_t sync_id,
                            std::uint64_t participant_mask,
                            std::uint64_t self_node_id,
                            std::span<const std::uint8_t> local_data,
                            ReduceOp op,
                            ReduceDType dtype,
                            std::chrono::milliseconds timeout);

    // v2.3 Phase 4 (P4-E): RH 算法驱动 — 接收方帧处理
    // 收到 RH 帧后，按 phase（ReduceScatter/AllGather）处理：
    //   - ReduceScatter：将 partner 数据规约到 work_buf 的 recv_offset 范围
    //   - AllGather：将 partner 数据覆盖到 work_buf 的 recv_offset 范围
    // 然后推进步进，若需发送下一步则锁外发送。
    // AllReduce 和 ReduceScatter 复用同一 handler（通过 op 字段区分）。
    void handle_all_reduce_rh_(const EpSyncFrame &frame);

    // v2.3 Phase 4 (P4-E): RH 状态机步进推进（锁内调用，不发数据）
    // 当前步 send + recv 均完成后，推进 current_step：
    //   - 若到达 log₂N 且 op=AllReduce：切换到 AllGather 阶段
    //   - 若全部步数完成：组装 result，标记 Completed
    // \param session 当前会话（调用方持锁）
    // \return true=全部完成（session 已标记 Completed），false=继续等待
    bool rh_advance_step_(SyncSession &session);

    // v2.3 Phase 4 (P4-F): PairwiseExchange AllToAll 发起方
    // all_to_all_pe_ 由所有节点主动调用，log₂N 步 PairwiseExchange。
    // local_chunk 视为 N 段拼接，段 j 是发给节点 j 的数据。
    // 完成后本节点（rank r）拥有 [C[0][r], C[1][r], ..., C[N-1][r]] 拼接结果。
    // 守卫失败返回 false（降级简化版），step 0 发送失败擦除 session 返回 false。
    bool all_to_all_pe_(std::uint64_t sync_id,
                        std::uint64_t participant_mask,
                        std::uint64_t self_node_id,
                        std::span<const std::uint8_t> local_chunk,
                        std::chrono::milliseconds timeout);

    // v2.3 Phase 4 (P4-F): PE 接收方处理
    // 校验 from_node_id == partner_bits[current_step]，拆包 frame.payload 到 chunks
    // 调用 pe_advance_step_ 推进，完成时触发 on_all_to_all_complete 回调
    void handle_all_to_all_pe_(const EpSyncFrame &frame);

    // v2.3 Phase 4 (P4-F): PE 状态机步进推进（锁内调用，不发数据）
    // 当前步 send + recv 均完成后，推进 current_step：
    //   - 若全部步数完成：组装 result（self_rank 索引对应的 N 个分片按 source 升序拼接），标记 Completed
    //   - 否则重置 step_send_done/step_recv_done，返回 false
    // \param session 当前会话（调用方持锁）
    // \return true=全部完成（session 已标记 Completed），false=继续等待
    bool pe_advance_step_(SyncSession &session);

    // 内部辅助：通知回调
    void notify_barrier_complete_(std::uint64_t sync_id);
    void notify_timeout_(std::uint64_t sync_id);
    void notify_all_reduce_complete_(std::uint64_t sync_id, std::span<const std::uint8_t> result);
    void notify_release_(std::uint64_t sync_id);
    // v2.1 Phase 2: 集合通信完成通知
    void notify_all_gather_complete_(std::uint64_t sync_id, std::span<const std::uint8_t> result);
    void notify_broadcast_received_(std::uint64_t sync_id, std::uint64_t root_node_id,
                                    std::span<const std::uint8_t> data);
    // v2.1 Phase 2 M2: ReduceScatter / AllToAll 完成通知
    void notify_reduce_scatter_complete_(std::uint64_t sync_id, std::span<const std::uint8_t> result);
    void notify_all_to_all_complete_(std::uint64_t sync_id, std::uint64_t from_mask,
                                     std::span<const std::uint8_t> data);

    // 内部辅助：ring all-reduce 算法
    /// 对两个数据块执行规约操作
    /// \param dtype 数据类型，决定元素宽度（U64=8, U32/F32=4, U16/F16/BF16=2, F64=8）
    static std::vector<std::uint8_t> apply_reduce_(std::span<const std::uint8_t> a,
                                                   std::span<const std::uint8_t> b,
                                                   ReduceOp op,
                                                   ReduceDType dtype);
    /// 统计 participant_mask 中参与的节点数
    static std::uint32_t popcount_(std::uint64_t mask);
    /// 将 participant_mask 转换为有序的节点 ID 列表
    static std::vector<std::uint64_t> mask_to_nodes_(std::uint64_t mask);

    // v1.7.0.7 C11: F16/BF16 与 float 互转辅助（apply_reduce_ 使用）
    static float half_to_float_(std::uint16_t h) noexcept;
    static std::uint16_t float_to_half_(float f) noexcept;
    static float bf16_to_float_(std::uint16_t b) noexcept;
    static std::uint16_t float_to_bf16_(float f) noexcept;
};

// ============================================================================
// 辅助函数（用于日志和测试）
// ============================================================================

/// ReduceOp 转字符串
const char *reduce_op_name(ReduceOp op) noexcept;

/// SyncState 转字符串
const char *sync_state_name(SyncState state) noexcept;

}  // namespace linoh::multimodal::ep
