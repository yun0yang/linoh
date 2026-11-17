// collective.hpp — 集合通信统一接口（v2.1 Phase 2）
//
// 在 SyncPrimitives（barrier/signal/all_reduce）基础上，统一封装 AllGather / Broadcast
// 等集合通信原语，为 DP/EP 推理拓扑提供标准化的跨节点数据交换 API。
//
// 设计目标：
//   - 统一入口：业务层通过 CollectiveSession 调用所有集合通信操作，无需直接操作 SyncPrimitives
//   - 算法可插拔：CollectiveAlgo 枚举标识算法，当前 P2 实现简化 ring/tree，后续可扩展
//   - 向后兼容：CollectiveSession 内部委托 SyncPrimitives，不改变现有 EP_SYNC 协议帧格式
//
// 支持的操作（CollectiveOp）：
//   - Barrier    : 屏障同步（委托 SyncPrimitives::barrier）
//   - AllReduce  : 跨节点规约（委托 SyncPrimitives::all_reduce）
//   - AllGather  : 跨节点全收集（委托 SyncPrimitives::all_gather，v2.1 Phase 2 新增）
//   - Broadcast  : root 广播（委托 SyncPrimitives::broadcast，v2.1 Phase 2 新增）
//   - ReduceScatter : 规约分散（委托 SyncPrimitives::reduce_scatter，v2.1 Phase 2 M2 新增）
//   - AllToAll   : 全交换（委托 SyncPrimitives::all_to_all，v2.1 Phase 2 M2 新增）
//
// 支持的算法（CollectiveAlgo）：
//   - Ring            : 环形（AllReduce/AllGather 默认，N-1 步收敛）
//   - Tree            : 树形（Broadcast 默认，log(N) 步收敛）
//   - RecursiveHalving: 递归减半（ReduceScatter 规划使用）
//   - PairwiseExchange: 配对交换（AllToAll 规划使用）
//
// 与 SyncPrimitives 关系：
//   - CollectiveSession 持有 SyncPrimitives 引用，所有操作委托 SyncPrimitives 实现
//   - SyncPrimitives 负责底层帧收发和会话状态管理
//   - CollectiveSession 负责算法选择、参数校验和结果封装
//
// 线程模型：
//   - 同步阻塞：barrier/all_reduce/all_gather 阻塞调用方线程直到完成或超时
//   - 异步回调：broadcast 非阻塞，接收方通过 on_broadcast_received 回调获取数据
//   - 线程安全：所有方法可并发调用（内部委托 SyncPrimitives 的 mutex 保护）

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "linoh/multimodal/sync_primitives.hpp"

namespace linoh::multimodal::ep {

/// 集合通信操作类型
enum class CollectiveOp : std::uint8_t {
    Barrier       = 0,  // 屏障同步
    AllReduce     = 1,  // 全规约
    AllGather     = 2,  // 全收集
    Broadcast     = 3,  // 广播
    ReduceScatter = 4,  // 规约分散（P3 规划）
    AllToAll      = 5,  // 全交换（P3 规划）
};

/// 集合通信算法
enum class CollectiveAlgo : std::uint8_t {
    Ring             = 0,  // 环形算法（AllReduce/AllGather 默认）
    Tree             = 1,  // 树形算法（Broadcast 默认）
    RecursiveHalving = 2,  // 递归减半（ReduceScatter 规划）
    PairwiseExchange = 3,  // 配对交换（AllToAll 规划）
};

/// 集合通信配置
struct CollectiveConfig {
    /// 默认超时（30s，与 SyncPrimitives 默认一致）
    std::chrono::milliseconds default_timeout{std::chrono::seconds(30)};
    /// 默认规约操作（AllReduce 使用）
    ReduceOp default_reduce_op{ReduceOp::SUM};
    /// 默认数据类型（AllReduce 使用）
    ReduceDType default_reduce_dtype{ReduceDType::U64};
    /// 默认算法（按操作类型有不同默认值，0=自动选择）
    CollectiveAlgo default_algo{CollectiveAlgo::Ring};
};

/// 集合通信会话
///
/// 统一封装 SyncPrimitives 提供的集合通信操作，为 DP/EP 推理拓扑提供标准化 API。
/// 业务层通过此类调用所有集合通信操作，无需直接操作 SyncPrimitives。
///
/// 用法：
///   EpChannel channel(data_conn);
///   channel.start_recv_loop();
///   SyncPrimitives sync(&channel);
///   channel.set_callbacks({.on_sync_received = [&](const EpSyncFrame& f){
///       sync.handle_sync_frame(f);
///   }});
///   CollectiveSession collective(sync);
///
///   // AllGather（4 节点）
///   auto result = collective.all_gather(1001, 0b1111, 0, local_chunk);
///   if (result) {
///       // result 为 4 个 chunk 拼接结果
///   }
///
///   // Broadcast（root=0 广播到 4 节点）
///   collective.broadcast(2001, 0b1111, 0, data);
class CollectiveSession {
public:
    /// 构造 CollectiveSession
    /// \param sync SyncPrimitives 引用（调用方需保证生命周期长于 CollectiveSession）
    explicit CollectiveSession(SyncPrimitives &sync);

    /// 构造 CollectiveSession（带自定义配置）
    CollectiveSession(SyncPrimitives &sync, CollectiveConfig config);

    // 不可拷贝、不可移动（内部持有引用）
    CollectiveSession(const CollectiveSession &) = delete;
    CollectiveSession &operator=(const CollectiveSession &) = delete;
    CollectiveSession(CollectiveSession &&) = delete;
    CollectiveSession &operator=(CollectiveSession &&) = delete;

    // ====================================================================
    // 集合通信操作 API
    // ====================================================================

    /// barrier：阻塞直到所有 participant 到齐
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图
    /// \param self_node_id 本节点 bit position
    /// \param timeout 超时（0 表示使用默认配置）
    /// \return true=成功完成，false=超时或失败
    bool barrier(std::uint64_t sync_id,
                 std::uint64_t participant_mask,
                 std::uint64_t self_node_id,
                 std::chrono::milliseconds timeout = std::chrono::milliseconds(0));

    /// all_reduce：跨节点张量规约
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图
    /// \param self_node_id 本节点 bit position
    /// \param local_data 本地数据（<=4KB）
    /// \param op 规约操作（默认使用配置中的 default_reduce_op）
    /// \param dtype 数据类型（默认使用配置中的 default_reduce_dtype）
    /// \param timeout 超时（0 表示使用默认配置）
    /// \param algo v2.2 Phase 3 (P3-F): 集合通信算法（默认 0=Ring，向后兼容）
    /// \return 规约结果（成功），nullopt（失败/超时）
    std::optional<std::vector<std::uint8_t>> all_reduce(
        std::uint64_t sync_id,
        std::uint64_t participant_mask,
        std::uint64_t self_node_id,
        std::span<const std::uint8_t> local_data,
        ReduceOp op = ReduceOp::SUM,
        ReduceDType dtype = ReduceDType::U64,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(0),
        CollectiveAlgo algo = CollectiveAlgo::Ring);

    /// all_gather：跨节点全收集
    ///
    /// 每个 participant 的 chunk 按 bit 升序拼接为完整结果。
    /// P2 阶段限制：单 chunk <= 4KB。
    ///
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图
    /// \param self_node_id 本节点 bit position
    /// \param local_chunk 本节点 chunk 数据（<=4KB）
    /// \param timeout 超时（0 表示使用默认配置）
    /// \param algo v2.2 Phase 3 (P3-F): 集合通信算法（默认 0=Ring，向后兼容）
    /// \return 拼接结果（成功，按 participant bit 升序），nullopt（失败/超时）
    std::optional<std::vector<std::uint8_t>> all_gather(
        std::uint64_t sync_id,
        std::uint64_t participant_mask,
        std::uint64_t self_node_id,
        std::span<const std::uint8_t> local_chunk,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(0),
        CollectiveAlgo algo = CollectiveAlgo::Ring);

    /// broadcast：root 节点数据广播
    ///
    /// root 节点发送数据，非 root 节点通过 on_broadcast_received 回调接收。
    /// root 节点调用后直接返回 true（不阻塞等待 ack）。
    ///
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图
    /// \param root_node_id root 节点 bit position
    /// \param data 广播数据（仅 root 节点提供，<=4KB）
    /// \param timeout 超时（0 表示使用默认配置，仅用于发送方）
    /// \param algo v2.2 Phase 3 (P3-F): 集合通信算法（默认 Tree，向后兼容）
    /// \return true=发送成功，false=失败
    bool broadcast(
        std::uint64_t sync_id,
        std::uint64_t participant_mask,
        std::uint64_t root_node_id,
        std::span<const std::uint8_t> data,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(0),
        CollectiveAlgo algo = CollectiveAlgo::Tree);

    // ====================================================================
    // v2.1 Phase 2 M2: ReduceScatter / AllToAll
    // ====================================================================

    /// reduce_scatter：跨节点规约后按 chunk 分散结果
    ///
    /// 每个 participant 将本地数据发送给所有其他 participant，接收方执行规约（SUM/MAX/MIN）
    /// 后将结果等分为 N 份（N=participant 数），每个 participant 获取自己对应的一份。
    ///
    /// P2 阶段限制：单 participant 数据 <= 4KB，数据长度必须能被 participant 数整除。
    ///
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图
    /// \param self_node_id 本节点 bit position
    /// \param local_data 本节点数据（<=4KB，长度必须能被 participant 数整除）
    /// \param op 规约操作（默认使用 config_.default_reduce_op）
    /// \param dtype 数据类型
    /// \param timeout 超时（0 表示使用默认配置）
    /// \param algo v2.2 Phase 3 (P3-F): 集合通信算法（默认 RecursiveHalving，向后兼容）
    /// \return 本节点的结果分片（成功），nullopt（失败/超时）
    std::optional<std::vector<std::uint8_t>> reduce_scatter(
        std::uint64_t sync_id,
        std::uint64_t participant_mask,
        std::uint64_t self_node_id,
        std::span<const std::uint8_t> local_data,
        ReduceOp op = ReduceOp::SUM,
        ReduceDType dtype = ReduceDType::U64,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(0),
        CollectiveAlgo algo = CollectiveAlgo::RecursiveHalving);

    /// all_to_all：全交换（每个节点向其他节点发送不同数据）
    ///
    /// 每个 participant 将本地 chunk 发送给所有其他 participant，接收方按发送方 bit
    /// position 收集数据，全部到齐后按 bit 升序拼接结果并触发完成回调。
    ///
    /// P2 阶段简化：每个节点发送自己的完整 chunk 给所有人（语义上与 AllGather 类似，
    /// 但 AllToAll 强调每个节点发送的是各自不同的数据）。P3 阶段将实现真正的
    /// pairwise exchange（每个节点向不同目标发送不同分片）。
    ///
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图
    /// \param self_node_id 本节点 bit position
    /// \param local_chunk 本节点 chunk 数据（<=4KB）
    /// \param timeout 超时（0 表示使用默认配置）
    /// \param algo v2.2 Phase 3 (P3-F): 集合通信算法（默认 PairwiseExchange，向后兼容）
    /// \return 拼接结果（按发送方 bit 升序），nullopt（失败/超时）
    std::optional<std::vector<std::uint8_t>> all_to_all(
        std::uint64_t sync_id,
        std::uint64_t participant_mask,
        std::uint64_t self_node_id,
        std::span<const std::uint8_t> local_chunk,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(0),
        CollectiveAlgo algo = CollectiveAlgo::PairwiseExchange);

    // ====================================================================
    // 配置访问
    // ====================================================================

    /// 获取当前配置
    const CollectiveConfig &config() const noexcept { return config_; }

    /// 更新配置（线程安全，仅影响后续操作）
    void set_config(CollectiveConfig config) noexcept { config_ = config; }

    /// 获取底层 SyncPrimitives 引用（用于直接注册回调等高级操作）
    SyncPrimitives &sync_primitives() noexcept { return sync_; }

    // ====================================================================
    // v2.2 Phase 3 (P3-F): 拓扑感知执行入口
    // ====================================================================

    /// execute_plan：根据 TopologyPlan 驱动集合通信
    ///
    /// 接收 CommPlannerV2 生成的 TopologyPlan，按 plan.op 分派到对应的集合通信方法，
    /// 同时透传 plan.algo 到 SyncPrimitives，使算法标识贯穿整个调用链：
    ///   CommPlannerV2::plan → CollectiveSession::execute_plan → SyncPrimitives::xxx
    ///   → EpChannel::send_sync → EpSyncFrame.algo 字段
    ///
    /// 当前 P3-F 阶段：algo 字段仅记录到会话和帧中用于诊断和未来 P4 真实算法分派，
    /// 实际传输仍使用 P2 的 broadcast-and-collect 简化实现（功能正确，带宽非最优）。
    /// P4 阶段将根据 algo 字段真正分派到 Ring/Tree/RH/PE 步进式通信。
    ///
    /// \param plan 拓扑规划（由 CommPlannerV2::plan 生成）
    /// \param sync_id 会话 ID
    /// \param participant_mask 参与节点位图（应与 plan.participants 对应）
    /// \param self_node_id 本节点 bit position
    /// \param local_data 本地数据（AllReduce/ReduceScatter 用，<=4KB）
    /// \param local_chunk 本地 chunk（AllGather/AllToAll 用，<=4KB）
    /// \param root_node_id root 节点 bit position（Broadcast 用）
    /// \param op 规约操作（AllReduce/ReduceScatter 用）
    /// \param dtype 数据类型（AllReduce/ReduceScatter 用）
    /// \param timeout 超时（0 表示使用默认配置）
    /// \return 操作结果（Broadcast 返回 nullopt 表示非数据返回；其他操作返回数据或 nullopt）
    ///
    /// \note 由于 TopologyPlan 定义在 comm_planner_v2.hpp，此处使用前向声明避免循环依赖。
    ///       调用方需确保 plan.participants 与 participant_mask 一致。
    std::optional<std::vector<std::uint8_t>> execute_plan(
        const struct TopologyPlan &plan,
        std::uint64_t sync_id,
        std::uint64_t participant_mask,
        std::uint64_t self_node_id,
        std::span<const std::uint8_t> local_data = {},
        std::span<const std::uint8_t> local_chunk = {},
        std::uint64_t root_node_id = 0,
        ReduceOp op = ReduceOp::SUM,
        ReduceDType dtype = ReduceDType::U64,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(0));

private:
    SyncPrimitives &sync_;
    CollectiveConfig config_;

    /// 解析超时：timeout=0 时使用 config_.default_timeout
    std::chrono::milliseconds resolve_timeout_(std::chrono::milliseconds timeout) const noexcept;
};

// ============================================================================
// 辅助函数（用于日志和测试）
// ============================================================================

/// CollectiveOp 转字符串
const char *collective_op_name(CollectiveOp op) noexcept;

/// CollectiveAlgo 转字符串
const char *collective_algo_name(CollectiveAlgo algo) noexcept;

}  // namespace linoh::multimodal::ep
