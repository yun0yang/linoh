// tree_engine.hpp — Tree 算法引擎（v2.2 Phase 3 / P3-C）
//
// 纯算法状态机，计算 Binomial Tree Broadcast / AllGather 的拓扑与发送/接收索引。
// 不依赖网络 IO，可独立单元测试。SyncPrimitives 调度层（P3-F）根据 EpSyncFrame.algo
// 字段分派到本引擎驱动实际通信。
//
// 算法原理（Binomial Tree Broadcast）：
//
// root 发给一个子节点，然后 root 和子节点各发给下一个子节点，⌈log₂N⌉ 步覆盖全部节点。
// 每步参与发送的节点数翻倍，呈指数增长。
//
//   N=8, root=0:
//     Step 0: 0 → 1                         (2 节点有数据)
//     Step 1: 0 → 2, 1 → 3                  (4 节点有数据)
//     Step 2: 0 → 4, 1 → 5, 2 → 6, 3 → 7    (8 节点有数据)
//
// 关键性质：
//   - 总步数 = ⌈log₂N⌉
//   - root 每步都参与发送（发送 log₂N 次）
//   - 每个非 root 节点恰好接收一次
//   - 节点 v 的接收步 = v 的最高有效位（MSB）位置
//   - 节点 v 的父节点 = v 清除 MSB（即 v - 2^MSB(v)）
//   - 节点 v 的子节点 = { v + 2^s | s ∈ [first_send_step(v), total_steps-1], v+2^s < N }
//
// 虚拟 rank 映射（支持任意 root）：
//   virtual_rank = real_rank XOR root_rank
//   所有计算基于 virtual_rank，root 映射到 0，树结构保持不变。
//
// 通信量：
//   - root 发送 ⌈log₂N⌉ 次，每次 msg_size 字节
//   - 每个非 root 节点接收 1 次
//   - 总通信量 = ⌈log₂N⌉ × msg_size（远小于扁平广播的 N × msg_size）
//
// 设计原则：
//   - 纯静态方法，无状态，线程安全
//   - 不依赖 EpChannel / SyncPrimitives / 真实网络
//   - 与 RingEngine 风格一致，便于 P3-F 调度层统一集成

#pragma once

#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

namespace linoh::multimodal::ep {

/// Tree 算法节点角色
enum class TreeNodeRole : std::uint8_t {
    Root     = 0,  // 根节点（数据源，仅发送）
    Internal = 1,  // 内部节点（接收后继续转发）
    Leaf     = 2,  // 叶子节点（仅接收，不转发）
};

/// Tree 算法引擎（无状态，纯算法逻辑）
///
/// 用法（与 SyncPrimitives 集成，P3-F）：
///   auto tree = TreeEngine::build_binomial_tree(participants, root_rank);
///   auto recv_step = TreeEngine::recv_step_of(self_virtual_rank);
///   // 等待 recv_step 接收父节点数据
///   // 从 first_send_step 开始每步向子节点发送
class TreeEngine {
public:
    // ========== 拓扑构建 ==========

    /// 构建二项树拓扑
    /// \param participants 有序节点 bit position 列表
    /// \param root_rank root 在 participants 中的索引（默认 0）
    /// \return 每个节点的子节点 bit 列表（key=自身 bit, value=子节点 bits 有序列表）
    static std::unordered_map<std::uint64_t, std::vector<std::uint64_t>>
    build_binomial_tree(const std::vector<std::uint64_t>& participants,
                        std::size_t root_rank = 0);

    // ========== 步数与阶段 ==========

    /// 总步数 = ⌈log₂N⌉
    static std::size_t total_steps(std::size_t N) noexcept;

    // ========== 虚拟 rank 映射（支持任意 root）==========

    /// real rank → virtual rank（virtual = real XOR root）
    static std::size_t to_virtual(std::size_t real_rank, std::size_t root_rank) noexcept {
        return real_rank ^ root_rank;
    }

    /// virtual rank → real rank
    static std::size_t to_real(std::size_t virtual_rank, std::size_t root_rank) noexcept {
        return virtual_rank ^ root_rank;
    }

    // ========== 节点角色与关系 ==========

    /// 节点角色判定
    /// \param virtual_rank 节点的虚拟 rank（real XOR root）
    /// \param N 节点数
    static TreeNodeRole node_role(std::size_t virtual_rank, std::size_t N) noexcept;

    /// 节点的父节点 virtual rank（root 返回 nullopt）
    /// \param virtual_rank 节点的虚拟 rank
    static std::optional<std::size_t>
    parent_of(std::size_t virtual_rank) noexcept;

    /// 节点的子节点 virtual rank 列表
    /// \param virtual_rank 节点的虚拟 rank
    /// \param N 节点数
    static std::vector<std::size_t>
    children_of(std::size_t virtual_rank, std::size_t N) noexcept;

    // ========== 步级调度 ==========

    /// 节点在哪一步接收数据（root 返回 nullopt）
    /// \param virtual_rank 节点的虚拟 rank
    /// \return 接收步数（= MSB 位置），nullopt 表示 root 不接收
    static std::optional<std::size_t>
    recv_step_of(std::size_t virtual_rank) noexcept;

    /// 节点第一个发送步（root=0；非 root = recv_step + 1；纯叶子无子节点返回 nullopt）
    static std::optional<std::size_t>
    first_send_step(std::size_t virtual_rank, std::size_t N) noexcept;

    /// 节点在某步的发送目标（broadcast/AllGather 场景）
    /// \param virtual_rank 本节点虚拟 rank
    /// \param step 当前步数
    /// \param N 节点数
    /// \return 目标 virtual rank（nullopt 表示本步不发送）
    static std::optional<std::size_t>
    send_target_at_step(std::size_t virtual_rank, std::size_t step, std::size_t N) noexcept;

    /// 节点在某步的接收来源
    /// \return nullopt 表示本步不接收，否则返回发送方 virtual rank
    static std::optional<std::size_t>
    recv_source_at_step(std::size_t virtual_rank, std::size_t step, std::size_t N) noexcept;

    // ========== 通信量预估 ==========

    /// Broadcast 每节点平均通信量 = ⌈log₂N⌉ × msg / N（root 发送 log₂N 次，叶子接收 1 次）
    static std::size_t broadcast_bytes_per_node(std::size_t N, std::size_t msg_size) noexcept;

    /// root 发送次数 = ⌈log₂N⌉
    static std::size_t root_send_count(std::size_t N) noexcept;

    /// 总发送次数（全网）= N - 1（每个非 root 节点被发送一次）
    static std::size_t total_send_count(std::size_t N) noexcept;
};

}  // namespace linoh::multimodal::ep
