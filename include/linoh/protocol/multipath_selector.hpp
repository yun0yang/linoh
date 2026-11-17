// multipath_selector.hpp — 多路径 strip/adaptive 选择器（P5-B-3）
//
// 借鉴 Sunshine round-robin 迭代器 + iroh 多路径并发：
//   - Backup 模式：现有行为（单路径 + 备份切换），由 PathSelectionStrategy 处理
//   - Strip 模式：round-robin 在多路径上分发 STREAM 帧，扩展带宽
//   - Adaptive 模式：按 RTT 反比加权分配（RTT 低的路径分配更多包）
//
// 与 PathSelectionStrategy 的关系：
//   - PathSelectionStrategy::select() 返回"主路径"，用于 Backup 模式
//   - MultipathStripSelector/AdaptiveSelector 用于 Strip/Adaptive 模式，
//     每次 STREAM 帧发送时调用 select_next_for_send() 获取下一条路径
//   - 两者并行存在，由 connection.cpp 根据 MultipathMode 选择使用哪个

#pragma once

#include "linoh/net/path.hpp"            // net::FourTuple
#include "linoh/base/endpoint_addr.hpp"  // base::TransportAddr, TransportKind

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace linoh::protocol {

/// 多路径模式
enum class MultipathMode : std::uint8_t {
    Backup      = 0,  // 单路径 + 备份切换（默认，向后兼容）
    Strip       = 1,  // round-robin 在多路径上分发
    Adaptive    = 2,  // 按 RTT 反比加权分配
    Coordinated = 3,  // v2.0: 拥塞控制协同加权（pacing_rate + 健康度）
};

/// Strip 分发策略（W2.2 独立项目方案：FEC 冗余块路径分集）
enum class StripPolicy : std::uint8_t {
    RoundRobin = 0,  // 逐包轮转（默认，向后兼容）
    RoleHash   = 1,  // 按 (flow_key, is_redundancy) 稳定哈希：同一 FEC 组的
                     // 数据块与冗余块固定异轨（灵衢 MultiRail 思想的组件级落地：
                     // 单轨故障只损失一类块，另一类可独立恢复）。
                     // 轨映射：data_idx = h(flow) % n；red_idx = (data_idx+1) % n
};

/// 多路径模式转字符串（日志用）
constexpr const char *multipath_mode_name(MultipathMode m) noexcept {
    switch (m) {
        case MultipathMode::Backup:      return "backup";
        case MultipathMode::Strip:       return "strip";
        case MultipathMode::Adaptive:    return "adaptive";
        case MultipathMode::Coordinated: return "coordinated";
    }
    return "unknown";
}

// ============================================================================
// MultipathStripSelector — round-robin 分发
// ============================================================================

/// Round-robin 多路径选择器
///
/// 每次调用 select_next_for_send() 返回下一条候选路径（循环）。
/// 适合带宽扩展场景：4 条 1Gbps 路径可聚合到接近 4Gbps。
class MultipathStripSelector {
public:
    /// 构造
    /// @param expected_paths 预期候选数量（仅用于 reserve，不影响行为）
    explicit MultipathStripSelector(std::size_t expected_paths = 4);

    /// 更新候选路径列表（路径变更时调用，例如新路径验证成功/旧路径放弃）
    /// 注意：更新会重置 next_idx_ 到 0
    void update_candidates(std::vector<net::FourTuple> paths);

    /// 选择下一个发送路径（round-robin）
    /// @return 候选路径，空候选时返回 nullopt
    std::optional<net::FourTuple> select_next_for_send();

    /// 跳过当前路径（路径故障时调用，切到下一条）
    /// 注意：仅移动 next_idx_，不从候选中移除（需调用 update_candidates 显式移除）
    void skip_current();

    // ========== W2.2: FEC 冗余块路径分集（独立项目方案） ==========

    /// 设置分发策略（默认 RoundRobin，行为不变）
    void set_policy(StripPolicy p);
    StripPolicy policy() const;

    /// 按流+角色选择路径（RoleHash 策略入口）
    /// @param flow_key 流标识（建议 stream_id 或 FEC group 级联 id）
    /// @param is_redundancy 是否冗余/校验块（true 时固定走数据轨的下一轨）
    /// @return 候选路径；RoundRobin 策略下退化为 select_next_for_send()；
    ///         空候选返回 nullopt；单候选时两类块同轨（无分集，不出错）
    std::optional<net::FourTuple> select_for_flow(std::uint64_t flow_key,
                                                  bool is_redundancy);

    /// 从候选中移除指定路径（故障倒换；与 skip_current 的"仅移动游标"不同，
    /// 此处真正移除并重置计数，需 update_candidates 恢复）
    void skip_path(const net::FourTuple &tuple);

    /// 当前候选数量
    std::size_t candidate_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return candidates_.size();
    }

    /// 每条路径被选中的次数（用于测试负载均衡）
    std::vector<std::pair<net::FourTuple, std::uint64_t>> selection_stats() const;

    /// 总选择次数
    std::uint64_t total_selections() const {
        std::lock_guard<std::mutex> lk(mu_);
        return total_selections_;
    }

private:
    // mp-M3 (v1.7.0.8): 加互斥锁保护 candidates_/selection_counts_/next_idx_
    //   update_candidates（路径变更线程）与 select_next_for_send（发送线程）并发调用
    //   会导致 next_idx_ 越界 / selection_counts_ 越界写入
    mutable std::mutex mu_;
    std::vector<net::FourTuple> candidates_;
    std::vector<std::uint64_t>  selection_counts_;
    std::size_t  next_idx_{0};
    std::uint64_t total_selections_{0};
    StripPolicy  policy_{StripPolicy::RoundRobin};  // W2.2
};

// ============================================================================
// MultipathAdaptiveSelector — 按 RTT 反比加权分配
// ============================================================================

/// 自适应多路径选择器
///
/// 按 RTT 反比加权随机选择路径：RTT 低的路径分配更多包。
/// 例如 RTT=10ms 与 RTT=100ms 的两条路径，前者分配约 10 倍的包。
class MultipathAdaptiveSelector {
public:
    struct PathInfo {
        net::FourTuple tuple{};
        std::chrono::microseconds srtt{0};  // 平滑 RTT，0 表示未测量
    };

    /// 构造
    /// @param expected_paths 预期候选数量（仅用于 reserve）
    explicit MultipathAdaptiveSelector(std::size_t expected_paths = 4);

    /// 更新候选路径列表（带 RTT 信息）
    void update_candidates(std::vector<PathInfo> paths);

    /// 选择下一个发送路径（加权随机）
    /// @return 候选路径，空候选时返回 nullopt
    std::optional<net::FourTuple> select_next_for_send();

    /// 跳过指定路径（路径故障时调用，从候选中移除）
    void skip_path(const net::FourTuple &tuple);

    /// 当前候选数量
    std::size_t candidate_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return candidates_.size();
    }

    /// 每条路径被选中的次数
    std::vector<std::pair<net::FourTuple, std::uint64_t>> selection_stats() const;

    /// 总选择次数
    std::uint64_t total_selections() const {
        std::lock_guard<std::mutex> lk(mu_);
        return total_selections_;
    }

    /// 设置随机种子（测试用，默认从 random_device 初始化）
    void set_seed(std::uint64_t seed);

private:
    // mp-M3 (v1.7.0.8): 加互斥锁保护 candidates_/weights_/rng_state_
    //   update_candidates（路径变更线程）、skip_path（路径故障线程）与
    //   select_next_for_send（发送线程）并发调用导致 weights_ 越界 / rng_state_ 竞争
    //   加权随机选择依赖 weights_ 归一化正确性，并发 recompute 期间读取会导致权重错乱
    mutable std::mutex mu_;
    std::vector<PathInfo>   candidates_;
    std::vector<std::uint64_t> selection_counts_;
    std::vector<double>     weights_;          // 归一化权重
    std::uint64_t           total_selections_{0};
    std::uint64_t           rng_state_{0};

    /// 重新计算归一化权重（RTT 反比，未测量按平均处理）
    void recompute_weights();

    /// 简单线性同余 RNG（保证可重现）
    std::uint64_t next_random();
};

}  // namespace linoh::protocol
