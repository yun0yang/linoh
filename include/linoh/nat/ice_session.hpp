// ice_session.hpp — P5-D-2 ICE 风格连接检查 + 提名
//
// 借鉴 WebRTC ICE (RFC 8445) §7 Connectivity Checks + §8 Nomination
//
// 设计原则：
//   - 候选对（local + remote）按双向优先级排序
//   - 连接检查并行（TaskPool 加速），STUN binding request/response 模式
//   - Controlling 角色提名最高优先级成功对
//   - Controlled 角色接受提名
//   - 触发检查（triggered check）支持动态新增候选
//
// 注意：
//   - 本模块定义 ICE 会话接口和状态机，实际 STUN binding 由注入的 checker 完成
//   - 单元测试用 mock checker 验证状态机和提名逻辑
//   - 实际部署时由 Endpoint 注入真实 STUN client

#pragma once

#include "linoh/nat/ice_candidate.hpp"
#include "linoh/util/task_pool.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace linoh::nat {

// ============================================================================
// ICE 角色定义（RFC 8445 §3.3.1）
// ============================================================================

/// ICE 角色
enum class IceRole : std::uint8_t {
    Controlling,  // 主导方，负责提名
    Controlled,   // 被控方，接受提名
};

/// 角色转字符串
constexpr const char *ice_role_name(IceRole r) {
    return r == IceRole::Controlling ? "controlling" : "controlled";
}

// ============================================================================
// 候选对状态（RFC 8445 §6.1.2.1）
// ============================================================================

/// 候选对状态
enum class CandidatePairState : std::uint8_t {
    Waiting,      // 等待检查（已加入检查列表，未发送请求）
    InProgress,   // 检查中（STUN binding 请求已发送，未收到响应）
    Succeeded,    // 检查成功
    Failed,       // 检查失败
    Frozen,       // 冻结（等待解冻）
};

/// 候选对状态转字符串
constexpr const char *pair_state_name(CandidatePairState s) {
    switch (s) {
        case CandidatePairState::Waiting:    return "waiting";
        case CandidatePairState::InProgress: return "in-progress";
        case CandidatePairState::Succeeded:  return "succeeded";
        case CandidatePairState::Failed:     return "failed";
        case CandidatePairState::Frozen:     return "frozen";
    }
    return "unknown";
}

// ============================================================================
// 候选对（RFC 8445 §6.1.2）
// ============================================================================

/// 候选对（本地 + 远端）
struct CandidatePair {
    Candidate local;
    Candidate remote;
    std::uint64_t priority{0};       ///< 双向优先级（RFC 8445 §6.1.2.3）
    CandidatePairState state{CandidatePairState::Waiting};
    bool nominated{false};           ///< 是否被提名
    std::chrono::milliseconds rtt{0};
    std::uint32_t request_count{0};  ///< 已发送请求次数
    std::chrono::steady_clock::time_point last_check_time;

    /// 默认构造
    CandidatePair() = default;

    /// 完整构造
    CandidatePair(Candidate l, Candidate r)
        : local(std::move(l)), remote(std::move(r)) {}

    /// 比较（按 priority 降序，priority 高的排前面）
    bool operator<(const CandidatePair &other) const {
        return priority > other.priority;
    }

    /// 相等比较（按 local + remote tuple）
    bool operator==(const CandidatePair &other) const {
        return local == other.local && remote == other.remote;
    }

    /// 转字符串
    std::string to_string() const;
};

/// 计算候选对优先级（RFC 8445 §6.1.2.3 公式）
///
/// Controlling: pair_priority = (2^32) * min(G, D) + 2 * max(G, D) + (G > D ? 1 : 0)
/// Controlled:  pair_priority = (2^32) * min(G, D) + 2 * max(G, D) + (G > D ? 0 : 1)
///
/// 其中 G = local priority, D = remote priority
///
/// @param local_prio 本地候选优先级
/// @param remote_prio 远端候选优先级
/// @param role ICE 角色
/// @return 64 位候选对优先级
constexpr std::uint64_t compute_pair_priority(
    std::uint32_t local_prio,
    std::uint32_t remote_prio,
    IceRole role) {
    std::uint64_t g = local_prio;
    std::uint64_t d = remote_prio;
    std::uint64_t min = (g < d) ? g : d;
    std::uint64_t max = (g < d) ? d : g;
    std::uint64_t tie_breaker = (g > d) ? 1 : 0;
    if (role == IceRole::Controlled) {
        tie_breaker = (g > d) ? 0 : 1;
    }
    return (static_cast<std::uint64_t>(1) << 32) * min + 2 * max + tie_breaker;
}

// ============================================================================
// 连接检查回调（注入式，便于测试）
// ============================================================================

/// 连接检查回调：发送 STUN binding request 并等待 response
///
/// @param pair 待检查的候选对
/// @param timeout 超时时间
/// @return 检查是否成功 + RTT
using ConnectivityChecker = std::function<
    std::future<std::pair<bool, std::chrono::milliseconds>>(
        const CandidatePair &pair,
        std::chrono::milliseconds timeout)>;

/// 默认连接检查器（占位实现，总是返回失败）
ConnectivityChecker default_connectivity_checker();

// ============================================================================
// ICE 会话（RFC 8445 §7 + §8）
// ============================================================================

/// ICE 会话配置
struct IceSessionConfig {
    /// 角色
    IceRole role{IceRole::Controlling};

    /// 连接检查总超时
    std::chrono::milliseconds timeout{std::chrono::seconds(5)};

    /// 单次 STUN 请求超时
    std::chrono::milliseconds request_timeout{std::chrono::milliseconds(500)};

    /// 最大重试次数
    std::uint32_t max_retries{3};

    /// 并行检查的候选对数量上限
    std::size_t max_parallel_checks{10};

    /// 是否启用提名（仅 Controlling 角色生效）
    bool enable_nomination{true};

    /// 提名策略：true=最高优先级，false=最低延迟
    bool nominate_by_priority{true};

    /// P0-G5-1: 全 relay 路径跳过初始 STUN 检查
    /// 当候选对两端均为 Relay 候选时，直接标记为 Succeeded（relay 已保证可达）
    bool presume_writable_when_fully_relayed{false};

    /// P0-G5-2: 过滤 relay↔direct 候选对
    /// 跳过"一端 relay 一端 direct"的候选对检查（避免 relay→direct 的 NAT 穿透失败浪费）
    bool skip_relay_to_non_relay_connections{false};

    /// P0-G5-3: 持续收集候选
    /// gather 阶段不一次性结束，而是周期性重新收集（适配网络变化）。
    /// 实际"持续"行为由 Endpoint 层读取此开关并周期调用 regather_candidates。
    bool gather_continually{false};

    /// P0-G5-4: 按历史成功率加权排序候选对
    /// 启用后候选对排序注入历史命中率权重（需配合 sort_pairs_by_priority_with_history）
    bool prioritize_most_likely_candidate_pairs{false};
};

/// ICE 会话
class IceSession {
public:
    /// 构造（使用默认 checker）
    IceSession(std::vector<Candidate> local_candidates,
                std::vector<Candidate> remote_candidates,
                IceSessionConfig config = {});

    /// 构造（注入 checker，便于测试）
    IceSession(std::vector<Candidate> local_candidates,
                std::vector<Candidate> remote_candidates,
                IceSessionConfig config,
                ConnectivityChecker checker);

    // nn-M4 (v1.7.0.8): 析构时对 pending_futures_ 做有界 wait_for 回收，
    // 避免后台 checker 任务访问已释放的 IceSession 资源；同时防止
    // 默认析构对 std::async future 的无条件阻塞等待导致析构卡死。
    ~IceSession();

    /// 形成候选对（按优先级排序）
    ///
    /// 规则（RFC 8445 §6.1.2）：
    ///   - 每个 local 与每个 remote 配对
    ///   - 排除不同地址族的配对（IPv4 vs IPv6）
    ///   - 按 compute_pair_priority 计算优先级
    ///   - 按优先级降序排序
    void form_candidate_pairs();

    /// 获取当前候选对列表（已排序）
    std::vector<CandidatePair> candidate_pairs() const;

    /// 启动连接检查（并行尝试所有候选对）
    ///
    /// 流程：
    ///   1. 按优先级顺序取出候选对
    ///   2. 并行调用 checker 检查（限制 max_parallel_checks）
    ///   3. 成功的对标记为 Succeeded
    ///   4. 失败的对标记为 Failed
    ///   5. Controlling 角色在至少一个成功后提名最高优先级对
    ///
    /// @return 是否有至少一个候选对检查成功
    std::future<bool> start_connectivity_checks();

    /// 同步版连接检查
    bool start_connectivity_checks_sync();

    /// 提名最高优先级成功的候选对（Controlling 角色）
    ///
    /// @return 被提名的候选对（nullopt 表示无成功对或非 Controlling 角色）
    std::optional<CandidatePair> nominate_best();

    /// 提名指定候选对（手动提名）
    bool nominate_pair(const CandidatePair &pair);

    /// 触发检查（收到新候选或对端请求时立即检查指定对）
    ///
    /// RFC 8445 §7.2.1.4: 收到对端 STUN 请求时，若请求来自未知候选对，
    /// 创建新候选对并立即触发检查
    void trigger_check(const CandidatePair &pair);

    /// 获取提名的候选对（如有）
    std::optional<CandidatePair> nominated_pair() const;

    /// 获取所有成功的候选对
    std::vector<CandidatePair> succeeded_pairs() const;

    /// 获取所有失败的候选对
    std::vector<CandidatePair> failed_pairs() const;

    /// 获取会话配置
    const IceSessionConfig &config() const { return config_; }

    /// 获取角色
    IceRole role() const { return config_.role; }

    /// 是否已完成检查
    bool is_completed() const { return completed_.load(); }

    /// 重置会话（清空所有状态）
    void reset();

    /// 添加新的本地候选（动态发现，如 PeerReflexive）
    void add_local_candidate(Candidate c);

    /// 添加新的远端候选（动态发现，如 PeerReflexive）
    void add_remote_candidate(Candidate c);

    /// P0-G5-3: 重新收集候选（配合 gather_continually，由上层周期调用）
    ///
    /// 合并新候选到现有列表（去重），重建候选对（应用 G5-2 过滤 + G5-4 加权排序）。
    /// IceSession 本身不持有定时器，"持续"行为由 Endpoint 层读取
    /// config.gather_continually 并周期调用本方法实现。
    ///
    /// @param new_local 新发现的本地候选
    /// @param new_remote 新发现的远端候选
    void regather_candidates(std::vector<Candidate> new_local,
                             std::vector<Candidate> new_remote);

private:
    std::vector<Candidate> local_candidates_;
    std::vector<Candidate> remote_candidates_;
    IceSessionConfig config_;
    ConnectivityChecker checker_;
    std::unique_ptr<util::TaskPool> task_pool_;

    mutable std::mutex pairs_mutex_;
    std::vector<CandidatePair> pairs_;
    std::optional<CandidatePair> nominated_pair_;
    std::atomic<bool> completed_{false};

    // nn-M4 (v1.7.0.8): 超时未完成的 checker future 不再 detach（避免线程累积
    // 泄漏 + 析构后访问已释放资源）。改为存入 pending_futures_，由 prune
    // 定期清理已完成的 future，析构时统一 wait_for 回收。
    // 注意：该容器受 pairs_mutex_ 保护，与 pairs_ 同锁，避免多锁死锁。
    std::vector<std::future<std::pair<bool, std::chrono::milliseconds>>> pending_futures_;

    /// 判断两个候选是否地址族兼容
    static bool is_address_family_compatible(const Candidate &a, const Candidate &b);

    /// 判断地址是否 IPv6
    static bool is_ipv6(const std::string &host);

    /// 检查单个候选对
    std::future<std::pair<bool, std::chrono::milliseconds>> check_pair(
        CandidatePair &pair);

    // nn-M5 (v1.7.0.8): form_candidate_pairs 的锁内实现，调用方必须已持有 pairs_mutex_。
    // 拆分此 helper 是为了让 add_local_candidate / add_remote_candidate 能在
    // 同一锁内完成"修改 candidates_ + 重建 pairs_"，避免 candidates_ 与 pairs_
    // 状态不一致的竞争窗口。
    void form_candidate_pairs_locked();

    // nn-M4 (v1.7.0.8): 清理 pending_futures_ 中已完成的 future，释放资源。
    /// 调用方必须已持有 pairs_mutex_。
    void prune_pending_futures_locked();
};

// ============================================================================
// 工具函数
// ============================================================================

/// 按优先级排序候选对（降序）
void sort_pairs_by_priority(std::vector<CandidatePair> &pairs);

/// 按延迟排序候选对（升序，延迟低的在前）
void sort_pairs_by_rtt(std::vector<CandidatePair> &pairs);

/// P0-G5-4: 按历史成功率加权排序候选对
///
/// 综合评分 = priority * (1 - history_weight) + history_score * history_weight * priority
/// history_score 范围 [0.0, 1.0]，无历史记录时调用方应返回 0.5（中性）。
///
/// @param pairs 候选对列表（就地排序，降序）
/// @param history_score 候选对 → 历史命中率回调
/// @param history_weight 历史权重 [0.0, 1.0]（默认 0.3，即 70% 优先级 + 30% 历史）
void sort_pairs_by_priority_with_history(
    std::vector<CandidatePair> &pairs,
    const std::function<double(const CandidatePair &)> &history_score,
    double history_weight = 0.3);

/// 统计各状态的候选对数量
struct PairStateCount {
    std::size_t waiting{0};
    std::size_t in_progress{0};
    std::size_t succeeded{0};
    std::size_t failed{0};
    std::size_t frozen{0};
};
PairStateCount count_pairs_by_state(const std::vector<CandidatePair> &pairs);

} // namespace linoh::nat
