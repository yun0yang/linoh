// linoh/net/bidirectional_holepuncher.hpp
//
// v5.0.0 (T-LP4-004): Hard-NAT 双向端口预测 + 多轮打洞协调器
//
// 借鉴 iroh 1.0.0-rc.1 noq#672：
//   - 双向端口预测：双方互相预测对方端口，并发送 PATH_CHALLENGE
//   - 多轮打洞：新地址到来即中止前轮，开启新轮（Simplified Round Handling）
//   - relay 辅助：通过 relay 转发 PATH_CHALLENGE（T-LP4-005），学习反射地址
//
// 设计原则：
//   - 纯状态管理层，不直接操作 socket（实际发包由 Endpoint 层调用）
//   - 线程安全：所有公共方法内部加锁
//   - 可测试：状态转换逻辑可独立单元测试

#pragma once

#include "linoh/base/key.hpp"       // EndpointId
#include "linoh/net/holepuncher.hpp" // HolepunchResult, predict_symmetric_nat_ports

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace linoh::net {

/// 打洞轮次状态
enum class RoundStatus {
    Active,     ///< 当前活跃轮次，正在发送 PATH_CHALLENGE
    Aborted,    ///< 被新轮次中止（新地址到来）
    Succeeded,  ///< 成功建立连接
    Failed,     ///< 超时或所有候选端口耗尽
};

/// 单个打洞轮次的状态快照
struct HolepunchRound {
    std::uint32_t round_id{0};                          ///< 轮次 ID（递增）
    RoundStatus status{RoundStatus::Active};
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;

    /// 本轮候选端口列表（本端预测的对端端口 + relay 反射地址）
    std::vector<std::uint16_t> candidate_ports;

    /// 已发送 PATH_CHALLENGE 的端口集合（避免重复发送）
    std::vector<std::uint16_t> sent_challenge_ports;

    /// 已收到 PATH_RESPONSE 的端口（命中端口）
    std::vector<std::uint16_t> responded_ports;

    /// relay 反射地址（通过 T-LP4-005 的 PathChallengeDeliver 获取）
    std::string relay_observed_host;
    std::uint16_t relay_observed_port{0};

    /// 本端预测的对端端口列表
    std::vector<std::uint16_t> predicted_remote_ports;

    /// 对端预测的本端端口列表（通过 relay 或信令交换获得）
    std::vector<std::uint16_t> predicted_local_ports;

    /// 轮次持续时间（毫秒）
    std::chrono::milliseconds duration() const {
        auto end = (status == RoundStatus::Active)
                       ? std::chrono::steady_clock::now()
                       : end_time;
        return std::chrono::duration_cast<std::chrono::milliseconds>(end - start_time);
    }

    /// 转字符串（用于日志）
    std::string to_string() const;
};

/// v5.0.0 (T-LP4-004): Hard-NAT 双向打洞协调器
///
/// 管理多轮打洞状态，支持：
///   1. 双向端口预测 — 双方互相预测对方端口
///   2. 多轮打洞 — 新地址到来中止前轮，开启新轮
///   3. relay 辅助 — 集成 T-LP4-005 的 PATH_CHALLENGE 转发
///   4. 超时管理 — 自动标记超时轮次为 Failed
///
/// 线程安全：所有公共方法内部加锁。
class BidirectionalHolepuncher {
public:
    /// 轮次超时（默认 10s，超时后标记 Failed）
    static constexpr auto kDefaultRoundTimeout = std::chrono::seconds(10);

    /// 最大历史轮次保留数（防止内存无限增长）
    static constexpr std::size_t kMaxHistoryRounds = 20;

    BidirectionalHolepuncher() = default;
    ~BidirectionalHolepuncher() = default;

    BidirectionalHolepuncher(const BidirectionalHolepuncher &) = delete;
    BidirectionalHolepuncher &operator=(const BidirectionalHolepuncher &) = delete;

    // ─── 轮次管理 ───

    /// 开始新的打洞轮次。
    ///
    /// 自动中止当前活跃轮次（如果有），并开始新轮次。
    /// 新地址到来时调用此方法，传入新的候选端口列表。
    ///
    /// @param candidate_ports 本轮候选端口列表
    /// @param predicted_remote 本端预测的对端端口列表
    /// @param predicted_local 对端预测的本端端口列表
    /// @return 新轮次的 round_id
    std::uint32_t start_round(
        std::vector<std::uint16_t> candidate_ports,
        std::vector<std::uint16_t> predicted_remote = {},
        std::vector<std::uint16_t> predicted_local = {});

    /// 中止当前活跃轮次
    void abort_current_round();

    /// 标记当前轮次成功
    ///
    /// @param established_port 成功建立连接的端口
    void mark_succeeded(std::uint16_t established_port);

    /// 标记当前轮次失败
    void mark_failed();

    /// 检查并标记超时轮次
    /// @param timeout 轮次超时时间
    /// @return 是否有轮次被标记为超时
    bool check_timeout(std::chrono::milliseconds timeout = kDefaultRoundTimeout);

    // ─── PATH_CHALLENGE 跟踪 ───

    /// 记录已发送的 PATH_CHALLENGE
    ///
    /// @param port 发送目标端口
    /// @return true 如果是首次对该端口发送（应发送），false 如果已发送过（跳过）
    bool record_challenge_sent(std::uint16_t port);

    /// 记录收到的 PATH_RESPONSE（匹配之前的 PATH_CHALLENGE）
    ///
    /// @param port 响应端口
    /// @return true 如果匹配到已发送的 CHALLENGE
    bool record_response(std::uint16_t port);

    /// 更新 relay 反射地址（来自 T-LP4-005 的 PathChallengeDeliver）
    ///
    /// @param host relay 观察到的本端公网 IP
    /// @param port relay 观察到的本端公网端口
    void update_relay_observed_addr(const std::string &host, std::uint16_t port);

    // ─── 状态查询 ───

    /// 获取当前活跃轮次（如有）
    std::optional<HolepunchRound> current_round() const;

    /// 是否有活跃轮次
    bool is_active() const;

    /// 获取历史轮次列表（不含当前活跃轮次）
    std::vector<HolepunchRound> history_rounds() const;

    /// 获取已完成轮次总数
    std::size_t total_rounds() const;

    /// 获取已成功的轮次（如有）
    std::optional<HolepunchRound> successful_round() const;

    // ─── 双向端口预测 ───

    /// v5.0.0 (T-LP4-004): 双向端口预测
    ///
    /// 基于双方的 STUN 观测端口，双向预测对方端口。
    /// 借鉴 iroh noq#672 — 双方同时向对方预测端口发送 PATH_CHALLENGE。
    ///
    /// @param local_observed_port_1  本端第一次 STUN 观测端口
    /// @param local_observed_port_2  本端第二次 STUN 观测端口
    /// @param remote_observed_port_1 对端第一次 STUN 观测端口
    /// @param remote_observed_port_2 对端第二次 STUN 观测端口
    /// @param predictions_count 每方向预测端口数
    /// @return {预测对端端口列表, 预测本端端口列表}
    static std::pair<std::vector<std::uint16_t>, std::vector<std::uint16_t>>
    predict_bidirectional_ports(
        std::uint16_t local_observed_port_1,
        std::uint16_t local_observed_port_2,
        std::uint16_t remote_observed_port_1,
        std::uint16_t remote_observed_port_2,
        std::size_t predictions_count = 10);

private:
    mutable std::mutex mu_;

    std::vector<HolepunchRound> rounds_;   ///< 所有轮次（含活跃和历史）
    std::uint32_t next_round_id_{1};       ///< 下一个轮次 ID
    std::optional<std::uint32_t> successful_round_id_;  ///< 成功轮次 ID

    /// 清理过旧的历史轮次（保留最近 kMaxHistoryRounds 轮）
    void prune_history_locked();
};

} // namespace linoh::net
