// network_rebuilder.hpp — P2-G7 网络切换重建状态机（独立可测组件）
//
// 借鉴 tdesktop 网络切换重建 + iroh connection migration：
// 网络类型变化后执行 5 步重建流程，恢复 P2P 连接或降级到 Relay。
//
// 设计原则：
//   - 独立组件：不依赖 Endpoint 内部状态，通过注入式 provider 完成各步 I/O
//   - 纯决策逻辑可测：decide_next_step() 是纯函数，便于单元测试
//   - 5 步状态机顺序执行，NotAvailable 直接跳 Step 5（不浪费 Step 3/4 时间）
//   - 旧连接优雅迁移：grace 期内旧连接继续交付在途帧，grace 结束 close
//   - 总超时强制降级：network_rebuild_timeout 到期强制进入 Step 5
//
// 5 步重建流程：
//   Step 1: 重置 UDP 可用性状态（清空缓存，标记需要重新探测）
//   Step 2: 重新探测 UDP（调 G1 UdpProber::probe）
//   Step 3: 重新收集 STUN 候选（CandidateCollector::gather_candidates_sync）
//   Step 4: 重新打洞（Holepuncher::attempt_with_probe）
//   Step 5: 降级 TCP Relay（G2 TcpFallback::orchestrate）
//
// 决策矩阵：
//   Step 2 结果:
//     Available → 继续 Step 3/4（打洞）
//     Bad       → 继续 Step 3/4（打洞 + FEC 增强）
//     NotAvailable → 跳过 Step 3/4，直接 Step 5
//   Step 4 结果:
//     Success → 重建完成（不走 Step 5）
//     Failure → Step 5
//   Step 5 结果:
//     Success → 重建完成（降级模式）
//     Failure → 标记 disconnected，触发 on_disconnected

#pragma once
#ifndef LINOH_NET_NETWORK_REBUILDER_HPP_
#define LINOH_NET_NETWORK_REBUILDER_HPP_

#include "linoh/net/udp_probe.hpp"        // net::UdpAvailability, UdpProbeResult
#include "linoh/relay/tcp_fallback.hpp"   // relay::FallbackResult, FallbackDecision
#include "linoh/net/holepuncher.hpp"      // HolepunchResult, HolepunchStrategy

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace linoh::net {

// ============================================================================
// 重建状态机枚举
// ============================================================================

/// 重建步骤
enum class RebuildStep : std::uint8_t {
    Idle          = 0,  ///< 空闲（未开始重建）
    Step1_Reset   = 1,  ///< 重置 UDP 可用性状态
    Step2_Probe   = 2,  ///< 重新探测 UDP
    Step3_Gather  = 3,  ///< 重新收集 STUN 候选
    Step4_Punch   = 4,  ///< 重新打洞
    Step5_Fallback = 5, ///< 降级 TCP Relay
    Done          = 6,  ///< 重建完成
    Disconnected  = 7,  ///< 重建失败，连接断开
};

/// 重建步骤转字符串
inline const char *to_string(RebuildStep s) noexcept {
    switch (s) {
        case RebuildStep::Idle:           return "idle";
        case RebuildStep::Step1_Reset:    return "step1-reset";
        case RebuildStep::Step2_Probe:    return "step2-probe";
        case RebuildStep::Step3_Gather:   return "step3-gather";
        case RebuildStep::Step4_Punch:    return "step4-punch";
        case RebuildStep::Step5_Fallback: return "step5-fallback";
        case RebuildStep::Done:           return "done";
        case RebuildStep::Disconnected:   return "disconnected";
    }
    return "unknown";
}

/// 重建结果
enum class RebuildOutcome : std::uint8_t {
    Success,       ///< 打洞成功（Step 4 通过）
    Degraded,      ///< 降级成功（Step 5 Relay/TCP 成功）
    Failed,        ///< 全部失败（disconnected）
    Timeout,       ///< 总超时强制降级
};

inline const char *to_string(RebuildOutcome o) noexcept {
    switch (o) {
        case RebuildOutcome::Success:  return "success";
        case RebuildOutcome::Degraded: return "degraded";
        case RebuildOutcome::Failed:   return "failed";
        case RebuildOutcome::Timeout:  return "timeout";
    }
    return "unknown";
}

// ============================================================================
// 重建配置与统计
// ============================================================================

/// 重建配置
struct NetworkRebuildConfig {
    /// 是否启用网络切换重建（默认 true）
    bool enabled{true};
    /// 重建总超时（默认 15s，到期强制 Step 5）
    std::chrono::milliseconds timeout{std::chrono::seconds(15)};
    /// 旧连接优雅迁移 grace 期（默认 3s，grace 期内旧连接继续交付在途帧）
    std::chrono::milliseconds old_connection_grace{std::chrono::seconds(3)};
    /// Step 2 UDP 探测配置
    UdpProbeConfig udp_probe_config{};
    /// Step 5 TCP 兜底配置
    relay::FallbackConfig fallback_config{};
};

/// 重建统计（原子计数器，线程安全）
struct NetworkRebuildStats {
    std::atomic<std::uint64_t> total{0};       ///< 重建总次数
    std::atomic<std::uint64_t> succeeded{0};   ///< 打洞成功次数
    std::atomic<std::uint64_t> degraded{0};    ///< 降级成功次数
    std::atomic<std::uint64_t> failed{0};      ///< 失败次数
    std::atomic<std::uint64_t> timeout{0};     ///< 超时次数
    std::atomic<std::uint64_t> total_duration_ms{0};  ///< 累计耗时（毫秒）

    /// 重置所有计数器
    void reset() noexcept {
        total.store(0);
        succeeded.store(0);
        degraded.store(0);
        failed.store(0);
        timeout.store(0);
        total_duration_ms.store(0);
    }
};

/// 重建结果详情
struct NetworkRebuildResult {
    RebuildOutcome outcome{RebuildOutcome::Failed};
    RebuildStep last_step{RebuildStep::Idle};
    UdpProbeResult udp_probe_result;        ///< Step 2 探测结果
    HolepunchResult holepunch_result;       ///< Step 4 打洞结果
    relay::FallbackResult fallback_result;  ///< Step 5 降级结果
    std::chrono::milliseconds duration{0};  ///< 总耗时
    std::string error_msg;                  ///< 错误信息

    /// 是否成功（含降级）
    bool is_success() const noexcept {
        return outcome == RebuildOutcome::Success || outcome == RebuildOutcome::Degraded;
    }
};

// ============================================================================
// 注入式 Provider（用于测试 mock）
// ============================================================================

/// Step 2: UDP 探测 provider（注入式）
/// 返回 UdpProbeResult，测试时可 mock 不同可用性
using RebuildUdpProbeProvider = std::function<UdpProbeResult()>;

/// Step 3: 候选收集 provider（注入式）
/// 返回是否成功收集到候选
using RebuildGatherProvider = std::function<bool()>;

/// Step 4: 打洞 provider（注入式）
/// 返回 HolepunchResult
using RebuildHolepunchProvider = std::function<HolepunchResult()>;

/// Step 5: TCP 兜底 provider（注入式）
/// 返回 FallbackResult
using RebuildFallbackProvider = std::function<relay::FallbackResult()>;

// ============================================================================
// NetworkRebuilder — 5 步重建状态机
// ============================================================================

/// 网络切换重建状态机
///
/// 通过注入式 provider 完成各步 I/O，决策逻辑（decide_next_step）为纯函数。
/// Endpoint 持有此组件，网络类型变化时调用 rebuild() 执行重建。
class NetworkRebuilder {
public:
    /// 默认构造
    explicit NetworkRebuilder(NetworkRebuildConfig config = {});

    /// 注入式构造（测试用：注入各步 provider）
    NetworkRebuilder(
        NetworkRebuildConfig config,
        RebuildUdpProbeProvider udp_probe_provider,
        RebuildGatherProvider gather_provider,
        RebuildHolepunchProvider holepunch_provider,
        RebuildFallbackProvider fallback_provider);

    /// 执行 5 步重建流程
    ///
    /// 流程：
    ///   Step 1: 重置 UDP 可用性状态（清空缓存）
    ///   Step 2: 重新探测 UDP → decide_next_step
    ///     Available/Bad → Step 3
    ///     NotAvailable  → Step 5
    ///   Step 3: 重新收集 STUN 候选
    ///   Step 4: 重新打洞 → decide_next_step
    ///     Success → Done
    ///     Failure → Step 5
    ///   Step 5: 降级 TCP Relay → decide_next_step
    ///     Success → Done (degraded)
    ///     Failure → Disconnected
    ///
    /// @return 重建结果
    NetworkRebuildResult rebuild();

    /// 纯决策逻辑：根据 Step 2 UDP 探测结果决定下一步
    ///
    /// 规则：
    ///   Available → Step3_Gather
    ///   Bad       → Step3_Gather（打洞 + FEC，由 Step4 内部处理）
    ///   NotAvailable → Step5_Fallback（跳过 Step3/4）
    static RebuildStep decide_after_probe(UdpAvailability availability) noexcept;

    /// 纯决策逻辑：根据 Step 4 打洞结果决定下一步
    ///
    /// 规则：
    ///   Success → Done
    ///   Failure → Step5_Fallback
    static RebuildStep decide_after_holepunch(const HolepunchResult &result) noexcept;

    /// 纯决策逻辑：根据 Step 5 降级结果决定最终状态
    ///
    /// 规则：
    ///   UseUdp/UseUdpWithFec/UseTcp/UseRelay 且非 error → Done (degraded)
    ///   error / 失败 → Disconnected
    static RebuildOutcome decide_after_fallback(const relay::FallbackResult &result) noexcept;

    /// 获取配置
    const NetworkRebuildConfig &config() const { return config_; }

    /// 获取统计
    const NetworkRebuildStats &stats() const { return stats_; }

private:
    NetworkRebuildConfig config_;
    NetworkRebuildStats stats_;
    RebuildUdpProbeProvider udp_probe_provider_;
    RebuildGatherProvider gather_provider_;
    RebuildHolepunchProvider holepunch_provider_;
    RebuildFallbackProvider fallback_provider_;
};

// ============================================================================
// 旧连接优雅迁移管理器
// ============================================================================

/// 旧连接优雅迁移状态
enum class GraceState : std::uint8_t {
    Inactive,     ///< 无旧连接（初始/已关闭）
    InGrace,      ///< grace 期内（旧连接继续交付在途帧）
    Closed,       ///< grace 期结束，旧连接已关闭
};

inline const char *to_string(GraceState s) noexcept {
    switch (s) {
        case GraceState::Inactive: return "inactive";
        case GraceState::InGrace:  return "in-grace";
        case GraceState::Closed:   return "closed";
    }
    return "unknown";
}

/// 旧连接优雅迁移管理器
///
/// 新连接就绪后，旧连接进入 grace 倒计时。
/// grace 期内旧连接继续交付在途 STREAM 帧。
/// grace 结束 → 旧连接 close()。
class OldConnectionGraceManager {
public:
    /// @param grace_duration grace 期（默认 3s）
    explicit OldConnectionGraceManager(
        std::chrono::milliseconds grace_duration = std::chrono::seconds(3));

    /// 进入 grace 期（新连接就绪后调用）
    /// @param close_callback grace 结束时调用的 close 回调
    void enter_grace(std::function<void()> close_callback);

    /// 是否在 grace 期内
    bool is_in_grace() const noexcept;

    /// grace 是否已结束（旧连接已关闭）
    bool is_closed() const noexcept;

    /// 当前状态
    GraceState state() const noexcept;

    /// 强制立即关闭（不等 grace 结束，用于总超时强制降级）
    void force_close();

    /// 等待 grace 结束（阻塞，测试用）
    void wait_grace_end();

private:
    std::chrono::milliseconds grace_duration_;
    std::atomic<GraceState> state_{GraceState::Inactive};
    std::function<void()> close_callback_;
    std::chrono::steady_clock::time_point grace_start_;
    std::thread grace_thread_;
    std::atomic<bool> stop_{false};
};

}  // namespace linoh::net

#endif  // LINOH_NET_NETWORK_REBUILDER_HPP_
