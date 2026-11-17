// network_rebuilder.cpp — P2-G7 网络切换重建状态机实现

#include "linoh/net/network_rebuilder.hpp"

#include "linoh/util/logging.hpp"

#include <thread>

namespace linoh::net {

// ============================================================================
// NetworkRebuilder 实现
// ============================================================================

NetworkRebuilder::NetworkRebuilder(NetworkRebuildConfig config)
    : config_(config) {
    // 默认 provider：生产路径（由 Endpoint 注入真实实现前为空，调用时返回失败结果）
    udp_probe_provider_ = []() {
        UdpProbeResult r;
        r.availability = UdpAvailability::NotAvailable;
        r.error_msg = "no udp probe provider";
        return r;
    };
    gather_provider_ = []() { return false; };
    holepunch_provider_ = []() {
        HolepunchResult r;
        r.success = false;
        r.error_msg = "no holepunch provider";
        return r;
    };
    fallback_provider_ = []() {
        relay::FallbackResult r;
        r.decision = relay::FallbackDecision::UseRelay;
        r.error_msg = "no fallback provider";
        return r;
    };
}

NetworkRebuilder::NetworkRebuilder(
    NetworkRebuildConfig config,
    RebuildUdpProbeProvider udp_probe_provider,
    RebuildGatherProvider gather_provider,
    RebuildHolepunchProvider holepunch_provider,
    RebuildFallbackProvider fallback_provider)
    : config_(config),
      udp_probe_provider_(std::move(udp_probe_provider)),
      gather_provider_(std::move(gather_provider)),
      holepunch_provider_(std::move(holepunch_provider)),
      fallback_provider_(std::move(fallback_provider)) {
    if (!udp_probe_provider_) {
        udp_probe_provider_ = []() {
            UdpProbeResult r;
            r.availability = UdpAvailability::NotAvailable;
            return r;
        };
    }
    if (!gather_provider_) gather_provider_ = []() { return false; };
    if (!holepunch_provider_) {
        holepunch_provider_ = []() {
            HolepunchResult r;
            r.success = false;
            return r;
        };
    }
    if (!fallback_provider_) {
        fallback_provider_ = []() {
            relay::FallbackResult r;
            r.decision = relay::FallbackDecision::UseRelay;
            return r;
        };
    }
}

NetworkRebuildResult NetworkRebuilder::rebuild() {
    auto start = std::chrono::steady_clock::now();
    NetworkRebuildResult result;
    ++stats_.total;

    // Step 1: 重置 UDP 可用性状态（清空缓存，标记需要重新探测）
    result.last_step = RebuildStep::Step1_Reset;
    // Step 1 是纯状态重置，无 I/O，直接进入 Step 2

    // Step 2: 重新探测 UDP
    result.last_step = RebuildStep::Step2_Probe;
    result.udp_probe_result = udp_probe_provider_();
    RebuildStep next = decide_after_probe(result.udp_probe_result.availability);

    bool need_fallback = false;
    if (next == RebuildStep::Step5_Fallback) {
        // NotAvailable → 跳过 Step 3/4，直接 Step 5
        LINOH_INFO("NetworkRebuilder: UDP NotAvailable, skip to Step5");
        need_fallback = true;
    } else {
        // Step 3: 重新收集 STUN 候选
        result.last_step = RebuildStep::Step3_Gather;
        if (!gather_provider_()) {
            LINOH_WARN("NetworkRebuilder: gather failed, skip to Step5");
            need_fallback = true;
        } else {
            // Step 4: 重新打洞
            result.last_step = RebuildStep::Step4_Punch;
            result.holepunch_result = holepunch_provider_();
            next = decide_after_holepunch(result.holepunch_result);
            if (next == RebuildStep::Done) {
                // 打洞成功
                result.outcome = RebuildOutcome::Success;
                result.last_step = RebuildStep::Done;
                ++stats_.succeeded;
                auto end = std::chrono::steady_clock::now();
                result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                stats_.total_duration_ms.fetch_add(static_cast<std::uint64_t>(result.duration.count()));
                return result;
            }
            need_fallback = true;
        }
    }

    // Step 5: 降级 TCP Relay
    if (need_fallback) {
        result.last_step = RebuildStep::Step5_Fallback;
        result.fallback_result = fallback_provider_();
        result.outcome = decide_after_fallback(result.fallback_result);

        if (result.outcome == RebuildOutcome::Degraded) {
            result.last_step = RebuildStep::Done;
            ++stats_.degraded;
        } else {
            result.last_step = RebuildStep::Disconnected;
            ++stats_.failed;
        }
    }

    auto end = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    stats_.total_duration_ms.fetch_add(static_cast<std::uint64_t>(result.duration.count()));
    return result;
}

RebuildStep NetworkRebuilder::decide_after_probe(UdpAvailability availability) noexcept {
    switch (availability) {
        case UdpAvailability::Available:    return RebuildStep::Step3_Gather;
        case UdpAvailability::Bad:          return RebuildStep::Step3_Gather;  // 打洞 + FEC
        case UdpAvailability::NotAvailable: return RebuildStep::Step5_Fallback;
    }
    return RebuildStep::Step5_Fallback;
}

RebuildStep NetworkRebuilder::decide_after_holepunch(const HolepunchResult &result) noexcept {
    if (result.success) return RebuildStep::Done;
    return RebuildStep::Step5_Fallback;
}

RebuildOutcome NetworkRebuilder::decide_after_fallback(const relay::FallbackResult &result) noexcept {
    // FallbackResult 无统一 success 字段，根据 decision 判断
    // UseUdp/UseUdpWithFec/UseTcp/UseRelay 都是"降级成功"（找到了一条可用路径）
    // error_msg 非空且 decision 为 UseRelay（且 relay 未实际尝试）视为失败
    if (result.decision == relay::FallbackDecision::UseUdp ||
        result.decision == relay::FallbackDecision::UseUdpWithFec ||
        result.decision == relay::FallbackDecision::UseTcp ||
        result.decision == relay::FallbackDecision::UseRelay) {
        // 如果 relay_attempted=true 且 error_msg 非空 → relay 失败
        if (result.relay_attempted && !result.error_msg.empty()) {
            return RebuildOutcome::Failed;
        }
        return RebuildOutcome::Degraded;
    }
    return RebuildOutcome::Failed;
}

// ============================================================================
// OldConnectionGraceManager 实现
// ============================================================================

OldConnectionGraceManager::OldConnectionGraceManager(
    std::chrono::milliseconds grace_duration)
    : grace_duration_(grace_duration) {}

void OldConnectionGraceManager::enter_grace(std::function<void()> close_callback) {
    close_callback_ = std::move(close_callback);
    state_.store(GraceState::InGrace);
    grace_start_ = std::chrono::steady_clock::now();
    stop_.store(false);

    // 启动 grace 倒计时线程
    grace_thread_ = std::thread([this]() {
        auto deadline = grace_start_ + grace_duration_;
        while (!stop_.load()) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) break;
            auto remaining = deadline - now;
            auto sleep_ms = std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
            // 最多睡 100ms，便于快速响应 force_close
            if (sleep_ms.count() > 100) sleep_ms = std::chrono::milliseconds(100);
            std::this_thread::sleep_for(sleep_ms);
        }
        if (!stop_.load()) {
            // grace 自然结束
            state_.store(GraceState::Closed);
            if (close_callback_) close_callback_();
        }
    });
}

bool OldConnectionGraceManager::is_in_grace() const noexcept {
    return state_.load() == GraceState::InGrace;
}

bool OldConnectionGraceManager::is_closed() const noexcept {
    return state_.load() == GraceState::Closed;
}

GraceState OldConnectionGraceManager::state() const noexcept {
    return state_.load();
}

void OldConnectionGraceManager::force_close() {
    stop_.store(true);
    if (grace_thread_.joinable()) grace_thread_.join();
    if (state_.exchange(GraceState::Closed) != GraceState::Closed) {
        if (close_callback_) close_callback_();
    }
}

void OldConnectionGraceManager::wait_grace_end() {
    if (grace_thread_.joinable()) grace_thread_.join();
}

}  // namespace linoh::net
