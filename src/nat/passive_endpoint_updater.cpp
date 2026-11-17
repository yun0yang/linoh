// passive_endpoint_updater.cpp — P0-G3 被动端点更新实现

#include "linoh/nat/passive_endpoint_updater.hpp"

namespace linoh::nat {

// ============================================================================
// 工具函数
// ============================================================================

bool address_differs(const base::TransportAddr &a, const base::TransportAddr &b) {
    // 仅比较 host + port（IP 或端口变化即视为地址不同）
    // kind 差异（Ip vs Relay vs Custom）由上层处理，此处只关注网络层地址
    return a.host != b.host || a.port != b.port;
}

// ============================================================================
// PassiveEndpointUpdater
// ============================================================================

PassiveEndpointUpdater::PassiveEndpointUpdater(PassiveEndpointUpdaterConfig config)
    : config_(std::move(config)) {}

std::optional<base::TransportAddr> PassiveEndpointUpdater::maybe_update(
    const base::EndpointId &peer,
    const base::TransportAddr &recorded_addr,
    const base::TransportAddr &actual_src,
    std::chrono::steady_clock::time_point now) {

    std::lock_guard<std::mutex> lk(mu_);

    if (config_.enable_stats) {
        ++stats_.total_packets_checked;
    }

    // 步骤 1：地址比较（enable_address_check=false 时跳过，视为需要更新）
    if (config_.enable_address_check) {
        if (!address_differs(recorded_addr, actual_src)) {
            // 地址一致，无需更新
            return std::nullopt;
        }
    }

    // 地址不同（或跳过检查）
    if (config_.enable_stats) {
        ++stats_.address_mismatches;
    }

    // 步骤 2：per-peer cooldown 限频检查
    auto &state = peers_[peer];
    if (state.has_last_update) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - state.last_update);
        if (elapsed < config_.cooldown) {
            // 限频窗口内，抑制更新
            if (config_.enable_stats) {
                ++stats_.updates_suppressed;
            }
            return std::nullopt;
        }
    }

    // 步骤 3：执行更新（记录限频时间点）
    state.last_update = now;
    state.has_last_update = true;
    if (config_.enable_stats) {
        ++stats_.updates_performed;
    }
    return actual_src;
}

PassiveEndpointUpdateStats PassiveEndpointUpdater::stats() const {
    std::lock_guard<std::mutex> lk(mu_);
    return stats_;
}

void PassiveEndpointUpdater::reset_stats() {
    std::lock_guard<std::mutex> lk(mu_);
    stats_ = PassiveEndpointUpdateStats{};
}

}  // namespace linoh::nat
