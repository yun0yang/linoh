// passive_endpoint_updater.hpp — P0-G3 被动端点更新
//
// 对称 NAT 从非反射端口发包时，Endpoint 收包路径检测到源地址与记录地址不符，
// 自适应更新端点地址。适配对称 NAT 端口跳跃场景（NAT 为每个新目的分配新映射，
// 对端响应包源端口可能与 STUN 观测端口不同）。
//
// 设计原则：
//   - 纯逻辑组件（无 socket I/O），由 Endpoint 层在收包路径调用
//   - 线程安全（内部 mutex，per-peer 独立状态）
//   - 限频更新（cooldown 窗口内仅首次触发，避免频繁抖动）
//   - 记录更新事件统计（供监控/NatStats 聚合）
//
// 集成点：
//   - Endpoint 持有 PassiveEndpointUpdater 成员
//   - DatagramHandler 收包时调用 maybe_update(from, recorded_addr, actual_src)
//   - 返回 nullopt → 地址一致或限频抑制，无需更新
//   - 返回新地址 → Endpoint 更新 from_addr → conn 反向映射

#pragma once

#include "linoh/base/endpoint_addr.hpp"  // TransportAddr
#include "linoh/base/key.hpp"            // EndpointId

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace linoh::nat {

/// 被动端点更新配置
struct PassiveEndpointUpdaterConfig {
    /// 更新限频窗口（默认 30s，窗口内仅首次触发更新，抑制后续）
    std::chrono::milliseconds cooldown{std::chrono::seconds(30)};
    /// 是否启用地址比较（false=总是返回 actual_src，调试用）
    bool enable_address_check{true};
    /// 是否记录统计（false=不记录，减少开销）
    bool enable_stats{true};
};

/// 被动端点更新统计
struct PassiveEndpointUpdateStats {
    std::uint64_t total_packets_checked{0};    ///< 检查的总包数
    std::uint64_t address_mismatches{0};       ///< 源地址不匹配次数
    std::uint64_t updates_performed{0};        ///< 实际更新次数
    std::uint64_t updates_suppressed{0};       ///< 因限频被抑制的更新次数
};

/// 被动端点更新器（per-peer 独立限频）
///
/// 线程安全：内部 mutex 保护 per-peer 状态与统计。
/// 由 Endpoint 在收包路径调用，回调内不阻塞。
class PassiveEndpointUpdater {
public:
    explicit PassiveEndpointUpdater(PassiveEndpointUpdaterConfig config = {});

    /// 检查并可能更新端点地址
    ///
    /// @param peer 对端 EndpointId（per-peer 限频 key）
    /// @param recorded_addr 当前记录的对端地址
    /// @param actual_src 实际收包源地址
    /// @param now 当前时间（默认 steady_clock::now，测试可注入）
    /// @return 若需更新返回新地址；nullopt 表示地址一致或限频抑制
    std::optional<base::TransportAddr> maybe_update(
        const base::EndpointId &peer,
        const base::TransportAddr &recorded_addr,
        const base::TransportAddr &actual_src,
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    /// 获取统计快照（线程安全）
    PassiveEndpointUpdateStats stats() const;

    /// 重置统计（线程安全，不影响 per-peer 限频状态）
    void reset_stats();

private:
    PassiveEndpointUpdaterConfig config_;
    mutable std::mutex mu_;

    /// per-peer 限频状态
    struct PeerState {
        std::chrono::steady_clock::time_point last_update;
        bool has_last_update{false};
    };
    std::unordered_map<base::EndpointId, PeerState> peers_;

    PassiveEndpointUpdateStats stats_;
};

/// 工具函数：判断两个 TransportAddr 是否地址不同（host 或 port 不同）
///
/// 仅比较 host + port（kind 相同前提下）。用于 maybe_update 内部决策，
/// 也可独立调用便于单元测试。
bool address_differs(const base::TransportAddr &a, const base::TransportAddr &b);

}  // namespace linoh::nat
