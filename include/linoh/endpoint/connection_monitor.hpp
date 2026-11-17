// connection_monitor.hpp — v3.9.1 ConnectionMonitor 带宽反馈闭环
//
// 连接质量监控：per-peer 带宽 + RTT 数据收集，供路径选择器动态调整权重。
// 与 v3.9.0 PacingLimiter/BBR pacing 配合：BBR pacing_rate 是模型估算值，
// ConnectionMonitor 收集实测带宽，路径权重优先用实测值（更准确）。
//
// 设计要点：
//   - shared_mutex 多读单写，get_connection_data 无锁快照读
//   - EndpointId（32 字节公钥）作为索引键
//   - last_updated 时间戳用于数据过期判断（steady_clock 单调时钟）
//   - 线程安全：多线程并发 on_bandwidth_measured + get_connection_data

#ifndef LINOH_ENDPOINT_CONNECTION_MONITOR_HPP
#define LINOH_ENDPOINT_CONNECTION_MONITOR_HPP

#include <linoh/base/key.hpp>  // EndpointId = PublicKey

#include <chrono>
#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <unordered_map>

namespace linoh::endpoint {

/// ConnectionMonitor — per-peer 连接质量监控
///
/// 收集每个 peer 的实测带宽和 RTT，供 MultipathCoordinatedSelector
/// 在 recompute_weights 时用实测带宽替代 BBR 估算的 pacing_rate。
class ConnectionMonitor {
public:
    /// 单个连接的质量数据
    struct ConnectionData {
        std::uint64_t bandwidth_bps{0};   ///< 实测带宽（bits/sec）
        std::uint32_t rtt_ms{0};          ///< 实测 RTT（毫秒）
        std::chrono::steady_clock::time_point last_updated;  ///< 最后更新时间

        /// 数据是否过期（超过 ttl 秒未更新）
        bool is_expired(std::uint32_t ttl_seconds = 30) const {
            if (bandwidth_bps == 0 && rtt_ms == 0) return true;
            auto age = std::chrono::steady_clock::now() - last_updated;
            return std::chrono::duration_cast<std::chrono::seconds>(age).count() >=
                   static_cast<std::int64_t>(ttl_seconds);
        }
    };

    ConnectionMonitor() = default;
    ~ConnectionMonitor() = default;

    // 不可拷贝（内部有 shared_mutex）
    ConnectionMonitor(const ConnectionMonitor&) = delete;
    ConnectionMonitor& operator=(const ConnectionMonitor&) = delete;

    // 不可移动（shared_mutex 不可移动）
    ConnectionMonitor(ConnectionMonitor&&) = delete;
    ConnectionMonitor& operator=(ConnectionMonitor&&) = delete;

    // ===== 数据上报 =====

    /// 上报带宽测量结果
    void on_bandwidth_measured(const base::EndpointId& peer, std::uint64_t bps);

    /// 上报 RTT 测量结果
    void on_rtt_measured(const base::EndpointId& peer, std::uint32_t rtt_ms);

    /// 握手完成时记录初始 RTT
    void on_handshake_completed(const base::EndpointId& peer, std::uint32_t rtt_ms);

    /// 综合上报（带宽 + RTT 一次性更新）
    void on_metrics_measured(const base::EndpointId& peer,
                             std::uint64_t bps,
                             std::uint32_t rtt_ms);

    // ===== 数据查询 =====

    /// 获取指定 peer 的连接数据（无锁快照读）
    /// @return ConnectionData，如果 peer 不存在则 bandwidth_bps=0, rtt_ms=0
    ConnectionData get_connection_data(const base::EndpointId& peer) const;

    /// 获取指定 peer 的实测带宽（便捷接口）
    /// @return 带宽 bps，如果不存在或过期返回 0
    std::uint64_t get_bandwidth_bps(const base::EndpointId& peer) const;

    /// 获取指定 peer 的实测 RTT（便捷接口）
    /// @return RTT ms，如果不存在返回 0
    std::uint32_t get_rtt_ms(const base::EndpointId& peer) const;

    // ===== 管理 =====

    /// 移除指定 peer 的连接数据
    void remove_connection(const base::EndpointId& peer);

    /// 清除所有连接数据
    void clear();

    /// 当前监控的连接数
    std::size_t connection_count() const;

    /// 清除所有过期数据
    /// @param ttl_seconds 超过此秒数未更新的数据被清除
    /// @return 清除的连接数
    std::size_t purge_expired(std::uint32_t ttl_seconds = 30);

    // ===== 统计 =====

    struct Stats {
        std::uint64_t total_bandwidth_reports{0};
        std::uint64_t total_rtt_reports{0};
        std::uint64_t total_handshake_reports{0};
        std::uint64_t total_purged{0};
    };

    const Stats& stats() const noexcept { return stats_; }

private:
    mutable std::shared_mutex data_mutex_;
    std::unordered_map<base::EndpointId, ConnectionData> connections_;
    Stats stats_;
};

}  // namespace linoh::endpoint

#endif  // LINOH_ENDPOINT_CONNECTION_MONITOR_HPP
