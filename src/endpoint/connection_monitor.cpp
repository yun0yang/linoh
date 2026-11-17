// connection_monitor.cpp — v3.9.1 ConnectionMonitor 带宽反馈闭环实现

#include "linoh/endpoint/connection_monitor.hpp"

#include <mutex>
#include <shared_mutex>

namespace linoh::endpoint {

// ===== 数据上报 =====

void ConnectionMonitor::on_bandwidth_measured(const base::EndpointId& peer, std::uint64_t bps) {
    {
        std::unique_lock<std::shared_mutex> lk(data_mutex_);
        auto& data = connections_[peer];
        data.bandwidth_bps = bps;
        data.last_updated = std::chrono::steady_clock::now();
    }
    ++stats_.total_bandwidth_reports;
}

void ConnectionMonitor::on_rtt_measured(const base::EndpointId& peer, std::uint32_t rtt_ms) {
    {
        std::unique_lock<std::shared_mutex> lk(data_mutex_);
        auto& data = connections_[peer];
        data.rtt_ms = rtt_ms;
        data.last_updated = std::chrono::steady_clock::now();
    }
    ++stats_.total_rtt_reports;
}

void ConnectionMonitor::on_handshake_completed(const base::EndpointId& peer, std::uint32_t rtt_ms) {
    {
        std::unique_lock<std::shared_mutex> lk(data_mutex_);
        auto& data = connections_[peer];
        data.rtt_ms = rtt_ms;
        data.last_updated = std::chrono::steady_clock::now();
    }
    ++stats_.total_handshake_reports;
}

void ConnectionMonitor::on_metrics_measured(const base::EndpointId& peer,
                                            std::uint64_t bps,
                                            std::uint32_t rtt_ms) {
    {
        std::unique_lock<std::shared_mutex> lk(data_mutex_);
        auto& data = connections_[peer];
        data.bandwidth_bps = bps;
        data.rtt_ms = rtt_ms;
        data.last_updated = std::chrono::steady_clock::now();
    }
    ++stats_.total_bandwidth_reports;
    ++stats_.total_rtt_reports;
}

// ===== 数据查询 =====

ConnectionMonitor::ConnectionData
ConnectionMonitor::get_connection_data(const base::EndpointId& peer) const {
    std::shared_lock<std::shared_mutex> lk(data_mutex_);
    auto it = connections_.find(peer);
    if (it == connections_.end()) {
        return ConnectionData{};
    }
    return it->second;  // 值拷贝快照
}

std::uint64_t ConnectionMonitor::get_bandwidth_bps(const base::EndpointId& peer) const {
    auto data = get_connection_data(peer);
    return data.bandwidth_bps;
}

std::uint32_t ConnectionMonitor::get_rtt_ms(const base::EndpointId& peer) const {
    auto data = get_connection_data(peer);
    return data.rtt_ms;
}

// ===== 管理 =====

void ConnectionMonitor::remove_connection(const base::EndpointId& peer) {
    std::unique_lock<std::shared_mutex> lk(data_mutex_);
    connections_.erase(peer);
}

void ConnectionMonitor::clear() {
    std::unique_lock<std::shared_mutex> lk(data_mutex_);
    connections_.clear();
}

std::size_t ConnectionMonitor::connection_count() const {
    std::shared_lock<std::shared_mutex> lk(data_mutex_);
    return connections_.size();
}

std::size_t ConnectionMonitor::purge_expired(std::uint32_t ttl_seconds) {
    std::size_t purged = 0;
    {
        std::unique_lock<std::shared_mutex> lk(data_mutex_);
        auto now = std::chrono::steady_clock::now();
        for (auto it = connections_.begin(); it != connections_.end();) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                           now - it->second.last_updated)
                           .count();
            if (age >= static_cast<std::int64_t>(ttl_seconds)) {
                it = connections_.erase(it);
                ++purged;
            } else {
                ++it;
            }
        }
    }
    stats_.total_purged += purged;
    return purged;
}

}  // namespace linoh::endpoint
