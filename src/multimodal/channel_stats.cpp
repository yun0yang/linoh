// channel_stats.cpp — 通道公平性计数器实现（v1.7.0.2 P1 / B4）

#include "linoh/multimodal/channel_stats.hpp"
#include "linoh/util/logging.hpp"

namespace linoh::multimodal {

ChannelStatsRegistry::ChannelStatsRegistry() = default;
ChannelStatsRegistry::~ChannelStatsRegistry() = default;

void ChannelStatsRegistry::record_send(ChannelType type, std::uint64_t bytes, std::uint64_t packets) {
    auto &c = counters_[index_of(type)];
    c.bytes_sent.fetch_add(bytes, std::memory_order_relaxed);
    c.packets_sent.fetch_add(packets, std::memory_order_relaxed);
}

void ChannelStatsRegistry::record_recv(ChannelType type, std::uint64_t bytes, std::uint64_t packets) {
    auto &c = counters_[index_of(type)];
    c.bytes_received.fetch_add(bytes, std::memory_order_relaxed);
    c.packets_received.fetch_add(packets, std::memory_order_relaxed);
}

void ChannelStatsRegistry::record_loss(ChannelType type, std::uint64_t count) {
    auto &c = counters_[index_of(type)];
    c.lost_packets.fetch_add(count, std::memory_order_relaxed);
}

ChannelStatsSnapshot ChannelStatsRegistry::snapshot(ChannelType type) const {
    std::lock_guard<std::mutex> lk(snapshot_mu_);
    auto &c = counters_[index_of(type)];
    ChannelStatsSnapshot s;
    s.type = type;
    s.bytes_sent = c.bytes_sent.load(std::memory_order_relaxed);
    s.bytes_received = c.bytes_received.load(std::memory_order_relaxed);
    s.packets_sent = c.packets_sent.load(std::memory_order_relaxed);
    s.packets_received = c.packets_received.load(std::memory_order_relaxed);
    s.lost_packets = c.lost_packets.load(std::memory_order_relaxed);
    return s;
}

std::vector<ChannelStatsSnapshot> ChannelStatsRegistry::all_snapshots() const {
    std::lock_guard<std::mutex> lk(snapshot_mu_);
    std::vector<ChannelStatsSnapshot> out;
    out.reserve(kChannelCount);
    for (std::size_t i = 0; i < kChannelCount; ++i) {
        auto &c = counters_[i];
        ChannelStatsSnapshot s;
        s.type = static_cast<ChannelType>(i);
        s.bytes_sent = c.bytes_sent.load(std::memory_order_relaxed);
        s.bytes_received = c.bytes_received.load(std::memory_order_relaxed);
        s.packets_sent = c.packets_sent.load(std::memory_order_relaxed);
        s.packets_received = c.packets_received.load(std::memory_order_relaxed);
        s.lost_packets = c.lost_packets.load(std::memory_order_relaxed);
        out.push_back(s);
    }
    return out;
}

double ChannelStatsRegistry::fairness_ratio() const {
    std::lock_guard<std::mutex> lk(snapshot_mu_);
    std::uint64_t max_bytes = 0;
    std::uint64_t min_bytes = UINT64_MAX;
    bool any_data = false;

    for (std::size_t i = 0; i < kChannelCount; ++i) {
        auto t = static_cast<ChannelType>(i);
        if (t == ChannelType::CONTROL) continue;  // 排除控制信道
        auto bytes = counters_[i].bytes_sent.load(std::memory_order_relaxed);
        if (bytes > 0) {
            any_data = true;
            if (bytes > max_bytes) max_bytes = bytes;
            if (bytes < min_bytes) min_bytes = bytes;
        }
    }

    if (!any_data) return 1.0;  // 全部为 0 视为公平
    if (min_bytes == 0) return 1.0;  // 防御性：理论上 any_data=true 时 min_bytes > 0
    return static_cast<double>(max_bytes) / static_cast<double>(min_bytes);
}

void ChannelStatsRegistry::reset() {
    std::lock_guard<std::mutex> lk(snapshot_mu_);
    for (auto &c : counters_) {
        c.bytes_sent.store(0, std::memory_order_relaxed);
        c.bytes_received.store(0, std::memory_order_relaxed);
        c.packets_sent.store(0, std::memory_order_relaxed);
        c.packets_received.store(0, std::memory_order_relaxed);
        c.lost_packets.store(0, std::memory_order_relaxed);
    }
}

} // namespace linoh::multimodal
