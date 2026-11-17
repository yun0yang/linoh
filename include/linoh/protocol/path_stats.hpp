// linoh/protocol/path_stats.hpp — B7 路径统计保留（v1.7.0.4 P3）
//
// 借鉴 iroh v1.0+ 的 PathStats / ConnectionStats 双层结构设计：
// - PathStats: 单条路径的统计（含瞬时状态 + 累计计数器）
// - ConnectionStats: 连接级聚合（仅累计计数器，瞬时状态不累加）
//
// 关键设计判断（来自 iroh noq_proto::connection::stats）：
//   "ConnectionStats = Σ(存活路径 PathStats) + Σ(已关闭路径 PathStats)"
// 但 rtt/cwnd/current_mtu 为瞬时状态，operator+= 显式忽略。

#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace linoh::protocol {

// ============================================================================
// UdpStats — UDP 传输层累计计数器
// ============================================================================
struct UdpStats {
    std::uint64_t packets_sent{0};
    std::uint64_t bytes_sent{0};
    std::uint64_t packets_received{0};
    std::uint64_t bytes_received{0};

    UdpStats &operator+=(const UdpStats &r) {
        packets_sent += r.packets_sent;
        bytes_sent += r.bytes_sent;
        packets_received += r.packets_received;
        bytes_received += r.bytes_received;
        return *this;
    }

    UdpStats operator+(const UdpStats &r) const {
        UdpStats out = *this;
        out += r;
        return out;
    }

    bool operator==(const UdpStats &r) const {
        return packets_sent == r.packets_sent && bytes_sent == r.bytes_sent &&
               packets_received == r.packets_received &&
               bytes_received == r.bytes_received;
    }
};

// ============================================================================
// FrameStats — QUIC 帧级累计计数器
// ============================================================================
struct FrameStats {
    std::uint64_t ack_sent{0};
    std::uint64_t ack_received{0};
    std::uint64_t stream_sent{0};
    std::uint64_t stream_received{0};
    std::uint64_t crypto_sent{0};
    std::uint64_t crypto_received{0};
    std::uint64_t ping_sent{0};
    std::uint64_t pong_received{0};

    FrameStats &operator+=(const FrameStats &r) {
        ack_sent += r.ack_sent;
        ack_received += r.ack_received;
        stream_sent += r.stream_sent;
        stream_received += r.stream_received;
        crypto_sent += r.crypto_sent;
        crypto_received += r.crypto_received;
        ping_sent += r.ping_sent;
        pong_received += r.pong_received;
        return *this;
    }

    FrameStats operator+(const FrameStats &r) const {
        FrameStats out = *this;
        out += r;
        return out;
    }

    bool operator==(const FrameStats &r) const {
        return ack_sent == r.ack_sent && ack_received == r.ack_received &&
               stream_sent == r.stream_sent &&
               stream_received == r.stream_received &&
               crypto_sent == r.crypto_sent &&
               crypto_received == r.crypto_received &&
               ping_sent == r.ping_sent && pong_received == r.pong_received;
    }
};

// ============================================================================
// PathStats — 单条路径统计（14 字段，对标 iroh noq_proto PathStats）
//
// 字段分两类：
//   1. 瞬时状态（gauge）：rtt / cwnd / current_mtu — 不参与 ConnectionStats 累加
//   2. 累计计数器（monotonic counter）：其余字段 — 参与 ConnectionStats 累加
// ============================================================================
struct PathStats {
    // --- 瞬时状态（gauge，不累加）---
    std::chrono::nanoseconds rtt{0};       // 当前 RTT
    std::uint64_t cwnd{0};                 // 当前拥塞窗口
    std::uint16_t current_mtu{0};          // 当前 MTU

    // --- 累计计数器（monotonic，累加）---
    UdpStats udp_tx;                       // UDP 发送
    UdpStats udp_rx;                       // UDP 接收
    FrameStats frame_tx;                   // QUIC 帧发送
    FrameStats frame_rx;                   // QUIC 帧接收
    std::uint64_t congestion_events{0};           // 拥塞事件数
    std::uint64_t spurious_congestion_events{0};  // 误判拥塞事件数
    std::uint64_t lost_packets{0};                // 丢包数
    std::uint64_t lost_bytes{0};                  // 丢字节数
    std::uint64_t sent_plpmtud_probes{0};         // PLPMTUD 探针发送数
    std::uint64_t lost_plpmtud_probes{0};         // PLPMTUD 探针丢失数
    std::uint64_t black_holes_detected{0};        // 黑洞检测次数
};

// ============================================================================
// ConnectionStats — 连接级聚合统计
//
// 仅包含累计计数器字段（剔除 rtt/cwnd/current_mtu 瞬时状态）。
// operator+= 显式忽略 PathStats 的瞬时字段，对标 iroh 的 Add 语义。
// ============================================================================
struct ConnectionStats {
    UdpStats udp_tx;
    UdpStats udp_rx;
    FrameStats frame_tx;
    FrameStats frame_rx;
    std::uint64_t congestion_events{0};
    std::uint64_t spurious_congestion_events{0};
    std::uint64_t lost_packets{0};
    std::uint64_t lost_bytes{0};
    std::uint64_t sent_plpmtud_probes{0};
    std::uint64_t lost_plpmtud_probes{0};
    std::uint64_t black_holes_detected{0};

    // 显式 Add 语义：累加 PathStats 的累计计数器，忽略瞬时状态（rtt/cwnd/current_mtu）
    // 对标 iroh noq_proto: impl Add<PathStats> for ConnectionStats
    ConnectionStats &operator+=(const PathStats &rhs) {
        udp_tx += rhs.udp_tx;
        udp_rx += rhs.udp_rx;
        frame_tx += rhs.frame_tx;
        frame_rx += rhs.frame_rx;
        congestion_events += rhs.congestion_events;
        spurious_congestion_events += rhs.spurious_congestion_events;
        lost_packets += rhs.lost_packets;
        lost_bytes += rhs.lost_bytes;
        sent_plpmtud_probes += rhs.sent_plpmtud_probes;
        lost_plpmtud_probes += rhs.lost_plpmtud_probes;
        black_holes_detected += rhs.black_holes_detected;
        // 注意：rtt / cwnd / current_mtu 为瞬时状态，不累加
        return *this;
    }

    ConnectionStats operator+(const PathStats &rhs) const {
        ConnectionStats out = *this;
        out += rhs;
        return out;
    }

    ConnectionStats &operator+=(const ConnectionStats &rhs) {
        udp_tx += rhs.udp_tx;
        udp_rx += rhs.udp_rx;
        frame_tx += rhs.frame_tx;
        frame_rx += rhs.frame_rx;
        congestion_events += rhs.congestion_events;
        spurious_congestion_events += rhs.spurious_congestion_events;
        lost_packets += rhs.lost_packets;
        lost_bytes += rhs.lost_bytes;
        sent_plpmtud_probes += rhs.sent_plpmtud_probes;
        lost_plpmtud_probes += rhs.lost_plpmtud_probes;
        black_holes_detected += rhs.black_holes_detected;
        return *this;
    }

    bool operator==(const ConnectionStats &r) const {
        return udp_tx == r.udp_tx && udp_rx == r.udp_rx &&
               frame_tx == r.frame_tx && frame_rx == r.frame_rx &&
               congestion_events == r.congestion_events &&
               spurious_congestion_events == r.spurious_congestion_events &&
               lost_packets == r.lost_packets && lost_bytes == r.lost_bytes &&
               sent_plpmtud_probes == r.sent_plpmtud_probes &&
               lost_plpmtud_probes == r.lost_plpmtud_probes &&
               black_holes_detected == r.black_holes_detected;
    }
};

// ============================================================================
// ConnectionStatsAggregator — 订阅 PathEvent 并累加 ConnectionStats
//
// 使用方式：
//   ConnectionStatsAggregator agg;
//   path_migrator.set_path_event_callback([&agg](const PathEvent &ev) {
//       agg.on_path_event(ev);
//   });
//   // 路径放弃时自动累加 last_stats
//   auto stats = agg.snapshot();
// ============================================================================
class ConnectionStatsAggregator {
public:
    // 处理 PathEvent：仅 kClosed 且携带 last_stats 时累加
    void on_path_closed(const PathStats &last_stats) {
        stats_ += last_stats;
    }

    ConnectionStats snapshot() const { return stats_; }

    void reset() { stats_ = ConnectionStats{}; }

private:
    ConnectionStats stats_;
};

}  // namespace linoh::protocol
