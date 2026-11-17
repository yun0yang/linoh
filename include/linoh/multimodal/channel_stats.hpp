// channel_stats.hpp — 通道公平性计数器（v1.7.0.2 P1 / B4）
//
// 借鉴 iroh v1.0.3 NetMetrics 思路（全局字节数统计），扩展为按 ChannelType 维度：
//   - 多模态场景下视频/图片/LLM hidden_state 共享同一 Endpoint
//   - 调度器需要 per-channel 字节/包/丢包 统计用于公平性决策
//   - 现有 ConnectionStats 仅 per-connection 全局，缺少 per-channel 维度
//
// 设计：
//   - ChannelStatsRegistry 按 ChannelType 维度聚合所有连接的统计
//   - 写路径：atomic fetch_add(memory_order_relaxed)，无锁
//   - 读路径：snapshot/all_snapshots/fairness_ratio 用 mutex 保证一次性一致性
//   - fairness_ratio 排除 CONTROL 通道（控制信道不计入数据公平性）
//
// 与 ChannelConfig/ALPN 解耦：仅按 ChannelType 枚举维度统计，不绑定具体 ALPN

#pragma once

#include "linoh/multimodal/channel.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace linoh::multimodal {

/// 单通道统计快照（值类型，可拷贝）
struct ChannelStatsSnapshot {
    ChannelType type{ChannelType::CONTROL};
    std::uint64_t bytes_sent{0};
    std::uint64_t bytes_received{0};
    std::uint64_t packets_sent{0};
    std::uint64_t packets_received{0};
    std::uint64_t lost_packets{0};
};

/// 通道公平性计数器注册表
///
/// 按 ChannelType 维度聚合所有连接的统计，线程安全。
/// 写路径使用 atomic（无锁），读路径使用 mutex 保证一次性快照一致性。
class ChannelStatsRegistry {
public:
    ChannelStatsRegistry();
    ~ChannelStatsRegistry();

    ChannelStatsRegistry(const ChannelStatsRegistry &) = delete;
    ChannelStatsRegistry &operator=(const ChannelStatsRegistry &) = delete;

    /// 记录一次发送
    /// @param type 通道类型
    /// @param bytes 发送字节数
    /// @param packets 发送包数（默认 1）
    void record_send(ChannelType type, std::uint64_t bytes, std::uint64_t packets = 1);

    /// 记录一次接收
    /// @param type 通道类型
    /// @param bytes 接收字节数
    /// @param packets 接收包数（默认 1）
    void record_recv(ChannelType type, std::uint64_t bytes, std::uint64_t packets = 1);

    /// 记录丢包
    /// @param type 通道类型
    /// @param count 丢包数（默认 1）
    void record_loss(ChannelType type, std::uint64_t count = 1);

    /// 获取指定通道的快照
    ChannelStatsSnapshot snapshot(ChannelType type) const;

    /// 获取所有通道快照（按 ChannelType 枚举顺序，共 9 个）
    std::vector<ChannelStatsSnapshot> all_snapshots() const;

    /// 公平性指标：max(bytes_sent) / min(bytes_sent)（排除 CONTROL）
    /// @return 公平性比率（≥1.0）：
    ///         - 1.0 表示所有数据通道字节数相等（完全公平）或全部为 0
    ///         - >1.0 表示存在不均衡，值越大越不公平
    /// @note 仅统计 bytes_sent 维度（出站方向）；接收方向可类似实现
    double fairness_ratio() const;

    /// 重置所有计数器（主要用于测试和重连场景）
    void reset();

private:
    // ChannelType 枚举值 0..8，共 9 个
    static constexpr std::size_t kChannelCount = 9;

    struct Counters {
        std::atomic<std::uint64_t> bytes_sent{0};
        std::atomic<std::uint64_t> bytes_received{0};
        std::atomic<std::uint64_t> packets_sent{0};
        std::atomic<std::uint64_t> packets_received{0};
        std::atomic<std::uint64_t> lost_packets{0};
    };

    /// ChannelType → 数组索引（防御性：未知值返回 CONTROL 索引 0）
    static std::size_t index_of(ChannelType t) {
        auto v = static_cast<std::size_t>(t);
        return v < kChannelCount ? v : 0;
    }

    mutable std::mutex snapshot_mu_;  // 仅保护 snapshot 读取一致性
    std::array<Counters, kChannelCount> counters_;
};

} // namespace linoh::multimodal
