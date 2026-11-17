// traffic_priority.hpp — v4.0.5 M23 流量优先级 QoS
//
// ALPN 级流量优先级 + 加权公平队列（WFQ），防止视频/图片大流量通道阻塞
// 控制指令和 hidden_state。控制面（ctrl/1）和 hidden_state（pp-hidden/1）
// 优先发送，低优先级通道按权重公平共享带宽，不会饿死。
//
// 设计要点：
//   - 4 级优先级：Critical > High > Medium > Low
//     ctrl/1     → Critical（控制指令、心跳、Observe、AddrInfo、Auth）
//     pp-hidden/1 → High（LLM hidden_state，推理链路关键数据）
//     pp-audio/1  → Medium（音频流，延迟敏感但带宽小）
//     pp-img/1/pp-video/1/pp-multi/1 → Low（大流量，延迟容忍）
//   - WFQ 加权公平队列：每个优先级一个 FIFO 子队列，按权重 round-robin 出队
//     默认权重 8:4:2:1（Critical:High:Medium:Low），deficit counter 算法
//     保证低优先级最终能获得带宽（不会饿死），同时高优先级优先出队
//   - 与 QUIC STREAM 优先级（RFC 9000 §3.1）对齐：linoh Endpoint 可将
//     TrafficPriority 映射到 QUIC STREAM priority 字段
//   - 配置化：PriorityConfig 可调整权重和 ALPN 映射，支持 encode/decode
//     用于带外公告节点优先级配置（与 ConnectPolicy 一致的序列化风格）
//   - 向后兼容：默认启用但不改变现有发送顺序（同优先级 FIFO），旧节点
//     不使用 WeightedFairQueue 时行为不变
//
// PriorityConfig 编码布局（定长 11 字节）：
//   offset  size  field
//   0       1     version (当前 1)
//   1       1     flags (bit0=enable_wfq, bit1-7 reserved)
//   2       2     critical_weight (小端序, 1-1000)
//   4       2     high_weight (小端序)
//   6       2     medium_weight (小端序)
//   8       2     low_weight (小端序)
//   10      1     quantum (出队单位，默认 1)
//
// 字节序：权重使用小端序（与 connect_policy.hpp / capabilities.hpp 一致）。
// 向后兼容：version 字段允许未来扩展；旧节点忽略 PriorityConfig 走默认权重。

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace linoh::protocol {

/// 流量优先级（4 级，ALPN 级 QoS）
//
// 映射关系（默认）：
//   - Critical(0)：ctrl/1（控制指令、心跳、Observe、AddrInfo、Auth）
//   - High(1)    ：pp-hidden/1（LLM hidden_state）
//   - Medium(2)  ：pp-audio/1（音频流）
//   - Low(3)     ：pp-img/1, pp-video/1, pp-multi/1（大流量模态）
enum class TrafficPriority : std::uint8_t {
    Critical = 0,  // 控制面（最高优先级）
    High     = 1,  // LLM hidden_state
    Medium   = 2,  // 音频
    Low      = 3,  // 图片/视频/融合（大流量）
};

/// 优先级数量常量
inline constexpr std::uint8_t kTrafficPriorityCount = 4;

/// TrafficPriority 转字符串（日志用）
inline const char *to_string(TrafficPriority p) noexcept {
    switch (p) {
        case TrafficPriority::Critical: return "Critical";
        case TrafficPriority::High:     return "High";
        case TrafficPriority::Medium:   return "Medium";
        case TrafficPriority::Low:      return "Low";
    }
    return "Unknown";
}

/// ALPN → TrafficPriority 默认映射
//
//   ctrl/1       → Critical
//   pp-hidden/1  → High
//   pp-llm/1     → High（兼容别名）
//   pp-audio/1   → Medium
//   pp-img/1     → Low
//   pp-video/1   → Low
//   pp-multi/1   → Low
//   其他/未知    → Low（保守降级，避免未知通道抢占关键带宽）
TrafficPriority priority_for_alpn(const std::string &alpn) noexcept;

/// 优先级配置（权重 + 开关）
//
// 用于 WeightedFairQueue 的权重配置和带外公告。
// 默认权重 8:4:2:1，可按场景调整（如纯 LLM 推理可提高 High 权重）。
struct PriorityConfig {
    static constexpr std::uint8_t kCurrentVersion = 1;
    static constexpr std::size_t kEncodedSize = 11;
    static constexpr std::uint16_t kMinWeight = 1;
    static constexpr std::uint16_t kMaxWeight = 1000;

    /// 默认权重常量（8:4:2:1）
    static constexpr std::uint16_t kDefaultCriticalWeight = 8;
    static constexpr std::uint16_t kDefaultHighWeight     = 4;
    static constexpr std::uint16_t kDefaultMediumWeight   = 2;
    static constexpr std::uint16_t kDefaultLowWeight      = 1;

    /// 是否启用 WFQ（false=严格优先级，可能饿死低优先级）
    bool enable_wfq{true};

    /// 各优先级权重（WFQ 出队比例）
    /// 权重越大，每轮获得的出队配额越多
    std::uint16_t critical_weight{kDefaultCriticalWeight};
    std::uint16_t high_weight{kDefaultHighWeight};
    std::uint16_t medium_weight{kDefaultMediumWeight};
    std::uint16_t low_weight{kDefaultLowWeight};

    /// 出队量子（每轮 deficit 增量基数，默认 1）
    /// 实际 deficit 增量 = quantum * weight
    std::uint8_t quantum{1};

    // -------- 工厂方法 --------

    /// 默认配置（8:4:2:1，启用 WFQ）
    static PriorityConfig default_weights();

    /// 严格优先级配置（禁用 WFQ，高优先级完全抢占）
    /// 适用于控制面绝对优先的场景（如故障恢复期）
    static PriorityConfig strict_priority();

    /// 均衡配置（4:4:4:4，所有优先级平等，等价无 QoS）
    /// 适用于带宽充足、无需区分优先级的场景
    static PriorityConfig balanced();

    /// LLM 推理优先配置（Critical:High:Medium:Low = 4:8:2:1）
    /// 提高 hidden_state 权重，适用于纯 LLM 推理链路
    static PriorityConfig llm_inference_priority();

    /// 获取指定优先级的权重
    std::uint16_t weight_of(TrafficPriority p) const noexcept;

    /// 设置指定优先级的权重（自动夹紧到 [kMinWeight, kMaxWeight]）
    void set_weight(TrafficPriority p, std::uint16_t w) noexcept;

    // -------- 序列化（用于配置传播） --------

    /// 序列化为字节流（定长 11 字节）
    std::vector<std::uint8_t> encode() const;

    /// 从字节流反序列化
    /// @return true=成功，false=数据格式错误（长度不足/version 不匹配/权重越界）
    static bool decode(std::span<const std::uint8_t> data, PriorityConfig &out);

    /// 简要描述（日志用）
    std::string to_string() const;

    /// 相等比较（测试用）
    bool operator==(const PriorityConfig &other) const noexcept {
        return enable_wfq == other.enable_wfq &&
               critical_weight == other.critical_weight &&
               high_weight == other.high_weight &&
               medium_weight == other.medium_weight &&
               low_weight == other.low_weight &&
               quantum == other.quantum;
    }
};

/// 队列项（泛型优先级队列元素）
//
// 携带优先级和数据，用于 WeightedFairQueue 入队。
// item_id 用于统计和追踪（可选，0=未追踪）。
struct QueueItem {
    TrafficPriority priority{TrafficPriority::Low};
    std::uint64_t item_id{0};        // 用户自定义标识（如 packet_number / stream_id）
    std::size_t size{1};             // 项大小（字节数，用于 WFQ deficit 计算）
    std::vector<std::uint8_t> data;  // 实际数据载荷
};

/// 加权公平队列（WFQ）
//
// 4 个 FIFO 子队列（每个优先级一个），按 WFQ 算法出队：
//   - 每个子队列维护一个 deficit counter
//   - 每轮按优先级顺序（Critical → Low）尝试出队
//   - deficit += quantum * weight
//   - 若 deficit ≥ item.size，出队并 deficit -= item.size
//   - 若 deficit < item.size 或队列为空，跳过该子队列
//   - 所有子队列空时停止
//
// WFQ 保证：
//   - 高优先级优先出队（weight 大，deficit 增长快）
//   - 低优先级不会饿死（每轮 deficit 都会增长，最终能出队）
//   - 同优先级 FIFO（子队列内部按入队顺序出队）
//
// 线程安全：所有公共方法加 mutex 保护。
class WeightedFairQueue {
public:
    /// per-priority 统计
    struct PriorityStats {
        std::uint64_t enqueued{0};   // 累计入队数
        std::uint64_t dequeued{0};   // 累计出队数
        std::uint64_t bytes_enqueued{0};
        std::uint64_t bytes_dequeued{0};
        std::size_t current_size{0};  // 当前队列内项数
    };

    /// 队列整体统计
    struct Stats {
        std::array<PriorityStats, kTrafficPriorityCount> per_priority;
        std::uint64_t total_enqueued{0};
        std::uint64_t total_dequeued{0};
        std::uint64_t total_bytes_enqueued{0};
        std::uint64_t total_bytes_dequeued{0};
        std::uint64_t starvation_avoided_count{0};  // WFQ 防饿死触发次数
                                          //（低优先级因 deficit 累积出队的次数）
    };

    /// 构造（使用默认配置）
    WeightedFairQueue();
    /// 构造（自定义配置）
    explicit WeightedFairQueue(PriorityConfig config);

    /// 获取配置
    PriorityConfig config() const;
    /// 更新配置（运行时调整权重，保留队列内容和 deficit）
    void set_config(const PriorityConfig &config);

    /// 入队（线程安全）
    /// @param item 队列项（priority + data + size）
    void enqueue(QueueItem item);

    /// 便捷入队（按 ALPN 自动判定优先级）
    void enqueue_for_alpn(const std::string &alpn, std::vector<std::uint8_t> data,
                          std::uint64_t item_id = 0);

    /// 出队（WFQ 算法）
    /// @return nullopt 如果所有队列空；否则返回队首项
    std::optional<QueueItem> dequeue();

    /// 查看队首但不移除（仅用于诊断）
    std::optional<QueueItem> peek() const;

    /// 队列总大小（所有优先级之和）
    std::size_t size() const;

    /// 指定优先级的队列大小
    std::size_t size_of(TrafficPriority p) const;

    /// 队列是否为空
    bool empty() const;

    /// 清空所有队列（重置 deficit 和统计的 current_size，保留累计计数）
    void clear();

    /// 获取统计
    Stats stats() const;

    /// 重置 deficit counter（用于权重变更后重新开始 WFQ 轮次）
    void reset_deficit();

private:
    /// 执行一次 WRR 出队（内部，不加锁）
    /// @return nullopt 如果所有队列空；否则返回出队项
    std::optional<QueueItem> dequeue_wrr_();

    /// 内部不加锁的 empty 检查（供持锁方法调用，避免死锁）
    bool empty_unlocked_() const noexcept {
        for (std::size_t i = 0; i < kTrafficPriorityCount; ++i) {
            if (!queues_[i].empty()) return false;
        }
        return true;
    }

    mutable std::mutex mu_;
    PriorityConfig config_;
    std::array<std::deque<QueueItem>, kTrafficPriorityCount> queues_;
    std::array<std::int64_t, kTrafficPriorityCount> deficit_{};
    std::uint64_t rr_counter_{0};  ///< WRR round-robin 计数器
    Stats stats_;
};

}  // namespace linoh::protocol
