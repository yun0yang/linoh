// traffic_priority.cpp — v4.0.5 M23 流量优先级 QoS 实现
//
// 实现 ALPN → 优先级映射、PriorityConfig 序列化、WeightedFairQueue WFQ 出队算法。

#include "linoh/protocol/traffic_priority.hpp"

#include <cstring>

namespace linoh::protocol {

// ============================================================================
// ALPN → TrafficPriority 映射
// ============================================================================

TrafficPriority priority_for_alpn(const std::string &alpn) noexcept {
    if (alpn == "ctrl/1") return TrafficPriority::Critical;
    if (alpn == "pp-hidden/1") return TrafficPriority::High;
    if (alpn == "pp-llm/1") return TrafficPriority::High;  // 兼容别名
    if (alpn == "pp-audio/1") return TrafficPriority::Medium;
    // pp-img/1 / pp-video/1 / pp-multi/1 / 其他 → Low
    return TrafficPriority::Low;
}

// ============================================================================
// PriorityConfig
// ============================================================================

PriorityConfig PriorityConfig::default_weights() {
    return PriorityConfig{};
}

PriorityConfig PriorityConfig::strict_priority() {
    PriorityConfig p;
    p.enable_wfq = false;  // 禁用 WFQ，严格优先级
    // 权重保持默认，但 enable_wfq=false 时退化为严格优先级出队
    return p;
}

PriorityConfig PriorityConfig::balanced() {
    PriorityConfig p;
    p.critical_weight = 4;
    p.high_weight = 4;
    p.medium_weight = 4;
    p.low_weight = 4;
    return p;
}

PriorityConfig PriorityConfig::llm_inference_priority() {
    PriorityConfig p;
    p.critical_weight = 4;
    p.high_weight = 8;  // hidden_state 权重最高
    p.medium_weight = 2;
    p.low_weight = 1;
    return p;
}

std::uint16_t PriorityConfig::weight_of(TrafficPriority p) const noexcept {
    switch (p) {
        case TrafficPriority::Critical: return critical_weight;
        case TrafficPriority::High:     return high_weight;
        case TrafficPriority::Medium:   return medium_weight;
        case TrafficPriority::Low:      return low_weight;
    }
    return low_weight;
}

void PriorityConfig::set_weight(TrafficPriority p, std::uint16_t w) noexcept {
    if (w < kMinWeight) w = kMinWeight;
    if (w > kMaxWeight) w = kMaxWeight;
    switch (p) {
        case TrafficPriority::Critical: critical_weight = w; break;
        case TrafficPriority::High:     high_weight = w; break;
        case TrafficPriority::Medium:   medium_weight = w; break;
        case TrafficPriority::Low:      low_weight = w; break;
    }
}

std::vector<std::uint8_t> PriorityConfig::encode() const {
    std::vector<std::uint8_t> out;
    out.reserve(kEncodedSize);

    // 夹紧权重到合法范围（编码时确保数据合法）
    auto clamped = [](std::uint16_t w) {
        if (w < kMinWeight) return kMinWeight;
        if (w > kMaxWeight) return kMaxWeight;
        return w;
    };

    out.push_back(kCurrentVersion);
    out.push_back(enable_wfq ? 0x01 : 0x00);

    auto push_u16_le = [&out](std::uint16_t v) {
        out.push_back(static_cast<std::uint8_t>(v & 0xFF));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    };
    push_u16_le(clamped(critical_weight));
    push_u16_le(clamped(high_weight));
    push_u16_le(clamped(medium_weight));
    push_u16_le(clamped(low_weight));

    out.push_back(quantum);
    return out;
}

bool PriorityConfig::decode(std::span<const std::uint8_t> data, PriorityConfig &out) {
    if (data.size() < kEncodedSize) return false;
    if (data[0] != kCurrentVersion) return false;

    PriorityConfig tmp;
    tmp.enable_wfq = (data[1] & 0x01) != 0;

    auto read_u16_le = [&data](std::size_t offset) -> std::uint16_t {
        return static_cast<std::uint16_t>(data[offset]) |
               (static_cast<std::uint16_t>(data[offset + 1]) << 8);
    };
    tmp.critical_weight = read_u16_le(2);
    tmp.high_weight     = read_u16_le(4);
    tmp.medium_weight   = read_u16_le(6);
    tmp.low_weight      = read_u16_le(8);
    tmp.quantum         = data[10];

    // 权重合法性校验
    auto valid_weight = [](std::uint16_t w) { return w >= kMinWeight && w <= kMaxWeight; };
    if (!valid_weight(tmp.critical_weight) ||
        !valid_weight(tmp.high_weight) ||
        !valid_weight(tmp.medium_weight) ||
        !valid_weight(tmp.low_weight)) {
        return false;
    }

    out = tmp;
    return true;
}

std::string PriorityConfig::to_string() const {
    return std::string("PriorityConfig{wfq=") +
           (enable_wfq ? "on" : "off") +
           ", weights=" + std::to_string(critical_weight) + ":" +
           std::to_string(high_weight) + ":" +
           std::to_string(medium_weight) + ":" +
           std::to_string(low_weight) +
           ", quantum=" + std::to_string(quantum) + "}";
}

// ============================================================================
// WeightedFairQueue
// ============================================================================

WeightedFairQueue::WeightedFairQueue() = default;

WeightedFairQueue::WeightedFairQueue(PriorityConfig config)
    : config_(config) {
    deficit_.fill(0);
}

PriorityConfig WeightedFairQueue::config() const {
    std::lock_guard<std::mutex> lk(mu_);
    return config_;
}

void WeightedFairQueue::set_config(const PriorityConfig &config) {
    std::lock_guard<std::mutex> lk(mu_);
    config_ = config;
    // 不重置 deficit，保留当前轮次进度（平滑过渡）
}

void WeightedFairQueue::enqueue(QueueItem item) {
    std::lock_guard<std::mutex> lk(mu_);
    auto idx = static_cast<std::size_t>(item.priority);
    if (idx >= kTrafficPriorityCount) {
        idx = static_cast<std::size_t>(TrafficPriority::Low);
        item.priority = TrafficPriority::Low;
    }
    auto &s = stats_.per_priority[idx];
    s.enqueued++;
    s.bytes_enqueued += item.size;
    s.current_size++;
    stats_.total_enqueued++;
    stats_.total_bytes_enqueued += item.size;
    queues_[idx].push_back(std::move(item));
}

void WeightedFairQueue::enqueue_for_alpn(const std::string &alpn,
                                          std::vector<std::uint8_t> data,
                                          std::uint64_t item_id) {
    QueueItem item;
    item.priority = priority_for_alpn(alpn);
    item.item_id = item_id;
    item.size = data.size();
    item.data = std::move(data);
    enqueue(std::move(item));
}

std::optional<QueueItem> WeightedFairQueue::dequeue() {
    std::lock_guard<std::mutex> lk(mu_);
    if (empty_unlocked_()) return std::nullopt;

    // WFQ 模式：加权 round-robin（WRR）出队
    if (config_.enable_wfq) {
        return dequeue_wrr_();
    }

    // 严格优先级模式（enable_wfq=false）：从 Critical 到 Low 找第一个非空队列
    for (std::size_t i = 0; i < kTrafficPriorityCount; ++i) {
        if (!queues_[i].empty()) {
            auto item = std::move(queues_[i].front());
            queues_[i].pop_front();
            auto &s = stats_.per_priority[i];
            s.dequeued++;
            s.bytes_dequeued += item.size;
            s.current_size--;
            stats_.total_dequeued++;
            stats_.total_bytes_dequeued += item.size;
            return item;
        }
    }
    return std::nullopt;
}

std::optional<QueueItem> WeightedFairQueue::peek() const {
    std::lock_guard<std::mutex> lk(mu_);
    // 两种模式都返回最高优先级非空队首（peek 不影响 WRR 状态）
    for (std::size_t i = 0; i < kTrafficPriorityCount; ++i) {
        if (!queues_[i].empty()) return queues_[i].front();
    }
    return std::nullopt;
}

std::size_t WeightedFairQueue::size() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::size_t total = 0;
    for (std::size_t i = 0; i < kTrafficPriorityCount; ++i) {
        total += queues_[i].size();
    }
    return total;
}

std::size_t WeightedFairQueue::size_of(TrafficPriority p) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto idx = static_cast<std::size_t>(p);
    if (idx >= kTrafficPriorityCount) return 0;
    return queues_[idx].size();
}

bool WeightedFairQueue::empty() const {
    std::lock_guard<std::mutex> lk(mu_);
    for (std::size_t i = 0; i < kTrafficPriorityCount; ++i) {
        if (!queues_[i].empty()) return false;
    }
    return true;
}

void WeightedFairQueue::clear() {
    std::lock_guard<std::mutex> lk(mu_);
    for (std::size_t i = 0; i < kTrafficPriorityCount; ++i) {
        queues_[i].clear();
        stats_.per_priority[i].current_size = 0;
    }
    deficit_.fill(0);
}

WeightedFairQueue::Stats WeightedFairQueue::stats() const {
    std::lock_guard<std::mutex> lk(mu_);
    // 更新 current_size（保持一致）
    Stats s = stats_;
    for (std::size_t i = 0; i < kTrafficPriorityCount; ++i) {
        s.per_priority[i].current_size = queues_[i].size();
    }
    return s;
}

void WeightedFairQueue::reset_deficit() {
    std::lock_guard<std::mutex> lk(mu_);
    deficit_.fill(0);
}

std::optional<QueueItem> WeightedFairQueue::dequeue_wrr_() {
    // 内部方法，调用者已持锁
    // 加权 round-robin（WRR）：按权重比例分配出队机会
    //
    // 算法：
    //   1. 计算总权重 total = sum(weights)
    //   2. pos = rr_counter_ % total
    //   3. 根据 pos 落在的区间决定首选优先级
    //   4. 如果首选队列空，降级到下一个优先级（向下）
    //
    // 例如权重 8:4:2:1，total=15：
    //   pos in [0,8)  → Critical
    //   pos in [8,12) → High
    //   pos in [12,14)→ Medium
    //   pos in [14,15)→ Low

    std::uint64_t total = static_cast<std::uint64_t>(config_.critical_weight) +
                          static_cast<std::uint64_t>(config_.high_weight) +
                          static_cast<std::uint64_t>(config_.medium_weight) +
                          static_cast<std::uint64_t>(config_.low_weight);
    if (total == 0) total = 1;  // 防御性兜底

    std::uint64_t pos = rr_counter_ % total;
    ++rr_counter_;

    // 计算首选优先级
    std::size_t preferred;
    std::uint64_t acc = 0;
    if (pos < (acc += config_.critical_weight)) {
        preferred = static_cast<std::size_t>(TrafficPriority::Critical);
    } else if (pos < (acc += config_.high_weight)) {
        preferred = static_cast<std::size_t>(TrafficPriority::High);
    } else if (pos < (acc += config_.medium_weight)) {
        preferred = static_cast<std::size_t>(TrafficPriority::Medium);
    } else {
        preferred = static_cast<std::size_t>(TrafficPriority::Low);
    }

    // 从首选优先级开始，向下寻找第一个非空队列
    std::size_t chosen = kTrafficPriorityCount;
    for (std::size_t i = preferred; i < kTrafficPriorityCount; ++i) {
        if (!queues_[i].empty()) {
            chosen = i;
            break;
        }
    }
    // 如果首选及更低都空，向上寻找（回绕到更高优先级）
    if (chosen == kTrafficPriorityCount) {
        for (std::size_t i = 0; i < preferred; ++i) {
            if (!queues_[i].empty()) {
                chosen = i;
                break;
            }
        }
    }
    if (chosen == kTrafficPriorityCount) {
        return std::nullopt;  // 所有队列空
    }

    // 出队
    auto item = std::move(queues_[chosen].front());
    queues_[chosen].pop_front();

    auto &s = stats_.per_priority[chosen];
    s.dequeued++;
    s.bytes_dequeued += item.size;
    s.current_size--;
    stats_.total_dequeued++;
    stats_.total_bytes_dequeued += item.size;

    // 防饿死统计：低优先级（Medium/Low）出队且更高优先级队列非空
    if (chosen == static_cast<std::size_t>(TrafficPriority::Medium) ||
        chosen == static_cast<std::size_t>(TrafficPriority::Low)) {
        bool has_higher = false;
        for (std::size_t j = 0; j < chosen; ++j) {
            if (!queues_[j].empty()) {
                has_higher = true;
                break;
            }
        }
        if (has_higher) {
            stats_.starvation_avoided_count++;
        }
    }
    return item;
}

}  // namespace linoh::protocol
