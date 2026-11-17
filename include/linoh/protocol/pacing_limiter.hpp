// linoh/protocol/pacing_limiter.hpp — BBR v2 pacing 令牌桶限速器
//
// v3.9.0: 将 BBR pacing_rate_bps 从诊断值落地为实际发送限速。
//
// 背景：
//   bbr_v2.hpp 原注释（line 26）"pacing_rate 暂未用于实际 pacing，仅诊断/日志"。
//   v3.9.0 引入 PacingLimiter，在 BbrV2Controller::can_send() 中接入令牌桶限速，
//   使发送速率不超过 pacing_rate_bps，防 burst 丢包（跨域长肥管道收益显著）。
//
// 设计：
//   - 令牌桶（token bucket）懒补充：每次 try_consume 基于时间差补充令牌
//   - 桶容量 = 2 * pacing_rate * rtt（允许 2 倍 BDP 突发，防过严限速降低吞吐）
//   - 线程安全：内部 mutex 保护（can_send 在发送路径，on_ack 在 ACK 路径，可能并发）
//   - 速率单位：bytes/sec（与 BBR max_bw_bps_ / pacing_rate_bps_ 一致）
//   - header-only：隐式 inline，无需独立 .cpp，便于测试与复用
//
// 集成点：
//   - BbrV2Controller::recalculate() 末尾调用 configure() 更新速率与桶容量
//   - BbrV2Controller::can_send() 在 cwnd 检查通过后调用 try_consume()
//   - BbrV2Controller::reset() 调用 reset() 清理状态
//
// 兼容性：
//   - pacing_rate_bps=0 时 try_consume 直接放行（等价于未启用 pacing）
//   - NewReno 不持有 PacingLimiter，行为不变

#pragma once

#include <cstdint>
#include <mutex>

namespace linoh::protocol {

/// Pacing 令牌桶限速器（v3.9.0）。
///
/// 将 BBR 计算的 pacing_rate_bps 落地为实际发送速率限制。
/// 令牌桶模型允许突发（bucket = 2×BDP），避免严格匀速降低吞吐。
class PacingLimiter {
public:
    PacingLimiter() = default;

    /// 配置 pacing 速率和 RTT，重算桶容量。
    /// @param pacing_rate_bps 速率（bytes/sec），0 表示禁用限速
    /// @param rtt_ms 当前 RTT（毫秒），用于计算桶容量（2 × pacing_rate × rtt）
    void configure(std::uint64_t pacing_rate_bps, double rtt_ms) {
        std::lock_guard<std::mutex> lock(mutex_);
        pacing_rate_bps_ = pacing_rate_bps;
        if (pacing_rate_bps > 0 && rtt_ms > 0.0) {
            // 桶容量 = 2 * pacing_rate(bytes/sec) * rtt(sec)
            // 允许 2 倍 BDP 突发，平衡限速与吞吐
            double rtt_sec = rtt_ms / 1000.0;
            double capacity = 2.0 * static_cast<double>(pacing_rate_bps) * rtt_sec;
            // 防溢出：上限 64MB（足够 1Gbps × 500ms 的 BDP）
            if (capacity > 67108864.0) capacity = 67108864.0;
            bucket_capacity_bytes_ = static_cast<std::uint64_t>(capacity);
            if (!configured_) {
                // 首次 configure：初始令牌 = 桶容量（允许首包突发，防启动阶段限速饿死）
                tokens_ = bucket_capacity_bytes_;
            } else if (tokens_ > bucket_capacity_bytes_) {
                // reconfigure：令牌截断到新容量（不重置，避免限速失效）
                tokens_ = bucket_capacity_bytes_;
            }
        } else {
            bucket_capacity_bytes_ = 0;
            tokens_ = 0;
        }
        configured_ = true;
    }

    /// 检查是否允许发送 bytes 字节。
    /// 令牌桶懒补充：基于上次检查到现在的时间差补充令牌，然后尝试扣减。
    /// @param bytes 待发送字节数
    /// @param now_ms 当前单调时钟（毫秒），由调用方传入便于测试注入
    /// @return true 表示允许发送（已扣减令牌），false 表示速率受限
    bool try_consume(std::uint64_t bytes, double now_ms) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pacing_rate_bps_ == 0 || bucket_capacity_bytes_ == 0) {
            return true;  // 未启用限速，放行
        }
        // 懒补充令牌：基于上次 refill 到现在的时间差
        if (last_refill_ms_ > 0.0) {
            double elapsed_sec = (now_ms - last_refill_ms_) / 1000.0;
            if (elapsed_sec > 0.0) {
                double refill = elapsed_sec * static_cast<double>(pacing_rate_bps_);
                double new_tokens = static_cast<double>(tokens_) + refill;
                if (new_tokens > static_cast<double>(bucket_capacity_bytes_)) {
                    new_tokens = static_cast<double>(bucket_capacity_bytes_);
                }
                tokens_ = static_cast<std::uint64_t>(new_tokens);
            }
        }
        last_refill_ms_ = now_ms;

        // 尝试扣减令牌
        if (tokens_ >= bytes) {
            tokens_ -= bytes;
            return true;
        }
        return false;
    }

    /// 是否已启用限速（已 configure 且 pacing_rate > 0）。
    bool enabled() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return configured_ && pacing_rate_bps_ > 0;
    }

    /// 当前可用令牌数（诊断用）
    std::uint64_t tokens_available() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return tokens_;
    }

    /// 当前桶容量（诊断用）
    std::uint64_t bucket_capacity() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return bucket_capacity_bytes_;
    }

    /// 当前 pacing 速率（bytes/sec，诊断用）
    std::uint64_t pacing_rate_bps() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pacing_rate_bps_;
    }

    /// 重置（连接恢复 / reset 时调用）
    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        pacing_rate_bps_ = 0;
        bucket_capacity_bytes_ = 0;
        tokens_ = 0;
        last_refill_ms_ = 0.0;
        configured_ = false;
    }

private:
    mutable std::mutex mutex_;
    std::uint64_t pacing_rate_bps_{0};        ///< 速率（bytes/sec）
    std::uint64_t bucket_capacity_bytes_{0};  ///< 桶容量（字节）= 2 × pacing_rate × rtt
    std::uint64_t tokens_{0};                 ///< 当前令牌数
    double last_refill_ms_{0.0};              ///< 上次补充令牌的单调时间（毫秒）
    bool configured_{false};                  ///< 是否已 configure
};

} // namespace linoh::protocol
