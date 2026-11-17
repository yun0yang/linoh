// rate_limiter.hpp — 令牌桶速率限制器（P4-C-2）
//
// 借鉴 iroh PR #4242（Expose Bucket rate-limit primitive）：
//   - TokenBucket：令牌桶算法，支持容量上限 + 持续补充
//   - RateLimiter：per-client 隔离的双桶（字节桶 + 请求桶）
//
// 用途：
//   - Relay Server 限制单个客户端的带宽和请求频率
//   - Endpoint 限制出站连接频率
//   - 任意需要按 key 隔离的限流场景

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace linoh::util {

/// 令牌桶速率限制器（借鉴 iroh Bucket rate-limit primitive）
///
/// 桶容量 = capacity（最大突发量）
/// 补充速率 = refill_rate per second
/// try_consume(n)：若桶中令牌 >= n 则消费并返回 true，否则返回 false
///
/// 线程安全：内部 mutex 保护。
class TokenBucket {
public:
    /// @param capacity 桶容量（字节或请求数，最大突发量）
    /// @param refill_rate 每秒补充速率
    TokenBucket(std::uint64_t capacity, std::uint64_t refill_rate);

    /// 尝试消费 n 个令牌
    /// @return true 若桶中令牌 >= n，消费成功
    ///         false 若令牌不足，桶状态不变
    bool try_consume(std::uint64_t n = 1);

    /// 当前剩余令牌数（线程安全快照）
    std::uint64_t available() const;

    /// 桶容量
    std::uint64_t capacity() const { return capacity_; }

    /// 补充速率（每秒）
    std::uint64_t refill_rate() const { return refill_rate_; }

    /// 重置桶到满状态
    void reset();

    /// v1.7.0.2 P1: 热更新桶容量和补充速率
    /// @param new_capacity 新容量（0 视为 1）
    /// @param new_refill_rate 新补充速率（每秒）
    /// @note 令牌数不重置：若当前 tokens > new_capacity，截断到 new_capacity
    ///       （避免热更新后突发流量）；last_refill_ 重置为当前时间
    void set_rate(std::uint64_t new_capacity, std::uint64_t new_refill_rate);

    /// 上次访问时间（用于 idle 清理）
    std::chrono::steady_clock::time_point last_access() const;

private:
    /// 按时间补充令牌（调用前需持有 mutex_）
    void refill_locked() const;

    mutable std::mutex mutex_;
    std::uint64_t capacity_;
    std::uint64_t refill_rate_;
    mutable std::uint64_t tokens_;
    mutable std::chrono::steady_clock::time_point last_refill_;
    mutable std::chrono::steady_clock::time_point last_access_;
};

/// Per-client 速率限制管理器
///
/// 为每个客户端维护两个桶：字节桶 + 请求桶
/// - 字节桶：限制带宽（bytes per second）
/// - 请求桶：限制请求频率（requests per second）
///
/// 线程安全：shared_mutex 保护，read 用 shared_lock，write 用 unique_lock
class RateLimiter {
public:
    /// @param bytes_per_second_per_client 每客户端每秒字节数
    /// @param requests_per_second_per_client 每客户端每秒请求数
    RateLimiter(std::uint64_t bytes_per_second_per_client,
                std::uint64_t requests_per_second_per_client);

    /// 尝试消费 n 字节（带宽限制）
    /// @param client_key 客户端标识（IP:Port 或 EndpointId hex）
    /// @param n 欲消费的字节数
    /// @return true 若允许，false 若超限
    bool try_consume_bytes(const std::string &client_key, std::uint64_t n);

    /// 尝试消费 1 个请求（频率限制）
    /// @param client_key 客户端标识
    /// @return true 若允许，false 若超限
    bool try_consume_request(const std::string &client_key);

    /// 获取指定客户端的字节桶（不存在则创建）
    TokenBucket &get_bytes_bucket(const std::string &client_key);

    /// 获取指定客户端的请求桶（不存在则创建）
    TokenBucket &get_requests_bucket(const std::string &client_key);

    /// 清理长时间无活动的客户端
    /// @param idle 超过此时间的客户端被清理（默认 5 分钟）
    /// @note 接受任意 chrono::duration 类型（seconds/milliseconds/minutes 等）
    template <typename Rep, typename Period>
    std::size_t cleanup_idle(std::chrono::duration<Rep, Period> idle) {
        return cleanup_idle_impl(std::chrono::duration_cast<std::chrono::milliseconds>(idle));
    }

    std::size_t cleanup_idle() {
        return cleanup_idle_impl(std::chrono::minutes(5));
    }

    /// 当前跟踪的客户端数量
    std::size_t client_count() const;

    /// v1.7.0.2 P1: 热更新所有限流配置
    /// @param new_bps 新的每客户端每秒字节数
    /// @param new_rps 新的每客户端每秒请求数
    /// @param update_existing_buckets true=同步更新已存在的桶；false=仅影响后续新创建的桶
    /// @note 热更新不重置已有桶的令牌数（若超过新容量会被截断）
    void set_rates(std::uint64_t new_bps, std::uint64_t new_rps,
                   bool update_existing_buckets = true);

    /// 配置参数
    std::uint64_t bytes_per_second() const { return bps_; }
    std::uint64_t requests_per_second() const { return rps_; }

private:
    struct ClientBuckets {
        std::unique_ptr<TokenBucket> bytes;
        std::unique_ptr<TokenBucket> requests;
    };

    /// cleanup_idle 实现内部接口（milliseconds 精度）
    std::size_t cleanup_idle_impl(std::chrono::milliseconds idle);

    mutable std::shared_mutex mutex_;
    std::uint64_t bps_;
    std::uint64_t rps_;
    std::unordered_map<std::string, ClientBuckets> buckets_;
};

} // namespace linoh::util
