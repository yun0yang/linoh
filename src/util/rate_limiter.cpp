// rate_limiter.cpp — 令牌桶速率限制器实现（P4-C-2）

#include "linoh/util/rate_limiter.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>

namespace linoh::util {

// ============================================================================
// TokenBucket
// ============================================================================

TokenBucket::TokenBucket(std::uint64_t capacity, std::uint64_t refill_rate)
    : capacity_(capacity == 0 ? 1 : capacity),
      refill_rate_(refill_rate),
      tokens_(capacity == 0 ? 1 : capacity),  // 初始满桶（容量 0 时为 1）
      last_refill_(std::chrono::steady_clock::now()),
      last_access_(std::chrono::steady_clock::now()) {
}

void TokenBucket::refill_locked() const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_refill_);
    if (elapsed.count() == 0) return;

    // 按毫秒粒度补充令牌，避免高频调用时被秒级截断
    double ms = static_cast<double>(elapsed.count());
    double tokens_to_add = (ms / 1000.0) * static_cast<double>(refill_rate_);

    if (tokens_to_add < 1.0) {
        // 不足 1 个令牌，等待更多时间累积
        return;
    }

    std::uint64_t add = static_cast<std::uint64_t>(tokens_to_add);
    std::uint64_t new_tokens = tokens_ + add;
    if (new_tokens > capacity_ || new_tokens < tokens_) {
        new_tokens = capacity_;  // 截断或防溢出
    }

    tokens_ = new_tokens;
    last_refill_ = now;
}

bool TokenBucket::try_consume(std::uint64_t n) {
    if (n == 0) return true;

    std::lock_guard<std::mutex> lk(mutex_);
    last_access_ = std::chrono::steady_clock::now();
    refill_locked();

    if (tokens_ >= n) {
        tokens_ -= n;
        return true;
    }
    return false;
}

std::uint64_t TokenBucket::available() const {
    std::lock_guard<std::mutex> lk(mutex_);
    refill_locked();
    return tokens_;
}

void TokenBucket::reset() {
    std::lock_guard<std::mutex> lk(mutex_);
    tokens_ = capacity_;
    last_refill_ = std::chrono::steady_clock::now();
    last_access_ = std::chrono::steady_clock::now();
}

// v1.7.0.2 P1: 热更新桶容量和补充速率
void TokenBucket::set_rate(std::uint64_t new_capacity, std::uint64_t new_refill_rate) {
    std::lock_guard<std::mutex> lk(mutex_);
    capacity_ = (new_capacity == 0) ? 1 : new_capacity;
    refill_rate_ = new_refill_rate;
    // 若当前令牌超过新容量，截断（避免热更新后突发）
    if (tokens_ > capacity_) {
        tokens_ = capacity_;
    }
    // 重置补充时间基准，避免下次 refill 用旧时间戳一次性补满
    last_refill_ = std::chrono::steady_clock::now();
    last_access_ = last_refill_;
}

std::chrono::steady_clock::time_point TokenBucket::last_access() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return last_access_;
}

// ============================================================================
// RateLimiter
// ============================================================================

RateLimiter::RateLimiter(std::uint64_t bytes_per_second_per_client,
                         std::uint64_t requests_per_second_per_client)
    : bps_(bytes_per_second_per_client),
      rps_(requests_per_second_per_client) {}

bool RateLimiter::try_consume_bytes(const std::string &client_key, std::uint64_t n) {
    return get_bytes_bucket(client_key).try_consume(n);
}

bool RateLimiter::try_consume_request(const std::string &client_key) {
    return get_requests_bucket(client_key).try_consume(1);
}

TokenBucket &RateLimiter::get_bytes_bucket(const std::string &client_key) {
    // 双重检查：先 shared_lock 查找，未命中再 unique_lock 创建
    {
        std::shared_lock<std::shared_mutex> lk(mutex_);
        auto it = buckets_.find(client_key);
        if (it != buckets_.end()) {
            return *it->second.bytes;
        }
    }
    std::unique_lock<std::shared_mutex> lk(mutex_);
    auto it = buckets_.find(client_key);
    if (it != buckets_.end()) {
        return *it->second.bytes;
    }
    auto bucket = std::make_unique<TokenBucket>(bps_, bps_);
    TokenBucket *ptr = bucket.get();
    ClientBuckets cb;
    cb.bytes = std::move(bucket);
    cb.requests = std::make_unique<TokenBucket>(rps_, rps_);
    buckets_.emplace(client_key, std::move(cb));
    return *ptr;
}

TokenBucket &RateLimiter::get_requests_bucket(const std::string &client_key) {
    {
        std::shared_lock<std::shared_mutex> lk(mutex_);
        auto it = buckets_.find(client_key);
        if (it != buckets_.end()) {
            return *it->second.requests;
        }
    }
    std::unique_lock<std::shared_mutex> lk(mutex_);
    auto it = buckets_.find(client_key);
    if (it != buckets_.end()) {
        return *it->second.requests;
    }
    auto bytes_bucket = std::make_unique<TokenBucket>(bps_, bps_);
    auto req_bucket = std::make_unique<TokenBucket>(rps_, rps_);
    TokenBucket *ptr = req_bucket.get();
    ClientBuckets cb;
    cb.bytes = std::move(bytes_bucket);
    cb.requests = std::move(req_bucket);
    buckets_.emplace(client_key, std::move(cb));
    return *ptr;
}

std::size_t RateLimiter::cleanup_idle_impl(std::chrono::milliseconds idle) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    auto now = std::chrono::steady_clock::now();
    std::size_t removed = 0;

    for (auto it = buckets_.begin(); it != buckets_.end();) {
        auto last_bytes = it->second.bytes->last_access();
        auto last_req = it->second.requests->last_access();
        auto last = (last_bytes > last_req) ? last_bytes : last_req;

        if (now - last > idle) {
            it = buckets_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }

    if (removed > 0) {
        LINOH_DEBUG("RateLimiter: cleaned up ", removed, " idle clients");
    }
    return removed;
}

std::size_t RateLimiter::client_count() const {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    return buckets_.size();
}

// v1.7.0.2 P1: 热更新所有限流配置
void RateLimiter::set_rates(std::uint64_t new_bps, std::uint64_t new_rps,
                            bool update_existing_buckets) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    bps_ = new_bps;
    rps_ = new_rps;
    if (update_existing_buckets) {
        for (auto &[key, cb] : buckets_) {
            cb.bytes->set_rate(new_bps, new_bps);
            cb.requests->set_rate(new_rps, new_rps);
        }
    }
}

} // namespace linoh::util
