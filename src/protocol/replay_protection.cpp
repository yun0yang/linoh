// replay_protection.cpp — v3.8.6 控制面指令 nonce + timestamp 防重放实现
//
// 依赖：linoh::protocol::NonceCache / ReplayProtection（replay_protection.hpp）
// 无外部依赖（纯 C++20 标准库 + STL 容器）

#include "linoh/protocol/replay_protection.hpp"

#include <algorithm>
#include <cstring>

namespace linoh::protocol {

// ============================================================================
// NonceCache 实现
// ============================================================================

NonceCache::NonceCache(std::size_t max_size, std::chrono::seconds ttl)
    : max_size_(max_size), ttl_(ttl) {}

bool NonceCache::check_and_insert(std::span<const std::uint8_t> nonce,
                                   std::chrono::steady_clock::time_point now) {
    // 校验 nonce 长度（必须 >= 32 字节，取前 32 字节）
    if (nonce.size() < kNonceSize) {
        return false;
    }

    // 拷贝 nonce 到定长数组
    NonceArray key{};
    std::memcpy(key.data(), nonce.data(), kNonceSize);

    std::unique_lock<std::shared_mutex> lock(mutex_);

    // 查找 nonce 是否已在缓存中
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        // nonce 已存在，检查是否过期
        const auto &entry = *(it->second);
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - entry.inserted_at);

        if (age >= ttl_) {
            // 已过期：删除旧条目，视为首次（允许 60s 后重用）
            lru_order_.erase(it->second);
            cache_.erase(it);
            ++stats_.expired;
            // 继续走首次插入逻辑（下方）
        } else {
            // 未过期：重复命中，拒绝
            ++stats_.hits;
            return false;
        }
    }

    // 首次见到：插入 list front（最新位置）
    lru_order_.push_front(NonceEntry{key, now});
    cache_[key] = lru_order_.begin();
    ++stats_.accepts;

    // LRU 淘汰：容量超限时淘汰 list back（最旧）
    if (lru_order_.size() > max_size_) {
        const auto &oldest = lru_order_.back();
        cache_.erase(oldest.nonce);
        lru_order_.pop_back();
        ++stats_.evicted;
    }

    return true;
}

std::size_t NonceCache::evict_expired(std::chrono::steady_clock::time_point now) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    std::size_t count = 0;
    // list back 是最旧的，从后往前清理过期条目
    while (!lru_order_.empty()) {
        const auto &oldest = lru_order_.back();
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - oldest.inserted_at);
        if (age >= ttl_) {
            cache_.erase(oldest.nonce);
            lru_order_.pop_back();
            ++count;
        } else {
            break;  // back 未过期，更新的一定也未过期
        }
    }

    stats_.expired += count;
    return count;
}

std::size_t NonceCache::size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return lru_order_.size();
}

std::size_t NonceCache::max_size() const noexcept {
    return max_size_;
}

std::chrono::seconds NonceCache::ttl() const noexcept {
    return ttl_;
}

NonceCache::Stats NonceCache::stats() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    Stats s = stats_;
    s.size = lru_order_.size();
    return s;
}

void NonceCache::clear() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    lru_order_.clear();
    cache_.clear();
    stats_ = Stats{};
}

// ============================================================================
// ReplayProtection 实现
// ============================================================================

ReplayProtection::ReplayProtection(std::size_t max_cache_size,
                                     std::chrono::seconds ttl)
    : nonce_cache_(max_cache_size, ttl), ttl_(ttl) {}

bool ReplayProtection::check(std::uint64_t timestamp,
                              std::span<const std::uint8_t> nonce) {
    // 1. timestamp 双向校验（|now_unix - timestamp| <= ttl）
    auto now_unix = std::chrono::system_clock::now();
    auto now_secs = std::chrono::duration_cast<std::chrono::seconds>(
                        now_unix.time_since_epoch()).count();
    // 用有符号差值防 uint64 下溢
    std::int64_t diff = static_cast<std::int64_t>(now_secs) -
                        static_cast<std::int64_t>(timestamp);
    auto ttl_secs = static_cast<std::int64_t>(ttl_.count());
    if (diff > ttl_secs || diff < -ttl_secs) {
        // timestamp 过期（旧指令）或未来偏移过大（时钟偏移）
        return false;
    }

    // 2. nonce 查重（check_and_insert 原子操作）
    return nonce_cache_.check_and_insert(nonce);
}

NonceCache::Stats ReplayProtection::stats() const {
    return nonce_cache_.stats();
}

std::size_t ReplayProtection::size() const {
    return nonce_cache_.size();
}

void ReplayProtection::clear() {
    nonce_cache_.clear();
}

} // namespace linoh::protocol
