// holepunch_cache.cpp — S6-③（v5.3）打洞结果缓存实现
#include "linoh/nat/holepunch_cache.hpp"

#include <algorithm>
#include <chrono>

namespace linoh::nat {

namespace {
std::int64_t now_ms_steady() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}
}  // namespace

void HolepunchCache::record(const base::EndpointId &peer,
                            const net::FourTuple &tuple) {
    std::lock_guard<std::mutex> lk(mu_);
    entries_[peer] = Entry{tuple, now_ms_steady()};
    if (entries_.size() > kMaxEntries) {
        evict_locked(now_ms_steady());
    }
}

std::optional<net::FourTuple> HolepunchCache::lookup(
    const base::EndpointId &peer, std::chrono::milliseconds ttl) const {
    if (ttl.count() <= 0) return std::nullopt;
    std::lock_guard<std::mutex> lk(mu_);
    auto it = entries_.find(peer);
    if (it == entries_.end()) return std::nullopt;
    if (now_ms_steady() - it->second.recorded_at_ms > ttl.count()) {
        return std::nullopt;  // 过期（惰性失效，不主动删——下次 record 覆盖）
    }
    return it->second.tuple;
}

std::size_t HolepunchCache::size() const {
    std::lock_guard<std::mutex> lk(mu_);
    return entries_.size();
}

void HolepunchCache::clear() {
    std::lock_guard<std::mutex> lk(mu_);
    entries_.clear();
}

HolepunchCache &HolepunchCache::global() {
    static HolepunchCache instance;
    return instance;
}

void HolepunchCache::evict_locked(std::int64_t now) {
    // 1) 先清过期项
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (now - it->second.recorded_at_ms > kDefaultTtl.count()) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
    // 2) 仍超限：按最旧清一半
    if (entries_.size() > kMaxEntries) {
        std::vector<std::pair<std::int64_t, base::EndpointId>> by_age;
        by_age.reserve(entries_.size());
        for (auto &kv : entries_) {
            by_age.emplace_back(kv.second.recorded_at_ms, kv.first);
        }
        std::sort(by_age.begin(), by_age.end());
        std::size_t to_remove = entries_.size() - kMaxEntries / 2;
        for (std::size_t i = 0; i < to_remove && i < by_age.size(); ++i) {
            entries_.erase(by_age[i].second);
        }
    }
}

}  // namespace linoh::nat
