// session_cache.cpp — v5.0.0 Session Ticket 缓存实现（T-LP4-003）
//
// 借鉴 iroh 0.96 Connection<OutgoingZeroRtt> + TLS 1.3 RFC 8446 §4.6.1

#include "linoh/endpoint/session_cache.hpp"

#include <algorithm>
#include <chrono>

namespace linoh::endpoint {

void SessionCache::store(const base::EndpointId &server_endpoint_id,
                          const protocol::SessionTicketFrame &ticket) {
    std::lock_guard<std::mutex> lk(mu_);

    // 容量管理：超满时先清理过期，仍满则移除最旧条目
    if (entries_.size() >= kMaxEntries) {
        cleanup_expired_locked_();
        // 仍满则移除最旧条目（stored_at 最早的）
        while (entries_.size() >= kMaxEntries) {
            auto oldest = entries_.begin();
            for (auto it = entries_.begin(); it != entries_.end(); ++it) {
                if (it->second.stored_at < oldest->second.stored_at) {
                    oldest = it;
                }
            }
            if (oldest != entries_.end()) {
                entries_.erase(oldest);
            } else {
                break;
            }
        }
    }

    CachedSessionTicket entry;
    entry.ticket = ticket;
    entry.stored_at = std::chrono::steady_clock::now();
    entry.server_endpoint_id = server_endpoint_id;
    entries_[server_endpoint_id] = std::move(entry);
}

std::optional<protocol::SessionTicketFrame> SessionCache::lookup(
    const base::EndpointId &server_endpoint_id) const {
    std::lock_guard<std::mutex> lk(mu_);

    auto it = entries_.find(server_endpoint_id);
    if (it == entries_.end()) return std::nullopt;

    const auto &entry = it->second;
    auto now = std::chrono::steady_clock::now();
    if (is_expired_(entry, now)) {
        // 过期条目：返回 nullopt（不主动删除，由 cleanup_expired 统一清理）
        return std::nullopt;
    }

    return entry.ticket;
}

std::optional<CachedSessionTicket> SessionCache::lookup_full(
    const base::EndpointId &server_endpoint_id) const {
    std::lock_guard<std::mutex> lk(mu_);

    auto it = entries_.find(server_endpoint_id);
    if (it == entries_.end()) return std::nullopt;

    const auto &entry = it->second;
    auto now = std::chrono::steady_clock::now();
    if (is_expired_(entry, now)) {
        return std::nullopt;
    }

    return entry;
}

void SessionCache::remove(const base::EndpointId &server_endpoint_id) {
    std::lock_guard<std::mutex> lk(mu_);
    entries_.erase(server_endpoint_id);
}

std::size_t SessionCache::cleanup_expired() {
    std::lock_guard<std::mutex> lk(mu_);
    return cleanup_expired_locked_();
}

std::size_t SessionCache::size() const {
    std::lock_guard<std::mutex> lk(mu_);
    return entries_.size();
}

void SessionCache::set_ttl(std::chrono::milliseconds ttl) {
    std::lock_guard<std::mutex> lk(mu_);
    ttl_ = ttl;
}

bool SessionCache::is_expired_(const CachedSessionTicket &entry,
                                std::chrono::steady_clock::time_point now) const {
    auto age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - entry.stored_at);
    // 同时检查本地 TTL（毫秒精度）和 ticket 自身的 lifetime（秒精度）
    if (age_ms >= ttl_) return true;
    // ticket_lifetime 单位为秒，转换为毫秒比较
    auto ticket_lifetime_ms = std::chrono::milliseconds{
        static_cast<std::int64_t>(entry.ticket.ticket_lifetime) * 1000};
    if (age_ms >= ticket_lifetime_ms) return true;
    return false;
}

std::size_t SessionCache::cleanup_expired_locked_() {
    auto now = std::chrono::steady_clock::now();
    std::size_t removed = 0;

    for (auto it = entries_.begin(); it != entries_.end(); ) {
        if (is_expired_(it->second, now)) {
            it = entries_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }

    return removed;
}

} // namespace linoh::endpoint
