// address_token_store.cpp — P4-A-2 全局地址验证 token 存储实现

#include "linoh/tls/address_token_store.hpp"

#include <algorithm>
#include <sstream>

namespace linoh::tls {

AddressTokenStore& AddressTokenStore::instance() {
    static AddressTokenStore inst;
    return inst;
}

std::string AddressTokenStore::addr_key(const linoh::base::TransportAddr& addr) {
    std::ostringstream oss;
    oss << static_cast<int>(addr.kind) << "|" << addr.host << ":" << addr.port;
    return oss.str();
}

void AddressTokenStore::store_token_impl(const std::vector<std::uint8_t>& token,
                                          const linoh::base::TransportAddr& peer_addr,
                                          std::chrono::seconds ttl) {
    if (token.empty()) return;

    std::unique_lock<std::shared_mutex> lk(mutex_);
    std::string key = addr_key(peer_addr);
    auto& vec = store_[key];

    // tc-L3 (v1.7.0.8): 容量超限时改进驱逐策略。
    //   原 FIFO 直接删 vec.begin()（最新插入但可能最远过期），可能丢弃
    //   仍长期有效的 token 而保留即将过期的，造成可用 token 浪费。
    //   修复策略（按优先级）：
    //     1) 优先删除已过期条目（cleanup 顺便完成）
    //     2) 若仍有超限，删除最早过期（nearest deadline）的未过期条目
    //        （类似 LRU by expiry：保留更长期有效的 token 提升命中率）
    auto now = std::chrono::steady_clock::now();
    if (vec.size() >= kMaxTokensPerPeer) {
        // 1) 删除所有已过期
        auto new_end = std::remove_if(vec.begin(), vec.end(),
            [&](const Entry& e) { return e.expires_at <= now; });
        vec.erase(new_end, vec.end());
        // 2) 仍超限：删除最早过期的（min expires_at）
        while (vec.size() >= kMaxTokensPerPeer) {
            auto earliest = std::min_element(vec.begin(), vec.end(),
                [](const Entry& a, const Entry& b) {
                    return a.expires_at < b.expires_at;
                });
            if (earliest == vec.end()) break;
            vec.erase(earliest);
        }
    }

    Entry e;
    e.token = token;
    e.expires_at = now + ttl;
    vec.push_back(std::move(e));
}

std::optional<std::vector<std::uint8_t>> AddressTokenStore::take_token(
    const linoh::base::TransportAddr& peer_addr) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    std::string key = addr_key(peer_addr);
    auto it = store_.find(key);
    if (it == store_.end() || it->second.empty()) {
        return std::nullopt;
    }

    // 找出第一个未过期的 token
    auto now = std::chrono::steady_clock::now();
    auto& vec = it->second;
    for (auto iter = vec.begin(); iter != vec.end(); ++iter) {
        if (iter->expires_at > now) {
            std::vector<std::uint8_t> token = std::move(iter->token);
            vec.erase(iter);
            if (vec.empty()) {
                store_.erase(it);
            }
            return token;
        }
    }

    // 全部已过期，清空
    store_.erase(it);
    return std::nullopt;
}

std::size_t AddressTokenStore::count_tokens(const linoh::base::TransportAddr& peer_addr) const {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    std::string key = addr_key(peer_addr);
    auto it = store_.find(key);
    if (it == store_.end()) return 0;

    auto now = std::chrono::steady_clock::now();
    std::size_t count = 0;
    for (const auto& e : it->second) {
        if (e.expires_at > now) ++count;
    }
    return count;
}

std::size_t AddressTokenStore::cleanup_expired() {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    std::size_t removed = 0;
    auto now = std::chrono::steady_clock::now();

    for (auto it = store_.begin(); it != store_.end(); ) {
        auto& vec = it->second;
        auto new_end = std::remove_if(vec.begin(), vec.end(),
            [&](const Entry& e) {
                if (e.expires_at <= now) { ++removed; return true; }
                return false;
            });
        vec.erase(new_end, vec.end());

        if (vec.empty()) {
            it = store_.erase(it);
        } else {
            ++it;
        }
    }
    return removed;
}

void AddressTokenStore::clear() {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    store_.clear();
}

std::size_t AddressTokenStore::total_tokens() const {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    std::size_t total = 0;
    for (const auto& [k, vec] : store_) {
        total += vec.size();
    }
    return total;
}

} // namespace linoh::tls
