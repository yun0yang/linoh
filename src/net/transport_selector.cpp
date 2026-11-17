// transport_selector.cpp - HW-accel transport selection implementation (P4)
//
// Priority: NVLink > CUDA IPC > (caller falls back to QUIC UDP).
// select() returns the first registered transport whose can_connect(peer)
// is true. If none qualifies, returns nullptr and the caller should fall
// back to the standard QUIC UDP transport.

#include "linoh/net/transport_selector.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <utility>

namespace linoh::net {

// ============================================================================
// Construction / destruction
// ============================================================================

TransportSelector::TransportSelector() = default;
TransportSelector::~TransportSelector() = default;

// ============================================================================
// register_transport
// ============================================================================

bool TransportSelector::register_transport(HwAccelTransportPtr transport,
                                           int priority) {
    if (!transport) {
        LINOH_WARN("TransportSelector::register_transport: null transport");
        return false;
    }
    std::lock_guard<std::mutex> lock(mu_);

    // Check for duplicate Type.
    auto t = transport->type();
    for (const auto &e : entries_) {
        if (e.transport && e.transport->type() == t) {
            LINOH_WARN("TransportSelector: type ", to_string(t),
                       " already registered");
            return false;
        }
    }

    Entry entry;
    entry.transport = std::move(transport);
    entry.priority = priority;
    entries_.push_back(std::move(entry));

    // Keep entries_ sorted by priority descending.
    std::sort(entries_.begin(), entries_.end(),
              [](const Entry &a, const Entry &b) {
                  return a.priority > b.priority;
              });

    // Invalidate cache since topology changed.
    cache_.clear();

    LINOH_INFO("TransportSelector: registered ", to_string(t),
               " priority=", priority,
               " total=", entries_.size());
    return true;
}

bool TransportSelector::unregister_transport(HwAccelTransport::Type type) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = std::remove_if(entries_.begin(), entries_.end(),
        [type](const Entry &e) {
            return e.transport && e.transport->type() == type;
        });
    if (it == entries_.end()) return false;
    entries_.erase(it, entries_.end());
    cache_.clear();
    LINOH_INFO("TransportSelector: unregistered ", to_string(type));
    return true;
}

void TransportSelector::unregister_all() noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    entries_.clear();
    cache_.clear();
}

// ============================================================================
// select_index_ (internal)
// ============================================================================

int TransportSelector::select_index_(NodeId peer) const {
    // entries_ is sorted by priority desc; return first match.
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        const auto &e = entries_[i];
        if (!e.transport) continue;
        if (e.transport->is_ready() && e.transport->can_connect(peer)) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

// ============================================================================
// select
// ============================================================================

HwAccelTransportPtr TransportSelector::select(NodeId peer) {
    // Check cache first.
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = cache_.find(peer);
        if (it != cache_.end()) {
            if (it->second < 0) return nullptr;
            // 返回 shared_ptr 拷贝，延长生命周期，避免锁外被 unregister 后悬空
            return entries_[it->second].transport;
        }
    }

    // Cache miss: scan entries_.
    std::lock_guard<std::mutex> lock(mu_);
    int idx = select_index_(peer);
    cache_[peer] = idx;
    if (idx < 0) return nullptr;
    return entries_[idx].transport;
}

void TransportSelector::preselect(const std::vector<NodeId> &peers) {
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto &peer : peers) {
        cache_[peer] = select_index_(peer);
    }
}

void TransportSelector::invalidate(NodeId peer) noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    cache_.erase(peer);
}

void TransportSelector::invalidate_all() noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    cache_.clear();
}

// ============================================================================
// Diagnostics
// ============================================================================

bool TransportSelector::has_hw_accel() const noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto &e : entries_) {
        if (e.transport && e.transport->is_ready()) {
            return true;
        }
    }
    return false;
}

bool TransportSelector::has_hw_accel_for(NodeId peer) const {
    std::lock_guard<std::mutex> lock(mu_);
    return select_index_(peer) >= 0;
}

std::vector<TransportSelector::TransportInfo>
TransportSelector::list_transports() const {
    std::vector<TransportInfo> result;
    std::lock_guard<std::mutex> lock(mu_);
    result.reserve(entries_.size());
    for (const auto &e : entries_) {
        if (!e.transport) continue;
        TransportInfo info;
        info.type = e.transport->type();
        info.name = e.transport->name();
        info.priority = e.priority;
        info.ready = e.transport->is_ready();
        info.mock_mode = e.transport->is_mock_mode();
        result.push_back(std::move(info));
    }
    return result;
}

std::vector<HwAccelTransport::Stats>
TransportSelector::aggregate_stats() const {
    std::vector<HwAccelTransport::Stats> result;
    std::lock_guard<std::mutex> lock(mu_);
    result.reserve(entries_.size());
    for (const auto &e : entries_) {
        if (!e.transport) continue;
        result.push_back(e.transport->stats());
    }
    return result;
}

std::size_t TransportSelector::transport_count() const noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    return entries_.size();
}

std::size_t TransportSelector::cache_size() const noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    return cache_.size();
}

// ============================================================================
// default_transport_selector (singleton)
// ============================================================================

TransportSelector &default_transport_selector() {
    static TransportSelector instance;
    return instance;
}

} // namespace linoh::net
