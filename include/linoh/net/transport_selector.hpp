// transport_selector.hpp - Per-peer hardware transport selection (v1.6.0.5 / P4)
//
// Selects the best HwAccelTransport for a given peer node, with a built-in
// fallback to the QUIC UDP transport (UdpTransport) when no hardware path
// is available.
//
// Priority order (highest first):
//   1. NvlinkTransport     - intra-node / cross-GPU NVLink (top priority)
//   2. CudaIpcTransport    - same-host CUDA IPC (fallback when no NVLink)
//   3. UdpTransport (QUIC) - cross-host / no-CUDA fallback (always available)
//
// P4 stage scope:
//   - TransportSelector class with register/select/has_hw_accel/list_transports
//   - Selection is per-peer (one transport may serve multiple peers)
//   - The QUIC UDP fallback is *not* registered by TransportSelector itself;
//     the caller (Endpoint) is responsible for invoking it when select()
//     returns nullptr. This keeps TransportSelector free of asio deps.
//
// Design principles:
//   - Thread-safe: internal mutex protects the registry
//   - No hardware probing on registration: a transport may be registered
//     even in mock mode; can_connect() is queried lazily on select()
//   - Result caching: select() results are cached per peer until
//     invalidate(peer) is called or a registered transport changes state
//   - Statistics aggregation: aggregate_stats() sums across all HW transports
//
// Integration points:
//   - Endpoint / TensorStreamer calls select(peer) before each send_gpu;
//     if nullptr, falls back to UdpTransport::send_to
//   - EpChannel may pre-warm the cache by calling preselect(peers) at
//     EP-group setup time
//   - The orchestrator may call list_transports() to expose HW capability
//     to the smart scheduler

#pragma once
#ifndef LINOH_NET_TRANSPORT_SELECTOR_HPP_
#define LINOH_NET_TRANSPORT_SELECTOR_HPP_

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "linoh/net/hw_accel.hpp"

namespace linoh::net {

/// TransportSelector - registry + per-peer selection of HwAccelTransport.
class TransportSelector {
public:
    TransportSelector();
    ~TransportSelector();

    // Non-copyable, non-movable (contains mutex)
    TransportSelector(const TransportSelector &) = delete;
    TransportSelector &operator=(const TransportSelector &) = delete;
    TransportSelector(TransportSelector &&) = delete;
    TransportSelector &operator=(TransportSelector &&) = delete;

    // ====================================================================
    // Registration
    // ====================================================================

    /// Register a hardware transport. Higher priority values are preferred.
    /// Built-in convention:
    ///   NvlinkTransport    -> priority 100
    ///   CudaIpcTransport   -> priority 50
    /// (QUIC UDP fallback is implicit and not registered here.)
    /// \return true on success, false if a transport of the same Type is
    ///         already registered (caller must unregister first)
    bool register_transport(HwAccelTransportPtr transport, int priority);

    /// Unregister a transport by Type.
    /// \return true if removed, false if not found
    bool unregister_transport(HwAccelTransport::Type type);

    /// Unregister all hardware transports (QUIC fallback remains implicit).
    void unregister_all() noexcept;

    // ====================================================================
    // Selection
    // ====================================================================

    /// Select the best hardware transport for peer.
    /// Walks registered transports in descending priority order, returning
    /// the first that is_ready() && can_connect(peer).
    /// \return shared_ptr to transport (延长生命周期，避免使用期间被 unregister),
    ///         或 nullptr 表示无 HW 路径（调用方应回退到 QUIC UDP）
    HwAccelTransportPtr select(NodeId peer);

    /// Pre-select and cache transports for a list of peers (warm-up).
    /// Useful at EP-group setup to amortise can_connect() cost.
    void preselect(const std::vector<NodeId> &peers);

    /// Invalidate cached selection for a peer (e.g. after topology change).
    void invalidate(NodeId peer) noexcept;

    /// Invalidate all cached selections.
    void invalidate_all() noexcept;

    // ====================================================================
    // Diagnostics
    // ====================================================================

    /// Whether any hardware transport is registered *and* ready.
    /// (Does NOT include QUIC UDP fallback.)
    bool has_hw_accel() const noexcept;

    /// Whether any hardware transport is registered *and* ready *and*
    /// can_connect(peer). Equivalent to select(peer) != nullptr but does
    /// not cache.
    bool has_hw_accel_for(NodeId peer) const;

    /// List all registered transports with their priority and readiness.
    struct TransportInfo {
        HwAccelTransport::Type type;
        std::string name;
        int priority;
        bool ready;
        bool mock_mode;
    };
    std::vector<TransportInfo> list_transports() const;

    /// Aggregate statistics across all registered HW transports.
    /// Mock-mode transports are included (their Stats.mock_mode flag is set).
    std::vector<HwAccelTransport::Stats> aggregate_stats() const;

    /// Number of registered transports.
    std::size_t transport_count() const noexcept;

    /// Number of cached peer selections.
    std::size_t cache_size() const noexcept;

private:
    struct Entry {
        HwAccelTransportPtr transport;
        int priority = 0;
    };

    mutable std::mutex mu_;
    std::vector<Entry> entries_;  // sorted by priority desc on insert

    /// Cached selection: peer -> index into entries_ (or -1 = no HW path)
    std::unordered_map<NodeId, int> cache_;

    /// Internal: select without updating cache; returns index or -1.
    int select_index_(NodeId peer) const;
};

/// Default singleton instance (per-process).
/// Lifetime: function-local static. Thread-safe initialisation.
TransportSelector &default_transport_selector();

}  // namespace linoh::net

#endif  // LINOH_NET_TRANSPORT_SELECTOR_HPP_
