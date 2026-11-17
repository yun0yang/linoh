// hw_accel.hpp - Hardware-accelerated transport abstraction (v1.6.0.5 / P4)
//
// Defines the abstract interface that all P4 hardware transports must
// implement. Concrete implementations:
//   - NvlinkTransport      : intra-node / cross-GPU NVLink
//   - CudaIpcTransport     : inter-process CUDA IPC (same host, no NVLink)
//   - (future) RdmaTransport: RDMA / GPUDirect over InfiniBand/RoCE
//
// P4 stage scope:
//   - Pure abstract interface; no CUDA dependency in this header
//   - Concrete transports include their own LINOH_WITH_CUDA guards
//   - Stub Mock mode (set_mock_mode(true)) lets tests run on CPU-only
//     machines while preserving the interface contract
//
// Design principles:
//   - Reuse CudaBuffer handle (no void* + size pairs)
//   - send_gpu / recv_gpu operate on DEVICE buffers when possible; the
//     transport is responsible for staging through pinned host memory if
//     the underlying hardware path requires it
//   - send_multicast is an opt-in capability (NVLink supports multicast
//     via CU_MEM_HANDLE_TYPE_MULTICAST; CUDA IPC does not)
//   - can_connect() is queried before any data op; transport_selector uses
//     it to rank candidates
//   - All methods are non-blocking; completion is reported via the
//     caller-supplied CudaBuffer state and stats counters
//
// Integration points:
//   - TransportSelector owns a registry of HwAccelTransport instances
//   - TensorStreamer may downgrade to QUIC UDP transport when no
//     HwAccelTransport can_connect() for the given peer
//   - EpChannel uses select() at dispatch time to pick the best path per dst

#pragma once
#ifndef LINOH_NET_HW_ACCEL_HPP_
#define LINOH_NET_HW_ACCEL_HPP_

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "linoh/net/cuda_buffer.hpp"

namespace linoh::net {

/// Node identifier (same type as linoh::multimodal::ep::NodeId).
using NodeId = std::uint64_t;

/// HwAccelTransport - abstract base for hardware-accelerated data paths.
///
/// All methods are thread-safe unless noted. Implementations are expected
/// to be reentrant for send_gpu / recv_gpu (different peers concurrently),
/// but a single peer's send/recv ordering is the caller's responsibility.
class HwAccelTransport {
public:
    /// Transport type tag.
    enum class Type : std::uint8_t {
        NVLINK    = 0,  // Intra-node / cross-GPU NVLink
        CUDA_IPC  = 1,  // Inter-process CUDA IPC (same host)
        RDMA      = 2,  // RDMA / GPUDirect (future)
    };

    /// Per-transport statistics snapshot.
    struct Stats {
        std::uint64_t send_total = 0;       // Number of send_gpu calls
        std::uint64_t recv_total = 0;       // Number of recv_gpu calls
        std::uint64_t send_bytes = 0;       // Total bytes sent
        std::uint64_t recv_bytes = 0;       // Total bytes received
        std::uint64_t send_failures = 0;    // Failed send_gpu calls
        std::uint64_t recv_failures = 0;    // Failed recv_gpu calls
        std::uint64_t multicast_total = 0;  // Number of send_multicast calls
        std::uint64_t multicast_bytes = 0;  // Total bytes sent via multicast
        double avg_latency_us = 0.0;        // Rolling average latency
        bool mock_mode = false;             // True if running as Stub Mock
    };

    virtual ~HwAccelTransport() = default;

    // ====================================================================
    // Identity
    // ====================================================================

    /// Transport type tag (NVLINK / CUDA_IPC / RDMA).
    virtual Type type() const noexcept = 0;

    /// Human-readable name for logging (e.g. "nvlink", "cuda-ipc").
    virtual std::string name() const = 0;

    // ====================================================================
    // Capability & readiness
    // ====================================================================

    /// Whether the underlying hardware path is initialised and ready.
    /// Returns false in mock mode unless set_mock_mode(true) was called.
    virtual bool is_ready() const noexcept = 0;

    /// Whether this transport can establish a hardware path to peer.
    /// \param peer remote node id
    /// \return true if a direct (non-fallback) path exists
    virtual bool can_connect(NodeId peer) const = 0;

    /// Whether send_multicast is supported (NVLink yes, CUDA IPC no).
    virtual bool supports_multicast() const noexcept = 0;

    /// Enable / disable Stub Mock mode. When mock_mode is true, the
    /// transport simulates all operations in CPU memory without touching
    /// any real hardware. Useful for unit tests on CPU-only machines.
    /// \return previous mock_mode state
    virtual bool set_mock_mode(bool enabled) = 0;

    /// Whether the transport is currently running in mock mode.
    virtual bool is_mock_mode() const noexcept = 0;

    // ====================================================================
    // Data path
    // ====================================================================

    /// Send a GPU buffer to peer (non-blocking).
    /// \param peer destination node id
    /// \param buf source buffer; location may be DEVICE or PINNED_HOST
    /// \return bytes actually sent, 0 on failure
    virtual std::size_t send_gpu(NodeId peer, const CudaBuffer &buf) = 0;

    /// Receive a GPU buffer from peer (non-blocking).
    /// \param peer source node id
    /// \param buf destination buffer (caller-allocated, must have capacity)
    /// \return bytes actually received, 0 on failure or no data
    virtual std::size_t recv_gpu(NodeId peer, CudaBuffer &buf) = 0;

    /// Multicast-send a buffer to multiple peers (NVLink only).
    /// Default implementation returns 0 (unsupported).
    /// \param peers list of destination node ids
    /// \param buf source buffer
    /// \return bytes sent to *one* peer (multicast counts once), 0 if failed
    virtual std::size_t send_multicast(const std::vector<NodeId> &peers,
                                       const CudaBuffer &buf) {
        (void)peers;
        (void)buf;
        return 0;
    }

    // ====================================================================
    // Diagnostics
    // ====================================================================

    /// Snapshot of per-transport statistics.
    virtual Stats stats() const = 0;

    /// Reset all statistics counters to zero.
    virtual void reset_stats() = 0;
};

/// Shared pointer alias for transport ownership.
using HwAccelTransportPtr = std::shared_ptr<HwAccelTransport>;

/// Convert Type enum to string (for logging).
const char *to_string(HwAccelTransport::Type t) noexcept;

}  // namespace linoh::net

#endif  // LINOH_NET_HW_ACCEL_HPP_
