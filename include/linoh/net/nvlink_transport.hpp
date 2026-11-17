// nvlink_transport.hpp - NVLink transport for intra-node GPU transfers
//                        (v1.6.0.5 / P4)
//
// Concrete HwAccelTransport implementation backed by NVIDIA NVLink.
// NVLink is the highest-bandwidth path between GPUs on the same node
// (typical bandwidth: 300-900 GB/s aggregate on H100 / B200).
//
// P4 stage scope:
//   - Class declaration only (implementation lives in nvlink_transport.cpp)
//   - Without LINOH_WITH_CUDA: compiled as Stub Mock (CPU memcpy simulation)
//   - With LINOH_WITH_CUDA: real NVLink path via cuMemAlloc / cuStreamWriteValue
//     and the NVLink multicast handle API (CU_MEM_HANDLE_TYPE_MULTICAST)
//   - Cross-node NVLink (NVSwitch C2C, Grace-Hopper) is out of P4 scope
//
// Design principles:
//   - Singleton-friendly: a single NvlinkTransport instance per process
//     (NVLink topology is global to the node)
//   - Mock mode is opt-in via set_mock_mode(true); construction never fails
//     even without CUDA, allowing the TransportSelector to register a
//     (mock) instance unconditionally
//   - send_multicast is supported when real CUDA is available
//   - Thread-safety: send_gpu / recv_gpu serialised by an internal mutex
//     (NVLink does not benefit from per-stream concurrency at this layer)
//
// Integration points:
//   - TransportSelector registers NvlinkTransport as the highest priority
//   - StaticBufferPool may share its DEVICE buffers directly with this
//     transport (zero-copy: no staging)
//   - On mock mode, the transport keeps its own std::vector<uint8_t> per
//     peer to emulate a recv queue

#pragma once
#ifndef LINOH_NET_NVLINK_TRANSPORT_HPP_
#define LINOH_NET_NVLINK_TRANSPORT_HPP_

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "linoh/net/cuda_buffer.hpp"
#include "linoh/net/hw_accel.hpp"

namespace linoh::net {

/// NvlinkTransport - NVLink-backed HwAccelTransport.
///
/// Usage:
///   auto t = NvlinkTransport::create();
///   t->set_mock_mode(true);  // for CPU-only tests
///   if (t->can_connect(peer_id)) {
///       t->send_gpu(peer_id, gpu_buf);
///   }
class NvlinkTransport : public HwAccelTransport {
public:
    /// Factory: returns a shared instance.
    /// Construction never throws; real CUDA init is deferred to first use
    /// (or never happens in mock mode).
    static std::shared_ptr<NvlinkTransport> create();

    /// Constructor (public for make_shared; prefer create()).
    /// Initialises in mock mode if LINOH_WITH_CUDA is not defined.
    NvlinkTransport();

    ~NvlinkTransport() override;

    // Non-copyable, non-movable (owns hardware state)
    NvlinkTransport(const NvlinkTransport &) = delete;
    NvlinkTransport &operator=(const NvlinkTransport &) = delete;
    NvlinkTransport(NvlinkTransport &&) = delete;
    NvlinkTransport &operator=(NvlinkTransport &&) = delete;

    // ====================================================================
    // HwAccelTransport impl
    // ====================================================================

    Type type() const noexcept override { return Type::NVLINK; }
    std::string name() const override { return "nvlink"; }

    bool is_ready() const noexcept override;
    bool can_connect(NodeId peer) const override;
    bool supports_multicast() const noexcept override;

    bool set_mock_mode(bool enabled) override;
    bool is_mock_mode() const noexcept override;

    std::size_t send_gpu(NodeId peer, const CudaBuffer &buf) override;
    std::size_t recv_gpu(NodeId peer, CudaBuffer &buf) override;
    std::size_t send_multicast(const std::vector<NodeId> &peers,
                               const CudaBuffer &buf) override;

    Stats stats() const override;
    void reset_stats() override;

    // ====================================================================
    // Nvlink-specific API
    // ====================================================================

    /// Number of GPUs detected on this node (0 in mock mode without CUDA).
    int gpu_count() const noexcept;

    /// NVLink topology version detected (e.g. 3 for H100, 4 for B200).
    /// Returns 0 in mock mode.
    int nvlink_version() const noexcept;

    /// Aggregate NVLink bandwidth (GB/s) across all links.
    /// Returns 0 in mock mode.
    double aggregate_bandwidth_gbps() const noexcept;

private:
    mutable std::mutex mu_;

    bool mock_mode_;
    int gpu_count_;
    int nvlink_version_;
    double bandwidth_gbps_;

    // Mock-mode peer recv queues: peer_id -> pending bytes
    std::unordered_map<NodeId, std::vector<std::uint8_t>> mock_queues_;

    // Statistics (atomic-friendly counters; guarded by mu_)
    std::uint64_t send_total_;
    std::uint64_t recv_total_;
    std::uint64_t send_bytes_;
    std::uint64_t recv_bytes_;
    std::uint64_t send_failures_;
    std::uint64_t recv_failures_;
    std::uint64_t multicast_total_;
    std::uint64_t multicast_bytes_;
    double latency_sum_us_;
    std::uint64_t latency_count_;

    /// Internal: lazily probe NVLink topology (real CUDA only).
    /// Sets gpu_count_ / nvlink_version_ / bandwidth_gbps_.
    void probe_topology_();

    /// Internal: real CUDA send (compiled only with LINOH_WITH_CUDA).
    std::size_t real_send_(NodeId peer, const CudaBuffer &buf);

    /// Internal: real CUDA recv (compiled only with LINOH_WITH_CUDA).
    std::size_t real_recv_(NodeId peer, CudaBuffer &buf);
};

}  // namespace linoh::net

#endif  // LINOH_NET_NVLINK_TRANSPORT_HPP_
