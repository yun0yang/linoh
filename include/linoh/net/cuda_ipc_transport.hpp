// cuda_ipc_transport.hpp - CUDA IPC transport for inter-process GPU buffer
//                           sharing on the same host (v1.6.0.5 / P4)
//
// Concrete HwAccelTransport implementation backed by CUDA IPC memory
// handles (cudaIpcGetMemHandle / cudaIpcOpenMemHandle). Used when two
// processes on the same machine need to exchange GPU buffers but NVLink
// direct access is unavailable (e.g. different MIG partitions, or when
// the application prefers explicit handle passing).
//
// P4 stage scope:
//   - Class declaration only (implementation in cuda_ipc_transport.cpp)
//   - Without LINOH_WITH_CUDA: compiled as Stub Mock (CPU shared memory
//     simulated with mmap / named shared memory on Windows)
//   - With LINOH_WITH_CUDA: real IPC handle export + open per peer
//   - Multicast is NOT supported (returns 0 from send_multicast)
//   - Cross-host IPC is impossible by design; can_connect returns false
//     for any peer whose node id maps to a different host
//
// Design principles:
//   - One CudaIpcTransport instance per process; handles are cached per
//     (peer, buffer) pair to amortise open cost
//   - Mock mode uses a process-local map of named shared regions; on
//     Windows CreateFileMapping /MapViewOfFile is used, on POSIX shm_open
//   - Thread-safety: send_gpu / recv_gpu guarded by internal mutex;
//     export_ipc on the producer side and open_ipc on the consumer side
//     can happen concurrently
//   - Lifecycle: buffers opened via open_ipc are non-owning views; the
//     producer must keep the source CudaBuffer alive for the duration
//
// Integration points:
//   - TransportSelector registers CudaIpcTransport at priority 2
//     (below NvlinkTransport, above QUIC UDP fallback)
//   - CudaBufferAllocator::export_ipc / open_ipc delegate to this transport
//     when DEVICE location is requested
//   - On mock mode the transport is fully functional for unit tests

#pragma once
#ifndef LINOH_NET_CUDA_IPC_TRANSPORT_HPP_
#define LINOH_NET_CUDA_IPC_TRANSPORT_HPP_

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "linoh/net/cuda_buffer.hpp"
#include "linoh/net/hw_accel.hpp"

namespace linoh::net {

/// CudaIpcTransport - CUDA IPC-backed HwAccelTransport.
///
/// Usage:
///   auto t = CudaIpcTransport::create();
///   t->set_mock_mode(true);
///   // Producer side:
///   CudaBuffer src = make_cuda_buffer(1<<20, BufferLocation::DEVICE);
///   t->export_for_peer(peer_id, src);
///   // Consumer side (different process):
///   auto handle = receive_handle_somehow(peer_id);
///   CudaBuffer view = t->open_for_peer(peer_id, handle, 1<<20);
class CudaIpcTransport : public HwAccelTransport {
public:
    /// Factory: returns a shared instance.
    static std::shared_ptr<CudaIpcTransport> create();

    /// Constructor (public for make_shared; prefer create()).
    CudaIpcTransport();

    ~CudaIpcTransport() override;

    // Non-copyable, non-movable
    CudaIpcTransport(const CudaIpcTransport &) = delete;
    CudaIpcTransport &operator=(const CudaIpcTransport &) = delete;
    CudaIpcTransport(CudaIpcTransport &&) = delete;
    CudaIpcTransport &operator=(CudaIpcTransport &&) = delete;

    // ====================================================================
    // HwAccelTransport impl
    // ====================================================================

    Type type() const noexcept override { return Type::CUDA_IPC; }
    std::string name() const override { return "cuda-ipc"; }

    bool is_ready() const noexcept override;
    bool can_connect(NodeId peer) const override;
    bool supports_multicast() const noexcept override { return false; }

    bool set_mock_mode(bool enabled) override;
    bool is_mock_mode() const noexcept override;

    std::size_t send_gpu(NodeId peer, const CudaBuffer &buf) override;
    std::size_t recv_gpu(NodeId peer, CudaBuffer &buf) override;
    // send_multicast inherited default (returns 0)

    Stats stats() const override;
    void reset_stats() override;

    // ====================================================================
    // CudaIpc-specific API
    // ====================================================================

    /// Export a DEVICE buffer's IPC handle and cache it for peer.
    /// \return true on success; buf.device_handle is populated
    bool export_for_peer(NodeId peer, CudaBuffer &buf);

    /// Open a remote IPC handle as a non-owning view for peer.
    /// \param handle exported device handle (from producer)
    /// \param size buffer size in bytes (must match producer)
    /// \param device_id target GPU index (-1 = default)
    /// \return valid CudaBuffer (owns_memory=false) or empty on failure
    CudaBuffer open_for_peer(NodeId peer,
                             const DeviceHandle &handle,
                             std::size_t size,
                             int device_id = -1);

    /// Close all cached handles for a peer (e.g. on disconnect).
    void close_peer(NodeId peer);

    /// Number of currently cached peer entries.
    std::size_t peer_count() const noexcept;

private:
    mutable std::mutex mu_;

    bool mock_mode_;
    int gpu_count_;

    /// Cached IPC handles: peer_id -> (device_handle, opened CudaBuffer view)
    struct PeerEntry {
        DeviceHandle handle;
        CudaBuffer view;
    };
    std::unordered_map<NodeId, PeerEntry> peer_cache_;

    /// Mock-mode shared memory regions keyed by peer id.
    std::unordered_map<NodeId, std::vector<std::uint8_t>> mock_shm_;

    // Statistics
    std::uint64_t send_total_;
    std::uint64_t recv_total_;
    std::uint64_t send_bytes_;
    std::uint64_t recv_bytes_;
    std::uint64_t send_failures_;
    std::uint64_t recv_failures_;
    double latency_sum_us_;
    std::uint64_t latency_count_;

    /// Internal: real CUDA export (compiled only with LINOH_WITH_CUDA).
    bool real_export_(NodeId peer, CudaBuffer &buf);

    /// Internal: real CUDA open (compiled only with LINOH_WITH_CUDA).
    CudaBuffer real_open_(NodeId peer,
                          const DeviceHandle &handle,
                          std::size_t size,
                          int device_id);
};

}  // namespace linoh::net

#endif  // LINOH_NET_CUDA_IPC_TRANSPORT_HPP_
