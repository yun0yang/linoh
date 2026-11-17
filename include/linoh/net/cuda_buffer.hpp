// cuda_buffer.hpp - CUDA buffer handle + allocator abstraction (v1.6.0.5 / P4)
//
// Hardware acceleration layer foundation:
//   - CudaBuffer: a lightweight handle describing a GPU (or mock) memory region
//   - CudaBufferAllocator: abstract factory for creating CudaBuffer instances
//
// P4 stage scope:
//   - Without CUDA SDK (default): compiled as Stub Mock using plain CPU heap
//     memory to emulate GPU buffer semantics (so EP / PP paths can be tested
//     on pure-CPU developer machines).
//   - With CUDA SDK (LINOH_WITH_CUDA defined): real implementation backed by
//     cudaMalloc / cudaMallocHost / cudaMallocManaged, plus optional IPC
//     export handle for cross-process sharing (used by CudaIpcTransport).
//
// Design principles:
//   - Reuse BufferLocation enum from linoh::multimodal::ep (do not duplicate)
//   - CudaBuffer is a *handle* (cheap to copy); ownership is controlled by
//     owns_memory flag so the same handle can represent borrowed pool buffers
//   - No CUDA headers pulled in unconditionally: keep this header includable
//     from any TU (translation unit) without NVCC.
//   - Real CUDA calls live in the .cpp side and are dispatched via the
//     LINOH_WITH_CUDA macro.
//
// Integration points:
//   - HwAccelTransport::send_gpu / recv_gpu accept CudaBuffer directly
//   - StaticBufferPool may wrap pre-allocated CudaBuffer for DEVICE location
//   - TensorStreamer / TensorReassembler treat CudaBuffer as opaque bytes
//     when location == REGULAR_HOST (mock mode transparent fallback)

#pragma once
#ifndef LINOH_NET_CUDA_BUFFER_HPP_
#define LINOH_NET_CUDA_BUFFER_HPP_

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

// Reuse BufferLocation definition from multimodal EP layer (single source of
// truth). REGULAR_HOST=0, PINNED_HOST=1, DEVICE=2.
#include "linoh/multimodal/buffer_pool.hpp"

namespace linoh::net {

/// Alias for buffer location enum (kept in sync with ep::BufferLocation).
using BufferLocation = linoh::multimodal::ep::BufferLocation;

/// Opaque device handle type.
///
/// Without CUDA SDK this is a pointer to an internal mock device struct.
/// With CUDA SDK this wraps a cudaIpcMemHandle_t (for IPC export) or a
/// custom device descriptor.
struct DeviceHandle {
    std::uint64_t opaque[4] = {0, 0, 0, 0};  // Reserved for future fields
    bool valid = false;
};

/// CudaBuffer - lightweight handle to a GPU or mock-GPU memory region.
///
/// Semantics:
///   - ptr: raw pointer to the underlying memory (CPU heap in mock mode,
///          device pointer in real CUDA mode)
///   - size: actual bytes of valid data stored in the buffer
///   - capacity: total bytes allocated (size <= capacity)
///   - location: where the memory physically resides
///   - device_handle: IPC export handle (valid only when location==DEVICE
///                    and CUDA IPC export has been called)
///   - device_id: GPU device index (0..N-1), -1 for mock/CPU
///   - owns_memory: if true, destructor frees the underlying allocation;
///                  if false, buffer is a non-owning view (e.g. borrowed
///                  from StaticBufferPool)
///
/// Copy semantics: cheap copy (handle only). The original buffer retains
/// ownership; copies are non-owning views unless explicitly cloned.
struct CudaBuffer {
    void *ptr = nullptr;
    std::size_t size = 0;
    std::size_t capacity = 0;
    BufferLocation location = BufferLocation::REGULAR_HOST;
    DeviceHandle device_handle;
    int device_id = -1;
    bool owns_memory = false;

    /// Default ctor: empty buffer.
    CudaBuffer() = default;

    /// Construct a non-owning view over an external memory region.
    CudaBuffer(void *p, std::size_t sz, BufferLocation loc = BufferLocation::REGULAR_HOST,
               int dev = -1) noexcept
        : ptr(p), size(sz), capacity(sz), location(loc), device_id(dev),
          owns_memory(false) {}

    /// Whether the handle references any memory.
    bool valid() const noexcept { return ptr != nullptr; }
    explicit operator bool() const noexcept { return valid(); }

    /// As a byte span (read-write).
    std::span<std::uint8_t> as_span() noexcept {
        return {static_cast<std::uint8_t *>(ptr), size};
    }
    std::span<const std::uint8_t> as_span() const noexcept {
        return {static_cast<const std::uint8_t *>(ptr), size};
    }

    /// Free the underlying memory if owns_memory is true and reset to empty.
    /// The actual free (cudaFree / free) is dispatched by the allocator
    /// implementation via the LINOH_WITH_CUDA macro; here we only clear the
    /// handle fields. Callers should typically destroy buffers via the
    /// allocator that created them.
    void reset() noexcept;
};

/// Statistics for an allocator instance.
struct CudaAllocatorStats {
    std::size_t total_allocated = 0;       // Currently outstanding bytes
    std::size_t total_capacity = 0;        // Capacity of outstanding buffers
    std::uint64_t alloc_count = 0;         // Total alloc calls
    std::uint64_t free_count = 0;          // Total free calls
    std::uint64_t alloc_failures = 0;      // Failed alloc attempts
    BufferLocation last_location = BufferLocation::REGULAR_HOST;
    int last_device_id = -1;
};

/// Abstract allocator interface for CudaBuffer.
///
/// Two concrete implementations live in the .cpp side:
///   - StubCudaBufferAllocator: CPU heap-backed mock (always available)
///   - RealCudaBufferAllocator: real CUDA-backed (requires LINOH_WITH_CUDA)
///
/// Selection is performed by make_default_allocator() based on macro.
class CudaBufferAllocator {
public:
    virtual ~CudaBufferAllocator() = default;

    /// Allocate a buffer of the requested capacity on the given device.
    /// \param capacity bytes to allocate
    /// \param loc target location (REGULAR_HOST / PINNED_HOST / DEVICE)
    /// \param device_id GPU index (ignored for REGULAR_HOST; -1 = default)
    /// \return CudaBuffer with owns_memory=true on success, empty on failure
    virtual CudaBuffer allocate(std::size_t capacity,
                                BufferLocation loc = BufferLocation::REGULAR_HOST,
                                int device_id = -1) = 0;

    /// Free a buffer previously returned by allocate().
    /// Resets the handle (owns_memory -> false, ptr -> nullptr).
    virtual void free(CudaBuffer &buf) = 0;

    /// Export an IPC handle for a DEVICE buffer (no-op in mock mode).
    /// \return true if a valid device_handle was attached to buf
    virtual bool export_ipc(CudaBuffer &buf) = 0;

    /// Open a buffer from a remote IPC handle (returns non-owning view).
    /// \return valid CudaBuffer on success, empty on failure
    virtual CudaBuffer open_ipc(const DeviceHandle &handle,
                                std::size_t size,
                                int device_id = -1) = 0;

    /// Whether the allocator is backed by real CUDA (false for mock).
    virtual bool is_real_cuda() const noexcept = 0;

    /// Human-readable name (e.g. "stub", "cuda").
    virtual const char *name() const noexcept = 0;

    /// Snapshot of allocator statistics.
    virtual CudaAllocatorStats stats() const = 0;
};

/// Factory: returns the default allocator for the current build.
/// - Without LINOH_WITH_CUDA: returns StubCudaBufferAllocator instance
/// - With LINOH_WITH_CUDA: returns RealCudaBufferAllocator instance
///
/// The returned pointer is owned by a function-local static; do not delete.
CudaBufferAllocator *default_cuda_allocator();

/// Convenience helper: allocate a buffer via the default allocator.
inline CudaBuffer make_cuda_buffer(std::size_t capacity,
                                   BufferLocation loc = BufferLocation::REGULAR_HOST,
                                   int device_id = -1) {
    return default_cuda_allocator()->allocate(capacity, loc, device_id);
}

/// Whether the current build links real CUDA runtime.
/// Equivalent to checking default_cuda_allocator()->is_real_cuda().
bool build_has_real_cuda() noexcept;

}  // namespace linoh::net

#endif  // LINOH_NET_CUDA_BUFFER_HPP_
