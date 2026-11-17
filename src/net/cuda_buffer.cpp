// cuda_buffer.cpp - CudaBuffer handle + allocator implementation (v1.6.0.5 / P4)
//
// Without LINOH_WITH_CUDA:
//   - CudaBuffer::reset() frees via std::free (CPU heap).
//   - StubCudaBufferAllocator uses std::malloc / std::free.
//   - export_ipc / open_ipc are no-ops (return false / empty buffer).
// With LINOH_WITH_CUDA:
//   - RealCudaBufferAllocator uses cudaMalloc / cudaMallocHost / cudaFree.

#include "linoh/net/cuda_buffer.hpp"
#include "linoh/util/logging.hpp"

#include <cstdlib>
#include <cstring>
#include <mutex>

namespace linoh::net {

// ============================================================================
// CudaBuffer::reset()
// ============================================================================

void CudaBuffer::reset() noexcept {
    if (owns_memory && ptr != nullptr) {
#ifdef LINOH_WITH_CUDA
        // Real CUDA path: 根据 location 调用对应的 CUDA 释放函数。
        // DEVICE 内存用 cudaFree，PINNED_HOST 内存用 cudaFreeHost，
        // 其他位置（普通 HOST）用 std::free。
        if (location == BufferLocation::DEVICE) {
            cudaFree(ptr);
        } else if (location == BufferLocation::PINNED_HOST) {
            cudaFreeHost(ptr);
        } else {
            std::free(ptr);
        }
#else
        // 无 CUDA SDK 时，所有内存都是 std::malloc 分配的 CPU heap 内存。
        std::free(ptr);
#endif
    }
    ptr = nullptr;
    size = 0;
    capacity = 0;
    owns_memory = false;
    device_handle = DeviceHandle{};
}

// ============================================================================
// StubCudaBufferAllocator (no CUDA SDK)
// ============================================================================

#ifndef LINOH_WITH_CUDA

class StubCudaBufferAllocator : public CudaBufferAllocator {
public:
    StubCudaBufferAllocator() = default;
    ~StubCudaBufferAllocator() override = default;

    CudaBuffer allocate(std::size_t capacity,
                        BufferLocation loc = BufferLocation::REGULAR_HOST,
                        int device_id = -1) override {
        CudaBuffer buf;
        if (capacity == 0) {
            ++stats_.alloc_failures;
            return buf;
        }
        void *p = std::malloc(capacity);
        if (p == nullptr) {
            ++stats_.alloc_failures;
            LINOH_ERROR("StubCudaBufferAllocator: malloc failed for ",
                        capacity, " bytes");
            return buf;
        }
        std::memset(p, 0, capacity);
        buf.ptr = p;
        buf.size = capacity;
        buf.capacity = capacity;
        buf.location = loc;
        buf.device_id = device_id;
        buf.owns_memory = true;

        stats_.total_allocated += capacity;
        stats_.total_capacity += capacity;
        ++stats_.alloc_count;
        stats_.last_location = loc;
        stats_.last_device_id = device_id;
        return buf;
    }

    void free(CudaBuffer &buf) override {
        if (!buf.owns_memory || buf.ptr == nullptr) {
            buf = CudaBuffer{};
            return;
        }
        if (stats_.total_allocated >= buf.capacity) {
            stats_.total_allocated -= buf.capacity;
        }
        if (stats_.total_capacity >= buf.capacity) {
            stats_.total_capacity -= buf.capacity;
        }
        ++stats_.free_count;
        std::free(buf.ptr);
        buf = CudaBuffer{};
    }

    bool export_ipc(CudaBuffer &buf) override {
        // Stub: just mark the handle as valid (no real IPC).
        if (!buf.valid()) return false;
        buf.device_handle.valid = true;
        return true;
    }

    CudaBuffer open_ipc(const DeviceHandle &handle,
                        std::size_t size,
                        int device_id = -1) override {
        // Stub: cannot really open IPC; return empty.
        (void)handle;
        (void)size;
        (void)device_id;
        return CudaBuffer{};
    }

    bool is_real_cuda() const noexcept override { return false; }
    const char *name() const noexcept override { return "stub"; }

    CudaAllocatorStats stats() const override { return stats_; }

private:
    mutable CudaAllocatorStats stats_;
};

#endif // !LINOH_WITH_CUDA

// ============================================================================
// default_cuda_allocator()
// ============================================================================

CudaBufferAllocator *default_cuda_allocator() {
#ifndef LINOH_WITH_CUDA
    static StubCudaBufferAllocator instance;
    return &instance;
#else
    // When LINOH_WITH_CUDA is defined, a RealCudaBufferAllocator would be
    // returned here. For now, fall back to stub (no CUDA SDK linked).
    static StubCudaBufferAllocator instance;
    return &instance;
#endif
}

// ============================================================================
// build_has_real_cuda()
// ============================================================================

bool build_has_real_cuda() noexcept {
#ifdef LINOH_WITH_CUDA
    return true;
#else
    return false;
#endif
}

} // namespace linoh::net
