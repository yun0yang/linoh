// buffer_pool.cpp — 静态 Buffer 池实现（v1.6.0.3 / P2）

#include "linoh/multimodal/buffer_pool.hpp"

#include <cstring>
#include <new>

#ifdef LINOH_WITH_CUDA
#include <cuda_runtime.h>
#endif

namespace linoh::multimodal::ep {

// ============================================================================
// BorrowedBuffer
// ============================================================================

BorrowedBuffer::~BorrowedBuffer() {
    if (pool_) {
        release_internal_();
    }
}

void BorrowedBuffer::release_internal_() noexcept {
    if (pool_) {
        pool_->release_internal_(index_);
    }
}

// ============================================================================
// StaticBufferPool
// ============================================================================

StaticBufferPool::StaticBufferPool(std::size_t buffer_count,
                                   std::size_t buffer_size,
                                   BufferLocation loc)
    : buffer_size_(buffer_size), location_(loc) {
    allocate_buffers_(buffer_count);
    for (std::size_t i = 0; i < buffer_count; ++i) {
        free_indices_.push(i);
    }
}

StaticBufferPool::~StaticBufferPool() {
    // buffers_ 析构自动释放内存
    // PINNED_HOST 需要调用 cudaFreeHost，由 buffers_ 析构时 vector 释放，
    // 但 cuda pinned memory 不能用 delete 释放，需特殊处理
    // P2 阶段仅实现 REGULAR_HOST，PINNED_HOST 留到后续版本
    buffers_.clear();
}

void StaticBufferPool::allocate_buffers_(std::size_t count) {
    buffers_.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        std::vector<std::uint8_t> buf(buffer_size_);
        // 预清零（便于 padding 场景直接使用）
        std::fill(buf.begin(), buf.end(), std::uint8_t{0});
        buffers_.push_back(std::move(buf));
    }
}

BorrowedBuffer StaticBufferPool::acquire() {
    std::lock_guard<std::mutex> lk(mu_);
    ++acquire_total_;
    if (free_indices_.empty()) {
        ++exhaust_total_;
        return BorrowedBuffer();  // 池耗尽，返回空
    }
    std::size_t idx = free_indices_.front();
    free_indices_.pop();
    return BorrowedBuffer(std::span<std::uint8_t>(buffers_[idx].data(),
                                                  buffers_[idx].size()),
                         this, idx);
}

std::optional<BorrowedBuffer> StaticBufferPool::try_acquire() {
    std::lock_guard<std::mutex> lk(mu_);
    ++acquire_total_;
    if (free_indices_.empty()) {
        ++exhaust_total_;
        return std::nullopt;
    }
    std::size_t idx = free_indices_.front();
    free_indices_.pop();
    return BorrowedBuffer(std::span<std::uint8_t>(buffers_[idx].data(),
                                                  buffers_[idx].size()),
                         this, idx);
}

void StaticBufferPool::release_internal_(std::size_t idx) noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    ++release_total_;
    free_indices_.push(idx);
}

std::size_t StaticBufferPool::free_count() const noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    return free_indices_.size();
}

std::size_t StaticBufferPool::in_use_count() const noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    return buffers_.size() - free_indices_.size();
}

BufferPoolStats StaticBufferPool::stats() const {
    std::lock_guard<std::mutex> lk(mu_);
    BufferPoolStats s;
    s.total_buffers = buffers_.size();
    s.free_buffers = free_indices_.size();
    s.in_use_buffers = buffers_.size() - free_indices_.size();
    s.buffer_size = buffer_size_;
    s.location = location_;
    s.acquire_total = acquire_total_;
    s.release_total = release_total_;
    s.exhaust_total = exhaust_total_;
    return s;
}

std::span<const std::uint8_t> StaticBufferPool::buffer_at(std::size_t idx) const {
    std::lock_guard<std::mutex> lk(mu_);
    if (idx >= buffers_.size()) return {};
    return std::span<const std::uint8_t>(buffers_[idx].data(),
                                         buffers_[idx].size());
}

}  // namespace linoh::multimodal::ep
