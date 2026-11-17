// buffer_pool.hpp — 静态 Buffer 池 + 零拷贝路径（v1.6.0.3 / P2）
//
// 借鉴 MoonEP 思想 ③（零拷贝 NVLink 对称内存）的 CPU 侧实现：
//   - EP 组建立时预分配 N 个固定大小 buffer（消除运行时 malloc/free 开销）
//   - acquire() 获取可用 buffer，release() 归还（RAII 自动归还）
//   - Buffer 位置分级：REGULAR_HOST（默认）/ PINNED_HOST（CUDA pinned）/ DEVICE（P4）
//
// P2 阶段定位：
//   - 仅实现 REGULAR_HOST（普通堆内存，无 CUDA 依赖，可在纯 CPU 环境测试）
//   - PINNED_HOST 通过条件编译 LINOH_WITH_CUDA 启用（win-worker 已有 CUDA）
//   - DEVICE 留到 P4 硬件加速层
//
// 设计原则：
//   - 不修改现有 TensorStreamer / TensorReassembler（PP 链兼容性优先）
//   - 预分配 buffer 数量 = EP 组节点数 × 每轮 dispatch 的 tensor 数
//   - buffer 大小 = 最大 tensor 大小（静态形状协商后固定，见 static_shape.hpp）
//   - 线程安全：mutex 保护 free_indices_ 队列
//   - 耗尽策略：acquire 返回 empty BorrowedBuffer（调用方决策等待或降级）
//
// 与 EpChannel 集成：
//   - EpChannel 持有 StaticBufferPool 引用，send_dispatch_zc 从 pool acquire
//   - ZeroCopySender 封装 acquire + write_scatter 路径
//   - ZeroCopyReceiver 封装 recv + pool buffer 写入路径

#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <queue>
#include <span>
#include <vector>

namespace linoh::multimodal::ep {

/// Buffer 位置类型（P2 默认 REGULAR_HOST，P4 扩展 DEVICE）
enum class BufferLocation : std::uint8_t {
    REGULAR_HOST = 0,  // 普通堆内存（malloc/new，P2 默认）
    PINNED_HOST  = 1,  // CUDA pinned host（cudaMallocHost，需 LINOH_WITH_CUDA）
    DEVICE       = 2,  // GPU 显存（cudaMalloc，P4 阶段启用）
};

/// Buffer 池统计
struct BufferPoolStats {
    std::size_t   total_buffers{0};       // 预分配 buffer 总数
    std::size_t   free_buffers{0};        // 当前空闲 buffer 数
    std::size_t   in_use_buffers{0};      // 当前借出 buffer 数
    std::size_t   buffer_size{0};         // 单个 buffer 字节数
    BufferLocation location{BufferLocation::REGULAR_HOST};
    std::uint64_t acquire_total{0};       // acquire 调用总次数
    std::uint64_t release_total{0};       // release 调用总次数
    std::uint64_t exhaust_total{0};       // 池耗尽次数
};

/// 前向声明（BorrowedBuffer 析构时回调 pool）
class StaticBufferPool;

/// 借出的 Buffer（RAII，独占所有权）
///
/// 用法：
///   auto buf = pool.acquire();
///   if (buf) {
///       // 写数据到 buf.data()
///       stream->write_scatter({buf.data()});
///   }  // 析构自动归还
class BorrowedBuffer {
public:
    BorrowedBuffer() = default;
    BorrowedBuffer(std::span<std::uint8_t> data,
                   StaticBufferPool *pool,
                   std::size_t index) noexcept
        : data_(data), pool_(pool), index_(index) {}

    ~BorrowedBuffer();

    // 不可拷贝（独占所有权）
    BorrowedBuffer(const BorrowedBuffer &) = delete;
    BorrowedBuffer &operator=(const BorrowedBuffer &) = delete;

    // 可移动
    BorrowedBuffer(BorrowedBuffer &&other) noexcept
        : data_(other.data_), pool_(other.pool_), index_(other.index_) {
        other.data_ = {};
        other.pool_ = nullptr;
        other.index_ = 0;
    }
    BorrowedBuffer &operator=(BorrowedBuffer &&other) noexcept {
        if (this != &other) {
            if (pool_) release_internal_();
            data_ = other.data_;
            pool_ = other.pool_;
            index_ = other.index_;
            other.data_ = {};
            other.pool_ = nullptr;
            other.index_ = 0;
        }
        return *this;
    }

    /// 是否有效（持有 buffer）
    /// 注意：buffer_size=0 的 buffer 仍视为有效（边界场景）
    bool valid() const noexcept { return pool_ != nullptr; }
    explicit operator bool() const noexcept { return valid(); }

    /// 访问 buffer 数据
    std::span<std::uint8_t> data() const noexcept { return data_; }
    std::size_t size() const noexcept { return data_.size(); }
    std::uint8_t *data_ptr() const noexcept { return data_.data(); }

    /// 手动归还（提前归还，析构时不再归还）
    void release() noexcept {
        if (pool_) {
            release_internal_();
            pool_ = nullptr;
            data_ = {};
        }
    }

    /// 在 pool 中的索引
    std::size_t index() const noexcept { return index_; }

private:
    std::span<std::uint8_t> data_;
    StaticBufferPool *pool_ = nullptr;
    std::size_t index_ = 0;

    void release_internal_() noexcept;
};

/// 静态 Buffer 池
///
/// 用法：
///   StaticBufferPool pool(8, 10 * 1024 * 1024);  // 8 个 buffer，每个 10MB
///   auto buf = pool.acquire();
///   if (buf) { /* 使用 buf.data() */ }
class StaticBufferPool {
public:
    /// 构造
    /// \param buffer_count 预分配 buffer 数量
    /// \param buffer_size 单个 buffer 字节数
    /// \param loc buffer 位置（P2 默认 REGULAR_HOST）
    StaticBufferPool(std::size_t buffer_count,
                     std::size_t buffer_size,
                     BufferLocation loc = BufferLocation::REGULAR_HOST);

    ~StaticBufferPool();

    // 不可拷贝、不可移动（被 BorrowedBuffer 引用）
    StaticBufferPool(const StaticBufferPool &) = delete;
    StaticBufferPool &operator=(const StaticBufferPool &) = delete;
    StaticBufferPool(StaticBufferPool &&) = delete;
    StaticBufferPool &operator=(StaticBufferPool &&) = delete;

    /// 获取一个可用 buffer（零拷贝 send 路径）
    /// \return 有效 BorrowedBuffer；池耗尽返回空 BorrowedBuffer（valid()==false）
    BorrowedBuffer acquire();

    /// 尝试获取一个可用 buffer（不阻塞，同 acquire）
    /// \return optional，valid 时含 BorrowedBuffer
    std::optional<BorrowedBuffer> try_acquire();

    /// 当前空闲 buffer 数
    std::size_t free_count() const noexcept;

    /// 当前借出 buffer 数
    std::size_t in_use_count() const noexcept;

    /// 总 buffer 数
    std::size_t total_count() const noexcept { return buffers_.size(); }

    /// 单个 buffer 大小
    std::size_t buffer_size() const noexcept { return buffer_size_; }

    /// buffer 位置
    BufferLocation location() const noexcept { return location_; }

    /// 获取统计
    BufferPoolStats stats() const;

    /// 测试访问器：指定索引的 buffer（用于测试，不推荐生产使用）
    std::span<const std::uint8_t> buffer_at(std::size_t idx) const;

private:
    std::vector<std::vector<std::uint8_t>> buffers_;  // 预分配
    mutable std::mutex mu_;
    std::queue<std::size_t> free_indices_;  // 空闲 buffer 索引队列

    std::size_t buffer_size_{0};
    BufferLocation location_{BufferLocation::REGULAR_HOST};

    // 统计计数器
    std::uint64_t acquire_total_{0};
    std::uint64_t release_total_{0};
    std::uint64_t exhaust_total_{0};

    /// 内部归还（BorrowedBuffer 析构调用）
    friend class BorrowedBuffer;
    void release_internal_(std::size_t idx) noexcept;

    /// 分配 buffer 内存（按 location 选择策略）
    void allocate_buffers_(std::size_t count);
};

}  // namespace linoh::multimodal::ep
