#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace linoh::util {

/// 轻量的不可变字节缓冲区。底层用 `shared_ptr` 持有实际分配的内存，
/// 复制成本极低；`slice()` 返回子视图与原 `Bytes` 共享同一存储。
///
/// 设计目标：在 IO 路径上减少无意义的 `memcpy`，替代 `std::vector<uint8_t>`。
class Bytes {
public:
    Bytes() = default;

    /// 从已有数据拷贝。
    explicit Bytes(std::span<const uint8_t> data)
        : storage_{std::make_shared<std::vector<uint8_t>>(data.begin(), data.end())},
          offset_{0},
          size_{storage_->size()} {}

    explicit Bytes(std::string_view s)
        : storage_{std::make_shared<std::vector<uint8_t>>(
              reinterpret_cast<const uint8_t *>(s.data()),
              reinterpret_cast<const uint8_t *>(s.data()) + s.size())},
          offset_{0},
          size_{storage_->size()} {}

    /// 分配 `size` 字节、未初始化的缓冲区，由调用者填充。
    static Bytes allocate(std::size_t size) {
        Bytes b;
        b.storage_ = std::make_shared<std::vector<uint8_t>>(size);
        b.size_ = size;
        return b;
    }

    /// 子视图（零拷贝）。
    Bytes slice(std::size_t offset, std::size_t length) const {
        Bytes b;
        b.storage_ = storage_;
        b.offset_ = offset_ + offset;
        b.size_ = length;
        return b;
    }

    Bytes slice(std::size_t offset) const { return slice(offset, size_ - offset); }

    /// 强制深拷贝（一般用于需要独立可变副本的情况）。
    Bytes copy() const { return Bytes{as_span()}; }

    const uint8_t *data() const { return storage_ ? storage_->data() + offset_ : nullptr; }
    std::size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }

    std::span<const uint8_t> as_span() const { return std::span<const uint8_t>(data(), size_); }
    std::string_view as_string_view() const {
        return std::string_view(reinterpret_cast<const char *>(data()), size_);
    }

    uint8_t operator[](std::size_t i) const { return data()[i]; }

    bool operator==(const Bytes &other) const {
        return size_ == other.size_ && (size_ == 0 || std::memcmp(data(), other.data(), size_) == 0);
    }

    friend class MutableBytes;

private:
    std::shared_ptr<std::vector<uint8_t>> storage_;
    std::size_t offset_{0};
    std::size_t size_{0};
};

/// 可变字节缓冲区，用于接收路径上写入 asio 异步操作。内部为独占的 `unique_ptr<uint8_t[]>`。
class MutableBytes {
public:
    MutableBytes() = default;
    explicit MutableBytes(std::size_t size)
        : data_{std::make_unique<uint8_t[]>(size)}, size_{size} {}

    uint8_t *data() { return data_.get(); }
    const uint8_t *data() const { return data_.get(); }
    std::size_t size() const { return size_; }

    std::span<uint8_t> as_span() { return std::span<uint8_t>(data_.get(), size_); }
    std::span<const uint8_t> as_span() const { return std::span<const uint8_t>(data_.get(), size_); }

    /// 把可变缓冲区"冻结"为只读的 `Bytes`（零拷贝移动语义）。
    Bytes freeze(std::size_t used) const {
        auto vec = std::make_shared<std::vector<uint8_t>>(data_.get(), data_.get() + used);
        Bytes b;
        b.storage_ = vec;
        b.offset_ = 0;
        b.size_ = used;
        return b;
    }

private:
    std::unique_ptr<uint8_t[]> data_;
    std::size_t size_{0};
};

} // namespace linoh::util
