// linoh/util/secure_buffer.hpp — 安全缓冲区（RAII 析构时清零内存）
//
// 用于包装私钥、会话密钥、master_secret 等敏感数据，防止内存残留泄漏。
// 析构时调用 secure_zero 显式清零（编译器不可优化掉）。
//
// 设计要点：
//   1. 使用 volatile 指针防止编译器消除 dead-store
//   2. 拷贝语义删除（避免无意识扩散），移动语义允许
//   3. 兼容 std::array<uint8_t, N> 接口（data/size/as_span）
//   4. 头文件 inline 实现，无额外链接负担

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <utility>

namespace linoh::util {

/// 安全清零一块内存（防止编译器消除 dead-store）
inline void secure_zero(void *ptr, std::size_t n) noexcept {
    if (!ptr || n == 0) return;
    volatile std::uint8_t *p = static_cast<volatile std::uint8_t *>(ptr);
    while (n--) {
        *p++ = 0;
    }
}

/// 安全缓冲区模板：包装固定长度字节数组，析构时清零
template <std::size_t N>
class SecureBuffer {
public:
    static constexpr std::size_t kSize = N;

    SecureBuffer() = default;

    // 拷贝：删除（防止无意识扩散敏感数据）
    SecureBuffer(const SecureBuffer &) = delete;
    SecureBuffer &operator=(const SecureBuffer &) = delete;

    // 移动：允许（转移所有权，源对象清零）
    SecureBuffer(SecureBuffer &&other) noexcept {
        std::memcpy(buf_.data(), other.buf_.data(), N);
        secure_zero(other.buf_.data(), N);
    }
    SecureBuffer &operator=(SecureBuffer &&other) noexcept {
        if (this != &other) {
            secure_zero(buf_.data(), N);
            std::memcpy(buf_.data(), other.buf_.data(), N);
            secure_zero(other.buf_.data(), N);
        }
        return *this;
    }

    // 析构：清零
    ~SecureBuffer() {
        secure_zero(buf_.data(), N);
    }

    // 兼容 std::array 接口
    std::uint8_t *data() noexcept { return buf_.data(); }
    const std::uint8_t *data() const noexcept { return buf_.data(); }
    constexpr std::size_t size() const noexcept { return N; }

    std::span<std::uint8_t> as_span() noexcept { return std::span<std::uint8_t>(buf_.data(), N); }
    std::span<const std::uint8_t> as_span() const noexcept { return std::span<const std::uint8_t>(buf_.data(), N); }

    // 直接访问底层（用于 API 兼容）
    std::uint8_t &operator[](std::size_t i) noexcept { return buf_[i]; }
    const std::uint8_t &operator[](std::size_t i) const noexcept { return buf_[i]; }

    // 与 std::array<uint8_t, N> 互转
    static SecureBuffer from_array(const std::array<std::uint8_t, N> &arr) noexcept {
        SecureBuffer sb;
        std::memcpy(sb.buf_.data(), arr.data(), N);
        return sb;
    }

    std::array<std::uint8_t, N> to_array() const noexcept {
        std::array<std::uint8_t, N> arr;
        std::memcpy(arr.data(), buf_.data(), N);
        return arr;
    }

    bool is_zero() const noexcept {
        for (std::size_t i = 0; i < N; ++i) {
            if (buf_[i] != 0) return false;
        }
        return true;
    }

    void clear() noexcept {
        secure_zero(buf_.data(), N);
    }

private:
    std::array<std::uint8_t, N> buf_{};
};

} // namespace linoh::util
