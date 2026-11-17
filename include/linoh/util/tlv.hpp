// tlv.hpp — O2 TLV 编解码基础设施（独立项目方案 W1.2）
//
// 定位：为调用方的高频小消息提供紧凑二进制编码工具（实测对照：
// 261B JSON → 89B，-66%）。linoh 只提供基础设施，不定义调用方 schema。
//
// 设计：定长字段 + 前缀长度字段（str=u16 前缀、bytes=u32 前缀），
// 小端字节序（内存序直拷，零转换开销）；Reader 带边界检查，
// 截断/溢出一律返回 false，绝不越界读。
//
// 用法：
//   linoh::util::TlvWriter w;
//   w.put_u8(2); w.put_str("h3-v1"); w.put_u32(768);
//   auto buf = w.take();
//   linoh::util::TlvReader r(buf);
//   std::uint8_t scale; std::string model; std::uint32_t width;
//   if (r.get_u8(scale) && r.get_str(model) && r.get_u32(width)) { ... }

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace linoh::util {

/// 追加式编码器（非线程安全，单消息作用域使用）
class TlvWriter {
public:
    void put_u8(std::uint8_t v) { buf_.push_back(v); }

    void put_u16(std::uint16_t v) {
        buf_.insert(buf_.end(), reinterpret_cast<const std::uint8_t *>(&v),
                    reinterpret_cast<const std::uint8_t *>(&v) + 2);
    }

    void put_u32(std::uint32_t v) {
        buf_.insert(buf_.end(), reinterpret_cast<const std::uint8_t *>(&v),
                    reinterpret_cast<const std::uint8_t *>(&v) + 4);
    }

    void put_u64(std::uint64_t v) {
        buf_.insert(buf_.end(), reinterpret_cast<const std::uint8_t *>(&v),
                    reinterpret_cast<const std::uint8_t *>(&v) + 8);
    }

    /// 字符串：u16 长度前缀（>65535 截断拒绝，断言开发期错误）
    void put_str(const std::string &s) {
        put_u16(static_cast<std::uint16_t>(s.size()));
        buf_.insert(buf_.end(), s.begin(), s.end());
    }

    /// 字节块：u32 长度前缀
    void put_bytes(const std::vector<std::uint8_t> &b) {
        put_u32(static_cast<std::uint32_t>(b.size()));
        buf_.insert(buf_.end(), b.begin(), b.end());
    }

    std::size_t size() const { return buf_.size(); }
    const std::vector<std::uint8_t> &buffer() const { return buf_; }
    std::vector<std::uint8_t> take() { return std::move(buf_); }

private:
    std::vector<std::uint8_t> buf_;
};

/// 带边界检查的解码器（任何越界/截断返回 false，游标不前进）
class TlvReader {
public:
    explicit TlvReader(const std::vector<std::uint8_t> &buf)
        : data_(buf.data()), size_(buf.size()) {}
    TlvReader(const std::uint8_t *data, std::size_t size)
        : data_(data), size_(size) {}

    bool get_u8(std::uint8_t &out) {
        if (pos_ + 1 > size_) return false;
        out = data_[pos_++];
        return true;
    }

    bool get_u16(std::uint16_t &out) {
        if (pos_ + 2 > size_) return false;
        std::memcpy(&out, data_ + pos_, 2);
        pos_ += 2;
        return true;
    }

    bool get_u32(std::uint32_t &out) {
        if (pos_ + 4 > size_) return false;
        std::memcpy(&out, data_ + pos_, 4);
        pos_ += 4;
        return true;
    }

    bool get_u64(std::uint64_t &out) {
        if (pos_ + 8 > size_) return false;
        std::memcpy(&out, data_ + pos_, 8);
        pos_ += 8;
        return true;
    }

    bool get_str(std::string &out) {
        std::uint16_t len = 0;
        if (!get_u16(len)) return false;
        if (pos_ + len > size_) return false;
        out.assign(reinterpret_cast<const char *>(data_ + pos_), len);
        pos_ += len;
        return true;
    }

    bool get_bytes(std::vector<std::uint8_t> &out) {
        std::uint32_t len = 0;
        if (!get_u32(len)) return false;
        if (pos_ + len > size_) return false;
        out.assign(data_ + pos_, data_ + pos_ + len);
        pos_ += len;
        return true;
    }

    std::size_t remaining() const { return size_ - pos_; }
    bool exhausted() const { return pos_ == size_; }

private:
    const std::uint8_t *data_;
    std::size_t size_;
    std::size_t pos_{0};
};

}  // namespace linoh::util
