// progress_report.cpp — v4.3.0 M21 双层进度上报 payload 实现
#include "linoh/protocol/progress_report.hpp"

#include <cstring>

namespace linoh::protocol {

// ============================================================================
// 序列化
// ============================================================================

std::size_t ProgressReportPayload::wire_size() const noexcept {
    return sizeof(overall_current)    // 4
         + sizeof(overall_total)      // 4
         + sizeof(std::uint16_t)      // item_name_len 2
         + item_name.size()           // N
         + sizeof(item_bytes_done)    // 8
         + sizeof(item_bytes_total);  // 8
}

std::vector<std::uint8_t> ProgressReportPayload::serialize() const {
    std::vector<std::uint8_t> out;
    out.reserve(wire_size());
    serialize_into(out);
    return out;
}

std::size_t ProgressReportPayload::serialize_into(
    std::vector<std::uint8_t> &out) const {
    // 限制 item_name 长度（防滥用，超长截断）
    std::uint16_t name_len = static_cast<std::uint16_t>(
        item_name.size() > kProgressReportMaxItemNameLen
            ? kProgressReportMaxItemNameLen
            : item_name.size());

    std::size_t start = out.size();
    out.reserve(out.size() + wire_size());

    // overall_current (4B LE)
    out.push_back(static_cast<std::uint8_t>(overall_current & 0xFF));
    out.push_back(static_cast<std::uint8_t>((overall_current >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((overall_current >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((overall_current >> 24) & 0xFF));

    // overall_total (4B LE)
    out.push_back(static_cast<std::uint8_t>(overall_total & 0xFF));
    out.push_back(static_cast<std::uint8_t>((overall_total >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((overall_total >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((overall_total >> 24) & 0xFF));

    // item_name_len (2B LE)
    out.push_back(static_cast<std::uint8_t>(name_len & 0xFF));
    out.push_back(static_cast<std::uint8_t>((name_len >> 8) & 0xFF));

    // item_name (NB UTF-8)
    if (name_len > 0) {
        out.insert(out.end(),
                    item_name.data(),
                    item_name.data() + name_len);
    }

    // item_bytes_done (8B LE)
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((item_bytes_done >> (i * 8)) & 0xFF));
    }

    // item_bytes_total (8B LE)
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((item_bytes_total >> (i * 8)) & 0xFF));
    }

    return out.size() - start;
}

// ============================================================================
// 反序列化
// ============================================================================

std::optional<ProgressReportPayload> ProgressReportPayload::parse(
    std::span<const std::uint8_t> data) {
    // 最小长度检查
    if (data.size() < kProgressReportMinWireSize) {
        return std::nullopt;
    }

    ProgressReportPayload p;
    std::size_t pos = 0;

    // overall_current (4B LE)
    p.overall_current = static_cast<std::uint32_t>(data[pos])
                      | (static_cast<std::uint32_t>(data[pos + 1]) << 8)
                      | (static_cast<std::uint32_t>(data[pos + 2]) << 16)
                      | (static_cast<std::uint32_t>(data[pos + 3]) << 24);
    pos += 4;

    // overall_total (4B LE)
    p.overall_total = static_cast<std::uint32_t>(data[pos])
                    | (static_cast<std::uint32_t>(data[pos + 1]) << 8)
                    | (static_cast<std::uint32_t>(data[pos + 2]) << 16)
                    | (static_cast<std::uint32_t>(data[pos + 3]) << 24);
    pos += 4;

    // item_name_len (2B LE)
    std::uint16_t name_len = static_cast<std::uint16_t>(data[pos])
                           | (static_cast<std::uint16_t>(data[pos + 1]) << 8);
    pos += 2;

    // 检查数据是否足够包含 item_name + 后续 16B
    if (pos + name_len + 16 > data.size()) {
        return std::nullopt;
    }

    // item_name (NB UTF-8)
    if (name_len > 0) {
        p.item_name.assign(reinterpret_cast<const char *>(data.data() + pos), name_len);
    }
    pos += name_len;

    // item_bytes_done (8B LE)
    std::uint64_t done = 0;
    for (int i = 0; i < 8; ++i) {
        done |= static_cast<std::uint64_t>(data[pos + i]) << (i * 8);
    }
    p.item_bytes_done = done;
    pos += 8;

    // item_bytes_total (8B LE)
    std::uint64_t total = 0;
    for (int i = 0; i < 8; ++i) {
        total |= static_cast<std::uint64_t>(data[pos + i]) << (i * 8);
    }
    p.item_bytes_total = total;

    return p;
}

// ============================================================================
// 便捷方法
// ============================================================================

double ProgressReportPayload::overall_percent() const noexcept {
    if (overall_total == 0) return 0.0;
    return static_cast<double>(overall_current) / static_cast<double>(overall_total);
}

double ProgressReportPayload::item_percent() const noexcept {
    if (item_bytes_total == 0) return 0.0;
    return static_cast<double>(item_bytes_done) / static_cast<double>(item_bytes_total);
}

}  // namespace linoh::protocol
