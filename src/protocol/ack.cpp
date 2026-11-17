// linoh/protocol/ack.cpp — QUIC ACK Frame 编解码实现 (RFC 9000 §19.3)

#include "linoh/protocol/ack.hpp"

#include <algorithm>
#include <cmath>

namespace linoh::protocol {

// ============================================================================
// AckFrame::from_acked_pns — 从已确认包编号集合构建 ACK 帧
// ============================================================================

AckFrame AckFrame::from_acked_pns(const std::vector<uint64_t> &acked_pns,
                                   uint64_t ack_delay_us,
                                   uint8_t type) {
    if (acked_pns.empty()) {
        AckFrame f;
        f.type = type;
        f.ack_delay_us = ack_delay_us;
        return f;
    }

    AckFrame f;
    f.type = type;
    f.largest_acked = acked_pns.back();
    f.ack_delay_us = ack_delay_us;

    // 从 largest_acked 往下，计算连续确认区间
    // 算法：
    //   1. first_ack_range = largest_acked - (第一个连续区间的最小PN)
    //   2. 每个 gap = 两个连续确认区间之间的未确认包数量
    //   3. ack_range_length = 确认区间中的包数量 - 1

    // 将已确认 PN 转换为区间列表
    // 区间: [start, end] 其中 start <= end，所有 PN 在区间内都被确认
    std::vector<std::pair<uint64_t, uint64_t>> intervals;
    uint64_t interval_start = acked_pns[0];
    uint64_t interval_end = acked_pns[0];

    for (size_t i = 1; i < acked_pns.size(); ++i) {
        if (acked_pns[i] == interval_end + 1) {
            // 连续，扩展当前区间
            interval_end = acked_pns[i];
        } else {
            // 不连续，保存当前区间，开启新区间
            intervals.push_back({interval_start, interval_end});
            interval_start = acked_pns[i];
            interval_end = acked_pns[i];
        }
    }
    intervals.push_back({interval_start, interval_end});

    // intervals 现在是从小到大排列的确认区间
    // 我们需要从 largest_acked 往下编码

    // First ACK Range: 从 largest_acked 往下的第一个连续区间长度减 1
    auto &last_interval = intervals.back();
    f.first_ack_range = last_interval.second - last_interval.first;

    // 后续区间（从大到小）
    for (int i = static_cast<int>(intervals.size()) - 2; i >= 0; --i) {
        auto &cur = intervals[i];
        auto &next = intervals[i + 1];

        // Gap: 下一个区间最小值 与 当前区间最大值之间的未确认包数量 减 1
        //   gap = next.first - cur.second - 2
        uint64_t gap = next.first - cur.second - 2;

        // ACK Range Length: 当前确认区间长度减 1
        uint64_t ack_len = cur.second - cur.first;

        f.ack_ranges.push_back({gap, ack_len});
    }

    return f;
}

// ============================================================================
// encode_ack_frame
// ============================================================================

std::vector<uint8_t> encode_ack_frame(const AckFrame &frame,
                                       uint8_t ack_delay_exponent) {
    std::vector<uint8_t> buf;

    // Type byte
    buf.push_back(frame.type);

    // Largest Acknowledged (VarInt)
    auto vi = util::varint_encode_vec(frame.largest_acked);
    buf.insert(buf.end(), vi.begin(), vi.end());

    // ACK Delay (VarInt) — 编码: field = delay_us / 2^exponent
    uint64_t delay_field = (ack_delay_exponent > 0 && frame.ack_delay_us > 0)
        ? frame.ack_delay_us >> ack_delay_exponent
        : frame.ack_delay_us;
    vi = util::varint_encode_vec(delay_field);
    buf.insert(buf.end(), vi.begin(), vi.end());

    // ACK Range Count (VarInt)
    vi = util::varint_encode_vec(frame.ack_ranges.size());
    buf.insert(buf.end(), vi.begin(), vi.end());

    // First ACK Range (VarInt)
    vi = util::varint_encode_vec(frame.first_ack_range);
    buf.insert(buf.end(), vi.begin(), vi.end());

    // ACK Ranges
    for (auto &r : frame.ack_ranges) {
        vi = util::varint_encode_vec(r.gap);
        buf.insert(buf.end(), vi.begin(), vi.end());
        vi = util::varint_encode_vec(r.ack_range_length);
        buf.insert(buf.end(), vi.begin(), vi.end());
    }

    // ECN Counts (if type == 0x03)
    if (frame.type == 0x03) {
        vi = util::varint_encode_vec(frame.ect0_count);
        buf.insert(buf.end(), vi.begin(), vi.end());
        vi = util::varint_encode_vec(frame.ect1_count);
        buf.insert(buf.end(), vi.begin(), vi.end());
        vi = util::varint_encode_vec(frame.ce_count);
        buf.insert(buf.end(), vi.begin(), vi.end());
    }

    return buf;
}

// ============================================================================
// decode_ack_frame
// ============================================================================

std::optional<AckFrame> decode_ack_frame(std::span<const uint8_t> data,
                                           uint8_t ack_delay_exponent) {
    if (data.empty()) return std::nullopt;

    AckFrame f;

    // Type byte
    uint8_t type = data[0];
    if (type != 0x02 && type != 0x03) return std::nullopt;
    f.type = type;

    size_t pos = 1;

    // Largest Acknowledged (VarInt)
    auto result = util::varint_decode(data.subspan(pos));
    if (!result) return std::nullopt;
    f.largest_acked = result->first;
    pos += result->second;

    // ACK Delay (VarInt) — 解码: delay_us = field * 2^exponent
    result = util::varint_decode(data.subspan(pos));
    if (!result) return std::nullopt;
    uint64_t delay_field = result->first;
    f.ack_delay_us = delay_field << ack_delay_exponent;
    pos += result->second;

    // ACK Range Count (VarInt)
    result = util::varint_decode(data.subspan(pos));
    if (!result) return std::nullopt;
    uint64_t range_count = result->first;
    pos += result->second;

    // First ACK Range (VarInt)
    result = util::varint_decode(data.subspan(pos));
    if (!result) return std::nullopt;
    f.first_ack_range = result->first;
    pos += result->second;

    // ACK Ranges
    for (uint64_t i = 0; i < range_count; ++i) {
        // Gap (VarInt)
        result = util::varint_decode(data.subspan(pos));
        if (!result) return std::nullopt;
        uint64_t gap = result->first;
        pos += result->second;

        // ACK Range Length (VarInt)
        result = util::varint_decode(data.subspan(pos));
        if (!result) return std::nullopt;
        uint64_t ack_len = result->first;
        pos += result->second;

        f.ack_ranges.push_back({gap, ack_len});
    }

    // ECN Counts (if type == 0x03)
    if (f.type == 0x03) {
        result = util::varint_decode(data.subspan(pos));
        if (!result) return std::nullopt;
        f.ect0_count = result->first;
        pos += result->second;

        result = util::varint_decode(data.subspan(pos));
        if (!result) return std::nullopt;
        f.ect1_count = result->first;
        pos += result->second;

        result = util::varint_decode(data.subspan(pos));
        if (!result) return std::nullopt;
        f.ce_count = result->first;
        pos += result->second;
    }

    return f;
}

// ============================================================================
// acked_pns_from_frame — 从 ACK 帧计算所有被确认的包编号
// ============================================================================

std::vector<uint64_t> acked_pns_from_frame(const AckFrame &frame) {
    std::vector<uint64_t> pns;

    if (frame.largest_acked == 0 && frame.first_ack_range == 0 && frame.ack_ranges.empty()) {
        return pns;
    }

    // v1.7.0.7 H3: 防御恶意 ACK 帧 — first_ack_range > largest_acked 会下溢，直接返回空
    if (frame.first_ack_range > frame.largest_acked) {
        return pns;
    }

    // 第一个连续区间：[largest_acked - first_ack_range, largest_acked]
    uint64_t range_start = frame.largest_acked - frame.first_ack_range;
    for (uint64_t pn = range_start; pn <= frame.largest_acked; ++pn) {
        pns.push_back(pn);
    }

    // 后续区间
    uint64_t current_top = range_start;

    for (auto &r : frame.ack_ranges) {
        // v1.7.0.7 H3: 防御下溢 — gap+1 > current_top 或 ack_range_length > acked_top 直接返回
        if (r.gap + 1 > current_top) {
            return pns;  // 恶意 gap 导致下溢，返回已收集的 pns
        }
        uint64_t unacked_bottom = current_top - (r.gap + 1);
        uint64_t acked_top = unacked_bottom - 1;
        if (r.ack_range_length > acked_top) {
            return pns;  // 恶意 ack_range_length 导致下溢
        }
        uint64_t acked_bottom = acked_top - r.ack_range_length;

        for (uint64_t pn = acked_bottom; pn <= acked_top; ++pn) {
            pns.push_back(pn);
        }
        current_top = acked_bottom;
    }

    // 排序结果（从小到大）
    std::sort(pns.begin(), pns.end());
    return pns;
}

} // namespace linoh::protocol
