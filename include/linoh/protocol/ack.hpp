// linoh/protocol/ack.hpp — QUIC ACK Frame (RFC 9000 §19.3)
//
// ACK Frame format:
//   Type (0x02 or 0x03)         — 1 byte
//   Largest Acknowledged        — VarInt
//   ACK Delay                   — VarInt (8-bit exponent encoded: delay * 2^ack_delay_exponent)
//   ACK Range Count             — VarInt
//   First ACK Range             — VarInt
//   ACK Ranges (optional)       — [Gap(VarInt), ACK Range Length(VarInt)] × N
//   ECN Counts (if Type=0x03)   — [ECT0(VarInt), ECT1(VarInt), CE(VarInt)]
//
// ACK Range encoding:
//   Every ACK Range acknowledges a contiguous range of packets.
//   The "First ACK Range" is the range just below Largest Acknowledged.
//   Subsequent ranges alternate between Gap (unacknowledged) and ACK Range Length.

#pragma once

#include "linoh/util/varint.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace linoh::protocol {

/// ACK 延迟指数（RFC 9000 §17.4.4：发送端告知接收端如何解码 ACK Delay）。
/// 默认值 3 → delay = ack_delay_field * 2^3 微秒。
static constexpr uint8_t kDefaultAckDelayExponent = 3;

/// 单个 ACK Range：一个连续的已确认包编号区间。
struct AckRange {
    uint64_t gap;              // 与前一个确认区间之间的未确认包数量
    uint64_t ack_range_length; // 本确认区间中的包数量（减 1 后存储）
};

/// ACK Frame 数据结构。
struct AckFrame {
    /// 0x02 = ACK（不含 ECN），0x03 = ACK_ECN（含 ECN 计数）
    uint8_t type = 0x02;

    /// 本帧确认的最大包编号。
    uint64_t largest_acked = 0;

    /// ACK Delay，单位：微秒（解码后）。
    /// 编码方式：field_value = delay_us / 2^ack_delay_exponent
    uint64_t ack_delay_us = 0;

    /// 从 largest_acked 往下连续确认的包数量减 1（First ACK Range）。
    /// 例：largest_acked=10, first_ack_range=3 → 确认了 10,9,8,7
    uint64_t first_ack_range = 0;

    /// 后续确认区间（交替 gap + ack_range_length）。
    std::vector<AckRange> ack_ranges;

    /// ECN 计数（仅 type=0x03 时有效）
    uint64_t ect0_count = 0;
    uint64_t ect1_count = 0;
    uint64_t ce_count   = 0;

    /// 从已确认的包编号集合构建 AckFrame。
    /// `acked_pns` 必须已排序（从小到大）。
    static AckFrame from_acked_pns(const std::vector<uint64_t> &acked_pns,
                                   uint64_t ack_delay_us,
                                   uint8_t type = 0x02);
};

/// 将 AckFrame 编码为字节序列（使用 QUIC VarInt）。
std::vector<uint8_t> encode_ack_frame(const AckFrame &frame,
                                      uint8_t ack_delay_exponent = kDefaultAckDelayExponent);

/// 从字节序列解码 AckFrame。
std::optional<AckFrame> decode_ack_frame(std::span<const uint8_t> data,
                                          uint8_t ack_delay_exponent = kDefaultAckDelayExponent);

/// 从 AckFrame 计算所有被确认的包编号集合。
std::vector<uint64_t> acked_pns_from_frame(const AckFrame &frame);

} // namespace linoh::protocol
