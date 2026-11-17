// linoh/util/varint.hpp — QUIC Variable-Length Integer (RFC 9000 §16)
//
// 2-bit length prefix in first byte:
//   00 → 1 byte  ( 6-bit value, max 63)
//   01 → 2 bytes (14-bit value, max 16383)
//   10 → 4 bytes (30-bit value, max 1073741823)
//   11 → 8 bytes (62-bit value, max 2^62-1)
//
// Values are encoded in big-endian byte order.

#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

namespace linoh::util {

/// Minimum number of bytes needed to encode `value` as a QUIC VarInt.
constexpr std::size_t varint_len(uint64_t value) {
    if (value < 64)        return 1;   // 2^6
    if (value < 16384)     return 2;   // 2^14
    if (value < 1073741824) return 4;  // 2^30
    return 8;                          // 2^62
}

/// Encode `value` as a QUIC VarInt into `buf`. Returns number of bytes written.
/// `buf` must have at least varint_len(value) bytes available.
inline std::size_t varint_encode(uint64_t value, std::span<uint8_t> buf) {
    const std::size_t len = varint_len(value);
    if (buf.size() < len) return 0;

    // Set the 2-bit prefix based on length
    switch (len) {
    case 1:
        buf[0] = static_cast<uint8_t>(value & 0x3F);  // prefix 00
        break;
    case 2:
        buf[0] = static_cast<uint8_t>(((value >> 8) & 0x3F) | 0x40);  // prefix 01
        buf[1] = static_cast<uint8_t>(value & 0xFF);
        break;
    case 4:
        buf[0] = static_cast<uint8_t>(((value >> 24) & 0x3F) | 0x80);  // prefix 10
        buf[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        buf[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        buf[3] = static_cast<uint8_t>(value & 0xFF);
        break;
    case 8:
        buf[0] = static_cast<uint8_t>(((value >> 56) & 0x3F) | 0xC0);  // prefix 11
        buf[1] = static_cast<uint8_t>((value >> 48) & 0xFF);
        buf[2] = static_cast<uint8_t>((value >> 40) & 0xFF);
        buf[3] = static_cast<uint8_t>((value >> 32) & 0xFF);
        buf[4] = static_cast<uint8_t>((value >> 24) & 0xFF);
        buf[5] = static_cast<uint8_t>((value >> 16) & 0xFF);
        buf[6] = static_cast<uint8_t>((value >> 8) & 0xFF);
        buf[7] = static_cast<uint8_t>(value & 0xFF);
        break;
    default:
        return 0;  // unreachable
    }
    return len;
}

/// Encode `value` as a QUIC VarInt into a vector.
inline std::vector<uint8_t> varint_encode_vec(uint64_t value) {
    const std::size_t len = varint_len(value);
    std::vector<uint8_t> buf(len);
    varint_encode(value, buf);
    return buf;
}

/// Decode a QUIC VarInt from `data`. Returns {value, bytes_consumed} or nullopt on error.
inline std::optional<std::pair<uint64_t, std::size_t>> varint_decode(std::span<const uint8_t> data) {
    if (data.empty()) return std::nullopt;

    // Read the 2-bit prefix
    const uint8_t first = data[0];
    const uint8_t prefix = (first >> 6) & 0x03;

    std::size_t len;
    uint64_t value;

    switch (prefix) {
    case 0:  // 1 byte
        len = 1;
        value = first & 0x3F;
        break;
    case 1:  // 2 bytes
        len = 2;
        if (data.size() < 2) return std::nullopt;
        value = ((static_cast<uint64_t>(first & 0x3F) << 8) |
                  static_cast<uint64_t>(data[1]));
        break;
    case 2:  // 4 bytes
        len = 4;
        if (data.size() < 4) return std::nullopt;
        value = ((static_cast<uint64_t>(first & 0x3F) << 24) |
                 (static_cast<uint64_t>(data[1]) << 16) |
                 (static_cast<uint64_t>(data[2]) << 8) |
                  static_cast<uint64_t>(data[3]));
        break;
    case 3:  // 8 bytes
        len = 8;
        if (data.size() < 8) return std::nullopt;
        value = ((static_cast<uint64_t>(first & 0x3F) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (static_cast<uint64_t>(data[2]) << 40) |
                 (static_cast<uint64_t>(data[3]) << 32) |
                 (static_cast<uint64_t>(data[4]) << 24) |
                 (static_cast<uint64_t>(data[5]) << 16) |
                 (static_cast<uint64_t>(data[6]) << 8) |
                  static_cast<uint64_t>(data[7]));
        break;
    default:
        return std::nullopt;  // unreachable
    }
    return std::make_pair(value, len);
}

}  // namespace linoh::util
