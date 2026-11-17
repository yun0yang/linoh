// shard_bitfield.cpp — v4.0.2 M20 分片可用性同步协议实现
//
// 实现 ShardBitfield 的 RLE 压缩与编解码逻辑。
// 详见 shard_bitfield.hpp 字段布局说明。

#include "linoh/protocol/shard_bitfield.hpp"

#include <cstring>
#include <sstream>

namespace linoh::protocol {

// ============================================================================
// 小端序读写辅助（与 connect_policy.cpp 风格一致）
// ============================================================================

namespace {

inline void put_u16_le(std::vector<std::uint8_t> &buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

inline void put_u32_le(std::vector<std::uint8_t> &buf, std::uint32_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
}

inline void put_u64_le(std::vector<std::uint8_t> &buf, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

inline std::uint16_t get_u16_le(const std::uint8_t *p) {
    return static_cast<std::uint16_t>(p[0]) |
           (static_cast<std::uint16_t>(p[1]) << 8);
}

inline std::uint32_t get_u32_le(const std::uint8_t *p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

inline std::uint64_t get_u64_le(const std::uint8_t *p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<std::uint64_t>(p[i]) << (i * 8);
    }
    return v;
}

}  // namespace

// ============================================================================
// RLE 压缩（PackBits 风格）
// ============================================================================
//
// 控制字节 c：
//   0x00-0x7F (0-127): literal run，后跟 (c+1) 个字节（1-128 字节 literal 数据）
//   0x80-0xFF (128-255): repeat run，后跟 1 个字节，重复 (c-128+2) 次（2-129 次）

std::vector<std::uint8_t> ShardBitfield::rle_encode(std::span<const std::uint8_t> raw) {
    std::vector<std::uint8_t> out;
    const std::size_t len = raw.size();
    if (len == 0) return out;

    out.reserve(len);  // RLE 通常会缩小，预分配原始大小避免频繁 realloc

    std::size_t i = 0;
    while (i < len) {
        // 检测连续相同字节的 run 长度
        std::size_t run = 1;
        while (i + run < len && raw[i] == raw[i + run] && run < 129) {
            ++run;
        }

        if (run >= 2) {
            // repeat run：2-129 个相同字节
            out.push_back(static_cast<std::uint8_t>(0x80 | (run - 2)));
            out.push_back(raw[i]);
            i += run;
        } else {
            // literal run：收集直到遇到 run>=2 或达到 128 字节
            std::size_t lit_start = i;
            ++i;  // 至少 1 个字节
            while (i < len) {
                // 检查下一个位置是否开始一个 >=2 的 run
                bool next_is_run = (i + 1 < len && raw[i] == raw[i + 1]);
                if (next_is_run) break;
                if (i - lit_start + 1 >= 128) break;
                ++i;
            }
            std::size_t lit_len = i - lit_start;
            out.push_back(static_cast<std::uint8_t>(lit_len - 1));  // 0-127 表示 1-128
            out.insert(out.end(), raw.data() + lit_start, raw.data() + i);
        }
    }
    return out;
}

std::vector<std::uint8_t> ShardBitfield::rle_decode(std::span<const std::uint8_t> rle) {
    std::vector<std::uint8_t> out;
    const std::size_t len = rle.size();
    std::size_t i = 0;
    while (i < len) {
        std::uint8_t c = rle[i++];
        if (c & 0x80) {
            // repeat run：(c & 0x7F) + 2 个相同字节
            std::size_t count = static_cast<std::size_t>(c & 0x7F) + 2;
            if (i >= len) return {};  // 损坏：缺少 repeat value
            std::uint8_t value = rle[i++];
            out.insert(out.end(), count, value);
        } else {
            // literal run：c + 1 个 literal 字节
            std::size_t count = static_cast<std::size_t>(c) + 1;
            if (i + count > len) return {};  // 损坏：literal 数据不足
            out.insert(out.end(), rle.data() + i, rle.data() + i + count);
            i += count;
        }
    }
    return out;
}

// ============================================================================
// ShardBitfield 编解码
// ============================================================================

std::vector<std::uint8_t> ShardBitfield::encode() const {
    // 校验 total_shards 合法性
    if (total_shards > kMaxShards) return {};

    // 校验 bitmap 长度与 total_shards 一致
    const std::size_t expected_bytes = bitmap_bytes(total_shards);
    if (bitmap.size() != expected_bytes) return {};

    // RLE 压缩 bitmap
    std::vector<std::uint8_t> rle = rle_encode(bitmap);
    if (rle.size() > kMaxRleBitmapLen) return {};  // 压缩后仍超限

    std::vector<std::uint8_t> buf;
    buf.reserve(kMinEncodedSize + rle.size());

    // offset 0: version (1B)
    buf.push_back(kCurrentVersion);

    // offset 1: flags (1B, bit0=is_incremental)
    std::uint8_t flags = is_incremental ? 0x01 : 0x00;
    buf.push_back(flags);

    // offset 2: tensor_id (8B, 小端)
    put_u64_le(buf, tensor_id);

    // offset 10: total_shards (4B, 小端)
    put_u32_le(buf, total_shards);

    // offset 14: base_shard_idx (4B, 小端)
    put_u32_le(buf, base_shard_idx);

    // offset 18: rle_bitmap_len (2B, 小端)
    put_u16_le(buf, static_cast<std::uint16_t>(rle.size()));

    // offset 20: rle_bitmap (N B)
    buf.insert(buf.end(), rle.begin(), rle.end());

    return buf;
}

bool ShardBitfield::decode(std::span<const std::uint8_t> data, ShardBitfield &out) {
    if (data.size() < kMinEncodedSize) return false;

    const std::uint8_t *p = data.data();

    // offset 0: version (1B)
    std::uint8_t version = p[0];
    if (version != kCurrentVersion) return false;

    // offset 1: flags (1B, bit0=is_incremental, bit1-7 reserved 忽略)
    std::uint8_t flags = p[1];
    out.is_incremental = (flags & 0x01) != 0;

    // offset 2: tensor_id (8B, 小端)
    out.tensor_id = get_u64_le(p + 2);

    // offset 10: total_shards (4B, 小端)
    out.total_shards = get_u32_le(p + 10);
    if (out.total_shards > kMaxShards) return false;

    // offset 14: base_shard_idx (4B, 小端)
    out.base_shard_idx = get_u32_le(p + 14);

    // offset 18: rle_bitmap_len (2B, 小端)
    std::uint16_t rle_len = get_u16_le(p + 18);

    // 校验 rle_bitmap 数据完整性
    if (data.size() < kMinEncodedSize + rle_len) return false;

    // offset 20: rle_bitmap (N B)
    std::span<const std::uint8_t> rle_span(p + 20, rle_len);
    std::vector<std::uint8_t> raw = rle_decode(rle_span);

    // RLE 解压失败（数据损坏）
    // 注意：rle_len==0 时 raw 为空，需要校验 total_shards 是否也为 0
    if (rle_len > 0 && raw.empty()) return false;

    // 校验解压后长度与 total_shards 一致
    const std::size_t expected_bytes = bitmap_bytes(out.total_shards);
    if (raw.size() != expected_bytes) return false;

    out.bitmap = std::move(raw);
    return true;
}

std::string ShardBitfield::to_string() const {
    std::ostringstream oss;
    oss << "ShardBitfield{tensor_id=0x" << std::hex << tensor_id
        << std::dec << ", total_shards=" << total_shards
        << ", available=" << available_count()
        << ", is_incremental=" << (is_incremental ? "true" : "false")
        << ", base_shard_idx=" << base_shard_idx
        << ", bitmap_bytes=" << bitmap.size()
        << "}";
    return oss.str();
}

}  // namespace linoh::protocol
