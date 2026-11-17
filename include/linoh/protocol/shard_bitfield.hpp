// shard_bitfield.hpp — v4.0.2 M20 分片可用性同步协议
//
// shard 可用性位图与 RLE 压缩，借鉴 sendme Bitfield 模式。
// 节点通过 ctrl/1 ALPN 发送 Observe(0x0045) 携带 ShardBitfield payload，
// 上游据此跳过已到达 shard，避免重复发送。
//
// 设计要点：
//   - 全量同步：tensor 首次到达时发送完整 bitmap（is_incremental=false）
//   - 增量同步：后续 shard 到达时发送增量变更（is_incremental=true，base_shard_idx 基准）
//   - 周期同步：每 5s 发送一次全量 bitmap（防增量丢失，由上层调度）
//   - RLE 压缩：bitmap 字节流用 PackBits 风格 RLE 压缩，大 tensor（100+ shards）压缩比 >5×
//   - 向后兼容：旧节点不识别 Observe MethodId → 丢弃（等价不发，上游发全量 shard）
//
// ShardBitfield 编码布局（变长）：
//   offset  size  field
//   0       1     version (当前 1)
//   1       1     flags (bit0=is_incremental, bit1-7 reserved)
//   2       8     tensor_id (小端序)
//   10      4     total_shards (小端序)
//   14      4     base_shard_idx (小端序)
//   18      2     rle_bitmap_len (小端序, 0-65535)
//   20      N     rle_bitmap (RLE 压缩后的字节流, N=rle_bitmap_len)
//
// 最小编码长度：20 字节（bitmap 为空时）
//
// RLE 压缩格式（PackBits 风格）：
//   控制字节 c：
//     0x00-0x7F (0-127): literal run，后跟 (c+1) 个字节（1-128 字节 literal 数据）
//     0x80-0xFF (128-255): repeat run，后跟 1 个字节，重复 (c-128+2) 次（2-129 次相同字节）
//   空输入编码为 0 字节（rle_bitmap_len=0）
//
// 字节序：多字节字段使用小端序（与 connect_policy.hpp 一致）。
// 向后兼容：version 字段允许未来扩展；flags bit1-7 保留位 decode 时忽略。

#pragma once

#include <bit>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace linoh::protocol {

/// shard 可用性位图（Observe 帧的 payload）
//
// 记录某 tensor 各 shard 的到达状态，每 bit 对应一个 shard：
//   - bit=1：shard 已到达（可用）
//   - bit=0：shard 未到达
//
// 支持全量与增量两种同步模式：
//   - 全量（is_incremental=false）：bitmap 表示 tensor 当前完整可用性状态
//   - 增量（is_incremental=true）：bitmap 表示自 base_shard_idx 起的变更
struct ShardBitfield {
    static constexpr std::uint8_t kCurrentVersion = 1;
    static constexpr std::size_t kMinEncodedSize = 20;  // version(1)+flags(1)+tensor_id(8)+total_shards(4)+base_shard_idx(4)+rle_len(2)
    static constexpr std::uint32_t kMaxShards = 524287;  // (65535*8-1)，受 rle_bitmap_len 2B 限制
    static constexpr std::uint16_t kMaxRleBitmapLen = 65535;

    /// 张量 ID
    std::uint64_t tensor_id{0};
    /// 总分片数
    std::uint32_t total_shards{0};
    /// 可用性位图（原始，每 bit 一个 shard；bit i = shard i 的可用性）
    std::vector<std::uint8_t> bitmap;
    /// true=增量变更，false=全量当前状态
    bool is_incremental{false};
    /// 增量模式：基准起始索引（全量模式忽略，应为 0）
    std::uint32_t base_shard_idx{0};

    // ---- 位图操作 ----

    /// 计算指定 total_shards 所需的 bitmap 字节数
    static constexpr std::size_t bitmap_bytes(std::uint32_t total_shards) noexcept {
        return total_shards == 0 ? 0 : (static_cast<std::size_t>(total_shards) + 7) / 8;
    }

    /// 按 total_shards 调整 bitmap 大小（新空间填 0）
    void resize_for_total() {
        bitmap.assign(bitmap_bytes(total_shards), 0);
    }

    /// 设置 shard idx 为可用（bit=1）。越界返回 false。
    bool set_shard(std::uint32_t idx) noexcept {
        if (idx >= total_shards) return false;
        const std::size_t byte_pos = idx / 8;
        const std::uint8_t bit_mask = static_cast<std::uint8_t>(0x80 >> (idx % 8));
        if (byte_pos >= bitmap.size()) return false;
        bitmap[byte_pos] |= bit_mask;
        return true;
    }

    /// 清除 shard idx（bit=0）。越界返回 false。
    bool clear_shard(std::uint32_t idx) noexcept {
        if (idx >= total_shards) return false;
        const std::size_t byte_pos = idx / 8;
        const std::uint8_t bit_mask = static_cast<std::uint8_t>(~(0x80 >> (idx % 8)));
        if (byte_pos >= bitmap.size()) return false;
        bitmap[byte_pos] &= bit_mask;
        return true;
    }

    /// 查询 shard idx 是否可用。越界返回 false。
    bool get_shard(std::uint32_t idx) const noexcept {
        if (idx >= total_shards) return false;
        const std::size_t byte_pos = idx / 8;
        const std::uint8_t bit_mask = static_cast<std::uint8_t>(0x80 >> (idx % 8));
        if (byte_pos >= bitmap.size()) return false;
        return (bitmap[byte_pos] & bit_mask) != 0;
    }

    /// 统计已可用 shard 数
    std::uint32_t available_count() const noexcept {
        std::uint32_t count = 0;
        for (std::uint8_t b : bitmap) {
            count += static_cast<std::uint32_t>(std::popcount(b));
        }
        // 末尾字节可能有 padding bit，按 total_shards 截断
        if (count > total_shards) count = total_shards;
        return count;
    }

    /// 是否所有 shard 都已可用
    bool is_complete() const noexcept {
        return total_shards > 0 && available_count() == total_shards;
    }

    // ---- 序列化 ----

    /// 序列化为字节流（含 RLE 压缩 bitmap）
    /// @return 编码后的字节流；total_shards 非法时返回空 vector
    std::vector<std::uint8_t> encode() const;

    /// 从字节流反序列化（自动 RLE 解压）
    /// @return true=成功，false=数据格式错误（长度不足/version 不匹配/字段越界/RLE 损坏）
    static bool decode(std::span<const std::uint8_t> data, ShardBitfield &out);

    /// 简要描述（日志用）
    std::string to_string() const;

    /// 相等比较（测试用，忽略 version 差异，比较所有业务字段）
    bool operator==(const ShardBitfield &other) const noexcept {
        return tensor_id == other.tensor_id &&
               total_shards == other.total_shards &&
               bitmap == other.bitmap &&
               is_incremental == other.is_incremental &&
               base_shard_idx == other.base_shard_idx;
    }

    // ---- RLE 压缩（公开，便于单测）----

    /// RLE 压缩原始字节流
    static std::vector<std::uint8_t> rle_encode(std::span<const std::uint8_t> raw);

    /// RLE 解压字节流
    /// @return 解压后的字节流；输入损坏时返回空 vector
    static std::vector<std::uint8_t> rle_decode(std::span<const std::uint8_t> rle);
};

/// Observe MethodId 转字符串（日志用）
inline const char *observe_method_name() noexcept {
    return "Observe";
}

}  // namespace linoh::protocol
