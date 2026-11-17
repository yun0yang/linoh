// config_entry.cpp — 配置条目/快照/增量序列化实现（v2.1 Phase 2）
//
// 复用 HeartbeatPayload 的小端序二进制序列化模式（src/multimodal/control_channel.cpp）。
// 所有多字节字段使用小端序，字符串以 2 字节长度前缀编码。

#include "linoh/config_entry.hpp"

#include <cstring>

namespace linoh {

// ============================================================================
// 序列化辅助函数（小端序）
// ============================================================================

namespace {

/// 写入 u16（小端序）
void put_u16(std::vector<std::uint8_t> &buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

/// 写入 u64（小端序）
void put_u64(std::vector<std::uint8_t> &buf, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

/// 写入字符串（2 字节长度前缀 + 内容）
void put_string(std::vector<std::uint8_t> &buf, const std::string &s) {
    put_u16(buf, static_cast<std::uint16_t>(s.size()));
    buf.insert(buf.end(), s.begin(), s.end());
}

/// 读取 u16（小端序）
std::uint16_t get_u16(std::span<const std::uint8_t> data, std::size_t off) {
    return static_cast<std::uint16_t>(data[off]) |
           (static_cast<std::uint16_t>(data[off + 1]) << 8);
}

/// 读取 u64（小端序）
std::uint64_t get_u64(std::span<const std::uint8_t> data, std::size_t off) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<std::uint64_t>(data[off + i]) << (i * 8);
    }
    return v;
}

/// 读取字符串（2 字节长度前缀 + 内容）
/// @return 消费字节数，0 表示数据不足
std::size_t get_string(std::span<const std::uint8_t> data, std::size_t off, std::string &out) {
    if (off + 2 > data.size()) return 0;
    std::uint16_t len = get_u16(data, off);
    if (off + 2 + len > data.size()) return 0;
    out.assign(reinterpret_cast<const char *>(data.data() + off + 2), len);
    return 2 + len;
}

/// TimePoint ↔ 毫秒时间戳
std::uint64_t timepoint_to_ms(TimePoint tp) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            tp.time_since_epoch()).count());
}

TimePoint ms_to_timepoint(std::uint64_t ms) {
    return TimePoint(std::chrono::milliseconds(ms));
}

}  // anonymous namespace

// ============================================================================
// ConfigEntry 序列化
// ============================================================================

std::vector<std::uint8_t> ConfigEntry::serialize() const {
    std::vector<std::uint8_t> buf;
    buf.reserve(4 + key.size() + value.size() + 16);
    put_string(buf, key);
    put_string(buf, value);
    put_u64(buf, version);
    put_u64(buf, timepoint_to_ms(updated_at));
    return buf;
}

std::size_t ConfigEntry::parse(std::span<const std::uint8_t> data, ConfigEntry &out) {
    std::size_t off = 0;
    // key
    auto n = get_string(data, off, out.key);
    if (n == 0) return 0;
    off += n;
    // value
    n = get_string(data, off, out.value);
    if (n == 0) return 0;
    off += n;
    // version
    if (off + 8 > data.size()) return 0;
    out.version = get_u64(data, off);
    off += 8;
    // timestamp
    if (off + 8 > data.size()) return 0;
    out.updated_at = ms_to_timepoint(get_u64(data, off));
    off += 8;
    return off;
}

// ============================================================================
// ConfigSnapshot 序列化
// ============================================================================

std::vector<std::uint8_t> ConfigSnapshot::signing_data() const {
    std::vector<std::uint8_t> buf;
    put_u64(buf, epoch);
    put_u64(buf, timepoint_to_ms(created_at));
    // origin (32 bytes)
    buf.insert(buf.end(), origin.data(), origin.data() + origin.size());
    // entries
    put_u16(buf, static_cast<std::uint16_t>(entries.size()));
    for (const auto &e : entries) {
        auto ebytes = e.serialize();
        buf.insert(buf.end(), ebytes.begin(), ebytes.end());
    }
    return buf;
}

std::vector<std::uint8_t> ConfigSnapshot::serialize() const {
    auto buf = signing_data();
    // signature (64 bytes)
    buf.insert(buf.end(), signature.begin(), signature.end());
    return buf;
}

std::size_t ConfigSnapshot::parse(std::span<const std::uint8_t> data, ConfigSnapshot &out) {
    std::size_t off = 0;
    // epoch
    if (off + 8 > data.size()) return 0;
    out.epoch = get_u64(data, off);
    off += 8;
    // created_at
    if (off + 8 > data.size()) return 0;
    out.created_at = ms_to_timepoint(get_u64(data, off));
    off += 8;
    // origin (32 bytes)
    if (off + 32 > data.size()) return 0;
    std::memcpy(out.origin.data(), data.data() + off, 32);
    off += 32;
    // entry_count
    if (off + 2 > data.size()) return 0;
    std::uint16_t entry_count = get_u16(data, off);
    off += 2;
    // entries
    out.entries.clear();
    out.entries.reserve(entry_count);
    for (std::uint16_t i = 0; i < entry_count; ++i) {
        ConfigEntry e;
        auto n = ConfigEntry::parse(data.subspan(off), e);
        if (n == 0) return 0;
        out.entries.push_back(std::move(e));
        off += n;
    }
    // signature (64 bytes)
    if (off + 64 > data.size()) return 0;
    std::memcpy(out.signature.data(), data.data() + off, 64);
    off += 64;
    return off;
}

// ============================================================================
// ConfigDelta 序列化
// ============================================================================

std::vector<std::uint8_t> ConfigDelta::signing_data() const {
    std::vector<std::uint8_t> buf;
    put_u64(buf, from_epoch);
    put_u64(buf, to_epoch);
    // changes
    put_u16(buf, static_cast<std::uint16_t>(changes.size()));
    for (const auto &e : changes) {
        auto ebytes = e.serialize();
        buf.insert(buf.end(), ebytes.begin(), ebytes.end());
    }
    // deletions
    put_u16(buf, static_cast<std::uint16_t>(deletions.size()));
    for (const auto &d : deletions) {
        put_string(buf, d);
    }
    return buf;
}

std::vector<std::uint8_t> ConfigDelta::serialize() const {
    auto buf = signing_data();
    // signature (64 bytes)
    buf.insert(buf.end(), signature.begin(), signature.end());
    return buf;
}

std::size_t ConfigDelta::parse(std::span<const std::uint8_t> data, ConfigDelta &out) {
    std::size_t off = 0;
    // from_epoch
    if (off + 8 > data.size()) return 0;
    out.from_epoch = get_u64(data, off);
    off += 8;
    // to_epoch
    if (off + 8 > data.size()) return 0;
    out.to_epoch = get_u64(data, off);
    off += 8;
    // change_count
    if (off + 2 > data.size()) return 0;
    std::uint16_t change_count = get_u16(data, off);
    off += 2;
    // changes
    out.changes.clear();
    out.changes.reserve(change_count);
    for (std::uint16_t i = 0; i < change_count; ++i) {
        ConfigEntry e;
        auto n = ConfigEntry::parse(data.subspan(off), e);
        if (n == 0) return 0;
        out.changes.push_back(std::move(e));
        off += n;
    }
    // deletion_count
    if (off + 2 > data.size()) return 0;
    std::uint16_t deletion_count = get_u16(data, off);
    off += 2;
    // deletions
    out.deletions.clear();
    out.deletions.reserve(deletion_count);
    for (std::uint16_t i = 0; i < deletion_count; ++i) {
        std::string s;
        auto n = get_string(data, off, s);
        if (n == 0) return 0;
        out.deletions.push_back(std::move(s));
        off += n;
    }
    // signature (64 bytes)
    if (off + 64 > data.size()) return 0;
    std::memcpy(out.signature.data(), data.data() + off, 64);
    off += 64;
    return off;
}

}  // namespace linoh
