// session_id.cpp — V3.4 SessionId 实现
//
// generate() 使用 linoh::crypto::crypto_random_bytes（Windows BCryptGenRandom /
// 等价 CSPRNG）填充 16 字节，再按 RFC 4122 设置 version=4 / variant=RFC4122 位。
//
// to_string() 输出标准 UUID 8-4-4-4-12 格式（小写十六进制 + 连字符）。

#include "linoh/protocol/session_id.hpp"

#include <cstring>  // std::memcpy

#include "linoh/util/crypto.hpp"  // linoh::crypto::crypto_random_bytes

namespace linoh::protocol {

SessionId SessionId::generate() {
    SessionId sid;
    // crypto_random_bytes 使用 Windows BCryptGenRandom / 等价 CSPRNG，线程安全
    // sid.bytes 为 std::array<uint8_t,16>，隐式转换为 std::span<uint8_t>
    if (!linoh::crypto::crypto_random_bytes(sid.bytes)) {
        // CSPRNG 失败极少见（仅系统熵池异常），降级为全零（is_null==true）
        // 调用方应检查 is_null 并决定是否重试
        return sid;
    }
    // 设置 UUID v4 version + variant 位（RFC 4122）
    sid.bytes[6] = static_cast<std::uint8_t>((sid.bytes[6] & 0x0F) | 0x40);  // version = 4
    sid.bytes[8] = static_cast<std::uint8_t>((sid.bytes[8] & 0x3F) | 0x80);  // variant = RFC 4122
    return sid;
}

std::optional<SessionId> SessionId::parse(std::span<const std::uint8_t> in) {
    if (in.size() < kSize) {
        return std::nullopt;
    }
    SessionId sid;
    std::memcpy(sid.bytes.data(), in.data(), kSize);
    return sid;
}

void SessionId::serialize_to(std::span<std::uint8_t, kSize> out) const {
    std::memcpy(out.data(), bytes.data(), kSize);
}

bool SessionId::is_null() const noexcept {
    // 16 字节全零判断（展开为两次 uint64_t 比较，配合 memcpy 避免对齐 UB）
    std::uint64_t lo = 0, hi = 0;
    std::memcpy(&lo, bytes.data(), 8);
    std::memcpy(&hi, bytes.data() + 8, 8);
    return (lo | hi) == 0;
}

std::string SessionId::to_string() const {
    // UUID 格式：8-4-4-4-12（小写十六进制 + 4 个连字符 = 36 字符）
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(36);
    const auto *p = bytes.data();
    // field 1: bytes[0..3] → 8 hex
    for (int i = 0; i < 4; ++i) {
        s.push_back(kHex[p[i] >> 4]);
        s.push_back(kHex[p[i] & 0x0F]);
    }
    s.push_back('-');
    // field 2: bytes[4..5] → 4 hex
    for (int i = 4; i < 6; ++i) {
        s.push_back(kHex[p[i] >> 4]);
        s.push_back(kHex[p[i] & 0x0F]);
    }
    s.push_back('-');
    // field 3: bytes[6..7] → 4 hex（byte[6] 高 4 位 = 0x4，version）
    for (int i = 6; i < 8; ++i) {
        s.push_back(kHex[p[i] >> 4]);
        s.push_back(kHex[p[i] & 0x0F]);
    }
    s.push_back('-');
    // field 4: bytes[8..9] → 4 hex（byte[8] 高 2 位 = 0b10，variant）
    for (int i = 8; i < 10; ++i) {
        s.push_back(kHex[p[i] >> 4]);
        s.push_back(kHex[p[i] & 0x0F]);
    }
    s.push_back('-');
    // field 5: bytes[10..15] → 12 hex
    for (int i = 10; i < 16; ++i) {
        s.push_back(kHex[p[i] >> 4]);
        s.push_back(kHex[p[i] & 0x0F]);
    }
    return s;
}

}  // namespace linoh::protocol
