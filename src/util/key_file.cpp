// linoh/util/key_file.cpp — endpoint_id 密钥文件持久化核心实现
//
// 文件格式 v1（42 字节）+ 旧格式兼容（32B/64B）+ 原子写 + 跨平台权限限制
//
// 此文件是密钥持久化的唯一权威实现，linoh C-API（linoh_c.cpp）和
// C++ 应用层（relay_bridge 等）都调用此处函数，避免逻辑重复。

#include "linoh/util/key_file.hpp"

#include "linoh/util/atomic_write.hpp"
#include "linoh/util/crc32.hpp"
#include "linoh/util/file_permission.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

namespace linoh::util {

namespace {

// 文件格式 v1 常量
constexpr uint8_t kMagicByte0 = 0x4C;  // 'L'
constexpr uint8_t kMagicByte1 = 0x4E;  // 'N'
constexpr uint8_t kMagicByte2 = 0x4F;  // 'O'
constexpr uint8_t kMagicByte3 = 0x48;  // 'H'
constexpr uint8_t kVersion1   = 0x01;
constexpr size_t kV1Size      = 42;
constexpr size_t kV1SkOffset  = 6;
constexpr size_t kV1CrcOffset = 38;
constexpr size_t kLegacySkSize  = 32;
constexpr size_t kLegacySkPkSize = 64;

/// 序列化 v1 格式到 42 字节缓冲区
void serialize_v1(uint8_t buf[kV1Size], const uint8_t sk[32]) {
    buf[0] = kMagicByte0;
    buf[1] = kMagicByte1;
    buf[2] = kMagicByte2;
    buf[3] = kMagicByte3;
    buf[4] = kVersion1;
    buf[5] = 0x00;  // flags
    std::memcpy(buf + kV1SkOffset, sk, 32);
    // CRC32(偏移 0..37)
    uint32_t crc = crc32_ieee(std::span<const uint8_t>(buf, kV1CrcOffset));
    // 小端写入
    buf[kV1CrcOffset]     = static_cast<uint8_t>(crc & 0xFF);
    buf[kV1CrcOffset + 1] = static_cast<uint8_t>((crc >> 8) & 0xFF);
    buf[kV1CrcOffset + 2] = static_cast<uint8_t>((crc >> 16) & 0xFF);
    buf[kV1CrcOffset + 3] = static_cast<uint8_t>((crc >> 24) & 0xFF);
}

/// 解析 v1 格式（含 magic/version/flags/CRC32 校验）
/// @return true 成功；false 格式不符或 CRC 校验失败
bool parse_v1(const uint8_t buf[kV1Size], uint8_t sk_out[32]) {
    if (buf[0] != kMagicByte0 || buf[1] != kMagicByte1 ||
        buf[2] != kMagicByte2 || buf[3] != kMagicByte3) {
        return false;  // magic 不匹配
    }
    if (buf[4] != kVersion1) {
        fprintf(stderr, "[LINOH] key_file: unsupported version %u\n", buf[4]);
        return false;
    }
    if (buf[5] != 0x00) {
        fprintf(stderr, "[LINOH] key_file: unsupported flags 0x%02X\n", buf[5]);
        return false;  // v1 flags 必须 0
    }
    // CRC32 校验
    uint32_t expected = crc32_ieee(std::span<const uint8_t>(buf, kV1CrcOffset));
    uint32_t actual = static_cast<uint32_t>(buf[kV1CrcOffset]) |
                      (static_cast<uint32_t>(buf[kV1CrcOffset + 1]) << 8) |
                      (static_cast<uint32_t>(buf[kV1CrcOffset + 2]) << 16) |
                      (static_cast<uint32_t>(buf[kV1CrcOffset + 3]) << 24);
    if (expected != actual) {
        fprintf(stderr, "[LINOH] key_file: CRC32 mismatch (expected=0x%08X actual=0x%08X)\n",
                expected, actual);
        return false;
    }
    std::memcpy(sk_out, buf + kV1SkOffset, 32);
    return true;
}

/// 读取整个文件到 vector
std::vector<uint8_t> read_file_all(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

} // namespace

bool save_key_file(std::string_view path, const base::SecretKey &sk) {
    if (path.empty() || sk.is_zero()) {
        fprintf(stderr, "[LINOH] key_file: save failed (empty path or zero key)\n");
        return false;
    }

    std::string p(path);
    uint8_t buf[kV1Size];
    auto sk_span = sk.as_span();
    serialize_v1(buf, sk_span.data());

    // 原子写：先写 .tmp 临时文件，再 rename
    if (!atomic_write_file(p, std::span<const uint8_t>(buf, kV1Size))) {
        fprintf(stderr, "[LINOH] key_file: atomic_write failed for %s\n", p.c_str());
        return false;
    }

    // 跨平台权限限制（原子写之后设置，确保临时文件和目标文件都被限制）
    // 注意：atomic_write_file 内部临时文件在 rename 后已被删除，目标文件继承
    //       临时文件的默认权限，因此此处对目标文件设置权限即可
    if (!restrict_file_permission(p)) {
        // 权限设置失败不阻断流程（文件已写入），但记录警告
        fprintf(stderr, "[LINOH] key_file: WARN restrict_file_permission failed for %s\n",
                p.c_str());
    }

    return true;
}

bool load_key_file(std::string_view path, base::SecretKey &out_sk) {
    if (path.empty()) return false;
    std::string p(path);

    auto bytes = read_file_all(p);
    if (bytes.empty()) {
        fprintf(stderr, "[LINOH] key_file: load failed (file empty or not found: %s)\n",
                p.c_str());
        return false;
    }

    uint8_t sk_bytes[32] = {};
    bool loaded = false;
    bool need_migrate = false;

    if (bytes.size() == kV1Size) {
        // 新格式 v1
        loaded = parse_v1(bytes.data(), sk_bytes);
    } else if (bytes.size() == kLegacySkPkSize) {
        // 旧 sk+pk 格式（64B），取前 32B 作为 sk
        fprintf(stderr, "[LINOH] key_file: legacy 64B (sk+pk) format detected, migrating...\n");
        std::memcpy(sk_bytes, bytes.data(), 32);
        loaded = true;
        need_migrate = true;
    } else if (bytes.size() == kLegacySkSize) {
        // 旧纯 sk 格式（32B）
        fprintf(stderr, "[LINOH] key_file: legacy 32B (sk-only) format detected, migrating...\n");
        std::memcpy(sk_bytes, bytes.data(), 32);
        loaded = true;
        need_migrate = true;
    } else {
        fprintf(stderr, "[LINOH] key_file: unknown format, size=%zu (expected 42/64/32)\n",
                bytes.size());
        return false;
    }

    if (!loaded) {
        return false;
    }

    out_sk = base::SecretKey::from_bytes(std::span<const uint8_t>(sk_bytes, 32));

    // 静默迁移：旧格式加载成功后用新格式覆盖保存
    if (need_migrate) {
        if (save_key_file(p, out_sk)) {
            fprintf(stderr, "[LINOH] key_file: migrated to v1 format (42B)\n");
        } else {
            fprintf(stderr, "[LINOH] key_file: WARN migration save failed, "
                    "loaded key remains valid\n");
            // 迁移失败不影响加载结果（密钥已加载成功）
        }
    }

    return true;
}

KeyFileLoadResult load_or_generate_key_file(std::string_view path) {
    KeyFileLoadResult result;

    if (path.empty()) {
        fprintf(stderr, "[LINOH] key_file: empty path\n");
        return result;
    }

    std::string p(path);

    // 文件存在 → 加载
    if (file_exists(p)) {
        if (load_key_file(p, result.sk)) {
            result.pk = result.sk.public_key();
            result.ok = true;
            return result;
        }
        fprintf(stderr, "[LINOH] key_file: load failed, generating new keypair\n");
        // 加载失败 → 重新生成（覆盖损坏文件）
    }

    // 文件不存在或加载失败 → 生成新密钥对
    result.sk = base::SecretKey::generate();
    if (result.sk.is_zero()) {
        fprintf(stderr, "[LINOH] key_file: SecretKey::generate failed\n");
        return result;
    }
    result.pk = result.sk.public_key();

    if (!save_key_file(p, result.sk)) {
        fprintf(stderr, "[LINOH] key_file: save new key failed for %s\n", p.c_str());
        return result;
    }

    fprintf(stderr, "[LINOH] key_file: generated new keypair, saved to %s\n", p.c_str());
    result.ok = true;
    return result;
}

} // namespace linoh::util
