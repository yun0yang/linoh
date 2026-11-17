// linoh/util/key_file.hpp — endpoint_id 密钥文件持久化（C++ 接口）
//
// 统一的 Ed25519 私钥文件持久化，供 linoh C-API 和 C++ 应用层共用。
//
// 文件格式 v1（42 字节）:
//   偏移  长度  字段     说明
//   0     4     magic    0x4C 0x4E 0x4F 0x48 ("LNOH"，小端 uint32 = 0x484F4E4C)
//   4     1     version  0x01
//   5     1     flags    0x00（bit0 预留：加密标志）
//   6     32    sk       Ed25519 私钥
//   38    4     crc32    CRC32(偏移0..37)，IEEE 802.3，小端 uint32
//
// 旧格式兼容（加载时按文件大小自动识别）:
//   - 42B + magic 正确 → v1 新格式，CRC32 校验
//   - 64B             → 旧 sk+pk 格式，取前 32B 作为 sk，静默迁移
//   - 32B             → 旧纯 sk 格式，直接作为 sk，静默迁移
//
// 安全保证：
//   - 原子写：先写 .tmp 临时文件，再 MoveFileExW/rename 原子替换
//   - 跨平台权限：Linux chmod 0600；Windows DACL 仅当前用户可访问（阻止继承）
//   - CRC32 完整性校验：检测磁盘损坏/半截写入

#pragma once

#include "linoh/base/key.hpp"

#include <string_view>

namespace linoh::util {

/// 密钥文件 v1 大小（42 字节）
/// 格式常量 LINOH_KEY_FILE_MAGIC_1/VERSION_1/V1_SIZE 定义在 linoh_c.h（C-API 公共头）
static constexpr size_t kKeyFileV1Size = 42;

/// 密钥文件加载结果
struct KeyFileLoadResult {
    base::SecretKey sk;
    base::PublicKey pk;
    bool ok{false};
};

/// 加载或生成密钥文件
/// - 文件存在 → 加载（自动识别新/旧格式，旧格式静默迁移）
/// - 文件不存在 → 生成新密钥对并保存
/// @param path 密钥文件路径（UTF-8）
/// @return KeyFileLoadResult（ok=false 表示失败）
KeyFileLoadResult load_or_generate_key_file(std::string_view path);

/// 仅保存私钥到文件（原子写 + 权限限制 + CRC32）
/// @param path 目标路径
/// @param sk 私钥
/// @return true 成功；false 失败
bool save_key_file(std::string_view path, const base::SecretKey &sk);

/// 仅加载私钥（自动识别新/旧格式，旧格式静默迁移为新格式）
/// @param path 密钥文件路径
/// @param[out] out_sk 加载成功的私钥
/// @return true 成功；false 失败（文件不存在/格式错误/CRC 校验失败）
bool load_key_file(std::string_view path, base::SecretKey &out_sk);

} // namespace linoh::util
