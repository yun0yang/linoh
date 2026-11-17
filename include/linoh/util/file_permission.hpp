// linoh/util/file_permission.hpp — 跨平台文件权限限制
//
// 将文件权限限制为仅 owner（当前用户）可读写，移除其他用户/组的访问。
//
// 平台实现：
//   - Linux:   chmod(path, 0600)
//   - Windows: 重建 DACL，仅授予当前用户 FILE_GENERIC_READ|FILE_GENERIC_WRITE|DELETE，
//              并设置 PROTECTED_DACL_SECURITY_INFORMATION 阻止继承父目录 ACE
//
// 用于密钥文件持久化的安全基线（硬约束：私钥文件仅 owner 可访问）

#pragma once

#include <string_view>

namespace linoh::util {

/// 限制文件权限为仅 owner 可读写
/// @param path 文件路径（UTF-8）
/// @return true 成功；false 失败（不改变原有权限）
/// @note Linux: chmod 0600
/// @note Windows: 重建 DACL 仅当前用户可访问，阻止继承
/// @note 调用方应确保文件已存在（权限设置在原子写之后）
bool restrict_file_permission(std::string_view path);

} // namespace linoh::util
