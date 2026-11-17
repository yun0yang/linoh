// linoh/util/file_permission.cpp — 跨平台文件权限限制实现
//
// Linux: chmod(path, 0600)
// Windows: SetNamedSecurityInfoW + PROTECTED_DACL_SECURITY_INFORMATION
//          重建 DACL 仅授予当前用户读写权限，阻止继承父目录 ACE

#include "linoh/util/file_permission.hpp"

#include <string>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <sys/stat.h>
#endif

namespace linoh::util {

#ifdef _WIN32

namespace {

/// UTF-8 → UTF-16 宽字符串
std::wstring to_wide(std::string_view s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                  static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        out.data(), len);
    return out;
}

/// 获取当前进程用户 SID（调用方负责 LocalFree）
/// @return 成功返回 SID 指针；失败返回 nullptr
PSID get_current_user_sid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return nullptr;
    }

    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0) {
        CloseHandle(token);
        return nullptr;
    }

    auto *buf = static_cast<TOKEN_USER *>(LocalAlloc(LPTR, needed));
    if (!buf) {
        CloseHandle(token);
        return nullptr;
    }

    BOOL ok = GetTokenInformation(token, TokenUser, buf, needed, &needed);
    CloseHandle(token);
    if (!ok) {
        LocalFree(buf);
        return nullptr;
    }

    // 复制 SID（独立于 token buffer 生命周期）
    DWORD sid_len = GetLengthSid(buf->User.Sid);
    PSID sid_copy = static_cast<PSID>(LocalAlloc(LPTR, sid_len));
    if (!sid_copy) {
        LocalFree(buf);
        return nullptr;
    }
    if (!CopySid(sid_len, sid_copy, buf->User.Sid)) {
        LocalFree(sid_copy);
        LocalFree(buf);
        return nullptr;
    }

    LocalFree(buf);
    return sid_copy;
}

} // namespace

bool restrict_file_permission(std::string_view path) {
    if (path.empty()) return false;

    // 1. 获取当前用户 SID
    PSID user_sid = get_current_user_sid();
    if (!user_sid) {
        return false;
    }

    // 2. 构建显式 ACE：授予当前用户读写+删除权限
    //    FILE_GENERIC_READ  = READ_CONTROL | SYNCHRONIZE | FILE_READ_DATA |
    //                         FILE_READ_ATTRIBUTES | FILE_READ_EA
    //    FILE_GENERIC_WRITE = READ_CONTROL | SYNCHRONIZE | FILE_WRITE_DATA |
    //                         FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA
    //    额外 DELETE 允许删除文件
    EXPLICIT_ACCESS_W ea{};
    ea.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | SYNCHRONIZE;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(user_sid);

    // 3. 构建 DACL（仅含一个 ACE，不合并已有 DACL）
    PACL new_dacl = nullptr;
    DWORD rc = SetEntriesInAclW(1, &ea, nullptr, &new_dacl);
    if (rc != ERROR_SUCCESS) {
        LocalFree(user_sid);
        return false;
    }

    // 4. 设置文件安全描述符
    //    DACL_SECURITY_INFORMATION：替换 DACL
    //    PROTECTED_DACL_SECURITY_INFORMATION：阻止继承父目录 ACE（关键）
    std::wstring wpath = to_wide(path);
    rc = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(wpath.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,       // owner 不变
        nullptr,       // group 不变
        new_dacl,      // 新 DACL
        nullptr);      // SACL 不变

    LocalFree(new_dacl);
    LocalFree(user_sid);

    return (rc == ERROR_SUCCESS);
}

#else // Linux

bool restrict_file_permission(std::string_view path) {
    if (path.empty()) return false;
    // NOLINTNEXTLINE: 需要构造 null 结尾的字符串传给 chmod
    std::string p(path);
    return ::chmod(p.c_str(), 0600) == 0;
}

#endif

} // namespace linoh::util
