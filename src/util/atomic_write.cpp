// =============================================================================
// atomic_write.cpp — v3.7.0 可靠性强化：临时目录 + 原子 rename 实现
//
// Windows：MoveFileExW + MOVEFILE_REPLACE_EXISTING（原子替换）
// Linux：std::filesystem::rename（同分区原子）
// =============================================================================

#include "linoh/util/atomic_write.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <thread>

#ifdef _WIN32
// 避免 Windows.h min/max 宏污染（硬约束：用 NOMINMAX + (std::min) 语法）
#define NOMINMAX
#include <windows.h>
#endif

namespace linoh::util {

namespace fs = std::filesystem;

namespace {

/// 生成唯一后缀：时间戳 + pid + 随机数
std::string generate_unique_suffix() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    std::random_device rd;
    std::stringstream ss;
    ss << std::hex << ms << "-" << std::this_thread::get_id() << "-"
       << (rd() & 0xFFFF);
    return ss.str();
}

#ifdef _WIN32
/// Windows：转宽字符
std::wstring to_wide(std::string_view s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                  static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        out.data(), len);
    return out;
}

/// Windows：获取路径所在卷根（如 "C:\"）
std::string get_volume_root(std::string_view path) {
    std::wstring wpath = to_wide(path);
    wchar_t vol_path[MAX_PATH + 1] = {0};
    if (!GetVolumePathNameW(wpath.c_str(), vol_path, MAX_PATH)) {
        return std::string(path);
    }
    int len = WideCharToMultiByte(CP_UTF8, 0, vol_path, -1, nullptr, 0,
                                  nullptr, nullptr);
    std::string out(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, vol_path, -1, out.data(), len,
                        nullptr, nullptr);
    return out;
}
#else
/// Linux：获取路径所在挂载点（简化：取绝对路径根目录前缀）
std::string get_volume_root(std::string_view path) {
    if (path.empty() || path[0] != '/') return std::string(path);
    // 简化：返回 "/" 作为根挂载点（足够覆盖典型场景）
    return "/";
}
#endif

} // namespace

// =============================================================================
// 原子文件操作
// =============================================================================

bool atomic_rename_file(std::string_view src, std::string_view dst) {
    if (src.empty() || dst.empty()) return false;

    fs::path src_path(src);
    fs::path dst_path(dst);

    std::error_code ec;
    if (!fs::exists(src_path, ec)) return false;

#ifdef _WIN32
    // Windows：用 MoveFileExW + MOVEFILE_REPLACE_EXISTING 实现原子替换
    // std::filesystem::rename 在 Windows 上对已存在目标可能抛异常
    std::wstring wsrc = to_wide(src);
    std::wstring wdst = to_wide(dst);
    BOOL ok = MoveFileExW(wsrc.c_str(), wdst.c_str(),
                          MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (!ok) {
        // 跨卷 rename 会失败，回退到 copy + remove（非原子，但保证可用）
        DWORD err = GetLastError();
        if (err == ERROR_NOT_SAME_DEVICE) {
            fs::copy_file(src_path, dst_path,
                          fs::copy_options::overwrite_existing, ec);
            if (ec) return false;
            fs::remove(src_path, ec);
            return !ec;
        }
        return false;
    }
    return true;
#else
    // Linux：rename(2) 同分区原子，跨分区返回 EXDEV
    fs::rename(src_path, dst_path, ec);
    if (ec) {
        if (ec.value() == EXDEV) {
            // 跨分区回退
            fs::copy_file(src_path, dst_path,
                          fs::copy_options::overwrite_existing, ec);
            if (ec) return false;
            fs::remove(src_path, ec);
            return !ec;
        }
        return false;
    }
    return true;
#endif
}

bool atomic_write_file(std::string_view path, std::span<const uint8_t> data) {
    if (path.empty()) return false;

    fs::path target(path);
    fs::path parent = target.parent_path();
    if (parent.empty()) parent = ".";

    std::error_code ec;
    if (!fs::exists(parent, ec)) {
        fs::create_directories(parent, ec);
        if (ec) return false;
    }

    // 临时文件命名：{path}.tmp.{pid}.{tid}.{rand}
    std::string temp_name = target.filename().string() + ".tmp." +
                            generate_unique_suffix();
    fs::path temp_path = parent / temp_name;

    // 写入临时文件
    {
        std::ofstream ofs(temp_path, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) return false;
        if (!data.empty()) {
            ofs.write(reinterpret_cast<const char *>(data.data()),
                      static_cast<std::streamsize>(data.size()));
        }
        ofs.flush();
        if (!ofs.good()) {
            fs::remove(temp_path, ec);
            return false;
        }
    }

    // 原子 rename
    if (!atomic_rename_file(temp_path.string(), target.string())) {
        fs::remove(temp_path, ec);
        return false;
    }
    return true;
}

bool file_exists(std::string_view path) {
    if (path.empty()) return false;
    std::error_code ec;
    return fs::exists(fs::path(path), ec);
}

bool file_size(std::string_view path, std::size_t &out_size) {
    if (path.empty()) return false;
    std::error_code ec;
    fs::path p(path);
    if (!fs::exists(p, ec)) return false;
    out_size = static_cast<std::size_t>(fs::file_size(p, ec));
    return !ec;
}

// =============================================================================
// AtomicWriter
// =============================================================================

AtomicWriter::AtomicWriter(std::string_view base_dir, std::string_view prefix) {
    if (base_dir.empty()) return;

    fs::path base(base_dir);
    std::error_code ec;
    if (!fs::exists(base, ec)) {
        fs::create_directories(base, ec);
        if (ec) return;
    }

    // 临时目录名 = prefix + 唯一后缀
    std::string dir_name = std::string(prefix) + generate_unique_suffix();
    fs::path temp = base / dir_name;
    fs::create_directory(temp, ec);
    if (ec) return;
    temp_dir_ = temp.string();
}

AtomicWriter::~AtomicWriter() {
    discard();
}

AtomicWriter::AtomicWriter(AtomicWriter &&other) noexcept
    : temp_dir_(std::move(other.temp_dir_)) {
    other.temp_dir_.clear();
}

AtomicWriter &AtomicWriter::operator=(AtomicWriter &&other) noexcept {
    if (this != &other) {
        discard();
        temp_dir_ = std::move(other.temp_dir_);
        other.temp_dir_.clear();
    }
    return *this;
}

std::string AtomicWriter::temp_path(std::string_view filename) const {
    if (temp_dir_.empty() || filename.empty()) return std::string();
    fs::path p = fs::path(temp_dir_) / fs::path(filename);
    return p.string();
}

bool AtomicWriter::commit(std::string_view temp_filename,
                           std::string_view target_path) {
    if (temp_dir_.empty() || temp_filename.empty() || target_path.empty()) {
        return false;
    }
    std::string src = temp_path(temp_filename);
    return commit_path(src, target_path);
}

bool AtomicWriter::commit_path(std::string_view temp_full_path,
                                std::string_view target_path) {
    if (temp_full_path.empty() || target_path.empty()) return false;

    std::error_code ec;
    if (!fs::exists(fs::path(temp_full_path), ec)) return false;

    // 确保目标父目录存在
    fs::path target(target_path);
    fs::path parent = target.parent_path();
    if (!parent.empty() && !fs::exists(parent, ec)) {
        fs::create_directories(parent, ec);
        if (ec) return false;
    }

    if (!atomic_rename_file(temp_full_path, target_path)) {
        return false;
    }

    // 提交成功后清理临时目录
    discard();
    return true;
}

void AtomicWriter::discard() {
    if (temp_dir_.empty()) return;
    std::error_code ec;
    fs::remove_all(fs::path(temp_dir_), ec);
    temp_dir_.clear();
}

// =============================================================================
// 残留临时目录清理
// =============================================================================

bool cleanup_stale_temp_dirs(std::string_view base_dir,
                              std::string_view prefix,
                              std::size_t *out_removed) {
    if (out_removed) *out_removed = 0;
    if (base_dir.empty() || prefix.empty()) return false;

    fs::path base(base_dir);
    std::error_code ec;
    if (!fs::exists(base, ec)) return false;
    if (!fs::is_directory(base, ec)) return false;

    std::size_t removed = 0;
    std::string prefix_str(prefix);
    for (auto &entry : fs::directory_iterator(base, ec)) {
        if (ec) break;
        if (!entry.is_directory()) continue;
        std::string name = entry.path().filename().string();
        // 前缀匹配
        if (name.size() >= prefix_str.size() &&
            name.compare(0, prefix_str.size(), prefix_str) == 0) {
            std::error_code rm_ec;
            fs::remove_all(entry.path(), rm_ec);
            if (!rm_ec) ++removed;
        }
    }

    if (out_removed) *out_removed = removed;
    return true;
}

// =============================================================================
// 同盘检测
// =============================================================================

bool same_volume(std::string_view path1, std::string_view path2) {
    if (path1.empty() || path2.empty()) return false;
    std::string vol1 = get_volume_root(path1);
    std::string vol2 = get_volume_root(path2);
    // 大小写不敏感比较（Windows 盘符大小写不敏感）
#ifdef _WIN32
    if (vol1.size() != vol2.size()) return false;
    for (std::size_t i = 0; i < vol1.size(); ++i) {
        char c1 = static_cast<char>(tolower(static_cast<unsigned char>(vol1[i])));
        char c2 = static_cast<char>(tolower(static_cast<unsigned char>(vol2[i])));
        if (c1 != c2) return false;
    }
    return true;
#else
    return vol1 == vol2;
#endif
}

} // namespace linoh::util
