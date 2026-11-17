#pragma once

// =============================================================================
// atomic_write.hpp — v3.7.0 可靠性强化：临时目录 + 原子 rename，根治 stale cache
//
// 设计来源：sendme iroh-blobs 接收端流程
//   1. 创建 .tmp-XXXX 临时目录（与目标同盘，保证 rename 原子）
//   2. 数据写入临时目录
//   3. 校验通过后原子 rename 到目标路径
//   4. 异常退出时下次启动清理残留临时目录
//
// Windows：MoveFileExW + MOVEFILE_REPLACE_EXISTING（原子替换）
// Linux：rename(2)（同分区原子）
//
// 硬约束遵守：
//   - 临时目录与目标同盘（Windows 跨卷 rename 非原子，强制同盘）
//   - 缓存路径放 exe 同目录（硬约束 8，调用方保证 base_dir 在 exe 同目录）
// =============================================================================

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace linoh::util {

// =============================================================================
// 原子文件操作
// =============================================================================

/// 原子 rename 文件（覆盖目标）
/// @param src 源文件路径（必须存在）
/// @param dst 目标文件路径（存在则覆盖，不存在则创建）
/// @return true 成功；false 失败（源不存在 / 跨卷 / 权限不足）
/// @note Windows 用 MoveFileExW + MOVEFILE_REPLACE_EXISTING，Linux 用 rename(2)
/// @note 同分区/同卷下 rename 是原子的；跨卷非原子，本函数会检测并返回 false
bool atomic_rename_file(std::string_view src, std::string_view dst);

/// 原子写入小文件（写入临时文件 → 原子 rename 到目标）
/// @param path 目标文件路径
/// @param data 写入数据
/// @return true 成功；false 失败（无法创建临时文件 / rename 失败）
/// @note 临时文件命名：{path}.tmp.{pid}.{tid}，与目标同目录（保证同盘）
bool atomic_write_file(std::string_view path, std::span<const uint8_t> data);

/// 检查文件是否存在
bool file_exists(std::string_view path);

/// 获取文件大小（字节）；文件不存在返回 false
bool file_size(std::string_view path, std::size_t &out_size);

// =============================================================================
// AtomicWriter — 临时目录 + 原子提交（大文件/多文件场景）
// =============================================================================

class AtomicWriter {
public:
    /// 构造：在 base_dir 下创建临时目录
    /// @param base_dir 目标目录（临时目录会创建在此目录下，保证同盘）
    /// @param prefix 临时目录前缀（如 ".merged-"，最终目录名 = prefix + 时间戳 + pid）
    /// @note 构造即创建临时目录；若 base_dir 不存在则创建
    AtomicWriter(std::string_view base_dir, std::string_view prefix);

    /// 析构：若未 commit，自动 discard 清理临时目录
    ~AtomicWriter();

    // 不可拷贝（持有临时目录资源）
    AtomicWriter(const AtomicWriter &) = delete;
    AtomicWriter &operator=(const AtomicWriter &) = delete;

    // 可移动
    AtomicWriter(AtomicWriter &&) noexcept;
    AtomicWriter &operator=(AtomicWriter &&) noexcept;

    /// 临时目录是否有效（构造成功且未 commit/discard）
    bool valid() const noexcept { return !temp_dir_.empty(); }

    /// 获取临时目录路径
    const std::string &temp_dir() const noexcept { return temp_dir_; }

    /// 在临时目录内构造文件路径
    /// @param filename 文件名（不含路径）
    /// @return 临时目录内完整路径
    std::string temp_path(std::string_view filename) const;

    /// 提交：将临时目录内的指定文件原子 rename 到目标路径
    /// @param temp_filename 临时目录内的文件名
    /// @param target_path 目标完整路径
    /// @return true 成功；false 失败（临时文件不存在 / rename 失败）
    /// @note 提交成功后临时目录自动清理，AtomicWriter 失效
    /// @note 若 target_path 所在盘与临时目录不同，rename 可能非原子，返回 false
    bool commit(std::string_view temp_filename, std::string_view target_path);

    /// 提交：将临时目录内的指定文件原子 rename 到目标路径（路径已构造）
    /// @param temp_full_path 临时目录内文件的完整路径
    /// @param target_path 目标完整路径
    /// @return true 成功；false 失败
    bool commit_path(std::string_view temp_full_path,
                     std::string_view target_path);

    /// 丢弃：删除临时目录及其内容
    /// @note 调用后 AtomicWriter 失效
    void discard();

private:
    std::string temp_dir_;
};

// =============================================================================
// 残留临时目录清理（异常退出恢复）
// =============================================================================

/// 清理 base_dir 下指定前缀的残留临时目录
/// @param base_dir 目标目录
/// @param prefix 临时目录前缀（如 ".merged-"）
/// @param[out] out_removed 清理的目录数（可选，nullptr 忽略）
/// @return true 清理完成（即使 0 个）；false base_dir 不存在或清理失败
/// @note 用于启动时清理上次异常退出残留的临时目录
bool cleanup_stale_temp_dirs(std::string_view base_dir,
                              std::string_view prefix,
                              std::size_t *out_removed = nullptr);

// =============================================================================
// 同盘检测
// =============================================================================

/// 检测两个路径是否在同一盘/卷（Windows 检测盘符，Linux 检测挂载点）
/// @return true 同盘；false 不同盘或检测失败
bool same_volume(std::string_view path1, std::string_view path2);

} // namespace linoh::util
