#pragma once

// =============================================================================
// shard_state_store.hpp — v3.7.4 可靠性强化：断点续传状态存储（stale cache 根治）
//
// 设计来源：sendme iroh-blobs 断点续传 store
//   - win-worker model_cache 引入轻量 shard_state.json（放 exe 同目录）
//   - 记录每个 layer shard 的已下载字节数 + sha256 校验状态
//   - 下载中断恢复时读取状态，跳过已完成的 shard，仅续传未完成的
//   - 配合 v3.7.0 sha256 chunk 校验，已下载段无需重验
//   - 状态文件本身原子写 + sha256 校验（防状态文件损坏）
//
// 设计决策：手写 JSON 而非 SQLite
//   - 零依赖（符合 linoh 设计哲学，避免引入 SQLite）
//   - 状态文件 KB 级（几十个 shard），JSON 性能足够
//   - 与 model_manifest 一致的 JSON 风格，便于调试
//   - 状态文件用 v3.7.0 atomic_write_file + v3.7.2 原子标记机制
//
// 硬约束遵守：
//   - 缓存路径放 exe 同目录（硬约束 8，调用方保证 store_path 在 exe 同目录）
//   - 状态文件本身用 atomic_write_file 保证原子性（防写入中断损坏）
//   - sha256 校验复用 v3.7.0 实现（用户确认先用 sha256 兼容）
// =============================================================================

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace linoh::collection {

// =============================================================================
// ShardState — 单个 shard 的下载状态
// =============================================================================

struct ShardState {
    std::uint32_t layer_index = 0;          // 层索引
    std::string filename;                    // 文件名（如 "layer_0000.gguf"）
    std::uint64_t total_size = 0;            // 文件总大小（字节，来自 manifest）
    std::uint64_t downloaded_bytes = 0;      // 已下载字节数
    std::string sha256_hex;                  // 完整文件的 sha256（来自 manifest）
    bool verified = false;                   // 是否已通过 sha256 校验
    std::uint64_t timestamp_ms = 0;          // 最后更新时间戳（Unix 毫秒）
    int retry_count = 0;                     // 下载重试次数（用于诊断）

    /// 是否已完整下载
    bool is_complete() const noexcept {
        return total_size > 0 && downloaded_bytes >= total_size;
    }

    /// 下载进度百分比（0-100）
    int progress_percent() const noexcept {
        if (total_size == 0) return 0;
        if (downloaded_bytes >= total_size) return 100;
        return static_cast<int>((downloaded_bytes * 100) / total_size);
    }

    /// 是否需要续传（部分下载但未完成）
    bool needs_resume() const noexcept {
        return !is_complete() && downloaded_bytes > 0;
    }
};

// =============================================================================
// ShardStateStore — 断点续传状态存储
// =============================================================================

class ShardStateStore {
public:
    /// 构造状态存储
    /// @param store_path 状态文件路径（如 "model_cache/shard_state.json"）
    explicit ShardStateStore(std::string store_path);

    ~ShardStateStore();

    // 不可拷贝（含文件路径资源）
    ShardStateStore(const ShardStateStore &) = delete;
    ShardStateStore &operator=(const ShardStateStore &) = delete;

    // 可移动
    ShardStateStore(ShardStateStore &&) noexcept = default;
    ShardStateStore &operator=(ShardStateStore &&) noexcept = default;

    // -------------------------------------------------------------------------
    // 文件读写
    // -------------------------------------------------------------------------

    /// 从文件加载状态（清空当前内存状态）
    /// @return true 成功；false 文件不存在/解析失败/校验失败
    /// @note 文件不存在时返回 false 但不设置错误（正常首次启动场景）
    bool load_from_file();

    /// 原子写入状态到文件
    /// @return true 成功；false 写入失败
    /// @note 使用 v3.7.0 atomic_write_file + v3.7.2 原子标记机制
    bool save_atomic();

    /// 状态文件是否存在
    bool file_exists() const;

    /// 删除状态文件
    /// @return true 成功；false 文件不存在或删除失败
    bool remove_file();

    // -------------------------------------------------------------------------
    // CRUD 操作
    // -------------------------------------------------------------------------

    /// 查找指定 layer_index 的状态
    /// @return 找到返回指针，否则 nullptr
    ShardState *find(std::uint32_t layer_index);

    /// 查找指定 layer_index 的状态（const 版本）
    const ShardState *find(std::uint32_t layer_index) const;

    /// 插入或更新状态（按 layer_index 去重）
    /// @return true 成功；false 失败
    bool upsert(const ShardState &state);

    /// 删除指定 layer_index 的状态
    /// @return true 删除成功；false 未找到
    bool remove(std::uint32_t layer_index);

    /// 清空所有状态
    void clear() noexcept;

    /// 状态数量
    std::size_t size() const noexcept { return states_.size(); }

    /// 是否为空
    bool empty() const noexcept { return states_.empty(); }

    /// 获取所有状态（按 layer_index 升序）
    std::vector<ShardState> &all() noexcept { return states_; }
    const std::vector<ShardState> &all() const noexcept { return states_; }

    // -------------------------------------------------------------------------
    // 查询辅助
    // -------------------------------------------------------------------------

    /// 统计已完成的 shard 数
    std::size_t completed_count() const;

    /// 统计需续传的 shard 数
    std::size_t resume_count() const;

    /// 统计未开始的 shard 数（manifest 中有但 store 中无或 downloaded_bytes=0）
    /// @param manifest_shards manifest 中的 shard 列表
    std::size_t pending_count(
        const std::vector<struct ShardEntry> &manifest_shards) const;

    /// 总下载字节数
    std::uint64_t total_downloaded_bytes() const;

    /// 状态文件路径
    const std::string &path() const noexcept { return store_path_; }

private:
    std::string store_path_;
    std::vector<ShardState> states_;
};

// =============================================================================
// 便捷辅助
// =============================================================================

/// 从 manifest 构建/同步状态（保留已有的 downloaded_bytes/verified）
/// @param store 状态存储
/// @param manifest_shards manifest 中的 shard 列表
/// @return 新增的 shard 数（manifest 有但 store 无的）
/// @note 已存在的状态保留 downloaded_bytes/verified/retry_count
std::size_t sync_from_manifest(
    ShardStateStore &store,
    const std::vector<ShardEntry> &manifest_shards);

/// 标记 shard 为已完成（downloaded_bytes=total_size, verified=true）
/// @return true 成功；false 未找到
bool mark_shard_completed(ShardStateStore &store,
                            std::uint32_t layer_index);

/// 标记 shard 下载进度
/// @param downloaded_bytes 已下载字节数
/// @return true 成功；false 未找到
bool mark_shard_progress(ShardStateStore &store,
                           std::uint32_t layer_index,
                           std::uint64_t downloaded_bytes);

} // namespace linoh::collection
