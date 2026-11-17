#pragma once

// =============================================================================
// parallel_downloader.hpp — v3.7.3 可靠性强化：并行下载器（stale cache 根治）
//
// 设计来源：sendme iroh-blobs import() 并行 + TryReference
//   - 基于 manifest 的 shard 列表，并行下载多个 layer shard
//   - 每 shard 下载完成立即 sha256 校验（v3.7.0 chunk_hash 复用）
//   - 失败重试（可配置次数 + 退避）
//   - TryReference 模式：下载即就地引用，不二次拷贝
//   - 全部 shard 就位 → 合并 merged.gguf（走 v3.7.0 临时目录原子写）
//
// 解耦设计：
//   - DownloadSource 抽象接口：win-worker 注入 HTTP 下载实现
//   - LocalFileCopySource：测试用，从本地目录拷贝模拟下载
//   - ParallelDownloader 不依赖具体下载协议
//
// 线程模型：
//   - std::thread 池（不引入 asio 依赖，避免与 linoh 主线程冲突）
//   - 主线程提交任务后等待完成，子线程并发执行 download_one
//   - 取消通过 std::atomic<bool> 标志，正在进行的 shard 会完成但不会启动新的
//
// 硬约束遵守：
//   - 缓存路径放 exe 同目录（硬约束 8，调用方保证 target_dir 在 exe 同目录）
//   - 并发度默认 4（避免 modelscope CDN 限流，硬约束 7 相关）
//   - sha256 校验复用 v3.7.0 实现（用户确认先用 sha256 兼容）
// =============================================================================

#include "linoh/collection/model_manifest.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace linoh::collection {

// =============================================================================
// DownloadSource — 下载源抽象接口
// =============================================================================

/// 下载源抽象接口（用于解耦下载实现）
/// 实现方：
///   - win-worker：注入 HTTP 下载实现（modelscope cdn）
///   - 测试：使用 LocalFileCopySource 从本地拷贝模拟下载
class DownloadSource {
public:
    virtual ~DownloadSource() = default;

    /// 下载单个 shard 到 target_path
    /// @param shard shard 元信息（含 filename + sha256_hex + size）
    /// @param target_path 目标文件完整路径
    /// @return true 下载成功；false 下载失败
    /// @note 实现方应将文件原子写入 target_path（参考 v3.7.0 atomic_write_file）
    virtual bool download(const ShardEntry &shard,
                           std::string_view target_path) = 0;
};

/// 本地文件拷贝下载源（测试用，模拟下载行为）
/// 从指定源目录读取 shard.filename 文件，拷贝到 target_path
class LocalFileCopySource : public DownloadSource {
public:
    /// 构造本地拷贝源
    /// @param source_dir 源目录（shard 文件位于 source_dir/filename）
    explicit LocalFileCopySource(std::string_view source_dir);

    bool download(const ShardEntry &shard,
                   std::string_view target_path) override;

private:
    std::string source_dir_;
};

/// 失败计数下载源（测试用，模拟前 N 次失败后成功）
/// 用于测试重试逻辑
class FailNTimesSource : public DownloadSource {
public:
    /// 构造失败计数源
    /// @param inner 内部真实下载源（失败到次数后调用 inner）
    /// @param fail_count 前 fail_count 次调用返回 false
    explicit FailNTimesSource(std::unique_ptr<DownloadSource> inner,
                                std::size_t fail_count);

    bool download(const ShardEntry &shard,
                   std::string_view target_path) override;

    /// 总调用次数
    std::size_t call_count() const noexcept { return call_count_; }

private:
    std::unique_ptr<DownloadSource> inner_;
    std::size_t fail_count_;
    std::atomic<std::size_t> call_count_{0};
};

// =============================================================================
// ShardDownloadResult — 单个 shard 下载结果
// =============================================================================

struct ShardDownloadResult {
    std::size_t shard_index = 0;       // shards 数组下标
    std::uint32_t layer_index = 0;     // 层索引（来自 shard.layer_index）
    bool success = false;              // 是否成功
    std::string error_msg;             // 失败原因（success=false 时填充）
    std::uint64_t bytes_downloaded = 0; // 已下载字节数
    std::uint64_t elapsed_ms = 0;      // 耗时（毫秒）
    int retries = 0;                   // 重试次数

    /// 是否成功
    explicit operator bool() const noexcept { return success; }
};

// =============================================================================
// ParallelDownloaderConfig — 并行下载器配置
// =============================================================================

struct ParallelDownloaderConfig {
    std::size_t max_concurrency = 4;       // 最大并发数（默认 4，避免 CDN 限流）
    int max_retries = 3;                    // 单 shard 最大重试次数（不含首次）
    bool verify_sha256 = true;             // 下载后校验 sha256
    std::size_t retry_backoff_ms = 100;    // 重试退避（毫秒，线性递增）
    bool skip_existing_valid = true;       // 跳过已存在且校验通过的 shard
};

// =============================================================================
// ParallelDownloader — 并行下载器
// =============================================================================

/// 并行下载器（线程池 + sha256 校验 + 失败重试）
class ParallelDownloader {
public:
    /// 进度回调（每个 shard 完成后调用，含成功和失败）
    using ProgressCallback = std::function<void(const ShardDownloadResult &)>;

    /// 构造并行下载器
    /// @param source 下载源（引用，调用方保证生命周期长于下载器）
    /// @param config 配置
    ParallelDownloader(DownloadSource &source,
                        ParallelDownloaderConfig config = {});

    ~ParallelDownloader();

    // 不可拷贝（含原子标志和引用成员）
    ParallelDownloader(const ParallelDownloader &) = delete;
    ParallelDownloader &operator=(const ParallelDownloader &) = delete;

    /// 并行下载所有 shard
    /// @param shards shard 列表（来自 manifest）
    /// @param target_dir 目标目录（shard 文件位于 target_dir/filename）
    /// @param progress_cb 进度回调（可选，每个 shard 完成后调用）
    /// @return 全部结果（按 shard_index 升序，含成功和失败）
    /// @note 调用此方法会阻塞直到所有 shard 完成（或取消）
    std::vector<ShardDownloadResult> download_all(
        const std::vector<ShardEntry> &shards,
        std::string_view target_dir,
        ProgressCallback progress_cb = nullptr);

    /// 取消下载（异步，正在进行的 shard 会完成但不会启动新的）
    void cancel();

    /// 是否已取消
    bool is_cancelled() const noexcept;

    /// 获取配置
    const ParallelDownloaderConfig &config() const noexcept { return config_; }

private:
    /// 下载单个 shard（含重试 + 校验）
    ShardDownloadResult download_one(
        const ShardEntry &shard,
        std::size_t shard_index,
        std::string_view target_path);

    /// 检查已存在文件是否有效（跳过下载）
    bool is_existing_valid(const ShardEntry &shard,
                            std::string_view target_path);

    DownloadSource &source_;
    ParallelDownloaderConfig config_;
    std::atomic<bool> cancelled_{false};
};

// =============================================================================
// 汇总辅助
// =============================================================================

/// 统计下载结果
struct DownloadSummary {
    std::size_t total = 0;          // 总 shard 数
    std::size_t succeeded = 0;      // 成功数
    std::size_t failed = 0;         // 失败数
    std::size_t skipped = 0;        // 跳过数（已存在且有效）
    std::uint64_t total_bytes = 0;  // 总下载字节数（不含跳过的）
    std::uint64_t total_elapsed_ms = 0;  // 总耗时（毫秒，含并发重叠）
    std::vector<std::size_t> failed_indices;  // 失败的 shard 索引
};

/// 汇总下载结果
/// @param results 所有 shard 的下载结果
/// @return 汇总统计
DownloadSummary summarize_results(const std::vector<ShardDownloadResult> &results);

/// 全部成功
inline bool all_succeeded(const std::vector<ShardDownloadResult> &results) {
    for (const auto &r : results) {
        if (!r.success) return false;
    }
    return !results.empty();
}

} // namespace linoh::collection
