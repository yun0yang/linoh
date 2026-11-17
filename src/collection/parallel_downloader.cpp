// =============================================================================
// parallel_downloader.cpp — v3.7.3 可靠性强化：并行下载器实现
//
// 复用 v3.7.0 的 sha256（util/crypto.hpp）+ atomic_write_file（util/atomic_write.hpp）
// 线程池：std::thread（不引入 asio 依赖）
// =============================================================================

#include "linoh/collection/parallel_downloader.hpp"

#include "linoh/util/atomic_write.hpp"
#include "linoh/util/crypto.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

namespace linoh::collection {

namespace {

// =========================================================================
// 内部辅助：文件 sha256 计算（流式）
// =========================================================================

bool compute_file_sha256_hex(std::string_view file_path, std::string &out_hex) {
    out_hex.clear();
    std::ifstream ifs((std::string(file_path)), std::ios::binary);
    if (!ifs.is_open()) return false;

    crypto::SHA256 ctx;
    constexpr std::size_t kBufSize = 64 * 1024;
    std::vector<uint8_t> buffer(kBufSize);

    while (true) {
        ifs.read(reinterpret_cast<char *>(buffer.data()),
                 static_cast<std::streamsize>(buffer.size()));
        std::streamsize n = ifs.gcount();
        if (n <= 0) break;
        std::span<const uint8_t> chunk(buffer.data(),
                                        static_cast<std::size_t>(n));
        ctx.update(chunk);
    }

    auto hash = ctx.finalize();
    static const char *kHexDigits = "0123456789abcdef";
    out_hex.resize(64);
    for (std::size_t i = 0; i < hash.size(); ++i) {
        out_hex[i * 2] = kHexDigits[(hash[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = kHexDigits[hash[i] & 0x0F];
    }
    return true;
}

/// 获取文件大小
std::uint64_t get_file_size(std::string_view path) {
    namespace fs = std::filesystem;
    std::error_code ec;
    auto sz = fs::file_size(fs::path(path), ec);
    if (ec) return 0;
    return static_cast<std::uint64_t>(sz);
}

/// 简单的线程安全队列（FIFO）用于分派 shard 任务
class ShardTaskQueue {
public:
    ShardTaskQueue(std::size_t total) : total_(total), next_(0) {}

    /// 取下一个任务索引（线程安全）
    /// @return true 取到任务；false 队列已空
    bool pop(std::size_t &out_index) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (next_ >= total_) return false;
        out_index = next_++;
        return true;
    }

private:
    std::mutex mtx_;
    std::size_t total_;
    std::size_t next_;
};

} // anonymous namespace

// =============================================================================
// LocalFileCopySource 实现
// =============================================================================

LocalFileCopySource::LocalFileCopySource(std::string_view source_dir)
    : source_dir_(source_dir) {}

bool LocalFileCopySource::download(const ShardEntry &shard,
                                     std::string_view target_path) {
    namespace fs = std::filesystem;
    fs::path src = fs::path(source_dir_) / shard.filename;
    fs::path dst(target_path);

    if (!fs::exists(src)) return false;

    // 读源文件
    std::ifstream ifs(src, std::ios::binary);
    if (!ifs.is_open()) return false;
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(ifs)),
                                std::istreambuf_iterator<char>());

    // 原子写入目标
    return util::atomic_write_file(std::string(target_path), data);
}

// =============================================================================
// FailNTimesSource 实现
// =============================================================================

FailNTimesSource::FailNTimesSource(std::unique_ptr<DownloadSource> inner,
                                     std::size_t fail_count)
    : inner_(std::move(inner)), fail_count_(fail_count) {}

bool FailNTimesSource::download(const ShardEntry &shard,
                                  std::string_view target_path) {
    std::size_t n = call_count_.fetch_add(1, std::memory_order_relaxed);
    if (n < fail_count_) {
        return false;  // 前 fail_count_ 次失败
    }
    return inner_->download(shard, target_path);
}

// =============================================================================
// ParallelDownloader 实现
// =============================================================================

ParallelDownloader::ParallelDownloader(DownloadSource &source,
                                         ParallelDownloaderConfig config)
    : source_(source), config_(config) {}

ParallelDownloader::~ParallelDownloader() = default;

void ParallelDownloader::cancel() {
    cancelled_.store(true, std::memory_order_relaxed);
}

bool ParallelDownloader::is_cancelled() const noexcept {
    return cancelled_.load(std::memory_order_relaxed);
}

bool ParallelDownloader::is_existing_valid(const ShardEntry &shard,
                                              std::string_view target_path) {
    namespace fs = std::filesystem;
    fs::path p(target_path);
    std::error_code ec;
    if (!fs::exists(p, ec)) return false;

    // 大小校验
    if (shard.size != 0) {
        auto actual = fs::file_size(p, ec);
        if (ec) return false;
        if (static_cast<std::uint64_t>(actual) != shard.size) return false;
    }

    // sha256 校验
    if (config_.verify_sha256 && !shard.sha256_hex.empty()) {
        std::string actual_hex;
        if (!compute_file_sha256_hex(target_path, actual_hex)) return false;
        if (actual_hex != shard.sha256_hex) return false;
    }

    return true;
}

ShardDownloadResult ParallelDownloader::download_one(
    const ShardEntry &shard,
    std::size_t shard_index,
    std::string_view target_path) {
    ShardDownloadResult result;
    result.shard_index = shard_index;
    result.layer_index = shard.layer_index;

    auto t_start = std::chrono::steady_clock::now();

    // 跳过已存在且有效的 shard
    if (config_.skip_existing_valid && is_existing_valid(shard, target_path)) {
        result.success = true;
        result.bytes_downloaded = 0;
        result.retries = 0;
        auto t_end = std::chrono::steady_clock::now();
        result.elapsed_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count());
        return result;
    }

    // 下载 + 重试
    int attempt = 0;
    const int max_attempts = config_.max_retries + 1;
    std::string last_error;

    while (attempt < max_attempts) {
        if (is_cancelled()) {
            result.success = false;
            result.error_msg = "cancelled";
            auto t_end = std::chrono::steady_clock::now();
            result.elapsed_ms = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count());
            return result;
        }

        bool ok = source_.download(shard, target_path);
        if (ok) {
            // 下载成功，校验 sha256（若启用）
            if (config_.verify_sha256 && !shard.sha256_hex.empty()) {
                std::string actual_hex;
                if (!compute_file_sha256_hex(target_path, actual_hex)) {
                    ok = false;
                    last_error = "sha256 compute failed";
                } else if (actual_hex != shard.sha256_hex) {
                    ok = false;
                    std::ostringstream oss;
                    oss << "sha256 mismatch: expected=" << shard.sha256_hex
                        << " actual=" << actual_hex;
                    last_error = oss.str();
                }
            }
        } else {
            last_error = "download source returned false";
        }

        if (ok) {
            result.success = true;
            result.bytes_downloaded = get_file_size(target_path);
            result.retries = attempt;
            break;
        }

        // 失败，准备重试
        ++attempt;
        if (attempt < max_attempts) {
            // 线性退避
            std::size_t backoff = config_.retry_backoff_ms * attempt;
            std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
        }
    }

    if (!result.success) {
        result.error_msg = last_error;
    }

    auto t_end = std::chrono::steady_clock::now();
    result.elapsed_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count());

    return result;
}

std::vector<ShardDownloadResult> ParallelDownloader::download_all(
    const std::vector<ShardEntry> &shards,
    std::string_view target_dir,
    ProgressCallback progress_cb) {
    std::vector<ShardDownloadResult> results(shards.size());
    if (shards.empty()) return results;

    namespace fs = std::filesystem;
    fs::path target(target_dir);
    std::error_code ec;
    fs::create_directories(target, ec);  // 确保目标目录存在

    // 任务队列
    ShardTaskQueue queue(shards.size());

    // 进度回调互斥锁（保证回调线程安全）
    std::mutex cb_mtx;

    // 工作线程数（不超过 shard 数）
    std::size_t num_threads = (std::min)(config_.max_concurrency, shards.size());
    if (num_threads == 0) num_threads = 1;

    // 工作线程函数
    auto worker = [&]() {
        std::size_t idx;
        while (queue.pop(idx)) {
            if (is_cancelled()) break;

            const ShardEntry &shard = shards[idx];
            fs::path target_path = target / shard.filename;
            ShardDownloadResult r = download_one(shard, idx, target_path.string());

            // 保存结果
            results[idx] = r;

            // 进度回调
            if (progress_cb) {
                std::lock_guard<std::mutex> lock(cb_mtx);
                progress_cb(r);
            }
        }
    };

    // 启动线程池
    std::vector<std::thread> threads;
    threads.reserve(num_threads);
    for (std::size_t i = 0; i < num_threads; ++i) {
        threads.emplace_back(worker);
    }

    // 等待所有线程完成
    for (auto &t : threads) {
        if (t.joinable()) t.join();
    }

    return results;
}

// =============================================================================
// 汇总辅助
// =============================================================================

DownloadSummary summarize_results(
    const std::vector<ShardDownloadResult> &results) {
    DownloadSummary s;
    s.total = results.size();
    std::uint64_t max_elapsed = 0;
    for (const auto &r : results) {
        if (r.success) {
            ++s.succeeded;
            s.total_bytes += r.bytes_downloaded;
            if (r.bytes_downloaded == 0) {
                ++s.skipped;  // 0 字节表示跳过已存在
            }
        } else {
            ++s.failed;
            s.failed_indices.push_back(r.shard_index);
        }
        if (r.elapsed_ms > max_elapsed) max_elapsed = r.elapsed_ms;
    }
    s.total_elapsed_ms = max_elapsed;  // 并发重叠，取最大单 shard 耗时
    return s;
}

} // namespace linoh::collection
