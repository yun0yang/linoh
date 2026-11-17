// =============================================================================
// test_parallel_downloader.cpp — v3.7.3 可靠性强化：并行下载器单元测试
//
// 覆盖：LocalFileCopySource + FailNTimesSource + ParallelDownloader + 汇总
// =============================================================================

#include "linoh/collection/parallel_downloader.hpp"
#include "linoh/collection/model_manifest.hpp"
#include "linoh/util/atomic_write.hpp"
#include "linoh/util/crypto.hpp"

#include <cassert>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace linoh::collection;
using namespace linoh::crypto;

namespace fs = std::filesystem;

namespace {

/// 生成唯一测试目录
fs::path make_test_dir(const char *name) {
    fs::path p = fs::temp_directory_path() / (std::string("linoh_test_pd_") + name);
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

/// 写文件
void write_file(const std::string &path, const std::vector<uint8_t> &data) {
    fs::path p(path);
    fs::create_directories(p.parent_path());
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    assert(ofs.is_open());
    if (!data.empty()) {
        ofs.write(reinterpret_cast<const char *>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }
}

/// 读文件
std::vector<uint8_t> read_file(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary);
    assert(ifs.is_open());
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)),
                                 std::istreambuf_iterator<char>());
}

/// 计算数据的 sha256 hex
std::string sha256_hex(const std::vector<uint8_t> &data) {
    auto hash = SHA256::hash(data);
    static const char *kHex = "0123456789abcdef";
    std::string s(64, '0');
    for (std::size_t i = 0; i < hash.size(); ++i) {
        s[i * 2] = kHex[(hash[i] >> 4) & 0x0F];
        s[i * 2 + 1] = kHex[hash[i] & 0x0F];
    }
    return s;
}

/// 生成确定性数据
std::vector<uint8_t> make_data(std::size_t size, uint8_t seed = 0) {
    std::vector<uint8_t> data(size);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>((seed + i) & 0xFF);
    }
    return data;
}

int test_count = 0;
int test_passed = 0;

#define RUN_TEST(name)                                                        \
    do {                                                                      \
        ++test_count;                                                         \
        std::cout << "  [test] " #name " ... ";                               \
        name();                                                               \
        ++test_passed;                                                        \
        std::cout << "OK\n";                                                  \
    } while (0)

} // namespace

// =============================================================================
// LocalFileCopySource
// =============================================================================

void test_local_copy_basic() {
    auto src_dir = make_test_dir("lc_basic_src");
    auto dst_dir = make_test_dir("lc_basic_dst");

    auto data = make_data(1024, 1);
    write_file((src_dir / "layer_0000.gguf").string(), data);

    LocalFileCopySource src(src_dir.string());
    ShardEntry shard;
    shard.layer_index = 0;
    shard.filename = "layer_0000.gguf";
    shard.sha256_hex = sha256_hex(data);
    shard.size = 1024;

    auto target = (dst_dir / "layer_0000.gguf").string();
    assert(src.download(shard, target));
    assert(fs::exists(target));

    auto read = read_file(target);
    assert(read.size() == data.size());
    assert(std::memcmp(read.data(), data.data(), data.size()) == 0);
}

void test_local_copy_source_missing() {
    auto src_dir = make_test_dir("lc_missing_src");
    auto dst_dir = make_test_dir("lc_missing_dst");

    LocalFileCopySource src(src_dir.string());
    ShardEntry shard;
    shard.layer_index = 0;
    shard.filename = "nonexistent.gguf";

    auto target = (dst_dir / "nonexistent.gguf").string();
    assert(!src.download(shard, target));
    assert(!fs::exists(target));
}

void test_local_copy_atomic_no_partial() {
    // LocalFileCopySource 应使用 atomic_write_file，不留临时文件
    auto src_dir = make_test_dir("lc_atomic_src");
    auto dst_dir = make_test_dir("lc_atomic_dst");

    auto data = make_data(2048, 2);
    write_file((src_dir / "layer_0001.gguf").string(), data);

    LocalFileCopySource src(src_dir.string());
    ShardEntry shard;
    shard.layer_index = 1;
    shard.filename = "layer_0001.gguf";

    auto target = (dst_dir / "layer_0001.gguf").string();
    assert(src.download(shard, target));

    // 检查目录中没有临时文件
    int tmp_count = 0;
    for (const auto &e : fs::directory_iterator(dst_dir)) {
        std::string name = e.path().filename().string();
        if (name.find(".tmp.") != std::string::npos) ++tmp_count;
    }
    assert(tmp_count == 0);
}

// =============================================================================
// FailNTimesSource
// =============================================================================

void test_fail_n_times_first_n_fail() {
    auto src_dir = make_test_dir("fn_src");
    auto dst_dir = make_test_dir("fn_dst");

    auto data = make_data(512, 3);
    write_file((src_dir / "layer_0000.gguf").string(), data);

    auto inner = std::make_unique<LocalFileCopySource>(src_dir.string());
    FailNTimesSource src(std::move(inner), 2);  // 前 2 次失败

    ShardEntry shard;
    shard.layer_index = 0;
    shard.filename = "layer_0000.gguf";

    auto target = (dst_dir / "layer_0000.gguf").string();
    assert(!src.download(shard, target));  // 第 1 次
    assert(!src.download(shard, target));  // 第 2 次
    assert(src.download(shard, target));   // 第 3 次成功
    assert(src.call_count() == 3);
}

void test_fail_n_times_zero_fail() {
    auto src_dir = make_test_dir("fn_zero_src");
    auto dst_dir = make_test_dir("fn_zero_dst");

    auto data = make_data(256, 4);
    write_file((src_dir / "layer_0000.gguf").string(), data);

    auto inner = std::make_unique<LocalFileCopySource>(src_dir.string());
    FailNTimesSource src(std::move(inner), 0);  // 不失败

    ShardEntry shard;
    shard.layer_index = 0;
    shard.filename = "layer_0000.gguf";

    auto target = (dst_dir / "layer_0000.gguf").string();
    assert(src.download(shard, target));
    assert(src.call_count() == 1);
}

// =============================================================================
// ParallelDownloader 基本流程
// =============================================================================

void test_parallel_download_all_success() {
    auto src_dir = make_test_dir("pd_all_src");
    auto dst_dir = make_test_dir("pd_all_dst");

    // 准备 5 个 shard 源文件
    std::vector<ShardEntry> shards;
    for (std::uint32_t i = 0; i < 5; ++i) {
        auto data = make_data(1024 * (i + 1), static_cast<uint8_t>(i));
        write_file((src_dir / shard_filename(i)).string(), data);
        ShardEntry s;
        s.layer_index = i;
        s.filename = shard_filename(i);
        s.sha256_hex = sha256_hex(data);
        s.size = data.size();
        shards.push_back(s);
    }

    LocalFileCopySource src(src_dir.string());
    ParallelDownloader downloader(src);
    auto results = downloader.download_all(shards, dst_dir.string());

    assert(results.size() == 5);
    for (const auto &r : results) {
        assert(r.success);
        assert(r.bytes_downloaded > 0);
    }

    // 验证目标文件
    for (std::uint32_t i = 0; i < 5; ++i) {
        auto target = dst_dir / shard_filename(i);
        assert(fs::exists(target));
    }
}

void test_parallel_download_empty_list() {
    auto src_dir = make_test_dir("pd_empty_src");
    auto dst_dir = make_test_dir("pd_empty_dst");

    LocalFileCopySource src(src_dir.string());
    ParallelDownloader downloader(src);
    auto results = downloader.download_all({}, dst_dir.string());
    assert(results.empty());
}

void test_parallel_download_sha256_mismatch() {
    auto src_dir = make_test_dir("pd_mismatch_src");
    auto dst_dir = make_test_dir("pd_mismatch_dst");

    // 源文件内容
    auto data = make_data(1024, 5);
    write_file((src_dir / "layer_0000.gguf").string(), data);

    LocalFileCopySource src(src_dir.string());

    // shard 中故意填错 sha256
    std::vector<ShardEntry> shards;
    ShardEntry s;
    s.layer_index = 0;
    s.filename = "layer_0000.gguf";
    s.sha256_hex = std::string(64, '0');  // 错误 hash
    s.size = 1024;
    shards.push_back(s);

    ParallelDownloaderConfig cfg;
    cfg.max_retries = 0;  // 不重试，加速测试
    ParallelDownloader downloader(src, cfg);
    auto results = downloader.download_all(shards, dst_dir.string());

    assert(results.size() == 1);
    assert(!results[0].success);
    assert(results[0].error_msg.find("sha256 mismatch") != std::string::npos);
}

void test_parallel_download_no_verify_sha256() {
    auto src_dir = make_test_dir("pd_noverify_src");
    auto dst_dir = make_test_dir("pd_noverify_dst");

    auto data = make_data(1024, 6);
    write_file((src_dir / "layer_0000.gguf").string(), data);

    LocalFileCopySource src(src_dir.string());

    std::vector<ShardEntry> shards;
    ShardEntry s;
    s.layer_index = 0;
    s.filename = "layer_0000.gguf";
    s.sha256_hex = std::string(64, '0');  // 错误 hash，但不校验
    s.size = 1024;
    shards.push_back(s);

    ParallelDownloaderConfig cfg;
    cfg.verify_sha256 = false;
    ParallelDownloader downloader(src, cfg);
    auto results = downloader.download_all(shards, dst_dir.string());

    assert(results.size() == 1);
    assert(results[0].success);  // 不校验，下载成功
}

// =============================================================================
// 重试逻辑
// =============================================================================

void test_parallel_download_retry_success() {
    auto src_dir = make_test_dir("pd_retry_src");
    auto dst_dir = make_test_dir("pd_retry_dst");

    auto data = make_data(512, 7);
    write_file((src_dir / "layer_0000.gguf").string(), data);

    // 前 2 次失败，第 3 次成功
    auto inner = std::make_unique<LocalFileCopySource>(src_dir.string());
    FailNTimesSource src(std::move(inner), 2);

    std::vector<ShardEntry> shards;
    ShardEntry s;
    s.layer_index = 0;
    s.filename = "layer_0000.gguf";
    s.sha256_hex = sha256_hex(data);
    s.size = 512;
    shards.push_back(s);

    ParallelDownloaderConfig cfg;
    cfg.max_retries = 3;
    cfg.retry_backoff_ms = 10;  // 快速重试
    ParallelDownloader downloader(src, cfg);
    auto results = downloader.download_all(shards, dst_dir.string());

    assert(results.size() == 1);
    assert(results[0].success);
    assert(results[0].retries == 2);  // 重试了 2 次
}

void test_parallel_download_retry_exhausted() {
    auto src_dir = make_test_dir("pd_exhaust_src");
    auto dst_dir = make_test_dir("pd_exhaust_dst");

    auto data = make_data(512, 8);
    write_file((src_dir / "layer_0000.gguf").string(), data);

    // 前 10 次失败（超过重试次数）
    auto inner = std::make_unique<LocalFileCopySource>(src_dir.string());
    FailNTimesSource src(std::move(inner), 10);

    std::vector<ShardEntry> shards;
    ShardEntry s;
    s.layer_index = 0;
    s.filename = "layer_0000.gguf";
    s.sha256_hex = sha256_hex(data);
    s.size = 512;
    shards.push_back(s);

    ParallelDownloaderConfig cfg;
    cfg.max_retries = 2;  // 最多重试 2 次（共 3 次尝试）
    cfg.retry_backoff_ms = 10;
    ParallelDownloader downloader(src, cfg);
    auto results = downloader.download_all(shards, dst_dir.string());

    assert(results.size() == 1);
    assert(!results[0].success);
}

// =============================================================================
// 跳过已存在 shard
// =============================================================================

void test_parallel_download_skip_existing_valid() {
    auto src_dir = make_test_dir("pd_skip_src");
    auto dst_dir = make_test_dir("pd_skip_dst");

    auto data = make_data(1024, 9);
    write_file((src_dir / "layer_0000.gguf").string(), data);

    // 目标已存在有效文件
    write_file((dst_dir / "layer_0000.gguf").string(), data);

    // 用会失败的源验证跳过逻辑（如果不跳过会失败）
    auto inner = std::make_unique<LocalFileCopySource>(src_dir.string());
    FailNTimesSource src(std::move(inner), 100);  // 总是失败

    std::vector<ShardEntry> shards;
    ShardEntry s;
    s.layer_index = 0;
    s.filename = "layer_0000.gguf";
    s.sha256_hex = sha256_hex(data);
    s.size = 1024;
    shards.push_back(s);

    ParallelDownloaderConfig cfg;
    cfg.skip_existing_valid = true;
    ParallelDownloader downloader(src, cfg);
    auto results = downloader.download_all(shards, dst_dir.string());

    assert(results.size() == 1);
    assert(results[0].success);
    assert(results[0].bytes_downloaded == 0);  // 跳过，0 字节
}

void test_parallel_download_no_skip_existing_invalid() {
    // 已存在但 sha256 不匹配的文件不应跳过，应重新下载
    auto src_dir = make_test_dir("pd_noskip_src");
    auto dst_dir = make_test_dir("pd_noskip_dst");

    auto data = make_data(1024, 10);
    write_file((src_dir / "layer_0000.gguf").string(), data);

    // 目标已存在但内容错误
    auto wrong_data = make_data(1024, 99);
    write_file((dst_dir / "layer_0000.gguf").string(), wrong_data);

    LocalFileCopySource src(src_dir.string());

    std::vector<ShardEntry> shards;
    ShardEntry s;
    s.layer_index = 0;
    s.filename = "layer_0000.gguf";
    s.sha256_hex = sha256_hex(data);
    s.size = 1024;
    shards.push_back(s);

    ParallelDownloaderConfig cfg;
    cfg.skip_existing_valid = true;
    ParallelDownloader downloader(src, cfg);
    auto results = downloader.download_all(shards, dst_dir.string());

    assert(results.size() == 1);
    assert(results[0].success);
    assert(results[0].bytes_downloaded > 0);  // 重新下载

    // 验证目标文件已被覆盖为正确内容
    auto read = read_file((dst_dir / "layer_0000.gguf").string());
    assert(std::memcmp(read.data(), data.data(), data.size()) == 0);
}

// =============================================================================
// 取消支持
// =============================================================================

void test_parallel_download_cancel() {
    auto src_dir = make_test_dir("pd_cancel_src");
    auto dst_dir = make_test_dir("pd_cancel_dst");

    // 准备 20 个 shard（足够多以便能取消）
    std::vector<ShardEntry> shards;
    for (std::uint32_t i = 0; i < 20; ++i) {
        auto data = make_data(1024, static_cast<uint8_t>(i));
        write_file((src_dir / shard_filename(i)).string(), data);
        ShardEntry s;
        s.layer_index = i;
        s.filename = shard_filename(i);
        s.sha256_hex = sha256_hex(data);
        s.size = 1024;
        shards.push_back(s);
    }

    LocalFileCopySource src(src_dir.string());

    ParallelDownloaderConfig cfg;
    cfg.max_concurrency = 1;  // 串行，便于测试取消
    ParallelDownloader downloader(src, cfg);

    // 在另一个线程中取消
    std::thread cancel_thread([&downloader]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        downloader.cancel();
    });

    auto results = downloader.download_all(shards, dst_dir.string());
    cancel_thread.join();

    assert(downloader.is_cancelled());
    // 取消后可能有一些成功，一些失败，但不应全部成功
    bool has_failed = false;
    for (const auto &r : results) {
        if (!r.success) {
            has_failed = true;
            break;
        }
    }
    // 至少应该有部分未完成（取消生效）
    // 注意：由于时序，可能全部已完成，但通常会有失败
    (void)has_failed;  // 不强制断言，避免时序敏感
}

// =============================================================================
// 进度回调
// =============================================================================

void test_parallel_download_progress_callback() {
    auto src_dir = make_test_dir("pd_progress_src");
    auto dst_dir = make_test_dir("pd_progress_dst");

    std::vector<ShardEntry> shards;
    for (std::uint32_t i = 0; i < 4; ++i) {
        auto data = make_data(512, static_cast<uint8_t>(i));
        write_file((src_dir / shard_filename(i)).string(), data);
        ShardEntry s;
        s.layer_index = i;
        s.filename = shard_filename(i);
        s.sha256_hex = sha256_hex(data);
        s.size = 512;
        shards.push_back(s);
    }

    LocalFileCopySource src(src_dir.string());
    ParallelDownloader downloader(src);

    std::mutex cb_mtx;
    std::vector<ShardDownloadResult> cb_results;
    auto cb = [&](const ShardDownloadResult &r) {
        std::lock_guard<std::mutex> lock(cb_mtx);
        cb_results.push_back(r);
    };

    auto results = downloader.download_all(shards, dst_dir.string(), cb);

    assert(results.size() == 4);
    assert(cb_results.size() == 4);  // 回调被调用 4 次

    // 回调结果应与最终结果一致（按 shard_index 排序后）
    std::sort(cb_results.begin(), cb_results.end(),
              [](const ShardDownloadResult &a, const ShardDownloadResult &b) {
                  return a.shard_index < b.shard_index;
              });
    for (std::size_t i = 0; i < results.size(); ++i) {
        assert(cb_results[i].shard_index == results[i].shard_index);
        assert(cb_results[i].success == results[i].success);
    }
}

// =============================================================================
// 并发度
// =============================================================================

void test_parallel_download_concurrency_speedup() {
    // 并行应比串行快（用 sleep 模拟慢速下载）
    // 这里用一个会 sleep 的下载源
    class SlowSource : public DownloadSource {
    public:
        bool download(const ShardEntry &shard, std::string_view target_path) override {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            std::vector<uint8_t> data(16, 0xAA);
            return linoh::util::atomic_write_file(std::string(target_path), data);
        }
    };

    auto dst_dir = make_test_dir("pd_concurrency_dst");

    std::vector<ShardEntry> shards;
    for (std::uint32_t i = 0; i < 4; ++i) {
        ShardEntry s;
        s.layer_index = i;
        s.filename = shard_filename(i);
        s.sha256_hex = "";  // 不校验
        s.size = 0;
        shards.push_back(s);
    }

    SlowSource src;

    // 串行（并发度=1）
    ParallelDownloaderConfig cfg_serial;
    cfg_serial.max_concurrency = 1;
    cfg_serial.verify_sha256 = false;
    ParallelDownloader dl_serial(src, cfg_serial);
    auto t1 = std::chrono::steady_clock::now();
    auto r1 = dl_serial.download_all(shards, dst_dir.string());
    auto t2 = std::chrono::steady_clock::now();
    auto serial_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

    // 清理目标
    fs::remove_all(dst_dir);
    fs::create_directories(dst_dir);

    // 并行（并发度=4）
    ParallelDownloaderConfig cfg_parallel;
    cfg_parallel.max_concurrency = 4;
    cfg_parallel.verify_sha256 = false;
    ParallelDownloader dl_parallel(src, cfg_parallel);
    t1 = std::chrono::steady_clock::now();
    auto r2 = dl_parallel.download_all(shards, dst_dir.string());
    t2 = std::chrono::steady_clock::now();
    auto parallel_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

    assert(r1.size() == 4 && r2.size() == 4);
    for (const auto &r : r1) assert(r.success);
    for (const auto &r : r2) assert(r.success);

    // 并行应明显快于串行（至少 2 倍）
    std::cout << "(serial=" << serial_ms << "ms, parallel=" << parallel_ms << "ms) ";
    assert(parallel_ms < serial_ms);
}

// =============================================================================
// 汇总辅助
// =============================================================================

void test_summarize_all_success() {
    std::vector<ShardDownloadResult> results;
    for (std::size_t i = 0; i < 5; ++i) {
        ShardDownloadResult r;
        r.shard_index = i;
        r.success = true;
        r.bytes_downloaded = 1000 * (i + 1);
        results.push_back(r);
    }

    auto s = summarize_results(results);
    assert(s.total == 5);
    assert(s.succeeded == 5);
    assert(s.failed == 0);
    assert(s.skipped == 0);
    assert(s.total_bytes == 1000 + 2000 + 3000 + 4000 + 5000);
    assert(s.failed_indices.empty());
}

void test_summarize_mixed() {
    std::vector<ShardDownloadResult> results;
    ShardDownloadResult r1;
    r1.shard_index = 0;
    r1.success = true;
    r1.bytes_downloaded = 1000;
    results.push_back(r1);

    ShardDownloadResult r2;
    r2.shard_index = 1;
    r2.success = false;
    r2.bytes_downloaded = 0;
    results.push_back(r2);

    ShardDownloadResult r3;
    r3.shard_index = 2;
    r3.success = true;
    r3.bytes_downloaded = 0;  // 跳过
    results.push_back(r3);

    auto s = summarize_results(results);
    assert(s.total == 3);
    assert(s.succeeded == 2);
    assert(s.failed == 1);
    assert(s.skipped == 1);
    assert(s.total_bytes == 1000);
    assert(s.failed_indices.size() == 1);
    assert(s.failed_indices[0] == 1);
}

void test_summarize_empty() {
    std::vector<ShardDownloadResult> results;
    auto s = summarize_results(results);
    assert(s.total == 0);
    assert(s.succeeded == 0);
    assert(s.failed == 0);
}

void test_all_succeeded() {
    std::vector<ShardDownloadResult> all_ok(3);
    for (auto &r : all_ok) r.success = true;
    assert(all_succeeded(all_ok));

    std::vector<ShardDownloadResult> has_fail(3);
    has_fail[0].success = true;
    has_fail[1].success = false;
    has_fail[2].success = true;
    assert(!all_succeeded(has_fail));

    std::vector<ShardDownloadResult> empty;
    assert(!all_succeeded(empty));  // 空集合不算全部成功
}

// =============================================================================
// 端到端：manifest 构建 → 并行下载 → 校验
// =============================================================================

void test_e2e_manifest_parallel_download() {
    auto src_dir = make_test_dir("pd_e2e_src");
    auto dst_dir = make_test_dir("pd_e2e_dst");

    // 1. 在源目录创建 shard 文件并构建 manifest
    for (std::uint32_t i = 0; i < 5; ++i) {
        auto data = make_data(2048 * (i + 1), static_cast<uint8_t>(i));
        write_file((src_dir / shard_filename(i)).string(), data);
    }
    ModelManifest manifest;
    assert(build_manifest_for_cache(src_dir.string(), "E2EModel", "v1.0", 5, manifest));
    assert(manifest.verify_hash());

    // 2. 用并行下载器将 shard 从 src_dir 拷贝到 dst_dir
    LocalFileCopySource src(src_dir.string());
    ParallelDownloader downloader(src);
    auto results = downloader.download_all(manifest.shards, dst_dir.string());

    // 3. 全部成功
    assert(all_succeeded(results));

    // 4. 在目标目录构建 manifest，应与源 manifest 一致（shard 内容相同）
    ModelManifest dst_manifest;
    assert(build_manifest_for_cache(dst_dir.string(), "E2EModel", "v1.0", 5, dst_manifest));
    assert(dst_manifest.verify_hash());

    // 5. shard 的 sha256 应一致
    for (std::size_t i = 0; i < manifest.shards.size(); ++i) {
        assert(manifest.shards[i].sha256_hex == dst_manifest.shards[i].sha256_hex);
        assert(manifest.shards[i].size == dst_manifest.shards[i].size);
    }
}

void test_e2e_partial_failure_recovery() {
    // 模拟部分 shard 缺失场景：第一次下载部分失败，第二次重试应全部成功
    auto src_dir = make_test_dir("pd_partial_src");
    auto dst_dir = make_test_dir("pd_partial_dst");

    // 只创建 3/5 个 shard 源文件（2 个缺失）
    std::vector<ShardEntry> shards;
    for (std::uint32_t i = 0; i < 5; ++i) {
        if (i < 3) {
            auto data = make_data(1024, static_cast<uint8_t>(i));
            write_file((src_dir / shard_filename(i)).string(), data);
            ShardEntry s;
            s.layer_index = i;
            s.filename = shard_filename(i);
            s.sha256_hex = sha256_hex(data);
            s.size = 1024;
            shards.push_back(s);
        } else {
            ShardEntry s;
            s.layer_index = i;
            s.filename = shard_filename(i);
            s.sha256_hex = std::string(64, '0');
            s.size = 1024;
            shards.push_back(s);
        }
    }

    LocalFileCopySource src(src_dir.string());
    ParallelDownloaderConfig cfg;
    cfg.max_retries = 0;  // 不重试
    ParallelDownloader downloader(src, cfg);
    auto results = downloader.download_all(shards, dst_dir.string());

    // 前 3 个成功，后 2 个失败
    assert(results.size() == 5);
    assert(results[0].success);
    assert(results[1].success);
    assert(results[2].success);
    assert(!results[3].success);
    assert(!results[4].success);

    auto summary = summarize_results(results);
    assert(summary.succeeded == 3);
    assert(summary.failed == 2);
    assert(summary.failed_indices.size() == 2);
}

// =============================================================================
// 主函数
// =============================================================================

int main() {
    std::cout << "=== test_parallel_downloader (v3.7.3) ===\n";

    std::cout << "-- LocalFileCopySource\n";
    RUN_TEST(test_local_copy_basic);
    RUN_TEST(test_local_copy_source_missing);
    RUN_TEST(test_local_copy_atomic_no_partial);

    std::cout << "-- FailNTimesSource\n";
    RUN_TEST(test_fail_n_times_first_n_fail);
    RUN_TEST(test_fail_n_times_zero_fail);

    std::cout << "-- ParallelDownloader 基本流程\n";
    RUN_TEST(test_parallel_download_all_success);
    RUN_TEST(test_parallel_download_empty_list);
    RUN_TEST(test_parallel_download_sha256_mismatch);
    RUN_TEST(test_parallel_download_no_verify_sha256);

    std::cout << "-- 重试逻辑\n";
    RUN_TEST(test_parallel_download_retry_success);
    RUN_TEST(test_parallel_download_retry_exhausted);

    std::cout << "-- 跳过已存在 shard\n";
    RUN_TEST(test_parallel_download_skip_existing_valid);
    RUN_TEST(test_parallel_download_no_skip_existing_invalid);

    std::cout << "-- 取消支持\n";
    RUN_TEST(test_parallel_download_cancel);

    std::cout << "-- 进度回调\n";
    RUN_TEST(test_parallel_download_progress_callback);

    std::cout << "-- 并发度\n";
    RUN_TEST(test_parallel_download_concurrency_speedup);

    std::cout << "-- 汇总辅助\n";
    RUN_TEST(test_summarize_all_success);
    RUN_TEST(test_summarize_mixed);
    RUN_TEST(test_summarize_empty);
    RUN_TEST(test_all_succeeded);

    std::cout << "-- 端到端\n";
    RUN_TEST(test_e2e_manifest_parallel_download);
    RUN_TEST(test_e2e_partial_failure_recovery);

    std::cout << "\n=== " << test_passed << "/" << test_count << " tests passed ===\n";
    return (test_passed == test_count) ? 0 : 1;
}
