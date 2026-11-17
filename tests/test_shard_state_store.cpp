// =============================================================================
// test_shard_state_store.cpp — v3.7.4 可靠性强化：断点续传状态存储单元测试
//
// 覆盖：ShardState 结构 + ShardStateStore CRUD + 文件读写 + 完整性校验 +
//       便捷辅助函数 + 端到端断点续传场景
// =============================================================================

#include "linoh/collection/shard_state_store.hpp"
#include "linoh/collection/model_manifest.hpp"

#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace linoh::collection;

namespace fs = std::filesystem;

namespace {

fs::path make_test_dir(const char *name) {
    fs::path p = fs::temp_directory_path() / (std::string("linoh_test_sss_") + name);
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

void write_file(const std::string &path, const std::string &content) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    assert(ofs.is_open());
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::string read_file(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary);
    assert(ifs.is_open());
    return std::string((std::istreambuf_iterator<char>(ifs)),
                       std::istreambuf_iterator<char>());
}

ShardState make_state(std::uint32_t idx, std::uint64_t total,
                       std::uint64_t downloaded, bool verified = false) {
    ShardState s;
    s.layer_index = idx;
    s.filename = shard_filename(idx);
    s.total_size = total;
    s.downloaded_bytes = downloaded;
    s.sha256_hex = std::string(64, '0' + static_cast<char>(idx % 10));
    s.verified = verified;
    s.timestamp_ms = 1000000 + idx;
    s.retry_count = 0;
    return s;
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
// ShardState 结构
// =============================================================================

void test_state_default() {
    ShardState s;
    assert(s.layer_index == 0);
    assert(s.filename.empty());
    assert(s.total_size == 0);
    assert(s.downloaded_bytes == 0);
    assert(s.sha256_hex.empty());
    assert(!s.verified);
    assert(s.timestamp_ms == 0);
    assert(s.retry_count == 0);
}

void test_state_is_complete() {
    ShardState s;
    s.total_size = 1000;
    s.downloaded_bytes = 500;
    assert(!s.is_complete());

    s.downloaded_bytes = 1000;
    assert(s.is_complete());

    s.downloaded_bytes = 1500;  // 超过 total_size
    assert(s.is_complete());

    s.total_size = 0;  // total_size=0 时永远 false
    s.downloaded_bytes = 100;
    assert(!s.is_complete());
}

void test_state_progress_percent() {
    ShardState s;
    s.total_size = 1000;

    s.downloaded_bytes = 0;
    assert(s.progress_percent() == 0);

    s.downloaded_bytes = 500;
    assert(s.progress_percent() == 50);

    s.downloaded_bytes = 1000;
    assert(s.progress_percent() == 100);

    s.downloaded_bytes = 1500;
    assert(s.progress_percent() == 100);

    s.total_size = 0;  // 除零保护
    assert(s.progress_percent() == 0);
}

void test_state_needs_resume() {
    ShardState s;
    s.total_size = 1000;

    s.downloaded_bytes = 0;
    assert(!s.needs_resume());  // 未开始

    s.downloaded_bytes = 500;
    assert(s.needs_resume());  // 部分下载

    s.downloaded_bytes = 1000;
    assert(!s.needs_resume());  // 已完成
}

// =============================================================================
// ShardStateStore 构造 + 基础 CRUD
// =============================================================================

void test_store_default_empty() {
    auto dir = make_test_dir("default");
    ShardStateStore store((dir / "state.json").string());
    assert(store.empty());
    assert(store.size() == 0);
    assert(!store.file_exists());
}

void test_store_upsert_find() {
    auto dir = make_test_dir("upsert_find");
    ShardStateStore store((dir / "state.json").string());

    ShardState s1 = make_state(0, 1000, 500);
    assert(store.upsert(s1));
    assert(store.size() == 1);

    ShardState *found = store.find(0);
    assert(found != nullptr);
    assert(found->layer_index == 0);
    assert(found->total_size == 1000);
    assert(found->downloaded_bytes == 500);

    // upsert 已存在的（更新）
    ShardState s1_update = make_state(0, 1000, 1000, true);
    assert(store.upsert(s1_update));
    assert(store.size() == 1);  // 数量不变

    found = store.find(0);
    assert(found->downloaded_bytes == 1000);
    assert(found->verified);
}

void test_store_find_not_found() {
    auto dir = make_test_dir("find_not_found");
    ShardStateStore store((dir / "state.json").string());
    store.upsert(make_state(0, 1000, 500));

    assert(store.find(0) != nullptr);
    assert(store.find(1) == nullptr);
    assert(store.find(99) == nullptr);
}

void test_store_find_const() {
    auto dir = make_test_dir("find_const");
    ShardStateStore store((dir / "state.json").string());
    store.upsert(make_state(5, 2000, 1500));

    const ShardStateStore &cstore = store;
    const ShardState *found = cstore.find(5);
    assert(found != nullptr);
    assert(found->layer_index == 5);
    assert(found->downloaded_bytes == 1500);

    assert(cstore.find(99) == nullptr);
}

void test_store_remove() {
    auto dir = make_test_dir("remove");
    ShardStateStore store((dir / "state.json").string());
    store.upsert(make_state(0, 1000, 500));
    store.upsert(make_state(1, 2000, 1000));
    assert(store.size() == 2);

    assert(store.remove(0));
    assert(store.size() == 1);
    assert(store.find(0) == nullptr);
    assert(store.find(1) != nullptr);

    assert(!store.remove(99));  // 不存在
    assert(store.size() == 1);
}

void test_store_clear() {
    auto dir = make_test_dir("clear");
    ShardStateStore store((dir / "state.json").string());
    store.upsert(make_state(0, 1000, 500));
    store.upsert(make_state(1, 2000, 1000));
    assert(store.size() == 2);

    store.clear();
    assert(store.empty());
    assert(store.size() == 0);
}

void test_store_upsert_keeps_sorted() {
    // upsert 应保持 layer_index 升序
    auto dir = make_test_dir("sorted");
    ShardStateStore store((dir / "state.json").string());

    store.upsert(make_state(5, 1000, 500));
    store.upsert(make_state(1, 1000, 500));
    store.upsert(make_state(3, 1000, 500));
    store.upsert(make_state(0, 1000, 500));

    auto &all = store.all();
    assert(all.size() == 4);
    assert(all[0].layer_index == 0);
    assert(all[1].layer_index == 1);
    assert(all[2].layer_index == 3);
    assert(all[3].layer_index == 5);
}

// =============================================================================
// 文件读写
// =============================================================================

void test_store_save_load_roundtrip() {
    auto dir = make_test_dir("roundtrip");
    auto path = (dir / "state.json").string();

    ShardStateStore store(path);
    store.upsert(make_state(0, 1000, 500));
    store.upsert(make_state(1, 2000, 2000, true));
    store.upsert(make_state(2, 3000, 0));

    assert(store.save_atomic());
    assert(store.file_exists());

    // 重新加载
    ShardStateStore store2(path);
    assert(store2.load_from_file());
    assert(store2.size() == 3);

    auto *s0 = store2.find(0);
    assert(s0 != nullptr);
    assert(s0->total_size == 1000);
    assert(s0->downloaded_bytes == 500);
    assert(!s0->verified);

    auto *s1 = store2.find(1);
    assert(s1 != nullptr);
    assert(s1->downloaded_bytes == 2000);
    assert(s1->verified);

    auto *s2 = store2.find(2);
    assert(s2 != nullptr);
    assert(s2->downloaded_bytes == 0);
}

void test_store_load_nonexistent() {
    auto dir = make_test_dir("load_nonexistent");
    ShardStateStore store((dir / "nonexistent.json").string());
    assert(!store.load_from_file());  // 文件不存在
    assert(store.empty());
}

void test_store_save_creates_parent_dir() {
    auto dir = make_test_dir("parent_dir");
    auto nested = dir / "a" / "b" / "c" / "state.json";

    ShardStateStore store(nested.string());
    store.upsert(make_state(0, 1000, 500));
    assert(store.save_atomic());
    assert(fs::exists(nested));
}

void test_store_remove_file() {
    auto dir = make_test_dir("remove_file");
    auto path = (dir / "state.json").string();

    ShardStateStore store(path);
    store.upsert(make_state(0, 1000, 500));
    assert(store.save_atomic());
    assert(store.file_exists());

    assert(store.remove_file());
    assert(!store.file_exists());

    assert(!store.remove_file());  // 再次删除失败
}

// =============================================================================
// 完整性校验
// =============================================================================

void test_store_load_rejects_tampered_hash() {
    auto dir = make_test_dir("tampered_hash");
    auto path = (dir / "state.json").string();

    ShardStateStore store(path);
    store.upsert(make_state(0, 1000, 500));
    assert(store.save_atomic());

    // 篡改文件内容（修改 downloaded_bytes 但保留 store_hash）
    std::string content = read_file(path);
    auto pos = content.find("\"downloaded_bytes\":500");
    assert(pos != std::string::npos);
    content[pos + 20] = '9';  // 500 → 900
    content[pos + 21] = '0';
    content[pos + 22] = '0';
    write_file(path, content);

    // 加载应失败（store_hash 不匹配）
    ShardStateStore store2(path);
    assert(!store2.load_from_file());
    assert(store2.empty());
}

void test_store_load_backward_compat_no_hash() {
    // 旧版状态文件（无 store_hash 字段）应能正常加载
    auto dir = make_test_dir("backward_compat");
    auto path = (dir / "state.json").string();

    std::string old_json = R"({
  "states": [
    {
      "layer_index": 0,
      "filename": "layer_0000.gguf",
      "total_size": 1000,
      "downloaded_bytes": 500,
      "sha256": "aaaa",
      "verified": false,
      "timestamp_ms": 1000,
      "retry_count": 0
    }
  ]
})";
    write_file(path, old_json);

    ShardStateStore store(path);
    assert(store.load_from_file());
    assert(store.size() == 1);
    auto *s = store.find(0);
    assert(s != nullptr);
    assert(s->downloaded_bytes == 500);
}

void test_store_load_rejects_uncommitted() {
    // atomic_committed=false 的文件应被拒绝
    auto dir = make_test_dir("reject_uncommitted");
    auto path = (dir / "state.json").string();

    std::string uncommitted_json = R"({
  "schema_version": 1,
  "atomic_committed": false,
  "store_hash": "dummy",
  "states": []
})";
    write_file(path, uncommitted_json);

    ShardStateStore store(path);
    assert(!store.load_from_file());
    assert(store.empty());
}

// =============================================================================
// 查询辅助
// =============================================================================

void test_store_completed_count() {
    auto dir = make_test_dir("completed_count");
    ShardStateStore store((dir / "state.json").string());

    store.upsert(make_state(0, 1000, 1000, true));   // 完成 + 校验
    store.upsert(make_state(1, 2000, 2000, false));  // 完成但未校验
    store.upsert(make_state(2, 3000, 1500, false));  // 部分下载
    store.upsert(make_state(3, 4000, 0, false));     // 未开始

    assert(store.completed_count() == 1);  // 只有 layer 0
}

void test_store_resume_count() {
    auto dir = make_test_dir("resume_count");
    ShardStateStore store((dir / "state.json").string());

    store.upsert(make_state(0, 1000, 1000, true));   // 完成
    store.upsert(make_state(1, 2000, 500, false));   // 部分下载
    store.upsert(make_state(2, 3000, 1500, false));  // 部分下载
    store.upsert(make_state(3, 4000, 0, false));     // 未开始

    assert(store.resume_count() == 2);  // layer 1 + layer 2
}

void test_store_pending_count() {
    auto dir = make_test_dir("pending_count");
    ShardStateStore store((dir / "state.json").string());

    store.upsert(make_state(0, 1000, 1000, true));   // 完成
    store.upsert(make_state(1, 2000, 500, false));   // 部分下载
    // layer 2 未在 store 中
    store.upsert(make_state(3, 4000, 0, false));     // 未开始

    std::vector<ShardEntry> manifest_shards = {
        {0, "layer_0000.gguf", "a", 1000, 1},
        {1, "layer_0001.gguf", "b", 2000, 1},
        {2, "layer_0002.gguf", "c", 3000, 1},  // store 中无
        {3, "layer_0003.gguf", "d", 4000, 1},  // store 中 downloaded_bytes=0
    };

    assert(store.pending_count(manifest_shards) == 2);  // layer 2 + layer 3
}

void test_store_total_downloaded_bytes() {
    auto dir = make_test_dir("total_bytes");
    ShardStateStore store((dir / "state.json").string());

    store.upsert(make_state(0, 1000, 500));
    store.upsert(make_state(1, 2000, 1500));
    store.upsert(make_state(2, 3000, 0));

    assert(store.total_downloaded_bytes() == 2000);
}

// =============================================================================
// 便捷辅助函数
// =============================================================================

void test_sync_from_manifest_new() {
    auto dir = make_test_dir("sync_new");
    ShardStateStore store((dir / "state.json").string());

    std::vector<ShardEntry> shards = {
        {0, "layer_0000.gguf", "aaaa", 1000, 1},
        {1, "layer_0001.gguf", "bbbb", 2000, 1},
        {2, "layer_0002.gguf", "cccc", 3000, 1},
    };

    std::size_t added = sync_from_manifest(store, shards);
    assert(added == 3);
    assert(store.size() == 3);

    auto *s0 = store.find(0);
    assert(s0 != nullptr);
    assert(s0->filename == "layer_0000.gguf");
    assert(s0->total_size == 1000);
    assert(s0->sha256_hex == "aaaa");
    assert(s0->downloaded_bytes == 0);  // 新增默认 0
    assert(!s0->verified);
}

void test_sync_from_manifest_preserves_progress() {
    auto dir = make_test_dir("sync_preserve");
    ShardStateStore store((dir / "state.json").string());

    // 预设 layer 0 已有部分下载进度
    ShardState existing;
    existing.layer_index = 0;
    existing.filename = "old_name.gguf";
    existing.total_size = 500;
    existing.downloaded_bytes = 300;
    existing.verified = false;
    existing.retry_count = 2;
    existing.timestamp_ms = 999;
    store.upsert(existing);

    std::vector<ShardEntry> shards = {
        {0, "layer_0000.gguf", "aaaa", 1000, 1},
        {1, "layer_0001.gguf", "bbbb", 2000, 1},
    };

    std::size_t added = sync_from_manifest(store, shards);
    assert(added == 1);  // 只新增 layer 1
    assert(store.size() == 2);

    // layer 0 的下载进度应保留
    auto *s0 = store.find(0);
    assert(s0 != nullptr);
    assert(s0->filename == "layer_0000.gguf");  // filename 更新
    assert(s0->total_size == 1000);             // total_size 更新
    assert(s0->sha256_hex == "aaaa");           // sha256 更新
    assert(s0->downloaded_bytes == 300);        // 下载进度保留
    assert(s0->retry_count == 2);               // 重试次数保留
}

void test_mark_shard_completed() {
    auto dir = make_test_dir("mark_completed");
    ShardStateStore store((dir / "state.json").string());
    store.upsert(make_state(0, 1000, 500));

    assert(mark_shard_completed(store, 0));
    auto *s = store.find(0);
    assert(s->downloaded_bytes == 1000);
    assert(s->verified);
    assert(s->timestamp_ms > 0);

    assert(!mark_shard_completed(store, 99));  // 不存在
}

void test_mark_shard_progress() {
    auto dir = make_test_dir("mark_progress");
    ShardStateStore store((dir / "state.json").string());
    store.upsert(make_state(0, 1000, 0));

    assert(mark_shard_progress(store, 0, 500));
    auto *s = store.find(0);
    assert(s->downloaded_bytes == 500);
    assert(!s->verified);

    // 完整下载后 verified 应为 false（待校验）
    assert(mark_shard_progress(store, 0, 1000));
    s = store.find(0);
    assert(s->is_complete());
    assert(!s->verified);

    assert(!mark_shard_progress(store, 99, 100));  // 不存在
}

// =============================================================================
// 端到端：断点续传场景
// =============================================================================

void test_e2e_resume_after_interrupt() {
    // 模拟断点续传场景：
    // 1. 首次下载：部分 shard 完成，部分部分下载，部分未开始
    // 2. 中断后保存状态
    // 3. 重启加载状态
    // 4. 继续下载：跳过已完成，续传部分下载，下载未开始
    auto dir = make_test_dir("e2e_resume");
    auto path = (dir / "state.json").string();

    // 1. 首次下载
    {
        ShardStateStore store(path);
        std::vector<ShardEntry> shards = {
            {0, "layer_0000.gguf", "aaaa", 1000, 1},
            {1, "layer_0001.gguf", "bbbb", 2000, 1},
            {2, "layer_0002.gguf", "cccc", 3000, 1},
        };
        sync_from_manifest(store, shards);

        // 模拟下载进度
        mark_shard_completed(store, 0);          // layer 0 完成
        mark_shard_progress(store, 1, 1000);     // layer 1 部分下载
        // layer 2 未开始

        assert(store.save_atomic());
    }

    // 2. 重启加载状态
    ShardStateStore store(path);
    assert(store.load_from_file());
    assert(store.size() == 3);

    // 3. 验证状态
    assert(store.completed_count() == 1);  // layer 0
    assert(store.resume_count() == 1);     // layer 1

    // 4. 继续下载
    auto *s0 = store.find(0);
    assert(s0->is_complete() && s0->verified);

    auto *s1 = store.find(1);
    assert(s1->needs_resume());
    assert(s1->downloaded_bytes == 1000);

    auto *s2 = store.find(2);
    assert(s2->downloaded_bytes == 0);

    // 5. 完成 layer 1 和 layer 2
    mark_shard_completed(store, 1);
    mark_shard_completed(store, 2);
    assert(store.completed_count() == 3);
}

void test_e2e_corrupted_state_recovery() {
    // 状态文件损坏后应能恢复（重新从 manifest 同步）
    auto dir = make_test_dir("e2e_corrupt");
    auto path = (dir / "state.json").string();

    // 1. 创建并保存状态
    {
        ShardStateStore store(path);
        store.upsert(make_state(0, 1000, 500));
        store.upsert(make_state(1, 2000, 1000));
        assert(store.save_atomic());
    }

    // 2. 篡改状态文件
    std::string content = read_file(path);
    // 修改内容但保留 store_hash（破坏完整性）
    auto pos = content.find("\"downloaded_bytes\":500");
    assert(pos != std::string::npos);
    content[pos + 20] = '9';
    content[pos + 21] = '9';
    content[pos + 22] = '9';
    write_file(path, content);

    // 3. 加载应失败
    ShardStateStore store(path);
    assert(!store.load_from_file());
    assert(store.empty());

    // 4. 从 manifest 重新同步
    std::vector<ShardEntry> shards = {
        {0, "layer_0000.gguf", "aaaa", 1000, 1},
        {1, "layer_0001.gguf", "bbbb", 2000, 1},
    };
    std::size_t added = sync_from_manifest(store, shards);
    assert(added == 2);
    assert(store.size() == 2);
    assert(store.save_atomic());

    // 5. 重新加载应成功
    ShardStateStore store2(path);
    assert(store2.load_from_file());
    assert(store2.size() == 2);
}

void test_e2e_state_survives_save_load_cycles() {
    // 多次保存/加载循环，状态应保持一致
    auto dir = make_test_dir("e2e_cycles");
    auto path = (dir / "state.json").string();

    std::vector<ShardState> states;
    for (std::uint32_t i = 0; i < 10; ++i) {
        states.push_back(make_state(i, 1000 * (i + 1), 500 * (i + 1), i % 2 == 0));
    }

    // 多次保存/加载
    for (int cycle = 0; cycle < 5; ++cycle) {
        ShardStateStore store(path);
        for (const auto &s : states) {
            store.upsert(s);
        }
        assert(store.save_atomic());

        ShardStateStore store2(path);
        assert(store2.load_from_file());
        assert(store2.size() == states.size());

        // 验证每个状态
        for (const auto &expected : states) {
            auto *actual = store2.find(expected.layer_index);
            assert(actual != nullptr);
            assert(actual->filename == expected.filename);
            assert(actual->total_size == expected.total_size);
            assert(actual->downloaded_bytes == expected.downloaded_bytes);
            assert(actual->sha256_hex == expected.sha256_hex);
            assert(actual->verified == expected.verified);
        }
    }
}

// =============================================================================
// 主函数
// =============================================================================

int main() {
    std::cout << "=== test_shard_state_store (v3.7.4) ===\n";

    std::cout << "-- ShardState 结构\n";
    RUN_TEST(test_state_default);
    RUN_TEST(test_state_is_complete);
    RUN_TEST(test_state_progress_percent);
    RUN_TEST(test_state_needs_resume);

    std::cout << "-- ShardStateStore 构造 + CRUD\n";
    RUN_TEST(test_store_default_empty);
    RUN_TEST(test_store_upsert_find);
    RUN_TEST(test_store_find_not_found);
    RUN_TEST(test_store_find_const);
    RUN_TEST(test_store_remove);
    RUN_TEST(test_store_clear);
    RUN_TEST(test_store_upsert_keeps_sorted);

    std::cout << "-- 文件读写\n";
    RUN_TEST(test_store_save_load_roundtrip);
    RUN_TEST(test_store_load_nonexistent);
    RUN_TEST(test_store_save_creates_parent_dir);
    RUN_TEST(test_store_remove_file);

    std::cout << "-- 完整性校验\n";
    RUN_TEST(test_store_load_rejects_tampered_hash);
    RUN_TEST(test_store_load_backward_compat_no_hash);
    RUN_TEST(test_store_load_rejects_uncommitted);

    std::cout << "-- 查询辅助\n";
    RUN_TEST(test_store_completed_count);
    RUN_TEST(test_store_resume_count);
    RUN_TEST(test_store_pending_count);
    RUN_TEST(test_store_total_downloaded_bytes);

    std::cout << "-- 便捷辅助函数\n";
    RUN_TEST(test_sync_from_manifest_new);
    RUN_TEST(test_sync_from_manifest_preserves_progress);
    RUN_TEST(test_mark_shard_completed);
    RUN_TEST(test_mark_shard_progress);

    std::cout << "-- 端到端\n";
    RUN_TEST(test_e2e_resume_after_interrupt);
    RUN_TEST(test_e2e_corrupted_state_recovery);
    RUN_TEST(test_e2e_state_survives_save_load_cycles);

    std::cout << "\n=== " << test_passed << "/" << test_count << " tests passed ===\n";
    return (test_passed == test_count) ? 0 : 1;
}
