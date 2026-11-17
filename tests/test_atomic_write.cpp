// =============================================================================
// test_atomic_write.cpp — v3.7.0 可靠性强化：临时目录 + 原子 rename 单元测试
//
// 覆盖：atomic_write_file + atomic_rename_file + AtomicWriter + cleanup + same_volume
// =============================================================================

#include "linoh/util/atomic_write.hpp"

#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

using namespace linoh::util;

namespace fs = std::filesystem;

namespace {

/// 生成唯一测试目录
fs::path make_test_dir(const char *name) {
    fs::path p = fs::temp_directory_path() / (std::string("linoh_test_aw_") + name);
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

/// 写文件（非原子，用于准备测试数据）
void write_file(const std::string &path, const std::vector<uint8_t> &data) {
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
// file_exists / file_size
// =============================================================================

void test_file_exists_true() {
    auto dir = make_test_dir("exists_true");
    auto p = (dir / "f.txt").string();
    write_file(p, {0x41, 0x42});
    assert(file_exists(p));
    fs::remove_all(dir);
}

void test_file_exists_false() {
    assert(!file_exists("nonexistent_xyz_123.bin"));
}

void test_file_size() {
    auto dir = make_test_dir("fsize");
    auto p = (dir / "f.bin").string();
    std::vector<uint8_t> data(1234, 0x55);
    write_file(p, data);
    std::size_t sz = 0;
    assert(file_size(p, sz));
    assert(sz == 1234);
    fs::remove_all(dir);
}

void test_file_size_not_exist() {
    std::size_t sz = 0;
    assert(!file_size("nonexistent_xyz_456.bin", sz));
}

// =============================================================================
// atomic_write_file
// =============================================================================

void test_atomic_write_small() {
    auto dir = make_test_dir("aw_small");
    auto p = (dir / "out.bin").string();
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    assert(atomic_write_file(p, data));
    assert(file_exists(p));
    auto read = read_file(p);
    assert(read.size() == data.size());
    assert(std::memcmp(read.data(), data.data(), data.size()) == 0);
    fs::remove_all(dir);
}

void test_atomic_write_empty() {
    auto dir = make_test_dir("aw_empty");
    auto p = (dir / "empty.bin").string();
    assert(atomic_write_file(p, std::span<const uint8_t>{}));
    assert(file_exists(p));
    std::size_t sz = 99;
    assert(file_size(p, sz));
    assert(sz == 0);
    fs::remove_all(dir);
}

void test_atomic_write_overwrite() {
    auto dir = make_test_dir("aw_overwrite");
    auto p = (dir / "over.bin").string();
    std::vector<uint8_t> old(100, 0xAA);
    write_file(p, old);
    std::vector<uint8_t> neu = {0xBB, 0xCC};
    assert(atomic_write_file(p, neu));
    auto read = read_file(p);
    assert(read.size() == 2);
    assert(read[0] == 0xBB && read[1] == 0xCC);
    fs::remove_all(dir);
}

void test_atomic_write_large() {
    auto dir = make_test_dir("aw_large");
    auto p = (dir / "large.bin").string();
    std::vector<uint8_t> data(100000, 0x77);
    assert(atomic_write_file(p, data));
    auto read = read_file(p);
    assert(read.size() == 100000);
    assert(std::memcmp(read.data(), data.data(), 100000) == 0);
    fs::remove_all(dir);
}

void test_atomic_write_no_temp_left() {
    auto dir = make_test_dir("aw_no_temp");
    auto p = (dir / "clean.bin").string();
    atomic_write_file(p, std::vector<uint8_t>{0x01});
    // 确保没有残留临时文件
    int tmp_count = 0;
    for (auto &e : fs::directory_iterator(dir)) {
        std::string name = e.path().filename().string();
        if (name.find(".tmp.") != std::string::npos) ++tmp_count;
    }
    assert(tmp_count == 0);
    fs::remove_all(dir);
}

// =============================================================================
// atomic_rename_file
// =============================================================================

void test_atomic_rename_basic() {
    auto dir = make_test_dir("rename_basic");
    auto src = (dir / "src.bin").string();
    auto dst = (dir / "dst.bin").string();
    write_file(src, {0x11, 0x22, 0x33});
    assert(atomic_rename_file(src, dst));
    assert(!file_exists(src));  // 源已移走
    assert(file_exists(dst));
    auto read = read_file(dst);
    assert(read.size() == 3 && read[0] == 0x11);
    fs::remove_all(dir);
}

void test_atomic_rename_overwrite() {
    auto dir = make_test_dir("rename_over");
    auto src = (dir / "src.bin").string();
    auto dst = (dir / "dst.bin").string();
    write_file(src, {0x99});
    write_file(dst, {0x00, 0x00, 0x00, 0x00});
    assert(atomic_rename_file(src, dst));
    auto read = read_file(dst);
    assert(read.size() == 1 && read[0] == 0x99);
    fs::remove_all(dir);
}

void test_atomic_rename_src_not_exist() {
    auto dir = make_test_dir("rename_no_src");
    auto dst = (dir / "dst.bin").string();
    assert(!atomic_rename_file("nonexistent_src.bin", dst));
    fs::remove_all(dir);
}

// =============================================================================
// AtomicWriter
// =============================================================================

void test_atomic_writer_create() {
    auto dir = make_test_dir("aw_create");
    AtomicWriter w(dir.string(), ".tmp-");
    assert(w.valid());
    assert(!w.temp_dir().empty());
    assert(fs::exists(fs::path(w.temp_dir())));
    // 临时目录在 base_dir 下
    assert(fs::path(w.temp_dir()).parent_path() == dir);
    fs::remove_all(dir);
}

void test_atomic_writer_commit() {
    auto dir = make_test_dir("aw_commit");
    auto target = (dir / "result.bin").string();
    {
        AtomicWriter w(dir.string(), ".tmp-");
        assert(w.valid());
        auto temp_file = w.temp_path("part.bin");
        write_file(temp_file, {0xAA, 0xBB, 0xCC});
        assert(w.commit("part.bin", target));
        assert(!w.valid());  // commit 后失效
    }
    assert(file_exists(target));
    auto read = read_file(target);
    assert(read.size() == 3 && read[0] == 0xAA);
    fs::remove_all(dir);
}

void test_atomic_writer_discard() {
    auto dir = make_test_dir("aw_discard");
    std::string temp_dir;
    {
        AtomicWriter w(dir.string(), ".tmp-");
        temp_dir = w.temp_dir();
        write_file(w.temp_path("part.bin"), {0x01});
        w.discard();
        assert(!w.valid());
    }
    assert(!fs::exists(fs::path(temp_dir)));  // 临时目录已清理
    fs::remove_all(dir);
}

void test_atomic_writer_destructor_cleanup() {
    auto dir = make_test_dir("aw_dtor");
    std::string temp_dir;
    {
        AtomicWriter w(dir.string(), ".tmp-");
        temp_dir = w.temp_dir();
        write_file(w.temp_path("part.bin"), {0x01});
        // 不调用 commit/discard，析构时自动清理
    }
    assert(!fs::exists(fs::path(temp_dir)));
    fs::remove_all(dir);
}

void test_atomic_writer_move() {
    auto dir = make_test_dir("aw_move");
    std::string temp_dir;
    {
        AtomicWriter w1(dir.string(), ".tmp-");
        temp_dir = w1.temp_dir();
        AtomicWriter w2 = std::move(w1);
        assert(!w1.valid());  // 源失效
        assert(w2.valid());
        assert(w2.temp_dir() == temp_dir);
    }
    assert(!fs::exists(fs::path(temp_dir)));  // w2 析构清理
    fs::remove_all(dir);
}

void test_atomic_writer_commit_path() {
    auto dir = make_test_dir("aw_commit_path");
    auto target = (dir / "out.bin").string();
    {
        AtomicWriter w(dir.string(), ".tmp-");
        auto tp = w.temp_path("data.bin");
        write_file(tp, {0x12, 0x34});
        assert(w.commit_path(tp, target));
    }
    auto read = read_file(target);
    assert(read.size() == 2 && read[0] == 0x12);
    fs::remove_all(dir);
}

void test_atomic_writer_commit_temp_not_exist() {
    auto dir = make_test_dir("aw_commit_no_exist");
    auto target = (dir / "out.bin").string();
    AtomicWriter w(dir.string(), ".tmp-");
    assert(!w.commit("nonexistent.bin", target));
    fs::remove_all(dir);
}

// =============================================================================
// cleanup_stale_temp_dirs
// =============================================================================

void test_cleanup_stale_dirs() {
    auto dir = make_test_dir("cleanup");
    // 创建 2 个残留临时目录
    fs::create_directory(dir / ".merged-aaa");
    fs::create_directory(dir / ".merged-bbb");
    fs::create_directory(dir / ".other-ccc");  // 不匹配前缀，不清理
    write_file((dir / ".merged-aaa" / "f.bin").string(), {0x01});

    std::size_t removed = 0;
    assert(cleanup_stale_temp_dirs(dir.string(), ".merged-", &removed));
    assert(removed == 2);
    assert(!fs::exists(dir / ".merged-aaa"));
    assert(!fs::exists(dir / ".merged-bbb"));
    assert(fs::exists(dir / ".other-ccc"));  // 保留
    fs::remove_all(dir);
}

void test_cleanup_stale_dirs_none() {
    auto dir = make_test_dir("cleanup_none");
    write_file((dir / "normal.txt").string(), {0x01});
    std::size_t removed = 99;
    assert(cleanup_stale_temp_dirs(dir.string(), ".tmp-", &removed));
    assert(removed == 0);
    fs::remove_all(dir);
}

void test_cleanup_stale_dirs_base_not_exist() {
    std::size_t removed = 0;
    assert(!cleanup_stale_temp_dirs("nonexistent_base_dir_xyz", ".tmp-", &removed));
}

// =============================================================================
// same_volume
// =============================================================================

void test_same_volume_true() {
    auto dir = make_test_dir("vol_true");
    auto p1 = (dir / "a.bin").string();
    auto p2 = (dir / "b.bin").string();
    assert(same_volume(p1, p2));
    fs::remove_all(dir);
}

void test_same_volume_empty() {
    assert(!same_volume("", ""));
    assert(!same_volume("a", ""));
}

// =============================================================================
// 集成场景：模拟 stale cache 根治流程
// =============================================================================

void test_integration_stale_cache_recovery() {
    auto dir = make_test_dir("integration");
    auto target = (dir / "merged.gguf").string();

    // 模拟写入中断：创建残留临时目录
    fs::create_directory(dir / ".merged-stale-xxx");
    write_file((dir / ".merged-stale-xxx" / "merged.gguf.part").string(),
               std::vector<uint8_t>(100, 0xCC));

    // 启动时清理残留
    std::size_t removed = 0;
    cleanup_stale_temp_dirs(dir.string(), ".merged-", &removed);
    assert(removed == 1);
    assert(!fs::exists(dir / ".merged-stale-xxx"));

    // 重新用 AtomicWriter 写入
    {
        AtomicWriter w(dir.string(), ".merged-");
        auto tp = w.temp_path("merged.gguf.part");
        std::vector<uint8_t> data(500, 0xDD);
        write_file(tp, data);
        assert(w.commit("merged.gguf.part", target));
    }

    // 验证目标文件完整
    assert(file_exists(target));
    auto read = read_file(target);
    assert(read.size() == 500);
    assert(read[0] == 0xDD && read[499] == 0xDD);

    fs::remove_all(dir);
}

int main() {
    std::cout << "=== test_atomic_write v3.7.0 ===\n";

    std::cout << "-- file_exists / file_size\n";
    RUN_TEST(test_file_exists_true);
    RUN_TEST(test_file_exists_false);
    RUN_TEST(test_file_size);
    RUN_TEST(test_file_size_not_exist);

    std::cout << "-- atomic_write_file\n";
    RUN_TEST(test_atomic_write_small);
    RUN_TEST(test_atomic_write_empty);
    RUN_TEST(test_atomic_write_overwrite);
    RUN_TEST(test_atomic_write_large);
    RUN_TEST(test_atomic_write_no_temp_left);

    std::cout << "-- atomic_rename_file\n";
    RUN_TEST(test_atomic_rename_basic);
    RUN_TEST(test_atomic_rename_overwrite);
    RUN_TEST(test_atomic_rename_src_not_exist);

    std::cout << "-- AtomicWriter\n";
    RUN_TEST(test_atomic_writer_create);
    RUN_TEST(test_atomic_writer_commit);
    RUN_TEST(test_atomic_writer_discard);
    RUN_TEST(test_atomic_writer_destructor_cleanup);
    RUN_TEST(test_atomic_writer_move);
    RUN_TEST(test_atomic_writer_commit_path);
    RUN_TEST(test_atomic_writer_commit_temp_not_exist);

    std::cout << "-- cleanup_stale_temp_dirs\n";
    RUN_TEST(test_cleanup_stale_dirs);
    RUN_TEST(test_cleanup_stale_dirs_none);
    RUN_TEST(test_cleanup_stale_dirs_base_not_exist);

    std::cout << "-- same_volume\n";
    RUN_TEST(test_same_volume_true);
    RUN_TEST(test_same_volume_empty);

    std::cout << "-- 集成场景\n";
    RUN_TEST(test_integration_stale_cache_recovery);

    std::cout << "\n[OK] test_atomic_write passed: " << test_passed << "/"
              << test_count << " tests\n";
    return 0;
}
