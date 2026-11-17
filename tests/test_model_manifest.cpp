// =============================================================================
// test_model_manifest.cpp — v3.7.1 可靠性强化：内容寻址 manifest 单元测试
//
// 覆盖：JSON 序列化/反序列化 + manifest_hash 计算/校验 + shard 校验 +
//       原子写入/读取 + build_manifest_for_cache + 文件名辅助
// =============================================================================

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

/// 生成唯一测试目录
fs::path make_test_dir(const char *name) {
    fs::path p = fs::temp_directory_path() / (std::string("linoh_test_mm_") + name);
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

/// 写文件（非原子，用于准备测试数据）
void write_file(const std::string &path, const std::string &content) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    assert(ofs.is_open());
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
}

/// 读文件
std::string read_file(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary);
    assert(ifs.is_open());
    return std::string((std::istreambuf_iterator<char>(ifs)),
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
// JSON 序列化 / 反序列化往返
// =============================================================================

void test_json_roundtrip_basic() {
    ModelManifest m;
    m.model_name = "Qwen3.5-122B";
    m.model_version = "v1.0";
    m.total_layers = 48;
    m.manifest_hash = "abcdef0123456789";

    ShardEntry s;
    s.layer_index = 0;
    s.filename = "layer_0000.gguf";
    s.sha256_hex = "deadbeef";
    s.size = 1610612736;
    s.version = 1;
    m.shards.push_back(s);

    std::string json = m.to_json();
    assert(!json.empty());
    assert(json.find("\"model_name\":\"Qwen3.5-122B\"") != std::string::npos);
    assert(json.find("\"total_layers\":48") != std::string::npos);
    assert(json.find("\"layer_0000.gguf\"") != std::string::npos);

    ModelManifest m2;
    assert(ModelManifest::from_json(json, m2));
    assert(m2.model_name == "Qwen3.5-122B");
    assert(m2.model_version == "v1.0");
    assert(m2.total_layers == 48);
    assert(m2.manifest_hash == "abcdef0123456789");
    assert(m2.shards.size() == 1);
    assert(m2.shards[0].layer_index == 0);
    assert(m2.shards[0].filename == "layer_0000.gguf");
    assert(m2.shards[0].sha256_hex == "deadbeef");
    assert(m2.shards[0].size == 1610612736);
    assert(m2.shards[0].version == 1);
}

void test_json_roundtrip_multiple_shards() {
    ModelManifest m;
    m.model_name = "GLM5.2-122B";
    m.model_version = "v2.0";
    m.total_layers = 48;

    for (std::uint32_t i = 0; i < 5; ++i) {
        ShardEntry s;
        s.layer_index = i;
        s.filename = shard_filename(i);
        s.sha256_hex = std::string(64, '0' + static_cast<char>(i));
        s.size = 1000000 * (i + 1);
        s.version = 2;
        m.shards.push_back(s);
    }

    std::string json = m.to_json(true);  // pretty
    assert(json.find('\n') != std::string::npos);  // pretty 模式有换行

    ModelManifest m2;
    assert(ModelManifest::from_json(json, m2));
    assert(m2.shards.size() == 5);
    assert(m2.shards[0].layer_index == 0);
    assert(m2.shards[4].layer_index == 4);
    assert(m2.shards[2].filename == "layer_0002.gguf");
    assert(m2.shards[3].size == 4000000);
    assert(m2.shards[1].version == 2);
}

void test_json_special_chars() {
    // 测试含特殊字符的字符串（引号、反斜杠、换行）
    ModelManifest m;
    m.model_name = "model\"with\\quotes\n";
    m.model_version = "v1.0";
    m.total_layers = 1;

    std::string json = m.to_json();
    ModelManifest m2;
    assert(ModelManifest::from_json(json, m2));
    assert(m2.model_name == "model\"with\\quotes\n");
}

void test_json_invalid_format() {
    ModelManifest m;
    assert(!ModelManifest::from_json("", m));
    assert(!ModelManifest::from_json("not json", m));
    assert(!ModelManifest::from_json("{", m));
    assert(!ModelManifest::from_json("{\"model_name\":}", m));
    assert(!ModelManifest::from_json("{\"model_name\":123}", m));  // 值类型错误
}

// =============================================================================
// manifest_hash 计算 / 校验
// =============================================================================

void test_compute_hash_consistent() {
    ModelManifest m1;
    m1.model_name = "TestModel";
    m1.model_version = "v1.0";
    m1.total_layers = 2;
    ShardEntry s1{0, "layer_0000.gguf", "aaaa", 1000, 1};
    ShardEntry s2{1, "layer_0001.gguf", "bbbb", 2000, 1};
    m1.shards = {s1, s2};

    ModelManifest m2 = m1;
    m1.compute_hash();
    m2.compute_hash();
    assert(m1.manifest_hash == m2.manifest_hash);
    assert(m1.manifest_hash.size() == 64);  // sha256 hex = 64 字符
    assert(!m1.manifest_hash.empty());
}

void test_compute_hash_changes_on_content() {
    ModelManifest m1;
    m1.model_name = "TestModel";
    m1.model_version = "v1.0";
    m1.total_layers = 1;
    m1.shards = {{0, "layer_0000.gguf", "aaaa", 1000, 1}};

    ModelManifest m2 = m1;
    m2.shards[0].sha256_hex = "bbbb";  // 改变内容

    m1.compute_hash();
    m2.compute_hash();
    assert(m1.manifest_hash != m2.manifest_hash);
}

void test_compute_hash_invariant_to_manifest_hash_field() {
    // manifest_hash 不应影响自身计算（canonical form 排除 manifest_hash）
    ModelManifest m;
    m.model_name = "TestModel";
    m.model_version = "v1.0";
    m.total_layers = 1;
    m.shards = {{0, "layer_0000.gguf", "aaaa", 1000, 1}};

    m.manifest_hash = "somedummyvalue";
    m.compute_hash();
    std::string h1 = m.manifest_hash;

    // 重新计算，应得到相同结果
    m.compute_hash();
    assert(m.manifest_hash == h1);
}

void test_verify_hash_ok() {
    ModelManifest m;
    m.model_name = "TestModel";
    m.model_version = "v1.0";
    m.total_layers = 1;
    m.shards = {{0, "layer_0000.gguf", "aaaa", 1000, 1}};
    m.compute_hash();
    assert(m.verify_hash());
}

void test_verify_hash_empty_allowed() {
    // 空 manifest_hash 视为"未设置"，verify_hash 返回 true（兼容）
    ModelManifest m;
    m.model_name = "TestModel";
    m.total_layers = 0;
    assert(m.manifest_hash.empty());
    assert(m.verify_hash());
}

void test_verify_hash_tampered() {
    ModelManifest m;
    m.model_name = "TestModel";
    m.model_version = "v1.0";
    m.total_layers = 1;
    m.shards = {{0, "layer_0000.gguf", "aaaa", 1000, 1}};
    m.compute_hash();

    // 篡改 manifest_hash
    m.manifest_hash[0] = (m.manifest_hash[0] == '0') ? '1' : '0';
    assert(!m.verify_hash());

    // 篡改内容但保留 manifest_hash
    m.manifest_hash.clear();
    m.compute_hash();
    std::string correct = m.manifest_hash;
    m.shards[0].size = 9999;  // 篡改内容
    m.manifest_hash = correct;  // 保留旧 hash
    assert(!m.verify_hash());
}

// =============================================================================
// shard 校验
// =============================================================================

void test_verify_shards_all_ok() {
    auto dir = make_test_dir("shards_ok");
    write_file((dir / "layer_0000.gguf").string(), "AAAA");
    write_file((dir / "layer_0001.gguf").string(), "BBBBBB");

    ModelManifest m;
    m.model_name = "Test";
    m.total_layers = 2;

    // 先 build 获取正确 hash
    assert(build_manifest_for_cache(dir.string(), "Test", "v1.0", 2, m));

    auto r = m.verify_shards(dir.string());
    assert(r.all_ok);
    assert(r.missing.empty());
    assert(r.hash_mismatch.empty());
    assert(r.size_mismatch.empty());
}

void test_verify_shards_missing() {
    auto dir = make_test_dir("shards_missing");
    write_file((dir / "layer_0000.gguf").string(), "AAAA");
    // 故意不创建 layer_0001.gguf

    ModelManifest m;
    m.model_name = "Test";
    m.total_layers = 2;
    m.shards = {{0, "layer_0000.gguf", "aaaa", 4, 1},
                {1, "layer_0001.gguf", "bbbb", 6, 1}};

    auto r = m.verify_shards(dir.string());
    assert(!r.all_ok);
    assert(r.missing.size() == 1);
    assert(r.missing[0] == 1);  // shards[1] 缺失
}

void test_verify_shards_hash_mismatch() {
    auto dir = make_test_dir("shards_hash");
    write_file((dir / "layer_0000.gguf").string(), "AAAA");

    ModelManifest m;
    m.model_name = "Test";
    m.total_layers = 1;
    // 故意填错 sha256
    m.shards = {{0, "layer_0000.gguf",
                  "0000000000000000000000000000000000000000000000000000000000000000",
                  4, 1}};

    auto r = m.verify_shards(dir.string());
    assert(!r.all_ok);
    assert(r.hash_mismatch.size() == 1);
    assert(r.hash_mismatch[0] == 0);
}

void test_verify_shards_size_mismatch() {
    auto dir = make_test_dir("shards_size");
    write_file((dir / "layer_0000.gguf").string(), "AAAA");  // 实际 4 字节

    ModelManifest m;
    m.model_name = "Test";
    m.total_layers = 1;
    m.shards = {{0, "layer_0000.gguf",
                  "0000000000000000000000000000000000000000000000000000000000000000",
                  9999, 1}};  // 故意填错 size

    auto r = m.verify_shards(dir.string());
    assert(!r.all_ok);
    assert(r.size_mismatch.size() == 1);
    assert(r.size_mismatch[0] == 0);
}

void test_verify_shards_empty_sha256_skipped() {
    // sha256_hex 为空时跳过 hash 校验（仅校验存在 + 大小）
    auto dir = make_test_dir("shards_empty_hash");
    write_file((dir / "layer_0000.gguf").string(), "AAAA");

    ModelManifest m;
    m.model_name = "Test";
    m.total_layers = 1;
    m.shards = {{0, "layer_0000.gguf", "", 4, 1}};

    auto r = m.verify_shards(dir.string());
    assert(r.all_ok);
}

void test_verify_shards_size_zero_skipped() {
    // size 为 0 时跳过大小校验（仅校验存在 + hash）
    auto dir = make_test_dir("shards_zero_size");
    write_file((dir / "layer_0000.gguf").string(), "AAAA");

    ModelManifest m;
    m.model_name = "Test";
    m.total_layers = 1;
    // 先 build 获取正确 hash
    assert(build_manifest_for_cache(dir.string(), "Test", "v1.0", 1, m));
    // 清空 size 但保留 hash
    m.shards[0].size = 0;

    auto r = m.verify_shards(dir.string());
    assert(r.all_ok);
}

// =============================================================================
// 原子写入 / 读取
// =============================================================================

void test_write_read_manifest() {
    auto dir = make_test_dir("write_read");
    auto path = (dir / "model.manifest").string();

    ModelManifest m;
    m.model_name = "TestModel";
    m.model_version = "v1.0";
    m.total_layers = 2;
    m.shards = {{0, "layer_0000.gguf", "aaaa", 1000, 1},
                {1, "layer_0001.gguf", "bbbb", 2000, 1}};
    m.compute_hash();

    assert(write_manifest_atomic(path, m));
    assert(fs::exists(path));

    ModelManifest m2;
    assert(read_manifest(path, m2));
    assert(m2.model_name == m.model_name);
    assert(m2.total_layers == m.total_layers);
    assert(m2.shards.size() == m.shards.size());
    assert(m2.manifest_hash == m.manifest_hash);
}

void test_read_and_verify_manifest() {
    auto dir = make_test_dir("read_verify");
    auto path = (dir / "model.manifest").string();

    ModelManifest m;
    m.model_name = "TestModel";
    m.model_version = "v1.0";
    m.total_layers = 1;
    m.shards = {{0, "layer_0000.gguf", "aaaa", 1000, 1}};
    m.compute_hash();

    assert(write_manifest_atomic(path, m));

    ModelManifest m2;
    assert(read_and_verify_manifest(path, m2));
    assert(m2.model_name == m.model_name);
}

void test_read_manifest_nonexistent() {
    ModelManifest m;
    assert(!read_manifest("nonexistent_file_xyz.manifest", m));
    assert(!read_and_verify_manifest("nonexistent_file_xyz.manifest", m));
}

void test_read_manifest_tampered_hash() {
    auto dir = make_test_dir("read_tampered");
    auto path = (dir / "model.manifest").string();

    ModelManifest m;
    m.model_name = "TestModel";
    m.total_layers = 1;
    m.shards = {{0, "layer_0000.gguf", "aaaa", 1000, 1}};
    m.compute_hash();
    assert(write_manifest_atomic(path, m));

    // 读取后篡改内容，写回（破坏 manifest_hash）
    std::string content = read_file(path);
    auto pos = content.find("\"manifest_hash\":\"");
    assert(pos != std::string::npos);
    content[pos + 18] = (content[pos + 18] == '0') ? '1' : '0';
    {
        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    // 能解析 JSON，但 manifest_hash 校验失败
    ModelManifest m2;
    assert(read_manifest(path, m2));
    assert(!read_and_verify_manifest(path, m2));
}

// =============================================================================
// build_manifest_for_cache
// =============================================================================

void test_build_manifest_basic() {
    auto dir = make_test_dir("build_basic");
    write_file((dir / "layer_0000.gguf").string(), "AAAA");
    write_file((dir / "layer_0001.gguf").string(), "BBBBBB");
    write_file((dir / "layer_0002.gguf").string(), "CCCCCCCC");

    ModelManifest m;
    assert(build_manifest_for_cache(dir.string(), "TestModel", "v1.0", 3, m));
    assert(m.model_name == "TestModel");
    assert(m.model_version == "v1.0");
    assert(m.total_layers == 3);
    assert(m.shards.size() == 3);
    assert(m.shards[0].layer_index == 0);
    assert(m.shards[1].layer_index == 1);
    assert(m.shards[2].layer_index == 2);
    assert(m.shards[0].filename == "layer_0000.gguf");
    assert(m.shards[0].size == 4);
    assert(m.shards[1].size == 6);
    assert(m.shards[2].size == 8);
    assert(m.shards[0].sha256_hex.size() == 64);
    assert(!m.manifest_hash.empty());
    assert(m.verify_hash());
}

void test_build_manifest_ignores_non_shard_files() {
    auto dir = make_test_dir("build_ignore");
    write_file((dir / "layer_0000.gguf").string(), "AAAA");
    write_file((dir / "README.txt").string(), "not a shard");
    write_file((dir / "config.json").string(), "{}");
    write_file((dir / "merged.gguf").string(), "merged");

    ModelManifest m;
    assert(build_manifest_for_cache(dir.string(), "Test", "v1.0", 1, m));
    assert(m.shards.size() == 1);
    assert(m.shards[0].filename == "layer_0000.gguf");
}

void test_build_manifest_empty_dir() {
    auto dir = make_test_dir("build_empty");
    ModelManifest m;
    assert(!build_manifest_for_cache(dir.string(), "Test", "v1.0", 0, m));
}

void test_build_manifest_nonexistent_dir() {
    ModelManifest m;
    assert(!build_manifest_for_cache("nonexistent_dir_xyz", "Test", "v1.0", 0, m));
}

void test_build_manifest_version_field() {
    auto dir = make_test_dir("build_version");
    write_file((dir / "layer_0000.gguf").string(), "AAAA");

    ModelManifest m;
    assert(build_manifest_for_cache(dir.string(), "Test", "v1.0", 1, m));
    assert(m.shards[0].version == 1);  // 默认 version=1
}

// =============================================================================
// 文件名辅助
// =============================================================================

void test_shard_filename() {
    assert(shard_filename(0) == "layer_0000.gguf");
    assert(shard_filename(1) == "layer_0001.gguf");
    assert(shard_filename(27) == "layer_0027.gguf");
    assert(shard_filename(47) == "layer_0047.gguf");
    assert(shard_filename(100) == "layer_0100.gguf");
    assert(shard_filename(9999) == "layer_9999.gguf");
}

void test_parse_shard_filename() {
    std::uint32_t idx = 0;
    assert(parse_shard_filename("layer_0000.gguf", idx));
    assert(idx == 0);

    assert(parse_shard_filename("layer_0027.gguf", idx));
    assert(idx == 27);

    assert(parse_shard_filename("layer_9999.gguf", idx));
    assert(idx == 9999);

    // 单位数（非标准但允许）
    assert(parse_shard_filename("layer_1.gguf", idx));
    assert(idx == 1);
}

void test_parse_shard_filename_invalid() {
    std::uint32_t idx = 0;
    assert(!parse_shard_filename("layer_0000.txt", idx));
    assert(!parse_shard_filename("layer_.gguf", idx));
    assert(!parse_shard_filename("layer_abc.gguf", idx));
    assert(!parse_shard_filename("notlayer_0000.gguf", idx));
    assert(!parse_shard_filename("layer_00000.gguf", idx));  // 5 位，超长
    assert(!parse_shard_filename("layer_0000", idx));  // 无扩展名
    assert(!parse_shard_filename("", idx));
}

// =============================================================================
// 便捷查询
// =============================================================================

void test_find_shard() {
    ModelManifest m;
    m.shards = {{0, "a", "x", 10, 1},
                {5, "b", "y", 20, 1},
                {10, "c", "z", 30, 1}};

    const ShardEntry *s = m.find_shard(5);
    assert(s != nullptr);
    assert(s->layer_index == 5);
    assert(s->filename == "b");

    assert(m.find_shard(0) != nullptr);
    assert(m.find_shard(10) != nullptr);
    assert(m.find_shard(3) == nullptr);
    assert(m.find_shard(11) == nullptr);
}

void test_total_size() {
    ModelManifest m;
    m.shards = {{0, "a", "x", 1000, 1},
                {1, "b", "y", 2000, 1},
                {2, "c", "z", 3000, 1}};
    assert(m.total_size() == 6000);

    m.shards.clear();
    assert(m.total_size() == 0);
}

void test_shard_count() {
    ModelManifest m;
    assert(m.shard_count() == 0);
    m.shards = {{0, "a", "x", 10, 1}};
    assert(m.shard_count() == 1);
    m.shards.push_back({1, "b", "y", 20, 1});
    assert(m.shard_count() == 2);
}

// =============================================================================
// 端到端：构建 → 写入 → 读取 → 校验 → 篡改检测
// =============================================================================

void test_e2e_build_write_read_verify() {
    auto dir = make_test_dir("e2e");
    write_file((dir / "layer_0000.gguf").string(), "AAAA");
    write_file((dir / "layer_0001.gguf").string(), "BBBBBB");

    // 1. build
    ModelManifest m;
    assert(build_manifest_for_cache(dir.string(), "E2EModel", "v1.0", 2, m));
    assert(m.verify_hash());

    // 2. write
    auto manifest_path = (dir / "model.manifest").string();
    assert(write_manifest_atomic(manifest_path, m));

    // 3. read + verify
    ModelManifest m2;
    assert(read_and_verify_manifest(manifest_path, m2));
    assert(m2.model_name == "E2EModel");
    assert(m2.shards.size() == 2);

    // 4. verify shards 全部通过
    auto r = m2.verify_shards(dir.string());
    assert(r.all_ok);

    // 5. 篡改 shard 文件，重新校验应失败
    write_file((dir / "layer_0000.gguf").string(), "XXXX");  // 改内容
    auto r2 = m2.verify_shards(dir.string());
    assert(!r2.all_ok);
    assert(r2.hash_mismatch.size() == 1);

    // 6. 删除 shard 文件，重新校验应报缺失
    fs::remove(dir / "layer_0001.gguf");
    auto r3 = m2.verify_shards(dir.string());
    assert(!r3.all_ok);
    assert(r3.missing.size() == 1);
}

// =============================================================================
// v3.7.2 原子性：schema_version + atomic_committed 字段
// =============================================================================

void test_v372_schema_version_default() {
    ModelManifest m;
    assert(m.schema_version == ModelManifest::kLatestSchemaVersion);
    assert(m.schema_version == 2);
}

void test_v372_atomic_committed_default() {
    ModelManifest m;
    assert(m.atomic_committed == true);  // 默认为 true（已提交）
}

void test_v372_schema_version_roundtrip() {
    ModelManifest m;
    m.model_name = "TestModel";
    m.total_layers = 1;
    m.shards = {{0, "layer_0000.gguf", "aaaa", 1000, 1}};
    m.schema_version = 1;  // 旧版 schema
    m.compute_hash();

    std::string json = m.to_json();
    assert(json.find("\"schema_version\":1") != std::string::npos);

    ModelManifest m2;
    assert(ModelManifest::from_json(json, m2));
    assert(m2.schema_version == 1);
}

void test_v372_atomic_committed_roundtrip_true() {
    ModelManifest m;
    m.model_name = "Test";
    m.total_layers = 0;
    m.atomic_committed = true;
    m.compute_hash();

    std::string json = m.to_json();
    assert(json.find("\"atomic_committed\":true") != std::string::npos);

    ModelManifest m2;
    assert(ModelManifest::from_json(json, m2));
    assert(m2.atomic_committed == true);
}

void test_v372_atomic_committed_roundtrip_false() {
    ModelManifest m;
    m.model_name = "Test";
    m.total_layers = 0;
    m.atomic_committed = false;
    m.compute_hash();

    std::string json = m.to_json();
    assert(json.find("\"atomic_committed\":false") != std::string::npos);

    ModelManifest m2;
    assert(ModelManifest::from_json(json, m2));
    assert(m2.atomic_committed == false);
}

void test_v372_compute_hash_includes_schema_version() {
    // 修改 schema_version 后 manifest_hash 应变化
    ModelManifest m1;
    m1.model_name = "Test";
    m1.total_layers = 0;
    m1.schema_version = 1;
    m1.compute_hash();

    ModelManifest m2 = m1;
    m2.schema_version = 2;
    m2.compute_hash();

    assert(m1.manifest_hash != m2.manifest_hash);
}

void test_v372_compute_hash_includes_atomic_committed() {
    // 修改 atomic_committed 后 manifest_hash 应变化
    ModelManifest m1;
    m1.model_name = "Test";
    m1.total_layers = 0;
    m1.atomic_committed = false;
    m1.compute_hash();

    ModelManifest m2 = m1;
    m2.atomic_committed = true;
    m2.compute_hash();

    assert(m1.manifest_hash != m2.manifest_hash);
}

void test_v372_is_freshly_committed_default() {
    ModelManifest m;
    assert(m.is_freshly_committed());  // 默认 atomic_committed=true + schema_version=2
}

void test_v372_is_freshly_committed_false_when_writing() {
    ModelManifest m;
    m.mark_writing();  // atomic_committed = false
    assert(!m.is_freshly_committed());
}

void test_v372_is_freshly_committed_after_mark_committed() {
    ModelManifest m;
    m.mark_writing();
    assert(!m.is_freshly_committed());
    m.mark_committed();
    assert(m.is_freshly_committed());
}

void test_v372_is_freshly_committed_invalid_schema() {
    ModelManifest m;
    m.schema_version = 0;  // 无效
    assert(!m.is_freshly_committed());

    m.schema_version = 99;  // 不受支持
    assert(!m.is_freshly_committed());

    m.schema_version = 1;  // 旧版，受支持
    assert(m.is_freshly_committed());

    m.schema_version = ModelManifest::kLatestSchemaVersion;  // 当前版
    assert(m.is_freshly_committed());
}

void test_v372_mark_writing_mark_committed() {
    ModelManifest m;
    assert(m.atomic_committed == true);

    m.mark_writing();
    assert(m.atomic_committed == false);

    m.mark_committed();
    assert(m.atomic_committed == true);
}

void test_v372_write_manifest_atomic_sets_committed() {
    // write_manifest_atomic 后读取应 atomic_committed=true
    auto dir = make_test_dir("v372_write_committed");
    auto path = (dir / "model.manifest").string();

    ModelManifest m;
    m.model_name = "TestModel";
    m.total_layers = 1;
    m.shards = {{0, "layer_0000.gguf", "aaaa", 1000, 1}};
    m.compute_hash();

    assert(write_manifest_atomic(path, m));

    // 读取文件内容，检查 atomic_committed=true
    std::string content = read_file(path);
    assert(content.find("\"atomic_committed\":true") != std::string::npos);
    assert(content.find("\"schema_version\":2") != std::string::npos);

    // 通过 read_manifest 读取，应成功（atomic_committed=true）
    ModelManifest m2;
    assert(read_manifest(path, m2));
    assert(m2.atomic_committed == true);
    assert(m2.schema_version == ModelManifest::kLatestSchemaVersion);
}

void test_v372_read_manifest_rejects_uncommitted() {
    // 手动构造 atomic_committed=false 的 manifest 文件
    // read_manifest 应返回 false（stale cache 检测）
    auto dir = make_test_dir("v372_reject_uncommitted");
    auto path = (dir / "model.manifest").string();

    ModelManifest m;
    m.model_name = "TestModel";
    m.total_layers = 1;
    m.shards = {{0, "layer_0000.gguf", "aaaa", 1000, 1}};
    m.mark_writing();  // atomic_committed=false
    m.compute_hash();  // hash 包含 atomic_committed=false

    // 手动写入（绕过 write_manifest_atomic 的 commit 流程）
    write_file(path, m.to_json(true));

    // read_manifest 应返回 false（atomic_committed=false）
    ModelManifest m2;
    assert(!read_manifest(path, m2));
}

void test_v372_read_and_verify_manifest_rejects_uncommitted() {
    auto dir = make_test_dir("v372_verify_reject_uncommitted");
    auto path = (dir / "model.manifest").string();

    ModelManifest m;
    m.model_name = "TestModel";
    m.total_layers = 1;
    m.shards = {{0, "layer_0000.gguf", "aaaa", 1000, 1}};
    m.mark_writing();
    m.compute_hash();

    write_file(path, m.to_json(true));

    ModelManifest m2;
    assert(!read_and_verify_manifest(path, m2));
}

void test_v372_backward_compat_old_manifest() {
    // 旧版 manifest（无 schema_version/atomic_committed 字段）应能正常解析
    // 反序列化时使用默认值（schema_version=kLatestSchemaVersion, atomic_committed=true）
    std::string old_json = R"({
  "model_name": "OldModel",
  "model_version": "v0.9",
  "total_layers": 1,
  "manifest_hash": "",
  "shards": [
    {
      "layer_index": 0,
      "filename": "layer_0000.gguf",
      "sha256": "aaaa",
      "size": 1000,
      "version": 1
    }
  ]
})";
    ModelManifest m;
    assert(ModelManifest::from_json(old_json, m));
    assert(m.model_name == "OldModel");
    assert(m.model_version == "v0.9");
    assert(m.total_layers == 1);
    // 默认值填充
    assert(m.schema_version == ModelManifest::kLatestSchemaVersion);
    assert(m.atomic_committed == true);
    assert(m.is_freshly_committed());  // 默认值应通过 is_freshly_committed 检查
}

void test_v372_from_json_rejects_wrong_type_schema_version() {
    // schema_version 不接受字符串
    std::string bad_json = R"({"schema_version":"2","model_name":"x"})";
    ModelManifest m;
    assert(!ModelManifest::from_json(bad_json, m));
}

void test_v372_from_json_rejects_wrong_type_atomic_committed_string() {
    // atomic_committed 不接受字符串
    std::string bad_json = R"({"atomic_committed":"true","model_name":"x"})";
    ModelManifest m;
    assert(!ModelManifest::from_json(bad_json, m));
}

void test_v372_from_json_rejects_wrong_type_atomic_committed_number() {
    // atomic_committed 不接受数值
    std::string bad_json = R"({"atomic_committed":1,"model_name":"x"})";
    ModelManifest m;
    assert(!ModelManifest::from_json(bad_json, m));
}

void test_v372_from_json_rejects_bool_for_wrong_field() {
    // bool 值不能赋给 model_name 等字段
    std::string bad_json = R"({"model_name":true})";
    ModelManifest m;
    assert(!ModelManifest::from_json(bad_json, m));

    bad_json = R"({"total_layers":false})";
    assert(!ModelManifest::from_json(bad_json, m));

    bad_json = R"({"schema_version":true})";
    assert(!ModelManifest::from_json(bad_json, m));
}

void test_v372_from_json_rejects_invalid_bool_literal() {
    // 't' 开头但不是 true
    std::string bad_json = R"({"atomic_committed":treu})";
    ModelManifest m;
    assert(!ModelManifest::from_json(bad_json, m));

    // 'f' 开头但不是 false
    bad_json = R"({"atomic_committed":flase})";
    assert(!ModelManifest::from_json(bad_json, m));
}

void test_v372_e2e_stale_cache_recovery() {
    // 模拟 stale cache 场景：写入未完成的 manifest 应被读取端检测到
    auto dir = make_test_dir("v372_stale_e2e");
    auto path = (dir / "model.manifest").string();

    // 1. 正常写入完整 manifest
    ModelManifest m;
    m.model_name = "StaleTest";
    m.total_layers = 1;
    m.shards = {{0, "layer_0000.gguf", "aaaa", 1000, 1}};
    m.compute_hash();
    assert(write_manifest_atomic(path, m));

    // 2. 读取应成功
    ModelManifest m2;
    assert(read_and_verify_manifest(path, m2));

    // 3. 模拟写入中断：手动覆盖为 atomic_committed=false 的版本
    ModelManifest writing_copy = m;
    writing_copy.mark_writing();
    writing_copy.compute_hash();
    write_file(path, writing_copy.to_json(true));

    // 4. 读取应失败（stale cache 检测）
    ModelManifest m3;
    assert(!read_manifest(path, m3));
    assert(!read_and_verify_manifest(path, m3));

    // 5. 重新正常写入，恢复
    assert(write_manifest_atomic(path, m));
    ModelManifest m4;
    assert(read_and_verify_manifest(path, m4));
    assert(m4.is_freshly_committed());
}

// =============================================================================
// 主函数
// =============================================================================

int main() {
    std::cout << "=== test_model_manifest (v3.7.1 + v3.7.2) ===\n";

    RUN_TEST(test_json_roundtrip_basic);
    RUN_TEST(test_json_roundtrip_multiple_shards);
    RUN_TEST(test_json_special_chars);
    RUN_TEST(test_json_invalid_format);
    RUN_TEST(test_compute_hash_consistent);
    RUN_TEST(test_compute_hash_changes_on_content);
    RUN_TEST(test_compute_hash_invariant_to_manifest_hash_field);
    RUN_TEST(test_verify_hash_ok);
    RUN_TEST(test_verify_hash_empty_allowed);
    RUN_TEST(test_verify_hash_tampered);
    RUN_TEST(test_verify_shards_all_ok);
    RUN_TEST(test_verify_shards_missing);
    RUN_TEST(test_verify_shards_hash_mismatch);
    RUN_TEST(test_verify_shards_size_mismatch);
    RUN_TEST(test_verify_shards_empty_sha256_skipped);
    RUN_TEST(test_verify_shards_size_zero_skipped);
    RUN_TEST(test_write_read_manifest);
    RUN_TEST(test_read_and_verify_manifest);
    RUN_TEST(test_read_manifest_nonexistent);
    RUN_TEST(test_read_manifest_tampered_hash);
    RUN_TEST(test_build_manifest_basic);
    RUN_TEST(test_build_manifest_ignores_non_shard_files);
    RUN_TEST(test_build_manifest_empty_dir);
    RUN_TEST(test_build_manifest_nonexistent_dir);
    RUN_TEST(test_build_manifest_version_field);
    RUN_TEST(test_shard_filename);
    RUN_TEST(test_parse_shard_filename);
    RUN_TEST(test_parse_shard_filename_invalid);
    RUN_TEST(test_find_shard);
    RUN_TEST(test_total_size);
    RUN_TEST(test_shard_count);
    RUN_TEST(test_e2e_build_write_read_verify);

    // v3.7.2 原子性测试
    std::cout << "\n-- v3.7.2 原子性（schema_version + atomic_committed）\n";
    RUN_TEST(test_v372_schema_version_default);
    RUN_TEST(test_v372_atomic_committed_default);
    RUN_TEST(test_v372_schema_version_roundtrip);
    RUN_TEST(test_v372_atomic_committed_roundtrip_true);
    RUN_TEST(test_v372_atomic_committed_roundtrip_false);
    RUN_TEST(test_v372_compute_hash_includes_schema_version);
    RUN_TEST(test_v372_compute_hash_includes_atomic_committed);
    RUN_TEST(test_v372_is_freshly_committed_default);
    RUN_TEST(test_v372_is_freshly_committed_false_when_writing);
    RUN_TEST(test_v372_is_freshly_committed_after_mark_committed);
    RUN_TEST(test_v372_is_freshly_committed_invalid_schema);
    RUN_TEST(test_v372_mark_writing_mark_committed);
    RUN_TEST(test_v372_write_manifest_atomic_sets_committed);
    RUN_TEST(test_v372_read_manifest_rejects_uncommitted);
    RUN_TEST(test_v372_read_and_verify_manifest_rejects_uncommitted);
    RUN_TEST(test_v372_backward_compat_old_manifest);
    RUN_TEST(test_v372_from_json_rejects_wrong_type_schema_version);
    RUN_TEST(test_v372_from_json_rejects_wrong_type_atomic_committed_string);
    RUN_TEST(test_v372_from_json_rejects_wrong_type_atomic_committed_number);
    RUN_TEST(test_v372_from_json_rejects_bool_for_wrong_field);
    RUN_TEST(test_v372_from_json_rejects_invalid_bool_literal);
    RUN_TEST(test_v372_e2e_stale_cache_recovery);

    std::cout << "\n=== " << test_passed << "/" << test_count << " tests passed ===\n";
    return (test_passed == test_count) ? 0 : 1;
}
