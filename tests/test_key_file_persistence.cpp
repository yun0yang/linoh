// =============================================================================
// test_key_file_persistence.cpp — v4.5.0 endpoint_id 密钥文件持久化单元测试
//
// 覆盖：
//   - linoh::util C++ 接口（save_key_file / load_key_file / load_or_generate_key_file）
//   - linoh C-API（linoh_save_key_file / linoh_load_key_file / linoh_load_or_generate_key_file）
//   - linoh_derive_public_key 公钥派生
//   - v1 42B 容器格式序列化/解析
//   - 旧 32B/64B 格式兼容识别 + 静默迁移
//   - CRC32 完整性校验（损坏检测）
//   - magic 不匹配检测
//   - 原子写（无半截文件残留）
//   - 跨平台文件权限限制
// =============================================================================

#include "linoh/util/key_file.hpp"
#include "linoh/util/atomic_write.hpp"
#include "linoh/util/file_permission.hpp"
#include "linoh/linoh_c.h"

#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#endif

using namespace linoh::util;
using namespace linoh::base;

namespace fs = std::filesystem;

namespace {

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

/// 生成唯一测试目录
fs::path make_test_dir(const char *name) {
    fs::path p = fs::temp_directory_path() / (std::string("linoh_test_kf_") + name);
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

/// 写原始字节到文件（用于构造旧格式测试文件）
void write_raw_file(const std::string &path, const std::vector<uint8_t> &data) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    assert(ofs.is_open());
    ofs.write(reinterpret_cast<const char *>(data.data()),
              static_cast<std::streamsize>(data.size()));
}

/// 读文件全部字节
std::vector<uint8_t> read_raw_file(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary);
    assert(ifs.is_open());
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)),
                                 std::istreambuf_iterator<char>());
}

} // namespace

// =============================================================================
// C++ 接口测试
// =============================================================================

void test_save_load_roundtrip() {
    auto dir = make_test_dir("roundtrip");
    auto path = (dir / "key.bin").string();

    auto sk = SecretKey::generate();
    assert(!sk.is_zero());
    auto pk = sk.public_key();

    assert(save_key_file(path, sk));

    SecretKey loaded_sk;
    assert(load_key_file(path, loaded_sk));

    // sk 字节一致
    auto sk_span = sk.as_span();
    auto loaded_span = loaded_sk.as_span();
    assert(std::memcmp(sk_span.data(), loaded_span.data(), 32) == 0);

    // 文件大小为 42B（v1 格式）
    assert(fs::file_size(path) == LINOH_KEY_FILE_V1_SIZE);

    fs::remove_all(dir);
}

void test_derive_public_key_matches_generate() {
    auto sk = SecretKey::generate();
    auto pk_direct = sk.public_key();

    // C-API 派生
    linoh_secret_key_t c_sk{};
    linoh_public_key_t c_pk{};
    auto sk_span = sk.as_span();
    std::memcpy(c_sk.bytes, sk_span.data(), 32);

    assert(linoh_derive_public_key(&c_sk, &c_pk) == LINOH_OK);

    auto pk_span = pk_direct.as_span();
    assert(std::memcmp(c_pk.bytes, pk_span.data(), 32) == 0);

    // C-API from_bytes
    linoh_public_key_t c_pk2{};
    assert(linoh_public_key_from_bytes(pk_span.data(), 32, &c_pk2) == LINOH_OK);
    assert(std::memcmp(c_pk2.bytes, pk_span.data(), 32) == 0);
}

void test_load_legacy_32b() {
    auto dir = make_test_dir("legacy32");
    auto path = (dir / "key.bin").string();

    // 构造旧 32B 纯 sk 格式
    auto sk = SecretKey::generate();
    auto sk_span = sk.as_span();
    std::vector<uint8_t> legacy(sk_span.data(), sk_span.data() + 32);
    write_raw_file(path, legacy);

    SecretKey loaded_sk;
    assert(load_key_file(path, loaded_sk));

    auto loaded_span = loaded_sk.as_span();
    assert(std::memcmp(sk_span.data(), loaded_span.data(), 32) == 0);

    fs::remove_all(dir);
}

void test_load_legacy_64b() {
    auto dir = make_test_dir("legacy64");
    auto path = (dir / "key.bin").string();

    // 构造旧 64B sk+pk 格式
    auto sk = SecretKey::generate();
    auto pk = sk.public_key();
    auto sk_span = sk.as_span();
    auto pk_span = pk.as_span();
    std::vector<uint8_t> legacy;
    legacy.insert(legacy.end(), sk_span.data(), sk_span.data() + 32);
    legacy.insert(legacy.end(), pk_span.data(), pk_span.data() + 32);
    assert(legacy.size() == 64);
    write_raw_file(path, legacy);

    SecretKey loaded_sk;
    assert(load_key_file(path, loaded_sk));

    // 取前 32B 作为 sk
    auto loaded_span = loaded_sk.as_span();
    assert(std::memcmp(sk_span.data(), loaded_span.data(), 32) == 0);

    fs::remove_all(dir);
}

void test_auto_migrate_legacy_32b() {
    auto dir = make_test_dir("migrate32");
    auto path = (dir / "key.bin").string();

    // 构造旧 32B 格式
    auto sk = SecretKey::generate();
    auto sk_span = sk.as_span();
    std::vector<uint8_t> legacy(sk_span.data(), sk_span.data() + 32);
    write_raw_file(path, legacy);
    assert(fs::file_size(path) == 32);

    // 加载（触发迁移）
    SecretKey loaded_sk;
    assert(load_key_file(path, loaded_sk));

    // 文件应已迁移为 42B
    assert(fs::file_size(path) == LINOH_KEY_FILE_V1_SIZE);

    // 再次加载，应按 v1 格式加载成功
    SecretKey loaded_sk2;
    assert(load_key_file(path, loaded_sk2));
    auto loaded_span = loaded_sk2.as_span();
    assert(std::memcmp(sk_span.data(), loaded_span.data(), 32) == 0);

    fs::remove_all(dir);
}

void test_auto_migrate_legacy_64b() {
    auto dir = make_test_dir("migrate64");
    auto path = (dir / "key.bin").string();

    // 构造旧 64B 格式
    auto sk = SecretKey::generate();
    auto pk = sk.public_key();
    auto sk_span = sk.as_span();
    auto pk_span = pk.as_span();
    std::vector<uint8_t> legacy;
    legacy.insert(legacy.end(), sk_span.data(), sk_span.data() + 32);
    legacy.insert(legacy.end(), pk_span.data(), pk_span.data() + 32);
    write_raw_file(path, legacy);
    assert(fs::file_size(path) == 64);

    // 加载（触发迁移）
    SecretKey loaded_sk;
    assert(load_key_file(path, loaded_sk));

    // 文件应已迁移为 42B
    assert(fs::file_size(path) == LINOH_KEY_FILE_V1_SIZE);

    fs::remove_all(dir);
}

void test_crc_corruption_detection() {
    auto dir = make_test_dir("crc_corrupt");
    auto path = (dir / "key.bin").string();

    // 保存正常文件
    auto sk = SecretKey::generate();
    assert(save_key_file(path, sk));
    assert(fs::file_size(path) == LINOH_KEY_FILE_V1_SIZE);

    // 篡改 sk 字节（偏移 6，sk 区域第一个字节）
    auto bytes = read_raw_file(path);
    bytes[6] ^= 0xFF;  // 翻转字节

    // 同时篡改 CRC 区域会导致 CRC 恰好匹配的概率极低，这里只篡改 sk
    // 但需要重新计算 CRC 否则 CRC 不匹配会被检测到
    // 实际上我们就是要测试 CRC 检测损坏，所以只篡改 sk 不修 CRC
    write_raw_file(path, bytes);

    // 加载应失败（CRC 不匹配）
    SecretKey loaded_sk;
    assert(!load_key_file(path, loaded_sk));

    fs::remove_all(dir);
}

void test_magic_mismatch() {
    auto dir = make_test_dir("magic_mismatch");
    auto path = (dir / "key.bin").string();

    // 构造 42B 文件但 magic 错误
    std::vector<uint8_t> bad(42, 0);
    bad[0] = 'X';  // 错误 magic
    bad[1] = 'X';
    bad[2] = 'X';
    bad[3] = 'X';
    bad[4] = 0x01;  // version
    write_raw_file(path, bad);

    // 加载应失败（magic 不匹配）
    SecretKey loaded_sk;
    assert(!load_key_file(path, loaded_sk));

    fs::remove_all(dir);
}

void test_atomic_write_no_partial() {
    auto dir = make_test_dir("atomic");
    auto path = (dir / "key.bin").string();

    // 保存文件
    auto sk = SecretKey::generate();
    assert(save_key_file(path, sk));

    // 验证无 .tmp 残留文件
    int tmp_count = 0;
    for (auto &entry : fs::directory_iterator(dir)) {
        std::string name = entry.path().filename().string();
        if (name.find(".tmp.") != std::string::npos) {
            ++tmp_count;
        }
    }
    assert(tmp_count == 0);

    // 目标文件完整
    assert(fs::file_size(path) == LINOH_KEY_FILE_V1_SIZE);

    fs::remove_all(dir);
}

void test_file_permission_restricted() {
    auto dir = make_test_dir("perm");
    auto path = (dir / "key.bin").string();

    auto sk = SecretKey::generate();
    assert(save_key_file(path, sk));

    // 验证权限被限制
#ifdef _WIN32
    // Windows: 验证 restrict_file_permission 返回 true
    // 完整的 DACL 验证需要 GetNamedSecurityInfo，此处简化为函数返回值检查
    assert(restrict_file_permission(path));
#else
    // Linux: stat 检查权限位
    struct stat st;
    assert(stat(path.c_str(), &st) == 0);
    assert((st.st_mode & 0777) == 0600);
#endif

    fs::remove_all(dir);
}

void test_load_or_generate_creates_new() {
    auto dir = make_test_dir("create_new");
    auto path = (dir / "new_key.bin").string();

    // 文件不存在 → 生成新密钥
    assert(!fs::exists(path));
    auto result = load_or_generate_key_file(path);
    assert(result.ok);
    assert(!result.sk.is_zero());
    assert(!result.pk.is_zero());

    // 文件已创建
    assert(fs::exists(path));
    assert(fs::file_size(path) == LINOH_KEY_FILE_V1_SIZE);

    // 公钥与私钥派生一致
    auto pk = result.sk.public_key();
    assert(std::memcmp(result.pk.as_span().data(), pk.as_span().data(), 32) == 0);

    fs::remove_all(dir);
}

void test_load_or_generate_loads_existing() {
    auto dir = make_test_dir("load_existing");
    auto path = (dir / "key.bin").string();

    // 先保存一个密钥
    auto sk_orig = SecretKey::generate();
    assert(save_key_file(path, sk_orig));

    // 再次调用 load_or_generate，应加载已有文件而非覆盖
    auto result = load_or_generate_key_file(path);
    assert(result.ok);

    auto orig_span = sk_orig.as_span();
    auto result_span = result.sk.as_span();
    assert(std::memcmp(orig_span.data(), result_span.data(), 32) == 0);

    fs::remove_all(dir);
}

// =============================================================================
// C-API 集成测试
// =============================================================================

void test_c_api_save_load_roundtrip() {
    auto dir = make_test_dir("capi_roundtrip");
    auto path = (dir / "key.bin").string();

    linoh_secret_key_t sk{};
    linoh_public_key_t pk{};
    assert(linoh_generate_keypair(&sk, &pk) == LINOH_OK);

    assert(linoh_save_key_file(path.c_str(), &sk) == LINOH_OK);

    linoh_secret_key_t loaded_sk{};
    assert(linoh_load_key_file(path.c_str(), &loaded_sk) == LINOH_OK);

    assert(std::memcmp(sk.bytes, loaded_sk.bytes, 32) == 0);

    fs::remove_all(dir);
}

void test_c_api_load_or_generate() {
    auto dir = make_test_dir("capi_log");
    auto path = (dir / "key.bin").string();

    // 文件不存在 → 生成
    linoh_secret_key_t sk1{};
    linoh_public_key_t pk1{};
    assert(linoh_load_or_generate_key_file(path.c_str(), &sk1, &pk1) == LINOH_OK);
    assert(fs::exists(path));

    // 文件存在 → 加载（同一密钥）
    linoh_secret_key_t sk2{};
    linoh_public_key_t pk2{};
    assert(linoh_load_or_generate_key_file(path.c_str(), &sk2, &pk2) == LINOH_OK);
    assert(std::memcmp(sk1.bytes, sk2.bytes, 32) == 0);
    assert(std::memcmp(pk1.bytes, pk2.bytes, 32) == 0);

    fs::remove_all(dir);
}

void test_c_api_derive_public_key() {
    linoh_secret_key_t sk{};
    linoh_public_key_t pk_generate{};
    assert(linoh_generate_keypair(&sk, &pk_generate) == LINOH_OK);

    linoh_public_key_t pk_derive{};
    assert(linoh_derive_public_key(&sk, &pk_derive) == LINOH_OK);

    assert(std::memcmp(pk_generate.bytes, pk_derive.bytes, 32) == 0);
}

int main() {
    std::cout << "=== test_key_file_persistence v4.5.0 ===\n";

    std::cout << "-- C++ 接口\n";
    RUN_TEST(test_save_load_roundtrip);
    RUN_TEST(test_derive_public_key_matches_generate);
    RUN_TEST(test_load_legacy_32b);
    RUN_TEST(test_load_legacy_64b);
    RUN_TEST(test_auto_migrate_legacy_32b);
    RUN_TEST(test_auto_migrate_legacy_64b);
    RUN_TEST(test_crc_corruption_detection);
    RUN_TEST(test_magic_mismatch);
    RUN_TEST(test_atomic_write_no_partial);
    RUN_TEST(test_file_permission_restricted);
    RUN_TEST(test_load_or_generate_creates_new);
    RUN_TEST(test_load_or_generate_loads_existing);

    std::cout << "-- C-API 集成\n";
    RUN_TEST(test_c_api_save_load_roundtrip);
    RUN_TEST(test_c_api_load_or_generate);
    RUN_TEST(test_c_api_derive_public_key);

    std::cout << "\n=== " << test_passed << "/" << test_count << " tests passed ===\n";
    return (test_passed == test_count) ? 0 : 1;
}
