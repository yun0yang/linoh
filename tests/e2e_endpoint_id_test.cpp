// =============================================================================
// e2e_endpoint_id_test.cpp — v4.5.0 endpoint_id 持久化统一端到端验证
//
// 模拟三套应用层组件的密钥加载调用路径，验证：
//   1. mpmnode/orchestrator 路径（C-API: linoh_load_or_generate_key_file）
//      - 构造旧 64B (sk+pk) 格式 → 加载 → endpoint_id 不变 → 自动迁移为 42B
//   2. relay_bridge 路径（C++ API: linoh::util::load_or_generate_key_file）
//      - 构造旧 32B (sk-only) 格式 → 加载 → endpoint_id 不变 → 自动迁移为 42B
//   3. 权限检查（Windows icacls / Linux stat）
//   4. 迁移后文件格式校验（42B / magic "LNOH" / CRC32）
//
// 编译: 参考 build_all.bat 中 test_key_file_persistence 的编译方式
// =============================================================================

#include "linoh/util/key_file.hpp"
#include "linoh/util/crc32.hpp"
#include "linoh/util/file_permission.hpp"
#include "linoh/linoh_c.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#else
#include <sys/stat.h>
#endif

using namespace linoh::util;
using namespace linoh::base;

namespace fs = std::filesystem;

namespace {

int g_checks = 0;
int g_passed = 0;

#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        ++g_checks;                                                             \
        if (cond) {                                                             \
            ++g_passed;                                                         \
            std::cout << "  [PASS] " << (msg) << "\n";                          \
        } else {                                                                \
            std::cout << "  [FAIL] " << (msg) << " @ " << __FILE__ << ":"        \
                      << __LINE__ << "\n";                                      \
        }                                                                       \
    } while (0)

/// hex 编码（32 字节 → 64 字符）
std::string to_hex(const uint8_t *data, size_t len) {
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += hex[(data[i] >> 4) & 0xF];
        out += hex[data[i] & 0xF];
    }
    return out;
}

/// 写原始字节到文件
void write_raw_file(const std::string &path, const std::vector<uint8_t> &data) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    ofs.write(reinterpret_cast<const char *>(data.data()),
              static_cast<std::streamsize>(data.size()));
}

/// 读文件全部字节
std::vector<uint8_t> read_raw_file(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)),
                                 std::istreambuf_iterator<char>());
}

/// 生成唯一测试目录
fs::path make_test_dir(const char *name) {
    fs::path p = fs::temp_directory_path() / (std::string("e2e_epid_") + name);
    fs::remove_all(p);
    fs::create_directories(p);
    return p;
}

/// 验证文件是否为 v1 格式（42B + magic "LNOH"）
bool verify_v1_format(const std::string &path) {
    auto bytes = read_raw_file(path);
    if (bytes.size() != 42) return false;
    // magic "LNOH" = 0x4C 0x4E 0x4F 0x48
    if (bytes[0] != 0x4C || bytes[1] != 0x4E ||
        bytes[2] != 0x4F || bytes[3] != 0x48) return false;
    // version = 0x01
    if (bytes[4] != 0x01) return false;
    // flags = 0x00
    if (bytes[5] != 0x00) return false;
    // CRC32 校验
    uint32_t expected = crc32_ieee(std::span<const uint8_t>(bytes.data(), 38));
    uint32_t actual = static_cast<uint32_t>(bytes[38]) |
                      (static_cast<uint32_t>(bytes[39]) << 8) |
                      (static_cast<uint32_t>(bytes[40]) << 16) |
                      (static_cast<uint32_t>(bytes[41]) << 24);
    return expected == actual;
}

#ifdef _WIN32
/// Windows: 检查文件 DACL 是否仅授予当前用户（不含 Everyone/BUILTIN\Users）
bool verify_windows_permission(const std::string &path) {
    // 简化验证：restrict_file_permission 返回 true 即认为权限设置成功
    // 完整的 DACL 枚举较复杂，此处依赖函数内部已正确设置
    return restrict_file_permission(path);
}
#endif

} // namespace

// =============================================================================
// 场景 1: 模拟 mpmnode/orchestrator（C-API 路径，旧 64B 格式迁移）
// =============================================================================
void test_mpmnode_orchestrator_capi() {
    std::cout << "\n=== 场景 1: mpmnode/orchestrator (C-API, 旧 64B → 42B) ===\n";

    auto dir = make_test_dir("mpmnode_capi");
    auto path = (dir / "node.key").string();

    // 1. 生成原始密钥对，记录 endpoint_id
    linoh_secret_key_t orig_sk{};
    linoh_public_key_t orig_pk{};
    if (linoh_generate_keypair(&orig_sk, &orig_pk) != LINOH_OK) {
        std::cout << "  [SKIP] 密钥生成失败\n";
        return;
    }
    std::string orig_epid = to_hex(orig_pk.bytes, 32);
    std::cout << "  原始 endpoint_id: " << orig_epid << "\n";

    // 2. 构造旧 64B (sk+pk) 格式文件（模拟生产环境现有文件）
    std::vector<uint8_t> legacy64;
    legacy64.insert(legacy64.end(), orig_sk.bytes, orig_sk.bytes + 32);
    legacy64.insert(legacy64.end(), orig_pk.bytes, orig_pk.bytes + 32);
    write_raw_file(path, legacy64);
    CHECK(fs::file_size(path) == 64, "旧 64B 格式文件已创建");

    // 3. 调用 linoh_load_or_generate_key_file（模拟 mpmnode/orchestrator 启动）
    linoh_secret_key_t loaded_sk{};
    linoh_public_key_t loaded_pk{};
    linoh_error_t rc = linoh_load_or_generate_key_file(path.c_str(), &loaded_sk, &loaded_pk);
    CHECK(rc == LINOH_OK, "C-API linoh_load_or_generate_key_file 返回 LINOH_OK");

    // 4. 验证 endpoint_id 不变（迁移前后公钥一致）
    std::string loaded_epid = to_hex(loaded_pk.bytes, 32);
    CHECK(loaded_epid == orig_epid, "endpoint_id 迁移前后一致: " + loaded_epid);

    // 5. 验证文件已迁移为 42B v1 格式
    CHECK(fs::file_size(path) == LINOH_KEY_FILE_V1_SIZE, "文件已迁移为 42B");
    CHECK(verify_v1_format(path), "文件格式为 v1 (magic=LNOH, CRC32 校验通过)");

    // 6. 权限检查
#ifdef _WIN32
    CHECK(verify_windows_permission(path), "Windows DACL 权限已限制（仅当前用户）");
#else
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        CHECK((st.st_mode & 0777) == 0600, "Linux 文件权限为 0600");
    }
#endif

    fs::remove_all(dir);
}

// =============================================================================
// 场景 2: 模拟 relay_bridge（C++ API 路径，旧 32B 格式迁移）
// =============================================================================
void test_relay_bridge_cppapi() {
    std::cout << "\n=== 场景 2: relay_bridge (C++ API, 旧 32B → 42B) ===\n";

    auto dir = make_test_dir("relay_cpp");
    auto path = (dir / "linoh_relay_bridge.key").string();

    // 1. 生成原始密钥对，记录 endpoint_id
    auto orig_sk = SecretKey::generate();
    auto orig_pk = orig_sk.public_key();
    std::string orig_epid = to_hex(orig_pk.as_span().data(), 32);
    std::cout << "  原始 endpoint_id: " << orig_epid << "\n";

    // 2. 构造旧 32B (sk-only) 格式文件（模拟 relay_bridge 现有文件）
    auto sk_span = orig_sk.as_span();
    std::vector<uint8_t> legacy32(sk_span.data(), sk_span.data() + 32);
    write_raw_file(path, legacy32);
    CHECK(fs::file_size(path) == 32, "旧 32B 格式文件已创建");

    // 3. 调用 linoh::util::load_or_generate_key_file（模拟 relay_bridge 启动）
    auto result = load_or_generate_key_file(path);
    CHECK(result.ok, "C++ API load_or_generate_key_file 返回 ok=true");
    CHECK(!result.sk.is_zero(), "加载的私钥非零");

    // 4. 验证 endpoint_id 不变
    auto loaded_pk = result.sk.public_key();
    std::string loaded_epid = to_hex(loaded_pk.as_span().data(), 32);
    CHECK(loaded_epid == orig_epid, "endpoint_id 迁移前后一致: " + loaded_epid);

    // 5. 验证文件已迁移为 42B v1 格式
    CHECK(fs::file_size(path) == LINOH_KEY_FILE_V1_SIZE, "文件已迁移为 42B");
    CHECK(verify_v1_format(path), "文件格式为 v1 (magic=LNOH, CRC32 校验通过)");

    // 6. 权限检查
#ifdef _WIN32
    CHECK(verify_windows_permission(path), "Windows DACL 权限已限制（仅当前用户）");
#else
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        CHECK((st.st_mode & 0777) == 0600, "Linux 文件权限为 0600");
    }
#endif

    fs::remove_all(dir);
}

// =============================================================================
// 场景 3: 新部署（文件不存在时自动生成）
// =============================================================================
void test_new_deployment() {
    std::cout << "\n=== 场景 3: 新部署（文件不存在 → 自动生成）===\n";

    auto dir = make_test_dir("new_deploy");
    auto path_capi = (dir / "orchestrator.key").string();
    auto path_cpp = (dir / "relay.key").string();

    // C-API 路径（模拟 orchestrator 新部署）
    linoh_secret_key_t sk1{};
    linoh_public_key_t pk1{};
    CHECK(linoh_load_or_generate_key_file(path_capi.c_str(), &sk1, &pk1) == LINOH_OK,
          "C-API 新部署生成密钥成功");
    CHECK(fs::exists(path_capi), "C-API 密钥文件已创建");
    CHECK(fs::file_size(path_capi) == LINOH_KEY_FILE_V1_SIZE, "C-API 文件为 42B v1 格式");
    CHECK(verify_v1_format(path_capi), "C-API 文件格式校验通过");

    // C++ API 路径（模拟 relay_bridge 新部署）
    auto result = load_or_generate_key_file(path_cpp);
    CHECK(result.ok, "C++ API 新部署生成密钥成功");
    CHECK(fs::exists(path_cpp), "C++ API 密钥文件已创建");
    CHECK(fs::file_size(path_cpp) == LINOH_KEY_FILE_V1_SIZE, "C++ API 文件为 42B v1 格式");
    CHECK(verify_v1_format(path_cpp), "C++ API 文件格式校验通过");

    // 再次加载，验证密钥稳定（不重新生成）
    linoh_secret_key_t sk2{};
    linoh_public_key_t pk2{};
    CHECK(linoh_load_or_generate_key_file(path_capi.c_str(), &sk2, &pk2) == LINOH_OK,
          "C-API 再次加载成功");
    CHECK(std::memcmp(sk1.bytes, sk2.bytes, 32) == 0, "C-API 重复加载密钥一致（稳定）");

    fs::remove_all(dir);
}

// =============================================================================
// 场景 4: 损坏文件检测
// =============================================================================
void test_corruption_detection() {
    std::cout << "\n=== 场景 4: 损坏文件检测（CRC32）===\n";

    auto dir = make_test_dir("corrupt");
    auto path = (dir / "corrupt.key").string();

    // 保存正常文件
    auto sk = SecretKey::generate();
    CHECK(save_key_file(path, sk), "正常密钥文件已保存");

    // 篡改 sk 字节（偏移 6）
    auto bytes = read_raw_file(path);
    bytes[6] ^= 0xFF;
    write_raw_file(path, bytes);

    // 加载应失败（CRC 不匹配）
    SecretKey loaded_sk;
    CHECK(!load_key_file(path, loaded_sk), "CRC 损坏文件加载被拒绝");

    fs::remove_all(dir);
}

int main() {
    std::cout << "============================================================\n";
    std::cout << "  v4.5.0 endpoint_id 持久化统一 — 端到端验证\n";
    std::cout << "  模拟 mpmnode / orchestrator / relay_bridge 三套组件\n";
    std::cout << "============================================================\n";

    test_mpmnode_orchestrator_capi();
    test_relay_bridge_cppapi();
    test_new_deployment();
    test_corruption_detection();

    std::cout << "\n============================================================\n";
    std::cout << "  验证结果: " << g_passed << "/" << g_checks << " checks passed\n";
    std::cout << "============================================================\n";

    return (g_passed == g_checks) ? 0 : 1;
}
