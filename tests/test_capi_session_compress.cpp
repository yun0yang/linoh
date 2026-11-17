// test_capi_session_compress.cpp — V3.5 P5-B C-API SessionId + 压缩单元测试
//
// 测试覆盖：
//   SessionId C-API（6 用例）：
//     1. generate 唯一性（1000 次无碰撞）+ 非 NULL
//     2. from_bytes / to_bytes 往返
//     3. to_string UUID 格式校验（8-4-4-4-12，36 字符）
//     4. is_null 零值判定
//     5. equal 相等判定
//     6. 参数错误处理（NULL / 缓冲不足）
//
//   压缩 C-API（6 用例）：
//     7. zstd 压缩/解压往返（4KB 随机 payload）
//     8. 空 payload no-op（返回 OK + out_len=0）
//     9. None 算法原样拷贝
//    10. Gzip 未实现返回 LINOH_ERR_PARAM
//    11. 缓冲区不足返回 LINOH_ERR_INTERNAL
//    12. recommend_compression 规则校验（Heartbeat/ForwardPP/CrossDomainDigest）

#include "linoh/linoh_c.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_set>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    if ((a) == (b)) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s != %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ========== SessionId C-API 测试 ==========

// 1. generate 唯一性 + 非 NULL
static void test_session_id_generate_unique() {
    std::printf("[test] linoh_session_id_generate uniqueness...\n");

    std::unordered_set<std::string> seen;
    bool any_null = false;
    for (int i = 0; i < 1000; ++i) {
        linoh_session_id_t sid;
        linoh_error_t err = linoh_session_id_generate(&sid);
        CHECK_EQ(err, LINOH_OK);
        if (linoh_session_id_is_null(&sid) == 1) {
            any_null = true;
        }
        // 用字符串作为去重 key
        char buf[37] = {0};
        size_t n = linoh_session_id_to_string(&sid, buf, sizeof(buf));
        CHECK_EQ(n, 37u);
        seen.emplace(buf);
    }
    CHECK(!any_null);
    CHECK_EQ(seen.size(), 1000u);  // 1000 次无碰撞
}

// 2. from_bytes / to_bytes 往返
static void test_session_id_from_to_bytes_roundtrip() {
    std::printf("[test] linoh_session_id_from_bytes / to_bytes roundtrip...\n");

    linoh_session_id_t sid1;
    CHECK_EQ(linoh_session_id_generate(&sid1), LINOH_OK);

    uint8_t bytes[16] = {0};
    size_t n = linoh_session_id_to_bytes(&sid1, bytes, sizeof(bytes));
    CHECK_EQ(n, 16u);

    linoh_session_id_t sid2;
    CHECK_EQ(linoh_session_id_from_bytes(bytes, 16, &sid2), LINOH_OK);
    CHECK_EQ(linoh_session_id_equal(&sid1, &sid2), 1);

    // from_bytes len < 16 应失败
    CHECK_EQ(linoh_session_id_from_bytes(bytes, 15, &sid2), LINOH_ERR_PARAM);
}

// 3. to_string UUID 格式校验
static void test_session_id_to_string_format() {
    std::printf("[test] linoh_session_id_to_string UUID format...\n");

    linoh_session_id_t sid;
    CHECK_EQ(linoh_session_id_generate(&sid), LINOH_OK);

    char buf[37] = {0};
    size_t n = linoh_session_id_to_string(&sid, buf, sizeof(buf));
    CHECK_EQ(n, 37u);  // 36 字符 + NUL

    // 格式：xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    // 连字符位置：8, 13, 18, 23
    CHECK_EQ(buf[8], '-');
    CHECK_EQ(buf[13], '-');
    CHECK_EQ(buf[18], '-');
    CHECK_EQ(buf[23], '-');
    CHECK_EQ(buf[36], '\0');

    // 长度 = 36
    CHECK_EQ(std::strlen(buf), 36u);

    // 缓冲不足应返回 0
    char small[36] = {0};
    CHECK_EQ(linoh_session_id_to_string(&sid, small, sizeof(small)), 0u);
}

// 4. is_null 零值判定
static void test_session_id_is_null() {
    std::printf("[test] linoh_session_id_is_null...\n");

    linoh_session_id_t zero;
    std::memset(&zero, 0, sizeof(zero));
    CHECK_EQ(linoh_session_id_is_null(&zero), 1);

    linoh_session_id_t sid;
    CHECK_EQ(linoh_session_id_generate(&sid), LINOH_OK);
    CHECK_EQ(linoh_session_id_is_null(&sid), 0);

    // NULL 参数返回 -1
    CHECK_EQ(linoh_session_id_is_null(nullptr), -1);
}

// 5. equal 相等判定
static void test_session_id_equal() {
    std::printf("[test] linoh_session_id_equal...\n");

    linoh_session_id_t sid1, sid2, sid3;
    CHECK_EQ(linoh_session_id_generate(&sid1), LINOH_OK);
    CHECK_EQ(linoh_session_id_generate(&sid2), LINOH_OK);

    // sid3 = sid1（拷贝）
    std::memcpy(&sid3, &sid1, sizeof(sid3));

    CHECK_EQ(linoh_session_id_equal(&sid1, &sid3), 1);   // 相等
    CHECK_EQ(linoh_session_id_equal(&sid1, &sid2), 0);   // 不等（极小概率相等）
    CHECK_EQ(linoh_session_id_equal(nullptr, &sid2), -1);
    CHECK_EQ(linoh_session_id_equal(&sid1, nullptr), -1);
}

// 6. 参数错误处理
static void test_session_id_param_errors() {
    std::printf("[test] linoh_session_id param errors...\n");

    // generate NULL
    CHECK_EQ(linoh_session_id_generate(nullptr), LINOH_ERR_PARAM);

    // from_bytes NULL / len < 16
    linoh_session_id_t sid;
    uint8_t bytes[16] = {0};
    CHECK_EQ(linoh_session_id_from_bytes(nullptr, 16, &sid), LINOH_ERR_PARAM);
    CHECK_EQ(linoh_session_id_from_bytes(bytes, 16, nullptr), LINOH_ERR_PARAM);
    CHECK_EQ(linoh_session_id_from_bytes(bytes, 15, &sid), LINOH_ERR_PARAM);

    // to_bytes NULL / 缓冲不足
    CHECK_EQ(linoh_session_id_to_bytes(&sid, nullptr, 16), 0u);
    CHECK_EQ(linoh_session_id_to_bytes(nullptr, bytes, 16), 0u);
    CHECK_EQ(linoh_session_id_to_bytes(&sid, bytes, 15), 0u);
}

// ========== 压缩 C-API 测试 ==========

// 7. zstd 压缩/解压往返
static void test_compress_zstd_roundtrip() {
    std::printf("[test] linoh_compress_payload zstd roundtrip...\n");

    // 4KB 随机 payload（含重复模式以利于压缩）
    std::vector<uint8_t> payload(4096);
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<uint8_t>((i * 7 + 3) & 0xFF);
    }

    // 压缩（缓冲区预留足够空间）
    std::vector<uint8_t> compressed(payload.size() + 256);
    size_t compressed_len = 0;
    linoh_error_t err = linoh_compress_payload(
        payload.data(), payload.size(),
        LINOH_COMPRESS_ZSTD, 0,  // level 0 = 默认 3
        compressed.data(), compressed.size(),
        &compressed_len);
    CHECK_EQ(err, LINOH_OK);
    CHECK(compressed_len > 0);
    CHECK(compressed_len <= payload.size() + 256);

    // 解压
    std::vector<uint8_t> decompressed(payload.size() + 256);
    size_t decompressed_len = 0;
    err = linoh_decompress_payload(
        compressed.data(), compressed_len,
        LINOH_COMPRESS_ZSTD, payload.size(),  // expected_size 已知
        decompressed.data(), decompressed.size(),
        &decompressed_len);
    CHECK_EQ(err, LINOH_OK);
    CHECK_EQ(decompressed_len, payload.size());

    // 内容一致
    CHECK(std::memcmp(decompressed.data(), payload.data(), payload.size()) == 0);
}

// 8. 空 payload no-op
static void test_compress_empty_payload() {
    std::printf("[test] linoh_compress_payload empty payload no-op...\n");

    uint8_t buf[16] = {0};
    size_t out_len = 999;  // 初始非零，验证被改写
    linoh_error_t err = linoh_compress_payload(
        nullptr, 0, LINOH_COMPRESS_ZSTD, 0,
        buf, sizeof(buf), &out_len);
    CHECK_EQ(err, LINOH_OK);
    CHECK_EQ(out_len, 0u);
}

// 9. None 算法原样拷贝
static void test_compress_none_passthrough() {
    std::printf("[test] linoh_compress_payload None passthrough...\n");

    std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03};
    std::vector<uint8_t> out(payload.size() + 16);
    size_t out_len = 0;
    linoh_error_t err = linoh_compress_payload(
        payload.data(), payload.size(),
        LINOH_COMPRESS_NONE, 0,
        out.data(), out.size(), &out_len);
    CHECK_EQ(err, LINOH_OK);
    CHECK_EQ(out_len, payload.size());
    CHECK(std::memcmp(out.data(), payload.data(), payload.size()) == 0);

    // None 解压也应原样
    std::vector<uint8_t> decompressed(payload.size() + 16);
    size_t de_len = 0;
    err = linoh_decompress_payload(
        out.data(), out_len,
        LINOH_COMPRESS_NONE, 0,
        decompressed.data(), decompressed.size(), &de_len);
    CHECK_EQ(err, LINOH_OK);
    CHECK_EQ(de_len, payload.size());
    CHECK(std::memcmp(decompressed.data(), payload.data(), payload.size()) == 0);
}

// 10. Gzip 未实现返回 LINOH_ERR_PARAM
static void test_compress_gzip_unimplemented() {
    std::printf("[test] linoh_compress_payload Gzip unimplemented...\n");

    std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> out(64);
    size_t out_len = 0;

    linoh_error_t err = linoh_compress_payload(
        payload.data(), payload.size(),
        LINOH_COMPRESS_GZIP, 6,
        out.data(), out.size(), &out_len);
    CHECK_EQ(err, LINOH_ERR_PARAM);

    err = linoh_decompress_payload(
        payload.data(), payload.size(),
        LINOH_COMPRESS_GZIP, 0,
        out.data(), out.size(), &out_len);
    CHECK_EQ(err, LINOH_ERR_PARAM);
}

// 11. 缓冲区不足返回 LINOH_ERR_INTERNAL
static void test_compress_buffer_too_small() {
    std::printf("[test] linoh_compress_payload buffer too small...\n");

    // 1KB payload，压缩缓冲区只有 8 字节（不足）
    std::vector<uint8_t> payload(1024);
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<uint8_t>(i & 0xFF);
    }
    std::vector<uint8_t> out(8);
    size_t out_len = 0;

    linoh_error_t err = linoh_compress_payload(
        payload.data(), payload.size(),
        LINOH_COMPRESS_ZSTD, 0,
        out.data(), out.size(), &out_len);
    CHECK_EQ(err, LINOH_ERR_INTERNAL);

    // 解压缓冲区不足也应失败
    std::vector<uint8_t> compressed(payload.size() + 256);
    size_t compressed_len = 0;
    CHECK_EQ(linoh_compress_payload(
        payload.data(), payload.size(), LINOH_COMPRESS_ZSTD, 0,
        compressed.data(), compressed.size(), &compressed_len), LINOH_OK);

    std::vector<uint8_t> small_out(8);
    size_t de_len = 0;
    err = linoh_decompress_payload(
        compressed.data(), compressed_len,
        LINOH_COMPRESS_ZSTD, payload.size(),
        small_out.data(), small_out.size(), &de_len);
    CHECK_EQ(err, LINOH_ERR_INTERNAL);
}

// 12. recommend_compression 规则校验
static void test_recommend_compression_rules() {
    std::printf("[test] linoh_recommend_compression rules...\n");

    // MethodId 值：Heartbeat=0x0004, ForwardPP=0x0010, ResultPP=0x0011,
    //              CrossDomainDigest=0x0050
    int algo = -1;

    // Heartbeat 始终 None（无论大小）
    CHECK_EQ(linoh_recommend_compression(100, 0x0004, &algo), LINOH_OK);
    CHECK_EQ(algo, LINOH_COMPRESS_NONE);
    CHECK_EQ(linoh_recommend_compression(100 * 1024, 0x0004, &algo), LINOH_OK);
    CHECK_EQ(algo, LINOH_COMPRESS_NONE);

    // ForwardPP：< 1KB None，>= 1KB Zstd
    CHECK_EQ(linoh_recommend_compression(512, 0x0010, &algo), LINOH_OK);
    CHECK_EQ(algo, LINOH_COMPRESS_NONE);
    CHECK_EQ(linoh_recommend_compression(1024, 0x0010, &algo), LINOH_OK);
    CHECK_EQ(algo, LINOH_COMPRESS_ZSTD);
    CHECK_EQ(linoh_recommend_compression(64 * 1024, 0x0010, &algo), LINOH_OK);
    CHECK_EQ(algo, LINOH_COMPRESS_ZSTD);

    // ResultPP：< 1KB None，>= 1KB Zstd
    CHECK_EQ(linoh_recommend_compression(512, 0x0011, &algo), LINOH_OK);
    CHECK_EQ(algo, LINOH_COMPRESS_NONE);
    CHECK_EQ(linoh_recommend_compression(2048, 0x0011, &algo), LINOH_OK);
    CHECK_EQ(algo, LINOH_COMPRESS_ZSTD);

    // CrossDomainDigest：< 16KB None，>= 16KB Zstd
    CHECK_EQ(linoh_recommend_compression(8 * 1024, 0x0050, &algo), LINOH_OK);
    CHECK_EQ(algo, LINOH_COMPRESS_NONE);
    CHECK_EQ(linoh_recommend_compression(16 * 1024, 0x0050, &algo), LINOH_OK);
    CHECK_EQ(algo, LINOH_COMPRESS_ZSTD);

    // NULL out_algo
    CHECK_EQ(linoh_recommend_compression(1024, 0x0010, nullptr), LINOH_ERR_PARAM);
}

// ========== main ==========

int main() {
    std::printf("=== test_capi_session_compress (V3.5 P5-B) ===\n\n");

    test_session_id_generate_unique();
    test_session_id_from_to_bytes_roundtrip();
    test_session_id_to_string_format();
    test_session_id_is_null();
    test_session_id_equal();
    test_session_id_param_errors();

    test_compress_zstd_roundtrip();
    test_compress_empty_payload();
    test_compress_none_passthrough();
    test_compress_gzip_unimplemented();
    test_compress_buffer_too_small();
    test_recommend_compression_rules();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
