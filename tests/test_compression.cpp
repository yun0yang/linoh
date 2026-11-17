// test_compression.cpp — 压缩模块单元测试（V3.4）
//
// 测试覆盖（对应 docs/LINOH_EVENTBUS_BINARY_FRAME_IMPL_PLAN.md §3.6）：
//   1. test_zstd_roundtrip         zstd 压缩→解压往返一致
//   2. test_zstd_levels            不同压缩级别往返
//   3. test_empty_input            空输入处理
//   4. test_large_payload          大 payload 压缩比 + 往返
//   5. test_recommend_compression  自动推荐算法表
//   6. test_gzip_not_implemented   gzip 未实现返回空
//   7. test_none_passthrough       None 原样返回

#include "linoh/protocol/compression.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace linoh::protocol;

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

// 辅助：构造可压缩数据（重复模式，zstd 压缩比高）
static std::vector<std::uint8_t> make_compressible(std::size_t n, std::uint8_t pattern) {
    return std::vector<std::uint8_t>(n, pattern);
}

// 辅助：构造随机数据（不可压缩，zstd 压缩后可能更大）
static std::vector<std::uint8_t> make_random(std::size_t n) {
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = static_cast<std::uint8_t>(i * 31 + 17);
    }
    return v;
}

// ============================================================================
// 1. zstd 压缩→解压往返
// ============================================================================

static void test_zstd_roundtrip() {
    std::printf("[test] zstd compress/decompress round-trip...\n");
    auto data = make_compressible(4096, 0xAA);
    std::span<const std::uint8_t> in(data.data(), data.size());

    auto compressed = compress_payload(in, CompressionAlgo::Zstd);
    CHECK(!compressed.empty());
    CHECK(compressed.size() < data.size());  // 可压缩数据应缩小

    // 解压（自动解析大小）
    auto decompressed = decompress_payload(
        std::span<const std::uint8_t>(compressed.data(), compressed.size()),
        CompressionAlgo::Zstd);
    CHECK(!decompressed.empty());
    CHECK_EQ(decompressed.size(), data.size());
    CHECK(std::memcmp(decompressed.data(), data.data(), data.size()) == 0);

    // 解压（提供预期大小）
    auto decompressed2 = decompress_payload(
        std::span<const std::uint8_t>(compressed.data(), compressed.size()),
        CompressionAlgo::Zstd, data.size());
    CHECK(!decompressed2.empty());
    CHECK_EQ(decompressed2.size(), data.size());
    CHECK(std::memcmp(decompressed2.data(), data.data(), data.size()) == 0);
}

// ============================================================================
// 2. 不同压缩级别往返
// ============================================================================

static void test_zstd_levels() {
    std::printf("[test] zstd different compression levels...\n");
    auto data = make_compressible(8192, 0x55);
    std::span<const std::uint8_t> in(data.data(), data.size());

    for (int level : {1, 3, 9, 19}) {
        auto compressed = compress_payload(in, CompressionAlgo::Zstd, level);
        CHECK(!compressed.empty());
        auto decompressed = decompress_payload(
            std::span<const std::uint8_t>(compressed.data(), compressed.size()),
            CompressionAlgo::Zstd);
        CHECK_EQ(decompressed.size(), data.size());
        CHECK(std::memcmp(decompressed.data(), data.data(), data.size()) == 0);
    }

    // level=0 使用默认级别（3）
    auto c0 = compress_payload(in, CompressionAlgo::Zstd, 0);
    CHECK(!c0.empty());
    // level>22 钳制为 22
    auto c99 = compress_payload(in, CompressionAlgo::Zstd, 99);
    CHECK(!c99.empty());
}

// ============================================================================
// 3. 空输入处理
// ============================================================================

static void test_empty_input() {
    std::printf("[test] empty input handling...\n");
    std::span<const std::uint8_t> empty;  // 默认构造空 span（MSVC 不接受 nullptr 构造）

    // zstd 压缩空输入 → 返回空
    auto c = compress_payload(empty, CompressionAlgo::Zstd);
    CHECK(c.empty());

    // zstd 解压空输入 → 返回空
    auto d = decompress_payload(empty, CompressionAlgo::Zstd);
    CHECK(d.empty());

    // None 压缩空输入 → 返回空
    auto n = compress_payload(empty, CompressionAlgo::None);
    CHECK(n.empty());

    // None 解压空输入 → 返回空
    auto nd = decompress_payload(empty, CompressionAlgo::None);
    CHECK(nd.empty());
}

// ============================================================================
// 4. 大 payload 压缩比 + 往返
// ============================================================================

static void test_large_payload() {
    std::printf("[test] large payload (1MB) compression ratio + round-trip...\n");
    constexpr std::size_t kSize = 1024 * 1024;  // 1 MB
    auto data = make_compressible(kSize, 0x00);  // 全 0，高度可压缩
    std::span<const std::uint8_t> in(data.data(), data.size());

    auto compressed = compress_payload(in, CompressionAlgo::Zstd);
    CHECK(!compressed.empty());
    CHECK(compressed.size() < kSize / 100);  // 全 0 数据压缩比应极高（< 1%）

    auto decompressed = decompress_payload(
        std::span<const std::uint8_t>(compressed.data(), compressed.size()),
        CompressionAlgo::Zstd);
    CHECK_EQ(decompressed.size(), kSize);
    CHECK(std::memcmp(decompressed.data(), data.data(), kSize) == 0);

    // 随机数据压缩比低（可能更大）
    auto rand_data = make_random(kSize);
    std::span<const std::uint8_t> rand_in(rand_data.data(), rand_data.size());
    auto rand_c = compress_payload(rand_in, CompressionAlgo::Zstd);
    CHECK(!rand_c.empty());
    auto rand_d = decompress_payload(
        std::span<const std::uint8_t>(rand_c.data(), rand_c.size()),
        CompressionAlgo::Zstd);
    CHECK_EQ(rand_d.size(), kSize);
    CHECK(std::memcmp(rand_d.data(), rand_data.data(), kSize) == 0);
}

// ============================================================================
// 5. recommend_compression 自动推荐算法表
// ============================================================================

static void test_recommend_compression() {
    std::printf("[test] recommend_compression algorithm table...\n");
    // Heartbeat：任何大小都不压缩
    CHECK_EQ(recommend_compression(0, MethodId::Heartbeat), CompressionAlgo::None);
    CHECK_EQ(recommend_compression(512, MethodId::Heartbeat), CompressionAlgo::None);
    CHECK_EQ(recommend_compression(100 * 1024 * 1024, MethodId::Heartbeat), CompressionAlgo::None);

    // ForwardPP：< 1KB 不压缩，≥ 1KB 压缩
    CHECK_EQ(recommend_compression(512, MethodId::ForwardPP), CompressionAlgo::None);
    CHECK_EQ(recommend_compression(1023, MethodId::ForwardPP), CompressionAlgo::None);
    CHECK_EQ(recommend_compression(1024, MethodId::ForwardPP), CompressionAlgo::Zstd);
    CHECK_EQ(recommend_compression(16 * 1024, MethodId::ForwardPP), CompressionAlgo::Zstd);
    CHECK_EQ(recommend_compression(1024 * 1024, MethodId::ForwardPP), CompressionAlgo::Zstd);

    // ResultPP：同 ForwardPP
    CHECK_EQ(recommend_compression(512, MethodId::ResultPP), CompressionAlgo::None);
    CHECK_EQ(recommend_compression(2048, MethodId::ResultPP), CompressionAlgo::Zstd);

    // CrossDomainDigest：结构化控制面，O1 v2 规则 300B+ 即压缩
    //（旧规则 16KB 阈值已按编码层优化方案判据 4 升级：1–16KB 是字典压缩主战场）
    CHECK_EQ(recommend_compression(200, MethodId::CrossDomainDigest), CompressionAlgo::None);
    CHECK_EQ(recommend_compression(1024, MethodId::CrossDomainDigest), CompressionAlgo::Zstd);
    CHECK_EQ(recommend_compression(15 * 1024, MethodId::CrossDomainDigest), CompressionAlgo::Zstd);
    CHECK_EQ(recommend_compression(16 * 1024, MethodId::CrossDomainDigest), CompressionAlgo::Zstd);
    CHECK_EQ(recommend_compression(100 * 1024, MethodId::CrossDomainDigest), CompressionAlgo::Zstd);

    // LoadModel：同属结构化控制面方法，300B+ 压缩
    CHECK_EQ(recommend_compression(200, MethodId::LoadModel), CompressionAlgo::None);
    CHECK_EQ(recommend_compression(1024, MethodId::LoadModel), CompressionAlgo::Zstd);
    CHECK_EQ(recommend_compression(16 * 1024, MethodId::LoadModel), CompressionAlgo::Zstd);

    // 0 字节 → None（所有方法）
    CHECK_EQ(recommend_compression(0, MethodId::ForwardPP), CompressionAlgo::None);
    CHECK_EQ(recommend_compression(0, MethodId::CrossDomainDigest), CompressionAlgo::None);
}

// ============================================================================
// 6. Gzip 未实现返回空
// ============================================================================

static void test_gzip_not_implemented() {
    std::printf("[test] gzip not implemented returns empty...\n");
    auto data = make_compressible(1024, 0xCC);
    std::span<const std::uint8_t> in(data.data(), data.size());

    auto c = compress_payload(in, CompressionAlgo::Gzip);
    CHECK(c.empty());

    auto d = decompress_payload(in, CompressionAlgo::Gzip);
    CHECK(d.empty());
}

// ============================================================================
// 7. None 原样返回（无压缩）
// ============================================================================

static void test_none_passthrough() {
    std::printf("[test] None passthrough (no compression)...\n");
    auto data = make_random(2048);
    std::span<const std::uint8_t> in(data.data(), data.size());

    auto c = compress_payload(in, CompressionAlgo::None);
    CHECK_EQ(c.size(), data.size());
    CHECK(std::memcmp(c.data(), data.data(), data.size()) == 0);

    auto d = decompress_payload(
        std::span<const std::uint8_t>(c.data(), c.size()),
        CompressionAlgo::None);
    CHECK_EQ(d.size(), data.size());
    CHECK(std::memcmp(d.data(), data.data(), data.size()) == 0);

    // None 解压非空数据
    CHECK_EQ(d.size(), 2048u);
}

// ============================================================================

int main() {
    std::printf("=== test_compression ===\n");

    test_zstd_roundtrip();
    test_zstd_levels();
    test_empty_input();
    test_large_payload();
    test_recommend_compression();
    test_gzip_not_implemented();
    test_none_passthrough();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
