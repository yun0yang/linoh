// test_message_compression.cpp — V3.4 P4 ApplicationMessage + zstd 压缩集成测试
//
// 测试覆盖：
//   1. compress(Zstd) + decompress 往返一致性
//   2. compress 设置 ZstdCompressed flag
//   3. decompress 清除 ZstdCompressed flag
//   4. compress(None) no-op
//   5. compress 空 payload
//   6. compress 大 payload 压缩比 >= 2:1
//   7. compress 无收益（随机数据）不置 flag
//   8. decompress 无 flag no-op
//   9. compress(Gzip) 未实现返回 false
//  10. decompress PayloadCompressed (gzip) 未实现返回 false
//  11. 两种压缩 flag 同时置位 → decompress 返回 false
//  12. compress + session_id 组合：serialize→parse→decompress 完整往返
//  13. compress + serialize → parse → decompress（无 session_id）

#include "linoh/protocol/application_message.hpp"
#include "linoh/protocol/compression.hpp"
#include "linoh/protocol/session_id.hpp"

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

// 生成可压缩 payload（重复模式，zstd 压缩比高）
static std::vector<std::uint8_t> make_compressible_payload(std::size_t size) {
    std::vector<std::uint8_t> p(size);
    for (std::size_t i = 0; i < size; ++i) {
        p[i] = static_cast<std::uint8_t>((i / 64) & 0xFF);  // 每 64 字节一个值
    }
    return p;
}

// 生成不可压缩 payload — 极小 payload（zstd 帧头开销 > 原始数据，压缩后更大）
// zstd 帧头至少 6+ 字节（magic 4B + frame header descriptor 1B + ...），
// 因此 4 字节 payload 压缩后必然 >= 原始，触发 compress 无收益检测
static std::vector<std::uint8_t> make_incompressible_payload() {
    return std::vector<std::uint8_t>{0xDE, 0xAD, 0xBE, 0xEF};
}

// ========== 测试用例 ==========

static void test_compress_decompress_zstd_roundtrip() {
    std::printf("[test] compress(Zstd) + decompress roundtrip...\n");

    auto original = make_compressible_payload(4096);
    auto msg = ApplicationMessage::request(1, MethodId::ForwardPP, original);

    // 压缩
    bool ok = msg.compress(CompressionAlgo::Zstd);
    CHECK(ok);
    CHECK(msg.is_zstd_compressed());
    // 压缩后 payload 应更小
    CHECK(msg.payload.size() < original.size());

    // 解压
    ok = msg.decompress();
    CHECK(ok);
    CHECK(!msg.is_zstd_compressed());
    // 解压后 payload 与原始一致
    CHECK_EQ(msg.payload.size(), original.size());
    CHECK(std::memcmp(msg.payload.data(), original.data(), original.size()) == 0);
}

static void test_compress_sets_flag() {
    std::printf("[test] compress(Zstd) sets ZstdCompressed flag...\n");

    auto payload = make_compressible_payload(2048);
    auto msg = ApplicationMessage::request(1, MethodId::ForwardPP, payload);

    CHECK(!msg.is_zstd_compressed());
    msg.compress(CompressionAlgo::Zstd);
    CHECK(msg.is_zstd_compressed());
    CHECK(has_flag(msg.flags, MessageFlags::ZstdCompressed));
}

static void test_decompress_clears_flag() {
    std::printf("[test] decompress clears ZstdCompressed flag...\n");

    auto payload = make_compressible_payload(2048);
    auto msg = ApplicationMessage::request(1, MethodId::ForwardPP, payload);

    msg.compress(CompressionAlgo::Zstd);
    CHECK(msg.is_zstd_compressed());

    msg.decompress();
    CHECK(!msg.is_zstd_compressed());
    CHECK(!has_flag(msg.flags, MessageFlags::ZstdCompressed));
}

static void test_compress_none_passthrough() {
    std::printf("[test] compress(None) no-op...\n");

    auto payload = make_compressible_payload(1024);
    auto msg = ApplicationMessage::request(1, MethodId::ForwardPP, payload);
    auto original_size = msg.payload.size();

    bool ok = msg.compress(CompressionAlgo::None);
    CHECK(ok);
    CHECK(!msg.is_zstd_compressed());
    CHECK_EQ(msg.payload.size(), original_size);
    // payload 未变
    CHECK(std::memcmp(msg.payload.data(), payload.data(), payload.size()) == 0);
}

static void test_compress_empty_payload() {
    std::printf("[test] compress empty payload...\n");

    auto msg = ApplicationMessage::request(1, MethodId::ForwardPP,
                                           std::vector<std::uint8_t>{});

    bool ok = msg.compress(CompressionAlgo::Zstd);
    CHECK(ok);
    CHECK(!msg.is_zstd_compressed());  // 空 payload 不置 flag
    CHECK(msg.payload.empty());
}

static void test_compress_large_payload_ratio() {
    std::printf("[test] compress 16KB+ payload ratio >= 2:1...\n");

    auto payload = make_compressible_payload(16 * 1024);
    auto msg = ApplicationMessage::request(1, MethodId::CrossDomainDigest, payload);
    auto original_size = msg.payload.size();

    msg.compress(CompressionAlgo::Zstd);
    CHECK(msg.is_zstd_compressed());
    // 压缩比 >= 2:1
    CHECK(msg.payload.size() * 2 <= original_size);
}

static void test_compress_no_benefit() {
    std::printf("[test] compress tiny payload (no benefit, zstd overhead > data)...\n");

    auto payload = make_incompressible_payload();  // 4 字节
    auto msg = ApplicationMessage::request(1, MethodId::ForwardPP, payload);
    auto original_size = msg.payload.size();

    bool ok = msg.compress(CompressionAlgo::Zstd);
    CHECK(ok);  // 返回 true（成功，但无收益）
    // zstd 帧头开销 > 4 字节数据 → 压缩后 >= 原始 → 不置 flag，payload 不变
    CHECK(!msg.is_zstd_compressed());
    CHECK_EQ(msg.payload.size(), original_size);
}

static void test_decompress_no_flag_passthrough() {
    std::printf("[test] decompress without flag (no-op)...\n");

    auto payload = make_compressible_payload(1024);
    auto msg = ApplicationMessage::request(1, MethodId::ForwardPP, payload);

    CHECK(!msg.is_zstd_compressed());
    bool ok = msg.decompress();
    CHECK(ok);  // no-op 返回 true
    CHECK_EQ(msg.payload.size(), payload.size());
    CHECK(std::memcmp(msg.payload.data(), payload.data(), payload.size()) == 0);
}

static void test_compress_gzip_not_implemented() {
    std::printf("[test] compress(Gzip) not implemented...\n");

    auto payload = make_compressible_payload(1024);
    auto msg = ApplicationMessage::request(1, MethodId::ForwardPP, payload);

    bool ok = msg.compress(CompressionAlgo::Gzip);
    CHECK(!ok);  // Gzip 未实现
    CHECK(!msg.is_zstd_compressed());
    CHECK(!msg.is_compressed());  // PayloadCompressed 也不置
}

static void test_decompress_gzip_not_implemented() {
    std::printf("[test] decompress PayloadCompressed (gzip) not implemented...\n");

    auto msg = ApplicationMessage::request(1, MethodId::ForwardPP,
                                           std::vector<std::uint8_t>(64, 0xAA));
    // 手动置 PayloadCompressed flag（模拟旧 gzip 消息）
    msg.set_flag(MessageFlags::PayloadCompressed);

    bool ok = msg.decompress();
    CHECK(!ok);  // Gzip 解压未实现
}

static void test_both_flags_illegal() {
    std::printf("[test] both compression flags set -> decompress fails...\n");

    auto msg = ApplicationMessage::request(1, MethodId::ForwardPP,
                                           std::vector<std::uint8_t>(64, 0xBB));
    // 同时置两种压缩 flag（非法状态）
    msg.set_flag(MessageFlags::ZstdCompressed);
    msg.set_flag(MessageFlags::PayloadCompressed);

    bool ok = msg.decompress();
    CHECK(!ok);  // 非法状态返回 false
}

static void test_compress_session_id_serialize_parse_decompress() {
    std::printf("[test] compress + session_id: serialize -> parse -> decompress...\n");

    auto sid = SessionId::generate();
    auto original = make_compressible_payload(8192);
    auto msg = ApplicationMessage::request(42, MethodId::ForwardPP, original);
    msg.set_session_id(sid);

    // 先压缩 payload（session_id 不参与压缩）
    bool ok = msg.compress(CompressionAlgo::Zstd);
    CHECK(ok);
    CHECK(msg.is_zstd_compressed());
    CHECK(msg.has_session_id());
    auto compressed_size = msg.payload.size();
    CHECK(compressed_size < original.size());

    // serialize（wire = header + session_id 16B + compressed payload）
    auto wire = msg.serialize();
    CHECK_EQ(wire.size(), msg.wire_size());

    // parse
    ApplicationMessage parsed;
    std::size_t consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(wire.data(), wire.size()), parsed);
    CHECK_EQ(consumed, wire.size());

    // session_id 正确剥离
    CHECK(parsed.has_session_id());
    CHECK(parsed.get_session_id().value() == sid);
    // payload 仍是压缩状态
    CHECK(parsed.is_zstd_compressed());
    CHECK_EQ(parsed.payload.size(), compressed_size);

    // decompress
    ok = parsed.decompress();
    CHECK(ok);
    CHECK(!parsed.is_zstd_compressed());
    // 解压后与原始一致
    CHECK_EQ(parsed.payload.size(), original.size());
    CHECK(std::memcmp(parsed.payload.data(), original.data(), original.size()) == 0);
}

static void test_compress_serialize_parse_decompress_no_sid() {
    std::printf("[test] compress + serialize -> parse -> decompress (no session_id)...\n");

    auto original = make_compressible_payload(4096);
    auto msg = ApplicationMessage::notification(MethodId::CrossDomainDigest, original);

    msg.compress(CompressionAlgo::Zstd);
    CHECK(msg.is_zstd_compressed());

    auto wire = msg.serialize();

    ApplicationMessage parsed;
    ApplicationMessage::parse(std::span<const std::uint8_t>(wire.data(), wire.size()), parsed);

    CHECK(parsed.is_zstd_compressed());
    CHECK(!parsed.has_session_id());

    parsed.decompress();
    CHECK(!parsed.is_zstd_compressed());
    CHECK_EQ(parsed.payload.size(), original.size());
    CHECK(std::memcmp(parsed.payload.data(), original.data(), original.size()) == 0);
}

// ========== main ==========

int main() {
    std::printf("=== test_message_compression (V3.4 P4) ===\n\n");

    test_compress_decompress_zstd_roundtrip();
    test_compress_sets_flag();
    test_decompress_clears_flag();
    test_compress_none_passthrough();
    test_compress_empty_payload();
    test_compress_large_payload_ratio();
    test_compress_no_benefit();
    test_decompress_no_flag_passthrough();
    test_compress_gzip_not_implemented();
    test_decompress_gzip_not_implemented();
    test_both_flags_illegal();
    test_compress_session_id_serialize_parse_decompress();
    test_compress_serialize_parse_decompress_no_sid();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
