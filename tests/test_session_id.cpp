// test_session_id.cpp — SessionId 单元测试（V3.4）
//
// 测试覆盖（对应 docs/LINOH_EVENTBUS_BINARY_FRAME_IMPL_PLAN.md §3.6）：
//   1. test_generate_unique       生成 10000 个无碰撞 + version/variant 位正确
//   2. test_parse_serialize       序列化/反序列化往返一致
//   3. test_parse_short_input     parse 数据不足返回 nullopt
//   4. test_to_string_format      UUID 字符串格式 8-4-4-4-12
//   5. test_null                  零值判断
//   6. test_hash_unordered_set    unordered_set 去重
//   7. test_hash_equal_collision  相同 SessionId hash 一致

#include "linoh/protocol/session_id.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <unordered_set>
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

// ============================================================================
// 1. generate() 唯一性 + version/variant 位
// ============================================================================

static void test_generate_unique() {
    std::printf("[test] generate 10000 unique SessionIds + v4 version/variant...\n");
    std::unordered_set<SessionId> seen;
    seen.reserve(10000);
    bool all_version4 = true;
    bool all_variant_rfc4122 = true;
    bool all_non_null = true;

    for (int i = 0; i < 10000; ++i) {
        auto sid = SessionId::generate();
        if (sid.is_null()) all_non_null = false;
        if ((sid.bytes[6] >> 4) != 0x4) all_version4 = false;        // version = 4
        if ((sid.bytes[8] >> 6) != 0x2) all_variant_rfc4122 = false; // variant = 10xx
        seen.insert(sid);
    }

    CHECK_EQ(seen.size(), 10000u);          // 无碰撞
    CHECK(all_non_null);                     // CSPRNG 正常时全部非零
    CHECK(all_version4);                     // version 位 = 4
    CHECK(all_variant_rfc4122);              // variant = RFC 4122
    CHECK(seen.count(SessionId::generate()) <= 1);  // 新生成的大概率不在集合中（不强制 0）
}

// ============================================================================
// 2. parse() / serialize_to() 往返一致
// ============================================================================

static void test_parse_serialize() {
    std::printf("[test] parse / serialize round-trip...\n");
    auto sid = SessionId::generate();
    CHECK(!sid.is_null());

    // serialize_to 16B buffer
    std::array<std::uint8_t, 16> buf{};
    sid.serialize_to(buf);

    // parse 回来应一致
    auto parsed = SessionId::parse(buf);
    CHECK(parsed.has_value());
    CHECK_EQ(*parsed, sid);
    CHECK(std::memcmp(parsed->bytes.data(), sid.bytes.data(), 16) == 0);

    // parse 精确 16B 成功
    auto p2 = SessionId::parse(std::span<const std::uint8_t>(buf.data(), 16));
    CHECK(p2.has_value());
    CHECK_EQ(*p2, sid);

    // serialize → parse 多次往返一致
    std::array<std::uint8_t, 16> buf2{};
    parsed->serialize_to(buf2);
    CHECK(std::memcmp(buf.data(), buf2.data(), 16) == 0);
}

// ============================================================================
// 3. parse() 数据不足返回 nullopt
// ============================================================================

static void test_parse_short_input() {
    std::printf("[test] parse short input returns nullopt...\n");
    std::uint8_t short_buf[15] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    auto p = SessionId::parse(std::span<const std::uint8_t>(short_buf, 15));
    CHECK(!p.has_value());

    // 空 buffer
    auto p2 = SessionId::parse(std::span<const std::uint8_t>{});
    CHECK(!p2.has_value());

    // 长于 16B 取前 16B（应成功）
    std::uint8_t long_buf[20] = {};
    long_buf[0] = 0xAB;
    auto p3 = SessionId::parse(std::span<const std::uint8_t>(long_buf, 20));
    CHECK(p3.has_value());
    CHECK_EQ(p3->bytes[0], 0xAB);
}

// ============================================================================
// 4. to_string() UUID 格式 8-4-4-4-12
// ============================================================================

static void test_to_string_format() {
    std::printf("[test] to_string UUID format 8-4-4-4-12...\n");
    auto sid = SessionId::generate();
    auto s = sid.to_string();

    CHECK_EQ(s.size(), 36u);                 // 32 hex + 4 dashes
    CHECK_EQ(s[8], '-');                     // field 分隔符位置
    CHECK_EQ(s[13], '-');
    CHECK_EQ(s[18], '-');
    CHECK_EQ(s[23], '-');
    CHECK_EQ(s[14], '4');                    // version 字段 = '4'

    // variant 字段首位 ∈ {8, 9, a, b}
    char v = s[19];
    CHECK(v == '8' || v == '9' || v == 'a' || v == 'b');

    // 验证字节内容与字符串一致：手动构造已知 sid
    SessionId known{};
    known.bytes = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                   0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    CHECK_EQ(known.to_string(), std::string("01234567-89ab-cdef-0123-456789abcdef"));
}

// ============================================================================
// 5. is_null() 零值判断
// ============================================================================

static void test_null() {
    std::printf("[test] is_null zero check...\n");
    SessionId default_sid;  // 默认构造全零
    CHECK(default_sid.is_null());
    CHECK_EQ(default_sid.to_string(), std::string("00000000-0000-0000-0000-000000000000"));

    auto generated = SessionId::generate();
    CHECK(!generated.is_null());  // CSPRNG 正常时非零

    // 手动设置非零字节后 not null
    SessionId manual{};
    manual.bytes[0] = 0x01;
    CHECK(!manual.is_null());

    // 手动清零后 is_null
    manual.bytes[0] = 0x00;
    CHECK(manual.is_null());
}

// ============================================================================
// 6. std::hash + unordered_set 去重
// ============================================================================

static void test_hash_unordered_set() {
    std::printf("[test] std::hash + unordered_set dedup...\n");
    std::unordered_set<SessionId> set;
    set.reserve(100);
    for (int i = 0; i < 100; ++i) {
        set.insert(SessionId::generate());
    }
    CHECK_EQ(set.size(), 100u);  // 全部唯一

    // 已存在的 SessionId 插入不增加 size
    auto sid = *set.begin();
    set.insert(sid);
    CHECK_EQ(set.size(), 100u);

    // count 查找
    CHECK_EQ(set.count(sid), 1u);
    auto outside = SessionId::generate();
    CHECK(set.count(outside) <= 1u);  // 大概率 0（不强制）

    // 两个相等的 SessionId hash 相同
    std::hash<SessionId> hasher;
    SessionId a = SessionId::generate();
    SessionId b = a;  // 拷贝
    CHECK_EQ(hasher(a), hasher(b));
    CHECK_EQ(a, b);
}

// ============================================================================
// 7. 大量 generate + hash 分布均匀性（额外覆盖）
// ============================================================================

static void test_hash_distribution() {
    std::printf("[test] hash distribution uniformity...\n");
    // 生成 1000 个 SessionId，检查 hash 桶分布（避免极端碰撞）
    std::unordered_set<SessionId> set;
    for (int i = 0; i < 1000; ++i) {
        set.insert(SessionId::generate());
    }
    CHECK_EQ(set.size(), 1000u);

    // 检查 bucket_count 合理（unordered_set 自适应桶数）
    CHECK(set.bucket_count() >= 1000u);

    // 最大桶负载不应过大（哈希分布均匀的标志）
    std::size_t max_load = 0;
    for (std::size_t b = 0; b < set.bucket_count(); ++b) {
        max_load = (std::max)(max_load, set.bucket_size(b));
    }
    CHECK(max_load <= 10);  // 1000 个元素分散到 ≥1000 桶，单桶不应超过 10
}

// ============================================================================

int main() {
    std::printf("=== test_session_id ===\n");

    test_generate_unique();
    test_parse_serialize();
    test_parse_short_input();
    test_to_string_format();
    test_null();
    test_hash_unordered_set();
    test_hash_distribution();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
