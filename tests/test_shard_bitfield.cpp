// test_shard_bitfield.cpp — v4.0.2 M20 分片可用性同步协议单元测试
//
// 测试覆盖：
//   1. bitmap_bytes 计算（0/1/8/9/100/最大）
//   2. set_shard/get_shard 基本操作
//   3. set_shard 越界返回 false
//   4. clear_shard 操作 + get_shard 验证
//   5. get_shard 越界返回 false
//   6. available_count 统计（部分/全部/空）
//   7. is_complete（全部到达/部分/空）
//   8. resize_for_total 调整大小
//   9. RLE 空输入往返
//  10. RLE 全相同字节（repeat run）
//  11. RLE 全不同字节（literal run）
//  12. RLE 混合输入往返
//  13. RLE 大 tensor 全 0（压缩比验证 >5x）
//  14. RLE repeat run 上限 129
//  15. RLE literal run 上限 128
//  16. RLE 解压损坏：缺 repeat value
//  17. RLE 解压损坏：literal 数据不足
//  18. encode/decode 全量模式往返
//  19. encode/decode 增量模式往返
//  20. encode 字节布局校验（version/flags/tensor_id）
//  21. encode total_shards=0（空 bitmap）
//  22. encode 大 tensor（500 shards 部分到达）
//  23. encode total_shards 超限返回空
//  24. encode bitmap 长度不匹配返回空
//  25. decode 数据不足返回 false
//  26. decode 版本不匹配返回 false
//  27. decode rle 损坏返回 false
//  28. decode 解压长度不匹配返回 false
//  29. decode flags 保留位忽略
//  30. to_string 输出格式
//  31. operator== 相等比较
//  32. Observe MethodId 枚举值 0x0045

#include "linoh/protocol/shard_bitfield.hpp"
#include "linoh/protocol/application_message.hpp"

#include <cstdio>
#include <cstring>
#include <string>
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

// ========== 测试用例 ==========

// 1. bitmap_bytes 计算
static void test_bitmap_bytes() {
    std::printf("[test] bitmap_bytes calculation...\n");
    CHECK_EQ(ShardBitfield::bitmap_bytes(0),   0u);
    CHECK_EQ(ShardBitfield::bitmap_bytes(1),   1u);
    CHECK_EQ(ShardBitfield::bitmap_bytes(8),   1u);
    CHECK_EQ(ShardBitfield::bitmap_bytes(9),   2u);
    CHECK_EQ(ShardBitfield::bitmap_bytes(100), 13u);  // (100+7)/8 = 13
    CHECK_EQ(ShardBitfield::bitmap_bytes(ShardBitfield::kMaxShards),
             (static_cast<std::size_t>(ShardBitfield::kMaxShards) + 7) / 8);
}

// 2. set_shard/get_shard 基本操作
static void test_set_get_shard() {
    std::printf("[test] set_shard/get_shard basic...\n");
    ShardBitfield bf;
    bf.total_shards = 20;
    bf.resize_for_total();
    CHECK_EQ(bf.bitmap.size(), 3u);  // (20+7)/8 = 3

    CHECK(bf.set_shard(0));   // 第 0 个
    CHECK(bf.set_shard(7));   // 第 7 个（同字节末位）
    CHECK(bf.set_shard(8));   // 第 8 个（下一字节首位）
    CHECK(bf.set_shard(19));  // 最后一个

    CHECK(bf.get_shard(0));
    CHECK(bf.get_shard(7));
    CHECK(bf.get_shard(8));
    CHECK(bf.get_shard(19));
    CHECK(!bf.get_shard(1));
    CHECK(!bf.get_shard(9));
    CHECK(!bf.get_shard(18));
}

// 3. set_shard 越界返回 false
static void test_set_shard_out_of_range() {
    std::printf("[test] set_shard out of range...\n");
    ShardBitfield bf;
    bf.total_shards = 10;
    bf.resize_for_total();
    CHECK(!bf.set_shard(10));  // 越界
    CHECK(!bf.set_shard(100));
    CHECK(!bf.set_shard(0xFFFFFFFF));
}

// 4. clear_shard 操作
static void test_clear_shard() {
    std::printf("[test] clear_shard...\n");
    ShardBitfield bf;
    bf.total_shards = 16;
    bf.resize_for_total();
    CHECK(bf.set_shard(5));
    CHECK(bf.get_shard(5));
    CHECK(bf.clear_shard(5));
    CHECK(!bf.get_shard(5));
    CHECK(!bf.clear_shard(16));  // 越界
}

// 5. get_shard 越界返回 false
static void test_get_shard_out_of_range() {
    std::printf("[test] get_shard out of range...\n");
    ShardBitfield bf;
    bf.total_shards = 8;
    bf.resize_for_total();
    CHECK(!bf.get_shard(8));
    CHECK(!bf.get_shard(100));
}

// 6. available_count 统计
static void test_available_count() {
    std::printf("[test] available_count...\n");
    ShardBitfield bf;
    bf.total_shards = 32;
    bf.resize_for_total();
    CHECK_EQ(bf.available_count(), 0u);

    bf.set_shard(0);
    bf.set_shard(15);
    bf.set_shard(31);
    CHECK_EQ(bf.available_count(), 3u);

    // 全部设置
    for (std::uint32_t i = 0; i < 32; ++i) bf.set_shard(i);
    CHECK_EQ(bf.available_count(), 32u);
}

// 7. is_complete
static void test_is_complete() {
    std::printf("[test] is_complete...\n");
    ShardBitfield bf;
    bf.total_shards = 16;
    bf.resize_for_total();
    CHECK(!bf.is_complete());  // 空

    for (std::uint32_t i = 0; i < 15; ++i) bf.set_shard(i);
    CHECK(!bf.is_complete());  // 部分

    bf.set_shard(15);
    CHECK(bf.is_complete());  // 全部

    // total_shards=0 时 is_complete=false
    ShardBitfield empty;
    CHECK(!empty.is_complete());
}

// 8. resize_for_total
static void test_resize_for_total() {
    std::printf("[test] resize_for_total...\n");
    ShardBitfield bf;
    bf.total_shards = 50;
    bf.resize_for_total();
    CHECK_EQ(bf.bitmap.size(), 7u);  // (50+7)/8 = 6.25 -> 7
    // 新空间应为 0
    for (auto b : bf.bitmap) CHECK_EQ(b, 0u);
}

// 9. RLE 空输入
static void test_rle_empty() {
    std::printf("[test] RLE empty input...\n");
    std::vector<std::uint8_t> empty;
    auto rle = ShardBitfield::rle_encode(empty);
    CHECK_EQ(rle.size(), 0u);
    auto dec = ShardBitfield::rle_decode(rle);
    CHECK_EQ(dec.size(), 0u);
}

// 10. RLE 全相同字节（repeat run）
static void test_rle_all_same() {
    std::printf("[test] RLE all same bytes (repeat run)...\n");
    std::vector<std::uint8_t> raw(100, 0x00);  // 100 个 0x00
    auto rle = ShardBitfield::rle_encode(raw);
    // 100 个相同字节 = 1 个 repeat(100) + 1 byte value
    // 100 = 0x80 | (100-2) = 0x80 | 98 = 0xE2，后跟 0x00
    CHECK_EQ(rle.size(), 2u);
    auto dec = ShardBitfield::rle_decode(rle);
    CHECK_EQ(dec.size(), 100u);
    CHECK_EQ(dec, raw);
}

// 11. RLE 全不同字节（literal run）
static void test_rle_all_different() {
    std::printf("[test] RLE all different (literal run)...\n");
    std::vector<std::uint8_t> raw;
    for (int i = 0; i < 50; ++i) raw.push_back(static_cast<std::uint8_t>(i));  // 0,1,2,...,49 全不同
    auto rle = ShardBitfield::rle_encode(raw);
    // 50 个不同字节 = 1 控制字节(49=0x31) + 50 literal = 51 字节
    CHECK_EQ(rle.size(), 51u);
    auto dec = ShardBitfield::rle_decode(rle);
    CHECK_EQ(dec, raw);
}

// 12. RLE 混合输入往返
static void test_rle_mixed() {
    std::printf("[test] RLE mixed input roundtrip...\n");
    std::vector<std::uint8_t> raw;
    // 10 个 0xFF + 5 个不同值 + 20 个 0x00 + 3 个不同值
    for (int i = 0; i < 10; ++i) raw.push_back(0xFF);
    raw.push_back(0x01); raw.push_back(0x02); raw.push_back(0x03); raw.push_back(0x04); raw.push_back(0x05);
    for (int i = 0; i < 20; ++i) raw.push_back(0x00);
    raw.push_back(0xAA); raw.push_back(0xBB); raw.push_back(0xCC);

    auto rle = ShardBitfield::rle_encode(raw);
    auto dec = ShardBitfield::rle_decode(rle);
    CHECK_EQ(dec, raw);
    // 压缩后应比原始小
    CHECK(rle.size() < raw.size());
}

// 13. RLE 大 tensor 全 0（压缩比 >5x）
static void test_rle_large_all_zero() {
    std::printf("[test] RLE large tensor all-zero (compression >5x)...\n");
    // 1000 shards = 125 字节全 0
    std::vector<std::uint8_t> raw(125, 0x00);
    auto rle = ShardBitfield::rle_encode(raw);
    // 125 个 0 = repeat(125) = 2 字节
    CHECK_EQ(rle.size(), 2u);
    auto dec = ShardBitfield::rle_decode(rle);
    CHECK_EQ(dec, raw);
    // 压缩比 = 125/2 = 62.5x > 5x
    CHECK(raw.size() / rle.size() > 5);
}

// 14. RLE repeat run 上限 129
static void test_rle_repeat_max_129() {
    std::printf("[test] RLE repeat run max 129...\n");
    std::vector<std::uint8_t> raw(129, 0xAB);
    auto rle = ShardBitfield::rle_encode(raw);
    // 129 个相同 = repeat(129) = 0x80|127=0xFF + value = 2 字节
    CHECK_EQ(rle.size(), 2u);
    auto dec = ShardBitfield::rle_decode(rle);
    CHECK_EQ(dec.size(), 129u);
    CHECK_EQ(dec, raw);
}

// 15. RLE literal run 上限 128
static void test_rle_literal_max_128() {
    std::printf("[test] RLE literal run max 128...\n");
    std::vector<std::uint8_t> raw;
    for (int i = 0; i < 128; ++i) raw.push_back(static_cast<std::uint8_t>(i % 50 + 1));  // 避免连续相同
    auto rle = ShardBitfield::rle_encode(raw);
    auto dec = ShardBitfield::rle_decode(rle);
    CHECK_EQ(dec, raw);
}

// 16. RLE 解压损坏：缺 repeat value
static void test_rle_decode_missing_repeat_value() {
    std::printf("[test] RLE decode missing repeat value...\n");
    std::vector<std::uint8_t> bad_rle = {0x85};  // repeat 7 次但缺 value
    auto dec = ShardBitfield::rle_decode(bad_rle);
    CHECK(dec.empty());  // 损坏返回空
}

// 17. RLE 解压损坏：literal 数据不足
static void test_rle_decode_literal_truncated() {
    std::printf("[test] RLE decode literal truncated...\n");
    std::vector<std::uint8_t> bad_rle = {0x0A, 0x01, 0x02};  // literal 11 字节但只给 2
    auto dec = ShardBitfield::rle_decode(bad_rle);
    CHECK(dec.empty());
}

// 18. encode/decode 全量模式往返
static void test_encode_decode_full_roundtrip() {
    std::printf("[test] encode/decode full mode roundtrip...\n");
    ShardBitfield bf;
    bf.tensor_id = 0xDEADBEEF12345678ULL;
    bf.total_shards = 64;
    bf.is_incremental = false;
    bf.base_shard_idx = 0;
    bf.resize_for_total();
    bf.set_shard(0);
    bf.set_shard(32);
    bf.set_shard(63);

    auto encoded = bf.encode();
    CHECK(!encoded.empty());
    CHECK(encoded.size() >= ShardBitfield::kMinEncodedSize);

    ShardBitfield decoded;
    CHECK(ShardBitfield::decode(encoded, decoded));
    CHECK(decoded == bf);
    CHECK_EQ(decoded.available_count(), 3u);
}

// 19. encode/decode 增量模式往返
static void test_encode_decode_incremental_roundtrip() {
    std::printf("[test] encode/decode incremental mode roundtrip...\n");
    ShardBitfield bf;
    bf.tensor_id = 0xABCDEFULL;
    bf.total_shards = 40;
    bf.is_incremental = true;
    bf.base_shard_idx = 20;
    bf.resize_for_total();
    bf.set_shard(20);
    bf.set_shard(25);

    auto encoded = bf.encode();
    CHECK(!encoded.empty());

    ShardBitfield decoded;
    CHECK(ShardBitfield::decode(encoded, decoded));
    CHECK(decoded == bf);
    CHECK(decoded.is_incremental);
    CHECK_EQ(decoded.base_shard_idx, 20u);
}

// 20. encode 字节布局校验
static void test_encode_byte_layout() {
    std::printf("[test] encode byte layout...\n");
    ShardBitfield bf;
    bf.tensor_id = 0x0102030405060708ULL;
    bf.total_shards = 8;
    bf.is_incremental = true;
    bf.base_shard_idx = 0;
    bf.resize_for_total();
    bf.set_shard(0);  // bitmap = [0x80, 0x00... 不对，8 shards = 1 byte]

    auto enc = bf.encode();
    CHECK_EQ(enc.size(), ShardBitfield::kMinEncodedSize + 2u);  // 20 + RLE(1 byte bitmap)
    // RLE of [0x80] = literal 1 byte = [0x00, 0x80] = 2 bytes

    // offset 0: version
    CHECK_EQ(enc[0], ShardBitfield::kCurrentVersion);
    // offset 1: flags bit0=1 (is_incremental)
    CHECK_EQ(enc[1] & 0x01, 0x01u);
    // offset 2: tensor_id 小端 = 08 07 06 05 04 03 02 01
    CHECK_EQ(enc[2], 0x08u);
    CHECK_EQ(enc[9], 0x01u);
    // offset 10: total_shards=8 小端 = 08 00 00 00
    CHECK_EQ(enc[10], 0x08u);
    // offset 18: rle_bitmap_len 小端
    CHECK_EQ(enc[18], 0x02u);  // 2 字节 RLE
    CHECK_EQ(enc[19], 0x00u);
}

// 21. encode total_shards=0（空 bitmap）
static void test_encode_zero_shards() {
    std::printf("[test] encode total_shards=0 (empty bitmap)...\n");
    ShardBitfield bf;
    bf.tensor_id = 0;
    bf.total_shards = 0;
    bf.is_incremental = false;
    // bitmap 为空（默认）

    auto enc = bf.encode();
    CHECK(!enc.empty());
    CHECK_EQ(enc.size(), ShardBitfield::kMinEncodedSize);  // 20 字节，无 RLE 数据

    ShardBitfield decoded;
    CHECK(ShardBitfield::decode(enc, decoded));
    CHECK(decoded == bf);
}

// 22. encode 大 tensor（500 shards 部分到达）
static void test_encode_large_tensor() {
    std::printf("[test] encode large tensor (500 shards)...\n");
    ShardBitfield bf;
    bf.tensor_id = 999;
    bf.total_shards = 500;
    bf.is_incremental = false;
    bf.resize_for_total();
    CHECK_EQ(bf.bitmap.size(), 63u);  // (500+7)/8 = 63

    // 设置连续的 shard（0-49），模拟实际推理中 shard 按顺序到达
    // 产生 6 字节 0xFF + 1 字节部分 + 56 字节 0x00，RLE 压缩效果好
    for (std::uint32_t i = 0; i < 50; ++i) {
        bf.set_shard(i);
    }
    CHECK_EQ(bf.available_count(), 50u);

    auto enc = bf.encode();
    CHECK(!enc.empty());
    // 连续 shard 到达：RLE 压缩后远小于原始 bitmap
    CHECK(enc.size() < ShardBitfield::kMinEncodedSize + bf.bitmap.size());

    ShardBitfield decoded;
    CHECK(ShardBitfield::decode(enc, decoded));
    CHECK(decoded == bf);
    CHECK_EQ(decoded.available_count(), 50u);
}

// 23. encode total_shards 超限返回空
static void test_encode_total_shards_exceed() {
    std::printf("[test] encode total_shards exceed limit...\n");
    ShardBitfield bf;
    bf.total_shards = ShardBitfield::kMaxShards + 1;
    bf.resize_for_total();
    auto enc = bf.encode();
    CHECK(enc.empty());
}

// 24. encode bitmap 长度不匹配返回空
static void test_encode_bitmap_mismatch() {
    std::printf("[test] encode bitmap length mismatch...\n");
    ShardBitfield bf;
    bf.total_shards = 16;
    bf.bitmap = {0xFF, 0xFF};  // 2 字节 = 16 shards，但故意填错大小
    // 实际 16 shards 需要 2 字节，这里匹配。改成不匹配：
    bf.bitmap = {0xFF};  // 1 字节但 total_shards=16 需要 2 字节
    auto enc = bf.encode();
    CHECK(enc.empty());
}

// 25. decode 数据不足返回 false
static void test_decode_short_data() {
    std::printf("[test] decode short data...\n");
    std::vector<std::uint8_t> short_data(ShardBitfield::kMinEncodedSize - 1, 0);
    ShardBitfield decoded;
    CHECK(!ShardBitfield::decode(short_data, decoded));
}

// 26. decode 版本不匹配返回 false
static void test_decode_bad_version() {
    std::printf("[test] decode bad version...\n");
    ShardBitfield bf;
    bf.total_shards = 8;
    bf.resize_for_total();
    auto enc = bf.encode();
    enc[0] = 0xFF;  // 坏 version
    ShardBitfield decoded;
    CHECK(!ShardBitfield::decode(enc, decoded));
}

// 27. decode rle 损坏返回 false
static void test_decode_corrupt_rle() {
    std::printf("[test] decode corrupt rle...\n");
    ShardBitfield bf;
    bf.total_shards = 8;
    bf.resize_for_total();
    bf.set_shard(0);
    auto enc = bf.encode();
    // rle_bitmap 从 offset 20 开始，rle_len 在 offset 18-19
    // 篡改 rle 数据：把 repeat value 删掉（缩短）
    std::uint16_t rle_len = enc[18] | (enc[19] << 8);
    if (rle_len > 0) {
        // 把 rle_len 改大，使其声称有更多数据但实际没有
        enc[18] = static_cast<std::uint8_t>((rle_len + 10) & 0xFF);
        enc[19] = static_cast<std::uint8_t>(((rle_len + 10) >> 8) & 0xFF);
        ShardBitfield decoded;
        CHECK(!ShardBitfield::decode(enc, decoded));
    }
}

// 28. decode 解压长度不匹配返回 false
static void test_decode_length_mismatch() {
    std::printf("[test] decode decompressed length mismatch...\n");
    // 构造一个 total_shards=16 但 bitmap 解压后只有 1 字节的 payload
    std::vector<std::uint8_t> enc;
    enc.push_back(ShardBitfield::kCurrentVersion);  // version
    enc.push_back(0x00);  // flags
    // tensor_id = 0
    for (int i = 0; i < 8; ++i) enc.push_back(0);
    enc.push_back(16); enc.push_back(0); enc.push_back(0); enc.push_back(0);  // total_shards=16
    enc.push_back(0); enc.push_back(0); enc.push_back(0); enc.push_back(0);  // base_shard_idx=0
    // RLE of [0xFF]（1 字节）但 total_shards=16 需要 2 字节
    enc.push_back(2); enc.push_back(0);  // rle_bitmap_len=2
    enc.push_back(0x00); enc.push_back(0xFF);  // literal 1 byte: 0xFF

    ShardBitfield decoded;
    CHECK(!ShardBitfield::decode(enc, decoded));  // 长度不匹配
}

// 29. decode flags 保留位忽略
static void test_decode_flags_reserved_ignored() {
    std::printf("[test] decode flags reserved bits ignored...\n");
    ShardBitfield bf;
    bf.total_shards = 8;
    bf.is_incremental = false;
    bf.resize_for_total();
    auto enc = bf.encode();
    // 设置保留位 bit1-7
    enc[1] |= 0xFE;
    ShardBitfield decoded;
    CHECK(ShardBitfield::decode(enc, decoded));
    CHECK(!decoded.is_incremental);  // bit0=0 保留位忽略
    CHECK_EQ(decoded.total_shards, 8u);
}

// 30. to_string 输出格式
static void test_to_string() {
    std::printf("[test] to_string output...\n");
    ShardBitfield bf;
    bf.tensor_id = 0x1234;
    bf.total_shards = 32;
    bf.resize_for_total();
    bf.set_shard(0);
    bf.set_shard(1);
    std::string s = bf.to_string();
    CHECK(s.find("ShardBitfield{") != std::string::npos);
    CHECK(s.find("tensor_id=0x1234") != std::string::npos);
    CHECK(s.find("total_shards=32") != std::string::npos);
    CHECK(s.find("available=2") != std::string::npos);
}

// 31. operator== 相等比较
static void test_operator_eq() {
    std::printf("[test] operator== equality...\n");
    ShardBitfield a, b;
    a.tensor_id = 100;
    a.total_shards = 16;
    a.is_incremental = false;
    a.resize_for_total();
    a.set_shard(5);

    b = a;
    CHECK(a == b);

    b.tensor_id = 200;
    CHECK(!(a == b));

    b = a;
    b.is_incremental = true;
    CHECK(!(a == b));
}

// 32. Observe MethodId 枚举值
static void test_observe_method_id() {
    std::printf("[test] Observe MethodId enum value...\n");
    CHECK_EQ(static_cast<std::uint16_t>(MethodId::Observe), 0x0045u);
    CHECK_EQ(static_cast<std::uint16_t>(MethodId::TensorShard), 0x0040u);
    CHECK_EQ(static_cast<std::uint16_t>(MethodId::ShardHashAnnounce), 0x0043u);
    CHECK(std::strcmp(observe_method_name(), "Observe") == 0);
}

// ========== main ==========

int main() {
    std::printf("=== test_shard_bitfield (v4.0.2 M20) ===\n\n");

    test_bitmap_bytes();
    test_set_get_shard();
    test_set_shard_out_of_range();
    test_clear_shard();
    test_get_shard_out_of_range();
    test_available_count();
    test_is_complete();
    test_resize_for_total();
    test_rle_empty();
    test_rle_all_same();
    test_rle_all_different();
    test_rle_mixed();
    test_rle_large_all_zero();
    test_rle_repeat_max_129();
    test_rle_literal_max_128();
    test_rle_decode_missing_repeat_value();
    test_rle_decode_literal_truncated();
    test_encode_decode_full_roundtrip();
    test_encode_decode_incremental_roundtrip();
    test_encode_byte_layout();
    test_encode_zero_shards();
    test_encode_large_tensor();
    test_encode_total_shards_exceed();
    test_encode_bitmap_mismatch();
    test_decode_short_data();
    test_decode_bad_version();
    test_decode_corrupt_rle();
    test_decode_length_mismatch();
    test_decode_flags_reserved_ignored();
    test_to_string();
    test_operator_eq();
    test_observe_method_id();

    std::printf("\n=== Results: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
