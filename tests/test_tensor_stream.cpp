// test_tensor_stream.cpp — P5-A-3 大 tensor 分片 + 重组单元测试
//
// 测试覆盖：
//   1.  TensorMeta 默认值
//   2.  TensorMeta 序列化大小（48 字节）
//   3.  TensorMeta 自定义值往返一致性
//   4.  TensorMeta parse 长度不足返回 false
//   5.  TensorMeta 边界值（最大 u64/u32）
//   6.  TensorShardMessage 序列化/反序列化
//   7.  TensorShardMessage parse 长度不足
//   8.  TensorDType 枚举值
//   9.  dtype_name 正确返回
//  10.  dtype_size 正确返回
//  11.  TensorStreamer 构造（默认参数）
//  12.  TensorStreamer 自定义参数
//  13.  TensorStreamer 零大小防御
//  14.  shard_count 计算（整除）
//  15.  shard_count 计算（非整除）
//  16.  shard_count 计算（0 字节）
//  17.  shard 小数据（1 字节）
//  18.  shard 整除场景
//  19.  shard 非整除场景
//  20.  shard 空 tensor
//  21.  shard 分片数据正确性（拼接还原）
//  22.  shard 元数据正确性（is_last/total_shards/shard_idx）
//  23.  assign_streams 4 路均衡
//  24.  assign_streams stream 数 > 分片数
//  25.  Reassembler 顺序重组
//  26.  Reassembler 乱序重组
//  27.  Reassembler 重复分片去重
//  28.  Reassembler 错误 shard_idx（越界）
//  29.  Reassembler 多 tensor 并发
//  30.  Reassembler 回调触发 + 数据完整
//  31.  Reassembler progress 进度查询
//  32.  Reassembler cleanup/clear
//  33.  Reassembler 无回调时不崩溃
//  34.  100MB 大 tensor 分片 + 重组（性能/正确性）
//  35.  round-trip：分片→序列化→反序列化→重组 = 原数据
//  36.  [mp-P9] 并发重组多个 tensor（8 线程 × 20 tensor，不同桶并行）
//  37.  [mp-P9] 并发投递同一 tensor 的分片（同桶串行化，回调仅一次）
//  38.  [mp-P9] 并发 on_shard + run_auto_cleanup（死锁/崩溃检测，500ms）
//  39.  [mp-P9] 并发查询 + 投递（pending_count/progress 无死锁，300ms）

#include "linoh/multimodal/tensor_stream.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <random>
#include <thread>

using namespace linoh;
using namespace linoh::multimodal;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL line %d: %s\n", __LINE__, #cond); } \
} while(0)

// ========== 1. TensorMeta 默认值 ==========
static void test_meta_default() {
    TensorMeta m;
    CHECK(m.tensor_id == 0);
    CHECK(m.total_shards == 0);
    CHECK(m.shard_idx == 0);
    CHECK(m.dtype == TensorDType::F32);
    CHECK(m.shape[0] == 0);
    CHECK(m.shape[1] == 0);
    CHECK(m.shape[2] == 0);
    CHECK(m.shape[3] == 0);
    CHECK(m.total_bytes == 0);
    CHECK(m.shard_bytes == 0);
    CHECK(m.is_last == false);
}

// ========== 2. TensorMeta 序列化大小 ==========
static void test_meta_serialize_size() {
    TensorMeta m;
    auto bytes = m.serialize();
    CHECK(bytes.size() == 48);
}

// ========== 3. TensorMeta 往返一致性 ==========
static void test_meta_roundtrip() {
    TensorMeta m;
    m.tensor_id = 0xABCDEF0123456789ULL;
    m.total_shards = 1600;
    m.shard_idx = 42;
    m.dtype = TensorDType::BF16;
    m.shape = {1, 3, 224, 224};
    m.total_bytes = 100 * 1024 * 1024;
    m.shard_bytes = 64 * 1024;
    m.is_last = true;

    auto bytes = m.serialize();
    CHECK(bytes.size() == 48);

    TensorMeta parsed;
    CHECK(TensorMeta::parse(bytes, parsed) == true);
    CHECK(parsed.tensor_id == 0xABCDEF0123456789ULL);
    CHECK(parsed.total_shards == 1600);
    CHECK(parsed.shard_idx == 42);
    CHECK(parsed.dtype == TensorDType::BF16);
    CHECK(parsed.shape[0] == 1);
    CHECK(parsed.shape[1] == 3);
    CHECK(parsed.shape[2] == 224);
    CHECK(parsed.shape[3] == 224);
    CHECK(parsed.total_bytes == 100 * 1024 * 1024);
    CHECK(parsed.shard_bytes == 64 * 1024);
    CHECK(parsed.is_last == true);
}

// ========== 4. TensorMeta parse 长度不足 ==========
static void test_meta_parse_short() {
    TensorMeta parsed;
    std::vector<std::uint8_t> empty;
    CHECK(TensorMeta::parse(empty, parsed) == false);

    std::vector<std::uint8_t> short_data(47, 0);
    CHECK(TensorMeta::parse(short_data, parsed) == false);
}

// ========== 5. TensorMeta 边界值 ==========
static void test_meta_boundary() {
    TensorMeta m;
    m.tensor_id = 0xFFFFFFFFFFFFFFFFULL;
    m.total_shards = 0xFFFFFFFF;
    m.shard_idx = 0xFFFFFFFE;
    m.dtype = TensorDType::I64;
    m.shape = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
    m.total_bytes = 0xFFFFFFFFFFFFFFFFULL;
    m.shard_bytes = 0xFFFFFFFF;
    m.is_last = true;

    auto bytes = m.serialize();
    TensorMeta parsed;
    CHECK(TensorMeta::parse(bytes, parsed) == true);
    CHECK(parsed.tensor_id == 0xFFFFFFFFFFFFFFFFULL);
    CHECK(parsed.total_shards == 0xFFFFFFFF);
    CHECK(parsed.shard_idx == 0xFFFFFFFE);
    CHECK(parsed.dtype == TensorDType::I64);
    CHECK(parsed.shape[0] == 0xFFFFFFFF);
    CHECK(parsed.total_bytes == 0xFFFFFFFFFFFFFFFFULL);
    CHECK(parsed.shard_bytes == 0xFFFFFFFF);
    CHECK(parsed.is_last == true);
}

// ========== 6. TensorShardMessage 序列化 ==========
static void test_shard_message_serialize() {
    TensorShardMessage msg;
    msg.meta.tensor_id = 0x1234;
    msg.meta.total_shards = 2;
    msg.meta.shard_idx = 0;
    msg.meta.dtype = TensorDType::F32;
    msg.meta.shape = {10, 10, 0, 0};
    msg.meta.total_bytes = 400;
    msg.meta.shard_bytes = 200;
    msg.meta.is_last = false;
    msg.data = std::vector<std::uint8_t>(200, 0xAB);

    auto bytes = msg.serialize();
    CHECK(bytes.size() == 48 + 200);

    TensorShardMessage parsed;
    CHECK(TensorShardMessage::parse(bytes, parsed) == true);
    CHECK(parsed.meta.tensor_id == 0x1234);
    CHECK(parsed.meta.total_shards == 2);
    CHECK(parsed.meta.shard_idx == 0);
    CHECK(parsed.meta.shard_bytes == 200);
    CHECK(parsed.data.size() == 200);
    CHECK(parsed.data[0] == 0xAB);
    CHECK(parsed.data[199] == 0xAB);
}

// ========== 7. TensorShardMessage parse 长度不足 ==========
static void test_shard_message_parse_short() {
    TensorShardMessage parsed;
    std::vector<std::uint8_t> short_data(48, 0);  // 头部够但 data 不够
    // 设置 shard_bytes=100，但 data 区只有 0 字节
    short_data[43] = 100;
    CHECK(TensorShardMessage::parse(short_data, parsed) == false);

    std::vector<std::uint8_t> empty;
    CHECK(TensorShardMessage::parse(empty, parsed) == false);
}

// ========== 8. TensorDType 枚举值 ==========
static void test_dtype_values() {
    CHECK(static_cast<int>(TensorDType::F32) == 0);
    CHECK(static_cast<int>(TensorDType::F16) == 1);
    CHECK(static_cast<int>(TensorDType::BF16) == 2);
    CHECK(static_cast<int>(TensorDType::I32) == 3);
    CHECK(static_cast<int>(TensorDType::U8) == 4);
}

// ========== 9. dtype_name ==========
static void test_dtype_name() {
    CHECK(std::string(dtype_name(TensorDType::F32)) == "f32");
    CHECK(std::string(dtype_name(TensorDType::F16)) == "f16");
    CHECK(std::string(dtype_name(TensorDType::BF16)) == "bf16");
    CHECK(std::string(dtype_name(TensorDType::U8)) == "u8");
}

// ========== 10. dtype_size ==========
static void test_dtype_size() {
    CHECK(dtype_size(TensorDType::F32) == 4);
    CHECK(dtype_size(TensorDType::F16) == 2);
    CHECK(dtype_size(TensorDType::BF16) == 2);
    CHECK(dtype_size(TensorDType::I32) == 4);
    CHECK(dtype_size(TensorDType::U8) == 1);
    CHECK(dtype_size(TensorDType::F64) == 8);
    CHECK(dtype_size(TensorDType::I64) == 8);
    CHECK(dtype_size(TensorDType::I8) == 1);
}

// ========== 11. TensorStreamer 默认构造 ==========
static void test_streamer_default() {
    TensorStreamer s;
    CHECK(s.shard_size() == 64 * 1024);
    CHECK(s.parallel_streams() == 4);
}

// ========== 12. TensorStreamer 自定义参数 ==========
static void test_streamer_custom() {
    TensorStreamer s(128 * 1024, 8);
    CHECK(s.shard_size() == 128 * 1024);
    CHECK(s.parallel_streams() == 8);
}

// ========== 13. TensorStreamer 零大小防御 ==========
static void test_streamer_zero_defense() {
    TensorStreamer s(0, 0);
    CHECK(s.shard_size() > 0);
    CHECK(s.parallel_streams() > 0);
}

// ========== 14. shard_count 整除 ==========
static void test_shard_count_exact() {
    TensorStreamer s(1024, 4);
    CHECK(s.shard_count(4096) == 4);
    CHECK(s.shard_count(8192) == 8);
}

// ========== 15. shard_count 非整除 ==========
static void test_shard_count_non_exact() {
    TensorStreamer s(1024, 4);
    CHECK(s.shard_count(4097) == 5);
    CHECK(s.shard_count(1) == 1);
    CHECK(s.shard_count(1023) == 1);
    CHECK(s.shard_count(1025) == 2);
}

// ========== 16. shard_count 0 字节 ==========
static void test_shard_count_zero() {
    TensorStreamer s(1024, 4);
    CHECK(s.shard_count(0) == 1);
}

// ========== 17. shard 1 字节 ==========
static void test_shard_one_byte() {
    TensorStreamer s(64 * 1024, 4);
    std::vector<std::uint8_t> data = {0xAA};
    auto shards = s.shard(100, data);
    CHECK(shards.size() == 1);
    CHECK(shards[0].meta.total_shards == 1);
    CHECK(shards[0].meta.shard_idx == 0);
    CHECK(shards[0].meta.shard_bytes == 1);
    CHECK(shards[0].meta.total_bytes == 1);
    CHECK(shards[0].meta.is_last == true);
    CHECK(shards[0].data.size() == 1);
    CHECK(shards[0].data[0] == 0xAA);
}

// ========== 18. shard 整除场景 ==========
static void test_shard_exact() {
    TensorStreamer s(100, 4);
    std::vector<std::uint8_t> data(500, 0xCC);
    auto shards = s.shard(200, data);
    CHECK(shards.size() == 5);
    for (std::size_t i = 0; i < 5; ++i) {
        CHECK(shards[i].meta.total_shards == 5);
        CHECK(shards[i].meta.shard_idx == i);
        CHECK(shards[i].meta.shard_bytes == 100);
        CHECK(shards[i].meta.total_bytes == 500);
        CHECK(shards[i].meta.is_last == (i == 4));
        CHECK(shards[i].data.size() == 100);
    }
}

// ========== 19. shard 非整除场景 ==========
static void test_shard_non_exact() {
    TensorStreamer s(100, 4);
    std::vector<std::uint8_t> data(503, 0xDD);
    auto shards = s.shard(300, data);
    CHECK(shards.size() == 6);
    for (std::size_t i = 0; i < 5; ++i) {
        CHECK(shards[i].meta.shard_bytes == 100);
        CHECK(shards[i].data.size() == 100);
        CHECK(shards[i].meta.is_last == false);
    }
    // 最后一片是 3 字节
    CHECK(shards[5].meta.shard_bytes == 3);
    CHECK(shards[5].data.size() == 3);
    CHECK(shards[5].meta.is_last == true);
}

// ========== 20. shard 空 tensor ==========
static void test_shard_empty() {
    TensorStreamer s(1024, 4);
    std::vector<std::uint8_t> data;
    auto shards = s.shard(400, data);
    CHECK(shards.size() == 1);
    CHECK(shards[0].meta.total_shards == 1);
    CHECK(shards[0].meta.total_bytes == 0);
    CHECK(shards[0].meta.shard_bytes == 0);
    CHECK(shards[0].meta.is_last == true);
    CHECK(shards[0].data.empty());
}

// ========== 21. shard 分片数据正确性 ==========
static void test_shard_data_correctness() {
    TensorStreamer s(50, 4);
    std::vector<std::uint8_t> data(125);
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i);

    auto shards = s.shard(500, data);
    CHECK(shards.size() == 3);

    // 重组验证
    std::vector<std::uint8_t> rebuilt;
    for (auto &s : shards) {
        rebuilt.insert(rebuilt.end(), s.data.begin(), s.data.end());
    }
    CHECK(rebuilt.size() == 125);
    CHECK(rebuilt == data);
}

// ========== 22. shard 元数据正确性 ==========
static void test_shard_meta_correctness() {
    TensorStreamer s(50, 4);
    std::vector<std::uint8_t> data(125, 0);
    auto shards = s.shard(600, data, TensorDType::F16, {1, 5, 5, 0});

    CHECK(shards.size() == 3);
    for (auto &s : shards) {
        CHECK(s.meta.tensor_id == 600);
        CHECK(s.meta.dtype == TensorDType::F16);
        CHECK(s.meta.shape[0] == 1);
        CHECK(s.meta.shape[1] == 5);
        CHECK(s.meta.shape[2] == 5);
        CHECK(s.meta.shape[3] == 0);
        CHECK(s.meta.total_bytes == 125);
    }
    CHECK(shards[0].meta.shard_idx == 0);
    CHECK(shards[1].meta.shard_idx == 1);
    CHECK(shards[2].meta.shard_idx == 2);
    CHECK(shards[0].meta.is_last == false);
    CHECK(shards[1].meta.is_last == false);
    CHECK(shards[2].meta.is_last == true);
}

// ========== 23. assign_streams 4 路均衡 ==========
static void test_assign_streams_balanced() {
    TensorStreamer s(100, 4);
    auto assignment = s.assign_streams(10);
    CHECK(assignment.size() == 4);
    // 10 个分片分配到 4 个 stream：3+3+2+2
    CHECK(assignment[0].size() == 3);
    CHECK(assignment[1].size() == 3);
    CHECK(assignment[2].size() == 2);
    CHECK(assignment[3].size() == 2);
    // 验证分片 idx 正确分配
    CHECK(assignment[0][0] == 0);
    CHECK(assignment[0][1] == 4);
    CHECK(assignment[0][2] == 8);
    CHECK(assignment[1][0] == 1);
    CHECK(assignment[3][0] == 3);
}

// ========== 24. assign_streams stream 数 > 分片数 ==========
static void test_assign_streams_more_streams_than_shards() {
    TensorStreamer s(100, 8);
    auto assignment = s.assign_streams(3);
    CHECK(assignment.size() == 8);
    int total = 0;
    for (auto &v : assignment) total += static_cast<int>(v.size());
    CHECK(total == 3);
    CHECK(assignment[0].size() == 1);
    CHECK(assignment[1].size() == 1);
    CHECK(assignment[2].size() == 1);
    CHECK(assignment[3].empty());
}

// ========== 25. Reassembler 顺序重组 ==========
static void test_reassemble_ordered() {
    TensorStreamer s(50, 4);
    std::vector<std::uint8_t> data(125);
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i);

    auto shards = s.shard(700, data);

    TensorReassembler reasm;
    std::vector<std::uint8_t> received;
    reasm.on_complete([&](std::uint64_t id, std::vector<std::uint8_t> d, TensorMeta) {
        CHECK(id == 700);
        received = std::move(d);
    });

    for (auto &sh : shards) {
        CHECK(reasm.on_shard(sh) == true);
    }
    CHECK(received.size() == 125);
    CHECK(received == data);
}

// ========== 26. Reassembler 乱序重组 ==========
static void test_reassemble_unordered() {
    TensorStreamer s(50, 4);
    std::vector<std::uint8_t> data(150);
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i + 1);

    auto shards = s.shard(800, data);
    // 打乱顺序
    std::vector<std::size_t> order = {2, 0, 1, 0};  // idx 顺序
    // shards 有 3 个
    CHECK(shards.size() == 3);

    TensorReassembler reasm;
    std::vector<std::uint8_t> received;
    bool cb_called = false;
    reasm.on_complete([&](std::uint64_t id, std::vector<std::uint8_t> d, TensorMeta) {
        CHECK(id == 800);
        received = std::move(d);
        cb_called = true;
    });

    // 乱序投递：先 2，再 0，再 1
    CHECK(reasm.on_shard(shards[2]) == true);
    CHECK(reasm.on_shard(shards[0]) == true);
    CHECK(cb_called == false);
    CHECK(reasm.on_shard(shards[1]) == true);
    CHECK(cb_called == true);
    CHECK(received.size() == 150);
    CHECK(received == data);
}

// ========== 27. Reassembler 重复分片去重 ==========
static void test_reassemble_duplicate() {
    TensorStreamer s(50, 4);
    std::vector<std::uint8_t> data(100, 0);
    auto shards = s.shard(900, data);
    CHECK(shards.size() == 2);

    TensorReassembler reasm;
    int cb_count = 0;
    reasm.on_complete([&](std::uint64_t, std::vector<std::uint8_t>, TensorMeta) {
        ++cb_count;
    });

    CHECK(reasm.on_shard(shards[0]) == true);
    // 重复投递 shard 0，应返回 false
    CHECK(reasm.on_shard(shards[0]) == false);
    CHECK(reasm.on_shard(shards[1]) == true);
    CHECK(cb_count == 1);
    // 完成后状态已清理，再次投递 shard 0 会被当作新 tensor 的第一个分片
    CHECK(reasm.on_shard(shards[0]) == true);
    // 清理新创建的状态
    reasm.cleanup(900);
}

// ========== 28. Reassembler 错误 shard_idx ==========
static void test_reassemble_invalid_shard_idx() {
    TensorShardMessage shard;
    shard.meta.tensor_id = 1000;
    shard.meta.total_shards = 2;
    shard.meta.shard_idx = 5;  // 越界
    shard.meta.shard_bytes = 0;
    shard.data = {};

    TensorReassembler reasm;
    CHECK(reasm.on_shard(shard) == false);
}

// ========== 29. Reassembler 多 tensor 并发 ==========
static void test_reassemble_multi_tensor() {
    TensorStreamer s(50, 4);
    std::vector<std::uint8_t> data1(100, 0xAA);
    std::vector<std::uint8_t> data2(125, 0xBB);

    auto shards1 = s.shard(1100, data1);
    auto shards2 = s.shard(1101, data2);

    TensorReassembler reasm;
    std::map<std::uint64_t, std::vector<std::uint8_t>> received;
    reasm.on_complete([&](std::uint64_t id, std::vector<std::uint8_t> d, TensorMeta) {
        received[id] = std::move(d);
    });

    // 交替投递
    CHECK(reasm.on_shard(shards1[0]) == true);
    CHECK(reasm.on_shard(shards2[0]) == true);
    CHECK(reasm.on_shard(shards1[1]) == true);  // tensor1 完成
    CHECK(reasm.on_shard(shards2[1]) == true);
    CHECK(reasm.on_shard(shards2[2]) == true);  // tensor2 完成

    CHECK(received.size() == 2);
    CHECK(received[1100] == data1);
    CHECK(received[1101] == data2);
}

// ========== 30. Reassembler 回调数据完整 ==========
static void test_reassemble_callback_integrity() {
    TensorStreamer s(1024, 4);
    // 用随机数据
    std::mt19937 rng(42);
    std::vector<std::uint8_t> data(5000);
    for (auto &b : data) b = static_cast<std::uint8_t>(rng());

    auto shards = s.shard(1200, data, TensorDType::BF16, {1, 100, 50, 0});

    TensorReassembler reasm;
    std::vector<std::uint8_t> received;
    TensorMeta received_meta;
    reasm.on_complete([&](std::uint64_t id, std::vector<std::uint8_t> d, TensorMeta m) {
        CHECK(id == 1200);
        received = std::move(d);
        received_meta = m;
    });

    for (auto &s : shards) reasm.on_shard(s);
    CHECK(received.size() == 5000);
    CHECK(received == data);
    CHECK(received_meta.dtype == TensorDType::BF16);
    CHECK(received_meta.shape[0] == 1);
    CHECK(received_meta.shape[1] == 100);
    CHECK(received_meta.shape[2] == 50);
    CHECK(received_meta.total_bytes == 5000);
}

// ========== 31. Reassembler progress ==========
static void test_reassemble_progress() {
    TensorStreamer s(50, 4);
    std::vector<std::uint8_t> data(150, 0);
    auto shards = s.shard(1300, data);
    CHECK(shards.size() == 3);

    TensorReassembler reasm;
    reasm.on_complete([](std::uint64_t, std::vector<std::uint8_t>, TensorMeta) {});

    CHECK(reasm.progress(1300) == 0.0f);
    reasm.on_shard(shards[0]);
    CHECK(reasm.progress(1300) > 0.32f);
    CHECK(reasm.progress(1300) < 0.35f);
    reasm.on_shard(shards[1]);
    CHECK(reasm.progress(1300) > 0.65f);
    CHECK(reasm.progress(1300) < 0.68f);
    reasm.on_shard(shards[2]);
    // 完成后状态已清理，progress 返回 0
    CHECK(reasm.progress(1300) == 0.0f);
}

// ========== 32. Reassembler cleanup/clear ==========
static void test_reassemble_cleanup() {
    TensorStreamer s(50, 4);
    std::vector<std::uint8_t> data(100, 0);
    auto shards = s.shard(1400, data);

    TensorReassembler reasm;
    reasm.on_complete([](std::uint64_t, std::vector<std::uint8_t>, TensorMeta) {});
    reasm.on_shard(shards[0]);
    CHECK(reasm.pending_count() == 1);
    CHECK(reasm.state(1400).has_value());

    reasm.cleanup(1400);
    CHECK(reasm.pending_count() == 0);
    CHECK(!reasm.state(1400).has_value());

    // 重新加数据然后 clear
    reasm.on_shard(shards[0]);
    reasm.on_shard(shards[0]);  // 重复，无效
    CHECK(reasm.pending_count() == 1);
    reasm.clear();
    CHECK(reasm.pending_count() == 0);
}

// ========== 33. Reassembler 无回调不崩溃 ==========
static void test_reassemble_no_callback() {
    TensorStreamer s(50, 4);
    std::vector<std::uint8_t> data(100, 0);
    auto shards = s.shard(1500, data);

    TensorReassembler reasm;  // 不设置回调
    CHECK(reasm.on_shard(shards[0]) == true);
    CHECK(reasm.on_shard(shards[1]) == true);  // 全部到齐，但因无回调不触发
    // 无回调时状态保留（便于上层查询），pending_count 仍为 1
    CHECK(reasm.pending_count() == 1);
    // 但可通过 state() 查询完整数据
    auto st = reasm.state(1500);
    CHECK(st.has_value());
    CHECK(st->shards.size() == 2);
}

// ========== 34. 100MB 大 tensor 分片 + 重组 ==========
static void test_large_tensor_100mb() {
    const std::size_t SIZE = 100 * 1024 * 1024;  // 100MB
    TensorStreamer s(64 * 1024, 4);  // 64KB 分片

    // 预期分片数：100MB / 64KB = 1600
    CHECK(s.shard_count(SIZE) == 1600);

    // 生成数据（用模式填充，避免分配 100MB 随机数）
    std::vector<std::uint8_t> data(SIZE);
    for (std::size_t i = 0; i < SIZE; ++i) {
        data[i] = static_cast<std::uint8_t>((i * 7) & 0xFF);
    }

    auto shards = s.shard(2000, data, TensorDType::F32, {1, 1, 100, 1024});
    CHECK(shards.size() == 1600);

    // 验证每个分片元数据
    for (std::size_t i = 0; i < shards.size(); ++i) {
        CHECK(shards[i].meta.tensor_id == 2000);
        CHECK(shards[i].meta.total_shards == 1600);
        CHECK(shards[i].meta.shard_idx == i);
        CHECK(shards[i].meta.total_bytes == SIZE);
        if (i < shards.size() - 1) {
            CHECK(shards[i].meta.shard_bytes == 64 * 1024);
            CHECK(shards[i].meta.is_last == false);
        } else {
            CHECK(shards[i].meta.is_last == true);
        }
    }

    // 重组（乱序）
    TensorReassembler reasm;
    std::vector<std::uint8_t> received;
    bool cb_called = false;
    reasm.on_complete([&](std::uint64_t id, std::vector<std::uint8_t> d, TensorMeta) {
        CHECK(id == 2000);
        received = std::move(d);
        cb_called = true;
    });

    // 乱序投递
    std::mt19937 rng(123);
    std::vector<std::size_t> order(shards.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::shuffle(order.begin(), order.end(), rng);

    for (std::size_t idx : order) {
        reasm.on_shard(shards[idx]);
    }
    CHECK(cb_called == true);
    CHECK(received.size() == SIZE);
    CHECK(received == data);
}

// ========== 35. round-trip 完整流程 ==========
static void test_round_trip() {
    TensorStreamer s(32, 2);  // 32 字节分片，2 stream
    std::vector<std::uint8_t> data(100);
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i);

    // 1. 分片
    auto shards = s.shard(3000, data, TensorDType::F16, {10, 5, 0, 0});
    CHECK(shards.size() == 4);  // 100 / 32 = 3.125 → 4

    // 2. 序列化每个分片
    std::vector<std::vector<std::uint8_t>> wire_data;
    for (auto &s : shards) {
        wire_data.push_back(s.serialize());
    }

    // 3. 反序列化
    std::vector<TensorShardMessage> parsed_shards;
    for (auto &w : wire_data) {
        TensorShardMessage msg;
        CHECK(TensorShardMessage::parse(w, msg) == true);
        parsed_shards.push_back(msg);
    }

    // 4. 重组
    TensorReassembler reasm;
    std::vector<std::uint8_t> received;
    reasm.on_complete([&](std::uint64_t id, std::vector<std::uint8_t> d, TensorMeta m) {
        CHECK(id == 3000);
        CHECK(m.dtype == TensorDType::F16);
        CHECK(m.shape[0] == 10);
        CHECK(m.shape[1] == 5);
        received = std::move(d);
    });

    for (auto &s : parsed_shards) {
        reasm.on_shard(s);
    }
    CHECK(received.size() == 100);
    CHECK(received == data);
}

// ============================================================================
// mp-P9 分桶锁并发测试（v1.7.0.9）
//   验证 16 桶独立 mutex 在多线程并发下的正确性与无死锁
// ============================================================================

// ========== 36. 并发重组多个 tensor（不同桶，验证并行性）==========
//   8 线程 × 20 tensor，tensor_id 跨多桶，验证全部正确重组
static void test_concurrent_multi_tensor() {
    TensorStreamer s(64, 4);
    constexpr int kThreads = 8;
    constexpr int kTensorsPerThread = 20;

    TensorReassembler reasm;
    std::atomic<int> completed_count{0};
    std::mutex recv_mu;
    std::map<std::uint64_t, std::vector<std::uint8_t>> received;

    reasm.on_complete([&](std::uint64_t id, std::vector<std::uint8_t> d, TensorMeta) {
        std::lock_guard<std::mutex> lk(recv_mu);
        received[id] = std::move(d);
        completed_count.fetch_add(1, std::memory_order_relaxed);
    });

    std::vector<std::thread> threads;
    std::vector<std::map<std::uint64_t, std::vector<std::uint8_t>>> expected(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < kTensorsPerThread; ++i) {
                // tensor_id 跨多桶（% 16 分布均匀）
                std::uint64_t tid = static_cast<std::uint64_t>(t) * 1000 + i + 5000;
                std::size_t sz = 64 + i * 10;  // 数据大小各异
                std::vector<std::uint8_t> data(sz);
                for (std::size_t b = 0; b < sz; ++b) {
                    data[b] = static_cast<std::uint8_t>(tid + b);
                }
                expected[t][tid] = data;
                auto shards = s.shard(tid, data);
                for (auto &sh : shards) {
                    reasm.on_shard(sh);
                }
            }
        });
    }

    for (auto &th : threads) th.join();

    CHECK(completed_count.load() == kThreads * kTensorsPerThread);
    for (int t = 0; t < kThreads; ++t) {
        for (auto &kv : expected[t]) {
            CHECK(received.count(kv.first) == 1);
            CHECK(received[kv.first] == kv.second);
        }
    }
}

// ========== 37. 并发投递同一 tensor 的分片（同桶串行化）==========
//   10 线程各投递 1 个分片到同一 tensor（同桶），验证正确重组 + 回调仅一次
static void test_concurrent_same_tensor() {
    TensorStreamer s(32, 4);
    const std::uint64_t tid = 99999;
    std::vector<std::uint8_t> data(320);  // 10 个分片 × 32B
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i);

    auto shards = s.shard(tid, data);
    CHECK(shards.size() == 10);

    TensorReassembler reasm;
    std::atomic<int> cb_count{0};
    std::vector<std::uint8_t> received;
    std::mutex recv_mu;

    reasm.on_complete([&](std::uint64_t id, std::vector<std::uint8_t> d, TensorMeta) {
        CHECK(id == tid);
        std::lock_guard<std::mutex> lk(recv_mu);
        received = std::move(d);
        cb_count.fetch_add(1, std::memory_order_relaxed);
    });

    // 10 线程并发投递同一 tensor 的不同分片（路由到同一桶，桶锁串行化）
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&, i]() {
            reasm.on_shard(shards[i]);
        });
    }
    for (auto &th : threads) th.join();

    CHECK(cb_count.load() == 1);
    CHECK(received == data);
}

// ========== 38. 并发 on_shard + run_auto_cleanup（死锁/崩溃检测）==========
//   一线程持续投递，一线程持续清理，运行 500ms 不死锁不崩溃
static void test_concurrent_cleanup() {
    TensorStreamer s(32, 4);
    TensorReassembler reasm;
    // 短超时，确保清理线程能实际清理到部分 tensor
    reasm.set_auto_cleanup_timeout_ms(std::chrono::milliseconds(50));

    std::atomic<bool> stop{false};
    std::atomic<int> shard_count{0};

    reasm.on_complete([](std::uint64_t, std::vector<std::uint8_t>, TensorMeta) {});

    // 投递线程：持续投递完整 tensor
    std::thread feeder([&]() {
        std::uint64_t tid = 100000;
        while (!stop.load(std::memory_order_relaxed)) {
            std::vector<std::uint8_t> data(64);
            auto shards = s.shard(tid, data);
            for (auto &sh : shards) {
                reasm.on_shard(sh);
                shard_count.fetch_add(1, std::memory_order_relaxed);
            }
            ++tid;
        }
    });

    // 清理线程：持续触发手动清理
    std::thread cleaner([&]() {
        while (!stop.load(std::memory_order_relaxed)) {
            reasm.run_auto_cleanup();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });

    // 运行 500ms
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    stop.store(true, std::memory_order_relaxed);

    feeder.join();
    cleaner.join();

    // 只要不死锁、不崩溃、有投递操作即通过
    CHECK(shard_count.load() > 0);
}

// ========== 39. 并发查询 + 投递（死锁/崩溃检测）==========
//   一线程投递，一线程并发 pending_count/progress 查询，验证无死锁
static void test_concurrent_query() {
    TensorStreamer s(32, 4);
    TensorReassembler reasm;

    std::atomic<bool> stop{false};
    std::atomic<int> ops{0};

    reasm.on_complete([](std::uint64_t, std::vector<std::uint8_t>, TensorMeta) {});

    // 投递线程
    std::thread feeder([&]() {
        std::uint64_t tid = 200000;
        while (!stop.load(std::memory_order_relaxed)) {
            std::vector<std::uint8_t> data(96);
            auto shards = s.shard(tid, data);
            for (auto &sh : shards) {
                reasm.on_shard(sh);
                ops.fetch_add(1, std::memory_order_relaxed);
            }
            ++tid;
        }
    });

    // 查询线程：并发 pending_count + progress
    std::thread querier([&]() {
        while (!stop.load(std::memory_order_relaxed)) {
            reasm.pending_count();
            reasm.progress(200000);
            ops.fetch_add(1, std::memory_order_relaxed);
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    stop.store(true, std::memory_order_relaxed);

    feeder.join();
    querier.join();

    CHECK(ops.load() > 0);
}

int main() {
    std::printf("=== test_tensor_stream ===\n");

    test_meta_default();
    test_meta_serialize_size();
    test_meta_roundtrip();
    test_meta_parse_short();
    test_meta_boundary();
    test_shard_message_serialize();
    test_shard_message_parse_short();
    test_dtype_values();
    test_dtype_name();
    test_dtype_size();
    test_streamer_default();
    test_streamer_custom();
    test_streamer_zero_defense();
    test_shard_count_exact();
    test_shard_count_non_exact();
    test_shard_count_zero();
    test_shard_one_byte();
    test_shard_exact();
    test_shard_non_exact();
    test_shard_empty();
    test_shard_data_correctness();
    test_shard_meta_correctness();
    test_assign_streams_balanced();
    test_assign_streams_more_streams_than_shards();
    test_reassemble_ordered();
    test_reassemble_unordered();
    test_reassemble_duplicate();
    test_reassemble_invalid_shard_idx();
    test_reassemble_multi_tensor();
    test_reassemble_callback_integrity();
    test_reassemble_progress();
    test_reassemble_cleanup();
    test_reassemble_no_callback();
    test_large_tensor_100mb();
    test_round_trip();

    // mp-P9 分桶锁并发测试
    test_concurrent_multi_tensor();
    test_concurrent_same_tensor();
    test_concurrent_cleanup();
    test_concurrent_query();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
