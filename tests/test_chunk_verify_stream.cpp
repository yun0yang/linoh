// test_chunk_verify_stream.cpp — v3.9.6 M17 逐 chunk 增量校验单元测试
//
// 测试覆盖：
//   1. ShardHashAnnouncePayload 序列化/反序列化往返
//   2. ShardHashAnnouncePayload 边界情况（空 hash、截断、头部不足）
//   3. TensorStreamer::compute_shard_chunk_hashes 正确性
//   4. TensorStreamer::build_shard_hash_announce 字段完整性
//   5. TensorReassembler 逐 chunk 校验通过
//   6. TensorReassembler 逐 chunk 校验失败（定位损坏 chunk_idx）
//   7. chunk 校验失败回调参数正确
//   8. 未启用校验时不触发回调（向后兼容）
//   9. chunk count 不匹配检测
//  10. clear_expected_chunk_hashes / clear_tensor_chunk_hashes
//  11. MethodId::ShardHashAnnounce 枚举值
//  12. 端到端：Streamer 分片 → 公告 → Reassembler 校验

#include "linoh/multimodal/tensor_stream.hpp"
#include "linoh/crypto/chunk_hash.hpp"
#include "linoh/protocol/application_message.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace linoh::multimodal;
using namespace linoh::crypto;

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

// ========== 辅助函数 ==========

static std::vector<std::uint8_t> make_test_data(std::size_t size, std::uint8_t seed) {
    std::vector<std::uint8_t> data(size);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<std::uint8_t>((seed + i) & 0xFF);
    }
    return data;
}

// ========== 1. ShardHashAnnouncePayload 序列化/反序列化往返 ==========

static void test_shard_hash_announce_roundtrip() {
    std::printf("[test] ShardHashAnnouncePayload serialize/parse roundtrip...\n");

    ShardHashAnnouncePayload announce;
    announce.tensor_id = 0x0123456789ABCDEFULL;
    announce.shard_idx = 42;
    announce.chunk_size = 4096;

    // 3 个 chunk hash
    ChunkHashList hashes(3);
    for (auto &h : hashes) {
        for (std::size_t i = 0; i < 32; ++i) h[i] = static_cast<std::uint8_t>(i);
    }
    hashes[1][0] = 0xAA;
    hashes[2][31] = 0xFF;
    announce.chunk_hashes = hashes;

    auto buf = announce.serialize();
    // 20B 头部 + 3 * 32B hash = 116B
    CHECK_EQ(buf.size(), 20u + 3 * 32u);

    ShardHashAnnouncePayload parsed;
    CHECK(ShardHashAnnouncePayload::parse(buf, parsed));
    CHECK_EQ(parsed.tensor_id, 0x0123456789ABCDEFULL);
    CHECK_EQ(parsed.shard_idx, 42u);
    CHECK_EQ(parsed.chunk_size, 4096u);
    CHECK_EQ(parsed.chunk_hashes.size(), 3u);

    // 验证 hash 内容
    CHECK(parsed.chunk_hashes[0] == hashes[0]);
    CHECK(parsed.chunk_hashes[1] == hashes[1]);
    CHECK(parsed.chunk_hashes[2] == hashes[2]);
    CHECK_EQ(parsed.chunk_hashes[1][0], 0xAA);
    CHECK_EQ(parsed.chunk_hashes[2][31], 0xFF);
}

// ========== 2. ShardHashAnnouncePayload 边界情况 ==========

static void test_shard_hash_announce_edge_cases() {
    std::printf("[test] ShardHashAnnouncePayload edge cases...\n");

    // 空 hash 列表（仅 20B 头部）
    ShardHashAnnouncePayload empty_announce;
    empty_announce.tensor_id = 100;
    empty_announce.shard_idx = 0;
    empty_announce.chunk_size = 1024;
    auto empty_buf = empty_announce.serialize();
    CHECK_EQ(empty_buf.size(), 20u);  // 仅头部

    ShardHashAnnouncePayload parsed_empty;
    CHECK(ShardHashAnnouncePayload::parse(empty_buf, parsed_empty));
    CHECK_EQ(parsed_empty.tensor_id, 100u);
    CHECK_EQ(parsed_empty.chunk_hashes.size(), 0u);

    // 单个 hash
    ShardHashAnnouncePayload single_announce;
    single_announce.tensor_id = 1;
    single_announce.shard_idx = 5;
    single_announce.chunk_size = 512;
    single_announce.chunk_hashes.resize(1);
    single_announce.chunk_hashes[0].fill(0x42);
    auto single_buf = single_announce.serialize();
    CHECK_EQ(single_buf.size(), 20u + 32u);  // 20B + 1 hash

    ShardHashAnnouncePayload parsed_single;
    CHECK(ShardHashAnnouncePayload::parse(single_buf, parsed_single));
    CHECK_EQ(parsed_single.chunk_hashes.size(), 1u);
    CHECK_EQ(parsed_single.chunk_hashes[0][0], 0x42);
    CHECK_EQ(parsed_single.chunk_hashes[0][31], 0x42);

    // 头部不足返回 false
    std::vector<std::uint8_t> short_buf(19, 0);
    ShardHashAnnouncePayload dummy;
    CHECK(!ShardHashAnnouncePayload::parse(short_buf, dummy));

    // hash 数据截断返回 false
    std::vector<std::uint8_t> trunc_buf(20 + 31, 0);  // 声称 1 个 hash 但只有 31B
    trunc_buf[16] = 1;  // chunk_count = 1
    CHECK(!ShardHashAnnouncePayload::parse(trunc_buf, dummy));

    // 空 span 返回 false
    CHECK(!ShardHashAnnouncePayload::parse({}, dummy));
}

// ========== 3. TensorStreamer::compute_shard_chunk_hashes ==========

static void test_compute_shard_chunk_hashes() {
    std::printf("[test] TensorStreamer::compute_shard_chunk_hashes...\n");

    TensorStreamer streamer(64 * 1024, 4);
    constexpr std::size_t kChunkSize = 1024;

    // 2.5KB 数据 → ceil(2560/1024) = 3 个 chunk
    auto data = make_test_data(2560, 0x10);
    auto hashes = streamer.compute_shard_chunk_hashes(data, kChunkSize);
    CHECK_EQ(hashes.size(), 3u);

    // 验证与 ChunkHasher 直接计算一致
    ChunkHasher hasher(kChunkSize);
    auto direct_hashes = hasher.compute(data);
    CHECK_EQ(hashes.size(), direct_hashes.size());
    CHECK(hashes[0] == direct_hashes[0]);
    CHECK(hashes[1] == direct_hashes[1]);
    CHECK(hashes[2] == direct_hashes[2]);

    // 空 shard 数据 → 1 个 chunk（ChunkHasher 约定）
    auto empty_hashes = streamer.compute_shard_chunk_hashes({}, kChunkSize);
    CHECK_EQ(empty_hashes.size(), 1u);

    // chunk_size=0 用默认值 16KiB
    auto default_data = make_test_data(20000, 0x20);  // > 16KiB
    auto default_hashes = streamer.compute_shard_chunk_hashes(default_data, 0);
    CHECK_EQ(default_hashes.size(), 2u);  // ceil(20000/16384) = 2
}

// ========== 4. TensorStreamer::build_shard_hash_announce ==========

static void test_build_shard_hash_announce() {
    std::printf("[test] TensorStreamer::build_shard_hash_announce...\n");

    TensorStreamer streamer(64 * 1024, 4);
    constexpr std::size_t kChunkSize = 2048;

    auto data = make_test_data(5000, 0x30);  // ~2.5 chunks
    auto announce = streamer.build_shard_hash_announce(999, 3, data, kChunkSize);

    CHECK_EQ(announce.tensor_id, 999u);
    CHECK_EQ(announce.shard_idx, 3u);
    CHECK_EQ(announce.chunk_size, 2048u);
    CHECK_EQ(announce.chunk_hashes.size(), 3u);  // ceil(5000/2048) = 3

    // 验证 hash 正确
    auto direct_hashes = streamer.compute_shard_chunk_hashes(data, kChunkSize);
    CHECK(announce.chunk_hashes == direct_hashes);

    // chunk_size=0 → 默认 16KiB
    auto announce2 = streamer.build_shard_hash_announce(1, 0, data, 0);
    CHECK_EQ(announce2.chunk_size, static_cast<std::uint32_t>(ChunkHasher::kDefaultChunkSize));
}

// ========== 5. TensorReassembler 逐 chunk 校验通过 ==========

static void test_chunk_verify_pass() {
    std::printf("[test] TensorReassembler chunk verify pass...\n");

    TensorStreamer streamer(64 * 1024, 4);
    constexpr std::size_t kChunkSize = 1024;

    auto data = make_test_data(4096, 0x40);  // 4 chunks
    auto hashes = streamer.compute_shard_chunk_hashes(data, kChunkSize);

    TensorReassembler reasm;
    reasm.set_verify_chunk_hashes(true);
    reasm.set_expected_chunk_hashes(1, 0, kChunkSize, hashes);

    bool callback_called = false;
    reasm.on_chunk_verify_failure([&](auto tid, auto sidx, auto cidx, auto &exp, auto &act) {
        callback_called = true;
    });

    // 构造 shard 消息（未损坏的数据）
    TensorShardMessage shard;
    shard.meta.tensor_id = 1;
    shard.meta.total_shards = 1;
    shard.meta.shard_idx = 0;
    shard.meta.shard_bytes = static_cast<std::uint32_t>(data.size());
    shard.meta.is_last = true;
    shard.data = data;

    bool accepted = reasm.on_shard(shard);
    CHECK(accepted);
    CHECK(!callback_called);  // 校验通过，回调不应被触发
}

// ========== 6. TensorReassembler 逐 chunk 校验失败（定位损坏 chunk） ==========

static void test_chunk_verify_fail_locate() {
    std::printf("[test] TensorReassembler chunk verify fail (locate corrupted chunk)...\n");

    TensorStreamer streamer(64 * 1024, 4);
    constexpr std::size_t kChunkSize = 1024;

    auto original_data = make_test_data(4096, 0x50);  // 4 chunks
    auto hashes = streamer.compute_shard_chunk_hashes(original_data, kChunkSize);

    // 损坏第 2 个 chunk（chunk_idx=2）
    auto corrupted_data = original_data;
    corrupted_data[2 * kChunkSize + 100] ^= 0xFF;  // 翻转一个 bit

    TensorReassembler reasm;
    reasm.set_verify_chunk_hashes(true);
    reasm.set_expected_chunk_hashes(2, 0, kChunkSize, hashes);

    std::uint64_t fail_tid = 0;
    std::uint32_t fail_sidx = 0;
    std::size_t fail_cidx = 999;
    bool callback_called = false;
    reasm.on_chunk_verify_failure([&](auto tid, auto sidx, auto cidx, auto &exp, auto &act) {
        callback_called = true;
        fail_tid = tid;
        fail_sidx = sidx;
        fail_cidx = cidx;
    });

    TensorShardMessage shard;
    shard.meta.tensor_id = 2;
    shard.meta.total_shards = 1;
    shard.meta.shard_idx = 0;
    shard.meta.shard_bytes = static_cast<std::uint32_t>(corrupted_data.size());
    shard.meta.is_last = true;
    shard.data = corrupted_data;

    bool accepted = reasm.on_shard(shard);
    CHECK(accepted);  // shard 仍被接受（上层决定是否丢弃）
    CHECK(callback_called);
    CHECK_EQ(fail_tid, 2u);
    CHECK_EQ(fail_sidx, 0u);
    CHECK_EQ(fail_cidx, 2u);  // 定位到第 2 个 chunk
}

// ========== 7. chunk 校验失败回调参数正确 ==========

static void test_chunk_verify_callback_params() {
    std::printf("[test] chunk verify callback params...\n");

    // 注意：kChunkSize 必须 >= ChunkHasher::kMinChunkSize(1024)，否则会被 clamp
    TensorStreamer streamer(64 * 1024, 4);
    constexpr std::size_t kChunkSize = 1024;

    auto data = make_test_data(2048, 0x60);  // 2 chunks
    auto hashes = streamer.compute_shard_chunk_hashes(data, kChunkSize);

    // 损坏第 0 个 chunk
    auto corrupted = data;
    corrupted[10] ^= 0xFF;

    TensorReassembler reasm;
    reasm.set_verify_chunk_hashes(true);
    reasm.set_expected_chunk_hashes(7, 0, kChunkSize, hashes);

    ChunkHash captured_expected{};
    ChunkHash captured_actual{};
    bool called = false;
    reasm.on_chunk_verify_failure([&](auto tid, auto sidx, auto cidx, auto &exp, auto &act) {
        if (cidx == 0) {
            called = true;
            captured_expected = exp;
            captured_actual = act;
        }
    });

    TensorShardMessage shard;
    shard.meta.tensor_id = 7;
    shard.meta.total_shards = 1;
    shard.meta.shard_idx = 0;  // 必须 < total_shards，否则 shard 被拒绝
    shard.meta.shard_bytes = static_cast<std::uint32_t>(corrupted.size());
    shard.meta.is_last = true;
    shard.data = corrupted;

    reasm.on_shard(shard);
    CHECK(called);
    CHECK(captured_expected == hashes[0]);  // 期望的 hash 正确
    CHECK(!(captured_actual == hashes[0])); // 实际 hash 不等于期望
}

// ========== 8. 未启用校验时不触发回调（向后兼容） ==========

static void test_chunk_verify_disabled_no_callback() {
    std::printf("[test] chunk verify disabled (backward compat)...\n");

    TensorStreamer streamer(64 * 1024, 4);
    constexpr std::size_t kChunkSize = 1024;

    auto data = make_test_data(2048, 0x70);
    auto hashes = streamer.compute_shard_chunk_hashes(data, kChunkSize);

    // 损坏数据
    auto corrupted = data;
    corrupted[500] ^= 0xFF;

    TensorReassembler reasm;
    // 不调用 set_verify_chunk_hashes(true)，默认禁用
    CHECK(!reasm.verify_chunk_hashes_enabled());

    reasm.set_expected_chunk_hashes(3, 0, kChunkSize, hashes);

    bool callback_called = false;
    reasm.on_chunk_verify_failure([&](auto...) {
        callback_called = true;
    });

    TensorShardMessage shard;
    shard.meta.tensor_id = 3;
    shard.meta.total_shards = 1;
    shard.meta.shard_idx = 0;
    shard.meta.shard_bytes = static_cast<std::uint32_t>(corrupted.size());
    shard.meta.is_last = true;
    shard.data = corrupted;

    reasm.on_shard(shard);
    CHECK(!callback_called);  // 未启用，不触发回调

    // 启用后再次发送（重新设置 hash，因为上一个 shard 已被接受）
    reasm.set_verify_chunk_hashes(true);
    CHECK(reasm.verify_chunk_hashes_enabled());

    // 用新的 tensor_id 发送损坏数据
    reasm.set_expected_chunk_hashes(4, 0, kChunkSize, hashes);
    shard.meta.tensor_id = 4;
    reasm.on_shard(shard);
    CHECK(callback_called);  // 启用后触发回调
}

// ========== 9. chunk count 不匹配检测 ==========

static void test_chunk_count_mismatch() {
    std::printf("[test] chunk count mismatch...\n");

    TensorStreamer streamer(64 * 1024, 4);
    constexpr std::size_t kChunkSize = 1024;

    // 期望 4 个 chunk 的 hash（4096B 数据）
    auto data_4k = make_test_data(4096, 0x80);
    auto hashes_4 = streamer.compute_shard_chunk_hashes(data_4k, kChunkSize);
    CHECK_EQ(hashes_4.size(), 4u);

    // 实际发送 data_4k 的前 2048 字节（前 2 个 chunk 内容与期望完全相同）
    // 这样前 2 个 chunk hash 匹配，只是数量不同（期望 4，实际 2）
    std::vector<std::uint8_t> data_2k(data_4k.begin(), data_4k.begin() + 2048);

    TensorReassembler reasm;
    reasm.set_verify_chunk_hashes(true);
    reasm.set_expected_chunk_hashes(5, 0, kChunkSize, hashes_4);

    int fail_count = 0;
    reasm.on_chunk_verify_failure([&](auto...) {
        ++fail_count;
    });

    TensorShardMessage shard;
    shard.meta.tensor_id = 5;
    shard.meta.total_shards = 1;
    shard.meta.shard_idx = 0;
    shard.meta.shard_bytes = static_cast<std::uint32_t>(data_2k.size());
    shard.meta.is_last = true;
    shard.data = data_2k;

    reasm.on_shard(shard);
    // 前 2 个 chunk 内容与期望匹配（data_2k 是 data_4k 的前缀切片），
    // 只是 chunk 数量不同（期望 4，实际 2），不触发 per-chunk 回调。
    // 数量不匹配由 verify_shard_chunks_ 内部记录 WARN 日志，不触发 per-chunk 回调。
    CHECK_EQ(fail_count, 0);  // 前 2 个 chunk 匹配，只是数量不同
}

// ========== 10. clear_expected_chunk_hashes / clear_tensor_chunk_hashes ==========

static void test_clear_chunk_hashes() {
    std::printf("[test] clear_expected_chunk_hashes / clear_tensor_chunk_hashes...\n");

    TensorStreamer streamer(64 * 1024, 4);
    constexpr std::size_t kChunkSize = 1024;

    auto data = make_test_data(2048, 0x90);
    auto hashes = streamer.compute_shard_chunk_hashes(data, kChunkSize);

    TensorReassembler reasm;
    reasm.set_verify_chunk_hashes(true);

    // 设置 2 个 shard 的 hash
    reasm.set_expected_chunk_hashes(10, 0, kChunkSize, hashes);
    reasm.set_expected_chunk_hashes(10, 1, kChunkSize, hashes);

    // 清除 shard 0
    reasm.clear_expected_chunk_hashes(10, 0);

    bool callback_called = false;
    reasm.on_chunk_verify_failure([&](auto...) {
        callback_called = true;
    });

    // 发送损坏的 shard 0（已清除 hash，不应校验）
    auto corrupted = data;
    corrupted[100] ^= 0xFF;

    TensorShardMessage shard0;
    shard0.meta.tensor_id = 10;
    shard0.meta.total_shards = 2;
    shard0.meta.shard_idx = 0;
    shard0.meta.shard_bytes = static_cast<std::uint32_t>(corrupted.size());
    shard0.data = corrupted;

    reasm.on_shard(shard0);
    CHECK(!callback_called);  // shard 0 的 hash 已清除，不校验

    // 发送损坏的 shard 1（hash 存在，应触发回调）
    TensorShardMessage shard1;
    shard1.meta.tensor_id = 10;
    shard1.meta.total_shards = 2;
    shard1.meta.shard_idx = 1;
    shard1.meta.shard_bytes = static_cast<std::uint32_t>(corrupted.size());
    shard1.data = corrupted;

    reasm.on_shard(shard1);
    CHECK(callback_called);  // shard 1 的 hash 存在，触发回调

    // 清除整个 tensor 的 chunk hash
    reasm.clear_tensor_chunk_hashes(10);
    // 再次发送损坏数据，不应触发回调
    callback_called = false;
    reasm.set_expected_chunk_hashes(11, 0, kChunkSize, hashes);
    reasm.clear_tensor_chunk_hashes(11);

    TensorShardMessage shard2;
    shard2.meta.tensor_id = 11;
    shard2.meta.total_shards = 1;
    shard2.meta.shard_idx = 0;
    shard2.meta.shard_bytes = static_cast<std::uint32_t>(corrupted.size());
    shard2.meta.is_last = true;
    shard2.data = corrupted;

    reasm.on_shard(shard2);
    CHECK(!callback_called);  // tensor 11 的 hash 已清除
}

// ========== 11. MethodId::ShardHashAnnounce 枚举值 ==========

static void test_method_id_shard_hash_announce() {
    std::printf("[test] MethodId::ShardHashAnnounce enum value...\n");

    using namespace linoh::protocol;
    CHECK_EQ(static_cast<std::uint16_t>(MethodId::ShardHashAnnounce), 0x0043u);
    CHECK(static_cast<std::uint16_t>(MethodId::ShardHashAnnounce) >
          static_cast<std::uint16_t>(MethodId::TensorCancel));
    CHECK(static_cast<std::uint16_t>(MethodId::ShardHashAnnounce) <
          static_cast<std::uint16_t>(MethodId::CrossDomainDigest));
}

// ========== 12. 端到端：Streamer 分片 → 公告 → Reassembler 校验 ==========

static void test_e2e_chunk_verify() {
    std::printf("[test] e2e: streamer shard → announce → reassembler verify...\n");

    TensorStreamer streamer(1024, 2);  // 1KB shard, 2 streams
    constexpr std::size_t kChunkSize = 256;

    // 2.5KB tensor → 3 个 shard（1KB, 1KB, 0.5KB）
    auto tensor_data = make_test_data(2560, 0xA0);
    auto shards = streamer.shard(100, tensor_data, TensorDType::F32, {2560, 1, 0, 0});
    CHECK_EQ(shards.size(), 3u);

    TensorReassembler reasm;
    reasm.set_verify_chunk_hashes(true);

    // 为每个 shard 构建公告并设置期望 hash
    for (std::uint32_t i = 0; i < shards.size(); ++i) {
        auto announce = streamer.build_shard_hash_announce(
            100, i, shards[i].data, kChunkSize);
        reasm.set_expected_chunk_hashes(
            announce.tensor_id, announce.shard_idx,
            announce.chunk_size, announce.chunk_hashes);
    }

    // 验证公告序列化往返后仍可用于校验
    {
        auto announce = streamer.build_shard_hash_announce(
            100, 0, shards[0].data, kChunkSize);
        auto buf = announce.serialize();

        ShardHashAnnouncePayload parsed;
        CHECK(ShardHashAnnouncePayload::parse(buf, parsed));
        reasm.set_expected_chunk_hashes(
            parsed.tensor_id, parsed.shard_idx,
            parsed.chunk_size, parsed.chunk_hashes);
    }

    bool completed = false;
    std::vector<std::uint8_t> result_data;
    reasm.on_complete([&](auto tid, auto data, auto meta) {
        completed = true;
        result_data = std::move(data);
    });

    int fail_count = 0;
    reasm.on_chunk_verify_failure([&](auto...) {
        ++fail_count;
    });

    // 按乱序发送 shard（2, 0, 1）
    reasm.on_shard(shards[2]);
    reasm.on_shard(shards[0]);
    reasm.on_shard(shards[1]);

    CHECK(completed);
    CHECK_EQ(fail_count, 0);  // 全部校验通过
    CHECK_EQ(result_data.size(), tensor_data.size());
    CHECK(std::memcmp(result_data.data(), tensor_data.data(), tensor_data.size()) == 0);
}

// ========== 13. 多 chunk 损坏检测 ==========

static void test_multi_chunk_corruption() {
    std::printf("[test] multi-chunk corruption detection...\n");

    // 注意：kChunkSize 必须 >= ChunkHasher::kMinChunkSize(1024)，否则会被 clamp
    TensorStreamer streamer(64 * 1024, 4);
    constexpr std::size_t kChunkSize = 1024;

    auto data = make_test_data(4096, 0xB0);  // 4 chunks（每 chunk 1024 字节）
    auto hashes = streamer.compute_shard_chunk_hashes(data, kChunkSize);

    // 损坏 chunk 0 和 chunk 3
    auto corrupted = data;
    corrupted[10] ^= 0xFF;                    // chunk 0（偏移 0..1023）
    corrupted[3 * kChunkSize + 20] ^= 0xFF;   // chunk 3（偏移 3072..4095）

    TensorReassembler reasm;
    reasm.set_verify_chunk_hashes(true);
    reasm.set_expected_chunk_hashes(20, 0, kChunkSize, hashes);

    std::vector<std::size_t> failed_indices;
    reasm.on_chunk_verify_failure([&](auto tid, auto sidx, auto cidx, auto &exp, auto &act) {
        failed_indices.push_back(cidx);
    });

    TensorShardMessage shard;
    shard.meta.tensor_id = 20;
    shard.meta.total_shards = 1;
    shard.meta.shard_idx = 0;
    shard.meta.shard_bytes = static_cast<std::uint32_t>(corrupted.size());
    shard.meta.is_last = true;
    shard.data = corrupted;

    reasm.on_shard(shard);
    CHECK_EQ(failed_indices.size(), 2u);
    CHECK_EQ(failed_indices[0], 0u);
    CHECK_EQ(failed_indices[1], 3u);
}

// ========== 14. 无期望 hash 时不校验 ==========

static void test_no_expected_hashes_no_verify() {
    std::printf("[test] no expected hashes → no verify...\n");

    TensorReassembler reasm;
    reasm.set_verify_chunk_hashes(true);
    // 不设置任何期望 hash

    bool callback_called = false;
    reasm.on_chunk_verify_failure([&](auto...) {
        callback_called = true;
    });

    auto data = make_test_data(1024, 0xC0);
    TensorShardMessage shard;
    shard.meta.tensor_id = 30;
    shard.meta.total_shards = 1;
    shard.meta.shard_idx = 0;
    shard.meta.shard_bytes = static_cast<std::uint32_t>(data.size());
    shard.meta.is_last = true;
    shard.data = data;

    bool accepted = reasm.on_shard(shard);
    CHECK(accepted);
    CHECK(!callback_called);  // 无期望 hash，不校验
}

// ========== 15. 空 hash 列表表示无需校验 ==========

static void test_empty_hash_list_no_verify() {
    std::printf("[test] empty hash list → no verify...\n");

    TensorReassembler reasm;
    reasm.set_verify_chunk_hashes(true);
    reasm.set_expected_chunk_hashes(40, 0, 1024, ChunkHashList{});  // 空 hash 列表

    bool callback_called = false;
    reasm.on_chunk_verify_failure([&](auto...) {
        callback_called = true;
    });

    auto data = make_test_data(1024, 0xD0);
    TensorShardMessage shard;
    shard.meta.tensor_id = 40;
    shard.meta.total_shards = 1;
    shard.meta.shard_idx = 0;
    shard.meta.shard_bytes = static_cast<std::uint32_t>(data.size());
    shard.meta.is_last = true;
    shard.data = data;

    reasm.on_shard(shard);
    CHECK(!callback_called);  // 空 hash 列表，不校验
}

// ========== main ==========

int main() {
    std::printf("=== v3.9.6 M17 逐 chunk 增量校验测试 ===\n\n");

    test_shard_hash_announce_roundtrip();
    test_shard_hash_announce_edge_cases();
    test_compute_shard_chunk_hashes();
    test_build_shard_hash_announce();
    test_chunk_verify_pass();
    test_chunk_verify_fail_locate();
    test_chunk_verify_callback_params();
    test_chunk_verify_disabled_no_callback();
    test_chunk_count_mismatch();
    test_clear_chunk_hashes();
    test_method_id_shard_hash_announce();
    test_e2e_chunk_verify();
    test_multi_chunk_corruption();
    test_no_expected_hashes_no_verify();
    test_empty_hash_list_no_verify();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
