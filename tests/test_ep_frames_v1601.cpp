// test_ep_frames_v1601.cpp — v1.6.0.1 (P0) EP 协议帧 + ALPN 通道单元测试
//
// 验证 P0 阶段交付物：
//   1. EP_DISPATCH_FRAME / EP_COMBINE_FRAME / EP_SYNC_FRAME 编解码
//   2. 帧格式边界值（空 payload、大 payload、最大 payload、padding）
//   3. 错误检测（错误 type、截断数据、超限 payload、未知 sync_op）
//   4. ChannelType 枚举新增 EP_DISPATCH/EP_COMBINE/EP_SYNC
//   5. ALPN 映射 alpn_for/channel_from_alpn 双向正确
//   6. for_channel 默认配置（FEC/MTU/crypto_level）
//   7. is_reliable_channel(EP_SYNC) = true
//   8. default_ep_alpns / default_all_alpns 返回正确列表
//   9. peek_ep_frame_type / ep_frame_type_name / ep_sync_op_name 辅助函数
//
// 测试基线：v1.5.0.12 (commit 190c90c)
// 目标版本：v1.6.0.1 (P0 首个交付)

#include "linoh/multimodal/channel.hpp"
#include "linoh/multimodal/ep_frames.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace linoh;
using namespace linoh::multimodal;
using namespace linoh::multimodal::ep;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

#define CHECK_GE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a >= _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s >= %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

#define CHECK_NE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a != _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s != %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ============================================================================
// TEST 1: EP_DISPATCH_FRAME 基础编解码
// ============================================================================
static void test_dispatch_frame_basic() {
    std::printf("[test] EP_DISPATCH_FRAME basic encode/decode...\n");

    EpDispatchFrame frame;
    frame.tensor_id = 12345;
    frame.expert_id = 7;
    frame.token_cnt = 128;
    frame.payload = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    frame.padding = {0x00, 0x00, 0x00};

    auto encoded = encode_dispatch_frame(frame);
    CHECK_GE(encoded.size(), 1u);
    CHECK_EQ(encoded[0], static_cast<std::uint8_t>(EpFrameType::DISPATCH));

    auto decoded = decode_dispatch_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
    CHECK(decoded.has_value());
    if (decoded) {
        CHECK_EQ(decoded->tensor_id, frame.tensor_id);
        CHECK_EQ(decoded->expert_id, frame.expert_id);
        CHECK_EQ(decoded->token_cnt, frame.token_cnt);
        CHECK_EQ(decoded->payload.size(), frame.payload.size());
        CHECK(std::memcmp(decoded->payload.data(), frame.payload.data(), frame.payload.size()) == 0);
        CHECK_EQ(decoded->padding.size(), frame.padding.size());
    }
}

// ============================================================================
// TEST 2: EP_COMBINE_FRAME 基础编解码
// ============================================================================
static void test_combine_frame_basic() {
    std::printf("[test] EP_COMBINE_FRAME basic encode/decode...\n");

    EpCombineFrame frame;
    frame.tensor_id = 99999;
    frame.expert_id = 3;
    frame.token_cnt = 64;
    frame.payload = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    auto encoded = encode_combine_frame(frame);
    CHECK_GE(encoded.size(), 1u);
    CHECK_EQ(encoded[0], static_cast<std::uint8_t>(EpFrameType::COMBINE));

    auto decoded = decode_combine_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
    CHECK(decoded.has_value());
    if (decoded) {
        CHECK_EQ(decoded->tensor_id, frame.tensor_id);
        CHECK_EQ(decoded->expert_id, frame.expert_id);
        CHECK_EQ(decoded->token_cnt, frame.token_cnt);
        CHECK_EQ(decoded->payload.size(), frame.payload.size());
        CHECK(std::memcmp(decoded->payload.data(), frame.payload.data(), frame.payload.size()) == 0);
    }
}

// ============================================================================
// TEST 3: EP_SYNC_FRAME 基础编解码 + 所有 sync_op
// v2.2 Phase 3 (P3-A): 增强 - 验证 algo/shard_idx/total_shards 字段
// ============================================================================
static void test_sync_frame_basic() {
    std::printf("[test] EP_SYNC_FRAME basic encode/decode (all sync_ops)...\n");

    const EpSyncOp ops[] = {
        EpSyncOp::Barrier,
        EpSyncOp::Signal,
        EpSyncOp::Ack,
        EpSyncOp::AllReduce,
        EpSyncOp::Release,
        // v2.1 Phase 2: 集合通信原语
        EpSyncOp::AllGather,
        EpSyncOp::Broadcast,
        EpSyncOp::ReduceScatter,
        EpSyncOp::AllToAll,
    };

    for (auto op : ops) {
        EpSyncFrame frame;
        frame.sync_id = 42;
        frame.sync_op = op;
        frame.algo = 2;  // v2.2 Phase 3 (P3-A): RecursiveHalving
        frame.participant_mask = 0xFF;  // 8 个节点
        frame.reduce_op = 1;  // MAX
        frame.shard_idx = 3;       // v2.2 Phase 3 (P3-A)
        frame.total_shards = 16;   // v2.2 Phase 3 (P3-A)
        frame.payload = {0x10, 0x20, 0x30};

        auto encoded = encode_sync_frame(frame);
        CHECK_GE(encoded.size(), 1u);
        CHECK_EQ(encoded[0], static_cast<std::uint8_t>(EpFrameType::SYNC));

        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->sync_id, frame.sync_id);
            CHECK_EQ(decoded->sync_op, frame.sync_op);
            CHECK_EQ(decoded->algo, frame.algo);                       // v2.2 P3-A
            CHECK_EQ(decoded->participant_mask, frame.participant_mask);
            CHECK_EQ(decoded->reduce_op, frame.reduce_op);             // v2.2 P3-A 增强校验
            CHECK_EQ(decoded->shard_idx, frame.shard_idx);             // v2.2 P3-A
            CHECK_EQ(decoded->total_shards, frame.total_shards);       // v2.2 P3-A
            CHECK_EQ(decoded->payload.size(), frame.payload.size());
            CHECK(std::memcmp(decoded->payload.data(), frame.payload.data(), frame.payload.size()) == 0);
        }
    }
}

// ============================================================================
// TEST 3b: v2.2 Phase 3 (P3-A) algo 字段所有取值
// ============================================================================
static void test_sync_frame_algo_field() {
    std::printf("[test] EP_SYNC_FRAME algo field (all CollectiveAlgo values)...\n");

    // algo 合法值 0-3，非法值 4-255
    for (std::uint8_t algo = 0; algo <= 3; ++algo) {
        EpSyncFrame frame;
        frame.sync_id = 100;
        frame.sync_op = EpSyncOp::AllReduce;
        frame.algo = algo;
        frame.participant_mask = 0x0F;
        frame.payload = {0xAA};

        auto encoded = encode_sync_frame(frame);
        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->algo, algo);
        }
    }

    // ep_sync_algo_name 字符串校验
    CHECK_EQ(std::string(ep_sync_algo_name(0)), std::string("ring"));
    CHECK_EQ(std::string(ep_sync_algo_name(1)), std::string("tree"));
    CHECK_EQ(std::string(ep_sync_algo_name(2)), std::string("recursive_halving"));
    CHECK_EQ(std::string(ep_sync_algo_name(3)), std::string("pairwise_exchange"));
    CHECK_EQ(std::string(ep_sync_algo_name(4)), std::string("unknown"));
    CHECK_EQ(std::string(ep_sync_algo_name(255)), std::string("unknown"));
}

// ============================================================================
// TEST 3c: v2.2 Phase 3 (P3-A) shard_idx/total_shards 字段
// ============================================================================
static void test_sync_frame_shard_fields() {
    std::printf("[test] EP_SYNC_FRAME shard_idx/total_shards fields...\n");

    // 默认值：单 chunk（shard_idx=0, total_shards=1）
    {
        EpSyncFrame frame;
        frame.sync_id = 1;
        frame.sync_op = EpSyncOp::AllGather;
        frame.algo = 0;  // Ring
        frame.participant_mask = 0xFF;
        frame.payload = {0x01, 0x02};

        auto encoded = encode_sync_frame(frame);
        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->shard_idx, 0u);
            CHECK_EQ(decoded->total_shards, 1u);
        }
    }

    // 分片场景：shard_idx=5, total_shards=10
    {
        EpSyncFrame frame;
        frame.sync_id = 2;
        frame.sync_op = EpSyncOp::AllReduce;
        frame.algo = 2;  // RecursiveHalving
        frame.participant_mask = 0x0F;
        frame.shard_idx = 5;
        frame.total_shards = 10;
        frame.payload.resize(64, 0xAB);

        auto encoded = encode_sync_frame(frame);
        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->shard_idx, 5u);
            CHECK_EQ(decoded->total_shards, 10u);
        }
    }

    // 边界值：shard_idx=65535, total_shards=65535
    {
        EpSyncFrame frame;
        frame.sync_id = 3;
        frame.sync_op = EpSyncOp::Broadcast;
        frame.algo = 1;  // Tree
        frame.participant_mask = 0xFFFF;
        frame.shard_idx = 65534;
        frame.total_shards = 65535;
        frame.payload = {0xFF};

        auto encoded = encode_sync_frame(frame);
        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->shard_idx, 65534u);
            CHECK_EQ(decoded->total_shards, 65535u);
        }
    }
}

// ============================================================================
// TEST 3d: v2.2 Phase 3 (P3-A) 非法 algo 值解码失败
// ============================================================================
static void test_unknown_algo_decode_fails() {
    std::printf("[test] unknown algo value decode fails...\n");

    EpSyncFrame frame;
    frame.sync_id = 1;
    frame.sync_op = EpSyncOp::AllReduce;
    frame.algo = 0;
    frame.participant_mask = 0x01;
    frame.payload = {0xFF};

    auto encoded = encode_sync_frame(frame);
    CHECK(encoded.size() > 3);

    // 篡改 algo 字节为非法值 4
    // 帧布局：type(1) + sync_id varint(1) + sync_op(1) + algo(1) + ...
    // sync_id=1 编码为 1B varint (0x01)，algo 在 offset=3
    std::vector<std::uint8_t> tampered(encoded.begin(), encoded.end());
    tampered[3] = 0x04;  // algo=4 非法

    auto decoded = decode_sync_frame(std::span<const std::uint8_t>(tampered.data(), tampered.size()));
    CHECK(!decoded.has_value());
}

// ============================================================================
// TEST 3e: v2.2 Phase 3 (P3-A) 非法 shard_idx/total_shards 解码失败
// ============================================================================
static void test_invalid_shard_fields_decode_fails() {
    std::printf("[test] invalid shard_idx/total_shards decode fails...\n");

    EpSyncFrame frame;
    frame.sync_id = 1;
    frame.sync_op = EpSyncOp::AllReduce;
    frame.algo = 0;
    frame.participant_mask = 0x01;
    frame.shard_idx = 0;
    frame.total_shards = 1;
    frame.payload = {0xFF};

    auto encoded = encode_sync_frame(frame);

    // 场景 1: total_shards=0（非法）
    {
        std::vector<std::uint8_t> tampered(encoded.begin(), encoded.end());
        // shard_idx/total_shards 在 reduce_op 后 2+2 字节
        // 布局：type(1) + sync_id(1) + sync_op(1) + algo(1) + participant_mask(1) + reduce_op(1) + shard_idx(2) + total_shards(2) + ...
        // sync_id=1, participant_mask=1 均为 1B varint
        // shard_idx 在 offset=6, total_shards 在 offset=8
        tampered[8] = 0x00;  // total_shards 低字节=0
        tampered[9] = 0x00;  // total_shards 高字节=0
        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(tampered.data(), tampered.size()));
        CHECK(!decoded.has_value());
    }

    // 场景 2: shard_idx >= total_shards（非法）
    {
        std::vector<std::uint8_t> tampered(encoded.begin(), encoded.end());
        // shard_idx=5, total_shards=3 → shard_idx >= total_shards
        tampered[6] = 0x05;  // shard_idx 低字节=5
        tampered[7] = 0x00;
        tampered[8] = 0x03;  // total_shards 低字节=3
        tampered[9] = 0x00;
        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(tampered.data(), tampered.size()));
        CHECK(!decoded.has_value());
    }
}

// ============================================================================
// TEST 4: 空 payload 编解码
// ============================================================================
static void test_empty_payload() {
    std::printf("[test] empty payload encode/decode...\n");

    EpDispatchFrame frame;
    frame.tensor_id = 1;
    frame.expert_id = 0;
    frame.token_cnt = 0;
    // payload 和 padding 都为空

    auto encoded = encode_dispatch_frame(frame);
    CHECK_GE(encoded.size(), 1u);

    auto decoded = decode_dispatch_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
    CHECK(decoded.has_value());
    if (decoded) {
        CHECK_EQ(decoded->payload.size(), 0u);
        CHECK_EQ(decoded->padding.size(), 0u);
    }
}

// ============================================================================
// TEST 5: 大 payload 编解码（1KB）
// ============================================================================
static void test_large_payload() {
    std::printf("[test] large payload (1KB) encode/decode...\n");

    EpCombineFrame frame;
    frame.tensor_id = 100;
    frame.expert_id = 5;
    frame.token_cnt = 256;
    frame.payload.resize(1024);
    for (std::size_t i = 0; i < frame.payload.size(); ++i) {
        frame.payload[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    auto encoded = encode_combine_frame(frame);
    CHECK_GE(encoded.size(), frame.payload.size());

    auto decoded = decode_combine_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
    CHECK(decoded.has_value());
    if (decoded) {
        CHECK_EQ(decoded->payload.size(), frame.payload.size());
        CHECK(std::memcmp(decoded->payload.data(), frame.payload.data(), frame.payload.size()) == 0);
    }
}

// ============================================================================
// TEST 6: 错误 type 字节
// ============================================================================
static void test_wrong_type_byte() {
    std::printf("[test] wrong type byte returns nullopt...\n");

    std::uint8_t wrong[] = {0x99, 0x01, 0x02, 0x03};
    auto t1 = peek_ep_frame_type(std::span<const std::uint8_t>(wrong, 4));
    CHECK(!t1.has_value());

    auto d1 = decode_dispatch_frame(std::span<const std::uint8_t>(wrong, 4));
    CHECK(!d1.has_value());

    auto c1 = decode_combine_frame(std::span<const std::uint8_t>(wrong, 4));
    CHECK(!c1.has_value());

    auto s1 = decode_sync_frame(std::span<const std::uint8_t>(wrong, 4));
    CHECK(!s1.has_value());
}

// ============================================================================
// TEST 7: 截断数据解码失败
// ============================================================================
static void test_truncated_data() {
    std::printf("[test] truncated data decode fails...\n");

    // 构造一个完整的 DISPATCH 帧，然后截断
    EpDispatchFrame frame;
    frame.tensor_id = 1;
    frame.expert_id = 1;
    frame.token_cnt = 1;
    frame.payload = {0xAA, 0xBB, 0xCC};

    auto encoded = encode_dispatch_frame(frame);
    CHECK(encoded.size() > 4);

    // 截断到只剩 type + 2 字节（不足 varint 完整）
    std::span<const std::uint8_t> truncated(encoded.data(), 3);
    auto decoded = decode_dispatch_frame(truncated);
    CHECK(!decoded.has_value());
}

// ============================================================================
// TEST 8: 超限 payload 解码失败
// ============================================================================
static void test_oversized_payload_decode() {
    std::printf("[test] oversized payload decode fails...\n");

    // 构造一个 payload_len > kMaxPayloadLen 的伪帧
    // 手工编码：type(0x20) + tensor_id(1) + expert_id(1) + token_cnt(1) +
    //           payload_len(8 bytes varint, value = kMaxPayloadLen + 1)
    std::vector<std::uint8_t> fake;
    fake.push_back(static_cast<std::uint8_t>(EpFrameType::DISPATCH));
    fake.push_back(0x01);  // tensor_id = 1
    fake.push_back(0x01);  // expert_id = 1
    fake.push_back(0x01);  // token_cnt = 1
    // payload_len = kMaxPayloadLen + 1，使用 8 字节 varint 编码
    std::uint64_t oversized = EpDispatchFrame::kMaxPayloadLen + 1;
    std::uint8_t len_buf[8];
    // 手工构造 8 字节 varint（prefix 11）
    len_buf[0] = static_cast<std::uint8_t>(((oversized >> 56) & 0x3F) | 0xC0);
    len_buf[1] = static_cast<std::uint8_t>((oversized >> 48) & 0xFF);
    len_buf[2] = static_cast<std::uint8_t>((oversized >> 40) & 0xFF);
    len_buf[3] = static_cast<std::uint8_t>((oversized >> 32) & 0xFF);
    len_buf[4] = static_cast<std::uint8_t>((oversized >> 24) & 0xFF);
    len_buf[5] = static_cast<std::uint8_t>((oversized >> 16) & 0xFF);
    len_buf[6] = static_cast<std::uint8_t>((oversized >> 8) & 0xFF);
    len_buf[7] = static_cast<std::uint8_t>(oversized & 0xFF);
    fake.insert(fake.end(), len_buf, len_buf + 8);

    auto decoded = decode_dispatch_frame(std::span<const std::uint8_t>(fake.data(), fake.size()));
    CHECK(!decoded.has_value());
}

// ============================================================================
// TEST 9: 未知 sync_op 解码失败
// ============================================================================
static void test_unknown_sync_op() {
    std::printf("[test] unknown sync_op decode fails...\n");

    EpSyncFrame frame;
    frame.sync_id = 1;
    frame.sync_op = EpSyncOp::AllToAll;  // v2.1 Phase 2 M2: 当前最大值
    frame.participant_mask = 0x01;
    frame.payload = {0xFF};

    auto encoded = encode_sync_frame(frame);
    CHECK(encoded.size() > 2);

    // 篡改 sync_op 字节为未知值（9，超过 AllToAll=8）
    // v2.1 Phase 2 M2: ReduceScatter=7 和 AllToAll=8 已合法，需用 9 测试未知值
    std::vector<std::uint8_t> tampered(encoded.begin(), encoded.end());
    // type(1) + sync_id varint(1) + sync_op(1)
    // sync_id=1 编码为 1B varint (0x01)，所以 sync_op 在 offset=2
    tampered[2] = 0x09;

    auto decoded = decode_sync_frame(std::span<const std::uint8_t>(tampered.data(), tampered.size()));
    CHECK(!decoded.has_value());
}

// ============================================================================
// TEST 10: ChannelType 枚举新增 EP 通道
// ============================================================================
static void test_channel_type_enum() {
    std::printf("[test] ChannelType enum has EP_DISPATCH/COMBINE/SYNC...\n");

    CHECK(static_cast<std::uint8_t>(ChannelType::EP_DISPATCH) == 6);
    CHECK(static_cast<std::uint8_t>(ChannelType::EP_COMBINE) == 7);
    CHECK(static_cast<std::uint8_t>(ChannelType::EP_SYNC) == 8);
}

// ============================================================================
// TEST 11: ALPN 映射 alpn_for / channel_from_alpn 双向
// ============================================================================
static void test_alpn_mapping() {
    std::printf("[test] ALPN mapping alpn_for/channel_from_alpn...\n");

    // alpn_for 正向
    CHECK_EQ(alpn_for(ChannelType::EP_DISPATCH), std::string_view("ep-dispatch/1"));
    CHECK_EQ(alpn_for(ChannelType::EP_COMBINE), std::string_view("ep-combine/1"));
    CHECK_EQ(alpn_for(ChannelType::EP_SYNC), std::string_view("ep-sync/1"));

    // channel_from_alpn 反向
    CHECK_EQ(channel_from_alpn("ep-dispatch/1"), ChannelType::EP_DISPATCH);
    CHECK_EQ(channel_from_alpn("ep-combine/1"), ChannelType::EP_COMBINE);
    CHECK_EQ(channel_from_alpn("ep-sync/1"), ChannelType::EP_SYNC);

    // 未知 ALPN 回落到 CONTROL
    CHECK_EQ(channel_from_alpn("unknown/1"), ChannelType::CONTROL);
}

// ============================================================================
// TEST 12: for_channel 默认配置
// ============================================================================
static void test_for_channel_defaults() {
    std::printf("[test] for_channel() defaults for EP channels...\n");

    auto dispatch_cfg = ChannelConfig::for_channel(ChannelType::EP_DISPATCH);
    CHECK_EQ(dispatch_cfg.type, ChannelType::EP_DISPATCH);
    CHECK(dispatch_cfg.fec_enabled);
    CHECK_EQ(dispatch_cfg.fec_type, FecType::ReedSolomon);
    CHECK_EQ(dispatch_cfg.fec_data_blocks, 16u);
    CHECK_EQ(dispatch_cfg.fec_recovery_blocks, 1u);
    CHECK_EQ(dispatch_cfg.crypto_level, CryptoLevel::Strong);
    CHECK_EQ(dispatch_cfg.preferred_mtu, 9000);

    auto combine_cfg = ChannelConfig::for_channel(ChannelType::EP_COMBINE);
    CHECK_EQ(combine_cfg.type, ChannelType::EP_COMBINE);
    CHECK(combine_cfg.fec_enabled);
    CHECK_EQ(combine_cfg.preferred_mtu, 9000);

    auto sync_cfg = ChannelConfig::for_channel(ChannelType::EP_SYNC);
    CHECK_EQ(sync_cfg.type, ChannelType::EP_SYNC);
    CHECK(!sync_cfg.fec_enabled);  // 同步原语小包，不需要 FEC
    CHECK_EQ(sync_cfg.crypto_level, CryptoLevel::Strong);
    CHECK_EQ(sync_cfg.preferred_mtu, 1280);  // 同步原语小包
}

// ============================================================================
// TEST 13: is_reliable_channel / is_data_channel / channel_type_name
// ============================================================================
static void test_channel_helpers() {
    std::printf("[test] is_reliable_channel/is_data_channel/channel_type_name...\n");

    // EP_SYNC 必须可靠（同步原语不能丢）
    CHECK(is_reliable_channel(ChannelType::EP_SYNC));
    // EP_DISPATCH/COMBINE 不是可靠通道（数据通道，丢包由上层处理）
    CHECK(!is_reliable_channel(ChannelType::EP_DISPATCH));
    CHECK(!is_reliable_channel(ChannelType::EP_COMBINE));

    // 所有 EP 通道都是数据通道
    CHECK(is_data_channel(ChannelType::EP_DISPATCH));
    CHECK(is_data_channel(ChannelType::EP_COMBINE));
    CHECK(is_data_channel(ChannelType::EP_SYNC));

    // channel_type_name
    CHECK_EQ(std::string(channel_type_name(ChannelType::EP_DISPATCH)), std::string("ep_dispatch"));
    CHECK_EQ(std::string(channel_type_name(ChannelType::EP_COMBINE)), std::string("ep_combine"));
    CHECK_EQ(std::string(channel_type_name(ChannelType::EP_SYNC)), std::string("ep_sync"));
}

// ============================================================================
// TEST 14: default_ep_alpns / default_all_alpns
// ============================================================================
static void test_default_alpn_lists() {
    std::printf("[test] default_ep_alpns / default_all_alpns...\n");

    auto ep_alpns = default_ep_alpns();
    CHECK_EQ(ep_alpns.size(), 3u);
    CHECK_EQ(ep_alpns[0], std::string_view("ep-dispatch/1"));
    CHECK_EQ(ep_alpns[1], std::string_view("ep-combine/1"));
    CHECK_EQ(ep_alpns[2], std::string_view("ep-sync/1"));

    auto all_alpns = default_all_alpns();
    CHECK_EQ(all_alpns.size(), 9u);  // control + 5 pp + 3 ep
    CHECK_EQ(all_alpns[0], std::string_view("ctrl/1"));
    CHECK_EQ(all_alpns[6], std::string_view("ep-dispatch/1"));
    CHECK_EQ(all_alpns[7], std::string_view("ep-combine/1"));
    CHECK_EQ(all_alpns[8], std::string_view("ep-sync/1"));
}

// ============================================================================
// TEST 15: peek_ep_frame_type / ep_frame_type_name / ep_sync_op_name
// ============================================================================
static void test_ep_frame_helpers() {
    std::printf("[test] peek_ep_frame_type/ep_frame_type_name/ep_sync_op_name...\n");

    // peek_ep_frame_type
    std::uint8_t dispatch_first = static_cast<std::uint8_t>(EpFrameType::DISPATCH);
    auto t1 = peek_ep_frame_type(std::span<const std::uint8_t>(&dispatch_first, 1));
    CHECK(t1.has_value());
    CHECK_EQ(*t1, EpFrameType::DISPATCH);

    std::uint8_t combine_first = static_cast<std::uint8_t>(EpFrameType::COMBINE);
    auto t2 = peek_ep_frame_type(std::span<const std::uint8_t>(&combine_first, 1));
    CHECK(t2.has_value());
    CHECK_EQ(*t2, EpFrameType::COMBINE);

    std::uint8_t sync_first = static_cast<std::uint8_t>(EpFrameType::SYNC);
    auto t3 = peek_ep_frame_type(std::span<const std::uint8_t>(&sync_first, 1));
    CHECK(t3.has_value());
    CHECK_EQ(*t3, EpFrameType::SYNC);

    std::uint8_t unknown = 0x99;
    auto t4 = peek_ep_frame_type(std::span<const std::uint8_t>(&unknown, 1));
    CHECK(!t4.has_value());

    // 空 span
    auto t5 = peek_ep_frame_type(std::span<const std::uint8_t>());
    CHECK(!t5.has_value());

    // ep_frame_type_name
    CHECK_EQ(std::string(ep_frame_type_name(EpFrameType::DISPATCH)), std::string("ep_dispatch"));
    CHECK_EQ(std::string(ep_frame_type_name(EpFrameType::COMBINE)), std::string("ep_combine"));
    CHECK_EQ(std::string(ep_frame_type_name(EpFrameType::SYNC)), std::string("ep_sync"));

    // ep_sync_op_name
    CHECK_EQ(std::string(ep_sync_op_name(EpSyncOp::Barrier)), std::string("barrier"));
    CHECK_EQ(std::string(ep_sync_op_name(EpSyncOp::Signal)), std::string("signal"));
    CHECK_EQ(std::string(ep_sync_op_name(EpSyncOp::Ack)), std::string("ack"));
    CHECK_EQ(std::string(ep_sync_op_name(EpSyncOp::AllReduce)), std::string("all_reduce"));
    CHECK_EQ(std::string(ep_sync_op_name(EpSyncOp::Release)), std::string("release"));
    // v2.1 Phase 2: 集合通信原语
    CHECK_EQ(std::string(ep_sync_op_name(EpSyncOp::AllGather)), std::string("all_gather"));
    CHECK_EQ(std::string(ep_sync_op_name(EpSyncOp::Broadcast)), std::string("broadcast"));
    CHECK_EQ(std::string(ep_sync_op_name(EpSyncOp::ReduceScatter)), std::string("reduce_scatter"));
    CHECK_EQ(std::string(ep_sync_op_name(EpSyncOp::AllToAll)), std::string("all_to_all"));
}

// ============================================================================
// TEST 16: round-trip 多次编解码稳定性
// ============================================================================
static void test_roundtrip_stability() {
    std::printf("[test] round-trip stability (100 iterations)...\n");

    for (int i = 0; i < 100; ++i) {
        EpDispatchFrame f;
        f.tensor_id = static_cast<std::uint64_t>(i) * 1000;
        f.expert_id = static_cast<std::uint64_t>(i) % 8;
        f.token_cnt = static_cast<std::uint64_t>(i) * 16;
        f.payload.resize(static_cast<std::size_t>(i * 7 + 1));
        for (std::size_t j = 0; j < f.payload.size(); ++j) {
            f.payload[j] = static_cast<std::uint8_t>((i + j) & 0xFF);
        }

        auto encoded = encode_dispatch_frame(f);
        auto decoded = decode_dispatch_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->tensor_id, f.tensor_id);
            CHECK_EQ(decoded->expert_id, f.expert_id);
            CHECK_EQ(decoded->token_cnt, f.token_cnt);
            CHECK_EQ(decoded->payload.size(), f.payload.size());
            if (decoded->payload.size() == f.payload.size()) {
                CHECK(std::memcmp(decoded->payload.data(), f.payload.data(), f.payload.size()) == 0);
            }
        }
    }
}

// ============================================================================
// TEST 17: 编码后帧大小符合预估
// ============================================================================
static void test_frame_size_estimate() {
    std::printf("[test] frame size estimate (kDispatchFrameMaxBytes etc.)...\n");

    // 构造一个空 payload 的 DISPATCH 帧，验证编码后大小 ≤ kDispatchFrameMaxBytes
    EpDispatchFrame f;
    f.tensor_id = 0;
    f.expert_id = 0;
    f.token_cnt = 0;
    auto encoded = encode_dispatch_frame(f);
    CHECK(encoded.size() <= kDispatchFrameMaxBytes);

    // COMBINE
    EpCombineFrame c;
    auto encoded_c = encode_combine_frame(c);
    CHECK(encoded_c.size() <= kCombineFrameMaxBytes);

    // SYNC
    EpSyncFrame s;
    auto encoded_s = encode_sync_frame(s);
    CHECK(encoded_s.size() <= kSyncFrameMaxBytes);
}

// ============================================================================
// TEST 18: varint 字段使用多字节编码
// ============================================================================
static void test_varint_multibyte() {
    std::printf("[test] varint multibyte fields (large tensor_id)...\n");

    EpDispatchFrame f;
    f.tensor_id = 0x3FFFFFFF;  // 30-bit max（4 字节 varint）
    f.expert_id = 0x3FFF;      // 14-bit max（2 字节 varint）
    f.token_cnt = 1;
    f.payload = {0x01};

    auto encoded = encode_dispatch_frame(f);
    auto decoded = decode_dispatch_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
    CHECK(decoded.has_value());
    if (decoded) {
        CHECK_EQ(decoded->tensor_id, f.tensor_id);
        CHECK_EQ(decoded->expert_id, f.expert_id);
    }
}

// ============================================================================
// TEST: v2.3 Phase 4 (P4-A) 条件性尾部字段 from_node_id + step
// ============================================================================
static void test_sync_frame_trailing_fields() {
    std::printf("[test] EP_SYNC_FRAME conditional trailing fields (from_node_id + step)...\n");

    // 1) 默认帧（from_node_id=0, step=0）：无尾部字节，wire 与改造前字节级一致
    std::vector<std::uint8_t> default_encoded;
    {
        EpSyncFrame frame;
        frame.sync_id = 42;
        frame.sync_op = EpSyncOp::AllReduce;
        frame.algo = 0;  // Ring
        frame.participant_mask = 0x0F;
        frame.payload = {0x10, 0x20, 0x30};
        default_encoded = encode_sync_frame(frame);

        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(default_encoded.data(), default_encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->from_node_id, 0ull);
            CHECK_EQ(decoded->step, 0u);
        }
    }

    // 2) 同一帧再次构造（显式 from_node_id=0, step=0）→ 字节序列应与 1) 完全一致
    {
        EpSyncFrame frame;
        frame.sync_id = 42;
        frame.sync_op = EpSyncOp::AllReduce;
        frame.algo = 0;
        frame.participant_mask = 0x0F;
        frame.payload = {0x10, 0x20, 0x30};
        frame.from_node_id = 0;
        frame.step = 0;
        auto encoded2 = encode_sync_frame(frame);
        CHECK_EQ(encoded2.size(), default_encoded.size());
        bool byte_equal = (encoded2.size() == default_encoded.size());
        for (std::size_t i = 0; byte_equal && i < encoded2.size(); ++i) {
            if (encoded2[i] != default_encoded[i]) byte_equal = false;
        }
        CHECK(byte_equal);  // 默认帧字节级兼容
    }

    // 3) Ring 多步帧：from_node_id=0b0010(2), step=3 → 有尾部字段
    {
        EpSyncFrame frame;
        frame.sync_id = 100;
        frame.sync_op = EpSyncOp::AllReduce;
        frame.algo = 0;  // Ring
        frame.participant_mask = 0x0F;
        frame.from_node_id = 2;   // bit 1
        frame.step = 3;
        frame.payload = {0xAA, 0xBB};

        auto encoded = encode_sync_frame(frame);
        // 尾部字段存在 → 编码后长度 > 默认帧长度
        CHECK(encoded.size() > default_encoded.size());

        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->from_node_id, 2ull);
            CHECK_EQ(decoded->step, 3u);
            CHECK_EQ(decoded->sync_id, 100ull);
            CHECK_EQ(decoded->algo, 0u);
        }
    }

    // 4) 大 from_node_id（bit 33，多字节 VarInt）+ 大 step
    {
        EpSyncFrame frame;
        frame.sync_id = 7;
        frame.sync_op = EpSyncOp::AllGather;
        frame.algo = 0;
        frame.participant_mask = 0xFFFFFFFF;
        frame.from_node_id = (1ull << 33);  // 需要 VarInt 多字节编码
        frame.step = 30000;
        frame.payload = {0x01};

        auto encoded = encode_sync_frame(frame);
        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->from_node_id, (1ull << 33));
            CHECK_EQ(decoded->step, 30000u);
        }
    }

    // 5) 仅 step != 0（from_node_id=0）→ 仍应追加尾部
    {
        EpSyncFrame frame;
        frame.sync_id = 9;
        frame.sync_op = EpSyncOp::ReduceScatter;
        frame.algo = 0;
        frame.participant_mask = 0x03;
        frame.step = 5;  // from_node_id 保持 0
        frame.payload = {0xCC};

        auto encoded = encode_sync_frame(frame);
        CHECK(encoded.size() > 0);
        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->from_node_id, 0ull);
            CHECK_EQ(decoded->step, 5u);
        }
    }

    // 6) 旧帧兼容：手工构造无尾部字节的帧（模拟 v2 编码），新解码器应得到 from_node_id=0/step=0
    {
        EpSyncFrame frame;
        frame.sync_id = 55;
        frame.sync_op = EpSyncOp::AllReduce;
        frame.algo = 0;
        frame.participant_mask = 0x07;
        frame.payload = {0x11, 0x22};
        // from_node_id=0, step=0 → 不写尾部（等价于旧 v2 帧）
        auto encoded = encode_sync_frame(frame);
        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->from_node_id, 0ull);
            CHECK_EQ(decoded->step, 0u);
            CHECK_EQ(decoded->sync_id, 55ull);
        }
    }
}

int main() {
    std::printf("=== linoh v1.6.0.1 (P0) EP 协议帧 + ALPN 通道单元测试 ===\n\n");

    test_dispatch_frame_basic();
    test_combine_frame_basic();
    test_sync_frame_basic();
    // v2.2 Phase 3 (P3-A): 新增 algo/shard 字段测试
    test_sync_frame_algo_field();
    test_sync_frame_shard_fields();
    test_unknown_algo_decode_fails();
    test_invalid_shard_fields_decode_fails();
    // v2.3 Phase 4 (P4-A): 条件性尾部字段（from_node_id + step）
    test_sync_frame_trailing_fields();
    test_empty_payload();
    test_large_payload();
    test_wrong_type_byte();
    test_truncated_data();
    test_oversized_payload_decode();
    test_unknown_sync_op();
    test_channel_type_enum();
    test_alpn_mapping();
    test_for_channel_defaults();
    test_channel_helpers();
    test_default_alpn_lists();
    test_ep_frame_helpers();
    test_roundtrip_stability();
    test_frame_size_estimate();
    test_varint_multibyte();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
