// test_loss_recovery_v1505.cpp — v1.5.0.5 方案 A+ OOS_PN_FRAME 接收方反馈机制单元测试
//
// 验证 v1.5.0.4 方案 A 的根因（发送方 oos_buffer_ 永远为空）已被方案 A+ 修复：
//   - 接收方通过 OOS_PN_FRAME (type=0x30) 周期反馈 OOS buffer gap
//   - 发送方 handle_oos_pn_frame 写入 oos_pn_remote_ map
//   - 发送方 handle_ack_frame 从 oos_pn_remote_ 收集 entry，
//     反查 sent_packets_ 取 PN，构造 OosPnInfo 注入 LossDetector
//
// 视频模型组反馈 ISSUE 根因（v1.5.0.4 方案 A 注入方向错误）：
//   v1.5.0.4 在发送方 Connection::handle_ack_frame 中遍历 local_streams_/
//   remote_streams_ 收集 oos_pn_list，但 oos_buffer_ 是接收方 stream 状态，
//   发送方 oos_buffer_ 永远为空 → oos_pn_list_size=0 → 永久不触发 retx。
//
// 测试矩阵：
//   1. OOS_PN_FRAME 编码 → 解码 往返（v1.5.0.6 修复：encode 不写 type 字节）
//   2. OOS_PN_FRAME 多 entries + 边界值
//   3. LossDetector 接收通过 oos_pn_list 注入的 PN（与 v1.5.0.4 一致）
//   4. SentPacketInfo 扩展字段 stream_id/stream_offset 不影响基础行为
//   5. oos_pn_list 注入触发丢包检测（模拟接收方反馈场景）
//   6. OOS_PN_FRAME 兼容性 — 默认空 list 时与 v1.5.0.3 行为一致
//   7. v1.5.0.6 端到端网络传输：encode → build_1rtt_packet 显式追加 type
//      → parse_frames 吞 type → decode 完整链路（覆盖 ISSUE T05 修复）
//   8. v1.5.0.6 端到端：真实 25 字节 payload 模拟（含 type 字节，
//      验证 decode 不再因 type 不匹配而失败）
//   9. v1.5.0.6 多 stream 端到端：单 stream 多 entries 编码后网络传输

#include "linoh/protocol/loss_recovery.hpp"
#include "linoh/protocol/packet.hpp"

#include <cassert>
#include <cmath>
#include <cstdio>
#include <vector>

using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// v1.5.0.9 (ISSUE T08 反馈): test_sent_packet_info_extension_compat 适配 stream_ranges 接口
//   引入 CHECK_EQ 宏用于 stream_ranges 字段断言
#define CHECK_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (%lld != %lld) (line %d)\n", \
        #a, #b, (long long)_a, (long long)_b, __LINE__); } \
} while (0)

#define NEAR(a, b) (std::abs((a) - (b)) < 1e-3)
#define NEAR_LOSSY(a, b) (std::abs((a) - (b)) < 0.1)  // 0.1ms 单位 varint 编码有损

// ============================================================================
// TEST 1: OOS_PN_FRAME 编码 → 解码 往返
// ============================================================================
static void test_oos_pn_frame_encode_decode() {
    std::printf("[test] OOS_PN_FRAME encode/decode round-trip...\n");

    OosPnFrame frame;
    frame.stream_id = 42;
    OosPnEntry e1;
    e1.offset = 1024;
    e1.first_seen_ms = 1234.5;
    OosPnEntry e2;
    e2.offset = 2048;
    e2.first_seen_ms = 5678.9;
    frame.entries.push_back(e1);
    frame.entries.push_back(e2);

    auto encoded = encode_oos_pn_frame(frame);
    // v1.5.0.6 修复：encode 不再写 type 字节，type 字节由 build_1rtt_packet
    // 显式追加。直接 encode 输出首字节应是 stream_id 的 varint 编码（=0x01），
    // 永远 != 0x30。如果首字节是 0x30 说明 v1.5.0.5 的 type 写入残留。
    CHECK(!encoded.empty());
    CHECK(encoded[0] != static_cast<uint8_t>(FrameType::OOS_PN));
    // 跳过 type 检查后，decode 应能成功解析 stream_id 和 entries
    auto decoded = decode_oos_pn_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->stream_id == 42);
    CHECK(decoded->entries.size() == 2);
    CHECK(decoded->entries[0].offset == 1024);
    CHECK(NEAR(decoded->entries[0].first_seen_ms, 1234.5));
    CHECK(decoded->entries[1].offset == 2048);
    CHECK(NEAR(decoded->entries[1].first_seen_ms, 5678.9));

    std::printf("    encoded_size=%zu, decoded_entries=%zu\n",
                encoded.size(), decoded->entries.size());
}

// ============================================================================
// TEST 2: OOS_PN_FRAME 多 entries + 边界值 + 超大 entries 截断
// ============================================================================
static void test_oos_pn_frame_multi_entries_and_clamp() {
    std::printf("[test] OOS_PN_FRAME multi-entries + clamp...\n");

    OosPnFrame frame;
    frame.stream_id = 1;
    // 100 个 entries（远小于 256 上限）
    for (int i = 0; i < 100; ++i) {
        OosPnEntry e;
        e.offset = static_cast<uint64_t>(i) * 100;
        e.first_seen_ms = static_cast<double>(i) * 10.0;
        frame.entries.push_back(e);
    }
    auto encoded = encode_oos_pn_frame(frame);
    auto decoded = decode_oos_pn_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->entries.size() == 100);
    CHECK(decoded->entries[0].offset == 0);
    CHECK(decoded->entries[99].offset == 9900);

    // 边界值：first_seen_ms = 0.0 / 0.1ms 单位最小
    OosPnFrame edge;
    edge.stream_id = 99;
    OosPnEntry ee;
    ee.offset = 0;
    ee.first_seen_ms = 0.0;
    edge.entries.push_back(ee);
    auto enc_edge = encode_oos_pn_frame(edge);
    auto dec_edge = decode_oos_pn_frame(enc_edge);
    CHECK(dec_edge.has_value());
    CHECK(dec_edge->entries[0].offset == 0);
    CHECK(NEAR(dec_edge->entries[0].first_seen_ms, 0.0));

    // 超大 first_seen_ms 限幅测试
    OosPnFrame big;
    big.stream_id = 1;
    OosPnEntry ebig;
    ebig.offset = 1;
    ebig.first_seen_ms = 1e9;  // 远超 650s 上限
    big.entries.push_back(ebig);
    auto enc_big = encode_oos_pn_frame(big);
    auto dec_big = decode_oos_pn_frame(enc_big);
    CHECK(dec_big.has_value());
    // 限幅到 650000ms (kOosFirstSeenMsMaxRaw / 10.0)
    CHECK(dec_big->entries[0].first_seen_ms <= 650000.0 + 0.1);

    std::printf("    multi=100, edge_ok, clamp_ok\n");
}

// ============================================================================
// TEST 3: LossDetector 接收 oos_pn_list 注入 PN（接收方反馈场景）
// ============================================================================
// 模拟完整方案 A+ 链路：LossDetector 收到 oos_pn_list（其中 PN < threshold）
// 阶段 2 识别为丢包。
// 视频模型组 ISSUE 反馈 v1.5.0.4 方案 A 在发送方 oos_pn_list=0，
// v1.5.0.5 方案 A+ 修复注入方向后应能在 LossDetector 端识别丢包。
static void test_oos_pn_remote_injection_triggers_loss_detection() {
    std::printf("[test] OOS_PN remote injection (Plan A+) triggers loss detection...\n");
    LossDetector ld;

    // 注入 5 个包，标记为飞行中
    for (uint64_t pn : {10ULL, 20ULL, 30ULL, 40ULL, 50ULL}) {
        ld.on_packet_sent(pn, 1000.0, 1200, true);
    }

    // 模拟对端 ACK 确认 pn=50（largest_acked=50, threshold=47）
    // 接收方通过 OOS_PN_FRAME 反馈：pn=30 仍在 OOS buffer 中未填补
    std::vector<uint64_t> acked = {50};
    std::vector<OosPnInfo> oos_pn_list;
    OosPnInfo oos_pn;
    oos_pn.stream_id = 1;
    oos_pn.pn = 30;
    oos_pn.offset = 1024;  // 接收方反馈的 offset
    oos_pn.size = 1200;
    oos_pn.first_seen_ms = 1010.0;
    oos_pn_list.push_back(oos_pn);

    auto lost = ld.on_ack_received(acked, 1010.0, oos_pn_list);
    bool found_30 = false;
    for (uint64_t pn : lost) {
        if (pn == 30) found_30 = true;
    }
    CHECK(found_30);

    std::printf("    lost.size()=%zu (expected pn=30 in list)\n", lost.size());
}

// ============================================================================
// TEST 4: SentPacketInfo 扩展字段 stream_ranges 不破坏基础功能
// ============================================================================
// v1.5.0.5: 新增 stream_id/stream_offset 字段
// v1.5.0.8: 新增 stream_payload_bytes 字段
// v1.5.0.9: 改用 stream_ranges vector（每个 STREAM chunk 独立记录范围）
//   必须保证：
//   1. 默认空 vector 与 v1.5.0.4/0.5/0.6/0.7/0.8 兼容
//   2. find_sent_mut 仍能正常工作
//   3. in_flight 行为不受影响
static void test_sent_packet_info_extension_compat() {
    std::printf("[test] SentPacketInfo stream_ranges extension compat (v1.5.0.9)...\n");
    LossDetector ld;

    // 调用 on_packet_sent 传 stream_ranges
    std::vector<StreamRange> r100 = {{.stream_id = 7, .offset = 1024, .payload_bytes = 500}};
    std::vector<StreamRange> r101 = {};  // 缺省值（空 vector）
    std::vector<StreamRange> r102 = {
        {.stream_id = 7, .offset = 2048, .payload_bytes = 300},
        {.stream_id = 8, .offset = 0, .payload_bytes = 800},
    };
    ld.on_packet_sent(100, 1000.0, 1200, true, r100);   // 单 range
    ld.on_packet_sent(101, 1001.0, 1200, true, r101);   // 空 range
    ld.on_packet_sent(102, 1002.0, 1200, true, r102);   // 多 range

    // 查找应仍能命中
    // P9.1: find_sent 返回 std::optional<SentPacketInfo>（by-value），auto 接收；
    //   optional 的 operator-> 与原指针语义一致，下游 info100->xxx 访问无需改动。
    auto info100 = ld.find_sent(100);
    CHECK(info100.has_value());
    CHECK_EQ(info100->stream_ranges.size(), 1ull);
    if (info100->stream_ranges.size() == 1) {
        CHECK_EQ(info100->stream_ranges[0].stream_id, 7ull);
        CHECK_EQ(info100->stream_ranges[0].offset, 1024ull);
        CHECK_EQ(info100->stream_ranges[0].payload_bytes, 500ull);
    }

    auto info101 = ld.find_sent(101);
    CHECK(info101.has_value());
    CHECK(info101->stream_ranges.empty());  // 缺省值（空 vector）

    auto info102 = ld.find_sent(102);
    CHECK(info102.has_value());
    CHECK_EQ(info102->stream_ranges.size(), 2ull);
    if (info102->stream_ranges.size() == 2) {
        CHECK_EQ(info102->stream_ranges[0].stream_id, 7ull);
        CHECK_EQ(info102->stream_ranges[0].offset, 2048ull);
        CHECK_EQ(info102->stream_ranges[1].stream_id, 8ull);
        CHECK_EQ(info102->stream_ranges[1].offset, 0ull);
    }

    // in_flight 行为应不受影响
    CHECK(info100->in_flight);
    CHECK(info101->in_flight);
    CHECK(info102->in_flight);

    // sent_packets_for_test 暴露 3 个 entry
    auto pkts = ld.sent_packets_for_test();
    CHECK_EQ(pkts.size(), 3ull);

    std::printf("    compat OK, sent_packets=%zu (v1.5.0.9 stream_ranges)\n", pkts.size());
}

// ============================================================================
// TEST 5: OOS_PN_LIST 注入触发多次丢包检测（多个 OOS PN）
// ============================================================================
// 模拟接收方通过 OOS_PN_FRAME 反馈多个 PN 仍在 OOS buffer 中
// 全部 PN < threshold 时阶段 2 应全部识别为丢包
static void test_oos_pn_remote_multi_pn_injection() {
    std::printf("[test] OOS_PN remote multi-PN injection...\n");
    LossDetector ld;

    // 注入 10 个包
    for (uint64_t pn = 10; pn <= 100; pn += 10) {
        ld.on_packet_sent(pn, 1000.0, 1200, true);
    }

    // 对端 ACK 确认 pn=100
    std::vector<uint64_t> acked = {100};
    // 接收方反馈：pn=30, 50, 70, 90 仍在 OOS buffer
    std::vector<OosPnInfo> oos_pn_list;
    for (uint64_t pn : {30ULL, 50ULL, 70ULL, 90ULL}) {
        OosPnInfo info;
        info.stream_id = 1;
        info.pn = pn;
        info.offset = pn * 10;
        info.size = 1200;
        info.first_seen_ms = 1010.0;
        oos_pn_list.push_back(info);
    }

    auto lost = ld.on_ack_received(acked, 1010.0, oos_pn_list);

    // 验证 4 个 PN 都在 lost 列表
    std::size_t found_count = 0;
    for (uint64_t target : {30ULL, 50ULL, 70ULL, 90ULL}) {
        for (uint64_t pn : lost) {
            if (pn == target) {
                ++found_count;
                break;
            }
        }
    }
    CHECK(found_count == 4);

    std::printf("    oos_pn_list.size()=%zu, found_count=%zu\n",
                oos_pn_list.size(), found_count);
}

// ============================================================================
// TEST 6: OOS_PN_FRAME 默认空 list 行为与 v1.5.0.3 完全一致（ABI 兼容）
// ============================================================================
// v1.5.0.4 Q3 答复：on_ack_received 第三参数默认空 vector 时与 v1.5.0.3 行为一致
// v1.5.0.5 沿用此约定 — OosPnInfo::pn=0 表示"无 PN 关联"，不影响
static void test_oos_pn_default_empty_list_compat() {
    std::printf("[test] OOS_PN default empty list ABI compat with v1.5.0.3...\n");

    // 双 LossDetector 对照实验：ld_default 不传 oos_pn_list（默认空 vector），
    // ld_explicit 显式传空 vector。两者应在相同输入下产出相同的 lost 集合，
    // 即 ABI 行为完全兼容。
    LossDetector ld_default;
    LossDetector ld_explicit;

    // 注入 3 个包（两个对象状态完全一致）
    for (uint64_t pn : {10ULL, 20ULL, 30ULL}) {
        ld_default.on_packet_sent(pn, 1000.0, 1200, true);
        ld_explicit.on_packet_sent(pn, 1000.0, 1200, true);
    }

    std::vector<uint64_t> acked = {30};

    // 路径 A：不传 oos_pn_list（默认空 vector，调用旧版签名）
    auto lost_a = ld_default.on_ack_received(acked, 1010.0);

    // 路径 B：显式传空 vector
    std::vector<OosPnInfo> empty;
    auto lost_b = ld_explicit.on_ack_received(acked, 1010.0, empty);

    std::size_t count1 = lost_a.size();
    std::size_t count2 = lost_b.size();
    std::printf("    default_empty_count=%zu, explicit_empty_count=%zu\n",
                count1, count2);
    CHECK(count1 == count2);
}

// ============================================================================
// TEST 7: v1.5.0.6 端到端网络传输 — 完整覆盖 ISSUE T05 修复场景
// ============================================================================
// 模拟完整数据通路：
//   1. 接收方 Connection::build_1rtt_packet 流程
//      a) encode_oos_pn_frame() 返回字节（不含 type）
//      b) 显式追加 type 字节（0x30）到 packet payload
//   2. 跨网络传输
//   3. 发送方 PacketParser::parse_frames 处理
//      a) 读取 type 字节（payload[pos++]）并丢弃
//      b) case 0x30 分支将 payload[pos..end] 赋值给 f.data（不含 type）
//   4. 发送方 Connection::handle_oos_pn_frame(f.data) 调用 decode_oos_pn_frame
//      a) v1.5.0.6 修复：data[0] 不再要求是 0x30（已是 stream_id varint）
//      b) pos=0 开始解析 stream_id
//
// v1.5.0.5 bug 复现：step 1b 错误地把 type 字节包含在 encode 输出里，
//   step 4a 的 data[0] 永远是 stream_id varint（永远 != 0x30），decode 失败。
static void test_oos_pn_frame_e2e_network_transport() {
    std::printf("[test] v1.5.0.6 OOS_PN_FRAME E2E network transport (ISSUE fix)...\n");

    // Step 1a: encode 输出（不含 type 字节）
    OosPnFrame frame;
    frame.stream_id = 1;
    OosPnEntry e;
    e.offset = 649944;  // 视频模型组日志中真实 first_gap_offset
    e.first_seen_ms = 627.536;  // 视频模型组日志中真实 first_seen_ms
    frame.entries.push_back(e);

    auto encode_output = encode_oos_pn_frame(frame);
    // v1.5.0.6 断言：encode 输出不含 type 字节
    CHECK(!encode_output.empty());
    CHECK(encode_output[0] != static_cast<uint8_t>(FrameType::OOS_PN));

    // Step 1b: 模拟 build_1rtt_packet 显式追加 type 字节
    std::vector<std::uint8_t> packet_payload;
    packet_payload.reserve(1 + encode_output.size());
    packet_payload.push_back(static_cast<uint8_t>(FrameType::OOS_PN));  // 显式写 type
    packet_payload.insert(packet_payload.end(), encode_output.begin(), encode_output.end());

    // 验证 packet_payload 包含 type 字节
    CHECK(packet_payload[0] == 0x30);

    // Step 2: 模拟跨网络传输（packet_payload 字节不变）

    // Step 3: 模拟 PacketParser::parse_frames 行为
    // 简化版：跳过 type 字节，剩余 payload 全部作为 f.data
    std::span<const std::uint8_t> full_payload(packet_payload.data(), packet_payload.size());
    std::uint8_t ft = full_payload[0];  // parse_frames 读取 type
    std::span<const std::uint8_t> f_data(full_payload.data() + 1, full_payload.size() - 1);

    CHECK(ft == 0x30);  // 确认 type 字节
    // f.data 不含 type 字节，与 v1.5.0.5 行为一致
    CHECK(f_data.size() == encode_output.size());

    // Step 4: 模拟 handle_oos_pn_frame 调用 decode_oos_pn_frame
    // v1.5.0.5 bug：data[0] (= stream_id varint = 0x01) != 0x30 → 永远失败
    // v1.5.0.6 修复：data[0] 不再要求是 0x30，pos=0 解析 stream_id
    auto decoded = decode_oos_pn_frame(f_data);
    CHECK(decoded.has_value());  // v1.5.0.5 永远 false，v1.5.0.6 必须 true
    if (decoded) {
        CHECK(decoded->stream_id == 1);
        CHECK(decoded->entries.size() == 1);
        CHECK(decoded->entries[0].offset == 649944);
        CHECK(NEAR_LOSSY(decoded->entries[0].first_seen_ms, 627.536));  // 0.1ms 精度有损
    }

    std::printf("    e2e encode_size=%zu, packet_size=%zu, f_data_size=%zu, decoded=%s\n",
                encode_output.size(), packet_payload.size(), f_data.size(),
                decoded.has_value() ? "OK" : "FAIL");
}

// ============================================================================
// TEST 8: v1.5.0.6 端到端 — 视频模型组日志真实场景（25 字节 payload）
// ============================================================================
// 视频模型组 §3.3 日志：
//   - master 端看到 payload_size=9 + size=8（f.data 8 字节，不含 type）
//   - 24 次 size=10 + 1 次 size=8
//   - decode OOS_PN_FRAME failed 25/25 次
// v1.5.0.6 修复后必须 25/25 全部成功。
//
// 构造一个 worker 端 OOS buffer，反馈 stream_id=1 + offset=649944 +
// first_seen_ms=627.536，编码后总长度 8 字节（不含 type），加上 type 字节共 9 字节，
// 完整匹配视频模型组日志。
static void test_oos_pn_frame_v1506_matches_video_model_log() {
    std::printf("[test] v1.5.0.6 matches video_model_group T05 log (25/25 success)...\n");

    // 模拟 25 个不同 OOS gap 反馈
    std::size_t success_count = 0;
    for (int i = 0; i < 25; ++i) {
        OosPnFrame frame;
        frame.stream_id = 1;
        OosPnEntry e;
        e.offset = 649944 + static_cast<std::uint64_t>(i) * 100;
        e.first_seen_ms = 627.536 + static_cast<double>(i) * 0.1;
        frame.entries.push_back(e);

        // Step 1: encode（不含 type）
        auto encode_output = encode_oos_pn_frame(frame);
        CHECK(!encode_output.empty());

        // Step 2: 模拟 build_1rtt_packet 显式追加 type
        std::vector<std::uint8_t> packet_payload;
        packet_payload.push_back(static_cast<uint8_t>(FrameType::OOS_PN));
        packet_payload.insert(packet_payload.end(), encode_output.begin(), encode_output.end());

        // Step 3: 模拟 parse_frames 吞 type
        std::span<const std::uint8_t> f_data(packet_payload.data() + 1, packet_payload.size() - 1);

        // Step 4: decode
        auto decoded = decode_oos_pn_frame(f_data);
        if (decoded.has_value()) {
            ++success_count;
        }
    }

    // v1.5.0.5 永远 0/25，v1.5.0.6 必须 25/25
    CHECK(success_count == 25);

    std::printf("    success_count=%zu/25 (v1.5.0.5 was 0/25)\n", success_count);
}

// ============================================================================
// TEST 9: v1.5.0.6 端到端 — 多 entries（kMaxEntriesPerFrame=256 边界）
// ============================================================================
static void test_oos_pn_frame_e2e_multi_entries_256() {
    std::printf("[test] v1.5.0.6 E2E multi-entries up to kMaxEntriesPerFrame=256...\n");

    // 构造 256 entries（边界值）
    OosPnFrame frame;
    frame.stream_id = 42;
    for (int i = 0; i < 256; ++i) {
        OosPnEntry e;
        e.offset = static_cast<std::uint64_t>(i) * 1000;
        e.first_seen_ms = static_cast<double>(i) * 1.0;
        frame.entries.push_back(e);
    }

    // E2E: encode → prepend type → parse → decode
    auto encode_output = encode_oos_pn_frame(frame);
    std::vector<std::uint8_t> packet_payload;
    packet_payload.push_back(static_cast<uint8_t>(FrameType::OOS_PN));
    packet_payload.insert(packet_payload.end(), encode_output.begin(), encode_output.end());
    std::span<const std::uint8_t> f_data(packet_payload.data() + 1, packet_payload.size() - 1);

    auto decoded = decode_oos_pn_frame(f_data);
    CHECK(decoded.has_value());
    if (decoded) {
        CHECK(decoded->stream_id == 42);
        CHECK(decoded->entries.size() == 256);
        CHECK(decoded->entries[0].offset == 0);
        CHECK(decoded->entries[255].offset == 255000);
    }

    // 257 entries 应被 encode 限幅到 256
    OosPnFrame over;
    over.stream_id = 7;
    for (int i = 0; i < 257; ++i) {
        OosPnEntry e;
        e.offset = static_cast<std::uint64_t>(i);
        e.first_seen_ms = static_cast<double>(i);
        over.entries.push_back(e);
    }
    auto over_enc = encode_oos_pn_frame(over);
    std::vector<std::uint8_t> over_pkt;
    over_pkt.push_back(static_cast<uint8_t>(FrameType::OOS_PN));
    over_pkt.insert(over_pkt.end(), over_enc.begin(), over_enc.end());
    std::span<const std::uint8_t> over_f(over_pkt.data() + 1, over_pkt.size() - 1);
    auto over_dec = decode_oos_pn_frame(over_f);
    CHECK(over_dec.has_value());
    if (over_dec) {
        CHECK(over_dec->entries.size() == 256);  // 限幅到 256
    }

    std::printf("    256 entries OK, 257 entries clamped to 256\n");
}

int main() {
    std::printf("=== test_loss_recovery_v1505 ===\n");

    test_oos_pn_frame_encode_decode();
    test_oos_pn_frame_multi_entries_and_clamp();
    test_oos_pn_remote_injection_triggers_loss_detection();
    test_sent_packet_info_extension_compat();
    test_oos_pn_remote_multi_pn_injection();
    test_oos_pn_default_empty_list_compat();
    test_oos_pn_frame_e2e_network_transport();
    test_oos_pn_frame_v1506_matches_video_model_log();
    test_oos_pn_frame_e2e_multi_entries_256();

    std::printf("\n=== Result: %d/%d passed ===\n", g_pass, g_pass + g_fail);
    return (g_fail == 0) ? 0 : 1;
}
