// test_loss_recovery_v1508.cpp — v1.5.0.8 Connection→LossDetector OOS_PN 同步测试
//
// 验证 v1.5.0.7 T07 反馈根因（ISSUE）：
//   v1.5.0.5/0.6/0.7 修复了 OOS_PN_FRAME 编码 + 触发链路 + 编解码对称性，
//   但 LossDetector 仍 oos_pn_list_size=0，OOS_PN 链路未触发重传。
//   根因：
//     1. Connection.oos_pn_remote_ 未同步到 LossDetector.oos_pn_list_
//        (Connection 层 oos_pn_remote_ 写入，LossDetector 仅基于 packet PN
//         gap/time gap 检测丢包，不感知 stream-level OOS gap)
//     2. handle_ack_frame 阶段 1 反查逻辑用 sent_bytes（1-RTT 包总大小）匹配
//        stream_offset → 永远不命中（v1.5.0.5/0.6/0.7 共有缺陷）
//
// v1.5.0.8 修复方案：
//   1. LossDetector 新增 on_oos_pn_received(stream_id, entries) 接口
//      - Connection.handle_oos_pn_frame decode 成功后立即调用
//      - 按 stream_id 严格过滤 sent_packets_
//      - 用 stream_payload_bytes 精确反查 PN
//      - 对 pn < largest_acked 且 in_flight 的 PN 立即 mark_lost
//   2. SentPacketInfo 新增 stream_payload_bytes 字段
//      - Connection::build_1rtt_packet 跟踪首个 STREAM 帧的 payload 字节数
//      - 0 表示非 STREAM 帧
//   3. handle_ack_frame 反查逻辑修补：stream_payload_bytes 替代 sent_bytes
//
// 测试矩阵（6 用例）：
//   1. on_oos_pn_received 基础功能（stream_id 过滤 + 命中 PN + mark_lost + 计数）
//   2. stream_payload_bytes 精确反查（offset 范围 [stream_offset, +stream_payload_bytes)）
//   3. 多 stream 独立处理（不同 stream_id 不串扰）
//   4. 同一 PN 去重（多个 entry 命中同一 PN 仅 mark_lost 一次）
//   5. 端到端 OOS_PN 触发重传（Connection handle_oos_pn_frame → LossDetector 反查 → retransmit_queue）
//   6. T07 业务场景回放（v1.5.0.5/0.6/0.7 失败用例重现，v1.5.0.8 修复确认）
//
// 测试基线：v1.5.0.7 (commit 61e6621)
// 目标版本：v1.5.0.8 (ISSUE T07 修复)

#include "linoh/base/key.hpp"
#include "linoh/endpoint/connection.hpp"
#include "linoh/endpoint/state_machine.hpp"
#include "linoh/protocol/loss_recovery.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/util/bytes.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <span>
#include <string>
#include <vector>

using namespace linoh;
using namespace linoh::endpoint;
using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (%lld != %lld) (line %d)\n", \
        #a, #b, (long long)_a, (long long)_b, __LINE__); } \
} while (0)

// 重定向 std::cerr 到 stringstream，用于验证 LINOH_INFO/WARN 埋点输出
class CerrCapture {
public:
    CerrCapture() : old_buf_(std::cerr.rdbuf(capture_.rdbuf())) {}
    ~CerrCapture() { std::cerr.rdbuf(old_buf_); }

    std::string drain() {
        std::string s = capture_.str();
        capture_.str("");
        capture_.clear();
        return s;
    }

    bool contains(const std::string &marker) {
        return capture_.str().find(marker) != std::string::npos;
    }

private:
    std::stringstream capture_;
    std::streambuf *old_buf_;
};

// ============================================================================
// Connection 握手助手
// ============================================================================
static void shuttle(std::shared_ptr<Connection> client, std::shared_ptr<Connection> server) {
    auto ch = client->take_handshake_flight();
    server->feed_handshake(ch);
    auto sf = server->take_handshake_flight();
    client->feed_handshake(sf);
    auto cf = client->take_handshake_flight();
    server->feed_handshake(cf);
}

static Connection::Config make_cfg(const base::SecretKey &sk, Direction dir,
                                   const protocol::ConnectionId &local,
                                   const protocol::ConnectionId &remote) {
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = local;
    cfg.remote_cid = remote;
    cfg.direction = dir;
    cfg.alpn = "linoh-tls13";
    cfg.handshake.mode = HandshakeMode::Tls13;
    return cfg;
}

static std::pair<std::shared_ptr<Connection>, std::shared_ptr<Connection>>
make_established_pair() {
    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    auto c_cid = protocol::ConnectionId::generate();
    auto s_cid = protocol::ConnectionId::generate();

    auto client = std::make_shared<Connection>(
        make_cfg(c_sk, Direction::Outbound, c_cid, s_cid));
    auto server = std::make_shared<Connection>(
        make_cfg(s_sk, Direction::Inbound, s_cid, c_cid));

    client->start_handshake(0.0);
    shuttle(client, server);

    if (client->state() != ConnState::Established ||
        server->state() != ConnState::Established) {
        return {nullptr, nullptr};
    }
    return {client, server};
}

// ============================================================================
// TEST 1: on_oos_pn_received 基础功能验证
// ============================================================================
// v1.5.0.8 关键修复：Connection.handle_oos_pn_frame decode 成功后立即调用
// on_oos_pn_received，LossDetector 按 stream_id 严格过滤 + 立即 mark_lost。
//
// 验证点：
//   - 入口计数器 oos_pn_received_total_ 增加
//   - 命中 PN 时 mark_lost 计数器 oos_pn_marked_lost_total_ 增加
//   - 命中 PN in_flight=false（mark_lost 副作用）
//   - 空 entries 不触发 mark_lost
static void test_v1508_on_oos_pn_received_basic() {
    std::printf("[test] v1.5.0.8 on_oos_pn_received basic function...\n");

    LossDetector ld;

    // 初始状态：所有计数器 0
    CHECK_EQ(ld.oos_pn_received_total_for_test(), 0ull);
    CHECK_EQ(ld.oos_pn_marked_lost_total_for_test(), 0ull);
    CHECK_EQ(ld.oos_pn_list_size_for_test(), 0ull);

    // 场景 A: 空 entries → 不 mark_lost
    {
        std::vector<OosPnEntry> empty;
        auto lost = ld.on_oos_pn_received(1, empty);
        CHECK(lost.empty());
        CHECK_EQ(ld.oos_pn_received_total_for_test(), 1ull);
        CHECK_EQ(ld.oos_pn_marked_lost_total_for_test(), 0ull);
    }

    // 场景 B: sent_packets_ 为空 → 反查不命中
    {
        std::vector<OosPnEntry> entries = {{.offset = 100, .first_seen_ms = 1000.0}};
        auto lost = ld.on_oos_pn_received(1, entries);
        CHECK(lost.empty());
        CHECK_EQ(ld.oos_pn_received_total_for_test(), 2ull);
        CHECK_EQ(ld.oos_pn_marked_lost_total_for_test(), 0ull);
    }

    // 场景 C: 构造 sent_packets_：PN=1 (stream 1, offset=0, 1000B),
    //   PN=2 (stream 2, offset=0, 500B)
    //   v1.5.0.8 修复: on_oos_pn_received 仅依赖 in_flight 判定，不再要求
    //   pn < largest_acked_。OOS buffer 语义已隐含"接收方已收到对端 ACK 推进
    //   recv_offset_"，所以无需调用 on_ack_received 推进 largest_acked_。
    //   v1.5.0.9: SentPacketInfo 改用 stream_ranges vector，单 stream PN 用 1 个 range
    {
        std::vector<StreamRange> r1 = {{.stream_id = 1, .offset = 0, .payload_bytes = 1000}};
        std::vector<StreamRange> r2 = {{.stream_id = 2, .offset = 0, .payload_bytes = 500}};
        ld.on_packet_sent(1, 0.0, 1500, true, r1);    // stream 1
        ld.on_packet_sent(2, 0.0, 1000, true, r2);     // stream 2

        std::vector<OosPnEntry> entries = {{.offset = 500, .first_seen_ms = 1000.0}};
        auto lost = ld.on_oos_pn_received(1, entries);
        CHECK_EQ(lost.size(), 1ull);
        CHECK_EQ(lost[0], 1ull);
        CHECK_EQ(ld.oos_pn_received_total_for_test(), 3ull);
        CHECK_EQ(ld.oos_pn_marked_lost_total_for_test(), 1ull);

        // 验证：sent_packets_ 中 PN=1 已 in_flight=false
        auto sent = ld.sent_packets_for_test();
        CHECK_EQ(sent.size(), 2ull);
        CHECK_EQ(sent[0].pn, 1ull);
        CHECK(!sent[0].in_flight);  // mark_lost 副作用
        // PN=2 仍 in_flight
        CHECK_EQ(sent[1].pn, 2ull);
        CHECK(sent[1].in_flight);
    }

    std::printf("    basic: received=%llu marked_lost=%llu oos_list_size=%llu\n",
                (unsigned long long)ld.oos_pn_received_total_for_test(),
                (unsigned long long)ld.oos_pn_marked_lost_total_for_test(),
                (unsigned long long)ld.oos_pn_list_size_for_test());
}

// ============================================================================
// TEST 2: stream_payload_bytes 精确反查验证
// ============================================================================
// v1.5.0.8 关键修复：用 stream_payload_bytes（仅 stream 字节）替代 sent_bytes
// （1-RTT 包总大小）做 OOS_PN_FRAME offset→PN 反查。
//
// v1.5.0.5/0.6/0.7 bug：sent_bytes 远大于 stream_payload_bytes（如 1500 vs 1000），
// 导致 handle_ack_frame 阶段 1 反查条件 `info.stream_offset + info.sent_bytes <= target_offset`
// 永远不命中 → OOS gap 永远不触发 retx。
//
// 验证点：
//   - offset 在 [stream_offset, stream_offset+stream_payload_bytes) 范围内才命中
//   - offset < stream_offset 不命中
//   - offset >= stream_offset+stream_payload_bytes 不命中
static void test_v1508_stream_payload_bytes_match() {
    std::printf("[test] v1.5.0.8 stream_payload_bytes precise match...\n");

    LossDetector ld;

    // 构造：PN=1 (stream 1, offset=0, payload=1000B)
    // 关键：sent_bytes=1500（含帧头/ACK/控制）vs stream_payload_bytes=1000（仅 stream data）
    {
        std::vector<StreamRange> r = {{.stream_id = 1, .offset = 0, .payload_bytes = 1000}};
        ld.on_packet_sent(1, 0.0, 1500, true, r);
    }

    // 场景 A: offset=500 在 [0, 1000) 范围内 → 命中
    {
        std::vector<OosPnEntry> entries = {{.offset = 500, .first_seen_ms = 1000.0}};
        auto lost = ld.on_oos_pn_received(1, entries);
        CHECK_EQ(lost.size(), 1ull);
        CHECK_EQ(lost[0], 1ull);
    }

    // 重置（构造新 detector 测试边界）
    LossDetector ld2;
    {
        std::vector<StreamRange> r = {{.stream_id = 1, .offset = 0, .payload_bytes = 1000}};
        ld2.on_packet_sent(1, 0.0, 1500, true, r);
    }

    // 场景 B: offset=999（接近上限）→ 命中 [0, 1000)
    {
        std::vector<OosPnEntry> entries = {{.offset = 999, .first_seen_ms = 1000.0}};
        auto lost = ld2.on_oos_pn_received(1, entries);
        CHECK_EQ(lost.size(), 1ull);
    }

    // 场景 C: offset=1009（超出上限 + 8 tolerance）→ 不命中
    //   v1.5.0.11: kRangeToleranceBytes=8，range 上界扩展为 [0, 1008)
    //   旧 v1.5.0.8 strict 测试用 offset=1000 不再适用（会命中），改为 +9
    {
        LossDetector ld3;
        {
            std::vector<StreamRange> r = {{.stream_id = 1, .offset = 0, .payload_bytes = 1000}};
            ld3.on_packet_sent(1, 0.0, 1500, true, r);
        }
        std::vector<OosPnEntry> entries = {{.offset = 1009, .first_seen_ms = 1000.0}};
        auto lost = ld3.on_oos_pn_received(1, entries);
        CHECK(lost.empty());
        CHECK_EQ(ld3.oos_pn_marked_lost_total_for_test(), 0ull);
    }

    // 场景 D: offset=0（边界，下界）→ 命中
    {
        LossDetector ld4;
        {
            std::vector<StreamRange> r = {{.stream_id = 1, .offset = 0, .payload_bytes = 1000}};
            ld4.on_packet_sent(1, 0.0, 1500, true, r);
        }
        std::vector<OosPnEntry> entries = {{.offset = 0, .first_seen_ms = 1000.0}};
        auto lost = ld4.on_oos_pn_received(1, entries);
        CHECK_EQ(lost.size(), 1ull);
    }

    // 场景 E: 多 PN 跨包：PN=1 (stream 1, offset=0, 1000B), PN=2 (stream 1, offset=1000, 800B)
    //   offset=1500 在 PN=2 范围内 → 仅 PN=2 命中
    {
        LossDetector ld5;
        {
            std::vector<StreamRange> r1 = {{.stream_id = 1, .offset = 0, .payload_bytes = 1000}};
            std::vector<StreamRange> r2 = {{.stream_id = 1, .offset = 1000, .payload_bytes = 800}};
            ld5.on_packet_sent(1, 0.0, 1500, true, r1);
            ld5.on_packet_sent(2, 0.0, 1300, true, r2);
        }

        std::vector<OosPnEntry> entries = {{.offset = 1500, .first_seen_ms = 1000.0}};
        auto lost = ld5.on_oos_pn_received(1, entries);
        CHECK_EQ(lost.size(), 1ull);
        CHECK_EQ(lost[0], 2ull);  // PN=2 而非 PN=1
    }

    std::printf("    stream_payload_bytes match: offset boundary + multi-PN cross-PN\n");
}

// ============================================================================
// TEST 3: 多 stream 独立处理（不同 stream_id 不串扰）
// ============================================================================
// v1.5.0.8 修复：on_oos_pn_received 按 stream_id 严格过滤 sent_packets_，
// 避免 v1.5.0.5/0.6/0.7 跨 stream 误匹配。
//
// 验证点：
//   - stream_id=1 的 entry 只反查 stream 1 的 PN
//   - stream_id=2 的 entry 只反查 stream 2 的 PN
//   - 即使 offset 重叠也不串扰
static void test_v1508_multi_stream_isolation() {
    std::printf("[test] v1.5.0.8 multi-stream isolation (no cross-stream false match)...\n");

    LossDetector ld;

    // PN=1 (stream 1, offset=0, 1000B)
    // PN=2 (stream 2, offset=0, 1000B)  ← 同样 offset=0
    {
        std::vector<StreamRange> r1 = {{.stream_id = 1, .offset = 0, .payload_bytes = 1000}};
        std::vector<StreamRange> r2 = {{.stream_id = 2, .offset = 0, .payload_bytes = 1000}};
        ld.on_packet_sent(1, 0.0, 1500, true, r1);
        ld.on_packet_sent(2, 0.0, 1500, true, r2);
    }

    // 查询 stream 1 → 仅 PN=1 命中
    {
        std::vector<OosPnEntry> entries = {{.offset = 500, .first_seen_ms = 1000.0}};
        auto lost = ld.on_oos_pn_received(1, entries);
        CHECK_EQ(lost.size(), 1ull);
        CHECK_EQ(lost[0], 1ull);
    }

    // 查询 stream 2 → 仅 PN=2 命中
    {
        std::vector<OosPnEntry> entries = {{.offset = 500, .first_seen_ms = 1000.0}};
        auto lost = ld.on_oos_pn_received(2, entries);
        CHECK_EQ(lost.size(), 1ull);
        CHECK_EQ(lost[0], 2ull);
    }

    // 查询 stream 99 (无对应 PN) → 不命中
    {
        std::vector<OosPnEntry> entries = {{.offset = 500, .first_seen_ms = 1000.0}};
        auto lost = ld.on_oos_pn_received(99, entries);
        CHECK(lost.empty());
    }

    // 多 stream 混合 entries 一次查询
    {
        LossDetector ld2;
        {
            std::vector<StreamRange> r1 = {{.stream_id = 1, .offset = 0, .payload_bytes = 1000}};
            std::vector<StreamRange> r2 = {{.stream_id = 2, .offset = 0, .payload_bytes = 1000}};
            std::vector<StreamRange> r3 = {{.stream_id = 3, .offset = 0, .payload_bytes = 1000}};
            ld2.on_packet_sent(1, 0.0, 1500, true, r1);
            ld2.on_packet_sent(2, 0.0, 1500, true, r2);
            ld2.on_packet_sent(3, 0.0, 1500, true, r3);
        }

        // 一次性给 stream 1 的 entry → 仅 PN=1 命中
        std::vector<OosPnEntry> entries = {{.offset = 500, .first_seen_ms = 1000.0}};
        auto lost = ld2.on_oos_pn_received(1, entries);
        CHECK_EQ(lost.size(), 1ull);
        CHECK_EQ(lost[0], 1ull);
    }

    std::printf("    multi-stream isolation verified\n");
}

// ============================================================================
// TEST 4: 同一 PN 去重（多个 entry 命中同一 PN 仅 mark_lost 一次）
// ============================================================================
// v1.5.0.8 修复：on_oos_pn_received 内部对同一 PN 去重，避免重复 mark_lost。
//
// 验证点：
//   - 多个 entry 命中同一 PN → lost vector 仅包含一次
//   - oos_pn_marked_lost_total_ 仅增加 1
//   - oos_pn_list_ 中该 PN 仅出现 1 次
static void test_v1508_same_pn_dedup() {
    std::printf("[test] v1.5.0.8 same-PN dedup (multi-entry hit same PN, mark_lost once)...\n");

    LossDetector ld;

    // 构造：PN=1 (stream 1, offset=0, 1000B)
    std::vector<StreamRange> r_dedup = {{.stream_id = 1, .offset = 0, .payload_bytes = 1000}};
    ld.on_packet_sent(1, 0.0, 1500, true, r_dedup);

    // 3 个 entry 都命中 PN=1（offset=100/200/300 都在 [0, 1000) 范围内）
    {
        std::vector<OosPnEntry> entries = {
            {.offset = 100, .first_seen_ms = 1000.0},
            {.offset = 200, .first_seen_ms = 1000.0},
            {.offset = 300, .first_seen_ms = 1000.0},
        };
        auto lost = ld.on_oos_pn_received(1, entries);
        CHECK_EQ(lost.size(), 1ull);  // 仅 1 个 PN
        CHECK_EQ(lost[0], 1ull);
        CHECK_EQ(ld.oos_pn_marked_lost_total_for_test(), 1ull);  // 计数器仅 1
        CHECK_EQ(ld.oos_pn_list_size_for_test(), 1ull);  // oos_pn_list_ 仅 1 个
    }

    // 验证：再次 on_oos_pn_received（PN=1 已 in_flight=false）→ 不再 mark_lost
    {
        std::vector<OosPnEntry> entries = {{.offset = 400, .first_seen_ms = 1000.0}};
        auto lost = ld.on_oos_pn_received(1, entries);
        CHECK(lost.empty());  // PN=1 已 in_flight=false 跳过
        CHECK_EQ(ld.oos_pn_marked_lost_total_for_test(), 1ull);  // 计数器不变
    }

    std::printf("    dedup verified: 3 entries → 1 PN → 1 mark_lost\n");
}

// ============================================================================
// TEST 5: 端到端 OOS_PN 触发重传
//   Connection handle_oos_pn_frame → LossDetector on_oos_pn_received → retransmit_queue
// ============================================================================
// v1.5.0.8 端到端验证：
//   1. Connection 构造完成握手
//   2. 模拟发送方在 sent_packets_ 中记录带 stream_payload_bytes 的 PN
//   3. 构造 OOS_PN_FRAME 反馈 OOS buffer
//   4. 接收方（也是发送方，因为 P2P 协议同一连接上）handle_oos_pn_frame
//   5. 验证 LossDetector.on_oos_pn_received 被调用 + oos_pn_received_total_ 增加
//   6. 验证 handle_oos_pn_frame 后 retransmit_queue_ 包含 mark_lost 的 PN
//
// 注：本测试使用 loss_detector_for_test() 访问器直接构造 sent_packets_ 状态，
//   避免依赖复杂的 STREAM 数据传输 + 实际 PN 跟踪。
static void test_v1508_e2e_oos_pn_trigger_retx() {
    std::printf("[test] v1.5.0.8 E2E OOS_PN trigger retx (Connection→LossDetector→retransmit)...\n");

    auto [client, server] = make_established_pair();
    CHECK(client != nullptr);
    CHECK(server != nullptr);
    if (!client || !server) return;

    // 步骤 1: 在 client 端 LossDetector 构造 sent_packets_ 状态
    //   PN=1 (stream 1, offset=0, 1000B)
    //   PN=2 (stream 1, offset=1000, 500B)
    //   PN=3 (stream 2, offset=0, 800B)
    auto &ld = client->loss_detector_for_test();
    std::vector<StreamRange> r_e2e_1 = {{.stream_id = 1, .offset = 0, .payload_bytes = 1000}};
    std::vector<StreamRange> r_e2e_2 = {{.stream_id = 1, .offset = 1000, .payload_bytes = 500}};
    std::vector<StreamRange> r_e2e_3 = {{.stream_id = 2, .offset = 0, .payload_bytes = 800}};
    ld.on_packet_sent(1, 0.0, 1500, true, r_e2e_1);
    ld.on_packet_sent(2, 0.0, 1000, true, r_e2e_2);
    ld.on_packet_sent(3, 0.0, 1300, true, r_e2e_3);

    CHECK_EQ(ld.oos_pn_received_total_for_test(), 0ull);
    CHECK_EQ(ld.oos_pn_marked_lost_total_for_test(), 0ull);
    CHECK(client->pending_retransmits().empty());

    // 步骤 2: 构造 OOS_PN_FRAME：stream 1, offset=500 落在 PN=1 范围内 [0, 1000)
    {
        OosPnFrame frame;
        frame.stream_id = 1;
        OosPnEntry e;
        e.offset = 500;
        e.first_seen_ms = 100.0;
        frame.entries.push_back(e);
        auto data = encode_oos_pn_frame(frame);

        // 步骤 3: client->handle_oos_pn_frame(data)
        client->handle_oos_pn_frame(data);

        // 步骤 4: 验证 LossDetector 计数器
        CHECK_EQ(ld.oos_pn_received_total_for_test(), 1ull);
        CHECK_EQ(ld.oos_pn_marked_lost_total_for_test(), 1ull);

        // 步骤 5: 验证 retransmit_queue_ 包含 PN=1
        auto retx = client->pending_retransmits();
        CHECK_EQ(retx.size(), 1ull);
        if (retx.size() == 1) {
            CHECK_EQ(retx[0], 1ull);
        }
    }

    // 步骤 6: 第二个 OOS_PN_FRAME：stream 1, offset=1200 落在 PN=2 范围内 [1000, 1500)
    {
        OosPnFrame frame;
        frame.stream_id = 1;
        OosPnEntry e;
        e.offset = 1200;
        e.first_seen_ms = 200.0;
        frame.entries.push_back(e);
        auto data = encode_oos_pn_frame(frame);

        client->handle_oos_pn_frame(data);

        CHECK_EQ(ld.oos_pn_received_total_for_test(), 2ull);
        CHECK_EQ(ld.oos_pn_marked_lost_total_for_test(), 2ull);

        auto retx = client->pending_retransmits();
        CHECK_EQ(retx.size(), 2ull);
    }

    // 步骤 7: 第三个 OOS_PN_FRAME：stream 2, offset=300 落在 PN=3 范围内 [0, 800)
    {
        OosPnFrame frame;
        frame.stream_id = 2;
        OosPnEntry e;
        e.offset = 300;
        e.first_seen_ms = 300.0;
        frame.entries.push_back(e);
        auto data = encode_oos_pn_frame(frame);

        client->handle_oos_pn_frame(data);

        CHECK_EQ(ld.oos_pn_received_total_for_test(), 3ull);
        CHECK_EQ(ld.oos_pn_marked_lost_total_for_test(), 3ull);

        auto retx = client->pending_retransmits();
        CHECK_EQ(retx.size(), 3ull);
        // 验证：retx 队列包含 1, 2, 3
        bool has_1 = std::find(retx.begin(), retx.end(), 1ull) != retx.end();
        bool has_2 = std::find(retx.begin(), retx.end(), 2ull) != retx.end();
        bool has_3 = std::find(retx.begin(), retx.end(), 3ull) != retx.end();
        CHECK(has_1);
        CHECK(has_2);
        CHECK(has_3);
    }

    std::printf("    E2E: 3 OOS_PN frames → 3 retx (PN 1, 2, 3)\n");
}

// ============================================================================
// TEST 6: T07 业务场景回放（v1.5.0.5/0.6/0.7 失败用例）
// ============================================================================
// ISSUE T07 反馈场景：
//   视频组部署 v1.5.0.7 后，T05 测试仍 OOS gap 永久不触发 retx。
//   根因复现：
//     - sent_packets_ 中 PN 已正确记录（v1.5.0.5+）
//     - OOS_PN_FRAME decode 成功（v1.5.0.6+）
//     - oos_pn_remote_ 写入成功（v1.5.0.5+）
//     - 但 LossDetector.oos_pn_list_size=0（v1.5.0.7 缺陷）
//   v1.5.0.8 修复：on_oos_pn_received 同步 + stream_payload_bytes 精确反查
//
// 验证点：
//   - 模拟视频组日志场景：real_offset=649944，real_stream_payload_bytes=1000
//   - v1.5.0.7 行为：on_oos_pn_received 未被调用 → oos_pn_list_size=0
//   - v1.5.0.8 行为：on_oos_pn_received 调用 → mark_lost 触发
static void test_v1508_t07_scenario_replay() {
    std::printf("[test] v1.5.0.8 T07 ISSUE scenario replay (real video offset)...\n");

    auto [client, server] = make_established_pair();
    CHECK(client != nullptr);
    CHECK(server != nullptr);
    if (!client || !server) return;

    // 模拟视频组日志场景：
    //   first_gap_offset = 649944
    //   对应发送方 PN=1 携带的 stream 范围 [649000, 650000) = 1000B
    auto &ld = client->loss_detector_for_test();
    std::vector<StreamRange> r_t07 = {{.stream_id = 1, .offset = 649000, .payload_bytes = 1000}};
    ld.on_packet_sent(1, 0.0, 1500, true, r_t07);

    // 视频组日志中 first_seen_ms = 627.536 (0.1ms 单位 → 实际 ms 精度)
    OosPnFrame frame;
    frame.stream_id = 1;
    OosPnEntry e;
    e.offset = 649944;
    e.first_seen_ms = 627.536;
    frame.entries.push_back(e);
    auto data = encode_oos_pn_frame(frame);

    CerrCapture cap;
    client->handle_oos_pn_frame(data);

    // v1.5.0.8 验证：on_oos_pn_received 被调用，mark_lost 触发
    CHECK_EQ(ld.oos_pn_received_total_for_test(), 1ull);
    CHECK_EQ(ld.oos_pn_marked_lost_total_for_test(), 1ull);

    // 验证：retransmit_queue_ 包含 PN=1
    auto retx = client->pending_retransmits();
    CHECK_EQ(retx.size(), 1ull);
    if (retx.size() == 1) {
        CHECK_EQ(retx[0], 1ull);
    }

    // 验证：INFO 日志包含 on_oos_pn_received summary
    std::string log = cap.drain();
    CHECK(log.find("on_oos_pn_received") != std::string::npos);
    CHECK(log.find("mark_lost_count=") != std::string::npos);

    // v1.5.0.7 行为对比：v1.5.0.7 oos_pn_list_size=0，未触发 retx
    //   本测试断言 oos_pn_list_size_for_test() == 1 验证 v1.5.0.8 已修复
    CHECK_EQ(ld.oos_pn_list_size_for_test(), 1ull);

    std::printf("    T07 replay: offset=649944 → PN=1 retx triggered (v1.5.0.7 was 0)\n");
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== v1.5.0.8 Connection→LossDetector OOS_PN sync tests ===\n");
    std::printf("=== Baseline: v1.5.0.7 (commit 61e6621) ===\n");
    std::printf("=== Target:   v1.5.0.8 (ISSUE T07 fix) ===\n\n");

    test_v1508_on_oos_pn_received_basic();
    test_v1508_stream_payload_bytes_match();
    test_v1508_multi_stream_isolation();
    test_v1508_same_pn_dedup();
    test_v1508_e2e_oos_pn_trigger_retx();
    test_v1508_t07_scenario_replay();

    std::printf("\n=== TEST RESULTS ===\n");
    std::printf("PASS: %d\n", g_pass);
    std::printf("FAIL: %d\n", g_fail);
    std::printf("=== END ===\n");

    return g_fail == 0 ? 0 : 1;
}
