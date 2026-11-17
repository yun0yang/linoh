// test_v500_frames.cpp — v5.0.0 阶段四 T-LP4-001 帧定义与编解码测试
//
// 验证内容：
//   - SESSION_TICKET 帧（0x31）encode/decode 往返
//   - ZERO_RTT_DATA 帧（0x32）encode/decode 往返
//   - 边界条件：空数据、超限数据、截断数据、非法值
//   - parse_frames 对新帧类型的识别
//
// 借鉴 iroh 0.96 Connection<OutgoingZeroRtt> + TLS 1.3 RFC 8446 §4.6.1

#include "linoh/protocol/packet.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <vector>

using namespace linoh::protocol;
using linoh::util::varint_encode_vec;
using linoh::util::varint_decode;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// SESSION_TICKET 帧测试
// ============================================================================

static void test_session_ticket_basic_roundtrip() {
    std::printf("[test] T-LP4-001: SESSION_TICKET basic roundtrip...\n");

    SessionTicketFrame in;
    in.ticket_lifetime = 86400;  // 1 天
    in.ticket_age_add = 0xDEADBEEF;
    in.ticket_nonce = {0x01, 0x02, 0x03, 0x04, 0x05};
    in.ticket = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    auto encoded = encode_session_ticket_frame(in);
    CHECK(!encoded.empty());

    auto decoded = decode_session_ticket_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->ticket_lifetime == 86400);
    CHECK(decoded->ticket_age_add == 0xDEADBEEF);
    CHECK(decoded->ticket_nonce == in.ticket_nonce);
    CHECK(decoded->ticket == in.ticket);
}

static void test_session_ticket_max_lifetime() {
    std::printf("[test] T-LP4-001: SESSION_TICKET max lifetime clamp (7 days)...\n");

    SessionTicketFrame in;
    in.ticket_lifetime = 999999999;  // 远超 7 天
    in.ticket_age_add = 0;
    in.ticket_nonce = {};
    in.ticket = {0x42};

    auto encoded = encode_session_ticket_frame(in);

    // encode 应限幅到 7 天
    auto decoded = decode_session_ticket_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->ticket_lifetime == SessionTicketFrame::kMaxLifetimeSec);
}

static void test_session_ticket_reject_lifetime_over_limit() {
    std::printf("[test] T-LP4-001: SESSION_TICKET reject lifetime > 7 days on decode...\n");

    // 手动构造非法帧（lifetime = 8 天）
    std::vector<uint8_t> bad;
    auto lt = varint_encode_vec(static_cast<std::uint64_t>(691200));  // 8 天
    bad.insert(bad.end(), lt.begin(), lt.end());
    auto taa = varint_encode_vec(0);
    bad.insert(bad.end(), taa.begin(), taa.end());
    auto nl = varint_encode_vec(0);
    bad.insert(bad.end(), nl.begin(), nl.end());
    auto tl = varint_encode_vec(0);
    bad.insert(bad.end(), tl.begin(), tl.end());

    auto decoded = decode_session_ticket_frame(bad);
    CHECK(!decoded.has_value());  // 超限应拒绝
}

static void test_session_ticket_empty_nonce_and_ticket() {
    std::printf("[test] T-LP4-001: SESSION_TICKET empty nonce + ticket...\n");

    SessionTicketFrame in;
    in.ticket_lifetime = 3600;
    in.ticket_age_add = 0x12345678;
    in.ticket_nonce = {};
    in.ticket = {};

    auto encoded = encode_session_ticket_frame(in);
    auto decoded = decode_session_ticket_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->ticket_lifetime == 3600);
    CHECK(decoded->ticket_age_add == 0x12345678);
    CHECK(decoded->ticket_nonce.empty());
    CHECK(decoded->ticket.empty());
}

static void test_session_ticket_large_ticket() {
    std::printf("[test] T-LP4-001: SESSION_TICKET large ticket (1KB)...\n");

    SessionTicketFrame in;
    in.ticket_lifetime = 604800;  // 7 天
    in.ticket_age_add = 0;
    in.ticket_nonce = {0x00};
    in.ticket.resize(1024, 0x55);

    auto encoded = encode_session_ticket_frame(in);
    auto decoded = decode_session_ticket_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->ticket.size() == 1024);
    CHECK(decoded->ticket == in.ticket);
}

static void test_session_ticket_truncated_data() {
    std::printf("[test] T-LP4-001: SESSION_TICKET reject truncated data...\n");

    // 截断数据：只编码 lifetime，缺少后续字段
    std::vector<uint8_t> truncated;
    auto lt = varint_encode_vec(static_cast<std::uint64_t>(3600));
    truncated.insert(truncated.end(), lt.begin(), lt.end());

    auto decoded = decode_session_ticket_frame(truncated);
    CHECK(!decoded.has_value());
}

static void test_session_ticket_empty_data_rejected() {
    std::printf("[test] T-LP4-001: SESSION_TICKET reject empty data...\n");

    auto decoded = decode_session_ticket_frame({});
    CHECK(!decoded.has_value());
}

// ============================================================================
// ZERO_RTT_DATA 帧测试
// ============================================================================

static void test_zero_rtt_data_basic_roundtrip() {
    std::printf("[test] T-LP4-001: ZERO_RTT_DATA basic roundtrip...\n");

    ZeroRttDataFrame in;
    in.stream_id = 42;
    in.offset = 0;
    in.fin = false;
    in.data = {0x01, 0x02, 0x03, 0x04, 0x05};

    auto encoded = encode_zero_rtt_data_frame(in);
    CHECK(!encoded.empty());

    auto decoded = decode_zero_rtt_data_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->stream_id == 42);
    CHECK(decoded->offset == 0);
    CHECK(decoded->fin == false);
    CHECK(decoded->data == in.data);
}

static void test_zero_rtt_data_fin_flag() {
    std::printf("[test] T-LP4-001: ZERO_RTT_DATA fin=true...\n");

    ZeroRttDataFrame in;
    in.stream_id = 7;
    in.offset = 100;
    in.fin = true;
    in.data = {0xFF, 0xFE};

    auto encoded = encode_zero_rtt_data_frame(in);
    auto decoded = decode_zero_rtt_data_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->stream_id == 7);
    CHECK(decoded->offset == 100);
    CHECK(decoded->fin == true);
    CHECK(decoded->data == in.data);
}

static void test_zero_rtt_data_empty_payload() {
    std::printf("[test] T-LP4-001: ZERO_RTT_DATA empty data payload...\n");

    ZeroRttDataFrame in;
    in.stream_id = 0;
    in.offset = 0;
    in.fin = false;
    in.data = {};

    auto encoded = encode_zero_rtt_data_frame(in);
    auto decoded = decode_zero_rtt_data_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->stream_id == 0);
    CHECK(decoded->offset == 0);
    CHECK(decoded->fin == false);
    CHECK(decoded->data.empty());
}

static void test_zero_rtt_data_large_stream_id() {
    std::printf("[test] T-LP4-001: ZERO_RTT_DATA large stream_id (VarInt)...\n");

    ZeroRttDataFrame in;
    in.stream_id = 0x123456789ABCDEF0ULL;  // VarInt 范围内（< 2^62-1）
    in.offset = 0x3FFFFFFFFFFFFFFFULL;     // VarInt 最大值（2^62-1）
    in.fin = true;
    in.data = {0x00};

    auto encoded = encode_zero_rtt_data_frame(in);
    auto decoded = decode_zero_rtt_data_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->stream_id == 0x123456789ABCDEF0ULL);
    CHECK(decoded->offset == 0x3FFFFFFFFFFFFFFFULL);
    CHECK(decoded->fin == true);
}

static void test_zero_rtt_data_truncated_data() {
    std::printf("[test] T-LP4-001: ZERO_RTT_DATA reject truncated (no fin byte)...\n");

    // 只编码 stream_id + offset，缺少 fin 字节
    std::vector<uint8_t> truncated;
    auto sid = varint_encode_vec(42);
    truncated.insert(truncated.end(), sid.begin(), sid.end());
    auto off = varint_encode_vec(0);
    truncated.insert(truncated.end(), off.begin(), off.end());

    auto decoded = decode_zero_rtt_data_frame(truncated);
    CHECK(!decoded.has_value());
}

static void test_zero_rtt_data_empty_data_rejected() {
    std::printf("[test] T-LP4-001: ZERO_RTT_DATA reject completely empty input...\n");

    auto decoded = decode_zero_rtt_data_frame({});
    CHECK(!decoded.has_value());
}

// ============================================================================
// parse_frames 集成测试 — 验证新帧类型可被 PacketParser 识别
// ============================================================================

static void test_parse_frames_recognizes_new_types() {
    std::printf("[test] T-LP4-001: parse_frames recognizes SESSION_TICKET + ZERO_RTT_DATA...\n");

    // 变长帧（SESSION_TICKET/ZERO_RTT_DATA）在 parse_frames 中吞掉剩余 payload
    // （与 OOS_PN 一致的设计），因此每个包只能包含一个变长帧。
    // 分别验证两个帧类型。

    // SESSION_TICKET 帧（单独包）
    std::vector<uint8_t> wire1;
    wire1.push_back(0x31);
    SessionTicketFrame ticket;
    ticket.ticket_lifetime = 3600;
    ticket.ticket_age_add = 0xCAFE;
    ticket.ticket_nonce = {0x01};
    ticket.ticket = {0x02, 0x03};
    auto ticket_enc = encode_session_ticket_frame(ticket);
    wire1.insert(wire1.end(), ticket_enc.begin(), ticket_enc.end());

    auto frames1 = PacketParser::parse_frames(wire1);
    CHECK(frames1.size() == 1);
    CHECK(frames1[0].type == FrameType::SESSION_TICKET);

    // 验证 SESSION_TICKET payload 可正确解码
    auto t_dec = decode_session_ticket_frame(frames1[0].data);
    CHECK(t_dec.has_value());
    CHECK(t_dec->ticket_lifetime == 3600);
    CHECK(t_dec->ticket_age_add == 0xCAFE);

    // ZERO_RTT_DATA 帧（单独包）
    std::vector<uint8_t> wire2;
    wire2.push_back(0x32);
    ZeroRttDataFrame zdata;
    zdata.stream_id = 5;
    zdata.offset = 0;
    zdata.fin = false;
    zdata.data = {0xAA, 0xBB};
    auto zdata_enc = encode_zero_rtt_data_frame(zdata);
    wire2.insert(wire2.end(), zdata_enc.begin(), zdata_enc.end());

    auto frames2 = PacketParser::parse_frames(wire2);
    CHECK(frames2.size() == 1);
    CHECK(frames2[0].type == FrameType::ZERO_RTT_DATA);

    // 验证 ZERO_RTT_DATA payload 可正确解码
    auto z_dec = decode_zero_rtt_data_frame(frames2[0].data);
    CHECK(z_dec.has_value());
    CHECK(z_dec->stream_id == 5);
    std::vector<uint8_t> expected_data{0xAA, 0xBB};
    CHECK(z_dec->data == expected_data);
}

static void test_parse_frames_unknown_type_preserved() {
    std::printf("[test] T-LP4-001: parse_frames preserves unknown frame type 0x3F...\n");

    // parse_frames 对未知帧类型无法获知 payload 长度，将其作为空 data 帧保留
    // （default case break 后 f 仍被 push_back），与 OOS_PN 等变长帧一致。
    std::vector<uint8_t> wire;
    wire.push_back(0x3F);  // 未定义帧类型（无 payload）

    auto frames = PacketParser::parse_frames(wire);
    CHECK(frames.size() >= 1);
    CHECK(frames[0].type == static_cast<FrameType>(0x3F));
}

// ============================================================================
// ADDRESS_DISCOVERY 帧测试（T-LP4-006）
// ============================================================================

static void test_address_discovery_basic_roundtrip() {
    std::printf("[test] T-LP4-006: ADDRESS_DISCOVERY basic roundtrip...\n");

    AddressDiscoveryFrame in;
    in.nonce = {0xAA, 0xBB, 0xCC, 0xDD};

    auto encoded = encode_address_discovery_frame(in);
    CHECK(!encoded.empty());

    auto decoded = decode_address_discovery_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->nonce == in.nonce);
}

static void test_address_discovery_empty_nonce() {
    std::printf("[test] T-LP4-006: ADDRESS_DISCOVERY empty nonce...\n");

    AddressDiscoveryFrame in;
    in.nonce = {};

    auto encoded = encode_address_discovery_frame(in);
    auto decoded = decode_address_discovery_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->nonce.empty());
}

static void test_address_discovery_max_nonce() {
    std::printf("[test] T-LP4-006: ADDRESS_DISCOVERY max nonce (32 bytes)...\n");

    AddressDiscoveryFrame in;
    in.nonce.resize(32, 0x42);

    auto encoded = encode_address_discovery_frame(in);
    auto decoded = decode_address_discovery_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->nonce.size() == 32);
    CHECK(decoded->nonce == in.nonce);
}

static void test_address_discovery_reject_oversized_nonce() {
    std::printf("[test] T-LP4-006: ADDRESS_DISCOVERY reject oversized nonce...\n");

    // 手动构造超长 nonce（33 字节）
    std::vector<uint8_t> bad;
    auto nl = varint_encode_vec(33);
    bad.insert(bad.end(), nl.begin(), nl.end());
    bad.insert(bad.end(), 33, 0x00);

    auto decoded = decode_address_discovery_frame(bad);
    CHECK(!decoded.has_value());
}

static void test_address_discovery_empty_data_rejected() {
    std::printf("[test] T-LP4-006: ADDRESS_DISCOVERY reject empty data...\n");

    auto decoded = decode_address_discovery_frame({});
    CHECK(!decoded.has_value());
}

// ============================================================================
// ADDRESS_DISCOVERY_RESPONSE 帧测试
// ============================================================================

static void test_address_discovery_response_roundtrip() {
    std::printf("[test] T-LP4-006: ADDRESS_DISCOVERY_RESPONSE roundtrip...\n");

    AddressDiscoveryResponseFrame in;
    in.nonce = {0x01, 0x02, 0x03};
    in.observed_host = "203.0.113.42";
    in.observed_port = 54321;

    auto encoded = encode_address_discovery_response_frame(in);
    CHECK(!encoded.empty());

    auto decoded = decode_address_discovery_response_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->nonce == in.nonce);
    CHECK(decoded->observed_host == "203.0.113.42");
    CHECK(decoded->observed_port == 54321);
}

static void test_address_discovery_response_ipv6() {
    std::printf("[test] T-LP4-006: ADDRESS_DISCOVERY_RESPONSE IPv6 address...\n");

    AddressDiscoveryResponseFrame in;
    in.nonce = {0xFF};
    in.observed_host = "2001:db8::1";
    in.observed_port = 8080;

    auto encoded = encode_address_discovery_response_frame(in);
    auto decoded = decode_address_discovery_response_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->observed_host == "2001:db8::1");
    CHECK(decoded->observed_port == 8080);
}

static void test_address_discovery_response_empty_host() {
    std::printf("[test] T-LP4-006: ADDRESS_DISCOVERY_RESPONSE empty host...\n");

    AddressDiscoveryResponseFrame in;
    in.nonce = {0x00};
    in.observed_host = "";
    in.observed_port = 0;

    auto encoded = encode_address_discovery_response_frame(in);
    auto decoded = decode_address_discovery_response_frame(encoded);
    CHECK(decoded.has_value());
    CHECK(decoded->observed_host.empty());
    CHECK(decoded->observed_port == 0);
}

static void test_address_discovery_response_truncated() {
    std::printf("[test] T-LP4-006: ADDRESS_DISCOVERY_RESPONSE reject truncated...\n");

    // 只编码 nonce，缺少 host 和 port
    std::vector<uint8_t> truncated;
    auto nl = varint_encode_vec(2);
    truncated.insert(truncated.end(), nl.begin(), nl.end());
    truncated.push_back(0xAA);
    truncated.push_back(0xBB);

    auto decoded = decode_address_discovery_response_frame(truncated);
    CHECK(!decoded.has_value());
}

static void test_address_discovery_response_reject_bad_port() {
    std::printf("[test] T-LP4-006: ADDRESS_DISCOVERY_RESPONSE reject port > 65535...\n");

    // 手动构造非法 port（65536）
    std::vector<uint8_t> bad;
    // nonce
    auto nl = varint_encode_vec(1);
    bad.insert(bad.end(), nl.begin(), nl.end());
    bad.push_back(0x00);
    // host (empty)
    auto hl = varint_encode_vec(0);
    bad.insert(bad.end(), hl.begin(), hl.end());
    // port = 65536 (0x10000) — 需要用 4 字节 varint 编码
    auto port = varint_encode_vec(static_cast<std::uint64_t>(65536));
    bad.insert(bad.end(), port.begin(), port.end());

    auto decoded = decode_address_discovery_response_frame(bad);
    CHECK(!decoded.has_value());
}

// ============================================================================
// 帧类型枚举值验证
// ============================================================================

static void test_frame_type_enum_values() {
    std::printf("[test] T-LP4-001: FrameType enum values...\n");

    CHECK(static_cast<std::uint8_t>(FrameType::SESSION_TICKET) == 0x31);
    CHECK(static_cast<std::uint8_t>(FrameType::ZERO_RTT_DATA) == 0x32);
    CHECK(static_cast<std::uint8_t>(FrameType::ADDRESS_DISCOVERY) == 0x33);
    CHECK(static_cast<std::uint8_t>(FrameType::ADDRESS_DISCOVERY_RESPONSE) == 0x34);

    // 确保不与现有帧类型冲突
    CHECK(static_cast<std::uint8_t>(FrameType::OOS_PN) == 0x30);
    CHECK(static_cast<std::uint8_t>(FrameType::HANDSHAKE_DONE) == 0x1e);
    CHECK(static_cast<std::uint8_t>(FrameType::MAX_DATA) == 0x10);
}

// ============================================================================
// 最大字节数常量验证
// ============================================================================

static void test_max_bytes_constants() {
    std::printf("[test] T-LP4-001: max bytes constants...\n");

    // SESSION_TICKET 理论上限
    // type(1) + lifetime(4) + age_add(4) + nonce_len(1) + nonce(255) + ticket_len(3) + ticket(65535)
    CHECK(kSessionTicketFrameMaxBytes == 1 + 4 + 4 + 1 + 255 + 3 + 65535);

    // ZERO_RTT_DATA 理论上限
    // type(1) + stream_id(8) + offset(8) + fin(1) + data(65535)
    CHECK(kZeroRttDataFrameMaxBytes == 1 + 8 + 8 + 1 + 65535);

    // ADDRESS_DISCOVERY 理论上限
    // type(1) + nonce_len(1) + nonce(32) = 34
    CHECK(kAddressDiscoveryFrameMaxBytes == 1 + 1 + 32);

    // ADDRESS_DISCOVERY_RESPONSE 理论上限
    // type(1) + nonce_len(1) + nonce(32) + host_len(1) + host(64) + port(2) = 101
    CHECK(kAddressDiscoveryResponseFrameMaxBytes == 1 + 1 + 32 + 1 + 64 + 2);
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);  // 禁用缓冲，崩溃时也能看到输出
    std::printf("=== v5.0.0 T-LP4-001 Frame Definition Tests ===\n\n");

    test_frame_type_enum_values();
    test_max_bytes_constants();

    test_session_ticket_basic_roundtrip();
    test_session_ticket_max_lifetime();
    test_session_ticket_reject_lifetime_over_limit();
    test_session_ticket_empty_nonce_and_ticket();
    test_session_ticket_large_ticket();
    test_session_ticket_truncated_data();
    test_session_ticket_empty_data_rejected();

    test_zero_rtt_data_basic_roundtrip();
    test_zero_rtt_data_fin_flag();
    test_zero_rtt_data_empty_payload();
    test_zero_rtt_data_large_stream_id();
    test_zero_rtt_data_truncated_data();
    test_zero_rtt_data_empty_data_rejected();

    test_parse_frames_recognizes_new_types();
    test_parse_frames_unknown_type_preserved();

    test_address_discovery_basic_roundtrip();
    test_address_discovery_empty_nonce();
    test_address_discovery_max_nonce();
    test_address_discovery_reject_oversized_nonce();
    test_address_discovery_empty_data_rejected();

    test_address_discovery_response_roundtrip();
    test_address_discovery_response_ipv6();
    test_address_discovery_response_empty_host();
    test_address_discovery_response_truncated();
    test_address_discovery_response_reject_bad_port();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
