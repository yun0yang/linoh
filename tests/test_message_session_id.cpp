// test_message_session_id.cpp — V3.4 P4 ApplicationMessage + SessionId 集成测试
//
// 测试覆盖：
//   1. set/get/clear session_id + flag 自动管理
//   2. serialize → parse 往返（含 session_id）
//   3. 旧消息兼容（无 HasSessionId 行为不变）
//   4. session_id + 空 payload 边界
//   5. session_id + 大 payload（64KB hidden_state 模拟）
//   6. wire_size / total_wire_size 正确反映 +16B
//   7. serialize_into 零拷贝路径 + session_id
//   8. serialize_to 预分配 buffer + session_id
//   9. serialize_to 容量不足返回 0
//  10. session_id + HasReturnAddress 共存（正交设计）
//  11. parse 降级（HasSessionId 但 payload_len < 16）

#include "linoh/protocol/application_message.hpp"
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

// ========== 测试用例 ==========

static void test_set_get_clear_session_id() {
    std::printf("[test] set/get/clear session_id + flag auto-management...\n");

    ApplicationMessage msg;
    // 默认无 session_id
    CHECK(!msg.has_session_id());
    CHECK(!msg.get_session_id().has_value());

    // set → 自动置 flag
    auto sid = SessionId::generate();
    msg.set_session_id(sid);
    CHECK(msg.has_session_id());
    CHECK(msg.get_session_id().has_value());
    CHECK(msg.get_session_id().value() == sid);

    // flags 含 HasSessionId 位
    CHECK(has_flag(msg.flags, MessageFlags::HasSessionId));

    // clear → 清 flag + 清值
    msg.clear_session_id();
    CHECK(!msg.has_session_id());
    CHECK(!msg.get_session_id().has_value());
    CHECK(!has_flag(msg.flags, MessageFlags::HasSessionId));
}

static void test_serialize_parse_with_session_id() {
    std::printf("[test] serialize -> parse roundtrip with session_id...\n");

    auto sid = SessionId::generate();
    std::vector<std::uint8_t> payload(256);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    auto msg = ApplicationMessage::request(42, MethodId::ForwardPP, payload);
    msg.set_session_id(sid);

    // wire_size 应 = header + 16 (sid) + 256 (payload)
    CHECK_EQ(msg.wire_size(), ApplicationMessage::kHeaderSize + SessionId::kSize + 256);

    auto wire = msg.serialize();
    CHECK_EQ(wire.size(), msg.wire_size());

    // 解析
    ApplicationMessage parsed;
    std::size_t consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(wire.data(), wire.size()), parsed);
    CHECK_EQ(consumed, wire.size());

    // 字段一致
    CHECK(parsed.has_session_id());
    CHECK(parsed.get_session_id().has_value());
    CHECK(parsed.get_session_id().value() == sid);
    CHECK_EQ(parsed.request_id, 42u);
    CHECK(parsed.method_id == MethodId::ForwardPP);
    CHECK_EQ(parsed.payload.size(), payload.size());
    CHECK(std::memcmp(parsed.payload.data(), payload.data(), payload.size()) == 0);
}

static void test_serialize_parse_without_session_id_compat() {
    std::printf("[test] old message (no HasSessionId) backward compat...\n");

    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto msg = ApplicationMessage::notification(MethodId::Heartbeat, payload);

    // 无 session_id
    CHECK(!msg.has_session_id());
    CHECK_EQ(msg.wire_size(), ApplicationMessage::kHeaderSize + payload.size());

    auto wire = msg.serialize();
    CHECK_EQ(wire.size(), msg.wire_size());

    ApplicationMessage parsed;
    std::size_t consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(wire.data(), wire.size()), parsed);
    CHECK_EQ(consumed, wire.size());

    // 解析后仍无 session_id
    CHECK(!parsed.has_session_id());
    CHECK(!parsed.get_session_id().has_value());
    CHECK_EQ(parsed.payload.size(), payload.size());
    CHECK(std::memcmp(parsed.payload.data(), payload.data(), payload.size()) == 0);
}

static void test_session_id_zero_payload() {
    std::printf("[test] session_id + empty payload boundary...\n");

    auto sid = SessionId::generate();
    auto msg = ApplicationMessage::request(1, MethodId::ForwardPP,
                                           std::vector<std::uint8_t>{});
    msg.set_session_id(sid);

    // wire = header + 16 (sid) + 0 (payload)
    CHECK_EQ(msg.wire_size(), ApplicationMessage::kHeaderSize + SessionId::kSize);

    auto wire = msg.serialize();
    CHECK_EQ(wire.size(), msg.wire_size());

    ApplicationMessage parsed;
    std::size_t consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(wire.data(), wire.size()), parsed);
    CHECK_EQ(consumed, wire.size());

    CHECK(parsed.has_session_id());
    CHECK(parsed.get_session_id().value() == sid);
    CHECK(parsed.payload.empty());
}

static void test_session_id_large_payload() {
    std::printf("[test] session_id + 64KB payload (hidden_state sim)...\n");

    auto sid = SessionId::generate();
    std::vector<std::uint8_t> payload(64 * 1024);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>((i * 7 + 3) & 0xFF);
    }

    auto msg = ApplicationMessage::request(99, MethodId::ForwardPP, payload);
    msg.set_session_id(sid);

    CHECK_EQ(msg.wire_size(), ApplicationMessage::kHeaderSize + SessionId::kSize + payload.size());

    auto wire = msg.serialize();
    CHECK_EQ(wire.size(), msg.wire_size());

    ApplicationMessage parsed;
    std::size_t consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(wire.data(), wire.size()), parsed);
    CHECK_EQ(consumed, wire.size());

    CHECK(parsed.get_session_id().value() == sid);
    CHECK_EQ(parsed.payload.size(), payload.size());
    CHECK(std::memcmp(parsed.payload.data(), payload.data(), payload.size()) == 0);
}

static void test_wire_size_and_total_wire_size() {
    std::printf("[test] wire_size / total_wire_size with session_id...\n");

    ApplicationMessage msg;
    msg.payload.resize(100);

    // 无 session_id
    CHECK_EQ(msg.wire_size(), ApplicationMessage::kHeaderSize + 100);
    CHECK_EQ(ApplicationMessage::total_wire_size(100), ApplicationMessage::kHeaderSize + 100);
    CHECK_EQ(ApplicationMessage::total_wire_size(100, false), ApplicationMessage::kHeaderSize + 100);

    // 有 session_id
    msg.set_session_id(SessionId::generate());
    CHECK_EQ(msg.wire_size(), ApplicationMessage::kHeaderSize + 100 + SessionId::kSize);
    CHECK_EQ(ApplicationMessage::total_wire_size(100, true),
             ApplicationMessage::kHeaderSize + 100 + SessionId::kSize);

    // 默认参数向后兼容
    CHECK_EQ(ApplicationMessage::total_wire_size(100),
             ApplicationMessage::total_wire_size(100, false));
}

static void test_serialize_into_with_session_id() {
    std::printf("[test] serialize_into (zero-copy append) + session_id...\n");

    auto sid = SessionId::generate();
    std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    auto msg = ApplicationMessage::response(7, MethodId::ResultPP, payload);
    msg.set_session_id(sid);

    std::vector<std::uint8_t> wire;
    wire.reserve(msg.wire_size());
    std::size_t written = msg.serialize_into(wire);
    CHECK_EQ(written, msg.wire_size());
    CHECK_EQ(wire.size(), msg.wire_size());

    // 与 serialize() 结果一致
    auto ref = msg.serialize();
    CHECK(wire == ref);

    // 解析往返
    ApplicationMessage parsed;
    ApplicationMessage::parse(std::span<const std::uint8_t>(wire.data(), wire.size()), parsed);
    CHECK(parsed.get_session_id().value() == sid);
    CHECK_EQ(parsed.payload.size(), payload.size());
    CHECK(std::memcmp(parsed.payload.data(), payload.data(), payload.size()) == 0);
}

static void test_serialize_to_with_session_id() {
    std::printf("[test] serialize_to (preallocated buffer) + session_id...\n");

    auto sid = SessionId::generate();
    std::vector<std::uint8_t> payload(512);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>(i & 0xFF);
    }
    auto msg = ApplicationMessage::request(5, MethodId::ForwardPP, payload);
    msg.set_session_id(sid);

    std::vector<std::uint8_t> buf(msg.wire_size());
    std::size_t written = msg.serialize_to(
        std::span<std::uint8_t>(buf.data(), buf.size()));
    CHECK_EQ(written, msg.wire_size());

    // 与 serialize() 结果一致
    auto ref = msg.serialize();
    CHECK(buf == ref);

    // 容量不足返回 0
    std::vector<std::uint8_t> small(msg.wire_size() - 1);
    std::size_t r = msg.serialize_to(
        std::span<std::uint8_t>(small.data(), small.size()));
    CHECK_EQ(r, 0u);
}

static void test_session_id_with_return_address() {
    std::printf("[test] session_id + HasReturnAddress coexist (orthogonal)...\n");

    auto sid = SessionId::generate();
    // 模拟 ForwardPP 消息同时携带 session_id 和 HasReturnAddress
    auto msg = ApplicationMessage::request(10, MethodId::ForwardPP,
                                           std::vector<std::uint8_t>(32, 0x77));
    msg.set_session_id(sid);
    msg.set_flag(MessageFlags::HasReturnAddress);

    CHECK(msg.has_session_id());
    CHECK(has_flag(msg.flags, MessageFlags::HasReturnAddress));

    auto wire = msg.serialize();
    ApplicationMessage parsed;
    ApplicationMessage::parse(std::span<const std::uint8_t>(wire.data(), wire.size()), parsed);

    // 两个 flag 都保留
    CHECK(parsed.has_session_id());
    CHECK(has_flag(parsed.flags, MessageFlags::HasReturnAddress));
    CHECK(parsed.get_session_id().value() == sid);
    CHECK_EQ(parsed.payload.size(), 32u);
}

static void test_parse_degrade_short_payload() {
    std::printf("[test] parse degrade: HasSessionId but payload_len < 16...\n");

    // 构造一个 HasSessionId 置位但 payload_len < 16 的帧（异常场景）
    // 正常流程不会产生，但旧节点可能误置位
    std::vector<std::uint8_t> wire;
    // magic
    wire.push_back(static_cast<std::uint8_t>((ApplicationMessage::kMagic >> 8) & 0xFF));
    wire.push_back(static_cast<std::uint8_t>(ApplicationMessage::kMagic & 0xFF));
    // version
    wire.push_back(ApplicationMessage::kVersion);
    // msg_type
    wire.push_back(static_cast<std::uint8_t>(MessageType::Notification));
    // method_id
    wire.push_back(0x00);
    wire.push_back(static_cast<std::uint8_t>(MethodId::Heartbeat));
    // request_id
    wire.push_back(0); wire.push_back(0); wire.push_back(0); wire.push_back(0);
    // flags = HasSessionId (0x0200)
    wire.push_back(0x02);
    wire.push_back(0x00);
    // payload_len = 8 (< 16，不足 session_id)
    wire.push_back(0); wire.push_back(0); wire.push_back(0); wire.push_back(8);
    // 8 bytes payload
    for (int i = 0; i < 8; ++i) wire.push_back(static_cast<std::uint8_t>(i));

    ApplicationMessage parsed;
    std::size_t consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(wire.data(), wire.size()), parsed);
    // 应正常消费（降级为无 session_id，payload 原样）
    CHECK_EQ(consumed, ApplicationMessage::kHeaderSize + 8);
    // 降级：session_id_ 被 reset，payload 为原始 8 字节
    CHECK(!parsed.get_session_id().has_value());
    CHECK_EQ(parsed.payload.size(), 8u);
    // 降级一致性：HasSessionId flag 应被清除，避免 has_session_id()==true 但 get_session_id()==nullopt
    CHECK(!parsed.has_session_id());
    CHECK(!has_flag(parsed.flags, MessageFlags::HasSessionId));
}

// ========== main ==========

int main() {
    std::printf("=== test_message_session_id (V3.4 P4) ===\n\n");

    test_set_get_clear_session_id();
    test_serialize_parse_with_session_id();
    test_serialize_parse_without_session_id_compat();
    test_session_id_zero_payload();
    test_session_id_large_payload();
    test_wire_size_and_total_wire_size();
    test_serialize_into_with_session_id();
    test_serialize_to_with_session_id();
    test_session_id_with_return_address();
    test_parse_degrade_short_payload();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
