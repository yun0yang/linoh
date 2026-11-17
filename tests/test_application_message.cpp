// test_application_message.cpp — ApplicationMessage 单元测试
//
// 测试覆盖：
//   1. 4 种工厂方法的字段正确性
//   2. serialize() 字节序和大端字段
//   3. parse() 往返（serialize → parse 字段一致）
//   4. 半包（数据不足返回 0）
//   5. 粘包（连续解析两条消息）
//   6. magic 错误（返回 0）
//   7. version 错误（返回 0）
//   8. 超长 payload 拒绝（返回 0）
//   9. 空 payload 支持
//  10. 大 payload 支持（1 MB）
//  11. validate_header 校验

#include "linoh/protocol/application_message.hpp"

#include <cassert>
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

// 辅助：initializer_list → std::vector<uint8_t>
template<typename... T>
std::vector<std::uint8_t> bytes(T... vals) {
    return std::vector<std::uint8_t>{static_cast<std::uint8_t>(vals)...};
}

static void test_factory_methods() {
    std::printf("[test] factory methods...\n");

    auto req = ApplicationMessage::request(42, MethodId::ForwardPP,
                                            bytes(0xAA, 0xBB, 0xCC));
    CHECK(req.msg_type == MessageType::Request);
    CHECK(req.method_id == MethodId::ForwardPP);
    CHECK(req.request_id == 42);
    CHECK(req.payload.size() == 3);
    CHECK(req.payload[0] == 0xAA);

    auto resp = ApplicationMessage::response(42, MethodId::ForwardPP,
                                              bytes(0x11, 0x22));
    CHECK(resp.msg_type == MessageType::Response);
    CHECK(resp.request_id == 42);
    CHECK(resp.payload.size() == 2);

    auto err = ApplicationMessage::error(42, MethodId::ForwardPP, "bad request");
    CHECK(err.msg_type == MessageType::ErrorResponse);
    CHECK(err.request_id == 42);
    CHECK(err.payload.size() == std::strlen("bad request"));

    auto notif = ApplicationMessage::notification(MethodId::StateChange,
                                                   bytes(0x01, 0x02, 0x03));
    CHECK(notif.msg_type == MessageType::Notification);
    CHECK(notif.request_id == 0);  // 通知固定 id=0
    CHECK(notif.payload.size() == 3);

    // request_id=0 时应自动改为 1
    std::vector<std::uint8_t> empty_payload;
    auto req_zero = ApplicationMessage::request(0, MethodId::Heartbeat, empty_payload);
    CHECK(req_zero.request_id == 1);
}

static void test_serialize_byte_order() {
    std::printf("[test] serialize byte order...\n");

    auto msg = ApplicationMessage::request(0x12345678, MethodId::ForwardPP, bytes(0xAB));
    auto b = msg.serialize();

    CHECK(b.size() == 17);  // 16B 头 + 1B payload

    // magic 大端: 0x4C 0x4E
    CHECK(b[0] == 0x4C);
    CHECK(b[1] == 0x4E);

    // version
    CHECK(b[2] == 0x01);

    // msg_type = 0 (Request)
    CHECK(b[3] == 0x00);

    // method_id 大端: ForwardPP = 0x0010
    CHECK(b[4] == 0x00);
    CHECK(b[5] == 0x10);

    // request_id 大端: 0x12345678
    CHECK(b[6] == 0x12);
    CHECK(b[7] == 0x34);
    CHECK(b[8] == 0x56);
    CHECK(b[9] == 0x78);

    // flags (2B) — LastFragment = 0x0002
    CHECK(b[10] == 0x00);
    CHECK(b[11] == 0x02);

    // payload_len 大端: 1
    CHECK(b[12] == 0x00);
    CHECK(b[13] == 0x00);
    CHECK(b[14] == 0x00);
    CHECK(b[15] == 0x01);

    // payload
    CHECK(b[16] == 0xAB);
}

static void test_parse_roundtrip() {
    std::printf("[test] parse roundtrip...\n");

    std::vector<std::uint8_t> payload = bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03);
    auto original = ApplicationMessage::request(999, MethodId::LoadModel, payload);
    auto b = original.serialize();

    ApplicationMessage parsed;
    auto consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(b.data(), b.size()), parsed);

    CHECK(consumed == b.size());
    CHECK(parsed.msg_type == original.msg_type);
    CHECK(parsed.method_id == original.method_id);
    CHECK(parsed.request_id == original.request_id);
    CHECK(parsed.payload == original.payload);
}

static void test_parse_half_packet() {
    std::printf("[test] parse half packet...\n");

    auto msg = ApplicationMessage::request(1, MethodId::Heartbeat, bytes(0x01, 0x02));
    auto b = msg.serialize();

    // 仅给 5 字节（不足 16B 头）
    ApplicationMessage parsed;
    auto consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(b.data(), 5), parsed);
    CHECK(consumed == 0);

    // 给 16B 头但 payload 未到齐
    consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(b.data(), 17), parsed);  // 16+1，差 1 字节
    CHECK(consumed == 0);
}

static void test_parse_multiple_messages() {
    std::printf("[test] parse multiple messages (粘包)...\n");

    auto msg1 = ApplicationMessage::request(1, MethodId::Heartbeat, bytes(0x01));
    auto msg2 = ApplicationMessage::response(1, MethodId::Heartbeat, bytes(0x02, 0x03));

    auto b1 = msg1.serialize();
    auto b2 = msg2.serialize();

    std::vector<std::uint8_t> combined;
    combined.insert(combined.end(), b1.begin(), b1.end());
    combined.insert(combined.end(), b2.begin(), b2.end());

    ApplicationMessage parsed1;
    auto consumed1 = ApplicationMessage::parse(
        std::span<const std::uint8_t>(combined.data(), combined.size()), parsed1);
    CHECK(consumed1 == b1.size());
    CHECK(parsed1.msg_type == MessageType::Request);
    CHECK(parsed1.request_id == 1);

    ApplicationMessage parsed2;
    auto consumed2 = ApplicationMessage::parse(
        std::span<const std::uint8_t>(combined.data() + consumed1,
                                       combined.size() - consumed1), parsed2);
    CHECK(consumed2 == b2.size());
    CHECK(parsed2.msg_type == MessageType::Response);
    CHECK(parsed2.request_id == 1);
    CHECK(parsed2.payload.size() == 2);
    CHECK(parsed2.payload[0] == 0x02);
}

static void test_parse_bad_magic() {
    std::printf("[test] parse bad magic...\n");

    auto msg = ApplicationMessage::request(1, MethodId::Heartbeat, bytes(0x01));
    auto b = msg.serialize();
    b[0] = 0xFF;  // 破坏 magic

    ApplicationMessage parsed;
    auto consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(b.data(), b.size()), parsed);
    CHECK(consumed == 0);
}

static void test_parse_bad_version() {
    std::printf("[test] parse bad version...\n");

    auto msg = ApplicationMessage::request(1, MethodId::Heartbeat, bytes(0x01));
    auto b = msg.serialize();
    b[2] = 0xFF;  // 破坏 version

    ApplicationMessage parsed;
    auto consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(b.data(), b.size()), parsed);
    CHECK(consumed == 0);
}

static void test_parse_oversized_payload() {
    std::printf("[test] parse oversized payload...\n");

    auto msg = ApplicationMessage::request(1, MethodId::Heartbeat, bytes(0x01));
    auto b = msg.serialize();

    // 篡改 payload_len 为 100MB（超过 64MB 限制）
    // payload_len 字段位于 b[12..15]
    b[12] = 0x06;  // 0x06000000 = 100MB
    b[13] = 0x00;
    b[14] = 0x00;
    b[15] = 0x00;

    ApplicationMessage parsed;
    auto consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(b.data(), b.size()), parsed);
    CHECK(consumed == 0);
}

static void test_empty_payload() {
    std::printf("[test] empty payload...\n");

    std::vector<std::uint8_t> empty;
    auto msg = ApplicationMessage::notification(MethodId::StateChange, empty);
    auto b = msg.serialize();
    CHECK(b.size() == 16);  // 仅 16B 头，无 payload

    ApplicationMessage parsed;
    auto consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(b.data(), b.size()), parsed);
    CHECK(consumed == 16);
    CHECK(parsed.payload.empty());
}

static void test_large_payload() {
    std::printf("[test] large payload (1 MB)...\n");

    std::vector<std::uint8_t> big(1024 * 1024, 0x42);
    auto msg = ApplicationMessage::request(7, MethodId::ForwardPP, big);
    auto b = msg.serialize();
    CHECK(b.size() == 16 + 1024 * 1024);

    ApplicationMessage parsed;
    auto consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(b.data(), b.size()), parsed);
    CHECK(consumed == b.size());
    CHECK(parsed.payload.size() == 1024 * 1024);
    CHECK(parsed.payload[0] == 0x42);
    CHECK(parsed.payload[1024 * 1024 - 1] == 0x42);
}

static void test_validate_header() {
    std::printf("[test] validate_header...\n");

    auto msg = ApplicationMessage::request(1, MethodId::Heartbeat, bytes(0x01));
    auto b = msg.serialize();

    // 完整 16B 头校验通过
    CHECK(ApplicationMessage::validate_header(
        std::span<const std::uint8_t>(b.data(), 16)));

    // 不足 16B 失败
    CHECK(!ApplicationMessage::validate_header(
        std::span<const std::uint8_t>(b.data(), 15)));

    // magic 错误失败
    b[0] = 0xFF;
    CHECK(!ApplicationMessage::validate_header(
        std::span<const std::uint8_t>(b.data(), 16)));
}

static void test_oversized_serialize_throws() {
    std::printf("[test] oversized serialize throws...\n");

    ApplicationMessage msg;
    msg.msg_type = MessageType::Request;
    msg.method_id = MethodId::Heartbeat;
    msg.request_id = 1;
    msg.payload.resize(ApplicationMessage::kMaxPayloadSize + 1, 0x00);

    bool threw = false;
    try {
        msg.serialize();
    } catch (const std::exception &) {
        threw = true;
    }
    CHECK(threw);
}

int main() {
    std::printf("=== test_application_message ===\n");

    test_factory_methods();
    test_serialize_byte_order();
    test_parse_roundtrip();
    test_parse_half_packet();
    test_parse_multiple_messages();
    test_parse_bad_magic();
    test_parse_bad_version();
    test_parse_oversized_payload();
    test_empty_payload();
    test_large_payload();
    test_validate_header();
    test_oversized_serialize_throws();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
