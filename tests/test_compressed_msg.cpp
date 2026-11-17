// test_compressed_msg.cpp — P1-8 应用层压缩/加密/签名标志位单元测试
//
// 验证 ApplicationMessage 的 flags 扩展：
//   1. 新增标志位 PayloadEncrypted/PayloadSigned/Fragment 定义正确
//   2. has_flag() / is_encrypted() / is_signed() 等便捷判定
//   3. set_flag() / clear_flag() 位操作
//   4. serialize/parse 时 flags 字段透传新位
//   5. 多 flag 位组合（如 Encrypted | Signed | LastFragment）
//   6. 非法 flag 位（保留位）也能被透传（不丢失）
//   7. has_flag 自由函数与成员函数一致性

#include "linoh/protocol/application_message.hpp"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 1. 新增标志位定义正确
// ============================================================================
static void test_flag_bit_values() {
    std::printf("[test] new flag bit values are correct...\n");
    CHECK(static_cast<std::uint16_t>(MessageFlags::None)              == 0x0000);
    CHECK(static_cast<std::uint16_t>(MessageFlags::PayloadCompressed) == 0x0001);
    CHECK(static_cast<std::uint16_t>(MessageFlags::LastFragment)      == 0x0002);
    CHECK(static_cast<std::uint16_t>(MessageFlags::EndOfStream)       == 0x0004);
    CHECK(static_cast<std::uint16_t>(MessageFlags::PayloadEncrypted)  == 0x0008);
    CHECK(static_cast<std::uint16_t>(MessageFlags::PayloadSigned)     == 0x0010);
    CHECK(static_cast<std::uint16_t>(MessageFlags::Fragment)          == 0x0020);

    // 常量
    CHECK(kEd25519SignatureSize == 64);
    CHECK(kAeadNonceSize == 12);
    CHECK(kAeadTagSize == 16);
}

// ============================================================================
// 2. 便捷判定方法
// ============================================================================
static void test_flag_convenience_methods() {
    std::printf("[test] flag convenience methods is_encrypted/is_signed/...\n");
    ApplicationMessage msg = ApplicationMessage::request(
        1, MethodId::ForwardPP, std::vector<std::uint8_t>{0x01, 0x02});

    // 默认 factory 仅设置 LastFragment
    CHECK(msg.is_last_fragment());
    CHECK(!msg.is_encrypted());
    CHECK(!msg.is_signed());
    CHECK(!msg.is_compressed());
    CHECK(!msg.is_fragment());
    CHECK(!msg.end_of_stream());
}

// ============================================================================
// 3. set_flag / clear_flag
// ============================================================================
static void test_set_clear_flag() {
    std::printf("[test] set_flag / clear_flag bit operations...\n");
    ApplicationMessage msg = ApplicationMessage::request(
        1, MethodId::ForwardPP, std::vector<std::uint8_t>{0x01});

    CHECK(msg.flags == static_cast<std::uint16_t>(MessageFlags::LastFragment));

    msg.set_flag(MessageFlags::PayloadEncrypted);
    CHECK(msg.is_encrypted());
    CHECK(msg.is_last_fragment());  // 其他位保留

    msg.set_flag(MessageFlags::PayloadSigned);
    CHECK(msg.is_encrypted());
    CHECK(msg.is_signed());
    CHECK(msg.is_last_fragment());

    msg.clear_flag(MessageFlags::PayloadEncrypted);
    CHECK(!msg.is_encrypted());
    CHECK(msg.is_signed());  // 其他位保留
    CHECK(msg.is_last_fragment());

    // 重复 clear 无副作用
    msg.clear_flag(MessageFlags::PayloadEncrypted);
    CHECK(!msg.is_encrypted());
}

// ============================================================================
// 4. serialize/parse 时 flags 透传新位
// ============================================================================
static void test_flags_transparent_through_serialize() {
    std::printf("[test] flags transparent through serialize/parse...\n");

    // 构造一个 Encrypted | Signed | LastFragment 的消息
    ApplicationMessage orig = ApplicationMessage::request(
        42, MethodId::ForwardPP,
        std::vector<std::uint8_t>{0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
    orig.set_flag(MessageFlags::PayloadEncrypted);
    orig.set_flag(MessageFlags::PayloadSigned);

    std::uint16_t expected_flags = orig.flags;
    CHECK((expected_flags & 0x0008) != 0);  // Encrypted
    CHECK((expected_flags & 0x0010) != 0);  // Signed
    CHECK((expected_flags & 0x0002) != 0);  // LastFragment

    auto bytes = orig.serialize();
    CHECK(bytes.size() == ApplicationMessage::kHeaderSize + orig.payload.size());

    ApplicationMessage parsed;
    std::size_t consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()), parsed);
    CHECK(consumed == bytes.size());
    CHECK(parsed.flags == expected_flags);
    CHECK(parsed.is_encrypted());
    CHECK(parsed.is_signed());
    CHECK(parsed.is_last_fragment());
    CHECK(parsed.payload == orig.payload);
    CHECK(parsed.request_id == 42);
    CHECK(parsed.method_id == MethodId::ForwardPP);
}

// ============================================================================
// 5. 多 flag 位组合
// ============================================================================
static void test_multiple_flags_combined() {
    std::printf("[test] multiple flags combined...\n");

    ApplicationMessage msg = ApplicationMessage::notification(
        MethodId::StateChange, std::vector<std::uint8_t>{0x01});
    // 默认 notification 只有 LastFragment
    CHECK(msg.flags == 0x0002);

    // 设置全部新位
    msg.set_flag(MessageFlags::PayloadEncrypted);
    msg.set_flag(MessageFlags::PayloadSigned);
    msg.set_flag(MessageFlags::PayloadCompressed);
    msg.set_flag(MessageFlags::EndOfStream);
    // Fragment 与 LastFragment 互斥（语义层面），但位运算层面允许共存
    msg.set_flag(MessageFlags::Fragment);

    // 所有位都应设置
    CHECK((msg.flags & 0x003F) == 0x003F);

    // 序列化往返
    auto bytes = msg.serialize();
    ApplicationMessage parsed;
    ApplicationMessage::parse(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()), parsed);
    CHECK(parsed.flags == msg.flags);
    CHECK(parsed.is_encrypted());
    CHECK(parsed.is_signed());
    CHECK(parsed.is_compressed());
    CHECK(parsed.is_fragment());
    CHECK(parsed.end_of_stream());
    CHECK(parsed.is_last_fragment());
}

// ============================================================================
// 6. 高位保留位透传（不丢失）
// ============================================================================
static void test_reserved_high_bits_transparent() {
    std::printf("[test] reserved high bits are transparent...\n");

    ApplicationMessage msg = ApplicationMessage::request(
        1, MethodId::ForwardPP, std::vector<std::uint8_t>{0x01});
    // 设置所有 16 位（包括高位保留位）
    msg.flags = 0xFFFF;

    auto bytes = msg.serialize();
    ApplicationMessage parsed;
    ApplicationMessage::parse(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()), parsed);
    CHECK(parsed.flags == 0xFFFF);  // 完整透传，无位丢失
}

// ============================================================================
// 7. has_flag 自由函数与成员函数一致
// ============================================================================
static void test_has_flag_consistency() {
    std::printf("[test] has_flag free function vs member methods...\n");

    ApplicationMessage msg = ApplicationMessage::request(
        1, MethodId::ForwardPP, std::vector<std::uint8_t>{0x01});
    msg.set_flag(MessageFlags::PayloadEncrypted);
    msg.set_flag(MessageFlags::EndOfStream);

    CHECK(has_flag(msg.flags, MessageFlags::PayloadEncrypted) == msg.is_encrypted());
    CHECK(has_flag(msg.flags, MessageFlags::EndOfStream) == msg.end_of_stream());
    CHECK(has_flag(msg.flags, MessageFlags::PayloadSigned) == msg.is_signed());
    CHECK(has_flag(msg.flags, MessageFlags::LastFragment) == msg.is_last_fragment());
}

// ============================================================================
// 8. operator| 组合 flags
// ============================================================================
static void test_flag_or_operator() {
    std::printf("[test] flag | operator combines bits...\n");

    auto combined = MessageFlags::PayloadEncrypted | MessageFlags::PayloadSigned
                    | MessageFlags::LastFragment;
    std::uint16_t v = static_cast<std::uint16_t>(combined);
    CHECK((v & 0x0008) != 0);
    CHECK((v & 0x0010) != 0);
    CHECK((v & 0x0002) != 0);
    CHECK((v & 0x0001) == 0);  // Compressed 未设置

    // std::uint16_t | MessageFlags
    std::uint16_t base = 0x0002;
    std::uint16_t result = base | MessageFlags::PayloadEncrypted;
    CHECK((result & 0x0008) != 0);
    CHECK((result & 0x0002) != 0);
}

// ============================================================================
// 9. parse 拒绝 payload 超长（kMaxPayloadSize 限制）
// ============================================================================
static void test_parse_rejects_oversize() {
    std::printf("[test] parse rejects oversize payload...\n");

    // 构造一个头部声明 payload_len = kMaxPayloadSize + 1 的消息
    std::vector<std::uint8_t> bytes(ApplicationMessage::kHeaderSize, 0);
    // magic
    bytes[0] = 0x4C; bytes[1] = 0x4E;
    // version
    bytes[2] = 0x01;
    // msg_type = Request
    bytes[3] = 0x00;
    // method_id
    bytes[4] = 0x00; bytes[5] = 0x10;
    // request_id
    bytes[6] = bytes[7] = bytes[8] = bytes[9] = 0x01;
    // flags = LastFragment
    bytes[10] = 0x00; bytes[11] = 0x02;
    // payload_len = 0x04000001 (> 64MB)
    bytes[12] = 0x04; bytes[13] = 0x00; bytes[14] = 0x00; bytes[15] = 0x01;

    ApplicationMessage parsed;
    std::size_t consumed = ApplicationMessage::parse(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()), parsed);
    CHECK(consumed == 0);  // 超长被拒绝
}

// ============================================================================
// 10. validate_header 接受合法头部
// ============================================================================
static void test_validate_header() {
    std::printf("[test] validate_header accepts valid header...\n");

    ApplicationMessage msg = ApplicationMessage::request(
        1, MethodId::ForwardPP, std::vector<std::uint8_t>{0x01, 0x02});
    msg.set_flag(MessageFlags::PayloadEncrypted);
    auto bytes = msg.serialize();

    CHECK(ApplicationMessage::validate_header(
        std::span<const std::uint8_t>(bytes.data(), ApplicationMessage::kHeaderSize)));

    // 篡改 magic
    std::vector<std::uint8_t> bad(bytes.begin(), bytes.begin() + ApplicationMessage::kHeaderSize);
    bad[0] = 0x00;
    CHECK(!ApplicationMessage::validate_header(
        std::span<const std::uint8_t>(bad.data(), bad.size())));

    // 篡改 version
    bad.assign(bytes.begin(), bytes.begin() + ApplicationMessage::kHeaderSize);
    bad[2] = 0x02;
    CHECK(!ApplicationMessage::validate_header(
        std::span<const std::uint8_t>(bad.data(), bad.size())));
}

int main() {
    std::printf("=== ApplicationMessage flags (P1-8) unit tests ===\n\n");

    test_flag_bit_values();
    test_flag_convenience_methods();
    test_set_clear_flag();
    test_flags_transparent_through_serialize();
    test_multiple_flags_combined();
    test_reserved_high_bits_transparent();
    test_has_flag_consistency();
    test_flag_or_operator();
    test_parse_rejects_oversize();
    test_validate_header();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
