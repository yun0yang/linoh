// test_return_address.cpp — ReturnAddress / ReturnAddrAckPayload 单元测试（v3.2.0）
//
// 测试覆盖：
//   1. encode() 字节数为 40
//   2. encode() 首字节为 marker (0xD7)
//   3. encode() stream_token 大端序正确
//   4. encode() master_endpoint 原样写入
//   5. encode() reserved 全 0
//   6. try_decode() 往返（encode → decode 字段一致）
//   7. try_decode() 首字节非 marker 返回 0
//   8. try_decode() 数据不足 40 字节返回 0
//   9. strip_address() 含 ReturnAddress 时正确剥离
//  10. strip_address() 不含 ReturnAddress 时原样返回
//  11. prepend_address() 拼接正确
//  12. prepend → strip 往返一致
//  13. ReturnAddrAckPayload encode/decode 往返
//  14. ReturnAddrAckPayload 数据不足返回 false
//  15. ReturnAddrAckPayload supported 标志编码正确

#include "linoh/protocol/return_address.hpp"

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

// 辅助：构造测试用 EndpointId（32 字节，填充模式）
static std::array<std::uint8_t, 32> make_endpoint(std::uint8_t fill) {
    std::array<std::uint8_t, 32> ep{};
    ep.fill(fill);
    return ep;
}

// ============================================================================
// ReturnAddress encode 测试
// ============================================================================

static void test_encode_size() {
    std::printf("[test] encode size = 40...\n");
    ReturnAddress addr;
    addr.master_endpoint = make_endpoint(0xAA);
    addr.stream_token = 0x12345678;
    auto buf = addr.encode();
    CHECK_EQ(buf.size(), ReturnAddress::kEncodedSize);
    CHECK_EQ(buf.size(), 40u);
}

static void test_encode_marker() {
    std::printf("[test] encode marker = 0xD7...\n");
    ReturnAddress addr;
    addr.stream_token = 0x12345678;
    auto buf = addr.encode();
    CHECK_EQ(buf[0], ReturnAddress::kMarker);
    CHECK_EQ(buf[0], 0xD7);
}

static void test_encode_byte_order() {
    std::printf("[test] encode stream_token big-endian...\n");
    ReturnAddress addr;
    addr.stream_token = 0x12345678;
    auto buf = addr.encode();
    // stream_token 位于 offset 33-36，大端序
    CHECK_EQ(buf[33], 0x12);
    CHECK_EQ(buf[34], 0x34);
    CHECK_EQ(buf[35], 0x56);
    CHECK_EQ(buf[36], 0x78);
}

static void test_encode_master_endpoint() {
    std::printf("[test] encode master_endpoint raw...\n");
    ReturnAddress addr;
    addr.master_endpoint = make_endpoint(0xBB);
    addr.stream_token = 0;
    auto buf = addr.encode();
    // master_endpoint 位于 offset 1-32
    for (std::size_t i = 0; i < 32; ++i) {
        CHECK_EQ(buf[1 + i], 0xBB);
    }
}

static void test_encode_reserved_zero() {
    std::printf("[test] encode reserved all zero...\n");
    ReturnAddress addr;
    addr.stream_token = 0;
    auto buf = addr.encode();
    // reserved 位于 offset 37-39
    CHECK_EQ(buf[37], 0x00);
    CHECK_EQ(buf[38], 0x00);
    CHECK_EQ(buf[39], 0x00);
}

// ============================================================================
// ReturnAddress try_decode 测试
// ============================================================================

static void test_decode_roundtrip() {
    std::printf("[test] encode/decode roundtrip...\n");
    ReturnAddress addr;
    addr.master_endpoint = make_endpoint(0xCC);
    addr.stream_token = 0xAABBCCDD;
    addr.reserved = {0x01, 0x02, 0x03};

    auto buf = addr.encode();
    ReturnAddress decoded;
    auto consumed = ReturnAddress::try_decode(
        std::span<const std::uint8_t>(buf.data(), buf.size()), decoded);

    CHECK_EQ(consumed, ReturnAddress::kEncodedSize);
    CHECK_EQ(decoded.stream_token, 0xAABBCCDD);
    CHECK(decoded.master_endpoint == make_endpoint(0xCC));
    CHECK(decoded.reserved == (std::array<std::uint8_t, 3>{0x01, 0x02, 0x03}));
}

static void test_decode_no_marker() {
    std::printf("[test] decode no marker returns 0...\n");
    // 首字节不是 0xD7（模拟纯 hidden_state payload）
    std::vector<std::uint8_t> payload(100, 0x42);
    payload[0] = 0xAB;  // 非 marker

    ReturnAddress decoded;
    auto consumed = ReturnAddress::try_decode(
        std::span<const std::uint8_t>(payload.data(), payload.size()), decoded);
    CHECK_EQ(consumed, 0u);
}

static void test_decode_short_data() {
    std::printf("[test] decode short data returns 0...\n");
    // 数据不足 40 字节
    std::vector<std::uint8_t> payload(30, 0x00);
    payload[0] = ReturnAddress::kMarker;

    ReturnAddress decoded;
    auto consumed = ReturnAddress::try_decode(
        std::span<const std::uint8_t>(payload.data(), payload.size()), decoded);
    CHECK_EQ(consumed, 0u);
}

// ============================================================================
// strip_address / prepend_address 测试
// ============================================================================

static void test_strip_with_address() {
    std::printf("[test] strip_address with ReturnAddress...\n");
    ReturnAddress addr;
    addr.master_endpoint = make_endpoint(0xDD);
    addr.stream_token = 0x11223344;

    std::vector<std::uint8_t> hidden = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto full = ReturnAddress::prepend_address(addr, hidden);

    std::optional<ReturnAddress> stripped_addr;
    auto stripped_hidden = ReturnAddress::strip_address(
        std::span<const std::uint8_t>(full.data(), full.size()), stripped_addr);

    CHECK(stripped_addr.has_value());
    CHECK_EQ(stripped_addr->stream_token, 0x11223344);
    CHECK(stripped_addr->master_endpoint == make_endpoint(0xDD));
    CHECK_EQ(stripped_hidden.size(), hidden.size());
    CHECK(std::memcmp(stripped_hidden.data(), hidden.data(), hidden.size()) == 0);
}

static void test_strip_without_address() {
    std::printf("[test] strip_address without ReturnAddress...\n");
    // 纯 hidden_state，首字节非 marker
    std::vector<std::uint8_t> hidden = {0x10, 0x20, 0x30, 0x40};

    std::optional<ReturnAddress> stripped_addr;
    auto stripped_hidden = ReturnAddress::strip_address(
        std::span<const std::uint8_t>(hidden.data(), hidden.size()), stripped_addr);

    CHECK(!stripped_addr.has_value());
    CHECK_EQ(stripped_hidden.size(), hidden.size());
    CHECK(std::memcmp(stripped_hidden.data(), hidden.data(), hidden.size()) == 0);
}

static void test_prepend_address() {
    std::printf("[test] prepend_address...\n");
    ReturnAddress addr;
    addr.stream_token = 0xCAFEBABE;
    addr.master_endpoint = make_endpoint(0xEE);

    std::vector<std::uint8_t> hidden(10, 0x77);
    auto full = ReturnAddress::prepend_address(addr, hidden);

    // 总长度 = 40 + 10
    CHECK_EQ(full.size(), 40u + 10u);
    // 首字节是 marker
    CHECK_EQ(full[0], ReturnAddress::kMarker);
    // 末尾 10 字节是 hidden_state
    for (std::size_t i = 0; i < 10; ++i) {
        CHECK_EQ(full[40 + i], 0x77);
    }
}

static void test_prepend_strip_roundtrip() {
    std::printf("[test] prepend -> strip roundtrip...\n");
    ReturnAddress addr;
    addr.master_endpoint = make_endpoint(0x99);
    addr.stream_token = 0xDEADBEEF;
    addr.reserved = {0x05, 0x06, 0x07};

    // 模拟 hidden_state（含随机内容，首字节可能恰好是 0xD7 验证 marker 逻辑）
    std::vector<std::uint8_t> hidden(256);
    for (std::size_t i = 0; i < hidden.size(); ++i) {
        hidden[i] = static_cast<std::uint8_t>(i);
    }

    auto full = ReturnAddress::prepend_address(addr, hidden);

    std::optional<ReturnAddress> decoded_addr;
    auto decoded_hidden = ReturnAddress::strip_address(
        std::span<const std::uint8_t>(full.data(), full.size()), decoded_addr);

    CHECK(decoded_addr.has_value());
    CHECK_EQ(decoded_addr->stream_token, 0xDEADBEEF);
    CHECK(decoded_addr->master_endpoint == make_endpoint(0x99));
    CHECK(decoded_addr->reserved == (std::array<std::uint8_t, 3>{0x05, 0x06, 0x07}));
    CHECK_EQ(decoded_hidden.size(), hidden.size());
    CHECK(std::memcmp(decoded_hidden.data(), hidden.data(), hidden.size()) == 0);
}

// ============================================================================
// ReturnAddrAckPayload 测试
// ============================================================================

static void test_ack_roundtrip_supported() {
    std::printf("[test] ReturnAddrAckPayload roundtrip (supported=true)...\n");
    ReturnAddrAckPayload ack;
    ack.supported = true;
    ack.version = 0x0100;
    ack.worker_endpoint = make_endpoint(0x11);

    auto buf = ack.encode();
    CHECK_EQ(buf.size(), 35u);

    ReturnAddrAckPayload decoded;
    bool ok = ReturnAddrAckPayload::decode(
        std::span<const std::uint8_t>(buf.data(), buf.size()), decoded);
    CHECK(ok);
    CHECK(decoded.supported);
    CHECK_EQ(decoded.version, 0x0100);
    CHECK(decoded.worker_endpoint == make_endpoint(0x11));
}

static void test_ack_roundtrip_unsupported() {
    std::printf("[test] ReturnAddrAckPayload roundtrip (supported=false)...\n");
    ReturnAddrAckPayload ack;
    ack.supported = false;
    ack.version = 0x0100;
    ack.worker_endpoint = {};  // 全 0

    auto buf = ack.encode();
    CHECK_EQ(buf[0], 0x00);  // supported=false

    ReturnAddrAckPayload decoded;
    bool ok = ReturnAddrAckPayload::decode(
        std::span<const std::uint8_t>(buf.data(), buf.size()), decoded);
    CHECK(ok);
    CHECK(!decoded.supported);
}

static void test_ack_short_data() {
    std::printf("[test] ReturnAddrAckPayload short data returns false...\n");
    std::vector<std::uint8_t> short_data(10, 0x00);
    ReturnAddrAckPayload decoded;
    bool ok = ReturnAddrAckPayload::decode(
        std::span<const std::uint8_t>(short_data.data(), short_data.size()), decoded);
    CHECK(!ok);
}

static void test_ack_version_byte_order() {
    std::printf("[test] ReturnAddrAckPayload version big-endian...\n");
    ReturnAddrAckPayload ack;
    ack.supported = true;
    ack.version = 0x0203;
    auto buf = ack.encode();
    // version 位于 offset 1-2，大端序
    CHECK_EQ(buf[1], 0x02);
    CHECK_EQ(buf[2], 0x03);
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::printf("=== test_return_address ===\n");

    test_encode_size();
    test_encode_marker();
    test_encode_byte_order();
    test_encode_master_endpoint();
    test_encode_reserved_zero();
    test_decode_roundtrip();
    test_decode_no_marker();
    test_decode_short_data();
    test_strip_with_address();
    test_strip_without_address();
    test_prepend_address();
    test_prepend_strip_roundtrip();
    test_ack_roundtrip_supported();
    test_ack_roundtrip_unsupported();
    test_ack_short_data();
    test_ack_version_byte_order();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
