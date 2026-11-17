// test_addr_info.cpp — v4.0.0 M18 地址交换协议分级单元测试
//
// 测试覆盖：
//   1. AddrInfoLevel 枚举值校验 + to_string + is_valid_level
//   2. DirectAddress IPv4 编码字节布局 + encoded_size
//   3. DirectAddress IPv4 encode/decode 往返
//   4. DirectAddress IPv6 encode/decode 往返
//   5. DirectAddress decode 数据不足返回 false
//   6. DirectAddress decode 非法 family 返回 false
//   7. DirectAddress to_string IPv4/IPv6
//   8. DirectAddress operator== / operator!=
//   9. AddrInfoPayload level=Id 编码字节布局（最小 34B）
//  10. AddrInfoPayload level=Id encode/decode 往返
//  11. AddrInfoPayload level=Relay encode/decode 往返
//  12. AddrInfoPayload level=Addresses encode/decode 往返
//  13. AddrInfoPayload level=RelayAndAddresses 全量往返
//  14. AddrInfoPayload 多地址场景（IPv4 + IPv6 混合）
//  15. AddrInfoPayload decode 数据不足返回 false
//  16. AddrInfoPayload decode 非法 level 返回 false
//  17. AddrInfoPayload relay_url 空字符串
//  18. AddrInfoPayload has_relay/has_addresses 判定
//  19. AddrInfoPayload 默认值 + 常量
//  20. AddrInfoPayload operator==
//  21. MethodId::AddrInfoAnnounce 枚举值校验

#include "linoh/protocol/addr_info.hpp"
#include "linoh/protocol/application_message.hpp"

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

// ========== 辅助函数 ==========

// 生成测试用 EndpointId（32 字节，填充模式 0xE0+i）
static std::array<std::uint8_t, 32> make_test_endpoint_id(std::uint8_t base = 0xE0) {
    std::array<std::uint8_t, 32> id{};
    for (int i = 0; i < 32; ++i) id[i] = static_cast<std::uint8_t>(base + i);
    return id;
}

// 生成测试用 IPv4 DirectAddress
static DirectAddress make_ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d, std::uint16_t port) {
    DirectAddress addr;
    addr.family = DirectAddress::Family::IPv4;
    addr.ip = {a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    addr.port = port;
    return addr;
}

// 生成测试用 IPv6 DirectAddress
static DirectAddress make_ipv6(std::uint16_t port) {
    DirectAddress addr;
    addr.family = DirectAddress::Family::IPv6;
    for (int i = 0; i < 16; ++i) addr.ip[i] = static_cast<std::uint8_t>(0x20 + i);
    addr.port = port;
    return addr;
}

// ========== 测试用例 ==========

// 1. AddrInfoLevel 枚举值 + to_string + is_valid_level
static void test_addr_info_level_enum() {
    std::printf("[test] AddrInfoLevel enum + to_string + is_valid_level...\n");
    CHECK_EQ(static_cast<std::uint8_t>(AddrInfoLevel::Id),                0u);
    CHECK_EQ(static_cast<std::uint8_t>(AddrInfoLevel::RelayAndAddresses), 1u);
    CHECK_EQ(static_cast<std::uint8_t>(AddrInfoLevel::Relay),             2u);
    CHECK_EQ(static_cast<std::uint8_t>(AddrInfoLevel::Addresses),         3u);

    CHECK(std::strcmp(to_string(AddrInfoLevel::Id), "Id") == 0);
    CHECK(std::strcmp(to_string(AddrInfoLevel::RelayAndAddresses), "RelayAndAddresses") == 0);
    CHECK(std::strcmp(to_string(AddrInfoLevel::Relay), "Relay") == 0);
    CHECK(std::strcmp(to_string(AddrInfoLevel::Addresses), "Addresses") == 0);

    CHECK(is_valid_level(0));
    CHECK(is_valid_level(1));
    CHECK(is_valid_level(2));
    CHECK(is_valid_level(3));
    CHECK(!is_valid_level(4));
    CHECK(!is_valid_level(255));
}

// 2. DirectAddress IPv4 编码字节布局 + encoded_size
static void test_direct_address_ipv4_encode_layout() {
    std::printf("[test] DirectAddress IPv4 encode layout...\n");
    auto addr = make_ipv4(192, 168, 1, 100, 9001);
    auto buf = addr.encode();

    CHECK_EQ(buf.size(), 7u);  // 1(family) + 4(ip) + 2(port)
    CHECK_EQ(addr.encoded_size(), 7u);

    CHECK_EQ(buf[0], static_cast<std::uint8_t>(4));  // family=IPv4

    // IP 大端序
    CHECK_EQ(buf[1], 192);
    CHECK_EQ(buf[2], 168);
    CHECK_EQ(buf[3], 1);
    CHECK_EQ(buf[4], 100);

    // port 大端序 0x23 0x29 = 9001
    CHECK_EQ(buf[5], static_cast<std::uint8_t>((9001 >> 8) & 0xFF));
    CHECK_EQ(buf[6], static_cast<std::uint8_t>(9001 & 0xFF));
}

// 3. DirectAddress IPv4 encode/decode 往返
static void test_direct_address_ipv4_roundtrip() {
    std::printf("[test] DirectAddress IPv4 roundtrip...\n");
    auto addr = make_ipv4(10, 0, 0, 1, 65535);
    auto buf = addr.encode();

    DirectAddress decoded;
    std::size_t consumed = 0;
    bool ok = DirectAddress::decode(buf, decoded, consumed);
    CHECK(ok);
    CHECK_EQ(consumed, 7u);
    CHECK(addr == decoded);
}

// 4. DirectAddress IPv6 encode/decode 往返
static void test_direct_address_ipv6_roundtrip() {
    std::printf("[test] DirectAddress IPv6 roundtrip...\n");
    auto addr = make_ipv6(443);
    auto buf = addr.encode();

    CHECK_EQ(buf.size(), 19u);  // 1(family) + 16(ip) + 2(port)
    CHECK_EQ(addr.encoded_size(), 19u);
    CHECK_EQ(buf[0], static_cast<std::uint8_t>(16));  // family=IPv6

    DirectAddress decoded;
    std::size_t consumed = 0;
    bool ok = DirectAddress::decode(buf, decoded, consumed);
    CHECK(ok);
    CHECK_EQ(consumed, 19u);
    CHECK(addr == decoded);
}

// 5. DirectAddress decode 数据不足返回 false
static void test_direct_address_decode_short_data() {
    std::printf("[test] DirectAddress decode short data...\n");
    std::vector<std::uint8_t> short_buf = {4, 192, 168};  // 仅 3 字节，不足 7
    DirectAddress decoded;
    std::size_t consumed = 999;
    bool ok = DirectAddress::decode(short_buf, decoded, consumed);
    CHECK(!ok);
    CHECK_EQ(consumed, 0u);
}

// 6. DirectAddress decode 非法 family 返回 false
static void test_direct_address_decode_bad_family() {
    std::printf("[test] DirectAddress decode bad family...\n");
    // family=6 既非 IPv4(4) 也非 IPv6(16)
    std::vector<std::uint8_t> bad_buf = {6, 0, 0, 0, 0, 0, 0};
    DirectAddress decoded;
    std::size_t consumed = 0;
    bool ok = DirectAddress::decode(bad_buf, decoded, consumed);
    CHECK(!ok);
}

// 7. DirectAddress to_string
static void test_direct_address_to_string() {
    std::printf("[test] DirectAddress to_string...\n");
    auto addr4 = make_ipv4(192, 168, 1, 1, 8080);
    auto s4 = addr4.to_string();
    CHECK(s4.find("192.168.1.1") != std::string::npos);
    CHECK(s4.find("8080") != std::string::npos);

    auto addr6 = make_ipv6(443);
    auto s6 = addr6.to_string();
    CHECK(s6.find("[") != std::string::npos);  // IPv6 用方括号
    CHECK(s6.find("443") != std::string::npos);
}

// 8. DirectAddress operator== / operator!=
static void test_direct_address_equality() {
    std::printf("[test] DirectAddress equality...\n");
    auto a1 = make_ipv4(10, 0, 0, 1, 9001);
    auto a2 = make_ipv4(10, 0, 0, 1, 9001);
    auto a3 = make_ipv4(10, 0, 0, 2, 9001);  // IP 不同
    auto a4 = make_ipv4(10, 0, 0, 1, 9002);  // port 不同

    CHECK(a1 == a2);
    CHECK(!(a1 == a3));
    CHECK(!(a1 == a4));

    // IPv4 vs IPv6 不同
    auto a6 = make_ipv6(9001);
    CHECK(!(a1 == a6));
}

// 9. AddrInfoPayload level=Id 编码字节布局（最小 34B）
static void test_addr_info_payload_id_level_layout() {
    std::printf("[test] AddrInfoPayload level=Id layout (min 34B)...\n");
    AddrInfoPayload p;
    p.level = AddrInfoLevel::Id;
    p.endpoint_id = make_test_endpoint_id();
    p.relay_url = "";
    p.addresses.clear();

    auto buf = p.encode();
    CHECK_EQ(buf.size(), AddrInfoPayload::kMinEncodedSize + 2);  // 34 + relay_url_len(1) + addr_count(1) = 36

    // offset 0: version
    CHECK_EQ(buf[0], AddrInfoPayload::kCurrentVersion);

    // offset 1: level = 0 (Id)
    CHECK_EQ(buf[1], 0u);

    // offset 2-33: endpoint_id
    for (int i = 0; i < 32; ++i) {
        CHECK_EQ(buf[2 + i], static_cast<std::uint8_t>(0xE0 + i));
    }

    // offset 34: relay_url_len = 0
    CHECK_EQ(buf[34], 0u);

    // offset 35: addr_count = 0
    CHECK_EQ(buf[35], 0u);
}

// 10. AddrInfoPayload level=Id encode/decode 往返
static void test_addr_info_payload_id_roundtrip() {
    std::printf("[test] AddrInfoPayload level=Id roundtrip...\n");
    AddrInfoPayload p;
    p.level = AddrInfoLevel::Id;
    p.endpoint_id = make_test_endpoint_id(0xB0);

    auto buf = p.encode();
    AddrInfoPayload decoded;
    bool ok = AddrInfoPayload::decode(buf, decoded);
    CHECK(ok);
    CHECK(decoded == p);
    CHECK_EQ(decoded.level, AddrInfoLevel::Id);
    CHECK(!decoded.has_relay());
    CHECK(!decoded.has_addresses());
}

// 11. AddrInfoPayload level=Relay encode/decode 往返
static void test_addr_info_payload_relay_roundtrip() {
    std::printf("[test] AddrInfoPayload level=Relay roundtrip...\n");
    AddrInfoPayload p;
    p.level = AddrInfoLevel::Relay;
    p.endpoint_id = make_test_endpoint_id(0xC0);
    p.relay_url = "https://relay.example.com:9002";
    p.addresses.clear();

    auto buf = p.encode();
    AddrInfoPayload decoded;
    bool ok = AddrInfoPayload::decode(buf, decoded);
    CHECK(ok);
    CHECK(decoded == p);
    CHECK_EQ(decoded.relay_url, std::string("https://relay.example.com:9002"));
    CHECK(decoded.has_relay());
    CHECK(!decoded.has_addresses());
}

// 12. AddrInfoPayload level=Addresses encode/decode 往返
static void test_addr_info_payload_addresses_roundtrip() {
    std::printf("[test] AddrInfoPayload level=Addresses roundtrip...\n");
    AddrInfoPayload p;
    p.level = AddrInfoLevel::Addresses;
    p.endpoint_id = make_test_endpoint_id(0xD0);
    p.relay_url = "";
    p.addresses = {make_ipv4(192, 168, 1, 50, 9101), make_ipv4(10, 0, 0, 5, 9101)};

    auto buf = p.encode();
    AddrInfoPayload decoded;
    bool ok = AddrInfoPayload::decode(buf, decoded);
    CHECK(ok);
    CHECK(decoded == p);
    CHECK_EQ(decoded.addresses.size(), 2u);
    CHECK(!decoded.has_relay());
    CHECK(decoded.has_addresses());
}

// 13. AddrInfoPayload level=RelayAndAddresses 全量往返
static void test_addr_info_payload_full_roundtrip() {
    std::printf("[test] AddrInfoPayload level=RelayAndAddresses full roundtrip...\n");
    AddrInfoPayload p;
    p.level = AddrInfoLevel::RelayAndAddresses;  // 默认
    p.endpoint_id = make_test_endpoint_id(0xF0);
    p.relay_url = "relay://203.0.113.10:9002";
    p.addresses = {make_ipv4(117, 50, 215, 7, 9001), make_ipv6(9103)};

    auto buf = p.encode();
    AddrInfoPayload decoded;
    bool ok = AddrInfoPayload::decode(buf, decoded);
    CHECK(ok);
    CHECK(decoded == p);
    CHECK_EQ(decoded.relay_url, std::string("relay://203.0.113.10:9002"));
    CHECK_EQ(decoded.addresses.size(), 2u);
    CHECK(decoded.addresses[0] == make_ipv4(117, 50, 215, 7, 9001));
    CHECK(decoded.addresses[1] == make_ipv6(9103));
    CHECK(decoded.has_relay());
    CHECK(decoded.has_addresses());
}

// 14. AddrInfoPayload 多地址场景（IPv4 + IPv6 混合）
static void test_addr_info_payload_mixed_addresses() {
    std::printf("[test] AddrInfoPayload mixed IPv4+IPv6 addresses...\n");
    AddrInfoPayload p;
    p.level = AddrInfoLevel::Addresses;
    p.endpoint_id = make_test_endpoint_id();
    p.addresses = {
        make_ipv4(1, 2, 3, 4, 100),
        make_ipv6(200),
        make_ipv4(5, 6, 7, 8, 300),
        make_ipv6(400),
    };

    auto buf = p.encode();
    AddrInfoPayload decoded;
    CHECK(AddrInfoPayload::decode(buf, decoded));
    CHECK_EQ(decoded.addresses.size(), 4u);
    CHECK(decoded.addresses[0] == make_ipv4(1, 2, 3, 4, 100));
    CHECK(decoded.addresses[1] == make_ipv6(200));
    CHECK(decoded.addresses[2] == make_ipv4(5, 6, 7, 8, 300));
    CHECK(decoded.addresses[3] == make_ipv6(400));
}

// 15. AddrInfoPayload decode 数据不足返回 false
static void test_addr_info_payload_decode_short_data() {
    std::printf("[test] AddrInfoPayload decode short data...\n");
    std::vector<std::uint8_t> short_buf(10, 0);  // 仅 10 字节，不足 34
    AddrInfoPayload decoded;
    CHECK(!AddrInfoPayload::decode(short_buf, decoded));

    std::vector<std::uint8_t> empty;
    CHECK(!AddrInfoPayload::decode(empty, decoded));
}

// 16. AddrInfoPayload decode 非法 level 返回 false
static void test_addr_info_payload_decode_bad_level() {
    std::printf("[test] AddrInfoPayload decode bad level...\n");
    std::vector<std::uint8_t> buf(36, 0);
    buf[1] = 99;  // 非法 level 值
    AddrInfoPayload decoded;
    CHECK(!AddrInfoPayload::decode(buf, decoded));
}

// 17. AddrInfoPayload relay_url 空字符串
static void test_addr_info_payload_empty_relay_url() {
    std::printf("[test] AddrInfoPayload empty relay_url...\n");
    AddrInfoPayload p;
    p.level = AddrInfoLevel::Relay;
    p.endpoint_id = make_test_endpoint_id();
    p.relay_url = "";

    auto buf = p.encode();
    CHECK_EQ(buf[34], 0u);  // relay_url_len = 0

    AddrInfoPayload decoded;
    CHECK(AddrInfoPayload::decode(buf, decoded));
    CHECK_EQ(decoded.relay_url.size(), 0u);
}

// 18. AddrInfoPayload has_relay/has_addresses 判定
static void test_addr_info_payload_has_flags() {
    std::printf("[test] AddrInfoPayload has_relay/has_addresses...\n");
    AddrInfoPayload p_id;
    p_id.level = AddrInfoLevel::Id;
    CHECK(!p_id.has_relay());
    CHECK(!p_id.has_addresses());

    AddrInfoPayload p_relay;
    p_relay.level = AddrInfoLevel::Relay;
    CHECK(p_relay.has_relay());
    CHECK(!p_relay.has_addresses());

    AddrInfoPayload p_addr;
    p_addr.level = AddrInfoLevel::Addresses;
    CHECK(!p_addr.has_relay());
    CHECK(p_addr.has_addresses());

    AddrInfoPayload p_full;
    p_full.level = AddrInfoLevel::RelayAndAddresses;
    CHECK(p_full.has_relay());
    CHECK(p_full.has_addresses());
}

// 19. AddrInfoPayload 默认值 + 常量
static void test_addr_info_payload_defaults() {
    std::printf("[test] AddrInfoPayload defaults + constants...\n");
    AddrInfoPayload p;
    CHECK_EQ(p.version, AddrInfoPayload::kCurrentVersion);
    CHECK_EQ(p.level, AddrInfoLevel::RelayAndAddresses);  // 默认全量
    CHECK_EQ(p.relay_url.size(), 0u);
    CHECK_EQ(p.addresses.size(), 0u);

    CHECK_EQ(AddrInfoPayload::kMinEncodedSize, 34u);
    CHECK_EQ(AddrInfoPayload::kCurrentVersion, 1u);
    CHECK_EQ(AddrInfoPayload::kMaxRelayUrlLen, 255u);
    CHECK_EQ(AddrInfoPayload::kMaxAddresses, 255u);
}

// 20. AddrInfoPayload operator==
static void test_addr_info_payload_equality() {
    std::printf("[test] AddrInfoPayload equality...\n");
    AddrInfoPayload p1;
    p1.level = AddrInfoLevel::RelayAndAddresses;
    p1.endpoint_id = make_test_endpoint_id();
    p1.relay_url = "test";
    p1.addresses = {make_ipv4(1, 2, 3, 4, 5)};

    AddrInfoPayload p2 = p1;
    CHECK(p1 == p2);

    p2.relay_url = "different";
    CHECK(!(p1 == p2));
}

// 21. MethodId::AddrInfoAnnounce 枚举值校验
static void test_method_id_addr_info_enum() {
    std::printf("[test] MethodId::AddrInfoAnnounce enum...\n");
    CHECK_EQ(static_cast<std::uint16_t>(MethodId::AddrInfoAnnounce), 0x0064u);
    // 紧接 CapabilitiesAck(0x0063)
    CHECK_EQ(static_cast<std::uint16_t>(MethodId::CapabilitiesAck), 0x0063u);
    CHECK(static_cast<std::uint16_t>(MethodId::AddrInfoAnnounce) >
          static_cast<std::uint16_t>(MethodId::CapabilitiesAck));
}

// ========== main ==========

int main() {
    std::printf("=== test_addr_info (v4.0.0 M18) ===\n");

    test_addr_info_level_enum();
    test_direct_address_ipv4_encode_layout();
    test_direct_address_ipv4_roundtrip();
    test_direct_address_ipv6_roundtrip();
    test_direct_address_decode_short_data();
    test_direct_address_decode_bad_family();
    test_direct_address_to_string();
    test_direct_address_equality();
    test_addr_info_payload_id_level_layout();
    test_addr_info_payload_id_roundtrip();
    test_addr_info_payload_relay_roundtrip();
    test_addr_info_payload_addresses_roundtrip();
    test_addr_info_payload_full_roundtrip();
    test_addr_info_payload_mixed_addresses();
    test_addr_info_payload_decode_short_data();
    test_addr_info_payload_decode_bad_level();
    test_addr_info_payload_empty_relay_url();
    test_addr_info_payload_has_flags();
    test_addr_info_payload_defaults();
    test_addr_info_payload_equality();
    test_method_id_addr_info_enum();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
