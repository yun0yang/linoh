// test_stun.cpp — STUN 协议编解码单元测试（P4-B-1）
//
// 覆盖：
//   - Binding Request 编码
//   - Binding Response 编码 + 解析往返
//   - XOR-MAPPED-ADDRESS 编解码（IPv4/IPv6）
//   - MAPPED-ADDRESS 编解码（IPv4/IPv6）
//   - generate_transaction_id 唯一性
//   - 非法消息拒绝（非 STUN 包、cookie 错误、长度不足）
//   - xor_port / xor_ipv4 工具函数

#include "linoh/net/stun.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

using namespace linoh::net::stun;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 工具：比较 transaction_id 是否相等
// ============================================================================
static bool tx_eq(const std::array<std::uint8_t, kTransactionIdSize> &a,
                  const std::array<std::uint8_t, kTransactionIdSize> &b) {
    return std::memcmp(a.data(), b.data(), kTransactionIdSize) == 0;
}

// ============================================================================
// 测试 1: encode_binding_request 格式正确
// ============================================================================
static void test_encode_binding_request_format() {
    std::printf("[test] encode_binding_request format...\n");

    std::array<std::uint8_t, kTransactionIdSize> tx_id{};
    for (std::size_t i = 0; i < kTransactionIdSize; ++i) tx_id[i] = static_cast<std::uint8_t>(i + 1);

    auto msg = encode_binding_request(tx_id);

    // 长度应为 header_size（20 字节）
    CHECK(msg.size() == kHeaderSize);

    // 消息类型 = 0x0001 (Binding Request)
    CHECK((msg[0] << 8 | msg[1]) == 0x0001);

    // 消息长度 = 0
    CHECK((msg[2] << 8 | msg[3]) == 0);

    // Magic Cookie = 0x2112A442
    CHECK((msg[4] << 24 | msg[5] << 16 | msg[6] << 8 | msg[7]) == 0x2112A442);

    // Transaction ID（offset 8..19）
    for (std::size_t i = 0; i < kTransactionIdSize; ++i) {
        CHECK(msg[8 + i] == tx_id[i]);
    }

    // 高 2 位必须为 00（STUN 消息标识）
    CHECK((msg[0] & 0xC0) == 0);
}

// ============================================================================
// 测试 2: generate_transaction_id 唯一性
// ============================================================================
static void test_generate_transaction_id_unique() {
    std::printf("[test] generate_transaction_id uniqueness...\n");

    std::set<std::vector<std::uint8_t>> seen;
    for (int i = 0; i < 1000; ++i) {
        auto id = generate_transaction_id();
        std::vector<std::uint8_t> v(id.begin(), id.end());
        auto [it, inserted] = seen.insert(v);
        CHECK(inserted);  // 不应有重复
        (void)it;
    }
    CHECK(seen.size() == 1000);
}

// ============================================================================
// 测试 3: parse_message 合法消息
// ============================================================================
static void test_parse_valid_message() {
    std::printf("[test] parse_message valid...\n");

    std::array<std::uint8_t, kTransactionIdSize> tx_id{};
    for (std::size_t i = 0; i < kTransactionIdSize; ++i) tx_id[i] = static_cast<std::uint8_t>(0xAA - i);

    auto msg_bytes = encode_binding_request(tx_id);
    auto parsed = parse_message(std::span<const std::uint8_t>(msg_bytes.data(), msg_bytes.size()));

    CHECK(parsed.has_value());
    CHECK(parsed->type == MessageType::BindingRequest);
    CHECK(tx_eq(parsed->transaction_id, tx_id));
    CHECK(parsed->attributes.empty());
}

// ============================================================================
// 测试 4: parse_message 非法消息（数据过短）
// ============================================================================
static void test_parse_short_data() {
    std::printf("[test] parse_message short data...\n");

    std::vector<std::uint8_t> short_data(10, 0);
    auto parsed = parse_message(std::span<const std::uint8_t>(short_data.data(), short_data.size()));
    CHECK(!parsed.has_value());
}

// ============================================================================
// 测试 5: parse_message 非 STUN 包（高 2 位非 00）
// ============================================================================
static void test_parse_non_stun_packet() {
    std::printf("[test] parse_message non-STUN packet...\n");

    std::vector<std::uint8_t> bad_packet(kHeaderSize, 0);
    // 高 2 位非 00
    bad_packet[0] = 0xC0;
    bad_packet[4] = 0x21; bad_packet[5] = 0x12;
    bad_packet[6] = 0xA4; bad_packet[7] = 0x42;

    auto parsed = parse_message(std::span<const std::uint8_t>(bad_packet.data(), bad_packet.size()));
    CHECK(!parsed.has_value());
}

// ============================================================================
// 测试 6: parse_message Magic Cookie 错误
// ============================================================================
static void test_parse_wrong_magic_cookie() {
    std::printf("[test] parse_message wrong magic cookie...\n");

    std::vector<std::uint8_t> bad_packet(kHeaderSize, 0);
    bad_packet[0] = 0x00; bad_packet[1] = 0x01;
    bad_packet[2] = 0x00; bad_packet[3] = 0x00;
    // 错误的 cookie
    bad_packet[4] = 0x00; bad_packet[5] = 0x00;
    bad_packet[6] = 0x00; bad_packet[7] = 0x00;

    auto parsed = parse_message(std::span<const std::uint8_t>(bad_packet.data(), bad_packet.size()));
    CHECK(!parsed.has_value());
}

// ============================================================================
// 测试 7: XOR-MAPPED-ADDRESS IPv4 编码往返
// ============================================================================
static void test_xor_mapped_ipv4_roundtrip() {
    std::printf("[test] XOR-MAPPED-ADDRESS IPv4 roundtrip...\n");

    std::array<std::uint8_t, kTransactionIdSize> tx_id{};
    for (std::size_t i = 0; i < kTransactionIdSize; ++i) tx_id[i] = static_cast<std::uint8_t>(i * 2);

    std::string ip = "192.168.1.100";
    std::uint16_t port = 12345;

    // 编码
    auto value = encode_xor_mapped_address(ip, port, tx_id);

    // 构造属性并解析
    StunAttribute attr{AttributeType::XorMappedAddress, value};
    auto parsed = parse_xor_mapped_address(attr, tx_id);

    CHECK(parsed.has_value());
    CHECK(parsed->first == ip);
    CHECK(parsed->second == port);
}

// ============================================================================
// 测试 8: XOR-MAPPED-ADDRESS IPv6 编码往返
// ============================================================================
static void test_xor_mapped_ipv6_roundtrip() {
    std::printf("[test] XOR-MAPPED-ADDRESS IPv6 roundtrip...\n");

    std::array<std::uint8_t, kTransactionIdSize> tx_id{};
    for (std::size_t i = 0; i < kTransactionIdSize; ++i) tx_id[i] = static_cast<std::uint8_t>(0xFF - i);

    std::string ip = "2001:db8::1";
    std::uint16_t port = 5678;

    auto value = encode_xor_mapped_address(ip, port, tx_id);
    StunAttribute attr{AttributeType::XorMappedAddress, value};
    auto parsed = parse_xor_mapped_address(attr, tx_id);

    CHECK(parsed.has_value());
    // IPv6 字符串可能有格式差异，但解析回的地址应能 inet_pton 回来
    // 这里直接比较标准化形式（小写、压缩）
    CHECK(parsed->second == port);
    // IPv6 字符串可能不等，但 inet_pton 应能解析两边
    in6_addr a1{}, a2{};
    int r1 = inet_pton(AF_INET6, ip.c_str(), &a1);
    int r2 = inet_pton(AF_INET6, parsed->first.c_str(), &a2);
    CHECK(r1 == 1);
    CHECK(r2 == 1);
    CHECK(std::memcmp(&a1, &a2, 16) == 0);
}

// ============================================================================
// 测试 9: MAPPED-ADDRESS IPv4 编码往返
// ============================================================================
static void test_mapped_ipv4_roundtrip() {
    std::printf("[test] MAPPED-ADDRESS IPv4 roundtrip...\n");

    std::string ip = "10.0.0.1";
    std::uint16_t port = 8080;

    auto value = encode_mapped_address(ip, port);
    StunAttribute attr{AttributeType::MappedAddress, value};
    auto parsed = parse_mapped_address(attr);

    CHECK(parsed.has_value());
    CHECK(parsed->first == ip);
    CHECK(parsed->second == port);
}

// ============================================================================
// 测试 10: MAPPED-ADDRESS IPv6 编码往返
// ============================================================================
static void test_mapped_ipv6_roundtrip() {
    std::printf("[test] MAPPED-ADDRESS IPv6 roundtrip...\n");

    std::string ip = "::1";
    std::uint16_t port = 443;

    auto value = encode_mapped_address(ip, port);
    StunAttribute attr{AttributeType::MappedAddress, value};
    auto parsed = parse_mapped_address(attr);

    CHECK(parsed.has_value());
    CHECK(parsed->second == port);
    in6_addr a1{}, a2{};
    inet_pton(AF_INET6, ip.c_str(), &a1);
    inet_pton(AF_INET6, parsed->first.c_str(), &a2);
    CHECK(std::memcmp(&a1, &a2, 16) == 0);
}

// ============================================================================
// 测试 11: xor_port 工具函数
// ============================================================================
static void test_xor_port() {
    std::printf("[test] xor_port...\n");

    std::uint16_t port = 19302;
    std::uint16_t xored = xor_port(port);
    std::uint16_t restored = xor_port(xored);  // XOR 自反
    CHECK(restored == port);

    // 验证具体值：port ^ (0x2112A442 >> 16) = port ^ 0x2112
    CHECK(xored == (port ^ 0x2112));
}

// ============================================================================
// 测试 12: xor_ipv4 工具函数（自反性）
// ============================================================================
static void test_xor_ipv4_reflexive() {
    std::printf("[test] xor_ipv4 reflexive...\n");

    std::array<std::uint8_t, kTransactionIdSize> tx_id{};
    for (std::size_t i = 0; i < kTransactionIdSize; ++i) tx_id[i] = 42;

    std::string ip = "172.16.254.1";
    std::string xored = xor_ipv4(ip, tx_id);
    std::string restored = xor_ipv4(xored, tx_id);  // XOR 自反

    CHECK(restored == ip);
}

// ============================================================================
// 测试 13: encode_binding_response 解析往返
// ============================================================================
static void test_binding_response_roundtrip() {
    std::printf("[test] binding_response roundtrip...\n");

    std::array<std::uint8_t, kTransactionIdSize> tx_id{};
    for (std::size_t i = 0; i < kTransactionIdSize; ++i) tx_id[i] = static_cast<std::uint8_t>(0x80 + i);

    std::string mapped_ip = "203.0.113.42";
    std::uint16_t mapped_port = 32768;

    auto msg_bytes = encode_binding_response(tx_id, mapped_ip, mapped_port);
    CHECK(msg_bytes.size() > kHeaderSize);

    auto parsed = parse_message(std::span<const std::uint8_t>(msg_bytes.data(), msg_bytes.size()));

    CHECK(parsed.has_value());
    CHECK(parsed->type == MessageType::BindingResponse);
    CHECK(tx_eq(parsed->transaction_id, tx_id));

    // 应包含 XOR-MAPPED-ADDRESS 属性
    const auto *attr = parsed->find(AttributeType::XorMappedAddress);
    CHECK(attr != nullptr);

    auto mapped = parse_xor_mapped_address(*attr, parsed->transaction_id);
    CHECK(mapped.has_value());
    CHECK(mapped->first == mapped_ip);
    CHECK(mapped->second == mapped_port);
}

// ============================================================================
// 测试 14: parse_message 多属性消息
// ============================================================================
static void test_parse_multiple_attributes() {
    std::printf("[test] parse_message multiple attributes...\n");

    std::array<std::uint8_t, kTransactionIdSize> tx_id{};
    for (std::size_t i = 0; i < kTransactionIdSize; ++i) tx_id[i] = static_cast<std::uint8_t>(i);

    // 手动构造一个包含多个属性的消息
    std::vector<std::uint8_t> body;

    // SOFTWARE 属性
    std::string software = "linoh-test";
    auto put_u16 = [](std::vector<std::uint8_t> &v, std::uint16_t x) {
        v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xFF));
        v.push_back(static_cast<std::uint8_t>(x & 0xFF));
    };

    put_u16(body, static_cast<std::uint16_t>(AttributeType::Software));
    put_u16(body, static_cast<std::uint16_t>(software.size()));
    body.insert(body.end(), software.begin(), software.end());
    while (body.size() % 4 != 0) body.push_back(0);  // padding

    // XOR-MAPPED-ADDRESS 属性
    auto xor_value = encode_xor_mapped_address("198.51.100.1", 5000, tx_id);
    put_u16(body, static_cast<std::uint16_t>(AttributeType::XorMappedAddress));
    put_u16(body, static_cast<std::uint16_t>(xor_value.size()));
    body.insert(body.end(), xor_value.begin(), xor_value.end());
    while (body.size() % 4 != 0) body.push_back(0);

    // 构造完整消息
    std::vector<std::uint8_t> msg;
    put_u16(msg, static_cast<std::uint16_t>(MessageType::BindingResponse));
    put_u16(msg, static_cast<std::uint16_t>(body.size()));
    // magic cookie
    msg.push_back(0x21); msg.push_back(0x12); msg.push_back(0xA4); msg.push_back(0x42);
    msg.insert(msg.end(), tx_id.begin(), tx_id.end());
    msg.insert(msg.end(), body.begin(), body.end());

    auto parsed = parse_message(std::span<const std::uint8_t>(msg.data(), msg.size()));

    CHECK(parsed.has_value());
    CHECK(parsed->attributes.size() == 2);

    const auto *sw = parsed->find(AttributeType::Software);
    CHECK(sw != nullptr);
    CHECK(sw->value.size() == software.size());
    CHECK(std::string(sw->value.begin(), sw->value.end()) == software);

    const auto *xm = parsed->find(AttributeType::XorMappedAddress);
    CHECK(xm != nullptr);
    auto mapped = parse_xor_mapped_address(*xm, parsed->transaction_id);
    CHECK(mapped.has_value());
    CHECK(mapped->first == "198.51.100.1");
    CHECK(mapped->second == 5000);
}

// ============================================================================
// 测试 15: parse_message 属性长度超出消息边界
// ============================================================================
static void test_parse_attribute_length_exceeds() {
    std::printf("[test] parse_message attribute length exceeds...\n");

    std::vector<std::uint8_t> msg;
    auto put_u16 = [](std::vector<std::uint8_t> &v, std::uint16_t x) {
        v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xFF));
        v.push_back(static_cast<std::uint8_t>(x & 0xFF));
    };

    put_u16(msg, static_cast<std::uint16_t>(MessageType::BindingResponse));
    put_u16(msg, 8);  // 声明 body 长度为 8
    msg.push_back(0x21); msg.push_back(0x12); msg.push_back(0xA4); msg.push_back(0x42);
    for (int i = 0; i < 12; ++i) msg.push_back(0);

    // 属性声明长度为 100（超出实际 body）
    put_u16(msg, static_cast<std::uint16_t>(AttributeType::Software));
    put_u16(msg, 100);
    put_u16(msg, 0); put_u16(msg, 0);  // 实际只有 4 字节

    auto parsed = parse_message(std::span<const std::uint8_t>(msg.data(), msg.size()));
    CHECK(!parsed.has_value());
}

// ============================================================================
// 测试 16: StunMessage::find 查找不存在的属性
// ============================================================================
static void test_find_nonexistent_attribute() {
    std::printf("[test] StunMessage::find nonexistent...\n");

    std::array<std::uint8_t, kTransactionIdSize> tx_id{};
    auto msg_bytes = encode_binding_request(tx_id);
    auto parsed = parse_message(std::span<const std::uint8_t>(msg_bytes.data(), msg_bytes.size()));

    CHECK(parsed.has_value());
    const auto *attr = parsed->find(AttributeType::Software);
    CHECK(attr == nullptr);
}

// ============================================================================
// 测试 17: encode_xor_mapped_address IPv4 具体值验证
// ============================================================================
static void test_xor_mapped_ipv4_specific_value() {
    std::printf("[test] XOR-MAPPED-ADDRESS IPv4 specific value...\n");

    // 已知值：tx_id 全 0，ip=192.0.2.1，port=32853
    // RFC 5389 示例值（参考 §15.2）
    std::array<std::uint8_t, kTransactionIdSize> tx_id{};  // 全 0

    std::string ip = "192.0.2.1";
    std::uint16_t port = 32853;

    auto value = encode_xor_mapped_address(ip, port, tx_id);

    // 期望：Reserved=0x00, Family=0x01, Port XOR(0x2112)=32853^0x2112
    CHECK(value.size() == 8);
    CHECK(value[0] == 0x00);
    CHECK(value[1] == 0x01);  // IPv4

    // Port XOR: 32853 ^ 0x2112 = 0x8055 ^ 0x2112 = 0xA147
    std::uint16_t expected_xport = port ^ 0x2112;
    CHECK(value[2] == static_cast<std::uint8_t>((expected_xport >> 8) & 0xFF));
    CHECK(value[3] == static_cast<std::uint8_t>(expected_xport & 0xFF));

    // Address XOR: 192.0.2.1 = 0xC0000201, XOR 0x2112A442 = 0xE112A643
    // 网络字节序：E1 12 A6 43
    std::uint32_t ip_host = (192u << 24) | (0u << 16) | (2u << 8) | 1u;
    std::uint32_t xored = ip_host ^ 0x2112A442u;
    CHECK(value[4] == static_cast<std::uint8_t>((xored >> 24) & 0xFF));
    CHECK(value[5] == static_cast<std::uint8_t>((xored >> 16) & 0xFF));
    CHECK(value[6] == static_cast<std::uint8_t>((xored >> 8) & 0xFF));
    CHECK(value[7] == static_cast<std::uint8_t>(xored & 0xFF));
}

// ============================================================================
// 测试 18: 并发调用 generate_transaction_id
// ============================================================================
static void test_concurrent_generate_transaction_id() {
    std::printf("[test] concurrent generate_transaction_id...\n");

    std::atomic<int> collisions{0};
    std::set<std::vector<std::uint8_t>> all_ids;
    std::mutex set_mu;

    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&]() {
            std::set<std::vector<std::uint8_t>> local_ids;
            for (int i = 0; i < 1000; ++i) {
                auto id = generate_transaction_id();
                std::vector<std::uint8_t> v(id.begin(), id.end());
                local_ids.insert(v);
            }
            std::lock_guard<std::mutex> lk(set_mu);
            for (auto &v : local_ids) {
                if (!all_ids.insert(v).second) {
                    ++collisions;
                }
            }
        });
    }
    for (auto &t : threads) t.join();

    CHECK(collisions.load() == 0);  // 不应有碰撞
    CHECK(all_ids.size() == 4000);
}

int main() {
    std::printf("=== test_stun ===\n");

    test_encode_binding_request_format();
    test_generate_transaction_id_unique();
    test_parse_valid_message();
    test_parse_short_data();
    test_parse_non_stun_packet();
    test_parse_wrong_magic_cookie();
    test_xor_mapped_ipv4_roundtrip();
    test_xor_mapped_ipv6_roundtrip();
    test_mapped_ipv4_roundtrip();
    test_mapped_ipv6_roundtrip();
    test_xor_port();
    test_xor_ipv4_reflexive();
    test_binding_response_roundtrip();
    test_parse_multiple_attributes();
    test_parse_attribute_length_exceeds();
    test_find_nonexistent_attribute();
    test_xor_mapped_ipv4_specific_value();
    test_concurrent_generate_transaction_id();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
