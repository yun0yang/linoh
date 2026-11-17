// test_capabilities.cpp — V3.5 P5-A 节点能力探测单元测试
//
// 测试覆盖：
//   1. 能力位掩码常量值校验（kCap*）
//   2. has_capability 位判定
//   3. NodeCapabilities 默认值 + 便捷判定 + to_string
//   4. CapabilitiesAckPayload encode 字节布局（39B）
//   5. CapabilitiesAckPayload encode/decode 往返
//   6. decode 长度不足返回 false
//   7. supported=false 降级（mask=0）
//   8. to_node_capabilities 转换
//   9. 全能力 mask 编解码
//  10. 多能力位组合
//  11. MethodId::CapabilitiesProbe/Ack 枚举值校验
//  12. peer_endpoint 32B 原样往返

#include "linoh/protocol/capabilities.hpp"
#include "linoh/protocol/application_message.hpp"

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

// 1. 能力位掩码常量值校验
static void test_capabilities_mask_constants() {
    std::printf("[test] capabilities mask constants...\n");
    CHECK_EQ(static_cast<std::uint32_t>(kCapNone),              0x0000u);
    CHECK_EQ(static_cast<std::uint32_t>(kCapHasReturnAddress),  0x0001u);
    CHECK_EQ(static_cast<std::uint32_t>(kCapDirectReturn),      0x0002u);
    CHECK_EQ(static_cast<std::uint32_t>(kCapResultShard),       0x0004u);
    CHECK_EQ(static_cast<std::uint32_t>(kCapHasSessionId),      0x0008u);
    CHECK_EQ(static_cast<std::uint32_t>(kCapZstdCompressed),    0x0010u);
}

// 2. has_capability 位判定
static void test_has_capability() {
    std::printf("[test] has_capability bit check...\n");
    std::uint32_t mask = kCapHasSessionId | kCapZstdCompressed | kCapDirectReturn;
    CHECK(has_capability(mask, kCapHasSessionId));
    CHECK(has_capability(mask, kCapZstdCompressed));
    CHECK(has_capability(mask, kCapDirectReturn));
    CHECK(!has_capability(mask, kCapHasReturnAddress));
    CHECK(!has_capability(mask, kCapResultShard));
    CHECK(!has_capability(0, kCapHasSessionId));
    CHECK(!has_capability(kCapNone, kCapDirectReturn));
}

// 3. NodeCapabilities 默认值 + 便捷判定
static void test_node_capabilities_default_and_convenience() {
    std::printf("[test] NodeCapabilities default + convenience...\n");
    NodeCapabilities caps;
    CHECK_EQ(caps.mask, static_cast<std::uint32_t>(kCapNone));
    CHECK_EQ(caps.version, 0);
    CHECK(!caps.probed);
    CHECK(!caps.supports_return_address());
    CHECK(!caps.supports_direct_return());
    CHECK(!caps.supports_result_shard());
    CHECK(!caps.supports_session_id());
    CHECK(!caps.supports_zstd_compression());

    // 设置全能力
    caps.mask = kCapHasReturnAddress | kCapDirectReturn | kCapResultShard |
                kCapHasSessionId | kCapZstdCompressed;
    caps.version = 0x0100;
    caps.probed = true;
    CHECK(caps.supports_return_address());
    CHECK(caps.supports_direct_return());
    CHECK(caps.supports_result_shard());
    CHECK(caps.supports_session_id());
    CHECK(caps.supports_zstd_compression());
}

// 4. NodeCapabilities::to_string
static void test_node_capabilities_to_string() {
    std::printf("[test] NodeCapabilities::to_string...\n");
    NodeCapabilities caps;
    caps.mask = kCapHasSessionId | kCapZstdCompressed;
    caps.version = 0x0100;
    caps.probed = true;
    auto s = caps.to_string();
    CHECK(s.find("SessionId") != std::string::npos);
    CHECK(s.find("Zstd") != std::string::npos);
    CHECK(s.find("mask=0x") != std::string::npos);
    CHECK(s.find("probed=true") != std::string::npos);

    // 未探测
    NodeCapabilities unprobed;
    auto s2 = unprobed.to_string();
    CHECK(s2.find("probed=false") != std::string::npos);
    CHECK(s2.find("legacy") != std::string::npos);
}

// 5. CapabilitiesAckPayload encode 字节布局
static void test_ack_payload_encode_layout() {
    std::printf("[test] CapabilitiesAckPayload encode layout...\n");
    CapabilitiesAckPayload ack;
    ack.supported = true;
    ack.version = 0x0100;
    ack.capabilities_mask = kCapHasSessionId | kCapZstdCompressed;  // 0x0018
    for (int i = 0; i < 32; ++i) ack.peer_endpoint[i] = static_cast<std::uint8_t>(i + 1);

    auto buf = ack.encode();
    CHECK_EQ(buf.size(), CapabilitiesAckPayload::kEncodedSize);  // 40 (v3.9.5: 39→40)
    CHECK_EQ(buf.size(), 40u);

    // offset 0: supported = 0x01
    CHECK_EQ(buf[0], 0x01);

    // offset 1-2: version 大端 0x01 0x00
    CHECK_EQ(buf[1], 0x01);
    CHECK_EQ(buf[2], 0x00);

    // offset 3-6: capabilities_mask 大端 0x00 0x00 0x00 0x18
    CHECK_EQ(buf[3], 0x00);
    CHECK_EQ(buf[4], 0x00);
    CHECK_EQ(buf[5], 0x00);
    CHECK_EQ(buf[6], 0x18);

    // offset 7-38: peer_endpoint 原样
    for (int i = 0; i < 32; ++i) {
        CHECK_EQ(buf[7 + i], static_cast<std::uint8_t>(i + 1));
    }
}

// 6. encode/decode 往返
static void test_ack_payload_decode_roundtrip() {
    std::printf("[test] CapabilitiesAckPayload encode/decode roundtrip...\n");
    CapabilitiesAckPayload ack;
    ack.supported = true;
    ack.version = 0x0100;
    ack.capabilities_mask = kCapHasReturnAddress | kCapDirectReturn |
                            kCapResultShard | kCapHasSessionId | kCapZstdCompressed;
    for (int i = 0; i < 32; ++i) ack.peer_endpoint[i] = static_cast<std::uint8_t>(0xA0 + i);

    auto buf = ack.encode();
    CapabilitiesAckPayload decoded;
    bool ok = CapabilitiesAckPayload::decode(buf, decoded);
    CHECK(ok);
    CHECK(decoded.supported);
    CHECK_EQ(decoded.version, static_cast<std::uint16_t>(0x0100));
    CHECK_EQ(decoded.capabilities_mask, ack.capabilities_mask);
    CHECK(std::memcmp(decoded.peer_endpoint.data(), ack.peer_endpoint.data(), 32) == 0);
}

// 7. decode 长度不足返回 false
static void test_ack_payload_decode_short() {
    std::printf("[test] CapabilitiesAckPayload decode short buffer...\n");
    std::vector<std::uint8_t> short_buf(38, 0x00);  // 38 < 39
    CapabilitiesAckPayload decoded;
    bool ok = CapabilitiesAckPayload::decode(short_buf, decoded);
    CHECK(!ok);

    // 空缓冲
    std::vector<std::uint8_t> empty;
    CHECK(!CapabilitiesAckPayload::decode(empty, decoded));

    // 刚好 40 字节应成功（M5 扩展 node_role 字段后从 39 扩为 40）
    CapabilitiesAckPayload ack;
    ack.supported = false;
    auto buf = ack.encode();
    CHECK_EQ(buf.size(), 40u);
    CHECK(CapabilitiesAckPayload::decode(buf, decoded));
}

// 8. supported=false 降级
static void test_ack_payload_supported_false() {
    std::printf("[test] CapabilitiesAckPayload supported=false degrade...\n");
    CapabilitiesAckPayload ack;
    ack.supported = false;
    ack.version = 0x0100;
    ack.capabilities_mask = kCapNone;  // 0
    ack.peer_endpoint.fill(0);

    auto buf = ack.encode();
    CHECK_EQ(buf[0], 0x00);  // supported=false

    CapabilitiesAckPayload decoded;
    bool ok = CapabilitiesAckPayload::decode(buf, decoded);
    CHECK(ok);
    CHECK(!decoded.supported);
    CHECK_EQ(decoded.capabilities_mask, static_cast<std::uint32_t>(kCapNone));
}

// 9. to_node_capabilities 转换
static void test_ack_payload_to_node_capabilities() {
    std::printf("[test] CapabilitiesAckPayload::to_node_capabilities...\n");
    CapabilitiesAckPayload ack;
    ack.supported = true;
    ack.version = 0x0100;
    ack.capabilities_mask = kCapHasSessionId | kCapZstdCompressed;

    auto caps = ack.to_node_capabilities();
    CHECK(caps.probed);
    CHECK_EQ(caps.mask, ack.capabilities_mask);
    CHECK_EQ(caps.version, ack.version);
    CHECK(caps.supports_session_id());
    CHECK(caps.supports_zstd_compression());
    CHECK(!caps.supports_direct_return());
}

// 10. 全能力 mask 编解码
static void test_ack_payload_all_caps() {
    std::printf("[test] CapabilitiesAckPayload all capabilities...\n");
    CapabilitiesAckPayload ack;
    ack.supported = true;
    ack.version = CapabilitiesAckPayload::kCurrentVersion;
    ack.capabilities_mask = kCapHasReturnAddress | kCapDirectReturn | kCapResultShard |
                            kCapHasSessionId | kCapZstdCompressed;  // 0x001F
    ack.peer_endpoint.fill(0xBB);

    auto buf = ack.encode();
    CHECK_EQ(buf.size(), 40u);

    // offset 3-6: 0x00 0x00 0x00 0x1F
    CHECK_EQ(buf[3], 0x00);
    CHECK_EQ(buf[4], 0x00);
    CHECK_EQ(buf[5], 0x00);
    CHECK_EQ(buf[6], 0x1F);

    CapabilitiesAckPayload decoded;
    CHECK(CapabilitiesAckPayload::decode(buf, decoded));
    auto caps = decoded.to_node_capabilities();
    CHECK(caps.supports_return_address());
    CHECK(caps.supports_direct_return());
    CHECK(caps.supports_result_shard());
    CHECK(caps.supports_session_id());
    CHECK(caps.supports_zstd_compression());
}

// 11. 多能力位组合（部分能力）
static void test_ack_payload_partial_caps() {
    std::printf("[test] CapabilitiesAckPayload partial capabilities...\n");
    // 仅支持 SessionId，不支持压缩（典型旧版本升级到 P4 但未启用 zstd）
    CapabilitiesAckPayload ack;
    ack.supported = true;
    ack.capabilities_mask = kCapHasSessionId;  // 仅 0x0008

    auto buf = ack.encode();
    CapabilitiesAckPayload decoded;
    CHECK(CapabilitiesAckPayload::decode(buf, decoded));
    auto caps = decoded.to_node_capabilities();
    CHECK(caps.supports_session_id());
    CHECK(!caps.supports_zstd_compression());
    CHECK(!caps.supports_direct_return());
}

// 12. MethodId::CapabilitiesProbe/Ack 枚举值校验
static void test_method_id_capabilities_enum() {
    std::printf("[test] MethodId::CapabilitiesProbe/Ack enum...\n");
    CHECK_EQ(static_cast<std::uint16_t>(MethodId::CapabilitiesProbe), 0x0062u);
    CHECK_EQ(static_cast<std::uint16_t>(MethodId::CapabilitiesAck),   0x0063u);
    // 紧接 ReturnAddrAck(0x0061)
    CHECK_EQ(static_cast<std::uint16_t>(MethodId::ReturnAddrAck),    0x0061u);
    CHECK(static_cast<std::uint16_t>(MethodId::CapabilitiesProbe) >
          static_cast<std::uint16_t>(MethodId::ReturnAddrAck));
}

// 13. kCurrentVersion 常量
static void test_current_version_constant() {
    std::printf("[test] kCurrentVersion constant...\n");
    CHECK_EQ(CapabilitiesAckPayload::kCurrentVersion, static_cast<std::uint16_t>(0x0100));
    CHECK_EQ(CapabilitiesAckPayload::kEncodedSize, static_cast<std::size_t>(40));  // v3.9.5: 39→40
}

// 14. peer_endpoint 全零往返（supported=false 时）
static void test_ack_payload_zero_endpoint() {
    std::printf("[test] CapabilitiesAckPayload zero endpoint...\n");
    CapabilitiesAckPayload ack;
    ack.supported = false;
    ack.peer_endpoint.fill(0);
    auto buf = ack.encode();

    CapabilitiesAckPayload decoded;
    CHECK(CapabilitiesAckPayload::decode(buf, decoded));
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (decoded.peer_endpoint[i] != 0) { all_zero = false; break; }
    }
    CHECK(all_zero);
}

// ========== main ==========

int main() {
    std::printf("=== test_capabilities (V3.5 P5-A) ===\n");

    test_capabilities_mask_constants();
    test_has_capability();
    test_node_capabilities_default_and_convenience();
    test_node_capabilities_to_string();
    test_ack_payload_encode_layout();
    test_ack_payload_decode_roundtrip();
    test_ack_payload_decode_short();
    test_ack_payload_supported_false();
    test_ack_payload_to_node_capabilities();
    test_ack_payload_all_caps();
    test_ack_payload_partial_caps();
    test_method_id_capabilities_enum();
    test_current_version_constant();
    test_ack_payload_zero_endpoint();

    std::printf("\n=== test_capabilities: %d pass, %d fail ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
