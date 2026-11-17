// =============================================================================
// test_role_alpn.cpp — v3.9.5 角色 ALPN 子集单元测试（M5）
//
// 覆盖场景：
//   1. NodeRole 枚举完整性 + role_name 转字符串
//   2. role_from_uint 安全转换（合法值 + 未知值回退 Unknown）
//   3. role_default_alpns 各角色返回正确 ALPN 子集
//   4. is_role_authorized 授权判定（Master 拒绝 pp-img/1，Worker 通过 pp-llm/1）
//   5. Unknown 角色支持所有 ALPN（向后兼容）
//   6. Relay/Observer 仅支持 ctrl/1
//   7. TempWorker 同 Worker 权限
//   8. CapabilitiesAckPayload 含 node_role 编解码 roundtrip
//   9. 旧节点 39 字节兼容解码（node_role=Unknown）
//  10. node_role 各值（0-5）编解码
// =============================================================================

#include "linoh/multimodal/channel.hpp"
#include "linoh/protocol/capabilities.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>

using namespace linoh::multimodal;
using namespace linoh::protocol;

// 简单断言宏（与现有测试风格一致）
#define CHECK(cond) do { if (!(cond)) { std::fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); std::exit(1); } } while(0)
#define CHECK_EQ(a, b) do { if (!((a) == (b))) { std::fprintf(stderr, "FAIL: %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b); std::exit(1); } } while(0)

static int g_pass_count = 0;

#define PASS() ++g_pass_count

// =============================================================================
// 1. NodeRole 枚举完整性 + role_name 转字符串
// =============================================================================
static void test_role_name() {
    std::printf("[test] NodeRole enum + role_name...\n");

    CHECK_EQ(role_name(NodeRole::Unknown),    "unknown");
    CHECK_EQ(role_name(NodeRole::Master),     "master");
    CHECK_EQ(role_name(NodeRole::Worker),     "worker");
    CHECK_EQ(role_name(NodeRole::TempWorker), "temp_worker");
    CHECK_EQ(role_name(NodeRole::Relay),      "relay");
    CHECK_EQ(role_name(NodeRole::Observer),   "observer");

    PASS();
}

// =============================================================================
// 2. role_from_uint 安全转换
// =============================================================================
static void test_role_from_uint() {
    std::printf("[test] role_from_uint safe conversion...\n");

    CHECK_EQ(role_from_uint(0), NodeRole::Unknown);
    CHECK_EQ(role_from_uint(1), NodeRole::Master);
    CHECK_EQ(role_from_uint(2), NodeRole::Worker);
    CHECK_EQ(role_from_uint(3), NodeRole::TempWorker);
    CHECK_EQ(role_from_uint(4), NodeRole::Relay);
    CHECK_EQ(role_from_uint(5), NodeRole::Observer);
    // 未知值回退 Unknown
    CHECK_EQ(role_from_uint(6),  NodeRole::Unknown);
    CHECK_EQ(role_from_uint(255), NodeRole::Unknown);

    PASS();
}

// =============================================================================
// 3. role_default_alpns 各角色返回正确 ALPN 子集
// =============================================================================
static void test_role_default_alpns() {
    std::printf("[test] role_default_alpns subsets...\n");

    // Master: ctrl/1 + pp-llm/1（2 个）
    {
        auto alpns = role_default_alpns(NodeRole::Master);
        CHECK_EQ(alpns.size(), static_cast<std::size_t>(2));
        CHECK(alpns[0] == "ctrl/1");
        CHECK(alpns[1] == "pp-llm/1");
    }

    // Worker: ctrl/1 + pp-llm/1 + pp-img/1 + pp-video/1 + pp-audio/1 + pp-multi/1（6 个）
    {
        auto alpns = role_default_alpns(NodeRole::Worker);
        CHECK_EQ(alpns.size(), static_cast<std::size_t>(6));
        CHECK(alpns[0] == "ctrl/1");
        CHECK(alpns[1] == "pp-llm/1");
        CHECK(alpns[2] == "pp-img/1");
        CHECK(alpns[3] == "pp-video/1");
        CHECK(alpns[4] == "pp-audio/1");
        CHECK(alpns[5] == "pp-multi/1");
    }

    // TempWorker: 同 Worker（6 个）
    {
        auto alpns = role_default_alpns(NodeRole::TempWorker);
        CHECK_EQ(alpns.size(), static_cast<std::size_t>(6));
        CHECK(alpns[0] == "ctrl/1");
        CHECK(alpns[5] == "pp-multi/1");
    }

    // Relay: 仅 ctrl/1（1 个）
    {
        auto alpns = role_default_alpns(NodeRole::Relay);
        CHECK_EQ(alpns.size(), static_cast<std::size_t>(1));
        CHECK(alpns[0] == "ctrl/1");
    }

    // Observer: 仅 ctrl/1（1 个）
    {
        auto alpns = role_default_alpns(NodeRole::Observer);
        CHECK_EQ(alpns.size(), static_cast<std::size_t>(1));
        CHECK(alpns[0] == "ctrl/1");
    }

    // Unknown: 所有 ALPN（default_all_alpns，9 个）
    {
        auto alpns = role_default_alpns(NodeRole::Unknown);
        CHECK_EQ(alpns.size(), default_all_alpns().size());  // 9
    }

    PASS();
}

// =============================================================================
// 4. is_role_authorized 授权判定
// =============================================================================
static void test_is_role_authorized() {
    std::printf("[test] is_role_authorized...\n");

    // Master: ctrl/1 通过, pp-llm/1 通过, pp-img/1 拒绝, pp-video/1 拒绝
    CHECK(is_role_authorized(NodeRole::Master, "ctrl/1"));
    CHECK(is_role_authorized(NodeRole::Master, "pp-llm/1"));
    CHECK(!is_role_authorized(NodeRole::Master, "pp-img/1"));
    CHECK(!is_role_authorized(NodeRole::Master, "pp-video/1"));
    CHECK(!is_role_authorized(NodeRole::Master, "pp-audio/1"));
    CHECK(!is_role_authorized(NodeRole::Master, "pp-multi/1"));

    // Worker: 全部通过
    CHECK(is_role_authorized(NodeRole::Worker, "ctrl/1"));
    CHECK(is_role_authorized(NodeRole::Worker, "pp-llm/1"));
    CHECK(is_role_authorized(NodeRole::Worker, "pp-img/1"));
    CHECK(is_role_authorized(NodeRole::Worker, "pp-video/1"));
    CHECK(is_role_authorized(NodeRole::Worker, "pp-audio/1"));
    CHECK(is_role_authorized(NodeRole::Worker, "pp-multi/1"));

    // Relay: ctrl/1 通过, pp-llm/1 拒绝
    CHECK(is_role_authorized(NodeRole::Relay, "ctrl/1"));
    CHECK(!is_role_authorized(NodeRole::Relay, "pp-llm/1"));
    CHECK(!is_role_authorized(NodeRole::Relay, "pp-img/1"));

    // Observer: 同 Relay
    CHECK(is_role_authorized(NodeRole::Observer, "ctrl/1"));
    CHECK(!is_role_authorized(NodeRole::Observer, "pp-llm/1"));

    // TempWorker: 同 Worker
    CHECK(is_role_authorized(NodeRole::TempWorker, "pp-img/1"));
    CHECK(is_role_authorized(NodeRole::TempWorker, "pp-video/1"));

    PASS();
}

// =============================================================================
// 5. Unknown 角色支持所有 ALPN（向后兼容）
// =============================================================================
static void test_unknown_role_backward_compat() {
    std::printf("[test] Unknown role backward compat...\n");

    // Unknown 对所有已知 ALPN 都返回 true
    CHECK(is_role_authorized(NodeRole::Unknown, "ctrl/1"));
    CHECK(is_role_authorized(NodeRole::Unknown, "pp-llm/1"));
    CHECK(is_role_authorized(NodeRole::Unknown, "pp-img/1"));
    CHECK(is_role_authorized(NodeRole::Unknown, "pp-video/1"));
    CHECK(is_role_authorized(NodeRole::Unknown, "pp-audio/1"));
    CHECK(is_role_authorized(NodeRole::Unknown, "pp-multi/1"));
    CHECK(is_role_authorized(NodeRole::Unknown, "ep-dispatch/1"));
    CHECK(is_role_authorized(NodeRole::Unknown, "ep-combine/1"));
    CHECK(is_role_authorized(NodeRole::Unknown, "ep-sync/1"));

    // 甚至未知 ALPN 也通过（Unknown 不做限制）
    CHECK(is_role_authorized(NodeRole::Unknown, "unknown-alpn/1"));

    PASS();
}

// =============================================================================
// 6. CapabilitiesAckPayload 含 node_role 编解码 roundtrip
// =============================================================================
static void test_ack_payload_node_role_roundtrip() {
    std::printf("[test] CapabilitiesAckPayload node_role roundtrip...\n");

    // 设置 node_role = Master (1)
    {
        CapabilitiesAckPayload ack;
        ack.supported = true;
        ack.version = 0x0100;
        ack.capabilities_mask = kCapHasSessionId;
        for (int i = 0; i < 32; ++i) ack.peer_endpoint[i] = static_cast<std::uint8_t>(0x40 + i);
        ack.node_role = static_cast<std::uint8_t>(NodeRole::Master);  // 1

        auto buf = ack.encode();
        CHECK_EQ(buf.size(), CapabilitiesAckPayload::kEncodedSize);  // 40
        CHECK_EQ(buf[39], static_cast<std::uint8_t>(1));  // node_role at offset 39

        CapabilitiesAckPayload decoded;
        CHECK(CapabilitiesAckPayload::decode(buf, decoded));
        CHECK_EQ(decoded.node_role, static_cast<std::uint8_t>(1));
        CHECK_EQ(role_from_uint(decoded.node_role), NodeRole::Master);
    }

    // 设置 node_role = Worker (2)
    {
        CapabilitiesAckPayload ack;
        ack.supported = true;
        ack.node_role = static_cast<std::uint8_t>(NodeRole::Worker);  // 2

        auto buf = ack.encode();
        CHECK_EQ(buf[39], static_cast<std::uint8_t>(2));

        CapabilitiesAckPayload decoded;
        CHECK(CapabilitiesAckPayload::decode(buf, decoded));
        CHECK_EQ(decoded.node_role, static_cast<std::uint8_t>(2));
        CHECK_EQ(role_from_uint(decoded.node_role), NodeRole::Worker);
    }

    // 默认 node_role = 0 (Unknown)
    {
        CapabilitiesAckPayload ack;  // 默认构造
        CHECK_EQ(ack.node_role, static_cast<std::uint8_t>(0));

        auto buf = ack.encode();
        CHECK_EQ(buf[39], static_cast<std::uint8_t>(0));

        CapabilitiesAckPayload decoded;
        CHECK(CapabilitiesAckPayload::decode(buf, decoded));
        CHECK_EQ(decoded.node_role, static_cast<std::uint8_t>(0));
        CHECK_EQ(role_from_uint(decoded.node_role), NodeRole::Unknown);
    }

    PASS();
}

// =============================================================================
// 7. 旧节点 39 字节兼容解码（node_role=Unknown）
// =============================================================================
static void test_legacy_39byte_compat() {
    std::printf("[test] legacy 39-byte compat decode...\n");

    // 手动构造 39 字节旧格式（无 node_role）
    std::vector<std::uint8_t> legacy(39, 0);
    legacy[0] = 0x01;  // supported = true
    legacy[1] = 0x01;  // version 大端高字节
    legacy[2] = 0x00;  // version 大端低字节
    legacy[3] = 0x00;  // mask 字节
    legacy[4] = 0x00;
    legacy[5] = 0x00;
    legacy[6] = 0x18;  // mask = 0x0018
    for (int i = 0; i < 32; ++i) legacy[7 + i] = static_cast<std::uint8_t>(i + 1);

    // 39 字节 < kEncodedSize(40)，但 >= kLegacyEncodedSize(39)，应该解码成功
    CHECK_EQ(legacy.size(), CapabilitiesAckPayload::kLegacyEncodedSize);

    CapabilitiesAckPayload decoded;
    CHECK(CapabilitiesAckPayload::decode(legacy, decoded));

    // 验证基本字段
    CHECK(decoded.supported);
    CHECK_EQ(decoded.version, static_cast<std::uint16_t>(0x0100));
    CHECK_EQ(decoded.capabilities_mask, static_cast<std::uint32_t>(0x0018));
    CHECK_EQ(decoded.peer_endpoint[0], static_cast<std::uint8_t>(1));
    CHECK_EQ(decoded.peer_endpoint[31], static_cast<std::uint8_t>(32));

    // node_role 应该默认 0 (Unknown) — 旧节点无此字段
    CHECK_EQ(decoded.node_role, static_cast<std::uint8_t>(0));
    CHECK_EQ(role_from_uint(decoded.node_role), NodeRole::Unknown);

    PASS();
}

// =============================================================================
// 8. 过短数据拒绝解码
// =============================================================================
static void test_too_short_rejected() {
    std::printf("[test] too short data rejected...\n");

    // 38 字节 < kLegacyEncodedSize(39)，应该解码失败
    std::vector<std::uint8_t> too_short(38, 0);
    CapabilitiesAckPayload decoded;
    CHECK(!CapabilitiesAckPayload::decode(too_short, decoded));

    // 0 字节也拒绝
    std::vector<std::uint8_t> empty;
    CHECK(!CapabilitiesAckPayload::decode(empty, decoded));

    PASS();
}

// =============================================================================
// 9. node_role 各值（0-5）编解码
// =============================================================================
static void test_all_role_values() {
    std::printf("[test] all node_role values (0-5)...\n");

    for (std::uint8_t r = 0; r <= 5; ++r) {
        CapabilitiesAckPayload ack;
        ack.supported = true;
        ack.node_role = r;

        auto buf = ack.encode();
        CHECK_EQ(buf[39], r);

        CapabilitiesAckPayload decoded;
        CHECK(CapabilitiesAckPayload::decode(buf, decoded));
        CHECK_EQ(decoded.node_role, r);
        CHECK_EQ(role_from_uint(decoded.node_role), role_from_uint(r));
    }

    PASS();
}

// =============================================================================
// 10. kLegacyEncodedSize 常量正确
// =============================================================================
static void test_legacy_encoded_size_constant() {
    std::printf("[test] kLegacyEncodedSize constant...\n");

    CHECK_EQ(CapabilitiesAckPayload::kLegacyEncodedSize, static_cast<std::size_t>(39));
    CHECK_EQ(CapabilitiesAckPayload::kEncodedSize, static_cast<std::size_t>(40));
    CHECK(CapabilitiesAckPayload::kEncodedSize > CapabilitiesAckPayload::kLegacyEncodedSize);

    PASS();
}

// =============================================================================
// main
// =============================================================================
int main() {
    std::printf("=== test_role_alpn (v3.9.5 角色 ALPN 子集) ===\n");

    test_role_name();
    test_role_from_uint();
    test_role_default_alpns();
    test_is_role_authorized();
    test_unknown_role_backward_compat();
    test_ack_payload_node_role_roundtrip();
    test_legacy_39byte_compat();
    test_too_short_rejected();
    test_all_role_values();
    test_legacy_encoded_size_constant();

    std::printf("\n=== Result: %d tests passed ===\n", g_pass_count);
    return 0;
}
