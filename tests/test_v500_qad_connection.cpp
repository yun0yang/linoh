// test_v500_qad_connection.cpp — v5.0.0 T-LP4-008 QAD Connection 级测试
//
// 验证内容：
//   - Connection::Config.qad_enabled / qad_stun_fallback 配置
//   - Connection::handle_address_discovery_frame（服务端反射）
//   - Connection::handle_address_discovery_response_frame（客户端回调）
//   - Connection::send_address_discovery_request（客户端请求）
//   - Connection::send_address_discovery_response（服务端响应）
//   - QAD 禁用时所有方法返回 false
//   - set_last_peer_addr + 回调机制
//
// 借鉴 iroh QAD（Moving from STUN to QUIC Address Discovery）

#include "linoh/endpoint/connection.hpp"
#include "linoh/protocol/capabilities.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/util/varint.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

using namespace linoh::endpoint;
using namespace linoh::protocol;
using linoh::base::EndpointId;
using linoh::base::PublicKey;
using linoh::base::SecretKey;
using linoh::util::varint_encode_vec;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// 创建测试用 Connection（绕过握手，直接测帧处理逻辑）
// 注意：Connection 构造需要有效的 Config，此处用最小配置
static std::unique_ptr<Connection> make_test_connection(bool qad_enabled) {
    Connection::Config cfg;
    cfg.qad_enabled = qad_enabled;
    cfg.qad_stun_fallback = true;
    // 填充必要字段（避免构造失败）
    cfg.alpn = "test";
    std::array<std::uint8_t, 4> local_cid_bytes{1, 2, 3, 4};
    std::array<std::uint8_t, 4> remote_cid_bytes{5, 6, 7, 8};
    cfg.local_cid = ConnectionId{
        std::span<const std::uint8_t>{local_cid_bytes.data(), local_cid_bytes.size()}};
    cfg.remote_cid = ConnectionId{
        std::span<const std::uint8_t>{remote_cid_bytes.data(), remote_cid_bytes.size()}};
    cfg.direction = Direction::Outbound;

    // 生成临时密钥对
    std::array<std::uint8_t, SecretKey::kSize> sk_bytes{};
    sk_bytes.fill(0x42);
    cfg.secret_key = SecretKey::from_bytes(
        std::span<const std::uint8_t>{sk_bytes.data(), sk_bytes.size()});

    return std::make_unique<Connection>(std::move(cfg));
}

// ============================================================================
// 配置测试
// ============================================================================

static void test_config_defaults() {
    std::printf("[test] T-LP4-008: QAD config defaults...\n");

    Connection::Config cfg;
    CHECK(cfg.qad_enabled == false);        // 默认禁用（回滚安全）
    CHECK(cfg.qad_stun_fallback == true);  // 默认允许 STUN fallback
}

static void test_is_qad_enabled() {
    std::printf("[test] T-LP4-008: is_qad_enabled / qad_stun_fallback_enabled...\n");

    auto conn_disabled = make_test_connection(false);
    CHECK(!conn_disabled->is_qad_enabled());
    CHECK(conn_disabled->qad_stun_fallback_enabled());

    auto conn_enabled = make_test_connection(true);
    CHECK(conn_enabled->is_qad_enabled());
    CHECK(conn_enabled->qad_stun_fallback_enabled());
}

// ============================================================================
// QAD 禁用时拒绝处理
// ============================================================================

static void test_qad_disabled_rejects_frames() {
    std::printf("[test] T-LP4-008: QAD disabled rejects ADDRESS_DISCOVERY frame...\n");

    auto conn = make_test_connection(false);

    // 构造合法的 ADDRESS_DISCOVERY 帧载荷
    AddressDiscoveryFrame req;
    req.nonce = {0x01, 0x02, 0x03};
    auto encoded = encode_address_discovery_frame(req);
    CHECK(!encoded.empty());

    // QAD 禁用时应返回 false
    auto data_span = std::span<const std::uint8_t>(encoded.data(), encoded.size());
    CHECK(!conn->handle_address_discovery_frame(data_span));
}

static void test_qad_disabled_rejects_response() {
    std::printf("[test] T-LP4-008: QAD disabled rejects ADDRESS_DISCOVERY_RESPONSE...\n");

    auto conn = make_test_connection(false);

    AddressDiscoveryResponseFrame resp;
    resp.nonce = {0x01};
    resp.observed_host = "203.0.113.42";
    resp.observed_port = 12345;
    auto encoded = encode_address_discovery_response_frame(resp);
    CHECK(!encoded.empty());

    auto data_span = std::span<const std::uint8_t>(encoded.data(), encoded.size());
    CHECK(!conn->handle_address_discovery_response_frame(data_span));
}

static void test_qad_disabled_skips_send_request() {
    std::printf("[test] T-LP4-008: QAD disabled skips send_address_discovery_request...\n");

    auto conn = make_test_connection(false);
    CHECK(!conn->send_address_discovery_request());
}

// ============================================================================
// QAD 启用时处理帧
// ============================================================================

static void test_qad_enabled_handles_response_with_callback() {
    std::printf("[test] T-LP4-008: QAD response triggers callback...\n");

    auto conn = make_test_connection(true);

    // 设置回调
    std::atomic<bool> callback_called{false};
    std::string cb_host;
    std::uint16_t cb_port = 0;
    conn->set_qad_address_callback([&](std::string host, std::uint16_t port) {
        cb_host = host;
        cb_port = port;
        callback_called.store(true);
    });

    // 构造 RESPONSE 帧
    AddressDiscoveryResponseFrame resp;
    resp.nonce = {0xAA, 0xBB};
    resp.observed_host = "203.0.113.99";
    resp.observed_port = 54321;
    auto encoded = encode_address_discovery_response_frame(resp);
    CHECK(!encoded.empty());

    auto data_span = std::span<const std::uint8_t>(encoded.data(), encoded.size());
    CHECK(conn->handle_address_discovery_response_frame(data_span));
    CHECK(callback_called.load());
    CHECK(cb_host == "203.0.113.99");
    CHECK(cb_port == 54321);
}

static void test_qad_enabled_handles_response_no_callback() {
    std::printf("[test] T-LP4-008: QAD response without callback (no crash)...\n");

    auto conn = make_test_connection(true);
    // 不设置回调

    AddressDiscoveryResponseFrame resp;
    resp.nonce = {0x00};
    resp.observed_host = "198.51.100.1";
    resp.observed_port = 8080;
    auto encoded = encode_address_discovery_response_frame(resp);

    auto data_span = std::span<const std::uint8_t>(encoded.data(), encoded.size());
    // 应正常处理（不崩溃），返回 true
    CHECK(conn->handle_address_discovery_response_frame(data_span));
}

static void test_qad_enabled_rejects_invalid_response() {
    std::printf("[test] T-LP4-008: QAD rejects invalid RESPONSE payload...\n");

    auto conn = make_test_connection(true);

    // 空数据
    CHECK(!conn->handle_address_discovery_response_frame({}));

    // 截断数据（只有 nonce，缺 host/port）
    std::vector<std::uint8_t> truncated;
    auto nl = varint_encode_vec(2);
    truncated.insert(truncated.end(), nl.begin(), nl.end());
    truncated.push_back(0xAA);
    truncated.push_back(0xBB);
    auto data_span = std::span<const std::uint8_t>(truncated.data(), truncated.size());
    CHECK(!conn->handle_address_discovery_response_frame(data_span));
}

// ============================================================================
// set_last_peer_addr 测试
// ============================================================================

static void test_set_last_peer_addr() {
    std::printf("[test] T-LP4-008: set_last_peer_addr (QAD server reflection)...\n");

    auto conn = make_test_connection(true);

    // 注入对端地址
    conn->set_last_peer_addr("203.0.113.50", 9876);

    // 构造 ADDRESS_DISCOVERY 请求
    AddressDiscoveryFrame req;
    req.nonce = {0x01, 0x02, 0x03, 0x04};
    auto encoded = encode_address_discovery_frame(req);
    CHECK(!encoded.empty());

    // 服务端处理请求 → 应自动回送 RESPONSE（返回 true）
    auto data_span = std::span<const std::uint8_t>(encoded.data(), encoded.size());
    CHECK(conn->handle_address_discovery_frame(data_span));
}

static void test_qad_server_no_peer_addr() {
    std::printf("[test] T-LP4-008: QAD server without peer addr returns false...\n");

    auto conn = make_test_connection(true);
    // 不调用 set_last_peer_addr — peer 地址未知

    AddressDiscoveryFrame req;
    req.nonce = {0x01};
    auto encoded = encode_address_discovery_frame(req);

    auto data_span = std::span<const std::uint8_t>(encoded.data(), encoded.size());
    // 无 peer 地址，应返回 false（无法反射）
    CHECK(!conn->handle_address_discovery_frame(data_span));
}

// ============================================================================
// 客户端发送请求测试
// ============================================================================

static void test_qad_client_send_request() {
    std::printf("[test] T-LP4-008: QAD client send_address_discovery_request...\n");

    auto conn = make_test_connection(true);
    // QAD 启用时应返回 true（请求已编码，实际发送由后续集成完成）
    CHECK(conn->send_address_discovery_request());
}

// ============================================================================
// CapabilitiesMask v5.0.0 能力位测试（T-LP4-007）
// ============================================================================

static void test_v500_capabilities_mask() {
    std::printf("[test] T-LP4-007: v5.0.0 CapabilitiesMask bits...\n");

    // 单独位
    CHECK(has_capability(kCapZeroRtt, kCapZeroRtt));
    CHECK(has_capability(kCapQad, kCapQad));
    CHECK(has_capability(kCapHardNat, kCapHardNat));

    // 组合位
    std::uint32_t mask = kCapZeroRtt | kCapQad | kCapHardNat;
    CHECK(has_capability(mask, kCapZeroRtt));
    CHECK(has_capability(mask, kCapQad));
    CHECK(has_capability(mask, kCapHardNat));
    CHECK(!has_capability(mask, kCapZstdCompressed));

    // 旧节点不设置新位
    std::uint32_t legacy_mask = kCapHasReturnAddress | kCapDirectReturn;
    CHECK(!has_capability(legacy_mask, kCapZeroRtt));
    CHECK(!has_capability(legacy_mask, kCapQad));
    CHECK(!has_capability(legacy_mask, kCapHardNat));
}

static void test_v500_node_capabilities_helpers() {
    std::printf("[test] T-LP4-007: NodeCapabilities v5.0.0 helpers...\n");

    NodeCapabilities caps;
    caps.mask = kCapZeroRtt | kCapQad;
    caps.probed = true;

    CHECK(caps.supports_zero_rtt());
    CHECK(caps.supports_qad());
    CHECK(!caps.supports_hard_nat());

    // 旧节点（无新能力位）
    NodeCapabilities legacy;
    legacy.mask = kCapZstdCompressed;
    legacy.probed = true;
    CHECK(!legacy.supports_zero_rtt());
    CHECK(!legacy.supports_qad());
    CHECK(!legacy.supports_hard_nat());
}

static void test_v500_capabilities_to_string() {
    std::printf("[test] T-LP4-007: NodeCapabilities::to_string includes v5.0.0 caps...\n");

    NodeCapabilities caps;
    caps.mask = kCapZeroRtt | kCapQad | kCapHardNat | kCapZstdCompressed;
    caps.probed = true;

    auto s = caps.to_string();
    CHECK(s.find("0RTT") != std::string::npos);
    CHECK(s.find("QAD") != std::string::npos);
    CHECK(s.find("HardNAT") != std::string::npos);
    CHECK(s.find("Zstd") != std::string::npos);
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== v5.0.0 T-LP4-008 QAD Connection + T-LP4-007 Capabilities Tests ===\n\n");

    test_config_defaults();
    test_is_qad_enabled();

    test_qad_disabled_rejects_frames();
    test_qad_disabled_rejects_response();
    test_qad_disabled_skips_send_request();

    test_qad_enabled_handles_response_with_callback();
    test_qad_enabled_handles_response_no_callback();
    test_qad_enabled_rejects_invalid_response();

    test_set_last_peer_addr();
    test_qad_server_no_peer_addr();

    test_qad_client_send_request();

    test_v500_capabilities_mask();
    test_v500_node_capabilities_helpers();
    test_v500_capabilities_to_string();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
