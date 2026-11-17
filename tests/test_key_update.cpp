// test_key_update.cpp — P1-5 KeyUpdate 机制单元测试
//
// 验证 tls::KeySchedule 的 KeyUpdate 派生 + Connection::rotate_keys 逻辑：
//   1. key_update_secret 派生新 secret（与旧 secret 不同）
//   2. 多次 key_update_secret 链式派生（每次都不同）
//   3. key_update 派生完整 TrafficKeys（key+iv 都更新）
//   4. derive_traffic_keys + key_update 往返：相同 old_secret 派生相同结果（确定性）
//   5. kKeyUpdatePacketThreshold 常量值正确（2^32）
//   6. Connection::rotate_keys 在非 TLS1.3 模式返回 false
//   7. Connection::trigger_key_update 在非 TLS1.3 模式返回 false
//   8. Connection::should_rotate_keys 默认 false
//   9. Connection::key_phase 默认 0
//  10. Connection::packets_sent_since_rotate 默认 0

#include "linoh/tls/key_schedule.hpp"
#include "linoh/endpoint/connection.hpp"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <array>

using namespace linoh::tls;
using namespace linoh::endpoint;
using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// 构造最小可用的 Connection 配置（非 TLS1.3 模式，default mode）
static Connection::Config make_test_cfg() {
    Connection::Config cfg{};
    cfg.alpn = "test/1";
    cfg.local_cid = ConnectionId::generate();
    cfg.remote_cid = ConnectionId::generate();
    return cfg;
}

// ============================================================================
// 1. key_update_secret 派生新 secret（与旧 secret 不同）
// ============================================================================
static void test_key_update_secret_produces_new_secret() {
    std::printf("[test] key_update_secret produces new secret...\n");
    std::array<uint8_t, 32> old_secret{};
    for (int i = 0; i < 32; ++i) old_secret[i] = static_cast<uint8_t>(i);

    auto new_secret = KeySchedule::key_update_secret(old_secret);
    CHECK(std::memcmp(new_secret.data(), old_secret.data(), 32) != 0);
}

// ============================================================================
// 2. 多次 key_update_secret 链式派生（每次都不同）
// ============================================================================
static void test_key_update_secret_chain() {
    std::printf("[test] key_update_secret chain produces distinct secrets...\n");
    std::array<uint8_t, 32> s0{};
    for (int i = 0; i < 32; ++i) s0[i] = static_cast<uint8_t>(0x10 + i);

    auto s1 = KeySchedule::key_update_secret(s0);
    auto s2 = KeySchedule::key_update_secret(s1);
    auto s3 = KeySchedule::key_update_secret(s2);

    // 每代都不同
    CHECK(std::memcmp(s0.data(), s1.data(), 32) != 0);
    CHECK(std::memcmp(s1.data(), s2.data(), 32) != 0);
    CHECK(std::memcmp(s2.data(), s3.data(), 32) != 0);
    CHECK(std::memcmp(s0.data(), s3.data(), 32) != 0);
}

// ============================================================================
// 3. key_update 派生完整 TrafficKeys
// ============================================================================
static void test_key_update_produces_traffic_keys() {
    std::printf("[test] key_update produces complete TrafficKeys...\n");
    std::array<uint8_t, 32> old_secret{};
    for (int i = 0; i < 32; ++i) old_secret[i] = static_cast<uint8_t>(0x20 + i);

    auto old_keys = KeySchedule::derive_traffic_keys(old_secret);
    auto new_keys = KeySchedule::key_update(old_secret);

    // secret 不同
    CHECK(std::memcmp(old_keys.secret.data(), new_keys.secret.data(), 32) != 0);
    // key 不同
    CHECK(std::memcmp(old_keys.key.data(), new_keys.key.data(), 32) != 0);
    // iv 不同
    CHECK(std::memcmp(old_keys.iv.data(), new_keys.iv.data(), 12) != 0);
}

// ============================================================================
// 4. 确定性：相同 old_secret 派生相同结果
// ============================================================================
static void test_key_update_deterministic() {
    std::printf("[test] key_update is deterministic...\n");
    std::array<uint8_t, 32> old_secret{};
    for (int i = 0; i < 32; ++i) old_secret[i] = static_cast<uint8_t>(0x30 + i);

    auto k1 = KeySchedule::key_update(old_secret);
    auto k2 = KeySchedule::key_update(old_secret);

    CHECK(std::memcmp(k1.secret.data(), k2.secret.data(), 32) == 0);
    CHECK(std::memcmp(k1.key.data(), k2.key.data(), 32) == 0);
    CHECK(std::memcmp(k1.iv.data(), k2.iv.data(), 12) == 0);
}

// ============================================================================
// 5. kKeyUpdatePacketThreshold 常量值正确
// ============================================================================
static void test_threshold_constant() {
    std::printf("[test] kKeyUpdatePacketThreshold == 2^32...\n");
    CHECK(KeySchedule::kKeyUpdatePacketThreshold == (1ULL << 32));
    CHECK(KeySchedule::kKeyUpdatePacketThreshold == 4294967296ULL);
}

// ============================================================================
// 6. Connection::rotate_keys 在非 TLS1.3 模式返回 false
// ============================================================================
static void test_rotate_keys_rejects_non_tls13() {
    std::printf("[test] rotate_keys rejects non-TLS1.3 mode...\n");
    auto conn = std::make_shared<Connection>(make_test_cfg());
    // 默认 mode 不是 Tls13，rotate_keys 应失败
    // 注：rotate_keys 是 private，通过 trigger_key_update 间接调用
    bool ok = conn->trigger_key_update();
    CHECK(!ok);
}

// ============================================================================
// 7. Connection::trigger_key_update 在非 TLS1.3 模式返回 false
// ============================================================================
static void test_trigger_key_update_rejects_non_tls13() {
    std::printf("[test] trigger_key_update rejects non-TLS1.3 mode...\n");
    auto conn = std::make_shared<Connection>(make_test_cfg());
    bool ok = conn->trigger_key_update();
    CHECK(!ok);
}

// ============================================================================
// 8. Connection::should_rotate_keys 默认 false
// ============================================================================
static void test_should_rotate_keys_default_false() {
    std::printf("[test] should_rotate_keys default false...\n");
    auto conn = std::make_shared<Connection>(make_test_cfg());
    CHECK(!conn->should_rotate_keys());
}

// ============================================================================
// 9. Connection::key_phase 默认 0
// ============================================================================
static void test_key_phase_default_zero() {
    std::printf("[test] key_phase default 0...\n");
    auto conn = std::make_shared<Connection>(make_test_cfg());
    CHECK(conn->key_phase() == 0);
}

// ============================================================================
// 10. Connection::packets_sent_since_rotate 默认 0
// ============================================================================
static void test_packets_sent_since_rotate_default_zero() {
    std::printf("[test] packets_sent_since_rotate default 0...\n");
    auto conn = std::make_shared<Connection>(make_test_cfg());
    CHECK(conn->packets_sent_since_rotate() == 0);
}

// ============================================================================
// 11. KeySchedule 完整流程：init_early → set_handshake → set_master → key_update
// ============================================================================
static void test_full_key_schedule_with_update() {
    std::printf("[test] full key schedule + key_update integration...\n");
    KeySchedule ks;
    ks.init_early();  // 空 PSK

    // 模拟 ECDHE 共享密钥
    std::array<uint8_t, 32> ecdhe{};
    for (int i = 0; i < 32; ++i) ecdhe[i] = static_cast<uint8_t>(0x40 + i);

    Transcript th;
    th.add(std::vector<uint8_t>{0x01, 0x02, 0x03});  // 模拟握手消息
    ks.set_handshake(ecdhe, th);
    ks.set_master(th);

    // 应用密钥应已就绪
    auto old_client_secret = ks.client_application.secret;
    auto old_server_secret = ks.server_application.secret;

    // 触发 KeyUpdate
    ks.update_client_application_keys();
    ks.update_server_application_keys();

    // 新密钥应不同
    CHECK(std::memcmp(old_client_secret.data(),
                      ks.client_application.secret.data(), 32) != 0);
    CHECK(std::memcmp(old_server_secret.data(),
                      ks.server_application.secret.data(), 32) != 0);

    // 二次 KeyUpdate 应再不同
    auto mid_client = ks.client_application.secret;
    ks.update_client_application_keys();
    CHECK(std::memcmp(mid_client.data(),
                      ks.client_application.secret.data(), 32) != 0);
}

// ============================================================================
// 12. key_update_secret 与 hkdf_expand_label("quic ku") 一致
// ============================================================================
static void test_key_update_label_correct() {
    std::printf("[test] key_update_secret uses 'quic ku' label...\n");
    std::array<uint8_t, 32> old_secret{};
    for (int i = 0; i < 32; ++i) old_secret[i] = static_cast<uint8_t>(0x50 + i);

    // 通过 key_update_secret
    auto new_secret = KeySchedule::key_update_secret(old_secret);

    // 通过 hkdf_expand_label 直接派生
    auto direct = linoh::crypto::hkdf_expand_label(
        std::span<const uint8_t>(old_secret.data(), old_secret.size()),
        "quic ku", std::span<const uint8_t>{}, 32);

    CHECK(std::memcmp(new_secret.data(), direct.data(), 32) == 0);
}

int main() {
    std::printf("=== KeyUpdate (P1-5) unit tests ===\n\n");

    test_key_update_secret_produces_new_secret();
    test_key_update_secret_chain();
    test_key_update_produces_traffic_keys();
    test_key_update_deterministic();
    test_threshold_constant();
    test_rotate_keys_rejects_non_tls13();
    test_trigger_key_update_rejects_non_tls13();
    test_should_rotate_keys_default_false();
    test_key_phase_default_zero();
    test_packets_sent_since_rotate_default_zero();
    test_full_key_schedule_with_update();
    test_key_update_label_correct();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
