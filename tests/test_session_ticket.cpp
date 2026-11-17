// test_session_ticket.cpp — P1-4 SessionTicket 加密 + 过期单元测试
//
// 验证 SessionTicket 的核心行为：
//   1. to_bytes/from_bytes 往返一致性
//   2. is_expired 过期检查（created_at=0、正常过期、时钟回退保守处理）
//   3. to_encrypted_bytes/from_encrypted_bytes AEAD 往返
//   4. 错误 key 解密失败
//   5. 篡改密文失败（AEAD 完整性）
//   6. 过期票据 from_bytes/from_encrypted_bytes 返回 nullopt
//   7. check_expiry=false 跳过过期检查
//   8. 错误 version 拒绝
//   9. 错误 key 长度拒绝（非 32 字节）
//  10. 数据太短拒绝
//  11. 移动构造后源对象 master_secret 清零（P1-6 联动）

#include "linoh/endpoint/connection.hpp"
#include "linoh/util/crypto.hpp"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <array>
#include <vector>
#include <chrono>

using namespace linoh::endpoint;
using namespace linoh::base;
using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// 构造一个有效的 SessionTicket 用于测试
static SessionTicket make_test_ticket(std::int64_t created_at = 0,
                                       std::uint32_t max_age = 86400) {
    SessionTicket t;
    // peer_cid: 8 字节
    std::array<std::uint8_t, 8> cid_bytes{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    t.peer_cid = ConnectionId(cid_bytes);
    // peer_node_id: 32 字节
    std::array<std::uint8_t, 32> eid_bytes{};
    for (int i = 0; i < 32; ++i) eid_bytes[i] = static_cast<std::uint8_t>(0xA0 + i);
    t.peer_node_id = EndpointId(eid_bytes);
    // alpn
    t.alpn = "pp-hidden/1";
    // master_secret: 32 字节
    for (int i = 0; i < 32; ++i) t.master_secret[i] = static_cast<std::uint8_t>(0xB0 + i);
    t.max_early_data_bytes = 0x00FFFFFF;
    t.created_at_unix = created_at;
    t.max_age_sec = max_age;
    return t;
}

// 当前 Unix 时间戳（秒）
static std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// 生成 32 字节随机 key
static std::array<std::uint8_t, 32> make_random_key() {
    std::array<std::uint8_t, 32> k{};
    linoh::crypto::crypto_random_bytes(k);
    return k;
}

// ============================================================================
// 1. to_bytes/from_bytes 往返一致性
// ============================================================================
static void test_bytes_roundtrip() {
    std::printf("[test] to_bytes/from_bytes roundtrip...\n");
    auto orig = make_test_ticket(now_unix(), 3600);
    auto bytes = orig.to_bytes();
    CHECK(!bytes.empty());

    auto restored = SessionTicket::from_bytes(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()), false);
    CHECK(restored.has_value());

    // 字段逐一比对
    CHECK(restored->peer_cid == orig.peer_cid);
    CHECK(restored->alpn == orig.alpn);
    CHECK(restored->max_early_data_bytes == orig.max_early_data_bytes);
    CHECK(restored->created_at_unix == orig.created_at_unix);
    CHECK(restored->max_age_sec == orig.max_age_sec);
    CHECK(std::memcmp(restored->master_secret.data(), orig.master_secret.data(), 32) == 0);

    // peer_node_id 比对
    auto orig_span = orig.peer_node_id.as_span();
    auto rest_span = restored->peer_node_id.as_span();
    CHECK(orig_span.size() == 32);
    CHECK(rest_span.size() == 32);
    CHECK(std::memcmp(orig_span.data(), rest_span.data(), 32) == 0);
}

// ============================================================================
// 2. is_expired 过期检查
// ============================================================================
static void test_is_expired_not_set() {
    std::printf("[test] is_expired: created_at=0 means never expires...\n");
    auto t = make_test_ticket(0, 100);
    CHECK(t.is_expired(now_unix() + 1000000) == false);
}

static void test_is_expired_normal() {
    std::printf("[test] is_expired: normal expiry...\n");
    std::int64_t now = now_unix();
    auto t = make_test_ticket(now - 200, 100);  // 200s ago, max_age=100s
    CHECK(t.is_expired(now) == true);

    auto t2 = make_test_ticket(now - 50, 100);  // 50s ago, max_age=100s
    CHECK(t2.is_expired(now) == false);
}

static void test_is_expired_clock_rollback() {
    std::printf("[test] is_expired: clock rollback (now < created_at) means not expired...\n");
    std::int64_t now = now_unix();
    auto t = make_test_ticket(now + 1000, 100);  // created in future (clock rollback)
    CHECK(t.is_expired(now) == false);
}

static void test_is_expired_default_now() {
    std::printf("[test] is_expired: default now_unix (-1) uses system_clock...\n");
    std::int64_t now = now_unix();
    auto t = make_test_ticket(now - 200, 100);  // expired
    CHECK(t.is_expired() == true);  // 默认参数

    auto t2 = make_test_ticket(now, 100);  // not expired
    CHECK(t2.is_expired() == false);
}

// ============================================================================
// 3. to_encrypted_bytes/from_encrypted_bytes AEAD 往返
// ============================================================================
static void test_encrypted_roundtrip() {
    std::printf("[test] to_encrypted_bytes/from_encrypted_bytes roundtrip...\n");
    auto orig = make_test_ticket(now_unix(), 3600);
    auto key = make_random_key();

    auto enc = orig.to_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()));
    CHECK(!enc.empty());

    // 加密结果应包含 nonce(12) + ciphertext + tag(16)
    CHECK(enc.size() >= 12 + 16);

    auto restored = SessionTicket::from_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()),
        std::span<const std::uint8_t>(enc.data(), enc.size()),
        false);
    CHECK(restored.has_value());

    // 字段比对
    CHECK(restored->alpn == orig.alpn);
    CHECK(restored->created_at_unix == orig.created_at_unix);
    CHECK(restored->max_age_sec == orig.max_age_sec);
    CHECK(std::memcmp(restored->master_secret.data(), orig.master_secret.data(), 32) == 0);
}

// ============================================================================
// 4. 错误 key 解密失败
// ============================================================================
static void test_encrypted_wrong_key() {
    std::printf("[test] from_encrypted_bytes with wrong key fails...\n");
    auto orig = make_test_ticket(now_unix(), 3600);
    auto key1 = make_random_key();
    auto key2 = make_random_key();
    // 确保两 key 不同（极端情况下 crypto_random_bytes 可能相同，概率极低）
    if (std::memcmp(key1.data(), key2.data(), 32) == 0) {
        key2[0] ^= 0xFF;
    }

    auto enc = orig.to_encrypted_bytes(
        std::span<const std::uint8_t>(key1.data(), key1.size()));
    CHECK(!enc.empty());

    auto restored = SessionTicket::from_encrypted_bytes(
        std::span<const std::uint8_t>(key2.data(), key2.size()),
        std::span<const std::uint8_t>(enc.data(), enc.size()),
        false);
    CHECK(!restored.has_value());  // 错误 key 解密失败
}

// ============================================================================
// 5. 篡改密文失败（AEAD 完整性）
// ============================================================================
static void test_encrypted_tamper_detected() {
    std::printf("[test] from_encrypted_bytes with tampered ciphertext fails...\n");
    auto orig = make_test_ticket(now_unix(), 3600);
    auto key = make_random_key();

    auto enc = orig.to_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()));
    CHECK(!enc.empty());

    // 篡改密文部分（nonce 之后的某个字节）
    std::vector<std::uint8_t> tampered(enc.begin(), enc.end());
    tampered[20] ^= 0xFF;  // 修改 nonce 之后的一个字节

    auto restored = SessionTicket::from_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()),
        std::span<const std::uint8_t>(tampered.data(), tampered.size()),
        false);
    CHECK(!restored.has_value());  // 篡改后 AEAD 验证失败
}

// ============================================================================
// 6. 过期票据 from_bytes/from_encrypted_bytes 返回 nullopt（check_expiry=true）
// ============================================================================
static void test_expired_ticket_rejected() {
    std::printf("[test] expired ticket rejected by from_bytes/from_encrypted_bytes...\n");
    std::int64_t now = now_unix();
    auto t = make_test_ticket(now - 1000, 100);  // 已过期 900s

    // from_bytes 默认 check_expiry=true
    auto bytes = t.to_bytes();
    CHECK(!bytes.empty());
    auto restored = SessionTicket::from_bytes(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    CHECK(!restored.has_value());

    // from_encrypted_bytes 默认 check_expiry=true
    auto key = make_random_key();
    auto enc = t.to_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()));
    CHECK(!enc.empty());
    auto restored2 = SessionTicket::from_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()),
        std::span<const std::uint8_t>(enc.data(), enc.size()));
    CHECK(!restored2.has_value());
}

// ============================================================================
// 7. check_expiry=false 跳过过期检查
// ============================================================================
static void test_check_expiry_false_skips() {
    std::printf("[test] check_expiry=false skips expiry check...\n");
    std::int64_t now = now_unix();
    auto t = make_test_ticket(now - 1000, 100);  // 已过期

    auto bytes = t.to_bytes();
    auto restored = SessionTicket::from_bytes(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()), false);
    CHECK(restored.has_value());  // check_expiry=false 跳过

    auto key = make_random_key();
    auto enc = t.to_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()));
    auto restored2 = SessionTicket::from_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()),
        std::span<const std::uint8_t>(enc.data(), enc.size()),
        false);
    CHECK(restored2.has_value());
}

// ============================================================================
// 8. 错误 version 拒绝
// ============================================================================
static void test_wrong_version_rejected() {
    std::printf("[test] from_bytes rejects unknown version...\n");
    auto t = make_test_ticket(now_unix(), 3600);
    auto bytes = t.to_bytes();
    CHECK(!bytes.empty());

    // 修改首字节（version）
    std::vector<std::uint8_t> bad(bytes.begin(), bytes.end());
    bad[0] = 0xFF;  // 未知 version

    auto restored = SessionTicket::from_bytes(
        std::span<const std::uint8_t>(bad.data(), bad.size()), false);
    CHECK(!restored.has_value());
}

// ============================================================================
// 9. 错误 key 长度拒绝（非 32 字节）
// ============================================================================
static void test_wrong_key_length_rejected() {
    std::printf("[test] to_encrypted_bytes/from_encrypted_bytes reject wrong key length...\n");
    auto t = make_test_ticket(now_unix(), 3600);

    // 16 字节 key（太短）
    std::array<std::uint8_t, 16> short_key{};
    auto enc_short = t.to_encrypted_bytes(
        std::span<const std::uint8_t>(short_key.data(), short_key.size()));
    CHECK(enc_short.empty());  // 拒绝

    // 64 字节 key（太长）
    std::array<std::uint8_t, 64> long_key{};
    auto enc_long = t.to_encrypted_bytes(
        std::span<const std::uint8_t>(long_key.data(), long_key.size()));
    CHECK(enc_long.empty());  // 拒绝

    // from_encrypted_bytes 也拒绝
    auto key = make_random_key();
    auto enc = t.to_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()));
    CHECK(!enc.empty());
    auto restored = SessionTicket::from_encrypted_bytes(
        std::span<const std::uint8_t>(short_key.data(), short_key.size()),
        std::span<const std::uint8_t>(enc.data(), enc.size()),
        false);
    CHECK(!restored.has_value());
}

// ============================================================================
// 10. 数据太短拒绝
// ============================================================================
static void test_too_short_rejected() {
    std::printf("[test] from_bytes/from_encrypted_bytes reject too-short data...\n");
    // from_bytes: < kTicketMinSize
    std::array<std::uint8_t, 10> tiny{};
    auto r1 = SessionTicket::from_bytes(
        std::span<const std::uint8_t>(tiny.data(), tiny.size()), false);
    CHECK(!r1.has_value());

    // from_encrypted_bytes: < nonce(12) + tag(16) + kTicketMinSize
    std::array<std::uint8_t, 30> tiny2{};
    auto key = make_random_key();
    auto r2 = SessionTicket::from_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()),
        std::span<const std::uint8_t>(tiny2.data(), tiny2.size()),
        false);
    CHECK(!r2.has_value());
}

// ============================================================================
// 11. created_at=0 票据不过期（兼容旧票据场景）
// ============================================================================
static void test_legacy_ticket_never_expires() {
    std::printf("[test] created_at=0 ticket never expires (legacy compat)...\n");
    auto t = make_test_ticket(0, 100);  // created_at=0

    auto bytes = t.to_bytes();
    auto restored = SessionTicket::from_bytes(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()));  // check_expiry=true
    CHECK(restored.has_value());  // 旧票据不判定过期

    auto key = make_random_key();
    auto enc = t.to_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()));
    auto restored2 = SessionTicket::from_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()),
        std::span<const std::uint8_t>(enc.data(), enc.size()));
    CHECK(restored2.has_value());
}

// ============================================================================
// 12. 移动构造后源对象 master_secret 清零（P1-6 联动）
// ============================================================================
static void test_move_clears_source_secret() {
    std::printf("[test] move ctor/assign clears source master_secret...\n");
    auto t1 = make_test_ticket(now_unix(), 3600);
    std::array<std::uint8_t, 32> orig_secret = t1.master_secret;

    SessionTicket t2(std::move(t1));
    // 源对象 master_secret 应被清零
    bool src_cleared = true;
    for (int i = 0; i < 32; ++i) {
        if (t1.master_secret[i] != 0) { src_cleared = false; break; }
    }
    CHECK(src_cleared);
    // 目标对象 master_secret 应等于原始值
    CHECK(std::memcmp(t2.master_secret.data(), orig_secret.data(), 32) == 0);

    // 移动赋值
    auto t3 = make_test_ticket(now_unix(), 3600);
    std::array<std::uint8_t, 32> orig_secret3 = t3.master_secret;
    auto t4 = make_test_ticket(now_unix(), 7200);
    t4 = std::move(t3);
    bool src3_cleared = true;
    for (int i = 0; i < 32; ++i) {
        if (t3.master_secret[i] != 0) { src3_cleared = false; break; }
    }
    CHECK(src3_cleared);
    CHECK(std::memcmp(t4.master_secret.data(), orig_secret3.data(), 32) == 0);
}

// ============================================================================
// 13. 加密结果每次不同（nonce 随机）
// ============================================================================
static void test_encryption_nonce_random() {
    std::printf("[test] to_encrypted_bytes produces different output each call (random nonce)...\n");
    auto t = make_test_ticket(now_unix(), 3600);
    auto key = make_random_key();

    auto enc1 = t.to_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()));
    auto enc2 = t.to_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()));
    CHECK(!enc1.empty());
    CHECK(!enc2.empty());
    // 两次加密结果应不同（nonce 随机）
    CHECK(enc1 != enc2);

    // 但都能正确解密
    auto r1 = SessionTicket::from_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()),
        std::span<const std::uint8_t>(enc1.data(), enc1.size()), false);
    auto r2 = SessionTicket::from_encrypted_bytes(
        std::span<const std::uint8_t>(key.data(), key.size()),
        std::span<const std::uint8_t>(enc2.data(), enc2.size()), false);
    CHECK(r1.has_value());
    CHECK(r2.has_value());
    CHECK(r1->alpn == r2->alpn);
}

// ============================================================================
// 14. 不同 alpn 长度边界测试（空字符串、长字符串）
// ============================================================================
static void test_alpn_boundary() {
    std::printf("[test] alpn boundary (empty and long)...\n");
    // 空 alpn
    auto t1 = make_test_ticket(now_unix(), 3600);
    t1.alpn = "";
    auto b1 = t1.to_bytes();
    CHECK(!b1.empty());
    auto r1 = SessionTicket::from_bytes(
        std::span<const std::uint8_t>(b1.data(), b1.size()), false);
    CHECK(r1.has_value());
    CHECK(r1->alpn.empty());

    // 长 alpn（256 字节）
    auto t2 = make_test_ticket(now_unix(), 3600);
    t2.alpn = std::string(256, 'x');
    auto b2 = t2.to_bytes();
    CHECK(!b2.empty());
    auto r2 = SessionTicket::from_bytes(
        std::span<const std::uint8_t>(b2.data(), b2.size()), false);
    CHECK(r2.has_value());
    CHECK(r2->alpn.size() == 256);
}

// ============================================================================
// 15. 空 peer_cid 边界
// ============================================================================
static void test_empty_peer_cid() {
    std::printf("[test] empty peer_cid boundary...\n");
    auto t = make_test_ticket(now_unix(), 3600);
    t.peer_cid = ConnectionId();  // 默认构造 = 空
    auto bytes = t.to_bytes();
    CHECK(!bytes.empty());
    auto restored = SessionTicket::from_bytes(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()), false);
    CHECK(restored.has_value());
    CHECK(restored->peer_cid.empty());
}

int main() {
    std::printf("=== SessionTicket (P1-4) unit tests ===\n\n");

    test_bytes_roundtrip();
    test_is_expired_not_set();
    test_is_expired_normal();
    test_is_expired_clock_rollback();
    test_is_expired_default_now();
    test_encrypted_roundtrip();
    test_encrypted_wrong_key();
    test_encrypted_tamper_detected();
    test_expired_ticket_rejected();
    test_check_expiry_false_skips();
    test_wrong_version_rejected();
    test_wrong_key_length_rejected();
    test_too_short_rejected();
    test_legacy_ticket_never_expires();
    test_move_clears_source_secret();
    test_encryption_nonce_random();
    test_alpn_boundary();
    test_empty_peer_cid();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
