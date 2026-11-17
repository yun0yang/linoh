// 0-RTT 和 C-API 集成测试
#include "linoh/linoh_c.h"
#include "linoh/endpoint/connection.hpp"
#include "linoh/util/logging.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace linoh;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) \
    do { \
        if (cond) { printf("  [PASS] %s\n", msg); g_pass++; } \
        else { printf("  [FAIL] %s\n", msg); g_fail++; } \
    } while (0)

// ============================================================================
// Test 1: HMAC-SHA256 (C-API)
// ============================================================================
void test_hmac() {
    printf("\n=== Test 1: HMAC-SHA256 C-API ===\n");
    const uint8_t key[] = "test_key_for_hmac_sha256!!";
    const char *msg = "hello linoh 0-rtt";
    linoh_hmac_t out1, out2;
    linoh_error_t err;

    err = linoh_hmac_sha256(key, sizeof(key),
                             (const uint8_t*)msg, strlen(msg), &out1);
    CHECK(err == LINOH_OK, "HMAC 返回 LINOH_OK");

    // 相同输入应该得到相同输出
    err = linoh_hmac_sha256(key, sizeof(key),
                             (const uint8_t*)msg, strlen(msg), &out2);
    int equal = (memcmp(out1.bytes, out2.bytes, 32) == 0);
    CHECK(equal != 0, "相同输入产生相同 HMAC");

    // 不同 key 应该产生不同输出
    const uint8_t key2[] = "different_key_xxxxxxxxxxxx";
    linoh_hmac_t out3;
    linoh_hmac_sha256(key2, sizeof(key2),
                      (const uint8_t*)msg, strlen(msg), &out3);
    int diff = (memcmp(out1.bytes, out3.bytes, 32) != 0);
    CHECK(diff != 0, "不同 key 产生不同 HMAC");

    // NULL 检查
    err = linoh_hmac_sha256(nullptr, 0, (const uint8_t*)msg, strlen(msg), &out1);
    CHECK(err == LINOH_ERR_PARAM, "NULL key 返回 LINOH_ERR_PARAM");
}

// ============================================================================
// Test 2: AEAD seal/open (C-API)
// ============================================================================
void test_aead() {
    printf("\n=== Test 2: AEAD C-API ===\n");
    linoh_aead_key_t key;
    memset(key.bytes, 0xAB, sizeof(key.bytes));
    uint8_t nonce[LINOH_AEAD_NONCE_SIZE] = {0};
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)i;
    const char *ad = "assoc data";
    const char *plain = "hello 0-rtt world 123456";
    size_t plain_len = strlen(plain);

    uint8_t cipher[256];
    size_t ct_len = linoh_aead_seal(&key, nonce,
                                     (const uint8_t*)ad, strlen(ad),
                                     (const uint8_t*)plain, plain_len,
                                     cipher, sizeof(cipher));
    CHECK(ct_len > 0, "seal() 返回非零长度");
    CHECK(ct_len >= plain_len + LINOH_AEAD_TAG_SIZE,
          "ciphertext 长度 >= plain + tag");

    // 解密
    uint8_t dec[256];
    size_t dec_len = linoh_aead_open(&key, nonce,
                                     (const uint8_t*)ad, strlen(ad),
                                     cipher, ct_len,
                                     dec, sizeof(dec));
    CHECK(dec_len == plain_len, "decrypt 返回正确 plaintext 长度");
    CHECK(memcmp(dec, plain, plain_len) == 0, "decrypt 还原明文");

    // 篡改密文应该失败
    cipher[0] ^= 0xFF;
    size_t bad_dec = linoh_aead_open(&key, nonce,
                                     (const uint8_t*)ad, strlen(ad),
                                     cipher, ct_len,
                                     dec, sizeof(dec));
    CHECK(bad_dec == 0, "篡改密文后 open 返回 0");
}

// ============================================================================
// Test 3: Session Ticket 序列化/反序列化
// ============================================================================
void test_ticket() {
    printf("\n=== Test 3: Session Ticket 序列化 ===\n");
    linoh_session_ticket_t t1;
    for (int i = 0; i < 32; i++) t1.peer_id.bytes[i] = (uint8_t)(i + 10);
    for (int i = 0; i < 32; i++) t1.master_secret[i] = (uint8_t)(i * 3 + 1);
    t1.max_early_data_bytes = 0x12345678;

    uint8_t buf[LINOH_TICKET_SIZE];
    linoh_ticket_to_bytes(&t1, buf);

    linoh_session_ticket_t t2;
    linoh_ticket_from_bytes(buf, &t2);

    CHECK(memcmp(t1.peer_id.bytes, t2.peer_id.bytes, 32) == 0,
          "peer_id 往返一致");
    CHECK(memcmp(t1.master_secret, t2.master_secret, 32) == 0,
          "master_secret 往返一致");
    CHECK(t1.max_early_data_bytes == t2.max_early_data_bytes,
          "max_early_data_bytes 往返一致");
}

// ============================================================================
// Test 4: Zero-RTT 密钥派生
// ============================================================================
void test_derive_0rtt() {
    printf("\n=== Test 4: Zero-RTT 密钥派生 ===\n");
    uint8_t master[LINOH_KEY_SIZE];
    for (int i = 0; i < 32; i++) master[i] = (uint8_t)(i * 7 + 13);

    linoh_aead_key_t key1, key2;
    linoh_error_t err;

    err = linoh_derive_zero_rtt(master, &key1);
    CHECK(err == LINOH_OK, "derive_zero_rtt 返回 LINOH_OK");

    // 检查 key 是否非零
    int all_zero = 1;
    for (int i = 0; i < 32; i++) if (key1.bytes[i] != 0) { all_zero = 0; break; }
    CHECK(all_zero == 0, "派生密钥非零");

    // 相同 master 应该产生相同 key
    err = linoh_derive_zero_rtt(master, &key2);
    CHECK(memcmp(key1.bytes, key2.bytes, 32) == 0,
          "相同 master_secret 产生相同 0-RTT key");

    // 不同 master 应该产生不同 key
    uint8_t master2[LINOH_KEY_SIZE];
    memset(master2, 0xFF, 32);
    linoh_aead_key_t key3;
    linoh_derive_zero_rtt(master2, &key3);
    CHECK(memcmp(key1.bytes, key3.bytes, 32) != 0,
          "不同 master_secret 产生不同 0-RTT key");
}

// ============================================================================
// Test 5: 随机数生成
// ============================================================================
void test_random() {
    printf("\n=== Test 5: 随机数 C-API ===\n");
    uint8_t buf1[64], buf2[64];
    linoh_error_t err;

    err = linoh_random_bytes(buf1, sizeof(buf1));
    CHECK(err == LINOH_OK, "random_bytes 返回 OK");

    err = linoh_random_bytes(buf2, sizeof(buf2));
    CHECK(err == LINOH_OK, "random_bytes 第二次 OK");

    int diff = (memcmp(buf1, buf2, sizeof(buf1)) != 0);
    CHECK(diff != 0, "两次调用产生不同随机数");

    err = linoh_random_bytes(nullptr, 10);
    CHECK(err == LINOH_ERR_PARAM, "NULL buf 返回 LINOH_ERR_PARAM");
}

// ============================================================================
// Test 6: 密钥生成 C-API
// ============================================================================
void test_keypair() {
    printf("\n=== Test 6: Keypair C-API ===\n");
    linoh_secret_key_t sk;
    linoh_public_key_t pk;
    linoh_error_t err = linoh_generate_keypair(&sk, &pk);
    CHECK(err == LINOH_OK, "generate_keypair 返回 LINOH_OK");

    int sk_zero = 1, pk_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (sk.bytes[i] != 0) sk_zero = 0;
        if (pk.bytes[i] != 0) pk_zero = 0;
    }
    CHECK(sk_zero == 0, "Secret Key 非零");
    CHECK(pk_zero == 0, "Public Key 非零");

    // pk 格式化
    char buf[128];
    size_t n = linoh_public_key_fmt_short(&pk, buf, sizeof(buf));
    CHECK(n > 0, "public_key_fmt_short 返回非零");
    CHECK(n < sizeof(buf), "格式化长度合理");
}

// ============================================================================
// Test 7: Connection 级别的 session save/restore（C++ API 验证）
// ============================================================================
void test_connection_session() {
    printf("\n=== Test 7: Connection Session Save ===\n");
    // 建立一个连接、模拟 handshake 完成
    endpoint::Connection::Config cfg;
    cfg.secret_key = base::SecretKey::generate();
    cfg.local_cid = protocol::ConnectionId::generate();
    cfg.remote_cid = protocol::ConnectionId::generate();
    cfg.direction = endpoint::Direction::Outbound;
    cfg.alpn = "linoh/1";

    auto conn = std::make_shared<endpoint::Connection>(std::move(cfg));
    conn->on_handshake_completed();

    // save session
    auto ticket = conn->save_session();
    CHECK(ticket.has_value(), "save_session 返回可选票据");
    CHECK(ticket->alpn == "linoh/1", "alpn 正确保存");

    int ms_zero = 1;
    for (int i = 0; i < 32; i++) if (ticket->master_secret[i] != 0) { ms_zero = 0; break; }
    CHECK(ms_zero == 0, "master_secret 非零");

    // 使用 ticket 建立新连接（0-RTT 模式）
    endpoint::Connection::Config cfg2;
    cfg2.secret_key = base::SecretKey::generate();
    cfg2.local_cid = protocol::ConnectionId::generate();
    cfg2.remote_cid = protocol::ConnectionId::generate();
    cfg2.direction = endpoint::Direction::Outbound;
    cfg2.alpn = "linoh/1";
    cfg2.resume_ticket = std::move(ticket);

    auto conn2 = std::make_shared<endpoint::Connection>(std::move(cfg2));
    CHECK(conn2->is_resumed(), "新连接标记为 session 恢复");
    printf("    [INFO ] 已恢复连接: is_resumed=true\n");

    conn2->close();
}

// ============================================================================
// Test 8: 0-RTT early data 入队 + build_0rtt_packet（C++ API 验证）
// ============================================================================
void test_0rtt_early_data() {
    printf("\n=== Test 8: 0-RTT Early Data ===\n");

    // 先建立一个正常连接、save session 然后恢复
    endpoint::Connection::Config cfg_init;
    cfg_init.secret_key = base::SecretKey::generate();
    cfg_init.local_cid = protocol::ConnectionId::generate();
    cfg_init.remote_cid = protocol::ConnectionId::generate();
    cfg_init.direction = endpoint::Direction::Outbound;
    cfg_init.alpn = "linoh/1";

    auto conn_init = std::make_shared<endpoint::Connection>(std::move(cfg_init));
    conn_init->on_handshake_completed();
    auto ticket = conn_init->save_session();
    CHECK(ticket.has_value(), "保存会话成功");

    // 恢复的连接：入队 early data 并构建 0-RTT 包
    endpoint::Connection::Config cfg_resume;
    cfg_resume.secret_key = base::SecretKey::generate();
    cfg_resume.local_cid = protocol::ConnectionId::generate();
    cfg_resume.remote_cid = protocol::ConnectionId::generate();
    cfg_resume.direction = endpoint::Direction::Outbound;
    cfg_resume.alpn = "linoh/1";
    cfg_resume.resume_ticket = std::move(ticket);

    auto conn = std::make_shared<endpoint::Connection>(std::move(cfg_resume));
    CHECK(conn->is_resumed(), "恢复的连接 is_resumed=true");

    // 入队 early data
    std::vector<uint8_t> early_data;
    for (int i = 0; i < 200; i++) early_data.push_back((uint8_t)(i * 3 + 7));
    conn->queue_early_data(std::span<const uint8_t>(early_data.data(), early_data.size()));
    printf("    [INFO ] early_data queued (%zu bytes)\n", early_data.size());

    // 构建 0-RTT 包
    std::vector<uint8_t> buf(1500);
    size_t len = conn->build_0rtt_packet(std::span<uint8_t>(buf.data(), buf.size()));
    CHECK(len > 0, "build_0rtt_packet 返回非零长度");
    CHECK(len <= buf.size(), "包长度不超过缓冲区");
    printf("    [INFO ] 0-RTT 包长度 = %zu bytes\n", len);

    conn->close();
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("=====================================================\n");
    printf("  linoh 0-RTT + C-API 集成测试\n");
    printf("=====================================================\n");

    printf("\n[INFO ] linoh version: %s\n", linoh_version());

    test_hmac();
    test_aead();
    test_ticket();
    test_derive_0rtt();
    test_random();
    test_keypair();
    test_connection_session();
    test_0rtt_early_data();

    printf("\n=====================================================\n");
    printf("  测试结果: %d 通过, %d 失败\n", g_pass, g_fail);
    printf("=====================================================\n");
    return g_fail == 0 ? 0 : 1;
}
