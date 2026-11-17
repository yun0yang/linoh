// test_ed25519_auth.cpp — v4.0.3 M15 跨集群 Ed25519 挑战认证测试
//
// 覆盖 10 个场景，35 断言：
//   1. AuthChallenge 编解码往返
//   2. AuthResponse 编解码往返
//   3. 三步认证完整流程（A→B→A）
//   4. 签名篡改检测
//   5. nonce 重放检测
//   6. timestamp 过期检测
//   7. timestamp 未来偏移检测
//   8. 会话缓存（认证后 state==Authenticated）
//   9. AuthMode::Auto 内网跳过 / 跨网强制
//  10. AuthMode::Always/Never 行为
//
// 编译：cl /std:c++20 /EHsc /permissive- /O2 /utf-8 /MD /DLINOH_USE_STUB_ASIO
//        /I. /Iinclude /Ithird_party\asio\include /Ithird_party\openssl\include
//        test_ed25519_auth.cpp /c
// 链接：link /OUT:test_ed25519_auth.exe test_ed25519_auth.obj
//        linoh.lib linoh-base.lib ws2_32.lib user32.lib

#include "linoh/protocol/ed25519_auth.hpp"
#include "linoh/protocol/replay_protection.hpp"
#include "linoh/base/key.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>

using namespace linoh;
using namespace linoh::protocol;
using namespace linoh::base;

// ============================================================================
// 测试工具
// ============================================================================

#define CHECK(cond) do { \
    ++g_assertions; \
    if (!(cond)) { \
        std::fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #cond); \
        ++g_failures; \
    } \
} while (0)

#define CHECK_EQ(a, b) CHECK((a) == (b))

static int g_assertions = 0;
static int g_failures = 0;

/// 生成测试密钥对（确定性，便于复现）
static SecretKey make_test_sk(std::uint8_t seed_byte) {
    std::array<std::uint8_t, SecretKey::kSize> seed{};
    for (std::size_t i = 0; i < SecretKey::kSize; ++i) {
        seed[i] = static_cast<std::uint8_t>(seed_byte + i);
    }
    return SecretKey::from_bytes(seed);
}

// ============================================================================
// 场景 1：AuthChallenge 编解码往返
// ============================================================================

static void test_challenge_encode_decode() {
    std::printf("[test] AuthChallenge encode/decode roundtrip...\n");

    AuthChallenge c;
    c.timestamp = 0xDEADBEEF12345678ULL;
    for (std::size_t i = 0; i < kAuthNonceSize; ++i) {
        c.nonce[i] = static_cast<std::uint8_t>(0xA0 + i);
    }
    SecretKey sk = make_test_sk(0x11);
    c.challenger = sk.public_key();

    auto encoded = c.encode();
    CHECK_EQ(encoded.size(), kAuthChallengeEncodedSize);  // 73

    AuthChallenge decoded;
    CHECK(AuthChallenge::decode(encoded, decoded));
    CHECK_EQ(decoded, c);

    // 损坏输入：长度不足
    std::vector<std::uint8_t> short_data(kAuthChallengeEncodedSize - 1, 0);
    CHECK(!AuthChallenge::decode(short_data, decoded));

    // 损坏输入：version 不匹配
    std::vector<std::uint8_t> bad_version = encoded;
    bad_version[0] = 0xFF;
    CHECK(!AuthChallenge::decode(bad_version, decoded));
}

// ============================================================================
// 场景 2：AuthResponse 编解码往返
// ============================================================================

static void test_response_encode_decode() {
    std::printf("[test] AuthResponse encode/decode roundtrip...\n");

    AuthResponse r;
    r.timestamp = 0xCAFEBABE87654321ULL;
    for (std::size_t i = 0; i < kAuthNonceSize; ++i) {
        r.nonce[i] = static_cast<std::uint8_t>(0xB0 + i);
    }
    SecretKey sk_from = make_test_sk(0x22);
    r.from = sk_from.public_key();
    for (std::size_t i = 0; i < Signature::kSize; ++i) {
        const_cast<std::uint8_t *>(r.signature.data())[i] = static_cast<std::uint8_t>(0xC0 + i);
    }

    auto encoded = r.encode();
    CHECK_EQ(encoded.size(), kAuthResponseEncodedSize);  // 137

    AuthResponse decoded;
    CHECK(AuthResponse::decode(encoded, decoded));
    CHECK_EQ(decoded, r);

    // 损坏输入：长度不足
    std::vector<std::uint8_t> short_data(kAuthResponseEncodedSize - 1, 0);
    CHECK(!AuthResponse::decode(short_data, decoded));

    // 损坏输入：version 不匹配
    std::vector<std::uint8_t> bad_version = encoded;
    bad_version[0] = 0xFF;
    CHECK(!AuthResponse::decode(bad_version, decoded));
}

// ============================================================================
// 场景 3：三步认证完整流程（A→B→A）
// ============================================================================
//
// @note A 侧和 B 侧各自维护独立的 ReplayProtection 实例：
//   - replay_b：B 侧防 A 重放旧挑战（handle_challenge 内 check）
//   - replay_a：A 侧防 B 重放旧响应（verify_response 内 check）
// 真实部署中 A/B 是不同进程，天然独立；测试中需显式分离。

static void test_full_auth_flow() {
    std::printf("[test] full authentication flow (A challenge -> B response -> A verify)...\n");

    // 准备密钥对
    SecretKey sk_a = make_test_sk(0x01);  // A 的私钥
    SecretKey sk_b = make_test_sk(0x02);  // B 的私钥
    PublicKey pub_a = sk_a.public_key();
    PublicKey pub_b = sk_b.public_key();

    AuthManager mgr(AuthMode::Always);
    ReplayProtection replay_b;  // B 侧防重放（防 A 重放旧挑战）
    ReplayProtection replay_a;  // A 侧防重放（防 B 重放旧响应）

    // Step 1: A 生成挑战
    AuthChallenge challenge = mgr.generate_challenge(sk_a);
    CHECK_EQ(challenge.challenger, pub_a);
    CHECK(challenge.timestamp > 0);

    // Step 2: B 处理挑战，生成响应（用 B 侧 replay 校验）
    auto response_opt = mgr.handle_challenge(challenge, sk_b, replay_b);
    CHECK(response_opt.has_value());

    AuthResponse response = *response_opt;
    CHECK_EQ(response.from, pub_b);
    CHECK_EQ(response.timestamp, challenge.timestamp);
    CHECK_EQ(response.nonce, challenge.nonce);

    // Step 3: A 验证响应（用 A 侧 replay 校验）
    bool ok = mgr.verify_response(response, pub_a, pub_b,
                                   challenge.nonce, challenge.timestamp, replay_a);
    CHECK(ok);

    // 验证成功后标记会话
    mgr.mark_authenticated(pub_b);
    CHECK_EQ(mgr.state(pub_b), AuthState::Authenticated);
    CHECK(mgr.is_authenticated(pub_b));
}

// ============================================================================
// 场景 4：签名篡改检测
// ============================================================================

static void test_signature_tamper() {
    std::printf("[test] signature tamper detection...\n");

    SecretKey sk_a = make_test_sk(0x01);
    SecretKey sk_b = make_test_sk(0x02);
    PublicKey pub_a = sk_a.public_key();
    PublicKey pub_b = sk_b.public_key();

    AuthManager mgr;
    ReplayProtection replay_b;  // B 侧
    ReplayProtection replay_a;  // A 侧

    AuthChallenge challenge = mgr.generate_challenge(sk_a);
    auto response_opt = mgr.handle_challenge(challenge, sk_b, replay_b);
    assert(response_opt.has_value());
    AuthResponse response = *response_opt;

    // 篡改 signature 第一个字节
    AuthResponse tampered = response;
    const_cast<std::uint8_t *>(tampered.signature.data())[0] ^= 0xFF;
    bool ok = mgr.verify_response(tampered, pub_a, pub_b,
                                   challenge.nonce, challenge.timestamp, replay_a);
    CHECK(!ok);  // 篡改后验签必须失败
}

// ============================================================================
// 场景 5：nonce 重放检测
// ============================================================================

static void test_nonce_replay() {
    std::printf("[test] nonce replay detection...\n");

    SecretKey sk_a = make_test_sk(0x01);
    SecretKey sk_b = make_test_sk(0x02);
    PublicKey pub_a = sk_a.public_key();
    PublicKey pub_b = sk_b.public_key();

    AuthManager mgr;
    ReplayProtection replay_b;  // B 侧
    ReplayProtection replay_a;  // A 侧

    AuthChallenge challenge = mgr.generate_challenge(sk_a);
    auto response_opt = mgr.handle_challenge(challenge, sk_b, replay_b);
    assert(response_opt.has_value());
    AuthResponse response = *response_opt;

    // 第一次验证（成功）- A 侧 replay 插入 nonce
    bool ok1 = mgr.verify_response(response, pub_a, pub_b,
                                    challenge.nonce, challenge.timestamp, replay_a);
    CHECK(ok1);

    // 第二次验证同一 nonce（必须失败 - A 侧 replay 已有 nonce，重放检测命中）
    bool ok2 = mgr.verify_response(response, pub_a, pub_b,
                                    challenge.nonce, challenge.timestamp, replay_a);
    CHECK(!ok2);
}

// ============================================================================
// 场景 6：timestamp 过期检测
// ============================================================================

static void test_timestamp_expired() {
    std::printf("[test] timestamp expired detection...\n");

    SecretKey sk_a = make_test_sk(0x01);
    SecretKey sk_b = make_test_sk(0x02);
    PublicKey pub_a = sk_a.public_key();
    PublicKey pub_b = sk_b.public_key();

    AuthManager mgr;
    ReplayProtection replay_b;  // B 侧

    // 构造一个过期的挑战（120 秒前）
    AuthChallenge challenge;
    challenge.timestamp = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()) - 120;
    challenge.challenger = pub_a;
    challenge.nonce.fill(0x55);

    // handle_challenge 应因 timestamp 过期返回 nullopt
    auto response_opt = mgr.handle_challenge(challenge, sk_b, replay_b);
    CHECK(!response_opt.has_value());
}

// ============================================================================
// 场景 7：timestamp 未来偏移检测
// ============================================================================

static void test_timestamp_future() {
    std::printf("[test] timestamp future offset detection...\n");

    SecretKey sk_a = make_test_sk(0x01);
    SecretKey sk_b = make_test_sk(0x02);
    PublicKey pub_a = sk_a.public_key();

    AuthManager mgr;
    ReplayProtection replay_b;  // B 侧

    // 构造一个未来 timestamp（+120 秒）
    AuthChallenge challenge;
    challenge.timestamp = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()) + 120;
    challenge.challenger = pub_a;
    challenge.nonce.fill(0x66);

    auto response_opt = mgr.handle_challenge(challenge, sk_b, replay_b);
    CHECK(!response_opt.has_value());
}

// ============================================================================
// 场景 8：会话缓存
// ============================================================================

static void test_session_cache() {
    std::printf("[test] session cache (state transitions)...\n");

    SecretKey sk_b = make_test_sk(0x02);
    PublicKey pub_b = sk_b.public_key();

    AuthManager mgr;

    // 初始状态
    CHECK_EQ(mgr.state(pub_b), AuthState::Unauthenticated);
    CHECK(!mgr.is_authenticated(pub_b));

    // 标记挑战已发送
    mgr.mark_challenge_sent(pub_b);
    CHECK_EQ(mgr.state(pub_b), AuthState::ChallengeSent);

    // 标记已认证
    mgr.mark_authenticated(pub_b);
    CHECK_EQ(mgr.state(pub_b), AuthState::Authenticated);
    CHECK(mgr.is_authenticated(pub_b));

    // 清除
    mgr.clear(pub_b);
    CHECK_EQ(mgr.state(pub_b), AuthState::Unauthenticated);
}

// ============================================================================
// 场景 9：AuthMode::Auto 内网跳过 / 跨网强制
// ============================================================================

static void test_auth_mode_auto() {
    std::printf("[test] AuthMode::Auto (skip LAN, enforce cross-network)...\n");

    AuthManager mgr(AuthMode::Auto);
    SecretKey sk = make_test_sk(0x01);
    PublicKey pub = sk.public_key();

    // 内网：跳过认证
    CHECK(!mgr.should_authenticate(pub, false));

    // 跨网：强制认证
    CHECK(mgr.should_authenticate(pub, true));
}

// ============================================================================
// 场景 10：AuthMode::Always / Never
// ============================================================================

static void test_auth_mode_always_never() {
    std::printf("[test] AuthMode::Always / Never...\n");

    SecretKey sk = make_test_sk(0x01);
    PublicKey pub = sk.public_key();

    AuthManager mgr_always(AuthMode::Always);
    CHECK(mgr_always.should_authenticate(pub, false));   // 内网也认证
    CHECK(mgr_always.should_authenticate(pub, true));    // 跨网也认证

    AuthManager mgr_never(AuthMode::Never);
    CHECK(!mgr_never.should_authenticate(pub, false));   // 内网不认证
    CHECK(!mgr_never.should_authenticate(pub, true));    // 跨网也不认证
}

// ============================================================================
// 额外场景：build_signed_data 一致性 + stats 统计
// ============================================================================

static void test_build_signed_data_and_stats() {
    std::printf("[test] build_signed_data consistency + stats...\n");

    SecretKey sk_a = make_test_sk(0x01);
    PublicKey pub_a = sk_a.public_key();

    std::array<std::uint8_t, kAuthNonceSize> nonce{};
    for (std::size_t i = 0; i < kAuthNonceSize; ++i) nonce[i] = static_cast<std::uint8_t>(0x10 + i);

    std::uint64_t ts = 0x1122334455667788ULL;

    auto sd = build_signed_data(nonce, ts, pub_a);
    CHECK_EQ(sd.size(), kAuthNonceSize + 8 + PublicKey::kSize);  // 32+8+32=72

    // 验证 nonce 部分一致
    CHECK(std::memcmp(sd.data(), nonce.data(), kAuthNonceSize) == 0);

    // 验证 timestamp 小端序
    CHECK_EQ(sd[kAuthNonceSize], 0x88);
    CHECK_EQ(sd[kAuthNonceSize + 1], 0x77);
    CHECK_EQ(sd[kAuthNonceSize + 7], 0x11);

    // 验证 challenger 部分一致
    CHECK(std::memcmp(sd.data() + kAuthNonceSize + 8, pub_a.data(), PublicKey::kSize) == 0);

    // stats 统计
    AuthManager mgr;
    SecretKey sk_b = make_test_sk(0x02);
    PublicKey pub_b = sk_b.public_key();
    SecretKey sk_c = make_test_sk(0x03);
    PublicKey pub_c = sk_c.public_key();

    mgr.mark_challenge_sent(pub_b);
    mgr.mark_authenticated(pub_c);

    auto s = mgr.stats();
    CHECK_EQ(s.total_peers, static_cast<std::size_t>(2));
    CHECK_EQ(s.authenticated, static_cast<std::size_t>(1));
    CHECK_EQ(s.pending, static_cast<std::size_t>(1));
    CHECK_EQ(s.failed, static_cast<std::size_t>(0));

    // mark_failed
    mgr.mark_failed(pub_b);
    s = mgr.stats();
    CHECK_EQ(s.pending, static_cast<std::size_t>(0));
    CHECK_EQ(s.failed, static_cast<std::size_t>(1));

    // clear_all
    mgr.clear_all();
    s = mgr.stats();
    CHECK_EQ(s.total_peers, static_cast<std::size_t>(0));
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== test_ed25519_auth: v4.0.3 M15 Ed25519 挑战认证 ===\n\n");

    test_challenge_encode_decode();
    test_response_encode_decode();
    test_full_auth_flow();
    test_signature_tamper();
    test_nonce_replay();
    test_timestamp_expired();
    test_timestamp_future();
    test_session_cache();
    test_auth_mode_auto();
    test_auth_mode_always_never();
    test_build_signed_data_and_stats();

    std::printf("\n=== Results: %d assertions, %d failures ===\n",
                g_assertions, g_failures);

    if (g_failures == 0) {
        std::printf("=== ALL TESTS PASSED ===\n");
        return 0;
    }
    std::printf("=== SOME TESTS FAILED ===\n");
    return 1;
}
