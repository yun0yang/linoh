// =============================================================================
// test_signed_message.cpp — v3.8.2 控制面 Ed25519 签名信封单元测试
//
// 覆盖场景：
//   1. 基本 roundtrip（sign → encode → decode → verify）
//   2. 便捷路径（sign_and_encode + decode_and_verify）
//   3. 篡改 data → 验签失败
//   4. 篡改 signature → 验签失败
//   5. 篡改 from → 验签失败（签名与公钥不匹配）
//   6. 错误公钥验签（签名 sk_A + from pk_B → 失败）
//   7. verify_from 匹配 → true
//   8. verify_from 不匹配 → false
//   9. 空消息（data={}）
//  10. 大 payload（1MB）
//  11. decode 长度不足（< 100）→ nullopt
//  12. decode data_len 越界 → nullopt
//  13. decode data_len 超上限（> 16MB）→ nullopt
//  14. 确定性签名（同 sk + 同 data → 同 signature）
//  15. encode 后翻转字节 → decode_and_verify 失败
//  16. 不同 sk 签同 data → signature 不同
//  17. 连续 10 条不同消息 roundtrip
//  18. from 字段正确性（decode 后 from == sk.public_key）
// =============================================================================

#include "linoh/crypto/signed_message.hpp"
#include "linoh/base/key.hpp"

#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>

using namespace linoh::crypto;
using linoh::base::PublicKey;
using linoh::base::SecretKey;
using linoh::base::Signature;

namespace {

/// 生成指定大小的确定性数据（按位置填充）
std::vector<uint8_t> make_data(std::size_t size, uint8_t seed = 0) {
    std::vector<uint8_t> data(size);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>((seed + i) & 0xFF);
    }
    return data;
}

int test_count = 0;
int test_passed = 0;

#define RUN_TEST(name)                                                        \
    do {                                                                      \
        ++test_count;                                                         \
        std::cout << "  [test] " #name " ... ";                               \
        name();                                                               \
        ++test_passed;                                                        \
        std::cout << "OK\n";                                                  \
    } while (0)

} // namespace

// =============================================================================
// 1. 基本 roundtrip
// =============================================================================

void test_basic_roundtrip() {
    SecretKey sk = SecretKey::generate();
    auto data = make_data(256, 0x42);

    SignedMessage sm = sign_message(sk, data);
    assert(sm.verify());  // 自验签通过

    std::vector<uint8_t> encoded = encode(sm);
    assert(encoded.size() == 100 + data.size());

    auto decoded = decode(encoded);
    assert(decoded.has_value());
    assert(decoded->verify());  // 解码后验签通过

    // data 一致
    assert(decoded->data.size() == data.size());
    assert(std::memcmp(decoded->data.data(), data.data(), data.size()) == 0);

    // from 一致
    assert(decoded->from == sk.public_key());
}

// =============================================================================
// 2. 便捷路径 sign_and_encode + decode_and_verify
// =============================================================================

void test_sign_and_encode_decode_and_verify() {
    SecretKey sk = SecretKey::generate();
    auto data = make_data(128, 0x11);

    std::vector<uint8_t> encoded = sign_and_encode(sk, data);

    VerifyResult r = decode_and_verify(encoded);
    assert(r.valid);
    assert(r.message.data.size() == data.size());
    assert(std::memcmp(r.message.data.data(), data.data(), data.size()) == 0);
    assert(r.message.from == sk.public_key());
}

// =============================================================================
// 3. 篡改 data → 验签失败
// =============================================================================

void test_tamper_data() {
    SecretKey sk = SecretKey::generate();
    auto data = make_data(64, 0xAB);

    std::vector<uint8_t> encoded = sign_and_encode(sk, data);

    // 翻转 data 区域第一个字节（偏移 100）
    encoded[100] ^= 0xFF;

    VerifyResult r = decode_and_verify(encoded);
    // decode 成功（长度合法），但验签失败
    assert(!r.valid);
}

// =============================================================================
// 4. 篡改 signature → 验签失败
// =============================================================================

void test_tamper_signature() {
    SecretKey sk = SecretKey::generate();
    auto data = make_data(64, 0xCD);

    std::vector<uint8_t> encoded = sign_and_encode(sk, data);

    // 翻转 signature 区域第一个字节（偏移 32）
    encoded[32] ^= 0xFF;

    VerifyResult r = decode_and_verify(encoded);
    assert(!r.valid);
}

// =============================================================================
// 5. 篡改 from → 验签失败（签名与公钥不匹配）
// =============================================================================

void test_tamper_from() {
    SecretKey sk = SecretKey::generate();
    auto data = make_data(64, 0xEF);

    std::vector<uint8_t> encoded = sign_and_encode(sk, data);

    // 翻转 from 区域第一个字节（偏移 0）
    encoded[0] ^= 0xFF;

    VerifyResult r = decode_and_verify(encoded);
    assert(!r.valid);
}

// =============================================================================
// 6. 错误公钥验签：签名 sk_A + from pk_B → 失败
// =============================================================================

void test_wrong_pubkey_verify() {
    SecretKey sk_A = SecretKey::generate();
    SecretKey sk_B = SecretKey::generate();
    auto data = make_data(128, 0x22);

    // 用 sk_A 签名
    std::array<uint8_t, 64> sig_A = sk_A.sign(data);

    // 手动构造 from=pk_B 的信封（签名与公钥不匹配）
    SignedMessage sm_wrong;
    sm_wrong.from = sk_B.public_key();  // 故意用 pk_B
    sm_wrong.data = data;
    sm_wrong.signature = Signature(sig_A);

    // 验签应该失败（sig_A 是 sk_A 签的，用 pk_B 验证不通过）
    assert(!sm_wrong.verify());

    // 对照：用正确的 pk_A 验证通过
    SignedMessage sm_right;
    sm_right.from = sk_A.public_key();
    sm_right.data = data;
    sm_right.signature = Signature(sig_A);
    assert(sm_right.verify());
}

// =============================================================================
// 7. verify_from 匹配
// =============================================================================

void test_verify_from_match() {
    SecretKey sk = SecretKey::generate();
    auto data = make_data(64, 0x33);

    SignedMessage sm = sign_message(sk, data);
    PublicKey pk = sk.public_key();

    assert(sm.verify_from(pk));  // from 匹配且签名有效
}

// =============================================================================
// 8. verify_from 不匹配
// =============================================================================

void test_verify_from_mismatch() {
    SecretKey sk_A = SecretKey::generate();
    SecretKey sk_B = SecretKey::generate();
    auto data = make_data(64, 0x44);

    SignedMessage sm = sign_message(sk_A, data);  // from = pk_A

    // 期望 from = pk_B，不匹配
    assert(!sm.verify_from(sk_B.public_key()));
}

// =============================================================================
// 9. 空消息（data={}）
// =============================================================================

void test_empty_message() {
    SecretKey sk = SecretKey::generate();
    std::vector<uint8_t> data;  // 空

    SignedMessage sm = sign_message(sk, data);
    assert(sm.verify());

    std::vector<uint8_t> encoded = encode(sm);
    assert(encoded.size() == 100);  // 仅头部，无 data

    VerifyResult r = decode_and_verify(encoded);
    assert(r.valid);
    assert(r.message.data.empty());
}

// =============================================================================
// 10. 大 payload（1MB）
// =============================================================================

void test_large_payload() {
    SecretKey sk = SecretKey::generate();
    auto data = make_data(1024 * 1024, 0x55);  // 1MB

    std::vector<uint8_t> encoded = sign_and_encode(sk, data);
    assert(encoded.size() == 100 + 1024 * 1024);

    VerifyResult r = decode_and_verify(encoded);
    assert(r.valid);
    assert(r.message.data.size() == data.size());
    assert(std::memcmp(r.message.data.data(), data.data(), data.size()) == 0);
}

// =============================================================================
// 11. decode 长度不足（< 100）→ nullopt
// =============================================================================

void test_decode_too_short() {
    std::vector<uint8_t> short_bytes(99, 0xAA);  // 99 字节 < 100
    auto decoded = decode(short_bytes);
    assert(!decoded.has_value());

    // 边界：恰好 100 字节但 data_len=0（空消息）应该成功
    SecretKey sk = SecretKey::generate();
    auto empty_encoded = sign_and_encode(sk, {});
    assert(empty_encoded.size() == 100);
    assert(decode(empty_encoded).has_value());
}

// =============================================================================
// 12. decode data_len 越界（data_len > 剩余字节）→ nullopt
// =============================================================================

void test_decode_data_len_out_of_range() {
    SecretKey sk = SecretKey::generate();
    auto data = make_data(32, 0x66);
    std::vector<uint8_t> encoded = sign_and_encode(sk, data);  // 100 + 32 = 132

    // 篡改 data_len 为 999（超过剩余字节）
    encoded[96] = 0xE7;  // 999 & 0xFF
    encoded[97] = 0x03;  // 999 >> 8
    encoded[98] = 0x00;
    encoded[99] = 0x00;

    auto decoded = decode(encoded);
    assert(!decoded.has_value());  // data_len=999 但仅 32 字节 data
}

// =============================================================================
// 13. decode data_len 超上限（> 16MB）→ nullopt
// =============================================================================

void test_decode_data_len_over_limit() {
    SecretKey sk = SecretKey::generate();
    auto data = make_data(16, 0x77);
    std::vector<uint8_t> encoded = sign_and_encode(sk, data);

    // 篡改 data_len 为 16MB+1（超过 kMaxSignedMessageDataLen）
    const uint32_t over_limit = kMaxSignedMessageDataLen + 1;
    encoded[96] = static_cast<uint8_t>(over_limit & 0xFF);
    encoded[97] = static_cast<uint8_t>((over_limit >> 8) & 0xFF);
    encoded[98] = static_cast<uint8_t>((over_limit >> 16) & 0xFF);
    encoded[99] = static_cast<uint8_t>((over_limit >> 24) & 0xFF);

    auto decoded = decode(encoded);
    assert(!decoded.has_value());
}

// =============================================================================
// 14. 确定性签名（同 sk + 同 data → 同 signature）
// =============================================================================

void test_deterministic() {
    SecretKey sk = SecretKey::generate();
    auto data = make_data(256, 0x88);

    SignedMessage sm1 = sign_message(sk, data);
    SignedMessage sm2 = sign_message(sk, data);

    // Ed25519 确定性签名：两次签名结果相同
    assert(std::memcmp(sm1.signature.data(), sm2.signature.data(),
                       Signature::kSize) == 0);
    assert(sm1.verify() && sm2.verify());
}

// =============================================================================
// 15. encode 后翻转字节 → decode_and_verify 失败
// =============================================================================

void test_encode_tamper_byte() {
    SecretKey sk = SecretKey::generate();
    auto data = make_data(256, 0x99);

    std::vector<uint8_t> encoded = sign_and_encode(sk, data);

    // 翻转中间某字节（落在 signature 区域，偏移 50）
    encoded[50] ^= 0x01;

    VerifyResult r = decode_and_verify(encoded);
    assert(!r.valid);
}

// =============================================================================
// 16. 不同 sk 签同 data → signature 不同
// =============================================================================

void test_different_sk_different_sig() {
    SecretKey sk_A = SecretKey::generate();
    SecretKey sk_B = SecretKey::generate();
    auto data = make_data(128, 0xAA);

    SignedMessage sm_A = sign_message(sk_A, data);
    SignedMessage sm_B = sign_message(sk_B, data);

    // 不同私钥签同 data，签名不同
    assert(std::memcmp(sm_A.signature.data(), sm_B.signature.data(),
                       Signature::kSize) != 0);
    // from 也不同
    assert(sm_A.from != sm_B.from);
    // 各自验签通过
    assert(sm_A.verify() && sm_B.verify());
}

// =============================================================================
// 17. 连续 10 条不同消息 roundtrip
// =============================================================================

void test_roundtrip_sequence() {
    SecretKey sk = SecretKey::generate();

    for (int i = 0; i < 10; ++i) {
        auto data = make_data(64 + i * 32, static_cast<uint8_t>(i));
        std::vector<uint8_t> encoded = sign_and_encode(sk, data);

        VerifyResult r = decode_and_verify(encoded);
        assert(r.valid);
        assert(r.message.data.size() == data.size());
        assert(std::memcmp(r.message.data.data(), data.data(), data.size()) == 0);
    }
}

// =============================================================================
// 18. from 字段正确性（decode 后 from == sk.public_key）
// =============================================================================

void test_from_correctness() {
    SecretKey sk = SecretKey::generate();
    PublicKey pk = sk.public_key();
    auto data = make_data(200, 0xBB);

    std::vector<uint8_t> encoded = sign_and_encode(sk, data);
    auto decoded = decode(encoded);

    assert(decoded.has_value());
    assert(decoded->from == pk);  // from 正确
    assert(!decoded->from.is_zero());  // 非全零
}

// =============================================================================
// main
// =============================================================================

int main() {
    std::cout << "=== test_signed_message (v3.8.2 Ed25519 签名信封) ===\n";

    RUN_TEST(test_basic_roundtrip);
    RUN_TEST(test_sign_and_encode_decode_and_verify);
    RUN_TEST(test_tamper_data);
    RUN_TEST(test_tamper_signature);
    RUN_TEST(test_tamper_from);
    RUN_TEST(test_wrong_pubkey_verify);
    RUN_TEST(test_verify_from_match);
    RUN_TEST(test_verify_from_mismatch);
    RUN_TEST(test_empty_message);
    RUN_TEST(test_large_payload);
    RUN_TEST(test_decode_too_short);
    RUN_TEST(test_decode_data_len_out_of_range);
    RUN_TEST(test_decode_data_len_over_limit);
    RUN_TEST(test_deterministic);
    RUN_TEST(test_encode_tamper_byte);
    RUN_TEST(test_different_sk_different_sig);
    RUN_TEST(test_roundtrip_sequence);
    RUN_TEST(test_from_correctness);

    std::cout << "\n=== Result: " << test_passed << "/" << test_count
              << " tests passed ===\n";

    return (test_passed == test_count) ? 0 : 1;
}
