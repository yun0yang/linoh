/// 最小核心库功能测试
///
/// 编译方法（任选其一）：
///   g++ -std=c++20 -I../include test_minimal.cpp \
///       ../src/base/key.cpp ../src/base/endpoint_addr.cpp \
///       ../src/tls/crypto_provider.cpp ../src/tls/ed25519_verifier.cpp \
///       ../src/tls/handshake_token_key.cpp \
///       -lssl -lcrypto -o test_minimal
///
///   或使用 CMake:  cmake .. -DLINOH_BUILD_TESTS=ON && make -j

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/tls/crypto_provider.hpp"
#include "linoh/tls/handshake_token_key.hpp"

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace linoh;

int main() {
    std::cout << "=== linoh minimal test ===\n";

    // 1. 测试 Ed25519 身份生成
    base::SecretKey sk = base::SecretKey::generate();
    base::PublicKey pk = sk.public_key();
    std::cout << "[1] 生成新身份: " << pk.fmt_short()
              << " (key size = " << pk.size() << " bytes)\n";

    // 2. 测试签名/验证
    std::string msg = "hello-linoh-from-2026";
    std::span<const uint8_t> payload(
        reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
    auto sig = sk.sign(payload);
    std::cout << "[2] 签名完成: " << sig.size() << " bytes\n";

    base::Signature sig_obj(sig);
    assert(sig_obj.verify(payload, pk) && "签名校验失败");
    std::cout << "[2] 签名校验通过 ✓\n";

    // 3. 测试"篡改"后的签名会被拒绝
    auto tampered = sig;
    tampered[0] ^= 0x01;
    base::Signature bad_sig(tampered);
    assert(!bad_sig.verify(payload, pk) && "篡改的签名应该失败");
    std::cout << "[3] 篡改签名被正确拒绝 ✓\n";

    // 4. 两个不同的密钥得到不同的公钥
    base::SecretKey sk2 = base::SecretKey::generate();
    base::PublicKey pk2 = sk2.public_key();
    assert(!(pk == pk2));
    std::cout << "[4] 不同密钥产生不同公钥 ✓\n";

    // 5. 握手令牌 AEAD 往返
    auto tk = tls::HandshakeTokenKey::generate();
    std::string token_plain = "connection-token-data-v1";
    std::span<const uint8_t> tp_bytes(
        reinterpret_cast<const uint8_t *>(token_plain.data()),
        token_plain.size());

    std::string ad = "src-peer-id: " + pk.fmt_short();
    std::span<const uint8_t> ad_span(
        reinterpret_cast<const uint8_t *>(ad.data()), ad.size());

    auto enc = tk.seal(/*nonce_int=*/0xC0FFEEULL, ad_span, tp_bytes);
    assert(enc.size() == token_plain.size() + 16);
    auto dec = tk.open(0xC0FFEEULL, ad_span, enc);
    assert(dec.size() == token_plain.size() &&
           std::memcmp(dec.data(), token_plain.data(), token_plain.size()) == 0);
    std::cout << "[5] 握手令牌 AEAD 往返成功 ✓ (密文 " << enc.size() << " bytes)\n";

    // 6. 篡改密文应当被拒绝
    auto bad = enc;
    bad[0] ^= 0xFF;
    auto bad_dec = tk.open(0xC0FFEEULL, ad_span, bad);
    assert(bad_dec.empty());
    std::cout << "[6] 篡改密文被 AEAD 校验正确拒绝 ✓\n";

    // 7. CryptoProvider 接口测试
    auto &provider = tls::global_provider();
    std::cout << "[7] 当前 crypto provider: " << provider.name() << "\n";
    auto default_aead = provider.default_aead();
    assert(default_aead != nullptr);
    std::cout << "[7]   default AEAD: key_size=" << default_aead->key_size()
              << ", nonce_size=" << default_aead->nonce_size()
              << ", tag_size=" << default_aead->tag_size() << "\n";

    std::cout << "\n=== 所有测试通过 ✓ ===\n";
    return 0;
}
