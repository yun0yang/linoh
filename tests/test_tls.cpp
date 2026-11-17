#include "linoh/tls/crypto_provider.hpp"
#include "linoh/tls/handshake_token_key.hpp"

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace linoh;

int main() {
    // 1. 默认 CryptoProvider 可用。
    auto &provider = tls::global_provider();
    std::cout << "provider: " << provider.name() << "\n";

    // 2. 默认 AEAD：seal/open 往返。
    auto cipher = provider.default_aead();
    assert(cipher != nullptr);
    std::cout << "key_size=" << cipher->key_size()
              << " nonce_size=" << cipher->nonce_size()
              << " tag_size=" << cipher->tag_size() << "\n";

    // 生成 key + nonce。
    std::vector<uint8_t> key(cipher->key_size(), 0xAB);
    std::vector<uint8_t> nonce(cipher->nonce_size(), 0x42);
    std::string ad_str = "demo ad";
    std::string pt_str = "hello cryptography world";
    std::span<const uint8_t> ad(reinterpret_cast<const uint8_t *>(ad_str.data()), ad_str.size());
    std::span<const uint8_t> pt(reinterpret_cast<const uint8_t *>(pt_str.data()), pt_str.size());

    // seal：out 至少需要 pt.size() + tag_size()。
    std::vector<uint8_t> ct(pt.size() + cipher->tag_size());
    std::size_t ct_len = cipher->seal(key, nonce, ad, pt, ct);
    assert(ct_len == pt.size() + cipher->tag_size());
    std::cout << "seal OK, ct_len=" << ct_len << "\n";

    // open：解密。
    std::vector<uint8_t> plain(pt.size());
    std::size_t pt_len = cipher->open(key, nonce, ad, ct, plain);
    assert(pt_len == pt.size());
    assert(std::memcmp(plain.data(), pt.data(), pt.size()) == 0);
    std::cout << "open OK, round trip matches plaintext\n";

    // 3. 错误 key 会失败。
    std::vector<uint8_t> bad_key(cipher->key_size(), 0x11);
    std::vector<uint8_t> decoy(pt.size());
    std::size_t bad_len = cipher->open(bad_key, nonce, ad, ct, decoy);
    assert(bad_len == 0);
    std::cout << "bad key: open rejected as expected\n";

    // 4. HandshakeTokenKey：加解密往返。
    auto tk = tls::HandshakeTokenKey::generate();
    std::string token_plain = "connection-id=42,ts=12345";
    std::span<const uint8_t> tp_bytes(
        reinterpret_cast<const uint8_t *>(token_plain.data()), token_plain.size());
    uint64_t nonce_int = 0xC0FFEEULL;
    std::string ad_bytes = "127.0.0.1:54321";
    std::span<const uint8_t> ad_span(
        reinterpret_cast<const uint8_t *>(ad_bytes.data()), ad_bytes.size());

    auto enc = tk.seal(nonce_int, ad_span, tp_bytes);
    assert(enc.size() == token_plain.size() + 16);  // AEAD 16B tag
    auto dec = tk.open(nonce_int, ad_span, enc);
    assert(dec.size() == token_plain.size());
    assert(std::memcmp(dec.data(), token_plain.data(), token_plain.size()) == 0);
    std::cout << "HandshakeTokenKey round-trip OK\n";

    // 5. 篡改密文：必须失败。
    auto bad = enc;
    bad[5] ^= 0x01;
    auto bad_dec = tk.open(nonce_int, ad_span, bad);
    assert(bad_dec.empty());
    std::cout << "HandshakeTokenKey tamper rejection OK\n";

    std::cout << "[OK] test_tls passed\n";
    return 0;
}
