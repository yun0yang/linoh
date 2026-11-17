// linoh 核心库测试程序
#include "linoh/base/key.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/util/bytes.hpp"
#include "linoh/tls/handshake_token_key.hpp"
#include "linoh/tls/crypto_provider.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <array>
#include <span>

using namespace linoh::crypto;
using namespace linoh::base;
using namespace linoh::protocol;
using namespace linoh::util;
using namespace linoh::tls;

static int g_pass = 0;
static int g_fail = 0;

#define PASS() do { g_pass++; } while(0)
#define FAIL() do { g_fail++; } while(0)

static void check_equal(const char *name, const uint8_t *a, const uint8_t *b, std::size_t n) {
    if (std::memcmp(a, b, n) == 0) {
        std::cout << "  [PASS] " << name << std::endl;
        g_pass++;
    } else {
        std::cout << "  [FAIL] " << name << std::endl;
        g_fail++;
    }
}

static void check_not_equal(const char *name, const uint8_t *a, const uint8_t *b, std::size_t n) {
    if (std::memcmp(a, b, n) != 0) {
        std::cout << "  [PASS] " << name << std::endl;
        g_pass++;
    } else {
        std::cout << "  [FAIL] " << name << std::endl;
        g_fail++;
    }
}

static void check_true(const char *name, bool cond) {
    std::cout << "  " << (cond ? "[PASS]" : "[FAIL]") << " " << name << std::endl;
    if (cond) g_pass++; else g_fail++;
}

static void print_hex(const char *label, std::span<const uint8_t> data) {
    std::cout << "    " << label << " (" << data.size() << " bytes): ";
    for (std::size_t i = 0; i < data.size() && i < 20; ++i) {
        printf("%02x ", data[i]);
    }
    if (data.size() > 20) std::cout << "...";
    std::cout << std::endl;
}

static void test_random() {
    std::cout << "\n=== Crypto Random Source ===" << std::endl;
    uint8_t buf[32] = {0};
    bool ok = crypto_random_bytes(std::span<uint8_t>(buf, 32));
    check_true("random bytes available", ok);
    int nz = 0;
    for (int i = 0; i < 32; ++i) if (buf[i] != 0) nz++;
    std::cout << "    non-zero: " << nz << "/32" << std::endl;
    check_true("has non-zero bytes", nz > 5);
    print_hex("sample", std::span<const uint8_t>(buf, 32));
}

static void test_sha256() {
    std::cout << "\n=== SHA-256 ===" << std::endl;
    uint8_t d1[] = {'h','e','l','l','o'};
    uint8_t d2[] = {'w','o','r','l','d'};
    auto hash1 = SHA256::hash(std::span<const uint8_t>(d1, 5));
    auto hash2 = SHA256::hash(std::span<const uint8_t>(d2, 5));
    check_not_equal("different inputs give different hashes",
                    hash1.data(), hash2.data(), 32);
    print_hex("hash('hello')", std::span<const uint8_t>(hash1.data(), hash1.size()));
    print_hex("hash('world')", std::span<const uint8_t>(hash2.data(), hash2.size()));

    // 重复测试确定性
    auto hash1b = SHA256::hash(std::span<const uint8_t>(d1, 5));
    check_equal("same input gives same hash",
                hash1.data(), hash1b.data(), 32);
}

static void test_hmac() {
    std::cout << "\n=== HMAC-SHA256 ===" << std::endl;
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(i + 1);
    const char *msg = "Test message for HMAC";
    auto h1 = HMAC_SHA256::compute(std::span<const uint8_t>(key, 32),
                                    std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(msg), strlen(msg)));
    auto h2 = HMAC_SHA256::compute(std::span<const uint8_t>(key, 32),
                                    std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(msg), strlen(msg)));
    check_equal("same (key,msg) -> same hmac", h1.data(), h2.data(), 32);

    uint8_t key2[32];
    for (int i = 0; i < 32; ++i) key2[i] = (uint8_t)(i + 100);
    auto h3 = HMAC_SHA256::compute(std::span<const uint8_t>(key2, 32),
                                    std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(msg), strlen(msg)));
    check_not_equal("different keys give different hmac", h1.data(), h3.data(), 32);
    print_hex("HMAC with key1", std::span<const uint8_t>(h1.data(), h1.size()));
    print_hex("HMAC with key2", std::span<const uint8_t>(h3.data(), h3.size()));
}

static void test_aead_direct() {
    std::cout << "\n=== ChaCha20-Poly1305 AEAD (custom impl) ===" << std::endl;
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(i + 1);
    uint8_t nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    uint8_t ad[4] = {0x01,0x02,0x03,0x04};
    const char *msg = "Hello, linoh!";
    std::size_t ml = strlen(msg);

    std::vector<uint8_t> ct(ml + 16);
    std::size_t w = ChaCha20Poly1305::seal(
        std::span<const uint8_t>(key, 32),
        std::span<const uint8_t>(nonce, 12),
        std::span<const uint8_t>(ad, 4),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(msg), ml),
        std::span<uint8_t>(ct.data(), ct.size()));
    check_true("seal produced valid output", w == ml + 16);
    std::cout << "    plaintext: " << ml << " bytes, ciphertext: " << w << " bytes" << std::endl;

    std::vector<uint8_t> dec(ml);
    std::size_t dl = ChaCha20Poly1305::open(
        std::span<const uint8_t>(key, 32),
        std::span<const uint8_t>(nonce, 12),
        std::span<const uint8_t>(ad, 4),
        std::span<const uint8_t>(ct.data(), w),
        std::span<uint8_t>(dec.data(), dec.size()));
    check_true("open produced valid output", dl == ml);
    check_equal("round-trip matches original",
                dec.data(), reinterpret_cast<const uint8_t *>(msg), ml);

    // tag corruption
    ct[ml] ^= 0xff;
    std::vector<uint8_t> dec2(ml);
    std::size_t dl2 = ChaCha20Poly1305::open(
        std::span<const uint8_t>(key, 32),
        std::span<const uint8_t>(nonce, 12),
        std::span<const uint8_t>(ad, 4),
        std::span<const uint8_t>(ct.data(), w),
        std::span<uint8_t>(dec2.data(), dec2.size()));
    check_true("corrupted tag correctly rejected", dl2 == 0);
}

static void test_keys() {
    std::cout << "\n=== SecretKey / PublicKey ===" << std::endl;
    auto sk = SecretKey::generate();
    check_true("generated secret key", sk.size() == 32);
    auto pk = sk.public_key();
    check_true("generated public key", pk.size() == 32);
    int nz = 0;
    for (std::size_t i = 0; i < pk.size(); ++i) if (pk.data()[i] != 0) nz++;
    std::cout << "    pk non-zero: " << nz << "/" << pk.size() << std::endl;
    check_true("public key has non-zero bytes", nz > 0);
    std::cout << "    pk short: " << pk.fmt_short() << std::endl;

    // 两个不同的 sk 产生不同的 pk
    auto sk2 = SecretKey::generate();
    auto pk2 = sk2.public_key();
    check_not_equal("different sk gives different pk", pk.data(), pk2.data(), 32);

    // 签名/验证
    const char *m = "test message to sign";
    auto sig = sk.sign(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(m), strlen(m)));
    check_true("signature is 64 bytes", sig.size() == 64);
    Signature sig_obj(sig);
    check_true("signature verifies",
               sig_obj.verify(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(m), strlen(m)), pk));
}

static void test_cid() {
    std::cout << "\n=== ConnectionId ===" << std::endl;
    auto cid = ConnectionId::generate();
    check_true("cid is not empty", !cid.empty());
    check_true("cid has length > 0", cid.len() > 0);
    std::cout << "    cid: " << cid.fmt_hex() << " (len=" << cid.len() << ")" << std::endl;

    auto cid2 = ConnectionId::generate();
    check_true("different cids compare different", !(cid == cid2));
}

static void test_bytes_util() {
    std::cout << "\n=== Bytes / MutableBytes ===" << std::endl;
    MutableBytes mb(16);
    check_true("mb has correct size", mb.size() == 16);
    for (std::size_t i = 0; i < 16; ++i) mb.data()[i] = (uint8_t)(i * 2);
    auto sp = mb.as_span();
    check_true("span matches size", sp.size() == 16);

    auto b = mb.freeze(16);
    check_true("frozen size matches", b.size() == 16);
    bool ok = true;
    for (std::size_t i = 0; i < 16; ++i) if (b[i] != (uint8_t)(i * 2)) { ok = false; break; }
    check_true("frozen values preserved", ok);
}

static void test_aead_provider() {
    std::cout << "\n=== AEAD via CryptoProvider ===" << std::endl;
    auto cipher = global_provider().default_aead();
    check_true("key_size=32", cipher->key_size() == 32);
    check_true("nonce_size=12", cipher->nonce_size() == 12);
    check_true("tag_size=16", cipher->tag_size() == 16);

    uint8_t key[32];
    uint8_t nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    uint8_t ad[8] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x11,0x22};
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)(i + 10);
    const char *p = "Encrypted message via CryptoProvider";
    std::size_t pl = strlen(p);

    std::vector<uint8_t> out(pl + cipher->tag_size());
    std::size_t w = cipher->seal(std::span<const uint8_t>(key, 32),
                                  std::span<const uint8_t>(nonce, 12),
                                  std::span<const uint8_t>(ad, 8),
                                  std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(p), pl),
                                  std::span<uint8_t>(out.data(), out.size()));
    check_true("provider seal produces ct+tag", w == pl + cipher->tag_size());

    std::vector<uint8_t> dec(pl);
    std::size_t d = cipher->open(std::span<const uint8_t>(key, 32),
                                  std::span<const uint8_t>(nonce, 12),
                                  std::span<const uint8_t>(ad, 8),
                                  std::span<const uint8_t>(out.data(), w),
                                  std::span<uint8_t>(dec.data(), dec.size()));
    check_true("provider open produces original", d == pl);
    check_equal("provider round-trip matches",
                dec.data(), reinterpret_cast<const uint8_t *>(p), pl);
}

static void test_hs_token() {
    std::cout << "\n=== HandshakeTokenKey ===" << std::endl;
    auto tk = HandshakeTokenKey::generate();
    check_true("token key size", tk.key().size() == 32);

    uint64_t nonce_val = 0x1122334455667788ULL;
    uint8_t src[4] = {127, 0, 0, 1};
    const char *pt = "handshake-token-payload";
    std::size_t pl = strlen(pt);

    auto ct = tk.seal(nonce_val,
                       std::span<const uint8_t>(src, 4),
                       std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(pt), pl));
    check_true("seal produces data", !ct.empty());
    std::cout << "    plaintext=" << pl << ", ciphertext=" << ct.size() << std::endl;

    auto dec = tk.open(nonce_val,
                        std::span<const uint8_t>(src, 4),
                        std::span<const uint8_t>(ct.data(), ct.size()));
    check_true("open produces same length", dec.size() == pl);
    check_equal("token round-trip",
                dec.data(), reinterpret_cast<const uint8_t *>(pt), pl);
}

static void test_packet_hdr() {
    std::cout << "\n=== QUIC Packet Header (1-RTT) ===" << std::endl;
    auto cid = ConnectionId::generate();
    auto hdr = PacketHeader::make_1rtt(cid, PnLen::Len2);
    check_true("type is OneRtt", hdr.type() == PacketType::OneRtt);

    uint8_t buf[256];
    std::size_t s = hdr.serialize_to(buf, 256);
    check_true("serialized to valid bytes", s > 0 && s < 256);
    std::cout << "    serialized to " << s << " bytes" << std::endl;

    auto parsed_opt = PacketHeader::parse_from(std::span<const uint8_t>(buf, s));
    check_true("parse returns value", parsed_opt.has_value());
    if (parsed_opt.has_value()) {
        auto &ph = parsed_opt.value().first;
        check_true("parsed type matches", ph.type() == PacketType::OneRtt);
    }
}

int main() {
    std::cout << "======== linoh 核心库测试 ========" << std::endl;
    std::cout << "  Compiler: MSVC C++20, Library: linoh.lib" << std::endl;

    test_random();
    test_sha256();
    test_hmac();
    test_aead_direct();
    test_keys();
    test_cid();
    test_bytes_util();
    test_aead_provider();
    test_hs_token();
    test_packet_hdr();

    std::cout << "\n======== Summary ========" << std::endl;
    std::cout << "  PASS: " << g_pass << "  FAIL: " << g_fail << std::endl;
    if (g_fail == 0) {
        std::cout << "  >>> ALL TESTS PASSED <<<" << std::endl;
        return 0;
    } else {
        std::cout << "  >>> SOME TESTS FAILED <<<" << std::endl;
        return 1;
    }
}
