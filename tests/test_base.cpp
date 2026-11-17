#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

using namespace linoh;

int main() {
    // 1. SecretKey::generate 两次不同，不为零。
    base::SecretKey k1 = base::SecretKey::generate();
    base::SecretKey k2 = base::SecretKey::generate();
    assert(k1.size() == 32 && k2.size() == 32);
    assert(!(k1 == k2));

    // 2. public_key 派生：相同私钥 -> 相同公钥；不同私钥通常不同。
    base::PublicKey pub1 = k1.public_key();
    base::PublicKey pub1_b = k1.public_key();
    assert(pub1 == pub1_b);
    base::PublicKey pub2 = k2.public_key();
    assert(pub1 != pub2);

    // 3. fmt_short 返回非空字符串。
    std::string fs = pub1.fmt_short();
    assert(!fs.empty());
    std::cout << "fmt_short: " << fs << "\n";

    // 4. 签名/验证：用 k1 签名 -> 用 pub1 验证成功；用 pub2 验证失败。
    std::string msg = "hello linoh";
    std::span<const uint8_t> payload(
        reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
    auto sig_bytes = k1.sign(payload);
    assert(sig_bytes.size() == base::Signature::kSize);
    base::Signature sig(sig_bytes);
    assert(sig.verify(payload, pub1));
    assert(!sig.verify(payload, pub2));
    std::cout << "sign/verify OK (" << sig_bytes.size() << " bytes)\n";

    // 5. EndpointAddr 基本构造。
    base::EndpointAddr addr{pub1};
    assert(addr.id() == pub1);
    base::TransportAddr ta;
    ta.kind = base::TransportKind::Ip;
    ta.host = "127.0.0.1";
    ta.port = 12345;
    addr.add_direct_address(ta);
    assert(addr.direct_addresses().size() == 1);

    base::RelayUrl relay("https://example.relay:443/");
    addr.add_relay(relay);
    assert(addr.relays().size() == 1);
    assert(relay.host() == "example.relay");
    assert(relay.port() == 443);

    // 6. fmt_short to_string 比较。
    std::string full = pub1.to_string();
    assert(!full.empty());
    std::cout << "to_string: " << full << "\n";

    std::cout << "[OK] test_base passed\n";
    return 0;
}
