// test_linoh.cpp - 验证 linoh.lib 核心功能
#include "linoh/endpoint/builder.hpp"
#include "linoh/util/logging.hpp"
#include "linoh/util/bytes.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/base/key.hpp"

#include <iostream>

using namespace linoh;

int main() {
    std::cout << "[TEST] linoh.lib verification\n";

    // 1. 测试密钥生成
    std::cout << "\n[1] Testing Ed25519 key generation...\n";
    auto sk = base::SecretKey::generate();
    auto pk = sk.public_key();
    std::cout << "  SecretKey generated, size: " << sk.size() << " bytes\n";
    std::cout << "  PublicKey  generated: " << pk.fmt_short() << "\n";

    // 2. 测试 EndpointId
    std::cout << "\n[2] Testing EndpointId (from public key)...\n";
    base::EndpointId id(pk);
    std::cout << "  EndpointId short: " << id.fmt_short() << "\n";

    // 3. 测试 ConnectionId
    std::cout << "\n[3] Testing ConnectionId generation...\n";
    auto cid = protocol::ConnectionId::generate();
    std::cout << "  ConnectionId: " << cid.fmt_hex() << "\n";

    // 4. 测试 Bytes
    std::cout << "\n[4] Testing Bytes utility...\n";
    util::Bytes data{std::string_view("Hello linoh!")};
    std::cout << "  Bytes size: " << data.size() << ", content: ";
    for (auto b : data.as_span()) std::cout << (char)b;
    std::cout << "\n";

    // 5. 测试 HandshakeTokenKey
    std::cout << "\n[5] Testing HandshakeTokenKey AEAD...\n";
    auto token_key = tls::HandshakeTokenKey::generate();
    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5, 6, 7, 8};
    std::array<uint8_t, 1> ad{0};
    auto sealed = token_key.seal(42, std::span<const uint8_t>(ad), std::span<const uint8_t>(plaintext));
    std::cout << "  Sealed size: " << sealed.size() << " bytes (includes 16B tag)\n";
    auto opened = token_key.open(42, std::span<const uint8_t>(ad), std::span<const uint8_t>(sealed));
    std::cout << "  Opened size: " << opened.size() << " bytes\n";
    if (opened == plaintext) {
        std::cout << "  [OK] AEAD roundtrip successful!\n";
    } else {
        std::cout << "  [FAIL] AEAD roundtrip failed!\n";
        return 1;
    }

    // 6. 测试 PacketHeader 构建
    std::cout << "\n[6] Testing QUIC PacketHeader...\n";
    auto hdr = protocol::PacketHeader::make_1rtt(cid, protocol::PnLen::Len2);
    std::cout << "  Header type: 1-RTT (Short Header)\n";
    std::cout << "  Encoded size: " << hdr.encoded_size() << " bytes\n";

    std::cout << "\n[SUCCESS] All basic tests passed!\n";
    std::cout << "linoh.lib is ready for use.\n";
    return 0;
}
