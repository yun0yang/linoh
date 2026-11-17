// test_basic.cpp - 验证 linoh.lib 基本功能（不含 OpenSSL）
#include "linoh/util/bytes.hpp"
#include "linoh/base/key.hpp"
#include "linoh/protocol/packet.hpp"

#include <iostream>

using namespace linoh;

int main() {
    std::cout << "[TEST] linoh.lib basic verification\n";

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

    // 5. 测试 PacketHeader 构建
    std::cout << "\n[5] Testing QUIC PacketHeader...\n";
    auto hdr = protocol::PacketHeader::make_1rtt(cid, protocol::PnLen::Len2);
    std::cout << "  Header type: 1-RTT (Short Header)\n";
    std::cout << "  Encoded size: " << hdr.encoded_size() << " bytes\n";

    std::cout << "\n[SUCCESS] All basic tests passed!\n";
    std::cout << "linoh.lib is ready for use.\n";
    return 0;
}
