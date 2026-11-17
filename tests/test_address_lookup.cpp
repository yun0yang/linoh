#include "linoh/address_lookup/lookup.hpp"
#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"

#include <cassert>
#include <cstring>
#include <iostream>

using namespace linoh;

int main() {
    // 1. MemoryLookup：publish -> lookup。
    base::SecretKey k = base::SecretKey::generate();
    base::EndpointId id = k.public_key();
    base::EndpointAddr addr{id};
    base::TransportAddr ta;
    ta.kind = base::TransportKind::Ip;
    ta.host = "10.0.0.1";
    ta.port = 9999;
    addr.add_direct_address(ta);
    addr.add_relay(base::RelayUrl("https://relay.example.com/"));

    address_lookup::MemoryLookup ml;
    ml.publish(addr);
    auto got = ml.lookup(id);
    assert(got.has_value());
    assert(got->id() == id);
    assert(got->direct_addresses().size() == 1);
    assert(got->relays().size() == 1);
    std::cout << "MemoryLookup OK, relay host="
              << got->relays().front().host() << "\n";

    // 2. PkarrPublisher：publish 一次，并且 last_signed_packet 非空（内部
    //    以 signed `vector<uint8_t>` 形式存储，此处我们暴露的 API 让测试可以访问）。
    address_lookup::PkarrPublisher publisher(SecretKey::generate());
    publisher.publish(addr);
    auto packet = publisher.last_signed_packet();
    assert(packet.has_value());
    assert(!packet->empty());
    std::cout << "PkarrPublisher OK, signed_packet_size=" << packet->size() << "\n";

    // 3. DnsAddressLookup：缓存式 publish/lookup。
    address_lookup::DnsAddressLookup dns;
    dns.inject(addr);
    auto got2 = dns.lookup(id);
    assert(got2.has_value());
    assert(got2->direct_addresses().front().port == 9999);
    std::cout << "DnsAddressLookup OK\n";

    std::cout << "[OK] test_address_lookup passed\n";
    return 0;
}
