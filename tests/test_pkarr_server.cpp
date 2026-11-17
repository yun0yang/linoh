// tests/test_pkarr_server.cpp — 自建 Pkarr DNS Server 端到端验证
//
// 覆盖：发布->查询->验签->提取地址（relay + direct）、未知节点 NXDOMAIN、
// 签名验证（篡改字节拒绝）、QNAME<->NodeId round-trip。
// 纯原生 UDP 回环，无需 OpenSSL，默认构建即可运行。

#include "linoh/address_lookup/lookup.hpp"
#include "linoh/address_lookup/pkarr_dns.hpp"
#include "linoh/address_lookup/pkarr_server.hpp"
#include "linoh/base/key.hpp"

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace linoh;

static int g_failures = 0;
#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            printf("  FAIL: %s\n", msg);                                      \
            ++g_failures;                                                     \
        } else {                                                              \
            printf("  ok:   %s\n", msg);                                      \
        }                                                                     \
    } while (0)

static base::EndpointAddr make_addr(const base::EndpointId &id) {
    base::EndpointAddr a(id);
    a.add_relay(base::RelayUrl("https://relay.example.iroh.link:33445/"));
    base::TransportAddr d;
    d.kind = base::TransportKind::Ip;
    d.host = "1.2.3.4";
    d.port = 12345;
    a.add_direct_address(d);
    return a;
}

static int test_publish_then_query() {
    printf("[test_publish_then_query]\n");
    auto sk = base::SecretKey::generate();
    base::EndpointId id = sk.public_key();
    auto addr = make_addr(id);

    auto server = std::make_shared<address_lookup::PkarrDnsServer>();
    auto r = server->start("127.0.0.1", 5333);
    CHECK(r.is_ok(), "server start ok");
    if (!r.is_ok()) return 1;

    address_lookup::PkarrPublisher pub(sk);
    pub.bind_server(server);
    pub.publish(addr);
    CHECK(server->record_count() == 1, "server holds 1 record");

    address_lookup::DnsAddressLookup lookup;
    lookup.set_server("127.0.0.1", 5333);
    auto got = lookup.lookup(id);
    CHECK(static_cast<bool>(got), "lookup returns an address");
    if (got) {
        CHECK(got->id() == id, "id matches");
        CHECK(got->relays().size() == 1, "has 1 relay");
        CHECK(got->direct_addresses().size() == 1, "has 1 direct address");
        if (!got->relays().empty())
            CHECK(got->relays()[0].url() == "https://relay.example.iroh.link:33445/",
                  "relay url round-trips");
        if (!got->direct_addresses().empty())
            CHECK(got->direct_addresses()[0].host == "1.2.3.4" &&
                      got->direct_addresses()[0].port == 12345,
                  "direct address round-trips");
    }
    server->stop();
    return 0;
}

static int test_unknown_node_nxdomain() {
    printf("[test_unknown_node_nxdomain]\n");
    auto server = std::make_shared<address_lookup::PkarrDnsServer>();
    auto r = server->start("127.0.0.1", 5333);
    CHECK(r.is_ok(), "server start ok");
    if (!r.is_ok()) return 1;

    address_lookup::DnsAddressLookup lookup;
    lookup.set_server("127.0.0.1", 5333);
    auto unknown = base::SecretKey::generate().public_key();
    auto got = lookup.lookup(unknown);
    CHECK(!static_cast<bool>(got), "unknown node -> nullopt (NXDOMAIN)");
    server->stop();
    return 0;
}

static int test_signature_verified() {
    printf("[test_signature_verified]\n");
    auto sk = base::SecretKey::generate();
    base::EndpointId id = sk.public_key();
    auto addr = make_addr(id);

    address_lookup::PkarrPublisher pub(sk);
    pub.publish(addr);
    auto sp_bytes = pub.last_signed_packet();
    CHECK(static_cast<bool>(sp_bytes), "publisher produced a signed packet");

    auto sp = address_lookup::pkarr::deserialize_signed_packet(
        std::span<const std::uint8_t>(sp_bytes->data(), sp_bytes->size()));
    CHECK(static_cast<bool>(sp), "deserialize ok");
    if (!sp) return 1;

    auto parsed = address_lookup::pkarr::parse_dns_response(*sp);
    CHECK(static_cast<bool>(parsed), "parse_dns_response ok (valid signature)");
    CHECK(parsed->id() == id, "parsed id matches publisher");

    // 篡改 dns_packet 中 1 字节 -> 验签失败 -> parse 返回 nullopt
    auto tampered = *sp;
    tampered.dns_packet[20] ^= 0xFF;
    auto parsed2 = address_lookup::pkarr::parse_dns_response(tampered);
    CHECK(!static_cast<bool>(parsed2), "tampered packet -> parse fails");
    return 0;
}

static int test_roundtrip_qname() {
    printf("[test_roundtrip_qname]\n");
    auto id = base::SecretKey::generate().public_key();
    std::string sq = address_lookup::pkarr::pkarr_srv_qname(id);
    auto back = address_lookup::pkarr::node_id_from_qname(sq);
    CHECK(static_cast<bool>(back) && *back == id, "srv qname round-trips");

    std::string tq = sq.substr(std::string("_iroh._tcp.").size());
    auto back2 = address_lookup::pkarr::node_id_from_qname(tq);
    CHECK(static_cast<bool>(back2) && *back2 == id, "txt qname round-trips");

    CHECK(!static_cast<bool>(address_lookup::pkarr::node_id_from_qname("garbage.com")),
          "invalid qname -> nullopt");
    CHECK(!static_cast<bool>(address_lookup::pkarr::node_id_from_qname("abc.iroh")),
          "too-short hex -> nullopt");
    return 0;
}

int main() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 2;
    }
#endif
    test_publish_then_query();
    test_unknown_node_nxdomain();
    test_signature_verified();
    test_roundtrip_qname();

    printf("\n=== Results: %d PASSED, %d FAILED ===\n", 4 - g_failures, g_failures);
#ifdef _WIN32
    WSACleanup();
#endif
    return g_failures;
}
