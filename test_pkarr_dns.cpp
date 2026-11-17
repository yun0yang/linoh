// test_pkarr_dns.cpp — Pkarr DNS wire format + signing tests
//
// Tests:
// 1. DNS name encoding
// 2. SRV record encoding
// 3. TXT record encoding
// 4. Full DNS packet building
// 5. SignedPacket sign/verify roundtrip
// 6. Serialization/deserialization

#include "linoh/address_lookup/pkarr_dns.hpp"
#include "linoh/base/key.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace linoh::address_lookup::pkarr;
using namespace linoh::base;

int main() {
    int failed = 0;

    // ─── Test 1: DNS name encoding ───
    printf("Test 1: DNS name encoding\n");
    {
        auto name = encode_dns_name("example.com");
        // Expected: [7]example[3]com[0]
        if (name.size() != 13 || name[0] != 7 || name[8] != 3 || name[12] != 0) {
            printf("FAIL: DNS name encode 'example.com'\n");
            failed++;
        }

        auto root = encode_dns_name("");
        if (root.size() != 1 || root[0] != 0) {
            printf("FAIL: DNS name encode root label\n");
            failed++;
        }

        auto single = encode_dns_name("localhost");
        if (single.size() != 11 || single[0] != 9 || single[10] != 0) {
            printf("FAIL: DNS name encode 'localhost', size=%zu\n", single.size());
            failed++;
        }
    }

    // ─── Test 2: SRV record encoding ───
    printf("Test 2: SRV record encoding\n");
    {
        auto srv = encode_srv_rdata(10, 20, 443, "relay.iroh.link");
        // [priority(2)][weight(2)][port(2)][DNS name]
        if (srv.size() < 6) {
            printf("FAIL: SRV rdata too small\n");
            failed++;
        } else if (srv[0] != 0 || srv[1] != 10 || srv[2] != 0 || srv[3] != 20) {
            printf("FAIL: SRV priority/weight: got [0x%02x 0x%02x 0x%02x 0x%02x]\n",
                   srv[0], srv[1], srv[2], srv[3]);
            failed++;
        }
        // port 443 = 0x01BB
        if (srv[4] != 0x01 || srv[5] != 0xBB) {
            printf("FAIL: SRV port: got [0x%02x 0x%02x], expected [0x01 0xBB]\n",
                   srv[4], srv[5]);
            failed++;
        }
    }

    // ─── Test 3: TXT record encoding ───
    printf("Test 3: TXT record encoding\n");
    {
        auto txt = encode_txt_rdata("1.2.3.4:12345");
        // [13]1.2.3.4:12345 (single character-string)
        if (txt.size() != 14 || txt[0] != 13) {
            printf("FAIL: TXT rdata for short string\n");
            failed++;
        }

        // Long string (> 255 bytes) should be split
        std::string long_str(300, 'x');
        auto long_txt = encode_txt_rdata(long_str);
        // Should be: [255]255_x_bytes + [45]45_x_bytes
        if (long_txt.size() != 255 + 1 + 45 + 1) {
            printf("FAIL: TXT rdata for long string, size=%Iu expected=%Iu\n",
                   long_txt.size(), 255 + 1 + 45 + 1);
            failed++;
        }

        // Empty string
        auto empty_txt = encode_txt_rdata("");
        if (empty_txt.size() != 1 || empty_txt[0] != 0) {
            printf("FAIL: TXT rdata for empty string\n");
            failed++;
        }
    }

    // ─── Test 4: Full DNS packet building ───
    printf("Test 4: Full DNS packet building\n");
    {
        SecretKey sk = SecretKey::generate();
        EndpointId node_id = sk.public_key();

        std::vector<std::string> relay_hosts = {"relay.iroh.link"};
        std::vector<uint16_t> relay_ports = {443};
        std::vector<std::string> direct_addrs = {"127.0.0.1:54321"};

        auto packet = build_pkarr_dns_packet(node_id, relay_hosts, relay_ports, direct_addrs);

        // Verify packet starts with DNS header (12 bytes)
        if (packet.size() < 12) {
            printf("FAIL: DNS packet too small\n");
            failed++;
        } else {
            // QR flag should be set (bit 15 of flags = 0x8000)
            uint16_t flags = (static_cast<uint16_t>(packet[2]) << 8) | packet[3];
            if (!(flags & 0x8000)) {
                printf("FAIL: DNS header QR flag not set\n");
                failed++;
            }
            // ANCOUNT should be 2 (1 SRV + 1 TXT)
            uint16_t ancount = (static_cast<uint16_t>(packet[6]) << 8) | packet[7];
            if (ancount != 2) {
                printf("FAIL: ANCOUNT=%u, expected 2\n", ancount);
                failed++;
            }
            // QDCOUNT should be 1
            uint16_t qdcount = (static_cast<uint16_t>(packet[4]) << 8) | packet[5];
            if (qdcount != 1) {
                printf("FAIL: QDCOUNT=%u, expected 1\n", qdcount);
                failed++;
            }
        }
    }

    // ─── Test 5: SignedPacket sign/verify roundtrip ───
    printf("Test 5: SignedPacket sign/verify\n");
    {
        SecretKey sk = SecretKey::generate();
        EndpointId node_id = sk.public_key();

        auto packet = build_pkarr_dns_packet(
            node_id, {"relay.example.com"}, {443}, {"10.0.0.1:12345"});

        // Sign
        auto signed_pkt = sign_dns_packet(packet, sk);

        // Verify with correct public key
        if (!verify_signed_packet(signed_pkt, node_id)) {
            printf("FAIL: signed packet should verify with correct key\n");
            failed++;
        }

        // Verify with wrong public key should fail
        SecretKey wrong_sk = SecretKey::generate();
        EndpointId wrong_id = wrong_sk.public_key();
        if (verify_signed_packet(signed_pkt, wrong_id)) {
            printf("FAIL: signed packet should NOT verify with wrong key\n");
            failed++;
        }

        // Tamper with dns_packet should fail verification
        auto tampered_pkt = signed_pkt;
        if (!tampered_pkt.dns_packet.empty()) {
            tampered_pkt.dns_packet[0] ^= 0xFF;  // flip first byte
            if (verify_signed_packet(tampered_pkt, node_id)) {
                printf("FAIL: tampered packet should NOT verify\n");
                failed++;
            }
        }
    }

    // ─── Test 6: Serialization/deserialization ───
    printf("Test 6: Serialization/deserialization\n");
    {
        SecretKey sk = SecretKey::generate();
        EndpointId node_id = sk.public_key();

        auto packet = build_pkarr_dns_packet(
            node_id, {"relay.test.com"}, {443}, {"192.168.1.1:8080"});

        auto signed_pkt = sign_dns_packet(packet, sk);
        auto serialized = serialize_signed_packet(signed_pkt);

        auto deserialized = deserialize_signed_packet(
            std::span<const uint8_t>(serialized.data(), serialized.size()));
        if (!deserialized) {
            printf("FAIL: deserialization returned null\n");
            failed++;
        } else {
            // Verify signature matches
            for (int i = 0; i < 64; i++) {
                if (deserialized->signature[i] != signed_pkt.signature[i]) {
                    printf("FAIL: deserialized signature byte %d mismatch\n", i);
                    failed++;
                    break;
                }
            }
            // Verify dns_packet matches
            if (deserialized->dns_packet.size() != signed_pkt.dns_packet.size()) {
                printf("FAIL: deserialized dns_packet size mismatch\n");
                failed++;
            }
            // Verify roundtrip
            if (!verify_signed_packet(*deserialized, node_id)) {
                printf("FAIL: deserialized packet verification failed\n");
                failed++;
            }
        }

        // Too short data should return null
        std::vector<uint8_t> short_data(70);  // < 64 + 12
        auto short_result = deserialize_signed_packet(
            std::span<const uint8_t>(short_data.data(), short_data.size()));
        if (short_result) {
            printf("FAIL: short data should return null\n");
            failed++;
        }
    }

    // ─── Summary ───
    if (failed == 0) {
        printf("\nALL PKARR DNS TESTS PASSED!\n");
    } else {
        printf("\nFAILED: %d tests\n", failed);
    }
    return failed;
}
