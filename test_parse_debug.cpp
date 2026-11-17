#include <cstdio>
#include <cstdint>
#include <vector>
#include <span>
#include <optional>
#include <array>
#include <algorithm>
#include <ranges>
#include "linoh/protocol/packet.hpp"

int main() {
    using namespace linoh::protocol;

    auto local_cid = ConnectionId::generate();
    auto remote_cid = ConnectionId{}; // empty

    auto hdr = PacketHeader::make_initial(remote_cid, local_cid);
    std::printf("encoded_size = %zu, local_cid.len = %zu\n", hdr.encoded_size(), local_cid.len());

    uint8_t buf[512];
    size_t len = hdr.serialize_to(buf, sizeof(buf));
    std::printf("serialized %zu bytes: ", len);
    for (size_t i = 0; i < len; ++i) {
        std::printf("%02x ", buf[i]);
    }
    std::printf("\n");

    auto result = PacketHeader::parse_from(std::span<const uint8_t>(buf, len));
    if (!result) {
        std::printf("FAILED TO PARSE!\n");
        return 1;
    }
    auto& [h, payload_start] = *result;
    std::printf("parsed ok, payload_start=%zu, type=%d, scid.len=%zu, pn_len=%d\n",
                payload_start, static_cast<int>(h.type()), h.scid().len(),
                static_cast<int>(h.pn_len()));

    // Now test PacketParser
    PacketParser parser(std::span<const uint8_t>(buf, len));
    auto pkt = parser.parse();
    if (!pkt) {
        std::printf("PacketParser::parse FAILED!\n");
        return 1;
    }
    std::printf("PacketParser parsed ok, payload.size=%zu\n", pkt->payload.as_span().size());

    // Test 1-RTT (short header)
    auto short_hdr = PacketHeader::make_1rtt(local_cid);
    uint8_t sbuf[64];
    size_t slen = short_hdr.serialize_to(sbuf, sizeof(sbuf));
    std::printf("\nshort header: %zu bytes: ", slen);
    for (size_t i = 0; i < slen; ++i) std::printf("%02x ", sbuf[i]);
    std::printf("\n");

    auto sres = PacketHeader::parse_from(std::span<const uint8_t>(sbuf, slen));
    if (!sres) {
        std::printf("FAILED TO PARSE short header!\n");
        return 1;
    }
    std::printf("parsed short ok, type=%d, dcid.len=%zu\n",
                static_cast<int>(sres->first.type()), sres->first.dcid().len());

    std::printf("\nALL TESTS PASSED!\n");
    return 0;
}
