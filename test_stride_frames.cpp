// test_stride_frames.cpp — VarInt + STRIDE frame codec unit tests
//
// Validates:
// 1. QUIC VarInt encode/decode (RFC 9000 §16)
// 2. STRIDE frame encode/decode
// 3. Datagram payload encode/decode
// 4. Ping/Pong encode/decode

#include <cassert>
#include <cstdio>
#include <cstring>
#include <array>
#include <optional>
#include <span>
#include <vector>

#include "linoh/util/varint.hpp"
#include "linoh/relay/stride.hpp"
#include "linoh/base/key.hpp"

using namespace linoh::util;
using namespace linoh::relay;
using namespace linoh::base;

// ─── VarInt tests ───

static int test_varint_encode_decode() {
    int failed = 0;

    // Test 1-byte values (0-63, prefix 00)
    struct Case1B { uint64_t val; uint8_t expected; };
    Case1B cases_1b[] = {
        {0,  0x00},
        {1,  0x01},
        {63, 0x3F},
    };
    for (auto &c : cases_1b) {
        auto enc = varint_encode_vec(c.val);
        if (enc.size() != 1 || enc[0] != c.expected) {
            printf("FAIL: varint_encode(%llu) → size=%zu byte=0x%02x, expected 0x%02x\n",
                   c.val, enc.size(), enc[0], c.expected);
            failed++;
        }
        auto dec = varint_decode(enc);
        if (!dec || dec->first != c.val || dec->second != 1) {
            printf("FAIL: varint_decode(%llu) → unexpected result\n", c.val);
            failed++;
        }
    }

    // Test 2-byte values (64-16383, prefix 01) — roundtrip only (no hardcoded bytes)
    uint64_t cases_2b[] = {64, 16383, 15293};
    for (auto v : cases_2b) {
        auto enc = varint_encode_vec(v);
        if (enc.size() != 2) {
            printf("FAIL: varint_encode(%llu) → size=%zu, expected 2\n", v, enc.size());
            failed++;
            continue;
        }
        // Verify prefix bit pattern
        if ((enc[0] & 0xC0) != 0x40) {
            printf("FAIL: varint_encode(%llu) → prefix=%02x, expected 01\n", v, enc[0] >> 6);
            failed++;
        }
        auto dec = varint_decode(enc);
        if (!dec || dec->first != v || dec->second != 2) {
            printf("FAIL: varint_decode(%llu) → unexpected result\n", v);
            failed++;
        }
    }

    // Test 4-byte values (16384-2^30-1, prefix 10) — roundtrip + prefix check
    uint64_t cases_4b[] = {16384, 1073741823, 494878333};
    for (auto v : cases_4b) {
        auto enc = varint_encode_vec(v);
        if (enc.size() != 4) {
            printf("FAIL: varint_encode(%llu) → size=%zu, expected 4\n", v, enc.size());
            failed++;
            continue;
        }
        if ((enc[0] & 0xC0) != 0x80) {
            printf("FAIL: varint_encode(%llu) → prefix=%02x, expected 10\n", v, enc[0] >> 6);
            failed++;
        }
        auto dec = varint_decode(enc);
        if (!dec || dec->first != v || dec->second != 4) {
            printf("FAIL: varint_decode(%llu) → unexpected result\n", v);
            failed++;
        }
    }

    // Test 8-byte values (2^30 to 2^62-1, prefix 11)
    struct Case8B { uint64_t val; };
    Case8B cases_8b[] = {
        {1073741824ULL},                    // 2^30
        {(1ULL << 62) - 1},                 // max value
    };
    for (auto &c : cases_8b) {
        auto enc = varint_encode_vec(c.val);
        if (enc.size() != 8) {
            printf("FAIL: varint_encode(%llu) → size=%zu, expected 8\n", c.val, enc.size());
            failed++;
            continue;
        }
        auto dec = varint_decode(enc);
        if (!dec || dec->first != c.val || dec->second != 8) {
            printf("FAIL: varint_decode(%llu) → got %llu, expected %llu\n",
                   c.val, dec ? dec->first : 0, c.val);
            failed++;
        }
    }

    // Edge: buffer too small
    uint8_t buf[1] = {};
    if (varint_encode(1000, buf) != 0) {
        printf("FAIL: varint_encode should return 0 when buffer too small\n");
        failed++;
    }

    // Edge: empty decode
    if (varint_decode({})) {
        printf("FAIL: varint_decode({}) should return nullopt\n");
        failed++;
    }

    // Edge: truncated decode (2-byte value but only 1 byte)
    uint8_t partial[] = {0x40};  // prefix 01, needs 2 bytes
    if (varint_decode(partial)) {
        printf("FAIL: varint_decode with truncated data should return nullopt\n");
        failed++;
    }

    printf("[varint] %d failures\n", failed);
    return failed;
}

// ─── STRIDE frame tests ───

static int test_stride_frame_encode_decode() {
    int failed = 0;

    // Test 1: ClientToRelayDatagram frame
    {
        Datagram dg;
        // Fill dst with a known pattern
        for (size_t i = 0; i < PublicKey::kSize; i++) dg.dst.data()[i] = static_cast<uint8_t>(i);
        dg.ecn = EcnCodepoint::None;
        dg.contents = {0xDE, 0xAD, 0xBE, 0xEF};

        auto frame = encode_client_to_relay_datagram(dg);

        // Verify: VarInt(4) = 0x04 (1 byte) + payload(32+1+2+4=39 bytes) = 40 total
        if (frame.size() != 1 + 32 + 1 + 2 + 4) {
            printf("FAIL: ClientToRelay frame size = %zu, expected %zu\n",
                   frame.size(), 1 + 32 + 1 + 4);
            failed++;
        }
        if (frame[0] != 0x04) {
            printf("FAIL: FrameType byte = 0x%02x, expected 0x04\n", frame[0]);
            failed++;
        }

        // Decode back
        auto decoded_frame = decode_frame(frame);
        if (!decoded_frame) {
            printf("FAIL: decode_frame returned nullopt\n");
            failed++;
        } else {
            if (decoded_frame->type != FrameType::ClientToRelayDatagram) {
                printf("FAIL: decoded FrameType = %llu, expected 4\n",
                       static_cast<uint64_t>(decoded_frame->type));
                failed++;
            }
            auto decoded_dg = decode_datagram(decoded_frame->payload);
            if (!decoded_dg) {
                printf("FAIL: decode_datagram returned nullopt\n");
                failed++;
            } else {
                if (decoded_dg->dst.data()[0] != 0 ||
                    decoded_dg->dst.data()[31] != 31 ||
                    decoded_dg->ecn != EcnCodepoint::None ||
                    decoded_dg->contents != dg.contents) {
                    printf("FAIL: decoded datagram content mismatch\n");
                    failed++;
                }
            }
        }
    }

    // Test 2: RelayToClientDatagram with ECN
    {
        Datagram dg;
        dg.dst.data()[0] = 0xAA;
        dg.ecn = EcnCodepoint::Ce;
        dg.contents = {0x01, 0x02, 0x03};

        auto frame = encode_relay_to_client_datagram(dg);
        auto decoded = decode_frame(frame);
        if (!decoded || decoded->type != FrameType::RelayToClientDatagram) {
            printf("FAIL: RelayToClient decode failed\n");
            failed++;
        } else {
            auto dg2 = decode_datagram(decoded->payload);
            if (!dg2 || dg2->ecn != EcnCodepoint::Ce) {
                printf("FAIL: ECN mismatch, got %d expected 3\n",
                       dg2 ? static_cast<int>(dg2->ecn) : -1);
                failed++;
            }
        }
    }

    // Test 3: Ping/Pong
    {
        std::array<uint8_t, 8> ping_data = {1, 2, 3, 4, 5, 6, 7, 8};
        auto ping_frame = encode_ping(ping_data);
        // VarInt(9) = 0x09 (1 byte) + 8 bytes payload = 9 total
        if (ping_frame.size() != 9) {
            printf("FAIL: Ping frame size = %zu, expected 9\n", ping_frame.size());
            failed++;
        }
        if (ping_frame[0] != 0x09) {
            printf("FAIL: Ping FrameType = 0x%02x, expected 0x09\n", ping_frame[0]);
            failed++;
        }

        auto decoded = decode_frame(ping_frame);
        if (!decoded || decoded->type != FrameType::Ping) {
            printf("FAIL: Ping decode failed\n");
            failed++;
        } else {
            auto pp = decode_ping_pong_payload(decoded->payload);
            if (!pp) {
                printf("FAIL: Ping payload decode failed\n");
                failed++;
            } else {
                for (int i = 0; i < 8; i++) {
                    if (pp->data()[i] != ping_data[i]) {
                        printf("FAIL: Ping payload byte %d mismatch\n", i);
                        failed++;
                    }
                }
            }
        }

        // Pong round-trip
        auto pong_frame = encode_pong(ping_data);
        auto decoded_pong = decode_frame(pong_frame);
        if (!decoded_pong || decoded_pong->type != FrameType::Pong) {
            printf("FAIL: Pong decode failed\n");
            failed++;
        }
    }

    // Test 4: Datagram with segment_size (batched)
    {
        Datagram dg;
        for (size_t i = 0; i < PublicKey::kSize; i++) dg.dst.data()[i] = 0xFF;
        dg.ecn = EcnCodepoint::Ect0;
        dg.segment_size = 512;  // each segment is 512 bytes
        // contents = 3 segments of 512 = 1536 bytes (simulate)
        dg.contents.resize(1536, 0xAB);

        auto payload = encode_datagram(dg);
        // Expected: 32B EndpointId + 1B ECN + 2B SegmentSize + 1536B contents = 1571
        if (payload.size() != 32 + 1 + 2 + 1536) {
            printf("FAIL: Batched datagram payload size = %zu, expected 1571\n", payload.size());
            failed++;
        }

        auto dg2 = decode_datagram(payload);
        if (!dg2) {
            printf("FAIL: Batched datagram decode failed\n");
            failed++;
        } else {
            if (dg2->segment_size != 512) {
                printf("FAIL: segment_size = %d, expected 512\n", dg2->segment_size);
                failed++;
            }
            if (dg2->contents.size() != 1536) {
                printf("FAIL: contents size = %zu, expected 1536\n", dg2->contents.size());
                failed++;
            }
        }
    }

    // Test 5: EndpointGone frame
    {
        // EndpointGone has a VarInt EndpointId as payload
        auto frame = encode_frame(FrameType::EndpointGone, {});
        auto decoded = decode_frame(frame);
        if (!decoded || decoded->type != FrameType::EndpointGone) {
            printf("FAIL: EndpointGone decode failed\n");
            failed++;
        }
    }

    // Test 6: Datagram with empty contents (still has 35-byte fixed header)
    {
        Datagram dg;
        dg.contents.clear();
        auto payload = encode_datagram(dg);
        // 32B EndpointId + 1B ECN + 2B SegmentSize = 35 bytes, no contents
        if (payload.size() != 35) {
            printf("FAIL: empty datagram payload size = %zu, expected 35\n", payload.size());
            failed++;
        }
        auto dg2 = decode_datagram(payload);
        if (!dg2 || !dg2->contents.empty()) {
            printf("FAIL: empty contents datagram decode failed\n");
            failed++;
        }
    }

    printf("[stride] %d failures\n", failed);
    return failed;
}

// ─── Round-trip stress test ───

static int test_varint_roundtrip() {
    int failed = 0;
    // Test a range of values
    uint64_t values[] = {
        0, 1, 2, 63, 64, 65, 127, 128, 16383, 16384,
        32768, 1073741823, 1073741824ULL,
        (1ULL << 40), (1ULL << 62) - 1,
    };
    for (auto v : values) {
        auto enc = varint_encode_vec(v);
        auto dec = varint_decode(enc);
        if (!dec || dec->first != v) {
            printf("FAIL: roundtrip varint(%llu) → decode = %s\n",
                   v, dec ? "wrong" : "nullopt");
            failed++;
        }
    }
    printf("[varint_roundtrip] %d failures\n", failed);
    return failed;
}

int main() {
    int total = 0;
    total += test_varint_encode_decode();
    total += test_varint_roundtrip();
    total += test_stride_frame_encode_decode();

    if (total == 0) {
        printf("\n=== ALL STRIDE/VARINT TESTS PASSED ===\n");
    } else {
        printf("\n=== %d TESTS FAILED ===\n", total);
    }
    return total;
}
