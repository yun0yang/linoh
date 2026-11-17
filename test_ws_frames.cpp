// test_ws_frames.cpp — WebSocket frame codec unit tests
//
// Validates:
// 1. Binary frame encode/decode (masked client frames)
// 2. Ping frame encode/decode
// 3. Unmasked server frame decode
// 4. Handshake request/response validation
// 5. Fragmented/extended-length frames

#include <cstdio>
#include <cstring>
#include <array>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "linoh/relay/ws_client.hpp"

using namespace linoh::relay;

// ─── Binary frame round-trip ───

static int test_binary_frame_roundtrip() {
    int failed = 0;

    // Test small payload (< 126 bytes)
    {
        std::vector<uint8_t> payload = {0x04, 0x00, 0x01, 0x02, 0x03};
        auto frame = ws_encode_binary_frame(payload);

        // Decode (client frame is masked, decoder handles unmasking)
        auto decoded = ws_decode_frame(frame);
        if (!decoded.ok) {
            printf("FAIL: small binary frame decode returned nullopt\n");
            failed++;
        } else {
            auto &wsf = decoded.frame;
            if (wsf.opcode != WsOpcode::Binary) {
                printf("FAIL: opcode = %d, expected Binary(2)\n", static_cast<int>(wsf.opcode));
                failed++;
            }
            if (!wsf.fin) {
                printf("FAIL: fin = false, expected true\n");
                failed++;
            }
            if (wsf.payload != payload) {
                printf("FAIL: payload mismatch, size=%zu expected=%zu\n",
                       wsf.payload.size(), payload.size());
                failed++;
            }
        }
    }

    // Test medium payload (126 bytes — triggers 16-bit length encoding)
    {
        std::vector<uint8_t> payload(126, 0xAB);
        auto frame = ws_encode_binary_frame(payload);
        auto decoded = ws_decode_frame(frame);
        if (!decoded.ok || decoded.frame.payload.size() != 126) {
            printf("FAIL: 126-byte payload decode failed, size=%zu\n",
                   decoded.ok ? decoded.frame.payload.size() : 0);
            failed++;
        }
        if (decoded.ok && decoded.frame.payload[0] != 0xAB) {
            printf("FAIL: 126-byte payload content mismatch\n");
            failed++;
        }
    }

    // Test larger payload (300 bytes)
    {
        std::vector<uint8_t> payload(300);
        for (size_t i = 0; i < 300; i++) payload[i] = static_cast<uint8_t>(i & 0xFF);
        auto frame = ws_encode_binary_frame(payload);
        auto decoded = ws_decode_frame(frame);
        if (!decoded.ok || decoded.frame.payload.size() != 300) {
            printf("FAIL: 300-byte payload decode failed\n");
            failed++;
        } else {
            for (size_t i = 0; i < 300; i++) {
                if (decoded.frame.payload[i] != (i & 0xFF)) {
                    printf("FAIL: 300-byte payload byte %zu mismatch\n", i);
                    failed++;
                    break;
                }
            }
        }
    }

    // Test empty payload
    {
        std::vector<uint8_t> payload;
        auto frame = ws_encode_binary_frame(payload);
        auto decoded = ws_decode_frame(frame);
        if (!decoded.ok || decoded.frame.opcode != WsOpcode::Binary || !decoded.frame.fin) {
            printf("FAIL: empty binary frame decode failed\n");
            failed++;
        }
        if (decoded.ok && !decoded.frame.payload.empty()) {
            printf("FAIL: empty payload should have no data\n");
            failed++;
        }
    }

    printf("[binary_frame] %d failures\n", failed);
    return failed;
}

// ─── Ping frame round-trip ───

static int test_ping_frame() {
    int failed = 0;

    // Ping with 8-byte payload
    {
        std::array<uint8_t, 8> ping_data = {1, 2, 3, 4, 5, 6, 7, 8};
        auto frame = ws_encode_ping_frame(ping_data);
        auto decoded = ws_decode_frame(frame);
        if (!decoded.ok) {
            printf("FAIL: Ping frame decode nullopt\n");
            failed++;
        } else {
            if (decoded.frame.opcode != WsOpcode::Ping) {
                printf("FAIL: Ping opcode = %d, expected 9\n",
                       static_cast<int>(decoded.frame.opcode));
                failed++;
            }
            if (decoded.frame.payload.size() != 8) {
                printf("FAIL: Ping payload size = %zu, expected 8\n",
                       decoded.frame.payload.size());
                failed++;
            }
            for (int i = 0; i < 8; i++) {
                if (decoded.frame.payload[i] != ping_data[i]) {
                    printf("FAIL: Ping payload byte %d mismatch\n", i);
                    failed++;
                }
            }
        }
    }

    // Empty Ping (no payload)
    {
        auto frame = ws_encode_ping_frame();
        auto decoded = ws_decode_frame(frame);
        if (!decoded.ok || decoded.frame.opcode != WsOpcode::Ping) {
            printf("FAIL: Empty Ping decode failed\n");
            failed++;
        }
        if (decoded.ok && !decoded.frame.payload.empty()) {
            printf("FAIL: Empty Ping should have no payload\n");
            failed++;
        }
    }

    printf("[ping_frame] %d failures\n", failed);
    return failed;
}

// ─── Unmasked server frame decode ───

static int test_unmasked_server_frame() {
    int failed = 0;

    // Server sends unmasked binary frame with 5 bytes
    // RFC 6455: server frames are NOT masked
    {
        std::vector<uint8_t> raw = {
            0x82,  // FIN=1, opcode=Binary
            0x05,  // MASK=0, payload_len=5
            0x04, 0x00, 0x01, 0x02, 0x03  // payload (STRIDE frame type 4 + data)
        };
        auto decoded = ws_decode_frame(raw);
        if (!decoded.ok) {
            printf("FAIL: unmasked server frame decode nullopt\n");
            failed++;
        } else {
            if (decoded.frame.opcode != WsOpcode::Binary) {
                printf("FAIL: unmasked opcode = %d, expected 2\n",
                       static_cast<int>(decoded.frame.opcode));
                failed++;
            }
            if (decoded.frame.payload.size() != 5) {
                printf("FAIL: unmasked payload size = %zu, expected 5\n",
                       decoded.frame.payload.size());
                failed++;
            }
            // Content should be unchanged (no masking)
            if (decoded.frame.payload[0] != 0x04) {
                printf("FAIL: unmasked payload byte 0 = 0x%02x, expected 0x04\n",
                       decoded.frame.payload[0]);
                failed++;
            }
        }
    }

    // Server sends unmasked Pong with 8 bytes
    {
        std::vector<uint8_t> raw = {
            0x8A,  // FIN=1, opcode=Pong(0xA)
            0x08,  // MASK=0, payload_len=8
            1, 2, 3, 4, 5, 6, 7, 8
        };
        auto decoded = ws_decode_frame(raw);
        if (!decoded.ok || decoded.frame.opcode != WsOpcode::Pong) {
            printf("FAIL: unmasked Pong decode failed\n");
            failed++;
        }
    }

    printf("[unmasked] %d failures\n", failed);
    return failed;
}

// ─── Handshake validation ───

static int test_handshake() {
    int failed = 0;

    // Build handshake request
    {
        auto req = ws_build_handshake_request("relay.iroh.network", "/", "443");
        if (req.find("GET / HTTP/1.1") == std::string::npos) {
            printf("FAIL: handshake request missing GET line\n");
            failed++;
        }
        if (req.find("Host: relay.iroh.network:443") == std::string::npos) {
            printf("FAIL: handshake request missing Host header\n");
            failed++;
        }
        if (req.find("Upgrade: websocket") == std::string::npos) {
            printf("FAIL: handshake request missing Upgrade header\n");
            failed++;
        }
        if (req.find("Sec-WebSocket-Protocol: iroh-relay-v2") == std::string::npos) {
            printf("FAIL: handshake request missing Sec-WebSocket-Protocol\n");
            failed++;
        }
        if (req.find("Sec-WebSocket-Version: 13") == std::string::npos) {
            printf("FAIL: handshake request missing Sec-WebSocket-Version\n");
            failed++;
        }
    }

    // Validate good handshake response
    {
        std::string resp_str = "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                                "\r\n";
        std::vector<uint8_t> resp(resp_str.begin(), resp_str.end());
        if (!ws_validate_handshake_response(resp)) {
            printf("FAIL: valid handshake response rejected\n");
            failed++;
        }
    }

    // Reject non-101 response
    {
        std::string resp_str = "HTTP/1.1 404 Not Found\r\n\r\n";
        std::vector<uint8_t> resp(resp_str.begin(), resp_str.end());
        if (ws_validate_handshake_response(resp)) {
            printf("FAIL: 404 response should be rejected\n");
            failed++;
        }
    }

    // HTTP header end detection
    {
        std::string resp_str = "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "\r\n";
        std::vector<uint8_t> resp(resp_str.begin(), resp_str.end());
        auto end = ws_http_header_end(resp);
        if (end == 0) {
            printf("FAIL: http_header_end returned 0 for complete headers\n");
            failed++;
        }
        if (end != resp.size()) {
            printf("FAIL: http_header_end = %zu, expected %zu\n", end, resp.size());
            failed++;
        }
    }

    // Incomplete headers
    {
        std::string partial = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n";
        std::vector<uint8_t> p(partial.begin(), partial.end());
        if (ws_http_header_end(p) != 0) {
            printf("FAIL: http_header_end should return 0 for incomplete headers\n");
            failed++;
        }
    }

    printf("[handshake] %d failures\n", failed);
    return failed;
}

// ─── Incomplete frame data ───

static int test_incomplete_frames() {
    int failed = 0;

    // Too short (1 byte)
    {
        uint8_t data[] = {0x82};
        auto decoded = ws_decode_frame(data);
        if (decoded.ok) {
            printf("FAIL: 1-byte data should not decode (need_more)\n");
            failed++;
        }
        if (!decoded.need_more) {
            printf("FAIL: 1-byte data should set need_more=true\n");
            failed++;
        }
    }

    // Complete header but missing payload
    {
        uint8_t data[] = {0x82, 0x85};  // FIN=1, Binary, MASK=1, len=5
        auto decoded = ws_decode_frame(data);
        if (decoded.ok) {
            printf("FAIL: incomplete payload should not decode (need_more)\n");
            failed++;
        }
        if (!decoded.need_more) {
            printf("FAIL: incomplete payload should set need_more=true\n");
            failed++;
        }
    }

    printf("[incomplete] %d failures\n", failed);
    return failed;
}

int main() {
    int total = 0;
    total += test_binary_frame_roundtrip();
    total += test_ping_frame();
    total += test_unmasked_server_frame();
    total += test_handshake();
    total += test_incomplete_frames();

    if (total == 0) {
        printf("\n=== ALL WEBSOCKET FRAME TESTS PASSED ===\n");
    } else {
        printf("\n=== %d TESTS FAILED ===\n", total);
    }
    return total;
}
