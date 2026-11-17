// test_auth_handshake.cpp — Relay auth handshake codec tests
//
// Tests:
// 1. ServerChallenge encode/decode roundtrip
// 2. ClientAuth encode/decode roundtrip
// 3. Challenge signing + verification (using real Ed25519)
// 4. ServerDeniesAuth decode
// 5. STRIDE frame integration (auth frames wrapped in STRIDE + WebSocket)

#include "linoh/relay/auth.hpp"
#include "linoh/relay/stride.hpp"
#include "linoh/relay/ws_client.hpp"
#include "linoh/base/key.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace linoh::relay;
using namespace linoh::base;

int main() {
    int failed = 0;

    // ─── Test 1: ServerChallenge decode ───
    printf("Test 1: ServerChallenge decode\n");
    {
        ServerChallenge sc;
        for (int i = 0; i < 32; i++) sc.challenge[i] = static_cast<uint8_t>(i + 100);

        // Encode as STRIDE frame
        std::vector<uint8_t> payload(sc.challenge.begin(), sc.challenge.end());
        auto frame = encode_frame(FrameType::ServerChallenge, payload);

        // Decode STRIDE frame type
        auto decoded = decode_frame(frame);
        if (!decoded || decoded->type != FrameType::ServerChallenge) {
            printf("FAIL: ServerChallenge STRIDE frame decode\n");
            failed++;
        } else {
            // Decode challenge payload
            auto sc2 = decode_server_challenge(decoded->payload);
            if (!sc2) {
                printf("FAIL: ServerChallenge payload decode returned null\n");
                failed++;
            } else {
                for (int i = 0; i < 32; i++) {
                    if (sc2->challenge[i] != static_cast<uint8_t>(i + 100)) {
                        printf("FAIL: ServerChallenge byte %d mismatch\n", i);
                        failed++;
                        break;
                    }
                }
            }
        }
    }

    // ─── Test 2: ClientAuth encode/decode roundtrip ───
    printf("Test 2: ClientAuth encode/decode\n");
    {
        SecretKey sk = SecretKey::generate();
        PublicKey pk = sk.public_key();

        // Create a challenge
        ServerChallenge sc;
        for (int i = 0; i < 32; i++) sc.challenge[i] = static_cast<uint8_t>(42 + i);

        // Sign it
        auto auth = sign_challenge(sc, sk);

        // Verify EndpointId matches public key
        if (auth.endpoint_id != pk) {
            printf("FAIL: ClientAuth endpoint_id doesn't match public key\n");
            failed++;
        }

        // Encode and decode ClientAuth
        auto encoded = encode_client_auth(auth);
        auto stride = decode_frame(encoded);
        if (!stride || stride->type != FrameType::ClientAuth) {
            printf("FAIL: ClientAuth STRIDE frame type mismatch\n");
            failed++;
        } else {
            auto decoded = decode_client_auth(stride->payload);
            if (!decoded) {
                printf("FAIL: ClientAuth decode returned null\n");
                failed++;
            } else {
                // Verify decoded EndpointId matches
                if (decoded->endpoint_id != pk) {
                    printf("FAIL: decoded endpoint_id mismatch\n");
                    failed++;
                }
                // Verify decoded signature bytes match
                for (int i = 0; i < 64; i++) {
                    if (decoded->signature.data()[i] != auth.signature.data()[i]) {
                        printf("FAIL: decoded signature byte %d mismatch\n", i);
                        failed++;
                        break;
                    }
                }
            }
        }
    }

    // ─── Test 3: Challenge signing + Ed25519 verification ───
    printf("Test 3: Challenge signing + Ed25519 verification\n");
    {
        SecretKey sk = SecretKey::generate();

        // Create multiple different challenges
        for (int round = 0; round < 3; round++) {
            ServerChallenge sc;
            // Different challenge each round
            sc.challenge[0] = static_cast<uint8_t>(round);
            sc.challenge[1] = static_cast<uint8_t>(round + 1);

            auto auth = sign_challenge(sc, sk);

            // Verify with correct challenge
            if (!verify_client_auth(auth, sc)) {
                printf("FAIL: round %d — correct challenge should verify\n", round);
                failed++;
            }

            // Verify with wrong challenge should fail
            ServerChallenge wrong_sc;
            wrong_sc.challenge[0] = 0xFF;
            wrong_sc.challenge[1] = 0xFF;
            if (verify_client_auth(auth, wrong_sc)) {
                printf("FAIL: round %d — wrong challenge should NOT verify\n", round);
                failed++;
            }
        }
    }

    // ─── Test 4: Domain separation prevents cross-protocol attacks ───
    printf("Test 4: Domain separation\n");
    {
        SecretKey sk = SecretKey::generate();
        ServerChallenge sc;
        for (int i = 0; i < 32; i++) sc.challenge[i] = static_cast<uint8_t>(i);

        auto msg = create_challenge_message(sc);
        // Verify the message starts with the domain prefix
        std::string prefix(msg.begin(), msg.begin() + kChallengeDomainPrefix.size());
        if (prefix != kChallengeDomainPrefix) {
            printf("FAIL: domain prefix mismatch: got '%s'\n", prefix.c_str());
            failed++;
        }
        // Verify the message ends with the challenge
        for (int i = 0; i < 32; i++) {
            if (msg[msg.size() - 32 + i] != sc.challenge[i]) {
                printf("FAIL: challenge bytes not appended correctly\n");
                failed++;
                break;
            }
        }
    }

    // ─── Test 5: ServerDeniesAuth decode ───
    printf("Test 5: ServerDeniesAuth decode\n");
    {
        // With reason string
        std::string reason = "access denied: invalid token";
        std::vector<uint8_t> payload(reason.begin(), reason.end());
        auto deny = decode_server_denies(payload);
        if (deny.reason != reason) {
            printf("FAIL: ServerDeniesAuth reason mismatch\n");
            failed++;
        }

        // Without reason (empty payload)
        std::vector<uint8_t> empty_payload;
        auto deny2 = decode_server_denies(empty_payload);
        if (!deny2.reason.empty()) {
            printf("FAIL: ServerDeniesAuth empty reason should be empty\n");
            failed++;
        }
    }

    // ─── Test 6: Full WebSocket + STRIDE + Auth roundtrip ───
    printf("Test 6: Full WS+STRIDE+Auth roundtrip\n");
    {
        SecretKey sk = SecretKey::generate();
        ServerChallenge sc;
        for (int i = 0; i < 32; i++) sc.challenge[i] = static_cast<uint8_t>(i * 3);

        // Build ServerChallenge STRIDE frame, wrap in WS binary frame
        std::vector<uint8_t> challenge_payload(sc.challenge.begin(), sc.challenge.end());
        auto challenge_stride = encode_frame(FrameType::ServerChallenge, challenge_payload);
        auto challenge_ws = ws_encode_binary_frame(challenge_stride);

        // Decode: WS frame → STRIDE frame → challenge
        auto ws_decoded = ws_decode_frame(
            std::span<const uint8_t>(challenge_ws.data(), challenge_ws.size()));
        if (!ws_decoded.ok) {
            printf("FAIL: WS decode of ServerChallenge\n");
            failed++;
        } else {
            auto &ws_frame = ws_decoded.frame;
            auto stride = decode_frame(ws_frame.payload);
            if (!stride || stride->type != FrameType::ServerChallenge) {
                printf("FAIL: STRIDE decode of ServerChallenge\n");
                failed++;
            } else {
                auto sc_decoded = decode_server_challenge(stride->payload);
                if (!sc_decoded) {
                    printf("FAIL: challenge payload decode\n");
                    failed++;
                } else {
                    // Sign it
                    auto auth = sign_challenge(*sc_decoded, sk);
                    auto auth_stride = encode_client_auth(auth);
                    auto auth_ws = ws_encode_binary_frame(auth_stride);

                    // Decode the ClientAuth response
                    auto auth_ws_decoded = ws_decode_frame(
                        std::span<const uint8_t>(auth_ws.data(), auth_ws.size()));
                    if (!auth_ws_decoded.ok) {
                        printf("FAIL: WS decode of ClientAuth\n");
                        failed++;
                    } else {
                        auto auth_stride_decoded = decode_frame(auth_ws_decoded.frame.payload);
                        if (!auth_stride_decoded || auth_stride_decoded->type != FrameType::ClientAuth) {
                            printf("FAIL: STRIDE decode of ClientAuth\n");
                            failed++;
                        } else {
                            auto auth_decoded = decode_client_auth(auth_stride_decoded->payload);
                            if (!auth_decoded || !verify_client_auth(*auth_decoded, *sc_decoded)) {
                                printf("FAIL: ClientAuth verify failed\n");
                                failed++;
                            }
                        }
                    }
                }
            }
        }
    }

    // ─── Summary ───
    if (failed == 0) {
        printf("\nALL AUTH HANDSHAKE TESTS PASSED!\n");
    } else {
        printf("\nFAILED: %d tests\n", failed);
    }
    return failed;
}
