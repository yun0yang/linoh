// test_p2p_stack.cpp — P2P protocol stack integration test
//
// Validates the complete protocol stack without network:
// 1. EndpointId generation + Ed25519 signing
// 2. Pkarr DNS wire format: build + sign + verify
// 3. VarInt → STRIDE → WebSocket → Auth full roundtrip
// 4. Relay Client simulated handshake (challenge → sign → confirm)
// 5. BootstrapConfig + Endpoint Builder
//
// This test verifies that all protocol modules work together correctly,
// even though actual network connectivity requires real Asio + TLS.

#include "linoh/address_lookup/pkarr_dns.hpp"
#include "linoh/base/key.hpp"
#include "linoh/endpoint/builder.hpp"
#include "linoh/relay/auth.hpp"
#include "linoh/relay/stride.hpp"
#include "linoh/relay/ws_client.hpp"
#include "linoh/util/varint.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace linoh;
using namespace linoh::base;
using namespace linoh::relay;
using namespace linoh::address_lookup::pkarr;

int main() {
    int failed = 0;

    printf("=== P2P Protocol Stack Integration Test ===\n\n");

    // ─── Phase A: Identity & Keys ───
    printf("Phase A: Identity & Keys\n");
    {
        SecretKey sk_a = SecretKey::generate();
        SecretKey sk_b = SecretKey::generate();
        EndpointId id_a = sk_a.public_key();
        EndpointId id_b = sk_b.public_key();

        printf("  Node A: %s\n", id_a.fmt_short().c_str());
        printf("  Node B: %s\n", id_b.fmt_short().c_str());

        // Ed25519 signing roundtrip
        std::vector<uint8_t> msg = {1, 2, 3, 4, 5};
        auto sig_a = sk_a.sign(msg);
        Signature s(sig_a);
        if (!s.verify(msg, id_a)) {
            printf("FAIL: Node A signature verification\n");
            failed++;
        }
        if (s.verify(msg, id_b)) {
            printf("FAIL: Node A signature should NOT verify with Node B key\n");
            failed++;
        }
    }

    // ─── Phase B: Pkarr Address Publishing ───
    printf("Phase B: Pkarr Address Publishing\n");
    {
        SecretKey sk = SecretKey::generate();
        EndpointId node_id = sk.public_key();

        // Build DNS packet with relay + direct address
        auto packet = build_pkarr_dns_packet(
            node_id,
            {"relay.iroh.link"}, {443},
            {"127.0.0.1:54321"});

        printf("  DNS packet size: %u bytes\n", static_cast<unsigned>(packet.size()));

        // Sign and verify
        auto signed_pkt = sign_dns_packet(packet, sk);
        if (!verify_signed_packet(signed_pkt, node_id)) {
            printf("FAIL: Pkarr signed packet verification\n");
            failed++;
        }

        // Serialize and deserialize
        auto serialized = serialize_signed_packet(signed_pkt);
        auto deserialized = deserialize_signed_packet(
            std::span<const uint8_t>(serialized.data(), serialized.size()));
        if (!deserialized || !verify_signed_packet(*deserialized, node_id)) {
            printf("FAIL: Pkarr roundtrip verification\n");
            failed++;
        }
    }

    // ─── Phase C: Relay Protocol Stack ───
    printf("Phase C: Relay Protocol Stack (VarInt → STRIDE → WebSocket → Auth)\n");
    {
        SecretKey sk = SecretKey::generate();
        EndpointId node_id = sk.public_key();

        // Step 1: Server sends challenge (STRIDE frame in WS binary frame)
        ServerChallenge sc;
        for (int i = 0; i < 32; i++) sc.challenge[i] = static_cast<uint8_t>(i + 42);
        std::vector<uint8_t> challenge_payload(sc.challenge.begin(), sc.challenge.end());
        auto challenge_stride = encode_frame(FrameType::ServerChallenge, challenge_payload);
        auto challenge_ws = ws_encode_binary_frame(challenge_stride);

        printf("  ServerChallenge: %u bytes (WS frame)\n",
               static_cast<unsigned>(challenge_ws.size()));

        // Step 2: Client decodes challenge, signs, sends ClientAuth
        auto ws_decoded = ws_decode_frame(
            std::span<const uint8_t>(challenge_ws.data(), challenge_ws.size()));
        if (!ws_decoded.ok) {
            printf("FAIL: WS decode of ServerChallenge\n");
            failed++;
            goto phase_d;
        }

        auto stride_decoded = decode_frame(ws_decoded.frame.payload);
        if (!stride_decoded || stride_decoded->type != FrameType::ServerChallenge) {
            printf("FAIL: STRIDE decode of ServerChallenge\n");
            failed++;
            goto phase_d;
        }

        auto sc_decoded = decode_server_challenge(stride_decoded->payload);
        if (!sc_decoded) {
            printf("FAIL: ServerChallenge payload decode\n");
            failed++;
            goto phase_d;
        }

        // Sign and encode ClientAuth
        auto auth = sign_challenge(*sc_decoded, sk);
        auto auth_stride = encode_client_auth(auth);
        auto auth_ws = ws_encode_binary_frame(auth_stride);

        printf("  ClientAuth: %u bytes (WS frame)\n",
               static_cast<unsigned>(auth_ws.size()));

        // Step 3: Server decodes ClientAuth, verifies signature
        auto auth_ws_decoded = ws_decode_frame(
            std::span<const uint8_t>(auth_ws.data(), auth_ws.size()));
        if (!auth_ws_decoded.ok) {
            printf("FAIL: WS decode of ClientAuth\n");
            failed++;
            goto phase_d;
        }

        auto auth_stride_decoded = decode_frame(auth_ws_decoded.frame.payload);
        if (!auth_stride_decoded || auth_stride_decoded->type != FrameType::ClientAuth) {
            printf("FAIL: STRIDE decode of ClientAuth\n");
            failed++;
            goto phase_d;
        }

        auto auth_decoded = decode_client_auth(auth_stride_decoded->payload);
        if (!auth_decoded) {
            printf("FAIL: ClientAuth payload decode\n");
            failed++;
            goto phase_d;
        }

        // Verify authentication
        if (!verify_client_auth(*auth_decoded, *sc_decoded)) {
            printf("FAIL: ClientAuth signature verification\n");
            failed++;
            goto phase_d;
        }

        printf("  Auth verified: EndpointId=%s\n", auth_decoded->endpoint_id.fmt_short().c_str());

        // Step 4: Server sends ServerConfirmsAuth
        auto confirm_stride = encode_frame(FrameType::ServerConfirmsAuth, {});
        auto confirm_ws = ws_encode_binary_frame(confirm_stride);

        printf("  ServerConfirmsAuth: %u bytes\n",
               static_cast<unsigned>(confirm_ws.size()));

        // Step 5: Client sends a datagram via relay
        Datagram dg;
        // Fake peer ID (32 bytes)
        std::array<uint8_t, 32> fake_peer{};
        for (int i = 0; i < 32; i++) fake_peer[i] = static_cast<uint8_t>(i);
        dg.dst = EndpointId(fake_peer);
        dg.ecn = EcnCodepoint::None;
        dg.contents = {0x01, 0x02, 0x03, 0x04};
        auto datagram_stride = encode_client_to_relay_datagram(dg);
        auto datagram_ws = ws_encode_binary_frame(datagram_stride);

        printf("  ClientToRelayDatagram: %u bytes\n",
               static_cast<unsigned>(datagram_ws.size()));

        // Verify datagram can be decoded
        auto dg_ws_decoded = ws_decode_frame(
            std::span<const uint8_t>(datagram_ws.data(), datagram_ws.size()));
        if (!dg_ws_decoded.ok) {
            printf("FAIL: WS decode of datagram\n");
            failed++;
            goto phase_d;
        }

        auto dg_stride_decoded = decode_frame(dg_ws_decoded.frame.payload);
        if (!dg_stride_decoded || dg_stride_decoded->type != FrameType::ClientToRelayDatagram) {
            printf("FAIL: STRIDE decode of datagram\n");
            failed++;
            goto phase_d;
        }

        auto dg_decoded = decode_datagram(dg_stride_decoded->payload);
        if (!dg_decoded || dg_decoded->contents.size() != 4) {
            printf("FAIL: datagram decode\n");
            failed++;
            goto phase_d;
        }
    }

phase_d:
    // ─── Phase D: BootstrapConfig & Builder ───
    printf("Phase D: BootstrapConfig & Builder\n");
    {
        // Build a complete BootstrapConfig
        endpoint::BootstrapConfig bootstrap;
        bootstrap.relay_urls.push_back(RelayUrl("https://relay1.iroh.link/"));
        bootstrap.relay_urls.push_back(RelayUrl("https://relay2.iroh.link/"));
        bootstrap.dns_urls.push_back("https://dns.iroh.link/dns-query");
        bootstrap.known_nodes.push_back(SecretKey::generate().public_key());
        bootstrap.auto_connect = true;

        printf("  Relay URLs: %u\n", static_cast<unsigned>(bootstrap.relay_urls.size()));
        printf("  DNS URLs: %u\n", static_cast<unsigned>(bootstrap.dns_urls.size()));
        printf("  Known nodes: %u\n", static_cast<unsigned>(bootstrap.known_nodes.size()));

        // Verify config can be created through Builder API
        endpoint::Endpoint::Config cfg;
        cfg.secret_key = SecretKey::generate();
        cfg.alpns = {"echo/1"};
        cfg.bootstrap = bootstrap;

        printf("  Config: node_id=%s, alpns=%u\n",
               cfg.secret_key.public_key().fmt_short().c_str(),
               static_cast<unsigned>(cfg.alpns.size()));

        // Verify BootstrapConfig fields
        if (cfg.bootstrap.relay_urls.size() != 2) {
            printf("FAIL: relay_urls count\n");
            failed++;
        }
        if (cfg.bootstrap.dns_urls.size() != 1) {
            printf("FAIL: dns_urls count\n");
            failed++;
        }
        if (cfg.bootstrap.known_nodes.size() != 1) {
            printf("FAIL: known_nodes count\n");
            failed++;
        }
        if (!cfg.bootstrap.auto_connect) {
            printf("FAIL: auto_connect should be true\n");
            failed++;
        }

        // Verify Builder chain compiles and links (API validation)
        SecretKey sk = SecretKey::generate();
        endpoint::Builder builder;
        builder.secret_key(sk)
                .alpns({"test/1"})
                .add_relay_url(RelayUrl("https://relay3.iroh.link/"))
                .add_dns_url("https://dns3.iroh.link/dns-query")
                .add_known_node(SecretKey::generate().public_key())
                .no_auto_connect();

        printf("  Builder API chain: OK (compiled and linked)\n");
    }

    // ─── Summary ───
    if (failed == 0) {
        printf("\n=== ALL P2P STACK INTEGRATION TESTS PASSED ===\n");
    } else {
        printf("\n=== FAILED: %d tests ===\n", failed);
    }
    return failed;
}
