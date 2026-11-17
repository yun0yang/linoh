// linoh/relay/auth.hpp — iroh relay v2 authentication handshake
//
// Authentication protocol (challenge-response):
// 1. After WebSocket upgrade, server sends ServerChallenge (FrameType=0):
//    [VarInt(0)][Challenge bytes (32B random)]
// 2. Client signs: domain_prefix + challenge, sends ClientAuth (FrameType=1):
//    [VarInt(1)][EndpointId(32B)][Signature(64B)]
// 3. Server verifies signature, sends ServerConfirmsAuth (FrameType=2)
//    or ServerDeniesAuth (FrameType=3).
//
// Domain separation prefix: "iroh-relay handshake v1 challenge signature"
// This prevents the relay from requesting arbitrary signatures.
//
// Reference: iroh-relay/src/protos/handshake.rs
// https://deepwiki.com/n0-computer/iroh/6.5-authentication-and-access-control

#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "linoh/base/key.hpp"       // EndpointId, SecretKey, Signature
#include "linoh/relay/stride.hpp"    // FrameType, Frame, decode_frame

namespace linoh::relay {

// ─── Constants ───

/// Domain separation prefix for challenge-response signatures.
/// Prevents relay from requesting arbitrary signatures.
constexpr std::string_view kChallengeDomainPrefix =
    "iroh-relay handshake v1 challenge signature";

/// Domain separation label for TLS keying material authentication.
constexpr std::string_view kTlsKeyMaterialLabel =
    "iroh-relay handshake v1";

/// Challenge size: 32 bytes of random data from the server.
constexpr std::size_t kChallengeSize = 32;

// ─── Auth frame payloads ───

/// ServerChallenge payload: 32 bytes of random challenge data.
struct ServerChallenge {
    std::array<uint8_t, kChallengeSize> challenge{};
};

/// ClientAuth payload: [EndpointId(32B)][Signature(64B)]
struct ClientAuth {
    base::EndpointId endpoint_id;
    base::Signature signature;
};

/// ServerConfirmsAuth payload: empty (just the frame type).
struct ServerConfirmsAuth {};

/// ServerDeniesAuth payload: optional reason string.
struct ServerDeniesAuth {
    std::string reason;
};

// ─── Encoder ───

/// Encode a ClientAuth frame: [VarInt(1)][EndpointId(32B)][Signature(64B)]
inline std::vector<uint8_t> encode_client_auth(const ClientAuth &auth) {
    std::vector<uint8_t> payload;
    payload.reserve(base::PublicKey::kSize + base::Signature::kSize);
    // EndpointId: 32 bytes
    payload.insert(payload.end(), auth.endpoint_id.data(),
                   auth.endpoint_id.data() + base::PublicKey::kSize);
    // Signature: 64 bytes
    payload.insert(payload.end(), auth.signature.data(),
                   auth.signature.data() + base::Signature::kSize);
    return encode_frame(FrameType::ClientAuth, payload);
}

// ─── Decoder ───

/// Decode a ServerChallenge frame payload (32 bytes).
inline std::optional<ServerChallenge> decode_server_challenge(
    std::span<const uint8_t> payload) {
    if (payload.size() < kChallengeSize) return std::nullopt;
    ServerChallenge sc;
    std::memcpy(sc.challenge.data(), payload.data(), kChallengeSize);
    return sc;
}

/// Decode a ClientAuth frame payload (32B EndpointId + 64B Signature).
inline std::optional<ClientAuth> decode_client_auth(
    std::span<const uint8_t> payload) {
    const std::size_t kExpected = base::PublicKey::kSize + base::Signature::kSize;
    if (payload.size() < kExpected) return std::nullopt;
    ClientAuth ca;
    std::memcpy(const_cast<uint8_t*>(ca.endpoint_id.data()), payload.data(), base::PublicKey::kSize);
    std::memcpy(const_cast<uint8_t*>(ca.signature.data()), payload.data() + base::PublicKey::kSize,
                base::Signature::kSize);
    return ca;
}

/// Decode a ServerDeniesAuth frame payload (optional reason string).
inline ServerDeniesAuth decode_server_denies(std::span<const uint8_t> payload) {
    ServerDeniesAuth sda;
    if (!payload.empty()) {
        sda.reason = std::string(payload.begin(), payload.end());
    }
    return sda;
}

// ─── Challenge signing ───

/// Create the signed message for challenge-response auth.
/// Format: [domain_prefix][challenge_bytes]
/// The domain prefix prevents the relay from requesting arbitrary signatures.
inline std::vector<uint8_t> create_challenge_message(
    const ServerChallenge &challenge) {
    std::vector<uint8_t> msg;
    // Domain prefix as raw bytes (UTF-8)
    msg.insert(msg.end(), kChallengeDomainPrefix.begin(),
               kChallengeDomainPrefix.end());
    // Challenge bytes
    msg.insert(msg.end(), challenge.challenge.begin(),
               challenge.challenge.end());
    return msg;
}

/// Sign a server challenge using the endpoint's secret key.
/// Returns a ClientAuth struct ready to be encoded and sent.
inline ClientAuth sign_challenge(const ServerChallenge &challenge,
                                 const base::SecretKey &secret_key) {
    auto msg = create_challenge_message(challenge);
    auto sig = secret_key.sign(msg);

    ClientAuth auth;
    auth.endpoint_id = secret_key.public_key();
    auth.signature = base::Signature(sig);
    return auth;
}

/// Verify a ClientAuth response against the server challenge.
/// Returns true if the Ed25519 signature is valid.
inline bool verify_client_auth(const ClientAuth &auth,
                               const ServerChallenge &challenge) {
    auto msg = create_challenge_message(challenge);
    return auth.signature.verify(msg, auth.endpoint_id);
}

// ─── Auth result ───

enum class AuthResult {
    Confirmed,   // ServerConfirmsAuth received
    Denied,      // ServerDeniesAuth received
    Timeout,     // No response within timeout
    Error,       // Protocol error
};

}  // namespace linoh::relay
