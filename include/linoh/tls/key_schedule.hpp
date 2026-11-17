#pragma once

// TLS 1.3 key schedule (RFC 8446 §7.1) adapted for QUIC (RFC 9001 §5.1).
//
// Chain:
//   Early Secret     = HKDF-Extract(salt=0,       IKM=PSK|0)
//   (derived)        = Derive-Secret(Early,     "derived", "")
//   Handshake Secret = HKDF-Extract(salt=derived, IKM=ECDHE)
//   (derived)        = Derive-Secret(Handshake, "derived", "")
//   Master Secret    = HKDF-Extract(salt=derived, IKM=0)
//
// Traffic secrets (context = transcript hash at that stage):
//   client_handshake  = Derive-Secret(Handshake, "c hs traffic", TH)
//   server_handshake  = Derive-Secret(Handshake, "s hs traffic", TH)
//   client_application= Derive-Secret(Master,    "c ap traffic", TH)
//   server_application= Derive-Secret(Master,    "s ap traffic", TH)
//
// Per-direction AEAD material (QUIC labels, RFC 9001 §5.1):
//   key = HKDF-Expand-Label(secret, "quic key", "", 32)   [ChaCha20-Poly1305]
//   iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)
//
// Header-only: depends only on linoh::crypto SHA-256 + HKDF. No OpenSSL.

#include "linoh/crypto/hkdf.hpp"
#include "linoh/util/crypto.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace linoh::tls {

// AEAD keying material for one direction.
struct TrafficKeys {
    std::array<uint8_t, 32> secret{};  // traffic secret
    std::array<uint8_t, 32> key{};     // ChaCha20-Poly1305 key
    std::array<uint8_t, 12> iv{};      // AEAD nonce base
};

// Running transcript of handshake messages; hashed on demand.
class Transcript {
public:
    void add(std::span<const uint8_t> msg) {
        buf_.insert(buf_.end(), msg.begin(), msg.end());
    }
    void add(const std::vector<uint8_t> &msg) {
        buf_.insert(buf_.end(), msg.begin(), msg.end());
    }
    std::array<uint8_t, 32> hash() const {
        return crypto::SHA256::hash(std::span<const uint8_t>(buf_.data(), buf_.size()));
    }
    const std::vector<uint8_t> &bytes() const { return buf_; }
    void clear() { buf_.clear(); }

private:
    std::vector<uint8_t> buf_;
};

// TLS 1.3 / QUIC key schedule state machine.
class KeySchedule {
public:
    // tc-M3 (v1.7.0.8): 析构时安全清零所有密钥材料。
    //   early_secret/handshake_secret/master_secret 及所有 TrafficKeys 的
    //   secret/key/iv 均为高敏感材料，握手完成后（或对象销毁时）应立即清零，
    //   防止进程内存转储/核心转储泄露会话密钥。
    ~KeySchedule() {
        crypto::secure_zero(early_secret);
        crypto::secure_zero(handshake_secret);
        crypto::secure_zero(master_secret);
        crypto::secure_zero(client_handshake.secret);
        crypto::secure_zero(client_handshake.key);
        crypto::secure_zero(client_handshake.iv);
        crypto::secure_zero(server_handshake.secret);
        crypto::secure_zero(server_handshake.key);
        crypto::secure_zero(server_handshake.iv);
        crypto::secure_zero(client_application.secret);
        crypto::secure_zero(client_application.key);
        crypto::secure_zero(client_application.iv);
        crypto::secure_zero(server_application.secret);
        crypto::secure_zero(server_application.key);
        crypto::secure_zero(server_application.iv);
    }

    // Derive AEAD key+iv from a traffic secret (QUIC labels).
    static TrafficKeys derive_traffic_keys(const std::array<uint8_t, 32> &secret) {
        TrafficKeys tk;
        tk.secret = secret;
        auto k = crypto::hkdf_expand_label(
            std::span<const uint8_t>(secret.data(), secret.size()), "quic key",
            std::span<const uint8_t>{}, 32);
        auto v = crypto::hkdf_expand_label(
            std::span<const uint8_t>(secret.data(), secret.size()), "quic iv",
            std::span<const uint8_t>{}, 12);
        std::memcpy(tk.key.data(), k.data(), 32);
        std::memcpy(tk.iv.data(), v.data(), 12);
        return tk;
    }

    // Step 1: Early Secret = HKDF-Extract(0, PSK|0). Empty psk -> 32 zero bytes.
    void init_early(std::span<const uint8_t> psk = {}) {
        std::array<uint8_t, 32> zero_ikm{};
        std::span<const uint8_t> ikm =
            psk.empty() ? std::span<const uint8_t>(zero_ikm.data(), zero_ikm.size()) : psk;
        early_secret = crypto::hkdf_extract(std::span<const uint8_t>{}, ikm);
    }

    // Step 2: Handshake Secret = HKDF-Extract(derive(Early,"derived",""), ECDHE).
    // Derives client/server handshake traffic secrets + keys from transcript `th`.
    void set_handshake(std::span<const uint8_t> ecdhe, const Transcript &th) {
        auto derived = derive_empty(early_secret, "derived");
        handshake_secret = crypto::hkdf_extract(
            std::span<const uint8_t>(derived.data(), derived.size()), ecdhe);

        auto thh = th.hash();
        auto cs = crypto::derive_secret(
            std::span<const uint8_t>(handshake_secret.data(), handshake_secret.size()),
            "c hs traffic", std::span<const uint8_t>(thh.data(), thh.size()));
        auto ss = crypto::derive_secret(
            std::span<const uint8_t>(handshake_secret.data(), handshake_secret.size()),
            "s hs traffic", std::span<const uint8_t>(thh.data(), thh.size()));
        client_handshake = derive_traffic_keys(cs);
        server_handshake = derive_traffic_keys(ss);
    }

    // Step 3: Master Secret = HKDF-Extract(derive(Handshake,"derived",""), 0).
    // Derives client/server application traffic secrets + keys from transcript `th`.
    void set_master(const Transcript &th) {
        auto derived = derive_empty(handshake_secret, "derived");
        std::array<uint8_t, 32> zero_ikm{};
        master_secret = crypto::hkdf_extract(
            std::span<const uint8_t>(derived.data(), derived.size()),
            std::span<const uint8_t>(zero_ikm.data(), zero_ikm.size()));

        auto thh = th.hash();
        auto cs = crypto::derive_secret(
            std::span<const uint8_t>(master_secret.data(), master_secret.size()),
            "c ap traffic", std::span<const uint8_t>(thh.data(), thh.size()));
        auto ss = crypto::derive_secret(
            std::span<const uint8_t>(master_secret.data(), master_secret.size()),
            "s ap traffic", std::span<const uint8_t>(thh.data(), thh.size()));
        client_application = derive_traffic_keys(cs);
        server_application = derive_traffic_keys(ss);
    }

    // Finished verify_data = HMAC(finished_key, transcript_hash),
    // finished_key = HKDF-Expand-Label(base_secret, "finished", "", 32).  (RFC 8446 §4.4.4)
    static std::array<uint8_t, 32> finished_verify_data(
        const std::array<uint8_t, 32> &base_secret, const Transcript &th) {
        auto fk = crypto::hkdf_expand_label(
            std::span<const uint8_t>(base_secret.data(), base_secret.size()), "finished",
            std::span<const uint8_t>{}, 32);
        auto thh = th.hash();
        return crypto::HMAC_SHA256::compute(
            std::span<const uint8_t>(fk.data(), fk.size()),
            std::span<const uint8_t>(thh.data(), thh.size()));
    }

    // ====================================================================
    // P1-5: KeyUpdate (RFC 9001 §6 / RFC 8446 §7.2)
    //
    // KeyUpdate 派生新一代 traffic secret：
    //   new_secret = HKDF-Expand-Label(old_secret, "quic ku", "", 32)
    //
    // 然后用 derive_traffic_keys() 派生新的 key + iv。
    // key_phase 位在 1-RTT 短包头中翻转，用于指示接收方使用新/旧密钥。
    //
    // 安全限制：ChaCha20-Poly1305 在单密钥下安全使用上限为 2^62 包，
    // 实际应在远低于此阈值时主动触发 KeyUpdate（如 2^32 包）。
    // ====================================================================

    /// P1-5: 从旧 traffic secret 派生新 traffic secret（HKDF-Expand-Label "quic ku"）。
    /// \param old_secret 旧 traffic secret（client_application.secret 或 server_application.secret）
    /// \return 新 traffic secret
    static std::array<uint8_t, 32> key_update_secret(
        const std::array<uint8_t, 32> &old_secret) {
        auto new_secret = crypto::hkdf_expand_label(
            std::span<const uint8_t>(old_secret.data(), old_secret.size()),
            "quic ku", std::span<const uint8_t>{}, 32);
        std::array<uint8_t, 32> result;
        std::memcpy(result.data(), new_secret.data(), 32);
        return result;
    }

    /// P1-5: 一键派生新一代 TrafficKeys（new_secret + new_key + new_iv）。
    /// \param old_secret 旧 traffic secret
    /// \return 新 TrafficKeys
    static TrafficKeys key_update(const std::array<uint8_t, 32> &old_secret) {
        auto new_secret = key_update_secret(old_secret);
        return derive_traffic_keys(new_secret);
    }

    /// P1-5: 触发 KeyUpdate，更新 client_application（本端发送）。
    /// 调用方在收到/发送 KEY_UPDATE 帧后调用。
    void update_client_application_keys() {
        client_application = key_update(client_application.secret);
    }

    /// P1-5: 触发 KeyUpdate，更新 server_application（本端发送）。
    void update_server_application_keys() {
        server_application = key_update(server_application.secret);
    }

    /// P1-5: AEAD 安全使用上限（包数）。
    /// 超过此阈值应主动触发 KeyUpdate。
    /// ChaCha20-Poly1305 安全上限是 2^62，此处保守取 2^32。
    static constexpr std::uint64_t kKeyUpdatePacketThreshold = 1ULL << 32;

    std::array<uint8_t, 32> early_secret{};
    std::array<uint8_t, 32> handshake_secret{};
    std::array<uint8_t, 32> master_secret{};
    TrafficKeys client_handshake, server_handshake;
    TrafficKeys client_application, server_application;

private:
    // Derive-Secret(secret, label, "") — context is hash of empty message list.
    static std::array<uint8_t, 32> derive_empty(const std::array<uint8_t, 32> &secret,
                                                const char *label) {
        auto empty_hash = crypto::SHA256::hash(std::span<const uint8_t>{});
        return crypto::derive_secret(
            std::span<const uint8_t>(secret.data(), secret.size()), label,
            std::span<const uint8_t>(empty_hash.data(), empty_hash.size()));
    }
};

} // namespace linoh::tls
