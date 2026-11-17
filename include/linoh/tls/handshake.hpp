#pragma once

// linoh TLS 1.3-style mutual-authentication handshake driver (AKE).
//
// ECDHE (X25519) forward secrecy + Ed25519 raw-public-key mutual identity
// authentication + HKDF key schedule. Transport-agnostic: feed handshake
// bytes in, get handshake bytes out. Drives two in-memory instances to
// completion; the Connection layer wraps CRYPTO frames around the flights.
//
// Flights:
//   1. Client -> Server:  ClientHello
//   2. Server -> Client:  ServerHello | ServerCertVerify | ServerFinished
//   3. Client -> Server:  ClientCertVerify | ClientFinished
//
// Transcript points (identical on both sides):
//   T_hs   = hash(CH|SH)                         -> handshake traffic secrets
//   SCV signs content(hash(CH|SH))
//   SFin   = HMAC(finished(server_hs), hash(CH|SH|SCV))
//   CCV signs content(hash(CH|SH|SCV|SFin))
//   CFin   = HMAC(finished(client_hs), hash(CH|SH|SCV|SFin|CCV))
//   T_ap   = hash(CH|SH|SCV|SFin|CCV|CFin)       -> application traffic secrets
//
// Header-only. Depends on x25519 / key_schedule / handshake_msg / base::key.

#include "linoh/base/key.hpp"
#include "linoh/crypto/x25519.hpp"
#include "linoh/tls/handshake_msg.hpp"
#include "linoh/tls/key_schedule.hpp"
#include "linoh/util/crypto.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace linoh::tls {

enum class Role { Client, Server };

enum class HsState {
    Start,
    WaitServerFlight,   // client waiting for SH|SCV|SFin
    WaitClientFlight,   // server waiting for CCV|CFin
    Done,
    Failed,
};

class Handshake {
public:
    Handshake(Role role, const base::SecretKey &node_sk, std::string alpn)
        : role_(role), node_sk_(node_sk), alpn_(std::move(alpn)) {
        node_pub_ = node_sk_.public_key();
        // tc-M1 (v1.7.0.8): 检查 CSPRNG 返回值。
        //   keygen 内部调用 crypto_random_bytes，失败时返回全零 sk 会生成可预测公钥，
        //   破坏 ECDHE 前向保密。失败时标记握手 Failed，后续 start()/on_message() 会拒绝执行。
        if (!crypto::x25519::keygen(eph_pk_.data(), eph_sk_.data())) {
            fail("CSPRNG failed: cannot generate ephemeral keypair");
        }
    }

    // tc-M3 (v1.7.0.8): 析构时安全清零敏感密钥材料。
    //   eph_sk_（ECDHE 临时私钥）、random_（Hello 随机数）、peer_eph_（对端临时公钥）
    //   在握手完成后不再需要，但会残留在内存中直到对象析构。进程核心转储/内存转储
    //   可泄露这些材料。使用 secure_zero（volatile 写入）防止编译器 dead-store 优化。
    ~Handshake() {
        crypto::secure_zero(eph_sk_);
        crypto::secure_zero(random_);
        crypto::secure_zero(peer_eph_);
        // ks_ (KeySchedule) 的密钥清零由其自身析构函数负责
    }

    Role role() const { return role_; }
    bool is_done() const { return state_ == HsState::Done; }
    bool is_failed() const { return state_ == HsState::Failed; }
    HsState state() const { return state_; }
    const base::PublicKey &peer_node() const { return peer_node_; }
    const KeySchedule &keys() const { return ks_; }
    const std::string &negotiated_alpn() const { return negotiated_alpn_; }
    const char *error() const { return error_; }

    /// v1.5.0.2 Step 3: 对端在 Hello 消息中声明的 preferred_mtu。
    /// 握手未完成时返回 1280（旧版节点无 MTU 字段时也是 1280）。
    std::uint16_t peer_preferred_mtu() const { return peer_preferred_mtu_; }

    /// v1.5.0.2 Step 4: 对端在 Hello 消息中声明的 preferred_crypto_level。
    /// 握手未完成时返回 None（旧版节点无 crypto_level 字段时也是 None）。
    multimodal::CryptoLevel peer_preferred_crypto_level() const {
        return peer_preferred_crypto_level_;
    }

    // Client only: produce the ClientHello flight. No-op (empty) for server.
    std::vector<uint8_t> start() {
        if (role_ != Role::Client || state_ != HsState::Start) return {};
        // tc-M1 (v1.7.0.8): 检查 CSPRNG 返回值，失败时中止握手。
        //   ClientHello random 是握手 transcript 的一部分，全零 random 会导致
        //   可预测的握手密钥，破坏前向保密。
        if (!crypto::crypto_random_bytes(std::span<uint8_t>(random_.data(), 32))) {
            fail("CSPRNG failed: cannot generate ClientHello random");
            return {};
        }
        Hello ch;
        ch.random = random_;
        ch.ephemeral = eph_pk_;
        ch.node_pub = to_arr(node_pub_);
        ch.alpn = alpn_;
        auto bytes = encode_hello(HsType::ClientHello, ch);
        transcript_.add(bytes);
        state_ = HsState::WaitServerFlight;
        return bytes;
    }

    // Feed an inbound flight; returns the outbound flight (possibly empty).
    std::vector<uint8_t> on_message(std::span<const uint8_t> in) {
        if (role_ == Role::Server) return server_on_message(in);
        return client_on_message(in);
    }

private:
    static std::array<uint8_t, 32> to_arr(const base::PublicKey &k) {
        std::array<uint8_t, 32> a{};
        std::memcpy(a.data(), k.data(), 32);
        return a;
    }
    void fail(const char *msg) { state_ = HsState::Failed; error_ = msg; }

    bool alpn_ok(const std::string &peer) {
        // tc-L2 (v1.7.0.8): 收紧 ALPN 协商语义。
        //   原逻辑：local 空 + peer 非空 → 接受 peer 任意值。
        //   风险：ALPN 决定协议路由（如 ctrl/1 vs pp-hidden/1），若 local 未指定，
        //   主动方（peer）可强制协商高权限 ALPN，绕过 Endpoint 的 ALPN 白名单。
        //   修复：要求 local alpn_ 必须非空（Endpoint 入口已强制 connect_with_alpn，
        //   空 ALPN 在 v1.7.0.5 C3 已拒绝）；且 local 与 peer 必须严格相等。
        if (alpn_.empty()) {
            // local 未设 ALPN，拒绝协商（不应发生，Endpoint 入口已过滤）
            return false;
        }
        if (peer.empty() || alpn_ != peer) {
            // peer 未设或不匹配
            return false;
        }
        negotiated_alpn_ = alpn_;
        return true;
    }

    // ---- Server ---------------------------------------------------------
    std::vector<uint8_t> server_on_message(std::span<const uint8_t> in) {
        if (state_ == HsState::Start) return server_handle_client_hello(in);
        if (state_ == HsState::WaitClientFlight) return server_handle_client_flight(in);
        fail("server: unexpected message");
        return {};
    }

    std::vector<uint8_t> server_handle_client_hello(std::span<const uint8_t> in) {
        auto ch = decode_hello(in, HsType::ClientHello);
        if (!ch) { fail("bad ClientHello"); return {}; }
        auto &h = ch->first;
        if (!alpn_ok(h.alpn)) { fail("alpn mismatch"); return {}; }
        peer_eph_ = h.ephemeral;
        peer_preferred_mtu_ = h.preferred_mtu;  // v1.5.0.2 Step 3
        peer_preferred_crypto_level_ = h.preferred_crypto_level;  // v1.5.0.2 Step 4
        peer_node_ = base::PublicKey::from_bytes(
            std::span<const uint8_t>(h.node_pub.data(), 32));
        transcript_.add(std::vector<uint8_t>(in.begin(), in.begin() + ch->second));

        // ECDHE.
        std::array<uint8_t, 32> ecdhe{};
        if (!crypto::x25519::scalarmult(ecdhe.data(), eph_sk_.data(), peer_eph_.data())) {
            fail("ECDHE all-zero output (small subgroup attack?)");
            return {};
        }

        // ServerHello.
        // tc-M1 (v1.7.0.8): 检查 CSPRNG 返回值，失败时中止握手。
        if (!crypto::crypto_random_bytes(std::span<uint8_t>(random_.data(), 32))) {
            fail("CSPRNG failed: cannot generate ServerHello random");
            return {};
        }
        Hello sh;
        sh.random = random_;
        sh.ephemeral = eph_pk_;
        sh.node_pub = to_arr(node_pub_);
        sh.alpn = negotiated_alpn_;
        auto sh_bytes = encode_hello(HsType::ServerHello, sh);
        transcript_.add(sh_bytes);

        // Handshake traffic secrets over hash(CH|SH).
        ks_.init_early();
        ks_.set_handshake(std::span<const uint8_t>(ecdhe.data(), 32), transcript_);

        // ServerCertVerify signs content(hash(CH|SH)).
        auto th_hs = transcript_.hash();
        auto content = cert_verify_signed_content(
            std::span<const uint8_t>(th_hs.data(), th_hs.size()));
        auto sig = node_sk_.sign(std::span<const uint8_t>(content.data(), content.size()));
        CertVerify scv;
        std::memcpy(scv.signature.data(), sig.data(), 64);
        auto scv_bytes = encode_cert_verify(scv);
        transcript_.add(scv_bytes);

        // ServerFinished over hash(CH|SH|SCV).
        auto vd = KeySchedule::finished_verify_data(ks_.server_handshake.secret, transcript_);
        Finished sfin; sfin.verify_data = vd;
        auto sfin_bytes = encode_finished(sfin);
        transcript_.add(sfin_bytes);

        std::vector<uint8_t> flight;
        flight.insert(flight.end(), sh_bytes.begin(), sh_bytes.end());
        flight.insert(flight.end(), scv_bytes.begin(), scv_bytes.end());
        flight.insert(flight.end(), sfin_bytes.begin(), sfin_bytes.end());
        state_ = HsState::WaitClientFlight;
        return flight;
    }

    std::vector<uint8_t> server_handle_client_flight(std::span<const uint8_t> in) {
        // th at this point = hash(CH|SH|SCV|SFin).
        auto th_sfin = transcript_.hash();

        auto ccv = decode_cert_verify(in);
        if (!ccv) { fail("bad ClientCertVerify"); return {}; }
        auto content = cert_verify_signed_content(
            std::span<const uint8_t>(th_sfin.data(), th_sfin.size()));
        base::Signature csig = base::Signature::from_bytes(
            std::span<const uint8_t>(ccv->first.signature.data(), 64));
        if (!csig.verify(std::span<const uint8_t>(content.data(), content.size()), peer_node_)) {
            fail("client identity verification failed");
            return {};
        }
        transcript_.add(std::vector<uint8_t>(in.begin(), in.begin() + ccv->second));

        // Verify ClientFinished over hash(CH|SH|SCV|SFin|CCV).
        auto expect = KeySchedule::finished_verify_data(ks_.client_handshake.secret, transcript_);
        auto cfin = decode_finished(in.subspan(ccv->second));
        if (!cfin) { fail("bad ClientFinished"); return {}; }
        if (std::memcmp(cfin->first.verify_data.data(), expect.data(), 32) != 0) {
            fail("client Finished mismatch");
            return {};
        }
        transcript_.add(std::vector<uint8_t>(
            in.begin() + ccv->second, in.begin() + ccv->second + cfin->second));

        ks_.set_master(transcript_);  // application keys over full transcript
        state_ = HsState::Done;
        return {};
    }

    // ---- Client ---------------------------------------------------------
    std::vector<uint8_t> client_on_message(std::span<const uint8_t> in) {
        if (state_ != HsState::WaitServerFlight) { fail("client: unexpected message"); return {}; }

        // ServerHello.
        auto sh = decode_hello(in, HsType::ServerHello);
        if (!sh) { fail("bad ServerHello"); return {}; }
        auto &h = sh->first;
        if (!alpn_ok(h.alpn)) { fail("alpn mismatch"); return {}; }
        peer_eph_ = h.ephemeral;
        peer_preferred_mtu_ = h.preferred_mtu;  // v1.5.0.2 Step 3
        peer_preferred_crypto_level_ = h.preferred_crypto_level;  // v1.5.0.2 Step 4
        peer_node_ = base::PublicKey::from_bytes(
            std::span<const uint8_t>(h.node_pub.data(), 32));
        transcript_.add(std::vector<uint8_t>(in.begin(), in.begin() + sh->second));

        // ECDHE + handshake traffic secrets over hash(CH|SH).
        std::array<uint8_t, 32> ecdhe{};
        if (!crypto::x25519::scalarmult(ecdhe.data(), eph_sk_.data(), peer_eph_.data())) {
            fail("ECDHE all-zero output (small subgroup attack?)");
            return {};
        }
        ks_.init_early();
        ks_.set_handshake(std::span<const uint8_t>(ecdhe.data(), 32), transcript_);
        auto th_hs = transcript_.hash();

        // ServerCertVerify — verify server identity over content(hash(CH|SH)).
        std::size_t off = sh->second;
        auto scv = decode_cert_verify(in.subspan(off));
        if (!scv) { fail("bad ServerCertVerify"); return {}; }
        {
            auto content = cert_verify_signed_content(
                std::span<const uint8_t>(th_hs.data(), th_hs.size()));
            base::Signature ssig = base::Signature::from_bytes(
                std::span<const uint8_t>(scv->first.signature.data(), 64));
            if (!ssig.verify(std::span<const uint8_t>(content.data(), content.size()),
                             peer_node_)) {
                fail("server identity verification failed");
                return {};
            }
        }
        transcript_.add(std::vector<uint8_t>(in.begin() + off, in.begin() + off + scv->second));
        off += scv->second;

        // ServerFinished over hash(CH|SH|SCV).
        auto expect_sfin =
            KeySchedule::finished_verify_data(ks_.server_handshake.secret, transcript_);
        auto sfin = decode_finished(in.subspan(off));
        if (!sfin) { fail("bad ServerFinished"); return {}; }
        if (std::memcmp(sfin->first.verify_data.data(), expect_sfin.data(), 32) != 0) {
            fail("server Finished mismatch");
            return {};
        }
        transcript_.add(std::vector<uint8_t>(in.begin() + off, in.begin() + off + sfin->second));
        off += sfin->second;

        // ---- Client authentication flight ----
        // ClientCertVerify signs content(hash(CH|SH|SCV|SFin)).
        auto th_sfin = transcript_.hash();
        auto content = cert_verify_signed_content(
            std::span<const uint8_t>(th_sfin.data(), th_sfin.size()));
        auto sig = node_sk_.sign(std::span<const uint8_t>(content.data(), content.size()));
        CertVerify ccv; std::memcpy(ccv.signature.data(), sig.data(), 64);
        auto ccv_bytes = encode_cert_verify(ccv);
        transcript_.add(ccv_bytes);

        // ClientFinished over hash(CH|SH|SCV|SFin|CCV).
        auto vd = KeySchedule::finished_verify_data(ks_.client_handshake.secret, transcript_);
        Finished cfin; cfin.verify_data = vd;
        auto cfin_bytes = encode_finished(cfin);
        transcript_.add(cfin_bytes);

        ks_.set_master(transcript_);  // application keys over full transcript
        state_ = HsState::Done;

        std::vector<uint8_t> flight;
        flight.insert(flight.end(), ccv_bytes.begin(), ccv_bytes.end());
        flight.insert(flight.end(), cfin_bytes.begin(), cfin_bytes.end());
        return flight;
    }

    Role role_;
    base::SecretKey node_sk_;
    base::PublicKey node_pub_;
    std::string alpn_;
    std::string negotiated_alpn_;

    std::array<uint8_t, 32> eph_sk_{};
    std::array<uint8_t, 32> eph_pk_{};
    std::array<uint8_t, 32> peer_eph_{};
    std::uint16_t peer_preferred_mtu_{1280};  // v1.5.0.2 Step 3
    multimodal::CryptoLevel peer_preferred_crypto_level_{  // v1.5.0.2 Step 4
        multimodal::CryptoLevel::None};
    std::array<uint8_t, 32> random_{};

    base::PublicKey peer_node_;
    Transcript transcript_;
    KeySchedule ks_;
    HsState state_{HsState::Start};
    const char *error_{""};
};

} // namespace linoh::tls
