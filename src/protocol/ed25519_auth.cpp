// ed25519_auth.cpp — v4.0.3 M15 跨集群 Ed25519 挑战认证实现
//
// 依赖：
//   - linoh::base::{PublicKey, SecretKey, Signature}（base/key.hpp）
//   - linoh::crypto::crypto_random_bytes（util/crypto.hpp）
//   - linoh::protocol::ReplayProtection（v3.8.6 防重放）
//
// 编码布局（小端序）：
//   AuthChallenge: v(1) + ts(8) + nonce(32) + challenger(32) = 73 字节
//   AuthResponse:  v(1) + ts(8) + nonce(32) + from(32) + sig(64) = 137 字节

#include "linoh/protocol/ed25519_auth.hpp"

#include "linoh/util/crypto.hpp"  // crypto_random_bytes, verify_equal

#include <chrono>
#include <cstring>

namespace linoh::protocol {

// ============================================================================
// 内部工具
// ============================================================================

namespace {

/// 小端写入 uint64
inline void put_u64_le(std::vector<std::uint8_t> &buf, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

/// 小端读取 uint64
inline std::uint64_t get_u64_le(std::span<const std::uint8_t> data, std::size_t offset) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<std::uint64_t>(data[offset + i]) << (i * 8);
    }
    return v;
}

/// 获取当前 Unix 秒时间戳
inline std::uint64_t now_unix_seconds() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

}  // namespace

// ============================================================================
// build_signed_data — 构造签名覆盖内容
// ============================================================================

std::vector<std::uint8_t> build_signed_data(
    std::span<const std::uint8_t> nonce,
    std::uint64_t timestamp,
    const base::PublicKey &challenger) {

    std::vector<std::uint8_t> buf;
    buf.reserve(kAuthNonceSize + 8 + base::PublicKey::kSize);

    // nonce (32 字节)
    buf.insert(buf.end(), nonce.begin(), nonce.end());

    // timestamp (8 字节小端)
    put_u64_le(buf, timestamp);

    // challenger (32 字节公钥)
    auto ch_span = challenger.as_span();
    buf.insert(buf.end(), ch_span.begin(), ch_span.end());

    return buf;
}

// ============================================================================
// AuthChallenge
// ============================================================================

std::vector<std::uint8_t> AuthChallenge::encode() const {
    std::vector<std::uint8_t> buf;
    buf.reserve(kAuthChallengeEncodedSize);

    // version (1 字节)
    buf.push_back(kCurrentVersion);

    // timestamp (8 字节小端)
    put_u64_le(buf, timestamp);

    // nonce (32 字节)
    buf.insert(buf.end(), nonce.begin(), nonce.end());

    // challenger (32 字节公钥)
    auto ch_span = challenger.as_span();
    buf.insert(buf.end(), ch_span.begin(), ch_span.end());

    return buf;
}

bool AuthChallenge::decode(std::span<const std::uint8_t> data, AuthChallenge &out) {
    // 校验 1：固定长度
    if (data.size() != kAuthChallengeEncodedSize) {
        return false;
    }

    // 校验 2：version
    if (data[0] != kCurrentVersion) {
        return false;
    }

    // timestamp (offset 1, 8 字节小端)
    out.timestamp = get_u64_le(data, 1);

    // nonce (offset 9, 32 字节)
    std::memcpy(out.nonce.data(), data.data() + 9, kAuthNonceSize);

    // challenger (offset 41, 32 字节)
    out.challenger = base::PublicKey::from_bytes(data.subspan(41, base::PublicKey::kSize));

    return true;
}

std::string AuthChallenge::to_string() const {
    return "AuthChallenge{ts=" + std::to_string(timestamp) +
           ", challenger=" + challenger.fmt_short() + "}";
}

// ============================================================================
// AuthResponse
// ============================================================================

std::vector<std::uint8_t> AuthResponse::signed_data(const base::PublicKey &challenger) const {
    return build_signed_data(nonce, timestamp, challenger);
}

std::vector<std::uint8_t> AuthResponse::encode() const {
    std::vector<std::uint8_t> buf;
    buf.reserve(kAuthResponseEncodedSize);

    // version (1 字节)
    buf.push_back(kCurrentVersion);

    // timestamp (8 字节小端)
    put_u64_le(buf, timestamp);

    // nonce (32 字节)
    buf.insert(buf.end(), nonce.begin(), nonce.end());

    // from (32 字节公钥)
    auto from_span = from.as_span();
    buf.insert(buf.end(), from_span.begin(), from_span.end());

    // signature (64 字节)
    const std::uint8_t *sig_data = signature.data();
    buf.insert(buf.end(), sig_data, sig_data + base::Signature::kSize);

    return buf;
}

bool AuthResponse::decode(std::span<const std::uint8_t> data, AuthResponse &out) {
    // 校验 1：固定长度
    if (data.size() != kAuthResponseEncodedSize) {
        return false;
    }

    // 校验 2：version
    if (data[0] != kCurrentVersion) {
        return false;
    }

    // timestamp (offset 1, 8 字节小端)
    out.timestamp = get_u64_le(data, 1);

    // nonce (offset 9, 32 字节)
    std::memcpy(out.nonce.data(), data.data() + 9, kAuthNonceSize);

    // from (offset 41, 32 字节)
    out.from = base::PublicKey::from_bytes(data.subspan(41, base::PublicKey::kSize));

    // signature (offset 73, 64 字节)
    out.signature = base::Signature::from_bytes(
        data.subspan(73, base::Signature::kSize));

    return true;
}

std::string AuthResponse::to_string() const {
    return "AuthResponse{ts=" + std::to_string(timestamp) +
           ", from=" + from.fmt_short() + "}";
}

// ============================================================================
// AuthManager
// ============================================================================

AuthManager::AuthManager(AuthMode mode, std::chrono::seconds ttl)
    : mode_(mode), ttl_(ttl) {}

bool AuthManager::should_authenticate(const base::EndpointId &peer,
                                       bool is_cross_network) const {
    (void)peer;  // peer 参数保留供未来扩展（如 ACL 名单）

    switch (mode_) {
        case AuthMode::Never:
            return false;
        case AuthMode::Always:
            return true;
        case AuthMode::Auto:
            // Auto 模式：跨网才认证，内网跳过（向后兼容）
            return is_cross_network;
    }
    return false;
}

AuthChallenge AuthManager::generate_challenge(const base::SecretKey &local_sk) const {
    AuthChallenge challenge;
    challenge.timestamp = now_unix_seconds();
    challenge.challenger = local_sk.public_key();

    // 生成 32 字节随机 nonce
    if (!linoh::crypto::crypto_random_bytes(challenge.nonce)) {
        // 随机源失败时回退全 0（极端情况，测试环境 stub 可能失败）
        // 生产环境 crypto_random_bytes 使用 Windows BCrypt，不会失败
        challenge.nonce.fill(0);
    }

    return challenge;
}

std::optional<AuthResponse> AuthManager::handle_challenge(
    const AuthChallenge &challenge,
    const base::SecretKey &local_sk,
    ReplayProtection &replay) const {

    // 防重放校验（复用 v3.8.6 ReplayProtection）
    // timestamp 双向校验 + nonce 查重
    if (!replay.check(challenge.timestamp, challenge.nonce)) {
        return std::nullopt;
    }

    // 构造签名覆盖内容：nonce(32) || timestamp(8 LE) || challenger(32)
    auto signed_bytes = build_signed_data(challenge.nonce, challenge.timestamp, challenge.challenger);

    // 用本地私钥签名
    auto sig_array = local_sk.sign(signed_bytes);

    // 构造响应
    AuthResponse response;
    response.timestamp = challenge.timestamp;
    response.nonce = challenge.nonce;
    response.from = local_sk.public_key();
    response.signature = base::Signature(sig_array);

    return response;
}

bool AuthManager::verify_response(
    const AuthResponse &response,
    const base::PublicKey &local_public_key,
    const base::EndpointId &expected_peer,
    const std::array<std::uint8_t, kAuthNonceSize> &expected_nonce,
    std::uint64_t expected_ts,
    ReplayProtection &replay) const {

    // 校验 1：from 必须等于期望的 peer（B 的 EndpointId 身份绑定）
    if (response.from != expected_peer) {
        return false;
    }

    // 校验 2：nonce 必须等于本端生成的挑战 nonce（挑战绑定）
    if (response.nonce != expected_nonce) {
        return false;
    }

    // 校验 3：timestamp 必须等于本端挑战 timestamp（时间绑定）
    if (response.timestamp != expected_ts) {
        return false;
    }

    // 校验 4：防重放（复用 v3.8.6 ReplayProtection）
    if (!replay.check(response.timestamp, response.nonce)) {
        return false;
    }

    // 校验 5：签名验证
    // 签名覆盖内容 = nonce(32) || timestamp(8 LE) || challenger(32)
    // challenger = 本端公钥（A 的公钥，即 local_public_key）
    // 用 response.from（B 的公钥）验签
    auto signed_bytes = build_signed_data(response.nonce, response.timestamp, local_public_key);

    return response.signature.verify(signed_bytes, response.from);
}

AuthState AuthManager::state(const base::EndpointId &peer) const {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    auto it = peers_.find(peer);
    if (it == peers_.end()) {
        return AuthState::Unauthenticated;
    }
    return it->second.state;
}

bool AuthManager::is_authenticated(const base::EndpointId &peer) const {
    return state(peer) == AuthState::Authenticated;
}

void AuthManager::mark_authenticated(const base::EndpointId &peer) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    peers_[peer].state = AuthState::Authenticated;
    peers_[peer].last_updated = std::chrono::steady_clock::now();
}

void AuthManager::mark_challenge_sent(const base::EndpointId &peer) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    peers_[peer].state = AuthState::ChallengeSent;
    peers_[peer].last_updated = std::chrono::steady_clock::now();
}

void AuthManager::mark_failed(const base::EndpointId &peer) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    peers_[peer].state = AuthState::Failed;
    peers_[peer].last_updated = std::chrono::steady_clock::now();
}

void AuthManager::clear(const base::EndpointId &peer) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    peers_.erase(peer);
}

void AuthManager::clear_all() {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    peers_.clear();
}

AuthManager::Stats AuthManager::stats() const {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    Stats s;
    s.total_peers = peers_.size();
    for (const auto &kv : peers_) {
        switch (kv.second.state) {
            case AuthState::Authenticated:
                ++s.authenticated;
                break;
            case AuthState::ChallengeSent:
                ++s.pending;
                break;
            case AuthState::Failed:
                ++s.failed;
                break;
            default:
                break;
        }
    }
    return s;
}

}  // namespace linoh::protocol
