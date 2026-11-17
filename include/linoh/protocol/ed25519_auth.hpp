// ed25519_auth.hpp — v4.0.3 M15 跨集群 Ed25519 挑战认证
//
// 握手后追加挑战-签名-验证三步认证（PrimeIntellect 双向挑战模式），
// 证明对端持有 EndpointId 对应的 Ed25519 私钥。复用 v3.8.5 SignedMessage
// 密钥基础设施 + v3.8.6 ReplayProtection 防重放，无新外部依赖。
//
// 设计要点：
//   - 算法选型：Ed25519（替代路线图原方案 ECDSA secp256k1）
//     理由：linoh OpenSSL 是 stub 空实现（EVP_DigestSign/Verify 返回 0），
//           无法实际执行 ECDSA；util/crypto.hpp 明确注释 no OpenSSL dependency。
//           Ed25519 与 v3.8.5 SignedMessage 一致，复用现有 ed25519_core 纯 C++ 实现，
//           更现代（确定性签名、抗侧信道、签名 64B 比 ECDSA DER 71B 更短）。
//   - 三步认证流程：
//     1. A → B：AuthChallenge {timestamp, nonce, A_pub}
//     2. B 用 B_sk 对 (nonce || ts || A_pub) 签名 → AuthResponse
//     3. A 验证签名 + from==expected + nonce/timestamp 未重放 → 缓存会话
//   - 防重放：复用 v3.8.6 ReplayProtection（nonce + timestamp 双向校验）
//     · timestamp |now - ts| > ttl → 丢弃（防旧指令重放 + 容忍时钟偏移）
//     · nonce 查 NonceCache LRU（防同一挑战重放）
//   - 会话缓存：认证成功后 is_authenticated_with_peer=true，连接不断开不重复认证
//   - 配置化：AuthMode Auto（内网跳过/跨网强制，默认）/Always/Never
//   - 向后兼容：默认 Auto 模式，内网节点等价旧行为（不认证）
//
// AuthChallenge 编码布局（73 字节固定，小端序）：
//   offset  size  field
//   0       1     version (当前 1)
//   1       8     timestamp (Unix 秒，小端序)
//   9       32    nonce (随机挑战字节)
//   41      32    challenger (A 的 Ed25519 公钥)
//
// AuthResponse 编码布局（137 字节固定，小端序）：
//   offset  size  field
//   0       1     version (当前 1)
//   1       8     timestamp (复用挑战 timestamp)
//   9       32    nonce (复用挑战 nonce)
//   41      32    from (B 的 Ed25519 公钥)
//   73      64    signature (Ed25519 签名，覆盖 nonce||ts||challenger)
//
// 字节序：多字节字段使用小端序（与 connect_policy.hpp / shard_bitfield.hpp 一致）。
// 向后兼容：version 字段允许未来扩展；旧节点不识别 MethodId 0x0046/0x0047 → 丢弃。

#pragma once

#include "linoh/base/key.hpp"              // PublicKey, SecretKey, Signature, EndpointId
#include "linoh/protocol/replay_protection.hpp"  // ReplayProtection

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>  // std::memcmp
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace linoh::protocol {

// ============================================================================
// 常量
// ============================================================================

/// 挑战 nonce 字节长度（与 v3.8.6 kNonceSize 一致）
constexpr std::size_t kAuthNonceSize = 32;

/// 默认认证窗口（与 v3.8.6 kDefaultReplayTtl 一致，60 秒）
constexpr std::chrono::seconds kDefaultAuthTtl{60};

/// AuthChallenge 编码固定长度（v1 + ts + nonce + challenger = 1+8+32+32 = 73）
constexpr std::size_t kAuthChallengeEncodedSize = 73;

/// AuthResponse 编码固定长度（v1 + ts + nonce + from + sig = 1+8+32+32+64 = 137）
constexpr std::size_t kAuthResponseEncodedSize = 137;

// ============================================================================
// 枚举
// ============================================================================

/// 认证模式
enum class AuthMode : std::uint8_t {
    Auto    = 0,  // 内网跳过/跨网强制（默认，向后兼容）
    Always  = 1,  // 总是强制认证
    Never   = 2,  // 总是跳过认证
};

/// AuthMode 转字符串（日志用）
inline const char *to_string(AuthMode m) noexcept {
    switch (m) {
        case AuthMode::Auto:   return "Auto";
        case AuthMode::Always: return "Always";
        case AuthMode::Never:  return "Never";
    }
    return "Unknown";
}

/// 认证状态机
enum class AuthState : std::uint8_t {
    Unauthenticated = 0,  // 未认证（初始）
    ChallengeSent   = 1,  // 已发送挑战，等待响应
    Authenticated   = 2,  // 已认证（会话缓存）
    Failed          = 3,  // 认证失败（超时/签名错误/重放）
};

/// AuthState 转字符串（日志用）
inline const char *to_string(AuthState s) noexcept {
    switch (s) {
        case AuthState::Unauthenticated: return "Unauthenticated";
        case AuthState::ChallengeSent:   return "ChallengeSent";
        case AuthState::Authenticated:   return "Authenticated";
        case AuthState::Failed:          return "Failed";
    }
    return "Unknown";
}

// ============================================================================
// AuthChallenge — 挑战帧（A → B）
// ============================================================================

/// 认证挑战（A 发起，B 响应）
///
/// 字段：
/// - `timestamp`：Unix 秒时间戳（复用 v3.8.6 timestamp 校验）
/// - `nonce`：32 字节随机挑战（复用 v3.8.6 NonceCache 防重放）
/// - `challenger`：发起方 A 的 Ed25519 公钥（EndpointId）
struct AuthChallenge {
    static constexpr std::uint8_t kCurrentVersion = 1;

    std::uint64_t timestamp{0};                    ///< Unix 秒时间戳
    std::array<std::uint8_t, kAuthNonceSize> nonce{};  ///< 随机挑战
    base::PublicKey challenger{};                  ///< A 的公钥

    /// 序列化为字节流（73 字节固定）
    std::vector<std::uint8_t> encode() const;

    /// 反序列化
    /// @return true=成功，false=数据格式错误（长度不足/version 不匹配）
    static bool decode(std::span<const std::uint8_t> data, AuthChallenge &out);

    /// 简要描述（日志用）
    std::string to_string() const;

    /// 相等比较（测试用）
    bool operator==(const AuthChallenge &other) const noexcept {
        return timestamp == other.timestamp &&
               nonce == other.nonce &&
               challenger == other.challenger;
    }
};

// ============================================================================
// AuthResponse — 响应帧（B → A）
// ============================================================================

/// 认证响应（B 签名后回传 A）
///
/// 签名覆盖内容（防重放绑定）：
///   signature = Ed25519.Sign(B_sk, nonce(32) || timestamp(8 LE) || challenger(32))
///
/// 验证时：
///   1. 用 from 公钥验签 signature 对 (nonce||ts||challenger)
///   2. 校验 from == 期望的 B 的 EndpointId
///   3. 复用 v3.8.6 ReplayProtection 校验 nonce + timestamp 防重放
struct AuthResponse {
    static constexpr std::uint8_t kCurrentVersion = 1;

    std::uint64_t timestamp{0};                    ///< 复用挑战 timestamp
    std::array<std::uint8_t, kAuthNonceSize> nonce{};  ///< 复用挑战 nonce
    base::PublicKey from{};                        ///< B 的公钥（响应方）
    base::Signature signature{};                   ///< Ed25519 签名

    /// 序列化为字节流（137 字节固定）
    std::vector<std::uint8_t> encode() const;

    /// 反序列化
    /// @return true=成功，false=数据格式错误（长度不足/version 不匹配）
    static bool decode(std::span<const std::uint8_t> data, AuthResponse &out);

    /// 简要描述（日志用）
    std::string to_string() const;

    /// 相等比较（测试用）
    /// @note Signature 类型未定义 operator==，用 std::memcmp 比较 64 字节签名数据
    bool operator==(const AuthResponse &other) const noexcept {
        return timestamp == other.timestamp &&
               nonce == other.nonce &&
               from == other.from &&
               std::memcmp(signature.data(), other.signature.data(),
                           base::Signature::kSize) == 0;
    }

    /// 计算签名覆盖内容（公开，便于测试和验证）
    /// @param challenger A 的公钥（挑战发起方）
    /// @return 签名覆盖的字节流：nonce(32) || timestamp(8 LE) || challenger(32)
    std::vector<std::uint8_t> signed_data(const base::PublicKey &challenger) const;
};

// ============================================================================
// AuthManager — 会话状态管理
// ============================================================================

/// 认证管理器（per-endpoint 单例，管理所有 peer 的认证状态）
///
/// 线程安全：shared_mutex 多读单写。
/// - should_authenticate / state：共享读锁
/// - generate_challenge / handle_challenge / verify_response / mark_*：独占写锁
///
/// 使用流程：
///   1. should_authenticate(peer, is_cross_network) 判断是否需要认证
///   2. generate_challenge(local_sk) 生成挑战 → 发送给 peer
///   3. peer 调用 handle_challenge(challenge, local_sk, replay) 生成响应
///   4. 本地调用 verify_response(response, expected_peer, expected_nonce, expected_ts, replay)
///   5. 成功后 mark_authenticated(peer) 缓存会话状态
///   6. 连接断开时 clear(peer) 清除状态
class AuthManager {
public:
    /// 构造认证管理器
    ///
    /// @param mode 认证模式（默认 Auto，内网跳过/跨网强制）
    /// @param ttl  认证窗口（默认 60s，与 v3.8.6 kDefaultReplayTtl 一致）
    explicit AuthManager(AuthMode mode = AuthMode::Auto,
                         std::chrono::seconds ttl = kDefaultAuthTtl);

    // -------- 决策 --------

    /// 是否需要对 peer 发起认证
    /// @param peer 对端 EndpointId
    /// @param is_cross_network 是否跨网（Auto 模式下跨网才认证）
    /// @return true=需要认证，false=可跳过
    ///
    /// 决策逻辑：
    ///   - Never：始终 false
    ///   - Always：始终 true
    ///   - Auto：is_cross_network=true 时 true，否则 false
    bool should_authenticate(const base::EndpointId &peer,
                              bool is_cross_network) const;

    // -------- 挑战生成（A 侧）--------

    /// 生成本地挑战
    /// @param local_sk 本地私钥（用于派生 challenger 公钥）
    /// @return AuthChallenge，timestamp=now，nonce=随机 32 字节，challenger=local_sk.public_key()
    ///
    /// @note timestamp 用 system_clock::now()（Unix 秒，与 v3.8.6 一致）
    ///       nonce 用 crypto_random_bytes（与 v3.8.6 NonceCache 一致）
    AuthChallenge generate_challenge(const base::SecretKey &local_sk) const;

    // -------- 挑战处理（B 侧）--------

    /// 处理收到的挑战，生成响应
    /// @param challenge 收到的挑战
    /// @param local_sk 本地私钥（B 的私钥，用于签名）
    /// @param replay 防重放保护器（校验 timestamp + nonce）
    /// @return AuthResponse；nullopt 若 timestamp/nonce 防重放校验失败
    ///
    /// @note 签名内容 = nonce(32) || timestamp(8 LE) || challenger(32)
    ///       from = local_sk.public_key()
    std::optional<AuthResponse> handle_challenge(
        const AuthChallenge &challenge,
        const base::SecretKey &local_sk,
        ReplayProtection &replay) const;

    // -------- 响应验证（A 侧）--------

    /// 验证收到的响应
    /// @param response 收到的响应
    /// @param local_public_key 本端公钥（A 的公钥，即 challenger；用于构造签名覆盖内容）
    /// @param expected_peer 期望的 B 的 EndpointId（from 必须等于此）
    /// @param expected_nonce 期望的 nonce（必须等于本端生成的挑战 nonce）
    /// @param expected_ts 期望的 timestamp（必须等于本端挑战 timestamp）
    /// @param replay 防重放保护器（校验 timestamp + nonce）
    /// @return true 仅当：
    ///         1. from == expected_peer（身份绑定）
    ///         2. nonce == expected_nonce（挑战绑定）
    ///         3. timestamp == expected_ts（时间绑定）
    ///         4. replay.check(timestamp, nonce) 通过（防重放）
    ///         5. 签名有效（from 验签 signature 对 (nonce||ts||local_public_key)）
    ///
    /// @note 验证成功后调用方应调用 mark_authenticated(peer) 缓存状态
    bool verify_response(const AuthResponse &response,
                         const base::PublicKey &local_public_key,
                         const base::EndpointId &expected_peer,
                         const std::array<std::uint8_t, kAuthNonceSize> &expected_nonce,
                         std::uint64_t expected_ts,
                         ReplayProtection &replay) const;

    // -------- 会话状态管理 --------

    /// 查询会话认证状态
    AuthState state(const base::EndpointId &peer) const;

    /// 查询是否已认证（便捷方法，state==Authenticated）
    bool is_authenticated(const base::EndpointId &peer) const;

    /// 标记会话已认证（verify_response 成功后调用）
    void mark_authenticated(const base::EndpointId &peer);

    /// 标记已发送挑战（generate_challenge 后调用）
    void mark_challenge_sent(const base::EndpointId &peer);

    /// 标记认证失败
    void mark_failed(const base::EndpointId &peer);

    /// 清除会话认证状态（连接断开时调用）
    void clear(const base::EndpointId &peer);

    /// 清除所有会话状态
    void clear_all();

    // -------- 配置 --------

    AuthMode mode() const noexcept { return mode_; }
    std::chrono::seconds ttl() const noexcept { return ttl_; }

    /// 统计信息
    struct Stats {
        std::size_t total_peers{0};        ///< 当前跟踪的 peer 数
        std::size_t authenticated{0};      ///< 已认证 peer 数
        std::size_t pending{0};            ///< 待认证（ChallengeSent）peer 数
        std::size_t failed{0};             ///< 认证失败 peer 数
    };
    Stats stats() const;

private:
    AuthMode mode_;
    std::chrono::seconds ttl_;
    mutable std::shared_mutex mutex_;

    struct PeerAuthState {
        AuthState state{AuthState::Unauthenticated};
        std::chrono::steady_clock::time_point last_updated;
    };
    std::unordered_map<base::EndpointId, PeerAuthState> peers_;
};

// ============================================================================
// 便捷函数（独立于 AuthManager，纯函数，便于测试）
// ============================================================================

/// 构造签名覆盖内容（公开，便于测试断言）
/// @param nonce 挑战 nonce
/// @param timestamp Unix 秒时间戳
/// @param challenger 挑战发起方公钥
/// @return nonce(32) || timestamp(8 LE) || challenger(32)，共 72 字节
std::vector<std::uint8_t> build_signed_data(
    std::span<const std::uint8_t> nonce,
    std::uint64_t timestamp,
    const base::PublicKey &challenger);

}  // namespace linoh::protocol
