#pragma once

/// @file address_token_store.hpp
/// 全局地址验证 token 存储（P4-A-2，借鉴 iroh PR #4317）。
///
/// RFC 9000 §19.7 NEW_TOKEN 帧：服务端可向客户端下发 token，客户端在后续新连接中
/// 通过 Initial 包的 token 字段携带，使服务端跳过 address validation 流程，降低
/// 首次连接延迟。本存储实现跨连接共享的 token 缓存：
///   - 服务端：下发 NEW_TOKEN 时调用 store_token()
///   - 客户端：发起连接前调用 take_token() 查询可用 token
///   - 按 peer_addr 隔离，TTL 过期自动清理
///
/// 线程安全：所有 public 方法可并发调用（shared_mutex 保护）。

#include "linoh/base/endpoint_addr.hpp"

#include <chrono>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace linoh::tls {

/// 全局地址验证 token 存储（单例）。
class AddressTokenStore {
public:
    /// 默认 TTL（1 小时，与 QUIC 推荐的 token 生命周期一致）。
    static constexpr std::chrono::seconds kDefaultTtl{3600};

    /// 默认每个 peer 保留的最大 token 数（避免恶意服务端下发过多 token 占内存）。
    static constexpr std::size_t kMaxTokensPerPeer = 8;

    /// 获取全局单例。
    static AddressTokenStore& instance();

    /// 服务端：下发 NEW_TOKEN 时存入。
    ///
    /// \param token NEW_TOKEN 帧的 token 字节流
    /// \param peer_addr 对端地址（用于隔离）
    /// \param ttl 生存时间（任意 std::chrono::duration，默认 1 小时）
    template <typename Rep, typename Period>
    void store_token(const std::vector<std::uint8_t>& token,
                     const linoh::base::TransportAddr& peer_addr,
                     std::chrono::duration<Rep, Period> ttl) {
        store_token_impl(token, peer_addr,
                         std::chrono::duration_cast<std::chrono::seconds>(ttl));
    }

    void store_token(const std::vector<std::uint8_t>& token,
                     const linoh::base::TransportAddr& peer_addr) {
        store_token_impl(token, peer_addr, kDefaultTtl);
    }

    /// 客户端：连接前查询可用 token。
    ///
    /// 取出后即从存储中删除（token 一次性使用，防重放）。
    /// \return 可用的 token，或 nullopt（无可用 token 或已过期）
    std::optional<std::vector<std::uint8_t>> take_token(
        const linoh::base::TransportAddr& peer_addr);

    /// 查询但不取出（用于诊断）。
    std::size_t count_tokens(const linoh::base::TransportAddr& peer_addr) const;

    /// 过期清理（定时调用，例如 linoh_endpoint_poll 中每 60s 调用一次）。
    std::size_t cleanup_expired();

    /// 清空所有 token（用于测试或 reset）。
    void clear();

    /// 全局 token 总数（用于测试和监控）。
    std::size_t total_tokens() const;

private:
    AddressTokenStore() = default;
    AddressTokenStore(const AddressTokenStore&) = delete;
    AddressTokenStore& operator=(const AddressTokenStore&) = delete;

    /// 实际存储实现（按秒精度 TTL）
    void store_token_impl(const std::vector<std::uint8_t>& token,
                          const linoh::base::TransportAddr& peer_addr,
                          std::chrono::seconds ttl);

    struct Entry {
        std::vector<std::uint8_t> token;
        std::chrono::steady_clock::time_point expires_at;
    };

    /// peer_addr → 已下发 token 列表
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::vector<Entry>> store_;

    /// 将 TransportAddr 转为字符串 key（kind + host + port）
    static std::string addr_key(const linoh::base::TransportAddr& addr);
};

} // namespace linoh::tls
