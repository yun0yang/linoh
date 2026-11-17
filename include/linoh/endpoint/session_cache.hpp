// session_cache.hpp — v5.0.0 Session Ticket 缓存（T-LP4-003）
//
// 借鉴 iroh 0.96 Connection<OutgoingZeroRtt> + TLS 1.3 RFC 8446 §4.6.1
//
// 设计要点：
//   - 客户端缓存服务端下发的 session_ticket，后续重连时携带发起 0-RTT
//   - ticket 与 endpoint_id 绑定（跨节点不可复用）
//   - TTL 7 天（604800 秒），超期自动失效
//   - 线程安全（mutex 保护，支持 Connection 多线程访问）
//   - 定期清理过期条目（cleanup_expired），避免内存无限增长
//   - 支持 ticket_age_add 防重放（RFC 8446 §4.6.1）
//
// API：
//   store(endpoint_id, ticket)  — 缓存 ticket
//   lookup(endpoint_id)         — 查询有效 ticket（过期返回 nullopt）
//   remove(endpoint_id)         — 主动移除（如服务端拒绝 0-RTT 后清除）
//   cleanup_expired()           — 清理所有过期条目
//   size()                      — 当前缓存条目数（含未清理的过期条目）

#pragma once

#include "linoh/base/key.hpp"
#include "linoh/protocol/packet.hpp"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace linoh::endpoint {

/// v5.0.0: Session ticket 缓存条目
struct CachedSessionTicket {
    /// 服务端下发的 session ticket
    protocol::SessionTicketFrame ticket;
    /// 缓存时间戳（用于 TTL 计算）
    std::chrono::steady_clock::time_point stored_at;
    /// 服务端 endpoint_id（用于绑定校验）
    base::EndpointId server_endpoint_id;
};

/// v5.0.0: Session ticket 缓存 — 客户端侧缓存服务端下发的 ticket
///
/// 线程安全：所有公共方法内部加锁，支持 Connection 多线程访问。
/// TTL：默认 7 天（604800 秒），可通过构造函数自定义。
class SessionCache {
public:
    /// 默认 TTL = 7 天（RFC 8446 建议最大值）
    static constexpr std::chrono::seconds kDefaultTtl{604800};

    /// 最大缓存条目数（防止内存无限增长）
    static constexpr std::size_t kMaxEntries = 1024;

    /// 构造函数
    /// @param ttl ticket 有效期（默认 7 天，支持毫秒级精度便于测试）
    /// @note 接受任意 duration 类型，内部存储为毫秒精度
    explicit SessionCache(std::chrono::milliseconds ttl = kDefaultTtl)
        : ttl_(ttl) {}

    /// 缓存 session ticket
    /// @param server_endpoint_id 服务端节点 ID（ticket 与此绑定）
    /// @param ticket 服务端下发的 session ticket
    /// @note 若缓存已满（size >= kMaxEntries），先清理过期条目，仍满则移除最旧条目
    void store(const base::EndpointId &server_endpoint_id,
               const protocol::SessionTicketFrame &ticket);

    /// 查询有效 ticket
    /// @param server_endpoint_id 目标服务端节点 ID
    /// @return 若存在且未过期，返回 ticket；否则返回 nullopt
    std::optional<protocol::SessionTicketFrame> lookup(
        const base::EndpointId &server_endpoint_id) const;

    /// 查询完整缓存条目（含时间戳，供上层做 ticket_age 计算）
    /// @param server_endpoint_id 目标服务端节点 ID
    /// @return 若存在且未过期，返回完整条目；否则返回 nullopt
    std::optional<CachedSessionTicket> lookup_full(
        const base::EndpointId &server_endpoint_id) const;

    /// 主动移除缓存条目
    /// @note 用于服务端拒绝 0-RTT 后清除本地缓存，回退到 1-RTT
    void remove(const base::EndpointId &server_endpoint_id);

    /// 清理所有过期条目
    /// @return 清理的条目数
    std::size_t cleanup_expired();

    /// 当前缓存条目数（含未清理的过期条目）
    std::size_t size() const;

    /// 设置 TTL（影响后续 lookup 判定，支持毫秒级精度）
    void set_ttl(std::chrono::milliseconds ttl);

    /// 获取当前 TTL（毫秒精度）
    std::chrono::milliseconds ttl() const { return ttl_; }

private:
    /// 检查条目是否过期
    bool is_expired_(const CachedSessionTicket &entry,
                     std::chrono::steady_clock::time_point now) const;

    /// 清理过期条目（调用方需持锁）
    std::size_t cleanup_expired_locked_();

    mutable std::mutex mu_;
    std::chrono::milliseconds ttl_;
    std::unordered_map<base::EndpointId, CachedSessionTicket> entries_;
};

} // namespace linoh::endpoint

// 注意：std::hash<linoh::base::PublicKey> 已在 linoh/base/key.hpp 中定义，
// 此处无需重复定义。
