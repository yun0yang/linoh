// holepunch_cache.hpp — S6-③（v5.3）打洞结果缓存
//
// 同 endpoint_id 对近期打洞成功的 FourTuple 映射，TTL 内复用免重打：
//   - UDP NAT 映射生命周期通常 30-120s（RFC 4787），默认 TTL 60s——
//     期内同对端重连/重打洞直接复用上次成功 tuple（打洞一轮省 ~1-10s）
//   - 失败方由调用方退避（缓存只记成功）
//   - 进程级单例（Endpoint 零构造改动）；容量上限 256，超限先清过期、
//     仍超限按最旧清一半
//   - 线程安全（mutex；读写低频）
#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/net/path.hpp"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace linoh::nat {

/// 打洞成功映射缓存（S6-③）
class HolepunchCache {
public:
    /// 默认 TTL：60s（NAT UDP 映射典型生命周期的保守取值）
    static constexpr std::chrono::milliseconds kDefaultTtl{60 * 1000};
    /// 容量上限
    static constexpr std::size_t kMaxEntries = 256;

    /// 记录一次成功映射（时间戳取内部 steady_clock）
    void record(const base::EndpointId &peer, const net::FourTuple &tuple);

    /// 查询缓存（TTL 内有效才返回）
    /// @param peer 对端 EndpointId
    /// @param ttl 有效期（默认 60s；<=0 视为禁用返回 nullopt）
    std::optional<net::FourTuple> lookup(
        const base::EndpointId &peer,
        std::chrono::milliseconds ttl = kDefaultTtl) const;

    /// 当前条目数（含过期未清理项）
    std::size_t size() const;

    /// 清空
    void clear();

    /// 进程级单例（Endpoint::try_last_attempt_before_relay 使用）
    static HolepunchCache &global();

private:
    /// 超限清理：先清过期，仍超限按最旧清一半
    void evict_locked(std::int64_t now_ms);

    mutable std::mutex mu_;
    struct Entry {
        net::FourTuple tuple{};
        std::int64_t recorded_at_ms{0};  // steady_clock 毫秒
    };
    std::unordered_map<base::EndpointId, Entry> entries_;

public:
    /// 构造公开（测试/多实例场景使用；常规路径经 global()）
    HolepunchCache() = default;
};

}  // namespace linoh::nat
