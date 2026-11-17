// incoming_filter.hpp — 握手前入站连接过滤器（v4.8.0 T-LP3-001）
//
// 借鉴 iroh 0.98 Router incoming_filter（iroh#3951）：
//   - 在 TLS 握手前过滤入站连接，避免对不想要的连接执行完整握手
//   - 拒绝路径（kReject）仅 close socket，吞吐比"接受后关闭"高 20x+
//   - 可组合多个过滤器形成 filter 链
//
// 三种过滤器实现：
//   - AddressWhitelistFilter：IP 白名单（仅接受白名单中的 remote_addr.host）
//   - EndpointIdBlacklistFilter：节点 ID 黑名单（拒绝已知恶意节点）
//   - RateLimitFilter：按 remote_addr.host 限频（滑动窗口 + 令牌桶）
//
// 集成点：Endpoint::accept() 在返回 Incoming 前执行 filter 链
// 回滚开关：EndpointConfig::incoming_filters 默认为空（无过滤，回退 v4.7.0 行为）

#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace linoh::endpoint {

/// 入站连接请求信息（从 Incoming 映射）
struct IncomingRequest {
    /// 对端传输地址（IP + port）
    base::TransportAddr remote_addr;

    /// 对端节点 ID（若已知）
    std::optional<base::EndpointId> endpoint_id;

    /// 应用层协议标识
    std::string_view alpn;

    /// 对端地址是否已验证（ICE/STUN 校验通过）
    bool remote_addr_validated{false};
};

/// 过滤器输出
enum class IncomingFilterOutcome {
    kAccept,   ///< 放行，继续下一个过滤器或完成接受
    kReject,   ///< 立即关闭连接（日志记录原因）
    kRetry,    ///< 要求对端验证地址后重试（当前等同 kReject）
    kIgnore,   ///< 静默丢弃（不记录日志）
};

/// 握手前入站连接过滤器接口（借鉴 iroh#3951 IncomingFilter trait）
class IncomingFilter {
public:
    virtual ~IncomingFilter() = default;

    /// 过滤入站连接请求
    ///
    /// @param req 入站请求信息
    /// @return 过滤结果（kAccept/kReject/kRetry/kIgnore）
    virtual IncomingFilterOutcome filter(const IncomingRequest &req) = 0;

    /// 过滤器名称（用于日志和诊断）
    virtual std::string_view name() const = 0;
};

/// 地址白名单过滤器
///
/// 仅接受白名单中的 IP 地址（remote_addr.host），其他直接拒绝。
/// 适用于已知对端 IP 的私有部署场景。
class AddressWhitelistFilter : public IncomingFilter {
public:
    /// @param allowed_hosts 允许的 IP 地址列表（如 "10.0.0.1", "192.168.1.0"）
    explicit AddressWhitelistFilter(std::vector<std::string> allowed_hosts)
        : allowed_hosts_(allowed_hosts.begin(), allowed_hosts.end()) {}

    IncomingFilterOutcome filter(const IncomingRequest &req) override {
        const auto &host = req.remote_addr.host;
        if (allowed_hosts_.find(host) != allowed_hosts_.end()) {
            return IncomingFilterOutcome::kAccept;
        }
        return IncomingFilterOutcome::kReject;
    }

    std::string_view name() const override { return "address-whitelist"; }

    /// 新增允许的 IP
    void add_host(std::string host) {
        std::lock_guard<std::mutex> lk(mu_);
        allowed_hosts_.insert(std::move(host));
    }

private:
    std::mutex mu_;
    std::unordered_set<std::string> allowed_hosts_;
};

/// 节点 ID 黑名单过滤器
///
/// 拒绝已知恶意/被封禁的 EndpointId。endpoint_id 未知时放行（交后续过滤器处理）。
class EndpointIdBlacklistFilter : public IncomingFilter {
public:
    /// @param blacklisted_ids 被封禁的 EndpointId 列表
    explicit EndpointIdBlacklistFilter(std::vector<base::EndpointId> blacklisted_ids)
        : blacklisted_ids_(blacklisted_ids.begin(), blacklisted_ids.end()) {}

    IncomingFilterOutcome filter(const IncomingRequest &req) override {
        if (!req.endpoint_id.has_value()) {
            return IncomingFilterOutcome::kAccept;  // 未知 endpoint_id，放行
        }
        std::lock_guard<std::mutex> lk(mu_);
        if (blacklisted_ids_.find(*req.endpoint_id) != blacklisted_ids_.end()) {
            return IncomingFilterOutcome::kReject;
        }
        return IncomingFilterOutcome::kAccept;
    }

    std::string_view name() const override { return "endpoint-id-blacklist"; }

    /// 新增封禁的 EndpointId
    void add_endpoint_id(base::EndpointId id) {
        std::lock_guard<std::mutex> lk(mu_);
        blacklisted_ids_.insert(std::move(id));
    }

    /// 解封 EndpointId
    void remove_endpoint_id(const base::EndpointId &id) {
        std::lock_guard<std::mutex> lk(mu_);
        blacklisted_ids_.erase(id);
    }

private:
    mutable std::mutex mu_;
    std::unordered_set<base::EndpointId> blacklisted_ids_;
};

/// 速率限制过滤器
///
/// 按 remote_addr.host 限频，使用滑动窗口算法。
/// 每个 IP 独立计数，超过窗口内最大连接数时拒绝。
///
/// 性能优化（v4.8.0 T-LP3-007）：定期清理过期条目而非每次调用都清理，
/// 避免大量 IP 场景下的 O(N²) 复杂度。清理间隔默认为窗口大小的 1/4。
class RateLimitFilter : public IncomingFilter {
public:
    /// @param window 窗口大小（默认 1s）
    /// @param max_per_window 窗口内最大连接数（默认 10）
    RateLimitFilter(std::chrono::milliseconds window = std::chrono::seconds(1),
                    std::uint32_t max_per_window = 10)
        : window_(window),
          max_per_window_(max_per_window),
          cleanup_interval_(window / 4 > std::chrono::milliseconds(10)
                                ? window / 4
                                : std::chrono::milliseconds(10)),
          last_cleanup_(std::chrono::steady_clock::now()) {}

    IncomingFilterOutcome filter(const IncomingRequest &req) override {
        const auto &host = req.remote_addr.host;
        const auto now = std::chrono::steady_clock::now();

        std::lock_guard<std::mutex> lk(mu_);

        // 定期清理过期条目（而非每次调用都清理）
        // 清理间隔为窗口大小的 1/4，避免 O(N²) 复杂度
        if ((now - last_cleanup_) >= cleanup_interval_) {
            cleanup_expired_locked(now);
            last_cleanup_ = now;
        }

        auto &entry = entries_[host];
        // 移除窗口外的旧时间戳（仅清理当前 IP 的条目）
        while (!entry.timestamps.empty() &&
               (now - entry.timestamps.front()) >= window_) {
            entry.timestamps.pop_front();
        }

        if (entry.timestamps.size() >= max_per_window_) {
            // 当前 IP 条目已空时不保留空 entry（减少内存占用）
            if (entry.timestamps.empty()) {
                entries_.erase(host);
            }
            return IncomingFilterOutcome::kReject;
        }

        entry.timestamps.push_back(now);
        return IncomingFilterOutcome::kAccept;
    }

    std::string_view name() const override { return "rate-limit"; }

    /// 重置指定 IP 的计数
    void reset(const std::string &host) {
        std::lock_guard<std::mutex> lk(mu_);
        entries_.erase(host);
    }

    /// 重置所有 IP 的计数
    void reset_all() {
        std::lock_guard<std::mutex> lk(mu_);
        entries_.clear();
    }

    /// 获取当前追踪的 IP 数量（用于监控）
    std::size_t tracked_ip_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return entries_.size();
    }

private:
    struct RateEntry {
        std::deque<std::chrono::steady_clock::time_point> timestamps;
    };

    void cleanup_expired_locked(std::chrono::steady_clock::time_point now) {
        auto it = entries_.begin();
        while (it != entries_.end()) {
            while (!it->second.timestamps.empty() &&
                   (now - it->second.timestamps.front()) >= window_) {
                it->second.timestamps.pop_front();
            }
            if (it->second.timestamps.empty()) {
                it = entries_.erase(it);
            } else {
                ++it;
            }
        }
    }

    mutable std::mutex mu_;
    std::chrono::milliseconds window_;
    std::uint32_t max_per_window_;
    std::chrono::milliseconds cleanup_interval_;  ///< 定期清理间隔
    std::chrono::steady_clock::time_point last_cleanup_;  ///< 上次清理时间
    std::unordered_map<std::string, RateEntry> entries_;
};

} // namespace linoh::endpoint
