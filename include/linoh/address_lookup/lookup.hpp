#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/util/watcher.hpp"

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace linoh::address_lookup {

// 前向声明：避免 pkarr_server.hpp 与 lookup.hpp 循环包含。
class PkarrDnsServer;

/// 地址查询服务的抽象：把 `EndpointId` 解析为 `EndpointAddr`（relay + 直连地址）。
class AddressLookup {
public:
    virtual ~AddressLookup() = default;
    virtual std::string name() const = 0;
    virtual std::optional<base::EndpointAddr> lookup(const base::EndpointId &id) = 0;
    virtual void publish(const base::EndpointAddr &addr) = 0;
};

/// 进程内的简易查找——便于单元测试与本地演示。
class MemoryLookup : public AddressLookup {
public:
    std::string name() const override { return "memory"; }
    std::optional<base::EndpointAddr> lookup(const base::EndpointId &id) override {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = table_.find(id);
        return it == table_.end() ? std::nullopt : std::optional{it->second};
    }
    void publish(const base::EndpointAddr &addr) override {
        std::lock_guard<std::mutex> lk(mu_);
        table_[addr.id()] = addr;
    }

private:
    std::mutex mu_;
    std::unordered_map<base::EndpointId, base::EndpointAddr> table_;
};

/// Pkarr 发布者：用 Ed25519 私钥签名当前节点地址，并发布到某个 DNS-over-HTTPS 服务器。
///
/// 对应 iroh 的 `PkarrPublisher`。完整实现需要 DNS wire 格式，这里保留接口以便后续填充。
class PkarrPublisher {
public:
    explicit PkarrPublisher(base::SecretKey key) : key_{std::move(key)} {}

    /// 签名并发布到 relay 服务器。这里只是演示性地把签名保存到内存表中。
    void publish(const base::EndpointAddr &addr);

    /// 绑定一个本地 PkarrDnsServer：publish 时同时写入其内存表（零网络）。
    void bind_server(std::shared_ptr<PkarrDnsServer> s);

    /// 从内存表中查找（序列化后的 SignedPacket 字节）。
    std::optional<std::vector<uint8_t>> last_signed_packet() const {
        std::lock_guard<std::mutex> lk(mu_);
        return signed_packet_;
    }

    const base::SecretKey &key() const { return key_; }

private:
    base::SecretKey key_;
    mutable std::mutex mu_;
    std::optional<std::vector<uint8_t>> signed_packet_;
    std::shared_ptr<PkarrDnsServer> server_;
};

/// DnsAddressLookup：从公共 DNS 解析 Pkarr 记录。
/// 当前实现只做"进程内解析"，真正的 HTTPS 查询留待后续。
///
/// P4-D-3：支持 fallback nameservers。主服务器查询失败时按顺序尝试 fallback 列表。
class DnsAddressLookup : public AddressLookup {
public:
    struct Server {
        std::string host;
        uint16_t port{5333};
    };

    std::string name() const override { return "dns"; }
    std::optional<base::EndpointAddr> lookup(const base::EndpointId &id) override;
    void publish(const base::EndpointAddr &addr) override;

    /// 显式地把一条记录注入缓存（给测试使用）。
    void inject(base::EndpointAddr addr) {
        std::lock_guard<std::mutex> lk(mu_);
        cache_[addr.id()] = std::move(addr);
    }

    /// 配置主 DNS 查询的目标（默认空 = 不发起网络查询，仅用缓存）。
    void set_server(std::string host, uint16_t port) {
        std::lock_guard<std::mutex> lk(mu_);
        server_host_ = std::move(host);
        server_port_ = port;
    }

    /// P4-D-3: 添加 fallback DNS 服务器（按添加顺序尝试）。
    void add_fallback_server(std::string host, uint16_t port) {
        std::lock_guard<std::mutex> lk(mu_);
        fallback_servers_.push_back({std::move(host), port});
    }

    /// P4-D-3: 批量添加 fallback DNS 服务器。
    void add_fallback_servers(const std::vector<Server> &servers) {
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto &s : servers) fallback_servers_.push_back(s);
    }

    /// P4-D-3: 清空 fallback 列表。
    void clear_fallback_servers() {
        std::lock_guard<std::mutex> lk(mu_);
        fallback_servers_.clear();
    }

    /// P4-D-3: 查询当前 fallback 列表（按顺序）。
    std::vector<Server> fallback_servers() const {
        std::lock_guard<std::mutex> lk(mu_);
        return fallback_servers_;
    }

    /// P4-D-3: 设置单个服务器查询超时（ms，默认 500ms）。
    void set_query_timeout_ms(std::uint32_t ms) {
        std::lock_guard<std::mutex> lk(mu_);
        query_timeout_ms_ = ms;
    }

    /// P4-D-3: 设置每个服务器最大重试次数（默认 3）。
    void set_max_retries(std::uint32_t n) {
        std::lock_guard<std::mutex> lk(mu_);
        max_retries_ = n;
    }

    /// P4-D-3: 查询统计（用于测试和监控）。
    struct Stats {
        std::uint64_t total_queries{0};
        std::uint64_t cache_hits{0};
        std::uint64_t primary_hits{0};
        std::uint64_t fallback_hits{0};
        std::uint64_t all_misses{0};
    };
    Stats stats() const {
        std::lock_guard<std::mutex> lk(mu_);
        return stats_;
    }

private:
    /// P4-D-3: 向指定服务器发起查询（重试 max_retries_ 次，每次 query_timeout_ms_ 超时）。
    /// 返回 true 且 resp 非空表示成功。
    bool query_one_server(const base::EndpointId &id,
                          const std::string &host,
                          uint16_t port,
                          std::vector<std::uint8_t> &resp);

    /// P4-D-3: 解析响应并写入缓存。
    std::optional<base::EndpointAddr> parse_and_cache(const base::EndpointId &id,
                                                      const std::vector<std::uint8_t> &resp);

    mutable std::mutex mu_;
    std::unordered_map<base::EndpointId, base::EndpointAddr> cache_;
    std::string server_host_;
    uint16_t server_port_{5333};
    std::vector<Server> fallback_servers_;
    std::uint32_t query_timeout_ms_{500};
    std::uint32_t max_retries_{3};
    mutable Stats stats_;
};

} // namespace linoh::address_lookup
