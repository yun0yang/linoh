#pragma once

#include "endpoint.hpp"
#include "linoh/address_lookup/lookup.hpp"
#include <string>
#include <vector>

namespace linoh::endpoint {

/// Endpoint 的构造器：链式配置 -> `build()`。
class Builder {
public:
    Builder &secret_key(SecretKey k) { cfg_.secret_key = std::move(k); return *this; }
    Builder &alpns(std::vector<std::string> v) { cfg_.alpns = std::move(v); return *this; }
    Builder &hooks(EndpointHooks h) { cfg_.hooks = std::move(h); return *this; }
    Builder &address_lookup(std::shared_ptr<address_lookup::AddressLookup> l) {
        cfg_.lookup = std::move(l); return *this;
    }

    /// Bootstrap configuration: relay URLs, DNS URLs, known nodes.
    Builder &bootstrap(BootstrapConfig b) { cfg_.bootstrap = std::move(b); return *this; }

    /// Add a single relay URL to the bootstrap config.
    Builder &add_relay_url(base::RelayUrl url) {
        cfg_.bootstrap.relay_urls.push_back(std::move(url));
        return *this;
    }

    /// Add a single DNS URL to the bootstrap config.
    Builder &add_dns_url(std::string url) {
        cfg_.bootstrap.dns_urls.push_back(std::move(url));
        return *this;
    }

    /// Add a known node EndpointId to the bootstrap config.
    Builder &add_known_node(base::EndpointId node_id) {
        cfg_.bootstrap.known_nodes.push_back(std::move(node_id));
        return *this;
    }

    /// Set the bootstrap config file path (JSON format).
    Builder &config_path(std::string path) {
        cfg_.bootstrap.config_path = std::move(path);
        return *this;
    }

    /// Disable auto-connect to relay servers on startup.
    Builder &no_auto_connect() { cfg_.bootstrap.auto_connect = false; return *this; }

    /// P4-D-3: 配置 DnsAddressLookup 的 fallback nameservers。
    /// 仅在 cfg_.lookup 是 DnsAddressLookup 实例时生效。
    /// servers 格式：[{host, port}, ...]，按顺序尝试。
    Builder &dns_fallback(std::vector<address_lookup::DnsAddressLookup::Server> servers) {
        dns_fallback_servers_ = std::move(servers);
        return *this;
    }

    /// P4-D-3: 添加单个 fallback DNS 服务器。
    Builder &add_dns_fallback(std::string host, uint16_t port) {
        dns_fallback_servers_.push_back({std::move(host), port});
        return *this;
    }

    /// P4-D-3: 配置 DNS 查询超时（ms）和重试次数。
    Builder &dns_query_params(std::uint32_t timeout_ms, std::uint32_t max_retries) {
        dns_query_timeout_ms_ = timeout_ms;
        dns_max_retries_ = max_retries;
        return *this;
    }

    /// 实际构造 Endpoint。确保 `secret_key` 已设置（未设置则随机生成）。
    std::shared_ptr<Endpoint> build(linoh_asio::io_context &ctx);

private:
    Endpoint::Config cfg_;
    std::vector<address_lookup::DnsAddressLookup::Server> dns_fallback_servers_;
    std::uint32_t dns_query_timeout_ms_{500};
    std::uint32_t dns_max_retries_{3};
};

} // namespace linoh::endpoint
