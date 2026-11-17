#pragma once

#include "linoh/base/key.hpp"
#include "linoh/net/custom_transport.hpp"
#include <string>
#include <vector>

namespace linoh::base {

/// Relay 服务器 URL：与 iroh 保持兼容。
///
/// 一个典型的 URL 形如 `https://example.relay.iroh.link/`。
class RelayUrl {
public:
    RelayUrl() = default;
    explicit RelayUrl(std::string url);

    const std::string &url() const { return url_; }
    std::string scheme() const { return scheme_; }
    std::string host() const { return host_; }
    uint16_t port() const { return port_; }

    bool operator==(const RelayUrl &other) const { return url_ == other.url_; }
    bool operator<(const RelayUrl &other) const { return url_ < other.url_; }

private:
    std::string url_;
    std::string scheme_;
    std::string host_;
    uint16_t port_{0};
};

/// 完整的对端可达信息：节点 ID + Relay 服务器列表 + 直连地址。
/// 对应 iroh 的 `EndpointAddr`。
class EndpointAddr {
public:
    EndpointAddr() = default;
    explicit EndpointAddr(EndpointId id) : id_{std::move(id)} {}

    const EndpointId &id() const { return id_; }
    const std::vector<RelayUrl> &relays() const { return relays_; }
    const std::vector<TransportAddr> &direct_addresses() const { return direct_addresses_; }

    /// P4-C-4: 自定义传输地址列表
    const std::vector<net::CustomTransportAddr> &custom_addrs() const { return custom_addrs_; }
    void add_custom_addr(net::CustomTransportAddr a) { custom_addrs_.push_back(std::move(a)); }

    void add_relay(RelayUrl r) { relays_.push_back(std::move(r)); }
    void add_direct_address(TransportAddr addr) { direct_addresses_.push_back(std::move(addr)); }

    /// 用户自定义的地址元数据（iroh 的 `UserData`），以字符串形式发布与解析。
    const std::string &user_data() const { return user_data_; }
    void set_user_data(std::string s) { user_data_ = std::move(s); }

    bool has_relay() const { return !relays_.empty(); }
    bool has_direct() const { return !direct_addresses_.empty(); }

    /// P4-C-4: 是否包含自定义传输地址
    bool has_custom() const { return !custom_addrs_.empty(); }

private:
    EndpointId id_;
    std::vector<RelayUrl> relays_;
    std::vector<TransportAddr> direct_addresses_;
    /// P4-C-4: 自定义传输地址（Tor/BLE/Mock 等非 IP 传输）
    std::vector<net::CustomTransportAddr> custom_addrs_;
    std::string user_data_;
};

} // namespace linoh::base
