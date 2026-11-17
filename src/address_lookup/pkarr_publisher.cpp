#include "linoh/address_lookup/lookup.hpp"
#include "linoh/address_lookup/pkarr_server.hpp"

#include "linoh/util/logging.hpp"

#include <chrono>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define PKARR_SOCKET SOCKET
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#define PKARR_SOCKET int
#endif

namespace linoh::address_lookup {

void PkarrPublisher::bind_server(std::shared_ptr<PkarrDnsServer> s) {
    server_ = std::move(s);
}

void PkarrPublisher::publish(const base::EndpointAddr &addr) {
    // 1) 用标准 DNS wire 格式构造并签名
    std::vector<std::string> relay_hosts;
    std::vector<std::uint16_t> relay_ports;
    for (const auto &r : addr.relays()) {
        relay_hosts.push_back(r.host());
        relay_ports.push_back(r.port());
    }
    std::vector<std::string> direct_addrs;
    for (const auto &d : addr.direct_addresses()) {
        direct_addrs.push_back(d.host + ":" + std::to_string(d.port));
    }
    auto dns = pkarr::build_pkarr_dns_packet(addr.id(), relay_hosts, relay_ports,
                                             direct_addrs);
    auto sp = pkarr::sign_dns_packet(dns, key_);
    // 2) 存内存（序列化后的字节）
    {
        std::lock_guard<std::mutex> lk(mu_);
        signed_packet_ = pkarr::serialize_signed_packet(sp);
    }
    // 3) 若已绑定 server，直接写入其内存表（零网络、确定性）
    if (server_) server_->publish(addr.id(), sp);
    LINOH_INFO("PkarrPublisher: published signed packet for", addr.id().fmt_short());
}

std::optional<base::EndpointAddr> DnsAddressLookup::lookup(const base::EndpointId &id) {
    ++stats_.total_queries;
    // 进程内缓存优先（离线/快速路径，保持向后兼容）
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = cache_.find(id);
        if (it != cache_.end()) {
            ++stats_.cache_hits;
            return it->second;
        }
    }
    if (server_host_.empty() && fallback_servers_.empty()) {
        ++stats_.all_misses;
        return std::nullopt;
    }

    // P4-D-3: 按顺序尝试 [主服务器] + [fallback 列表]
    // 构建候选列表（在锁外执行网络 IO）
    std::vector<Server> candidates;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (!server_host_.empty()) {
            candidates.push_back({server_host_, server_port_});
        }
        for (const auto &s : fallback_servers_) candidates.push_back(s);
    }

    for (std::size_t i = 0; i < candidates.size(); ++i) {
        const auto &srv = candidates[i];
        std::vector<std::uint8_t> resp;
        if (!query_one_server(id, srv.host, srv.port, resp)) continue;
        auto addr = parse_and_cache(id, resp);
        if (addr) {
            if (i == 0 && !server_host_.empty()) ++stats_.primary_hits;
            else ++stats_.fallback_hits;
            return addr;
        }
    }
    ++stats_.all_misses;
    return std::nullopt;
}

bool DnsAddressLookup::query_one_server(const base::EndpointId &id,
                                         const std::string &host,
                                         uint16_t port,
                                         std::vector<std::uint8_t> &resp) {
    auto query = pkarr::build_pkarr_dns_query(id, 0x1234);
    std::intptr_t s = static_cast<std::intptr_t>(
        ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    if (s < 0) return false;
    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
#ifdef _WIN32
    srv.sin_addr.s_addr = inet_addr(host.c_str());
#else
    inet_pton(AF_INET, host.c_str(), &srv.sin_addr);
#endif

    bool got = false;
    std::uint32_t max_retries = max_retries_;
    std::uint32_t timeout_ms = query_timeout_ms_;
    for (std::uint32_t attempt = 0; attempt < max_retries && !got; ++attempt) {
        ::sendto(static_cast<PKARR_SOCKET>(s),
                 reinterpret_cast<const char *>(query.data()),
                 static_cast<int>(query.size()), 0,
                 reinterpret_cast<sockaddr *>(&srv), sizeof(srv));
        fd_set fds;
        FD_ZERO(&fds);
#ifdef _WIN32
        FD_SET(static_cast<PKARR_SOCKET>(s), &fds);
#else
        FD_SET(static_cast<int>(s), &fds);
#endif
        timeval tv;
        tv.tv_sec = static_cast<long>(timeout_ms / 1000);
        tv.tv_usec = static_cast<long>((timeout_ms % 1000) * 1000);
        int r = ::select(static_cast<int>(s) + 1, &fds, nullptr, nullptr, &tv);
        if (r <= 0) continue;
        std::uint8_t buf[8192];
        int n = static_cast<int>(::recvfrom(static_cast<PKARR_SOCKET>(s),
                                             reinterpret_cast<char *>(buf), sizeof(buf), 0,
                                             nullptr, nullptr));
        if (n <= 0) continue;
        resp.assign(buf, buf + n);
        got = true;
    }
#ifdef _WIN32
    ::closesocket(static_cast<PKARR_SOCKET>(s));
#else
    ::close(static_cast<int>(s));
#endif
    return got;
}

std::optional<base::EndpointAddr> DnsAddressLookup::parse_and_cache(
    const base::EndpointId &id,
    const std::vector<std::uint8_t> &resp) {
    auto sp = pkarr::deserialize_signed_packet(resp);
    if (!sp) return std::nullopt;
    auto addr = pkarr::parse_dns_response(*sp);
    if (addr) {
        std::lock_guard<std::mutex> lk(mu_);
        cache_[id] = *addr;
    }
    return addr;
}

void DnsAddressLookup::publish(const base::EndpointAddr &addr) {
    std::lock_guard<std::mutex> lk(mu_);
    cache_[addr.id()] = addr;
}

} // namespace linoh::address_lookup
