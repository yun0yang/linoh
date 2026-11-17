// net_report.cpp — 网络探测模块实现（P4-B-1）

#include "linoh/net/net_report.hpp"
#include "linoh/net/stun.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <future>
#include <random>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
// POSIX 平台 SOCKET 类型补丁（与 linoh_c.cpp 做法一致）
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#endif

namespace linoh::net {

// ============================================================================
// NetReport::to_string
// ============================================================================

std::string NetReport::to_string() const {
    auto nat_str = [](NatType t) -> const char * {
        switch (t) {
            case NatType::OpenInternet:       return "OpenInternet";
            case NatType::FullCone:           return "FullCone";
            case NatType::RestrictedCone:     return "RestrictedCone";
            case NatType::PortRestrictedCone: return "PortRestrictedCone";
            case NatType::Symmetric:          return "Symmetric";
            case NatType::Unknown:            return "Unknown";
        }
        return "?";
    };

    auto fw_str = [](UdpFirewall f) -> const char * {
        switch (f) {
            case UdpFirewall::Open:    return "Open";
            case UdpFirewall::Blocked: return "Blocked";
            case UdpFirewall::Unknown: return "Unknown";
        }
        return "?";
    };

    std::string s;
    s += "nat=" + std::string(nat_str(nat_type));
    s += " udp_fw=" + std::string(fw_str(udp_firewall));
    s += " v4=" + std::string(ipv4_reachable ? "ok" : "no");
    s += " v6=" + std::string(ipv6_reachable ? "ok" : "no");
    s += " relay_rec=" + std::string(relay_recommended ? "yes" : "no");
    s += " rtt_ms=" + std::to_string(avg_rtt.count() / 1000.0);
    if (!public_ip.empty()) {
        s += " public=" + public_ip + ":" + std::to_string(public_port);
    }
    return s;
}

// ============================================================================
// NetReporter
// ============================================================================

const std::vector<std::string> &NetReporter::default_stun_servers() {
    static const std::vector<std::string> servers = {
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun2.l.google.com:19302",
        "stun.cloudflare.com:3478",
    };
    return servers;
}

namespace {

/// 单次 STUN 探测结果
struct StunProbeResult {
    bool success{false};
    std::string mapped_ip;
    std::uint16_t mapped_port{0};
    std::chrono::microseconds rtt{0};
    std::string error;
};

/// 解析 host:port 字符串，DNS 解析为 IPv4/IPv6 地址列表
struct ResolvedAddr {
    std::string ip;
    std::uint16_t port{0};
    bool is_v6{false};
};

std::vector<ResolvedAddr> resolve_host(const std::string &host_port, bool enable_ipv6) {
    std::vector<ResolvedAddr> result;

    auto colon = host_port.rfind(':');
    if (colon == std::string::npos) return result;

    std::string host = host_port.substr(0, colon);
    std::string port_str = host_port.substr(colon + 1);
    std::uint16_t port = static_cast<std::uint16_t>(std::atoi(port_str.c_str()));
    if (port == 0) return result;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo *res = nullptr;
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0 || !res) {
        return result;
    }

    for (addrinfo *p = res; p != nullptr; p = p->ai_next) {
        char buf[INET6_ADDRSTRLEN] = {};
        if (p->ai_family == AF_INET) {
            auto *sin = reinterpret_cast<sockaddr_in *>(p->ai_addr);
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            result.push_back({std::string(buf), port, false});
        } else if (p->ai_family == AF_INET6 && enable_ipv6) {
            auto *sin6 = reinterpret_cast<sockaddr_in6 *>(p->ai_addr);
            inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
            result.push_back({std::string(buf), port, true});
        }
    }

    freeaddrinfo(res);
    return result;
}

/// 单次 STUN Binding Request/Response 探测
StunProbeResult stun_probe_once(const ResolvedAddr &target,
                                 std::chrono::milliseconds timeout) {
    StunProbeResult r{};

    int af = target.is_v6 ? AF_INET6 : AF_INET;
    SOCKET sock = ::socket(af, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
    if (sock == INVALID_SOCKET) {
        r.error = "socket() failed";
        return r;
    }
#else
    if (sock < 0) {
        r.error = "socket() failed";
        return r;
    }
#endif

    // 设置接收超时
#ifdef _WIN32
    DWORD ms = static_cast<DWORD>(timeout.count());
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&ms), sizeof(ms));
#else
    struct timeval tv;
    tv.tv_sec = timeout.count() / 1000;
    tv.tv_usec = (timeout.count() % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    // 绑定到任意本地端口
    if (target.is_v6) {
        sockaddr_in6 local{};
        local.sin6_family = AF_INET6;
        local.sin6_port = 0;
        local.sin6_addr = in6addr_any;
        if (::bind(sock, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0) {
            r.error = "bind(v6) failed";
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            return r;
        }
    } else {
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = 0;
        local.sin_addr.s_addr = INADDR_ANY;
        if (::bind(sock, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0) {
            r.error = "bind(v4) failed";
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            return r;
        }
    }

    // 构造 Binding Request
    auto tx_id = stun::generate_transaction_id();
    auto request = stun::encode_binding_request(tx_id);

    // 发送
    if (target.is_v6) {
        sockaddr_in6 dst{};
        dst.sin6_family = AF_INET6;
        dst.sin6_port = htons(target.port);
        inet_pton(AF_INET6, target.ip.c_str(), &dst.sin6_addr);
        auto sent = ::sendto(sock, reinterpret_cast<const char *>(request.data()),
                              static_cast<int>(request.size()), 0,
                              reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
        if (sent < 0 || static_cast<size_t>(sent) != request.size()) {
            r.error = "sendto(v6) failed";
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            return r;
        }
    } else {
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(target.port);
        inet_pton(AF_INET, target.ip.c_str(), &dst.sin_addr);
        auto sent = ::sendto(sock, reinterpret_cast<const char *>(request.data()),
                              static_cast<int>(request.size()), 0,
                              reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
        if (sent < 0 || static_cast<size_t>(sent) != request.size()) {
            r.error = "sendto(v4) failed";
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            return r;
        }
    }

    // 接收
    auto start = std::chrono::steady_clock::now();

    std::array<std::uint8_t, 2048> recv_buf{};
    sockaddr_storage from{};
    socklen_t from_len = sizeof(from);
    auto n = ::recvfrom(sock, reinterpret_cast<char *>(recv_buf.data()),
                        static_cast<int>(recv_buf.size()), 0,
                        reinterpret_cast<sockaddr *>(&from), &from_len);

    auto end = std::chrono::steady_clock::now();
    r.rtt = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

#ifdef _WIN32
    closesocket(sock);
#else
    ::close(sock);
#endif

    if (n <= 0) {
        r.error = "recvfrom timeout or failed";
        return r;
    }

    // 解析响应
    auto msg = stun::parse_message(std::span<const std::uint8_t>(recv_buf.data(), n));
    if (!msg) {
        r.error = "parse_message failed";
        return r;
    }

    // 验证事务 ID 匹配
    if (msg->transaction_id != tx_id) {
        r.error = "transaction_id mismatch";
        return r;
    }

    // 优先使用 XOR-MAPPED-ADDRESS，其次 MAPPED-ADDRESS
    if (auto *xor_attr = msg->find(stun::AttributeType::XorMappedAddress)) {
        auto parsed = stun::parse_xor_mapped_address(*xor_attr, msg->transaction_id);
        if (parsed) {
            r.mapped_ip = parsed->first;
            r.mapped_port = parsed->second;
            r.success = true;
            return r;
        }
    }

    if (auto *mapped_attr = msg->find(stun::AttributeType::MappedAddress)) {
        auto parsed = stun::parse_mapped_address(*mapped_attr);
        if (parsed) {
            r.mapped_ip = parsed->first;
            r.mapped_port = parsed->second;
            r.success = true;
            return r;
        }
    }

    r.error = "no MAPPED-ADDRESS attribute";
    return r;
}

} // namespace

// ============================================================================
// probe 实现
// ============================================================================

NetReport NetReporter::probe(const std::vector<std::string> &stun_servers) {
    return probe(Config{}, stun_servers);
}

NetReport NetReporter::probe(const Config &cfg,
                              const std::vector<std::string> &stun_servers) {
    NetReport report{};

    const auto &servers = stun_servers.empty() ? default_stun_servers() : stun_servers;

    // 至少需要 2 个 STUN 服务器才能判定 Symmetric NAT
    // 但即使只有 1 个，也能判定 UDP 是否可达

    struct ProbeResult {
        ResolvedAddr target;
        StunProbeResult result;
        bool v6{false};
    };

    std::vector<ProbeResult> results;

    for (const auto &srv : servers) {
        auto addrs = resolve_host(srv, cfg.enable_ipv6);
        for (auto &a : addrs) {
            // 重试逻辑
            StunProbeResult r{};
            r.success = false;
            for (int retry = 0; retry <= cfg.max_retries && !r.success; ++retry) {
                r = stun_probe_once(a, cfg.request_timeout);
                if (r.success) break;
            }
            results.push_back({a, r, a.is_v6});

            // 只取每个服务器第一个解析结果（避免过多探测）
            break;
        }

        // 已经够判断了：至少 2 个成功的探测
        size_t success_count = 0;
        for (auto &pr : results) if (pr.result.success) ++success_count;
        if (success_count >= 2) break;
    }

    // 汇总结果
    bool any_v4_success = false;
    bool any_v6_success = false;
    std::chrono::microseconds total_rtt{0};
    int rtt_count = 0;
    std::string first_mapped_ip;
    std::uint16_t first_mapped_port = 0;

    for (auto &pr : results) {
        if (pr.result.success) {
            if (pr.v6) any_v6_success = true;
            else any_v4_success = true;

            total_rtt += pr.result.rtt;
            ++rtt_count;

            if (first_mapped_ip.empty()) {
                first_mapped_ip = pr.result.mapped_ip;
                first_mapped_port = pr.result.mapped_port;
            }
        }
    }

    report.ipv4_reachable = any_v4_success;
    report.ipv6_reachable = any_v6_success;
    if (rtt_count > 0) {
        report.avg_rtt = total_rtt / rtt_count;
    }
    report.public_ip = first_mapped_ip;
    report.public_port = first_mapped_port;

    // UDP 防火墙判定
    if (any_v4_success || any_v6_success) {
        report.udp_firewall = UdpFirewall::Open;
    } else {
        report.udp_firewall = UdpFirewall::Blocked;
    }

    // NAT 类型判定
    if (!any_v4_success && !any_v6_success) {
        // 全部失败：无法判定
        report.nat_type = NatType::Unknown;
    } else if (results.size() >= 2 && results[0].result.success && results[1].result.success) {
        // 有 2 个成功探测，对比映射端口
        if (results[0].result.mapped_port == results[1].result.mapped_port) {
            // 端口相同：Cone NAT（OpenInternet/FullCone/RestrictedCone/PortRestrictedCone）
            // P4-B-1 不进一步区分，统一标记为 FullCone（最常见的可穿透类型）
            // OpenInternet：本地地址 == 公网映射地址
            if (results[0].result.mapped_ip == results[0].target.ip) {
                report.nat_type = NatType::OpenInternet;
            } else {
                report.nat_type = NatType::FullCone;
            }
        } else {
            // 端口不同：Symmetric NAT（hard NAT）
            report.nat_type = NatType::Symmetric;
        }
    } else {
        // 只有 1 个成功：无法对比，保守标记为 Unknown
        // 不影响 UDP 可达性判定
        report.nat_type = NatType::Unknown;
    }

    report.update_relay_recommendation();

    LINOH_INFO("NetReport: ", report.to_string());
    return report;
}

std::future<NetReport> NetReporter::probe_async(
    const std::vector<std::string> &stun_servers) {
    return std::async(std::launch::async, [stun_servers]() {
        return probe(stun_servers);
    });
}

} // namespace linoh::net
