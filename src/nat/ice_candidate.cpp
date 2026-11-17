// ice_candidate.cpp — P5-D-1 ICE 风格候选地址收集实现
//
// 实现：
//   - Candidate::to_string()
//   - make_foundation()
//   - CandidateGatherResult 方法
//   - CandidateCollector 实现
//   - merge_and_deduplicate / count_by_type 工具函数

#include "linoh/nat/ice_candidate.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace linoh::nat {

// ============================================================================
// Candidate 方法
// ============================================================================

std::string Candidate::to_string() const {
    std::ostringstream oss;
    oss << "Candidate{type=" << candidate_type_name(type)
        << ", prio=" << priority
        << ", foundation=" << (foundation.empty() ? "<none>" : foundation)
        << ", tuple=" << tuple.to_string()
        << ", rtt=" << rtt.count() << "ms"
        << ", relayed=" << (is_relayed ? "true" : "false");
    if (!related_address.empty()) {
        oss << ", related=" << related_address;
    }
    oss << "}";
    return oss.str();
}

// ============================================================================
// Foundation 构造
// ============================================================================

std::string make_foundation(CandidateType type,
                             const std::string &base_addr,
                             std::uint16_t base_port) {
    std::ostringstream oss;
    oss << candidate_type_code(type) << ":" << base_addr << ":" << base_port;
    return oss.str();
}

// ============================================================================
// CandidateGatherResult 方法
// ============================================================================

std::vector<Candidate> CandidateGatherResult::filter_by_type(CandidateType t) const {
    std::vector<Candidate> result;
    for (const auto &c : candidates) {
        if (c.type == t) result.push_back(c);
    }
    return result;
}

void CandidateGatherResult::deduplicate() {
    std::vector<Candidate> unique;
    std::unordered_set<std::string> seen;
    seen.reserve(candidates.size() * 2);

    for (const auto &c : candidates) {
        std::string key = std::string(candidate_type_name(c.type)) + "|" + c.tuple.to_string();
        if (seen.insert(key).second) {
            unique.push_back(c);
        }
    }
    candidates = std::move(unique);
}

void CandidateGatherResult::sort_by_priority() {
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate &a, const Candidate &b) {
                  return a.priority > b.priority;
              });
}

std::string CandidateGatherResult::to_string() const {
    std::ostringstream oss;
    oss << "CandidateGatherResult{count=" << candidates.size()
        << ", duration=" << duration.count() << "ms";
    if (!errors.empty()) {
        oss << ", errors=[";
        for (std::size_t i = 0; i < errors.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << "\"" << errors[i] << "\"";
        }
        oss << "]";
    }
    oss << "}";
    return oss.str();
}

// ============================================================================
// 工具函数
// ============================================================================

std::vector<Candidate> merge_and_deduplicate(
    const std::vector<std::vector<Candidate>> &lists) {
    std::vector<Candidate> merged;
    std::unordered_set<std::string> seen;

    for (const auto &list : lists) {
        for (const auto &c : list) {
            std::string key = std::string(candidate_type_name(c.type)) + "|" + c.tuple.to_string();
            if (seen.insert(key).second) {
                merged.push_back(c);
            }
        }
    }
    return merged;
}

std::vector<std::pair<CandidateType, std::size_t>> count_by_type(
    const std::vector<Candidate> &candidates) {
    std::map<CandidateType, std::size_t> counter;
    for (const auto &c : candidates) {
        counter[c.type]++;
    }
    std::vector<std::pair<CandidateType, std::size_t>> result;
    for (const auto &[type, count] : counter) {
        result.emplace_back(type, count);
    }
    return result;
}

// ============================================================================
// P2-G8 候选过滤位掩码实现（隐藏 IP 隐私模式）
// ============================================================================

std::vector<Candidate> apply_filter(const std::vector<Candidate> &candidates,
                                    CandidateFilter filter) noexcept {
    std::vector<Candidate> result;
    if (filter == CF_NONE) return result;  // 全过滤
    // CF_ALL 时直接复制（避免逐个位检查）
    if (filter == CF_ALL) {
        result = candidates;
        return result;
    }
    result.reserve(candidates.size());
    for (const auto &c : candidates) {
        CandidateFilter bit = candidate_type_to_filter(c.type);
        if ((static_cast<std::uint16_t>(filter) & static_cast<std::uint16_t>(bit)) != 0) {
            result.push_back(c);
        }
    }
    return result;
}

const char *candidate_filter_name(CandidateFilter f) noexcept {
    if (f == CF_NONE) return "none";
    if (f == CF_ALL) return "all";
    // 组合掩码：返回 "mixed"（精确组合名仅用于日志，无需枚举全部）
    switch (f) {
        case CF_HOST:             return "host-only";
        case CF_SERVER_REFLEXIVE: return "srflx-only";
        case CF_PEER_REFLEXIVE:   return "prflx-only";
        case CF_RELAY:            return "relay-only";
        case CF_UPNP:             return "upnp-only";
        case CF_MDNS:             return "mdns-only";
    }
    return "mixed";
}

// ============================================================================
// CandidateCollector 实现
// ============================================================================

CandidateCollector::CandidateCollector(CandidateCollectorConfig config)
    : config_(std::move(config)) {
    // nn-L2 (v1.7.0.8): 移除未使用的 task_pool_（4 线程 TaskPool 创建后从未 submit
    //   任何任务，gather_candidates 用 std::async 替代，纯浪费 4 个线程的栈内存
    //   + 调度开销）。如未来需要并行 candidate 收集，应改用 task_pool_->submit。
    // 默认 provider 绑定
    host_provider_ = [this]() {
        return default_host_provider(config_);
    };
    srflx_provider_ = [this](const std::string &stun) {
        return default_srflx_provider(config_, stun);
    };
    relay_provider_ = [this](const std::string &url) {
        return default_relay_provider(config_, url);
    };
    upnp_provider_ = [this]() {
        return default_upnp_provider(config_);
    };
    mdns_provider_ = [this]() {
        return default_mdns_provider(config_);
    };
}

CandidateCollector::CandidateCollector(
    CandidateCollectorConfig config,
    HostCandidateProvider host_provider,
    SrflxCandidateProvider srflx_provider,
    RelayCandidateProvider relay_provider,
    UpnpCandidateProvider upnp_provider,
    MdnsCandidateProvider mdns_provider)
    : config_(std::move(config)),
      host_provider_(std::move(host_provider)),
      srflx_provider_(std::move(srflx_provider)),
      relay_provider_(std::move(relay_provider)),
      upnp_provider_(std::move(upnp_provider)),
      mdns_provider_(std::move(mdns_provider)) {
    // nn-L2 (v1.7.0.8): 同上，移除 task_pool_ 初始化
}

std::future<CandidateGatherResult> CandidateCollector::gather_candidates() {
    return std::async(std::launch::async, [this]() {
        return gather_candidates_sync();
    });
}

CandidateGatherResult CandidateCollector::gather_candidates_sync() {
    auto start = std::chrono::steady_clock::now();
    CandidateGatherResult result;

    // 1. 同步收集 host candidate（<10ms，立即完成）
    if (config_.enable_host) {
        try {
            auto hosts = host_provider_();
            for (auto &h : hosts) {
                result.candidates.push_back(std::move(h));
            }
        } catch (const std::exception &e) {
            result.errors.push_back(std::string("host: ") + e.what());
        }
    }

    // 2. 异步并行收集 srflx/relay/upnp/mdns
    std::vector<std::future<std::vector<Candidate>>> srflx_futs;
    std::vector<std::future<std::vector<Candidate>>> relay_futs;
    std::future<std::optional<Candidate>> upnp_fut;
    std::future<std::optional<Candidate>> mdns_fut;

    // P2-G8: enable_srflx=false 时跳过 STUN 探测（隐藏 IP 模式禁用 srflx）
    if (config_.enable_srflx) {
        for (const auto &stun : config_.stun_servers) {
            srflx_futs.push_back(srflx_provider_(stun));
        }
    }
    for (const auto &url : config_.relay_servers) {
        relay_futs.push_back(relay_provider_(url));
    }
    if (config_.enable_upnp) {
        upnp_fut = upnp_provider_();
    }
    if (config_.enable_mdns) {
        mdns_fut = mdns_provider_();
    }

    // 3. 等待所有 future 完成或超时
    auto deadline = start + config_.timeout;

    auto wait_futures = [&](auto &futs, const char *name) {
        for (auto &f : futs) {
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
            if (remaining.count() <= 0) {
                result.errors.push_back(std::string(name) + ": timeout");
                break;
            }
            auto status = f.wait_for(remaining);
            if (status == std::future_status::ready) {
                try {
                    auto cs = f.get();
                    for (auto &c : cs) {
                        result.candidates.push_back(std::move(c));
                    }
                } catch (const std::exception &e) {
                    result.errors.push_back(std::string(name) + std::string(": ") + e.what());
                }
            } else {
                result.errors.push_back(std::string(name) + ": timeout");
            }
        }
    };

    wait_futures(srflx_futs, "srflx");
    wait_futures(relay_futs, "relay");

    if (config_.enable_upnp && upnp_fut.valid()) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() > 0) {
            auto status = upnp_fut.wait_for(remaining);
            if (status == std::future_status::ready) {
                try {
                    auto c = upnp_fut.get();
                    if (c.has_value()) {
                        result.candidates.push_back(std::move(*c));
                    }
                } catch (const std::exception &e) {
                    result.errors.push_back(std::string("upnp: ") + e.what());
                }
            } else {
                result.errors.push_back("upnp: timeout");
            }
        }
    }

    if (config_.enable_mdns && mdns_fut.valid()) {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() > 0) {
            auto status = mdns_fut.wait_for(remaining);
            if (status == std::future_status::ready) {
                try {
                    auto c = mdns_fut.get();
                    if (c.has_value()) {
                        result.candidates.push_back(std::move(*c));
                    }
                } catch (const std::exception &e) {
                    result.errors.push_back(std::string("mdns: ") + e.what());
                }
            } else {
                result.errors.push_back("mdns: timeout");
            }
        }
    }

    // 4. 去重 + 排序
    result.deduplicate();
    result.sort_by_priority();

    // P2-G8: 按候选过滤位掩码过滤（默认 CF_ALL 全保留，隐藏 IP 模式设为 CF_RELAY）
    if (config_.candidate_filter != CF_ALL) {
        result.candidates = apply_filter(result.candidates, config_.candidate_filter);
    }

    auto end = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    return result;
}

// ============================================================================
// 默认 provider 实现
// ============================================================================

std::vector<Candidate> CandidateCollector::default_host_provider(
    const CandidateCollectorConfig &config) {
    std::vector<Candidate> candidates;

#ifdef _WIN32
    WSADATA wsaData;
    static std::once_flag wsa_flag;
    std::call_once(wsa_flag, [&]() {
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    });
#endif

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        return candidates;
    }

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // IPv4 + IPv6
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *result_list = nullptr;
    if (getaddrinfo(hostname, nullptr, &hints, &result_list) != 0) {
        return candidates;
    }

    std::set<std::string> seen_addrs;
    for (struct addrinfo *p = result_list; p != nullptr; p = p->ai_next) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        if (p->ai_family == AF_INET) {
            auto *sin = reinterpret_cast<struct sockaddr_in *>(p->ai_addr);
            inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
        } else if (p->ai_family == AF_INET6) {
            auto *sin6 = reinterpret_cast<struct sockaddr_in6 *>(p->ai_addr);
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
        } else {
            continue;
        }

        std::string ip(ip_str);
        // 跳过回环地址
        if (ip == "127.0.0.1" || ip == "::1") continue;
        // 跳过 link-local
        if (ip.find("169.254.") == 0) continue;
        if (ip.find("fe80:") == 0) continue;

        // IPv4/IPv6 过滤
        bool is_ipv6 = ip.find(':') != std::string::npos;
        if (config.ipv4_only && is_ipv6) continue;
        if (config.ipv6_only && !is_ipv6) continue;

        if (!seen_addrs.insert(ip).second) continue;

        // 构造候选
        base::TransportAddr local_addr;
        local_addr.kind = base::TransportKind::Ip;
        local_addr.host = ip;
        local_addr.port = 0;  // host candidate 端口待绑定

        base::TransportAddr remote_addr;
        remote_addr.kind = base::TransportKind::Ip;
        remote_addr.host = ip;
        remote_addr.port = 0;

        net::FourTuple tuple;
        tuple.local_addr = local_addr;
        tuple.remote_addr = remote_addr;

        Candidate c;
        c.type = CandidateType::Host;
        c.tuple = std::move(tuple);
        // S6-④（v5.3）v6 优先：同 type 内 v6 地址 local_preference +1
        //（happy-eyeballs 一致的 v6 优先策略；config.local_preference=65535
        // 时 v6=65535、v4=65534——priority 排序 v6 前置，避免运营商 v4 NAT
        // 层级叠加；IPv4 过滤器不受影响）
        c.priority = compute_candidate_priority(
            CandidateType::Host,
            is_ipv6 ? config.local_preference
                    : (config.local_preference > 0 ? config.local_preference - 1 : 0));
        c.foundation = make_foundation(CandidateType::Host, ip, 0);
        c.related_address = "";
        candidates.push_back(std::move(c));
    }

    freeaddrinfo(result_list);
    return candidates;
}

std::future<std::vector<Candidate>> CandidateCollector::default_srflx_provider(
    const CandidateCollectorConfig &config,
    const std::string &stun_server) {
    return std::async(std::launch::async, [config, stun_server]() {
        std::vector<Candidate> candidates;

        // 解析 stun_server (host:port)
        auto colon = stun_server.find(':');
        if (colon == std::string::npos) {
            throw std::runtime_error("invalid stun server format: " + stun_server);
        }
        std::string host = stun_server.substr(0, colon);
        std::string port_str = stun_server.substr(colon + 1);
        std::uint16_t port = static_cast<std::uint16_t>(std::stoi(port_str));

        // 调用 NetReporter 探测（复用 P4-B-1 实现）
        auto report = net::NetReporter::probe({stun_server});
        if (report.public_ip.empty() || report.public_port == 0) {
            return candidates;
        }

        // 构造 server-reflexive candidate
        base::TransportAddr local_addr;
        local_addr.kind = base::TransportKind::Ip;
        local_addr.host = report.public_ip;
        local_addr.port = report.public_port;

        base::TransportAddr remote_addr;
        remote_addr.kind = base::TransportKind::Ip;
        remote_addr.host = host;
        remote_addr.port = port;

        net::FourTuple tuple;
        tuple.local_addr = local_addr;
        tuple.remote_addr = remote_addr;

        Candidate c;
        c.type = CandidateType::ServerReflexive;
        c.tuple = std::move(tuple);
        // S6-④（v5.3）v6 优先（与 Host 候选同策略：v6 reflexive 地址 +1）
        {
            const bool pub_is_ipv6 =
                report.public_ip.find(':') != std::string::npos;
            c.priority = compute_candidate_priority(
                CandidateType::ServerReflexive,
                pub_is_ipv6 ? config.local_preference
                            : (config.local_preference > 0
                                   ? config.local_preference - 1 : 0));
        }
        c.foundation = make_foundation(CandidateType::ServerReflexive, report.public_ip, report.public_port);
        c.related_address = host;
        candidates.push_back(std::move(c));

        return candidates;
    });
}

std::future<std::vector<Candidate>> CandidateCollector::default_relay_provider(
    const CandidateCollectorConfig &config,
    const std::string &relay_url) {
    return std::async(std::launch::async, [config, relay_url]() {
        std::vector<Candidate> candidates;

        // 解析 relay_url (relay://host:port)
        std::string host;
        std::uint16_t port = 0;
        const std::string prefix = "relay://";
        if (relay_url.find(prefix) == 0) {
            std::string rest = relay_url.substr(prefix.size());
            auto colon = rest.find(':');
            if (colon != std::string::npos) {
                host = rest.substr(0, colon);
                port = static_cast<std::uint16_t>(std::stoi(rest.substr(colon + 1)));
            } else {
                host = rest;
                port = 9002;  // 默认端口
            }
        } else {
            // 兼容 host:port 格式
            auto colon = relay_url.find(':');
            if (colon != std::string::npos) {
                host = relay_url.substr(0, colon);
                port = static_cast<std::uint16_t>(std::stoi(relay_url.substr(colon + 1)));
            } else {
                host = relay_url;
                port = 9002;
            }
        }

        // 默认实现：构造一个 placeholder Relay candidate
        // 实际部署时由 Endpoint 注入真实的 Relay client 调用
        base::TransportAddr local_addr;
        local_addr.kind = base::TransportKind::Relay;
        local_addr.host = host;
        local_addr.port = port;

        base::TransportAddr remote_addr;
        remote_addr.kind = base::TransportKind::Relay;
        remote_addr.host = host;
        remote_addr.port = port;

        net::FourTuple tuple;
        tuple.local_addr = local_addr;
        tuple.remote_addr = remote_addr;

        Candidate c;
        c.type = CandidateType::Relay;
        c.tuple = std::move(tuple);
        c.priority = compute_candidate_priority(CandidateType::Relay, config.local_preference);
        c.foundation = make_foundation(CandidateType::Relay, host, port);
        c.is_relayed = true;
        c.related_address = host;
        candidates.push_back(std::move(c));

        return candidates;
    });
}

std::future<std::optional<Candidate>> CandidateCollector::default_upnp_provider(
    const CandidateCollectorConfig &config) {
    return std::async(std::launch::async, [config]() -> std::optional<Candidate> {
        // UPnP 集成占位（实际部署需要 miniupnpc 依赖）
        // 返回 nullopt 表示未启用或失败
        (void)config;
        return std::nullopt;
    });
}

std::future<std::optional<Candidate>> CandidateCollector::default_mdns_provider(
    const CandidateCollectorConfig &config) {
    return std::async(std::launch::async, [config]() -> std::optional<Candidate> {
        // mDNS 集成占位（实际部署需要 mDNS 广告/发现）
        // 返回 nullopt 表示未启用或失败
        (void)config;
        return std::nullopt;
    });
}

} // namespace linoh::nat
