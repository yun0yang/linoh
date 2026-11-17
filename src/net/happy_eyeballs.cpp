// happy_eyeballs.cpp — Happy Eyeballs v2（RFC 8305）实现

#include "linoh/net/happy_eyeballs.hpp"
#include "linoh/net/stun.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <future>
#include <mutex>
#include <thread>
#include <unordered_set>
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
// POSIX 平台 SOCKET 类型补丁（与 linoh_c.cpp 做法一致）
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#endif

namespace linoh::net {

namespace {

/// DNS 解析单个 host:port，返回 IPv4/IPv6 地址列表
std::vector<HappyEyeballsResult::Candidate> resolve_host(
    const std::string &host, std::uint16_t port, bool enable_ipv6) {
    std::vector<HappyEyeballsResult::Candidate> result;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo *res = nullptr;
    int rc = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);
    if (rc != 0 || !res) {
        return result;
    }

    for (addrinfo *p = res; p != nullptr; p = p->ai_next) {
        char buf[INET6_ADDRSTRLEN] = {};
        if (p->ai_family == AF_INET) {
            auto *sin = reinterpret_cast<sockaddr_in *>(p->ai_addr);
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            result.push_back({std::string(buf), port, false, false, "", std::chrono::microseconds{0}});
        } else if (p->ai_family == AF_INET6 && enable_ipv6) {
            auto *sin6 = reinterpret_cast<sockaddr_in6 *>(p->ai_addr);
            inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
            result.push_back({std::string(buf), port, true, false, "", std::chrono::microseconds{0}});
        }
    }

    freeaddrinfo(res);
    return result;
}

/// 单次 UDP STUN 探测
HappyEyeballsResult::Candidate probe_one_address(
    const HappyEyeballsResult::Candidate &target,
    std::chrono::milliseconds timeout) {
    HappyEyeballsResult::Candidate result = target;

    int af = target.is_v6 ? AF_INET6 : AF_INET;
    SOCKET sock = ::socket(af, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
    if (sock == INVALID_SOCKET) {
        result.error = "socket() failed";
        return result;
    }
#else
    if (sock < 0) {
        result.error = "socket() failed";
        return result;
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
            result.error = "bind(v6) failed";
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            return result;
        }
    } else {
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = 0;
        local.sin_addr.s_addr = INADDR_ANY;
        if (::bind(sock, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0) {
            result.error = "bind(v4) failed";
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            return result;
        }
    }

    // 构造 STUN Binding Request
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
            result.error = "sendto(v6) failed";
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            return result;
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
            result.error = "sendto(v4) failed";
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            return result;
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
    result.rtt = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

#ifdef _WIN32
    closesocket(sock);
#else
    ::close(sock);
#endif

    if (n <= 0) {
        result.error = "recvfrom timeout or failed";
        return result;
    }

    // 验证 STUN 响应
    auto msg = stun::parse_message(std::span<const std::uint8_t>(recv_buf.data(), n));
    if (!msg) {
        result.error = "parse_message failed";
        return result;
    }

    if (msg->transaction_id != tx_id) {
        result.error = "transaction_id mismatch";
        return result;
    }

    result.success = true;
    return result;
}

} // namespace

// ============================================================================
// resolve_and_sort
// ============================================================================

std::vector<HappyEyeballsResult::Candidate> resolve_and_sort(
    const std::string &host,
    std::uint16_t port,
    bool enable_ipv6) {

    auto all = resolve_host(host, port, enable_ipv6);

    // 按 RFC 8305 §4 排序：IPv6 优先，IPv4 紧随，交替排列
    std::vector<HappyEyeballsResult::Candidate> v6, v4;
    for (auto &c : all) {
        if (c.is_v6) v6.push_back(c);
        else v4.push_back(c);
    }

    std::vector<HappyEyeballsResult::Candidate> sorted;
    sorted.reserve(v6.size() + v4.size());

    // 交替插入：v6[0], v4[0], v6[1], v4[1], ...
    std::size_t i = 0;
    while (i < v6.size() || i < v4.size()) {
        if (i < v6.size()) sorted.push_back(v6[i]);
        if (i < v4.size()) sorted.push_back(v4[i]);
        ++i;
    }

    return sorted;
}

// ============================================================================
// happy_eyeballs_probe
// ============================================================================

HappyEyeballsResult happy_eyeballs_probe(
    const std::string &host,
    std::uint16_t port,
    const HappyEyeballsOptions &options) {

    HappyEyeballsResult result{};

    // 1. DNS 解析 + 排序
    auto candidates = resolve_and_sort(host, port, options.enable_ipv6);
    if (candidates.empty()) {
        LINOH_WARN("HappyEyeballs: no candidates for ", host, ":", port);
        return result;
    }

    // 限制并发数（括号防止 Windows.h 的 min/max 宏污染）
    std::size_t max_concurrent = (std::min)(options.concurrency, candidates.size());

    if (!options.enabled) {
        // 顺序尝试模式
        for (auto &c : candidates) {
            auto probed = probe_one_address(c, options.probe_timeout);
            result.candidates.push_back(probed);
            if (probed.success) {
                result.ip = probed.ip;
                result.port = probed.port;
                result.is_v6 = probed.is_v6;
                result.rtt = probed.rtt;
                return result;
            }
        }
        return result;
    }

    // 2. 并发探测模式
    // 用 promise/future 机制：第一个成功的探测设置 winner
    std::atomic<bool> has_winner{false};
    std::mutex mu;
    std::condition_variable cv;

    HappyEyeballsResult::Candidate winner{};

    std::vector<std::thread> threads;
    std::atomic<std::size_t> next_idx{0};

    auto worker = [&]() {
        while (true) {
            if (has_winner.load()) return;

            std::size_t idx = next_idx.fetch_add(1);
            if (idx >= candidates.size()) return;

            auto probed = probe_one_address(candidates[idx], options.probe_timeout);

            {
                std::lock_guard<std::mutex> lk(mu);
                result.candidates.push_back(probed);
            }

            if (probed.success) {
                bool expected = false;
                if (has_winner.compare_exchange_strong(expected, true)) {
                    std::lock_guard<std::mutex> lk(mu);
                    winner = probed;
                    cv.notify_all();
                }
                return;
            }
        }
    };

    // 启动 max_concurrent 个工作线程
    for (std::size_t i = 0; i < max_concurrent; ++i) {
        threads.emplace_back(worker);
    }

    // 等待所有线程完成或出现 winner
    for (auto &t : threads) {
        if (t.joinable()) t.join();
    }

    if (has_winner.load()) {
        result.ip = winner.ip;
        result.port = winner.port;
        result.is_v6 = winner.is_v6;
        result.rtt = winner.rtt;
    }

    // 按原始候选顺序填充未探测的条目
    // nn-P3 (v1.7.0.8): O(n²) 双重循环去重 → unordered_set O(n)
    //   原实现遍历 candidates 对每个 c 再遍历 result.candidates 查重，O(n²)
    //   改用 unordered_set 记录已存在的 (ip,port,is_v6) 三元组，O(n)
    std::unordered_set<std::string> seen;
    seen.reserve(result.candidates.size());
    for (const auto &r : result.candidates) {
        seen.insert(r.ip + ":" + std::to_string(r.port) + ":" + (r.is_v6 ? "6" : "4"));
    }
    for (auto &c : candidates) {
        std::string key = c.ip + ":" + std::to_string(c.port) + ":" + (c.is_v6 ? "6" : "4");
        if (seen.insert(key).second) {
            result.candidates.push_back(c);
        }
    }

    return result;
}

std::future<HappyEyeballsResult> happy_eyeballs_probe_async(
    const std::string &host,
    std::uint16_t port,
    const HappyEyeballsOptions &options) {
    return std::async(std::launch::async, [=]() {
        return happy_eyeballs_probe(host, port, options);
    });
}

} // namespace linoh::net
