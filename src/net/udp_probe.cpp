// udp_probe.cpp — UDP 可用性三态探测实现（NAT 穿透优化 P0-G1）

#include "linoh/net/udp_probe.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <numeric>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
// POSIX 平台 SOCKET 类型补丁（与 holepuncher.cpp 做法一致）
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#endif

namespace linoh::net {

// ============================================================================
// UdpProbeResult::to_string
// ============================================================================

std::string UdpProbeResult::to_string() const {
    std::string s = "UdpProbeResult{availability=";
    s += std::string(to_string_view(availability));
    s += ", sent=";
    s += std::to_string(sent_count);
    s += ", received=";
    s += std::to_string(received_count);
    s += ", loss_rate=";
    // 格式化为百分比，保留 1 位小数
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%.1f%%", loss_rate * 100.0);
    s += buf;
    if (received_count > 0) {
        s += ", rtt[min=";
        s += std::to_string(min_rtt.count());
        s += "ms, max=";
        s += std::to_string(max_rtt.count());
        s += "ms, avg=";
        s += std::to_string(avg_rtt.count());
        s += "ms]";
    }
    s += ", duration=";
    s += std::to_string(total_duration.count());
    s += "ms";
    if (!error_msg.empty()) {
        s += ", error='";
        s += error_msg;
        s += "'";
    }
    s += "}";
    return s;
}

// ============================================================================
// UdpProber::classify — 纯逻辑三态判定
// ============================================================================

UdpAvailability UdpProber::classify(
    double loss_rate,
    std::uint32_t sent_count,
    double available_threshold,
    double bad_threshold) {

    // 未发送任何包，直接判定 NotAvailable
    if (sent_count == 0) {
        return UdpAvailability::NotAvailable;
    }

    // 回复率 = 1 - loss_rate
    double reply_rate = 1.0 - loss_rate;

    // Available: 回复率 >= available_threshold
    if (reply_rate >= available_threshold) {
        return UdpAvailability::Available;
    }
    // NotAvailable: 回复率 <= bad_threshold
    if (reply_rate <= bad_threshold) {
        return UdpAvailability::NotAvailable;
    }
    // Bad: 介于两者之间
    return UdpAvailability::Bad;
}

// ============================================================================
// UdpProber::probe_with_provider — mock 路径（测试用）
// ============================================================================

UdpProbeResult UdpProber::probe_with_provider(
    const std::string &remote_ip, std::uint16_t remote_port,
    const UdpProbeConfig &config,
    UdpPingProvider provider) {

    auto start = std::chrono::steady_clock::now();
    UdpProbeResult result;
    result.sent_count = config.ping_count;

    if (!provider) {
        result.error_msg = "provider is null";
        result.availability = UdpAvailability::NotAvailable;
        result.loss_rate = 1.0;
        result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    std::vector<std::chrono::milliseconds> rtts;
    rtts.reserve(config.ping_count);

    for (std::uint32_t i = 0; i < config.ping_count; ++i) {
        auto rtt = provider(remote_ip, remote_port, config.recv_timeout);
        if (rtt.has_value()) {
            ++result.received_count;
            rtts.push_back(*rtt);
        }
        // 模拟 ping_interval 间隔（provider 内部已模拟 recv_timeout，这里只补间隔）
        if (i + 1 < config.ping_count) {
            std::this_thread::sleep_for(config.ping_interval);
        }
    }

    // 统计 RTT
    if (!rtts.empty()) {
        auto [min_it, max_it] = std::minmax_element(rtts.begin(), rtts.end());
        result.min_rtt = *min_it;
        result.max_rtt = *max_it;
        auto sum = std::accumulate(rtts.begin(), rtts.end(), std::chrono::milliseconds{0});
        result.avg_rtt = sum / static_cast<std::int64_t>(rtts.size());
    }

    // 计算丢包率
    result.loss_rate = (result.sent_count == 0)
        ? 1.0
        : 1.0 - static_cast<double>(result.received_count) / static_cast<double>(result.sent_count);

    // 三态判定
    result.availability = classify(
        result.loss_rate, result.sent_count,
        config.available_threshold, config.bad_threshold);

    result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    LINOH_INFO("UdpProber: probe_with_provider result=", result.to_string());
    return result;
}

// ============================================================================
// UdpProber::probe — 真实 socket 路径（生产用）
// ============================================================================

UdpProbeResult UdpProber::probe(
    const std::string &local_ip, std::uint16_t local_port,
    const std::string &remote_ip, std::uint16_t remote_port,
    const UdpProbeConfig &config) {

    auto start = std::chrono::steady_clock::now();
    UdpProbeResult result;
    result.sent_count = config.ping_count;

    // 创建 UDP socket
    SOCKET sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
    if (sock == INVALID_SOCKET) {
        result.error_msg = "socket() failed: " + std::to_string(WSAGetLastError());
        result.availability = UdpAvailability::NotAvailable;
        result.loss_rate = 1.0;
        result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }
#else
    if (sock < 0) {
        result.error_msg = "socket() failed";
        result.availability = UdpAvailability::NotAvailable;
        result.loss_rate = 1.0;
        result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }
#endif

    // 绑定到本地地址
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(local_port);
    if (local_ip.empty() || local_ip == "0.0.0.0" ||
        inet_pton(AF_INET, local_ip.c_str(), &local.sin_addr) != 1) {
        local.sin_addr.s_addr = htonl(INADDR_ANY);  // 回退到任意地址
    }
    if (::bind(sock, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0) {
        result.error_msg = "bind() failed";
#ifdef _WIN32
        closesocket(sock);
#else
        ::close(sock);
#endif
        result.availability = UdpAvailability::NotAvailable;
        result.loss_rate = 1.0;
        result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    // 远端地址
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(remote_port);
    if (inet_pton(AF_INET, remote_ip.c_str(), &remote.sin_addr) != 1) {
        result.error_msg = "invalid remote ip";
#ifdef _WIN32
        closesocket(sock);
#else
        ::close(sock);
#endif
        result.availability = UdpAvailability::NotAvailable;
        result.loss_rate = 1.0;
        result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    // ping/pong 载荷
    const auto &ping = config.ping_payload;
    const auto &pong = config.pong_payload;

    std::vector<std::chrono::milliseconds> rtts;
    rtts.reserve(config.ping_count);

    // 循环发送 ping 并等待 pong
    for (std::uint32_t i = 0; i < config.ping_count; ++i) {
        auto send_ts = std::chrono::steady_clock::now();

        // 设置本次 recv 超时
#ifdef _WIN32
        DWORD ms = static_cast<DWORD>(
            (std::min<std::int64_t>)(config.recv_timeout.count(), 5000));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char *>(&ms), sizeof(ms));
#else
        struct timeval tv;
        tv.tv_sec = config.recv_timeout.count() / 1000;
        tv.tv_usec = (config.recv_timeout.count() % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

        // 发送 ping
        auto sent = ::sendto(sock, reinterpret_cast<const char *>(ping.data()),
                             static_cast<int>(ping.size()), 0,
                             reinterpret_cast<sockaddr *>(&remote), sizeof(remote));
        if (sent < 0) {
            LINOH_WARN("UdpProber: sendto failed on ping #", i);
            // 发送失败不算收到，继续下一个
            if (i + 1 < config.ping_count) {
                std::this_thread::sleep_for(config.ping_interval);
            }
            continue;
        }

        // 等待 pong
        std::array<std::uint8_t, 2048> recv_buf{};
        sockaddr_storage from{};
        socklen_t from_len = sizeof(from);
        auto n = ::recvfrom(sock, reinterpret_cast<char *>(recv_buf.data()),
                            static_cast<int>(recv_buf.size()), 0,
                            reinterpret_cast<sockaddr *>(&from), &from_len);

        if (n > 0) {
            // 校验 pong 载荷
            bool payload_ok = true;
            if (!pong.empty()) {
                if (static_cast<std::size_t>(n) < pong.size()) {
                    payload_ok = false;
                } else {
                    payload_ok = (std::memcmp(recv_buf.data(), pong.data(),
                                              pong.size()) == 0);
                }
            }

            if (payload_ok) {
                auto recv_ts = std::chrono::steady_clock::now();
                auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
                    recv_ts - send_ts);
                ++result.received_count;
                rtts.push_back(rtt);
            } else {
                LINOH_WARN("UdpProber: pong payload mismatch on ping #", i);
            }
        }
        // n <= 0 表示超时或错误，不计入 received

        // ping 间隔
        if (i + 1 < config.ping_count) {
            std::this_thread::sleep_for(config.ping_interval);
        }
    }

#ifdef _WIN32
    closesocket(sock);
#else
    ::close(sock);
#endif

    // 统计 RTT
    if (!rtts.empty()) {
        auto [min_it, max_it] = std::minmax_element(rtts.begin(), rtts.end());
        result.min_rtt = *min_it;
        result.max_rtt = *max_it;
        auto sum = std::accumulate(rtts.begin(), rtts.end(), std::chrono::milliseconds{0});
        result.avg_rtt = sum / static_cast<std::int64_t>(rtts.size());
    }

    // 计算丢包率
    result.loss_rate = (result.sent_count == 0)
        ? 1.0
        : 1.0 - static_cast<double>(result.received_count) / static_cast<double>(result.sent_count);

    // 三态判定
    result.availability = classify(
        result.loss_rate, result.sent_count,
        config.available_threshold, config.bad_threshold);

    result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    LINOH_INFO("UdpProber: probe to ", remote_ip, ":", remote_port,
               " result=", result.to_string());
    return result;
}

} // namespace linoh::net
