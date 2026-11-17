// happy_eyeballs.hpp — Happy Eyeballs v2（RFC 8305）实现
//
// P4-B-2：IPv4/IPv6 并发连接，避免 IPv6 优先时等待超时。
//
// 设计：
//   1. DNS 解析返回多个 A/AAAA 记录
//   2. 按 RFC 8305 §4 排序：IPv6 优先，但 IPv4 紧随其后（交替）
//   3. 对前 N 个地址并发 UDP 探测（发送 STUN Binding Request）
//   4. 首个收到响应的地址胜出，其他取消
//
// 借鉴 iroh PR #4299（Connect IPv4 and IPv6 concurrently）。
//
// 注意：linoh 的传输层是 UDP（QUIC），所以"连接成功"的判定是：
//   - UDP socket 能绑定本地端口
//   - sendto 不返回错误
//   - （可选）收到对端响应（用 STUN 探测）
//
// 本实现采用 STUN 探测方式，与 P4-B-1 的 NetReport 复用底层 stun 模块。

#pragma once

#include "linoh/base/endpoint_addr.hpp"

#include <chrono>
#include <cstdint>
#include <future>
#include <optional>
#include <string>
#include <vector>

namespace linoh::net {

/// Happy Eyeballs 探测结果
struct HappyEyeballsResult {
    /// 选中的目标地址
    std::string ip;
    std::uint16_t port{0};
    bool is_v6{false};

    /// 探测 RTT（从发送到收到响应）
    std::chrono::microseconds rtt{0};

    /// 尝试过的所有候选地址（按优先级排序）
    struct Candidate {
        std::string ip;
        std::uint16_t port{0};
        bool is_v6{false};
        bool success{false};
        std::string error;
        std::chrono::microseconds rtt{0};
    };
    std::vector<Candidate> candidates;
};

/// Happy Eyeballs 配置（RFC 8305）
struct HappyEyeballsOptions {
    /// 并发连接数（默认 2，IPv4+IPv6）
    std::size_t concurrency{2};

    /// 首选地址族超时（默认 250ms，RFC 8305 §5 推荐）
    /// 第一个地址尝试后等待此时间，若无响应则启动下一个
    std::chrono::milliseconds connection_attempt_delay{std::chrono::milliseconds(250)};

    /// 单次探测超时
    std::chrono::milliseconds probe_timeout{std::chrono::milliseconds(2000)};

    /// 是否启用 IPv6
    bool enable_ipv6{true};

    /// 是否启用 Happy Eyeballs（false 则顺序尝试）
    bool enabled{true};
};

/// DNS 解析 + RFC 8305 §4 地址排序
///
/// 返回按 Happy Eyeballs 规则排序的候选地址列表：
///   - IPv6 地址优先（AAAA 记录）
///   - IPv4 地址紧随其后（A 记录）
///   - 多个 IPv6/IPv4 交替排列
///
/// @param host 主机名或 IP 地址
/// @param port 端口
/// @param enable_ipv6 是否解析 IPv6
std::vector<HappyEyeballsResult::Candidate> resolve_and_sort(
    const std::string &host,
    std::uint16_t port,
    bool enable_ipv6 = true);

/// Happy Eyeballs 并发探测
///
/// @param host 目标主机
/// @param port 目标端口
/// @param options 探测选项
/// @return 探测结果（包含选中的地址和所有候选），全部失败时 result.ip 为空
HappyEyeballsResult happy_eyeballs_probe(
    const std::string &host,
    std::uint16_t port,
    const HappyEyeballsOptions &options = {});

/// 异步版本
std::future<HappyEyeballsResult> happy_eyeballs_probe_async(
    const std::string &host,
    std::uint16_t port,
    const HappyEyeballsOptions &options = {});

} // namespace linoh::net
