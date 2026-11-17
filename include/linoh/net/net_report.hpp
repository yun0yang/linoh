// net_report.hpp — 网络探测模块（P4-B-1）
//
// 借鉴 iroh iroh-net-report crate：主动探测 NAT 类型、UDP 防火墙状态、
// IPv4/IPv6 可达性，为 PathSelector 提供决策依据。
//
// 探测策略：
//   1. 向 STUN 服务器发 Binding Request，获取 MAPPED-ADDRESS（映射后的公网地址）
//   2. 用同一本地 socket 向不同 STUN 服务器发请求，对比映射地址端口：
//      - 端口相同 → Cone NAT（OpenInternet/FullCone/RestrictedCone/PortRestrictedCone）
//      - 端口不同 → Symmetric NAT（hard NAT）
//   3. 探测失败 → Unknown
//
// 注意：完整的 NAT 类型分类（Cone 子类）需要多个 STUN 服务器配合，
//      P4-B-1 仅实现 Symmetric vs Cone 的二分类（最关键的 hard NAT 判定）。

#pragma once

#include "linoh/base/endpoint_addr.hpp"

#include <chrono>
#include <cstdint>
#include <future>
#include <string>
#include <vector>

namespace linoh::net {

/// NAT 类型（借鉴 iroh net_report 分类）
enum class NatType {
    OpenInternet,       // 公网直连，无 NAT
    FullCone,           // Full Cone NAT
    RestrictedCone,     // Restricted Cone
    PortRestrictedCone, // Port Restricted Cone
    Symmetric,          // 对称 NAT（hard NAT，需要 Relay）
    Unknown,            // 探测失败
};

/// UDP 防火墙状态
enum class UdpFirewall {
    Open,       // UDP 出入均通畅
    Blocked,    // UDP 被防火墙阻断
    Unknown,    // 探测失败
};

/// 网络探测结果
struct NetReport {
    NatType nat_type{NatType::Unknown};
    UdpFirewall udp_firewall{UdpFirewall::Unknown};
    bool ipv4_reachable{false};     // IPv4 STUN 服务器是否可达
    bool ipv6_reachable{false};     // IPv6 STUN 服务器是否可达
    bool relay_recommended{false};  // 根据探测结果推荐是否用 Relay
    std::chrono::microseconds avg_rtt{0};

    /// 公网映射地址（从 STUN MAPPED-ADDRESS 获取）
    std::string public_ip;
    std::uint16_t public_port{0};

    /// 人类可读描述
    std::string to_string() const;

    /// 根据 nat_type 和可达性自动设置 relay_recommended
    void update_relay_recommendation() {
        relay_recommended = (nat_type == NatType::Symmetric) ||
                           (udp_firewall == UdpFirewall::Blocked) ||
                           (!ipv4_reachable && !ipv6_reachable);
    }
};

/// 网络探测器
class NetReporter {
public:
    /// 默认 STUN 服务器列表（按优先级排序，第一个失败自动切换下一个）
    static const std::vector<std::string> &default_stun_servers();

    /// 同步探测（阻塞，约 3-10s）
    /// @param stun_servers STUN 服务器列表（host:port 格式），空则用默认列表
    static NetReport probe(const std::vector<std::string> &stun_servers = {});

    /// 异步探测
    static std::future<NetReport> probe_async(
        const std::vector<std::string> &stun_servers = {});

    /// 探测配置
    struct Config {
        /// 单次 STUN 请求超时
        std::chrono::milliseconds request_timeout{std::chrono::milliseconds(2000)};
        /// 最大重试次数
        int max_retries{2};
        /// 是否启用 IPv6 探测
        bool enable_ipv6{true};
    };

    /// 带配置的同步探测
    static NetReport probe(const Config &cfg,
                            const std::vector<std::string> &stun_servers = {});
};

} // namespace linoh::net
