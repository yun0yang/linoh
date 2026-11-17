// ice_candidate.hpp — P5-D-1 ICE 风格候选地址收集
//
// 借鉴 WebRTC ICE (RFC 8445) §5 Candidate Gathering + iroh v1.0 NAT 穿透工程化经验
//
// 设计原则：
//   - 候选类型按 RFC 8445 §5.1.1 分类（Host/Srflx/Prflx/Relay）
//   - 扩展类型支持 UPnPPortMapped（家庭路由器端口映射）和 Mdns（局域网匿名地址）
//   - 优先级按 RFC 8445 §5.1.2 公式计算
//   - foundation 字段用于候选去重和配对形成
//   - 收集过程异步并行（TaskPool 加速），可设置总超时
//
// 注意：
//   - 本模块仅定义候选结构和收集器接口，实际 STUN/UPnP/mDNS 操作由对应模块完成
//   - 收集器内部不持有 socket，通过回调或注入的 NetReporter 获取数据
//   - 收集结果缓存建议在 Endpoint 层做（5min TTL）

#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/net/path.hpp"
#include "linoh/net/net_report.hpp"
#include "linoh/util/task_pool.hpp"  // nn-L2: 保留以维持 ABI 兼容（下游可能 transitively 依赖）

#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace linoh::nat {

// ============================================================================
// 候选类型定义（RFC 8445 §5.1.1 + 扩展）
// ============================================================================

/// ICE 候选类型
enum class CandidateType : std::uint8_t {
    Host            = 0,  // 本地接口地址
    ServerReflexive = 1,  // STUN 探测的外部地址（srflx）
    PeerReflexive   = 2,  // 对端探测发现的地址（prflx）
    Relay           = 3,  // Relay 服务器分配的地址
    UPnPPortMapped  = 4,  // UPnP 端口映射的地址（扩展）
    Mdns            = 5,  // mDNS 匿名本地地址（扩展）
};

/// 候选类型转字符串（用于日志和序列化）
constexpr const char *candidate_type_name(CandidateType t) {
    switch (t) {
        case CandidateType::Host:            return "host";
        case CandidateType::ServerReflexive: return "srflx";
        case CandidateType::PeerReflexive:   return "prflx";
        case CandidateType::Relay:           return "relay";
        case CandidateType::UPnPPortMapped:  return "upnp";
        case CandidateType::Mdns:            return "mdns";
    }
    return "unknown";
}

/// 候选类型转简短代号（用于 foundation 字符串）
constexpr char candidate_type_code(CandidateType t) {
    switch (t) {
        case CandidateType::Host:            return 'H';
        case CandidateType::ServerReflexive: return 'S';
        case CandidateType::PeerReflexive:   return 'P';
        case CandidateType::Relay:           return 'R';
        case CandidateType::UPnPPortMapped:  return 'U';
        case CandidateType::Mdns:            return 'M';
    }
    return '?';
}

// ============================================================================
// 候选地址结构（RFC 8445 §5.1.1）
// ============================================================================

/// ICE 候选地址
struct Candidate {
    CandidateType type{CandidateType::Host};
    net::FourTuple tuple;
    std::uint32_t priority{0};        ///< RFC 8445 §5.1.2 优先级计算结果
    std::string foundation;           ///< 同类型同基础地址的标识
    std::chrono::milliseconds rtt{0}; ///< 探测 RTT（0 表示未测量）
    bool is_relayed{false};           ///< 是否经过 Relay（用于路径选择惩罚）
    std::string related_address;      ///< 关联地址（Host candidate 关联空；Srflx 关联 Host）

    /// 默认构造
    Candidate() = default;

    /// 完整构造
    Candidate(CandidateType t, net::FourTuple tup, std::uint32_t prio,
              std::string found, std::chrono::milliseconds r = std::chrono::milliseconds(0))
        : type(t), tuple(std::move(tup)), priority(prio),
          foundation(std::move(found)), rtt(r),
          is_relayed(t == CandidateType::Relay) {}

    /// 比较（按 priority 降序）
    bool operator<(const Candidate &other) const {
        return priority > other.priority;  // 优先级高的排前面
    }

    /// 相等比较（按 type + tuple）
    bool operator==(const Candidate &other) const {
        return type == other.type && tuple == other.tuple;
    }

    /// 转字符串（用于日志）
    std::string to_string() const;
};

// ============================================================================
// 优先级计算（RFC 8445 §5.1.2）
// ============================================================================

/// 候选类型偏好值（RFC 8445 §5.1.2 + 扩展）
/// 范围 0-126，越大越优先
constexpr std::uint32_t type_preference(CandidateType t) {
    switch (t) {
        case CandidateType::Host:            return 126;  // 最高
        case CandidateType::Mdns:            return 125;  // 仅次 Host
        case CandidateType::UPnPPortMapped:  return 120;  // UPnP 端口映射
        case CandidateType::PeerReflexive:   return 110;  // 对端发现
        case CandidateType::ServerReflexive: return 100;  // STUN 探测
        case CandidateType::Relay:           return 0;    // 最低（带宽成本高）
    }
    return 0;
}

/// 计算候选优先级（RFC 8445 §5.1.2 公式）
///
/// priority = (2^24) * type_preference
///          + (2^8)  * local_preference
///          + (2^0)  * (256 - component_id)
///
/// @param type 候选类型
/// @param local_pref 本地偏好（0-65535），默认 65535
/// @param component_id 组件 ID（1=RTP, 2=RTCP），linoh 通常为 1；
///                     0 视为非法，按 1 处理
/// @return 32 位优先级
constexpr std::uint32_t compute_candidate_priority(
    CandidateType type,
    std::uint16_t local_pref = 65535,
    std::uint8_t component_id = 1) {
    // RFC 8445: component_id 必须是 1 或 2；0 视为非法，按 1 处理
    std::uint8_t cid = (component_id == 0) ? 1 : component_id;
    std::uint32_t tp = type_preference(type);
    std::uint32_t lp = local_pref;
    std::uint32_t ci = static_cast<std::uint32_t>(256 - cid);
    return (tp << 24) | (lp << 8) | ci;
}

// ============================================================================
// Foundation 字符串构造（RFC 8445 §5.1.1.3）
// ============================================================================

/// 构造 foundation 字符串
/// 规则：<type_code><base_addr>:<port>
/// 同 type + 同 base 地址 + 同端口的候选共享同一 foundation
std::string make_foundation(CandidateType type,
                             const std::string &base_addr,
                             std::uint16_t base_port);

// ============================================================================
// P2-G8 候选过滤位掩码（隐藏 IP 隐私模式）
// ============================================================================
//
// 借鉴 WebRTC RTCIceCandidateFilter + tdesktop 隐藏 IP 策略：
// 通过位掩码按类型过滤候选，仅保留 Relay 候选时可隐藏本机真实 IP。
//
// 用法：
//   apply_filter(candidates, CF_RELAY)               → 仅保留 Relay
//   apply_filter(candidates, CF_HOST | CF_RELAY)     → 保留 Host + Relay
//   apply_filter(candidates, CF_ALL)                 → 全保留（默认）
//   apply_filter(candidates, CF_NONE)                → 全过滤

/// 候选过滤位掩码（可按位或组合）
enum CandidateFilter : std::uint16_t {
    CF_NONE              = 0,       ///< 过滤全部
    CF_HOST              = 1 << 0,  ///< 本地接口地址
    CF_SERVER_REFLEXIVE  = 1 << 1,  ///< STUN srflx
    CF_PEER_REFLEXIVE    = 1 << 2,  ///< 对端 prflx
    CF_RELAY             = 1 << 3,  ///< Relay 中继
    CF_UPNP              = 1 << 4,  ///< UPnP 端口映射
    CF_MDNS              = 1 << 5,  ///< mDNS 匿名地址
    CF_ALL               = 0x3F,    ///< 全部类型（低 6 位全 1）
};

/// 将 CandidateType 映射到对应的 CandidateFilter 位
constexpr CandidateFilter candidate_type_to_filter(CandidateType t) noexcept {
    switch (t) {
        case CandidateType::Host:            return CF_HOST;
        case CandidateType::ServerReflexive: return CF_SERVER_REFLEXIVE;
        case CandidateType::PeerReflexive:   return CF_PEER_REFLEXIVE;
        case CandidateType::Relay:           return CF_RELAY;
        case CandidateType::UPnPPortMapped:  return CF_UPNP;
        case CandidateType::Mdns:            return CF_MDNS;
    }
    return CF_NONE;
}

/// 按位掩码过滤候选列表（G8 隐藏 IP 核心函数）
///
/// @param candidates 原始候选列表
/// @param filter 位掩码（CF_HOST | CF_RELAY 等），CF_NONE 过滤全部，CF_ALL 保留全部
/// @return 过滤后的候选列表（保持原顺序）
std::vector<Candidate> apply_filter(const std::vector<Candidate> &candidates,
                                    CandidateFilter filter) noexcept;

/// CandidateFilter 转字符串（用于日志）
const char *candidate_filter_name(CandidateFilter f) noexcept;

// ============================================================================
// 候选收集器配置
// ============================================================================

/// 候选收集配置
struct CandidateCollectorConfig {
    /// STUN 服务器列表（host:port）
    std::vector<std::string> stun_servers;

    /// Relay 服务器列表（url 格式：relay://host:port）
    std::vector<std::string> relay_servers;

    /// 是否启用 UPnP 端口映射
    bool enable_upnp{true};

    /// 是否启用 mDNS 匿名地址
    bool enable_mdns{true};

    /// 是否启用 host candidate（本地网卡遍历）
    bool enable_host{true};

    /// P2-G8: 是否启用 ServerReflexive candidate（STUN 探测）
    /// false 时即使 stun_servers 非空也不收集 srflx（隐藏 IP 模式禁用）
    bool enable_srflx{true};

    /// P2-G8: 候选类型过滤位掩码（gather 完成后应用）
    /// 默认 CF_ALL（全保留，向后兼容）；隐藏 IP 模式设为 CF_RELAY
    CandidateFilter candidate_filter{CF_ALL};

    /// 收集总超时（默认 5s）
    std::chrono::milliseconds timeout{std::chrono::seconds(5)};

    /// 单个 STUN 请求超时
    std::chrono::milliseconds stun_timeout{std::chrono::milliseconds(2000)};

    /// 本地偏好值（0-65535，越大越优）
    std::uint16_t local_preference{65535};

    /// 是否仅收集 IPv4（默认 false，双栈）
    bool ipv4_only{false};

    /// 是否仅收集 IPv6（默认 false，双栈）
    bool ipv6_only{false};
};

// ============================================================================
// 候选收集器
// ============================================================================

/// 候选收集结果
struct CandidateGatherResult {
    std::vector<Candidate> candidates;       ///< 收集到的所有候选
    std::vector<std::string> errors;         ///< 收集过程中的错误信息
    std::chrono::milliseconds duration{0};   ///< 收集总耗时

    /// 按类型筛选候选
    std::vector<Candidate> filter_by_type(CandidateType t) const;

    /// 去重（同 type + 同 tuple）
    void deduplicate();

    /// 按优先级排序（降序）
    void sort_by_priority();

    /// 转字符串（用于日志）
    std::string to_string() const;
};

/// 候选收集回调类型（用于注入 STUN/Relay/UPnP/mDNS 实际操作）
///
/// 设计目的：解耦收集器与底层网络操作，便于单元测试 mock
/// 实际部署时由 Endpoint 注入真实实现
using HostCandidateProvider = std::function<std::vector<Candidate>()>;
using SrflxCandidateProvider = std::function<std::future<std::vector<Candidate>>(const std::string &stun_server)>;
using RelayCandidateProvider = std::function<std::future<std::vector<Candidate>>(const std::string &relay_url)>;
using UpnpCandidateProvider = std::function<std::future<std::optional<Candidate>>()>;
using MdnsCandidateProvider = std::function<std::future<std::optional<Candidate>>()>;

/// 候选收集器
///
/// 异步并行收集所有类型的候选地址，可注入自定义 provider 便于测试
class CandidateCollector {
public:
    /// 默认构造（使用内置 provider，依赖 NetReporter 等）
    explicit CandidateCollector(CandidateCollectorConfig config = {});

    /// 注入式构造（用于测试）
    CandidateCollector(
        CandidateCollectorConfig config,
        HostCandidateProvider host_provider,
        SrflxCandidateProvider srflx_provider,
        RelayCandidateProvider relay_provider,
        UpnpCandidateProvider upnp_provider,
        MdnsCandidateProvider mdns_provider);

    /// 收集所有候选地址（异步，超时由 config.timeout 控制）
    ///
    /// 流程：
    ///   1. 同步收集 host candidate（遍历本地网卡，<10ms）
    ///   2. 异步并行收集 srflx/relay/upnp/mdns candidate
    ///   3. 等待所有 future 完成或超时
    ///   4. 合并 + 去重 + 按优先级排序
    std::future<CandidateGatherResult> gather_candidates();

    /// 同步版（阻塞直到收集完成或超时）
    CandidateGatherResult gather_candidates_sync();

    /// 获取配置
    const CandidateCollectorConfig &config() const { return config_; }

private:
    CandidateCollectorConfig config_;
    HostCandidateProvider host_provider_;
    SrflxCandidateProvider srflx_provider_;
    RelayCandidateProvider relay_provider_;
    UpnpCandidateProvider upnp_provider_;
    MdnsCandidateProvider mdns_provider_;
    // nn-L2 (v1.7.0.8): task_pool_ 已移除（从未使用，浪费 4 线程）

    /// 默认 host provider（基于 getaddrinfo / 系统调用）
    static std::vector<Candidate> default_host_provider(
        const CandidateCollectorConfig &config);

    /// 默认 srflx provider（基于 NetReporter）
    static std::future<std::vector<Candidate>> default_srflx_provider(
        const CandidateCollectorConfig &config,
        const std::string &stun_server);

    /// 默认 relay provider（向 Relay 服务器申请分配）
    static std::future<std::vector<Candidate>> default_relay_provider(
        const CandidateCollectorConfig &config,
        const std::string &relay_url);

    /// 默认 UPnP provider（miniupnpc）
    static std::future<std::optional<Candidate>> default_upnp_provider(
        const CandidateCollectorConfig &config);

    /// 默认 mDNS provider（局域网匿名地址）
    static std::future<std::optional<Candidate>> default_mdns_provider(
        const CandidateCollectorConfig &config);
};

// ============================================================================
// 工具函数
// ============================================================================

/// 合并多个候选列表并去重
std::vector<Candidate> merge_and_deduplicate(
    const std::vector<std::vector<Candidate>> &lists);

/// 按候选类型统计数量
std::vector<std::pair<CandidateType, std::size_t>> count_by_type(
    const std::vector<Candidate> &candidates);

/// 判断候选是否适合作为本地候选（非 Relay）
inline bool is_local_candidate(const Candidate &c) {
    return c.type != CandidateType::Relay;
}

/// 判断候选是否需要 Relay 中转
inline bool needs_relay(const Candidate &c) {
    return c.type == CandidateType::Relay || c.is_relayed;
}

} // namespace linoh::nat
