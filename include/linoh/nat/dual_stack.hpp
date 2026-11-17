// dual_stack.hpp — P5-D-4 IPv6/IPv4 跨栈双栈连接
//
// 借鉴 iroh Happy Eyeballs + RFC 8305 + IPv6-only 网络的 NAT64
//
// 设计原则：
//   - 检测本机网络栈支持情况（IPv4-only / IPv6-only / DualStack）
//   - 跨栈连接：IPv6-only → IPv4-only 通过 NAT64
//   - 跨栈连接：IPv4-only → IPv6-only 通过 6to4 隧道
//   - NAT64 地址合成（WKP 64:ff9b::/96 + 自定义前缀）
//   - DNS64 合成 AAAA 记录（占位，实际部署需要 DNS 查询）
//
// 注意：
//   - 默认禁用 NAT64/6to4 隧道（仅在检测到单栈网络时启用）
//   - 本模块仅定义接口和地址合成算法，实际 socket 操作由 Endpoint 注入

#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/net/path.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace linoh::nat {

// ============================================================================
// 双栈模式定义
// ============================================================================

/// 双栈连接模式
enum class DualStackMode : std::uint8_t {
    IPv4Only,      // 仅 IPv4
    IPv6Only,      // 仅 IPv6
    DualStack,     // 双栈（Happy Eyeballs）
    NAT64,         // IPv6 网络通过 NAT64 连接 IPv4 节点
    DNS64,         // DNS64 合成 AAAA 记录
    Disabled,      // 双栈均不可用（P5-D-3 边界修复）
};

/// 模式转字符串
constexpr const char *dual_stack_mode_name(DualStackMode m) {
    switch (m) {
        case DualStackMode::IPv4Only:  return "ipv4-only";
        case DualStackMode::IPv6Only:  return "ipv6-only";
        case DualStackMode::DualStack: return "dual-stack";
        case DualStackMode::NAT64:     return "nat64";
        case DualStackMode::DNS64:     return "dns64";
        case DualStackMode::Disabled:  return "disabled";
    }
    return "unknown";
}

// ============================================================================
// NAT64 前缀定义
// ============================================================================

/// NAT64 Well-Known Prefix（RFC 6052 §2.1）
/// 64:ff9b::/96
constexpr std::array<std::uint8_t, 12> kNat64WkpPrefix = {
    0x00, 0x64, 0xff, 0x9b, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/// NAT64 前缀长度（96 位，后 32 位为嵌入的 IPv4）
constexpr std::size_t kNat64PrefixBits = 96;

/// 自定义 NAT64 前缀
struct Nat64Prefix {
    std::array<std::uint8_t, 12> bytes{kNat64WkpPrefix};
    std::size_t prefix_bits{kNat64PrefixBits};

    /// 是否为 WKP
    bool is_wkp() const {
        return bytes == kNat64WkpPrefix && prefix_bits == kNat64PrefixBits;
    }

    /// 比较
    bool operator==(const Nat64Prefix &other) const {
        return bytes == other.bytes && prefix_bits == other.prefix_bits;
    }
};

// ============================================================================
// 地址族工具
// ============================================================================

/// 判断 IP 地址是否为 IPv6
/// 简单判断：包含冒号为 IPv6
bool is_ipv6_address(const std::string &ip);

/// 判断 IP 地址是否为 IPv4
/// 简单判断：包含点且不含冒号为 IPv4
bool is_ipv4_address(const std::string &ip);

/// 将 IPv4 字符串转换为 4 字节数组
/// @return 失败返回 nullopt
std::optional<std::array<std::uint8_t, 4>> parse_ipv4(const std::string &ip);

/// 将 4 字节数组转换为 IPv4 字符串
std::string format_ipv4(const std::array<std::uint8_t, 4> &bytes);

/// 将 IPv6 字符串转换为 16 字节数组
/// @return 失败返回 nullopt
std::optional<std::array<std::uint8_t, 16>> parse_ipv6(const std::string &ip);

/// 将 16 字节数组转换为 IPv6 字符串（简化格式）
std::string format_ipv6(const std::array<std::uint8_t, 16> &bytes);

// ============================================================================
// NAT64 地址合成（RFC 6052）
// ============================================================================

/// 合成 NAT64 地址（IPv4 嵌入 IPv6）
///
/// RFC 6052 §2.2: NAT64 前缀 96 位 + IPv4 32 位 = 128 位 IPv6 地址
/// WKP: 64:ff9b::/96
///
/// @param ipv4 IPv4 地址字符串
/// @param prefix NAT64 前缀（默认 WKP）
/// @return 合成的 IPv6 地址字符串；IPv4 解析失败返回 nullopt
std::optional<std::string> synthesize_nat64_address(
    const std::string &ipv4,
    const Nat64Prefix &prefix = {});

/// 从 NAT64 地址中提取嵌入的 IPv4
///
/// @param nat64_ipv6 NAT64 合成的 IPv6 地址
/// @param prefix NAT64 前缀（用于验证）
/// @return 提取的 IPv4 地址；非 NAT64 地址返回 nullopt
std::optional<std::string> extract_ipv4_from_nat64(
    const std::string &nat64_ipv6,
    const Nat64Prefix &prefix = {});

// ============================================================================
// 6to4 隧道地址合成（RFC 3056）
// ============================================================================

/// 6to4 前缀：2002::/16
constexpr std::array<std::uint8_t, 2> k6to4Prefix = {0x20, 0x02};

/// 合成 6to4 隧道地址
///
/// RFC 3056: 2002:VVVV:VVVV::/48，其中 VVVV:VVVV 是 IPv4 地址
///
/// @param ipv4 IPv4 地址
/// @return 合成的 6to4 IPv6 地址
std::optional<std::string> synthesize_6to4_address(const std::string &ipv4);

/// 判断 IPv6 地址是否为 6to4 地址
bool is_6to4_address(const std::string &ipv6);

/// 从 6to4 地址中提取 IPv4
std::optional<std::string> extract_ipv4_from_6to4(const std::string &ipv6);

// ============================================================================
// 双栈能力检测
// ============================================================================

/// 本机网络栈能力
struct LocalStackCapability {
    bool supports_ipv4{false};
    bool supports_ipv6{false};
    bool supports_nat64{false};      // 是否检测到 NAT64 网关
    bool supports_dns64{false};      // 是否检测到 DNS64
    std::vector<std::string> ipv4_addresses;
    std::vector<std::string> ipv6_addresses;

    /// 推断双栈模式（P5-D-3 边界修复：双栈均不可用时返回 Disabled）
    DualStackMode infer_mode() const {
        if (supports_ipv4 && supports_ipv6) return DualStackMode::DualStack;
        if (supports_ipv6 && supports_nat64) return DualStackMode::NAT64;
        if (supports_ipv6 && supports_dns64) return DualStackMode::DNS64;
        if (supports_ipv6) return DualStackMode::IPv6Only;
        if (supports_ipv4) return DualStackMode::IPv4Only;
        // 双栈均不可用（socket 创建失败 / 网络栈初始化异常）
        return DualStackMode::Disabled;
    }

    /// 转字符串
    std::string to_string() const;
};

/// 双栈检测回调（注入式，便于测试）
using StackDetector = std::function<LocalStackCapability()>;

/// 双栈连接器配置
struct DualStackConfig {
    /// 自定义 NAT64 前缀（默认 WKP）
    Nat64Prefix nat64_prefix{};

    /// 是否启用 NAT64 合成
    bool enable_nat64{true};

    /// 是否启用 6to4 隧道
    bool enable_6to4{false};

    /// 是否启用 DNS64 查询
    bool enable_dns64{false};

    /// Happy Eyeballs 延迟（IPv6 优先 ms）
    std::chrono::milliseconds happy_eyeballs_delay{std::chrono::milliseconds(250)};
};

// ============================================================================
// 双栈连接器
// ============================================================================

/// 双栈连接器
class DualStackConnector {
public:
    /// 默认构造（使用内置检测器）
    explicit DualStackConnector(DualStackConfig config = {});

    /// 注入式构造（用于测试）
    DualStackConnector(DualStackConfig config, StackDetector detector);

    /// 检测本机网络栈支持情况
    LocalStackCapability detect_local_stack();

    /// 跨栈地址转换
    ///
    /// 若本机 IPv6-only 但对端 IPv4-only，合成 NAT64 地址
    /// 若本机 IPv4-only 但对端 IPv6-only，尝试 6to4 隧道
    ///
    /// @param peer_address 对端地址
    /// @param local_cap 本机栈能力
    /// @return 转换后的地址（无需转换则返回原地址）；不支持返回 nullopt
    std::optional<std::string> translate_address(
        const std::string &peer_address,
        const LocalStackCapability &local_cap);

    /// 综合选择最佳连接地址
    ///
    /// 决策逻辑：
    ///   1. 若本机和对端都支持 IPv6，优先 IPv6 直连
    ///   2. 若本机和对端都支持 IPv4，IPv4 直连
    ///   3. 若本机 IPv6-only 但对端 IPv4，走 NAT64
    ///   4. 若本机 IPv4-only 但对端 IPv6，走 6to4（如启用）
    ///   5. 无可用地址返回 nullopt
    ///
    /// @param peer_candidates 对端候选地址列表
    /// @param local_cap 本机栈能力
    /// @return 选中的地址 + 使用的模式
    struct ConnectAddress {
        std::string address;
        DualStackMode mode;
    };
    std::optional<ConnectAddress> select_best_address(
        const std::vector<std::string> &peer_candidates,
        const LocalStackCapability &local_cap);

    /// 获取配置
    const DualStackConfig &config() const { return config_; }

private:
    DualStackConfig config_;
    StackDetector detector_;

    /// 默认栈检测实现
    static LocalStackCapability default_detect();
};

// ============================================================================
// 工具函数
// ============================================================================

/// 过滤 IPv4 地址
std::vector<std::string> filter_ipv4(const std::vector<std::string> &addrs);

/// 过滤 IPv6 地址
std::vector<std::string> filter_ipv6(const std::vector<std::string> &addrs);

/// 判断地址列表是否包含 IPv4
bool has_ipv4(const std::vector<std::string> &addrs);

/// 判断地址列表是否包含 IPv6
bool has_ipv6(const std::vector<std::string> &addrs);

} // namespace linoh::nat
