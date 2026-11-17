// ipv6_deprecated.hpp — IPv6 地址弃用检查（v4.8.0 T-LP3-004）
//
// 借鉴 iroh 0.98 #4106（Filter deprecated IPv6 addresses）：
//   - RFC 4862 定义了 IPv6 地址生命周期：tentative → preferred → deprecated → invalid
//   - 弃用地址（deprecated）不应作为候选通告给对端
//   - Linux: 解析 /proc/net/if_inet6 的 flags 字段（0x20 = IFA_F_DEPRECATED）
//   - Windows: GetAdaptersAddresses 检查 DadState == IpDadStatePreferred
//
// 集成点：ICE 候选收集时调用 is_ipv6_deprecated 过滤弃用地址
// 回滚开关：默认不调用（向后兼容），候选收集逻辑可选集成

#pragma once

#include <cctype>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
// DadState 是 IP_ADAPTER_UNICAST_ADDRESS_LH 的成员（非 IP_ADAPTER_ADDRESSES_LH）
// 需要 _WIN32_WINNT >= 0x0600，build_all.bat 已全局定义
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <fstream>
#include <sstream>
#endif

namespace linoh::net {

/// 检查 IPv6 地址是否已弃用（RFC 4862 deprecated 状态）
///
/// @param ipv6_addr IPv6 地址字符串（如 "fe80::1"）
/// @param ifname 网卡名称（Linux 用，Windows 可忽略）
/// @return true 表示地址已弃用，不应作为候选通告
inline bool is_ipv6_deprecated(std::string_view ipv6_addr,
                               std::string_view ifname = {}) {
    (void)ifname;  // 目前实现不依赖 ifname

#ifdef _WIN32
    // Windows: 使用 GetAdaptersAddresses 检查 DadState
    ULONG buf_len = 0;
    if (GetAdaptersAddresses(AF_INET6, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                             nullptr, nullptr, &buf_len) == ERROR_BUFFER_OVERFLOW) {
        std::vector<uint8_t> buf(buf_len);
        auto *addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
        if (GetAdaptersAddresses(AF_INET6,
                                 GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                                 nullptr, addrs, &buf_len) == NO_ERROR) {
            for (auto *adapter = addrs; adapter; adapter = adapter->Next) {
                for (auto *ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
                    if (ua->Address.lpSockaddr->sa_family != AF_INET6) continue;
                    auto *sin6 = reinterpret_cast<sockaddr_in6 *>(ua->Address.lpSockaddr);
                    char buf6[INET6_ADDRSTRLEN] = {};
                    inet_ntop(AF_INET6, &sin6->sin6_addr, buf6, sizeof(buf6));
                    if (ipv6_addr == buf6) {
                        // DadState 是 IP_ADAPTER_UNICAST_ADDRESS_LH 的成员
                        //   IpDadStatePreferred(4) = 可用
                        //   IpDadStateDeprecated(3) = 弃用
                        return ua->DadState != IpDadStatePreferred;
                    }
                }
            }
        }
    }
    return false;  // 未找到地址信息，默认不弃用
#else
    // Linux: 解析 /proc/net/if_inet6
    // 格式: addr16 ifindex prefix scope flags ifname
    // flags 第 5 位（0x20）= IFA_F_DEPRECATED
    std::ifstream f("/proc/net/if_inet6");
    if (!f.is_open()) return false;

    // 将输入地址转换为 /proc/net/if_inet6 格式（无冒号，小写）
    std::string normalized;
    normalized.reserve(32);
    for (char c : ipv6_addr) {
        if (c != ':') {
            normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
    }
    // 补全缩写（:: 展开）— 简化实现：仅检查完全匹配
    // 完整实现需要解析 :: 缩写，这里用子串匹配
    if (normalized.size() < 4) return false;

    std::string line;
    while (std::getline(f, line)) {
        // 提取 addr 字段（前 32 字符）
        if (line.size() < 37) continue;
        std::string addr_field = line.substr(0, 32);
        // 提取 flags 字段（第 36 个字符起的 hex）
        // 格式: addr(32) + space + ifindex(2) + space + prefix(2) + space + scope(1) + space + flags(2)
        // 位置:  0-31      33-34      36-37        39          41-42
        if (line.size() > 42) {
            std::string flags_str = line.substr(41, 2);
            unsigned flags = 0;
            std::istringstream(flags_str) >> std::hex >> flags;
            if (flags & 0x20) {  // IFA_F_DEPRECATED
                // 检查地址匹配（子串或完全匹配）
                if (addr_field.find(normalized) != std::string::npos ||
                    normalized.find(addr_field) != std::string::npos) {
                    return true;
                }
            }
        }
    }
    return false;
#endif
}

} // namespace linoh::net
