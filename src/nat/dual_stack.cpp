// dual_stack.cpp — P5-D-4 IPv6/IPv4 跨栈双栈连接实现
//
// 实现 NAT64 地址合成（RFC 6052）、6to4 隧道（RFC 3056）、双栈检测、跨栈地址转换。

#include "linoh/nat/dual_stack.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <thread>

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
// 地址族工具
// ============================================================================

bool is_ipv6_address(const std::string &ip) {
    // IPv6 必须包含冒号
    if (ip.find(':') == std::string::npos) return false;
    // 不应包含 IPv4 风格的点（除非是 IPv4-mapped 或 IPv4-compatible，仍按 IPv6 处理）
    // 实际为 '::ffff:1.2.3.4' 这种形式，仍属 IPv6
    return true;
}

bool is_ipv4_address(const std::string &ip) {
    // 不含冒号且含点
    if (ip.find(':') != std::string::npos) return false;
    if (ip.find('.') == std::string::npos) return false;
    return true;
}

std::optional<std::array<std::uint8_t, 4>> parse_ipv4(const std::string &ip) {
    std::array<std::uint8_t, 4> bytes{};
    int last = -1;
    int idx = 0;
    for (std::size_t i = 0; i <= ip.size(); ++i) {
        if (i == ip.size() || ip[i] == '.') {
            if (idx >= 4) return std::nullopt;
            if (i == static_cast<std::size_t>(last + 1)) return std::nullopt; // 空段
            std::string seg = ip.substr(last + 1, i - last - 1);
            if (seg.empty() || seg.size() > 3) return std::nullopt;
            for (char c : seg) {
                if (c < '0' || c > '9') return std::nullopt;
            }
            int v = std::stoi(seg);
            if (v < 0 || v > 255) return std::nullopt;
            bytes[idx++] = static_cast<std::uint8_t>(v);
            last = static_cast<int>(i);
        }
    }
    if (idx != 4) return std::nullopt;
    return bytes;
}

std::string format_ipv4(const std::array<std::uint8_t, 4> &bytes) {
    std::ostringstream oss;
    oss << static_cast<int>(bytes[0]) << "."
        << static_cast<int>(bytes[1]) << "."
        << static_cast<int>(bytes[2]) << "."
        << static_cast<int>(bytes[3]);
    return oss.str();
}

std::optional<std::array<std::uint8_t, 16>> parse_ipv6(const std::string &ip) {
    std::array<std::uint8_t, 16> bytes{};

    // 处理 :: 简化
    // 策略：split by ':'，处理 '::'
    std::vector<std::string> segments;
    std::string seg;
    bool seen_double_colon = false;
    std::size_t double_colon_pos = std::string::npos;

    for (std::size_t i = 0; i < ip.size(); ++i) {
        if (ip[i] == ':') {
            if (i + 1 < ip.size() && ip[i + 1] == ':') {
                // :: - 双冒号
                if (!seg.empty()) {
                    segments.push_back(seg);
                    seg.clear();
                }
                segments.push_back("::");
                seen_double_colon = true;
                double_colon_pos = segments.size() - 1;
                ++i; // skip next ':'
            } else {
                if (!seg.empty()) {
                    segments.push_back(seg);
                    seg.clear();
                }
            }
        } else {
            seg.push_back(ip[i]);
        }
    }
    if (!seg.empty()) segments.push_back(seg);

    // 处理 IPv4-mapped: ::ffff:1.2.3.4
    // 若最后一段含 '.', 视为嵌入 IPv4
    std::array<std::uint8_t, 4> v4_embedded{};
    bool has_v4_embedded = false;
    if (!segments.empty() && !segments.back().empty() && segments.back() != "::" &&
        segments.back().find('.') != std::string::npos) {
        auto v4 = parse_ipv4(segments.back());
        if (!v4) return std::nullopt;
        v4_embedded = *v4;
        has_v4_embedded = true;
        segments.pop_back();
    }

    // 计算实际段数
    std::vector<std::uint16_t> words;
    std::size_t empty_count = 0;
    for (auto &s : segments) {
        if (s == "::") {
            empty_count++;
        } else {
            if (s.empty()) return std::nullopt; // 单 ':' 错误
            if (s.size() > 4) return std::nullopt;
            for (char c : s) {
                bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex) return std::nullopt;
            }
            words.push_back(static_cast<std::uint16_t>(std::stoul(s, nullptr, 16)));
        }
    }

    // 一个合法 IPv6 应有 8 段（含 IPv4 嵌入时占 2 段）
    std::size_t total_words = words.size() + (has_v4_embedded ? 2 : 0);
    std::size_t needed = 8;

    if (empty_count > 0) {
        if (empty_count > 1) return std::nullopt; // 多个 :: 非法
        // 用 0 填充到 8 段
        std::size_t fill = needed - total_words;
        std::vector<std::uint16_t> result;
        // nn-L1 (v1.7.0.8): 删除原首段 dead-code for 循环（仅 push 0 且 else 分支
        //   仅含注释无实际写入 words，紧接着 result.clear() 全部丢弃）。
        //   下方重组循环一次性完成":: 之前 words → 0 填充 → :: 之后 words"。
        std::size_t wi = 0;
        for (auto &s : segments) {
            if (s == "::") {
                for (std::size_t k = 0; k < fill; ++k) result.push_back(0);
            } else {
                if (wi < words.size()) {
                    result.push_back(words[wi++]);
                }
            }
        }
        if (result.size() + (has_v4_embedded ? 2 : 0) != 8) return std::nullopt;
        // 拷贝到 bytes
        for (std::size_t i = 0; i < result.size(); ++i) {
            bytes[i * 2]     = static_cast<std::uint8_t>(result[i] >> 8);
            bytes[i * 2 + 1] = static_cast<std::uint8_t>(result[i] & 0xFF);
        }
    } else {
        if (total_words != needed) return std::nullopt;
        for (std::size_t i = 0; i < words.size(); ++i) {
            bytes[i * 2]     = static_cast<std::uint8_t>(words[i] >> 8);
            bytes[i * 2 + 1] = static_cast<std::uint8_t>(words[i] & 0xFF);
        }
    }

    // 嵌入 IPv4
    if (has_v4_embedded) {
        bytes[12] = v4_embedded[0];
        bytes[13] = v4_embedded[1];
        bytes[14] = v4_embedded[2];
        bytes[15] = v4_embedded[3];
    }

    return bytes;
}

std::string format_ipv6(const std::array<std::uint8_t, 16> &bytes) {
    // 转为 8 个 words
    std::array<std::uint16_t, 8> words{};
    for (int i = 0; i < 8; ++i) {
        words[i] = (static_cast<std::uint16_t>(bytes[i * 2]) << 8) | bytes[i * 2 + 1];
    }

    // 查找最长连续 0 段
    int best_start = -1, best_len = 0;
    int cur_start = -1, cur_len = 0;
    for (int i = 0; i < 8; ++i) {
        if (words[i] == 0) {
            if (cur_start == -1) cur_start = i;
            cur_len++;
            if (cur_len > best_len) {
                best_len = cur_len;
                best_start = cur_start;
            }
        } else {
            cur_start = -1;
            cur_len = 0;
        }
    }

    std::ostringstream oss;
    bool in_skip = false;
    for (int i = 0; i < 8; ++i) {
        if (best_start >= 0 && i >= best_start && i < best_start + best_len) {
            if (!in_skip) {
                oss << "::";
                in_skip = true;
            }
        } else {
            if (i > 0 && !in_skip) oss << ":";
            in_skip = false;
            oss << std::hex << words[i];
        }
    }
    return oss.str();
}

// ============================================================================
// NAT64 地址合成（RFC 6052）
// ============================================================================

std::optional<std::string> synthesize_nat64_address(
    const std::string &ipv4,
    const Nat64Prefix &prefix) {
    auto v4 = parse_ipv4(ipv4);
    if (!v4) return std::nullopt;

    // NAT64 前缀 96 位 + IPv4 32 位 = 128 位
    // 前 12 字节为前缀，后 4 字节为 IPv4
    if (prefix.prefix_bits != 96) return std::nullopt;

    std::array<std::uint8_t, 16> v6{};
    for (int i = 0; i < 12; ++i) v6[i] = prefix.bytes[i];
    v6[12] = (*v4)[0];
    v6[13] = (*v4)[1];
    v6[14] = (*v4)[2];
    v6[15] = (*v4)[3];

    return format_ipv6(v6);
}

std::optional<std::string> extract_ipv4_from_nat64(
    const std::string &nat64_ipv6,
    const Nat64Prefix &prefix) {
    auto v6 = parse_ipv6(nat64_ipv6);
    if (!v6) return std::nullopt;

    // 校验前缀
    for (int i = 0; i < 12; ++i) {
        if ((*v6)[i] != prefix.bytes[i]) return std::nullopt;
    }

    std::array<std::uint8_t, 4> v4{
        (*v6)[12], (*v6)[13], (*v6)[14], (*v6)[15]
    };
    return format_ipv4(v4);
}

// ============================================================================
// 6to4 隧道地址合成（RFC 3056）
// ============================================================================

std::optional<std::string> synthesize_6to4_address(const std::string &ipv4) {
    auto v4 = parse_ipv4(ipv4);
    if (!v4) return std::nullopt;

    // 2002:VVVV:VVVV::/48
    // 前 2 字节 2002，后 2 字节为 IPv4，其余 0
    std::array<std::uint8_t, 16> v6{};
    v6[0] = k6to4Prefix[0];
    v6[1] = k6to4Prefix[1];
    v6[2] = (*v4)[0];
    v6[3] = (*v4)[1];
    v6[4] = (*v4)[2];
    v6[5] = (*v4)[3];
    // 其余为 0

    return format_ipv6(v6);
}

bool is_6to4_address(const std::string &ipv6) {
    auto v6 = parse_ipv6(ipv6);
    if (!v6) return false;
    return (*v6)[0] == k6to4Prefix[0] && (*v6)[1] == k6to4Prefix[1];
}

std::optional<std::string> extract_ipv4_from_6to4(const std::string &ipv6) {
    auto v6 = parse_ipv6(ipv6);
    if (!v6) return std::nullopt;
    if ((*v6)[0] != k6to4Prefix[0] || (*v6)[1] != k6to4Prefix[1]) return std::nullopt;

    std::array<std::uint8_t, 4> v4{
        (*v6)[2], (*v6)[3], (*v6)[4], (*v6)[5]
    };
    return format_ipv4(v4);
}

// ============================================================================
// 双栈检测与连接器
// ============================================================================

std::string LocalStackCapability::to_string() const {
    std::ostringstream oss;
    oss << "LocalStackCapability{ipv4=" << (supports_ipv4 ? "yes" : "no")
        << ", ipv6=" << (supports_ipv6 ? "yes" : "no")
        << ", nat64=" << (supports_nat64 ? "yes" : "no")
        << ", dns64=" << (supports_dns64 ? "yes" : "no")
        << ", ipv4_addrs=[";
    for (std::size_t i = 0; i < ipv4_addresses.size(); ++i) {
        if (i) oss << ",";
        oss << ipv4_addresses[i];
    }
    oss << "], ipv6_addrs=[";
    for (std::size_t i = 0; i < ipv6_addresses.size(); ++i) {
        if (i) oss << ",";
        oss << ipv6_addresses[i];
    }
    oss << "], mode=" << dual_stack_mode_name(infer_mode()) << "}";
    return oss.str();
}

LocalStackCapability DualStackConnector::default_detect() {
    LocalStackCapability cap;

#ifdef _WIN32
    // v1.7.0.6 (C8 fix): 用 std::call_once 全局初始化 WSA，避免引用计数失衡
    WSADATA wsaData;
    static std::once_flag wsa_flag;
    std::call_once(wsa_flag, []() {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
    });
    bool wsa_inited = true;
#else
    bool wsa_inited = true;
#endif

    // 尝试创建 IPv4 UDP socket
    {
#ifdef _WIN32
        SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s != INVALID_SOCKET) {
            cap.supports_ipv4 = true;
            closesocket(s);
        }
#else
        int s = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (s >= 0) {
            cap.supports_ipv4 = true;
            ::close(s);
        }
#endif
    }

    // 尝试创建 IPv6 UDP socket
    {
#ifdef _WIN32
        SOCKET s = socket(AF_INET6, SOCK_DGRAM, 0);
        if (s != INVALID_SOCKET) {
            cap.supports_ipv6 = true;
            closesocket(s);
        }
#else
        int s = ::socket(AF_INET6, SOCK_DGRAM, 0);
        if (s >= 0) {
            cap.supports_ipv6 = true;
            ::close(s);
        }
#endif
    }

    // 收集本地地址（getaddrinfo 自身地址）
    if (wsa_inited) {
        // IPv4 loopback 一定可用
        if (cap.supports_ipv4) {
            cap.ipv4_addresses.push_back("127.0.0.1");
        }
        if (cap.supports_ipv6) {
            cap.ipv6_addresses.push_back("::1");
        }
    }

    // v1.7.0.6: WSA 由 std::call_once 全局初始化，不再 WSACleanup

    return cap;
}

DualStackConnector::DualStackConnector(DualStackConfig config)
    : config_(std::move(config)), detector_(default_detect) {}

DualStackConnector::DualStackConnector(DualStackConfig config, StackDetector detector)
    : config_(std::move(config)), detector_(std::move(detector)) {}

LocalStackCapability DualStackConnector::detect_local_stack() {
    if (detector_) return detector_();
    return default_detect();
}

std::optional<std::string> DualStackConnector::translate_address(
    const std::string &peer_address,
    const LocalStackCapability &local_cap) {
    bool peer_is_v4 = is_ipv4_address(peer_address);
    bool peer_is_v6 = is_ipv6_address(peer_address);

    // 本机 IPv6-only 但对端 IPv4 → NAT64
    if (peer_is_v4 && !local_cap.supports_ipv4 && local_cap.supports_ipv6) {
        if (!config_.enable_nat64) return std::nullopt;
        return synthesize_nat64_address(peer_address, config_.nat64_prefix);
    }

    // 本机 IPv4-only 但对端 IPv6 → 6to4
    if (peer_is_v6 && !local_cap.supports_ipv6 && local_cap.supports_ipv4) {
        if (!config_.enable_6to4) return std::nullopt;
        // 仅对 6to4 地址可逆
        if (is_6to4_address(peer_address)) {
            return extract_ipv4_from_6to4(peer_address);
        }
        return std::nullopt;
    }

    // 无需转换
    return peer_address;
}

std::optional<DualStackConnector::ConnectAddress> DualStackConnector::select_best_address(
    const std::vector<std::string> &peer_candidates,
    const LocalStackCapability &local_cap) {
    DualStackConnector::ConnectAddress best;
    best.address = "";
    best.mode = local_cap.infer_mode();

    // 分类对端地址
    std::vector<std::string> peer_v4;
    std::vector<std::string> peer_v6;
    for (const auto &addr : peer_candidates) {
        if (is_ipv4_address(addr)) peer_v4.push_back(addr);
        else if (is_ipv6_address(addr)) peer_v6.push_back(addr);
    }

    // 优先 IPv6 直连（Happy Eyeballs 偏好）
    if (local_cap.supports_ipv6 && !peer_v6.empty()) {
        best.address = peer_v6[0];
        best.mode = local_cap.infer_mode();
        return best;
    }

    // 次选 IPv4 直连
    if (local_cap.supports_ipv4 && !peer_v4.empty()) {
        best.address = peer_v4[0];
        best.mode = local_cap.supports_ipv6 ? DualStackMode::DualStack : DualStackMode::IPv4Only;
        return best;
    }

    // 跨栈转换
    // 本机 IPv6-only 但对端只有 IPv4 → NAT64
    if (!local_cap.supports_ipv4 && local_cap.supports_ipv6 && !peer_v4.empty()) {
        if (config_.enable_nat64) {
            auto translated = synthesize_nat64_address(peer_v4[0], config_.nat64_prefix);
            if (translated) {
                best.address = *translated;
                best.mode = DualStackMode::NAT64;
                return best;
            }
        }
    }

    // 本机 IPv4-only 但对端只有 IPv6 → 6to4（仅 6to4 地址可逆）
    if (!local_cap.supports_ipv6 && local_cap.supports_ipv4 && !peer_v6.empty()) {
        if (config_.enable_6to4) {
            for (const auto &v6 : peer_v6) {
                if (is_6to4_address(v6)) {
                    auto v4 = extract_ipv4_from_6to4(v6);
                    if (v4) {
                        best.address = *v4;
                        best.mode = DualStackMode::IPv4Only; // 走 6to4 后本机用 IPv4
                        return best;
                    }
                }
            }
        }
    }

    // 无可用地址
    return std::nullopt;
}

// ============================================================================
// 工具函数
// ============================================================================

std::vector<std::string> filter_ipv4(const std::vector<std::string> &addrs) {
    std::vector<std::string> result;
    for (const auto &a : addrs) {
        if (is_ipv4_address(a)) result.push_back(a);
    }
    return result;
}

std::vector<std::string> filter_ipv6(const std::vector<std::string> &addrs) {
    std::vector<std::string> result;
    for (const auto &a : addrs) {
        if (is_ipv6_address(a)) result.push_back(a);
    }
    return result;
}

bool has_ipv4(const std::vector<std::string> &addrs) {
    for (const auto &a : addrs) {
        if (is_ipv4_address(a)) return true;
    }
    return false;
}

bool has_ipv6(const std::vector<std::string> &addrs) {
    for (const auto &a : addrs) {
        if (is_ipv6_address(a)) return true;
    }
    return false;
}

} // namespace linoh::nat
