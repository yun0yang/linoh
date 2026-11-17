// udp_probe.hpp — UDP 可用性三态探测（NAT 穿透优化 P0-G1）
//
// 借鉴 tdesktop MTPPingDelayDisconnect 机制：在发起 P2P 连接前，先向对端
// 发送多个 UDP ping 包统计 pong 回复率，判定 UDP 通道可用性三态：
//   - Available    : 回复率 >= available_threshold，UDP 可用，可走打洞
//   - Bad          : 回复率在 (bad_threshold, available_threshold)，质量差，
//                    可走打洞但需启用 FEC/重传增强
//   - NotAvailable : 回复率 <= bad_threshold 或全部超时，UDP 不可用，
//                    必须降级到 TCP/Relay 兜底（由 G2 TcpFallback 编排）
//
// 设计原则：
//   - 三态判定与 socket I/O 分离：classify 是纯函数，便于单元测试
//   - 提供 UdpPingProvider 回调，测试可注入 mock 而不依赖真实网络
//   - 复用 holepuncher.cpp 的 socket 操作模式（bind + SO_RCVTIMEO + sendto/recvfrom）
//   - ping/pong 载荷可自定义，默认 "LINOH-PING" / "LINOH-PONG"
//
// 与 tdesktop 对比：
//   tdesktop 在 MTPPingDelayDisconnect 中发送 ping 包，若 1 个 RTT 内无 pong
//   则判定 UDP 不可用并切换到 TCP。本实现将其推广为多包统计 + 三态分类，
//   避免单次丢包误判，同时保留"快速降级"能力（NotAvailable 时立即降级）。

#pragma once
#ifndef LINOH_NET_UDP_PROBE_HPP_
#define LINOH_NET_UDP_PROBE_HPP_

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace linoh::net {

// ============================================================================
// UDP 可用性三态（借鉴 tdesktop MTPPingDelayDisconnect）
// ============================================================================

enum class UdpAvailability {
    Available,     ///< 回复率 >= available_threshold，UDP 可用
    Bad,           ///< 回复率在 (bad_threshold, available_threshold)，质量差
    NotAvailable,  ///< 回复率 <= bad_threshold 或全部超时，UDP 不可用
};

/// UdpAvailability 转字符串（用于日志和测试断言）
inline std::string_view to_string_view(UdpAvailability a) {
    switch (a) {
        case UdpAvailability::Available:    return "available";
        case UdpAvailability::Bad:          return "bad";
        case UdpAvailability::NotAvailable: return "not-available";
    }
    return "unknown";
}

// ============================================================================
// 探测结果与配置
// ============================================================================

/// UDP 探测结果
struct UdpProbeResult {
    UdpAvailability availability{UdpAvailability::NotAvailable};
    std::uint32_t sent_count{0};          ///< 发送 ping 数
    std::uint32_t received_count{0};      ///< 收到 pong 数
    double loss_rate{1.0};                ///< 丢包率 = 1 - received/sent
    std::chrono::milliseconds min_rtt{0}; ///< 最小 RTT
    std::chrono::milliseconds max_rtt{0}; ///< 最大 RTT
    std::chrono::milliseconds avg_rtt{0}; ///< 平均 RTT
    std::chrono::milliseconds total_duration{0}; ///< 探测总耗时
    std::string error_msg;                ///< 错误信息（socket 失败等）

    /// 结果转字符串（用于日志）
    std::string to_string() const;
};

/// UDP 探测配置
struct UdpProbeConfig {
    std::uint32_t ping_count{5};                       ///< ping 次数（默认 5）
    std::chrono::milliseconds ping_interval{200};      ///< ping 间隔（默认 200ms）
    std::chrono::milliseconds recv_timeout{500};       ///< 单次 recv 超时（默认 500ms）
    double available_threshold{0.7};                   ///< 回复率 >= 此值判定 Available
    double bad_threshold{0.3};                         ///< 回复率 <= 此值判定 NotAvailable
    std::vector<std::uint8_t> ping_payload;            ///< 自定义 ping 载荷
    std::vector<std::uint8_t> pong_payload;            ///< 期望的 pong 载荷

    /// 默认构造：填充默认 ping/pong 载荷
    UdpProbeConfig() {
        ping_payload = {'L', 'I', 'N', 'O', 'H', '-', 'P', 'I', 'N', 'G'};
        pong_payload = {'L', 'I', 'N', 'O', 'H', '-', 'P', 'O', 'N', 'G'};
    }
};

// ============================================================================
// UdpPingProvider 回调（用于 mock 测试）
// ============================================================================

/// UDP ping 回调接口：发送一个 ping 并返回 RTT（nullopt 表示超时/失败）。
///
/// 测试时注入 mock provider，避免依赖真实网络。生产代码使用 probe() 走真实 socket。
///
/// @param remote_ip 对端 IP
/// @param remote_port 对端端口
/// @param recv_timeout 本次 recv 超时
/// @return nullopt 表示超时/失败；返回 RTT 表示成功收到 pong
using UdpPingProvider = std::function<std::optional<std::chrono::milliseconds>(
    const std::string &remote_ip,
    std::uint16_t remote_port,
    std::chrono::milliseconds recv_timeout)>;

// ============================================================================
// UdpProber 探测器
// ============================================================================

/// UDP 可用性探测器
class UdpProber {
public:
    /// 使用真实 socket 探测（生产路径）
    ///
    /// 流程：
    ///   1. 创建 UDP socket，bind 到 (local_ip, local_port)
    ///   2. 循环 ping_count 次：
    ///      a. sendto ping_payload 到 (remote_ip, remote_port)
    ///      b. 设置 SO_RCVTIMEO = recv_timeout
    ///      c. recvfrom 等待 pong，校验载荷 == pong_payload
    ///      d. 记录 RTT（sendto 时刻到 recvfrom 时刻）
    ///      e. sleep ping_interval
    ///   3. 统计 received_count / sent_count，计算 loss_rate
    ///   4. 调用 classify() 判定三态
    ///
    /// @param local_ip 本地绑定 IP（空串或 "0.0.0.0" 表示任意地址）
    /// @param local_port 本地绑定端口（0 表示系统分配）
    /// @param remote_ip 对端 IP
    /// @param remote_port 对端端口
    /// @param config 探测配置
    /// @return 探测结果
    static UdpProbeResult probe(
        const std::string &local_ip, std::uint16_t local_port,
        const std::string &remote_ip, std::uint16_t remote_port,
        const UdpProbeConfig &config = {});

    /// 使用 mock provider 探测（测试路径）
    ///
    /// 与 probe() 逻辑一致，但 ping/pong 由 provider 回调模拟，
    /// 不创建真实 socket。便于单元测试覆盖三态判定。
    static UdpProbeResult probe_with_provider(
        const std::string &remote_ip, std::uint16_t remote_port,
        const UdpProbeConfig &config,
        UdpPingProvider provider);

    /// 根据丢包率判定三态（纯逻辑，便于单元测试）
    ///
    /// 判定规则：
    ///   - sent_count == 0 → NotAvailable（未发送任何包）
    ///   - loss_rate <= (1 - available_threshold) → Available
    ///   - loss_rate >= (1 - bad_threshold) → NotAvailable
    ///   - 其他 → Bad
    ///
    /// @param loss_rate 丢包率 [0.0, 1.0]
    /// @param sent_count 发送总数（0 时直接判定 NotAvailable）
    /// @param available_threshold 回复率上限阈值（如 0.7）
    /// @param bad_threshold 回复率下限阈值（如 0.3）
    static UdpAvailability classify(
        double loss_rate,
        std::uint32_t sent_count,
        double available_threshold,
        double bad_threshold);

    /// UdpAvailability 转字符串（兼容旧调用）
    static std::string_view availability_name(UdpAvailability a) {
        return to_string_view(a);
    }
};

} // namespace linoh::net

#endif // LINOH_NET_UDP_PROBE_HPP_
