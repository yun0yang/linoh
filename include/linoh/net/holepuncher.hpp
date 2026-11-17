// holepuncher.hpp — NAT 打洞器（P4-C-3）
//
// 借鉴 iroh PR #4254（noq patch for holepunching when server is behind hard NAT）：
//   - 标准 STUN-based 打洞（RFC 5389）
//   - 对称 NAT 端口预测算法
//   - Relay 回退策略
//
// 设计原则：
//   - 纯算法层，不直接依赖 socket I/O（实际打洞由 Endpoint 调用 Holepuncher 提供的端口序列）
//   - predict_symmetric_nat_ports 是纯函数，便于单元测试
//   - attempt() 是阻塞调用，由 Endpoint 在 connect 前调用

#pragma once

#include "linoh/net/path.hpp"
#include "linoh/net/stun.hpp"
#include "linoh/net/udp_probe.hpp"  // P0-G1: UDP 可用性三态探测（attempt_with_probe 集成）
#include "linoh/nat/port_predictor.hpp"  // P5-D-4: PortPredictor + PortPredictModel（build_adaptive_candidates 参数需要枚举完整定义）

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace linoh::net {

/// NAT 打洞策略
enum class HolepunchStrategy {
    None,               // 不打洞，直接连接
    StandardRfc5389,    // 标准 STUN-based
    SymmetricNat,       // 对称 NAT 端口预测
    RelayFallback,      // 直接打洞失败，回退 Relay
};

/// 打洞结果
struct HolepunchResult {
    bool success{false};
    net::FourTuple established_tuple;
    HolepunchStrategy strategy_used{HolepunchStrategy::None};
    std::chrono::milliseconds duration{0};
    std::string error_msg;

    /// P0-G1: UDP 可用性探测结果（仅 attempt_with_probe 填充）
    /// 默认 udp_probed=false，区分"未探测"和"探测后 NotAvailable"
    bool udp_probed{false};
    UdpProbeResult udp_probe;

    /// P0-G4: 单一目的外发统计（仅 attempt_symmetric_single_dest 填充）
    /// 默认 single_dest_used=false，区分"未使用单一目的"和"使用后失败"
    bool single_dest_used{false};
    std::uint16_t single_dest_port{0};        ///< 实际命中端口（成功时填充）
    std::uint16_t single_dest_attempts{0};    ///< 尝试次数（含 fallback 回退）

    /// 结果转字符串（用于日志）
    std::string to_string() const;
};

/// P0-G4: 单一目的地址外发配置
///
/// 对称 NAT 下向多个预测端口发包会触发 NAT 为每个目的创建独立映射，反而
/// 破坏打洞。启用单一目的模式后，仅向 candidates[0]（最高置信度）发包，
/// 失败后按 fallback_retries 顺序回退到 candidates[1], [2]...
struct SingleDestConfig {
    /// 是否启用单一目的模式（false=回退多端口并发，兼容旧行为）
    bool enabled{true};
    /// 置信度门限：仅当 PortPrediction.confidence >= 此值时启用单一目的
    /// 低于门限时回退多端口并发（避免低置信度下赌错端口）
    double confidence_threshold{0.6};
    /// 单一目的发包后等待响应的超时（默认 2s）
    std::chrono::milliseconds response_timeout{std::chrono::seconds(2)};
    /// 单一目的失败后的重试次数（回退到 candidates[1..N]，默认 2 次）
    std::uint16_t fallback_retries{2};
};

/// 对称 NAT 端口预测算法
///
/// 对称 NAT 的特性：每个不同的 (src_ip, src_port, dst_ip, dst_port) 四元组
/// 会映射到不同的外部端口。但如果两次连接的目标 IP 相同，端口差值通常是固定的。
///
/// 算法：
///   1. 观察两次 STUN 探测的映射端口 p1, p2
///   2. 计算端口差值 delta = p2 - p1
///   3. 预测下一次端口 = p2 + delta * k（k=1,2,3,...）
///   4. 同时也尝试 +1, -1 的简单增量作为 fallback
///
/// @param observed_port_1 第一次观测到的外部端口
/// @param observed_port_2 第二次观测到的外部端口
/// @param predictions_count 预测端口数量（默认 10）
/// @return 预测的端口列表（按可能性排序，最可能的在前）
std::vector<std::uint16_t> predict_symmetric_nat_ports(
    std::uint16_t observed_port_1,
    std::uint16_t observed_port_2,
    std::size_t predictions_count = 10);

/// NAT 打洞器
class Holepuncher {
public:
    /// 尝试打洞（阻塞，超时 5s）
    ///
    /// @param local_addr 本地地址（含端口）
    /// @param remote_addr 远端地址（含端口）
    /// @param strategy 打洞策略
    /// @return 打洞结果
    static HolepunchResult attempt(
        const base::TransportAddr &local_addr,
        const base::TransportAddr &remote_addr,
        HolepunchStrategy strategy = HolepunchStrategy::StandardRfc5389,
        std::chrono::milliseconds timeout = std::chrono::seconds(5));

    /// 简化版：仅 IP + 端口
    ///
    /// 注意（nn-M1, v3.6.0）：当 strategy == SymmetricNat 时，本重载缺乏对端
    /// STUN 观测端口，会降级为 StandardRfc5389 + 警告日志（而非猜测预测）。
    /// 生产场景必须使用下方接受 remote_observed_port_1/2 的专用重载。
    static HolepunchResult attempt(
        const std::string &local_ip, std::uint16_t local_port,
        const std::string &remote_ip, std::uint16_t remote_port,
        HolepunchStrategy strategy = HolepunchStrategy::StandardRfc5389,
        std::chrono::milliseconds timeout = std::chrono::seconds(5));

    /// SymmetricNat 专用重载（nn-M1, v3.6.0）：传入对端两次 STUN 探测观测到的
    /// 外部映射端口（observed_port_1/2），用于精确端口预测。
    ///
    /// 对称 NAT 的端口预测必须基于对端实际 STUN 观测端口，而非 remote_port
    /// （remote_port 是对端 contact 端口，与其 NAT 外部映射端口无关）。
    /// 其他策略（None/StandardRfc5389/RelayFallback）忽略 observed_ports 参数。
    ///
    /// @param remote_observed_port_1 对端第一次 STUN 观测到的外部端口
    /// @param remote_observed_port_2 对端第二次 STUN 观测到的外部端口
    static HolepunchResult attempt(
        const std::string &local_ip, std::uint16_t local_port,
        const std::string &remote_ip, std::uint16_t remote_port,
        std::uint16_t remote_observed_port_1,
        std::uint16_t remote_observed_port_2,
        HolepunchStrategy strategy,
        std::chrono::milliseconds timeout = std::chrono::seconds(5));

    /// P5-D-4: 自适应候选数的 SymmetricNat 打洞
    ///
    /// 决策逻辑：
    ///   1. predictor != nullptr 且 peer 有历史观测 → 调用 predictor->predict(peer)
    ///      使用其自适应候选数（adaptive_count 按置信度 5-20）+ 多模型融合
    ///   2. predictor == nullptr 或冷启动（candidates 为空）→ 回退固定 10 候选
    ///   3. 把两个 STUN 观测端口追加到候选列表末尾作为兜底
    ///   4. 调用 attempt_symmetric 执行打洞
    ///   5. 成功后若 predictor 可用，调用 feedback 反馈命中（actual_port 来自
    ///      established_tuple.remote_addr.port）
    ///
    /// @param predictor 端口预测器（可为 nullptr，表示未启用 NAT 强化）
    /// @param peer 对端 EndpointId（用于 predictor 查询 per-peer 历史）
    /// @param remote_observed_port_1/2 对端两次 STUN 观测端口
    /// @return 打洞结果
    static HolepunchResult attempt_symmetric_adaptive(
        const std::string &local_ip, std::uint16_t local_port,
        const std::string &remote_ip, std::uint16_t remote_port,
        std::uint16_t remote_observed_port_1,
        std::uint16_t remote_observed_port_2,
        nat::PortPredictor *predictor,
        const base::EndpointId &peer,
        std::chrono::milliseconds timeout = std::chrono::seconds(5),
        /// S6-②（v5.3）并发扇出自适应提示：>0 时覆盖步骤 2 回退路径的
        /// 固定 10 候选（调用方按 nat_stats 该 NAT 类型对历史成功率调参：
        /// 成功率越低扇出越大，如 <30%→40 / <60%→20 / 其他→默认）。
        /// predictor 命中路径不受影响（自适应候选数 5-20 由置信度驱动）。
        std::size_t fanout_hint = 0);

    /// P5-D-4: 构建自适应候选端口列表（纯逻辑，不涉及 socket，便于单元测试）
    ///
    /// 决策逻辑同 attempt_symmetric_adaptive 步骤 1-3，但不执行实际打洞。
    ///
    /// @param predictor 端口预测器（可为 nullptr）
    /// @param peer 对端 EndpointId
    /// @param used_predictor_out [out] 是否实际使用了 predictor 候选
    /// @param model_used_out [out] 使用的预测模型
    /// @param confidence_out [out] 预测置信度
    /// @return 候选端口列表（已去重 + 追加观测端口兜底）
    static std::vector<std::uint16_t> build_adaptive_candidates(
        std::uint16_t remote_observed_port_1,
        std::uint16_t remote_observed_port_2,
        const nat::PortPredictor *predictor,
        const base::EndpointId &peer,
        bool &used_predictor_out,
        nat::PortPredictModel &model_used_out,
        double &confidence_out,
        /// S6-②（v5.3）：>0 覆盖回退路径固定 10 候选（nat_stats 自适应扇出）
        std::size_t fanout_hint = 0);

    /// P0-G4: 单一目的地址外发的对称 NAT 打洞
    ///
    /// 与 attempt_symmetric 的区别：
    ///   - attempt_symmetric: 向所有 predicted_ports 并发发包（多 NAT 映射风险）
    ///   - attempt_symmetric_single_dest: 仅向 candidates[0]（最高置信度）单一发包
    ///     失败后按 fallback_retries 回退到 candidates[1], [2]...
    ///
    /// 设计依据：对称 NAT 下，向多个预测端口发包会触发 NAT 为每个目的创建
    /// 独立映射，反而破坏打洞。单一目的保证一个 NAT 映射。
    ///
    /// @param predicted_ports 预测端口列表（按置信度降序，[0] 为最高）
    /// @param config 单一目的配置
    /// @return 打洞结果（含 single_dest_used/port/attempts 统计）
    static HolepunchResult attempt_symmetric_single_dest(
        const std::string &local_ip, std::uint16_t local_port,
        const std::string &remote_ip,
        const std::vector<std::uint16_t> &predicted_ports,
        std::chrono::milliseconds timeout = std::chrono::seconds(5),
        const SingleDestConfig &config = {});

    /// P0-G4: 计算单一目的模式的实际尝试次数（纯逻辑，便于单元测试）
    ///
    /// @param candidates_size 预测端口列表长度
    /// @param config 单一目的配置
    /// @return 实际尝试次数 = min(fallback_retries + 1, candidates_size)
    static std::size_t single_dest_max_attempts(
        std::size_t candidates_size,
        const SingleDestConfig &config);

    /// P0-G4: 决策是否启用单一目的模式（纯逻辑，便于单元测试）
    ///
    /// @param confidence PortPrediction.confidence
    /// @param candidates_size 预测端口列表长度
    /// @param config 单一目的配置
    /// @return true=启用单一目的，false=回退多端口并发
    static bool should_use_single_dest(
        double confidence,
        std::size_t candidates_size,
        const SingleDestConfig &config);

    /// 端口预测（便于测试和外部调用）
    static std::vector<std::uint16_t> predict_next_ports(
        std::uint16_t observed_port_1,
        std::uint16_t observed_port_2,
        std::size_t predictions_count = 10) {
        return predict_symmetric_nat_ports(observed_port_1, observed_port_2,
                                           predictions_count);
    }

    /// 策略转字符串
    static std::string_view strategy_name(HolepunchStrategy s);

    /// P0-G1: 带 UDP 可用性探测的打洞（NAT 穿透优化）
    ///
    /// 在执行打洞前先调用 UdpProber::probe 探测 UDP 通道可用性，根据探测结果
    /// 决策是否继续打洞：
    ///   - Available → 走原打洞逻辑（StandardRfc5389/SymmetricNat）
    ///   - Bad → 走原打洞逻辑（记录警告，上层可启用 FEC 增强）
    ///   - NotAvailable → 直接返回失败（error_msg 说明 UDP 不可用），
    ///                    由上层 TcpFallback 降级到 TCP/Relay
    ///
    /// 探测结果填充到 result.udp_probe 和 result.udp_probed=true。
    /// 原 attempt() 方法不执行探测（udp_probed=false），保持向后兼容。
    ///
    /// @param probe_config UDP 探测配置（ping_count/timeout/threshold 等）
    /// @return 打洞结果（含 UDP 探测信息）
    static HolepunchResult attempt_with_probe(
        const std::string &local_ip, std::uint16_t local_port,
        const std::string &remote_ip, std::uint16_t remote_port,
        HolepunchStrategy strategy = HolepunchStrategy::StandardRfc5389,
        std::chrono::milliseconds timeout = std::chrono::seconds(5),
        const UdpProbeConfig &probe_config = {});

private:
    /// 标准 STUN 打洞：双方互发 UDP 包打洞
    static HolepunchResult attempt_standard(
        const std::string &local_ip, std::uint16_t local_port,
        const std::string &remote_ip, std::uint16_t remote_port,
        std::chrono::milliseconds timeout);

    /// 对称 NAT 端口预测打洞
    /// @param predicted_ports 预测的远端端口列表
    static HolepunchResult attempt_symmetric(
        const std::string &local_ip, std::uint16_t local_port,
        const std::string &remote_ip,
        const std::vector<std::uint16_t> &predicted_ports,
        std::chrono::milliseconds timeout);
};

} // namespace linoh::net
