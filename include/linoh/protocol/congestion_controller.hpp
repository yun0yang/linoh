// linoh/protocol/congestion_controller.hpp — 拥塞控制算法抽象接口
//
// v2.0 Phase 1: 将 NewReno 从 Connection 硬编码成员解耦为可插拔算法。
// 设计目标：
//   1. 算法可插拔 — NewReno / BBR v2 / CUBIC 通过同一接口切换，由 Config 选择
//   2. 向后兼容   — NewRenoController 接口签名不变，现有测试零改动
//   3. 优雅降级   — 协商失败或异常时回退 NewReno（v1.7.0.9 行为）
//
// 接口分两层：
//   - 核心纯虚 API（所有算法必须实现）：on_ack / on_loss / on_rto / can_send / cwnd_bytes / reset / algo_name
//   - 可选虚 API（默认空实现，子类按需 override）：
//       update_retx_pending   — NewReno cwnd 抑制用（BBR 可选）
//       is_cwnd_suppressed    — NewReno retx 抑制态查询
//       pacing_rate_bps       — BBR pacing 速率（NewReno 返回 0）
//       set_rtt_estimator     — BBR 需要精确 RTT（NewReno 忽略）
//       retx_pending_count_for_test — 测试诊断用
//
// 工厂函数 make_congestion_controller() 按 CongestionAlgo 创建对应实例，
// 定义在 bbr_v2.cpp 中（需引用 BbrV2Controller 完整定义）。

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

namespace linoh::protocol {

// 前向声明（避免与 loss_recovery.hpp 循环依赖）
class RttEstimator;

/// 拥塞控制算法枚举（Config.congestion_algo 用）。
enum class CongestionAlgo : uint8_t {
    NewReno = 0,  // RFC 9002 §7 + NewReno fast recovery（默认，v1.7.0.9 行为）
    BbrV2   = 1,  // BBR v2（Startup/Drain/ProbeBW/ProbeRTT 四状态机）
};

/// V3-B: BBR 跨域参数配置（协议规范 §6.2）
///
/// 跨域链路特征：高 RTT（50-200ms）、高 BDP、可能高丢包。
/// BBR 默认参数针对局域网/城域网优化，跨域需自适应：
///   - min_rtt_window 扩展（10s→30s）：适应跨域 RTT 抖动，避免误判
///   - ProbeRTT 间隔拉长（10s→60s）：减少跨域带宽浪费（ProbeRTT 期间 cwnd=4*MSS）
///   - cwnd_gain 提高（2.0→3.0）：应对跨域高 BDP，提升吞吐
///   - pacing 启用：跨域长肥管道 pacing 收益大（防 burst 丢包）
///
/// 应用时机：Connection 检测到 is_cross_domain=true 且首次 RTT > 50ms 时，
/// 调用 CongestionController::apply_cross_domain_config()。
struct BbrCrossDomainConfig {
    /// 跨域 min_rtt_window（默认 30s，比单域 10s 长，适应跨域 RTT 抖动）
    std::chrono::seconds cross_domain_min_rtt_window{30};

    /// 跨域 ProbeRTT 间隔（默认 60s，比单域 10s 长，减少跨域带宽浪费）
    std::chrono::seconds cross_domain_probe_rtt_interval{60};

    /// 跨域 startup_gain（默认 2.77，同单域）
    double cross_domain_startup_gain{2.77};

    /// 跨域 cwnd_gain（默认 2.0，跨域可适当提高到 3.0 应对 BDP）
    double cross_domain_cwnd_gain{3.0};

    /// 跨域是否启用 pacing（默认 true，跨域长肥管道 pacing 收益大）
    bool cross_domain_enable_pacing{true};
};

/// 拥塞控制算法抽象基类。
///
/// Connection 通过 unique_ptr<CongestionController> 持有，运行时多态分发。
/// 所有方法在 Connection 的发送/ACK/丢包路径中被调用，实现需保证线程安全
/// （Connection 保证同一 connection 的发送路径串行化，但 ACK 回调可能与
///  发送并发，因此实现内部需自行加锁或依赖 Connection 外层锁）。
class CongestionController {
public:
    virtual ~CongestionController() = default;

    // ===== 核心 API（纯虚，所有算法必须实现）=====

    /// 收到 ACK 时调用（确认了 newly_acked_bytes 字节的飞行数据）。
    /// \param newly_acked_bytes  本次 ACK 新确认的字节数
    /// \param largest_acked_pn   本次 ACK 确认的最大包编号（UINT64_MAX = 哨兵）
    virtual void on_ack(uint64_t newly_acked_bytes,
                        uint64_t largest_acked_pn = UINT64_MAX) = 0;

    /// 检测到丢包时调用。
    /// \param current_largest_acked  当前最大已确认 PN（用于 recovery 退出判断）
    virtual void on_loss(uint64_t current_largest_acked = 0) = 0;

    /// RTO 超时时调用。
    virtual void on_rto() = 0;

    /// 检查当前是否允许发送 bytes 字节的新数据。
    virtual bool can_send(uint64_t bytes) const = 0;

    /// 获取当前拥塞窗口（字节）。
    virtual uint64_t cwnd_bytes() const = 0;

    /// 重置（连接恢复或版本协商后）。
    virtual void reset() = 0;

    /// 算法名称（诊断/日志用）。
    virtual std::string_view algo_name() const = 0;

    // ===== 可选 API（默认空实现，子类按需 override）=====

    /// 更新当前 retx 队列大小（NewReno cwnd 抑制用，BBR 可选）。
    virtual void update_retx_pending(std::size_t count) { (void)count; }

    /// 是否处于 cwnd 抑制态（NewReno retx 积压时为 true，BBR 默认 false）。
    virtual bool is_cwnd_suppressed() const { return false; }

    /// 获取当前 pacing 速率（bps）。BBR 返回计算值，NewReno 返回 0（未实现 pacing）。
    virtual uint64_t pacing_rate_bps() const { return 0; }

    /// 注入 RTT 估算器引用（BBR 需要精确 RTT，NewReno 忽略）。
    virtual void set_rtt_estimator(const RttEstimator* rtt) { (void)rtt; }

    /// 测试诊断：获取 retx 队列大小（NewReno 实现，BBR 返回 0）。
    virtual std::size_t retx_pending_count_for_test() const { return 0; }

    // ===== V3-B: 跨域参数自适应（协议规范 §6.2）=====

    /// 应用跨域 BBR 参数配置。
    /// 仅 BbrV2Controller override 生效；NewReno 等无状态机参数的算法忽略。
    /// @param cfg 跨域参数配置（由 Connection 在检测到跨域链路时调用）
    /// @return 是否应用成功（不支持跨域自适应的算法返回 false）
    virtual bool apply_cross_domain_config(const BbrCrossDomainConfig &cfg) {
        (void)cfg;
        return false;  // 默认不支持
    }

    /// 查询是否已应用跨域参数（诊断/测试用）。
    virtual bool is_cross_domain_configured() const noexcept { return false; }
};

/// 工厂函数：按算法枚举创建拥塞控制器实例。
/// \param algo  算法枚举
/// \param rtt   RTT 估算器指针（BBR 用，NewReno 可传 nullptr）
/// \return unique_ptr 拥有的控制器实例
/// \note 定义在 bbr_v2.cpp 中（需引用 BbrV2Controller 完整定义）。
std::unique_ptr<CongestionController> make_congestion_controller(
    CongestionAlgo algo, const RttEstimator* rtt);

} // namespace linoh::protocol
