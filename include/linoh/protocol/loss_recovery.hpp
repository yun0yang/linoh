// linoh/protocol/loss_recovery.hpp — QUIC 丢包检测 + NewReno 重传 (RFC 9002)
//
// 核心组件:
//   1. SentPacketTracker — 记录已发送包的 PN、时间、大小
//   2. LossDetector      — 基于 ACK 和超时阈值检测丢包
//   3. RttEstimator      — RFC 9002 RTT 估算 (SRTT + RTTVAR + RTO)
//   4. NewRenoController  — 简化拥塞控制 (cwnd + recovery)

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

#include "linoh/protocol/packet.hpp"  // v1.5.0.8: OosPnEntry 完整定义（OOS_PN_FRAME 反序列化结果）
#include "linoh/protocol/congestion_controller.hpp"  // v2.0: 拥塞控制抽象基类（NewReno/BBR 可插拔）

namespace linoh::protocol {

// v1.5.0.4: 提前声明 OosPnInfo（Stream::entry 级别 OOS buffer PN 注入）
//   - OosPnInfo 在本文件中完整定义（on_ack_received 第三个参数）
// v1.5.0.8: OosPnEntry 来自 packet.hpp（OOS_PN_FRAME 反序列化结果）

/// 默认参数（RFC 9002 推荐）
static constexpr double kInitialRttMs       = 100.0;  // 初始 RTT 假设
static constexpr double kAlpha              = 0.125;   // SRTT 平滑因子 (1/8)
static constexpr double kBeta               = 0.25;    // RTTVAR 平滑因子 (1/4)
static constexpr double kRtoMinMs           = 50.0;    // RTO 最小值 (6-3 retx 调优: 100->50, 加快 5% drop 下的 retx 重传间隔)
static constexpr double kRtoMaxMs           = 60000.0; // RTO 最大值 (60s)
static constexpr double kPacketThreshold    = 3.0;     // 丢包包编号阈值 (kPacketThreshold)
static constexpr double kTimeThresholdFactor = 9.0/8.0; // 丢包时间阈值因子
static constexpr uint64_t kInitialCwnd      = 32;      // 初始拥塞窗口 (包数) — relay路径需要大cwnd快速排空282KB帧
static constexpr uint64_t kMinimumCwnd      = 64;      // 最小拥塞窗口（relay路径TCP传输无丢包，64*MSS=93KB确保大帧一轮发完）
static constexpr uint64_t kMssBytes         = 1460;    // v1.5.0.1 P2-2: Ethernet MSS (RFC 6928)
static constexpr uint64_t kInitialCwndBytes = kInitialCwnd * kMssBytes;  // v1.5.0.1 P2-2: 14600 = RFC 6928 IW10
static constexpr double kGranularityMs      = 1.0;     // PTO 最小粒度 (RFC 9002 §6.2.1)
static constexpr double kPtoBackoffFactor   = 2.0;     // PTO 指数退避因子
static constexpr uint32_t kMaxPtoCount      = 16;      // PTO 退避上限

// v4.6.0 (借鉴 noq#523): PTO 上限 — 防止持续丢包下 PTO 指数退避到数十秒导致连接假死
//   - 握手完成后上限 2s（与 noq 一致）
//   - 握手期上限 500ms（更激进，加快握手失败发现）
static constexpr double kPtoMaxPostHandshakeMs = 2000.0;  // PTO 握手后上限 2s
static constexpr double kPtoMaxHandshakeMs     = 500.0;   // PTO 握手期上限 500ms

// v4.6.0 (借鉴 noq#561): TLP 强制 PING 标记 — on_pto_timeout 在无 ack-eliciting
//   in-flight 时返回 {kForcePingPn}，上层必须发 PING 帧（ack-eliciting）激发对端 ACK
static constexpr uint64_t kForcePingPn = UINT64_MAX;

/// v1.5.0.9 (ISSUE T08 反馈): 一个 PN 中 STREAM 帧数据范围
///
/// 单个 1-RTT 包可能包含多个 STREAM 帧（不同 stream_id 或同一 stream 的多个 chunk），
/// 每个 STREAM 帧在 PN 内占据一段独立的 [offset, offset+payload_bytes) 区间。
/// SentPacketInfo 用 vector<StreamRange> 记录所有区间，OOS_PN 反查时遍历匹配，
/// 避免 v1.5.0.8 单字段 (stream_id/offset/payload_bytes) 累加导致的多 stream 误匹配。
struct StreamRange {
    uint64_t stream_id{0};       // STREAM 帧所属 stream
    uint64_t offset{0};          // 该 STREAM 帧在 stream 内的起始 offset
    uint64_t payload_bytes{0};   // 该 STREAM 帧的 payload 字节数（仅 data 部分，不含帧头）
};

/// 一个已发送包的追踪信息。
struct SentPacketInfo {
    uint64_t pn;              // 包编号
    double send_time_ms;      // 发送时间（相对/绝对毫秒）
    uint64_t sent_bytes;      // 包大小（字节）
    bool ack_eliciting;       // 是否期望触发 ACK（含 STREAM/PING 等帧）
    bool in_flight;           // 是否仍在飞行中（未确认也未声明丢包）
    // v1.5.0.9 (ISSUE T08 反馈): PN 内所有 STREAM 帧的精确范围列表
    //   - v1.5.0.5/0.6/0.7 用单 stream_id+offset+sent_bytes 字段导致永久不命中
    //   - v1.5.0.8 改用 stream_payload_bytes（仅首个 stream 累加）但多 stream PN
    //     反查范围被扩大到包含其他 stream 的字节，OOS_PN_FRAME offset 反查精度
    //     错位（视频组 T08 实测：651980 处 2024 字节稳定缺口 = A_chunk 1000 + B_chunk 1024 累加）
    //   - v1.5.0.9: 每个 STREAM chunk 独立 push 一个 StreamRange，OOS_PN 反查遍历
    //     vector 精确匹配 [range.offset, range.offset+range.payload_bytes) 区间
    //   - 空 vector 表示该 PN 不含 STREAM 帧（控制帧/PING/纯 ACK）
    //   - 由 Connection::build_1rtt_packet 在 on_packet_sent 时填充
    std::vector<StreamRange> stream_ranges;
};

/// v1.5.0.4: OOS buffer PN 反向注入信息（视频模型组 LINOH_V1504_LOSSDETECTOR_DESIGN 方案 A）
///
/// 接收侧 Stream::oos_buffer_ 中的每个 entry 在被 ACK 确认后，连接层
/// 仍会保留其 PN 信息。本结构由 Connection::handle_ack_frame 收集并
/// 注入到 LossDetector，用于对"已被对端 ACK 但尚未填补 OOS gap"的 PN
/// 重新评估丢包状态，避免"幻影确认"导致 OOS gap 永久不触发 retx。
///
/// 设计要点：
///   - stream_id：接收侧 stream 编号，便于 OOS PN 与 stream 关联追溯
///   - pn：该 OOS entry 对应的发送侧包编号
///   - offset / size：OOS entry 在 stream 内的位置和大小（诊断用）
///   - first_seen_ms：该 OOS entry 首次进入 buffer 的时间（毫秒，Q1 答复：entry 级别）
///
/// ABI 兼容：作为 on_ack_received 第三个参数（默认空 vector）传入，
/// 旧调用方不传时与原行为一致（Q3 答复）。
struct OosPnInfo {
    std::uint64_t stream_id{0};
    std::uint64_t pn{0};
    std::uint64_t offset{0};
    std::size_t  size{0};
    double       first_seen_ms{0.0};
};

/// RTT 估算器（RFC 9002 §5）。
class RttEstimator {
public:
    RttEstimator();

    /// 用最新确认样本更新 RTT。
    /// `ack_delay_ms`: 对端报告的 ACK Delay（从 ACK 帧解码后）
    /// P9.1: 内部加 rtt_mu_ 锁
    void update(double latest_rtt_ms, double ack_delay_ms);

    /// 获取平滑 RTT (SRTT)。
    /// P9.1: 内部加 rtt_mu_ 锁（返回 by-value，跨线程安全）
    double srtt_ms() const;

    /// 获取 RTT 方差 (RTTVAR)。
    /// P9.1: 内部加 rtt_mu_ 锁
    double rttvar_ms() const;

    /// 获取重传超时 (RTO)。
    /// P9.1: 内部加 rtt_mu_ 锁
    double rto_ms() const;

    /// 重置（连接恢复或版本协商后）。
    /// P9.1: 内部加 rtt_mu_ 锁
    void reset();

    /// v1.5 P2-1: RTO 触发回调（由 LossDetector::on_rto_timeout 调用）。
    ///
    /// RFC 6298 §2.5: 触发 RTO 时 back off RTO（×2，封顶 kRtoMaxMs）。
    /// RFC 9002 §5.5: RTO 雪崩防护 — srtt 不应继续被偏大的 RTT 样本推高，
    /// 反而应被 clamp 到 RTO 自身；rttvar 也按 SRTT/2 重新对齐。
    void on_rto();

    /// v4.6.0 (借鉴 noq#545): 网络变化通知 — 重置 RTT 估计器。
    /// 网络切换后旧 SRTT 不再适用（如 WiFi 50ms → Cellular 200ms），
    /// 重置为初始值（kInitialRttMs）让新样本快速收敛，避免 PTO/RTO
    /// 基于过时 RTT 估算导致重传过迟或过频。
    /// 实现在 .cpp（使用 LINOH_INFO 日志宏，避免头文件依赖 logging.hpp）
    void on_network_change();

    /// S4（v5.3）: 是否已有真实 RTT 样本。
    /// 冷启动/网络切换 reset 后，srtt 是 kInitialRttMs(100ms) 假设值——
    /// 高 RTT 链路（如跨公网 640ms）上首个包会在首个 ACK 到达前被时间
    /// 阈值误判丢失（心跳流冷启动单包误判 ~1 次/s 的根因）。
    /// detect_loss_by_time 据此跳过判定（PN 阈值检测不受影响）。
    bool has_sample() const;

private:
    mutable std::mutex rtt_mu_;  // P9.1: 保护 srtt/rttvar/rto 跨线程读写（recv_thread 读 / timeout 写）
    double srtt_ms_;     // 平滑 RTT
    double rttvar_ms_;   // RTT 方差
    double rto_ms_;      // 重传超时
    bool first_sample_;  // 是否是第一个样本
};

/// 丢包检测器（RFC 9002 §6）。
class LossDetector {
public:
    LossDetector();

    /// 当收到 ACK 帧时调用。
    /// `acked_pns`: 本帧确认的所有包编号集合。
    /// `send_time_ms`: 当前时间（毫秒），用于时间阈值检测。
    /// `oos_pn_list` (v1.5.0.4): 接收侧 OOS buffer 中各 entry 对应的 PN 列表，
    ///   由 Connection::handle_ack_frame 从所有 stream 的 oos_pn_map_ 聚合。
    ///   用于对"已被对端 ACK 但 OOS gap 仍未填补"的 PN 重新评估丢包状态。
    ///   默认空 vector，行为与 v1.5.0.3 完全一致（Q3 答复 ABI 向后兼容）。
    /// 返回：被检测为丢包的包编号列表。
    std::vector<uint64_t> on_ack_received(
        const std::vector<uint64_t> &acked_pns,
        double send_time_ms,
        const std::vector<OosPnInfo> &oos_pn_list = {});

    /// 当 RTO 超时触发时调用。
    /// 返回：需要重传的所有飞行中包编号。
    std::vector<uint64_t> on_rto_timeout(double send_time_ms);

    /// P0-6: 当 PTO（Probe Timeout）触发时调用 (RFC 9002 §6.2.1)。
    /// PTO 不会声明丢包，而是发送 1-2 个探测包以激发对端 ACK。
    /// 返回：需要作为探测重传的最早飞行中包编号（最多 2 个）。
    ///       若无飞行中包（如仅 ack-eliciting 已确认），返回空。
    std::vector<uint64_t> on_pto_timeout(double now_ms);

    /// P0-6: 计算下一次 PTO 超时时间（毫秒，距离 now 的剩余时间）。
    /// PTO = max(SRTT + 4*RTTVAR, kGranularity) * 2^pto_count
    /// v4.6.0 (借鉴 noq#523): PTO 上限 clamp — 握手后 2s，握手期 500ms
    /// 无飞行中包时返回 -1.0。
    double pto_timeout_ms(double now_ms) const;

    /// v4.6.0 (借鉴 noq#523): 标记握手完成，影响 PTO 上限阈值。
    /// 由 Connection 在进入 Established 状态时调用。
    void set_handshake_complete(bool v) {
        std::lock_guard<std::mutex> lk(sent_mu_);
        is_handshake_complete_ = v;
    }

    /// v4.6.0 (借鉴 noq#545): 网络变化通知 — 重置 PTO backoff，
    /// 避免短暂中断（如 WiFi↔Cellular 切换）导致连接长睡眠。
    /// 由 Connection 在 RouteMonitor 触发 on_network_change 回调时调用。
    void on_network_change();

    /// 记录一个新发送的包。
    /// v1.5.0.5: 新增 stream_id / stream_offset 参数，用于 OOS_PN_FRAME 反查 PN
    ///   - 0 / 0 表示非 STREAM 帧（ACK / PING / 控制帧等）
    /// v1.5.0.8: 新增 stream_payload_bytes 参数，用于 OOS_PN_FRAME offset→PN 精确反查
    ///   - 仅 stream 帧 payload 字节数（不含 ACK/控制帧/加密头）
    ///   - 0 表示该 PN 不含 STREAM 帧
    /// v1.5.0.9 (ISSUE T08 反馈): 重构为 stream_ranges vector，多 stream PN
    ///   精确反查（替代 v1.5.0.8 单 stream_payload_bytes 字段，避免多 stream
    ///   累加错位导致 2024 字节稳定缺口）
    ///   - 空 vector = 不含 STREAM 帧
    ///   - 1 个 range = 单 stream PN（最常见）
    ///   - N 个 range = PN 包含 N 个不同 STREAM 帧（多 stream / 多 chunk）
    void on_packet_sent(uint64_t pn, double send_time_ms,
                        uint64_t sent_bytes, bool ack_eliciting,
                        std::vector<StreamRange> stream_ranges = {});

    /// v1.5.0.8 (ISSUE T07 反馈): 接收 Connection::handle_oos_pn_frame 同步的
    /// OOS buffer PN 列表，立即反查 sent_packets_ 找匹配 PN 并 mark_lost 触发重传。
    ///
    /// 根因（v1.5.0.5/0.6/0.7 共有缺陷）：
    ///   - LossDetector 仅基于 packet PN gap / time gap 检测丢包
    ///   - stream-level OOS gap（应用层 byte offset 缺口）无法触发重传
    ///   - handle_ack_frame 阶段 1 反查逻辑用 sent_bytes 匹配 stream_offset，
    ///     永远不命中（sent_bytes 是 1-RTT 包总大小，含 ACK/控制帧/加密头）
    ///   - 即使 OOS_PN 链路全通，LossDetector 仍 oos_pn_list_size=0
    ///
    /// 本接口修复：
    ///   - Connection.handle_oos_pn_frame decode 成功后立即调用本接口
    ///   - 内部按 stream_id 过滤 sent_packets_，对每个 entry 在
    ///     [stream_offset, stream_offset+stream_payload_bytes) 范围内反查 PN
    ///   - 对 pn < largest_acked 且 in_flight 的 PN **立即** mark_lost
    ///   - 返回 mark_lost 的 PN 列表，由 Connection 加入 retransmit_queue_
    ///   - 不依赖 ACK 事件触发，避免"packet-level 无 PN gap →
    ///     on_ack_received 不频繁调用 → OOS_PN 永不被消费"死锁
    ///
    /// 安全护栏：
    ///   - 同一 entry 可能反查到多个 PN（罕见但可能），内部去重
    ///   - pn >= largest_acked_ 的 PN 不 mark_lost（被新 ACK 确认前不应丢包）
    ///   - in_flight=false 的 PN 跳过（已 ACK 或已 mark_lost）
    ///   - P9.1: on_oos_pn_received 内部全程持有 sent_mu_ 锁，覆盖 collect
    ///     （收集 SentPacketInfo* 指针）+ match + mark_lost 全流程，杜绝指针悬空
    ///
    /// @param stream_id  OOS_PN_FRAME 中报告的 stream ID
    /// @param entries    接收方 OOS buffer 中的 gap 列表
    ///                   (offset + first_seen_ms，无 PN 字段)
    /// @return 被 mark_lost 的 PN 列表
    std::vector<uint64_t> on_oos_pn_received(
        uint64_t stream_id,
        const std::vector<OosPnEntry> &entries);

    /// v1.5.0.8: 测试访问器 — 返回 on_oos_pn_received 调用次数
    /// P9.1: 内部加 sent_mu_ 锁
    std::size_t oos_pn_received_total_for_test() const;

    /// v1.5.0.8: 测试访问器 — 返回 oos_pn_marked_lost 触发次数
    /// P9.1: 内部加 sent_mu_ 锁
    std::size_t oos_pn_marked_lost_total_for_test() const;

    /// v1.5.0.8: 测试访问器 — 返回 oos_pn_list_ 中所有 stream 的 PN 总数
    /// P9.1: 内部加 sent_mu_ 锁
    std::size_t oos_pn_list_size_for_test() const;

    /// v1.5.0.10 (ISSUE T09 反馈): 测试访问器 — stream_range 命中数（range_matched=true 累计）
    /// P9.1: 内部加 sent_mu_ 锁
    std::size_t stream_range_matched_total_for_test() const;

    /// v1.5.0.10 (ISSUE T09 反馈): 测试访问器 — stream_range 未命中数（range_matched=false 累计）
    /// P9.1: 内部加 sent_mu_ 锁
    std::size_t stream_range_unmatched_total_for_test() const;

    /// v1.5.0.10 (ISSUE T09 反馈): 测试访问器 — 由 on_oos_pn_received 触发的 mark_lost 计数
    /// P9.1: 内部加 sent_mu_ 锁
    std::size_t retx_by_oos_pn_total_for_test() const;

    /// v1.5.0.11 (ISSUE T10 反馈): 测试访问器 — StreamRange 注册总数
    ///   - on_packet_sent 中 stream_ranges 参数 size 累加
    ///   - 用于验证 T05 业务 master 端是否正确注册 STREAM 帧 range
    /// P9.1: 内部加 sent_mu_ 锁
    std::size_t stream_range_add_total_for_test() const;

    /// v1.5.0.11 (ISSUE T10 反馈): 测试访问器 — StreamRange 清理总数
    ///   - on_ack_received / on_oos_pn_received 触发 mark_acked/mark_lost 时
    ///     清理 sent_packets_ 对应 stream_ranges 累加
    /// P9.1: 内部加 sent_mu_ 锁
    std::size_t stream_range_remove_total_for_test() const;

    /// v1.5.0.11 (ISSUE T10 反馈): 测试访问器 — StreamRange 当前活跃数
    ///   - 派生 gauge = add_total - remove_total
    ///   - T05 业务 master 端正常运行时应 ≥ 1（stream_id=1 持续在途）
    ///   - 若 = 0 表明 on_packet_sent 未注册或反查链路异常清理
    /// P9.1: 内部加 sent_mu_ 锁
    std::size_t stream_range_active_size_for_test() const;

    /// v1.5.0.12 (ISSUE T11 反馈 P0): 测试访问器 — sent_packets_ 中实际 stream_ranges 总数
    ///   - 遍历 sent_packets_ 累加每个 PN 的 stream_ranges.size()
    ///   - 与派生 gauge（add - remove）对比，诊断清理时机异常
    ///   - T05 业务 200+ PN 场景下应 ≥ 200（每个 PN 至少 1 个 STREAM chunk）
    ///   - 若远小于 200：on_packet_sent 注册遗漏或 sent_packets_ 被 ACK 过早清理
    /// P9.1: 内部加 sent_mu_ 锁（遍历 sent_packets_ 需持锁）
    std::size_t stream_range_actual_active_size_for_test() const;

    /// v1.5.0.11 (ISSUE T10 反馈): 测试访问器 — mark_lost 总调用次数
    ///   - 包括成功调用和跳过的调用
    ///   - 与 retx_by_oos_pn_total_（成功 mark_lost 数）对比可定位跳过的根因
    /// P9.1: 内部加 sent_mu_ 锁
    std::size_t mark_lost_call_total_for_test() const;

    /// v1.5.0.11 (ISSUE T10 反馈): 测试访问器 — mark_lost 跳过原因：in_flight=false
    ///   - OOS_PN 报告的 PN 可能已被 ACK 或已 mark_lost
    ///   - 跳过后未触发重传，OOS gap 永久不补
    ///   - 视频组 T10 推测：20 命中但 0 触发可能因 PN 不在 in-flight 集
    /// P9.1: 内部加 sent_mu_ 锁
    std::size_t mark_lost_skipped_no_inflight_total_for_test() const;

    /// v1.5.0.11 (ISSUE T10 反馈): 测试访问器 — mark_lost 跳过原因：pn >= largest_acked
    ///   - OOS_PN 报告的 PN 已被最新 ACK 覆盖，无需重传
    ///   - 通常不应频繁触发（OOS buffer 内 PN 应小于 largest_acked）
    /// P9.1: 内部加 sent_mu_ 锁
    std::size_t mark_lost_skipped_out_of_window_total_for_test() const;

    /// 根据当前 RTO 计算下一次超时的时间（毫秒）。
    /// P9.1: 内部加 sent_mu_ 锁
    double next_timeout_ms(double now_ms) const;

    /// 获取最大的已确认包编号。
    /// P9.1: 内部加 sent_mu_ 锁
    uint64_t largest_acked() const;

    /// 获取飞行中包数量（用于拥塞控制）。
    /// P9.1: 内部加 sent_mu_ 锁
    uint64_t in_flight_count() const;

    /// 获取飞行中字节总量。
    /// P9.1: 内部加 sent_mu_ 锁
    uint64_t in_flight_bytes() const;

    /// P0-6: 获取 PTO 退避计数。
    /// P9.1: 内部加 sent_mu_ 锁
    uint32_t pto_count() const;

    /// 查找已发送包信息（用于获取确认包的大小）。
    /// P9.1: 返回 by-value optional（原返回 const*，锁外失效）；内部加 sent_mu_ 锁
    std::optional<SentPacketInfo> find_sent(uint64_t pn) const;

    /// v1.5.0.5: 测试访问器 — 返回 sent_packets_ 用于 OOS_PN_FRAME offset→PN 反查
    /// P9.1: 返回 by-value 快照（原返回 const&，悬空风险）；内部加 sent_mu_ 锁
    std::vector<SentPacketInfo> sent_packets_for_test() const;

    /// 获取 RTT 估算器的引用（用于 Connection 更新 RTT 统计）。
    /// P9.1: rtt_ 访问由 RttEstimator 内部 rtt_mu_ 保护，返回引用安全
    RttEstimator &rtt() { return rtt_; }
    const RttEstimator &rtt() const { return rtt_; }

    // v1.5.0.11 (ISSUE T10 反馈): mark_acked/mark_lost 保持 public 以支持
    //   StreamRange 生命周期测试（active_size = add - remove 一致性验证）。
    // P9.1: 调用方必须持有 sent_mu_ 锁（内部不加锁，避免重入死锁）。
    //   - on_ack_received / on_oos_pn_received / on_rto_timeout / detect_loss_by_*
    //     均在 sent_mu_ 锁内调用
    //   - 测试单线程调用，无需加锁
    void mark_acked(uint64_t pn);
    void mark_lost(uint64_t pn);

private:
    /// 包编号阈值检测 (kPacketThreshold)
    /// v1.5.0.4: 增加 oos_pn_list 参数（Q2 答复），对 OOS buffer 内的 PN
    ///   独立应用包编号阈值检测，避免"已被 ACK 但 OOS gap 仍存在"的 PN
    ///   永久不触发 retx。
    std::vector<uint64_t> detect_loss_by_pn(
        const std::vector<uint64_t> &acked_pns,
        const std::vector<OosPnInfo> &oos_pn_list = {});

    /// 时间阈值检测 (kTimeThreshold * SRTT)
    /// v1.5.0.4: 增加 oos_pn_list 参数，对 OOS buffer 内的 PN
    ///   独立应用时间阈值检测（OOS entry wait > kTimeThreshold * SRTT 触发 retx）。
    std::vector<uint64_t> detect_loss_by_time(
        const std::vector<uint64_t> &acked_pns,
        double now_ms,
        const std::vector<OosPnInfo> &oos_pn_list = {});

    /// P0-6: Early Retransmit 检测 (RFC 9002 §6.1.2)
    /// 当未确认的 ack-eliciting 包数量 < kPacketThreshold 时，
    /// 在 SRTT * kTimeThresholdFactor 后触发早期丢包检测。
    std::vector<uint64_t> detect_early_retransmit(double now_ms);

    const SentPacketInfo *find_sent_const(uint64_t pn) const;
    // P9.1: find_sent_mut 移至 private（返回裸指针，锁外不安全；仅 mark_acked/mark_lost
    //   等持锁方法内部使用）
    SentPacketInfo *find_sent_mut(uint64_t pn);

    // P9.1: LossDetector 线程安全锁 — 保护 sent_packets_ / largest_acked_ / oos_pn_list_ /
    //   所有 *_total_ 计数器 / pto_count_ / last_ack_time_ms_。
    //   被三方并发访问：recv_thread（handle_ack_frame）、send_loop（build_1rtt_packet）、
    //   heartbeat/应用 flush 线程。锁序：sent_mu_ →（释放）→ retransmit_mu_ →（释放）→
    //   newreno mu_，三锁绝不嵌套。
    //   rtt_ 由 RttEstimator 内部 rtt_mu_ 独立保护（持有 sent_mu_ 时调用 rtt_.xxx()
    //   会嵌套获取 rtt_mu_，顺序固定 sent_mu_→rtt_mu_，安全）。
    mutable std::mutex sent_mu_;

    std::vector<SentPacketInfo> sent_packets_;
    uint64_t largest_acked_;
    RttEstimator rtt_;
    uint32_t pto_count_;  ///< P0-6: PTO 退避计数（收到 ACK 后重置为 0）
    double last_ack_time_ms_;  ///< P0-6: 上次收到 ACK 的时间（用于 Early Retransmit）
    bool is_handshake_complete_{false};  ///< v4.6.0: 握手完成标记，影响 PTO 上限阈值

    // v1.5.0.8 (ISSUE T07 反馈): OOS_PN_FRAME 同步状态
    //   - oos_pn_list_：按 stream_id 索引的 PN 列表（用于诊断 + 重传记录）
    //   - oos_pn_received_total_：on_oos_pn_received 入口无条件计数（v1.5.0.7
    //     缺此埋点，video 组无法判断"未调用"还是"调用但反查失败"）
    //   - oos_pn_marked_lost_total_：mark_lost 触发计数（验证 stream-level OOS
    //     gap 是否真的被 LossDetector 识别并触发重传）
    std::map<uint64_t, std::vector<uint64_t>> oos_pn_list_;
    std::size_t oos_pn_received_total_{0};
    std::size_t oos_pn_marked_lost_total_{0};

    // v1.5.0.10 (ISSUE T09 反馈): OOS_PN 反查链路诊断计数器
    //   - 视频组 T09 实测：v1.5.0.9 master 端 OOS_PN_FRAME received=0
    //     无法定位是 A1（路由未注册）/A3（UDP 丢包）/A4（判定错）中的哪一个
    //   - stream_range_matched_total_  + stream_range_unmatched_total_
    //     可独立统计 StreamRange 精确反查命中率
    //   - retx_by_oos_pn_total_ 单独量化 OOS_PN 触发的重传总数
    //     （区别于 detect_loss_by_pn/time 的 packet-level 触发）
    //   - 全部为 private 字段，ABI 向后兼容
    std::size_t stream_range_matched_total_{0};   ///< StreamRange 命中累计（range_matched=true）
    std::size_t stream_range_unmatched_total_{0}; ///< StreamRange 未命中累计（range_matched=false）
    std::size_t retx_by_oos_pn_total_{0};         ///< on_oos_pn_received 触发的 mark_lost 累计

    // v1.5.0.11 (ISSUE T10 反馈): StreamRange 注册完整性埋点
    //   - 视频组 T10 实测反查命中率 0.4%（20/4842），需独立诊断 add/remove 链路
    //   - stream_range_add_total_：on_packet_sent 中 stream_ranges.size() 累加
    //   - stream_range_remove_total_：mark_acked/mark_lost 时清理的 stream_ranges 累加
    //   - 派生 gauge = add - remove，T05 业务 stream_id=1 应持续 ≥ 1
    //   - 若 active=0 且 add>0：on_packet_sent 注册了但反查链路异常清理
    //   - 若 active=0 且 add=0：on_packet_sent 未注册（master 端调用遗漏）
    std::size_t stream_range_add_total_{0};
    std::size_t stream_range_remove_total_{0};

    // v1.5.0.11 (ISSUE T10 反馈): mark_lost 触发条件审计埋点
    //   - 视频组 T10 实测 20 命中但 0 触发（retx_by_oos_pn_total=0）
    //   - mark_lost_call_total_：mark_lost 总调用次数（含跳过）
    //   - mark_lost_skipped_no_inflight_total_：in_flight=false 跳过数
    //     （OOS_PN 报告的 PN 已 ACK 或已 mark_lost）
    //   - mark_lost_skipped_out_of_window_total_：pn >= largest_acked 跳过数
    //   - 三者求和 = mark_lost_call_total_
    //   - 区分这两个跳过原因可定位：v1.5.0.11 是否需要放宽 in_flight 约束
    std::size_t mark_lost_call_total_{0};
    std::size_t mark_lost_skipped_no_inflight_total_{0};
    std::size_t mark_lost_skipped_out_of_window_total_{0};
};

/// NewReno 拥塞控制（RFC 9002 §7 + NewReno fast recovery）。
class NewRenoController : public CongestionController {
public:
    NewRenoController();

    /// 收到 ACK 时调用（确认了 new_bytes 字节的飞行数据）。
    /// v1.5.0.9 (ISSUE T08 反馈): cwnd 抑制 — 当 retx_pending_count > 100
    ///   时，cwnd 停止增长，避免新数据挤压重传包。RFC 9002 §7 隐含
    ///   "ACK 增加 cwnd" 是为新数据腾出空间，retx backlog 大时新数据
    ///   应被 backoff。
    void on_ack(uint64_t newly_acked_bytes, uint64_t largest_acked_pn = UINT64_MAX) override;

    /// 检测到丢包时调用。
    /// v1.7.0.7 H5/H6: current_largest_acked 用于记录 recovery 起始 PN，
    ///   供 on_ack 按 RFC 9002 §7.3.2 退出 recovery（默认 0 = 不启用退出逻辑，向后兼容）。
    void on_loss(uint64_t current_largest_acked = 0) override;

    /// RTO 超时时调用。
    void on_rto() override;

    /// v2.0: 算法名称（CongestionController 接口）。
    std::string_view algo_name() const override { return "newreno"; }

    /// v1.5.0.9 (ISSUE T08 反馈): 更新当前 retx 队列大小
    ///   - 由 Connection::build_1rtt_packet 在每次 send 前调用
    ///   - retx_pending_count_ > 100 触发 cwnd 抑制 + 优先 retx
    /// P9.1: 内部加 mu_ 锁
    void update_retx_pending(std::size_t count) override;

    /// v1.5.0.9: 获取 retx 队列大小（测试用）
    /// P9.1: 内部加 mu_ 锁
    std::size_t retx_pending_count_for_test() const override;

    /// v1.5.0.9: 检查是否处于 cwnd 抑制态
    /// P9.1: 内部加 mu_ 锁
    bool is_cwnd_suppressed() const override;

    /// 检查当前是否允许发送 bytes 字节的数据。
    /// v1.5.0.9: cwnd 抑制态下拒绝新数据（仅允许 retx 块，retx 在 build_1rtt_packet
    ///   中优先于 stream 块写入，不受此检查影响）
    /// P9.1: 内部加 mu_ 锁
    bool can_send(uint64_t bytes) const override;

    /// 获取当前拥塞窗口（字节）。
    /// P9.1: 内部加 mu_ 锁
    uint64_t cwnd_bytes() const override;

    /// 重置。
    /// P9.1: 内部加 mu_ 锁
    void reset() override;

private:
    /// v1.5.0.9 (ISSUE T08 反馈): retx 队列抑制阈值
    ///   - 超过此值时 on_ack 停止 cwnd 增长（避免新数据挤压重传）
    ///   - 100 是经验值，参考 QUIC 实现 + 视频组 T08 反馈（retx_queue_size=3900
    ///     时 cwnd 仍持续增长，导致 stream 块占满 payload，retx 块饿死）
    static constexpr std::size_t kCwndSuppressThreshold = 100;

    /// P9.2: cwnd 抑制态最大持续时间（毫秒）
    ///   - 抑制态超过此时间后强制退出，打破"retx backlog > 100 → cwnd 不增长 →
    ///     in-flight 无法 ACK → retx 永不成功 → 抑制态自维持"的死锁链
    ///   - 5000ms = 5s，覆盖正常 RTT 抖动（SRTT ~100ms × 50 倍），不会误退出
    static constexpr double kSuppressMaxMs = 5000.0;

    // P9.1: NewReno 线程安全锁 — 保护 cwnd/ssthresh/in_recovery/recovery_start_pn/
    //   retx_pending_count。被 recv_thread（on_ack/on_loss/on_rto）和 send_loop
    //   （can_send/cwnd_bytes/update_retx_pending）并发访问。
    //   锁序：sent_mu_ →（释放）→ retransmit_mu_ →（释放）→ mu_，绝不嵌套。
    mutable std::mutex mu_;

    uint64_t cwnd_bytes_;        // 拥塞窗口（字节）
    uint64_t ssthresh_;          // 慢启动阈值
    bool in_recovery_;           // 是否处于快速恢复阶段
    uint64_t recovery_start_pn_; // 进入恢复阶段时的最大确认 PN
    std::size_t retx_pending_count_{0};  // v1.5.0.9: 当前 retx 队列大小

    /// P9.2: 进入 cwnd 抑制态的时间戳（steady_clock 毫秒），0 = 未进入抑制态
    ///   - update_retx_pending 进入抑制态时记录 now_ms
    ///   - is_cwnd_suppressed / can_send / on_ack 检查超时（> kSuppressMaxMs 强制退出）
    double suppressed_since_ms_{0.0};

    /// P9.2: 获取当前时间（steady_clock 毫秒），用于抑制态超时判断
    static double now_ms_steady();
};

} // namespace linoh::protocol
