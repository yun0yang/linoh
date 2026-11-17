#pragma once

/// @file path_migration.hpp
/// QUIC 连接迁移与路径验证（RFC 9000 §9）+ CID 管理（§5.3）。
///
/// 帧类型：
///   PATH_CHALLENGE   (0x1a) — 8字节随机数据，验证新路径
///   PATH_RESPONSE    (0x1b) — 回应 PATH_CHALLENGE 的8字节
///   NEW_CONNECTION_ID(0x18) — 新备选 CID + stateless reset token
///   RETIRE_CONNECTION_ID(0x19) — 退休旧 CID
///
/// 连接迁移流程：
///   1. peer 地址变更（NAT 重绑、移动网络切换等）
///   2. 本端发送 PATH_CHALLENGE(8B random) 到新地址
///   3. 对端收到后回 PATH_RESPONSE(相同 8B)
///   4. 本端验证回应匹配 → 新路径可用
///   5. 自动切换到新路径（或保持多路径）

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/net/path.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/protocol/path_event.hpp"
#include "linoh/protocol/path_stats.hpp"
#include "linoh/util/varint.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace linoh::protocol {

class PathSelectionStrategy;  // v4.7.0 前向声明（避免与 path_strategy.hpp 循环 include）

// ---------------------------------------------------------------------------
// Path validation frames
// ---------------------------------------------------------------------------

/// PATH_CHALLENGE 帧 (RFC 9000 §19.17)。
/// 包含 8 字节随机数据，用于验证对端在特定路径上可达。
struct PathChallengeFrame {
    std::array<std::uint8_t, 8> data;  // 8-byte random challenge
};

/// PATH_RESPONSE 帧 (RFC 9000 §19.18)。
/// 必须包含与 PATH_CHALLENGE 相同的 8 字节。
struct PathResponseFrame {
    std::array<std::uint8_t, 8> data;  // 8-byte response (matches challenge)
};

// ---------------------------------------------------------------------------
// CID management frames
// ---------------------------------------------------------------------------

/// NEW_CONNECTION_ID 帧 (RFC 9000 §19.15)。
/// 向对端提供备选 CID，可用于连接迁移。
struct NewConnectionIdFrame {
    std::uint64_t sequence_number;       // VarInt — CID 序号
    std::uint64_t retire_prior_to;       // VarInt — 退休所有序号 < 此值的 CID
    std::uint8_t connection_id_length;   // 1 byte — CID 长度
    std::vector<std::uint8_t> connection_id;  // CID 数据
    std::array<std::uint8_t, 16> stateless_reset_token;  // 16 bytes
};

/// RETIRE_CONNECTION_ID 帧 (RFC 9000 §19.16)。
/// 通知对端不再使用指定序号的 CID。
struct RetireConnectionIdFrame {
    std::uint64_t sequence_number;  // VarInt
};

// ---------------------------------------------------------------------------
// Path validation state
// ---------------------------------------------------------------------------

/// 单个路径验证挑战的状态跟踪。
struct PathValidationState {
    std::array<std::uint8_t, 8> challenge_data;  // 发送的挑战数据
    bool validated{false};                         // 是否已通过验证
    std::uint64_t challenge_count{0};              // 发送次数（最多 3 次）
    double challenge_sent_ms{0.0};                 // 发送时间戳
    /// P4-A-1: 关联的四元组路径标识（用于日志和路径变更诊断）
    net::FourTuple four_tuple{};
    /// P4-A-1: 路径标识是否已设置（旧调用路径可能未设置）
    bool has_four_tuple{false};
};

/// CID 管理条目。
struct ConnectionIdEntry {
    std::uint64_t sequence_number{0};
    ConnectionId cid;
    std::array<std::uint8_t, 16> stateless_reset_token{};
    bool retired{false};
};

/// 连接迁移管理器：路径验证 + CID 管理。
class PathMigrationManager {
public:
    static constexpr std::size_t kMaxChallengeAttempts = 3;
    static constexpr double kChallengeTimeoutMs = 500.0;  // 500ms per attempt
    // mp-M5 (v1.7.0.8): pending_validations_ 硬上限，防止已验证条目永不清理导致无限增长
    //   mark_path_validated 仅设置 validated=true 不 erase，长期运行（频繁路径迁移）
    //   会导致 pending_validations_ 无限增长。record_challenge_sent 时清理已验证条目，
    //   超此上限则强制清理最旧未验证条目（兜底防内存爆炸）。
    static constexpr std::size_t kMaxPendingValidations = 128;

    /// v4.3.0 M16: 带宽 tier 枚举（三键 peer 排序第一键）
    ///
    /// 借鉴 Psyche ConnectionMonitor 带宽反馈闭环，按带宽测量状态分级：
    ///   - MeasuredPositive: 已测量且带宽 > 0（最优，有实测数据支撑选路）
    ///   - NotMeasured:      未测量（中等，新路径或采样窗口未满）
    ///   - MeasuredZero:     已测量但带宽 = 0（最差，可能断连/对端无响应）
    ///
    /// 排序优先级：MeasuredPositive(0) > NotMeasured(1) > MeasuredZero(2)
    /// 枚举值即排序权重（升序，值小的优先）。
    enum class BandwidthTier : std::uint8_t {
        MeasuredPositive = 0,  // 已测量，bandwidth > 0
        NotMeasured     = 1,   // 未测量
        MeasuredZero    = 2,   // 已测量，bandwidth = 0
    };

    /// P4-A-4: 路径质量指标（借鉴 iroh PR #4296）
    ///
    /// 跟踪单条路径的 RTT、丢包、最后活跃时间，用于路径放弃决策。
    /// v1.7.0.4 P3 (B7): 集成 PathStats 累计计数器，路径放弃时通过 PathEvent 流出。
    /// v3.3.0 突破4: 新增 srtt_baseline（EMA 基线）用于退化检测。
    /// v4.3.0 M16: 新增 bandwidth_tier + measured_bandwidth_bps 用于三键 peer 排序。
    struct PathQuality {
        std::uint64_t path_id{0};
        net::FourTuple four_tuple{};
        std::chrono::microseconds srtt{0};       // 平滑 RTT
        std::uint32_t loss_count{0};             // 近期丢包数
        std::chrono::steady_clock::time_point last_seen;
        bool has_tuple{false};
        // v1.7.0.4 P3 (B7): 累计统计（路径放弃时构造 PathStats 携带到 PathEvent）
        UdpStats udp_tx;
        UdpStats udp_rx;
        std::uint64_t lost_packets{0};
        std::uint64_t lost_bytes{0};
        std::uint64_t congestion_events{0};

        /// v3.3.0 突破4: RTT 基线（EMA），用于检测 RTT 突增退化
        ///
        /// 基线更新策略（update_path_quality 中）：
        ///   - 首次采样：baseline = srtt
        ///   - 后续：baseline = baseline * 0.875 + srtt * 0.125（EMA, alpha=0.125）
        ///
        /// 突增检测：当 srtt > baseline * rtt_degradation_ratio 时判定为退化。
        /// 基线用慢速 EMA，能过滤短期抖动，只在持续 RTT 上涨时触发。
        std::chrono::microseconds srtt_baseline{0};

        /// v4.3.0 M16: 带宽 tier（三键排序第一键）
        ///
        /// 分级语义（借鉴 Psyche ConnectionMonitor 带宽反馈闭环）：
        ///   MeasuredPositive: 已测量且有正带宽（实测 bps > 0），最优 tier
        ///   NotMeasured:      未测量带宽（新路径或 ConnectionMonitor 未采样到），中等
        ///   MeasuredZero:      已测量但带宽为零（可能断连/对端无响应），最差 tier
        ///
        /// BandwidthTierStrategy 排序优先级：MeasuredPositive > NotMeasured > MeasuredZero
        BandwidthTier bandwidth_tier{BandwidthTier::NotMeasured};

        /// v4.3.0 M16: 实测带宽（bps，三键排序第二键）
        ///
        /// 来源：ConnectionMonitor 周期采样（发送字节 / 采样窗口）。
        /// 仅当 bandwidth_tier == MeasuredPositive 时有意义（>0）。
        /// 排序时按降序（带宽大的路径优先）。
        std::uint64_t measured_bandwidth_bps{0};
    };

    /// P4-A-4: 路径放弃策略配置（借鉴 iroh PR #4296）
    ///
    /// - rtt_worse_threshold: 新路径 RTT 不超过老路径的此倍数时才放弃老路径。
    ///   默认 1.5 表示新路径 RTT 比老路径差 50% 以内时放弃老路径（切换到新路径）；
    ///   若新路径 RTT 超过老路径 1.5 倍（明显更差），则保留老路径。
    /// - idle_timeout: 路径超过此时间无活动则被放弃。
    /// - rtt_degradation_ratio: v3.3.0 突破4，单路径 RTT 退化检测阈值。
    ///   当 srtt > srtt_baseline * ratio 时判定退化（默认 3.0，即 RTT 涨到 3 倍基线）。
    /// - loss_rate_threshold: v3.3.0 突破4，丢包率退化检测阈值（默认 0.3=30%）。
    struct AbandonPolicy {
        double rtt_worse_threshold{1.5};
        std::chrono::seconds idle_timeout{std::chrono::seconds(30)};
        /// v3.3.0 突破4: 退化检测参数
        double rtt_degradation_ratio{3.0};
        double loss_rate_threshold{0.3};
    };

    explicit PathMigrationManager(std::uint64_t initial_cid_seq = 0);

    // --- PATH_CHALLENGE / PATH_RESPONSE --- //

    /// 生成新的 PATH_CHALLENGE 帧（8字节随机数据）。
    PathChallengeFrame generate_challenge();

    /// P4-A-1: 生成新的 PATH_CHALLENGE 并关联四元组（用于日志诊断）。
    PathChallengeFrame generate_challenge_with_tuple(const net::FourTuple &tuple);

    /// 验证收到的 PATH_RESPONSE 是否匹配某个 pending challenge。
    /// 返回匹配的 challenge 序号（-1 表示不匹配）。
    int validate_response(const PathResponseFrame &response) const;

    /// 标记指定序号的挑战已验证成功。
    void mark_path_validated(int index);

    /// P4-A-1: 标记指定序号的挑战已验证成功，并返回关联的 FourTuple（若有）。
    /// 用于路径迁移日志输出"从 X 迁移到 Y"。
    std::optional<net::FourTuple> mark_path_validated_with_tuple(int index);

    /// 记录已发送的 PATH_CHALLENGE（跟踪验证状态）。
    void record_challenge_sent(const PathChallengeFrame &challenge, double now_ms);

    /// P4-A-1: 记录已发送的 PATH_CHALLENGE 并关联四元组。
    void record_challenge_sent_with_tuple(const PathChallengeFrame &challenge,
                                           double now_ms,
                                           const net::FourTuple &tuple);

    /// 检查是否有挑战超时需要重发。
    bool has_expired_challenges(double now_ms) const;

    /// 获取需要重发的 PATH_CHALLENGE 列表。
    std::vector<PathChallengeFrame> pending_challenges() const;

    /// P4-A-1: 查询指定四元组是否已有 pending 挑战（避免重复打洞）。
    bool has_challenge_for_tuple(const net::FourTuple &tuple) const;

    /// P4-A-1: 获取所有已验证路径的四元组列表（用于诊断）。
    std::vector<net::FourTuple> validated_tuples() const;

    // --- CID management --- //

    /// 添加一个新的 CID 条目（NEW_CONNECTION_ID 帧）。
    void add_cid(const ConnectionIdEntry &entry);

    /// 退休指定序号的 CID。
    void retire_cid(std::uint64_t sequence_number);

    /// 获取当前可用的 CID 列表（非 retired）。
    std::vector<ConnectionIdEntry> active_cids() const;

    /// 获取下一个可用的 CID（用于路径迁移）。
    std::optional<ConnectionIdEntry> next_available_cid() const;

    /// 当前活跃 CID 数量。
    std::size_t active_cid_count() const;

    // --- P4-A-4: 路径质量监控与放弃策略 --- //

    /// 配置路径放弃策略。
    void set_abandon_policy(const AbandonPolicy &policy) {
        std::lock_guard<std::mutex> lk(mu_);
        policy_ = policy;
    }

    /// 获取当前路径放弃策略。
    AbandonPolicy abandon_policy() const {
        std::lock_guard<std::mutex> lk(mu_);
        return policy_;
    }

    /// 更新路径质量指标（handle_packet 收到 ACK 时调用）。
    /// 若路径不存在则新建条目。
    void update_path_quality(std::uint64_t path_id,
                              std::chrono::microseconds srtt,
                              std::uint32_t loss_count,
                              std::chrono::steady_clock::time_point now);

    /// P4-A-4: 更新路径质量并关联 FourTuple（重载）。
    void update_path_quality(std::uint64_t path_id,
                              std::chrono::microseconds srtt,
                              std::uint32_t loss_count,
                              std::chrono::steady_clock::time_point now,
                              const net::FourTuple &tuple);

    /// 查询指定路径的质量指标。不存在返回 nullopt。
    std::optional<PathQuality> path_quality(std::uint64_t path_id) const;

    /// 评估是否应放弃老路径（借鉴 iroh PR #4296 修复逻辑）。
    ///
    /// 返回 true 表示应放弃老路径（切换到新路径）；
    /// 返回 false 表示应保留老路径（新路径 RTT 明显更差）。
    ///
    /// 判定逻辑：
    ///   - 若任一路径 srtt 为 0（未测量），保守返回 false
    ///   - 否则当 new_q.srtt <= old_q.srtt * rtt_worse_threshold 时返回 true
    bool should_abandon_old_path(const PathQuality &old_q,
                                  const PathQuality &new_q) const;

    /// 放弃指定路径：仅影响当前 manager（借鉴 iroh PR #4284 修复逻辑）。
    ///
    /// 注意：本方法只修改本 PathMigrationManager 实例的 path_qualities_，
    /// 不影响其他 Connection 的 PathMigrationManager 实例。
    void abandon_path(std::uint64_t path_id);

    /// 放弃所有超过 idle_timeout 无活动的路径。
    /// 返回被放弃的 path_id 列表。
    std::vector<std::uint64_t> abandon_idle_paths(
        std::chrono::steady_clock::time_point now);

    /// v3.3.0 突破4: 主动健康检测 — 返回质量退化的活跃路径列表。
    ///
    /// 退化判定（满足任一即判定退化）：
    ///   - RTT 突增：srtt > srtt_baseline * rtt_degradation_ratio
    ///     （当前 RTT 超过基线的 N 倍，如基线 50ms → 阈值 150ms 时触发）
    ///   - 丢包率突增：loss_count / max(packets, 1) > loss_rate_threshold
    ///     （近期丢包率超过阈值，默认 30%）
    ///
    /// 基线过滤：srtt_baseline 用慢速 EMA（alpha=0.125）更新，
    /// 能过滤短期抖动，只在持续 RTT 上涨时触发，避免误报。
    ///
    /// 上层可定期调用此方法，当返回非空时主动触发路径迁移（如有备选路径）
    /// 或降级节点状态（如无备选路径）。
    ///
    /// \param now 当前时间点（用于过滤 last_seen 过老的路径）
    /// \return 退化路径的 path_id 列表（仅活跃路径，不含已放弃的）
    std::vector<std::uint64_t> detect_degraded_paths(
        std::chrono::steady_clock::time_point now) const;

    /// 当前活跃路径数量（未放弃的）。
    std::size_t active_path_count() const;

    /// 路径是否已被放弃（不存在或被 abandon_path 移除均返回 true）。
    bool is_path_abandoned(std::uint64_t path_id) const;

    // --- v1.7.0.4 P3 (B7): PathEvent 集成 --- //

    /// 设置路径事件回调（借鉴 iroh path_watcher.rs 的订阅模式）。
    /// 路径放弃时通过此回调流出 PathEvent::closed 携带 last_stats。
    ///
    /// v4.7.0: 此 API 已废弃，请使用 Connection::path_events() 替代。
    /// 新 API 支持：
    ///   - 多消费者订阅（旧 API 仅支持单消费者）
    ///   - 全事件类型（Opened/Selected/Closed/Lagged，旧 API 仅 Closed）
    ///   - 'static 流对象（不依赖 Connection 存活，旧 API 回调依赖 Connection 存活）
    ///
    /// 兼容性：保留到 v5.0.0，之后移除。Connection 内部使用此 API 桥接到新 fan-out。
    /// 调用方使用此 API 时，事件仍会通过 Connection::bridge_path_event_callback
    /// 转发到 PathEventStream（不影响新 API 订阅者）。
    [[deprecated("Use Connection::path_events() instead (v4.7.0+, multi-consumer, full events)")]]
    void set_path_event_callback(PathEventCallback cb) {
        std::lock_guard<std::mutex> lk(mu_);
        path_event_cb_ = std::move(cb);
    }

    /// 查询是否已设置路径事件回调。
    /// v4.7.0: 随 set_path_event_callback 废弃，仅用于内部桥接诊断。
    [[deprecated("Use Connection::has_path_strategy() or PathEventStream diagnostics instead")]]
    bool has_path_event_callback() const {
        std::lock_guard<std::mutex> lk(mu_);
        return static_cast<bool>(path_event_cb_);
    }

    // --- v4.7.0: PathSelectionStrategy 集成（激活原有死代码） --- //

    /// v4.7.0: 设置路径选择策略（用于 select_primary_path 决策）。
    ///
    /// 传入 nullptr 清除策略（select_primary_path 将返回 nullopt，保守不切换）。
    void set_strategy(std::shared_ptr<PathSelectionStrategy> s) {
        std::lock_guard<std::mutex> lk(mu_);
        strategy_ = std::move(s);
    }

    /// v4.7.0: 查询是否已设置路径选择策略。
    bool has_strategy() const {
        std::lock_guard<std::mutex> lk(mu_);
        return static_cast<bool>(strategy_);
    }

    /// v4.7.0: 从当前 path_qualities_ 中选主路径。
    ///
    /// 锁内拷贝候选列表，锁外调用 strategy_->select()（避免复杂选路逻辑持锁，
    /// 也避免回调反向调用 public 方法导致死锁，复用 H10 修复模式）。
    /// 无 strategy 或候选为空时返回 nullopt（保守不切换）。
    std::optional<net::FourTuple> select_primary_path() const;

    /// v4.7.0: 路径质量快照（供 Connection::paths() 使用，返回 path_qualities_ 拷贝）。
    std::vector<PathQuality> path_qualities_snapshot() const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<PathQuality> out;
        out.reserve(path_qualities_.size());
        for (const auto &kv : path_qualities_) {
            out.push_back(kv.second);
        }
        return out;
    }

private:
    /// v1.7.0.4 P3 (B7): 从 PathQuality 构造 PathStats 快照（用于 PathEvent::closed）。
    /// 将 PathQuality 的累计字段填充到 PathStats，瞬时字段（rtt/cwnd/current_mtu）按当前 srtt 填充。
    PathStats build_path_stats(const PathQuality &q) const;

    /// v1.7.0.4 P3 (B7): 触发 PathEvent::closed 事件。
    /// 在 abandon_path / abandon_idle_paths 删除路径前调用。
    /// v1.7.0.7 H10: 本方法不得在持有 mu_ 时调用（回调可能反向调用 public 方法导致死锁），
    ///   调用方须先释放锁。
    void emit_path_closed_event(const PathQuality &q, const std::string &reason);

    /// v4.7.0: 触发 PathEvent::opened 事件。
    /// 在 update_path_quality 首次见到新 path_id 时调用。
    /// H10: 本方法不得在持有 mu_ 时调用（回调可能反向调用 public 方法导致死锁）。
    /// @param path_id 新路径 ID
    /// @param tuple 路径四元组（若 update_path_quality 带 tuple 重载则有值）
    void emit_path_opened_event(std::uint64_t path_id,
                                const std::optional<net::FourTuple> &tuple);

    // v1.7.0.7 H9: 全类互斥锁，保护 pending_validations_ / cid_entries_ / path_qualities_
    //   - 发送线程（generate_challenge / record_challenge_sent）、接收线程
    //     （validate_response / mark_path_validated）、定时器线程（abandon_idle_paths）
    //     三者并发访问同一实例，v1.7.0.6 之前完全无锁
    //   - validate_response 返回 index 后 mark_path_validated(index) 使用前，
    //     pending_validations_ 可能被 push_back 导致 vector 重分配（TOCTOU + UAF）
    mutable std::mutex mu_;

    std::vector<PathValidationState> pending_validations_;
    std::vector<ConnectionIdEntry> cid_entries_;
    std::uint64_t next_cid_seq_;

    // P4-A-4: 路径质量监控与放弃策略
    AbandonPolicy policy_;
    std::unordered_map<std::uint64_t, PathQuality> path_qualities_;
    // 明确注释：path_qualities_ 是本 manager 私有，abandon_path 仅修改此实例，
    // 不影响其他 Connection 的 PathMigrationManager 实例（iroh PR #4284 修复点）

    // v1.7.0.4 P3 (B7): 路径事件回调
    PathEventCallback path_event_cb_;

    // v4.7.0: 路径选择策略（可选，nullptr 时 select_primary_path 返回 nullopt）
    std::shared_ptr<PathSelectionStrategy> strategy_;
};

// ---------------------------------------------------------------------------
// Frame encoding / decoding
// ---------------------------------------------------------------------------

/// 编码 PATH_CHALLENGE 帧。
std::vector<std::uint8_t> encode_path_challenge(const PathChallengeFrame &frame);

/// 解码 PATH_CHALLENGE 帧（去掉 type 字节的 payload）。
std::optional<PathChallengeFrame> decode_path_challenge(std::span<const std::uint8_t> payload);

/// 编码 PATH_RESPONSE 帧。
std::vector<std::uint8_t> encode_path_response(const PathResponseFrame &frame);

/// 解码 PATH_RESPONSE 帧。
std::optional<PathResponseFrame> decode_path_response(std::span<const std::uint8_t> payload);

/// 编码 NEW_CONNECTION_ID 帧。
std::vector<std::uint8_t> encode_new_connection_id(const NewConnectionIdFrame &frame);

/// 解码 NEW_CONNECTION_ID 帧。
std::optional<NewConnectionIdFrame> decode_new_connection_id(std::span<const std::uint8_t> payload);

/// 编码 RETIRE_CONNECTION_ID 帧。
std::vector<std::uint8_t> encode_retire_connection_id(const RetireConnectionIdFrame &frame);

/// 解码 RETIRE_CONNECTION_ID 帧。
std::optional<RetireConnectionIdFrame> decode_retire_connection_id(std::span<const std::uint8_t> payload);

} // namespace linoh::protocol
