#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/endpoint/path_observation.hpp"
#include "linoh/endpoint/session_cache.hpp"
#include "linoh/endpoint/state_machine.hpp"
#include "linoh/net/net_report.hpp"
#include "linoh/net/path.hpp"
#include "linoh/protocol/ack.hpp"
#include "linoh/protocol/application_message.hpp"
#include "linoh/protocol/capabilities.hpp"  // O1.2: 对端压缩能力缓存
#include "linoh/protocol/flow_control.hpp"
#include "linoh/protocol/loss_recovery.hpp"
#include "linoh/protocol/path_migration.hpp"
#include "linoh/protocol/path_strategy.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/tls/crypto_level.hpp"
#include "linoh/tls/handshake.hpp"
#include "linoh/tls/handshake_token_key.hpp"
#include "linoh/tls/key_schedule.hpp"
#include "linoh/util/bytes.hpp"
#include "linoh/util/result.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace linoh::endpoint::internal {
class ConnectionState;
class StreamManager;
class PacketBuilder;
} // namespace linoh::endpoint::internal

namespace linoh::endpoint {

using base::EndpointId;
using base::SecretKey;

/// 连接方向。
enum class Direction { Inbound, Outbound };

/// 双向字节流抽象（模拟 QUIC 的双向流语义，含 offset 跟踪 + FIN）。
class Stream {
public:
    enum class Dir { Unidirectional, Bidirectional };

    explicit Stream(std::uint64_t id, Dir d) : id_{id}, dir_{d} {}

    std::uint64_t id() const { return id_; }
    Dir dir() const { return dir_; }
    bool is_closed() const { return closed_; }
    bool fin_received() const { return fin_received_; }
    bool fin_sent() const { return send_finished_; }

    void write(std::span<const std::uint8_t> data);
    void recv(std::span<const std::uint8_t> data, std::uint64_t offset = 0);

    /// v1.6.0.3 P2: scatter-gather write（零拷贝路径支持）
    ///
    /// 接受多段 span，内部依次 append 到 send_buffer（一次性预留容量减少 reallocate）
    /// 不修改现有 write 行为，PP 链零感知
    ///
    /// \param parts 多段数据 span（按顺序拼接）
    void write_scatter(const std::vector<std::span<const std::uint8_t>> &parts);

    /// v3.3.0 突破2: 零拷贝 write — move 接管外部 vector 所有权。
    ///
    /// 策略（自动选择 fast path）：
    ///   - 若 send_ 无可读数据（send_readable_size()==0 且 send_read_pos_==0）：
    ///     直接 swap send_ 与 buf，O(1) 真零拷贝，zero_copy_writes_++
    ///   - 否则：reserve + move insert（对 uint8_t 仍为 memcpy，但消除 span→vector 中间拷贝）
    ///
    /// 典型用法（配合 ApplicationMessage::serialize_into 消除 2 次拷贝）：
    ///   std::vector<std::uint8_t> wire;
    ///   wire.reserve(msg.wire_size());
    ///   msg.serialize_into(wire);
    ///   stream->write_ref(std::move(wire));  // send_ 空时 O(1) swap
    ///
    /// \param buf 外部 vector，调用后 buf 为空（所有权转移）
    void write_ref(std::vector<std::uint8_t> &&buf);

    /// v3.3.0 突破2: 零拷贝 scatter — move 接管多个 vector 所有权。
    ///
    /// 一次性 reserve + 逐个 move insert，避免多次 reallocate。
    /// 适用于"多段消息拼接发送"场景（如 header + payload 分离）。
    ///
    /// \param parts 多个外部 vector，调用后全部为空（所有权转移）
    void write_scatter_ref(std::vector<std::vector<std::uint8_t>> &&parts);
    /// 读取最多 max_len 字节（不清空缓冲，需显式 consume）。
    std::span<const std::uint8_t> read(std::size_t max_len = 0);
    /// 确认已消费 n 字节，从 recv_ 中移除。
    void consume(std::size_t n);
    /// P1-P3 fix(2026-07-20): 确认已发送 n 字节，推进 send_read_pos_。
    /// 用于 build_1rtt_packet 切片发送后替代 send_buffer().erase()。
    void consume_send(std::size_t n);
    /// P1-P3 fix(2026-07-20): 清空发送缓冲并重置 read_pos。
    /// 用于 0-RTT 拼装场景一次性取走全部数据。
    void clear_send() {
        send_.clear();
        send_read_pos_ = 0;
    }
    void finish_send();
    /// 标记对端已发送 FIN。
    void mark_fin_received();
    /// v5.5 K-OOSRESET-001: 显式流重置（对端 STREAM_RESET 0x38 帧触发）。
    /// recv_offset_ 归零 + 清 OOS/recv_——此后本流进入新消息代际；
    /// explicit_reset_seen_=true 期间隐式重置禁用（陈旧重传帧不再误清流）。
    void handle_explicit_reset();
    void close();
    /// A9 fix: 半关闭发送方向（FIN 已发送），保留接收方向可用（RFC 9000 §3.2）。
    /// 只清空 send 缓冲并标记 send_closed_，不动 recv 相关成员。
    void close_send();
    /// A9 fix: 发送方向是否已半关闭（FIN 帧已发送到网络）。
    bool send_closed() const { return send_closed_; }

    /// K-LINOH-READBLK-001 (v5.3.1): 连接死亡标记（idle 超时/Connection::close 置位）。
    /// 与 closed_（完全关闭清缓冲）区分：只标记死、不清 recv——业务仍可排空残留
    /// 数据，C API read 侧据此返回 CONN_DEAD 触发重连。
    void mark_conn_dead() { conn_dead_ = true; }
    bool conn_dead() const { return conn_dead_; }

    /// 底层 recv buffer（包含已消费数据，用 readable_size() 取有效长度）。
    std::vector<std::uint8_t> &recv_buffer() { return recv_; }
    /// 底层 send buffer（包含已发送数据，用 send_readable_size() 取有效长度）。
    std::vector<std::uint8_t> &send_buffer() { return send_; }
    bool send_finished() const { return send_finished_; }

    /// P1-P3 fix(2026-07-20): 可读数据长度 = recv_.size() - recv_read_pos_。
    std::size_t readable_size() const { return recv_.size() - recv_read_pos_; }
    /// P1-P3 fix(2026-07-20): 可读数据起始指针。
    const std::uint8_t *readable_data() const { return recv_.data() + recv_read_pos_; }
    /// P1-P3 fix(2026-07-20): 待发送数据长度 = send_.size() - send_read_pos_。
    std::size_t send_readable_size() const { return send_.size() - send_read_pos_; }
    /// P1-P3 fix(2026-07-20): 待发送数据起始指针。
    const std::uint8_t *send_readable_data() const { return send_.data() + send_read_pos_; }

    /// 当前已发送的最大 offset（用于 STREAM 帧编码）。
    std::uint64_t send_offset() const { return send_offset_; }
    /// 当前已接收的最大 offset（用于流量控制）。
    std::uint64_t recv_offset() const { return recv_offset_; }
    /// 跳过 gap，更新 send_offset。
    void advance_send_offset(std::uint64_t new_offset);
    /// [FIX 2026-08-14] 重置 send_offset 为 0（PP 推理场景：每条消息从 offset=0 开始）
    /// v5.5（K-OOSRESET-001）：同时置 stream_reset_pending_——build_1rtt_packet
    /// 在本消息首帧前写入 STREAM_RESET(0x38) 帧，接收方显式重置接收状态，
    /// 替代"猜"的隐式重置（陈旧重传帧与新消息首帧在偏移空间不可区分）。
    void reset_send_offset() { send_offset_ = 0; stream_reset_pending_ = true; }
    /// v5.5: 是否有待发的 STREAM_RESET 宣告（build_1rtt_packet 消费后清除）
    bool stream_reset_pending() const { return stream_reset_pending_; }
    void clear_stream_reset_pending() { stream_reset_pending_ = false; }
    /// [FIX 2026-08-14] 重置接收侧 OOS 状态
    /// 用于 PP 推理场景：PP tunnel 在 read_frame 前调用，清空上一条消息的残留 OOS 条目。
    /// 仅清除 OOS 缓冲区，不清除 recv_ 和 recv_offset_（避免丢失已接收的下一消息数据）。
    /// 调用方必须持有 stream_mu_ 锁（通过 linoh_stream_reset_recv C API 保证）。
    /// 配合 Stream::recv 中的 skip gap 逻辑（offset=0 && oos_buffer_.empty()）实现
    /// 新消息的正确交付：C API 清空 OOS → skip gap 条件满足 → recv_offset_ 重置为 0。
    void reset_recv_state() {
        oos_buffer_.clear();
        oos_pn_map_.clear();
        oos_first_seen_ms_map_.clear();
        oos_first_seen_ms_ = -1.0;
        // [FIX 2026-08-14] 不清空 recv_ 和 recv_offset_：
        // FORWARD binary 数据可能正在 recv_ 中被读取，清空会导致数据丢失。
        // implicit reset 逻辑（不清空 OOS）已能正确处理新消息边界。
    }
    /// v1.4.3 P1-#4: 写时合并 oos_buffer_ 相邻/重叠区间，避免消费时 O(n²) 遍历。
    void insert_oos_merged(std::uint64_t offset, std::span<const std::uint8_t> data);

    // === v1.5.0.3: F3 OOS 主动通知 API 支撑 ============================
    // 当前 OOS buffer 字节总数（所有 entry 的 .second.size() 之和）。
    std::size_t oos_size_bytes() const;
    // 第一个 OOS gap：offset = recv_offset_（已消费尾部），size = 第一个 entry 的长度
    // 返回 false 表示当前无 OOS gap。
    bool oos_first_gap(std::uint64_t *offset, std::size_t *size) const;
    // 注册/清除 OOS 累积回调。回调签名见 linoh_c.h::linoh_on_oos_threshold_fn。
    // threshold_bytes=0 表示每次 OOS 累积均触发，>0 表示仅当 first_gap_size >= 阈值触发。
    // 回调在 Stream::recv 内同步调用，调用方需避免在回调内做阻塞操作。
    using OosCallback = void(*)(void *user_data,
                                std::uint64_t first_gap_offset,
                                std::size_t first_gap_size,
                                std::size_t oos_total_bytes);
    void set_oos_callback(OosCallback cb, void *user_data, std::size_t threshold_bytes);
    void clear_oos_callback();
    // 当前最近一次 recv 的 packet number（用于埋点关联 PN）
    std::uint64_t last_pn() const { return last_pn_; }
    // 由 Connection::handle_packet 在调用 st->recv 前注入 PN
    void set_last_pn(std::uint64_t pn) { last_pn_ = pn; }

    // v3.3.0 突破2: 零拷贝 write 统计访问器
    /// write_ref 走 swap fast path 的次数（O(1) 真零拷贝命中）
    std::uint64_t zero_copy_writes() const { return zero_copy_writes_; }
    /// 所有 write 系列调用总次数（用于计算命中率）
    std::uint64_t total_writes() const { return total_writes_; }
    /// 零拷贝命中率（0.0-1.0），total_writes_==0 时返回 0
    double zero_copy_hit_rate() const {
        return total_writes_ == 0 ? 0.0
                                  : static_cast<double>(zero_copy_writes_) /
                                        static_cast<double>(total_writes_);
    }

    // v1.5.0.4: OOS buffer PN 反向注入（视频模型组 LINOH_V1504_LOSSDETECTOR_DESIGN 方案 A）
    // Connection::handle_ack_frame 遍历以下两个 map 构造 OosPnInfo 列表注入 LossDetector，
    // 解决"已 mark_acked 的 OOS buffer 内的 PN 永久不触发 retx"问题。
    // 访问约束：仅 Connection 内部访问（friend StreamManager/ConnectionState/PacketBuilder）。
    const std::map<std::uint64_t, std::uint64_t> &oos_pn_map_for_test() const { return oos_pn_map_; }
    const std::map<std::uint64_t, double> &oos_first_seen_ms_map_for_test() const { return oos_first_seen_ms_map_; }
    // v1.5.0.4: oos_buffer_ 只读访问（Q4 答复：用于 Connection 构造 OosPnInfo 时取 entry size）。
    const std::map<std::uint64_t, std::vector<std::uint8_t>> &oos_buffer_for_test() const { return oos_buffer_; }

    // [FIX 2026-08-14] 抑制/恢复 implicit reset 的 public setter。
    // win-worker 读取 FORWARD binary 帧期间置 true，防止 HEARTBEAT_ACK retransmission
    // 触发 implicit reset 破坏 binary 数据；读取完成后置 false 恢复。
    void set_suppress_implicit_reset(bool v) { suppress_implicit_reset_.store(v, std::memory_order_release); }

private:
    // v1.5.0.3.1 P0-1 fix: 显式禁用 Stream 拷贝/移动构造
    // 根因：Stream 通过 shared_from_this 关联到 Connection，拷贝会破坏
    // 生命周期/回调指向，导致 F3 OOS 回调注册后被重置为 nullptr。
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    Stream(Stream&&) = delete;
    Stream& operator=(Stream&&) = delete;

    std::uint64_t id_;
    Dir dir_;
    std::vector<std::uint8_t> recv_;
    std::vector<std::uint8_t> send_;
    std::uint64_t send_offset_{0};  // 发送侧偏移量
    std::uint64_t recv_offset_{0};  // 接收侧已连续写入的最大 offset
    // [FIX 2026-08-14] 抑制 implicit reset 标志：win-worker 读取 binary 帧期间置 true，
    // 防止 HEARTBEAT_ACK retransmission 触发 implicit reset 破坏 binary 数据。
    std::atomic<bool> suppress_implicit_reset_{false};
    // P1-P3 fix(2026-07-20): Ring Buffer 读偏移量，consume(n) 仅推进 read_pos，
    // 不再 erase 头部数据（O(n)→O(1)）。read_pos > capacity/2 时才整体前移。
    std::size_t recv_read_pos_{0};
    // P1-P3 fix(2026-07-20): 发送侧同样使用 read_pos 避免 erase。
    std::size_t send_read_pos_{0};
    bool send_finished_{false};
    /// A9 fix: 发送方向已半关闭（FIN-only 帧已发送），防重复发送 FIN。
    /// 与 closed_ 区分：closed_ 表示完全关闭（发送+接收都关闭），
    /// send_closed_ 只关闭发送方向，recv 方向保持可用直到对端 FIN 或 close()。
    bool send_closed_{false};
    bool fin_received_{false};
    bool closed_{false};
    // K-LINOH-READBLK-001 (v5.3.1): 所属连接已死（见 mark_conn_dead 注释）。
    // 仅 recv_thread 巡检与 Connection::close 写，业务线程读——bool 自然原子。
    bool conn_dead_{false};
    // v5.5 K-OOSRESET-001: STREAM_RESET(0x38) 宣告挂起（reset_send_offset 置位，
    // build_1rtt_packet 消费）；explicit_reset_seen_=true 期间禁用隐式重置。
    bool stream_reset_pending_{false};
    bool explicit_reset_seen_{false};
    // B6 fix(2026-07-20): 乱序数据缓冲，key=起始 offset，value=数据。
    // 当 offset > recv_offset_ 时缓存于此，gap 填满后按序拼接进 recv_。
    std::map<std::uint64_t, std::vector<std::uint8_t>> oos_buffer_;
    // v1.5.0.4: oos_buffer_ 内每个 entry 对应的 PN（offset → pn）。
    // 由 Stream::insert_oos_merged 写入，Connection::handle_ack_frame 读取并构造 OosPnInfo 列表。
    // 设计：与 oos_buffer_ 同步更新（erase 时同步删除），避免悬挂 PN 引用。
    std::map<std::uint64_t, std::uint64_t> oos_pn_map_;
    // v1.5.0.4: oos_buffer_ 内每个 entry 的首次插入时间（毫秒），entry 级别精度（Q1 答复）。
    // 用于 LossDetector 评估"OOS gap wait > K * SRTT"是否触发 retx。
    std::map<std::uint64_t, double> oos_first_seen_ms_map_;
    // v1.5.0.3: 最近一次 recv 调用的 packet number（埋点关联用）
    std::uint64_t last_pn_{0};
    // v1.5.0.3: OOS 主动通知回调 + 阈值
    OosCallback oos_cb_{nullptr};
    void *oos_cb_user_data_{nullptr};
    std::size_t oos_cb_threshold_bytes_{0};
    // v1.5.0.3: 自首次出现 OOS 累积起的时间戳（毫秒），用于计算 oos_wait_ms
    double oos_first_seen_ms_{-1.0};

    // v3.3.0 突破2: 零拷贝 write 统计（用于观测零拷贝命中率）
    // zero_copy_writes_: write_ref 走 swap fast path 的次数（O(1) 真零拷贝）
    // total_writes_: 所有 write/write_scatter/write_ref/write_scatter_ref 调用总次数
    std::uint64_t zero_copy_writes_{0};
    std::uint64_t total_writes_{0};
};

/// 连接统计信息。
struct ConnectionStats {
    std::uint64_t packets_sent{0};
    std::uint64_t packets_received{0};
    std::uint64_t bytes_sent{0};
    std::uint64_t bytes_received{0};
    std::uint64_t lost_packets{0};
    std::uint64_t retransmitted_packets{0};
    double rtt_ema_ms{0.0};
    double rttvar_ms{0.0};
    double rto_ms{0.0};
    // v3.9.1: 带宽反馈闭环字段（默认 0，向后兼容）
    std::uint64_t bandwidth_bps{0};      ///< 实测带宽（bits/sec，由 ConnectionMonitor 维护）
    std::uint64_t pacing_rate_bps{0};    ///< BBR pacing rate（估算值）
    std::uint32_t cwnd_bytes{0};         ///< 拥塞窗口（字节）

    // ---- v5.4 F7（借鉴 ScaleFabric 可观测方法论）：消息级画像 + 路径占比 ----
    // 语义：尽力而为快照（与既有字段一致，包处理线程并发写、读侧值拷贝）。
    // 直方图 8 桶上界：[0,64) [64,256) [256,1K) [1K,4K) [4K,16K) [16K,64K) [64K,256K) [256K,+∞)
    static constexpr size_t kMsgBucketCount = 8;
    std::uint64_t msgs_sent{0};
    std::uint64_t msgs_received{0};
    std::uint64_t msg_size_sent_buckets[kMsgBucketCount]{};
    std::uint64_t msg_size_recv_buckets[kMsgBucketCount]{};
    std::uint64_t pkts_via_direct{0};    ///< direct UDP 路径发包数
    std::uint64_t pkts_via_relay{0};     ///< relay 代理路径发包数
};

/// V3-B: 跨域连接统计（独立于 ConnectionStats，避免污染既有结构）
///
/// 跨域连接复用既有连接状态机，仅在 Config 中标记 is_cross_domain=true。
/// 跨域流量计数与总流量计数解耦：bytes_sent 仍记总流量，cross_domain_bytes_sent
/// 额外记跨域流量（仅跨域连接才累加），便于 orchestrator 统计跨域带宽消耗。
struct CrossDomainStats {
    std::uint64_t bytes_sent_cross_domain{0};      // 跨域发送字节（仅跨域连接累积）
    std::uint64_t bytes_received_cross_domain{0};  // 跨域接收字节（仅跨域连接累积）
    std::uint32_t rtt_ms{0};                        // 跨域 RTT（毫秒，由 SRTT 推导）
    std::uint32_t peer_domain_id{0};                // 对端域 ID（跨域连接有效，本域为 0）
};

/// 0-RTT 会话票据（TLS 1.3 session resumption）。
struct SessionTicket {
    SessionTicket() = default;
    protocol::ConnectionId peer_cid;
    EndpointId peer_node_id;
    std::string alpn;
    std::array<std::uint8_t, 32> master_secret;  // 会话主密钥
    std::uint64_t max_early_data_bytes{0x00FFFFFF};

    /// P1-4: 创建时间戳（Unix 秒，UTC）。save_session 时设置。
    /// 序列化/反序列化时一并写入/读取。0 表示未设置（兼容旧票据）。
    std::int64_t created_at_unix{0};

    /// P1-4: 最大存活时长（秒）。默认 24h（86400s）。
    /// from_bytes/from_encrypted_bytes 时校验 now - created_at <= max_age。
    std::uint32_t max_age_sec{86400};

    /// P1-4: 检查票据是否过期。created_at=0 视为未设置（不过期）。
    /// \param now_unix 当前 Unix 时间戳（秒）。默认用 system_clock::now()。
    bool is_expired(std::int64_t now_unix = -1) const noexcept;

    /// P1-4: 序列化为明文字节流（不含 AEAD 加密）。
    /// 格式：[version:1][created_at:8][max_age:4][cid_len:1][cid][eid:32][alpn_len:2][alpn][max_early:8][secret:32]
    /// \return 序列化后的字节；失败返回空 vector
    std::vector<std::uint8_t> to_bytes() const;

    /// P1-4: 从明文字节流反序列化。
    /// \param data 字节流
    /// \param check_expiry 是否校验过期（默认 true）。测试场景可传 false。
    /// \return 反序列化的 SessionTicket；失败（格式错/过期）返回 std::nullopt
    static std::optional<SessionTicket> from_bytes(
        std::span<const std::uint8_t> data, bool check_expiry = true);

    /// P1-4: AEAD 加密序列化。
    /// \param key 32 字节 AEAD key（调用方持久化管理）
    /// \return [nonce:12][ciphertext||tag:plaintext_len+16]；失败返回空 vector
    std::vector<std::uint8_t> to_encrypted_bytes(
        std::span<const std::uint8_t> key) const;

    /// P1-4: AEAD 解密反序列化。
    /// \param key 32 字节 AEAD key（必须与加密时相同）
    /// \param data [nonce:12][ciphertext||tag]
    /// \param check_expiry 是否校验过期（默认 true）
    /// \return 反序列化的 SessionTicket；失败（解密失败/过期）返回 std::nullopt
    static std::optional<SessionTicket> from_encrypted_bytes(
        std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> data,
        bool check_expiry = true);

    /// P1-6: 析构时安全清零 master_secret
    ~SessionTicket() {
        util::secure_zero(master_secret.data(), master_secret.size());
    }

    /// P1-6: 拷贝构造（密钥正常复制）
    SessionTicket(const SessionTicket &) = default;
    SessionTicket &operator=(const SessionTicket &) = default;

    /// P1-6: 移动构造（源对象 master_secret 清零）
    SessionTicket(SessionTicket &&other) noexcept
        : peer_cid(other.peer_cid)
        , peer_node_id(other.peer_node_id)
        , alpn(std::move(other.alpn))
        , master_secret(other.master_secret)
        , max_early_data_bytes(other.max_early_data_bytes)
        , created_at_unix(other.created_at_unix)
        , max_age_sec(other.max_age_sec) {
        util::secure_zero(other.master_secret.data(), other.master_secret.size());
    }
    SessionTicket &operator=(SessionTicket &&other) noexcept {
        if (this != &other) {
            util::secure_zero(master_secret.data(), master_secret.size());
            peer_cid = other.peer_cid;
            peer_node_id = other.peer_node_id;
            alpn = std::move(other.alpn);
            master_secret = other.master_secret;
            max_early_data_bytes = other.max_early_data_bytes;
            created_at_unix = other.created_at_unix;
            max_age_sec = other.max_age_sec;
            util::secure_zero(other.master_secret.data(), other.master_secret.size());
        }
        return *this;
    }
};

/// 一个活跃的 QUIC 连接。
class Connection : public std::enable_shared_from_this<Connection> {
public:
    struct Config {
        SecretKey secret_key;
        protocol::ConnectionId local_cid;
        protocol::ConnectionId remote_cid;
        Direction direction;
        std::string alpn;
    std::optional<SessionTicket> resume_ticket;   // 可选：使用已有会话恢复
    /// 连接空闲超时（毫秒），0 = 不超时。
    std::chrono::milliseconds idle_timeout{30000};
    /// 心跳保活间隔（毫秒），0 = 不保活。
    std::chrono::milliseconds keepalive_interval{15000};
    /// Connection-level 初始流控窗口（字节）。
    std::uint64_t initial_conn_window{protocol::FlowController::kDefaultConnWindow};
    /// Stream-level 初始流控窗口（字节）。
    std::uint64_t initial_stream_window{protocol::FlowController::kDefaultStreamWindow};
    /// 最大双向并发流数。
    std::uint64_t max_bidi_streams{protocol::FlowController::kDefaultMaxBidiStreams};
    /// 最大单向并发流数。
    std::uint64_t max_uni_streams{protocol::FlowController::kDefaultMaxUniStreams};
    /// 握手配置。
    HandshakeConfig handshake{HandshakeConfig{}};

    /// v1.5.0.2 Step 3: 本端 preferred MTU（握手时发送给对方）。
    /// 默认 1280（IPv6 最小保证）。局域网 jumbo frame 节点可设为 9000。
    std::uint16_t local_preferred_mtu{1280};

    /// v1.5.0.2 Step 4: 本端 preferred_crypto_level（握手时发送给对端）。
    /// 默认 None — 协商时按 select_crypto_level(local_network_class, alpn) 兜底。
    multimodal::CryptoLevel local_preferred_crypto_level{multimodal::CryptoLevel::None};

    /// v1.5.0.2 Step 4: 本端 NetworkClass（协商时用于 select_crypto_level 兜底）。
    /// 默认 Lan — 上层可从 net::NetReport 推导出实际值。
    tls::NetworkClass local_network_class{tls::NetworkClass::Lan};

    /// v2.0 Phase 1: 拥塞控制算法选择。
    /// v3.3.0 突破1: 默认改为 BbrV2（跨域长肥管道吞吐提升 2-5 倍）。
    /// NewReno 保留为兜底（BBR 异常时可手动降级）。
    protocol::CongestionAlgo congestion_algo{protocol::CongestionAlgo::BbrV2};

    /// V3-B: 是否为跨域数据面连接（默认 false，向后兼容）
    /// 设置为 true 时，握手完成后应用跨域 BBR/MTU 参数；流量计入 CrossDomainStats
    bool is_cross_domain{false};

    /// V3-B: 对端域 ID（跨域连接有效，本域为 0）
    /// 用于跨域连接标记 + Relay 选择；is_cross_domain=true 时应同时设置此字段
    std::uint32_t peer_domain_id{0};

    /// v3.3.0 突破4: 跨域稳定性参数覆盖（0 = 不覆盖，使用上方默认值）
    ///
    /// 跨域链路特征：RTT 大（50-300ms）、抖动大、易断。
    /// - cross_domain_idle_timeout：跨域空闲超时（默认 60000ms，比本域 30000ms 宽松，
    ///   避免跨域抖动导致的误判超时关闭连接）
    /// - cross_domain_keepalive_interval：跨域心跳间隔（默认 8000ms，比本域 15000ms 更短，
    ///   更快探测跨域链路故障）
    ///
    /// 当 is_cross_domain=true 或 RTT 自动检测识别为跨域时，apply_cross_domain_stability_params()
    /// 会用这两个值覆盖 cfg_.idle_timeout / cfg_.keepalive_interval。
    /// 设为 0 表示不覆盖该字段（保持原值）。
    std::chrono::milliseconds cross_domain_idle_timeout{60000};
    std::chrono::milliseconds cross_domain_keepalive_interval{8000};

    /// v4.6.0 (借鉴 iroh#4041): 路径类型差异化 idle timeout
    ///
    /// 不同路径类型的可靠性不同，idle timeout 应差异化设置：
    /// - relay_idle_timeout: Relay 中继路径（默认 60000ms，Relay 路径延迟较大，
    ///   需更宽松的超时避免误判；0 = 使用 idle_timeout）
    /// - tcp_fallback_idle_timeout: TCP 降级路径（默认 20000ms，TCP 降级意味着
    ///   UDP 不可用，应更快超时以触发重试直连；0 = 使用 idle_timeout）
    ///
    /// 由 Connection::set_path_class() 在路径类型变化时自动应用。
    std::chrono::milliseconds relay_idle_timeout{60000};
    std::chrono::milliseconds tcp_fallback_idle_timeout{20000};

    // ===== v4.7.0: PathSelector + Path Observation API v2 =====

    /// v4.7.0 (借鉴 iroh#4232): 路径选择策略开关（默认 false，回滚用）
    ///
    /// true: 启用 PathSelectionStrategy 决策路径迁移（path_strategy 字段生效）
    /// false: 回退 v4.6.x 行为（基于 should_abandon_old_path 硬编码 RTT 阈值）
    ///
    /// 回滚路径：将此开关设为 false 即可禁用策略接入点 A，不影响其他 v4.7.0 API。
    bool path_strategy_enabled{false};

    /// v4.7.0 (借鉴 iroh#4232): 路径选择策略实例（path_strategy_enabled=true 时生效）
    ///
    /// 由 Endpoint::Config 传入。若为 nullptr 且 path_strategy_enabled=true，
    /// 则回退到 RttBasedStrategy（与 v4.6.x 等价，仅按 srtt 选路）。
    ///
    /// 业务场景：
    ///   - PP 链首节点：PpFirstStageStrategy（首 token 延迟优先）
    ///   - PP 链末节点：PpLastStageStrategy（hidden_state 回传带宽优先）
    ///   - 隐私敏感场景：PreferRelayStrategy（强制走 Relay）
    std::shared_ptr<protocol::PathSelectionStrategy> path_strategy;

    /// v4.7.0 (借鉴 iroh#4232): Path Observation API v2 开关（默认 false，回滚用)
    ///
    /// true: 启用 paths() / path_events() 新 API（PathList + PathEventStream）
    /// false: 回退 v4.6.x 行为（仅 PathMigrationManager::set_path_event_callback 单消费者回调）
    ///
    /// 回滚路径：将此开关设为 false 即可禁用新 API，旧回调仍可用。
    /// 注意：即使 path_api_v2_enabled=false，新 API 仍可调用（返回有效对象），
    ///       但不会触发 emit_path_event fan-out（避免无订阅者时的开销）。
    bool path_api_v2_enabled{false};

    // ===== v5.0.0: 0-RTT 重连支持（借鉴 iroh 0.96 Connection<OutgoingZeroRtt>） =====

    /// v5.0.0: 是否启用 0-RTT 重连（默认 true，回滚用）
    ///
    /// true: 握手完成后服务端自动下发 SESSION_TICKET 帧，客户端缓存后
    ///       下次重连时携带 ticket 发起 0-RTT，实现秒级重连
    /// false: 禁用 0-RTT，每次连接走完整 1-RTT 握手（v4.x 行为）
    ///
    /// 回滚路径：将此开关设为 false 即可禁用 0-RTT，不影响其他 v5.0.0 特性。
    bool enable_0rtt{true};

    /// v5.0.0: session ticket 有效期（默认 7 天 = 604800 秒）
    ///
    /// 服务端下发 ticket 时设置此值，客户端缓存 TTL 也使用此值。
    /// RFC 8446 §4.6.1 建议最大 7 天。
    std::chrono::seconds session_ticket_ttl{604800};

    /// v5.0.0: 是否接受 0-RTT 早期数据（服务端侧，默认 false）
    ///
    /// true: 服务端接受 0-RTT 阶段的 ZERO_RTT_DATA 帧（需做重放保护）
    /// false: 服务端拒绝 0-RTT 数据，回退到 1-RTT（更安全，防重放攻击）
    ///
    /// 安全建议：PP 推理首请求走 1-RTT（确保新鲜性），后续重连可走 0-RTT
    bool accept_0rtt_data{false};

    // ===== v5.0.0: QUIC Address Discovery（借鉴 iroh QAD） =====

    /// v5.0.0: 是否启用 QAD 替代 STUN（默认 false，回滚用）
    ///
    /// true: 优先使用 ADDRESS_DISCOVERY 帧获取反射地址（通过已有连接）
    /// false: 使用独立 STUN-like 机制（v4.x 行为）
    ///
    /// 回滚路径：将此开关设为 false 即可回退到 STUN，不影响其他 v5.0.0 特性。
    bool qad_enabled{false};

    /// v5.0.0: QAD 失败时是否回退到 STUN（默认 true）
    ///
    /// true: QAD 超时/失败后自动回退到 STUN-like 机制
    /// false: QAD 失败后不回退，直接报错
    bool qad_stun_fallback{true};
};

/// v4.6.0: 路径类型枚举（用于 idle timeout 差异化）
enum class PathClass : std::uint8_t {
    Direct      = 0,  ///< UDP 直连（P2P 打洞成功）
    Relay       = 1,  ///< Relay 中继路径
    TcpFallback = 2,  ///< TCP 降级路径（UDP 不可用时兜底）
};

    explicit Connection(Config cfg);
    ~Connection();

    ConnState state() const { return state_.load(); }
    const EndpointId &peer_id() const { return peer_id_; }
    const protocol::ConnectionId &local_cid() const { return cfg_.local_cid; }
    const protocol::ConnectionId &remote_cid() const { return cfg_.remote_cid; }
    Direction direction() const { return cfg_.direction; }
    const std::string &alpn() const { return cfg_.alpn; }
    bool is_closed() const {
        ConnState s = state_.load();
        return s == ConnState::Closed || s == ConnState::Draining;
    }

    bool handle_packet(util::Bytes wire);
    void on_handshake_completed();

    /// v4.6.0 (借鉴 noq#545): 网络变化通知 — 重置 PTO backoff 和 RTT 估计。
    ///
    /// 由 Endpoint 在 NetworkChangeTracker 触发回调时对受影响的 Connection 调用。
    /// 解决 WiFi↔Cellular 切换后旧 SRTT 不再适用（如 WiFi 50ms → Cellular 200ms），
    /// 导致 PTO/RTO 基于过时 RTT 估算引发重传过迟（连接假死）或过频（加剧拥塞）的问题。
    ///
    /// 内部动作：
    ///   1. loss_detector_.on_network_change() — 重置 pto_count=0，RTT 回到初始值
    ///   2. 唤醒 loss_tick_loop 立即重算超时（避免等待下一个 tick）
    ///   3. 请求 PING 探测对端可达性（ack-eliciting，激发快速 ACK 收敛新 RTT）
    ///
    /// 幂等安全：多次调用效果等同一次（PTO/RTT 重置为确定值）。
    void on_network_change();

    /// v4.6.0: 设置当前路径类型，自动调整 idle_timeout
    ///
    /// 当连接从 Direct 降级到 Relay 或 TCP 兜底时调用，自动将 cfg_.idle_timeout
    /// 调整为对应路径类型的超时值（relay_idle_timeout / tcp_fallback_idle_timeout）。
    /// 设为 0 的路径超时表示回退到默认 idle_timeout。
    ///
    /// @param pc 路径类型（Direct/Relay/TcpFallback）
    void set_path_class(PathClass pc);

    /// v4.6.0: 获取当前路径类型
    PathClass current_path_class() const noexcept { return current_path_class_; }

    /// 方案 A（2026-07-19）：PSK fast-complete - 强制 conn 状态机从任意状态跳到 Established
    /// 用于 master 端处理 worker 0-RTT / 1-RTT-first 场景：worker 已"认为"握手完成，
    /// 直接发 1-RTT 短包头，master 不能让它走 Initial→Handshake→Established 标准路径。
    void force_psk_established() {
        state_.store(ConnState::Established);
        // 同步流控和 hs_done_ 状态（避免 handle_1rtt_packet 把 Established 当成 Handshake 处理）
        hs_done_ = true;
        flow_ctrl_.on_remote_max_bidi_streams(cfg_.max_bidi_streams);
        flow_ctrl_.on_remote_max_uni_streams(cfg_.max_uni_streams);
    }

    /// 启动握手流程（Outbound 连接需要调用）。
    /// 在 PSK 模式下，会构建简化的 CRYPTO Initial 帧并发送。
    /// 在 TLS 1.3 模式下，会启动 ECDHE+签名 AKE 并产出首段握手指纹（见 take_handshake_flight）。
    util::ResultVoid start_handshake(double now_ms = 0.0);

    /// TLS 1.3 模式是否启用（由 HandshakeConfig::mode 决定）。
    bool tls13_enabled() const {
        return cfg_.handshake.mode == HandshakeMode::Tls13;
    }
    /// TLS 1.3 握手是否已完成并激活（应用层 AEAD 密钥已就绪，1-RTT 数据面已加密）。
    bool tls13_active() const { return tls13_enabled() && hs_done_; }

    /// 取出待发送的握手指纹字节（transport 层包裹为 CRYPTO 帧后发送）。取出后清空缓冲。
    std::vector<std::uint8_t> take_handshake_flight();

    /// 喂入手握手指纹字节（来自对端的 CRYPTO 帧）。驱动 tls::Handshake 推进 AKE；
    /// 若本次交互产生了新的待发送指纹，可通过 take_handshake_flight() 取走。
    /// 握手完成时自动派生应用密钥、校验对端节点身份并进入 Established。
    void feed_handshake(std::span<const std::uint8_t> bytes);

    /// 检查握手是否超时（返回 true 表示连接应关闭）。
    bool check_handshake_timeout(double now_ms) const;

    /// 尝试接受对端创建的流，返回 Result（非 Established 状态返回 InvalidState）。
    util::Result<std::shared_ptr<Stream>> try_accept_stream();

    std::shared_ptr<Stream> open_stream();
    /// 尝试打开新流，返回 Result（流数限制时返回 StreamLimitError，非 Established 返回 InvalidState）。
    util::Result<std::shared_ptr<Stream>> try_open_stream();
    std::shared_ptr<Stream> accept_stream();
    void send_stream(std::uint64_t stream_id, std::span<const std::uint8_t> data);
    void finish_stream(std::uint64_t stream_id);

    // ====================================================================
    // P1-1: RPC Stream 复用（2026-07-19 新增）
    //
    // 这些方法暴露为 public 以便测试和上层（如 ApplicationApi）直接管理 stream 池。
    // 常规 RPC 用户应使用 call()/respond()/respond_error()，它们内部已自动调用
    // acquire/release/register/take。
    // ====================================================================
    /// RPC stream 空闲池上限。
    static constexpr std::size_t kRpcStreamPoolMax = 32;

    /// 从池中取空闲 stream；池空则 open_stream 新建。返回 nullptr 表示失败。
    std::shared_ptr<Stream> acquire_rpc_stream();

    /// 归还 stream 到空闲池（池满则忽略）。已 close/fin_sent 的 stream 不归还。
    void release_rpc_stream(std::shared_ptr<Stream> stream);

    /// 服务端：记录 request_id → stream 映射（rpc_stream_handler 处理 Request 时自动调用）。
    void register_request_stream(std::uint32_t request_id,
                                  std::shared_ptr<Stream> stream);

    /// 服务端：取出 request_id 对应的 stream（respond/respond_error 自动调用）。
    /// 返回 nullptr 表示映射不存在或 stream 已失效。
    std::shared_ptr<Stream> take_request_stream(std::uint32_t request_id);

    void on_stream(std::function<void(std::shared_ptr<Stream>)> h) { on_stream_ = std::move(h); }
    void on_close(std::function<void()> h) { on_close_ = std::move(h); }

    /// Stream 读写锁（修复 2026-07-17：linoh_stream_write/read 需与
    /// build_1rtt_packet/handle_1rtt_packet 使用同一把锁，否则并发访问
    /// send_/recv_ vector 会导致数据损坏，表现为 "unexpected frame type: 0x00"）
    std::mutex& stream_mutex() { return stream_mu_; }

    void close(std::uint16_t error_code = 0, std::string reason = {});

    /// P4-A-3: 关闭模式（借鉴 iroh PR #4270）
    ///
    /// - Graceful: 走标准 Closing→Closed 状态转换，留出时间发送 CONNECTION_CLOSE 帧
    ///             让对端感知关闭（默认行为，与无参 close() 一致）
    /// - Immediate: 跳过 Closing 中间状态，直接进入 Closed。
    ///             适用于应用主动退出场景，避免等待 draining period。
    ///             代价：对端可能要靠心跳超时才发现本端退出。
    enum class CloseMode {
        Graceful,
        Immediate,
    };

    /// P4-A-3: 带模式的 close 重载。
    void close(std::uint16_t error_code, std::string reason, CloseMode mode);

    /// P4-A-3: 便捷方法 — 立即关闭。
    void close_immediate(std::uint16_t error_code = 0, std::string reason = {}) {
        close(error_code, std::move(reason), CloseMode::Immediate);
    }

    // ====================================================================
    // 应用层 RPC（借鉴 qt-easy-tier DaemonClient，2026-07-19 新增）
    //
    // 在 STREAM 字节流之上提供请求-响应匹配语义：
    //   - call()            发送请求并等待响应（带超时）
    //   - notify()          发送通知（无响应）
    //   - respond()         服务端响应请求
    //   - respond_error()   服务端返回错误
    //
    // 启用方式：调用 set_application_message_handler() 注册消息处理器后，
    // Connection 会自动接管 on_stream_ 回调，将 stream 数据解析为
    // ApplicationMessage 并分发到对应处理器。
    // ====================================================================

    /// 发送 RPC 请求（Request 消息，id > 0）。
    /// \param method     方法枚举
    /// \param payload    二进制 payload
    /// \param timeout_ms 超时（毫秒），0 = 不超时
    /// \return future，调用方 get() 等待响应 payload；超时或断线抛异常
    std::future<std::vector<std::uint8_t>> call(
        protocol::MethodId method,
        std::span<const std::uint8_t> payload,
        std::uint32_t timeout_ms = 120000);

    /// 发送通知（Notification 消息，id = 0，无响应）。
    void notify(protocol::MethodId method,
                std::span<const std::uint8_t> payload);

    /// 服务端响应请求（Response 消息）。
    void respond(std::uint32_t request_id, protocol::MethodId method,
                 std::span<const std::uint8_t> payload);

    /// 服务端返回错误（ErrorResponse 消息）。
    void respond_error(std::uint32_t request_id, protocol::MethodId method,
                       const std::string &error_msg);

    /// 注册 Request/ErrorResponse 处理器（服务端侧）。
    /// 设置后 Connection 自动接管 on_stream_，将 stream 数据解析为
    /// ApplicationMessage 并调用 handler。Request 和 ErrorResponse 都会触发此 handler。
    void set_request_handler(
        std::function<void(const protocol::ApplicationMessage &)> h);

    /// 注册 Notification 处理器（双向）。
    void set_notification_handler(
        std::function<void(const protocol::ApplicationMessage &)> h);

    /// 注册 Response 处理器（可选，默认走 pending_requests_ 匹配）。
    /// 设置后 Response 也会触发此 handler（用于调试/旁路监听）。
    void set_response_handler(
        std::function<void(const protocol::ApplicationMessage &)> h);

    /// 当前 pending 请求数量（用于监控/调试）。
    std::size_t pending_request_count() const {
        std::lock_guard<std::shared_mutex> lk(pending_mu_);
        return pending_requests_.size();
    }

    /// P1-1: RPC stream 空闲池当前大小（用于监控/测试）。
    std::size_t rpc_stream_pool_size() const {
        std::lock_guard<std::mutex> lk(rpc_stream_mu_);
        return rpc_stream_pool_.size();
    }

    /// P1-1: RPC in-flight（等待响应的 stream）数量。
    std::size_t rpc_in_flight_count() const {
        std::lock_guard<std::mutex> lk(rpc_stream_mu_);
        return rpc_in_flight_.size();
    }

    util::Bytes encrypt_packet(std::span<const std::uint8_t> header,
                               std::span<const std::uint8_t> payload);
    std::optional<util::Bytes> decrypt_packet(std::span<const std::uint8_t> header,
                                              std::span<const std::uint8_t> cipher);

    std::size_t build_1rtt_packet(std::span<std::uint8_t> out);
    std::size_t build_0rtt_packet(std::span<std::uint8_t> out);
    void update_rtt(double rtt_ms);

    /// v1.5 P0-2: 强制构造 1-RTT 包（仅含 FIN 帧），绕过常规 cwnd/space 检查。
    ///
    /// cluster BACKLOG 反馈：旧实现 FIN-only 帧与 STREAM data 共用同一发送逻辑，
    /// 当 cwnd 满 / payload 空间不足时 FIN 帧会被丢弃，导致对端连接长时间处于
    /// half-closed 状态。本接口单独构造一个最小 1-RTT 包，强制 FIN 必达。
    ///
    /// 返回：写入 out 的字节数（0 = 无待发 FIN）。
    std::size_t build_fin_only_packet(std::span<std::uint8_t> out);

    /// 处理收到的 ACK 帧：更新 RTT、标记已确认、触发丢包检测。
    void handle_ack_frame(const protocol::AckFrame &ack);

    /// v1.5.0.5: 处理收到的 OOS_PN 帧（type=0x30）。
    /// 接收方 → 发送方反馈 OOS buffer PN 列表，写入 oos_pn_remote_ map。
    /// 下次 handle_ack_frame 会将 oos_pn_remote_ 中未过期的 entries 反查 PN
    /// 注入 LossDetector，触发主动 retx（Q3 答复：30s 过期清理）。
    /// \param data 帧字节流（不含 type 字节前的所有字段，参见 packet.cpp parse_frames 0x30 case）
    void handle_oos_pn_frame(std::span<const uint8_t> data);

    /// 获取当前需要重传的包编号列表。
    std::vector<std::uint64_t> pending_retransmits() const;

    // v1.5.0.1 P0-1: 测试钩子 — 注入丢包 PN + 对应 plaintext 模拟重传场景。
    // 仅用于单元测试，生产代码请使用 handle_ack_frame 真实路径。
    void __test_inject_lost_packet(std::uint64_t pn, std::vector<std::uint8_t> plaintext);

    // v1.5.0.5: 单个 OOS_PN 远程条目结构体（公开以便测试访问器返回引用）。
    struct OosRemoteEntry {
        std::uint64_t offset{0};
        double first_seen_ms{0.0};
        double recv_time_ms{0.0};
    };

    // v1.5.0.5: 测试访问器 — 直接读写 oos_pn_remote_ map，便于单测覆盖 handle_oos_pn_frame
    // 解析 + handle_ack_frame 注入 LossDetector 的端到端链路。
    std::unordered_map<std::uint64_t, std::vector<OosRemoteEntry>> &oos_pn_remote_for_test() {
        return oos_pn_remote_;
    }
    std::mutex &oos_pn_remote_mu_for_test() { return oos_pn_remote_mu_; }

    // v1.5.0.7 (ISSUE T06 反馈): 测试访问器 — 调用 build_oos_pn_data() 验证触发逻辑
    // （首次直接触发 + 节拍 50ms + 仅成功发送更新节拍），并读取 5 个计数器埋点。
    std::vector<std::uint8_t> build_oos_pn_data_for_test() { return build_oos_pn_data(); }
    std::uint64_t build_oos_pn_data_total_for_test() const { return build_oos_pn_data_total_; }
    std::uint64_t OOS_PN_frame_total_for_test() const { return OOS_PN_frame_total_; }
    std::uint64_t decode_OOS_PN_total_for_test() const { return decode_OOS_PN_total_; }
    std::uint64_t OOS_PN_decode_total_for_test() const { return OOS_PN_decode_total_; }
    std::uint64_t OOS_PN_decode_failed_total_for_test() const { return OOS_PN_decode_failed_total_; }
    double last_oos_pn_send_ms_for_test() const { return last_oos_pn_send_ms_; }
    void reset_last_oos_pn_send_ms_for_test() { last_oos_pn_send_ms_ = 0.0; }

    // v1.5.0.10 (ISSUE T09 反馈): OOS_PN 帧全链路埋点测试访问器
    //   - recv_total: parse_frames 已分发到 handle_oos_pn_frame（确认 A1 路由）
    //   - decode_fail_total: decode_oos_pn_frame 失败（确认编解码对称性）
    //   - dropped_total: parse_frames default 分支丢弃的 OOS_PN 帧（罕见，ALPN 异常时可能）
    //   - resent_total: 50ms 合并 + 500ms 重发机制的 OOS_PN 帧重发计数（Step 2 启用）
    std::uint64_t oos_pn_frame_recv_total_for_test() const { return oos_pn_frame_recv_total_; }
    std::uint64_t oos_pn_frame_decode_fail_total_for_test() const { return oos_pn_frame_decode_fail_total_; }
    std::uint64_t oos_pn_frame_dropped_total_for_test() const { return oos_pn_frame_dropped_total_; }
    std::uint64_t oos_pn_frame_resent_total_for_test() const { return oos_pn_frame_resent_total_; }

    // v1.5.0.10 (ISSUE T09 反馈): OOS_PN 帧重发链路测试访问器
    //   - pending_size: 当前 pending_oos_pn_frames_ 队列大小（应为 0~streams_with_gap）
    //   - resend_total: 累计重发次数（>0 表示触发过 500ms 重传机制）
    std::size_t pending_oos_pn_frames_size_for_test() const;
    std::uint64_t oos_pn_resend_total_for_test() const { return oos_pn_resend_total_; }

    // v1.5.0.11 (ISSUE T10 反馈 P1+P2): high_priority + 丢包分桶测试访问器
    //   - high_priority_sent_total: high_priority 通道累计发送（含首发+重发）
    //   - acked_implicit_total: 隐式确认总数（用于派生 loss_rate = (sent-acked)/sent）
    std::uint64_t oos_pn_high_priority_sent_total_for_test() const { return oos_pn_high_priority_sent_total_; }
    std::uint64_t oos_pn_acked_implicit_total_for_test() const { return oos_pn_acked_implicit_total_; }

    // v1.5.0.12 (ISSUE T11 反馈 P2): resend 节拍解耦可观测性测试访问器
    //   - call_total: resend_oos_pn_if_needed 被调用次数（1Hz heartbeat）
    //   - skipped_rhythm_total: 因节拍未到被跳过的次数
    //   - triggered_total: 实际触发重发的次数
    //   - last_resend_check_ms: 上次重传检查时间戳（诊断节拍）
    //   - 矩阵：skipped_rhythm + triggered <= call_total（triggered 仅在节拍满足时计数）
    std::uint64_t resend_oos_pn_call_total_for_test() const { return resend_oos_pn_call_total_; }
    std::uint64_t resend_oos_pn_skipped_rhythm_total_for_test() const { return resend_oos_pn_skipped_rhythm_total_; }
    std::uint64_t resend_oos_pn_triggered_total_for_test() const { return resend_oos_pn_triggered_total_; }
    double last_resend_check_ms_for_test() const { return last_resend_check_ms_; }

    // v1.5.0.8 (ISSUE T07 反馈): 测试访问器 — 直接访问 LossDetector，便于单测
    //   on_oos_pn_received 反查逻辑 + Connection→LossDetector OOS_PN 同步链路。
    //   非 public API，不在文档中暴露。
    protocol::LossDetector &loss_detector_for_test() { return loss_detector_; }

    /// 构建 ACK 帧数据（编码到 1-RTT 包中）。
    std::vector<std::uint8_t> build_ack_data();

    /// 检查空闲超时（返回 true 表示连接应关闭）。
    bool check_idle_timeout(double now_ms);

    /// 检查是否需要发送保活 PING。
    bool needs_keepalive(double now_ms) const;

    /// 请求在下次 build_1rtt_packet 中包含 PING 帧。
    void request_ping() { ping_pending_ = true; }

    /// v5.4 F4：发送 STREAM_DATA_BLOCKED(sid, offset) 声明发送需求（credit 预约）。
    /// 对端（v5.4+）收到即保障窗口至少到 offset+一窗并回 MAX_STREAM_DATA；
    /// 老对端仅记日志（无保障，调用方 write_ex 超时降级）。线程安全。
    void send_stream_data_blocked(std::uint64_t stream_id, std::uint64_t offset);

    /// v5.4 F4：指定流的发送可用容量（remote 窗口 - 已发 offset）。
    std::uint64_t stream_send_capacity(std::uint64_t stream_id,
                                       std::uint64_t send_offset) const;

    /// S1（v5.3）：控制帧捎带通道——SESSION_TICKET / ADDRESS_DISCOVERY /
    /// ADDRESS_DISCOVERY_RESPONSE 等低频控制帧入队，由 build_1rtt_packet
    /// 在 ACK 帧之后捎带发送（空间不足留队下一包）。线程安全。
    /// @param frame_with_type 完整帧字节（含 type 首字节）
    void queue_control_frame(std::vector<std::uint8_t> frame_with_type);

    /// v1.5.0.1 P3-1: 1Hz 周期流控主动通告。
    /// 检查 should_send_max_data() / should_send_max_stream_data(sid)，
    /// 命中则编码为完整帧（type 字节 + varint）push 到 pending_fc_frames_。
    /// 由 heartbeat_loop 在 1Hz 周期调用，无 ACK 触发路径（用户确认暂不调整）。
    void emit_periodic_flow_control();

    // v1.5.0.1 P3-1: 测试访问器（仅 tests/ 下使用），允许单测直接观察内部状态。
    // 非 public API，不在文档中暴露。
    std::vector<std::vector<std::uint8_t>>& pending_fc_frames_for_test() { return pending_fc_frames_; }
    protocol::FlowController& flow_controller_for_test() { return flow_ctrl_; }

    /// 更新最后活动时间。
    void record_activity(double now_ms);

    /// 处理流控帧（MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS 等）。
    void handle_flow_control_frame(std::uint8_t frame_type,
                                    std::span<const std::uint8_t> payload);

    /// 处理路径迁移帧（PATH_CHALLENGE / PATH_RESPONSE / NEW_CONNECTION_ID / RETIRE_CONNECTION_ID）。
    void handle_path_migration_frame(std::uint8_t frame_type,
                                      std::span<const std::uint8_t> payload);

    // ====================================================================
    // v1.5.0.2 Step 3: MTU 协商（jumbo frame 9000）
    // ====================================================================
public:
    /// 获取当前协商后的 MTU（握手完成后可用，否则为 1280）。
    std::uint16_t negotiated_mtu() const { return negotiated_mtu_; }

    /// 获取对端在 Hello 中声明的 preferred_mtu（握手完成后有效）。
    std::uint16_t remote_preferred_mtu() const {
        return hs_driver_ ? hs_driver_->peer_preferred_mtu() : 1280;
    }

    /// v1.5.0.2 Step 3: 当前最大包大小 = max(1280, negotiated_mtu)。
    /// 握手前为 1280，握手完成后为协商 MTU（jumbo 9000 / 跨网 1500 / 默认 1280）。
    std::size_t current_max_packet_size() const {
        constexpr std::size_t kMinPacketSize = 1280;  // QUIC 最小保证
        return static_cast<std::size_t>(negotiated_mtu_) > kMinPacketSize
                   ? static_cast<std::size_t>(negotiated_mtu_)
                   : kMinPacketSize;
    }

    /// 显式调用 MTU 协商（握手完成后由 on_handshake_completed 自动调用，
    /// 也可由应用层基于 net_report 主动触发重新协商）。
    /// \param nat_type NAT 类型（用于降级策略）
    /// \param firewall 是否有严格防火墙
    void renegotiate_mtu(net::NatType nat_type = net::NatType::Unknown,
                          bool firewall = false);

    // ====================================================================
    // v1.5.0.2 Step 4: CryptoLevel 协商（按模态 + 网络分级加密）
    // ====================================================================
    /// 获取当前协商后的 CryptoLevel（握手完成后可用，握手前为 None）。
    multimodal::CryptoLevel effective_crypto_level() const {
        return effective_crypto_level_;
    }

    /// 获取对端在 Hello 中声明的 preferred_crypto_level（握手完成后有效）。
    multimodal::CryptoLevel remote_preferred_crypto_level() const {
        return hs_driver_ ? hs_driver_->peer_preferred_crypto_level()
                          : multimodal::CryptoLevel::None;
    }

    /// 协商算法：取 max(local, remote) + LLM/Control ALPN 兜底到 Strong 以上
    /// 握手完成后由 on_handshake_completed 自动调用。
    void negotiate_crypto_level();

    /// 获取 EffectiveCryptoSpec（包含 algorithm/key_bits/extra_mac）。
    /// 应用层用于实际配置 AEAD 算法。
    tls::CryptoSpec effective_crypto_spec() const {
        return tls::crypto_spec_for(effective_crypto_level_);
    }

    /// 获取 FlowController（用于外部查询窗口状态）。
    const protocol::FlowController &flow_controller() const { return flow_ctrl_; }

    /// 获取 PathMigrationManager。
    const protocol::PathMigrationManager &path_manager() const { return path_mgr_; }

    /// v1.7.0.1 P0: 触发重新打洞（网络变更后调用）
    ///
    /// 借鉴 iroh #3928：网络切换（WiFi↔4G/5G、网卡启用/禁用、DHCP 续租）后，
    /// 旧路径候选失效但 ICE 不会自动重收集，连接可能卡死。
    /// 本方法复用 PathMigrationManager::generate_challenge_with_tuple() 流程，
    /// 生成一个新的 PATH_CHALLENGE 并触发路径重验证。
    ///
    /// @return true 表示已成功触发（处于 Established 状态）；
    ///         false 表示连接未就绪（非 Established 或已关闭）
    /// @note 仅当 Endpoint::Config::auto_reholepunch_on_network_change=true 时自动调用。
    ///       用户也可手动调用以强制重打洞。
    bool trigger_reholepunch();

    /// v1.7.0.1 P0: 自上次 reholepunch 以来已触发的次数（用于测试/诊断）
    std::uint64_t reholepunch_count() const noexcept { return reholepunch_count_.load(); }

    // ====================================================================
    // v4.7.0: Path Observation API v2（借鉴 iroh#4232）
    // ====================================================================

    /// v4.7.0: 路径快照（不可变视图，借鉴 iroh PathList<'_>）
    ///
    /// 返回当前所有路径的质量快照（含 srtt/loss/bandwidth_tier 等）。
    /// 调用 infallible：内部加锁拷贝，不依赖 Connection 存活（返回值类型）。
    ///
    /// "先订阅后快照"模式：
    ///   auto stream = conn.path_events();   // 1. 先订阅事件流
    ///   auto snap = conn.paths();           // 2. 后取快照
    ///   // snap 包含订阅时刻的所有路径，stream 不会丢失订阅后的事件
    ///
    /// @return PathList 值类型（含 vector<PathQuality> + current_idx_）
    /// @note 即使 path_api_v2_enabled=false 也可调用（API 总是可用，开关只影响 fan-out）
    PathList paths() const;

    /// v4.7.0: 路径事件流（'static，借鉴 iroh PathEventStream）
    ///
    /// 返回独立的 PathEventStream 对象，可 'static 持有（不延长 Connection 生命周期）。
    /// Connection 析构时通过 weak_ptr 自动 close 所有流。
    ///
    /// 事件类型：Opened / Selected / Closed / Lagged
    ///   - Opened:  新路径加入 PathList（update_path_quality 首次见到 path_id）
    ///   - Selected: 路径切换（接入点 A 决策切换主路径）
    ///   - Closed:  路径放弃（abandon_path / abandon_idle_paths）
    ///   - Lagged:  队列溢出（消费者过慢，丢弃最旧事件后投递）
    ///
    /// @return PathEventStream 值类型（持 shared_ptr<Impl>）
    /// @note 即使 path_api_v2_enabled=false 也可调用，但不会收到事件（无 fan-out）
    PathEventStream path_events();

    /// v4.7.0: 设置路径选择策略（运行时覆盖 Config::path_strategy）
    ///
    /// 传入 nullptr 清除策略（select_primary_path 返回 nullopt，保守不切换）。
    /// @note 此方法仅设置 PathMigrationManager 的策略实例；
    ///       接入点 A 是否调用 select_primary_path 由 Config::path_strategy_enabled 决定。
    void set_path_strategy(std::shared_ptr<protocol::PathSelectionStrategy> s) {
        path_mgr_.set_strategy(std::move(s));
    }

    /// v4.7.0: 查询是否已设置路径选择策略
    bool has_path_strategy() const noexcept {
        return path_mgr_.has_strategy();
    }

    /// v4.7.0: 手动触发路径选择决策（接入点 A，测试用）
    ///
    /// 内部调用 PathMigrationManager::select_primary_path()，若有更优路径则切换。
    /// @return 选中的路径四元组（nullopt 表示无策略或无候选，保守不切换）
    /// @note Config::path_strategy_enabled=false 时直接返回 nullopt
    std::optional<net::FourTuple> try_select_better_path();

    /// 会话保存与恢复（0-RTT）
    /// save_session() 在 Established 之后可调用，返回可用于下次快速恢复的票据。
    std::optional<SessionTicket> save_session() const;
    /// 当前连接是否在使用会话恢复（0-RTT 模式）。
    bool is_resumed() const { return cfg_.resume_ticket.has_value(); }
    /// 向 0-RTT 缓冲区写入 early data，可直接在新连接上发送。
    void queue_early_data(std::span<const std::uint8_t> data);

    // ===== v5.0.0: SESSION_TICKET 帧处理（借鉴 iroh 0.96） =====

    /// v5.0.0: 处理收到的 SESSION_TICKET 帧
    /// 服务端在握手完成后下发，客户端缓存 ticket 用于后续 0-RTT 重连。
    /// @param data 帧载荷（不含 type 字节，由 parse_frames 吞下）
    /// @return true=处理成功，false=解码失败或 0-RTT 被禁用
    bool handle_session_ticket_frame(std::span<const std::uint8_t> data);

    /// v5.0.0: 发送 SESSION_TICKET 帧给对端
    /// 服务端在握手完成后调用，下发 session ticket。
    /// @param ticket 要发送的 session ticket
    /// @return true=发送成功，false=encode 失败或 0-RTT 被禁用
    bool send_session_ticket(const protocol::SessionTicketFrame &ticket);

    /// v5.0.0: 处理收到的 ZERO_RTT_DATA 帧
    /// 接收方需做重放保护（检测重复的 0-RTT 数据并丢弃）。
    /// @param data 帧载荷（不含 type 字节）
    /// @return true=接受数据，false=拒绝（重放/0-RTT 被禁用/解码失败）
    bool handle_zero_rtt_data_frame(std::span<const std::uint8_t> data);

    // ---- v5.1.0: PSK_IDENTITY 帧（K-LINOH-PEERMISMATCH 根治） -------------
    /// 构造本端身份帧体（node_pub + Ed25519 签名，不含 type 字节）
    std::vector<std::uint8_t> build_psk_identity_data();

    /// 标记待发身份帧（由 build_1rtt_packet 在包尾附加；幂等）
    /// 叠加层设计：不改变状态机，连接照常立即可用
    void send_psk_identity();

    /// 处理收到的对端身份帧：时间窗校验 + Ed25519 验签，
    /// 通过后 peer_id_ = 对端真实 EndpointId 并置 peer_authenticated_。
    /// 失败（格式/超窗/伪造）不影响连接，peer_id_ 保持旧行为（降级兼容）。
    bool handle_psk_identity_frame(std::span<const std::uint8_t> data);

    /// 对端身份是否已通过 PSK_IDENTITY 认证（应用层可信 peer_id 的判据）
    bool peer_authenticated() const;

    /// v5.0.0: 设置 session cache（客户端侧）
    /// 由 Endpoint 在创建 Connection 时注入，用于缓存/查询 session ticket。
    void set_session_cache(std::shared_ptr<SessionCache> cache) {
        session_cache_ = std::move(cache);
    }

    /// v5.0.0: 查询是否启用了 0-RTT
    bool is_0rtt_enabled() const noexcept { return cfg_.enable_0rtt; }

    /// v5.0.0: 查询是否接受 0-RTT 早期数据（服务端侧）
    bool accepts_0rtt_data() const noexcept { return cfg_.accept_0rtt_data; }

    /// v5.0.0: 0-RTT 被服务端拒绝后，清除本地缓存的 ticket
    /// 客户端在收到 0-RTT 拒绝信号后调用，回退到 1-RTT。
    void on_0rtt_rejected();

    // ===== v5.0.0: QUIC Address Discovery 帧处理（借鉴 iroh QAD） =====

    /// v5.0.0: 处理收到的 ADDRESS_DISCOVERY 请求帧（服务端侧）
    /// 客户端通过已有连接发送请求，服务端响应观察到的客户端公网地址。
    /// @param data 帧载荷（不含 type 字节）
    /// @return true=处理成功并已回送 RESPONSE，false=QAD 禁用或解码失败
    bool handle_address_discovery_frame(std::span<const std::uint8_t> data);

    /// v5.0.0: 处理收到的 ADDRESS_DISCOVERY_RESPONSE 帧（客户端侧）
    /// 服务端回送客户端观察到的公网地址，客户端据此更新本地候选地址列表。
    /// @param data 帧载荷（不含 type 字节）
    /// @return true=处理成功，false=QAD 禁用或解码失败
    bool handle_address_discovery_response_frame(std::span<const std::uint8_t> data);

    /// v5.0.0: 客户端主动发送 ADDRESS_DISCOVERY 请求
    /// 通过已有连接请求服务端反射客户端公网地址，替代独立 STUN 服务器。
    /// @return true=发送成功，false=QAD 禁用或 encode 失败
    bool send_address_discovery_request();

    /// v5.0.0: 服务端发送 ADDRESS_DISCOVERY_RESPONSE 响应
    /// @param nonce 客户端请求中的 nonce（原样回传，防重放）
    /// @param observed_host 观察到的客户端公网 IP（字符串形式）
    /// @param observed_port 观察到的客户端公网端口
    /// @return true=发送成功，false=encode 失败
    bool send_address_discovery_response(
        const std::vector<std::uint8_t> &nonce,
        std::string_view observed_host,
        std::uint16_t observed_port);

    /// v5.0.0: 查询是否启用了 QAD
    bool is_qad_enabled() const noexcept { return cfg_.qad_enabled; }

    /// v5.0.0: 查询 QAD 是否允许 STUN fallback
    bool qad_stun_fallback_enabled() const noexcept { return cfg_.qad_stun_fallback; }

    /// v5.0.0: 设置 QAD 回调（地址发现完成时通知上层）
    /// @param cb 回调函数（host, port），nullptr 清除回调
    using QadAddressCallback = std::function<void(std::string, std::uint16_t)>;
    void set_qad_address_callback(QadAddressCallback cb) {
        qad_address_cb_ = std::move(cb);
    }

    /// v5.0.0: 注入最近接收到的对端公网地址（由 Endpoint 在 handle_packet 时调用）
    /// QAD 服务端侧用它构造 ADDRESS_DISCOVERY_RESPONSE 的 observed_host/port。
    /// @param host 对端 IP 字符串（如 "203.0.113.42"）
    /// @param port 对端端口
    void set_last_peer_addr(std::string host, std::uint16_t port) {
        std::lock_guard<std::mutex> lk(peer_addr_mu_);
        last_peer_host_ = std::move(host);
        last_peer_port_ = port;
    }

    ConnectionStats stats() const { return stats_; }

    // ---- v5.4 F7：消息画像与路径计数写入点（C API 层调用；尽力而为累加） ----
    static size_t msg_bucket_index(size_t len) {
        // 上界：64/256/1K/4K/16K/64K/256K/∞
        if (len <   64) return 0;
        if (len <  256) return 1;
        if (len < 1024) return 2;
        if (len < 4096) return 3;
        if (len < 16384) return 4;
        if (len < 65536) return 5;
        if (len < 262144) return 6;
        return 7;
    }
    void record_msg_sent(size_t len) {
        stats_.msgs_sent++;
        stats_.msg_size_sent_buckets[msg_bucket_index(len)]++;
    }
    void record_msg_received(size_t len) {
        stats_.msgs_received++;
        stats_.msg_size_recv_buckets[msg_bucket_index(len)]++;
    }
    void record_pkt_path(bool via_relay) {
        if (via_relay) stats_.pkts_via_relay++; else stats_.pkts_via_direct++;
    }
    /// F7: 流数量快照（local+remote，持 stream_mu_）
    size_t open_stream_count();
    /// F7: 距最近收包活动的毫秒数（活性观测；steady 时钟）
    double last_activity_age_ms() const;
    /// F7: 活性配置快照（idle/keepalive，毫秒；0=关闭）
    std::uint32_t idle_timeout_cfg_ms() const;
    std::uint32_t keepalive_cfg_ms() const;

    // ========== O1.2（独立项目方案 W1.1）：对端能力缓存 ==========

    /// 设置对端能力掩码（kCap* 组合）。
    /// 库内自动通路：接收路径解析到 CapabilitiesAck 响应时自动调用；
    /// 调用方也可在自有协商完成后显式设置（后写覆盖）。
    /// 掩码驱动 maybe_auto_compress 的降级矩阵（0=未探测→不压缩）。
    void set_peer_capabilities(std::uint32_t mask) {
        peer_capabilities_ = mask;
    }

    /// 对端能力掩码（默认 0=未探测）
    std::uint32_t peer_capabilities() const { return peer_capabilities_; }
    std::uint64_t id() const { return id_; }
    /// v1.7.0.4 P3 (B8): stable_id 别名 — 对标 iroh conn.stable_id() tracing 约定
    /// 用于 LINOH_CONN_LOG 宏携带 conn_id 日志字段
    std::uint64_t stable_id() const noexcept { return id_; }

    // ====================================================================
    // V3-B: 跨域连接标记与统计
    // ====================================================================

    /// 是否为跨域数据面连接（由 Config.is_cross_domain 设置）
    bool is_cross_domain() const noexcept { return cfg_.is_cross_domain; }

    /// 对端域 ID（跨域连接有效，本域连接为 0）
    std::uint32_t peer_domain_id() const noexcept { return cfg_.peer_domain_id; }

    /// 跨域连接统计快照（线程安全，原子读）
    /// @return CrossDomainStats 副本（含 bytes/rtt/peer_domain_id）
    /// @note 非跨域连接返回全零字段（peer_domain_id=0）
    CrossDomainStats cross_domain_stats() const noexcept {
        CrossDomainStats s;
        s.bytes_sent_cross_domain = cross_domain_bytes_sent_.load(std::memory_order_relaxed);
        s.bytes_received_cross_domain = cross_domain_bytes_received_.load(std::memory_order_relaxed);
        s.rtt_ms = cross_domain_rtt_ms_.load(std::memory_order_relaxed);
        s.peer_domain_id = cfg_.peer_domain_id;
        return s;
    }

    /// V3-B: 累积跨域发送字节（仅跨域连接调用有效，由发送路径调用）
    void add_cross_domain_bytes_sent(std::uint64_t n) noexcept {
        if (cfg_.is_cross_domain) {
            cross_domain_bytes_sent_.fetch_add(n, std::memory_order_relaxed);
        }
    }

    /// V3-B: 累积跨域接收字节（仅跨域连接调用有效，由接收路径调用）
    void add_cross_domain_bytes_received(std::uint64_t n) noexcept {
        if (cfg_.is_cross_domain) {
            cross_domain_bytes_received_.fetch_add(n, std::memory_order_relaxed);
        }
    }

    /// V3-B: 更新跨域 RTT（由 RttEstimator 回调，仅跨域连接累积）
    void set_cross_domain_rtt_ms(std::uint32_t rtt_ms) noexcept {
        if (cfg_.is_cross_domain) {
            cross_domain_rtt_ms_.store(rtt_ms, std::memory_order_relaxed);
        }
    }

    /// V3-B: 运行时标记连接为跨域数据面连接
    ///
    /// 用于连接建立后由 C-API linoh_connect_cross_domain 标记。
    /// 调用时机：连接建立后、数据传输前（单线程上下文，避免与发送/接收路径竞争）。
    /// 调用后 cross_domain_stats() / add_cross_domain_bytes_* 才会累积跨域统计。
    ///
    /// @param is_cross_domain  是否为跨域连接
    /// @param peer_domain_id   对端域 ID（is_cross_domain=true 时有效）
    void set_cross_domain(bool is_cross_domain, std::uint32_t peer_domain_id = 0) noexcept {
        cfg_.is_cross_domain = is_cross_domain;
        if (is_cross_domain) {
            cfg_.peer_domain_id = peer_domain_id;
        }
    }

    /// V3-B: 获取拥塞控制器指针（用于跨域 BBR 参数应用）
    /// @return 拥塞控制器裸指针（非拥有，Connection 持有所有权）；未配置时返回 nullptr
    /// @note 调用方不得释放返回的指针；指针有效期与 Connection 存活期一致
    protocol::CongestionController *congestion_controller() noexcept {
        return congestion_ctrl_.get();
    }
    const protocol::CongestionController *congestion_controller() const noexcept {
        return congestion_ctrl_.get();
    }

    // ====================================================================
    // P1-5: KeyUpdate 公开接口（RFC 9001 §6）
    // ====================================================================
    /// 当前 key_phase 位（0 或 1，每次 KeyUpdate 翻转）
    std::uint8_t key_phase() const noexcept {
        return key_phase_.load(std::memory_order_acquire);
    }

    /// P1-5: 主动触发密钥轮换。调用后本端发送的后续包使用新密钥。
    /// \return true=成功；false=非 TLS1.3 模式或未握手完成
    bool trigger_key_update();

    /// P1-5: 查询是否应触发主动 KeyUpdate（基于包计数阈值）。
    /// \return true=已发送包数超过安全阈值，应触发 KeyUpdate
    bool should_rotate_keys() const noexcept {
        return tls13_active() &&
               packets_sent_since_rotate_.load(std::memory_order_acquire) >=
                   tls::KeySchedule::kKeyUpdatePacketThreshold;
    }

    /// P1-5: 自上次 KeyUpdate 以来已发送的包数
    std::uint64_t packets_sent_since_rotate() const noexcept {
        return packets_sent_since_rotate_.load(std::memory_order_acquire);
    }

    // v1.5.0.11 (ISSUE T10 反馈): OOS_PN 重传参数提升为 public 以支持
    //   编译期测试（test_oos_pn_reliability_v1511）。
    //   原 private 段，lessons learned: 测试访问 private 优于 friend 声明。
    /// v1.5.0.11: OOS_PN 帧重传超时 100ms（v1.5.0.10 为 500ms，T10 反馈 66% 丢包下不足）
    static constexpr double kOosPnResendTimeoutMs = 100.0;
    /// v1.5.0.11: 单条 OOS_PN 帧最大重发次数 8 次（v1.5.0.10 为 3 次）
    static constexpr std::uint64_t kOosPnMaxResendCount = 8;

private:
    void handle_initial_packet(protocol::PacketHeader &hdr, util::Bytes &payload);
    void handle_handshake_packet(protocol::PacketHeader &hdr, util::Bytes &payload);
    void handle_1rtt_packet(protocol::PacketHeader &hdr, util::Bytes &payload);
    void handle_0rtt_packet(protocol::PacketHeader &hdr, util::Bytes &payload);
    std::uint64_t next_local_stream_id(bool bidi);
    tls::HandshakeTokenKey crypto_key_;
    std::array<std::uint8_t, 32> zero_rtt_secret_{};
    /// v1.7.0.6 (C10 fix): 0-RTT nonce 派生方案改为 HMAC(zero_rtt_secret, local_cid || pn)，
    /// 不再使用固定 IV。local_cid 在构造时随机生成且连接唯一，避免跨连接 nonce 重用。
    /// 参考 RFC 9001 §5.8：每连接 0-RTT key 应混入连接唯一盐值。
    std::vector<std::uint8_t> early_data_buf_;
    std::atomic<bool> has_early_data_{false};

    // v5.0.0: Session ticket cache（客户端侧，由 Endpoint 注入）
    std::shared_ptr<SessionCache> session_cache_;
    // v5.0.0: 0-RTT 重放保护 — 记录已处理的 0-RTT 数据 (stream_id, offset) 去重
    std::unordered_set<std::uint64_t> seen_0rtt_offsets_;
    std::mutex seen_0rtt_mu_;

    // v5.0.0: QAD 地址发现回调（客户端侧，收到 RESPONSE 时通知上层）
    QadAddressCallback qad_address_cb_;

    // v5.0.0: 最近接收到的对端公网地址（QAD 服务端侧反射用）
    // 由 Endpoint::handle_packet 派发数据包时通过 set_last_peer_addr 注入
    mutable std::mutex peer_addr_mu_;
    std::string last_peer_host_;
    std::uint16_t last_peer_port_{0};

    // v1.5.0.2 Step 3: 协商后的 MTU。默认 1280，握手完成后由 renegotiate_mtu() 设置。
    std::uint16_t negotiated_mtu_{1280};

    // v1.5.0.2 Step 4: 协商后的 CryptoLevel。默认 None，握手完成后由 negotiate_crypto_level() 设置。
    multimodal::CryptoLevel effective_crypto_level_{multimodal::CryptoLevel::None};

    Config cfg_;
    std::uint64_t id_;
    EndpointId peer_id_;
    std::atomic<ConnState> state_{ConnState::Initial};

    /// v4.6.0: 当前路径类型（用于 idle timeout 差异化），默认 Direct
    PathClass current_path_class_{PathClass::Direct};
    /// v4.6.0: 原始 idle_timeout 备份（set_path_class 覆盖前保存，回退 Direct 时恢复）
    std::chrono::milliseconds original_idle_timeout_{};

    std::uint64_t send_pn_[3] = {0, 0, 0};
    std::uint64_t recv_pn_[3] = {0, 0, 0};
    // B5 fix(2026-07-20): 用于 RFC 9000 §A.3 PN 解码的 largest_acked 和 largest_pn_seen。
    // 替代原 lockstep 假设（recv_pn_[2]++），支持丢包/重传/乱序场景。
    std::uint64_t largest_pn_seen_[3] = {0, 0, 0};
    // 当前正在处理的入站包的完整 PN（handle_packet 解码后存入，handle_1rtt_packet 读取）
    std::uint64_t current_incoming_pn_ = 0;
    // 已接收的 ApplicationData PN 集合（用于 build_ack_data 构建 ACK 帧）。
    // 替代原连续区间 [0, recv_pn_[2]) 假设，支持乱序/跳号。
    // 注：PoC 阶段用 vector，生产环境可优化为 interval set。
    std::vector<std::uint64_t> received_app_pns_;

    // ACK / 丢包检测 / 拥塞控制
    protocol::LossDetector loss_detector_;
    std::unique_ptr<protocol::CongestionController> congestion_ctrl_;
    // v1.5.0.1 P0-1: 重传子系统的互斥锁，保护以下字段的并发访问：
    //   - retransmit_queue_  （读 + 写 + erase）
    //   - sent_payloads_     （读 + insert + erase）
    //   - sent_payloads_bytes_（累加 + 减）
    //   - force_retx_        （set + clear）
    //   - retx_attempts_     （读 + 写 + erase）
    // LossDetector 内部 sent_packets_ 有自己的并发控制，retx 块读 sent_payloads_
    // 与 build_1rtt_packet 写 sent_payloads_ 通过本锁串行化。
    // v1.7.0.6 (H1-4 fix): 改为 mutable，使 const 方法 pending_retransmits() 可加锁
    mutable std::mutex retransmit_mu_;
    std::vector<std::uint64_t> retransmit_queue_;  // 需要重传的 PN 队列
    // v1.5.0.1 P0-1: 重传链路重建 — 缓存已发送包原始 plaintext，供 build_1rtt_packet
    // 末尾 retx 块使用。key = packet number，value = plaintext payload（未加密）。
    // 字节级封顶 128MB（与 P2-3 sent_packets_ 一致），超出时按 PN 升序驱逐最旧条目。
    std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> sent_payloads_;
    size_t sent_payloads_bytes_ = 0;
    static constexpr size_t kSentPayloadsBytesCap = 512ULL * 1024ULL * 1024ULL;  // 512 MiB (6-3: 128MB->512MB)
    // force_retx_ 标志：handle_ack_frame 检测到丢包时置 true，build_1rtt_packet
    // 检测到时即便 STREAM 队列为空也强制出一包 retx（避免依赖应用层立即发包）。
    bool force_retx_{false};
    // retx 重试计数（每个 PN 最多重传 max_retx_per_packet_ 次，超出从队列驱逐）
    // P9.3 §4.1: kMaxRetxPerPacket 由 static 50 改为非 static 成员，默认 20
    //   5% 丢包下 0.95^20 ≈ 0.36 失败率，可接受；Config 可调
    std::unordered_map<std::uint64_t, int> retx_attempts_;
    int max_retx_per_packet_ = 20;  // P9.3 §4.1: 原 static kMaxRetxPerPacket=50，降为 20

    /// P9.3 §4.2: per-PN retx 退避 — 记录每个 PN 上次重传时间（steady_clock ms）
    ///   build_1rtt_packet retx 块写入某 PN 前检查 now - retx_last_sent_ms_[pn] >= srtt_ms_，
    ///   避免同一 PN 一个 RTT 内多次重传（retx 风暴根因）
    ///   受 retransmit_mu_ 保护（与 retransmit_queue_/retx_attempts_ 同锁）
    std::unordered_map<std::uint64_t, double> retx_last_sent_ms_;
    // 6-3: 单次 build_1rtt_packet 最多写入的 retx 块数量
    // 分离 per-build 批量限制和 per-PN 生命周期限制
    // 6-3 retx 调优: 5->10, 16KB payload + 50/50 空间预留下, 10 个 PN retx 可写满
    static constexpr int kMaxRetxPerBuild = 10;
    double last_activity_ms_{0.0};                  // 最后活动时间
    double last_ping_sent_ms_{0.0};                 // 最后 PING 发送时间

    // ====================================================================
    // v1.5.0.5: 接收方反馈的 OOS buffer PN 远程缓存（方案 A+ 核心）
    // ====================================================================
    /// OOS_PN_FRAME 远程缓存：key=stream_id, value=该 stream 的 entries 列表。
    /// 接收 handle_oos_pn_frame 写入；handle_ack_frame 阶段 1 后读取并构造 OosPnInfo 注入 LossDetector。
    /// 单 stream 上限 kOosPnRemoteMaxEntriesPerStream（防恶意攻击或极端场景内存爆炸）。
    std::mutex oos_pn_remote_mu_;
    std::unordered_map<std::uint64_t, std::vector<OosRemoteEntry>> oos_pn_remote_;

    /// OOS_PN_FRAME 上行发送节拍（Q2 答复：100ms 周期）。
    /// v1.5.0.7 (ISSUE T06 反馈): 调整为 50ms，加快 OOS_PN 反馈频率，
    /// 避免 100ms 周期内 OOS buffer 累积过快（T05 场景 OOS buffer 峰值 887KB）。
    static constexpr double kOosPnSendIntervalMs = 50.0;
    /// oos_pn_remote_ 单 stream 缓存上限（视频模型组建议 256）。
    static constexpr std::size_t kOosPnRemoteMaxEntriesPerStream = 256;
    /// oos_pn_remote_ 全局有效期（Q3 答复：30s）。
    static constexpr double kOosPnRemoteTtlMs = 30000.0;

    /// 上次 OOS_PN_FRAME 发送时间（用于 build_1rtt_packet 节拍控制）。
    /// v1.5.0.7 (ISSUE T06 反馈): 仅在成功发送 OOS_PN 帧时更新，
    /// 避免"无 OOS gap 时也累加 last_oos_pn_send_ms_"导致节拍永久错过。
    /// 0.0 表示首次调用（应直接触发，绕过节拍阻挡）。
    double last_oos_pn_send_ms_{0.0};

    // v1.5.0.7 (ISSUE T06 反馈): OOS_PN 触发链路诊断计数器
    //   - v1.5.0.6 缺失这些埋点，视频模型组 T05 反馈"build_oos_pn_data_total=0 /
    //     OOS_PN_frame_total=0 / decode_OOS_PN_total=0"无法定位触发链断裂点
    //   - 全部为 private 字段，不影响 ABI 兼容
    std::uint64_t build_oos_pn_data_total_{0};       ///< build_oos_pn_data() 入口无条件 +1
    std::uint64_t OOS_PN_frame_total_{0};            ///< OOS_PN 帧成功写入 payload 时 +1
    std::uint64_t decode_OOS_PN_total_{0};           ///< handle_oos_pn_frame() 入口无条件 +1
    std::uint64_t OOS_PN_decode_total_{0};           ///< OOS_PN 帧 decode 成功时 +1
    std::uint64_t OOS_PN_decode_failed_total_{0};    ///< OOS_PN 帧 decode 失败时 +1

    // v1.5.0.10 (ISSUE T09 反馈): OOS_PN 帧全链路诊断计数器
    //   - 视频组 T09 实测：v1.5.0.9 master 端 OOS_PN_FRAME received=0
    //     无法定位是 A1（路由未注册）/A3（UDP 丢包）/A4（判定错）中的哪一个
    //   - oos_pn_frame_recv_total_  在 parse_frames case FrameType::OOS_PN 入口 +1
    //     （确认路由注册 → 排查 A1）
    //   - oos_pn_frame_decode_fail_total_ 在 handle_oos_pn_frame decode 失败 +1
    //     （确认编解码对称性 → 排查 A2）
    //   - oos_pn_frame_dropped_total_  在 parse_frames default 分支遇到 type=0x30 +1
    //     （确认静默丢弃 → 排查 A1/A2 退化路径）
    //   - oos_pn_frame_resent_total_   在 Step 2 启用，50ms 合并 + 500ms 重发机制 +1
    //     （确认 OOS_PN 帧重发机制触发 → 排查 A3 UDP 丢包）
    //   - 全部为 private 字段，ABI 向后兼容
    std::uint64_t oos_pn_frame_recv_total_{0};       ///< parse_frames 已分发到 handle_oos_pn_frame
    std::uint64_t oos_pn_frame_decode_fail_total_{0};///< decode_oos_pn_frame 失败（冗余 alias）
    std::uint64_t oos_pn_frame_dropped_total_{0};    ///< parse_frames default 分支丢弃 type=0x30
    std::uint64_t oos_pn_frame_resent_total_{0};     ///< Step 2: OOS_PN 帧重发计数（暂未启用）

    // v1.5.0.10 (ISSUE T09 反馈): OOS_PN 帧 UDP 可靠性机制
    //   根因：v1.5.0.9 OOS_PN 帧仅周期性 build（50ms 节拍）+ 写入 1-RTT 包发送，
    //         若该 1-RTT 包 UDP 丢包，对端永远收不到 OOS_PN 反馈，
    //         导致 oos_pn_remote_ 不更新，retx 永不触发（"T09 received=0"症状）。
    //   修复：维护最近一次发送的 OOS_PN 帧 + 发送时间，500ms 后若对端未确认（用
    //         oos_pn_frame_recv_total_ 在对端的递增作为隐式 ACK，因为 OOS_PN 帧是
    //         单向反馈无显式 ACK 帧），触发 1 次重发。
    //   简化设计：key=stream_id, value=(encoded_bytes, send_time_ms, resent_count)
    //     - 同一 stream_id 的新 OOS_PN 帧覆盖旧条目（避免队列膨胀）
    //     - 接收方每收到一帧 OOS_PN，删除对应 stream_id 条目（隐式确认）
    //     - 500ms 超时（kOosPnResendTimeoutMs）后 periodic tick 重发，最多 3 次
    //   不引入新协议帧（保持 wire format 稳定），仅依赖 oos_pn_frame_recv_total_ 计数器
    struct PendingOosPnFrame {
        std::uint64_t stream_id{0};
        /// v1.5.0.10: 完整带 type 字节的 OOS_PN 帧（type=0x30 + stream_id varint + ...）
        ///   - v1.5.0.6 修复后 encode_oos_pn_frame 不写 type 字节，由 build_1rtt_packet 显式追加
        ///   - 但 resend 路径走 pending_fc_frames_ 复用通道（P3-1 块 memcpy 整段），
        ///     不经过 build_1rtt_packet 的 OOS_PN 特殊处理，因此这里预先 prepend type 字节
        ///   - build_1rtt_packet 主路径仍走 build_oos_pn_data() 拿 body + 显式追加 type 字节
        std::vector<std::uint8_t> encoded;   ///< 完整帧（含 type 字节），可直接 memcpy 到 payload
        double send_time_ms{0.0};
        std::uint64_t resent_count{0};        ///< 已重发次数（限 3 次）
    };
    //   v1.5.0.10 (ISSUE T09): 500ms × 3 次（保守，5% 丢包覆盖）
    //   v1.5.0.11 (ISSUE T10 反馈 P1): **100ms × 8 次（激进）**
    //     - T10 业务实测 UDP 接收率仅 34%（66% 丢包），500ms × 3 不足
    //     - 100ms 超时：覆盖 95% 丢包场景，缩短 OOS gap 填补延迟
    //     - 8 次重发：给高丢包链路更多机会（首发 + 8 次重传 = 共 9 次到达机会）
    //     - 总覆盖时长 = 100ms × 8 = 800ms，配合 200ms 周期性节拍，符合工业实践
    //     - 与 high_priority 队列 + ACK-eliciting 标记配合，避免 cwnd 抑制雪崩
    /// v1.5.0.11: OOS_PN 帧重传超时 100ms（v1.5.0.10 为 500ms，T10 反馈 66% 丢包下不足）
    ///  - 100ms ≈ 1 个 RTT（局域网 1-5ms × 10-20 buffer，符合工业实践 10x RTT）
    ///  - 过短：触发雪崩重传；过长：增加 OOS gap 填补延迟
    ///  - 与 kOosPnSendIntervalMs=50ms 配套，2:1 比例（每节拍最多触发 1 次重传）
    // v1.5.0.11: kOosPnResendTimeoutMs/kOosPnMaxResendCount 已提升至 public 段
    //   （line 721-723），避免重复定义。
    /// pending_oos_pn_frames_ 互斥锁（heartbeat tick + build_oos_pn_data 并发安全）
    mutable std::mutex pending_oos_pn_mu_;
    /// 待确认 OOS_PN 帧队列（key=stream_id 单 stream，避免恶意/异常 stream 膨胀）
    std::unordered_map<std::uint64_t, PendingOosPnFrame> pending_oos_pn_frames_;
    /// 累计 OOS_PN 帧重发次数（oos_pn_frame_resent_total_ 别名，单独暴露便于测试）。
    ///  - 与 oos_pn_frame_resent_total_ 同步递增（保持 7 计数器语义清晰）
    ///  - 测试用 oos_pn_resend_total_ 访问器读此字段
    std::uint64_t oos_pn_resend_total_{0};

    // v1.5.0.11 (ISSUE T10 反馈 P1): high_priority 队列 + ACK-eliciting 标记
    //   - T10 业务实测 UDP 接收率仅 34%（66% 丢包），OOS_PN 帧被 cwnd 抑制雪崩
    //   - high_priority 队列：OOS_PN 帧作为关键控制帧，单独高优先级通道
    //     * 在 build_1rtt_packet 中优先于 retx 块 + pending_fc_frames_ 处理
    //     * 不计入 cwnd 抑制（cwnd_suppressed 触发时仍可发送）
    //   - ACK-eliciting 标记：OOS_PN 帧在 on_packet_sent 时标记 ack_eliciting=true
    //     * 确保对端每帧都发回 ACK 帧（1-RTT 包级别 ACK，而非隐式）
    //     * 与 v1.5.0.10 "按节拍强制重发 + 限次"叠加，形成显式 + 隐式双确认
    /// v1.5.0.11: OOS_PN 帧 high_priority 队列（绕过 cwnd 抑制）
    ///  - 在 build_1rtt_packet 中先于 retx 块 + pending_fc_frames_ 写入
    ///  - 单独统计 oos_pn_high_priority_sent_total_ 计数器
    ///  - 由 resend_oos_pn_if_needed() 填充
    /// v1.7.0.6 (C9 fix): 新增 pending_hp_mu_ 保护，解决数据竞争
    /// （resend_oos_pn_if_needed 在 heartbeat 线程 push_back，
    ///   build_1rtt_packet 在发送线程消费，之前无锁）
    std::vector<std::vector<std::uint8_t>> pending_oos_pn_high_priority_frames_;
    std::mutex pending_hp_mu_;
    /// v1.5.0.11: 累计 OOS_PN 帧 high_priority 发送次数（含首发 + 重发）
    ///  - 与 oos_pn_resend_total_ 区分：本计数器统计 high_priority 通道总发送数
    std::uint64_t oos_pn_high_priority_sent_total_{0};

    // v1.5.0.11 (ISSUE T10 反馈 P2): UDP 丢包分桶埋点
    //   - 派生自 oos_pn_frame_total_（构造）+ ack_oos_pn_frame 累计
    //   - 提供 sent / acked_implicit / loss_rate 三个 gauge 供测试 + 监控
    /// v1.5.0.11: 累计 ack_oos_pn_frame 调用次数（隐式确认总数）
    ///  - 由接收方每收到一帧 OOS_PN 帧 → 通知发送方 ack_oos_pn_frame 递增
    ///  - 与 oos_pn_high_priority_sent_total_ 配合计算 loss_rate
    std::uint64_t oos_pn_acked_implicit_total_{0};

    // v1.5.0.12 (ISSUE T11 反馈 P0): resend 节拍解耦 — 解耦 resend 触发与 build_oos_pn_data 节拍
    //   根因：build_oos_pn_data 每 50ms 重置 pof.send_time_ms = now，
    //         导致 resend_oos_pn_if_needed 中 now - send_time_ms < 100ms 永远成立，
    //         resend 永不触发，high_priority 队列始终为空。
    //   修复：resend 触发条件改为基于 last_resend_check_ms_ 节拍时间追踪，
    //         与 build_oos_pn_data 完全解耦。
    /// v1.5.0.12: 上次重传检查时间戳（由 resend_oos_pn_if_needed 维护，初值 0 触发首次检查）
    double last_resend_check_ms_{0.0};
    /// v1.5.0.12: resend_oos_pn_if_needed 被调用次数（1Hz heartbeat 调用）
    std::uint64_t resend_oos_pn_call_total_{0};
    /// v1.5.0.12: 因节拍未到被跳过的次数（now - last_resend_check_ms_ < kOosPnResendTimeoutMs）
    std::uint64_t resend_oos_pn_skipped_rhythm_total_{0};
    /// v1.5.0.12: 实际触发重发的次数（节拍满足且有超时条目）
    std::uint64_t resend_oos_pn_triggered_total_{0};

    /// 构建本端 OOS_PN_FRAME 字节流（用于 build_1rtt_packet 写入块）。
    /// 遍历所有 stream 的 oos_buffer_，取每个 stream 的首个 gap（first_gap_offset+first_seen_ms）。
    /// 当 last_oos_pn_send_ms_ 距 now < kOosPnSendIntervalMs 时跳过（节拍控制）。
    /// 返回：OOS_PN_FRAME 字节流（含 type 字节），空 vector 表示无需发送。
    std::vector<std::uint8_t> build_oos_pn_data();

public:  // v1.5.0.10: OOS_PN UDP 可靠性接口（heartbeat_loop 内部 + 测试验证都需要访问，
        //   提升到 public 不影响 ABI，向后兼容）
    /// v1.5.0.10 (ISSUE T09 反馈): 检查 pending_oos_pn_frames_ 中是否有超时未确认的
    /// OOS_PN 帧（发送后 500ms 仍未被对端 oos_pn_frame_recv_total_ 隐式确认），
    /// 若有且重发次数 < kOosPnMaxResendCount，则触发一次重发。
    /// 由 heartbeat_loop（1Hz 周期）调用。
    /// \return 重发的帧数（用于上层 log + oos_pn_resend_total_ 计数）
    std::size_t resend_oos_pn_if_needed();

    /// v1.5.0.10 (ISSUE T09 反馈): 接收方每收到一帧 OOS_PN 帧时调用，
    /// 删除 pending_oos_pn_frames_ 中对应 stream_id 条目（隐式确认）。
    /// 由 handle_oos_pn_frame decode 成功后调用。
    /// \param stream_id 已成功接收的 OOS_PN 帧所属 stream
    void ack_oos_pn_frame(std::uint64_t stream_id);

private:
    /// 清理 oos_pn_remote_ 中超过 kOosPnRemoteTtlMs 的 entries（handle_oos_pn_frame 入口调用）。
    void prune_oos_pn_remote_locked(double now_ms);

    // 流量控制
    protocol::FlowController flow_ctrl_;

    // 路径迁移 + CID 管理
    protocol::PathMigrationManager path_mgr_;

    // v1.7.0.1 P0: reholepunch 触发计数（用于诊断和测试）
    std::atomic<std::uint64_t> reholepunch_count_{0};

    // v4.7.0: PathEventStream fan-out 注册表
    //
    // path_events() 创建 stream 后，将 stream 的 weak_ptr<Impl> 加入此向量。
    // emit_path_event() 遍历此向量，lock 成功的 stream 推入事件，失败的 erase。
    // Connection 析构时遍历此向量 close 所有 stream（避免悬挂）。
    //
    // 互斥保护：path_event_streams_mu_（与 path_mgr_.mu_ 独立，避免锁嵌套）
    // 锁序：path_event_streams_mu_ 独立，不与 path_mgr_.mu_ 嵌套
    //       （emit_path_event 在 path_mgr_ 锁外调用，复用 H10 模式）
    std::vector<std::weak_ptr<PathEventStreamImpl>> path_event_streams_;
    mutable std::mutex path_event_streams_mu_;

    // v4.7.0: 当前主路径 ID（接入点 A 决策后更新，用于 emit_path_event 的 Selected 事件）
    // 由 try_select_better_path / 路径迁移成功回调更新
    std::atomic<std::uint64_t> current_primary_path_id_{0};

    // v4.8.0: PreferRelayStrategy 强制 relay 主路径标志
    //
    // 在 Connection 构造时，若 path_strategy 为 PreferRelayStrategy 则置 true。
    // 作用：
    //   1. on_handshake_completed 中立即调用 try_select_better_path 选择 relay 路径
    //   2. loss_tick_loop 中每 5s 定期调用 try_select_better_path，确保 relay 路径
    //      被持续选中（防止路径迁移后回退到 P2P 直连）
    //
    // 根因：try_select_better_path 之前未被定期调用，导致 PreferRelayStrategy 选择的
    //       relay 路径未生效，master 仍通过 P2P 直连发送 FORWARD 数据，引发公网 UDP 丢包。
    bool force_relay_primary_{false};

    // v4.8.0: loss_tick_loop 中上次调用 try_select_better_path 的时间戳（ms, steady_clock）
    // 用于限制定期调用频率为每 5s 一次（避免每轮 tick 都调用增加开销）
    double last_path_select_ms_{0.0};

    /// v4.7.0: 向所有订阅的 PathEventStream fan-out 一个事件
    ///
    /// 内部遍历 path_event_streams_，lock 成功的 stream 推入事件，失败的 erase。
    /// 调用方必须未持有 path_event_streams_mu_（避免回调反向调用导致死锁）。
    /// @note 此方法不依赖 path_mgr_.mu_，可在 path_mgr_ 锁外调用
    void emit_path_event(protocol::PathEvent ev);

    /// v4.7.0: 桥接 PathMigrationManager 的 closed 事件到 PathEventStream fan-out
    ///
    /// 在 Connection 构造时注册到 path_mgr_.set_path_event_callback，
    /// PathMigrationManager emit_path_closed_event 时转发到所有 stream。
    /// 回调内调用 emit_path_event（已离开 path_mgr_.mu_，安全）。
    void bridge_path_event_callback();

    // V3-B: 跨域连接统计原子成员（仅 is_cross_domain=true 时累加）
    // 与 stats_ 解耦，避免污染既有 ConnectionStats 序列化兼容性
    std::atomic<std::uint64_t> cross_domain_bytes_sent_{0};
    std::atomic<std::uint64_t> cross_domain_bytes_received_{0};
    std::atomic<std::uint32_t> cross_domain_rtt_ms_{0};

    // 握手进度跟踪
    HandshakeTracker handshake_tracker_;
    bool handshake_started_{false};
    bool ping_pending_{false};  // 需要发送 PING 保活帧

    // S1（v5.3）：控制帧捎带队列（SESSION_TICKET/QAD 等低频帧，
    // build_1rtt_packet 在 ACK 后消费；mutex 保护跨线程 queue/consume）
    std::deque<std::vector<std::uint8_t>> pending_ctrl_frames_;
    std::mutex ctrl_frames_mu_;

    // v1.5.0.1 P3-1: 1Hz 周期 MAX_DATA / MAX_STREAM_DATA 主动通告队列。
    // heartbeat_loop 每秒调用 emit_periodic_flow_control() 填充，
    // build_1rtt_packet 在 process_stream 之后、retx 块之前批量写出。
    // 用 FIFO 避免饥饿；MAX_DATA 帧排在最前，MAX_STREAM_DATA 帧按 stream_id 排序。
    // v1.7.0.6 (C9 fix): 新增 pending_fc_mu_ 保护，解决数据竞争
    // （emit_periodic_flow_control 在 heartbeat 线程 push_back，
    //   build_1rtt_packet 在发送线程消费，之前无锁）
    std::vector<std::vector<std::uint8_t>> pending_fc_frames_;
    std::mutex pending_fc_mu_;

    std::mutex stream_mu_;
    // P5 fix(2026-07-20): 用 unordered_map 替代 vector，按 stream_id 索引，
    // O(1) 查找替代 O(N) find_if 遍历。
    std::unordered_map<std::uint64_t, std::shared_ptr<Stream>> local_streams_;
    std::unordered_map<std::uint64_t, std::shared_ptr<Stream>> remote_streams_;
    std::uint64_t next_local_bidi_stream_{0};
    std::uint64_t next_local_uni_stream_{2};
    std::queue<std::shared_ptr<Stream>> pending_accept_;
    std::function<void(std::shared_ptr<Stream>)> on_stream_;
    std::function<void()> on_close_;
    std::function<void()> on_handshake_done_;  // 握手完成回调

    // ---- TLS 1.3 集成（mode-gated，仅 HandshakeConfig::mode==Tls13 时激活）----
    std::unique_ptr<tls::Handshake> hs_driver_;  // AKE 状态机（transport-agnostic）
    tls::TrafficKeys app_write_;                // 出站 1-RTT AEAD 密钥
    tls::TrafficKeys app_read_;                 // 入站 1-RTT AEAD 密钥
    bool hs_done_{false};                       // 应用密钥是否就绪
    std::vector<std::uint8_t> pending_flight_;  // 待 transport 发送的握手字节

    // ---- v5.1.0: PSK_IDENTITY（K-LINOH-PEERMISMATCH）----
    /// 待发身份帧标记（build_1rtt_packet 包尾附加后清除）
    bool psk_identity_pending_send_{false};
    /// 对端身份已通过 PSK_IDENTITY 验签（peer_id_ 可信判据）
    bool peer_authenticated_{false};

    // ---- P1-5: KeyUpdate 状态（RFC 9001 §6）----
    /// key_phase 位：0=初始密钥，1=第一代更新密钥，每次 KeyUpdate 翻转。
    /// 1-RTT 短包头中包含此位，接收方据此选择使用旧/新密钥解密。
    /// \note 当前实现简化：仅记录相位，AEAD 加密/解密仍用 app_write_/app_read_，
    ///       触发 KeyUpdate 时通过 rotate_keys() 派生新一代 key+iv 并替换。
    std::atomic<std::uint8_t> key_phase_{0};

    /// P1-5: 上一代 app_read_（KeyUpdate 切换期间暂存，用于处理对端
    /// 仍用旧密钥发送的 in-flight 包）。当前实现简化为单代，未实际使用。
    tls::TrafficKeys app_read_prev_;

    /// P1-5: 已发送包计数（用于触发主动 KeyUpdate）。
    /// 超过 KeySchedule::kKeyUpdatePacketThreshold 时应触发 rotate_keys()。
    std::atomic<std::uint64_t> packets_sent_since_rotate_{0};

    /// P1-5: 触发本端 KeyUpdate（派生新一代 write/read 密钥，翻转 key_phase）。
    /// 调用后本端发送的包使用新 key_phase + 新密钥；接收对端包时
    /// 若 key_phase 不匹配，需用旧密钥解密（保留 app_read_prev_）。
    /// \return true=成功派生新密钥；false=非 TLS1.3 模式或未握手完成
    bool rotate_keys();

    /// TLS 1.3 握手完成后：派生应用密钥、记录认证后的对端身份、进入 Established。
    void finalize_tls13();

    ConnectionStats stats_{};

    /// O1.2: 对端能力掩码（CapabilitiesAck 自动缓存/调用方显式设置）
    std::uint32_t peer_capabilities_{0};

    // ====================================================================
    // 应用层 RPC 状态（2026-07-19 新增）
    // ====================================================================
private:
    /// pending 请求条目：promise + 超时时间点 + 是否已取消
    struct PendingEntry {
        std::promise<std::vector<std::uint8_t>> promise;
        std::chrono::steady_clock::time_point deadline;
        std::atomic<bool> done{false};  // true=已完成（响应/取消），无需超时清理
    };

    mutable std::shared_mutex pending_mu_;  // P1-2: 读写锁，timeout_loop 用 read lock
    std::unordered_map<std::uint32_t, std::shared_ptr<PendingEntry>> pending_requests_;
    std::atomic<std::uint32_t> next_request_id_{1};

    /// 超时扫描线程（单一守护线程，定期检查 pending 是否超时）
    std::atomic<bool> timeout_thread_running_{false};
    std::thread timeout_thread_;
    std::condition_variable timeout_cv_;
    std::mutex timeout_mu_;
    std::atomic<bool> timeout_thread_stop_{false};

    /// 消息处理器（任一非空时 Connection 自动接管 on_stream_）
    std::function<void(const protocol::ApplicationMessage &)> request_handler_;
    std::function<void(const protocol::ApplicationMessage &)> notification_handler_;
    std::function<void(const protocol::ApplicationMessage &)> response_handler_;
    std::atomic<bool> rpc_enabled_{false};

    /// 用户原始 on_stream_ 处理器（启用 RPC 前保存，非 RPC stream 回退调用）
    std::function<void(std::shared_ptr<Stream>)> user_on_stream_;

    /// P0-5: RPC 半包缓冲 — 每个 stream 的未完成 ApplicationMessage 缓冲
    /// key=stream_id, value=累积的字节数据
    /// 当 stream 数据到达不完整时累积，直到能 parse 出完整消息
    std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> pending_rpc_buffers_;

    /// ====================================================================
    /// P1-1: RPC Stream 复用（2026-07-19 新增）
    ///
    /// 设计：每个 RPC 请求-响应对使用一条双向 stream，stream 在请求发送时
    /// 占用，响应到达后归还到空闲池供下次 call() 复用。stream **不发 FIN**，
    /// 保持可写。服务端收到 Request 后记录 request_id → stream 映射，
    /// respond() 通过该映射在同一条 stream 上回送 Response。
    ///
    /// 池上限 32（避免无限增长），超过则直接 close 多余 stream。
    /// ====================================================================

    mutable std::mutex rpc_stream_mu_;
    /// 空闲 stream 池（call() 取，响应到达时还）
    std::vector<std::shared_ptr<Stream>> rpc_stream_pool_;
    /// 客户端：request_id → 等待响应的 stream（响应到达时移除并归还到池）
    std::unordered_map<std::uint32_t, std::shared_ptr<Stream>> rpc_in_flight_;
    /// 服务端：request_id → 接收 Request 的 stream（respond 时取，respond 后移除）
    std::unordered_map<std::uint32_t, std::shared_ptr<Stream>> request_stream_map_;

    /// 启动超时扫描线程（懒启动，首次 call() 时触发）
    void ensure_timeout_thread();

    /// 超时扫描主循环
    void timeout_loop();

    /// 处理收到的应用层消息（匹配 pending 或调用 handler）
    void on_application_message(const protocol::ApplicationMessage &msg);

    /// RPC 模式下的 stream 处理器：读取 stream 数据 → parse → on_application_message
    void rpc_stream_handler(std::shared_ptr<Stream> stream);

    /// 清理所有 pending 请求（断线时调用）
    void fail_all_pending_locked(const std::string &reason);

    /// 在 close() 中调用，清理 RPC 状态
    void on_close_impl();

    // ====================================================================
    // P1-1: on_close_ 去重（2026-07-19 新增）
    // ====================================================================
private:
    /// on_close_ 是否已触发（全生命周期只触发一次）
    std::atomic<bool> on_close_triggered_{false};

    /// on_close_impl 是否已执行（幂等保护）
    std::atomic<bool> cleaned_up_{false};

    /// 统一触发入口：CAS 保证 on_close_ 仅调用一次
    void trigger_on_close_once();

    // ====================================================================
    // P1-2: 心跳同步机制（2026-07-19 新增）
    // ====================================================================
public:
    /// 启动心跳线程（Established 后调用）。interval_ms=PING 间隔，timeout_ms=PONG 超时阈值
    void start_heartbeat(std::uint32_t interval_ms = 10000,
                         std::uint32_t timeout_ms = 30000);

    /// 停止心跳线程（close/析构时自动调用）
    void stop_heartbeat();

    /// 注册心跳超时回调（连续 miss 触发，由上层决定是否 close）
    std::function<void()> on_heartbeat_timeout_;

    /// B8 fix(2026-07-20): 心跳需要发送 PING 时触发，由上层调用
    /// build_1rtt_packet + socket flush 将 PING 帧发出。
    /// 原 heartbeat_loop 开新 stream 发 RPC ping，既浪费资源又因无 flush 导致 PING 发不出。
    std::function<void()> on_ping_send_requested_;

private:
    std::atomic<bool> heartbeat_in_flight_{false};
    std::chrono::steady_clock::time_point last_pong_time_;
    std::thread heartbeat_thread_;
    std::atomic<bool> heartbeat_running_{false};
    std::atomic<std::uint32_t> heartbeat_miss_count_{0};
    std::mutex heartbeat_mu_;
    std::condition_variable heartbeat_cv_;
    std::atomic<bool> heartbeat_stop_{false};

    // ====================================================================
    // P9.3 §4.4: loss_tick_loop — RTO/PTO 超时检测 + OOS gap 兜底
    //
    // 根因修复：on_rto_timeout / on_pto_timeout / next_timeout_ms 方法存在但从未被调用，
    // 导致对端不回 ACK 时 in-flight 永不丢包，retransmit_queue 无限增长。
    // loss_tick_loop 线程定时检查 RTO/PTO 超时，驱动丢包声明和重传。
    // 同时追踪 OOS gap，30s 未填补则触发 on_unrecoverable_gap_ 回调。
    // ====================================================================
public:
    /// 启动丢包超时检测线程（Established 后调用，与 start_heartbeat 同生命周期）
    void start_loss_tick_loop();

    /// 停止丢包超时检测线程（close/析构时自动调用）
    void stop_loss_tick_loop();

    /// 注册 OOS gap 不可恢复回调（30s 未填补 gap 时触发，上层决定是否 close/重调度）
    std::function<void(uint64_t stream_id, uint64_t offset)> on_unrecoverable_gap_;

private:
    std::thread loss_tick_thread_;
    std::atomic<bool> loss_tick_running_{false};
    std::atomic<bool> loss_tick_stop_{false};
    std::mutex loss_tick_mu_;
    std::condition_variable loss_tick_cv_;

    /// OOS gap 超时阈值（30s），超过此时间未填补的 gap 触发 unrecoverable 回调
    static constexpr double kOosGapAbandonMs = 30000.0;

    /// OOS gap 追踪：key = stream_id * 1000000000 + offset，value = first_seen_ms
    std::unordered_map<uint64_t, double> oos_gap_first_seen_;
    std::mutex oos_gap_mu_;

    /// 丢包超时检测主循环（5ms tick）
    void loss_tick_loop();

    /// v3.3.0 突破1: RTT-based 跨域自动检测标志（仅检查一次，首次 SRTT > 50ms 时触发）
    bool cross_domain_auto_checked_{false};

    /// v3.3.0 突破4: 跨域稳定性参数是否已应用（幂等保护，避免重复覆盖）
    bool cross_domain_stability_applied_{false};

    /// v3.3.0 突破4: 应用跨域稳定性参数（idle_timeout / keepalive_interval 覆盖）
    ///
    /// 在跨域检测触发时调用（on_handshake_completed 的 is_cross_domain=true 路径，
    /// 或 handle_ack_frame 的 SRTT > 50ms 自动检测路径）。
    /// 用 cfg_.cross_domain_idle_timeout / cross_domain_keepalive_interval 覆盖
    /// cfg_.idle_timeout / keepalive_interval（值为 0 表示不覆盖）。
    /// 幂等：cross_domain_stability_applied_=true 后不再重复应用。
    void apply_cross_domain_stability_params();

    /// 心跳主循环
    void heartbeat_loop(std::uint32_t interval_ms, std::uint32_t timeout_ms);

    // ====================================================================
    // P4-D-1: Connection 类内部拆分（2026-07-20 新增）
    //
    // 将内部逻辑按职责委托给 3 个内部组件：
    //   - ConnectionState:  状态机 + TLS 1.3 + KeyUpdate
    //   - StreamManager:    流管理 + RPC stream 池
    //   - PacketBuilder:    包构建 + ACK + 加密
    //
    // 内部组件作为友元，直接访问 Connection 的私有成员。
    // 公共 API 保持不变，公共方法委托给内部组件。
    // ====================================================================
    friend class internal::ConnectionState;
    friend class internal::StreamManager;
    friend class internal::PacketBuilder;

    /// P4-D-1: 获取内部组件引用（用于内部实现委托）
    internal::ConnectionState &state_component() { return *state_component_; }
    internal::StreamManager &stream_component() { return *stream_component_; }
    internal::PacketBuilder &packet_component() { return *packet_component_; }

private:
    std::unique_ptr<internal::ConnectionState> state_component_;
    std::unique_ptr<internal::StreamManager> stream_component_;
    std::unique_ptr<internal::PacketBuilder> packet_component_;
};

} // namespace linoh::endpoint
