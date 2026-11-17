#pragma once

/// @file flow_control.hpp
/// QUIC 流量控制帧编解码（RFC 9000 §4 + §19.4-19.9）。
///
/// 帧类型：
///   MAX_DATA            (0x10) — connection-level 流控窗口
///   MAX_STREAM_DATA     (0x11) — stream-level 流控窗口
///   MAX_STREAMS_BIDI    (0x12) — 最大双向并发流数
///   MAX_STREAMS_UNI     (0x13) — 最大单向并发流数
///   DATA_BLOCKED        (0x14) — connection-level 阻塞信号
///   STREAM_DATA_BLOCKED (0x15) — stream-level 阻塞信号
///   STREAMS_BLOCKED_BIDI(0x16) — 双向流数阻塞信号
///   STREAMS_BLOCKED_UNI (0x17) — 单向流数阻塞信号

#include "linoh/util/varint.hpp"

#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace linoh::protocol {

// ---------------------------------------------------------------------------
// Flow-control frame structures
// ---------------------------------------------------------------------------

/// MAX_DATA 帧 (RFC 9000 §19.4)。
/// 通知对端：本端允许的 connection-level 最大数据量。
struct MaxDataFrame {
    std::uint64_t maximum_data;  // VarInt — connection-level 窗口
};

/// MAX_STREAM_DATA 帧 (RFC 9000 §19.5)。
/// 通知对端：指定 stream 允许的最大数据 offset。
struct MaxStreamDataFrame {
    std::uint64_t stream_id;     // VarInt
    std::uint64_t maximum_stream_data;  // VarInt — stream-level 窗口
};

/// MAX_STREAMS 帧（双向/单向，RFC 9000 §19.6）。
/// 通知对端：允许的最大并发流数。
struct MaxStreamsFrame {
    std::uint64_t maximum_streams;  // VarInt
    bool bidirectional;  // true → type=0x12, false → type=0x13
};

/// DATA_BLOCKED 帧 (RFC 9000 §19.7)。
/// 通知对端：本端有数据要发，但被 connection-level 窗口限制。
struct DataBlockedFrame {
    std::uint64_t maximum_data;  // VarInt — 阻塞时的窗口值
};

/// STREAM_DATA_BLOCKED 帧 (RFC 9000 §19.8)。
/// 通知对端：本端有数据要发，但被 stream-level 窗口限制。
struct StreamDataBlockedFrame {
    std::uint64_t stream_id;     // VarInt
    std::uint64_t maximum_stream_data;  // VarInt — 阻塞时的窗口值
};

/// STREAMS_BLOCKED 帧（双向/单向，RFC 9000 §19.9）。
struct StreamsBlockedFrame {
    std::uint64_t maximum_streams;  // VarInt
    bool bidirectional;  // true → type=0x16, false → type=0x17
};

// ---------------------------------------------------------------------------
// Flow-control window manager
// ---------------------------------------------------------------------------

/// 管理 connection-level 和 stream-level 流控窗口。
class FlowController {
public:
    /// 默认初始窗口值（PP推理场景：connection = 16MB, stream = 4MB）。
    /// 原RFC 9000建议(1MB/256KB)不够传输hidden_state(282KB fp16 + FEC ≈ 565KB)。
    static constexpr std::uint64_t kDefaultConnWindow = 1 << 24;   // 16 MB
    static constexpr std::uint64_t kDefaultStreamWindow = 1 << 22; // 4 MB
    static constexpr std::uint64_t kDefaultMaxBidiStreams = 100;
    static constexpr std::uint64_t kDefaultMaxUniStreams = 100;

    explicit FlowController(
        std::uint64_t initial_conn_window = kDefaultConnWindow,
        std::uint64_t initial_stream_window = kDefaultStreamWindow,
        std::uint64_t max_bidi_streams = kDefaultMaxBidiStreams,
        std::uint64_t max_uni_streams = kDefaultMaxUniStreams);

    // --- Connection-level window management --- //
    // v1.7.0.7 H4 注：以下 8 个 inline 单字段读取方法（remote_conn_window /
    //   conn_bytes_sent / local_conn_window / conn_bytes_recv / *_max_*_streams）
    //   保持 inline 不加锁。理由：
    //   1. x86_64 上 aligned uint64_t 单指令读取是原子的，无 torn read 风险
    //   2. 这些方法主要用于诊断/日志，弱一致性（stale 值）可接受
    //   3. 实际发送/stream 创建决策走已加锁的复杂方法（conn_send_capacity /
    //      stream_send_capacity / can_open_bidi_stream / can_open_uni_stream）
    //   4. 加锁开销可能超过单字段读取本身，得不偿失
    //   严格一致性需求的调用方应使用已加锁的复杂方法，而非组合多个 inline 读取。

    /// 对端允许本端发送的最大 connection-level offset。
    std::uint64_t remote_conn_window() const { return remote_conn_window_; }

    /// 本端已发送的 connection-level offset（所有 stream send_offset 的总和）。
    std::uint64_t conn_bytes_sent() const { return conn_bytes_sent_; }

    /// 本端还能发送多少字节（connection-level）。
    std::uint64_t conn_send_capacity() const;

    /// 记录本端发送了 n 字节（更新 conn_bytes_sent_）。
    void on_conn_bytes_sent(std::uint64_t n);

    /// 对端通告新的 connection-level 窗口（MAX_DATA 帧）。
    void on_remote_max_data(std::uint64_t new_window);

    /// 本端通告给对端的 connection-level 窗口。
    std::uint64_t local_conn_window() const { return local_conn_window_; }

    /// 本端已接收的 connection-level offset（所有 stream recv_offset 的总和）。
    std::uint64_t conn_bytes_recv() const { return conn_bytes_recv_; }

    /// 记录本端接收了 n 字节（更新 conn_bytes_recv_）。
    void on_conn_bytes_recv(std::uint64_t n);

    /// 检查是否需要发送 MAX_DATA 帧（当已消费超过窗口的 1/2 时）。
    bool should_send_max_data() const;

    /// 计算下一个 MAX_DATA 值（自动扩展窗口）。
    std::uint64_t next_max_data_value() const;

    // --- Stream-level window management --- //

    /// 对端允许本端在指定 stream 上发送的最大 offset。
    std::uint64_t remote_stream_window(std::uint64_t stream_id) const;

    /// 设置对端通告的 stream-level 窗口（MAX_STREAM_DATA 帧）。
    void on_remote_max_stream_data(std::uint64_t stream_id, std::uint64_t new_window);

    /// v5.4 F4（借鉴 ScaleFabric credit 预约式无损流控）：保障指定流的接收授权
    /// 窗口至少为 at_least 字节（对端 STREAM_DATA_BLOCKED 声明需求后调用——
    /// "建立时预约"的软件层等价：把运行时窗口挤占风险转为声明即保障）。
    void grant_stream_window(std::uint64_t stream_id, std::uint64_t at_least);

    /// 计算指定 stream 的剩余发送容量。
    std::uint64_t stream_send_capacity(std::uint64_t stream_id,
                                        std::uint64_t stream_send_offset) const;

    /// 本端通告给指定 stream 的接收窗口。
    std::uint64_t local_stream_window(std::uint64_t stream_id) const;

    /// 记录在指定 stream 上接收了 n 字节。
    void on_stream_bytes_recv(std::uint64_t stream_id, std::uint64_t n);

    /// 检查是否需要为指定 stream 发送 MAX_STREAM_DATA 帧。
    bool should_send_max_stream_data(std::uint64_t stream_id) const;

    /// 计算下一个 MAX_STREAM_DATA 值。
    std::uint64_t next_max_stream_data_value(std::uint64_t stream_id) const;

    /// v1.5.0.1 P3-1: 返回所有已知 local-stream 窗口的 stream_id 列表（用于 1Hz 周期扫描）。
    /// 调用方：Connection::emit_periodic_flow_control()。
    /// 拷贝返回避免锁竞争；数据流控窗口在 emit 期间被新到达的 on_stream_bytes_recv 增量更新。
    std::vector<std::uint64_t> local_stream_ids() const;

    /// v1.5.0.1 P3-1: 标记 conn-level 窗口已通告，避免下次 emit 重复发。
    /// 由 emit_periodic_flow_control 在 encode 完 MAX_DATA 帧后调用。
    void mark_max_data_advertised(std::uint64_t advertised_value);

    /// mp-L7 (v1.7.0.8): 标记 stream-level 窗口已通告。
    ///   由调用方在 encode 完 MAX_STREAM_DATA 帧后调用，记录 last_advertised 值。
    ///   与 mark_max_data_advertised 同模式，分离"计算值"与"标记已通告"职责。
    ///   注意：必须调用此方法才能使 should_send_max_stream_data 的去重生效，
    ///   否则每次周期任务都会因 (next_value - 0) >= threshold 恒返回 true。
    void mark_stream_data_advertised(std::uint64_t stream_id, std::uint64_t advertised_value);

    // --- Stream count management --- //

    /// 对端允许本端打开的最大双向流数。
    std::uint64_t remote_max_bidi_streams() const { return remote_max_bidi_streams_; }
    /// 对端允许本端打开的最大单向流数。
    std::uint64_t remote_max_uni_streams() const { return remote_max_uni_streams_; }

    /// 本端通告给对端的最大双向流数。
    std::uint64_t local_max_bidi_streams() const { return local_max_bidi_streams_; }
    /// 本端通告给对端的最大单向流数。
    std::uint64_t local_max_uni_streams() const { return local_max_uni_streams_; }

    /// 对端通告新的最大双向流数。
    void on_remote_max_bidi_streams(std::uint64_t n);
    /// 对端通告新的最大单向流数。
    void on_remote_max_uni_streams(std::uint64_t n);

    /// 检查本端是否还能打开新的双向流。
    bool can_open_bidi_stream(std::uint64_t current_count) const;
    /// 检查本端是否还能打开新的单向流。
    bool can_open_uni_stream(std::uint64_t current_count) const;

private:
    // v1.7.0.7 H4: 全类互斥锁，保护所有成员变量（含 STL 容器）。
    //   - FlowController 被 Connection 的发送线程、接收线程、流控 emit 线程并发访问
    //   - v1.7.0.6 之前完全无锁，remote_stream_windows_ / local_stream_windows_ 遍历
    //     与 push_back 竞争会导致迭代器失效 / UAF
    //   - mutable 使 const 访问器（conn_send_capacity / local_stream_window 等）可加锁
    mutable std::mutex mu_;

    // v1.7.0.7 H4: _locked_ 内部方法（调用方已持 mu_），避免 public 方法间相互调用
    //   导致递归加锁死锁（参考 v1.7.0.6 H5-3 EpSession _locked_ 模式）
    //   - conn_send_capacity_locked_() — on_conn_bytes_sent / stream_send_capacity 调用
    //   - remote_stream_window_locked_() — stream_send_capacity 调用
    //   - local_stream_window_locked_() — next_max_stream_data_value 调用
    std::uint64_t conn_send_capacity_locked_() const;
    std::uint64_t remote_stream_window_locked_(std::uint64_t stream_id) const;
    std::uint64_t local_stream_window_locked_(std::uint64_t stream_id) const;

    // Connection-level window: 本端视角
    std::uint64_t local_conn_window_;     // 本端通告给对端的 conn 窗口
    std::uint64_t conn_bytes_recv_;       // 本端已接收的 conn 数据量
    std::uint64_t last_advertised_max_data_ = 0;  // v1.5.0.1 P3-1: 上一次通告的 conn 窗口（用于 1Hz 周期变化检测）

    // Connection-level window: 对端视角
    std::uint64_t remote_conn_window_;    // 对端通告给本端的 conn 窗口
    std::uint64_t conn_bytes_sent_;       // 本端已发送的 conn 数据量

    // Per-stream remote windows: stream_id → maximum_stream_data
    // mp-P4 (v1.7.0.8): vector<pair> 线性查找 O(N) → unordered_map O(1)
    //   原 vector 每次 remote_stream_window_locked_ / on_remote_max_stream_data
    //   都线性扫描，stream 数多时（如多模态并行 16+ stream）成为热路径瓶颈。
    std::unordered_map<std::uint64_t, std::uint64_t> remote_stream_windows_;

    // Per-stream local windows: stream_id → recv_bytes (已接收字节数)
    // mp-P4 (v1.7.0.8): 同上，vector → unordered_map
    std::unordered_map<std::uint64_t, std::uint64_t> local_stream_windows_;

    // mp-L7 (v1.7.0.8): per-stream last advertised tracking
    //   原 should_send_max_stream_data 恒返回 true，导致每次周期任务都为每个 stream
    //   构造并发送 MAX_STREAM_DATA 帧，即使窗口未推进也发，浪费带宽 + 帧配额。
    //   现记录每 stream 上次通告的 max 值，仅在 (recv - last_advertised) > threshold
    //   时返回 true，避免无意义的重复通告。
    // mp-P4 (v1.7.0.8): vector<pair> → unordered_map O(1) 查找
    std::unordered_map<std::uint64_t, std::uint64_t> last_advertised_stream_data_;

    // Stream count limits
    std::uint64_t local_max_bidi_streams_;
    std::uint64_t local_max_uni_streams_;
    std::uint64_t remote_max_bidi_streams_;
    std::uint64_t remote_max_uni_streams_;
};

// ---------------------------------------------------------------------------
// Frame encoding / decoding functions
// ---------------------------------------------------------------------------

/// 编码 MAX_DATA 帧。
std::vector<std::uint8_t> encode_max_data(const MaxDataFrame &frame);

/// 解码 MAX_DATA 帧（payload 是去掉 type 字节的剩余数据）。
std::optional<MaxDataFrame> decode_max_data(std::span<const std::uint8_t> payload);

/// 编码 MAX_STREAM_DATA 帧。
std::vector<std::uint8_t> encode_max_stream_data(const MaxStreamDataFrame &frame);

/// 解码 MAX_STREAM_DATA 帧。
std::optional<MaxStreamDataFrame> decode_max_stream_data(std::span<const std::uint8_t> payload);

/// 编码 MAX_STREAMS 帧。
std::vector<std::uint8_t> encode_max_streams(const MaxStreamsFrame &frame);

/// 解码 MAX_STREAMS 帧。
std::optional<MaxStreamsFrame> decode_max_streams(std::uint8_t frame_type,
                                                   std::span<const std::uint8_t> payload);

/// 编码 DATA_BLOCKED 帧。
std::vector<std::uint8_t> encode_data_blocked(const DataBlockedFrame &frame);

/// 解码 DATA_BLOCKED 帧。
std::optional<DataBlockedFrame> decode_data_blocked(std::span<const std::uint8_t> payload);

/// 编码 STREAM_DATA_BLOCKED 帧。
std::vector<std::uint8_t> encode_stream_data_blocked(const StreamDataBlockedFrame &frame);

/// 解码 STREAM_DATA_BLOCKED 帧。
std::optional<StreamDataBlockedFrame> decode_stream_data_blocked(std::span<const std::uint8_t> payload);

/// 编码 STREAMS_BLOCKED 帧。
std::vector<std::uint8_t> encode_streams_blocked(const StreamsBlockedFrame &frame);

/// 解码 STREAMS_BLOCKED 帧。
std::optional<StreamsBlockedFrame> decode_streams_blocked(std::uint8_t frame_type,
                                                           std::span<const std::uint8_t> payload);

} // namespace linoh::protocol
