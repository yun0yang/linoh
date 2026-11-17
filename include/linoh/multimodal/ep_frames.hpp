// ep_frames.hpp — EP（Expert Parallelism）协议帧定义（v1.6.0.1 / P0）
//
// 借鉴 MoonEP 静态形状 + 零拷贝思想：
//   - 帧格式固定长度头部 + VarInt 变长字段，便于接收端预分配 buffer
//   - tensor_id 全局唯一，支持分片重组（复用 v1.5.x TensorStreamer 机制）
//   - payload 直接承载 token embedding 字节流，零中间拷贝
//
// 三类帧：
//   EP_DISPATCH_FRAME (0x20) — EP-master → EP-worker，分发 token 到目标专家
//   EP_COMBINE_FRAME  (0x21) — EP-worker → EP-master，聚合专家计算结果
//   EP_SYNC_FRAME     (0x22) — 双向，跨节点同步原语（barrier/signal/ack/all-reduce/release）
//
// 编码风格与 OOS_PN 帧一致：
//   - 1 字节 type 前缀（由 encode 函数追加，接收端 decode 时校验）
//   - 数值字段全部使用 QUIC VarInt（RFC 9000 §16）编码
//   - payload 长度显式编码，便于解码时校验 buffer 边界
//
// 与 packet.hpp FrameType 的关系：
//   EP 帧走独立 ALPN 通道（ep-dispatch/1 等），不与 QUIC 标准帧混包；
//   type 字节 0x20-0x22 落在 FrameType 枚举空闲区段（0x20-0x2f），
//   后续若需在 PacketBuilder 中复用，可在 packet.hpp 补充枚举值。

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "linoh/util/varint.hpp"

namespace linoh::multimodal::ep {

/// EP 帧类型常量（type 字节）
/// 注意：与 packet.hpp FrameType 占用空间不冲突（QUIC 标准帧 ≤ 0x1e，OOS_PN=0x30）
enum class EpFrameType : std::uint8_t {
    DISPATCH = 0x20,  // EP_DISPATCH_FRAME
    COMBINE  = 0x21,  // EP_COMBINE_FRAME
    SYNC     = 0x22,  // EP_SYNC_FRAME
    ACK      = 0x23,  // EP_ACK_FRAME (v1.6.0.7 / P6): 接收方 -> 发送方确认
};

/// EP 同步操作类型（EP_SYNC_FRAME.sync_op 字段）
enum class EpSyncOp : std::uint8_t {
    Barrier       = 0,  // 屏障：所有 participant 到齐后统一释放
    Signal        = 1,  // 单向信号：EP-worker 完成计算后通知 EP-master
    Ack           = 2,  // 确认：对 signal 的应答
    AllReduce     = 3,  // 全规约：跨 participant 聚合标量（如 loss）
    Release       = 4,  // 释放：EP-master 广播解除阻塞
    // v2.1 Phase 2: 集合通信原语
    AllGather     = 5,  // 全收集：跨 participant 收集所有 chunk 并拼接
    Broadcast     = 6,  // 广播：root 节点数据分发到所有 participant
    ReduceScatter = 7,  // 规约分散：跨 participant 规约后按 chunk 分散结果
    AllToAll      = 8,  // 全交换：每个节点向其他节点发送不同数据（EP token 路由）
};

/// EP_DISPATCH_FRAME 数据结构
/// 帧格式（type=0x20 由 encode 追加）：
///   tensor_id      (VarInt) — tensor 全局唯一 ID，用于分片重组
///   expert_id      (VarInt) — 目标专家 ID
///   token_cnt      (VarInt) — 本帧携带的 token 数
///   payload_len   (VarInt) — payload 字节数（≤ kMaxPayloadLen）
///   payload        (payload_len 字节) — token embedding 字节流
///   padding_len    (VarInt) — padding 字节数（对齐到 64B 边界，0 表示无 padding）
///   padding        (padding_len 字节) — 0x00 填充
struct EpDispatchFrame {
    std::uint64_t tensor_id{0};
    std::uint64_t expert_id{0};
    std::uint64_t token_cnt{0};
    std::vector<std::uint8_t> payload;
    std::vector<std::uint8_t> padding;  // 对齐填充（可选）

    static constexpr std::size_t kMaxPayloadLen = 16 * 1024 * 1024;  // 16 MiB
    static constexpr std::size_t kMaxPaddingLen = 64;                // 64B 对齐
};

/// EP_COMBINE_FRAME 数据结构
/// 帧格式（type=0x21 由 encode 追加）：
///   tensor_id      (VarInt)
///   expert_id      (VarInt)
///   token_cnt      (VarInt)
///   payload_len    (VarInt)
///   payload        (payload_len 字节) — 专家输出结果字节流
struct EpCombineFrame {
    std::uint64_t tensor_id{0};
    std::uint64_t expert_id{0};
    std::uint64_t token_cnt{0};
    std::vector<std::uint8_t> payload;

    static constexpr std::size_t kMaxPayloadLen = 16 * 1024 * 1024;
};

/// EP_SYNC_FRAME 数据结构
/// 帧格式（type=0x22 由 encode 追加）：
///   sync_id          (VarInt) — 同步会话 ID
///   sync_op          (1 字节) — EpSyncOp 枚举值
///   algo             (1 字节) — v2.2 Phase 3 (P3-A): CollectiveAlgo 枚举值
///                                  0=Ring 1=Tree 2=RecursiveHalving 3=PairwiseExchange
///                                  （sync_op==AllReduce/AllGather/Broadcast/ReduceScatter/AllToAll 时有意义，
///                                   其他 sync_op 置 0 兼容）。P2 帧无此字段，解码时由 P2 节点
///                                   视为 0=Ring（与 P2 默认行为一致）。
///   participant_mask (VarInt) — 参与节点位图（bit i = 节点 i 是否参与）
///   reduce_op        (1 字节) — mp-M2 (v1.7.0.8): AllReduce 规约操作
///                                  0=SUM 1=MAX 2=MIN 3=AVG（仅 sync_op==AllReduce 时有意义，
///                                  其他 sync_op 置 0 兼容）。原实现被动会话硬编码 SUM，
///                                  发起方用 MAX/MIN 时被动方按 SUM 处理导致结果错误。
///   shard_idx        (2 字节 LE) — v2.2 Phase 3 (P3-A): 大 chunk 分片序号（0-indexed）
///                                  单 chunk 场景为 0，分片传输时标识当前分片序号。
///   total_shards     (2 字节 LE) — v2.2 Phase 3 (P3-A): 总分片数
///                                  单 chunk 场景为 1，分片传输时标识总分片数。
///   payload_len      (VarInt) — payload 字节数（AllReduce 时携带标量）
///   payload          (payload_len 字节)
///   ── v2.3 Phase 4 (P4-A): 条件性尾部字段（仅 from_node_id!=0 || step!=0 时追加）──
///   from_node_id     (VarInt) — 发送方 bit position（多 EpChannel 来源识别）。
///                                  默认 0 时不写入 wire，向后兼容 v2/v1 帧。
///   step             (2 字节 LE) — 集合通信步数（0..2N-3 Ring / 0..⌈log₂N⌉-1 Tree/PE）。
///                                  接收方按 step 对齐状态机。默认 0 时不写入 wire。
struct EpSyncFrame {
    std::uint64_t sync_id{0};
    EpSyncOp sync_op{EpSyncOp::Barrier};
    std::uint8_t algo{0};  // v2.2 Phase 3 (P3-A): CollectiveAlgo 枚举值（默认 0=Ring）
    std::uint64_t participant_mask{0};
    std::uint8_t reduce_op{0};  // mp-M2 (v1.7.0.8): AllReduce 规约操作
    std::uint16_t shard_idx{0};     // v2.2 Phase 3 (P3-A): 大 chunk 分片序号
    std::uint16_t total_shards{1};  // v2.2 Phase 3 (P3-A): 总分片数（默认 1=单 chunk）
    std::vector<std::uint8_t> payload;
    // v2.3 Phase 4 (P4-A): 条件性尾部字段（默认 0，不写入 wire，字节级向后兼容）
    std::uint64_t from_node_id{0};  // 发送方 bit position（多 EpChannel 来源识别）
    std::uint16_t step{0};          // 集合通信步数（状态机对齐）

    // v2.2 Phase 3 (P3-A): payload 上限扩到 4GB（支持大 chunk 分片重组）
    // 注：单帧 payload 仍受 MTU 限制，大 chunk 通过 shard_idx/total_shards 分片传输
    static constexpr std::size_t kMaxPayloadLen = 4ULL * 1024 * 1024 * 1024;  // 4 GiB
};

/// EP_ACK_FRAME 数据结构（v1.6.0.7 / P6）
/// 帧格式（type=0x23 由 encode 追加）：
///   frame_seq   (VarInt) — 被确认的帧序列号（发送方分配，全局递增）
///   tensor_id   (VarInt) — 业务关联（便于发送方定位）
///   frame_type  (1 字节) — 被确认的帧类型（DISPATCH=0x20 / COMBINE=0x21）
struct EpAckFrame {
    std::uint64_t frame_seq{0};
    std::uint64_t tensor_id{0};
    EpFrameType frame_type{EpFrameType::DISPATCH};
};

// ============================================================================
// 编码函数：返回包含 1B type 前缀的完整字节序列
// ============================================================================

/// 编码 EP_DISPATCH_FRAME（含 1B type=0x20 前缀）
std::vector<std::uint8_t> encode_dispatch_frame(const EpDispatchFrame &frame);

/// 编码 EP_COMBINE_FRAME（含 1B type=0x21 前缀）
std::vector<std::uint8_t> encode_combine_frame(const EpCombineFrame &frame);

/// 编码 EP_SYNC_FRAME（含 1B type=0x22 前缀）
std::vector<std::uint8_t> encode_sync_frame(const EpSyncFrame &frame);

/// 编码 EP_ACK_FRAME（含 1B type=0x23 前缀）（v1.6.0.7 / P6）
std::vector<std::uint8_t> encode_ack_frame(const EpAckFrame &frame);

// ============================================================================
// 解码函数：data 必须以 type 字节开头；返回 nullopt 表示格式错误或超限
// ============================================================================

/// 解码 EP_DISPATCH_FRAME
std::optional<EpDispatchFrame> decode_dispatch_frame(std::span<const std::uint8_t> data);

/// 解码 EP_COMBINE_FRAME
std::optional<EpCombineFrame> decode_combine_frame(std::span<const std::uint8_t> data);

/// 解码 EP_SYNC_FRAME
std::optional<EpSyncFrame> decode_sync_frame(std::span<const std::uint8_t> data);

/// 解码 EP_ACK_FRAME（v1.6.0.7 / P6）
std::optional<EpAckFrame> decode_ack_frame(std::span<const std::uint8_t> data);

// ============================================================================
// 辅助：帧类型识别（接收端路由用）
// ============================================================================

/// 从字节序列首字节识别 EP 帧类型（不消费数据）
/// 返回 nullopt 表示首字节不是 EP 帧类型
std::optional<EpFrameType> peek_ep_frame_type(std::span<const std::uint8_t> data) noexcept;

/// EP 帧类型转字符串（用于日志）
const char *ep_frame_type_name(EpFrameType t) noexcept;

/// EP 同步操作转字符串
const char *ep_sync_op_name(EpSyncOp op) noexcept;

/// v2.2 Phase 3 (P3-A): EP 同步算法转字符串（CollectiveAlgo 枚举值）
/// 0=ring 1=tree 2=recursive_halving 3=pairwise_exchange 其他=unknown
const char *ep_sync_algo_name(std::uint8_t algo) noexcept;

// ============================================================================
// 容量预估（用于 build_1rtt_packet 容量预估）
// ============================================================================

/// 单个 EP_DISPATCH_FRAME 编码后的最大字节数
///   type(1) + tensor_id(8) + expert_id(8) + token_cnt(8) +
///   payload_len(4) + payload(kMaxPayloadLen) +
///   padding_len(1) + padding(kMaxPaddingLen)
static constexpr std::size_t kDispatchFrameMaxBytes =
    1 + 8 + 8 + 8 + 4 + EpDispatchFrame::kMaxPayloadLen + 1 + EpDispatchFrame::kMaxPaddingLen;

/// 单个 EP_COMBINE_FRAME 编码后的最大字节数
static constexpr std::size_t kCombineFrameMaxBytes =
    1 + 8 + 8 + 8 + 4 + EpCombineFrame::kMaxPayloadLen;

/// 单个 EP_SYNC_FRAME 编码后的最大字节数
/// v2.2 Phase 3 (P3-A): +1B algo + 2B shard_idx + 2B total_shards
/// v2.3 Phase 4 (P4-A): +8B from_node_id VarInt(最大) + 2B step（条件性尾部字段）
/// 注：kMaxPayloadLen 已扩到 4GB，但实际单帧 payload 受 MTU 限制（典型 1280-9000B）
/// 此常量仅用于容量预估上限，build_1rtt_packet 实际容量由 MTU 决定
static constexpr std::size_t kSyncFrameMaxBytes =
    1 + 8 + 1 + 1 + 8 + 1 + 2 + 2 + 4 + EpSyncFrame::kMaxPayloadLen + 8 + 2;

/// 单个 EP_ACK_FRAME 编码后的最大字节数（v1.6.0.7 / P6）
///   type(1) + frame_seq(8) + tensor_id(8) + frame_type(1)
static constexpr std::size_t kAckFrameMaxBytes = 1 + 8 + 8 + 1;

}  // namespace linoh::multimodal::ep
