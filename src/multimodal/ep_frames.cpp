// ep_frames.cpp — EP 协议帧编解码实现（v1.6.0.1 / P0）
//
// 编码风格与 OOS_PN 帧一致：
//   - 1 字节 type 前缀
//   - 数值字段全部 QUIC VarInt
//   - payload 长度显式编码
//   - 解码时严格校验长度边界，超限返回 nullopt

#include "linoh/multimodal/ep_frames.hpp"

#include <cstring>

namespace linoh::multimodal::ep {

namespace {

/// 追加 VarInt 到 vector
void append_varint(std::vector<std::uint8_t> &out, std::uint64_t value) {
    auto encoded = util::varint_encode_vec(value);
    out.insert(out.end(), encoded.begin(), encoded.end());
}

/// 从 span 读取 VarInt，成功返回 value 并推进 offset；失败返回 false
bool read_varint(std::span<const std::uint8_t> data, std::size_t &offset, std::uint64_t &value) {
    if (offset >= data.size()) return false;
    auto sub = data.subspan(offset);
    auto result = util::varint_decode(sub);
    if (!result) return false;
    value = result->first;
    offset += result->second;
    return true;
}

/// 追加 payload（长度前缀 + 字节）
bool append_payload(std::vector<std::uint8_t> &out, const std::vector<std::uint8_t> &payload,
                    std::size_t max_len) {
    if (payload.size() > max_len) return false;
    append_varint(out, static_cast<std::uint64_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    return true;
}

/// 读取 payload（长度前缀 + 字节），校验 max_len
bool read_payload(std::span<const std::uint8_t> data, std::size_t &offset,
                  std::vector<std::uint8_t> &payload, std::size_t max_len) {
    std::uint64_t len = 0;
    if (!read_varint(data, offset, len)) return false;
    if (len > max_len) return false;
    if (offset + len > data.size()) return false;
    payload.assign(data.data() + offset, data.data() + offset + len);
    offset += static_cast<std::size_t>(len);
    return true;
}

}  // namespace

// ============================================================================
// EP_DISPATCH_FRAME 编解码
// ============================================================================

std::vector<std::uint8_t> encode_dispatch_frame(const EpDispatchFrame &frame) {
    std::vector<std::uint8_t> out;
    // 预留容量：type(1) + 头部(≤32) + payload + padding(≤64)
    out.reserve(1 + 32 + frame.payload.size() + frame.padding.size() + 8);

    // 1B type
    out.push_back(static_cast<std::uint8_t>(EpFrameType::DISPATCH));

    // VarInt 字段
    append_varint(out, frame.tensor_id);
    append_varint(out, frame.expert_id);
    append_varint(out, frame.token_cnt);

    // payload（长度前缀 + 字节）
    append_payload(out, frame.payload, EpDispatchFrame::kMaxPayloadLen);

    // padding（长度前缀 + 字节）
    append_payload(out, frame.padding, EpDispatchFrame::kMaxPaddingLen);

    return out;
}

std::optional<EpDispatchFrame> decode_dispatch_frame(std::span<const std::uint8_t> data) {
    if (data.empty() || data[0] != static_cast<std::uint8_t>(EpFrameType::DISPATCH)) {
        return std::nullopt;
    }

    EpDispatchFrame frame;
    std::size_t offset = 1;  // 跳过 type

    if (!read_varint(data, offset, frame.tensor_id)) return std::nullopt;
    if (!read_varint(data, offset, frame.expert_id)) return std::nullopt;
    if (!read_varint(data, offset, frame.token_cnt)) return std::nullopt;
    if (!read_payload(data, offset, frame.payload, EpDispatchFrame::kMaxPayloadLen)) {
        return std::nullopt;
    }
    if (!read_payload(data, offset, frame.padding, EpDispatchFrame::kMaxPaddingLen)) {
        return std::nullopt;
    }

    // 校验：解码后应消费所有字节（允许尾部 padding 已在 payload 中处理）
    // 这里不强制 offset == data.size()，因为 padding 长度可能为 0，允许尾部多余字节
    return frame;
}

// ============================================================================
// EP_COMBINE_FRAME 编解码
// ============================================================================

std::vector<std::uint8_t> encode_combine_frame(const EpCombineFrame &frame) {
    std::vector<std::uint8_t> out;
    out.reserve(1 + 32 + frame.payload.size());

    out.push_back(static_cast<std::uint8_t>(EpFrameType::COMBINE));

    append_varint(out, frame.tensor_id);
    append_varint(out, frame.expert_id);
    append_varint(out, frame.token_cnt);

    append_payload(out, frame.payload, EpCombineFrame::kMaxPayloadLen);

    return out;
}

std::optional<EpCombineFrame> decode_combine_frame(std::span<const std::uint8_t> data) {
    if (data.empty() || data[0] != static_cast<std::uint8_t>(EpFrameType::COMBINE)) {
        return std::nullopt;
    }

    EpCombineFrame frame;
    std::size_t offset = 1;

    if (!read_varint(data, offset, frame.tensor_id)) return std::nullopt;
    if (!read_varint(data, offset, frame.expert_id)) return std::nullopt;
    if (!read_varint(data, offset, frame.token_cnt)) return std::nullopt;
    if (!read_payload(data, offset, frame.payload, EpCombineFrame::kMaxPayloadLen)) {
        return std::nullopt;
    }

    return frame;
}

// ============================================================================
// EP_SYNC_FRAME 编解码
// ============================================================================

std::vector<std::uint8_t> encode_sync_frame(const EpSyncFrame &frame) {
    std::vector<std::uint8_t> out;
    out.reserve(1 + 32 + frame.payload.size());

    out.push_back(static_cast<std::uint8_t>(EpFrameType::SYNC));

    append_varint(out, frame.sync_id);

    // sync_op：1 字节定长（不使用 VarInt，便于接收端快速路由）
    out.push_back(static_cast<std::uint8_t>(frame.sync_op));

    // v2.2 Phase 3 (P3-A): algo 1 字节定长（CollectiveAlgo 枚举值）
    out.push_back(frame.algo);

    append_varint(out, frame.participant_mask);

    // mp-M2 (v1.7.0.8): reduce_op 1 字节定长（AllReduce 规约操作）
    out.push_back(frame.reduce_op);

    // v2.2 Phase 3 (P3-A): shard_idx + total_shards 各 2 字节 LE（大 chunk 分片）
    out.push_back(static_cast<std::uint8_t>(frame.shard_idx & 0xFF));
    out.push_back(static_cast<std::uint8_t>((frame.shard_idx >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(frame.total_shards & 0xFF));
    out.push_back(static_cast<std::uint8_t>((frame.total_shards >> 8) & 0xFF));

    append_payload(out, frame.payload, EpSyncFrame::kMaxPayloadLen);

    // v2.3 Phase 4 (P4-A): 条件性尾部字段
    // 仅当 from_node_id!=0 || step!=0 时追加，保证默认帧 wire format 字节级不变（向后兼容）
    if (frame.from_node_id != 0 || frame.step != 0) {
        append_varint(out, frame.from_node_id);
        out.push_back(static_cast<std::uint8_t>(frame.step & 0xFF));
        out.push_back(static_cast<std::uint8_t>((frame.step >> 8) & 0xFF));
    }

    return out;
}

std::optional<EpSyncFrame> decode_sync_frame(std::span<const std::uint8_t> data) {
    if (data.empty() || data[0] != static_cast<std::uint8_t>(EpFrameType::SYNC)) {
        return std::nullopt;
    }

    EpSyncFrame frame;
    std::size_t offset = 1;

    if (!read_varint(data, offset, frame.sync_id)) return std::nullopt;

    // sync_op：1 字节定长
    // v2.1 Phase 2: 扩展合法范围到 AllToAll=8（原 Release=4 + AllGather=5 + Broadcast=6 + ReduceScatter=7 + AllToAll=8）
    if (offset >= data.size()) return std::nullopt;
    std::uint8_t op = data[offset++];
    if (op > static_cast<std::uint8_t>(EpSyncOp::AllToAll)) {
        return std::nullopt;  // 未知 sync_op
    }
    frame.sync_op = static_cast<EpSyncOp>(op);

    // v2.2 Phase 3 (P3-A): algo 1 字节定长（CollectiveAlgo 枚举值）
    // 合法范围 0-3（Ring/Tree/RecursiveHalving/PairwiseExchange），其他值视为非法
    if (offset >= data.size()) return std::nullopt;
    std::uint8_t algo = data[offset++];
    if (algo > 3) {
        return std::nullopt;  // 未知 algo
    }
    frame.algo = algo;

    if (!read_varint(data, offset, frame.participant_mask)) return std::nullopt;

    // mp-M2 (v1.7.0.8): reduce_op 1 字节定长
    if (offset >= data.size()) return std::nullopt;
    frame.reduce_op = data[offset++];

    // v2.2 Phase 3 (P3-A): shard_idx + total_shards 各 2 字节 LE
    if (offset + 4 > data.size()) return std::nullopt;
    frame.shard_idx = static_cast<std::uint16_t>(data[offset])
                    | (static_cast<std::uint16_t>(data[offset + 1]) << 8);
    offset += 2;
    frame.total_shards = static_cast<std::uint16_t>(data[offset])
                       | (static_cast<std::uint16_t>(data[offset + 1]) << 8);
    offset += 2;
    // 校验：total_shards 必须大于 0，shard_idx 必须小于 total_shards
    if (frame.total_shards == 0 || frame.shard_idx >= frame.total_shards) {
        return std::nullopt;
    }

    if (!read_payload(data, offset, frame.payload, EpSyncFrame::kMaxPayloadLen)) {
        return std::nullopt;
    }

    // v2.3 Phase 4 (P4-A): 条件性尾部字段（向后兼容）
    // 旧帧/默认帧（from_node_id=0, step=0）无尾部字节 → offset==data.size() → 默认 0/0
    // 新帧（Ring 多步通信）有尾部 → 读取 from_node_id VarInt + step 2B LE
    if (offset < data.size()) {
        if (!read_varint(data, offset, frame.from_node_id)) return std::nullopt;
        if (offset + 2 > data.size()) return std::nullopt;  // step 字节不足，格式错误
        frame.step = static_cast<std::uint16_t>(data[offset])
                   | (static_cast<std::uint16_t>(data[offset + 1]) << 8);
        offset += 2;
    }

    return frame;
}

// ============================================================================
// EP_ACK_FRAME 编解码（v1.6.0.7 / P6）
// ============================================================================

std::vector<std::uint8_t> encode_ack_frame(const EpAckFrame &frame) {
    std::vector<std::uint8_t> out;
    out.reserve(kAckFrameMaxBytes);

    // 1B type
    out.push_back(static_cast<std::uint8_t>(EpFrameType::ACK));

    // VarInt frame_seq + VarInt tensor_id
    append_varint(out, frame.frame_seq);
    append_varint(out, frame.tensor_id);

    // 1B frame_type（被确认的帧类型，DISPATCH=0x20 / COMBINE=0x21）
    out.push_back(static_cast<std::uint8_t>(frame.frame_type));

    return out;
}

std::optional<EpAckFrame> decode_ack_frame(std::span<const std::uint8_t> data) {
    if (data.empty() || data[0] != static_cast<std::uint8_t>(EpFrameType::ACK)) {
        return std::nullopt;
    }

    EpAckFrame frame;
    std::size_t offset = 1;  // 跳过 type

    if (!read_varint(data, offset, frame.frame_seq)) return std::nullopt;
    if (!read_varint(data, offset, frame.tensor_id)) return std::nullopt;

    // 1B frame_type
    if (offset >= data.size()) return std::nullopt;
    std::uint8_t ft = data[offset++];
    // 仅允许 DISPATCH(0x20) / COMBINE(0x21)，其他值非法
    if (ft != static_cast<std::uint8_t>(EpFrameType::DISPATCH) &&
        ft != static_cast<std::uint8_t>(EpFrameType::COMBINE)) {
        return std::nullopt;
    }
    frame.frame_type = static_cast<EpFrameType>(ft);

    return frame;
}

// ============================================================================
// 辅助函数
// ============================================================================

std::optional<EpFrameType> peek_ep_frame_type(std::span<const std::uint8_t> data) noexcept {
    if (data.empty()) return std::nullopt;
    std::uint8_t t = data[0];
    switch (t) {
        case static_cast<std::uint8_t>(EpFrameType::DISPATCH):
            return EpFrameType::DISPATCH;
        case static_cast<std::uint8_t>(EpFrameType::COMBINE):
            return EpFrameType::COMBINE;
        case static_cast<std::uint8_t>(EpFrameType::SYNC):
            return EpFrameType::SYNC;
        case static_cast<std::uint8_t>(EpFrameType::ACK):
            return EpFrameType::ACK;
        default:
            return std::nullopt;
    }
}

const char *ep_frame_type_name(EpFrameType t) noexcept {
    switch (t) {
        case EpFrameType::DISPATCH: return "ep_dispatch";
        case EpFrameType::COMBINE:  return "ep_combine";
        case EpFrameType::SYNC:     return "ep_sync";
        case EpFrameType::ACK:      return "ep_ack";
    }
    return "unknown";
}

const char *ep_sync_op_name(EpSyncOp op) noexcept {
    switch (op) {
        case EpSyncOp::Barrier:       return "barrier";
        case EpSyncOp::Signal:        return "signal";
        case EpSyncOp::Ack:           return "ack";
        case EpSyncOp::AllReduce:     return "all_reduce";
        case EpSyncOp::Release:       return "release";
        case EpSyncOp::AllGather:     return "all_gather";
        case EpSyncOp::Broadcast:     return "broadcast";
        case EpSyncOp::ReduceScatter: return "reduce_scatter";
        case EpSyncOp::AllToAll:      return "all_to_all";
    }
    return "unknown";
}

// v2.2 Phase 3 (P3-A): CollectiveAlgo 枚举值转字符串
// 0=Ring 1=Tree 2=RecursiveHalving 3=PairwiseExchange
const char *ep_sync_algo_name(std::uint8_t algo) noexcept {
    switch (algo) {
        case 0: return "ring";
        case 1: return "tree";
        case 2: return "recursive_halving";
        case 3: return "pairwise_exchange";
    }
    return "unknown";
}

}  // namespace linoh::multimodal::ep
