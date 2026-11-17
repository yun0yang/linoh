#include "linoh/protocol/packet.hpp"
#include "linoh/protocol/ack.hpp"

#include "linoh/util/logging.hpp"

#include <algorithm>
#include <cstring>
#include <random>

namespace linoh::protocol {

// ============================================================================
// ConnectionId
// ============================================================================

ConnectionId::ConnectionId(std::span<const std::uint8_t> data) {
    if (data.size() > kMaxSize) return;
    len_ = static_cast<std::size_t>(data.size());
    std::memcpy(bytes_.data(), data.data(), len_);
}

ConnectionId ConnectionId::generate() {
    // Use std::random_device directly as CSPRNG (avoids mt19937 which is not cryptographically secure).
    // On Windows this calls BCryptGenRandom; on Linux it reads /dev/urandom.
    std::random_device rd;

    ConnectionId cid;
    cid.len_ = kDefaultSize;
    for (std::size_t i = 0; i < cid.len_; ++i) {
        cid.bytes_[i] = static_cast<std::uint8_t>(rd() & 0xFF);
    }
    return cid;
}

std::array<std::uint8_t, ConnectionId::kMaxSize> ConnectionId::to_array() const {
    std::array<std::uint8_t, kMaxSize> arr{};
    std::memcpy(arr.data(), bytes_.data(), len_);
    return arr;
}

std::string ConnectionId::fmt_hex() const {
    static const char *kHex = "0123456789abcdef";
    std::string s;
    s.reserve(len_ * 2);
    for (std::size_t i = 0; i < len_; ++i) {
        s.push_back(kHex[bytes_[i] >> 4]);
        s.push_back(kHex[bytes_[i] & 0xF]);
    }
    return s;
}

std::string ConnectionId::fmt_short() const {
    std::string h = fmt_hex();
    if (h.size() <= 8) return h;
    return h.substr(0, 4) + ".." + h.substr(h.size() - 4);
}

// ============================================================================
// PacketHeader
// ============================================================================

PacketHeader PacketHeader::make_0rtt(ConnectionId dcid, PnLen pn_len) {
    PacketHeader h;
    h.type_ = PacketType::ZeroRtt;
    h.dcid_ = dcid;
    h.pn_len_ = pn_len;
    return h;
}

PacketHeader PacketHeader::make_1rtt(ConnectionId dcid, PnLen pn_len) {
    PacketHeader h;
    h.type_ = PacketType::OneRtt;
    h.dcid_ = dcid;
    h.pn_len_ = pn_len;
    return h;
}

PacketHeader PacketHeader::make_initial(ConnectionId dcid, ConnectionId scid,
                                       std::uint32_t version, PnLen pn_len) {
    PacketHeader h;
    h.type_ = PacketType::Initial;
    h.version_ = version;
    h.dcid_ = dcid;
    h.scid_ = scid;
    h.pn_len_ = pn_len;
    return h;
}

PacketHeader PacketHeader::make_handshake(ConnectionId dcid, ConnectionId scid, PnLen pn_len) {
    PacketHeader h;
    h.type_ = PacketType::Handshake;
    h.dcid_ = dcid;
    h.scid_ = scid;
    h.pn_len_ = pn_len;
    return h;
}

PacketHeader PacketHeader::make_retry(ConnectionId dcid, ConnectionId odcid,
                                     std::span<const std::uint8_t> token) {
    PacketHeader h;
    h.type_ = PacketType::Retry;
    h.dcid_ = dcid;
    h.token_.assign(token.begin(), token.end());
    h.pn_len_ = PnLen::Len2;
    return h;
}

std::size_t PacketHeader::encoded_size() const {
    if (type_ == PacketType::OneRtt) {
        return 1 + dcid_.len() + static_cast<std::uint8_t>(pn_len_) + 1;
    }
    // Long header
    std::size_t n = 1 + 4                          // type + version
                  + 1 + dcid_.len()               // dcil + dcid
                  + 1 + scid_.len();              // scil + scid
    // Token: Initial 和 Retry 都有 token 字段
    if (type_ == PacketType::Initial || (type_ == PacketType::Retry && !token_.empty())) {
        n += 1 + token_.size();                    // token len + token
    }
    // pn_len 字段(1 字节) + pn 实际数据(pn_len_ + 1 字节)
    n += 1 + (static_cast<std::uint8_t>(pn_len_) + 1);
    return n;
}

std::size_t PacketHeader::serialize_to(std::uint8_t *out, std::size_t max_len) const {
    std::size_t pos = 0;
    // v1.7.0.7 H1: write lambda 增加边界检查，避免 pos+n > max_len 时越界写
    auto write = [&](const void *src, std::size_t n) {
        if (pos + n > max_len) {
            // 缓冲区不足，截断写入（调用方应通过 encoded_size 预分配足够空间）
            n = (pos < max_len) ? (max_len - pos) : 0;
            if (n == 0) return;
        }
        std::memcpy(out + pos, src, n);
        pos += n;
    };

    if (type_ == PacketType::OneRtt) {
        // Short Header: self-describing format
        std::uint8_t dcil = static_cast<std::uint8_t>(dcid_.len() & 0x0F);
        std::uint8_t h = 0x40 | (static_cast<std::uint8_t>(pn_len_) << 4) | dcil;
        write(&h, 1);
        if (dcid_.len() > 0) {
            write(dcid_.data().data(), dcid_.len());
        }
        // pn
        std::size_t pn_bytes = static_cast<std::size_t>(static_cast<std::uint8_t>(pn_len_) + 1);
        if (pos + pn_bytes > max_len) return pos;  // 边界检查
        for (std::size_t i = 0; i < pn_bytes; ++i) {
            out[pos++] = 0;
        }
        return pos;
    }

    // Long Header
    std::uint8_t type_byte = static_cast<std::uint8_t>(type_) | 0x80;
    write(&type_byte, 1);

    // Version: 写入网络字节序（大端），保持与 parse_from 一致
    std::uint32_t ver = version_;
    std::uint8_t ver_bytes[4];
    ver_bytes[0] = static_cast<std::uint8_t>((ver >> 24) & 0xFF);
    ver_bytes[1] = static_cast<std::uint8_t>((ver >> 16) & 0xFF);
    ver_bytes[2] = static_cast<std::uint8_t>((ver >> 8) & 0xFF);
    ver_bytes[3] = static_cast<std::uint8_t>(ver & 0xFF);
    write(ver_bytes, 4);

    std::uint8_t dcil = static_cast<std::uint8_t>(dcid_.len());
    write(&dcil, 1);
    write(dcid_.data().data(), dcid_.len());

    std::uint8_t scil = static_cast<std::uint8_t>(scid_.len());
    write(&scil, 1);
    write(scid_.data().data(), scid_.len());

    // Token: Initial 和 Retry 都有 token 字段
    if (type_ == PacketType::Initial || (type_ == PacketType::Retry && !token_.empty())) {
        std::uint8_t tl = static_cast<std::uint8_t>(token_.size());
        write(&tl, 1);
        write(token_.data(), token_.size());
    }

    // pn_len (encoded as 0, 1, 2, 3 for 1, 2, 3, 4 bytes)
    std::uint8_t pn_enc = static_cast<std::uint8_t>(pn_len_);
    write(&pn_enc, 1);
    std::size_t pn_bytes = static_cast<std::size_t>(pn_enc) + 1;
    if (pos + pn_bytes > max_len) return pos;  // 边界检查
    for (std::size_t i = 0; i < pn_bytes; ++i) {
        out[pos++] = 0;
    }
    return pos;
}

std::optional<std::pair<PacketHeader, std::size_t>>
PacketHeader::parse_from(std::span<const std::uint8_t> data) {
    if (data.size() < 5) return std::nullopt;

    PacketHeader h;
    std::size_t pos = 0;

    std::uint8_t first = data[pos++];
    bool is_long = (first & 0x80) != 0;

    if (is_long) {
        std::uint8_t type_byte = first & 0x7F;
        if (type_byte > 3) type_byte = 0; // 未知类型 → Initial
        h.type_ = static_cast<PacketType>(type_byte);

        if (data.size() < pos + 4) return std::nullopt;
        h.version_ = (static_cast<std::uint32_t>(data[pos]) << 24) |
                     (static_cast<std::uint32_t>(data[pos+1]) << 16) |
                     (static_cast<std::uint32_t>(data[pos+2]) << 8) |
                     static_cast<std::uint32_t>(data[pos+3]);
        pos += 4;

        if (data.size() < pos + 1) return std::nullopt;
        std::uint8_t dcil = data[pos++];
        if (dcil > ConnectionId::kMaxSize || data.size() < pos + dcil) return std::nullopt;
        h.dcid_ = ConnectionId(data.subspan(pos, dcil));
        pos += dcil;

        if (data.size() < pos + 1) return std::nullopt;
        std::uint8_t scil = data[pos++];
        if (scil > ConnectionId::kMaxSize || data.size() < pos + scil) return std::nullopt;
        h.scid_ = ConnectionId(data.subspan(pos, scil));
        pos += scil;

        // Token (Initial only, for Retry)
        if (h.type_ == PacketType::Retry || h.type_ == PacketType::Initial) {
            if (data.size() > pos) {
                std::uint8_t tl = data[pos++];
                if (tl > 0 && data.size() >= pos + tl) {
                    h.token_.assign(data.begin() + pos, data.begin() + pos + tl);
                    pos += tl;
                }
            }
        }

        if (data.size() < pos + 1) return std::nullopt;
        h.pn_len_ = static_cast<PnLen>(data[pos++] & 0x03);
    } else {
        // Short Header: 1-RTT
        // byte 0: 0x40 | (pn_len << 4) | dcid_len
        h.type_ = PacketType::OneRtt;
        h.pn_len_ = static_cast<PnLen>((first >> 4) & 0x03);
        std::uint8_t dcil = first & 0x0F;
        if (data.size() < pos + dcil) return std::nullopt;
        if (dcil > 0) {
            h.dcid_ = ConnectionId(data.subspan(pos, dcil));
        }
        pos += dcil;
    }

    // pn_len bytes are part of the header but belong to payload area
    return std::make_pair(h, pos);
}

// ============================================================================
// PacketNumber
// ============================================================================

std::uint8_t PacketNumber::encoded_len() const {
    // QUIC 编码：基于包编号范围（RFC 9000）
    if (value < 1 << 8)  return 1;
    if (value < 1 << 16) return 2;
    if (value < 1 << 24) return 3;
    return 4;
}

std::array<std::uint8_t, 4> PacketNumber::encode_bytes(std::uint64_t value,
                                                      std::uint8_t trunc_len) {
    std::array<std::uint8_t, 4> arr{};
    for (int i = static_cast<int>(trunc_len) - 1; i >= 0; --i) {
        arr[i] = static_cast<std::uint8_t>(value & 0xFF);
        value >>= 8;
    }
    return arr;
}

std::uint64_t PacketNumber::decode_truncated(
    std::span<const std::uint8_t> bytes,
    std::uint64_t largest_acked,
    std::uint64_t /*max_val*/) {
    // RFC 9000 Appendix A.4: Sample Packet Number Decoding Algorithm
    //
    // 输入：
    //   bytes         = 截断的 packet_number 字节（1-4 字节）
    //   largest_acked = 同一 packet number space 中已确认的最大 PN
    //
    // 算法：
    //   expected_pn = largest_acked + 1
    //   pn_win = 1 << (pn_numbits * 8)
    //   pn_hwin = pn_win / 2
    //   pn_mask = pn_win - 1
    //   candidate_pn = (expected_pn & ~pn_mask) | (truncated_pn & pn_mask)
    //   if candidate_pn <= expected_pn - pn_hwin:
    //       candidate_pn += pn_win
    //   elif candidate_pn > expected_pn + pn_hwin and candidate_pn > pn_win:
    //       candidate_pn -= pn_win
    //   return candidate_pn

    if (bytes.empty()) return 0;

    // 1. 解析截断的 PN（大端字节）
    std::uint64_t truncated_pn = 0;
    for (std::uint8_t b : bytes) {
        truncated_pn = (truncated_pn << 8) | b;
    }

    // 2. 计算窗口参数
    std::uint64_t pn_numbits = bytes.size();  // 1/2/3/4 字节
    std::uint64_t pn_win     = std::uint64_t{1} << (pn_numbits * 8);
    std::uint64_t pn_hwin    = pn_win / 2;
    std::uint64_t pn_mask    = pn_win - 1;

    // 3. 计算 expected_pn = largest_acked + 1
    //    若 largest_acked == 0 表示尚未收到 ACK，expected_pn = 0
    std::uint64_t expected_pn = (largest_acked == 0) ? 0 : largest_acked + 1;

    // 4. 候选 PN = (expected_pn & ~pn_mask) | (truncated_pn & pn_mask)
    std::uint64_t candidate_pn = (expected_pn & ~pn_mask) | (truncated_pn & pn_mask);

    // 5. 边界环绕调整（RFC 9000 Appendix A.4）
    //    注意：expected_pn - pn_hwin 在无符号下会下溢，需先检查 expected_pn >= pn_hwin
    if (expected_pn >= pn_hwin && candidate_pn <= expected_pn - pn_hwin) {
        // 候选值过小，可能是窗口环绕到下一个周期
        // 仅当不溢出时加 pn_win
        if (candidate_pn + pn_win > candidate_pn) {  // 防溢出
            candidate_pn += pn_win;
        }
    } else if (candidate_pn > expected_pn + pn_hwin && candidate_pn > pn_win) {
        // 候选值过大，可能是窗口环绕到上一个周期
        candidate_pn -= pn_win;
    }

    return candidate_pn;
}

// ============================================================================
// PacketBuilder
// ============================================================================

void PacketBuilder::add_frame(std::uint8_t frame_type, std::span<const std::uint8_t> data) {
    if (offset_ + 1 + data.size() > out_.size()) return;
    out_[offset_++] = frame_type;
    if (!data.empty()) {
        std::memcpy(out_.data() + offset_, data.data(), data.size());
        offset_ += data.size();
    }
}

std::size_t PacketBuilder::build() {
    // 序列化 header 到 buffer 开头
    auto hdr_bytes = header_.encoded_size();
    std::size_t written = header_.serialize_to(out_.data(), hdr_bytes);

    // PN starts right after header.
    // 边界检查：written 必须 >= pn_len+1，否则 size_t 下溢成巨大值导致越界写。
    const std::size_t pn_field_len = static_cast<std::uint8_t>(header_.pn_len()) + 1;
    if (written < pn_field_len || written > out_.size()) {
        return 0;  // 序列化异常，返回 0 表示失败
    }
    std::size_t pn_offset = written - pn_field_len;
    auto enc = pn_.encode_bytes(pn_.value, static_cast<std::uint8_t>(pn_field_len));
    std::memcpy(out_.data() + pn_offset, enc.data(), pn_field_len);

    // payload already written after pn bytes.
    // 边界检查：written + offset_ 必须 >= pn_field_len + hdr_bytes，否则下溢。
    std::size_t total = written + offset_;
    std::size_t overhead = pn_field_len + hdr_bytes;
    if (total < overhead) {
        return 0;
    }
    return total - overhead;
}

// ============================================================================
// PacketParser
// ============================================================================

std::optional<PacketHeader> PacketParser::peek_header() const {
    if (wire_.size() < 5) return std::nullopt;
    auto result = PacketHeader::parse_from(wire_);
    if (!result) return std::nullopt;
    return result->first;
}

std::optional<Packet> PacketParser::parse() {
    auto result = PacketHeader::parse_from(wire_);
    if (!result) return std::nullopt;

    auto &[h, payload_start] = *result;

    std::size_t pn_len_bytes = static_cast<std::uint8_t>(h.pn_len()) + 1;
    if (wire_.size() < payload_start + pn_len_bytes) return std::nullopt;

    // Extract packet number
    std::array<std::uint8_t, 4> pn_bytes{};
    std::memcpy(pn_bytes.data(),
                wire_.data() + payload_start,
                std::min<std::size_t>(pn_len_bytes, 4));

    PacketNumber pn;
    pn.space = (h.type() == PacketType::Initial)   ? PacketNumber::Space::Initial
             : (h.type() == PacketType::Handshake) ? PacketNumber::Space::Handshake
                                                   : PacketNumber::Space::ApplicationData;

    // B5 fix(2026-07-20): 保留截断 PN 原始字节，供 Connection 层用
    // PacketNumber::decode_truncated() 还原完整 PN（RFC 9000 §A.3）。
    // 原 Simplified 实现直接用截断值作为完整 PN，丢包/乱序时 AEAD 解密失败。
    pn.value = 0;
    for (std::size_t i = 0; i < pn_len_bytes; ++i) {
        pn.value = (pn.value << 8) | pn_bytes[i];
    }

    // Payload starts after pn_len bytes - 允许空 payload（例如只有 header 的握手包）
    std::size_t payload_offset = payload_start + pn_len_bytes;

    Packet pkt;
    pkt.header = h;
    // B5: 保存截断 PN 字节和长度
    pkt.truncated_pn = pn_bytes;
    pkt.pn_len_bytes = static_cast<std::uint8_t>(pn_len_bytes);
    if (payload_offset < wire_.size()) {
        pkt.payload = util::Bytes(wire_.subspan(payload_offset));
    } else {
        pkt.payload = util::Bytes(); // empty payload
    }
    return pkt;
}

std::vector<Frame> PacketParser::parse_frames(std::span<const std::uint8_t> payload) {
    std::vector<Frame> frames;
    std::size_t pos = 0;

    while (pos < payload.size()) {
        std::uint8_t ft = payload[pos++];
        Frame f;
        f.type = static_cast<FrameType>(ft);

        // 根据 frame type 读取 data
        switch (ft) {
            case 0x00: // PADDING
                // padding = rest of packet, done
                return frames;
            case 0x02: case 0x03: { // ACK / ACK_ECN
                // 必须精确计算 ACK 帧长度并推进 pos，否则后续帧（如 STREAM）会被
                // 错误并入本帧的 f.data 而永远无法解析。decode_ack_frame 要求 data[0]
                // 为 type 字节，故用 type_pos 重建"含 type 字节"的完整帧视图。
                std::size_t type_pos = pos - 1;  // 当前 pos 已跳过 type 字节
                std::span<const std::uint8_t> full_frame(
                    payload.data() + type_pos, payload.size() - type_pos);
                auto ack = decode_ack_frame(full_frame);
                if (ack) {
                    // 重新编码求得完整帧长（含 type 字节），用其推进 pos。
                    std::size_t frame_len = encode_ack_frame(*ack).size();
                    f.data.assign(payload.begin() + type_pos,
                                  payload.begin() + type_pos + frame_len);
                    pos = type_pos + frame_len;
                } else {
                    f.data.assign(payload.begin() + type_pos, payload.end());
                    pos = payload.size();
                }
                break;
            }
            case 0x06: // PING
                break;
            // Flow-control frames: entire remaining payload → f.data
            // Connection handler will use VarInt-based decoding
            case 0x10: // MAX_DATA
            case 0x14: // DATA_BLOCKED
            case 0x12: case 0x13: // MAX_STREAMS_BIDI / MAX_STREAMS_UNI
            case 0x16: case 0x17: // STREAMS_BLOCKED_BIDI / STREAMS_BLOCKED_UNI
            case 0x19: // RETIRE_CONNECTION_ID
                f.data.assign(payload.begin() + pos, payload.end());
                pos = payload.size();
                break;
            // Multi-VarInt flow-control frames
            case 0x11: // MAX_STREAM_DATA (stream_id + max_stream_data)
            case 0x15: // STREAM_DATA_BLOCKED (stream_id + max_stream_data)
                f.data.assign(payload.begin() + pos, payload.end());
                pos = payload.size();
                break;
            // Path migration frames
            case 0x1a: // PATH_CHALLENGE (8 bytes)
                if (pos + 8 <= payload.size()) {
                    f.data.assign(payload.begin() + pos, payload.begin() + pos + 8);
                    pos += 8;
                } else {
                    return frames;  // malformed
                }
                break;
            case 0x1b: // PATH_RESPONSE (8 bytes)
                if (pos + 8 <= payload.size()) {
                    f.data.assign(payload.begin() + pos, payload.begin() + pos + 8);
                    pos += 8;
                } else {
                    return frames;  // malformed
                }
                break;
            case 0x18: { // NEW_CONNECTION_ID (VarInt + VarInt + 1B + CID + 16B token)
                f.data.assign(payload.begin() + pos, payload.end());
                pos = payload.size();
                break;
            }
            case 0x08: case 0x09: case 0x0a: case 0x0b:
            case 0x0c: case 0x0d: case 0x0e: case 0x0f: { // STREAM frame
                // RFC 9000 §19.8:
                // type byte flags: b0=OFF, b1=LEN, b2=FIN
                // format: Stream ID (VarInt) [Offset (VarInt)] [Length (VarInt)] Data
                //
                // 修复（P0-3）：正确解析 STREAM 帧字段并推进 pos，
                // 使后续帧（如 PADDING/HANDSHAKE_DONE 等）能被正确解析。
                // f.data 仍包含 stream_id + offset + length + data，供 Connection 层二次解析。

                std::size_t frame_start = pos - 1;  // type byte 位置
                std::size_t p = pos;

                // stream_id (VarInt) — 必有
                if (p >= payload.size()) {
                    // malformed: stream_id 缺失
                    return frames;
                }
                auto vi = util::varint_decode(payload.subspan(p));
                if (!vi) return frames;
                p += vi->second;

                // offset (VarInt) — if OFF bit set
                bool has_offset = (ft & 0x01) != 0;
                if (has_offset && p < payload.size()) {
                    vi = util::varint_decode(payload.subspan(p));
                    if (!vi) return frames;
                    p += vi->second;
                }

                // length (VarInt) — if LEN bit set
                bool has_len = (ft & 0x02) != 0;
                uint64_t data_len = 0;
                if (has_len && p < payload.size()) {
                    vi = util::varint_decode(payload.subspan(p));
                    if (!vi) return frames;
                    data_len = vi->first;
                    p += vi->second;
                } else {
                    // 无 LEN bit：data 占满剩余包
                    data_len = payload.size() - p;
                }

                // 检查 data_len 不越界
                if (p + data_len > payload.size()) {
                    // malformed
                    return frames;
                }
                p += static_cast<std::size_t>(data_len);

                // f.data 包含 type 字节之后的所有字段（stream_id + offset + length + data）
                // Connection 层会从 f.data 重新解析这些字段
                f.data.assign(payload.begin() + pos, payload.begin() + p);
                pos = p;
                break;
            }
            case 0x1c: case 0x1d: { // CONNECTION_CLOSE / APPLICATION_CLOSE
                // RFC 9000 §19.19:
                //   type(1) + error_code(VarInt) + frame_type(VarInt, 仅 0x1c)
                //   + reason_length(VarInt) + reason(reason_length bytes)
                // 修复（P0-4）：正确解析字段并推进 pos

                std::size_t p = pos;

                // error_code (VarInt)
                if (p >= payload.size()) return frames;
                auto vi = util::varint_decode(payload.subspan(p));
                if (!vi) return frames;
                p += vi->second;

                // frame_type (VarInt) — 仅 type=0x1c (CONNECTION_CLOSE)
                if (ft == 0x1c && p < payload.size()) {
                    vi = util::varint_decode(payload.subspan(p));
                    if (!vi) return frames;
                    p += vi->second;
                }

                // reason_length (VarInt) + reason
                if (p < payload.size()) {
                    vi = util::varint_decode(payload.subspan(p));
                    if (!vi) return frames;
                    p += vi->second;
                    uint64_t reason_len = vi->first;
                    if (p + reason_len > payload.size()) {
                        // malformed reason
                        return frames;
                    }
                    p += static_cast<std::size_t>(reason_len);
                }

                // f.data 包含 type 字节之后的所有字段（error_code + frame_type + reason_length + reason）
                f.data.assign(payload.begin() + pos, payload.begin() + p);
                pos = p;
                break;
            }
            case 0x1e: // HANDSHAKE_DONE
                break;
            case 0x30: { // v1.5.0.5: OOS_PN_FRAME
                // 帧格式（OOS_PN 帧内不含 type 字节，因 parse_frames 已吞下 type）：
                //   Stream ID        (VarInt)
                //   OOS PN Count     (VarInt, max 256)
                //   For each entry:
                //     Offset         (VarInt)
                //     First Seen Ms  (VarInt, 单位 0.1ms)
                //
                // OOS_PN_FRAME 结构简单（嵌套 VarInt 序列），无需类似 STREAM 帧的长度字段，
                // 因此直接将剩余 payload 全部赋予 f.data，由 Connection::handle_oos_pn_frame
                // 调用 decode_oos_pn_frame 解析。
                f.data.assign(payload.begin() + pos, payload.end());
                pos = payload.size();
                break;
            }
            case 0x31: { // v5.0.0: SESSION_TICKET — 服务端下发 session ticket
                // 与 OOS_PN 风格一致：不含 type 字节，剩余 payload 全部赋予 f.data
                f.data.assign(payload.begin() + pos, payload.end());
                pos = payload.size();
                break;
            }
            case 0x32: { // v5.0.0: ZERO_RTT_DATA — 握手前早期数据
                f.data.assign(payload.begin() + pos, payload.end());
                pos = payload.size();
                break;
            }
            case 0x33: { // v5.0.0: ADDRESS_DISCOVERY — QAD 请求
                f.data.assign(payload.begin() + pos, payload.end());
                pos = payload.size();
                break;
            }
            case 0x34: { // v5.0.0: ADDRESS_DISCOVERY_RESPONSE — QAD 响应
                f.data.assign(payload.begin() + pos, payload.end());
                pos = payload.size();
                break;
            }
            case 0x35: { // v5.1.0: PSK_IDENTITY — PSK 模式节点身份交换
                // rest-of-payload 风格；发送方必须将其作为包内最后一个帧
                f.data.assign(payload.begin() + pos, payload.end());
                pos = payload.size();
                break;
            }
            default:
                // Unknown frame type: skip it
                break;
        }
        frames.push_back(std::move(f));
    }
    return frames;
}

// ============================================================================
// v1.5.0.5: OOS_PN_FRAME encode/decode
// ============================================================================

// v1.5.0.5: first_seen_ms 编码为 0.1ms 单位 VarInt（限幅 0~6.5e6 ≈ 650 秒）。
// 真实使用中 entry 通常 < 10s（kTimeThreshold * SRTT 量级），650s 上限足够覆盖 30s oos_pn_remote 有效期。
static constexpr double kOosFirstSeenMsScale = 10.0;
static constexpr std::uint64_t kOosFirstSeenMsMaxRaw = 6500000ULL;  // 650000ms = 650s

std::vector<uint8_t> encode_oos_pn_frame(const OosPnFrame &frame) {
    std::vector<uint8_t> out;
    // v1.5.0.6 修复 (ISSUE T05 反馈): 此前错误地写入了 type 字节 (0x30)，
    // 但 PacketParser::parse_frames 在 case 0x30 之前已通过 payload[pos++]
    // 吞掉 type 字节，导致 f.data 不含 type，接收方 handle_oos_pn_frame
    // 调用 decode_oos_pn_frame 时 data[0] 永远不是 0x30，decode 失败 25/25 次。
    //
    // 修复策略（方案 A 补全）：encode 不写 type 字节，由 build_1rtt_packet
    // 显式追加 type 字节（仿 PING 帧 L952 风格），parse_frames 行为不变
    // （f.data 不含 type 字节），decode_oos_pn_frame 对应删除 type 检查
    // 并从 pos=0 开始解析 stream_id。
    //
    // 不再写入 type 字节（与 parse_frames f.data 语义对齐）：
    // out.push_back(static_cast<uint8_t>(FrameType::OOS_PN));  // v1.5.0.5 旧代码，已删除
    // stream_id (VarInt)
    auto sid = util::varint_encode_vec(frame.stream_id);
    out.insert(out.end(), sid.begin(), sid.end());
    // entries (限幅到 kMaxEntriesPerFrame，防止单帧过大)
    std::size_t n = std::min(frame.entries.size(), OosPnFrame::kMaxEntriesPerFrame);
    auto count = util::varint_encode_vec(static_cast<uint64_t>(n));
    out.insert(out.end(), count.begin(), count.end());
    for (std::size_t i = 0; i < n; ++i) {
        const auto &e = frame.entries[i];
        auto off = util::varint_encode_vec(e.offset);
        out.insert(out.end(), off.begin(), off.end());
        // first_seen_ms 限幅后编码
        double scaled = e.first_seen_ms * kOosFirstSeenMsScale;
        if (scaled < 0.0) scaled = 0.0;
        if (scaled > static_cast<double>(kOosFirstSeenMsMaxRaw)) {
            scaled = static_cast<double>(kOosFirstSeenMsMaxRaw);
        }
        auto seen = util::varint_encode_vec(static_cast<std::uint64_t>(scaled));
        out.insert(out.end(), seen.begin(), seen.end());
    }
    return out;
}

std::optional<OosPnFrame> decode_oos_pn_frame(std::span<const uint8_t> data) {
    if (data.empty()) return std::nullopt;
    // v1.5.0.6 修复 (ISSUE T05 反馈): 此前检查 data[0] == 0x30 是错误的，
    // 因为 PacketParser::parse_frames 在 case 0x30 之前已通过 payload[pos++]
    // 吞掉 type 字节，handle_oos_pn_frame 收到的 f.data 不含 type 字节，
    // data[0] 实际是 stream_id 的 varint 编码（永远 != 0x30），
    // 导致 25/25 次 decode 失败，OOS_PN_FRAME 数据通路断裂。
    //
    // 修复策略（方案 A 补全）：删除 type 字节检查，pos 从 0 开始解析 stream_id，
    // 与 parse_frames f.data 语义对齐。
    // if (data[0] != static_cast<uint8_t>(FrameType::OOS_PN)) return std::nullopt;  // v1.5.0.5 旧代码，已删除

    OosPnFrame frame;
    std::size_t pos = 0;  // v1.5.0.6: f.data 不含 type 字节，从 stream_id 开始

    // stream_id
    auto vi = util::varint_decode(data.subspan(pos));
    if (!vi) return std::nullopt;
    frame.stream_id = vi->first;
    pos += vi->second;

    // count
    if (pos >= data.size()) return std::nullopt;
    vi = util::varint_decode(data.subspan(pos));
    if (!vi) return std::nullopt;
    std::uint64_t count = vi->first;
    if (count > OosPnFrame::kMaxEntriesPerFrame) return std::nullopt;
    pos += vi->second;

    // entries
    frame.entries.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        OosPnEntry e;
        if (pos >= data.size()) return std::nullopt;
        vi = util::varint_decode(data.subspan(pos));
        if (!vi) return std::nullopt;
        e.offset = vi->first;
        pos += vi->second;

        if (pos >= data.size()) return std::nullopt;
        vi = util::varint_decode(data.subspan(pos));
        if (!vi) return std::nullopt;
        e.first_seen_ms = static_cast<double>(vi->first) / kOosFirstSeenMsScale;
        pos += vi->second;

        frame.entries.push_back(e);
    }
    return frame;
}

// ============================================================================
// v5.0.0: SESSION_TICKET 帧 encode/decode
// ============================================================================

std::vector<uint8_t> encode_session_ticket_frame(const SessionTicketFrame &frame) {
    std::vector<uint8_t> out;

    // ticket_lifetime (VarInt, 限幅 7 天)
    std::uint64_t lifetime = frame.ticket_lifetime;
    if (lifetime > SessionTicketFrame::kMaxLifetimeSec) {
        lifetime = SessionTicketFrame::kMaxLifetimeSec;
    }
    auto lt = util::varint_encode_vec(lifetime);
    out.insert(out.end(), lt.begin(), lt.end());

    // ticket_age_add (VarInt, 4B 随机混淆值)
    auto taa = util::varint_encode_vec(static_cast<std::uint64_t>(frame.ticket_age_add));
    out.insert(out.end(), taa.begin(), taa.end());

    // ticket_nonce_len (VarInt) + ticket_nonce
    std::size_t nonce_len = std::min(frame.ticket_nonce.size(), SessionTicketFrame::kMaxNonceLen);
    auto nl = util::varint_encode_vec(static_cast<std::uint64_t>(nonce_len));
    out.insert(out.end(), nl.begin(), nl.end());
    out.insert(out.end(), frame.ticket_nonce.begin(), frame.ticket_nonce.begin() + nonce_len);

    // ticket_len (VarInt) + ticket
    std::size_t ticket_len = std::min(frame.ticket.size(), SessionTicketFrame::kMaxTicketLen);
    auto tl = util::varint_encode_vec(static_cast<std::uint64_t>(ticket_len));
    out.insert(out.end(), tl.begin(), tl.end());
    out.insert(out.end(), frame.ticket.begin(), frame.ticket.begin() + ticket_len);

    return out;
}

std::optional<SessionTicketFrame> decode_session_ticket_frame(std::span<const uint8_t> data) {
    if (data.empty()) return std::nullopt;

    SessionTicketFrame frame;
    std::size_t pos = 0;

    // ticket_lifetime
    auto vi = util::varint_decode(data.subspan(pos));
    if (!vi) return std::nullopt;
    frame.ticket_lifetime = vi->first;
    if (frame.ticket_lifetime > SessionTicketFrame::kMaxLifetimeSec) return std::nullopt;
    pos += vi->second;

    // ticket_age_add
    if (pos >= data.size()) return std::nullopt;
    vi = util::varint_decode(data.subspan(pos));
    if (!vi) return std::nullopt;
    frame.ticket_age_add = static_cast<std::uint32_t>(vi->first);
    pos += vi->second;

    // ticket_nonce_len + ticket_nonce
    if (pos >= data.size()) return std::nullopt;
    vi = util::varint_decode(data.subspan(pos));
    if (!vi) return std::nullopt;
    std::uint64_t nonce_len = vi->first;
    if (nonce_len > SessionTicketFrame::kMaxNonceLen) return std::nullopt;
    pos += vi->second;
    if (pos + nonce_len > data.size()) return std::nullopt;
    frame.ticket_nonce.assign(data.begin() + pos, data.begin() + pos + nonce_len);
    pos += nonce_len;

    // ticket_len + ticket
    if (pos >= data.size()) return std::nullopt;
    vi = util::varint_decode(data.subspan(pos));
    if (!vi) return std::nullopt;
    std::uint64_t ticket_len = vi->first;
    if (ticket_len > SessionTicketFrame::kMaxTicketLen) return std::nullopt;
    pos += vi->second;
    if (pos + ticket_len > data.size()) return std::nullopt;
    frame.ticket.assign(data.begin() + pos, data.begin() + pos + ticket_len);
    pos += ticket_len;

    return frame;
}

// ============================================================================
// v5.0.0: ZERO_RTT_DATA 帧 encode/decode
// ============================================================================

std::vector<uint8_t> encode_zero_rtt_data_frame(const ZeroRttDataFrame &frame) {
    std::vector<uint8_t> out;

    // stream_id (VarInt)
    auto sid = util::varint_encode_vec(frame.stream_id);
    out.insert(out.end(), sid.begin(), sid.end());

    // offset (VarInt)
    auto off = util::varint_encode_vec(frame.offset);
    out.insert(out.end(), off.begin(), off.end());

    // fin (1 byte)
    out.push_back(frame.fin ? 0x01 : 0x00);

    // data (限幅 kMaxDataLen)
    std::size_t data_len = std::min(frame.data.size(), ZeroRttDataFrame::kMaxDataLen);
    out.insert(out.end(), frame.data.begin(), frame.data.begin() + data_len);

    return out;
}

std::optional<ZeroRttDataFrame> decode_zero_rtt_data_frame(std::span<const uint8_t> data) {
    if (data.empty()) return std::nullopt;

    ZeroRttDataFrame frame;
    std::size_t pos = 0;

    // stream_id
    auto vi = util::varint_decode(data.subspan(pos));
    if (!vi) return std::nullopt;
    frame.stream_id = vi->first;
    pos += vi->second;

    // offset
    if (pos >= data.size()) return std::nullopt;
    vi = util::varint_decode(data.subspan(pos));
    if (!vi) return std::nullopt;
    frame.offset = vi->first;
    pos += vi->second;

    // fin (1 byte)
    if (pos >= data.size()) return std::nullopt;
    frame.fin = (data[pos] != 0x00);
    pos += 1;

    // data (剩余字节)
    if (pos > data.size()) return std::nullopt;
    std::size_t data_len = data.size() - pos;
    if (data_len > ZeroRttDataFrame::kMaxDataLen) return std::nullopt;
    frame.data.assign(data.begin() + pos, data.end());

    return frame;
}

// ============================================================================
// v5.0.0: ADDRESS_DISCOVERY 帧 encode/decode
// ============================================================================

std::vector<uint8_t> encode_address_discovery_frame(const AddressDiscoveryFrame &frame) {
    std::vector<uint8_t> out;

    // nonce_len (VarInt) + nonce
    std::size_t nonce_len = std::min(frame.nonce.size(), AddressDiscoveryFrame::kMaxNonceLen);
    auto nl = util::varint_encode_vec(static_cast<std::uint64_t>(nonce_len));
    out.insert(out.end(), nl.begin(), nl.end());
    out.insert(out.end(), frame.nonce.begin(), frame.nonce.begin() + nonce_len);

    return out;
}

std::optional<AddressDiscoveryFrame> decode_address_discovery_frame(std::span<const uint8_t> data) {
    if (data.empty()) return std::nullopt;

    AddressDiscoveryFrame frame;
    std::size_t pos = 0;

    // nonce_len + nonce
    auto vi = util::varint_decode(data.subspan(pos));
    if (!vi) return std::nullopt;
    std::uint64_t nonce_len = vi->first;
    if (nonce_len > AddressDiscoveryFrame::kMaxNonceLen) return std::nullopt;
    pos += vi->second;
    if (pos + nonce_len > data.size()) return std::nullopt;
    frame.nonce.assign(data.begin() + pos, data.begin() + pos + nonce_len);
    pos += nonce_len;

    return frame;
}

// ============================================================================
// v5.0.0: ADDRESS_DISCOVERY_RESPONSE 帧 encode/decode
// ============================================================================

std::vector<uint8_t> encode_address_discovery_response_frame(const AddressDiscoveryResponseFrame &frame) {
    std::vector<uint8_t> out;

    // nonce_len (VarInt) + nonce
    std::size_t nonce_len = std::min(frame.nonce.size(), AddressDiscoveryResponseFrame::kMaxNonceLen);
    auto nl = util::varint_encode_vec(static_cast<std::uint64_t>(nonce_len));
    out.insert(out.end(), nl.begin(), nl.end());
    out.insert(out.end(), frame.nonce.begin(), frame.nonce.begin() + nonce_len);

    // observed_host_len (VarInt) + observed_host
    std::size_t host_len = std::min(frame.observed_host.size(),
                                     AddressDiscoveryResponseFrame::kMaxHostLen);
    auto hl = util::varint_encode_vec(static_cast<std::uint64_t>(host_len));
    out.insert(out.end(), hl.begin(), hl.end());
    out.insert(out.end(), frame.observed_host.begin(),
               frame.observed_host.begin() + host_len);

    // observed_port (VarInt)
    auto port = util::varint_encode_vec(static_cast<std::uint64_t>(frame.observed_port));
    out.insert(out.end(), port.begin(), port.end());

    return out;
}

std::optional<AddressDiscoveryResponseFrame> decode_address_discovery_response_frame(
    std::span<const uint8_t> data) {
    if (data.empty()) return std::nullopt;

    AddressDiscoveryResponseFrame frame;
    std::size_t pos = 0;

    // nonce_len + nonce
    auto vi = util::varint_decode(data.subspan(pos));
    if (!vi) return std::nullopt;
    std::uint64_t nonce_len = vi->first;
    if (nonce_len > AddressDiscoveryResponseFrame::kMaxNonceLen) return std::nullopt;
    pos += vi->second;
    if (pos + nonce_len > data.size()) return std::nullopt;
    frame.nonce.assign(data.begin() + pos, data.begin() + pos + nonce_len);
    pos += nonce_len;

    // observed_host_len + observed_host
    if (pos >= data.size()) return std::nullopt;
    vi = util::varint_decode(data.subspan(pos));
    if (!vi) return std::nullopt;
    std::uint64_t host_len = vi->first;
    if (host_len > AddressDiscoveryResponseFrame::kMaxHostLen) return std::nullopt;
    pos += vi->second;
    if (pos + host_len > data.size()) return std::nullopt;
    frame.observed_host.assign(reinterpret_cast<const char *>(data.data() + pos),
                               static_cast<std::size_t>(host_len));
    pos += host_len;

    // observed_port
    if (pos >= data.size()) return std::nullopt;
    vi = util::varint_decode(data.subspan(pos));
    if (!vi) return std::nullopt;
    std::uint64_t port = vi->first;
    if (port > 65535) return std::nullopt;
    frame.observed_port = static_cast<std::uint16_t>(port);
    pos += vi->second;

    return frame;
}

// ============================================================================
// v5.1.0: PSK_IDENTITY 帧 encode/decode（K-LINOH-PEERMISMATCH）
// ============================================================================

namespace {
/// 签名标签（参照 TLS1.3 CertVerify 的 64×0x20 前缀惯例）
constexpr char kPskIdentityLabel[] = "linoh psk node identity";
constexpr std::size_t kPskIdentityLabelLen = sizeof(kPskIdentityLabel) - 1;

void put_u64_le(std::vector<std::uint8_t> &out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
    }
}
std::uint64_t get_u64_le(const std::uint8_t *p) {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | p[i];
    }
    return v;
}
} // namespace

std::vector<std::uint8_t> psk_identity_signed_content(const PskIdentityFrame &frame) {
    std::vector<std::uint8_t> out;
    out.reserve(64 + kPskIdentityLabelLen + 1 + 3 + 8 + 32);
    // 64×0x20 前缀（TLS1.3 CertVerify 惯例，防跨协议签名滥用）
    out.insert(out.end(), 64, 0x20);
    out.insert(out.end(), kPskIdentityLabel, kPskIdentityLabel + kPskIdentityLabelLen);
    out.push_back(0x00);
    out.push_back(PskIdentityFrame::kVersion);
    out.push_back(frame.caps);
    put_u64_le(out, frame.created_at_unix);
    out.insert(out.end(), frame.node_pub.begin(), frame.node_pub.end());
    return out;
}

std::vector<std::uint8_t> encode_psk_identity_frame(const PskIdentityFrame &frame) {
    std::vector<std::uint8_t> out;
    out.reserve(PskIdentityFrame::kBodyBytes);
    out.push_back(PskIdentityFrame::kMagic);
    out.push_back(PskIdentityFrame::kVersion);
    out.push_back(frame.caps);
    put_u64_le(out, frame.created_at_unix);
    out.insert(out.end(), frame.node_pub.begin(), frame.node_pub.end());
    out.insert(out.end(), frame.signature.begin(), frame.signature.end());
    return out;
}

std::optional<PskIdentityFrame> decode_psk_identity_frame(std::span<const uint8_t> data) {
    if (data.size() != PskIdentityFrame::kBodyBytes) return std::nullopt;

    PskIdentityFrame frame;
    std::size_t pos = 0;
    if (data[pos] != PskIdentityFrame::kMagic) return std::nullopt;
    ++pos;
    if (data[pos] != PskIdentityFrame::kVersion) return std::nullopt;
    ++pos;
    frame.caps = data[pos];
    ++pos;
    frame.created_at_unix = get_u64_le(data.data() + pos);
    pos += 8;
    std::memcpy(frame.node_pub.data(), data.data() + pos, frame.node_pub.size());
    pos += frame.node_pub.size();
    std::memcpy(frame.signature.data(), data.data() + pos, frame.signature.size());
    pos += frame.signature.size();
    return frame;
}

} // namespace linoh::protocol
