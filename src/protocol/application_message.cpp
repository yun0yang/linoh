// application_message.cpp — linoh 应用层消息协议实现
//
// 实现 ApplicationMessage 的序列化/反序列化 + 4 个工厂方法。
// 所有多字节字段使用大端（网络）字节序，避免跨平台字节序问题。

#include "linoh/protocol/application_message.hpp"

#include <cstring>
#include <stdexcept>

#include "linoh/protocol/compression.hpp"  // V3.4 P3: compress/decompress 实现
#include "linoh/protocol/capabilities.hpp"  // O1.2: kCapZstdDict/kCapZstdCompressed 能力位

namespace linoh::protocol {

namespace {

// 大端写入辅助（network byte order）。
inline void put_u16_be(std::vector<std::uint8_t> &buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

inline void put_u32_be(std::vector<std::uint8_t> &buf, std::uint32_t v) {
    buf.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

// 大端读取辅助。
inline std::uint16_t get_u16_be(const std::uint8_t *p) {
    return (static_cast<std::uint16_t>(p[0]) << 8) |
           (static_cast<std::uint16_t>(p[1]));
}

inline std::uint32_t get_u32_be(const std::uint8_t *p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8)  |
           (static_cast<std::uint32_t>(p[3]));
}

}  // namespace

std::vector<std::uint8_t> ApplicationMessage::serialize() const {
    if (payload.size() > kMaxPayloadSize) {
        throw std::runtime_error("ApplicationMessage::serialize: payload exceeds kMaxPayloadSize");
    }

    // V3.4 P3: 若 HasSessionId，wire payload = [session_id 16B][payload]
    const bool has_sid = has_session_id();
    const std::size_t sid_size = has_sid ? SessionId::kSize : 0;
    const std::size_t wire_payload_len = payload.size() + sid_size;

    std::vector<std::uint8_t> buf;
    buf.reserve(kHeaderSize + wire_payload_len);

    // magic (2B)
    put_u16_be(buf, kMagic);
    // version (1B)
    buf.push_back(kVersion);
    // msg_type (1B)
    buf.push_back(static_cast<std::uint8_t>(msg_type));
    // method_id (2B)
    put_u16_be(buf, static_cast<std::uint16_t>(method_id));
    // request_id (4B)
    put_u32_be(buf, request_id);
    // flags (2B)
    put_u16_be(buf, flags);
    // payload_len (4B) — V3.4: 含 session_id 16B（若 HasSessionId）
    put_u32_be(buf, static_cast<std::uint32_t>(wire_payload_len));
    // V3.4 P3: session_id 前置（若 HasSessionId）
    if (has_sid) {
        const auto &bytes = session_id_ ? session_id_->bytes : SessionId{}.bytes;
        buf.insert(buf.end(), bytes.begin(), bytes.end());
    }
    // payload (N B)
    buf.insert(buf.end(), payload.begin(), payload.end());

    return buf;
}

// v3.3.0 突破2: 零拷贝序列化 — 直写现有 vector。
// 消除 serialize() 返回新 vector 的堆分配 + 调用方再 write(span) 的拷贝。
std::size_t ApplicationMessage::serialize_into(std::vector<std::uint8_t> &out) const {
    if (payload.size() > kMaxPayloadSize) {
        throw std::runtime_error("ApplicationMessage::serialize_into: payload exceeds kMaxPayloadSize");
    }

    // V3.4 P3: 若 HasSessionId，wire payload = [session_id 16B][payload]
    const bool has_sid = has_session_id();
    const std::size_t sid_size = has_sid ? SessionId::kSize : 0;
    const std::size_t wire_payload_len = payload.size() + sid_size;
    const std::size_t total = kHeaderSize + wire_payload_len;

    out.reserve(out.size() + total);  // 一次性预留，避免多次 reallocate

    // magic (2B)
    put_u16_be(out, kMagic);
    // version (1B)
    out.push_back(kVersion);
    // msg_type (1B)
    out.push_back(static_cast<std::uint8_t>(msg_type));
    // method_id (2B)
    put_u16_be(out, static_cast<std::uint16_t>(method_id));
    // request_id (4B)
    put_u32_be(out, request_id);
    // flags (2B)
    put_u16_be(out, flags);
    // payload_len (4B) — V3.4: 含 session_id 16B（若 HasSessionId）
    put_u32_be(out, static_cast<std::uint32_t>(wire_payload_len));
    // V3.4 P3: session_id 前置（若 HasSessionId）
    if (has_sid) {
        const auto &bytes = session_id_ ? session_id_->bytes : SessionId{}.bytes;
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    // payload (N B)
    out.insert(out.end(), payload.begin(), payload.end());

    return total;
}

// v3.3.0 突破2: 零拷贝序列化 — 写入预分配 buffer（不分配堆内存）。
// 用于复用 thread_local / pool buffer 场景。
std::size_t ApplicationMessage::serialize_to(std::span<std::uint8_t> out) const {
    if (payload.size() > kMaxPayloadSize) {
        return 0;
    }

    // V3.4 P3: 若 HasSessionId，wire payload = [session_id 16B][payload]
    const bool has_sid = has_session_id();
    const std::size_t sid_size = has_sid ? SessionId::kSize : 0;
    const std::size_t wire_payload_len = payload.size() + sid_size;
    const std::size_t total = kHeaderSize + wire_payload_len;

    if (out.size() < total) {
        return 0;  // 容量不足
    }

    std::uint8_t *p = out.data();
    // magic (2B)
    p[0] = static_cast<std::uint8_t>((kMagic >> 8) & 0xFF);
    p[1] = static_cast<std::uint8_t>(kMagic & 0xFF);
    // version (1B)
    p[2] = kVersion;
    // msg_type (1B)
    p[3] = static_cast<std::uint8_t>(msg_type);
    // method_id (2B)
    {
        std::uint16_t v = static_cast<std::uint16_t>(method_id);
        p[4] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
        p[5] = static_cast<std::uint8_t>(v & 0xFF);
    }
    // request_id (4B)
    {
        std::uint32_t v = request_id;
        p[6] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
        p[7] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
        p[8] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
        p[9] = static_cast<std::uint8_t>(v & 0xFF);
    }
    // flags (2B)
    {
        std::uint16_t v = flags;
        p[10] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
        p[11] = static_cast<std::uint8_t>(v & 0xFF);
    }
    // payload_len (4B) — V3.4: 含 session_id 16B（若 HasSessionId）
    {
        std::uint32_t v = static_cast<std::uint32_t>(wire_payload_len);
        p[12] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
        p[13] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
        p[14] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
        p[15] = static_cast<std::uint8_t>(v & 0xFF);
    }
    // V3.4 P3: session_id 前置（若 HasSessionId）
    if (has_sid) {
        const auto &bytes = session_id_ ? session_id_->bytes : SessionId{}.bytes;
        std::memcpy(p + kHeaderSize, bytes.data(), SessionId::kSize);
    }
    // payload (N B)
    if (!payload.empty()) {
        std::memcpy(p + kHeaderSize + sid_size, payload.data(), payload.size());
    }

    return total;
}

std::size_t ApplicationMessage::parse(std::span<const std::uint8_t> buffer,
                                       ApplicationMessage &out) {
    if (buffer.size() < kHeaderSize) {
        return 0;  // 数据不足
    }

    const std::uint8_t *p = buffer.data();

    // magic 校验
    std::uint16_t magic = get_u16_be(p);
    if (magic != kMagic) {
        // 格式错误：调用方应丢弃 buffer 或寻找下一个 magic
        // 返回 0 让调用方决策（典型实现是丢弃一字节后重试）
        return 0;
    }

    // version 校验
    std::uint8_t version = p[2];
    if (version != kVersion) {
        return 0;
    }

    std::uint8_t  msg_type_byte = p[3];
    std::uint16_t method_id_raw = get_u16_be(p + 4);
    std::uint32_t request_id    = get_u32_be(p + 6);
    std::uint16_t flags         = get_u16_be(p + 10);
    std::uint32_t payload_len   = get_u32_be(p + 12);

    if (payload_len > kMaxPayloadSize) {
        return 0;  // 超长拒绝
    }

    if (buffer.size() < kHeaderSize + payload_len) {
        return 0;  // payload 未到齐
    }

    // msg_type 合法性校验
    if (msg_type_byte > 3) {
        return 0;
    }

    out.msg_type   = static_cast<MessageType>(msg_type_byte);
    out.method_id  = static_cast<MethodId>(method_id_raw);
    out.request_id = request_id;
    out.flags      = flags;

    // V3.4 P3: 若 HasSessionId，从 wire payload 头部剥离 16B session_id
    const bool has_sid = has_flag(flags, MessageFlags::HasSessionId);
    if (has_sid && payload_len >= SessionId::kSize) {
        // 解析 session_id（parse 失败时填零值，保证 payload 偏移正确）
        auto sid_opt = SessionId::parse(
            std::span<const std::uint8_t>(p + kHeaderSize, SessionId::kSize));
        out.session_id_ = sid_opt.value_or(SessionId{});
        // 实际 payload 跳过前 16B
        out.payload.assign(p + kHeaderSize + SessionId::kSize,
                           p + kHeaderSize + payload_len);
    } else {
        // 无 session_id（旧消息兼容，或 payload_len < 16 降级）
        out.session_id_.reset();
        // 降级一致性修复：HasSessionId 置位但 payload_len < 16 时，
        // 清除 flag 避免出现 has_session_id()==true 但 get_session_id()==nullopt 的不一致
        if (has_sid) {
            out.flags &= ~static_cast<std::uint16_t>(MessageFlags::HasSessionId);
        }
        out.payload.assign(p + kHeaderSize, p + kHeaderSize + payload_len);
    }

    return kHeaderSize + payload_len;
}

bool ApplicationMessage::validate_header(std::span<const std::uint8_t> header_bytes) {
    if (header_bytes.size() < kHeaderSize) return false;
    const std::uint8_t *p = header_bytes.data();
    if (get_u16_be(p) != kMagic) return false;
    if (p[2] != kVersion) return false;
    if (p[3] > 3) return false;  // msg_type 范围
    std::uint32_t payload_len = get_u32_be(p + 12);
    if (payload_len > kMaxPayloadSize) return false;
    return true;
}

// ========== V3.4 P3: 按需压缩（zstd）实现 ==========

bool ApplicationMessage::compress(CompressionAlgo algo, int level) {
    if (algo == CompressionAlgo::None) {
        return true;  // no-op
    }
    if (payload.empty()) {
        return true;  // 空 payload 不压缩
    }

    if (algo == CompressionAlgo::Zstd) {
        auto compressed = compress_payload(
            std::span<const std::uint8_t>(payload.data(), payload.size()),
            CompressionAlgo::Zstd, level);
        // 压缩失败（返回空但输入非空）
        if (compressed.empty()) {
            return false;
        }
        // 压缩无收益（压缩后 >= 原始）— 不替换 payload，不置 flag
        if (compressed.size() >= payload.size()) {
            return true;
        }
        payload = std::move(compressed);
        set_flag(MessageFlags::ZstdCompressed);
        return true;
    }

    // Gzip 未实现
    return false;
}

bool ApplicationMessage::decompress() {
    const bool is_zstd = is_zstd_compressed();
    const bool is_gzip = is_compressed();  // PayloadCompressed（gzip）
    const bool is_dict = is_zstd_dict_compressed();

    // 非法状态：多种压缩 flag 同时置位
    if ((is_zstd ? 1 : 0) + (is_gzip ? 1 : 0) + (is_dict ? 1 : 0) > 1) {
        return false;
    }

    if (is_dict) {
        if (payload.empty()) {
            clear_flag(MessageFlags::ZstdDictCompressed);
            return true;  // 空 payload 直接清 flag
        }
        auto decompressed = decompress_payload_dict(
            std::span<const std::uint8_t>(payload.data(), payload.size()));
        if (decompressed.empty()) {
            return false;  // 字典缺失 / 格式错误 / 解压失败
        }
        payload = std::move(decompressed);
        clear_flag(MessageFlags::ZstdDictCompressed);
        return true;
    }

    if (is_zstd) {
        if (payload.empty()) {
            clear_flag(MessageFlags::ZstdCompressed);
            return true;  // 空 payload 直接清 flag
        }
        auto decompressed = decompress_payload(
            std::span<const std::uint8_t>(payload.data(), payload.size()),
            CompressionAlgo::Zstd);
        if (decompressed.empty()) {
            return false;  // 解压失败
        }
        payload = std::move(decompressed);
        clear_flag(MessageFlags::ZstdCompressed);
        return true;
    }

    if (is_gzip) {
        // Gzip 未实现（V3.4 暂不支持）
        return false;
    }

    // 无压缩 flag — no-op
    return true;
}

// ========== O1: 协议字典压缩 ==========

bool ApplicationMessage::compress_dict(std::uint8_t dict_id, int level) {
    if (payload.empty()) {
        return false;  // 空 payload 不压缩
    }
    // 互斥：已置任意压缩 flag
    if (is_zstd_compressed() || is_compressed() || is_zstd_dict_compressed()) {
        return false;
    }
    auto compressed = compress_payload_dict(
        std::span<const std::uint8_t>(payload.data(), payload.size()),
        level, dict_id);
    // 字典未加载 / 压缩失败
    if (compressed.empty()) {
        return false;
    }
    // 压缩无收益（含 1B dict_id 前缀仍 >= 原始）— 不替换，不置 flag
    if (compressed.size() >= payload.size()) {
        return false;
    }
    payload = std::move(compressed);
    set_flag(MessageFlags::ZstdDictCompressed);
    return true;
}

bool ApplicationMessage::maybe_auto_compress() {
    // 无参版本：调用方自担"对端能力已确认"（默认全支持）
    constexpr std::uint32_t kAssumeAllCaps = 0xFFFFFFFFu;
    return maybe_auto_compress(kAssumeAllCaps);
}

bool ApplicationMessage::maybe_auto_compress(std::uint32_t peer_capabilities) {
    if (!auto_compress_enabled()) {
        return false;
    }
    if (payload.empty() || is_zstd_compressed() || is_compressed() ||
        is_zstd_dict_compressed()) {
        return false;
    }
    auto algo = recommend_compression(payload.size(), method_id);
    if (algo != CompressionAlgo::Zstd) {
        return false;
    }
    // O1.2 能力降级：无任何压缩能力位（未探测/旧对端）→ 不压
    const bool peer_dict = (peer_capabilities &
                            static_cast<std::uint32_t>(CapabilitiesMask::kCapZstdDict)) != 0;
    const bool peer_zstd = (peer_capabilities &
                            static_cast<std::uint32_t>(CapabilitiesMask::kCapZstdCompressed)) != 0;
    if (!peer_dict && !peer_zstd) {
        return false;
    }
    // 字典优先（仅对端支持字典压缩时），失败回退普通 zstd
    if (peer_dict && has_any_protocol_dict()) {
        if (compress_dict(default_dict_id())) {
            return true;
        }
    }
    return compress(CompressionAlgo::Zstd) && is_zstd_compressed();
}

// ========== 工厂方法 ==========

ApplicationMessage ApplicationMessage::request(std::uint32_t id, MethodId method,
                                                std::span<const std::uint8_t> payload) {
    ApplicationMessage m;
    m.msg_type   = MessageType::Request;
    m.method_id  = method;
    m.request_id = id == 0 ? 1 : id;  // Request 必须 id > 0
    m.flags      = static_cast<std::uint16_t>(MessageFlags::LastFragment);
    m.payload.assign(payload.begin(), payload.end());
    return m;
}

ApplicationMessage ApplicationMessage::response(std::uint32_t id, MethodId method,
                                                 std::span<const std::uint8_t> payload) {
    ApplicationMessage m;
    m.msg_type   = MessageType::Response;
    m.method_id  = method;
    m.request_id = id == 0 ? 1 : id;  // Response 必须 id > 0（与 Request 匹配）
    m.flags      = static_cast<std::uint16_t>(MessageFlags::LastFragment);
    m.payload.assign(payload.begin(), payload.end());
    return m;
}

ApplicationMessage ApplicationMessage::error(std::uint32_t id, MethodId method,
                                              const std::string &error_msg) {
    ApplicationMessage m;
    m.msg_type   = MessageType::ErrorResponse;
    m.method_id  = method;
    m.request_id = id == 0 ? 1 : id;
    m.flags      = static_cast<std::uint16_t>(MessageFlags::LastFragment);
    m.payload.assign(error_msg.begin(), error_msg.end());
    return m;
}

ApplicationMessage ApplicationMessage::notification(MethodId method,
                                                     std::span<const std::uint8_t> payload) {
    ApplicationMessage m;
    m.msg_type   = MessageType::Notification;
    m.method_id  = method;
    m.request_id = 0;  // 通知固定 id = 0
    m.flags      = static_cast<std::uint16_t>(MessageFlags::LastFragment);
    m.payload.assign(payload.begin(), payload.end());
    return m;
}

}  // namespace linoh::protocol
