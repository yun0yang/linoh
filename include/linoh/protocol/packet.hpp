#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/util/bytes.hpp"
#include "linoh/util/varint.hpp"  // v1.5.0.5: OosPnFrame encode/decode 使用 varint

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace linoh::protocol {

/// QUIC 版本号（draft-29）。
static constexpr std::uint32_t kVersion   = 0xff00002du;
static constexpr std::uint32_t kVersionV2 = 0x6b33403cu;

/// QUIC 包类型。
enum class PacketType : std::uint8_t {
    Initial   = 0,
    Handshake = 1,
    ZeroRtt   = 2,
    OneRtt    = 3,
    Retry     = 4,
};

/// 包编号长度编码。
enum class PnLen : std::uint8_t { Len1 = 0, Len2 = 1, Len3 = 2, Len4 = 3 };

/// 连接 ID（QUIC 协议中的 Connection ID）。
class ConnectionId {
public:
    static constexpr std::size_t kMaxSize    = 20;
    static constexpr std::size_t kDefaultSize = 8;

    ConnectionId() = default;
    explicit ConnectionId(std::span<const std::uint8_t> data);

    static ConnectionId generate();

    std::span<const std::uint8_t> data() const { return std::span<const std::uint8_t>(bytes_.data(), len_); }
    std::size_t len() const { return len_; }
    bool empty() const { return len_ == 0; }
    std::array<std::uint8_t, kMaxSize> to_array() const;
    std::string fmt_hex() const;
    std::string fmt_short() const;
    bool operator==(const ConnectionId &) const = default;

private:
    std::size_t len_{0};
    std::array<std::uint8_t, kMaxSize> bytes_{};
};

/// 单个 Frame 的类型标识。
enum class FrameType : std::uint8_t {
    PADDING            = 0x00,
    PING               = 0x01,
    ACK                = 0x02,  // ACK / ACK_ECN (0x02/0x03 in wire format)
    CRYPTO             = 0x06, // RFC 9000 §19.6 — TLS handshake data
    NEW_TOKEN          = 0x07, // RFC 9000 §19.7
    STREAM             = 0x08, // STREAM type varies (0x08 + fin/off/len bits)
    MAX_DATA           = 0x10,
    MAX_STREAM_DATA    = 0x11,
    MAX_STREAMS_BIDI   = 0x12,
    MAX_STREAMS_UNI    = 0x13,
    DATA_BLOCKED       = 0x14,
    STREAM_DATA_BLOCKED= 0x15,
    STREAMS_BLOCKED_BIDI=0x16,
    STREAMS_BLOCKED_UNI= 0x17,
    NEW_CONNECTION_ID  = 0x18,
    RETIRE_CONNECTION_ID=0x19,
    PATH_CHALLENGE     = 0x1a,
    PATH_RESPONSE      = 0x1b,
    CONNECTION_CLOSE   = 0x1c,
    APPLICATION_CLOSE  = 0x1d,
    HANDSHAKE_DONE     = 0x1e,
    // v1.5.0.5: 接收方 → 发送方反馈 OOS buffer PN 列表，触发对端 LossDetector 主动 retx
    OOS_PN             = 0x30,
    // v5.0.0: 0-RTT 重连支持（借鉴 iroh 0.96 Connection<OutgoingZeroRtt>）
    //   SESSION_TICKET — 服务端握手成功后下发，客户端缓存后用于 0-RTT 重连
    //   ZERO_RTT_DATA  — 握手完成前发送的早期数据，接收方需做重放保护
    SESSION_TICKET     = 0x31,
    ZERO_RTT_DATA      = 0x32,
    // v5.0.0: QUIC Address Discovery 替代 STUN（借鉴 iroh QAD）
    //   客户端通过已有连接发送请求，服务端响应中携带观察到的客户端公网地址
    ADDRESS_DISCOVERY          = 0x33,
    ADDRESS_DISCOVERY_RESPONSE = 0x34,
    // v5.1.0: PSK 模式节点身份交换（K-LINOH-PEERMISMATCH 根治）
    //   PSK 握手为桩（force_psk_established 零身份交换），peer_id_ 无法回答
    //   "这条连接属于哪个节点"。此帧携带 node_pub + Ed25519 签名，随首个
    //   Initial/1-RTT 包发送（必须作为包内最后一个帧——老对端 parse_frames
    //   的 default 分支按未知类型跳 1 字节，非末帧会破坏后续帧解析）。
    PSK_IDENTITY               = 0x35,
    // v5.5 K-OOSRESET-001: STREAM_RESET——发送方 reset_send_offset() 后的显式
    // "新消息从 offset=0 开始"宣告（单字节帧）。接收方据此显式重置流接收状态，
    // 替代隐式猜测（陈旧重传帧与新消息首帧在偏移空间不可区分）。
    // 老对端按未知类型跳过（parse_frames default 分支），零兼容风险。
    STREAM_RESET               = 0x38,
};

/// v1.5.0.5: 单个 OOS PN 条目（OOS_PN_FRAME 帧内的 entry）。
/// 由接收方 stream 的 oos_buffer_ 第一个 gap 派生，
/// 携带 offset（让发送方查 sent_packets_ 反查 PN）+ first_seen_ms（供 LossDetector 时间阈值）。
struct OosPnEntry {
    std::uint64_t offset{0};
    double first_seen_ms{0.0};
};

/// v1.5.0.5: OOS_PN_FRAME 数据结构。
/// 帧格式（type=0x30 已含 1B type 字节，由 encode 函数追加）：
///   Stream ID        (VarInt)
///   OOS PN Count     (VarInt, 最大 256 防止单帧过大)
///   For each entry:
///     Offset         (VarInt)
///     First Seen Ms  (VarInt, 单位 0.1ms, 范围 0~6.5e6 即 0~650000ms)
struct OosPnFrame {
    std::uint64_t stream_id{0};
    std::vector<OosPnEntry> entries;
    static constexpr std::size_t kMaxEntriesPerFrame = 256;
};

/// v1.5.0.5: 将 OosPnFrame 编码为字节序列（含 1B type 字节 0x30）。
std::vector<uint8_t> encode_oos_pn_frame(const OosPnFrame &frame);

/// v1.5.0.5: 从字节序列解码 OosPnFrame。
/// `data` 必须以 type 字节 (0x30) 开头；返回 nullopt 表示格式错误或条目数超限。
std::optional<OosPnFrame> decode_oos_pn_frame(std::span<const uint8_t> data);

/// v1.5.0.5: 单个 OOS_PN_FRAME 编码后的最大字节数（用于 build_1rtt_packet 容量预估）。
///   type(1) + stream_id(8) + count(2) + 256 * (offset(8) + first_seen(4)) = 1+8+2+3072 = 3083
static constexpr std::size_t kOosPnFrameMaxBytes = 1 + 8 + 2 + (OosPnFrame::kMaxEntriesPerFrame * (8 + 4));

// ============================================================================
// v5.0.0: SESSION_TICKET 帧（借鉴 iroh 0.96 + TLS 1.3 RFC 8446 §4.6.1）
// ============================================================================
//
// 服务端在握手完成后通过 SESSION_TICKET 帧下发 session ticket，客户端缓存后
// 在后续重连时携带该 ticket 发起 0-RTT 连接，实现秒级重连（vs 3-RTT 完整握手）。
//
// 帧格式（type=0x31 已含 1B type 字节，由 encode 函数不含 type，由
// build_1rtt_packet 显式追加 type 字节，与 OOS_PN 帧风格一致）：
//   ticket_lifetime   (VarInt, 单位秒, 最大 604800=7天)
//   ticket_age_add    (VarInt, 4B 随机值，用于混淆 ticket 年龄防指纹追踪)
//   ticket_nonce_len  (VarInt, nonce 长度, 最大 255)
//   ticket_nonce      (ticket_nonce_len 字节, 唯一标识本次 ticket 签发)
//   ticket_len        (VarInt, ticket 不透明数据长度, 最大 65535)
//   ticket            (ticket_len 字节, 服务端自定义的密钥派生材料)
//
// 安全约束：
//   - ticket 与 endpoint_id 绑定，跨节点不可复用
//   - ticket_lifetime 限制 7 天（604800 秒），超期自动失效
//   - 0-RTT 数据仅限幂等请求（避免重放攻击）

struct SessionTicketFrame {
    /// ticket 有效期（秒），最大 604800（7 天）
    std::uint64_t ticket_lifetime{0};
    /// ticket 年龄混淆值（RFC 8446 §4.6.1，4B 随机数）
    std::uint32_t ticket_age_add{0};
    /// ticket nonce（唯一标识本次签发，防重放）
    std::vector<std::uint8_t> ticket_nonce;
    /// ticket 不透明数据（服务端自定义，客户端不解析）
    std::vector<std::uint8_t> ticket;

    static constexpr std::uint64_t kMaxLifetimeSec = 604800;   // 7 天
    static constexpr std::size_t kMaxNonceLen = 255;
    static constexpr std::size_t kMaxTicketLen = 65535;
};

/// v5.0.0: 将 SessionTicketFrame 编码为字节序列（不含 type 字节，与 OOS_PN 风格一致）。
std::vector<uint8_t> encode_session_ticket_frame(const SessionTicketFrame &frame);

/// v5.0.0: 从字节序列解码 SessionTicketFrame。
/// `data` 不含 type 字节（parse_frames 已吞下 type），返回 nullopt 表示格式错误。
std::optional<SessionTicketFrame> decode_session_ticket_frame(std::span<const uint8_t> data);

/// v5.0.0: 单个 SESSION_TICKET 帧编码后的最大字节数（用于 build_1rtt_packet 容量预估）。
///   type(1) + lifetime(4) + age_add(4) + nonce_len(1) + nonce(255) + ticket_len(3) + ticket(65535)
///   实际通常 < 512B，此处为理论上限。
static constexpr std::size_t kSessionTicketFrameMaxBytes =
    1 + 4 + 4 + 1 + SessionTicketFrame::kMaxNonceLen + 3 + SessionTicketFrame::kMaxTicketLen;

// ============================================================================
// v5.0.0: ZERO_RTT_DATA 帧（借鉴 iroh 0.96 OutgoingZeroRtt）
// ============================================================================
//
// 在 TLS 握手完成前发送的早期数据。与 STREAM 帧语义类似，但显式标记为 0-RTT，
// 接收方需做重放保护（检测重复的 0-RTT 数据并丢弃）。
//
// 帧格式（type=0x32 已含 1B type 字节，encode 不含 type）：
//   stream_id  (VarInt, 流 ID)
//   offset     (VarInt, 流内偏移)
//   fin        (1 byte, 0=非结束 / 1=流结束)
//   data       (剩余字节, 0-RTT 早期数据)
//
// 安全约束：
//   - 仅限幂等请求（PING、心跳、PP 推理首请求走 1-RTT）
//   - 接收方维护 replay_protection 表，重复 nonce 的 0-RTT 数据丢弃
//   - 服务端可拒绝 0-RTT（返回 ZERO_RTT_REJECT 或 APPLICATION_CLOSE）

struct ZeroRttDataFrame {
    std::uint64_t stream_id{0};
    std::uint64_t offset{0};
    bool fin{false};
    std::vector<std::uint8_t> data;

    static constexpr std::size_t kMaxDataLen = 65535;  // 单帧最大数据长度
};

/// v5.0.0: 将 ZeroRttDataFrame 编码为字节序列（不含 type 字节）。
std::vector<uint8_t> encode_zero_rtt_data_frame(const ZeroRttDataFrame &frame);

/// v5.0.0: 从字节序列解码 ZeroRttDataFrame。
/// `data` 不含 type 字节，返回 nullopt 表示格式错误。
std::optional<ZeroRttDataFrame> decode_zero_rtt_data_frame(std::span<const uint8_t> data);

/// v5.0.0: 单个 ZERO_RTT_DATA 帧编码后的最大字节数。
///   type(1) + stream_id(8) + offset(8) + fin(1) + data(65535) = 65553
static constexpr std::size_t kZeroRttDataFrameMaxBytes =
    1 + 8 + 8 + 1 + ZeroRttDataFrame::kMaxDataLen;

// ============================================================================
// v5.0.0: ADDRESS_DISCOVERY 帧（借鉴 iroh QAD — QUIC Address Discovery）
// ============================================================================
//
// 客户端通过已有 linoh 连接发送 ADDRESS_DISCOVERY 请求，
// 服务端响应中携带观察到的客户端公网地址（替代独立 STUN 服务器）。
//
// 优势：
//   - 无需额外 STUN 服务器，减少外部依赖
//   - ADDRESS_DISCOVERY 帧加密传输，防止中间人观察
//   - 与 v4.x STUN 机制并存，通过 Config::qad_enabled 切换
//
// 帧格式（ADDRESS_DISCOVERY 请求, type=0x33, encode 不含 type）：
//   nonce_len  (VarInt, nonce 长度, 最大 32)
//   nonce      (nonce_len 字节, 唯一标识本次请求，用于匹配响应)
//
// 帧格式（ADDRESS_DISCOVERY_RESPONSE 响应, type=0x34, encode 不含 type）：
//   nonce_len      (VarInt, 与请求中的 nonce 相同)
//   nonce          (nonce_len 字节, echo 请求 nonce)
//   observed_host_len (VarInt, 主机地址字符串长度)
//   observed_host  (observed_host_len 字节, IPv4/IPv6 字符串)
//   observed_port  (VarInt, 端口号)

struct AddressDiscoveryFrame {
    /// 请求 nonce（唯一标识本次请求，用于匹配响应）
    std::vector<std::uint8_t> nonce;

    static constexpr std::size_t kMaxNonceLen = 32;
};

struct AddressDiscoveryResponseFrame {
    /// echo 请求 nonce（与请求中的 nonce 相同）
    std::vector<std::uint8_t> nonce;
    /// 服务端观察到的客户端公网地址（IPv4/IPv6 字符串）
    std::string observed_host;
    /// 服务端观察到的客户端公网端口
    std::uint16_t observed_port{0};

    static constexpr std::size_t kMaxNonceLen = 32;
    static constexpr std::size_t kMaxHostLen = 64;  // IPv6 最长 45 字符，留余量
};

/// v5.0.0: 将 AddressDiscoveryFrame 编码为字节序列（不含 type 字节）。
std::vector<uint8_t> encode_address_discovery_frame(const AddressDiscoveryFrame &frame);

/// v5.0.0: 从字节序列解码 AddressDiscoveryFrame。
std::optional<AddressDiscoveryFrame> decode_address_discovery_frame(std::span<const uint8_t> data);

/// v5.0.0: 将 AddressDiscoveryResponseFrame 编码为字节序列（不含 type 字节）。
std::vector<uint8_t> encode_address_discovery_response_frame(const AddressDiscoveryResponseFrame &frame);

/// v5.0.0: 从字节序列解码 AddressDiscoveryResponseFrame。
std::optional<AddressDiscoveryResponseFrame> decode_address_discovery_response_frame(std::span<const uint8_t> data);

/// v5.0.0: ADDRESS_DISCOVERY 帧编码后最大字节数。
///   type(1) + nonce_len(1) + nonce(32) = 34
static constexpr std::size_t kAddressDiscoveryFrameMaxBytes =
    1 + 1 + AddressDiscoveryFrame::kMaxNonceLen;

/// v5.0.0: ADDRESS_DISCOVERY_RESPONSE 帧编码后最大字节数。
///   type(1) + nonce_len(1) + nonce(32) + host_len(1) + host(64) + port(2) = 101
static constexpr std::size_t kAddressDiscoveryResponseFrameMaxBytes =
    1 + 1 + AddressDiscoveryResponseFrame::kMaxNonceLen +
    1 + AddressDiscoveryResponseFrame::kMaxHostLen + 2;

// ============================================================================
// v5.1.0: PSK_IDENTITY 帧（K-LINOH-PEERMISMATCH 根治）
// ============================================================================
//
// PSK 模式握手为桩（force_psk_established 零身份交换），peer_id_ 退化为
// 本端密钥/入站随机临时密钥，应用层无法回答"这条连接属于哪个节点"。
// PSK_IDENTITY 帧随首个 Initial / 1-RTT 包携带发送方节点身份：
//
//   node_pub     — 发送方 EndpointId（32B Ed25519 公钥，自报）
//   signature    — Ed25519(node_pub 对应私钥, 签名内容)（64B），
//                  证明发送方持有该节点私钥（防自报伪造）
//   created_at   — 签名时间戳（unix 秒），接收方校验 ±kMaxClockSkewSec
//                  时间窗，防跨时段重放
//
// 签名内容（参照 TLS1.3 CertVerify 惯例）：
//   64×0x20 || "linoh psk node identity" || 0x00 || version || caps || created_at(8) || node_pub(32)
//
// 帧格式（type=0x35 已含 1B type 字节，encode 不含 type，与 v5.0 帧风格一致；
// parse_frames 按 rest-of-payload 消费——**必须作为包内最后一个帧**）：
//   magic         (1 byte, 0x4C)
//   version       (1 byte, 0x01)
//   caps          (1 byte, bit0=支持身份交换)
//   created_at    (8 bytes, LE, unix 秒)
//   node_pub      (32 bytes)
//   signature     (64 bytes)
//
// 兼容性：老版本对端 parse_frames 走 default 跳过（未知类型仅消耗 type 字节，
// 后无其他帧故无解析错乱）；身份未认证时 peer_id_ 保持旧行为，连接照常可用。

struct PskIdentityFrame {
    static constexpr std::uint8_t kMagic = 0x4C;
    static constexpr std::uint8_t kVersion = 0x01;
    static constexpr std::uint8_t kCapIdentity = 0x01;

    /// 能力位（bit0 = 支持身份交换）
    std::uint8_t caps{kCapIdentity};
    /// 签名时间戳（unix 秒）
    std::uint64_t created_at_unix{0};
    /// 发送方节点公钥（自报，签名证明持有私钥）
    std::array<std::uint8_t, 32> node_pub{};
    /// Ed25519 签名
    std::array<std::uint8_t, 64> signature{};

    /// 帧体（不含 type 字节）固定长度：1+1+1+8+32+64 = 107
    static constexpr std::size_t kBodyBytes = 1 + 1 + 1 + 8 + 32 + 64;
};

/// v5.1.0: 构造签名内容（不含私钥操作，供编码与验签共用）。
std::vector<std::uint8_t> psk_identity_signed_content(const PskIdentityFrame &frame);

/// v5.1.0: 将 PskIdentityFrame 编码为字节序列（不含 type 字节）。
std::vector<std::uint8_t> encode_psk_identity_frame(const PskIdentityFrame &frame);

/// v5.1.0: 从字节序列解码 PskIdentityFrame。
/// `data` 不含 type 字节（parse_frames 已吞下 type），返回 nullopt 表示格式错误。
std::optional<PskIdentityFrame> decode_psk_identity_frame(std::span<const uint8_t> data);

/// v5.1.0: 单个 PSK_IDENTITY 帧编码后最大字节数（type + 定长体）。
static constexpr std::size_t kPskIdentityFrameMaxBytes = 1 + PskIdentityFrame::kBodyBytes;

/// 验收时间窗（秒）：签名时间戳与本地时钟的最大允许偏差。
/// 超窗拒绝认证（peer_id_ 保持旧行为），连接不受影响。
static constexpr std::int64_t kPskIdentityMaxClockSkewSec = 300;

/// 单个已解析的 Frame。
struct Frame {
    FrameType type;
    std::vector<std::uint8_t> data; // frame-specific payload
};

/// QUIC 包头。
class PacketHeader {
public:
    PacketHeader() = default;

    static PacketHeader make_initial(ConnectionId dcid, ConnectionId scid,
                                     std::uint32_t version = kVersion,
                                     PnLen pn_len = PnLen::Len4);
    static PacketHeader make_handshake(ConnectionId dcid, ConnectionId scid,
                                       PnLen pn_len = PnLen::Len3);
    static PacketHeader make_retry(ConnectionId dcid, ConnectionId odcid,
                                   std::span<const std::uint8_t> token);
    static PacketHeader make_1rtt(ConnectionId dcid, PnLen pn_len = PnLen::Len2);
    static PacketHeader make_0rtt(ConnectionId dcid, PnLen pn_len = PnLen::Len2);

    std::size_t serialize_to(std::uint8_t *out, std::size_t max_len) const;
    static std::optional<std::pair<PacketHeader, std::size_t>>
    parse_from(std::span<const std::uint8_t> data);

    PacketType type() const { return type_; }
    std::uint32_t version() const { return version_; }
    const ConnectionId &dcid() const { return dcid_; }
    const ConnectionId &scid() const { return scid_; }
    PnLen pn_len() const { return pn_len_; }
    const std::vector<std::uint8_t> &token() const { return token_; }
    /// v4.3.0 M21: 设置 token（用于在 Initial 包中携带 ALPN 字符串）
    void set_token(std::span<const std::uint8_t> t) {
        token_.assign(t.begin(), t.end());
    }
    std::size_t encoded_size() const;

private:
    PacketType type_{PacketType::OneRtt};
    std::uint32_t version_{kVersion};
    ConnectionId dcid_;
    ConnectionId scid_;
    std::vector<std::uint8_t> token_;
    PnLen pn_len_{PnLen::Len1};
};

/// 包编号。
struct PacketNumber {
    enum class Space { Initial, Handshake, ApplicationData };
    Space space;
    std::uint64_t value;

    std::uint8_t encoded_len() const;
    static std::array<std::uint8_t, 4> encode_bytes(std::uint64_t value,
                                                     std::uint8_t trunc_len);
    static std::uint64_t decode_truncated(std::span<const std::uint8_t> bytes,
                                          std::uint64_t largest_ack,
                                          std::uint64_t max_val);
};

/// 已加密的完整 QUIC 包。
struct Packet {
    PacketHeader header;
    util::Bytes payload;
    // B5 fix(2026-07-20): 保留截断的 PN 原始字节和长度，供 Connection 层
    // 调用 PacketNumber::decode_truncated() 还原完整 PN（RFC 9000 §A.3）。
    // 原 parse() 解码后丢弃了 pn 字节，导致 Connection 只能用 lockstep 假设。
    std::array<std::uint8_t, 4> truncated_pn{};
    std::uint8_t pn_len_bytes = 0;
};

/// 帧解析器。
class PacketParser {
public:
    explicit PacketParser(std::span<const std::uint8_t> wire)
        : wire_{wire}, pos_{0} {}

    std::optional<Packet> parse();
    std::optional<PacketHeader> peek_header() const;

    /// 解析字节序列中的所有 frames。
    static std::vector<Frame> parse_frames(std::span<const std::uint8_t> payload);

private:
    std::span<const std::uint8_t> wire_;
    std::size_t pos_{0};
};

/// 包构建器。
class PacketBuilder {
public:
    PacketBuilder(std::span<std::uint8_t> out, PacketHeader header, PacketNumber pn)
        : out_{out}, header_{header}, pn_{pn}, offset_{0} {}

    void add_frame(std::uint8_t frame_type, std::span<const std::uint8_t> data);
    std::size_t build();
    const PacketHeader &header() const { return header_; }
    PacketNumber pn() const { return pn_; }

private:
    std::span<std::uint8_t> out_;
    PacketHeader header_;
    PacketNumber pn_;
    std::size_t offset_{0};
};

} // namespace linoh::protocol
