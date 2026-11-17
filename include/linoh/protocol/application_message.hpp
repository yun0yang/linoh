// application_message.hpp — linoh 应用层消息协议（借鉴 qt-easy-tier IpcMessage）
//
// 在 linoh 裸 STREAM 字节流之上增加 16 字节二进制帧头 + payload 的消息封装，
// 区分 4 种消息类型（Request / Response / ErrorResponse / Notification），
// 通过 method_id 枚举替代字符串省带宽，通过 request_id 实现请求-响应匹配。
//
// 帧格式（16 字节头 + payload）：
//   ┌──────────┬───────────┬───────────┬───────────┬───────────┐
//   │ magic    │ version   │ msg_type  │ method_id │ request_id│
//   │ 2 bytes  │ 1 byte    │ 1 byte    │ 2 bytes   │ 4 bytes   │
//   ├──────────┼───────────┼───────────┼───────────┼───────────┤
//   │ flags    │ payload_len (4 bytes) │ payload              │
//   │ 2 bytes  │ 4 bytes              │ N bytes              │
//   └──────────┴───────────────────────┴───────────────────────┘
//
// 头部字段总计 16 字节：magic(2) + version(1) + msg_type(1) + method_id(2)
//                     + request_id(4) + flags(2) + payload_len(4)
//
// 所有多字节字段使用大端（网络）字节序。

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "linoh/protocol/session_id.hpp"  // V3.4: SessionId（session_id_ 成员，无循环依赖）

namespace linoh::protocol {

// V3.4: 前向声明 CompressionAlgo（compression.hpp 本身 include 本头文件取 MethodId，
//        故不能反向 include；compress()/decompress() 实现在 application_message.cpp）
//        完整定义见 linoh/protocol/compression.hpp
enum class CompressionAlgo : std::uint8_t;

/// 消息类型（对应 qt-easy-tier IpcMessage 的 4 种消息）。
enum class MessageType : std::uint8_t {
    Request      = 0,  // {id>0, method, params}
    Response     = 1,  // {id>0, method, result}
    ErrorResponse = 2,  // {id>0, method, error}
    Notification = 3,  // {id=0, method, params}
};

/// 方法枚举（uint16，替代字符串省带宽）。
/// 编号空间：0x0001-0x000F 节点管理，0x0010-0x001F 推理，0x0020-0x002F 模型管理，0x0030-0x003F 通知，
///           0x0040-0x004F 多模态 tensor 分片（P5-A-3 新增），
///           0x0050-0x005F 跨域控制面（V3-A 新增）。
enum class MethodId : std::uint16_t {
    // 节点管理
    Join            = 0x0001,  // WORKER → MASTER：加入集群
    JoinAck         = 0x0002,  // MASTER → WORKER：确认加入
    Leave           = 0x0003,  // WORKER → MASTER：离开集群
    Heartbeat       = 0x0004,  // 双向心跳

    // 推理
    ForwardPP       = 0x0010,  // MASTER → WORKER：转发 hidden_state
    ResultPP        = 0x0011,  // WORKER → MASTER：返回推理结果
    CancelInference = 0x0012,  // MASTER → WORKER：取消推理

    // 模型管理
    LoadModel       = 0x0020,  // 加载模型
    LoadModelAck    = 0x0021,  // 加载模型响应
    Drain           = 0x0022,  // 驱逐节点

    // 通知（request_id=0）
    StateChange     = 0x0030,  // 状态变更通知
    ErrorReport     = 0x0031,  // 错误上报

    // 多模态 tensor 分片（P5-A-3 新增）
    TensorShard     = 0x0040,  // tensor 分片消息（Notification，request_id=0）
    TensorShardAck  = 0x0041,  // tensor 分片确认（可选，用于可靠传输）
    TensorCancel    = 0x0042,  // tensor 传输取消
    ShardHashAnnounce = 0x0043,  // v3.9.6 M17: shard chunk hash 公告（带外，Notification，request_id=0）

    // v4.0.2 M20: 分片可用性同步（走 ctrl/1 ALPN）
    // 节点定期广播本地 shard 可用性 bitmap（Observe 帧），上游据此跳过已到达 shard。
    // 旧节点不识别此 MethodId → 丢弃（等价不发 Observe，上游发全量 shard，行为不变）。
    Observe          = 0x0045,  // 节点 → 对端：shard 可用性公告（Notification，request_id=0，ShardBitfield payload）

    // v4.0.3 M15: 跨集群 Ed25519 挑战认证（走 ctrl/1 ALPN）
    // 握手后追加挑战-签名-验证三步认证，证明对端持有 EndpointId 对应的私钥。
    // 算法选型调整：原路线图 ECDSA secp256k1 → Ed25519（linoh OpenSSL 是 stub 空实现，
    // 无法执行 ECDSA；Ed25519 与 v3.8.5 SignedMessage 一致，复用现有 ed25519_core）。
    // 旧节点不识别此 MethodId → 丢弃（auto 模式下内网不认证，行为不变）。
    AuthChallenge    = 0x0046,  // A → B：认证挑战（Request，request_id>0，AuthChallenge payload 73B）
    AuthResponse     = 0x0047,  // B → A：认证响应（Response，request_id 与 Challenge 对应，AuthResponse payload 137B）

    // 跨域控制面（V3-A 新增）
    // 跨域摘要通过 ctrl/1 ALPN 通道传输，复用既有控制连接，不新增 ALPN/端口
    CrossDomainDigest    = 0x0050,  // V3-A: 跨域节点摘要（域代表间传播，Notification，request_id=0）
    CrossDomainDigestReq = 0x0051,  // V3-A: 跨域摘要请求（新加入域代表主动拉取，Request，request_id>0）

    // 跨域数据面通道（V3-B 新增）
    // 复用 ctrl/1 ALPN 通道，传播跨域节点地址提示/查询/响应，供跨域数据面连接解析 EndpointAddr
    CrossDomainAddrHint  = 0x0052,  // V3-B: 跨域节点地址提示（域代表间传播，Notification，request_id=0）
    CrossDomainAddrQuery = 0x0053,  // V3-B: 跨域地址查询（节点→域代表按需拉取，Request，request_id>0）
    CrossDomainAddrResp  = 0x0054,  // V3-B: 跨域地址响应（域代表→节点，Response，request_id 与 Query 对应）

    // Direct Return Path（v3.2.0 新增）
    // PP 链末节点 RESULT 直连回传 MASTER 的能力探测与确认，走 ctrl/1 ALPN
    ReturnAddrProbe   = 0x0060,  // MASTER → WORKER：探测是否支持 Direct Return（Request，request_id>0）
    ReturnAddrAck     = 0x0061,  // WORKER → MASTER：能力确认（Response，携带 supported + 本端 EndpointId）

    // V3.5 P5-A: 统一节点能力探测（走 ctrl/1 ALPN，借鉴 ReturnAddrProbe 模式）
    // MASTER 在 WORKER Join 后发送 CapabilitiesProbe，WORKER 回复 CapabilitiesAck
    // 携带 capabilities_mask 位掩码（HasReturnAddress/DirectReturn/ResultShard/
    // HasSessionId/ZstdCompressed）。旧节点不识别此 MethodId，超时降级 mask=0。
    // 与 ReturnAddrProbe 并存：新节点优先用 CapabilitiesProbe（涵盖 Direct Return 位）
    CapabilitiesProbe = 0x0062,  // MASTER → WORKER：统一能力探测（Request，request_id>0，payload 空）
    CapabilitiesAck   = 0x0063,  // WORKER → MASTER：能力确认（Response，39B CapabilitiesAckPayload）

    // v4.0.0 M18: 地址交换协议分级（走 ctrl/1 ALPN）
    // 节点发送 AddrInfoAnnounce 携带分级地址信息（Id/Relay/Addresses/RelayAndAddresses），
    // 对端据此选择最优连接路径。旧节点不识别此 MethodId → 丢弃（等价不交换）。
    AddrInfoAnnounce  = 0x0064,  // 节点 → 对端：分级地址公告（Notification，request_id=0，变长 AddrInfoPayload）

    // v4.3.0 M21: 双层进度上报（走 ctrl/1 ALPN）
    // 模型加载/大 tensor 传输时，节点发送 ProgressReport 携带 overall + current_item 双层进度，
    // MASTER 据此向 orchestrator 汇报详细进度（替代粗粒度 "loading" 状态）。
    // 旧节点不识别此 MethodId → 丢弃（等价不上报进度，行为不变）。
    ProgressReport    = 0x0065,  // 节点 → 对端：双层进度上报（Notification，request_id=0，ProgressReportPayload）
};

/// flags 位定义。
///
/// P1-8 扩展（2026-07-19）：新增 Encrypted / Signed 标志位，支持 payload
/// 端到端加密和签名。压缩/加密/签名由上层（ApplicationApi 或用户代码）在
/// serialize 之前/parse 之后处理；ApplicationMessage 本身只做标志位透传。
///   - serialize()：原样写入 flags 和 payload（不自动压缩/加密/签名）
///   - parse()：原样读出 flags 和 payload（不自动解压/解密/验签）
/// 这样保持消息层薄封装，安全策略由上层选择。
enum class MessageFlags : std::uint16_t {
    None              = 0x0000,
    PayloadCompressed = 0x0001,  // payload 已压缩（zstd/gzip，预留）
    LastFragment      = 0x0002,  // 分片消息的最后一帧（预留，单帧消息始终置 1）
    EndOfStream       = 0x0004,  // 处理完后关闭 stream
    /// P1-8: payload 已使用 AEAD 加密（密钥由上层管理）。
    /// 加密时 payload 格式为 [nonce:12][ciphertext||tag]。
    PayloadEncrypted  = 0x0008,
    /// P1-8: payload 末尾附加 Ed25519 签名（64 字节）。
    /// 签名内容 = header(16B) + payload(不含签名)。
    PayloadSigned     = 0x0010,
    /// P1-8: payload 为分片消息的非末帧（LastFragment=0）。
    /// 用于大 payload 分片传输，与 LastFragment 互斥。
    Fragment          = 0x0020,
    /// v3.2.0 Direct Return Path: ForwardPP payload 头部携带 ReturnAddress
    /// （MASTER EndpointId + stream_token）。末节点收到后缓存 ReturnAddress，
    /// 推理完成后通过直连 STREAM 回传 RESULT。旧节点不识别此位，忽略 payload
    /// 头部的 ReturnAddress 字段（向后兼容，需先经 ReturnAddrProbe 能力探测）。
    HasReturnAddress  = 0x0040,
    /// v3.2.0 Direct Return Path: ResultPP 通过直连 STREAM 回传（非逐跳反向）。
    /// MASTER 收到此标记的 ResultPP 后，按 payload 头部 stream_token 路由到对应推理请求。
    DirectReturn      = 0x0080,
    /// v3.2.1 P3-1: ResultPP[DirectReturn] 为大 RESULT 分片（shard）。
    /// payload 格式：[stream_token(4B,LE)][shard_idx(2B,LE)][total_shards(2B,LE)][result_chunk]
    /// MASTER 端按 stream_token 累积所有 shard，total_shards 到齐后 set_value。
    /// 与 DirectReturn 同时置位；LastFragment 标记最后一个 shard。
    ResultShard       = 0x0100,
    /// V3.4 P3: payload 头部携带 16B SessionId（推理会话级去重/关联）。
    /// wire 格式：[header 16B][session_id 16B][payload N bytes]
    /// payload_len 字段 = N + 16（含 session_id）；in-memory payload 不含 session_id。
    /// serialize 时自动前置 session_id；parse 时自动剥离到 session_id_ 成员。
    /// 旧节点不识别此位（需先经能力探测 P5），不会误处理。
    HasSessionId      = 0x0200,
    /// V3.4 P3: payload 已用 zstd 压缩（与 PayloadCompressed gzip 互斥）。
    /// compress(Zstd) 后置位；decompress() 检测此位用 zstd 解压并清除。
    /// session_id 不参与压缩（serialize 先压缩 payload 再前置 session_id，
    /// parse 先剥离 session_id 再解压）。
    ZstdCompressed    = 0x0400,
    /// O1（编码层优化方案）: payload 已用协议字典 zstd 压缩。
    /// wire 格式：payload = [dict_id: 1B][zstd frame]；与 ZstdCompressed /
    /// PayloadCompressed 互斥。compress_dict() 后置位；decompress() 检测此位
    /// 按首字节 dict_id 选字典解压并清除。旧节点不识别此位 —— 发送端须在
    /// 能力确认（kCapZstdDict，O1.2）后启用；自动压缩开关默认 off。
    ZstdDictCompressed = 0x0800,
};

inline MessageFlags operator|(MessageFlags a, MessageFlags b) {
    return static_cast<MessageFlags>(
        static_cast<std::uint16_t>(a) | static_cast<std::uint16_t>(b));
}

inline std::uint16_t operator|(std::uint16_t a, MessageFlags b) {
    return a | static_cast<std::uint16_t>(b);
}

inline MessageFlags &operator|=(MessageFlags &a, MessageFlags b) {
    a = a | b;
    return a;
}

/// P1-8: flags 便捷判定函数（内联，无副作用）
inline bool has_flag(std::uint16_t flags, MessageFlags bit) noexcept {
    return (flags & static_cast<std::uint16_t>(bit)) != 0;
}

/// P1-8: Ed25519 签名长度（字节）
constexpr std::size_t kEd25519SignatureSize = 64;

/// P1-8: AEAD nonce 长度（字节，ChaCha20-Poly1305）
constexpr std::size_t kAeadNonceSize = 12;

/// P1-8: AEAD tag 长度（字节，ChaCha20-Poly1305）
constexpr std::size_t kAeadTagSize = 16;

/// 应用层消息封装。
///
/// 使用方式：
///   // 客户端发送请求
///   auto msg = ApplicationMessage::request(req_id, MethodId::ForwardPP, hidden_state_bytes);
///   stream->write(msg.serialize());
///
///   // 服务端解析
///   ApplicationMessage parsed;
///   size_t consumed = ApplicationMessage::parse(recv_buffer, parsed);
///   if (consumed > 0) { /* 处理 parsed */ recv_buffer.erase(0, consumed); }
///
struct ApplicationMessage {
    static constexpr std::uint16_t kMagic = 0x4C4E;   // "LN"
    static constexpr std::uint8_t  kVersion = 0x01;
    static constexpr std::size_t   kHeaderSize = 16;
    static constexpr std::uint32_t kMaxPayloadSize = 64u * 1024 * 1024;  // 64 MB

    MessageType  msg_type{MessageType::Notification};
    MethodId     method_id{MethodId::Heartbeat};
    std::uint32_t request_id{0};   // 0 = 通知，>0 = 请求/响应
    std::uint16_t flags{0};
    std::vector<std::uint8_t> payload;

    // V3.4 P3: 推理会话 ID（仅当 flags 含 HasSessionId 时有效）
    // serialize 时前置到 payload 头部 16B；parse 时从 payload 头部剥离到此成员
    // 与 payload 字段分离，避免上层处理 payload 时需手动跳过 16B
    std::optional<SessionId> session_id_;

    /// 序列化为字节流（16 字节头 + payload）。
    std::vector<std::uint8_t> serialize() const;

    /// v3.3.0 突破2: 零拷贝序列化 — 直写现有 vector（append，避免返回新 vector 的分配）。
    ///
    /// \param out 目标 vector，函数会 reserve(out.size() + total) 后 append 头部 + payload
    /// \return 本次追加的字节数（= kHeaderSize + payload.size()）
    ///
    /// 典型用法（消除 serialize() 返回值 + write(span) 两次拷贝）：
    ///   std::vector<std::uint8_t> wire;
    ///   wire.reserve(msg.wire_size());
    ///   msg.serialize_into(wire);
    ///   stream->write_ref(std::move(wire));  // send_ 空时 O(1) swap 真零拷贝
    std::size_t serialize_into(std::vector<std::uint8_t> &out) const;

    /// v3.3.0 突破2: 零拷贝序列化 — 写入预分配 buffer（不分配，不拷贝 payload 外部内存）。
    ///
    /// \param out 预分配 buffer，容量必须 >= total_wire_size(payload.size())
    /// \return 实际写入字节数；out 容量不足返回 0
    ///
    /// 用于复用 thread_local / pool buffer 场景，彻底消除堆分配。
    std::size_t serialize_to(std::span<std::uint8_t> out) const;

    /// v3.3.0 突破2: 本消息的总线字节数（header + payload），供预分配。
    /// V3.4 P3: 若 HasSessionId 置位，额外 +16B（session_id 前置于 payload 头部）。
    /// 非 constexpr：std::vector::size() 在 C++20 GCC 11.4 非 constexpr
    std::size_t wire_size() const noexcept {
        return kHeaderSize + payload.size() +
               (has_session_id() ? SessionId::kSize : 0);
    }

    /// v3.3.0 突破2: 给定 payload 长度的总线字节数（静态，供预分配）。
    /// V3.4 P3: has_sid 参数控制是否额外 +16B session_id（默认 false，向后兼容）。
    static constexpr std::size_t total_wire_size(
        std::size_t payload_len, bool has_sid = false) noexcept {
        return kHeaderSize + payload_len + (has_sid ? SessionId::kSize : 0);
    }

    /// 从字节流解析一条完整消息。
    ///
    /// \param buffer 输入字节流
    /// \param out    输出解析结果
    /// \return 0 = 数据不足或格式错误（buffer 应保留等待更多数据），
    ///         n = 成功消费 n 字节（buffer 应前移 n 字节）
    static std::size_t parse(std::span<const std::uint8_t> buffer,
                              ApplicationMessage &out);

    /// 校验消息头是否合法（magic / version / payload_len）。
    static bool validate_header(std::span<const std::uint8_t> header_bytes);

    // ========== 工厂方法 ==========

    /// 构造 Request 消息（id > 0）。
    static ApplicationMessage request(std::uint32_t id, MethodId method,
                                       std::span<const std::uint8_t> payload);

    /// 便捷重载：接受 std::vector（MSVC span 不支持 initializer_list 直接构造）。
    static ApplicationMessage request(std::uint32_t id, MethodId method,
                                       const std::vector<std::uint8_t> &payload) {
        return request(id, method,
                       std::span<const std::uint8_t>(payload.data(), payload.size()));
    }

    /// 构造 Response 消息（id 与对应 Request 一致）。
    static ApplicationMessage response(std::uint32_t id, MethodId method,
                                        std::span<const std::uint8_t> payload);

    /// 便捷重载：接受 std::vector。
    static ApplicationMessage response(std::uint32_t id, MethodId method,
                                        const std::vector<std::uint8_t> &payload) {
        return response(id, method,
                        std::span<const std::uint8_t>(payload.data(), payload.size()));
    }

    /// 构造 ErrorResponse 消息（payload 为 UTF-8 错误描述）。
    static ApplicationMessage error(std::uint32_t id, MethodId method,
                                     const std::string &error_msg);

    /// 构造 Notification 消息（id 固定为 0）。
    static ApplicationMessage notification(MethodId method,
                                            std::span<const std::uint8_t> payload);

    /// 便捷重载：接受 std::vector。
    static ApplicationMessage notification(MethodId method,
                                            const std::vector<std::uint8_t> &payload) {
        return notification(method,
                            std::span<const std::uint8_t>(payload.data(), payload.size()));
    }

    // ========== 便捷判定 ==========

    bool is_request() const  { return msg_type == MessageType::Request; }
    bool is_response() const { return msg_type == MessageType::Response; }
    bool is_error() const    { return msg_type == MessageType::ErrorResponse; }
    bool is_notification() const { return msg_type == MessageType::Notification; }

    // ========== P1-8: flags 便捷判定 ==========

    bool is_compressed() const noexcept {
        return has_flag(flags, MessageFlags::PayloadCompressed);
    }
    bool is_encrypted() const noexcept {
        return has_flag(flags, MessageFlags::PayloadEncrypted);
    }
    bool is_signed() const noexcept {
        return has_flag(flags, MessageFlags::PayloadSigned);
    }
    bool is_fragment() const noexcept {
        return has_flag(flags, MessageFlags::Fragment);
    }
    bool is_last_fragment() const noexcept {
        return has_flag(flags, MessageFlags::LastFragment);
    }
    bool end_of_stream() const noexcept {
        return has_flag(flags, MessageFlags::EndOfStream);
    }

    /// P1-8: 设置单个 flag 位（保留其他位）
    void set_flag(MessageFlags bit) noexcept {
        flags |= static_cast<std::uint16_t>(bit);
    }

    /// P1-8: 清除单个 flag 位（保留其他位）
    void clear_flag(MessageFlags bit) noexcept {
        flags &= ~static_cast<std::uint16_t>(bit);
    }

    // ========== V3.4 P3: SessionId 会话标识 ==========

    /// 设置 SessionId（自动置 HasSessionId flag）
    /// @param sid 推理会话 ID（UUID v4）
    void set_session_id(const SessionId &sid) {
        session_id_ = sid;
        set_flag(MessageFlags::HasSessionId);
    }

    /// 获取 SessionId（仅当 HasSessionId 置位时有值）
    /// @return SessionId 的 optional；未设置返回 nullopt
    std::optional<SessionId> get_session_id() const noexcept {
        return session_id_;
    }

    /// 是否携带 SessionId（检查 HasSessionId flag）
    bool has_session_id() const noexcept {
        return has_flag(flags, MessageFlags::HasSessionId);
    }

    /// 清除 SessionId（清除 session_id_ 成员 + HasSessionId flag）
    void clear_session_id() noexcept {
        session_id_.reset();
        clear_flag(MessageFlags::HasSessionId);
    }

    // ========== V3.4 P3: 按需压缩（zstd） ==========

    /// 压缩 payload（按算法选择），成功后置对应压缩 flag
    /// @param algo 压缩算法（None=不操作返回 true，Zstd=压缩置 ZstdCompressed，
    ///             Gzip=未实现返回 false）
    /// @param level 压缩级别（zstd: 1-22，0=默认 3）
    /// @return true=成功（含 None no-op）；false=压缩失败或算法未实现
    /// @note 空 payload 不压缩（返回 true）；压缩 + session_id 组合时
    ///       serialize 先压缩 payload 再前置 session_id（session_id 不参与压缩）
    bool compress(CompressionAlgo algo, int level = 0);

    /// 解压 payload（根据压缩 flag 自动选择算法），成功后清压缩 flag
    /// @return true=成功（含无压缩 flag 的 no-op）；false=解压失败或算法未实现
    /// @note ZstdCompressed → zstd 解压；PayloadCompressed → gzip（未实现返回 false）；
    ///       两者均无 → no-op 返回 true；两者同时置位 → 返回 false（非法状态）
    bool decompress();

    /// 是否已用 zstd 压缩（检查 ZstdCompressed flag）
    bool is_zstd_compressed() const noexcept {
        return has_flag(flags, MessageFlags::ZstdCompressed);
    }

    // ========== O1: 协议字典压缩 ==========

    /// 是否已用协议字典 zstd 压缩（检查 ZstdDictCompressed flag）
    bool is_zstd_dict_compressed() const noexcept {
        return has_flag(flags, MessageFlags::ZstdDictCompressed);
    }

    /// 用协议字典压缩 payload（O1）
    /// @param dict_id 字典编号（须已 load_protocol_dict 加载）
    /// @param level 压缩级别（0=默认 3）
    /// @return true=压缩成功并置 ZstdDictCompressed；false=字典未加载/压缩失败/
    ///         结果不小于原始（不值得）/payload 为空（no-op 返回 false 不置位）/
    ///         已置任意压缩 flag（互斥）
    /// @note wire payload = [dict_id: 1B][zstd frame]；session_id 不参与压缩
    bool compress_dict(std::uint8_t dict_id, int level = 0);

    /// 按当前策略自动压缩（O1，由 Connection 发送 helper 调用）
    /// 条件：auto_compress_enabled() && payload 非空 && 未压缩过 &&
    ///       recommend_compression(method, size) == Zstd
    /// 字典优先：已加载字典时尝试 compress_dict，失败回退普通 zstd。
    /// @return true=已压缩（flag 置位）；false=未压缩（任何原因）
    bool maybe_auto_compress();

    /// O1.2（独立项目方案 W1.1）：带对端能力位的自动压缩。
    /// Connection 层自动传入缓存的对端 capabilities_mask；直接调用时
    /// 默认 0xFFFFFFFF（调用方自担"已确认对端支持"的语义）。
    /// 降级矩阵：
    ///   含 kCapZstdDict(0x0100)  → 字典优先 → 回退普通 zstd → 不压
    ///   含 kCapZstdCompressed(0x0010)（无 0x0100）→ 仅普通 zstd
    ///   两者皆无 / mask=0（未探测）→ 不压缩（混跑安全默认）
    bool maybe_auto_compress(std::uint32_t peer_capabilities);

    /// 按压缩 flag 自动解压（O1 接收侧）
    /// 无压缩 flag 时 no-op 返回 true；decompress() 的薄别名，供接收
    /// 分发路径显式调用（失败 = payload 损坏/字典缺失，调用方应丢弃消息）
    bool maybe_auto_decompress() { return decompress(); }
};

}  // namespace linoh::protocol
