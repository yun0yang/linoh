// capabilities.hpp — V3.5 节点能力探测（P5-A）
//
// 统一的能力探测协议，借鉴 v3.2.0 ReturnAddrProbe/Ack 模式（走 ctrl/1 ALPN）。
// MASTER 在 WORKER Join 后发送 CapabilitiesProbe(0x0062)，WORKER 回复
// CapabilitiesAck(0x0063) 携带本端支持的能力位掩码。
//
// 设计要点：
//   - 统一探测：CapabilitiesProbe 涵盖所有新 flag 能力（HasReturnAddress/
//     DirectReturn/ResultShard/HasSessionId/ZstdCompressed），替代分散探测
//   - 向后兼容：旧节点不识别 CapabilitiesProbe MethodId，丢弃或超时降级
//     （capabilities_mask=0，所有新 flag 不使用）
//   - 位掩码紧凑：4B 覆盖 32 种能力，扩展性强
//   - 与 ReturnAddrProbe 并存：ReturnAddrProbe 保留向后兼容，新节点优先用
//     CapabilitiesProbe（包含 Direct Return 能力位）
//
// CapabilitiesAckPayload 编码布局（40 字节，v3.9.5 扩展）：
//   offset  size  field
//   0       1     supported (0=不支持/旧节点, 1=支持)
//   1       2     version (大端 uint16, 当前 0x0100 = v1.0)
//   3       4     capabilities_mask (大端 uint32, 位掩码)
//   7       32    peer_endpoint (Ed25519 公钥，supported=1 时有效，supported=0 时全 0)
//   39      1     node_role (v3.9.5 M5: 节点角色, 0=Unknown, 1=Master, 2=Worker,
//                3=TempWorker, 4=Relay, 5=Observer; 与 multimodal::NodeRole 枚举值对齐)
//
// 向后兼容：旧节点发送 39 字节（无 node_role），decode 时长度 < 40 → node_role=0(Unknown)
//
// capabilities_mask 位定义：
//   0x0001  kCapHasReturnAddress  ForwardPP payload 携带 ReturnAddress（v3.2.0）
//   0x0002  kCapDirectReturn      ResultPP 直连回传（v3.2.0）
//   0x0004  kCapResultShard       大 RESULT 分片传输（v3.2.1）
//   0x0008  kCapHasSessionId      payload 头部携带 SessionId（v3.4.0 P4）
//   0x0010  kCapZstdCompressed    payload 支持 zstd 压缩（v3.4.0 P4）
//   0x0020  kCapZeroRtt           支持 0-RTT 重连（v5.0.0，SESSION_TICKET + ZERO_RTT_DATA）
//   0x0040  kCapQad               支持 QUIC Address Discovery（v5.0.0，替代 STUN）
//   0x0080  kCapHardNat           支持 Hard-NAT 双向端口预测打洞（v5.0.0）
//   0x0100  kCapZstdDict          支持协议字典 zstd 压缩（O1，编码层优化方案；
//                                 ZstdDictCompressed flag + [dict_id:1B] wire 前缀。
//                                 协商联动为 O1.2，本期仅定义位常量）
//   0x0200+ 预留扩展
//
// 字节序：capabilities_mask 使用大端（网络）字节序，与 application_message.hpp 一致。

#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace linoh::protocol {

/// 能力位掩码常量（对应 ApplicationMessage flags 的新增能力）
/// 用于 CapabilitiesAckPayload.capabilities_mask 位判定
enum CapabilitiesMask : std::uint32_t {
    kCapNone              = 0x0000,  // 无能力（旧节点）
    kCapHasReturnAddress  = 0x0001,  // ForwardPP 携带 ReturnAddress（v3.2.0）
    kCapDirectReturn      = 0x0002,  // ResultPP 直连回传（v3.2.0）
    kCapResultShard       = 0x0004,  // 大 RESULT 分片（v3.2.1）
    kCapHasSessionId      = 0x0008,  // payload 携带 SessionId（v3.4.0 P4）
    kCapZstdCompressed    = 0x0010,  // payload 支持 zstd 压缩（v3.4.0 P4）
    // v5.0.0 阶段四新增能力位（T-LP4-007）
    kCapZeroRtt           = 0x0020,  // 支持 0-RTT 重连（SESSION_TICKET + ZERO_RTT_DATA）
    kCapQad               = 0x0040,  // 支持 QUIC Address Discovery（替代 STUN）
    kCapHardNat           = 0x0080,  // 支持 Hard-NAT 双向端口预测打洞
    kCapZstdDict          = 0x0100,  // 支持协议字典 zstd 压缩（O1）
    // 0x0200+ 预留扩展
};

/// 判定 mask 是否包含指定能力位
/// @param mask 能力位掩码
/// @param bit  能力位常量（kCap*）
/// @return true=包含该能力
inline bool has_capability(std::uint32_t mask, CapabilitiesMask bit) noexcept {
    return (mask & static_cast<std::uint32_t>(bit)) != 0;
}

/// 节点能力描述（解析后的便捷结构，供 ApplicationApi 缓存）
///
/// 由 CapabilitiesAckPayload 解析得到，或旧节点降级为 kCapNone。
/// ApplicationApi 据此决定发送消息时使用哪些新 flag。
struct NodeCapabilities {
    /// 能力位掩码（kCap* 组合）
    std::uint32_t mask{kCapNone};

    /// 协议版本（来自 AckPayload.version，0x0100 = v1.0）
    std::uint16_t version{0};

    /// 是否已探测（false=未探测/超时降级，true=已收到 Ack）
    bool probed{false};

    // ========== 便捷判定（基于 mask） ==========

    bool supports_return_address() const noexcept {
        return has_capability(mask, kCapHasReturnAddress);
    }
    bool supports_direct_return() const noexcept {
        return has_capability(mask, kCapDirectReturn);
    }
    bool supports_result_shard() const noexcept {
        return has_capability(mask, kCapResultShard);
    }
    bool supports_session_id() const noexcept {
        return has_capability(mask, kCapHasSessionId);
    }
    bool supports_zstd_compression() const noexcept {
        return has_capability(mask, kCapZstdCompressed);
    }

    // ========== v5.0.0 阶段四能力便捷判定（T-LP4-007） ==========

    /// 是否支持 0-RTT 重连（SESSION_TICKET + ZERO_RTT_DATA 帧）
    bool supports_zero_rtt() const noexcept {
        return has_capability(mask, kCapZeroRtt);
    }
    /// 是否支持 QUIC Address Discovery（替代 STUN）
    bool supports_qad() const noexcept {
        return has_capability(mask, kCapQad);
    }
    /// 是否支持 Hard-NAT 双向端口预测打洞
    bool supports_hard_nat() const noexcept {
        return has_capability(mask, kCapHardNat);
    }

    /// 简要描述（日志用）
    std::string to_string() const;
};

/// CapabilitiesAck payload 序列化结构（MethodId::CapabilitiesAck 的 payload）
///
/// WORKER 响应 MASTER 的 CapabilitiesProbe，携带本端能力位掩码与 EndpointId。
/// 编码格式（39 字节定长）：
///   offset  size  field
///   0       1     supported (0=不支持, 1=支持)
///   1       2     version (大端 uint16, 当前 0x0100 = v1.0)
///   3       4     capabilities_mask (大端 uint32, 位掩码)
///   7       32    peer_endpoint (Ed25519 公钥，supported=1 时有效，supported=0 时全 0)
struct CapabilitiesAckPayload {
    static constexpr std::size_t kEncodedSize = 40;        // v3.9.5: 39→40（新增 node_role）
    static constexpr std::size_t kLegacyEncodedSize = 39;  // 旧节点兼容（无 node_role）
    static constexpr std::uint16_t kCurrentVersion = 0x0100;  // v1.0

    bool supported{false};
    std::uint16_t version{kCurrentVersion};
    std::uint32_t capabilities_mask{kCapNone};
    std::array<std::uint8_t, 32> peer_endpoint{};

    /// v3.9.5 (M5): 节点角色（0=Unknown, 1=Master, 2=Worker, 3=TempWorker, 4=Relay, 5=Observer）
    /// 与 multimodal::NodeRole 枚举值对齐，调用方可用 multimodal::role_from_uint() 转换
    std::uint8_t node_role{0};

    /// 序列化为字节流（40 字节）
    std::vector<std::uint8_t> encode() const;

    /// 从字节流反序列化
    /// @return true=成功，false=数据格式错误（长度不足）
    /// @note 兼容 39 字节旧格式（无 node_role → 默认 0=Unknown）
    static bool decode(std::span<const std::uint8_t> data, CapabilitiesAckPayload &out);

    /// 转换为 NodeCapabilities（便捷，供 ApplicationApi 缓存）
    NodeCapabilities to_node_capabilities() const noexcept {
        return NodeCapabilities{capabilities_mask, version, /*probed=*/true};
    }
};

}  // namespace linoh::protocol
