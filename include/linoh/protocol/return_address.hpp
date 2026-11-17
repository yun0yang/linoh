// return_address.hpp — Direct Return Path 地址信息（v3.2.0）
//
// 在 PP 链 ForwardPP 消息的 payload 头部携带可选的 ReturnAddress，供末节点
// 推理完成后直连 MASTER 回传 RESULT，绕过逐跳反向中继（N 跳 → 1 跳）。
//
// 设计要点：
//   - 字段定长 40 字节（marker 1B + master_endpoint 32B + stream_token 4B + reserved 3B）
//   - marker=0xD7 用于快速校验 ReturnAddress 是否存在（避免旧节点误判）
//   - master_endpoint 为 MASTER 的 Ed25519 公钥（EndpointId），末节点据此 dial 直连
//   - stream_token 为 MASTER 预分配的 return stream 标识（hash(req_id+timestamp) 低 32 位）
//   - reserved 3B 保留扩展（未来可放 dtype/MTU 协商），当前全 0
//
// 与 ApplicationMessage 的关系：
//   - 仅当 ForwardPP 的 flags 含 HasReturnAddress=0x0040 时，payload 起始 40B 为 ReturnAddress
//   - 之后才是真正的 hidden_state 字节流
//   - 旧节点不识别 HasReturnAddress（需先经 ReturnAddrProbe 能力探测），不会误处理
//
// 字节序：stream_token 使用大端（网络）字节序，与 application_message.hpp 一致。
//
// 编码后布局（40 字节）：
//   offset  size  field
//   0       1     marker (0xD7)
//   1       32    master_endpoint (Ed25519 公钥，原样写入)
//   33      4     stream_token (大端 uint32)
//   37      3     reserved (0x00 填充)

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace linoh::protocol {

/// Direct Return Path 地址信息（v3.2.0）
///
/// 携带在 ForwardPP payload 头部（仅当 ApplicationMessage.flags 含
/// HasReturnAddress 时）。末节点提取后用于：
///   1. dial master_endpoint 建立 P2P 直连（pp-llm/1 ALPN）
///   2. 在直连上 open_stream，发送 ResultPP[DirectReturn=1]
///   3. payload 头部写入 stream_token 供 MASTER 路由匹配
struct ReturnAddress {
    /// 魔数标记，用于校验 ReturnAddress 字段存在性
    static constexpr std::uint8_t kMarker = 0xD7;

    /// 编码后的固定字节数
    static constexpr std::size_t kEncodedSize = 40;

    /// MASTER 的 Ed25519 公钥（EndpointId，32 字节）
    std::array<std::uint8_t, 32> master_endpoint{};

    /// MASTER 预分配的 return stream 标识
    /// 生成规则：fnv1a_64(req_id || timestamp_ms) 取低 32 位
    /// MASTER 端维护 (stream_token → ReturnSlot) 映射用于路由
    std::uint32_t stream_token{0};

    /// 保留扩展字段（当前全 0，未来可用于 dtype/MTU 协商）
    std::array<std::uint8_t, 3> reserved{};

    // ========================================================================
    // 编码 / 解码
    // ========================================================================

    /// 编码为 40 字节（含 marker 前缀）
    /// \return 40 字节字节流：[marker(1)][master_endpoint(32)][stream_token(4,BE)][reserved(3)]
    std::vector<std::uint8_t> encode() const;

    /// 从 payload 起始位置尝试解码 ReturnAddress
    ///
    /// \param data payload 字节流（从 ForwardPP.payload 起始）
    /// \param out  输出 ReturnAddress（仅当返回 40 时有效）
    /// \return 0  = 首字节不是 marker（无 ReturnAddress，payload 为纯 hidden_state）
    ///         40 = 成功消费 40 字节（调用方应从 offset=40 起读取 hidden_state）
    ///
    /// 注意：data 长度 < 40 时返回 0（视为无 ReturnAddress）
    static std::size_t try_decode(std::span<const std::uint8_t> data,
                                   ReturnAddress &out);

    // ========================================================================
    // payload 分离工具
    // ========================================================================

    /// 从 ForwardPP 完整 payload 中分离 ReturnAddress 与 hidden_state
    ///
    /// \param full_payload ForwardPP 完整 payload（可能含 ReturnAddress 前缀）
    /// \param addr 输出 ReturnAddress（若存在），不存在时为 nullopt
    /// \return hidden_state 字节流（剥离 ReturnAddress 前缀后的部分）
    ///
    /// 用法（末节点收到 ForwardPP 后）：
    ///   std::optional<ReturnAddress> addr;
    ///   auto hidden = ReturnAddress::strip_address(msg.payload, addr);
    ///   if (addr) { /* 启用直连回传 */ } else { /* 走逐跳反向 */ }
    static std::vector<std::uint8_t> strip_address(
        std::span<const std::uint8_t> full_payload,
        std::optional<ReturnAddress> &addr);

    /// 将 ReturnAddress 前缀拼接到 hidden_state 前，构造完整 ForwardPP payload
    ///
    /// 用法（MASTER 发送 ForwardPP 时）：
    ///   auto payload = ReturnAddress::prepend_address(addr, hidden_state);
    ///   msg.flags |= MessageFlags::HasReturnAddress;
    ///   msg.payload = payload;
    static std::vector<std::uint8_t> prepend_address(
        const ReturnAddress &addr,
        std::span<const std::uint8_t> hidden_state);
};

/// ReturnAddrAck payload 序列化结构（MethodId::ReturnAddrAck 的 payload）
///
/// WORKER 响应 MASTER 的 ReturnAddrProbe，携带本端能力与 EndpointId。
/// 编码格式（变长，但字段定长）：
///   offset  size  field
///   0       1     supported (0=不支持, 1=支持)
///   1       2     version (大端 uint16, 当前 0x0100 = v1.0)
///   3       32    worker_endpoint (Ed25519 公钥，supported=1 时有效，supported=0 时全 0)
struct ReturnAddrAckPayload {
    bool supported{false};
    std::uint16_t version{0x0100};
    std::array<std::uint8_t, 32> worker_endpoint{};

    /// 序列化为字节流（35 字节）
    std::vector<std::uint8_t> encode() const;

    /// 从字节流反序列化
    /// \return true=成功，false=数据格式错误
    static bool decode(std::span<const std::uint8_t> data, ReturnAddrAckPayload &out);
};

}  // namespace linoh::protocol
