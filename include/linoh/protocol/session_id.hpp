// session_id.hpp — V3.4 推理会话 ID（UUID v4）
//
// 16 字节 UUID v4，用于推理会话级去重/关联。借鉴 gpustack
// websocket_proxy/message.py 的 session_id 设计（详见
// docs/GPUSTACK_NETWORK_ANALYSIS.md Top 2 与
// docs/LINOH_EVENTBUS_BINARY_FRAME_IMPL_PLAN.md §3.3.2）。
//
// 使用场景：
//   - PP 推理请求：MASTER 生成 SessionId，ForwardPP / ResultPP 共享同一 SessionId
//   - 跨域摘要：域代表生成 SessionId，Digest / DigestReq 共享
//   - 去重：接收方缓存近 N 个 SessionId，重复消息丢弃（防重放/防网络抖动重复）
//
// 生成：SessionId::generate()（线程安全，基于 linoh::crypto::crypto_random_bytes
//       即 Windows BCryptGenRandom / 等价 CSPRNG，再设置 v4 version/variant 位）
// 序列化：16B 固定布局，原样字节序（UUID v4 标准字节序，无需大端转换）
//
// UUID v4 格式（RFC 4122）：
//   bytes[6] = (bytes[6] & 0x0F) | 0x40   // version = 4
//   bytes[8] = (bytes[8] & 0x3F) | 0x80   // variant = RFC 4122
//   字符串：xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx（8-4-4-4-12，小写十六进制）
//
// 与 ApplicationMessage 的关系（P3-2 集成阶段）：
//   - 仅当 ApplicationMessage.flags 含 HasSessionId(0x0200) 时，payload 头部 16B 为 SessionId
//   - 之后才是真正的 payload 字节流
//   - 旧节点不识别 HasSessionId（需先经能力探测），不会误处理
//
// 与 SessionDeduper 的关系（P3-2）：
//   - 接收方用 SessionDeduper 缓存近 N 个 SessionId 做去重（LRU 淘汰）

#pragma once

#include <array>
#include <cstdint>
#include <cstring>      // std::memcpy（std::hash 特化用）
#include <functional>   // std::hash
#include <optional>
#include <span>
#include <string>

namespace linoh::protocol {

/// 会话 ID（16 字节 UUID v4），用于推理会话级去重/关联。
///
/// 设计要点：
///   - 16 字节定长，序列化/反序列化零额外开销（memcpy 16B）
///   - generate() 使用 crypto_random_bytes（加密级 CSPRNG），线程安全
///   - 比较运算符 + std::hash 特化，可直接用于 unordered_set/unordered_map
///   - to_string() 输出标准 UUID 格式（日志/调试用，36 字符含 4 个连字符）
///   - is_null() 判断零值（generate 失败或默认构造时为 true）
struct SessionId {
    /// UUID v4 字节长度
    static constexpr std::size_t kSize = 16;

    /// 16 字节 UUID v4 数据（默认全零 = 未设置）
    std::array<std::uint8_t, kSize> bytes{};

    // ========================================================================
    // 工厂 / 序列化
    // ========================================================================

    /// 生成随机 SessionId（UUID v4）
    /// @note 线程安全；基于 linoh::crypto::crypto_random_bytes（加密级 CSPRNG）
    ///       CSPRNG 失败时返回全零 sid（is_null()==true），调用方应检查并决定重试
    static SessionId generate();

    /// 从字节流解析 16B SessionId
    /// @param in 输入字节流（长度 >= 16 时取前 16B）
    /// @return 解析结果；in.size() < 16 返回 nullopt
    /// @note 不校验 version/variant 位（容忍非 v4 UUID，兼容外部生成的 UUID）
    static std::optional<SessionId> parse(std::span<const std::uint8_t> in);

    /// 序列化到 16B 输出缓冲
    /// @param out 固定 16B span（编译期 extent 校验）
    void serialize_to(std::span<std::uint8_t, kSize> out) const;

    // ========================================================================
    // 查询
    // ========================================================================

    /// 是否为零值（未设置）
    bool is_null() const noexcept;

    /// UUID 字符串表示（8-4-4-4-12 小写十六进制，36 字符含连字符）
    std::string to_string() const;

    // ========================================================================
    // 比较（用于容器去重）
    // ========================================================================

    bool operator==(const SessionId &) const = default;
};

}  // namespace linoh::protocol

// ============================================================================
// std::hash 特化（用于 unordered_set / unordered_map 去重）
// ============================================================================
namespace std {

template <>
struct hash<linoh::protocol::SessionId> {
    size_t operator()(const linoh::protocol::SessionId &sid) const noexcept {
        // 16 字节折叠为 8 字节哈希
        // memcpy 安全处理对齐（std::array<uint8_t,16> 内部对齐为 1，reinterpret_cast 会 UB）
        std::uint64_t lo = 0, hi = 0;
        std::memcpy(&lo, sid.bytes.data(), 8);
        std::memcpy(&hi, sid.bytes.data() + 8, 8);
        return std::hash<std::uint64_t>{}(lo ^ hi);
    }
};

}  // namespace std
