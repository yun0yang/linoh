// ports.hpp — 端口规划（P5-C-4）
//
// 借鉴 Sunshine map_port(offset)：
//   - 统一管理 linoh 各服务端口，避免硬编码分散
//   - 支持 port_offset 配置偏移（用于一台机器跑多实例）
//   - 多模态通道端口从 9100 开始，按 ChannelType 偏移
//
// 端口规划表（遵循"不新增外网端口"约束）：
//   | 端口 | 用途 | 外网开放 |
//   | 9000 | VMS | 是 |
//   | 9001 | linoh bootstrap | 是 |
//   | 9002 | linoh relay | 是 |
//   | 9003 | linoh relay TLS（备用） | 是 |
//   | 9100-9105 | 多模态通道（仅内网） | 否 |
//   | 5333 | DNS 内部 | 否 |
//   | 9999 | orchestrator | 是 |
//
// 注意：多模态通道端口（9100-9105）仅内网使用，不申请新外网端口。

#pragma once

#include <cstdint>
#include <string>

namespace linoh::util {

/// 基础端口（所有 linoh 服务从此偏移）
constexpr std::uint16_t PORT_BASE = 9000;

/// 多模态通道端口起始（仅内网）
constexpr std::uint16_t PORT_CHANNEL_BASE = 9100;

/// 内部 DNS 端口（不对外）
constexpr std::uint16_t PORT_DNS_INTERNAL = 5333;

/// orchestrator HTTP REST 端口
constexpr std::uint16_t PORT_ORCHESTRATOR = 9999;

// --------------------------------------------------------------------------
// 基础端口（固定，不受 port_offset 影响）
// --------------------------------------------------------------------------

/// linoh bootstrap 端口（worker JOIN 用，UDP）
constexpr std::uint16_t port_bootstrap() { return PORT_BASE + 1; }  // 9001

/// linoh relay 端口（UDP/TCP，兼容 iroh relay v2）
constexpr std::uint16_t port_relay() { return PORT_BASE + 2; }  // 9002

/// linoh relay TLS 端口（备用，wss://）
constexpr std::uint16_t port_relay_tls() { return PORT_BASE + 3; }  // 9003

/// VMS 端口
constexpr std::uint16_t port_vms() { return PORT_BASE; }  // 9000

/// DNS 内部端口
constexpr std::uint16_t port_dns_internal() { return PORT_DNS_INTERNAL; }  // 5333

/// orchestrator HTTP REST 端口
constexpr std::uint16_t port_orchestrator() { return PORT_ORCHESTRATOR; }  // 9999

// --------------------------------------------------------------------------
// 多模态通道端口（仅内网，按 ChannelType 偏移）
// --------------------------------------------------------------------------

/// 多模态通道类型枚举（与 multimodal::ChannelType 对应）
enum class ChannelPortType : std::uint8_t {
    CONTROL       = 0,  // 9100
    LLM_HIDDEN    = 1,  // 9101
    IMG_FEATURE   = 2,  // 9102
    VIDEO_FEATURE = 3,  // 9103
    AUDIO_FEATURE = 4,  // 9104
    FUSION        = 5,  // 9105
};

/// 多模态通道端口（仅内网）
constexpr std::uint16_t port_channel(ChannelPortType type) {
    return PORT_CHANNEL_BASE + static_cast<std::uint16_t>(type);
}

/// 多模态通道端口（按整数偏移）
constexpr std::uint16_t port_channel(std::uint8_t channel_type) {
    return PORT_CHANNEL_BASE + channel_type;
}

// --------------------------------------------------------------------------
// 端口名称（用于日志/配置）
// --------------------------------------------------------------------------

/// 端口名称（用于日志输出）
constexpr const char* port_name_bootstrap() { return "linoh_bootstrap"; }
constexpr const char* port_name_relay() { return "linoh_relay"; }
constexpr const char* port_name_relay_tls() { return "linoh_relay_tls"; }
constexpr const char* port_name_vms() { return "vms"; }
constexpr const char* port_name_dns() { return "linoh_dns_internal"; }
constexpr const char* port_name_orchestrator() { return "orchestrator"; }

/// 多模态通道端口名称
constexpr const char* port_name_channel(ChannelPortType type) {
    switch (type) {
        case ChannelPortType::CONTROL:       return "ctrl_channel";
        case ChannelPortType::LLM_HIDDEN:    return "llm_channel";
        case ChannelPortType::IMG_FEATURE:   return "img_channel";
        case ChannelPortType::VIDEO_FEATURE: return "video_channel";
        case ChannelPortType::AUDIO_FEATURE: return "audio_channel";
        case ChannelPortType::FUSION:        return "fusion_channel";
    }
    return "unknown_channel";
}

// --------------------------------------------------------------------------
// PortMapper：支持 port_offset 偏移（一台机器跑多实例）
// --------------------------------------------------------------------------

/// @brief 端口映射器（支持偏移配置）
///
/// 用法：
/// @code
///   PortMapper mapper;            // 默认 offset=0
///   mapper.bootstrap();           // 9001
///
///   PortMapper offsetted(100);    // offset=100
///   offsetted.bootstrap();        // 9101
///   offsetted.channel(ChannelPortType::LLM_HIDDEN);  // 9201
/// @endcode
class PortMapper {
public:
    /// @param offset 端口偏移（用于多实例部署）
    constexpr explicit PortMapper(std::uint16_t offset = 0) : offset_(offset) {}

    /// 偏移量
    constexpr std::uint16_t offset() const noexcept { return offset_; }

    /// 是否启用偏移
    constexpr bool has_offset() const noexcept { return offset_ > 0; }

    // 基础服务端口（受 offset 影响）
    constexpr std::uint16_t bootstrap() const noexcept {
        return static_cast<std::uint16_t>(PORT_BASE + 1 + offset_);
    }
    constexpr std::uint16_t relay() const noexcept {
        return static_cast<std::uint16_t>(PORT_BASE + 2 + offset_);
    }
    constexpr std::uint16_t relay_tls() const noexcept {
        return static_cast<std::uint16_t>(PORT_BASE + 3 + offset_);
    }
    constexpr std::uint16_t vms() const noexcept {
        return static_cast<std::uint16_t>(PORT_BASE + offset_);
    }

    // 多模态通道端口（受 offset 影响）
    constexpr std::uint16_t channel(ChannelPortType type) const noexcept {
        return static_cast<std::uint16_t>(PORT_CHANNEL_BASE +
                                          static_cast<std::uint16_t>(type) + offset_);
    }
    constexpr std::uint16_t channel(std::uint8_t channel_type) const noexcept {
        return static_cast<std::uint16_t>(PORT_CHANNEL_BASE + channel_type + offset_);
    }

    // 固定端口（不受 offset 影响）
    constexpr std::uint16_t dns_internal() const noexcept { return PORT_DNS_INTERNAL; }
    constexpr std::uint16_t orchestrator() const noexcept { return PORT_ORCHESTRATOR; }

    /// 端口范围检查
    constexpr bool is_valid_port(std::uint16_t p) const noexcept {
        return p > 0 && p <= 65535;
    }

    /// 是否是 linoh 内部端口（用于防火墙配置）
    constexpr bool is_linoh_port(std::uint16_t p) const noexcept {
        if (p == dns_internal() || p == orchestrator()) return true;
        if (p >= vms() && p <= relay_tls()) return true;
        if (p >= channel(ChannelPortType::CONTROL) &&
            p <= channel(ChannelPortType::FUSION)) return true;
        return false;
    }

    /// 是否外网开放端口
    constexpr bool is_public_port(std::uint16_t p) const noexcept {
        // 外网开放：vms/bootstrap/relay/relay_tls/orchestrator
        // 不开放：dns_internal + 多模态通道
        if (p == dns_internal()) return false;
        if (p >= channel(ChannelPortType::CONTROL) &&
            p <= channel(ChannelPortType::FUSION)) return false;
        if (p == vms() || p == bootstrap() || p == relay() ||
            p == relay_tls() || p == orchestrator()) return true;
        return false;
    }

private:
    std::uint16_t offset_;
};

// --------------------------------------------------------------------------
// 便捷全局函数（使用默认 PortMapper）
// --------------------------------------------------------------------------

namespace defaults {
    constexpr std::uint16_t bootstrap = port_bootstrap();
    constexpr std::uint16_t relay = port_relay();
    constexpr std::uint16_t relay_tls = port_relay_tls();
    constexpr std::uint16_t vms = port_vms();
    constexpr std::uint16_t dns = port_dns_internal();
    constexpr std::uint16_t orchestrator = port_orchestrator();
    constexpr std::uint16_t channel_ctrl = port_channel(ChannelPortType::CONTROL);
    constexpr std::uint16_t channel_llm = port_channel(ChannelPortType::LLM_HIDDEN);
    constexpr std::uint16_t channel_img = port_channel(ChannelPortType::IMG_FEATURE);
    constexpr std::uint16_t channel_video = port_channel(ChannelPortType::VIDEO_FEATURE);
    constexpr std::uint16_t channel_audio = port_channel(ChannelPortType::AUDIO_FEATURE);
    constexpr std::uint16_t channel_fusion = port_channel(ChannelPortType::FUSION);
}  // namespace defaults

}  // namespace linoh::util
