// crypto_level.cpp — 加密模式分级实现（P5-B-2）

#include "linoh/tls/crypto_level.hpp"

namespace linoh::tls {

// ============================================================================
// classify_network
// ============================================================================

NetworkClass classify_network(const net::NetReport &report) noexcept {
    // UDP 被防火墙阻断 → 困难网络
    if (report.udp_firewall == net::UdpFirewall::Blocked) {
        return NetworkClass::Hard;
    }
    // 对称 NAT（hard NAT）→ 困难网络
    if (report.nat_type == net::NatType::Symmetric) {
        return NetworkClass::Hard;
    }
    // 探测失败 → 保守按困难网络处理
    if (report.nat_type == net::NatType::Unknown) {
        return NetworkClass::Hard;
    }
    // OpenInternet / FullCone → 局域网/公网直连
    if (report.nat_type == net::NatType::OpenInternet ||
        report.nat_type == net::NatType::FullCone) {
        return NetworkClass::Lan;
    }
    // RestrictedCone / PortRestrictedCone → 广域网
    return NetworkClass::Wan;
}

// ============================================================================
// select_crypto_level
// ============================================================================

CryptoLevel select_crypto_level(NetworkClass net_class,
                                 multimodal::ChannelType channel) noexcept {
    // 选择策略矩阵（行=网络，列=模态）
    //                LLM          IMG          VIDEO        AUDIO        CTRL         FUSION
    // Lan         Strong       Standard     Light        Standard     Strong       Strong
    // Wan         Strong       Strong       Standard     Standard     Strong       Strong
    // Hard        Maximum      Strong       Standard     Standard     Maximum      Maximum

    using CL = multimodal::CryptoLevel;
    using CT = multimodal::ChannelType;

    // 默认值（CONTROL 在所有网络下都 Strong，Hard 网络下升 Maximum）
    const CL lan_default  = CL::Strong;
    const CL hard_default = CL::Maximum;

    // 按模态选择基础级别（Lan 网络下的级别）
    CL base;
    switch (channel) {
        case CT::LLM_HIDDEN:
            base = CL::Strong;     // LLM 始终强加密
            break;
        case CT::IMG_FEATURE:
            base = CL::Standard;   // 图片：Lan=Standard, Wan/Hard 升 Strong
            break;
        case CT::VIDEO_FEATURE:
            base = CL::Light;      // 视频：Lan=Light, Wan=Standard, Hard=Standard
            break;
        case CT::AUDIO_FEATURE:
            base = CL::Standard;   // 音频：所有网络 Standard
            break;
        case CT::CONTROL:
            base = CL::Strong;     // 控制：Lan/Wan=Strong, Hard=Maximum
            break;
        case CT::FUSION:
            base = CL::Strong;     // 融合：Lan/Wan=Strong, Hard=Maximum
            break;
        default:
            base = CL::Strong;
            break;
    }

    // 按网络分级调整
    switch (net_class) {
        case NetworkClass::Lan:
            return base;  // Lan：使用基础级别

        case NetworkClass::Wan:
            // Wan：视频 Light→Standard，图片 Standard→Strong，其他不变
            if (channel == CT::VIDEO_FEATURE && base == CL::Light) {
                return CL::Standard;
            }
            if (channel == CT::IMG_FEATURE && base == CL::Standard) {
                return CL::Strong;
            }
            return base;

        case NetworkClass::Hard:
            // Hard：LLM/CTRL/FUSION 升 Maximum，其他保持 Strong 以上
            if (channel == CT::LLM_HIDDEN ||
                channel == CT::CONTROL ||
                channel == CT::FUSION) {
                return CL::Maximum;
            }
            // 视频/音频：Standard（与 Wan 相同）
            if (channel == CT::VIDEO_FEATURE || channel == CT::AUDIO_FEATURE) {
                return CL::Standard;
            }
            // 图片：Strong
            return CL::Strong;
    }

    // 兜底（不应到达）
    (void)lan_default;
    (void)hard_default;
    return CL::Strong;
}

CryptoLevel select_crypto_level(const net::NetReport &report,
                                 multimodal::ChannelType channel) noexcept {
    return select_crypto_level(classify_network(report), channel);
}

// ============================================================================
// crypto_spec_for
// ============================================================================

CryptoSpec crypto_spec_for(CryptoLevel level) noexcept {
    using CL = multimodal::CryptoLevel;
    switch (level) {
        case CL::None:
            return {CL::None,      "None",                0,   false};
        case CL::Light:
            return {CL::Light,     "ChaCha20-Poly1305",   256, false};
        case CL::Standard:
            return {CL::Standard,  "AES-128-GCM",         128, false};
        case CL::Strong:
            return {CL::Strong,    "AES-256-GCM",         256, false};
        case CL::Maximum:
            return {CL::Maximum,   "AES-256-GCM",         256, true};
    }
    return {CL::None, "None", 0, false};
}

}  // namespace linoh::tls
