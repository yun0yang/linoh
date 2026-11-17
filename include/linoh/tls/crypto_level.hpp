// crypto_level.hpp — 加密模式分级（P5-B-2）
//
// 借鉴 Sunshine `encryption_mode_for_address` 思路：根据网络环境（LAN/WAN/CGN）
// 和模态（LLM/图片/视频/音频/控制）选择不同强度的加密算法。
//
// 设计原则：
//   - LLM hidden_state 始终强加密（AES-256-GCM），防止推理内容泄露
//   - 视频大流量在 LAN 下降级为 ChaCha20-Poly1305（性能优）
//   - CGN/Symmetric NAT 场景所有通道升级到 Maximum（AES-256-GCM + 额外 MAC）
//   - CryptoLevel 枚举复用 multimodal::CryptoLevel（已定义于 channel.hpp）
//
// 选择策略矩阵：
//   | 网络 \ 模态 | LLM | 图片 | 视频 | 音频 | 控制 | 融合 |
//   |---|---|---|---|---|---|---|
//   | Lan   | Strong   | Standard | Light    | Standard | Strong   | Strong   |
//   | Wan   | Strong   | Strong   | Standard | Standard | Strong   | Strong   |
//   | Hard  | Maximum  | Strong   | Standard | Standard | Maximum  | Maximum  |

#pragma once

#include "linoh/multimodal/channel.hpp"   // CryptoLevel, ChannelType
#include "linoh/net/net_report.hpp"        // NetReport, NatType

#include <cstdint>

namespace linoh::tls {

// CryptoLevel 定义在 multimodal::CryptoLevel（channel.hpp），此处导入以便简洁引用
using multimodal::CryptoLevel;

/// 网络环境分级（三档，简化决策）
enum class NetworkClass : std::uint8_t {
    Lan  = 0,  // 局域网/公网直连（OpenInternet/FullCone）
    Wan  = 1,  // 广域网普通 NAT（RestrictedCone/PortRestrictedCone）
    Hard = 2,  // 困难网络（Symmetric/CGN/Unknown/UDP Blocked）
};

/// 从 NetReport 推断网络分级
NetworkClass classify_network(const net::NetReport &report) noexcept;

/// 根据网络分级和模态选择加密级别
CryptoLevel select_crypto_level(NetworkClass net_class,
                                 multimodal::ChannelType channel) noexcept;

/// 便捷重载：直接从 NetReport 选择加密级别
CryptoLevel select_crypto_level(const net::NetReport &report,
                                 multimodal::ChannelType channel) noexcept;

/// 加密算法规格描述
struct CryptoSpec {
    CryptoLevel  level{CryptoLevel::None};
    const char  *algorithm{""};   // "AES-256-GCM" / "AES-128-GCM" / "ChaCha20-Poly1305" / "None"
    std::uint16_t key_bits{0};    // 0 / 128 / 256
    bool         extra_mac{false};  // Maximum 级别附加独立 MAC
};

/// 获取加密级别对应的算法规格
CryptoSpec crypto_spec_for(CryptoLevel level) noexcept;

/// 网络分级转字符串（日志用）
constexpr const char *network_class_name(NetworkClass c) noexcept {
    switch (c) {
        case NetworkClass::Lan:  return "lan";
        case NetworkClass::Wan:  return "wan";
        case NetworkClass::Hard: return "hard";
    }
    return "unknown";
}

}  // namespace linoh::tls
