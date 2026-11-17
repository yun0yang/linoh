// channel.hpp — 多模态通道定义（P5-A-1）
//
// 借鉴 Sunshine 多通道端口分离（video/audio/control 独立 socket）思想：
//   - 按模态划分通道类型（LLM/图片/视频/音频/融合）
//   - 每个模态对应独立 ALPN，便于按模态分连接、分 stream 池
//   - 控制信道独立 ALPN（ctrl/1），与数据信道隔离
//
// 设计原则：
//   - 不修改现有 ALPN（ctrl/1 与 pp-hidden/1 向后兼容）
//   - 新增 pp-llm/1、pp-img/1、pp-video/1、pp-audio/1、pp-multi/1
//   - ChannelConfig 携带 MTU/FEC/多路径/加密级别等可配置项
//     （对应字段在 P5-B 阶段实际生效，P5-A 仅定义结构）
//   - 双连接模型：connect_multimodal 先建 ctrl_conn 再建 data_conn

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace linoh::multimodal {

/// 加密级别（P5-B-2 实际生效，P5-A 仅定义枚举供 ChannelConfig 引用）
/// 在 P5-A 阶段所有连接仍走 TLS 1.3 完整握手；分级策略在 P5-B-2 落地。
enum class CryptoLevel : std::uint8_t {
    None      = 0,  // 不加密（仅内网调试，生产环境禁用）
    Light     = 1,  // ChaCha20-Poly1305（轻量，适合内网视频流）
    Standard  = 2,  // AES-128-GCM（标准，适合图片/音频）
    Strong    = 3,  // AES-256-GCM（强加密，适合 LLM hidden_state）
    Maximum   = 4,  // AES-256-GCM + 额外 MAC（适合密钥交换、CGN 场景）
};

/// FEC 类型（P5-B-1 实际生效，P5-A 仅定义枚举供 ChannelConfig 引用）
enum class FecType : std::uint8_t {
    None          = 0,  // 不启用 FEC
    Xor           = 1,  // XOR 简单奇偶校验（M=1）
    ReedSolomon   = 2,  // RS 纠错码（M 任意）
};

/// 多模态通道类型
enum class ChannelType : std::uint8_t {
    CONTROL       = 0,  // RPC、心跳、状态上报，可靠传输
    LLM_HIDDEN    = 1,  // LLM hidden_state，小包低延迟
    IMG_FEATURE   = 2,  // 图片模型特征图，大包突发
    VIDEO_FEATURE = 3,  // 视频模型特征，持续大流量
    AUDIO_FEATURE = 4,  // 音频特征（多模态）
    FUSION        = 5,  // 多模态融合层
    // v1.6.0.1 (P0): EP（Expert Parallelism）通道，支持 MoE 模型专家并行
    EP_DISPATCH   = 6,  // EP token 分发到专家节点（EP-master → EP-worker）
    EP_COMBINE    = 7,  // EP 专家结果聚合回主节点（EP-worker → EP-master）
    EP_SYNC       = 8,  // EP 跨节点同步原语（barrier/signal/all-reduce）
};

// ============================================================================
// v3.9.5 (M5): 节点角色枚举 + 角色 ALPN 子集
//
// 设计要点：
//   - 不同角色（MASTER/WORKER/Relay/Observer）支持不同 ALPN 子集
//   - MASTER 仅 ctrl/1 + pp-llm/1（不能收 RESULT，不能发 img/video）
//   - WORKER 支持全模态数据面 ALPN
//   - role=Unknown 时支持所有 ALPN（向后兼容，默认行为）
//   - Endpoint::Config.role 设置后，accept/connect 时校验 ALPN 是否授权
// ============================================================================

/// 节点角色（v3.9.5 M5）
enum class NodeRole : std::uint8_t {
    Unknown     = 0,  // 未指定（向后兼容，支持所有 ALPN）
    Master      = 1,  // MASTER 节点（前N层，固定 [0,27]）
    Worker      = 2,  // WORKER 节点（后N层）
    TempWorker  = 3,  // 临时 WORKER（同 Worker 权限）
    Relay       = 4,  // Relay 服务节点（仅控制面）
    Observer    = 5,  // 观察者（仅控制面，不参与推理）
};

/// 节点角色转字符串（用于日志/序列化）
constexpr std::string_view role_name(NodeRole r) {
    switch (r) {
        case NodeRole::Unknown:    return "unknown";
        case NodeRole::Master:     return "master";
        case NodeRole::Worker:     return "worker";
        case NodeRole::TempWorker: return "temp_worker";
        case NodeRole::Relay:      return "relay";
        case NodeRole::Observer:   return "observer";
    }
    return "unknown";
}

/// 从 uint8_t 安全转换 NodeRole（未知值返回 Unknown）
constexpr NodeRole role_from_uint(std::uint8_t v) {
    switch (v) {
        case 0: return NodeRole::Unknown;
        case 1: return NodeRole::Master;
        case 2: return NodeRole::Worker;
        case 3: return NodeRole::TempWorker;
        case 4: return NodeRole::Relay;
        case 5: return NodeRole::Observer;
        default: return NodeRole::Unknown;
    }
}

/// 通道配置
struct ChannelConfig {
    ChannelType type{ChannelType::CONTROL};

    /// 期望 MTU（P5-B-4 协商生效，P5-A 阶段使用默认 1280）
    std::uint16_t preferred_mtu{1280};

    /// 单通道最大并发 stream
    std::size_t max_stream_concurrency{4};

    /// 是否启用 FEC（P5-B-1 生效）
    bool fec_enabled{false};
    FecType fec_type{FecType::None};
    std::size_t fec_data_blocks{10};       // K
    std::size_t fec_recovery_blocks{2};    // M

    /// 是否启用多路径 strip（P5-B-3 生效）
    bool multipath_strip{false};

    /// 加密级别（P5-B-2 生效，P5-A 阶段所有通道仍走完整 TLS 1.3）
    CryptoLevel crypto_level{CryptoLevel::Strong};

    /// 默认构造：CONTROL 通道的最小配置
    ChannelConfig() = default;

    /// 按通道类型生成默认配置
    static ChannelConfig for_channel(ChannelType t) {
        ChannelConfig c;
        c.type = t;
        switch (t) {
            case ChannelType::CONTROL:
                c.fec_enabled = false;
                c.crypto_level = CryptoLevel::Strong;
                c.preferred_mtu = 1280;
                break;
            case ChannelType::LLM_HIDDEN:
                // P5-B-1 默认：RS K=10 M=2（高保护）
                c.fec_enabled = true;
                c.fec_type = FecType::ReedSolomon;
                c.fec_data_blocks = 10;
                c.fec_recovery_blocks = 2;
                c.crypto_level = CryptoLevel::Strong;
                c.preferred_mtu = 1280;
                break;
            case ChannelType::IMG_FEATURE:
                // 图片突发，依赖 QUIC 重传，无 FEC
                c.fec_enabled = false;
                c.crypto_level = CryptoLevel::Standard;
                c.preferred_mtu = 9000;  // jumbo frame
                break;
            case ChannelType::VIDEO_FEATURE:
                // P5-B-1 默认：RS K=16 M=1（轻度保护）
                c.fec_enabled = true;
                c.fec_type = FecType::ReedSolomon;
                c.fec_data_blocks = 16;
                c.fec_recovery_blocks = 1;
                c.crypto_level = CryptoLevel::Light;
                c.preferred_mtu = 9000;
                c.multipath_strip = true;  // 视频流启用多路径 strip
                break;
            case ChannelType::AUDIO_FEATURE:
                c.fec_enabled = false;
                c.crypto_level = CryptoLevel::Standard;
                c.preferred_mtu = 1280;
                break;
            case ChannelType::FUSION:
                c.fec_enabled = false;
                c.crypto_level = CryptoLevel::Strong;
                c.preferred_mtu = 1280;
                break;
            // v1.6.0.1 (P0): EP 通道默认配置
            // EP_DISPATCH: token 分发，大包突发，启用 RS FEC + jumbo frame
            case ChannelType::EP_DISPATCH:
                c.fec_enabled = true;
                c.fec_type = FecType::ReedSolomon;
                c.fec_data_blocks = 16;       // K=16 与 video 对齐
                c.fec_recovery_blocks = 1;    // M=1 轻度保护
                c.crypto_level = CryptoLevel::Strong;  // EP 调度敏感，强加密
                c.preferred_mtu = 9000;       // jumbo frame（局域网）
                c.multipath_strip = false;    // P4 阶段再启用多路径
                break;
            // EP_COMBINE: 专家结果聚合，大 tensor 持续流量
            case ChannelType::EP_COMBINE:
                c.fec_enabled = true;
                c.fec_type = FecType::ReedSolomon;
                c.fec_data_blocks = 16;
                c.fec_recovery_blocks = 1;
                c.crypto_level = CryptoLevel::Strong;
                c.preferred_mtu = 9000;
                c.multipath_strip = false;
                break;
            // EP_SYNC: 同步原语，小包低延迟，可靠传输
            case ChannelType::EP_SYNC:
                c.fec_enabled = false;
                c.crypto_level = CryptoLevel::Strong;
                c.preferred_mtu = 1280;
                break;
        }
        return c;
    }
};

/// ALPN 字符串映射
/// 注意：保持 ctrl/1 与现有实现兼容，pp-hidden/1 不再使用（被 pp-llm/1 替代）
/// v1.6.0.1 (P0): 新增 EP 三条独立通道 ALPN
constexpr std::string_view alpn_for(ChannelType c) {
    switch (c) {
        case ChannelType::CONTROL:       return "ctrl/1";
        case ChannelType::LLM_HIDDEN:    return "pp-llm/1";
        case ChannelType::IMG_FEATURE:   return "pp-img/1";
        case ChannelType::VIDEO_FEATURE: return "pp-video/1";
        case ChannelType::AUDIO_FEATURE: return "pp-audio/1";
        case ChannelType::FUSION:        return "pp-multi/1";
        // v1.6.0.1 (P0): EP 通道 ALPN
        case ChannelType::EP_DISPATCH:   return "ep-dispatch/1";
        case ChannelType::EP_COMBINE:    return "ep-combine/1";
        case ChannelType::EP_SYNC:       return "ep-sync/1";
    }
    return "ctrl/1";
}

/// 从 ALPN 字符串反解通道类型（未知 ALPN 返回 CONTROL）
constexpr ChannelType channel_from_alpn(std::string_view alpn) {
    if (alpn == "ctrl/1")       return ChannelType::CONTROL;
    if (alpn == "pp-llm/1")     return ChannelType::LLM_HIDDEN;
    if (alpn == "pp-img/1")     return ChannelType::IMG_FEATURE;
    if (alpn == "pp-video/1")   return ChannelType::VIDEO_FEATURE;
    if (alpn == "pp-audio/1")   return ChannelType::AUDIO_FEATURE;
    if (alpn == "pp-multi/1")   return ChannelType::FUSION;
    // v1.6.0.1 (P0): EP ALPN 反解
    if (alpn == "ep-dispatch/1") return ChannelType::EP_DISPATCH;
    if (alpn == "ep-combine/1")  return ChannelType::EP_COMBINE;
    if (alpn == "ep-sync/1")     return ChannelType::EP_SYNC;
    // 向后兼容：旧版 pp-hidden/1 映射到 LLM_HIDDEN
    if (alpn == "pp-hidden/1")  return ChannelType::LLM_HIDDEN;
    return ChannelType::CONTROL;
}

/// 通道类型转字符串（用于日志/序列化）
constexpr std::string_view channel_type_name(ChannelType c) {
    switch (c) {
        case ChannelType::CONTROL:       return "control";
        case ChannelType::LLM_HIDDEN:    return "llm_hidden";
        case ChannelType::IMG_FEATURE:   return "img_feature";
        case ChannelType::VIDEO_FEATURE: return "video_feature";
        case ChannelType::AUDIO_FEATURE: return "audio_feature";
        case ChannelType::FUSION:        return "fusion";
        // v1.6.0.1 (P0): EP 通道名
        case ChannelType::EP_DISPATCH:   return "ep_dispatch";
        case ChannelType::EP_COMBINE:    return "ep_combine";
        case ChannelType::EP_SYNC:       return "ep_sync";
    }
    return "unknown";
}

/// 加密级别转字符串
constexpr std::string_view crypto_level_name(CryptoLevel l) {
    switch (l) {
        case CryptoLevel::None:     return "none";
        case CryptoLevel::Light:    return "light";
        case CryptoLevel::Standard: return "standard";
        case CryptoLevel::Strong:   return "strong";
        case CryptoLevel::Maximum:  return "maximum";
    }
    return "unknown";
}

/// FEC 类型转字符串
constexpr std::string_view fec_type_name(FecType f) {
    switch (f) {
        case FecType::None:         return "none";
        case FecType::Xor:          return "xor";
        case FecType::ReedSolomon:  return "reed_solomon";
    }
    return "unknown";
}

/// 是否为数据通道（非控制通道）
constexpr bool is_data_channel(ChannelType c) {
    return c != ChannelType::CONTROL;
}

/// 通道是否需要可靠传输（控制通道需要；数据通道按模态决定）
/// v1.6.0.1 (P0): EP_SYNC 同步原语必须可靠传输（barrier/signal/all-reduce 不能丢）
constexpr bool is_reliable_channel(ChannelType c) {
    return c == ChannelType::CONTROL || c == ChannelType::EP_SYNC;
}

// ============================================================================
// v1.6.0.1 (P0): EP 通道 ALPN 列表辅助函数
//
// 用于 Endpoint::Config.alpns 初始化，让 Endpoint 能接受 EP 通道的入站连接。
// 用法：
//   Endpoint::Config cfg;
//   cfg.alpns = multimodal::default_alpns();  // 包含 ctrl/1 + pp-*/1 + ep-*/1
//   或仅 EP 通道：
//   cfg.alpns = multimodal::default_ep_alpns();  // 仅 ep-dispatch/1 + ep-combine/1 + ep-sync/1
// ============================================================================

/// 返回所有 EP 通道的 ALPN 列表（ep-dispatch/1 + ep-combine/1 + ep-sync/1）
inline std::vector<std::string_view> default_ep_alpns() {
    return {
        alpn_for(ChannelType::EP_DISPATCH),
        alpn_for(ChannelType::EP_COMBINE),
        alpn_for(ChannelType::EP_SYNC),
    };
}

/// 返回所有已知通道的 ALPN 列表（control + pp-* + ep-*）
/// 用于 EP 节点同时支持 PP 和 EP 的场景
inline std::vector<std::string_view> default_all_alpns() {
    return {
        alpn_for(ChannelType::CONTROL),
        alpn_for(ChannelType::LLM_HIDDEN),
        alpn_for(ChannelType::IMG_FEATURE),
        alpn_for(ChannelType::VIDEO_FEATURE),
        alpn_for(ChannelType::AUDIO_FEATURE),
        alpn_for(ChannelType::FUSION),
        alpn_for(ChannelType::EP_DISPATCH),
        alpn_for(ChannelType::EP_COMBINE),
        alpn_for(ChannelType::EP_SYNC),
    };
}

// ===== v3.9.5 M5: 角色 ALPN 子集（需在 alpn_for/default_all_alpns 之后定义）=====

/// 返回角色对应的默认 ALPN 子集
/// - Master: ctrl/1 + pp-llm/1（不能收 RESULT，不能发 img/video）
/// - Worker/TempWorker: ctrl/1 + pp-llm/1 + pp-img/1 + pp-video/1 + pp-audio/1 + pp-multi/1
/// - Relay/Observer: ctrl/1（仅控制面）
/// - Unknown: 所有 ALPN（向后兼容）
inline std::vector<std::string_view> role_default_alpns(NodeRole role) {
    switch (role) {
        case NodeRole::Master:
            return {
                alpn_for(ChannelType::CONTROL),
                alpn_for(ChannelType::LLM_HIDDEN),
            };
        case NodeRole::Worker:
        case NodeRole::TempWorker:
            return {
                alpn_for(ChannelType::CONTROL),
                alpn_for(ChannelType::LLM_HIDDEN),
                alpn_for(ChannelType::IMG_FEATURE),
                alpn_for(ChannelType::VIDEO_FEATURE),
                alpn_for(ChannelType::AUDIO_FEATURE),
                alpn_for(ChannelType::FUSION),
            };
        case NodeRole::Relay:
        case NodeRole::Observer:
            return {
                alpn_for(ChannelType::CONTROL),
            };
        case NodeRole::Unknown:
            return default_all_alpns();
    }
    return default_all_alpns();
}

/// 校验角色是否被授权使用指定 ALPN
/// @param role 节点角色
/// @param alpn 请求的 ALPN 字符串
/// @return true=授权通过，false=未授权（角色不支持该 ALPN）
/// @note role=Unknown 时始终返回 true（向后兼容）
inline bool is_role_authorized(NodeRole role, std::string_view alpn) {
    if (role == NodeRole::Unknown) return true;  // 向后兼容
    const auto allowed = role_default_alpns(role);
    for (const auto &a : allowed) {
        if (a == alpn) return true;
    }
    return false;
}

// ============================================================================
// 序列化/反序列化（实现在 channel.cpp）
// ============================================================================

/// ChannelConfig 序列化为 JSON 风格字符串
/// 格式：{"type":"llm_hidden","mtu":1280,"fec_enabled":true,"fec_type":"reed_solomon","fec_k":10,"fec_m":2,"multipath_strip":false,"crypto":"strong"}
std::string channel_config_to_json(const ChannelConfig &c);

/// 从 JSON 字符串反序列化 ChannelConfig
/// 解析失败时返回 for_channel(default_type) 默认配置
ChannelConfig channel_config_from_json(std::string_view json, ChannelType default_type);

}  // namespace linoh::multimodal
