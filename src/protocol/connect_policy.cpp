// connect_policy.cpp — v4.0.1 M19 连接策略直连优先实现
//
// 实现 ConnectPolicy 的工厂方法、决策逻辑和序列化编解码。
// 详见 connect_policy.hpp 字段布局说明。
//
// 决策核心：依据 CGN Detector 置信度 + ALPN 通道特征选择连接路径
//   - 高置信度（≥0.7）：直连可行 → DirectOnly
//   - 中置信度（0.3-0.7）：直连可能成功 → DirectWithRelay（并行兜底）
//   - 低置信度（<0.3）：直连几乎必败 → RelayOnly
//   - require_direct=true 时：强制直连优先，relay_fallback=false 则宁可失败也不走 Relay

#include "linoh/protocol/connect_policy.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace linoh::protocol {

// ============================================================================
// 内部辅助：flags 位掩码 + cgn_confidence 序列化
// ============================================================================

namespace {

// flags 位定义（与 connect_policy.hpp 注释一致）
constexpr std::uint8_t kFlagRequireDirect  = 0x01;  // bit0
constexpr std::uint8_t kFlagRelayFallback  = 0x02;  // bit1
// bit2-7 reserved（必须为 0）

// cgn_confidence 量化精度：×100 存储（0.0-1.0 → 0-10000）
constexpr std::uint16_t kConfidenceScale = 100;

/// 将置信度 [0.0, 1.0] 量化为 uint16_t（夹紧到合法范围）
std::uint16_t confidence_to_u16(double v) {
    if (v < 0.0) v = 0.0;
    if (v > 1.0) v = 1.0;
    return static_cast<std::uint16_t>(v * kConfidenceScale + 0.5);
}

/// 将 uint16_t 还原为置信度 [0.0, 1.0]
double u16_to_confidence(std::uint16_t v) {
    return static_cast<double>(v) / static_cast<double>(kConfidenceScale);
}

/// 写入 4 字节小端 uint32
void write_u32_le(std::vector<std::uint8_t> &buf, std::uint32_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
}

/// 写入 2 字节小端 uint16
void write_u16_le(std::vector<std::uint8_t> &buf, std::uint16_t v) {
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

/// 读取 4 字节小端 uint32
std::uint32_t read_u32_le(const std::uint8_t *p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

/// 读取 2 字节小端 uint16
std::uint16_t read_u16_le(const std::uint8_t *p) {
    return static_cast<std::uint16_t>(p[0]) |
           static_cast<std::uint16_t>(p[1] << 8);
}

}  // namespace

// ============================================================================
// 工厂方法
// ============================================================================

ConnectPolicy ConnectPolicy::default_relaxed() {
    ConnectPolicy p;
    p.require_direct = false;
    p.direct_timeout_ms = 5000;
    p.relay_fallback = true;
    p.alpn.clear();
    p.cgn_confidence_threshold = kLowConfidenceThreshold;  // 0.3
    return p;
}

ConnectPolicy ConnectPolicy::strict_direct(const std::string &alpn) {
    ConnectPolicy p;
    p.require_direct = true;
    p.direct_timeout_ms = 10000;  // 关键数据：给足直连时间
    p.relay_fallback = false;     // 强制直连：宁可失败也不走 Relay
    p.alpn = alpn;
    p.cgn_confidence_threshold = kLowConfidenceThreshold;  // 0.3（仍按置信度决策）
    return p;
}

ConnectPolicy ConnectPolicy::control_channel() {
    ConnectPolicy p;
    p.require_direct = false;
    p.direct_timeout_ms = 3000;   // 控制面要求快速建立
    p.relay_fallback = true;      // 控制面必须可达，允许 Relay 兜底
    p.alpn = "ctrl/1";
    p.cgn_confidence_threshold = kLowConfidenceThreshold;  // 0.3
    return p;
}

ConnectPolicy ConnectPolicy::for_alpn(const std::string &alpn) {
    if (alpn == "pp-hidden/1" || alpn == "pp-llm/1") {
        // LLM hidden_state 等关键数据：强制直连
        return strict_direct(alpn);
    }
    if (alpn == "ctrl/1") {
        // 控制面：允许 Relay 兜底
        return control_channel();
    }
    // 其他模态（img/video/audio/multi）：默认宽松
    ConnectPolicy p = default_relaxed();
    p.alpn = alpn;
    return p;
}

// ============================================================================
// 决策函数
// ============================================================================

ConnectDecision ConnectPolicy::decide(double cgn_confidence) const {
    // 夹紧置信度到 [0.0, 1.0]
    if (cgn_confidence < 0.0) cgn_confidence = 0.0;
    if (cgn_confidence > 1.0) cgn_confidence = 1.0;

    if (require_direct) {
        // 强制直连模式
        if (cgn_confidence >= kHighConfidenceThreshold) {
            // 高置信度：直连可行
            return ConnectDecision::DirectOnly;
        }
        if (cgn_confidence >= cgn_confidence_threshold) {
            // 中置信度但仍尝试直连（require_direct 强制不走 Relay）
            return ConnectDecision::DirectOnly;
        }
        // 低置信度：直连几乎必败
        if (relay_fallback) {
            return ConnectDecision::RelayOnly;
        }
        // require_direct=true 且 relay_fallback=false：宁可失败也不走 Relay
        return ConnectDecision::DirectOnly;
    }

    // 非强制直连模式（允许 Relay 兜底）
    if (cgn_confidence >= kHighConfidenceThreshold) {
        // 高置信度：直连即可
        return ConnectDecision::DirectOnly;
    }
    if (cgn_confidence >= cgn_confidence_threshold) {
        // 中置信度：直连优先 + Relay 并行兜底
        return ConnectDecision::DirectWithRelay;
    }
    // 低置信度：直接走 Relay
    return ConnectDecision::RelayOnly;
}

// ============================================================================
// 序列化
// ============================================================================

std::vector<std::uint8_t> ConnectPolicy::encode() const {
    std::vector<std::uint8_t> buf;
    // 预估容量：version(1) + flags(1) + timeout(4) + alpn_len(1) + alpn(N) + threshold(2)
    buf.reserve(kMinEncodedSize + alpn.size());

    // offset 0: version (1B)
    buf.push_back(kCurrentVersion);

    // offset 1: flags (1B)
    std::uint8_t flags = 0;
    if (require_direct)  flags |= kFlagRequireDirect;
    if (relay_fallback)  flags |= kFlagRelayFallback;
    buf.push_back(flags);

    // offset 2-5: direct_timeout_ms (4B, 小端序)
    write_u32_le(buf, direct_timeout_ms);

    // offset 6: alpn_len (1B)
    const std::size_t alpn_len = (alpn.size() > kMaxAlpnLen)
                                     ? static_cast<std::size_t>(kMaxAlpnLen)
                                     : alpn.size();
    buf.push_back(static_cast<std::uint8_t>(alpn_len));

    // offset 7~7+N-1: alpn (N B)
    if (alpn_len > 0) {
        buf.insert(buf.end(), alpn.data(), alpn.data() + alpn_len);
    }

    // offset 7+N~8+N: cgn_confidence_threshold_x100 (2B, 小端序)
    write_u16_le(buf, confidence_to_u16(cgn_confidence_threshold));

    return buf;
}

bool ConnectPolicy::decode(std::span<const std::uint8_t> data, ConnectPolicy &out) {
    // 最小长度：version(1) + flags(1) + timeout(4) + alpn_len(1) + threshold(2) = 9
    if (data.size() < kMinEncodedSize) {
        return false;
    }

    std::size_t off = 0;

    // offset 0: version (1B)
    const std::uint8_t version = data[off++];
    if (version != kCurrentVersion) {
        // 版本不匹配：拒绝解码（向后兼容由调用方决定是否走默认策略）
        return false;
    }

    // offset 1: flags (1B)
    const std::uint8_t flags = data[off++];
    out.require_direct = (flags & kFlagRequireDirect) != 0;
    out.relay_fallback = (flags & kFlagRelayFallback) != 0;
    // bit2-7 保留位忽略（未来扩展兼容）

    // offset 2-5: direct_timeout_ms (4B, 小端序)
    out.direct_timeout_ms = read_u32_le(data.data() + off);
    off += 4;

    // offset 6: alpn_len (1B)
    const std::uint8_t alpn_len = data[off++];

    // 检查 alpn 长度是否足够
    if (data.size() < off + alpn_len + 2) {
        // 需要 alpn(N) + threshold(2)
        return false;
    }

    // offset 7~7+N-1: alpn (N B)
    out.alpn.assign(reinterpret_cast<const char *>(data.data() + off), alpn_len);
    off += alpn_len;

    // offset 7+N~8+N: cgn_confidence_threshold_x100 (2B, 小端序)
    const std::uint16_t threshold_u16 = read_u16_le(data.data() + off);
    out.cgn_confidence_threshold = u16_to_confidence(threshold_u16);
    off += 2;

    return true;
}

// ============================================================================
// 描述
// ============================================================================

std::string ConnectPolicy::to_string() const {
    std::ostringstream oss;
    oss << "ConnectPolicy{version=" << static_cast<int>(kCurrentVersion)
        << ", require_direct=" << (require_direct ? "true" : "false")
        << ", direct_timeout_ms=" << direct_timeout_ms
        << ", relay_fallback=" << (relay_fallback ? "true" : "false")
        << ", alpn=\"" << alpn << "\""
        << ", cgn_confidence_threshold=" << cgn_confidence_threshold
        << "}";
    return oss.str();
}

}  // namespace linoh::protocol
