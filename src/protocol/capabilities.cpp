// capabilities.cpp — V3.5 节点能力探测实现（P5-A）
//
// 实现 CapabilitiesAckPayload 的编解码逻辑 + NodeCapabilities::to_string。
// 详见 capabilities.hpp 字段布局说明。

#include "linoh/protocol/capabilities.hpp"

#include <cstring>
#include <sstream>

namespace linoh::protocol {

// ============================================================================
// CapabilitiesAckPayload 编码
// ============================================================================

std::vector<std::uint8_t> CapabilitiesAckPayload::encode() const {
    std::vector<std::uint8_t> buf;
    buf.reserve(kEncodedSize);

    // offset 0: supported (1B)
    buf.push_back(supported ? 0x01 : 0x00);

    // offset 1: version (2B，大端序)
    buf.push_back(static_cast<std::uint8_t>((version >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(version & 0xFF));

    // offset 3: capabilities_mask (4B，大端序)
    buf.push_back(static_cast<std::uint8_t>((capabilities_mask >> 24) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((capabilities_mask >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((capabilities_mask >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(capabilities_mask & 0xFF));

    // offset 7: peer_endpoint (32B，原样写入)
    buf.insert(buf.end(), peer_endpoint.begin(), peer_endpoint.end());

    // offset 39: node_role (1B，v3.9.5 M5)
    buf.push_back(node_role);

    return buf;
}

// ============================================================================
// CapabilitiesAckPayload 解码
// ============================================================================

bool CapabilitiesAckPayload::decode(std::span<const std::uint8_t> data,
                                      CapabilitiesAckPayload &out) {
    // 最小长度：supported(1) + version(2) + capabilities_mask(4) + peer_endpoint(32) = 39
    // v3.9.5: 兼容 39 字节旧格式（无 node_role），最小长度用 kLegacyEncodedSize
    if (data.size() < kLegacyEncodedSize) {
        return false;
    }

    // offset 0: supported (1B)
    out.supported = (data[0] != 0x00);

    // offset 1: version (2B，大端序)
    out.version =
        (static_cast<std::uint16_t>(data[1]) << 8) |
        static_cast<std::uint16_t>(data[2]);

    // offset 3: capabilities_mask (4B，大端序)
    out.capabilities_mask =
        (static_cast<std::uint32_t>(data[3]) << 24) |
        (static_cast<std::uint32_t>(data[4]) << 16) |
        (static_cast<std::uint32_t>(data[5]) << 8)  |
        static_cast<std::uint32_t>(data[6]);

    // offset 7: peer_endpoint (32B)
    std::memcpy(out.peer_endpoint.data(), data.data() + 7, 32);

    // offset 39: node_role (1B，v3.9.5 M5)
    // 兼容旧节点：长度 < 40 时 node_role 默认 0 (Unknown)
    out.node_role = (data.size() >= kEncodedSize) ? data[39] : 0;

    return true;
}

// ============================================================================
// NodeCapabilities 描述（日志用）
// ============================================================================

std::string NodeCapabilities::to_string() const {
    std::ostringstream oss;
    oss << "NodeCapabilities{mask=0x" << std::hex << mask << std::dec
        << ", version=0x" << std::hex << version << std::dec
        << ", probed=" << (probed ? "true" : "false");

    if (probed) {
        oss << ", caps=[";
        bool first = true;
        if (supports_return_address())   { oss << (first ? "" : ",") << "ReturnAddr";   first = false; }
        if (supports_direct_return())    { oss << (first ? "" : ",") << "DirectReturn"; first = false; }
        if (supports_result_shard())     { oss << (first ? "" : ",") << "ResultShard";  first = false; }
        if (supports_session_id())       { oss << (first ? "" : ",") << "SessionId";    first = false; }
        if (supports_zstd_compression()) { oss << (first ? "" : ",") << "Zstd";         first = false; }
        // v5.0.0 阶段四新增能力
        if (supports_zero_rtt())         { oss << (first ? "" : ",") << "0RTT";         first = false; }
        if (supports_qad())              { oss << (first ? "" : ",") << "QAD";          first = false; }
        if (supports_hard_nat())         { oss << (first ? "" : ",") << "HardNAT";      first = false; }
        oss << "]";
    } else {
        oss << ", caps=[none/legacy]";
    }
    oss << "}";
    return oss.str();
}

}  // namespace linoh::protocol
