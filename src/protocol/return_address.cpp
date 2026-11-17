// return_address.cpp — Direct Return Path 地址信息实现（v3.2.0）
//
// 实现 ReturnAddress / ReturnAddrAckPayload 的编解码逻辑。
// 详见 return_address.hpp 字段布局说明。

#include "linoh/protocol/return_address.hpp"

#include <cstring>

namespace linoh::protocol {

// ============================================================================
// ReturnAddress 编码
// ============================================================================

std::vector<std::uint8_t> ReturnAddress::encode() const {
    std::vector<std::uint8_t> buf;
    buf.reserve(kEncodedSize);

    // offset 0: marker (1B)
    buf.push_back(kMarker);

    // offset 1: master_endpoint (32B，原样写入)
    buf.insert(buf.end(), master_endpoint.begin(), master_endpoint.end());

    // offset 33: stream_token (4B，大端序)
    buf.push_back(static_cast<std::uint8_t>((stream_token >> 24) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((stream_token >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((stream_token >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(stream_token & 0xFF));

    // offset 37: reserved (3B，全 0)
    buf.insert(buf.end(), reserved.begin(), reserved.end());

    return buf;
}

// ============================================================================
// ReturnAddress 解码
// ============================================================================

std::size_t ReturnAddress::try_decode(std::span<const std::uint8_t> data,
                                       ReturnAddress &out) {
    // 长度不足 40 字节，视为无 ReturnAddress
    if (data.size() < kEncodedSize) {
        return 0;
    }

    // 首字节不是 marker，视为无 ReturnAddress（payload 为纯 hidden_state）
    if (data[0] != kMarker) {
        return 0;
    }

    // offset 1: master_endpoint (32B)
    std::memcpy(out.master_endpoint.data(), data.data() + 1, 32);

    // offset 33: stream_token (4B，大端序)
    out.stream_token =
        (static_cast<std::uint32_t>(data[33]) << 24) |
        (static_cast<std::uint32_t>(data[34]) << 16) |
        (static_cast<std::uint32_t>(data[35]) << 8)  |
        static_cast<std::uint32_t>(data[36]);

    // offset 37: reserved (3B)
    std::memcpy(out.reserved.data(), data.data() + 37, 3);

    return kEncodedSize;
}

// ============================================================================
// ReturnAddress payload 分离工具
// ============================================================================

std::vector<std::uint8_t> ReturnAddress::strip_address(
    std::span<const std::uint8_t> full_payload,
    std::optional<ReturnAddress> &addr) {
    ReturnAddress parsed;
    std::size_t consumed = try_decode(full_payload, parsed);

    if (consumed == kEncodedSize) {
        // 存在 ReturnAddress，剥离前 40 字节
        addr = parsed;
        std::vector<std::uint8_t> hidden;
        hidden.insert(hidden.end(),
                      full_payload.begin() + kEncodedSize,
                      full_payload.end());
        return hidden;
    }

    // 无 ReturnAddress，payload 即纯 hidden_state
    addr = std::nullopt;
    std::vector<std::uint8_t> hidden(full_payload.begin(), full_payload.end());
    return hidden;
}

std::vector<std::uint8_t> ReturnAddress::prepend_address(
    const ReturnAddress &addr,
    std::span<const std::uint8_t> hidden_state) {
    auto prefix = addr.encode();
    // 拼接：ReturnAddress(40B) + hidden_state
    prefix.insert(prefix.end(), hidden_state.begin(), hidden_state.end());
    return prefix;
}

// ============================================================================
// ReturnAddrAckPayload 编解码
// ============================================================================

std::vector<std::uint8_t> ReturnAddrAckPayload::encode() const {
    std::vector<std::uint8_t> buf;
    buf.reserve(35);

    // offset 0: supported (1B)
    buf.push_back(supported ? 0x01 : 0x00);

    // offset 1: version (2B，大端序)
    buf.push_back(static_cast<std::uint8_t>((version >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(version & 0xFF));

    // offset 3: worker_endpoint (32B)
    buf.insert(buf.end(), worker_endpoint.begin(), worker_endpoint.end());

    return buf;
}

bool ReturnAddrAckPayload::decode(std::span<const std::uint8_t> data,
                                   ReturnAddrAckPayload &out) {
    // 最小长度：supported(1) + version(2) + worker_endpoint(32) = 35
    if (data.size() < 35) {
        return false;
    }

    out.supported = (data[0] != 0x00);
    out.version =
        (static_cast<std::uint16_t>(data[1]) << 8) |
        static_cast<std::uint16_t>(data[2]);
    std::memcpy(out.worker_endpoint.data(), data.data() + 3, 32);

    return true;
}

}  // namespace linoh::protocol
