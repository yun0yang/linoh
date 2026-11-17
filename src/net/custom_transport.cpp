// custom_transport.cpp — 自定义传输注册机制实现（P4-C-4）

#include "linoh/net/custom_transport.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <chrono>
#include <future>
#include <sstream>
#include <thread>

namespace linoh::net {

// ============================================================================
// 十六进制工具
// ============================================================================

static char hex_nibble(std::uint8_t n) {
    return static_cast<char>(n < 10 ? '0' + n : 'a' + (n - 10));
}

static std::uint8_t hex_to_nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
    return 0xFF;  // 非法字符
}

static bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static std::string bytes_to_hex(const std::uint8_t *data, std::size_t len) {
    std::string s;
    s.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        s.push_back(hex_nibble(data[i] >> 4));
        s.push_back(hex_nibble(data[i] & 0x0F));
    }
    return s;
}

static std::vector<std::uint8_t> hex_to_bytes(std::string_view hex) {
    std::vector<std::uint8_t> result;
    if (hex.size() % 2 != 0) return result;
    result.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        std::uint8_t hi = hex_to_nibble(hex[i]);
        std::uint8_t lo = hex_to_nibble(hex[i + 1]);
        if (hi == 0xFF || lo == 0xFF) return {};
        result.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return result;
}

// ============================================================================
// TransportId 工具函数
// ============================================================================

std::string transport_id_to_hex(TransportId id) {
    std::string s;
    s.reserve(10);
    s += "0x";
    char buf[8];
    for (int i = 7; i >= 0; --i) {
        std::uint8_t byte = static_cast<std::uint8_t>((id >> (i * 4)) & 0xF);
        buf[7 - i] = hex_nibble(byte);
    }
    s.append(buf, 8);
    // 去掉前导 0（保留至少一位）
    std::size_t prefix = 2;  // "0x"
    while (prefix < s.size() - 1 && s[prefix] == '0') ++prefix;
    return "0x" + s.substr(prefix);
}

std::optional<TransportId> transport_id_from_hex(std::string_view s) {
    if (s.empty()) return std::nullopt;

    // 去掉 0x 前缀
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
    }
    if (s.empty() || s.size() > 8) return std::nullopt;

    TransportId id = 0;
    for (char c : s) {
        if (!is_hex_char(c)) return std::nullopt;
        id = (id << 4) | hex_to_nibble(c);
    }
    return id;
}

std::string_view well_known_transport_name(TransportId id) {
    switch (id) {
        case kTransportIdTest:       return "test";
        case kTransportIdMock:       return "mock";
        case kTransportIdTor:        return "tor";
        case kTransportIdBle:        return "ble";
        case kTransportIdWifiDirect: return "wifi-direct";
        default:                     return "unknown";
    }
}

// ============================================================================
// CustomTransportAddr
// ============================================================================

CustomTransportAddr CustomTransportAddr::from_hex(TransportId tid, std::string_view hex_addr) {
    CustomTransportAddr addr;
    addr.transport_id = tid;
    addr.address_bytes = hex_to_bytes(hex_addr);
    return addr;
}

std::string CustomTransportAddr::to_string() const {
    std::string s;
    s += transport_id_to_hex(transport_id);
    s += ":";
    if (address_bytes.empty()) {
        s += "";
    } else {
        s += bytes_to_hex(address_bytes.data(), address_bytes.size());
    }
    return s;
}

std::optional<CustomTransportAddr> CustomTransportAddr::parse(std::string_view s) {
    if (s.empty()) return std::nullopt;

    // 查找分隔符 ':'
    auto colon = s.find(':');
    if (colon == std::string_view::npos) return std::nullopt;

    auto id_str = s.substr(0, colon);
    auto addr_hex = s.substr(colon + 1);

    auto id = transport_id_from_hex(id_str);
    if (!id.has_value()) return std::nullopt;

    CustomTransportAddr addr;
    addr.transport_id = *id;
    if (!addr_hex.empty()) {
        addr.address_bytes = hex_to_bytes(addr_hex);
        // 若解析失败（奇数长度或非法字符），返回 nullopt
        if (addr.address_bytes.empty() && !addr_hex.empty()) {
            // 检查是否真的是非法 hex
            if (addr_hex.size() % 2 != 0) return std::nullopt;
            for (char c : addr_hex) {
                if (!is_hex_char(c)) return std::nullopt;
            }
            // 此时为空字符串解析，是合法的
        }
    }
    return addr;
}

std::vector<std::uint8_t> CustomTransportAddr::to_bytes() const {
    std::vector<std::uint8_t> out;
    // transport_id (4 字节 BE)
    out.push_back(static_cast<std::uint8_t>((transport_id >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((transport_id >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((transport_id >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(transport_id & 0xFF));
    // 长度 (2 字节 BE)
    std::uint16_t len = static_cast<std::uint16_t>(address_bytes.size());
    out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(len & 0xFF));
    // 地址字节
    out.insert(out.end(), address_bytes.begin(), address_bytes.end());
    return out;
}

std::optional<CustomTransportAddr> CustomTransportAddr::from_bytes(std::span<const std::uint8_t> data) {
    if (data.size() < 6) return std::nullopt;
    CustomTransportAddr addr;
    addr.transport_id = (static_cast<TransportId>(data[0]) << 24) |
                        (static_cast<TransportId>(data[1]) << 16) |
                        (static_cast<TransportId>(data[2]) << 8) |
                        static_cast<TransportId>(data[3]);
    std::uint16_t len = (static_cast<std::uint16_t>(data[4]) << 8) |
                        static_cast<std::uint16_t>(data[5]);
    if (data.size() < static_cast<std::size_t>(6) + len) return std::nullopt;
    addr.address_bytes.assign(data.data() + 6, data.data() + 6 + len);
    return addr;
}

// ============================================================================
// TransportRegistry
// ============================================================================

bool TransportRegistry::register_transport(std::shared_ptr<CustomTransport> transport) {
    if (!transport) return false;
    TransportId id = transport->id();
    if (is_reserved_transport(id)) {
        LINOH_WARN("TransportRegistry: reject reserved transport id=", id);
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(mu_);
    auto [it, inserted] = transports_.try_emplace(id, std::move(transport));
    return inserted;
}

bool TransportRegistry::unregister_transport(TransportId id) {
    std::unique_lock<std::shared_mutex> lock(mu_);
    return transports_.erase(id) > 0;
}

std::shared_ptr<CustomTransport> TransportRegistry::find(TransportId id) const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = transports_.find(id);
    if (it == transports_.end()) return nullptr;
    return it->second;
}

std::size_t TransportRegistry::size() const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    return transports_.size();
}

std::vector<TransportId> TransportRegistry::registered_ids() const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    std::vector<TransportId> ids;
    ids.reserve(transports_.size());
    for (const auto & [id, _] : transports_) {
        ids.push_back(id);
    }
    return ids;
}

std::vector<std::string> TransportRegistry::registered_names() const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    std::vector<std::string> names;
    names.reserve(transports_.size());
    for (const auto & [_, t] : transports_) {
        names.emplace_back(t->name());
    }
    return names;
}

void TransportRegistry::clear() {
    std::unique_lock<std::shared_mutex> lock(mu_);
    transports_.clear();
}

std::shared_ptr<CustomTransport> TransportRegistry::find_for_address(
    const CustomTransportAddr &addr) const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = transports_.find(addr.transport_id);
    if (it == transports_.end()) return nullptr;
    if (!it->second->supports_address(addr)) return nullptr;
    return it->second;
}

TransportConnHandle TransportRegistry::try_connect_concurrent(
    const std::vector<TransportId> &candidates,
    const CustomTransportAddr &addr,
    std::chrono::milliseconds timeout) {

    if (candidates.empty()) return nullptr;

    // 异步启动每个候选传输的 connect
    std::vector<std::future<TransportConnHandle>> futures;
    futures.reserve(candidates.size());

    for (TransportId tid : candidates) {
        std::shared_ptr<CustomTransport> transport;
        {
            std::shared_lock<std::shared_mutex> lock(mu_);
            auto it = transports_.find(tid);
            if (it == transports_.end()) continue;
            transport = it->second;
        }
        if (!transport) continue;

        futures.push_back(std::async(std::launch::async,
            [transport, addr, timeout]() -> TransportConnHandle {
                return transport->connect(addr, timeout);
            }));
    }

    if (futures.empty()) return nullptr;

    // 等待第一个成功，或全部失败
    TransportConnHandle result = nullptr;
    auto deadline = std::chrono::steady_clock::now() + timeout;

    // 轮询检查每个 future 的状态
    std::vector<bool> done(futures.size(), false);
    std::size_t done_count = 0;

    while (done_count < futures.size()) {
        for (std::size_t i = 0; i < futures.size(); ++i) {
            if (done[i]) continue;
            auto status = futures[i].wait_for(std::chrono::milliseconds(10));
            if (status == std::future_status::ready) {
                done[i] = true;
                ++done_count;
                auto h = futures[i].get();
                if (h) {
                    // 第一个成功，返回；其余 future 不再等待（但需保证其结束）
                    result = h;
                    // 取消其他 future（通过让它们超时自然结束）
                    return result;
                }
            }
        }
        if (std::chrono::steady_clock::now() > deadline) break;
    }

    // 全部失败，等待所有 future 结束（避免资源泄漏）
    for (auto &f : futures) {
        if (f.valid()) {
            try {
                f.wait();
            } catch (...) {
                // 忽略
            }
        }
    }

    return nullptr;
}

} // namespace linoh::net
