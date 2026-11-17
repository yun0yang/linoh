// custom_transport.hpp — 自定义传输注册机制（P4-C-4）
//
// 借鉴 iroh TRANSPORTS.md：通过 transport id 注册表支持多种传输。
//
// 设计原则：
//   - 传输类型 ID（TransportId）全局唯一，参考 iroh 注册表
//   - CustomTransport 抽象接口：connect/listen/id/name
//   - TransportRegistry 管理已注册传输，支持按 id 查找
//   - EndpointAddr 通过 custom_addrs 字段携带自定义传输地址
//   - 注册表与 Endpoint 解耦，便于单元测试
//
// 用法示例：
//   TransportRegistry registry;
//   auto mock = std::make_shared<MockTransport>();
//   registry.register_transport(mock);
//   auto found = registry.find(mock->id());
//   assert(found.get() == mock.get());

#pragma once

#include "linoh/base/key.hpp"
#include "linoh/util/bytes.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace linoh::net {

// ============================================================================
// TransportId 注册表（参考 iroh TRANSPORTS.md）
// ============================================================================
//
// 0x00-0x1F: 保留（IANA-like 标准传输）
// 0x20:      Test（测试用）
// 0x21:      Mock（mock 测试用）
// 0x544F52:  Tor (experimental)
// 0x424C45:  BLE (reserved)
// 0x574952:  Wi-Fi Direct (reserved)
// 0x80+:     用户自定义起点

/// 传输类型 ID
using TransportId = std::uint32_t;

/// 知名传输 ID 常量
constexpr TransportId kTransportIdReserved   = 0x00;
constexpr TransportId kTransportIdTest       = 0x20;
constexpr TransportId kTransportIdMock       = 0x21;
constexpr TransportId kTransportIdTor        = 0x544F52;  // 'TOR'
constexpr TransportId kTransportIdBle        = 0x424C45;  // 'BLE'
constexpr TransportId kTransportIdWifiDirect = 0x574952;  // 'WIR'
constexpr TransportId kTransportIdUserStart  = 0x80;

/// 判断传输 ID 是否为用户自定义范围
/// 注意：Tor/BLE/WifiDirect 等知名大 ID 虽然值 >= 0x80，但属于知名传输，
/// 不算作用户自定义。
inline bool is_user_transport(TransportId id) {
    if (id < kTransportIdUserStart) return false;
    if (id == kTransportIdTor) return false;
    if (id == kTransportIdBle) return false;
    if (id == kTransportIdWifiDirect) return false;
    return true;
}

/// 判断传输 ID 是否为保留范围（不可注册）
inline bool is_reserved_transport(TransportId id) {
    return id <= 0x1F;
}

// ============================================================================
// CustomTransportAddr 自定义传输地址
// ============================================================================
//
// 二进制格式（由具体传输定义），可序列化为字符串（hex 或自定义格式）。
// 字符串格式："<transport_id>:<hex_address>"
// 例如 "0x544F52:7c8a9b3f" 表示 Tor 传输，地址 7c8a9b3f。

struct CustomTransportAddr {
    TransportId transport_id{0};
    std::vector<std::uint8_t> address_bytes;

    /// 默认构造（空地址）
    CustomTransportAddr() = default;

    /// 从 transport_id + 字节构造
    CustomTransportAddr(TransportId tid, std::vector<std::uint8_t> addr)
        : transport_id(tid), address_bytes(std::move(addr)) {}

    /// 从 transport_id + 字符串地址构造（自动 hex 解码）
    static CustomTransportAddr from_hex(TransportId tid, std::string_view hex_addr);

    /// 转字符串："<transport_id_hex>:<hex_address>"
    std::string to_string() const;

    /// 从字符串解析（与 to_string 互逆）
    static std::optional<CustomTransportAddr> parse(std::string_view s);

    /// 比较运算符（用于容器）
    bool operator==(const CustomTransportAddr &other) const {
        return transport_id == other.transport_id &&
               address_bytes == other.address_bytes;
    }
    bool operator!=(const CustomTransportAddr &other) const {
        return !(*this == other);
    }

    /// 是否为空
    bool empty() const {
        return transport_id == 0 && address_bytes.empty();
    }

    /// 序列化为字节流（transport_id(4B BE) + len(2B BE) + bytes）
    std::vector<std::uint8_t> to_bytes() const;

    /// 从字节流解析（与 to_bytes 互逆）
    static std::optional<CustomTransportAddr> from_bytes(std::span<const std::uint8_t> data);
};

// ============================================================================
// CustomTransport 抽象接口
// ============================================================================
//
/// 自定义传输的连接结果（避免直接依赖 Connection，使用 void* 句柄）
using TransportConnHandle = std::shared_ptr<void>;

/// 自定义传输连接回调
using TransportAcceptCallback = std::function<void(TransportConnHandle conn,
                                                    const CustomTransportAddr &from)>;

/// 自定义传输接口
class CustomTransport {
public:
    virtual ~CustomTransport() = default;

    /// 传输 ID
    virtual TransportId id() const = 0;

    /// 传输名称（如 "tor", "ble", "mock"）
    virtual std::string_view name() const = 0;

    /// 连接到指定地址
    /// @param addr 目标地址
    /// @param timeout 连接超时
    /// @return 连接句柄（失败返回 nullptr）
    virtual TransportConnHandle connect(
        const CustomTransportAddr &addr,
        std::chrono::milliseconds timeout) = 0;

    /// 监听传入连接
    /// @param bind_addr 绑定地址
    /// @param on_accept 接受连接回调
    /// @return 是否成功开始监听
    virtual bool listen(const CustomTransportAddr &bind_addr,
                        TransportAcceptCallback on_accept) = 0;

    /// 停止监听
    virtual void stop_listen() {}

    /// 关闭传输（释放资源）
    virtual void close() {}

    /// 是否支持该地址格式（用于校验）
    virtual bool supports_address(const CustomTransportAddr &addr) const {
        return addr.transport_id == id();
    }

    /// 传输是否就绪（可用于健康检查）
    virtual bool is_ready() const { return true; }
};

// ============================================================================
// TransportRegistry 传输注册表
// ============================================================================
//
/// 传输注册表：管理已注册的多个自定义传输
class TransportRegistry {
public:
    TransportRegistry() = default;
    ~TransportRegistry() = default;

    TransportRegistry(const TransportRegistry &) = delete;
    TransportRegistry &operator=(const TransportRegistry &) = delete;

    /// 注册一个传输
    /// @return false 若 id 重复或为保留 ID
    bool register_transport(std::shared_ptr<CustomTransport> transport);

    /// 注销传输
    /// @return false 若未注册
    bool unregister_transport(TransportId id);

    /// 按 ID 查找传输
    std::shared_ptr<CustomTransport> find(TransportId id) const;

    /// 已注册的传输数量
    std::size_t size() const;

    /// 已注册的所有传输 ID 列表
    std::vector<TransportId> registered_ids() const;

    /// 已注册的所有传输名称列表
    std::vector<std::string> registered_names() const;

    /// 清空所有注册
    void clear();

    /// 根据地址查找支持该地址的传输
    /// @return 第一个支持该地址的传输，未找到返回 nullptr
    std::shared_ptr<CustomTransport> find_for_address(const CustomTransportAddr &addr) const;

    /// 并发尝试多个传输进行连接（用于多传输并发场景）
    /// @param candidates 候选传输列表
    /// @param addr 目标地址
    /// @param timeout 总超时
    /// @return 第一个成功建立的连接，全部失败返回 nullptr
    TransportConnHandle try_connect_concurrent(
        const std::vector<TransportId> &candidates,
        const CustomTransportAddr &addr,
        std::chrono::milliseconds timeout);

private:
    mutable std::shared_mutex mu_;
    std::unordered_map<TransportId, std::shared_ptr<CustomTransport>> transports_;
};

// ============================================================================
// 工具函数
// ============================================================================

/// 传输 ID 转十六进制字符串（"0x544F52"）
std::string transport_id_to_hex(TransportId id);

/// 十六进制字符串转传输 ID（解析失败返回 nullopt）
std::optional<TransportId> transport_id_from_hex(std::string_view s);

/// 传输名称注册表（内置知名传输）
std::string_view well_known_transport_name(TransportId id);

} // namespace linoh::net
