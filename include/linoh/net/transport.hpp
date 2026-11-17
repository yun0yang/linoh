#pragma once
#ifndef LINOH_NET_TRANSPORT_HPP_
#define LINOH_NET_TRANSPORT_HPP_

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/util/bytes.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#ifdef LINOH_WITH_BOOST_ASIO
#include <boost/asio.hpp>
namespace linoh_asio = boost::asio;
#else
#include <asio.hpp>
// linoh's bundled stub asio.hpp already defines namespace linoh_asio.
// For real asio, create an alias from asio to linoh_asio.
#ifndef LINOH_USE_STUB_ASIO
namespace linoh_asio = asio;
#endif
#endif

namespace linoh::net {

using base::EndpointId;
using base::EndpointAddr;
using util::Bytes;

/// 收到的一个 UDP 包。
struct RecvPacket {
    Bytes data;
    base::TransportAddr from;
    std::uint64_t received_at_ms{0};
};

/// Transport 抽象：对 `Endpoint` 隐藏底层是直连 UDP、Relay
/// 还是用户自定义通道的区别。
class Transport {
public:
    virtual ~Transport() = default;

    /// 人类可读的名字（用于日志）。
    virtual std::string name() const = 0;

    /// 是否可用（例如 socket 是否已绑定）。
    virtual bool is_running() const = 0;

    /// 投递一个包。返回实际发送字节数，失败返回 0。
    virtual std::size_t send_to(const base::TransportAddr &dst, std::span<const uint8_t> payload) = 0;

    /// 入站数据报回调（对所有接收者统一接口）。
    using PacketHandler = std::function<void(RecvPacket)>;
    virtual void set_packet_handler(PacketHandler h) = 0;

    /// 返回当前实际监听的端口（对 UDP Transport 有意义）。
    virtual uint16_t local_port() const { return 0; }

    /// 绑定/打开资源。
    virtual void start() = 0;
    /// 关闭资源。
    virtual void stop() = 0;
};

/// UDP Transport：最常用的直连类型。
///
/// 支持 IPv4 / IPv6 双栈绑定；使用 asio 的 UDP socket + steady_timer
/// 完成心跳与超时管理。
class UdpTransport : public Transport, public std::enable_shared_from_this<UdpTransport> {
public:
    /// 以通配地址绑定（0.0.0.0:port / [::]:port）。
    static std::shared_ptr<UdpTransport> make(linoh_asio::io_context &ctx,
                                               bool ipv6 = false,
                                               uint16_t port = 0);

    // Transport impl
    std::string name() const override { return ipv6_ ? "udp6" : "udp4"; }
    bool is_running() const override { return running_; }
    std::size_t send_to(const base::TransportAddr &dst, std::span<const uint8_t> payload) override;
    // v1.7.0.7 net H3: handler_ 加锁保护，避免 set_packet_handler 与 loop_recv 并发访问导致数据竞争（UB）
    //   根因：原实现 set_packet_handler 直接赋值 handler_，loop_recv 在 asio 回调中无锁读取 handler_，
    //         两者无同步，并发调用会导致 std::function 内部状态损坏或 UAF
    //   修复：新增 handler_mu_ 保护 handler_，set_packet_handler 加锁写入，
    //         loop_recv 加锁拷贝到局部变量后锁外调用（swap-out-of-lock 模式）
    void set_packet_handler(PacketHandler h) override {
        std::lock_guard<std::mutex> lk(handler_mu_);
        handler_ = std::move(h);
    }
    uint16_t local_port() const override { return bound_port_; }
    void start() override;
    void stop() override;

private:
    UdpTransport(linoh_asio::io_context &ctx, bool ipv6, uint16_t port)
        : ctx_{ctx}, socket_{ctx}, ipv6_{ipv6}, requested_port_{port} {}

    void loop_recv();

    linoh_asio::io_context &ctx_;
    linoh_asio::ip::udp::socket socket_;
    bool ipv6_{false};
    uint16_t requested_port_{0};
    uint16_t bound_port_{0};
    std::atomic<bool> running_{false};
    mutable std::mutex handler_mu_;  // v1.7.0.7 net H3: 保护 handler_ 的并发读写
    PacketHandler handler_;

    // 每次接收都用新的 peer_endpoint + buffer 记录
    linoh_asio::ip::udp::endpoint recv_endpoint_;
    std::vector<uint8_t> recv_buffer_;
};

} // namespace linoh::net

#endif // LINOH_NET_TRANSPORT_HPP_
