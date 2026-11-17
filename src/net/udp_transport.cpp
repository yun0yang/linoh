#include "linoh/net/transport.hpp"

#include "linoh/util/logging.hpp"

#include <chrono>
#include <system_error>
#include <vector>

namespace linoh::net {

std::shared_ptr<UdpTransport> UdpTransport::make(linoh_asio::io_context &ctx, bool ipv6, uint16_t port) {
    // 使用 new 而非 make_shared 允许访问 private ctor
    struct make_shared_enabler : public UdpTransport {
        make_shared_enabler(linoh_asio::io_context &c, bool ipv6_, uint16_t p) : UdpTransport(c, ipv6_, p) {}
    };
    auto t = std::make_shared<make_shared_enabler>(ctx, ipv6, port);
    return t;
}

void UdpTransport::start() {
    try {
        if (ipv6_) {
            socket_.open(linoh_asio::ip::udp::v6());
            socket_.set_option(linoh_asio::ip::v6_only(true));
        } else {
            socket_.open(linoh_asio::ip::udp::v4());
        }
        socket_.bind(linoh_asio::ip::udp::endpoint(
            ipv6_ ? linoh_asio::ip::udp::v6() : linoh_asio::ip::udp::v4(), requested_port_));
        bound_port_ = socket_.local_endpoint().port();
        running_ = true;
        loop_recv();
    } catch (const std::exception &e) {
        LINOH_ERROR("UdpTransport start failed:", e.what());
        running_ = false;
    }
}

void UdpTransport::stop() {
    running_ = false;
    std::error_code ec;
    socket_.close(ec);
}

std::size_t UdpTransport::send_to(const base::TransportAddr &dst, std::span<const uint8_t> payload) {
    try {
        linoh_asio::ip::udp::resolver res(ctx_);
        auto results = res.resolve(ipv6_ ? linoh_asio::ip::udp::v6() : linoh_asio::ip::udp::v4(),
                                    dst.host, std::to_string(dst.port));
        // Use iterator dereference (compatible with both real asio and stub)
        auto it = results.begin();
        if (it == results.end()) return 0;
        auto ep = (*it).endpoint();
        return socket_.send_to(linoh_asio::buffer(payload.data(), payload.size()), ep);
    } catch (const std::exception &e) {
        LINOH_ERROR("UdpTransport send_to failed:", e.what());
        return 0;
    }
}

void UdpTransport::loop_recv() {
    if (!running_) return;
    // v1.7.0.6: 缓冲区扩容到 9000 字节以支持 Jumbo Frame（局域网 MTU 9000）
    // 之前 1500 字节会导致启用 Jumbo Frame 后大包被截断
    // K-FIX-MTU-001: 同步 connection.cpp kMaxPacketSize=9300，扩容到 9300
    //   容纳 send_buf=9200 构建的 1-RTT 包，避免 DoS 保护误关闭连接
    recv_buffer_.resize(9300);
    socket_.async_receive_from(
        linoh_asio::buffer(recv_buffer_.data(), recv_buffer_.size()),
        recv_endpoint_,
        [this, self = shared_from_this()](std::error_code ec, std::size_t n) {
            if (ec) {
                if (ec == linoh_asio::error::operation_aborted) {
                    // 正常关闭，不重启 recv loop
                    return;
                }
                // v1.7.0.5 P4 (C5): 容忍 Windows UDP 瞬态错误（借鉴 iroh #4348 v1.0.1）
                // Windows UDP socket 收到 ICMP Port Unreachable 时返回 WSAECONNRESET (10054)，
                // 这是瞬态错误，不应杀掉 recv loop。继续重启 async_receive_from。
                // 常见瞬态错误码：
                //   - WSAECONNRESET (10054): ICMP Port Unreachable
                //   - WSAEMSGSIZE (10040): 消息过大（缓冲区不够）
                //   - WSAEWOULDBLOCK (10035): 非阻塞 socket 无数据
                LINOH_WARN("UdpTransport recv transient error (continuing):", ec.message());
                loop_recv();  // 重启 recv loop
                return;
            }
            // v1.7.0.7 net H3: 加锁拷贝 handler_ 到局部变量后锁外调用，
            //   避免 set_packet_handler 并发修改 handler_ 时数据竞争
            PacketHandler handler_copy;
            {
                std::lock_guard<std::mutex> lk(handler_mu_);
                handler_copy = handler_;
            }
            if (handler_copy && n > 0) {
                util::Bytes b(std::span<const uint8_t>(recv_buffer_.data(), n));
                base::TransportAddr from;
                from.kind = base::TransportKind::Ip;
#ifdef LINOH_USE_STUB_ASIO
                from.host = recv_endpoint_.address_().to_string();
#else
                from.host = recv_endpoint_.address().to_string();
#endif
                from.port = recv_endpoint_.port();
                handler_copy(RecvPacket{std::move(b), std::move(from), /*received_at=*/0});
            }
            loop_recv();
        });
}

} // namespace linoh::net
