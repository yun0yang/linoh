/// router_server.cpp - 基于 linoh.lib 的 Router 服务器示例
/// 展示: Router ALPN 路由 / ProtocolHandler / EchoHandler
///
/// Router 架构:
///   Router 持有 Endpoint，spawn() 启动 accept loop
///   accept_step() 轮询 Endpoint::accept()，按 ALPN 分派到对应 ProtocolHandler
///   每个 ProtocolHandler 在独立线程中处理连接
///
/// 用法:
///   1. 运行 router_server.exe
///   2. 运行 quic_client 连接并指定 ALPN（如 iroh/1）

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WINSOCKAPI_
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/endpoint/endpoint.hpp"
#include "linoh/endpoint/builder.hpp"
#include "linoh/protocol/router.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/util/bytes.hpp"

#include <iostream>
#include <vector>
#include <map>
#include <chrono>
#include <cstring>
#include <mutex>
#include <atomic>

using namespace linoh;
using namespace linoh::base;
using namespace linoh::protocol;
using namespace linoh::endpoint;

// ============================================================================
// 常量
// ============================================================================
static constexpr uint16_t SERVER_UDP_PORT = 54321;
static constexpr size_t MAX_PKT = 2048;

// ============================================================================
// 工具
// ============================================================================
static void print_time() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    auto sec = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()) % 60;
    printf("[%02lld:%02lld.%03lld] ", (long long)sec.count(), (long long)ms.count(), (long long)ms.count());
}

static std::string ipv4_str(const sockaddr_in *sa) {
    char buf[32];
    inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
    return std::string(buf);
}

static void print_key(const char *label, std::span<const uint8_t> key) {
    printf("  %s: ", label);
    for (size_t i = 0; i < (std::min<size_t>(key.size(), 8)); ++i)
        printf("%02x", key[i]);
    printf("...\n");
}

// ============================================================================
// EchoHandler: 处理一条已建立连接，回显所有收到的 STREAM 数据
// ============================================================================
class EchoHandler : public ProtocolHandler {
public:
    explicit EchoHandler(std::string alpn) : alpn_(std::move(alpn)) {}

    void accept(std::shared_ptr<Connection> conn) override {
        print_time();
        printf("[EchoHandler] accepted conn=%llu alpn=%s\n",
               (unsigned long long)conn->id(), alpn_.c_str());

        // 注册 stream 回调
        conn->on_stream([conn](std::shared_ptr<Stream> s) {
            // P1-P3 fix(2026-07-20): 用 readable_*() 替代 recv_buffer()
            std::size_t n = s->readable_size();
            if (n > 0) {
                print_time();
                printf("[Stream] id=%llu recv=%zu bytes: ", (unsigned long long)s->id(), n);
                for (size_t i = 0; i < (std::min<size_t>(n, 32)); ++i)
                    printf("%02x ", s->readable_data()[i]);
                if (n > 32) printf("...");
                printf("\n");

                // Echo back
                conn->send_stream(s->id(), std::span<const uint8_t>(s->readable_data(), n));
                s->consume(n);
            }
            if (s->send_finished()) {
                conn->finish_stream(s->id());
            }
        });

        // 注册关闭回调
        conn->on_close([this, id = conn->id()]() {
            print_time();
            printf("[EchoHandler] conn=%llu closed\n", (unsigned long long)id);
            active_conns_--;
        });

        active_conns_++;
        printf("[EchoHandler] conn=%llu active=%d\n",
               (unsigned long long)conn->id(), (int)active_conns_);

        // 短暂运行，然后关闭（模拟处理完）
        // 真实 server 会在这里运行事件循环
        std::this_thread::sleep_for(std::chrono::seconds(30));
        print_time();
        printf("[EchoHandler] conn=%llu finishing (30s timeout)\n",
               (unsigned long long)conn->id());
        conn->close(0, "handler done");
    }

    void shutdown() override {
        print_time();
        printf("[EchoHandler] shutdown, was_active=%d\n", (int)active_conns_);
    }

    std::string alpn() const { return alpn_; }

private:
    std::string alpn_;
    std::atomic<int> active_conns_{0};
};

// ============================================================================
// Router 服务器
// ============================================================================
class RouterServer {
public:
    RouterServer(uint16_t udp_port)
        : udp_port_(udp_port)
    {
        // Winsock
        WSADATA wsa{};
        int ret = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (ret != 0) {
            std::cerr << "[ERROR] WSAStartup: " << ret << "\n";
            return;
        }

        sock_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock_ == INVALID_SOCKET) {
            std::cerr << "[ERROR] socket: " << WSAGetLastError() << "\n";
            return;
        }

        int reuse = 1;
        setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

        sockaddr_in bind_addr{};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons(udp_port);
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(sock_, (sockaddr*)&bind_addr, sizeof(bind_addr)) != 0) {
            std::cerr << "[ERROR] bind: " << WSAGetLastError() << "\n";
            return;
        }

        // 创建 Endpoint
        ctx_ = std::make_unique<linoh_asio::io_context>();
        ep_ = endpoint::Builder()
            .secret_key(SecretKey::generate())
            .alpns({"echo/1", "iroh/1", "test/1"})
            .build(*ctx_);

        // 创建 Router
        router_ = std::make_shared<Router>(ep_);

        // 注册 ALPN handlers
        auto echo1 = std::make_shared<EchoHandler>("echo/1");
        auto iroh1 = std::make_shared<EchoHandler>("iroh/1");
        auto test1 = std::make_shared<EchoHandler>("test/1");
        router_->accept("echo/1", echo1);
        router_->accept("iroh/1", iroh1);
        router_->accept("test/1", test1);
        handlers_.push_back(echo1);
        handlers_.push_back(iroh1);
        handlers_.push_back(test1);

        // 设置过滤器：演示如何 reject 来自特定地址的连接
        router_->filter([](const Incoming &inc) {
            // 简单示例：拒绝空 ALPN
            if (inc.alpn.empty()) {
                print_time();
                printf("[Filter] rejecting empty alpn from %s:%d\n",
                       inc.from.host.c_str(), inc.from.port);
                return FilterOutcome::Reject;
            }
            return FilterOutcome::Accept;
        });

        // 启动 Router 的 accept loop
        router_->spawn();

        print_time();
        printf("[Server] NodeId: ");
        print_key("id", ep_->id().as_span());
        printf("[Server] UDP port: %d\n", udp_port);
        printf("[Server] ALPN handlers: echo/1, iroh/1, test/1\n");
        printf("[Server] Router accept loop started\n");
    }

    ~RouterServer() {
        if (sock_ != INVALID_SOCKET) closesocket(sock_);
        WSACleanup();
    }

    void run() {
        std::vector<uint8_t> recv_buf(MAX_PKT);
        std::vector<uint8_t> send_buf(MAX_PKT);
        sockaddr_in client_addr{};
        int addr_len = sizeof(client_addr);
        int tick = 0;

        while (!ep_->is_closed() && !router_->is_shutdown()) {
            tick++;

            int timeout_ms = 50;
            setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));

            int n = recvfrom(sock_, (char*)recv_buf.data(), (int)recv_buf.size(), 0,
                            (sockaddr*)&client_addr, &addr_len);
            if (n > 0) {
                TransportAddr from_addr;
                from_addr.kind = TransportKind::Ip;
                from_addr.host = ipv4_str(&client_addr);
                from_addr.port = (uint16_t)ntohs(client_addr.sin_port);

                // 交给 Endpoint 处理
                std::span<const uint8_t> wire_span(recv_buf.data(), (size_t)n);
                ep_->handle_incoming(from_addr, util::Bytes(wire_span));
            }

            // Router 的 accept loop 在独立线程运行，我们只需持续收 UDP 包
            // 每个已建立的连接会由 Connection 自己处理包（通过 build_1rtt_packet）
            // 这里演示：通过 Endpoint::send_datagram 向 peer 发送响应
            //
            // 注意：由于 Connection 不直接发送，我们需要在 Connection 的 send_buffer
            // 被填充后调用 build_1rtt_packet()。这里演示手动构建响应。
        }

        print_time();
        printf("[Server] Shutdown detected, exiting run loop\n");
    }

private:
    uint16_t udp_port_;
    SOCKET sock_{INVALID_SOCKET};
    std::unique_ptr<linoh_asio::io_context> ctx_;
    std::shared_ptr<Endpoint> ep_;
    std::shared_ptr<Router> router_;
    std::vector<std::shared_ptr<EchoHandler>> handlers_;
};

// ============================================================================
// 主函数
// ============================================================================
int main() {
    printf("========================================================\n");
    printf("  linoh Router Server (ALPN routing)\n");
    printf("  UDP port: %d\n", SERVER_UDP_PORT);
    printf("========================================================\n\n");

    RouterServer server(SERVER_UDP_PORT);
    server.run();

    printf("\n[EXIT]\n");
    return 0;
}
