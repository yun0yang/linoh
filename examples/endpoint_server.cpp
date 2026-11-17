/// endpoint_server.cpp - 基于 linoh.lib 的 Endpoint 服务器示例
/// 展示: Endpoint 创建 / accept() 入站连接 / Stream 收发数据
///
/// 用法:
///   1. 运行 endpoint_server.exe，记住打印的 NodeId
///   2. 运行 quic_client.exe <NodeId> <port> 连接到此服务器

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
#include "linoh/protocol/packet.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/util/bytes.hpp"

#include <iostream>
#include <vector>
#include <map>
#include <chrono>
#include <cstring>
#include <optional>
#include <mutex>

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

static void print_hex(const char *label, const uint8_t *data, size_t n) {
    printf("  %s: ", label);
    for (size_t i = 0; i < (std::min<size_t>(n, 16)); ++i)
        printf("%02x ", data[i]);
    if (n > 16) printf("... (%zu bytes)", n);
    printf("\n");
}

static void print_key(const char *label, std::span<const uint8_t> key) {
    printf("  %s: ", label);
    for (size_t i = 0; i < (std::min<size_t>(key.size(), 8)); ++i)
        printf("%02x", key[i]);
    printf("...\n");
}

// ============================================================================
// Endpoint 服务器
// ============================================================================
class EndpointServer {
public:
    EndpointServer(uint16_t udp_port)
        : udp_port_(udp_port)
        , ctx_(std::make_unique<linoh_asio::io_context>())
    {
        // Winsock 初始化
        WSADATA wsa{};
        int ret = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (ret != 0) {
            std::cerr << "[ERROR] WSAStartup failed: " << ret << "\n";
            return;
        }

        // 创建 UDP socket
        sock_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock_ == INVALID_SOCKET) {
            std::cerr << "[ERROR] socket() failed: " << WSAGetLastError() << "\n";
            return;
        }

        int reuse = 1;
        setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

        sockaddr_in bind_addr{};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons(udp_port_);
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(sock_, (sockaddr*)&bind_addr, sizeof(bind_addr)) != 0) {
            std::cerr << "[ERROR] bind() failed on port " << udp_port_
                      << ": " << WSAGetLastError() << "\n";
            return;
        }

        // 创建 Endpoint（使用流式 Builder API）
        ep_ = endpoint::Builder()
            .secret_key(SecretKey::generate())
            .alpns({"echo/1", "iroh/1"})
            .build(*ctx_);

        // 设置接受连接回调
        ep_->set_accept_handler([this](Incoming inc) {
            this->on_incoming(std::move(inc));
        });

        print_time();
        printf("[Server] NodeId: ");
        print_key("id", ep_->id().as_span());
        printf("[Server] UDP port: %d\n", udp_port_);
        printf("[Server] Listening for connections...\n");
    }

    ~EndpointServer() {
        if (sock_ != INVALID_SOCKET) closesocket(sock_);
        WSACleanup();
    }

    /// 主循环：接收 UDP 包 -> 分发给 Endpoint -> 轮询 accept -> 轮询连接发包
    void run() {
        std::vector<uint8_t> recv_buf(MAX_PKT);
        std::vector<uint8_t> send_buf(MAX_PKT);
        sockaddr_in client_addr{};
        int addr_len = sizeof(client_addr);
        int tick = 0;

        while (!ep_->is_closed()) {
            tick++;

            // 接收 UDP 包（非阻塞，超时 100ms）
            int timeout_ms = 100;
            setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));

            int n = recvfrom(sock_, (char*)recv_buf.data(), (int)recv_buf.size(), 0,
                            (sockaddr*)&client_addr, &addr_len);

            if (n > 0) {
                // 构造 TransportAddr
                TransportAddr from_addr;
                from_addr.kind = TransportKind::Ip;
                from_addr.host = ipv4_str(&client_addr);
                from_addr.port = (uint16_t)ntohs(client_addr.sin_port);

                // 交给 Endpoint 处理（路由到对应 Connection）
                std::span<const uint8_t> wire_span(recv_buf.data(), (size_t)n);
                ep_->handle_incoming(from_addr, util::Bytes(wire_span));
            }

            // 轮询 accept()
            while (true) {
                auto inc_opt = ep_->accept();
                if (!inc_opt) break;
                on_incoming(std::move(*inc_opt));
            }

            // 轮询所有活跃连接：构建 1-RTT 包并发送
            std::lock_guard lock(conn_mu_);
            for (auto &kv : connections_) {
                auto &entry = kv.second;
                auto conn = entry.conn.lock();
                if (!conn) continue;

                std::span<uint8_t> out_buf(send_buf.data(), send_buf.size());
                std::size_t pkt_len = conn->build_1rtt_packet(out_buf);
                if (pkt_len == 0) continue;

                // 发送到对端
                sockaddr_in dest{};
                dest.sin_family = AF_INET;
                dest.sin_port = htons(entry.peer_port);
                inet_pton(AF_INET, entry.peer_host.c_str(), &dest.sin_addr);

                int sent = sendto(sock_, (char*)send_buf.data(), (int)pkt_len, 0,
                                 (sockaddr*)&dest, sizeof(dest));
                if (sent > 0) {
                    print_time();
                    printf("[TX] %d bytes -> %s:%d (conn=%llu)\n",
                           sent, entry.peer_host.c_str(), entry.peer_port,
                           (unsigned long long)conn->id());
                }
            }
        }
    }

private:
    void on_incoming(Incoming inc) {
        auto conn = inc.conn.lock();
        if (!conn) return;

        print_time();
        printf("[INCOMING] peer: ");
        print_key("id", conn->peer_id().as_span());
        printf("  alpn=%s  from=%s:%d\n",
               inc.alpn.c_str(), inc.from.host.c_str(), inc.from.port);

        // 注册 stream 回调
        auto conn_weak = inc.conn;
        conn->on_stream([conn_weak](std::shared_ptr<Stream> s) {
            auto c = conn_weak.lock();
            if (!c) return;
            // P1-P3 fix(2026-07-20): 用 readable_*() 替代 recv_buffer()
            std::size_t n = s->readable_size();
            if (n > 0) {
                print_hex("[STREAM] recv", s->readable_data(), n);
                c->send_stream(s->id(), std::span<const uint8_t>(s->readable_data(), n));
                s->consume(n);
            }
            if (s->send_finished()) {
                c->finish_stream(s->id());
            }
        });

        // 注册关闭回调
        auto conn_id = conn->id();
        conn->on_close([this, conn_id]() {
            print_time();
            printf("[CLOSE] connection %llu closed\n", (unsigned long long)conn_id);
            std::lock_guard lock(this->conn_mu_);
            for (auto it = this->connections_.begin(); it != this->connections_.end(); ) {
                if (it->second.conn.expired()) {
                    it = this->connections_.erase(it);
                } else {
                    ++it;
                }
            }
        });

        // 保存连接信息（用于后续发送）
        {
            std::lock_guard lock(conn_mu_);
            ConnectionEntry entry;
            entry.conn = conn;
            entry.peer_host = inc.from.host;
            entry.peer_port = inc.from.port;
            connections_[conn->id()] = std::move(entry);
        }
    }

    struct ConnectionEntry {
        std::weak_ptr<Connection> conn;
        std::string peer_host;
        uint16_t peer_port{0};
    };

    uint16_t udp_port_;
    SOCKET sock_{INVALID_SOCKET};
    std::unique_ptr<linoh_asio::io_context> ctx_;
    std::shared_ptr<Endpoint> ep_;
    std::mutex conn_mu_;
    std::map<uint64_t, ConnectionEntry> connections_;
};

// ============================================================================
// 主函数
// ============================================================================
int main() {
    printf("========================================================\n");
    printf("  linoh Endpoint Server\n");
    printf("  UDP port: %d\n", SERVER_UDP_PORT);
    printf("========================================================\n\n");

    EndpointServer server(SERVER_UDP_PORT);
    server.run();

    printf("\n[EXIT]\n");
    return 0;
}
