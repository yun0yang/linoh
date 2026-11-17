/// linoh_echo_server.cpp - 端到端 Echo 服务器
/// 用法: linoh_echo_server.exe [端口号]

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/endpoint/endpoint.hpp"
#include "linoh/endpoint/builder.hpp"
#include "linoh/endpoint/connection.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/util/bytes.hpp"

#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <memory>

using namespace linoh;
using namespace linoh::base;
using namespace linoh::protocol;
using namespace linoh::endpoint;

struct PeerInfo {
    std::shared_ptr<Connection> conn;
    sockaddr_in addr;
};

static std::string ipv4_str(const sockaddr_in *sa) {
    char buf[32];
    inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
    return std::string(buf);
}

int main(int argc, char *argv[]) {
    uint16_t port = 54321;
    if (argc >= 2) port = (uint16_t)atoi(argv[1]);

    printf("========================================================\n");
    printf("  linoh Echo Server (v1.0)\n");
    printf("  UDP port: %d\n", port);
    printf("========================================================\n\n");

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[ERROR] WSAStartup failed\n"); return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        printf("[ERROR] socket: %d\n", WSAGetLastError());
        WSACleanup(); return 1;
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(port);
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (sockaddr*)&bind_addr, sizeof(bind_addr)) != 0) {
        printf("[ERROR] bind: %d\n", WSAGetLastError());
        closesocket(sock); WSACleanup(); return 1;
    }
    int rcv_timeout = 100;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&rcv_timeout, sizeof(rcv_timeout));

    // Endpoint 管理连接
    auto ctx = std::make_shared<linoh_asio::io_context>();
    auto ep = Builder()
        .secret_key(SecretKey::generate())
        .alpns({"echo/1"})
        .build(*ctx);

    printf("[READY] Listening on UDP :%d\n", port);
    printf("        (Use Ctrl-C to stop)\n\n");

    std::vector<uint8_t> recv_buf(4096);
    std::vector<uint8_t> send_buf(4096);
    std::map<std::string, PeerInfo> peers; // key = "host:port"
    std::mutex peers_mu;

    while (true) {
        sockaddr_in from{};
        int from_len = sizeof(from);
        int n = recvfrom(sock, (char*)recv_buf.data(), (int)recv_buf.size(), 0,
                        (sockaddr*)&from, &from_len);
        if (n > 0) {
            TransportAddr from_addr;
            from_addr.kind = TransportKind::Ip;
            from_addr.host = ipv4_str(&from);
            from_addr.port = (uint16_t)ntohs(from.sin_port);
            std::string peer_key = from_addr.host + ":" + std::to_string(from_addr.port);

            std::span<const uint8_t> wire(recv_buf.data(), (size_t)n);
            try {
                ep->handle_incoming(from_addr, util::Bytes(wire));
            } catch (const std::exception &e) {
                printf("[EXCEPTION] %s\n", e.what());
            }

            // 轮询 accept
            while (auto inc = ep->accept()) {
                auto conn = inc->conn;
                if (!conn) continue;
                printf("[ACCEPT] conn #%llu from %s\n",
                       (unsigned long long)conn->id(), peer_key.c_str());

                // 注册 stream 回调：回显
                std::weak_ptr<Connection> weak = conn;
                conn->on_stream([weak](std::shared_ptr<Stream> s) {
                    auto c = weak.lock();
                    if (!c) return;
                    auto data = s->read();
                    if (!data.empty()) {
                        s->write(data);  // 在同一流上回写
                    }
                });

                std::lock_guard<std::mutex> lk(peers_mu);
                peers[peer_key] = {conn, from};
            }
        }

        // 轮询所有连接：构建回包并 UDP 发送
        {
            std::lock_guard<std::mutex> lk(peers_mu);
            for (auto &kv : peers) {
                auto &pi = kv.second;
                if (!pi.conn) continue;
                std::span<uint8_t> out(send_buf.data(), send_buf.size());
                size_t pkt_len = pi.conn->build_1rtt_packet(out);
                if (pkt_len > 0) {
                    int sent = sendto(sock, (char*)send_buf.data(), (int)pkt_len, 0,
                                     (sockaddr*)&pi.addr, sizeof(pi.addr));
                    if (sent > 0) {
                        printf("[SEND] %zu bytes -> %s\n", pkt_len, kv.first.c_str());
                    }
                }
            }
        }
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
