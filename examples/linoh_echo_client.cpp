/// linoh_echo_client.cpp - 端到端 Echo 客户端
/// 用法: linoh_echo_client.exe [服务器IP] [端口]

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/endpoint/connection.hpp"
#include "linoh/endpoint/builder.hpp"
#include "linoh/endpoint/endpoint.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/util/bytes.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <memory>

using namespace linoh;
using namespace linoh::base;
using namespace linoh::protocol;
using namespace linoh::endpoint;

int main(int argc, char *argv[]) {
    const char *server_ip = "127.0.0.1";
    uint16_t server_port = 54321;
    if (argc >= 2) server_ip = argv[1];
    if (argc >= 3) server_port = (uint16_t)atoi(argv[2]);

    printf("========================================================\n");
    printf("  linoh Echo Client (v1.0)\n");
    printf("  Server: %s:%d\n", server_ip, server_port);
    printf("========================================================\n\n");

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[ERROR] WSAStartup\n"); return 1;
    }
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        printf("[ERROR] socket: %d\n", WSAGetLastError());
        WSACleanup(); return 1;
    }
    int timeout = 1500;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    // === Phase 1: 发送 Initial 包 ===
    ConnectionId client_cid = ConnectionId::generate();
    ConnectionId server_dcid;

    // 用 make_initial 构造 Initial 包
    auto initial_hdr = PacketHeader::make_initial(server_dcid, client_cid);
    std::vector<uint8_t> initial_wire(512);
    std::size_t hdr_bytes = initial_hdr.serialize_to(initial_wire.data(), initial_wire.size());
    // 最小化 payload
    initial_wire.resize(hdr_bytes);

    printf("[SEND] Initial packet (%zu bytes) -> %s:%d\n",
           initial_wire.size(), server_ip, server_port);
    sendto(sock, (const char*)initial_wire.data(), (int)initial_wire.size(), 0,
          (sockaddr*)&server_addr, sizeof(server_addr));

    // 等待服务器响应（可选）
    std::vector<uint8_t> recv_buf(4096);
    {
        sockaddr_in from{}; int from_len = sizeof(from);
        int rn = recvfrom(sock, (char*)recv_buf.data(), (int)recv_buf.size(), 0,
                         (sockaddr*)&from, &from_len);
        if (rn > 0) {
            printf("[RECV] Server acknowledged (%d bytes)\n", rn);
        } else {
            printf("[INFO] No server response to Initial — continuing.\n");
        }
    }

    // === Phase 2: 创建 Connection 并通过 Connection API 发送 STREAM 数据 ===
    // 客户端方向 Outbound，local_cid = client_cid, remote_cid = client_cid
    Connection::Config conn_cfg;
    conn_cfg.secret_key = SecretKey::generate();
    conn_cfg.local_cid = client_cid;
    conn_cfg.remote_cid = client_cid;
    conn_cfg.direction = Direction::Outbound;
    conn_cfg.alpn = "echo/1";
    auto conn = std::make_shared<Connection>(std::move(conn_cfg));

    // 注册 stream 回调：接收回显
    int echo_received = 0;
    int echo_success = 0;
    conn->on_stream([&](std::shared_ptr<Stream> s) {
        auto data = s->read();
        if (!data.empty()) {
            std::string echo_str(data.begin(), data.end());
            printf("  [ECHO] stream #%llu: %s\n",
                   (unsigned long long)s->id(), echo_str.c_str());
            echo_received++;
            if (!echo_str.empty()) echo_success++;
        }
    });

    const char *messages[] = {
        "Hello linoh!",
        "Echo test",
        "Packet test message",
        "Test 12345",
        "Goodbye!"
    };
    int msg_count = sizeof(messages) / sizeof(messages[0]);

    printf("\n=== Sending STREAM messages (1-RTT packets) ===\n\n");

    for (int i = 0; i < msg_count; i++) {
        std::string msg(messages[i]);
        // 用 Connection API 写数据到 stream
        auto st = conn->open_stream();
        st->write(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(msg.data()), msg.size()));

        // 构造 1-RTT 包
        std::vector<uint8_t> out_buf(2048);
        std::span<uint8_t> out_span(out_buf.data(), out_buf.size());
        std::size_t pkt_len = conn->build_1rtt_packet(out_span);

        if (pkt_len > 0) {
            printf("[Msg %d/%d] \"%s\" -> %zu-byte wire\n",
                   i + 1, msg_count, msg.c_str(), pkt_len);
            sendto(sock, (const char*)out_buf.data(), (int)pkt_len, 0,
                  (sockaddr*)&server_addr, sizeof(server_addr));

            // 等待回显
            sockaddr_in from{}; int from_len = sizeof(from);
            int rn = recvfrom(sock, (char*)recv_buf.data(), (int)recv_buf.size(), 0,
                             (sockaddr*)&from, &from_len);
            if (rn > 0) {
                conn->handle_packet(util::Bytes(
                    std::span<const uint8_t>(recv_buf.data(), (size_t)rn)));
            } else {
                printf("  (timeout)\n");
            }
        }
    }

    printf("\n=== Summary ===\n");
    printf("  Messages sent:      %d\n", msg_count);
    printf("  Echoes received:    %d\n", echo_received);
    printf("  Echoes with data:   %d\n", echo_success);
    printf("  Status:             %s\n",
           (echo_success >= msg_count - 1) ? "PASSED" : "FAILED");

    closesocket(sock);
    WSACleanup();
    return (echo_success >= msg_count - 1) ? 0 : 1;
}
