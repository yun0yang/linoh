/// linoh UDP echo client (WinSock2)
/// 协议格式: [4B seq BE][AEAD ciphertext+tag]
/// 双方 PSK 相同，AD 固定为 "linoh-echo-demo"

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/tls/handshake_token_key.hpp"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace linoh;

static constexpr uint16_t SERVER_PORT = 54321;
static constexpr size_t   MAX_PKT = 2048;
static constexpr size_t   SEQ_SIZE = 4;

// 演示 PSK（必须与服务器完全一致）
static const uint8_t DEMO_PSK[32] = {
    0x6c, 0x69, 0x6e, 0x6f, 0x68, 0x2d, 0x64, 0x65,
    0x6d, 0x6f, 0x2d, 0x70, 0x73, 0x6b, 0x2d, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30
};

// 固定 AD（双方约定）
static const char* AD_STR = "linoh-echo-demo";

int main() {
    std::cout << "=== linoh UDP echo client ===\n";
    std::cout << "    (End-to-End AEAD encryption demo)\n\n";

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup 失败\n";
        return 1;
    }

    base::SecretKey sk = base::SecretKey::generate();
    base::EndpointId  id = sk.public_key();
    auto tk = tls::HandshakeTokenKey::from_bytes(
        std::span<const uint8_t>(DEMO_PSK, 32));

    std::cout << "[client] 节点 ID: " << id.fmt_short() << "\n";
    std::cout << "[client] 目标: 127.0.0.1:" << SERVER_PORT << "\n\n";

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        std::cerr << "socket() 失败\n";
        WSACleanup();
        return 1;
    }

    int timeout_ms = 2000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr);
    srv.sin_port = htons(SERVER_PORT);

    // AD：固定字符串（简单起见）
    std::string ad = AD_STR;
    std::span<const uint8_t> ad_bytes(
        reinterpret_cast<const uint8_t*>(ad.data()), ad.size());

    std::vector<std::string> messages = {
        "hello linoh!",
        "AEAD encryption test 123",
        "End-to-End Secure Message ✓",
        "这是一条中文消息 —— 测试 UTF-8"
    };

    int ok_count = 0;

    for (size_t i = 0; i < messages.size(); ++i) {
        const std::string& msg = messages[i];
        uint32_t seq = static_cast<uint32_t>(i + 1);

        std::cout << "发送 #" << seq << ": \"" << msg << "\"\n";

        std::span<const uint8_t> payload(
            reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
        auto enc = tk.seal(/*nonce_int=*/ static_cast<uint64_t>(seq),
                           ad_bytes, payload);

        // 组装: [4B seq BE][enc]
        std::vector<uint8_t> pkt(SEQ_SIZE + enc.size());
        pkt[0] = static_cast<uint8_t>((seq >> 24) & 0xFF);
        pkt[1] = static_cast<uint8_t>((seq >> 16) & 0xFF);
        pkt[2] = static_cast<uint8_t>((seq >> 8) & 0xFF);
        pkt[3] = static_cast<uint8_t>(seq & 0xFF);
        std::memcpy(pkt.data() + SEQ_SIZE, enc.data(), enc.size());

        int sent = sendto(s, reinterpret_cast<const char*>(pkt.data()),
                          static_cast<int>(pkt.size()), 0,
                          reinterpret_cast<sockaddr*>(&srv), sizeof(srv));
        if (sent == SOCKET_ERROR) {
            std::cerr << "  sendto 失败: " << WSAGetLastError() << "\n";
            continue;
        }
        std::cout << "  已发送 " << sent << " 字节 (密文 " << enc.size()
                  << " bytes + 4B seq = " << pkt.size() << " bytes)\n";

        // 等待回复
        std::vector<uint8_t> reply_buf(MAX_PKT);
        sockaddr_in from{};
        int fromlen = sizeof(from);
        int n = recvfrom(s, reinterpret_cast<char*>(reply_buf.data()),
                         static_cast<int>(reply_buf.size()), 0,
                         reinterpret_cast<sockaddr*>(&from), &fromlen);

        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                std::cout << "  ⏱ 等待超时（确保服务器已启动）\n";
            } else {
                std::cerr << "  recvfrom 失败: " << err << "\n";
            }
            std::cout << "\n";
            continue;
        }
        if (static_cast<size_t>(n) < SEQ_SIZE) continue;

        // 解析回复
        uint32_t reply_seq =
            (static_cast<uint32_t>(reply_buf[0]) << 24) |
            (static_cast<uint32_t>(reply_buf[1]) << 16) |
            (static_cast<uint32_t>(reply_buf[2]) << 8) |
            static_cast<uint32_t>(reply_buf[3]);

        std::span<const uint8_t> ct(reply_buf.data() + SEQ_SIZE,
                                    n - SEQ_SIZE);
        auto dec = tk.open(/*nonce_int=*/ static_cast<uint64_t>(reply_seq),
                           ad_bytes, ct);

        if (dec.empty()) {
            std::cerr << "  ✗ AEAD 解密回复失败\n\n";
            continue;
        }

        std::string reply(dec.begin(), dec.end());
        std::cout << "  ✓ 回复 #" << reply_seq << ": \"" << reply
                  << "\" (" << n << " 字节密文)\n\n";
        ++ok_count;
    }

    closesocket(s);
    WSACleanup();

    std::cout << "=== 完成 ===" << std::endl;
    std::cout << "成功: " << ok_count << "/" << messages.size() << std::endl;
    return (ok_count == static_cast<int>(messages.size())) ? 0 : 1;
}
