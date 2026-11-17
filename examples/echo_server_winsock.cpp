/// linoh UDP echo server (WinSock2)
///
/// 简化的端到端加密协议：
///   客户端包格式: [4B seq BE][payload (AEAD 认证加密)]
///   服务器包格式: [4B seq BE][ACK payload (AEAD)]
///
/// 其中: 我们用 "linoh-demo-aead" 作为双方都知道的 PSK
///
/// 运行方式:
///   终端 A： echo_server_winsock.exe
///   终端 B： echo_client_winsock.exe

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

static constexpr uint16_t PORT = 54321;
static constexpr size_t   MAX_PKT = 2048;
static constexpr size_t   SEQ_SIZE = 4; // 4 字节序列号（明文）

// 演示用 PSK：32 字节（与客户端保持一致）
static const uint8_t DEMO_PSK[32] = {
    0x6c, 0x69, 0x6e, 0x6f, 0x68, 0x2d, 0x64, 0x65,
    0x6d, 0x6f, 0x2d, 0x70, 0x73, 0x6b, 0x2d, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30
};

// 固定 AD（与客户端约定）
static const char* AD_STR = "linoh-echo-demo";

int main() {
    std::cout << "=== linoh UDP echo server ===\n";
    std::cout << "    (End-to-End AEAD encryption demo)\n\n";

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup 失败\n";
        return 1;
    }

    // 身份（Ed25519 公钥 = EndpointId）
    base::SecretKey sk = base::SecretKey::generate();
    base::EndpointId  id = sk.public_key();
    auto tk = tls::HandshakeTokenKey::from_bytes(
        std::span<const uint8_t>(DEMO_PSK, 32));

    std::cout << "[server] 节点 ID: " << id.fmt_short() << "\n";
    std::cout << "[server] 监听 UDP:" << PORT << " (127.0.0.1 only)\n";
    std::cout << "[server] 等待消息...\n\n";

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        std::cerr << "socket() 失败\n";
        WSACleanup();
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(PORT);

    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "bind() 失败: " << WSAGetLastError() << "\n";
        closesocket(s);
        WSACleanup();
        return 1;
    }

    std::vector<uint8_t> buf(MAX_PKT);
    size_t pkt_count = 0;

    while (true) {
        sockaddr_in from{};
        int fromlen = sizeof(from);

        int n = recvfrom(s, reinterpret_cast<char*>(buf.data()),
                         static_cast<int>(buf.size()), 0,
                         reinterpret_cast<sockaddr*>(&from), &fromlen);
        if (n <= 0) {
            std::cerr << "recvfrom 失败: " << WSAGetLastError() << "\n";
            continue;
        }
        ++pkt_count;

        char fromIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from.sin_addr, fromIP, sizeof(fromIP));
        uint16_t fromPort = ntohs(from.sin_port);
        std::cout << "[server] 收到 " << n << " 字节 来自 " << fromIP
                  << ":" << fromPort << " (#" << pkt_count << ")\n";

        if (static_cast<size_t>(n) < SEQ_SIZE) {
            std::cerr << "  包太小，忽略\n";
            continue;
        }

        // 解析包: [4B seq (big-endian)][AEAD ciphertext+tag]
        uint32_t seq = (static_cast<uint32_t>(buf[0]) << 24) |
                       (static_cast<uint32_t>(buf[1]) << 16) |
                       (static_cast<uint32_t>(buf[2]) << 8) |
                       static_cast<uint32_t>(buf[3]);

        std::span<const uint8_t> ct(buf.data() + SEQ_SIZE, n - SEQ_SIZE);

        // AD（关联数据）：固定字符串，简化演示
        std::string ad = AD_STR;
        std::span<const uint8_t> ad_bytes(
            reinterpret_cast<const uint8_t*>(ad.data()), ad.size());

        // AEAD 解密（密钥：DEMO_PSK；nonce：把 32 位 seq 填入 12 字节 nonce）
        auto dec = tk.open(/*nonce_int=*/ static_cast<uint64_t>(seq),
                           ad_bytes, ct);
        if (dec.empty()) {
            std::cerr << "  ✗ AEAD 解密失败（密钥或 nonce 不匹配，或已被篡改）\n";
            continue;
        }

        std::string plaintext(dec.begin(), dec.end());
        std::cout << "  seq = " << seq << " | 明文 = \"" << plaintext << "\"\n";

        // 构造 ACK 回复
        std::string reply = "ACK(" + std::to_string(seq) + "): " + plaintext;
        std::span<const uint8_t> reply_bytes(
            reinterpret_cast<const uint8_t*>(reply.data()), reply.size());

        // 回复的 nonce = 原 seq + 1000（区分方向，避免混淆）
        uint32_t reply_seq = seq + 1000;
        auto enc = tk.seal(/*nonce_int=*/ static_cast<uint64_t>(reply_seq),
                           ad_bytes, reply_bytes);

        // 组装包: [4B reply_seq BE][enc]
        std::vector<uint8_t> reply_pkt(SEQ_SIZE + enc.size());
        reply_pkt[0] = static_cast<uint8_t>((reply_seq >> 24) & 0xFF);
        reply_pkt[1] = static_cast<uint8_t>((reply_seq >> 16) & 0xFF);
        reply_pkt[2] = static_cast<uint8_t>((reply_seq >> 8) & 0xFF);
        reply_pkt[3] = static_cast<uint8_t>(reply_seq & 0xFF);
        std::memcpy(reply_pkt.data() + SEQ_SIZE, enc.data(), enc.size());

        sendto(s, reinterpret_cast<const char*>(reply_pkt.data()),
               static_cast<int>(reply_pkt.size()), 0,
               reinterpret_cast<sockaddr*>(&from), fromlen);

        std::cout << "  ✓ 已回复 " << reply_pkt.size() << " 字节: \""
                  << reply << "\"\n\n";
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
