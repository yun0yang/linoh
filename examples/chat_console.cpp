/// linoh 聊天 - 简易控制台版
///  用法: 先启动 echo_server_winsock.exe，再启动本程序
#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/tls/handshake_token_key.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

static constexpr uint16_t SERVER_PORT = 54321;
static const uint8_t DEMO_PSK[32] = {
    0x6c, 0x69, 0x6e, 0x6f, 0x68, 0x2d, 0x64, 0x65,
    0x6d, 0x6f, 0x2d, 0x70, 0x73, 0x6b, 0x2d, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x30
};

static std::string utf8_from_wstring(const std::wstring &w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string r(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, r.data(), n, nullptr, nullptr);
    return r;
}

static std::wstring wstring_from_utf8(const std::string &s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 1) return {};
    std::wstring r(n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, r.data(), n);
    return r;
}

int wmain() {
    std::wcout << L"=== linoh 聊天 (控制台版) ===\n"
               << L"正在连接 127.0.0.1:" << SERVER_PORT << L"\n\n";

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup 失败\n";
        return 1;
    }

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        std::cerr << "socket() 失败: " << WSAGetLastError() << "\n";
        WSACleanup(); return 1;
    }

    int timeout_ms = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);

    auto tk = linoh::tls::HandshakeTokenKey::from_bytes(
        std::span<const uint8_t>(DEMO_PSK, 32));

    std::wcout << L"AEAD 密钥已加载。\n"
               << L"输入消息回车发送；空行退出。\n\n";

    uint32_t seq = 0;
    std::wstring line;
    while (std::getline(std::wcin, line)) {
        if (line.empty()) break;
        seq++;

        std::string msg = utf8_from_wstring(line);
        auto enc = tk.seal(seq, std::span<const uint8_t>((const uint8_t*)"linoh-echo-demo", 13),
                          std::span<const uint8_t>((const uint8_t*)msg.data(), msg.size()));
        if (enc.empty()) {
            std::wcout << L"  [错误] AEAD 加密失败\n";
            continue;
        }

        std::vector<uint8_t> pkt(4 + enc.size());
        pkt[0] = (uint8_t)((seq >> 24) & 0xFF);
        pkt[1] = (uint8_t)((seq >> 16) & 0xFF);
        pkt[2] = (uint8_t)((seq >> 8) & 0xFF);
        pkt[3] = (uint8_t)(seq & 0xFF);
        memcpy(pkt.data() + 4, enc.data(), enc.size());

        int sent = sendto(s, (const char*)pkt.data(), (int)pkt.size(), 0,
                          (sockaddr*)&sa, sizeof(sa));
        if (sent == SOCKET_ERROR) {
            std::wcout << L"  [错误] sendto 失败: " << WSAGetLastError() << L"\n";
            continue;
        }
        std::wcout << L"  已发送 #" << seq << L" (" << pkt.size() << L" 字节密文)\n";

        uint8_t rbuf[4096];
        sockaddr_in from{};
        int fromlen = sizeof(from);
        int n = recvfrom(s, (char*)rbuf, sizeof(rbuf), 0, (sockaddr*)&from, &fromlen);
        if (n == SOCKET_ERROR) {
            std::wcout << L"  [错误] recvfrom 失败或超时: " << WSAGetLastError() << L"\n";
            continue;
        }
        if (n < 4) continue;

        uint32_t rseq = (uint32_t(rbuf[0]) << 24) |
                        (uint32_t(rbuf[1]) << 16) |
                        (uint32_t(rbuf[2]) << 8) |
                        uint32_t(rbuf[3]);

        auto dec = tk.open(rseq, std::span<const uint8_t>((const uint8_t*)"linoh-echo-demo", 13),
                           std::span<const uint8_t>(rbuf + 4, n - 4));
        if (dec.empty()) {
            std::wcout << L"  [错误] AEAD 解密失败 (seq=" << rseq << L")\n";
            continue;
        }
        std::string reply((char*)dec.data(), dec.size());
        std::wcout << L"  服务器 #" << rseq << L": " << wstring_from_utf8(reply) << L"\n\n";
    }

    closesocket(s);
    WSACleanup();
    std::wcout << L"再见！\n";
    return 0;
}
