/// quic_client.cpp - 基于 linoh.lib 的 QUIC 客户端示例
/// 展示: QUIC Initial 包构建 + 1-RTT 握手 + STREAM 通信
///
/// 与 quic_server.cpp 配套使用

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
#pragma comment(lib, "user32.lib")

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/util/bytes.hpp"

#include <iostream>
#include <vector>
#include <chrono>
#include <cstring>
#include <random>

using namespace linoh;
using namespace linoh::base;
using namespace linoh::protocol;

// ============================================================================
// 协议常量
// ============================================================================
static constexpr uint16_t SERVER_PORT  = 54321;
static const char *SERVER_IP   = "127.0.0.1";
static constexpr size_t MAX_PKT = 2048;

// ============================================================================
// 工具函数
// ============================================================================
static void print_hex_ptr(const char *label, const uint8_t *data, size_t n) {
    printf("  %s: ", label);
    size_t limit = n < 32 ? n : 32;
    for (size_t i = 0; i < limit; ++i)
        printf("%02x ", data[i]);
    if (n > 32) printf("... (%zu bytes)", n);
    printf("\n");
}

static std::string bytes_to_hex(std::span<const uint8_t> data) {
    char buf[64];
    size_t n = data.size() <= 32 ? data.size() : 32;
    for (size_t i = 0; i < n; i++)
        snprintf(buf + i * 3, 4, "%02x ", data[i]);
    return std::string(buf);
}

// ============================================================================
// 包构建函数
// ============================================================================

// CRYPTO frame: [0x06][offset][length][data]
static std::vector<uint8_t> build_crypto_frame(std::span<const uint8_t> data) {
    std::vector<uint8_t> frame;
    frame.push_back(0x06); // CRYPTO frame type
    frame.push_back(0x00); frame.push_back(0x00); frame.push_back(0x00); // offset=0 (3 bytes)
    frame.push_back((uint8_t)((data.size() >> 8) & 0xFF));
    frame.push_back((uint8_t)(data.size() & 0xFF));
    frame.insert(frame.end(), data.begin(), data.end());
    return frame;
}

// STREAM frame: [0x1A][stream_id][length][data]
static std::vector<uint8_t> build_stream_frame(uint64_t stream_id, std::span<const uint8_t> data, bool fin = false) {
    std::vector<uint8_t> frame;
    frame.push_back(fin ? 0x1B : 0x1A);
    frame.push_back((uint8_t)(stream_id & 0xFF));
    frame.push_back((uint8_t)((data.size() >> 8) & 0xFF));
    frame.push_back((uint8_t)(data.size() & 0xFF));
    frame.insert(frame.end(), data.begin(), data.end());
    return frame;
}

// 构建 Initial 包 (Long Header)
// Wire: [0xC0|pkn_len][version(4)][DCIL][DEST_CONN_ID][SCIL][SRC_CONN_ID][token=0][PKN][payload]
static std::vector<uint8_t> build_initial_packet(
    const ConnectionId &dcid,
    const ConnectionId &scid,
    uint32_t version,
    std::span<const uint8_t> frames) {

    std::vector<uint8_t> out;
    out.reserve(256);
    size_t dcil_off = 1 + 4; // first_byte + version
    size_t scil_off = dcil_off + 1 + dcid.len();
    size_t payload_off = scil_off + 1 + scid.len() + 1 + 3; // +token_len(1) + pkn(3)

    out.push_back(0xC0); // first byte
    // version
    for (int i = 3; i >= 0; --i) out.push_back((uint8_t)((version >> (i * 8)) & 0xFF));
    // DCIL + DCID
    out.push_back(static_cast<uint8_t>(dcid.len()));
    if (dcid.len()) {
        std::span<const uint8_t> b = dcid.data();
        out.insert(out.end(), b.begin(), b.end());
    }
    // SCIL + SCID
    out.push_back(static_cast<uint8_t>(scid.len()));
    if (scid.len()) {
        std::span<const uint8_t> b = scid.data();
        out.insert(out.end(), b.begin(), b.end());
    }
    // token length = 0
    out.push_back(0x00);
    // PKN (3 bytes) = 0
    out.push_back(0x00); out.push_back(0x00); out.push_back(0x00);
    // payload
    out.insert(out.end(), frames.begin(), frames.end());
    return out;
}

// 解析 STREAM frame
static std::optional<std::pair<uint64_t, std::vector<uint8_t>>> parse_stream(
    std::span<const uint8_t> payload) {
    if (payload.empty()) return std::nullopt;
    uint8_t ft = payload[0];
    if ((ft & 0xF8) != 0x18) return std::nullopt;
    size_t pos = 1;
    if (pos >= payload.size()) return std::nullopt;
    uint64_t sid = payload[pos++];
    if (pos + 2 > payload.size()) return std::nullopt;
    size_t len = ((size_t)payload[pos] << 8) | (size_t)payload[pos + 1];
    pos += 2;
    if (pos + len > payload.size()) return std::nullopt;
    std::vector<uint8_t> data(payload.begin() + pos, payload.begin() + pos + len);
    return std::make_pair(sid, std::move(data));
}

// 解析 CRYPTO frame
static std::optional<std::vector<uint8_t>> parse_crypto(std::span<const uint8_t> payload) {
    if (payload.empty() || payload[0] != 0x06) return std::nullopt;
    size_t pos = 1;
    while (pos < payload.size() && (payload[pos] & 0x80) != 0) pos++;
    if (pos >= payload.size()) return std::nullopt;
    pos++;
    size_t start = pos;
    while (pos < payload.size() && (payload[pos] & 0x80) != 0) pos++;
    if (pos >= payload.size()) return std::nullopt;
    pos++;
    size_t len = ((size_t)payload[start] << 8) | (size_t)payload[start + 1];
    if (pos + len > payload.size()) return std::nullopt;
    return std::vector<uint8_t>(payload.begin() + pos, payload.begin() + pos + len);
}

// ============================================================================
// 主函数
// ============================================================================
int main(int argc, char *argv[]) {
    const char *server_ip = SERVER_IP;
    uint16_t server_port = SERVER_PORT;
    if (argc >= 2) server_ip = argv[1];
    if (argc >= 3) server_port = (uint16_t)atoi(argv[2]);

    printf("=====================================================\n");
    printf("  linoh QUIC Client\n");
    printf("  服务器: %s:%d\n", server_ip, server_port);
    printf("=====================================================\n\n");

    // Winsock 初始化
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[错误] WSAStartup 失败\n");
        return 1;
    }

    // 创建 UDP socket
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        printf("[错误] socket() 失败: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // 设置超时
    int timeout_ms = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));

    // 服务器地址
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    // 生成连接 ID (客户端 CID = 8 bytes)
    uint8_t client_cid_bytes[8];
    crypto::crypto_random_bytes(std::span<uint8_t>(client_cid_bytes, 8));
    ConnectionId client_cid(std::span<const uint8_t>(client_cid_bytes, 8));
    print_hex_ptr("[客户端] 生成 CID", client_cid_bytes, 8);

    // 生成客户端密钥
    SecretKey client_sk = SecretKey::generate();
    PublicKey client_pk = client_sk.public_key();
    print_hex_ptr("[客户端] 公钥 (前16B)", client_pk.as_span().data(), 16);
    printf("\n");

    // ==================== 阶段 1: 发送 Initial 包 ====================
    printf("=== 阶段 1: QUIC Initial 包 ===\n");

    // 构建 TLS ClientHello (简化版, 用随机数据模拟 TLS 握手内容)
    std::vector<uint8_t> client_hello;
    client_hello.push_back(0x01); // handshake type: client_hello
    client_hello.push_back(0x00); client_hello.push_back(0x02); // length
    // 模拟 TLS 内容 (在真实实现中是 TLS 1.3 握手)
    for (int i = 0; i < 32; ++i) client_hello.push_back((uint8_t)(i * 7 + 0xAB));

    auto crypto_frame = build_crypto_frame(std::span<const uint8_t>(client_hello.data(), client_hello.size()));
    auto initial_packet = build_initial_packet(
        ConnectionId(), // server DCID = 空 (不知道服务器 CID)
        client_cid,
        0x00000001, // QUIC version 1
        std::span<const uint8_t>(crypto_frame.data(), crypto_frame.size()));

    printf("[发送] Initial 包 (%zu bytes)\n", initial_packet.size());
    print_hex_ptr("  Initial wire (前32B)", initial_packet.data(), (size_t)initial_packet.size());

    int sent = sendto(sock, (const char*)initial_packet.data(), (int)initial_packet.size(), 0,
                      (sockaddr*)&server_addr, sizeof(server_addr));
    printf("[发送] sendto 返回: %d bytes\n\n", sent);

    // ==================== 阶段 2: 接收服务器响应 ====================
    printf("=== 阶段 2: 等待服务器响应 ===\n");

    uint8_t recv_buf[MAX_PKT];
    sockaddr_in from{};
    int from_len = sizeof(from);
    int n = recvfrom(sock, (char*)recv_buf, sizeof(recv_buf), 0,
                     (sockaddr*)&from, &from_len);

    if (n > 0) {
        printf("[接收] %d 字节 from server\n", n);
        print_hex_ptr("  前24字节", recv_buf, (size_t)n);

        uint8_t first = recv_buf[0];
        printf("  first=0x%02X ", first);

        if ((first & 0x80) == 0) {
            // Short Header (1-RTT) - 握手完成信号
            printf("(Short Header / 1-RTT)\n");
            print_hex_ptr("  1-RTT wire", recv_buf, (size_t)n);

            // 尝试解析 STREAM frame
            std::span<const uint8_t> payload(recv_buf + 1, recv_buf + n); // 跳过 header
            auto stream_opt = parse_stream(payload);
            if (stream_opt) {
                auto &[sid, data] = *stream_opt;
                std::string msg(data.begin(), data.end());
                printf("  [STREAM] sid=%llu data: %s\n", sid, msg.c_str());

                if (msg.find("QUIC_HANDSHAKE_COMPLETE") == 0) {
                    printf("  [握手] 服务器握手完成信号!\n\n");
                }
            }
        } else {
            // Long Header
            uint8_t type = (first & 0x30) >> 4;
            printf("(Long Header type=%d)\n", type);
        }
    } else {
        printf("[超时] 5秒内未收到响应\n");
        printf("  (服务器可能需要更长时间，或 QUIC Initial 包格式不匹配)\n\n");
    }

    // ==================== 阶段 3: 发送实际数据 ====================
    printf("=== 阶段 3: 通过 Short Header 发送应用数据 ===\n");

    // 构建 Short Header 包
    // [0x40|dcil][dcid][pkn][frames]
    std::vector<uint8_t> s1rtt;
    s1rtt.push_back(0x40 | (client_cid.len() & 0x0F));
    std::span<const uint8_t> cid_span = client_cid.data();
    s1rtt.insert(s1rtt.end(), cid_span.begin(), cid_span.end());
    // PKN
    s1rtt.push_back(0x00); s1rtt.push_back(0x01);
    // STREAM frame
    std::string app_msg1 = "Hello QUIC!";
    auto sf1 = build_stream_frame(0, std::span<const uint8_t>((const uint8_t*)app_msg1.data(), app_msg1.size()));
    s1rtt.insert(s1rtt.end(), sf1.begin(), sf1.end());

    printf("[发送] Short Header 数据包 (%zu bytes)\n", s1rtt.size());
    print_hex_ptr("  1-RTT wire", s1rtt.data(), (size_t)s1rtt.size());

    sent = sendto(sock, (const char*)s1rtt.data(), (int)s1rtt.size(), 0,
                  (sockaddr*)&server_addr, sizeof(server_addr));
    printf("[发送] sendto 返回: %d bytes\n\n", sent);

    // ==================== 阶段 4: 批量发送测试 ====================
    printf("=== 阶段 4: 批量发送测试 ===\n");
    const char *messages[] = {
        "QUIC stream message #1",
        "0123456789",
        "A", "BB", "CCC",
        "这是一条中文消息 via QUIC STREAM frame",
        "Ping!",
        "Message with special chars: !@#$%^&*()",
        "Long message: " "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
        "Final message",
    };

    int success = 0;
    for (int i = 0; i < 9; ++i) {
        std::string msg(messages[i]);
        std::vector<uint8_t> pkt;
        pkt.push_back(0x40 | ((i % 2) << 4) | (client_cid.len() & 0x0F));
        pkt.insert(pkt.end(), cid_span.begin(), cid_span.end());
        pkt.push_back(0x00); pkt.push_back((uint8_t)((i + 2) & 0xFF));
        auto sf = build_stream_frame(i % 4, std::span<const uint8_t>((const uint8_t*)msg.data(), msg.size()));
        pkt.insert(pkt.end(), sf.begin(), sf.end());

        int s = sendto(sock, (const char*)pkt.data(), (int)pkt.size(), 0,
                      (sockaddr*)&server_addr, sizeof(server_addr));
        if (s > 0) { success++; printf("  [%d] sent: \"%s\" (%d bytes)\n", i + 1, msg.c_str(), s); }
        else { printf("  [%d] FAILED: %d\n", i + 1, WSAGetLastError()); }
    }

    printf("\n=== 测试完成 ===\n");
    printf("  成功发送: %d/9 消息\n", success);
    printf("  服务器: %s:%d\n", server_ip, server_port);
    printf("  客户端 CID: %s\n", bytes_to_hex(client_cid.data()).c_str());

    closesocket(sock);
    WSACleanup();

    printf("\n[提示] 配合 quic_server.cpp 查看服务端日志\n");
    return 0;
}
