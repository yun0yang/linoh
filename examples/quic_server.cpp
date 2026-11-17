/// quic_server.cpp - 基于 linoh.lib 的 QUIC 服务端示例
/// 展示: WinSock2 UDP 监听 + QUIC 1-RTT 连接 + Stream 通信
///
/// 协议演示:
///   - Long Header (Initial/Handshake) 用于密钥交换
///   - Short Header (1-RTT) 用于数据传输
///   - STREAM frame 用于流式消息
///   - Connection ID 用于连接标识

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
#include <map>
#include <algorithm>
#include <chrono>
#include <cstring>

using namespace linoh;
using namespace linoh::base;
using namespace linoh::protocol;

// ============================================================================
// 协议常量
// ============================================================================
static constexpr uint16_t SERVER_PORT = 54321;
static constexpr size_t MAX_PKT = 2048;

// QUIC 连接状态
enum class ConnState {
    Initial,
    Handshake,
    Established,
    Closing,
    Closed
};

// ConnectionId 比较器 (用于 std::map)
struct CIDLess {
    bool operator()(const ConnectionId& a, const ConnectionId& b) const {
        auto ad = a.data();
        auto bd = b.data();
        if (ad.size() != bd.size()) return ad.size() < bd.size();
        return std::lexicographical_compare(ad.begin(), ad.end(), bd.begin(), bd.end());
    }
};

// 已建立连接的客户端信息
struct ClientSession {
    ConnectionId  dcid;          // 客户端连接 ID
    ConnectionId  scid;           // 服务端连接 ID
    SecretKey    secret_key;     // 服务端密钥
    PublicKey    public_key;     // 服务端公钥
    ConnState    state = ConnState::Initial;
    uint64_t     remote_max_data = 0;
    uint64_t     local_max_data = 1024 * 1024;  // 1MB
    std::vector<uint8_t> recv_buffer;
    uint64_t     recv_offset = 0;
    uint64_t     send_offset = 0;
};

// ============================================================================
// 工具函数
// ============================================================================
static void print_hex(const char *label, const uint8_t *data, size_t n) {
    printf("  %s: ", label);
    for (size_t i = 0; i < std::min<size_t>(n, 16); ++i)
        printf("%02x ", data[i]);
    if (n > 16) printf("... (%zu bytes)", n);
    printf("\n");
}

static void print_hex_span(const char *label, std::span<const uint8_t> data) {
    print_hex(label, data.data(), data.size());
}

static void print_time() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    auto sec = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()) % 60;
    printf("[%02lld:%02lld.%03lld] ", sec.count(), ms.count(), ms.count());
}

static std::string ipv4_str(const sockaddr_in *sa) {
    char buf[32];
    inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
    return std::string(buf);
}

// ============================================================================
// QUIC 包处理
// ============================================================================

// 从 Initial/Handshake 包中提取客户端公钥
// QUIC TLS layout: 第一个字节是帧类型，后跟 2 字节长度字段，然后是 TLS 内容
static std::optional<std::vector<uint8_t>> extract_tls_data(std::span<const uint8_t> payload) {
    if (payload.size() < 3) return std::nullopt;
    // CRYPTO frame: type=0x06, offset=varint, length=varint, data
    if (payload[0] != 0x06) return std::nullopt;
    // 简化: 直接跳过前 3 字节（类型 + 2字节长度），取剩余部分作为 TLS 数据
    size_t len = (size_t)payload[1] << 8 | (size_t)payload[2];
    if (payload.size() < 3 + len) return std::nullopt;
    return std::vector<uint8_t>(payload.begin() + 3, payload.begin() + 3 + len);
}

// 简化版: 提取 CRYPTO frame 数据 (frame type=0x06)
// QUIC CRYPTO frame: [0x06][offset(varint)][length(varint)][crypto data]
static std::optional<std::vector<uint8_t>> parse_crypto_frame(std::span<const uint8_t> payload) {
    if (payload.empty() || payload[0] != 0x06) return std::nullopt;
    size_t pos = 1;
    // 读取 offset (simplified varint)
    while (pos < payload.size() && (payload[pos] & 0x80) != 0) pos++;
    if (pos >= payload.size()) return std::nullopt;
    pos++; // skip offset
    // 读取 length
    size_t start = pos;
    while (pos < payload.size() && (payload[pos] & 0x80) != 0) pos++;
    if (pos >= payload.size()) return std::nullopt;
    pos++;
    size_t end = start + (payload[start] << 8 | payload[start + 1]);
    if (pos + end > payload.size()) return std::nullopt;
    return std::vector<uint8_t>(payload.begin() + pos, payload.begin() + pos + end);
}

// 简化版 CRYPTO frame 构建
// [0x06][offset=0 3bytes][length 2bytes][data]
static std::vector<uint8_t> build_crypto_frame(std::span<const uint8_t> data) {
    std::vector<uint8_t> frame;
    frame.push_back(0x06); // CRYPTO frame type
    frame.push_back(0x00); frame.push_back(0x00); frame.push_back(0x00); // offset=0 (3 bytes)
    frame.push_back((uint8_t)((data.size() >> 8) & 0xFF));
    frame.push_back((uint8_t)(data.size() & 0xFF)); // length (2 bytes)
    frame.insert(frame.end(), data.begin(), data.end());
    return frame;
}

// PING frame: [0x01]
static std::vector<uint8_t> build_ping_frame() {
    return {0x01};
}

// STREAM frame: 简化版 [0x0A][stream_id][data]
// STREAM frame type byte: 0b00011010 = 0x1A (off=0, len=1, fin=0)
//   wire: [0x1A][stream_id(varint)][length(varint)][data]
static std::vector<uint8_t> build_stream_frame(uint64_t stream_id, std::span<const uint8_t> data, bool fin = false) {
    std::vector<uint8_t> frame;
    // STREAM frame type: 0b00011000|fin|off(2bits) = 0x18|0x02 = 0x1A
    frame.push_back(fin ? 0x1B : 0x1A);
    // stream_id (simplified, just 1 byte for demo)
    frame.push_back((uint8_t)(stream_id & 0xFF));
    // length
    frame.push_back((uint8_t)((data.size() >> 8) & 0xFF));
    frame.push_back((uint8_t)(data.size() & 0xFF));
    // data
    frame.insert(frame.end(), data.begin(), data.end());
    return frame;
}

// ACK frame: 简化版 [0x02][largest_acked(8B)][ack_delay][first_ack_range][num_blocks]
static std::vector<uint8_t> build_ack_frame(uint64_t largest_acked) {
    std::vector<uint8_t> frame;
    frame.push_back(0x02); // ACK frame type
    for (int i = 7; i >= 0; --i) frame.push_back((uint8_t)((largest_acked >> (i * 8)) & 0xFF));
    frame.push_back(0x00); // ack_delay
    frame.push_back(0x00); frame.push_back(0x00); frame.push_back(0x01); // first_ack_range=0, num_blocks=0
    return frame;
}

// 解析 STREAM frame
static std::optional<std::pair<uint64_t, std::vector<uint8_t>>> parse_stream_frame(
    std::span<const uint8_t> payload) {
    if (payload.empty()) return std::nullopt;
    uint8_t ft = payload[0];
    if ((ft & 0xF8) != 0x18) return std::nullopt; // not a STREAM frame
    size_t pos = 1;
    if (pos >= payload.size()) return std::nullopt;
    uint64_t stream_id = payload[pos++];
    if (pos + 2 > payload.size()) return std::nullopt;
    size_t len = ((size_t)payload[pos] << 8) | (size_t)payload[pos + 1];
    pos += 2;
    if (pos + len > payload.size()) return std::nullopt;
    std::vector<uint8_t> data(payload.begin() + pos, payload.begin() + pos + len);
    return std::make_pair(stream_id, std::move(data));
}

// ============================================================================
// Long Header 包构建
// ============================================================================

// 构建 Initial 包 (Long Header)
// Wire format: [0xC0|version(4)][DCIL(1)][DEST_CONN_ID][SCIL(1)][SRC_CONN_ID][Token Len][Token][PKN][payload]
static std::vector<uint8_t> build_initial_packet(
    const ConnectionId &dcid,
    const ConnectionId &scid,
    uint32_t version,
    std::span<const uint8_t> frames,
    uint8_t pkn_bytes = 3) {

    std::vector<uint8_t> out;
    out.reserve(128);

    // 第一个字节: 0xC0 | (pkn_bytes - 1)
    uint8_t h0 = 0xC0 | ((pkn_bytes - 1) & 0x03);
    out.push_back(h0);

    // Version (4 bytes)
    for (int i = 3; i >= 0; --i) out.push_back((uint8_t)((version >> (i * 8)) & 0xFF));

    // DCIL + DEST_CONN_ID
    out.push_back(static_cast<uint8_t>(dcid.len() & 0xFF));
    if (dcid.len() > 0) {
        std::span<const uint8_t> dcid_bytes = dcid.data();
        out.insert(out.end(), dcid_bytes.begin(), dcid_bytes.end());
    }

    // SCIL + SRC_CONN_ID
    out.push_back(static_cast<uint8_t>(scid.len() & 0xFF));
    if (scid.len() > 0) {
        std::span<const uint8_t> scid_bytes = scid.data();
        out.insert(out.end(), scid_bytes.begin(), scid_bytes.end());
    }

    // Token Length (0)
    out.push_back(0x00);

    // PKN (Packet Number, 3 bytes for Initial)
    uint8_t pkn_buf[3] = {0, 0, 1};
    out.insert(out.end(), pkn_buf, pkn_buf + pkn_bytes);

    // Payload (frames)
    out.insert(out.end(), frames.begin(), frames.end());

    return out;
}

// 从 wire 数据中解析 STREAM frame
static std::optional<std::pair<uint64_t, std::vector<uint8_t>>> try_parse_stream(
    std::span<const uint8_t> payload) {
    return parse_stream_frame(payload);
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    printf("=====================================================\n");
    printf("  linoh QUIC Server\n");
    printf("  Port: %d\n", SERVER_PORT);
    printf("=====================================================\n\n");

    // Winsock 初始化
    WSADATA wsa{};
    int ret = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (ret != 0) {
        printf("[错误] WSAStartup 失败: %d\n", ret);
        return 1;
    }

    // 创建 UDP socket
    SOCKET srv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (srv_sock == INVALID_SOCKET) {
        printf("[错误] socket() 失败: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // SO_REUSEADDR
    int reuse = 1;
    setsockopt(srv_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    // 绑定
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(SERVER_PORT);
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(srv_sock, (sockaddr*)&bind_addr, sizeof(bind_addr)) != 0) {
        printf("[错误] bind() 失败: %d (端口 %d 已被占用)\n", WSAGetLastError(), SERVER_PORT);
        closesocket(srv_sock);
        WSACleanup();
        return 1;
    }

    // 设置超时
    int timeout_ms = 1000;
    setsockopt(srv_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));

    printf("[启动] 监听 0.0.0.0:%d\n", SERVER_PORT);

    // 已连接的客户端
    std::map<ConnectionId, ClientSession, CIDLess> sessions;

    uint8_t recv_buf[MAX_PKT];
    sockaddr_in client_addr{};
    int addr_len = sizeof(client_addr);
    uint64_t total_received = 0;
    uint64_t total_sent = 0;
    int client_count = 0;
    int tick = 0;

    while (true) {
        tick++;

        // 接收数据
        int n = recvfrom(srv_sock, (char*)recv_buf, sizeof(recv_buf), 0,
                        (sockaddr*)&client_addr, &addr_len);

        if (n > 0) {
            total_received += n;
            print_time();
            printf("[接收] %d 字节 from %s:%d\n",
                   n, ipv4_str(&client_addr).c_str(), ntohs(client_addr.sin_port));

            if ((size_t)n < 5) {
                printf("  [丢弃] 数据太短\n");
                continue;
            }

            uint8_t first = recv_buf[0];
            ConnectionId dcid_from_wire(std::span<const uint8_t>(recv_buf + 5, n - 5)); // 简化

            // 判断包类型
            if ((first & 0x80) == 0) {
                // Short Header (1-RTT) 包
                printf("  [类型] Short Header (1-RTT)\n");
                print_hex_span("  前16字节", std::span<const uint8_t>(recv_buf, std::min<size_t>(n, 16u)));

                // 查找对应 session
                auto it = sessions.find(dcid_from_wire);
                if (it != sessions.end()) {
                    printf("  [Session] 找到已建立连接, state=%d\n", (int)it->second.state);
                    if (it->second.state == ConnState::Established) {
                        // 简单 echo: 收到什么回什么
                        int sent = sendto(srv_sock, (const char*)recv_buf, n, 0,
                                         (sockaddr*)&client_addr, sizeof(client_addr));
                        if (sent > 0) total_sent += sent;
                        printf("  [Echo] 1-RTT 包已回传 (%d bytes)\n", sent);
                    }
                }
            } else {
                // Long Header 包
                uint8_t type = (first & 0x30) >> 4;
                printf("  [类型] Long Header: ");
                switch (type) {
                    case 0: printf("Initial"); break;
                    case 1: printf("0x00 (特殊)"); break;
                    case 2: printf("Handshake"); break;
                    case 3: printf("0x30 (特殊)"); break;
                    default: printf("未知(0x%02X)", first); break;
                }
                printf("\n");

                if (type == 0) {
                    // ==================== Initial 包 ====================
                    print_hex_span("  DCID", std::span<const uint8_t>(recv_buf + 5, std::min<size_t>(n - 5, 16u)));

                    // 生成服务端连接 ID (8 bytes random)
                    uint8_t scid_bytes[8];
                    crypto::crypto_random_bytes(std::span<uint8_t>(scid_bytes, 8));
                    ConnectionId our_scid(std::span<const uint8_t>(scid_bytes, 8));

                    // 生成服务端密钥
                    SecretKey our_sk = SecretKey::generate();
                    PublicKey our_pk = our_sk.public_key();

                    // 创建 session
                    ClientSession sess;
                    sess.dcid = dcid_from_wire;
                    sess.scid = our_scid;
                    sess.secret_key = std::move(our_sk);
                    sess.public_key = sess.secret_key.public_key();
                    sess.state = ConnState::Handshake;

                    // 提取 CRYPTO frame 数据
                    std::span<const uint8_t> payload(recv_buf + 5, recv_buf + n);
                    auto crypto_data = parse_crypto_frame(payload);
                    if (crypto_data) {
                        print_hex_span("  CRYPTO frame", std::span<const uint8_t>(crypto_data->data(), std::min<size_t>(crypto_data->size(), 32u)));
                    } else {
                        printf("  [注意] 无法解析 CRYPTO frame (非标准 Initial 负载)\n");
                    }

                    // 构建 Handshake response (简化版, 直接进入 1-RTT)
                    // 在真实 QUIC 中: 使用 TLS 1.3 握手
                    // 这里演示: 发送 "已握手完成" 的 Short Header 包
                    printf("  [Handshake] 生成服务端密钥完成\n");
                    print_hex_span("  服务端公钥 (前16B)", std::span<const uint8_t>(sess.public_key.as_span().data(), 16));

                    // 构建 Short Header (1-RTT) 包作为握手完成信号
                    // [0x40|dcil|pkn][dcid][payload]
                    std::vector<uint8_t> resp;
                    uint8_t hdr = 0x40 | ((dcid_from_wire.len() & 0x0F) << 0);
                    resp.push_back(hdr);
                    std::span<const uint8_t> dcid_span = dcid_from_wire.data();
                    resp.insert(resp.end(), dcid_span.begin(), dcid_span.end());
                    // PN placeholder
                    resp.push_back(0x00); resp.push_back(0x01);

                    // STREAM frame (简化握手完成消息)
                    std::string handshake_msg = "QUIC_HANDSHAKE_COMPLETE";
                    auto stream_frame = build_stream_frame(0, std::span<const uint8_t>(
                        (const uint8_t*)handshake_msg.data(), handshake_msg.size()));
                    resp.insert(resp.end(), stream_frame.begin(), stream_frame.end());

                    int sent = sendto(srv_sock, (const char*)resp.data(), (int)resp.size(), 0,
                                     (sockaddr*)&client_addr, sizeof(client_addr));
                    if (sent > 0) total_sent += sent;

                    sessions[our_scid] = std::move(sess);
                    client_count++;
                    printf("  [Handshake] 发送 Short Header 响应 (%d bytes)\n", sent);
                    printf("  [Session] 已创建, scid_len=%zu, 共 %d 个连接\n", our_scid.len(), client_count);
                } else if (type == 2) {
                    // Handshake 包
                    printf("  [类型] Handshake 包\n");
                }
            }
        } else if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                // 超时，每秒显示状态
                if (tick % 10 == 0) {
                    print_time();
                    printf("[状态] 等待连接中... | sessions=%zu | recv=%lluB | sent=%lluB\n",
                           sessions.size(), total_received, total_sent);
                }
            } else {
                print_time();
                printf("[错误] recvfrom: %d\n", err);
            }
        } else {
            // n == 0: 对端关闭连接
            if (tick % 10 == 0) {
                print_time();
                printf("[状态] 空闲 | sessions=%zu | recv=%lluB | sent=%lluB\n",
                       sessions.size(), total_received, total_sent);
            }
        }
    }

    closesocket(srv_sock);
    WSACleanup();
    printf("\n[退出]\n");
    return 0;
}
