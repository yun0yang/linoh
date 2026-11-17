/// test_debug_echo.cpp - 调试 echo 服务器中的问题

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

#include <cstdio>
#include <vector>
#include <string>

using namespace linoh;
using namespace linoh::base;
using namespace linoh::protocol;
using namespace linoh::endpoint;

int main() {
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    auto ctx = std::make_shared<linoh_asio::io_context>();
    auto ep = Builder()
        .secret_key(SecretKey::generate())
        .alpns({"echo/1"})
        .build(*ctx);

    printf("=== Test 1: Send Initial packet to endpoint ===\n");
    ConnectionId client_cid = ConnectionId::generate();
    ConnectionId server_dcid;

    // 用 PacketHeader 构造 Initial 包
    auto hdr = PacketHeader::make_initial(server_dcid, client_cid);
    size_t hdr_size = hdr.encoded_size();
    printf("Initial header size: %zu bytes\n", hdr_size);

    // 构造：header + client_hello payload
    std::vector<uint8_t> pkt(hdr_size + 64);
    size_t actual_hdr = hdr.serialize_to(pkt.data(), pkt.size());
    printf("Header serialized: %zu bytes\n", actual_hdr);
    // 添加 client_hello payload
    for (int i = 0; i < 32; i++)
        pkt[actual_hdr + i] = (uint8_t)(i + 1);

    printf("Total initial pkt: %zu bytes\n", actual_hdr + 32);

    // 发送
    TransportAddr from;
    from.kind = TransportKind::Ip;
    from.host = "127.0.0.1";
    from.port = 55555;

    std::span<const uint8_t> wire(pkt.data(), actual_hdr + 32);
    ep->handle_incoming(from, util::Bytes(wire));

    // 轮询 accept
    for (int i = 0; i < 3; i++) {
        auto inc = ep->accept();
        if (inc) {
            auto conn = inc->conn.lock();
            if (conn) {
                printf("[PASS] Accepted! conn state=%d\n", (int)conn->state());
                // 尝试写一些数据
                auto s = conn->open_stream();
                const char *msg = "ECHO";
                s->write(std::span<const uint8_t>((const uint8_t*)msg, 4));
                std::vector<uint8_t> out(1024);
                size_t plen = conn->build_1rtt_packet(std::span<uint8_t>(out.data(), out.size()));
                printf("       build_1rtt_packet: %zu bytes\n", plen);
            }
        } else {
            printf("       accept() returned null (try %d)\n", i);
        }
    }

    // 测试 2：发送 Short Header + STREAM
    printf("\n=== Test 2: Send Short Header STREAM packet ===\n");
    // 包格式：[0x40 | pkn_len<<4 | dcid_len][dcid][pkn(2)][STREAM frame...]
    std::vector<uint8_t> sh_pkt;
    uint8_t pkn_len = 1;  // 2 bytes
    uint8_t first_byte = 0x40 | (pkn_len << 4) | (uint8_t)(client_cid.len() & 0x0F);
    sh_pkt.push_back(first_byte);
    auto cd = client_cid.data();
    sh_pkt.insert(sh_pkt.end(), cd.begin(), cd.end());
    sh_pkt.push_back(0x00);  // pkn byte 1
    sh_pkt.push_back(0x01);  // pkn byte 2
    // STREAM frame: [0x08 | len_bit][sid][len(2)][data]
    const char *data = "HELLO!";
    uint16_t dl = 6;
    sh_pkt.push_back(0x08 | 0x02);  // STREAM + 2-byte length
    sh_pkt.push_back(0x00);  // stream id = 0
    sh_pkt.push_back((uint8_t)(dl >> 8));
    sh_pkt.push_back((uint8_t)(dl & 0xFF));
    for (int i = 0; i < 6; i++) sh_pkt.push_back((uint8_t)data[i]);

    printf("SH packet size: %zu bytes\n", sh_pkt.size());
    std::span<const uint8_t> sh_wire(sh_pkt.data(), sh_pkt.size());
    ep->handle_incoming(from, util::Bytes(sh_wire));

    for (int i = 0; i < 3; i++) {
        auto inc = ep->accept();
        if (inc) {
            auto conn = inc->conn.lock();
            if (conn) {
                printf("[PASS] Accepted! conn state=%d\n", (int)conn->state());
                auto s = conn->open_stream();
                const char *msg = "ECHO";
                s->write(std::span<const uint8_t>((const uint8_t*)msg, 4));
                std::vector<uint8_t> out(1024);
                size_t plen = conn->build_1rtt_packet(std::span<uint8_t>(out.data(), out.size()));
                printf("       build_1rtt_packet: %zu bytes\n", plen);
            }
        }
    }

    printf("\n=== DONE ===\n");
    WSACleanup();
    return 0;
}
