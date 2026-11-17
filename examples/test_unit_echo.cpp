/// test_unit_echo.cpp - 单元测试：验证 PacketHeader 和 Endpoint 行为

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
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
#include <cstring>
#include <string>
#include <vector>

using namespace linoh;
using namespace linoh::base;
using namespace linoh::protocol;
using namespace linoh::endpoint;

static void print_hex(const char *label, std::span<const uint8_t> data) {
    printf("  %s: ", label);
    size_t n = data.size() < 40 ? data.size() : 40;
    for (size_t i = 0; i < n; i++) printf("%02x ", data[i]);
    if (data.size() > 40) printf("... (%zu bytes)", data.size());
    printf("\n");
}

int main() {
    printf("========================================================\n");
    printf("  Unit Test: Echo Roundtrip\n");
    printf("========================================================\n\n");

    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

    // ----------------------------------------------------------------------
    // Test 1: PacketHeader 编码/解码
    // ----------------------------------------------------------------------
    printf("[Test 1] PacketHeader encode/decode\n");

    ConnectionId client_cid = ConnectionId::generate();
    ConnectionId server_dcid;

    auto hdr = PacketHeader::make_initial(server_dcid, client_cid);
    printf("  Type: %d (Initial=%d)\n", (int)hdr.type(), (int)PacketType::Initial);
    printf("  pn_len: %d (encoded value)\n", (int)hdr.pn_len());
    printf("  dcid.len: %zu, scid.len: %zu\n", hdr.dcid().len(), hdr.scid().len());

    std::vector<uint8_t> pkt(1024);
    size_t hdr_bytes = hdr.serialize_to(pkt.data(), pkt.size());
    printf("  Serialized header size: %zu bytes\n", hdr_bytes);
    print_hex("  Header bytes", std::span<const uint8_t>(pkt.data(), hdr_bytes));

    // 尝试 decode
    auto parse_result = PacketHeader::parse_from(std::span<const uint8_t>(pkt.data(), hdr_bytes));
    if (parse_result) {
        auto &[decoded_hdr, payload_start] = *parse_result;
        printf("  Decoded OK! payload_start=%zu\n", payload_start);
        printf("    Type: %d\n", (int)decoded_hdr.type());
        printf("    dcid.len: %zu, scid.len: %zu\n",
               decoded_hdr.dcid().len(), decoded_hdr.scid().len());
    } else {
        printf("  [FAIL] parse_from returned null!\n");
    }
    printf("\n");

    // ----------------------------------------------------------------------
    // Test 2: Endpoint::handle_incoming + accept
    // ----------------------------------------------------------------------
    printf("[Test 2] Endpoint handle_initial + accept\n");

    auto ctx = std::make_shared<linoh_asio::io_context>();
    auto ep = Builder()
        .secret_key(SecretKey::generate())
        .alpns({"echo/1"})
        .build(*ctx);

    // 构造一个完整的 Initial 包
    auto init_hdr = PacketHeader::make_initial(server_dcid, client_cid);
    std::vector<uint8_t> full_pkt(256);
    size_t init_hdr_bytes = init_hdr.serialize_to(full_pkt.data(), full_pkt.size());

    // 添加一些 payload (模拟 TLS ClientHello)
    std::vector<uint8_t> client_hello;
    for (int i = 0; i < 32; i++) client_hello.push_back((uint8_t)(i + 1));
    for (size_t i = 0; i < client_hello.size(); i++)
        full_pkt[init_hdr_bytes + i] = client_hello[i];
    size_t total_pkt = init_hdr_bytes + client_hello.size();

    printf("  Initial packet: %zu bytes\n", total_pkt);
    print_hex("    bytes", std::span<const uint8_t>(full_pkt.data(), total_pkt));

    // 调用 handle_incoming
    TransportAddr from;
    from.kind = TransportKind::Ip;
    from.host = "127.0.0.1";
    from.port = 55555;
    std::span<const uint8_t> wire(full_pkt.data(), total_pkt);
    printf("  Calling ep->handle_incoming()...\n");
    ep->handle_incoming(from, util::Bytes(wire));

    // 尝试 accept
    int accept_count = 0;
    std::shared_ptr<Connection> accepted_conn;
    for (int i = 0; i < 5; i++) {
        auto inc = ep->accept();
        if (inc) {
            auto conn = inc->conn;
            if (conn) {
                printf("  [OK] accept #%d: conn #%llu state=%d\n",
                       i + 1, (unsigned long long)conn->id(), (int)conn->state());
                accepted_conn = conn;
                accept_count++;
            } else {
                printf("  accept() returned inc but conn is null\n");
            }
        } else {
            printf("  accept #%d: null\n", i + 1);
        }
    }
    printf("  Total accepted: %d\n\n", accept_count);

    // ----------------------------------------------------------------------
    // Test 3: Stream 数据 + build_1rtt_packet
    // ----------------------------------------------------------------------
    printf("[Test 3] Send STREAM packet, echo back, build_1rtt_packet\n");

    if (accepted_conn) {
        // 构造 Short Header + STREAM frame
        auto sh_hdr = PacketHeader::make_1rtt(client_cid);
        std::vector<uint8_t> sh_pkt(256);
        size_t sh_header_bytes = sh_hdr.serialize_to(sh_pkt.data(), sh_pkt.size());

        // STREAM frame: [0x08|0x02][stream_id][len_h][len_l][data]
        const char *msg = "Hello linoh!";
        uint16_t data_len = (uint16_t)strlen(msg);
        size_t pos = sh_header_bytes;
        sh_pkt[pos++] = 0x08 | 0x02;
        sh_pkt[pos++] = 0;  // stream_id = 0
        sh_pkt[pos++] = (uint8_t)(data_len >> 8);
        sh_pkt[pos++] = (uint8_t)(data_len & 0xFF);
        for (size_t i = 0; i < data_len; i++)
            sh_pkt[pos++] = (uint8_t)msg[i];
        size_t sh_total = pos;

        printf("  Sending SH packet: %zu bytes\n", sh_total);
        print_hex("    bytes", std::span<const uint8_t>(sh_pkt.data(), sh_total));

        ep->handle_incoming(from, util::Bytes(std::span<const uint8_t>(sh_pkt.data(), sh_total)));

        // 应该触发 on_stream 回调
        auto weak_conn = std::weak_ptr<Connection>(accepted_conn);
        bool got_stream = false;
        accepted_conn->on_stream([&](std::shared_ptr<Stream> s) {
            // P1-P3 fix(2026-07-20): 用 readable_*() 替代 send_buffer()（原为 bug，应读取 recv 侧）
            std::size_t n = s->readable_size();
            printf("    [on_stream] stream#%llu got %zu bytes\n",
                   (unsigned long long)s->id(), n);
            if (n > 0) {
                std::string data(s->readable_data(), s->readable_data() + n);
                printf("    data: %s\n", data.c_str());
                // 回显
                auto echo_s = accepted_conn->open_stream();
                echo_s->write(std::span<const uint8_t>(s->readable_data(), n));
                s->consume(n);
                got_stream = true;
            }
        });

        // 尝试 build_1rtt_packet
        std::vector<uint8_t> out_buf(1024);
        size_t reply_len = accepted_conn->build_1rtt_packet(std::span<uint8_t>(out_buf.data(), out_buf.size()));
        printf("  build_1rtt_packet returned: %zu bytes\n", reply_len);
        if (reply_len > 0) {
            print_hex("    reply bytes", std::span<const uint8_t>(out_buf.data(), reply_len));
        }

        printf("  on_stream called: %s\n", got_stream ? "YES" : "NO");
        printf("\n");
    } else {
        printf("  SKIP: No connection accepted in Test 2\n\n");
    }

    // ----------------------------------------------------------------------
    // Test 4: 在 on_stream 里收到数据后再 build_1rtt_packet
    // ----------------------------------------------------------------------
    printf("[Test 4] Send another STREAM, check if build_1rtt_packet returns data\n");

    if (accepted_conn) {
        // 重新发送 STREAM
        std::vector<uint8_t> sh_pkt2(256);
        auto sh_hdr2 = PacketHeader::make_1rtt(client_cid);
        size_t hdr2 = sh_hdr2.serialize_to(sh_pkt2.data(), sh_pkt2.size());

        const char *msg2 = "Echo_test_2";
        uint16_t data_len2 = (uint16_t)strlen(msg2);
        size_t pos2 = hdr2;
        sh_pkt2[pos2++] = 0x08 | 0x02;
        sh_pkt2[pos2++] = 1;  // stream_id = 1
        sh_pkt2[pos2++] = (uint8_t)(data_len2 >> 8);
        sh_pkt2[pos2++] = (uint8_t)(data_len2 & 0xFF);
        for (size_t i = 0; i < data_len2; i++)
            sh_pkt2[pos2++] = (uint8_t)msg2[i];

        // 先打开一个本地流用于回显
        // 直接写数据到本地流
        auto local_stream = accepted_conn->open_stream();
        local_stream->write(std::span<const uint8_t>((uint8_t*)msg2, data_len2));

        std::vector<uint8_t> out_buf(1024);
        size_t reply_len = accepted_conn->build_1rtt_packet(std::span<uint8_t>(out_buf.data(), out_buf.size()));
        printf("  build_1rtt_packet (manual stream write): %zu bytes\n\n", reply_len);

        if (reply_len > 0) {
            print_hex("    reply bytes", std::span<const uint8_t>(out_buf.data(), reply_len));
        }
    } else {
        printf("  SKIP: No connection accepted\n\n");
    }

    // ----------------------------------------------------------------------
    // Summary
    // ----------------------------------------------------------------------
    printf("========================================================\n");
    printf("  Tests complete.\n");
    printf("========================================================\n");

    WSACleanup();
    return 0;
}
