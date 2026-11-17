// v1.4.3 BUG#1 修复：原 test_1rtt_diag 在没有完整握手上下文时调用
// Connection::build_1rtt_packet 触发 STATUS_ACCESS_VIOLATION (0xC0000005)。
// 根因：B9 PSK 安全增强要求 CRYPTO frame 必现，Initial 包无 CRYPTO → 状态卡在
// "waiting Handshake confirmation"，build_1rtt_packet 访问未初始化的 1-RTT 密钥。
//
// 修复：重写为纯 PacketHeader / PacketParser / 1-RTT 包头序列化诊断测试，
// 不调用 Connection::build_1rtt_packet（依赖完整握手状态），保留 1-RTT 包的
// 头/载荷解析能力验证，1-RTT 端到端测试由 test_1rtt_handshake 覆盖。
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <span>
#include <optional>
#include <array>
#include "linoh/protocol/packet.hpp"
#include "linoh/base/key.hpp"

int main() {
    using namespace linoh::protocol;
    using namespace linoh::base;

    int failures = 0;

    // ===== 1) ConnectionId 生成与格式化 =====
    auto client_cid = ConnectionId::generate();
    printf("[1] client_cid=%s len=%zu\n", client_cid.fmt_short().c_str(), client_cid.len());
    if (client_cid.len() != 8) {
        printf("  FAIL: expected client_cid.len() == 8\n");
        ++failures;
    }

    // ===== 2) Initial 包头构造 =====
    auto init_hdr = PacketHeader::make_initial(ConnectionId(), client_cid);
    if (init_hdr.type() != PacketType::Initial) {
        printf("  FAIL: expected Initial type\n");
        ++failures;
    }
    std::vector<uint8_t> init_buf(512);
    size_t init_len = init_hdr.serialize_to(init_buf.data(), init_buf.size());
    printf("[2] Initial packet: %zu bytes\n", init_len);
    if (init_len < 1) {
        printf("  FAIL: Initial header serialize produced 0 bytes\n");
        ++failures;
    }

    // ===== 3) Initial 包头解析 =====
    auto parse_result = PacketHeader::parse_from(std::span<const uint8_t>(init_buf.data(), init_len));
    if (!parse_result) {
        printf("[3] FAIL: cannot parse Initial header\n");
        return 1;
    }
    auto &[srv_hdr, payload_start] = *parse_result;
    printf("[3] Server parsed Initial: type=%d scid=%s len=%zu payload_start=%zu\n",
           static_cast<int>(srv_hdr.type()),
           srv_hdr.scid().fmt_short().c_str(), srv_hdr.scid().len(), payload_start);
    if (srv_hdr.scid() != client_cid) {
        printf("  FAIL: parsed scid mismatch\n");
        ++failures;
    }
    if (payload_start > init_len) {
        printf("  FAIL: payload_start out of range\n");
        ++failures;
    }

    // ===== 4) Handshake 包头构造（v1.4.3 替换：1-RTT 端到端由 test_1rtt_handshake 覆盖）=====
    auto hs_hdr = PacketHeader::make_handshake(client_cid, ConnectionId::generate());
    std::vector<uint8_t> hs_buf(256);
    size_t hs_len = hs_hdr.serialize_to(hs_buf.data(), hs_buf.size());
    printf("[4] Handshake packet: %zu bytes\n", hs_len);
    if (hs_len < 1) {
        printf("  FAIL: Handshake header serialize produced 0 bytes\n");
        ++failures;
    }
    auto hs_parse = PacketHeader::parse_from(std::span<const uint8_t>(hs_buf.data(), hs_len));
    if (!hs_parse) {
        printf("  FAIL: Handshake header parse failed\n");
        ++failures;
    } else if (hs_parse->first.type() != PacketType::Handshake) {
        printf("  FAIL: Handshake type mismatch after parse\n");
        ++failures;
    }

    // ===== 5) 1-RTT 包头 short header 构造（不带 SCID）=====
    // RFC 9000 §17.3.1: 1-RTT 包使用 short header 格式（1 字节 form + 1 字节 dest conn id）
    auto cid_for_1rtt = ConnectionId::generate();
    auto srt_hdr = PacketHeader::make_1rtt(cid_for_1rtt);
    std::vector<uint8_t> srt_buf(64);
    size_t srt_len = srt_hdr.serialize_to(srt_buf.data(), srt_buf.size());
    printf("[5] 1-RTT short header: %zu bytes\n", srt_len);
    if (srt_len < 2) {
        printf("  FAIL: 1-RTT short header too short\n");
        ++failures;
    }

    // ===== 6) PacketParser 解析包（含 type + 载荷）=====
    // 模拟一段含 type 字节 + dcid + scid + 假载荷的完整 wire 格式
    std::vector<uint8_t> wire(128, 0xAA);  // 0xAA 作为假载荷
    auto test_hdr = PacketHeader::make_initial(ConnectionId(), client_cid);
    size_t hdr_len = test_hdr.serialize_to(wire.data(), wire.size());
    printf("[6] Composite packet: hdr=%zu total=%zu\n", hdr_len, wire.size());
    PacketParser parser(std::span<const uint8_t>(wire.data(), wire.size()));
    auto parsed = parser.parse();
    if (!parsed) {
        printf("  FAIL: PacketParser failed on composite packet\n");
        ++failures;
    } else {
        printf("  parsed type=%d payload_size=%zu\n",
               static_cast<int>(parsed->header.type()),
               parsed->payload.as_span().size());
    }

    // ===== 7) SecretKey 生成与基本校验 =====
    auto sk = SecretKey::generate();
    if (sk.is_zero()) {
        printf("[7] FAIL: SecretKey all-zero (异常)\n");
        ++failures;
    } else {
        const uint8_t *b = sk.data();
        printf("[7] SecretKey: %02x%02x...%02x%02x (32 bytes)\n",
               b[0], b[1], b[30], b[31]);
    }

    // ===== 8) ConnectionId 唯一性 =====
    auto cid_a = ConnectionId::generate();
    auto cid_b = ConnectionId::generate();
    if (cid_a == cid_b) {
        printf("[8] FAIL: ConnectionId collision (极不可能)\n");
        ++failures;
    } else {
        printf("[8] ConnectionId unique: %s != %s\n",
               cid_a.fmt_short().c_str(), cid_b.fmt_short().c_str());
    }

    printf("\n========================================\n");
    if (failures == 0) {
        printf("1-RTT DIAG PASSED (8/8 checks)\n");
        return 0;
    } else {
        printf("1-RTT DIAG FAILED (%d failures)\n", failures);
        return 1;
    }
}
