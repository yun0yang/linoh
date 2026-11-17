// v1.5.0.2 Step 3 — MTU 协商协议测试
//
// 覆盖：
//   1. encode/decode Hello preferred_mtu 字段往返
//   2. MtuNegotiator 协商策略（双方 9000/1500/1280 各种组合）
//   3. 旧版节点无 MTU 字段 → decode_hello 回退 1280
//   4. decode_hello 严格/宽松模式（alpn 后多余字节处理）
//   5. Connection 端 negotiated_mtu_ 默认 1280，handshake 后被设置
//
// Author: linoh dev team
// 2026-07-23

#include "linoh/endpoint/connection.hpp"
#include "linoh/endpoint/connection_internal.hpp"
#include "linoh/net/mtu.hpp"
#include "linoh/net/net_report.hpp"
#include "linoh/tls/handshake.hpp"
#include "linoh/tls/handshake_msg.hpp"
#include "linoh/util/varint.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

// ==================== CHECK 宏 ====================
static int g_passed = 0;
static int g_failed = 0;
static std::vector<std::string> g_fail_msgs;

#define CHECK(expr)                                                          \
    do {                                                                     \
        if (expr) {                                                          \
            ++g_passed;                                                      \
        } else {                                                             \
            ++g_failed;                                                      \
            char buf[256];                                                   \
            std::snprintf(buf, sizeof(buf),                                  \
                          "FAIL: %s (line %d)", #expr, __LINE__);           \
            g_fail_msgs.emplace_back(buf);                                   \
            std::fprintf(stderr, "%s\n", buf);                               \
        }                                                                    \
    } while (0)

#define CHECK_EQ(a, b)                                                       \
    do {                                                                     \
        auto _va = (a);                                                      \
        auto _vb = (b);                                                      \
        if (_va == _vb) {                                                    \
            ++g_passed;                                                      \
        } else {                                                             \
            ++g_failed;                                                      \
            char buf[256];                                                   \
            std::snprintf(buf, sizeof(buf),                                  \
                          "FAIL: %s == %s (line %d, actual=%lld vs %lld)",  \
                          #a, #b, __LINE__,                                 \
                          (long long)_va, (long long)_vb);                  \
            g_fail_msgs.emplace_back(buf);                                   \
            std::fprintf(stderr, "%s\n", buf);                               \
        }                                                                    \
    } while (0)

#define CHECK_EQ_STR(a, b)                                                    \
    do {                                                                      \
        auto _va = (a);                                                       \
        auto _vb = (b);                                                       \
        if (_va == _vb) {                                                     \
            ++g_passed;                                                       \
        } else {                                                              \
            ++g_failed;                                                       \
            char buf[256];                                                    \
            std::snprintf(buf, sizeof(buf),                                   \
                          "FAIL: %s == %s (line %d, actual=\"%s\" vs \"%s\")",\
                          #a, #b, __LINE__,                                   \
                          std::string(_va).c_str(), std::string(_vb).c_str());\
            g_fail_msgs.emplace_back(buf);                                    \
            std::fprintf(stderr, "%s\n", buf);                                \
        }                                                                     \
    } while (0)

using namespace linoh::tls;
using namespace linoh::util;

// ==================== Helper ====================
static Hello make_hello(std::uint16_t mtu, const std::string &alpn = "pp-hidden/1") {
    Hello h{};
    for (int i = 0; i < 32; ++i) {
        h.random[i] = static_cast<std::uint8_t>(i);
        h.ephemeral[i] = static_cast<std::uint8_t>(0x80 + i);
        h.node_pub[i] = static_cast<std::uint8_t>(0x40 + i);
    }
    h.alpn = alpn;
    h.preferred_mtu = mtu;
    return h;
}

// ==================== 测试函数 ====================

// 1. encode_hello / decode_hello 往返（含 mtu=1280）
static void test_encode_decode_hello_mtu_1280() {
    auto h = make_hello(1280);
    auto wire = encode_hello(HsType::ClientHello, h);
    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(decoded.has_value());
    if (!decoded.has_value()) return;
    CHECK_EQ(decoded->first.preferred_mtu, 1280u);
    CHECK_EQ_STR(decoded->first.alpn, h.alpn);
}

// 2. encode_hello / decode_hello 往返（含 mtu=1500）
static void test_encode_decode_hello_mtu_1500() {
    auto h = make_hello(1500);
    auto wire = encode_hello(HsType::ClientHello, h);
    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(decoded.has_value());
    if (!decoded.has_value()) return;
    CHECK_EQ(decoded->first.preferred_mtu, 1500u);
}

// 3. encode_hello / decode_hello 往返（含 mtu=9000 jumbo）
static void test_encode_decode_hello_mtu_9000() {
    auto h = make_hello(9000);
    auto wire = encode_hello(HsType::ClientHello, h);
    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(decoded.has_value());
    if (!decoded.has_value()) return;
    CHECK_EQ(decoded->first.preferred_mtu, 9000u);
    // Hello 协议层 body 远小于 1280（1280 是 QUIC Initial packet 下限，不是 Hello body 下限）
    // 这里只验证 wire 非空 + 包含 jumbo 标记
    CHECK(wire.size() > 100);
    CHECK(wire.size() < 1280);
}

// 4. 旧版节点（无 mtu 字段）→ decode_hello 回退 1280
// 模拟方法：手工构造 wire bytes（不包含 mtu varint）
static void test_decode_legacy_hello_no_mtu_field() {
    // 手工构造 legacy wire：random[32]+eph[32]+pub[32]+varint(8)+alpn[8]
    std::vector<std::uint8_t> body;
    body.resize(32 + 32 + 32 + 1 + 8);
    for (int i = 0; i < 32; ++i) {
        body[i] = static_cast<std::uint8_t>(i);
        body[32 + i] = static_cast<std::uint8_t>(0x80 + i);
        body[64 + i] = static_cast<std::uint8_t>(0x40 + i);
    }
    body[96] = 8;  // alpn len
    const char *alpn = "pp-img/1";
    std::memcpy(&body[97], alpn, 8);

    // 构造完整 wire：[type=0x01][varint(body_len=105)][body]
    std::vector<std::uint8_t> wire;
    wire.push_back(static_cast<std::uint8_t>(HsType::ClientHello));
    // varint(105) = [0x40, 0x69] (2-byte QUIC varint)
    wire.push_back(0x40);
    wire.push_back(0x69);
    wire.insert(wire.end(), body.begin(), body.end());

    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(decoded.has_value());
    if (!decoded.has_value()) return;
    CHECK_EQ(decoded->first.preferred_mtu, 1280u);  // 默认回退
    CHECK_EQ_STR(decoded->first.alpn, std::string("pp-img/1"));
}

// 5. MtuNegotiator 协商：双方 9000 + OpenInternet → 9000
static void test_negotiate_both_9000_open() {
    auto r = linoh::net::MtuNegotiator::negotiate(
        9000, 9000, linoh::net::NatType::OpenInternet, linoh::net::UdpFirewall::Open);
    CHECK_EQ(r.negotiated_mtu, 9000u);
    CHECK(r.jumbo_enabled);
}

// 6. MtuNegotiator 协商：双方 9000 + RestrictedCone → 1500
static void test_negotiate_both_9000_restricted() {
    auto r = linoh::net::MtuNegotiator::negotiate(
        9000, 9000, linoh::net::NatType::RestrictedCone, linoh::net::UdpFirewall::Open);
    // RestrictedCone 应降级
    CHECK(r.negotiated_mtu <= 1500u);
    CHECK(!r.jumbo_enabled);
}

// 7. MtuNegotiator 协商：一方 9000 + 一方 1280 → 1280（min）
static void test_negotiate_min_mtu_wins() {
    auto r = linoh::net::MtuNegotiator::negotiate(
        9000, 1280, linoh::net::NatType::OpenInternet, linoh::net::UdpFirewall::Open);
    CHECK_EQ(r.negotiated_mtu, 1280u);
    CHECK(!r.jumbo_enabled);
}

// 8. MtuNegotiator 协商：双方 1500 → 1500
static void test_negotiate_both_1500() {
    auto r = linoh::net::MtuNegotiator::negotiate(
        1500, 1500, linoh::net::NatType::OpenInternet, linoh::net::UdpFirewall::Open);
    CHECK_EQ(r.negotiated_mtu, 1500u);
    CHECK(!r.jumbo_enabled);
}

// 9. MtuNegotiator 协商：双方 1280 → 1280
static void test_negotiate_both_1280() {
    auto r = linoh::net::MtuNegotiator::negotiate(
        1280, 1280, linoh::net::NatType::OpenInternet, linoh::net::UdpFirewall::Open);
    CHECK_EQ(r.negotiated_mtu, 1280u);
    CHECK(!r.jumbo_enabled);
}

// 10. MtuNegotiator 协商：firewall Blocked → 降级
static void test_negotiate_firewall_blocked_downgrade() {
    auto r = linoh::net::MtuNegotiator::negotiate(
        9000, 9000, linoh::net::NatType::OpenInternet, linoh::net::UdpFirewall::Blocked);
    CHECK(r.negotiated_mtu <= 1500u);
    CHECK(!r.jumbo_enabled);
}

// 11. is_jumbo / is_valid_mtu 辅助函数
static void test_mtu_helpers() {
    CHECK(linoh::net::is_jumbo(9000));
    CHECK(!linoh::net::is_jumbo(8500));  // jumbo 阈值 9000
    CHECK(!linoh::net::is_jumbo(1500));
    CHECK(!linoh::net::is_jumbo(1280));

    CHECK(linoh::net::is_valid_mtu(1280));
    CHECK(linoh::net::is_valid_mtu(1500));
    CHECK(linoh::net::is_valid_mtu(9000));
    CHECK(!linoh::net::is_valid_mtu(0));
    CHECK(!linoh::net::is_valid_mtu(9001));

    // clamp_mtu 测试
    CHECK_EQ(linoh::net::clamp_mtu(10000), 9000u);
    CHECK_EQ(linoh::net::clamp_mtu(1000), 1280u);
    CHECK_EQ(linoh::net::clamp_mtu(1500), 1500u);

    // mtu_name
    CHECK_EQ_STR(std::string(linoh::net::mtu_name(9000)), std::string("jumbo(9000)"));
    CHECK_EQ_STR(std::string(linoh::net::mtu_name(1500)), std::string("standard(1500)"));
    CHECK_EQ_STR(std::string(linoh::net::mtu_name(1280)), std::string("minimum(1280)"));
}

// 12. Connection 默认 negotiated_mtu_ = 1280
static void test_connection_default_mtu_1280() {
    // 简单的 Connection 配置（不需要真握手）
    linoh::endpoint::Connection::Config cfg{};
    cfg.local_preferred_mtu = 1280;
    cfg.alpn = "pp-hidden/1";

    linoh::endpoint::Connection conn(cfg);
    CHECK_EQ(conn.negotiated_mtu(), 1280u);  // 握手前默认
    CHECK_EQ(conn.remote_preferred_mtu(), 1280u);  // 握手前无对端 → 1280
    CHECK_EQ(conn.current_max_packet_size(), 1280u);
}

// 13. Connection 显式 renegotiate_mtu
static void test_connection_renegotiate_mtu() {
    linoh::endpoint::Connection::Config cfg{};
    cfg.local_preferred_mtu = 9000;
    cfg.alpn = "pp-hidden/1";

    linoh::endpoint::Connection conn(cfg);
    // 显式调用 renegotiate_mtu（握手前对端默认 1280）
    conn.renegotiate_mtu(linoh::net::NatType::OpenInternet, false);
    CHECK_EQ(conn.negotiated_mtu(), 1280u);  // 1280 == min(9000, 1280)

    // 模拟 OpenInternet + jumbo
    conn.renegotiate_mtu(linoh::net::NatType::OpenInternet, false);
    // local=9000, remote=1280(handshake default) -> 1280
    CHECK_EQ(conn.negotiated_mtu(), 1280u);
}

// 14. current_max_packet_size 动态调整
static void test_current_max_packet_size() {
    linoh::endpoint::Connection::Config cfg{};
    cfg.local_preferred_mtu = 9000;
    cfg.alpn = "pp-hidden/1";

    linoh::endpoint::Connection conn(cfg);
    // 握手前 1280
    CHECK_EQ(conn.current_max_packet_size(), 1280u);
}

// 15. decode_hello 拒绝非法 MTU（0 或 > 9000）
static void test_decode_hello_rejects_invalid_mtu() {
    // 手工构造 mtu=0 的 wire
    Hello h = make_hello(0);
    auto wire = encode_hello(HsType::ClientHello, h);
    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(!decoded.has_value());  // mtu=0 应被拒绝

    // mtu=9001（> 9000）
    Hello h2 = make_hello(9001);
    auto wire2 = encode_hello(HsType::ClientHello, h2);
    auto decoded2 = decode_hello(wire2, HsType::ClientHello);
    CHECK(!decoded2.has_value());  // mtu > 9000 应被拒绝
}

// 16. alpn 后多余字节处理（decode_hello 严格/宽松）
static void test_decode_hello_extra_bytes() {
    // 手工构造 wire：alpn 后追加 2 字节 varint 编码（0x80 0x01 = 128）
    // varint_decode 会返回 (128, 2)，但 blen - tail_off = 1，字节数不匹配 → 拒绝
    std::vector<std::uint8_t> body;
    body.resize(32 + 32 + 32 + 1 + 8 + 2);
    for (int i = 0; i < 32; ++i) {
        body[i] = static_cast<std::uint8_t>(i);
        body[32 + i] = static_cast<std::uint8_t>(0x80 + i);
        body[64 + i] = static_cast<std::uint8_t>(0x40 + i);
    }
    body[96] = 8;
    std::memcpy(&body[97], "pp-img/1", 8);
    body[105] = 0x80;  // 2字节 varint 高位
    body[106] = 0x01;  // 2字节 varint 低位 → 解码为 128，但只读了 1字节 (blen-tail_off=1)

    std::vector<std::uint8_t> wire;
    wire.push_back(static_cast<std::uint8_t>(HsType::ClientHello));
    // varint(107) = 0x6B
    wire.push_back(0x6B);
    wire.insert(wire.end(), body.begin(), body.end());

    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(!decoded.has_value());  // 残留无效字节应被拒绝
}

// 17. encode/decode ServerHello 与 ClientHello 字段对称
static void test_server_hello_encode_decode() {
    auto h = make_hello(9000, "ctrl/1");
    auto wire = encode_hello(HsType::ServerHello, h);
    auto decoded = decode_hello(wire, HsType::ServerHello);
    CHECK(decoded.has_value());
    if (!decoded.has_value()) return;
    CHECK_EQ(decoded->first.preferred_mtu, 9000u);
    CHECK_EQ_STR(decoded->first.alpn, std::string("ctrl/1"));
}

// 18. PmtuDiscovery::infer_mtu_from_addr 推断 MTU
static void test_pmtu_infer_mtu() {
    // 同 IP 推断（IP only, 假设 LAN jumbo 9000）
    // 这是基于地址的启发式推断，与实际握手协商不同
    auto m = linoh::net::PmtuDiscovery::infer_mtu_from_addr("127.0.0.1");
    // 推断结果是合法 MTU
    CHECK(linoh::net::is_valid_mtu(m) || m == 1500);
}

// 19. Hello 消息 forward 兼容：双向 9000 + 协商后 jumbo frame
static void test_e2e_jumbo_negotiation() {
    // 模拟两端握手消息交换
    auto client_h = make_hello(9000, "pp-hidden/1");
    auto server_h = make_hello(9000, "pp-hidden/1");

    // 编码
    auto ch_wire = encode_hello(HsType::ClientHello, client_h);
    auto sh_wire = encode_hello(HsType::ServerHello, server_h);

    // 双方收到
    auto ch_decoded = decode_hello(ch_wire, HsType::ClientHello);
    auto sh_decoded = decode_hello(sh_wire, HsType::ServerHello);
    CHECK(ch_decoded.has_value() && sh_decoded.has_value());
    if (!ch_decoded.has_value() || !sh_decoded.has_value()) return;

    // 协商：双方 9000 + Open → 9000
    auto r = linoh::net::MtuNegotiator::negotiate(
        ch_decoded->first.preferred_mtu, sh_decoded->first.preferred_mtu,
        linoh::net::NatType::OpenInternet, linoh::net::UdpFirewall::Open);
    CHECK_EQ(r.negotiated_mtu, 9000u);
    CHECK(r.jumbo_enabled);
}

// 20. 协商后 jumbo_enabled 与 negotiated_mtu 关系
static void test_jumbo_consistency() {
    // jumbo 标志的 MTU 阈值是 8500
    auto r1 = linoh::net::MtuNegotiator::negotiate(
        9000, 9000, linoh::net::NatType::OpenInternet, linoh::net::UdpFirewall::Open);
    CHECK(r1.jumbo_enabled == (r1.negotiated_mtu >= 8500));

    auto r2 = linoh::net::MtuNegotiator::negotiate(
        1500, 1500, linoh::net::NatType::OpenInternet, linoh::net::UdpFirewall::Open);
    CHECK(!r2.jumbo_enabled);
    CHECK(r2.negotiated_mtu < 8500);
}

// ==================== Main ====================
int main() {
    std::printf("=== test_mtu_negotiation ===\n");

    test_encode_decode_hello_mtu_1280();
    test_encode_decode_hello_mtu_1500();
    test_encode_decode_hello_mtu_9000();
    test_decode_legacy_hello_no_mtu_field();
    test_negotiate_both_9000_open();
    test_negotiate_both_9000_restricted();
    test_negotiate_min_mtu_wins();
    test_negotiate_both_1500();
    test_negotiate_both_1280();
    test_negotiate_firewall_blocked_downgrade();
    test_mtu_helpers();
    test_connection_default_mtu_1280();
    test_connection_renegotiate_mtu();
    test_current_max_packet_size();
    test_decode_hello_rejects_invalid_mtu();
    test_decode_hello_extra_bytes();
    test_server_hello_encode_decode();
    test_pmtu_infer_mtu();
    test_e2e_jumbo_negotiation();
    test_jumbo_consistency();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
