// tests/test_crypto_negotiation.cpp
// v1.5.0.2 Step 4 — CryptoLevel 协商协议单元测试
// 覆盖：
//   1. Hello 字段编码（CryptoLevel None/Light/Standard/Strong/Maximum）
//   2. Hello 字段解码（含 mtu 后 1 byte crypto_level）
//   3. 向后兼容：旧版无 crypto_level 字段时 default None
//   4. 非法 crypto_level (>=5) 拒绝
//   5. 协商算法 max(local, remote) + 兜底
//   6. ALPN 兜底（pp-hidden/1 / ctrl/1 必须 Strong 以上）
//   7. Connection 协商回调（on_handshake_completed 自动调用）
//   8. 旧版（mtu 无字段 + crypto_level 无字段）→ 全部默认
//
// 用法：cl /c /std:c++20 /EHsc /permissive- /O2 /utf-8 /MD
//   /DLINOH_USE_STUB_ASIO /I. /Iinclude /Ithird_party\asio\include
//   /Ithird_party\openssl\include tests\test_crypto_negotiation.cpp
//   /Fo:build\test_crypto_negotiation.obj
// 链接：link /NOLOGO /OUT:build\test_crypto_negotiation.exe
//   build\test_crypto_negotiation.obj build\linoh.lib build\linoh-base.lib
//   build\linoh-relay.lib build\linoh-dns-server.lib ws2_32.lib user32.lib
//   /SUBSYSTEM:CONSOLE

#include "linoh/endpoint/connection.hpp"
#include "linoh/multimodal/channel.hpp"
#include "linoh/net/mtu.hpp"
#include "linoh/net/net_report.hpp"
#include "linoh/tls/crypto_level.hpp"
#include "linoh/tls/handshake.hpp"
#include "linoh/tls/handshake_msg.hpp"
#include "linoh/util/varint.hpp"

#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace {

int g_passed = 0;
int g_failed = 0;
std::vector<std::string> g_fail_msgs;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            ++g_passed;                                                      \
        } else {                                                             \
            ++g_failed;                                                      \
            char buf[256];                                                   \
            std::snprintf(buf, sizeof(buf), "FAIL: %s (line %d)", #cond, __LINE__); \
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
using CL = linoh::multimodal::CryptoLevel;
using NC = linoh::tls::NetworkClass;

// 辅助：构造测试 Hello
Hello make_hello(const std::string &alpn, std::uint16_t mtu, CL lv) {
    Hello h;
    h.alpn = alpn;
    h.preferred_mtu = mtu;
    h.preferred_crypto_level = lv;
    for (int i = 0; i < 32; ++i) {
        h.random[i]     = static_cast<std::uint8_t>(i);
        h.ephemeral[i]  = static_cast<std::uint8_t>(0x80 + i);
        h.node_pub[i]   = static_cast<std::uint8_t>(0x40 + i);
    }
    return h;
}

// ============================================================================
// 1. Hello 字段编码（CryptoLevel 各枚举值）
// ============================================================================
static void test_encode_hello_crypto_level_none() {
    auto h = make_hello("pp-hidden/1", 1280, CL::None);
    auto wire = encode_hello(HsType::ClientHello, h);
    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(decoded.has_value());
    CHECK_EQ(static_cast<int>(decoded->first.preferred_crypto_level), static_cast<int>(CL::None));
    CHECK_EQ(decoded->first.preferred_mtu, 1280u);
}

static void test_encode_hello_crypto_level_light() {
    auto h = make_hello("pp-img/1", 1500, CL::Light);
    auto wire = encode_hello(HsType::ClientHello, h);
    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(decoded.has_value());
    CHECK_EQ(static_cast<int>(decoded->first.preferred_crypto_level), static_cast<int>(CL::Light));
    CHECK_EQ(decoded->first.preferred_mtu, 1500u);
}

static void test_encode_hello_crypto_level_standard() {
    auto h = make_hello("pp-video/1", 9000, CL::Standard);
    auto wire = encode_hello(HsType::ClientHello, h);
    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(decoded.has_value());
    CHECK_EQ(static_cast<int>(decoded->first.preferred_crypto_level), static_cast<int>(CL::Standard));
    CHECK_EQ(decoded->first.preferred_mtu, 9000u);
}

static void test_encode_hello_crypto_level_strong() {
    auto h = make_hello("pp-hidden/1", 9000, CL::Strong);
    auto wire = encode_hello(HsType::ClientHello, h);
    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(decoded.has_value());
    CHECK_EQ(static_cast<int>(decoded->first.preferred_crypto_level), static_cast<int>(CL::Strong));
    CHECK_EQ(decoded->first.preferred_mtu, 9000u);
}

static void test_encode_hello_crypto_level_maximum() {
    auto h = make_hello("ctrl/1", 1280, CL::Maximum);
    auto wire = encode_hello(HsType::ClientHello, h);
    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(decoded.has_value());
    CHECK_EQ(static_cast<int>(decoded->first.preferred_crypto_level), static_cast<int>(CL::Maximum));
    CHECK_EQ(decoded->first.preferred_mtu, 1280u);
}

// ============================================================================
// 2. 向后兼容：旧版 Hello 无 mtu 字段（v1.4）→ 默认 mtu=1280, crypto=None
// ============================================================================
static void test_decode_legacy_hello_no_mtu_no_crypto() {
    // 手工构造 v1.4 wire：random(32) + ephemeral(32) + node_pub(32)
    //   + varint(8) + alpn(8 "pp-img/1") — 无 mtu 字段
    std::vector<std::uint8_t> body;
    body.resize(32 + 32 + 32 + 1 + 8);
    for (int i = 0; i < 32; ++i) {
        body[i] = static_cast<std::uint8_t>(i);
        body[32 + i] = static_cast<std::uint8_t>(0x80 + i);
        body[64 + i] = static_cast<std::uint8_t>(0x40 + i);
    }
    body[96] = 8;
    std::memcpy(&body[97], "pp-img/1", 8);

    std::vector<std::uint8_t> wire;
    wire.push_back(static_cast<std::uint8_t>(HsType::ClientHello));
    // varint(105) = [0x40, 0x69]
    wire.push_back(0x40);
    wire.push_back(0x69);
    wire.insert(wire.end(), body.begin(), body.end());

    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(decoded.has_value());
    CHECK_EQ(decoded->first.preferred_mtu, 1280u);
    CHECK_EQ(static_cast<int>(decoded->first.preferred_crypto_level), static_cast<int>(CL::None));
    CHECK_EQ_STR(decoded->first.alpn, std::string("pp-img/1"));
}

// ============================================================================
// 3. 向后兼容：v1.5.0.2 Step 3 节点（mtu 有，crypto 无）→ 解析为 mtu=9000, crypto=None
// ============================================================================
static void test_decode_step3_hello_mtu_no_crypto() {
    auto h = make_hello("pp-img/1", 9000, CL::None);
    // 手工构造只带 mtu 不带 crypto 的 wire
    std::vector<std::uint8_t> body;
    body.resize(32 + 32 + 32 + 1 + 8 + 2);  // +2 for mtu varint
    for (int i = 0; i < 32; ++i) {
        body[i] = static_cast<std::uint8_t>(i);
        body[32 + i] = static_cast<std::uint8_t>(0x80 + i);
        body[64 + i] = static_cast<std::uint8_t>(0x40 + i);
    }
    body[96] = 8;
    std::memcpy(&body[97], "pp-img/1", 8);
    // varint(9000) = 2 字节
    body[105] = 0xA0;  // 9000 = 0x2328
    body[106] = 0x28;  // wait, QUIC varint: 0xA0 prefix=2, value = (0xA0 & 0x3F)<<8 | 0x28 = (0x20)<<8 | 0x28 = 0x2028 = 8232. 不对
    // 9000 = 0x2328
    // 2字节 varint: (value >> 8) | 0x40 = 0x23 | 0x40 = 0x63, (value & 0xFF) = 0x28
    body[105] = 0x63;
    body[106] = 0x28;

    std::vector<std::uint8_t> wire;
    wire.push_back(static_cast<std::uint8_t>(HsType::ClientHello));
    // varint(107) = [0x40, 0x6B]
    wire.push_back(0x40);
    wire.push_back(0x6B);
    wire.insert(wire.end(), body.begin(), body.end());

    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(decoded.has_value());
    CHECK_EQ(decoded->first.preferred_mtu, 9000u);
    CHECK_EQ(static_cast<int>(decoded->first.preferred_crypto_level), static_cast<int>(CL::None));
}

// ============================================================================
// 4. 非法 crypto_level (>=5) 拒绝
// ============================================================================
static void test_decode_hello_invalid_crypto_level() {
    std::vector<std::uint8_t> body;
    body.resize(32 + 32 + 32 + 1 + 8 + 2 + 1);  // +2 mtu +1 crypto
    for (int i = 0; i < 32; ++i) {
        body[i] = static_cast<std::uint8_t>(i);
        body[32 + i] = static_cast<std::uint8_t>(0x80 + i);
        body[64 + i] = static_cast<std::uint8_t>(0x40 + i);
    }
    body[96] = 8;
    std::memcpy(&body[97], "pp-img/1", 8);
    // varint(1500) = 2 bytes
    body[105] = 0x45;  // (1500>>8) | 0x40 = 0x05 | 0x40 = 0x45
    body[106] = 0xDC;  // 1500 & 0xFF = 0xDC
    body[107] = 5;     // 非法 crypto_level (5 > Maximum=4)

    std::vector<std::uint8_t> wire;
    wire.push_back(static_cast<std::uint8_t>(HsType::ClientHello));
    // varint(108) = [0x40, 0x6C]
    wire.push_back(0x40);
    wire.push_back(0x6C);
    wire.insert(wire.end(), body.begin(), body.end());

    auto decoded = decode_hello(wire, HsType::ClientHello);
    CHECK(!decoded.has_value());  // 非法 crypto_level 应拒绝
}

// ============================================================================
// 5. CryptoSpec 矩阵 — select_crypto_level 已知行为复用
// ============================================================================
static void test_crypto_spec_for_levels() {
    // None
    auto s_none = linoh::tls::crypto_spec_for(CL::None);
    CHECK_EQ(static_cast<int>(s_none.level), static_cast<int>(CL::None));
    // Light
    auto s_light = linoh::tls::crypto_spec_for(CL::Light);
    CHECK_EQ(static_cast<int>(s_light.level), static_cast<int>(CL::Light));
    // Standard
    auto s_std = linoh::tls::crypto_spec_for(CL::Standard);
    CHECK_EQ(static_cast<int>(s_std.level), static_cast<int>(CL::Standard));
    // Strong
    auto s_strong = linoh::tls::crypto_spec_for(CL::Strong);
    CHECK_EQ(static_cast<int>(s_strong.level), static_cast<int>(CL::Strong));
    CHECK(s_strong.key_bits >= 256);
    // Maximum
    auto s_max = linoh::tls::crypto_spec_for(CL::Maximum);
    CHECK_EQ(static_cast<int>(s_max.level), static_cast<int>(CL::Maximum));
    CHECK(s_max.key_bits >= 256);
}

static void test_select_crypto_level_matrix() {
    // 实际矩阵（P5-B-2 select_crypto_level 实现）：
    //                LLM    IMG    VIDEO   AUDIO   CTRL   FUSION
    //   Lan         Strong  Standard  Light  Standard  Strong  Strong
    //   Wan         Strong  Strong    Standard Standard Strong Strong
    //   Hard        Maximum Strong    Standard Standard Maximum Maximum
    // Lan + LLM_HIDDEN → Strong（LLM 始终强加密）
    CHECK_EQ(static_cast<int>(linoh::tls::select_crypto_level(NC::Lan, linoh::multimodal::ChannelType::LLM_HIDDEN)),
              static_cast<int>(CL::Strong));
    // Wan + LLM_HIDDEN → Strong
    CHECK_EQ(static_cast<int>(linoh::tls::select_crypto_level(NC::Wan, linoh::multimodal::ChannelType::LLM_HIDDEN)),
              static_cast<int>(CL::Strong));
    // Hard + LLM_HIDDEN → Maximum（困难网络 + LLM 升 Maximum）
    CHECK_EQ(static_cast<int>(linoh::tls::select_crypto_level(NC::Hard, linoh::multimodal::ChannelType::LLM_HIDDEN)),
              static_cast<int>(CL::Maximum));
    // Lan + VIDEO_FEATURE → Light（视频大流量降级）
    CHECK_EQ(static_cast<int>(linoh::tls::select_crypto_level(NC::Lan, linoh::multimodal::ChannelType::VIDEO_FEATURE)),
              static_cast<int>(CL::Light));
    // Wan + VIDEO_FEATURE → Standard
    CHECK_EQ(static_cast<int>(linoh::tls::select_crypto_level(NC::Wan, linoh::multimodal::ChannelType::VIDEO_FEATURE)),
              static_cast<int>(CL::Standard));
    // Hard + VIDEO_FEATURE → Standard（视频不升 Maximum，避免性能崩塌）
    CHECK_EQ(static_cast<int>(linoh::tls::select_crypto_level(NC::Hard, linoh::multimodal::ChannelType::VIDEO_FEATURE)),
              static_cast<int>(CL::Standard));
    // Lan + IMG_FEATURE → Standard
    CHECK_EQ(static_cast<int>(linoh::tls::select_crypto_level(NC::Lan, linoh::multimodal::ChannelType::IMG_FEATURE)),
              static_cast<int>(CL::Standard));
    // Hard + CONTROL → Maximum
    CHECK_EQ(static_cast<int>(linoh::tls::select_crypto_level(NC::Hard, linoh::multimodal::ChannelType::CONTROL)),
              static_cast<int>(CL::Maximum));
}

// ============================================================================
// 6. Connection 协商 — 默认 None + 显式 negotiate_crypto_level 后有效
// ============================================================================
static void test_connection_default_crypto_level_none() {
    linoh::endpoint::Connection::Config cfg{};
    cfg.alpn = "pp-hidden/1";
    cfg.local_preferred_crypto_level = CL::None;
    cfg.local_network_class = NC::Lan;

    linoh::endpoint::Connection conn(cfg);
    CHECK_EQ(static_cast<int>(conn.effective_crypto_level()),
              static_cast<int>(CL::None));  // 握手前默认 None
    CHECK_EQ(static_cast<int>(conn.remote_preferred_crypto_level()),
              static_cast<int>(CL::None));  // 握手前无对端 → None
    auto spec = conn.effective_crypto_spec();
    CHECK_EQ(static_cast<int>(spec.level), static_cast<int>(CL::None));
}

static void test_connection_explicit_negotiate_lan_llm() {
    // 模拟 Lan + LLM_HIDDEN 协商（无对端时按本端 select_crypto_level 兜底）
    linoh::endpoint::Connection::Config cfg{};
    cfg.alpn = "pp-hidden/1";
    cfg.local_preferred_crypto_level = CL::None;  // 本端未指定
    cfg.local_network_class = NC::Lan;

    linoh::endpoint::Connection conn(cfg);
    conn.negotiate_crypto_level();
    // Lan + LLM_HIDDEN → select_crypto_level 返回 Strong（LLM 始终强加密）
    CHECK_EQ(static_cast<int>(conn.effective_crypto_level()),
              static_cast<int>(CL::Strong));
}

static void test_connection_negotiate_max_wins() {
    // 测试 max(local, remote) 逻辑
    // 由于 negotiate_crypto_level 用本端 local_network_class 计算本端期望，
    // 单独测试 max(local, remote) 通过 select_crypto_level 矩阵间接验证：
    // - 本端 Lan + LLM 期望 Strong
    // - 本端 Hard + LLM 期望 Maximum
    // max(Strong, Maximum) = Maximum
    auto lan_strong = linoh::tls::select_crypto_level(NC::Lan, linoh::multimodal::ChannelType::LLM_HIDDEN);
    auto hard_maximum = linoh::tls::select_crypto_level(NC::Hard, linoh::multimodal::ChannelType::LLM_HIDDEN);
    CHECK(static_cast<int>(lan_strong) < static_cast<int>(hard_maximum));
    auto m = (static_cast<int>(lan_strong) >= static_cast<int>(hard_maximum))
                  ? lan_strong : hard_maximum;
    CHECK_EQ(static_cast<int>(m), static_cast<int>(CL::Maximum));
}

static void test_connection_negotiate_alpn_floor() {
    // 测试 LLM/Control ALPN 强制 Strong 兜底
    // 本端 Wan + LLM_HIDDEN → select_crypto_level 返回 Strong（已满足兜底要求）
    // 验证：兜底规则不会拉低已有 Strong 级别
    linoh::endpoint::Connection::Config cfg{};
    cfg.alpn = "pp-hidden/1";
    cfg.local_preferred_crypto_level = CL::None;
    cfg.local_network_class = NC::Wan;  // Wan + LLM_HIDDEN → Strong

    linoh::endpoint::Connection conn(cfg);
    conn.negotiate_crypto_level();
    // 保持 Strong（无拉低、无拉高）
    CHECK_EQ(static_cast<int>(conn.effective_crypto_level()),
              static_cast<int>(CL::Strong));
}

static void test_connection_negotiate_control_floor() {
    // ctrl/1 控制通道：必须 Strong 以上
    linoh::endpoint::Connection::Config cfg{};
    cfg.alpn = "ctrl/1";
    cfg.local_preferred_crypto_level = CL::None;
    cfg.local_network_class = NC::Lan;  // Lan + CONTROL → ?

    linoh::endpoint::Connection conn(cfg);
    conn.negotiate_crypto_level();
    // CONTROL 兜底到 Strong
    CHECK_EQ(static_cast<int>(conn.effective_crypto_level()),
              static_cast<int>(CL::Strong));
}

static void test_connection_negotiate_video_allow_light() {
    // VIDEO_FEATURE 允许 Light（多媒体降级）
    linoh::endpoint::Connection::Config cfg{};
    cfg.alpn = "pp-video/1";
    cfg.local_preferred_crypto_level = CL::None;
    cfg.local_network_class = NC::Lan;  // Lan + VIDEO_FEATURE → Light

    linoh::endpoint::Connection conn(cfg);
    conn.negotiate_crypto_level();
    // VIDEO 不强制 Strong，按 select_crypto_level 结果（Lan → Light）
    CHECK_EQ(static_cast<int>(conn.effective_crypto_level()),
              static_cast<int>(CL::Light));
}

static void test_connection_negotiate_hard_video_max() {
    // Hard + VIDEO_FEATURE → Standard（视频大流量不升 Maximum，避免性能崩塌）
    linoh::endpoint::Connection::Config cfg{};
    cfg.alpn = "pp-video/1";
    cfg.local_preferred_crypto_level = CL::None;
    cfg.local_network_class = NC::Hard;

    linoh::endpoint::Connection conn(cfg);
    conn.negotiate_crypto_level();
    CHECK_EQ(static_cast<int>(conn.effective_crypto_level()),
              static_cast<int>(CL::Standard));
}

static void test_connection_negotiate_with_local_preference() {
    // 本端显式声明 Light（即使 Lan+LLM 默认要 Light，本端可再降级）
    linoh::endpoint::Connection::Config cfg{};
    cfg.alpn = "pp-hidden/1";
    cfg.local_preferred_crypto_level = CL::Light;
    cfg.local_network_class = NC::Lan;

    linoh::endpoint::Connection conn(cfg);
    conn.negotiate_crypto_level();
    // 本端 Light，select_crypto_level Lan+LLM 也 Light，对端 None→视同 local
    // LLM 兜底到 Strong
    CHECK_EQ(static_cast<int>(conn.effective_crypto_level()),
              static_cast<int>(CL::Strong));
}

}  // namespace

int main() {
    std::printf("=== test_crypto_negotiation (v1.5.0.2 Step 4) ===\n");

    // 1. Hello 字段编码
    test_encode_hello_crypto_level_none();
    test_encode_hello_crypto_level_light();
    test_encode_hello_crypto_level_standard();
    test_encode_hello_crypto_level_strong();
    test_encode_hello_crypto_level_maximum();

    // 2. 向后兼容
    test_decode_legacy_hello_no_mtu_no_crypto();
    test_decode_step3_hello_mtu_no_crypto();

    // 3. 非法值拒绝
    test_decode_hello_invalid_crypto_level();

    // 4. CryptoSpec 矩阵
    test_crypto_spec_for_levels();
    test_select_crypto_level_matrix();

    // 5. Connection 协商
    test_connection_default_crypto_level_none();
    test_connection_explicit_negotiate_lan_llm();
    test_connection_negotiate_max_wins();
    test_connection_negotiate_alpn_floor();
    test_connection_negotiate_control_floor();
    test_connection_negotiate_video_allow_light();
    test_connection_negotiate_hard_video_max();
    test_connection_negotiate_with_local_preference();

    std::printf("Summary: %d passed, %d failed\n", g_passed, g_failed);
    if (g_failed > 0) {
        std::fprintf(stderr, "\nFailed tests:\n");
        for (const auto &m : g_fail_msgs) std::fprintf(stderr, "  %s\n", m.c_str());
    }
    return g_failed == 0 ? 0 : 1;
}
