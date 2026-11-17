// test_crypto_level.cpp — P5-B-2 加密分级测试
//
// 验证矩阵：
//   | 网络 \ 模态 | LLM | 图片 | 视频 | 音频 | 控制 | 融合 |
//   | Lan   | Strong   | Standard | Light    | Standard | Strong   | Strong   |
//   | Wan   | Strong   | Strong   | Standard | Standard | Strong   | Strong   |
//   | Hard  | Maximum  | Strong   | Standard | Standard | Maximum  | Maximum  |
//
// 另外验证：
//   - classify_network 对所有 NatType/UdpFirewall 组合的正确分类
//   - crypto_spec_for 各级别的算法名/密钥长度/extra_mac
//   - 便捷重载 select_crypto_level(NetReport, Channel) 与显式重载一致性

#include "linoh/tls/crypto_level.hpp"
#include "linoh/multimodal/channel.hpp"
#include "linoh/net/net_report.hpp"

#include <cstdio>
#include <cstdint>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh;
using multimodal::ChannelType;
using multimodal::CryptoLevel;
using tls::NetworkClass;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// classify_network 测试
// ============================================================================

static net::NetReport make_report(net::NatType nat, net::UdpFirewall fw = net::UdpFirewall::Open) {
    net::NetReport r;
    r.nat_type = nat;
    r.udp_firewall = fw;
    return r;
}

static void test_classify_open_internet() {
    auto r = make_report(net::NatType::OpenInternet);
    CHECK(tls::classify_network(r) == NetworkClass::Lan);
}

static void test_classify_full_cone() {
    auto r = make_report(net::NatType::FullCone);
    CHECK(tls::classify_network(r) == NetworkClass::Lan);
}

static void test_classify_restricted_cone() {
    auto r = make_report(net::NatType::RestrictedCone);
    CHECK(tls::classify_network(r) == NetworkClass::Wan);
}

static void test_classify_port_restricted() {
    auto r = make_report(net::NatType::PortRestrictedCone);
    CHECK(tls::classify_network(r) == NetworkClass::Wan);
}

static void test_classify_symmetric() {
    auto r = make_report(net::NatType::Symmetric);
    CHECK(tls::classify_network(r) == NetworkClass::Hard);
}

static void test_classify_unknown() {
    auto r = make_report(net::NatType::Unknown);
    CHECK(tls::classify_network(r) == NetworkClass::Hard);
}

static void test_classify_udp_blocked() {
    // 即使 NAT 是 OpenInternet，UDP 被阻断也按困难网络处理
    auto r = make_report(net::NatType::OpenInternet, net::UdpFirewall::Blocked);
    CHECK(tls::classify_network(r) == NetworkClass::Hard);
}

static void test_classify_udp_blocked_overrides_fullcone() {
    auto r = make_report(net::NatType::FullCone, net::UdpFirewall::Blocked);
    CHECK(tls::classify_network(r) == NetworkClass::Hard);
}

// ============================================================================
// select_crypto_level LAN 矩阵
// ============================================================================

static void test_lan_llm() {
    CHECK(tls::select_crypto_level(NetworkClass::Lan, ChannelType::LLM_HIDDEN) == CryptoLevel::Strong);
}

static void test_lan_img() {
    CHECK(tls::select_crypto_level(NetworkClass::Lan, ChannelType::IMG_FEATURE) == CryptoLevel::Standard);
}

static void test_lan_video() {
    CHECK(tls::select_crypto_level(NetworkClass::Lan, ChannelType::VIDEO_FEATURE) == CryptoLevel::Light);
}

static void test_lan_audio() {
    CHECK(tls::select_crypto_level(NetworkClass::Lan, ChannelType::AUDIO_FEATURE) == CryptoLevel::Standard);
}

static void test_lan_control() {
    CHECK(tls::select_crypto_level(NetworkClass::Lan, ChannelType::CONTROL) == CryptoLevel::Strong);
}

static void test_lan_fusion() {
    CHECK(tls::select_crypto_level(NetworkClass::Lan, ChannelType::FUSION) == CryptoLevel::Strong);
}

// ============================================================================
// select_crypto_level WAN 矩阵
// ============================================================================

static void test_wan_llm() {
    CHECK(tls::select_crypto_level(NetworkClass::Wan, ChannelType::LLM_HIDDEN) == CryptoLevel::Strong);
}

static void test_wan_img() {
    CHECK(tls::select_crypto_level(NetworkClass::Wan, ChannelType::IMG_FEATURE) == CryptoLevel::Strong);
}

static void test_wan_video() {
    CHECK(tls::select_crypto_level(NetworkClass::Wan, ChannelType::VIDEO_FEATURE) == CryptoLevel::Standard);
}

static void test_wan_audio() {
    CHECK(tls::select_crypto_level(NetworkClass::Wan, ChannelType::AUDIO_FEATURE) == CryptoLevel::Standard);
}

static void test_wan_control() {
    CHECK(tls::select_crypto_level(NetworkClass::Wan, ChannelType::CONTROL) == CryptoLevel::Strong);
}

static void test_wan_fusion() {
    CHECK(tls::select_crypto_level(NetworkClass::Wan, ChannelType::FUSION) == CryptoLevel::Strong);
}

// ============================================================================
// select_crypto_level HARD 矩阵
// ============================================================================

static void test_hard_llm() {
    CHECK(tls::select_crypto_level(NetworkClass::Hard, ChannelType::LLM_HIDDEN) == CryptoLevel::Maximum);
}

static void test_hard_img() {
    CHECK(tls::select_crypto_level(NetworkClass::Hard, ChannelType::IMG_FEATURE) == CryptoLevel::Strong);
}

static void test_hard_video() {
    CHECK(tls::select_crypto_level(NetworkClass::Hard, ChannelType::VIDEO_FEATURE) == CryptoLevel::Standard);
}

static void test_hard_audio() {
    CHECK(tls::select_crypto_level(NetworkClass::Hard, ChannelType::AUDIO_FEATURE) == CryptoLevel::Standard);
}

static void test_hard_control() {
    CHECK(tls::select_crypto_level(NetworkClass::Hard, ChannelType::CONTROL) == CryptoLevel::Maximum);
}

static void test_hard_fusion() {
    CHECK(tls::select_crypto_level(NetworkClass::Hard, ChannelType::FUSION) == CryptoLevel::Maximum);
}

// ============================================================================
// 便捷重载 select_crypto_level(NetReport, ChannelType)
// ============================================================================

static void test_overload_open_internet_llm() {
    auto r = make_report(net::NatType::OpenInternet);
    CHECK(tls::select_crypto_level(r, ChannelType::LLM_HIDDEN) == CryptoLevel::Strong);
}

static void test_overload_symmetric_control() {
    auto r = make_report(net::NatType::Symmetric);
    CHECK(tls::select_crypto_level(r, ChannelType::CONTROL) == CryptoLevel::Maximum);
}

static void test_overload_restricted_video() {
    auto r = make_report(net::NatType::RestrictedCone);
    CHECK(tls::select_crypto_level(r, ChannelType::VIDEO_FEATURE) == CryptoLevel::Standard);
}

static void test_overload_consistency() {
    // 验证 (NetReport, Channel) 与 (classify_network(NetReport), Channel) 结果一致
    for (auto nat : {net::NatType::OpenInternet, net::NatType::FullCone,
                     net::NatType::RestrictedCone, net::NatType::PortRestrictedCone,
                     net::NatType::Symmetric, net::NatType::Unknown}) {
        auto r = make_report(nat);
        auto nc = tls::classify_network(r);
        for (auto ch : {ChannelType::LLM_HIDDEN, ChannelType::IMG_FEATURE,
                        ChannelType::VIDEO_FEATURE, ChannelType::AUDIO_FEATURE,
                        ChannelType::CONTROL, ChannelType::FUSION}) {
            CHECK(tls::select_crypto_level(r, ch) == tls::select_crypto_level(nc, ch));
        }
    }
}

// ============================================================================
// crypto_spec_for 测试
// ============================================================================

static void test_spec_none() {
    auto s = tls::crypto_spec_for(CryptoLevel::None);
    CHECK(s.level == CryptoLevel::None);
    CHECK(std::string(s.algorithm) == "None");
    CHECK(s.key_bits == 0);
    CHECK(s.extra_mac == false);
}

static void test_spec_light() {
    auto s = tls::crypto_spec_for(CryptoLevel::Light);
    CHECK(s.level == CryptoLevel::Light);
    CHECK(std::string(s.algorithm) == "ChaCha20-Poly1305");
    CHECK(s.key_bits == 256);
    CHECK(s.extra_mac == false);
}

static void test_spec_standard() {
    auto s = tls::crypto_spec_for(CryptoLevel::Standard);
    CHECK(s.level == CryptoLevel::Standard);
    CHECK(std::string(s.algorithm) == "AES-128-GCM");
    CHECK(s.key_bits == 128);
    CHECK(s.extra_mac == false);
}

static void test_spec_strong() {
    auto s = tls::crypto_spec_for(CryptoLevel::Strong);
    CHECK(s.level == CryptoLevel::Strong);
    CHECK(std::string(s.algorithm) == "AES-256-GCM");
    CHECK(s.key_bits == 256);
    CHECK(s.extra_mac == false);
}

static void test_spec_maximum() {
    auto s = tls::crypto_spec_for(CryptoLevel::Maximum);
    CHECK(s.level == CryptoLevel::Maximum);
    CHECK(std::string(s.algorithm) == "AES-256-GCM");
    CHECK(s.key_bits == 256);
    CHECK(s.extra_mac == true);  // Maximum 附加 MAC
}

// ============================================================================
// network_class_name 测试
// ============================================================================

static void test_network_class_name() {
    CHECK(std::string(tls::network_class_name(NetworkClass::Lan)) == "lan");
    CHECK(std::string(tls::network_class_name(NetworkClass::Wan)) == "wan");
    CHECK(std::string(tls::network_class_name(NetworkClass::Hard)) == "hard");
}

// ============================================================================
// 完整矩阵覆盖（3 网络 × 6 模态 = 18 组合）
// ============================================================================

static void test_full_matrix() {
    using CL = CryptoLevel;
    // Lan 矩阵
    CHECK(tls::select_crypto_level(NetworkClass::Lan, ChannelType::LLM_HIDDEN)    == CL::Strong);
    CHECK(tls::select_crypto_level(NetworkClass::Lan, ChannelType::IMG_FEATURE)   == CL::Standard);
    CHECK(tls::select_crypto_level(NetworkClass::Lan, ChannelType::VIDEO_FEATURE) == CL::Light);
    CHECK(tls::select_crypto_level(NetworkClass::Lan, ChannelType::AUDIO_FEATURE) == CL::Standard);
    CHECK(tls::select_crypto_level(NetworkClass::Lan, ChannelType::CONTROL)       == CL::Strong);
    CHECK(tls::select_crypto_level(NetworkClass::Lan, ChannelType::FUSION)        == CL::Strong);
    // Wan 矩阵
    CHECK(tls::select_crypto_level(NetworkClass::Wan, ChannelType::LLM_HIDDEN)    == CL::Strong);
    CHECK(tls::select_crypto_level(NetworkClass::Wan, ChannelType::IMG_FEATURE)   == CL::Strong);
    CHECK(tls::select_crypto_level(NetworkClass::Wan, ChannelType::VIDEO_FEATURE) == CL::Standard);
    CHECK(tls::select_crypto_level(NetworkClass::Wan, ChannelType::AUDIO_FEATURE) == CL::Standard);
    CHECK(tls::select_crypto_level(NetworkClass::Wan, ChannelType::CONTROL)       == CL::Strong);
    CHECK(tls::select_crypto_level(NetworkClass::Wan, ChannelType::FUSION)        == CL::Strong);
    // Hard 矩阵
    CHECK(tls::select_crypto_level(NetworkClass::Hard, ChannelType::LLM_HIDDEN)    == CL::Maximum);
    CHECK(tls::select_crypto_level(NetworkClass::Hard, ChannelType::IMG_FEATURE)   == CL::Strong);
    CHECK(tls::select_crypto_level(NetworkClass::Hard, ChannelType::VIDEO_FEATURE) == CL::Standard);
    CHECK(tls::select_crypto_level(NetworkClass::Hard, ChannelType::AUDIO_FEATURE) == CL::Standard);
    CHECK(tls::select_crypto_level(NetworkClass::Hard, ChannelType::CONTROL)       == CL::Maximum);
    CHECK(tls::select_crypto_level(NetworkClass::Hard, ChannelType::FUSION)        == CL::Maximum);
}

// ============================================================================
// LLM 始终强加密以上（关键安全约束）
// ============================================================================

static void test_llm_always_strong_or_above() {
    // LLM hidden_state 在所有网络下至少 Strong
    for (auto nc : {NetworkClass::Lan, NetworkClass::Wan, NetworkClass::Hard}) {
        auto level = tls::select_crypto_level(nc, ChannelType::LLM_HIDDEN);
        CHECK(level == CryptoLevel::Strong || level == CryptoLevel::Maximum);
    }
}

// ============================================================================
// Control 始终强加密以上
// ============================================================================

static void test_control_always_strong_or_above() {
    for (auto nc : {NetworkClass::Lan, NetworkClass::Wan, NetworkClass::Hard}) {
        auto level = tls::select_crypto_level(nc, ChannelType::CONTROL);
        CHECK(level == CryptoLevel::Strong || level == CryptoLevel::Maximum);
    }
}

// ============================================================================
// 完整 NatType × UdpFirewall × ChannelType 组合一致性
// ============================================================================

static void test_all_combinations_consistent() {
    // 遍历所有 NatType、UdpFirewall、ChannelType 组合
    // 验证结果在合理范围内（None 不应出现，最低是 Light）
    for (auto nat : {net::NatType::OpenInternet, net::NatType::FullCone,
                     net::NatType::RestrictedCone, net::NatType::PortRestrictedCone,
                     net::NatType::Symmetric, net::NatType::Unknown}) {
        for (auto fw : {net::UdpFirewall::Open, net::UdpFirewall::Blocked, net::UdpFirewall::Unknown}) {
            auto r = make_report(nat, fw);
            for (auto ch : {ChannelType::LLM_HIDDEN, ChannelType::IMG_FEATURE,
                            ChannelType::VIDEO_FEATURE, ChannelType::AUDIO_FEATURE,
                            ChannelType::CONTROL, ChannelType::FUSION}) {
                auto level = tls::select_crypto_level(r, ch);
                // 不应返回 None
                CHECK(level != CryptoLevel::None);
                // 范围检查
                std::uint8_t lv = static_cast<std::uint8_t>(level);
                CHECK(lv >= 1 && lv <= 4);
            }
        }
    }
}

int main() {
    std::printf("=== test_crypto_level ===\n");

    test_classify_open_internet();
    test_classify_full_cone();
    test_classify_restricted_cone();
    test_classify_port_restricted();
    test_classify_symmetric();
    test_classify_unknown();
    test_classify_udp_blocked();
    test_classify_udp_blocked_overrides_fullcone();

    test_lan_llm();
    test_lan_img();
    test_lan_video();
    test_lan_audio();
    test_lan_control();
    test_lan_fusion();

    test_wan_llm();
    test_wan_img();
    test_wan_video();
    test_wan_audio();
    test_wan_control();
    test_wan_fusion();

    test_hard_llm();
    test_hard_img();
    test_hard_video();
    test_hard_audio();
    test_hard_control();
    test_hard_fusion();

    test_overload_open_internet_llm();
    test_overload_symmetric_control();
    test_overload_restricted_video();
    test_overload_consistency();

    test_spec_none();
    test_spec_light();
    test_spec_standard();
    test_spec_strong();
    test_spec_maximum();

    test_network_class_name();

    test_full_matrix();

    test_llm_always_strong_or_above();
    test_control_always_strong_or_above();

    test_all_combinations_consistent();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
