// test_multimodal_channel.cpp — P5-A-1 多模态通道单元测试
//
// 测试覆盖：
//   1.  ALPN 字符串映射（channel → alpn）
//   2.  ALPN 反解（alpn → channel）
//   3.  旧 ALPN pp-hidden/1 向后兼容映射到 LLM_HIDDEN
//   4.  未知 ALPN 回退到 CONTROL
//   5.  channel_type_name 字符串
//   6.  crypto_level_name 字符串
//   7.  fec_type_name 字符串
//   8.  is_data_channel 判定
//   9.  is_reliable_channel 判定
//  10.  ChannelConfig 默认构造
//  11.  ChannelConfig::for_channel(CONTROL) 默认配置
//  12.  ChannelConfig::for_channel(LLM_HIDDEN) 默认配置（RS K=10 M=2 Strong）
//  13.  ChannelConfig::for_channel(IMG_FEATURE) 默认配置（无 FEC Standard 9000 MTU）
//  14.  ChannelConfig::for_channel(VIDEO_FEATURE) 默认配置（RS K=16 M=1 Light 9000 strip）
//  15.  ChannelConfig::for_channel(AUDIO_FEATURE) 默认配置
//  16.  ChannelConfig::for_channel(FUSION) 默认配置
//  17.  channel_config_to_json 序列化基本字段
//  18.  channel_config_from_json 反序列化基本字段
//  19.  channel_config_from_json 解析失败回退默认配置
//  20.  channel_config_to_json → from_json 往返一致性
//  21.  for_channel + 修改字段后 to_json 反映修改
//  22.  C-API linoh_channel_alpn 字符串
//  23.  C-API 通道常量值正确
//  24.  CryptoLevel 枚举值有序
//  25.  FecType 枚举值有序

#include "linoh/multimodal/channel.hpp"
#include "linoh/linoh_c.h"

#include <cassert>
#include <cstdio>
#include <string>
#include <string_view>

using namespace linoh::multimodal;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL line %d: %s\n", __LINE__, #cond); } \
} while(0)

// ========== 1. ALPN 字符串映射 ==========
static void test_alpn_mapping() {
    CHECK(alpn_for(ChannelType::CONTROL)       == "ctrl/1");
    CHECK(alpn_for(ChannelType::LLM_HIDDEN)    == "pp-llm/1");
    CHECK(alpn_for(ChannelType::IMG_FEATURE)   == "pp-img/1");
    CHECK(alpn_for(ChannelType::VIDEO_FEATURE) == "pp-video/1");
    CHECK(alpn_for(ChannelType::AUDIO_FEATURE) == "pp-audio/1");
    CHECK(alpn_for(ChannelType::FUSION)        == "pp-multi/1");
}

// ========== 2. ALPN 反解 ==========
static void test_channel_from_alpn() {
    CHECK(channel_from_alpn("ctrl/1")       == ChannelType::CONTROL);
    CHECK(channel_from_alpn("pp-llm/1")     == ChannelType::LLM_HIDDEN);
    CHECK(channel_from_alpn("pp-img/1")     == ChannelType::IMG_FEATURE);
    CHECK(channel_from_alpn("pp-video/1")   == ChannelType::VIDEO_FEATURE);
    CHECK(channel_from_alpn("pp-audio/1")   == ChannelType::AUDIO_FEATURE);
    CHECK(channel_from_alpn("pp-multi/1")   == ChannelType::FUSION);
}

// ========== 3. 旧 ALPN 向后兼容 ==========
static void test_legacy_alpn_compat() {
    CHECK(channel_from_alpn("pp-hidden/1") == ChannelType::LLM_HIDDEN);
}

// ========== 4. 未知 ALPN 回退 ==========
static void test_unknown_alpn_fallback() {
    CHECK(channel_from_alpn("unknown/1")  == ChannelType::CONTROL);
    CHECK(channel_from_alpn("")           == ChannelType::CONTROL);
    CHECK(channel_from_alpn("foo")        == ChannelType::CONTROL);
}

// ========== 5. channel_type_name ==========
static void test_channel_type_name() {
    CHECK(channel_type_name(ChannelType::CONTROL)       == "control");
    CHECK(channel_type_name(ChannelType::LLM_HIDDEN)    == "llm_hidden");
    CHECK(channel_type_name(ChannelType::IMG_FEATURE)   == "img_feature");
    CHECK(channel_type_name(ChannelType::VIDEO_FEATURE) == "video_feature");
    CHECK(channel_type_name(ChannelType::AUDIO_FEATURE) == "audio_feature");
    CHECK(channel_type_name(ChannelType::FUSION)        == "fusion");
}

// ========== 6. crypto_level_name ==========
static void test_crypto_level_name() {
    CHECK(crypto_level_name(CryptoLevel::None)     == "none");
    CHECK(crypto_level_name(CryptoLevel::Light)    == "light");
    CHECK(crypto_level_name(CryptoLevel::Standard) == "standard");
    CHECK(crypto_level_name(CryptoLevel::Strong)   == "strong");
    CHECK(crypto_level_name(CryptoLevel::Maximum)  == "maximum");
}

// ========== 7. fec_type_name ==========
static void test_fec_type_name() {
    CHECK(fec_type_name(FecType::None)         == "none");
    CHECK(fec_type_name(FecType::Xor)          == "xor");
    CHECK(fec_type_name(FecType::ReedSolomon)  == "reed_solomon");
}

// ========== 8. is_data_channel ==========
static void test_is_data_channel() {
    CHECK(!is_data_channel(ChannelType::CONTROL));
    CHECK(is_data_channel(ChannelType::LLM_HIDDEN));
    CHECK(is_data_channel(ChannelType::IMG_FEATURE));
    CHECK(is_data_channel(ChannelType::VIDEO_FEATURE));
    CHECK(is_data_channel(ChannelType::AUDIO_FEATURE));
    CHECK(is_data_channel(ChannelType::FUSION));
}

// ========== 9. is_reliable_channel ==========
static void test_is_reliable_channel() {
    CHECK(is_reliable_channel(ChannelType::CONTROL));
    CHECK(!is_reliable_channel(ChannelType::LLM_HIDDEN));
    CHECK(!is_reliable_channel(ChannelType::VIDEO_FEATURE));
}

// ========== 10. ChannelConfig 默认构造 ==========
static void test_default_config() {
    ChannelConfig c;
    CHECK(c.type == ChannelType::CONTROL);
    CHECK(c.preferred_mtu == 1280);
    CHECK(c.max_stream_concurrency == 4);
    CHECK(!c.fec_enabled);
    CHECK(c.fec_type == FecType::None);
    CHECK(c.fec_data_blocks == 10);
    CHECK(c.fec_recovery_blocks == 2);
    CHECK(!c.multipath_strip);
    CHECK(c.crypto_level == CryptoLevel::Strong);
}

// ========== 11. for_channel(CONTROL) ==========
static void test_for_channel_control() {
    auto c = ChannelConfig::for_channel(ChannelType::CONTROL);
    CHECK(c.type == ChannelType::CONTROL);
    CHECK(!c.fec_enabled);
    CHECK(c.crypto_level == CryptoLevel::Strong);
    CHECK(c.preferred_mtu == 1280);
    CHECK(!c.multipath_strip);
}

// ========== 12. for_channel(LLM_HIDDEN) ==========
static void test_for_channel_llm() {
    auto c = ChannelConfig::for_channel(ChannelType::LLM_HIDDEN);
    CHECK(c.type == ChannelType::LLM_HIDDEN);
    CHECK(c.fec_enabled);
    CHECK(c.fec_type == FecType::ReedSolomon);
    CHECK(c.fec_data_blocks == 10);
    CHECK(c.fec_recovery_blocks == 2);
    CHECK(c.crypto_level == CryptoLevel::Strong);
    CHECK(c.preferred_mtu == 1280);
}

// ========== 13. for_channel(IMG_FEATURE) ==========
static void test_for_channel_img() {
    auto c = ChannelConfig::for_channel(ChannelType::IMG_FEATURE);
    CHECK(c.type == ChannelType::IMG_FEATURE);
    CHECK(!c.fec_enabled);
    CHECK(c.crypto_level == CryptoLevel::Standard);
    CHECK(c.preferred_mtu == 9000);  // jumbo frame
    CHECK(!c.multipath_strip);
}

// ========== 14. for_channel(VIDEO_FEATURE) ==========
static void test_for_channel_video() {
    auto c = ChannelConfig::for_channel(ChannelType::VIDEO_FEATURE);
    CHECK(c.type == ChannelType::VIDEO_FEATURE);
    CHECK(c.fec_enabled);
    CHECK(c.fec_type == FecType::ReedSolomon);
    CHECK(c.fec_data_blocks == 16);
    CHECK(c.fec_recovery_blocks == 1);
    CHECK(c.crypto_level == CryptoLevel::Light);
    CHECK(c.preferred_mtu == 9000);
    CHECK(c.multipath_strip);  // 视频流启用多路径 strip
}

// ========== 15. for_channel(AUDIO_FEATURE) ==========
static void test_for_channel_audio() {
    auto c = ChannelConfig::for_channel(ChannelType::AUDIO_FEATURE);
    CHECK(c.type == ChannelType::AUDIO_FEATURE);
    CHECK(!c.fec_enabled);
    CHECK(c.crypto_level == CryptoLevel::Standard);
    CHECK(c.preferred_mtu == 1280);
}

// ========== 16. for_channel(FUSION) ==========
static void test_for_channel_fusion() {
    auto c = ChannelConfig::for_channel(ChannelType::FUSION);
    CHECK(c.type == ChannelType::FUSION);
    CHECK(!c.fec_enabled);
    CHECK(c.crypto_level == CryptoLevel::Strong);
    CHECK(c.preferred_mtu == 1280);
}

// ========== 17. channel_config_to_json 基本字段 ==========
static void test_config_to_json() {
    auto c = ChannelConfig::for_channel(ChannelType::LLM_HIDDEN);
    std::string json = channel_config_to_json(c);
    CHECK(json.find("\"type\":\"llm_hidden\"") != std::string::npos);
    CHECK(json.find("\"mtu\":1280") != std::string::npos);
    CHECK(json.find("\"fec_enabled\":true") != std::string::npos);
    CHECK(json.find("\"fec_type\":\"reed_solomon\"") != std::string::npos);
    CHECK(json.find("\"fec_k\":10") != std::string::npos);
    CHECK(json.find("\"fec_m\":2") != std::string::npos);
    CHECK(json.find("\"crypto\":\"strong\"") != std::string::npos);
    CHECK(json.find("\"multipath_strip\":false") != std::string::npos);
}

// ========== 18. channel_config_from_json 基本字段 ==========
static void test_config_from_json() {
    std::string json = R"({"type":"video_feature","mtu":9000,"max_streams":8,
                            "fec_enabled":true,"fec_type":"reed_solomon",
                            "fec_k":16,"fec_m":1,
                            "multipath_strip":true,"crypto":"light"})";
    auto c = channel_config_from_json(json, ChannelType::CONTROL);
    CHECK(c.type == ChannelType::VIDEO_FEATURE);
    CHECK(c.preferred_mtu == 9000);
    CHECK(c.max_stream_concurrency == 8);
    CHECK(c.fec_enabled);
    CHECK(c.fec_type == FecType::ReedSolomon);
    CHECK(c.fec_data_blocks == 16);
    CHECK(c.fec_recovery_blocks == 1);
    CHECK(c.multipath_strip);
    CHECK(c.crypto_level == CryptoLevel::Light);
}

// ========== 19. from_json 解析失败回退默认配置 ==========
static void test_config_from_json_invalid() {
    auto c = channel_config_from_json("invalid json", ChannelType::LLM_HIDDEN);
    // 回退到 LLM_HIDDEN 默认配置
    CHECK(c.type == ChannelType::LLM_HIDDEN);
    CHECK(c.fec_enabled);
    CHECK(c.fec_type == FecType::ReedSolomon);
    CHECK(c.crypto_level == CryptoLevel::Strong);
}

// ========== 20. to_json → from_json 往返一致性 ==========
static void test_config_roundtrip() {
    auto orig = ChannelConfig::for_channel(ChannelType::VIDEO_FEATURE);
    std::string json = channel_config_to_json(orig);
    auto restored = channel_config_from_json(json, ChannelType::CONTROL);
    CHECK(restored.type == orig.type);
    CHECK(restored.preferred_mtu == orig.preferred_mtu);
    CHECK(restored.max_stream_concurrency == orig.max_stream_concurrency);
    CHECK(restored.fec_enabled == orig.fec_enabled);
    CHECK(restored.fec_type == orig.fec_type);
    CHECK(restored.fec_data_blocks == orig.fec_data_blocks);
    CHECK(restored.fec_recovery_blocks == orig.fec_recovery_blocks);
    CHECK(restored.multipath_strip == orig.multipath_strip);
    CHECK(restored.crypto_level == orig.crypto_level);
}

// ========== 21. for_channel + 修改字段后 to_json 反映修改 ==========
static void test_config_modify_then_serialize() {
    auto c = ChannelConfig::for_channel(ChannelType::LLM_HIDDEN);
    c.preferred_mtu = 9000;
    c.multipath_strip = true;
    std::string json = channel_config_to_json(c);
    CHECK(json.find("\"mtu\":9000") != std::string::npos);
    CHECK(json.find("\"multipath_strip\":true") != std::string::npos);
    // 保留 LLM 的默认 FEC 配置
    CHECK(json.find("\"fec_type\":\"reed_solomon\"") != std::string::npos);
    CHECK(json.find("\"fec_k\":10") != std::string::npos);
}

// ========== 22. C-API linoh_channel_alpn ==========
static void test_c_api_alpn() {
    CHECK(std::string(linoh_channel_alpn(LINOH_CHANNEL_CONTROL))       == "ctrl/1");
    CHECK(std::string(linoh_channel_alpn(LINOH_CHANNEL_LLM_HIDDEN))    == "pp-llm/1");
    CHECK(std::string(linoh_channel_alpn(LINOH_CHANNEL_IMG_FEATURE))   == "pp-img/1");
    CHECK(std::string(linoh_channel_alpn(LINOH_CHANNEL_VIDEO_FEATURE)) == "pp-video/1");
    CHECK(std::string(linoh_channel_alpn(LINOH_CHANNEL_AUDIO_FEATURE)) == "pp-audio/1");
    CHECK(std::string(linoh_channel_alpn(LINOH_CHANNEL_FUSION))        == "pp-multi/1");
}

// ========== 23. C-API 通道常量值 ==========
static void test_c_api_constants() {
    CHECK(LINOH_CHANNEL_CONTROL       == 0);
    CHECK(LINOH_CHANNEL_LLM_HIDDEN    == 1);
    CHECK(LINOH_CHANNEL_IMG_FEATURE   == 2);
    CHECK(LINOH_CHANNEL_VIDEO_FEATURE == 3);
    CHECK(LINOH_CHANNEL_AUDIO_FEATURE == 4);
    CHECK(LINOH_CHANNEL_FUSION        == 5);

    // C 常量与 C++ 枚举值一致
    CHECK(static_cast<std::uint8_t>(ChannelType::CONTROL)       == LINOH_CHANNEL_CONTROL);
    CHECK(static_cast<std::uint8_t>(ChannelType::LLM_HIDDEN)    == LINOH_CHANNEL_LLM_HIDDEN);
    CHECK(static_cast<std::uint8_t>(ChannelType::VIDEO_FEATURE) == LINOH_CHANNEL_VIDEO_FEATURE);
}

// ========== 24. CryptoLevel 枚举值有序 ==========
static void test_crypto_level_ordering() {
    // 确保枚举值递增，便于比较运算
    CHECK(static_cast<int>(CryptoLevel::None)     < static_cast<int>(CryptoLevel::Light));
    CHECK(static_cast<int>(CryptoLevel::Light)    < static_cast<int>(CryptoLevel::Standard));
    CHECK(static_cast<int>(CryptoLevel::Standard) < static_cast<int>(CryptoLevel::Strong));
    CHECK(static_cast<int>(CryptoLevel::Strong)   < static_cast<int>(CryptoLevel::Maximum));
}

// ========== 25. FecType 枚举值有序 ==========
static void test_fec_type_ordering() {
    CHECK(static_cast<int>(FecType::None)         < static_cast<int>(FecType::Xor));
    CHECK(static_cast<int>(FecType::Xor)          < static_cast<int>(FecType::ReedSolomon));
}

int main() {
    std::printf("=== test_multimodal_channel (P5-A-1) ===\n");

    test_alpn_mapping();
    test_channel_from_alpn();
    test_legacy_alpn_compat();
    test_unknown_alpn_fallback();
    test_channel_type_name();
    test_crypto_level_name();
    test_fec_type_name();
    test_is_data_channel();
    test_is_reliable_channel();
    test_default_config();
    test_for_channel_control();
    test_for_channel_llm();
    test_for_channel_img();
    test_for_channel_video();
    test_for_channel_audio();
    test_for_channel_fusion();
    test_config_to_json();
    test_config_from_json();
    test_config_from_json_invalid();
    test_config_roundtrip();
    test_config_modify_then_serialize();
    test_c_api_alpn();
    test_c_api_constants();
    test_crypto_level_ordering();
    test_fec_type_ordering();

    std::printf("=== Result: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
