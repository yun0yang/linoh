// test_ports.cpp — P5-C-4 端口规划测试
//
// 验证：
//   1. 基础端口常量正确
//   2. 多模态通道端口映射
//   3. PortMapper 默认无偏移
//   4. PortMapper 带偏移
//   5. 端口名称
//   6. is_linoh_port / is_public_port
//   7. defaults 命名空间常量
//   8. 配置文件 port_offset=100 场景
//   9. 边界：偏移 0、最大偏移
//  10. ChannelPortType 枚举值

#include "linoh/util/ports.hpp"

#include <cstdio>
#include <cstdint>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh::util;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 1. 基础端口常量
// ============================================================================

static void test_base_port_constants() {
    CHECK(PORT_BASE == 9000);
    CHECK(PORT_CHANNEL_BASE == 9100);
    CHECK(PORT_DNS_INTERNAL == 5333);
    CHECK(PORT_ORCHESTRATOR == 9999);
}

static void test_basic_ports() {
    CHECK(port_bootstrap() == 9001);
    CHECK(port_relay() == 9002);
    CHECK(port_relay_tls() == 9003);
    CHECK(port_vms() == 9000);
    CHECK(port_dns_internal() == 5333);
    CHECK(port_orchestrator() == 9999);
}

// ============================================================================
// 2. 多模态通道端口
// ============================================================================

static void test_channel_ports_by_enum() {
    CHECK(port_channel(ChannelPortType::CONTROL) == 9100);
    CHECK(port_channel(ChannelPortType::LLM_HIDDEN) == 9101);
    CHECK(port_channel(ChannelPortType::IMG_FEATURE) == 9102);
    CHECK(port_channel(ChannelPortType::VIDEO_FEATURE) == 9103);
    CHECK(port_channel(ChannelPortType::AUDIO_FEATURE) == 9104);
    CHECK(port_channel(ChannelPortType::FUSION) == 9105);
}

static void test_channel_ports_by_int() {
    CHECK(port_channel(static_cast<std::uint8_t>(0)) == 9100);
    CHECK(port_channel(static_cast<std::uint8_t>(1)) == 9101);
    CHECK(port_channel(static_cast<std::uint8_t>(2)) == 9102);
    CHECK(port_channel(static_cast<std::uint8_t>(3)) == 9103);
    CHECK(port_channel(static_cast<std::uint8_t>(4)) == 9104);
    CHECK(port_channel(static_cast<std::uint8_t>(5)) == 9105);
}

static void test_channel_port_type_enum_values() {
    // 验证枚举值与方案文档一致
    CHECK(static_cast<int>(ChannelPortType::CONTROL) == 0);
    CHECK(static_cast<int>(ChannelPortType::LLM_HIDDEN) == 1);
    CHECK(static_cast<int>(ChannelPortType::IMG_FEATURE) == 2);
    CHECK(static_cast<int>(ChannelPortType::VIDEO_FEATURE) == 3);
    CHECK(static_cast<int>(ChannelPortType::AUDIO_FEATURE) == 4);
    CHECK(static_cast<int>(ChannelPortType::FUSION) == 5);
}

// ============================================================================
// 3. PortMapper 默认无偏移
// ============================================================================

static void test_port_mapper_default() {
    PortMapper mapper;
    CHECK(mapper.offset() == 0);
    CHECK(mapper.has_offset() == false);

    CHECK(mapper.bootstrap() == 9001);
    CHECK(mapper.relay() == 9002);
    CHECK(mapper.relay_tls() == 9003);
    CHECK(mapper.vms() == 9000);

    CHECK(mapper.channel(ChannelPortType::CONTROL) == 9100);
    CHECK(mapper.channel(ChannelPortType::LLM_HIDDEN) == 9101);
    CHECK(mapper.channel(ChannelPortType::VIDEO_FEATURE) == 9103);

    // 固定端口不受 offset 影响
    CHECK(mapper.dns_internal() == 5333);
    CHECK(mapper.orchestrator() == 9999);
}

// ============================================================================
// 4. PortMapper 带偏移
// ============================================================================

static void test_port_mapper_with_offset() {
    PortMapper mapper(100);  // offset=100
    CHECK(mapper.offset() == 100);
    CHECK(mapper.has_offset() == true);

    CHECK(mapper.bootstrap() == 9101);
    CHECK(mapper.relay() == 9102);
    CHECK(mapper.relay_tls() == 9103);
    CHECK(mapper.vms() == 9100);

    CHECK(mapper.channel(ChannelPortType::CONTROL) == 9200);
    CHECK(mapper.channel(ChannelPortType::LLM_HIDDEN) == 9201);
    CHECK(mapper.channel(ChannelPortType::VIDEO_FEATURE) == 9203);

    // 固定端口仍不受影响
    CHECK(mapper.dns_internal() == 5333);
    CHECK(mapper.orchestrator() == 9999);
}

static void test_port_mapper_offset_zero_explicit() {
    PortMapper mapper(0);
    CHECK(mapper.offset() == 0);
    CHECK(mapper.has_offset() == false);
    CHECK(mapper.bootstrap() == 9001);
    CHECK(mapper.channel(ChannelPortType::FUSION) == 9105);
}

// ============================================================================
// 5. 端口名称
// ============================================================================

static void test_port_names() {
    CHECK(std::string(port_name_bootstrap()) == "linoh_bootstrap");
    CHECK(std::string(port_name_relay()) == "linoh_relay");
    CHECK(std::string(port_name_relay_tls()) == "linoh_relay_tls");
    CHECK(std::string(port_name_vms()) == "vms");
    CHECK(std::string(port_name_dns()) == "linoh_dns_internal");
    CHECK(std::string(port_name_orchestrator()) == "orchestrator");
}

static void test_channel_port_names() {
    CHECK(std::string(port_name_channel(ChannelPortType::CONTROL)) == "ctrl_channel");
    CHECK(std::string(port_name_channel(ChannelPortType::LLM_HIDDEN)) == "llm_channel");
    CHECK(std::string(port_name_channel(ChannelPortType::IMG_FEATURE)) == "img_channel");
    CHECK(std::string(port_name_channel(ChannelPortType::VIDEO_FEATURE)) == "video_channel");
    CHECK(std::string(port_name_channel(ChannelPortType::AUDIO_FEATURE)) == "audio_channel");
    CHECK(std::string(port_name_channel(ChannelPortType::FUSION)) == "fusion_channel");
}

// ============================================================================
// 6. is_linoh_port / is_public_port
// ============================================================================

static void test_is_linoh_port() {
    PortMapper mapper;
    CHECK(mapper.is_linoh_port(9000) == true);   // VMS
    CHECK(mapper.is_linoh_port(9001) == true);   // bootstrap
    CHECK(mapper.is_linoh_port(9002) == true);   // relay
    CHECK(mapper.is_linoh_port(9003) == true);   // relay_tls
    CHECK(mapper.is_linoh_port(9100) == true);   // ctrl channel
    CHECK(mapper.is_linoh_port(9101) == true);   // llm channel
    CHECK(mapper.is_linoh_port(9105) == true);   // fusion channel
    CHECK(mapper.is_linoh_port(5333) == true);   // dns
    CHECK(mapper.is_linoh_port(9999) == true);   // orchestrator

    CHECK(mapper.is_linoh_port(8000) == false);
    CHECK(mapper.is_linoh_port(8080) == false);
    CHECK(mapper.is_linoh_port(10000) == false);
    CHECK(mapper.is_linoh_port(9106) == false);  // 超出通道范围
    CHECK(mapper.is_linoh_port(9004) == false);  // 空缺
}

static void test_is_public_port() {
    PortMapper mapper;
    // 外网开放
    CHECK(mapper.is_public_port(9000) == true);   // VMS
    CHECK(mapper.is_public_port(9001) == true);   // bootstrap
    CHECK(mapper.is_public_port(9002) == true);   // relay
    CHECK(mapper.is_public_port(9003) == true);   // relay_tls
    CHECK(mapper.is_public_port(9999) == true);   // orchestrator

    // 内网专用
    CHECK(mapper.is_public_port(5333) == false);  // dns
    CHECK(mapper.is_public_port(9100) == false);  // ctrl channel
    CHECK(mapper.is_public_port(9101) == false);  // llm channel
    CHECK(mapper.is_public_port(9105) == false);  // fusion channel

    // 非 linoh 端口
    CHECK(mapper.is_public_port(8000) == false);
    CHECK(mapper.is_public_port(8080) == false);
}

static void test_is_public_port_with_offset() {
    PortMapper mapper(100);
    CHECK(mapper.is_public_port(9100) == true);   // vms with offset
    CHECK(mapper.is_public_port(9101) == true);   // bootstrap with offset
    CHECK(mapper.is_public_port(9102) == true);   // relay with offset
    CHECK(mapper.is_public_port(9103) == true);   // relay_tls with offset
    CHECK(mapper.is_public_port(9200) == false);  // ctrl channel with offset
    CHECK(mapper.is_public_port(9201) == false);  // llm channel with offset
    CHECK(mapper.is_public_port(9999) == true);   // orchestrator (fixed)
    CHECK(mapper.is_public_port(5333) == false);  // dns (fixed)
}

// ============================================================================
// 7. defaults 命名空间
// ============================================================================

static void test_defaults_namespace() {
    CHECK(defaults::bootstrap == 9001);
    CHECK(defaults::relay == 9002);
    CHECK(defaults::relay_tls == 9003);
    CHECK(defaults::vms == 9000);
    CHECK(defaults::dns == 5333);
    CHECK(defaults::orchestrator == 9999);
    CHECK(defaults::channel_ctrl == 9100);
    CHECK(defaults::channel_llm == 9101);
    CHECK(defaults::channel_img == 9102);
    CHECK(defaults::channel_video == 9103);
    CHECK(defaults::channel_audio == 9104);
    CHECK(defaults::channel_fusion == 9105);
}

// ============================================================================
// 8. 配置文件 port_offset=100 场景
// ============================================================================

static void test_config_offset_100_scenario() {
    // 模拟配置文件 port_offset=100
    std::uint16_t config_offset = 100;
    PortMapper mapper(config_offset);

    // 所有 linoh 服务端口 +100
    CHECK(mapper.bootstrap() == 9101);
    CHECK(mapper.relay() == 9102);
    CHECK(mapper.relay_tls() == 9103);
    CHECK(mapper.vms() == 9100);

    // 多模态通道 +100
    CHECK(mapper.channel(ChannelPortType::CONTROL) == 9200);
    CHECK(mapper.channel(ChannelPortType::LLM_HIDDEN) == 9201);
    CHECK(mapper.channel(ChannelPortType::VIDEO_FEATURE) == 9203);

    // 固定端口不变
    CHECK(mapper.dns_internal() == 5333);
    CHECK(mapper.orchestrator() == 9999);
}

// ============================================================================
// 9. 端口有效性检查
// ============================================================================

static void test_is_valid_port() {
    PortMapper mapper;
    CHECK(mapper.is_valid_port(1) == true);
    CHECK(mapper.is_valid_port(80) == true);
    CHECK(mapper.is_valid_port(9000) == true);
    CHECK(mapper.is_valid_port(65535) == true);
    CHECK(mapper.is_valid_port(0) == false);
}

// ============================================================================
// 10. 多实例部署场景（不同 offset）
// ============================================================================

static void test_multi_instance_deployment() {
    // 实例 1：默认偏移
    PortMapper instance1(0);
    // 实例 2：偏移 1000（避免端口冲突）
    PortMapper instance2(1000);
    // 实例 3：偏移 2000
    PortMapper instance3(2000);

    // 三个实例的端口不冲突
    CHECK(instance1.bootstrap() == 9001);
    CHECK(instance2.bootstrap() == 10001);
    CHECK(instance3.bootstrap() == 11001);

    CHECK(instance1.channel(ChannelPortType::LLM_HIDDEN) == 9101);
    CHECK(instance2.channel(ChannelPortType::LLM_HIDDEN) == 10101);
    CHECK(instance3.channel(ChannelPortType::LLM_HIDDEN) == 11101);

    // 固定端口仍共享（orchestrator/dns）
    CHECK(instance1.orchestrator() == 9999);
    CHECK(instance2.orchestrator() == 9999);
    CHECK(instance3.orchestrator() == 9999);
}

// ============================================================================
// 11. 端口范围完整覆盖
// ============================================================================

static void test_port_range_coverage() {
    PortMapper mapper;
    // 9000-9003 基础服务
    CHECK(mapper.is_linoh_port(9000));
    CHECK(mapper.is_linoh_port(9001));
    CHECK(mapper.is_linoh_port(9002));
    CHECK(mapper.is_linoh_port(9003));
    CHECK(!mapper.is_linoh_port(9004));  // 空缺
    CHECK(!mapper.is_linoh_port(9005));

    // 9100-9105 多模态通道
    for (int i = 0; i <= 5; ++i) {
        CHECK(mapper.is_linoh_port(9100 + i));
    }
    CHECK(!mapper.is_linoh_port(9106));

    // 5333 DNS
    CHECK(mapper.is_linoh_port(5333));

    // 9999 orchestrator
    CHECK(mapper.is_linoh_port(9999));
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::printf("=== test_ports.cpp — P5-C-4 端口规划 ===\n");

    test_base_port_constants();
    test_basic_ports();

    test_channel_ports_by_enum();
    test_channel_ports_by_int();
    test_channel_port_type_enum_values();

    test_port_mapper_default();
    test_port_mapper_with_offset();
    test_port_mapper_offset_zero_explicit();

    test_port_names();
    test_channel_port_names();

    test_is_linoh_port();
    test_is_public_port();
    test_is_public_port_with_offset();

    test_defaults_namespace();

    test_config_offset_100_scenario();

    test_is_valid_port();

    test_multi_instance_deployment();

    test_port_range_coverage();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
