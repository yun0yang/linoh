// test_net_report.cpp — NetReport 模块测试（P4-B-1）
//
// 覆盖：
//   - NatType / UdpFirewall 枚举
//   - NetReport 默认值与 to_string
//   - update_relay_recommendation 逻辑
//   - default_stun_servers 返回
//   - probe 在无网络环境下优雅降级（不崩溃，返回 Unknown）
//
// 注意：probe 的真实网络测试在 CI 中标记为 flaky，单元测试只验证接口契约。
//      真实网络探测的成功率验证在 P4-B 阶段集成测试中完成。

#include "linoh/net/net_report.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <future>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

using namespace linoh::net;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 测试 1: NetReport 默认值
// ============================================================================
static void test_default_values() {
    std::printf("[test] NetReport default values...\n");

    NetReport r;
    CHECK(r.nat_type == NatType::Unknown);
    CHECK(r.udp_firewall == UdpFirewall::Unknown);
    CHECK(r.ipv4_reachable == false);
    CHECK(r.ipv6_reachable == false);
    CHECK(r.relay_recommended == false);
    CHECK(r.avg_rtt.count() == 0);
    CHECK(r.public_ip.empty());
    CHECK(r.public_port == 0);
}

// ============================================================================
// 测试 2: to_string 包含所有关键字段
// ============================================================================
static void test_to_string_content() {
    std::printf("[test] NetReport::to_string content...\n");

    NetReport r;
    r.nat_type = NatType::Symmetric;
    r.udp_firewall = UdpFirewall::Open;
    r.ipv4_reachable = true;
    r.ipv6_reachable = false;
    r.relay_recommended = true;
    r.avg_rtt = std::chrono::microseconds(50000);
    r.public_ip = "1.2.3.4";
    r.public_port = 5678;

    std::string s = r.to_string();
    CHECK(s.find("nat=Symmetric") != std::string::npos);
    CHECK(s.find("udp_fw=Open") != std::string::npos);
    CHECK(s.find("v4=ok") != std::string::npos);
    CHECK(s.find("v6=no") != std::string::npos);
    CHECK(s.find("relay_rec=yes") != std::string::npos);
    CHECK(s.find("public=1.2.3.4:5678") != std::string::npos);
}

// ============================================================================
// 测试 3: update_relay_recommendation - Symmetric NAT 推荐 Relay
// ============================================================================
static void test_relay_recommendation_symmetric() {
    std::printf("[test] relay_recommendation: Symmetric NAT...\n");

    NetReport r;
    r.nat_type = NatType::Symmetric;
    r.udp_firewall = UdpFirewall::Open;
    r.ipv4_reachable = true;
    r.update_relay_recommendation();
    CHECK(r.relay_recommended == true);
}

// ============================================================================
// 测试 4: update_relay_recommendation - OpenInternet 不推荐 Relay
// ============================================================================
static void test_relay_recommendation_open_internet() {
    std::printf("[test] relay_recommendation: OpenInternet...\n");

    NetReport r;
    r.nat_type = NatType::OpenInternet;
    r.udp_firewall = UdpFirewall::Open;
    r.ipv4_reachable = true;
    r.ipv6_reachable = true;
    r.update_relay_recommendation();
    CHECK(r.relay_recommended == false);
}

// ============================================================================
// 测试 5: update_relay_recommendation - UDP 阻断推荐 Relay
// ============================================================================
static void test_relay_recommendation_udp_blocked() {
    std::printf("[test] relay_recommendation: UDP blocked...\n");

    NetReport r;
    r.nat_type = NatType::FullCone;
    r.udp_firewall = UdpFirewall::Blocked;
    r.ipv4_reachable = false;
    r.update_relay_recommendation();
    CHECK(r.relay_recommended == true);
}

// ============================================================================
// 测试 6: update_relay_recommendation - 无可达地址推荐 Relay
// ============================================================================
static void test_relay_recommendation_no_reachable() {
    std::printf("[test] relay_recommendation: no reachable addresses...\n");

    NetReport r;
    r.nat_type = NatType::Unknown;
    r.udp_firewall = UdpFirewall::Unknown;
    r.ipv4_reachable = false;
    r.ipv6_reachable = false;
    r.update_relay_recommendation();
    CHECK(r.relay_recommended == true);
}

// ============================================================================
// 测试 7: default_stun_servers 非空且包含 Google STUN
// ============================================================================
static void test_default_stun_servers() {
    std::printf("[test] default_stun_servers...\n");

    const auto &servers = NetReporter::default_stun_servers();
    CHECK(!servers.empty());
    CHECK(servers.size() >= 2);

    // 至少有一个是 Google STUN
    bool has_google = false;
    for (const auto &s : servers) {
        if (s.find("stun.l.google.com") != std::string::npos) {
            has_google = true;
            break;
        }
    }
    CHECK(has_google);

    // 所有服务器都应是 host:port 格式
    for (const auto &s : servers) {
        auto colon = s.rfind(':');
        CHECK(colon != std::string::npos);
        CHECK(colon > 0);
        CHECK(colon < s.size() - 1);
    }
}

// ============================================================================
// 测试 8: probe 在无网络环境下优雅降级
// ============================================================================
static void test_probe_graceful_degradation_no_network() {
    std::printf("[test] probe graceful degradation (no network)...\n");

    // 用一个不可达的 STUN 服务器，确保探测失败但不崩溃
    NetReporter::Config cfg;
    cfg.request_timeout = std::chrono::milliseconds(100);  // 短超时
    cfg.max_retries = 0;
    cfg.enable_ipv6 = false;

    auto report = NetReporter::probe(cfg, {"192.0.2.1:3478"});  // TEST-NET-1，不可路由

    // 失败时应返回 Unknown / Blocked，不崩溃
    CHECK(report.nat_type == NatType::Unknown);
    CHECK(report.udp_firewall == UdpFirewall::Blocked);
    CHECK(report.ipv4_reachable == false);
    CHECK(report.ipv6_reachable == false);
    CHECK(report.relay_recommended == true);  // 失败时推荐 Relay
    CHECK(report.public_ip.empty());
}

// ============================================================================
// 测试 9: probe_async 异步返回
// ============================================================================
static void test_probe_async_returns_future() {
    std::printf("[test] probe_async returns future...\n");

    NetReporter::Config cfg;
    cfg.request_timeout = std::chrono::milliseconds(50);
    cfg.max_retries = 0;
    cfg.enable_ipv6 = false;

    // probe_async 是 probe 的异步包装
    auto future = NetReporter::probe_async({"192.0.2.1:3478"});
    CHECK(future.valid());

    // 等待结果（应快速返回，因为超时很短）
    auto status = future.wait_for(std::chrono::seconds(30));
    CHECK(status == std::future_status::ready);

    auto report = future.get();
    CHECK(report.nat_type == NatType::Unknown);
}

// ============================================================================
// 测试 10: NatType 枚举完整性
// ============================================================================
static void test_nat_type_enum() {
    std::printf("[test] NatType enum...\n");

    // 确保所有枚举值都可用
    NatType types[] = {
        NatType::OpenInternet,
        NatType::FullCone,
        NatType::RestrictedCone,
        NatType::PortRestrictedCone,
        NatType::Symmetric,
        NatType::Unknown,
    };

    // 验证枚举值互不相同
    for (size_t i = 0; i < std::size(types); ++i) {
        for (size_t j = i + 1; j < std::size(types); ++j) {
            CHECK(types[i] != types[j]);
        }
    }

    // 验证 to_string 包含正确的枚举名
    NetReport r;
    r.nat_type = NatType::OpenInternet;       CHECK(r.to_string().find("OpenInternet") != std::string::npos);
    r.nat_type = NatType::FullCone;           CHECK(r.to_string().find("FullCone") != std::string::npos);
    r.nat_type = NatType::RestrictedCone;     CHECK(r.to_string().find("RestrictedCone") != std::string::npos);
    r.nat_type = NatType::PortRestrictedCone; CHECK(r.to_string().find("PortRestrictedCone") != std::string::npos);
    r.nat_type = NatType::Symmetric;          CHECK(r.to_string().find("Symmetric") != std::string::npos);
    r.nat_type = NatType::Unknown;            CHECK(r.to_string().find("Unknown") != std::string::npos);
}

// ============================================================================
// 测试 11: UdpFirewall 枚举完整性
// ============================================================================
static void test_udp_firewall_enum() {
    std::printf("[test] UdpFirewall enum...\n");

    UdpFirewall fws[] = {UdpFirewall::Open, UdpFirewall::Blocked, UdpFirewall::Unknown};
    for (size_t i = 0; i < std::size(fws); ++i) {
        for (size_t j = i + 1; j < std::size(fws); ++j) {
            CHECK(fws[i] != fws[j]);
        }
    }

    NetReport r;
    r.udp_firewall = UdpFirewall::Open;    CHECK(r.to_string().find("udp_fw=Open") != std::string::npos);
    r.udp_firewall = UdpFirewall::Blocked; CHECK(r.to_string().find("udp_fw=Blocked") != std::string::npos);
    r.udp_firewall = UdpFirewall::Unknown; CHECK(r.to_string().find("udp_fw=Unknown") != std::string::npos);
}

// ============================================================================
// 测试 12: probe 自定义配置生效
// ============================================================================
static void test_probe_custom_config() {
    std::printf("[test] probe with custom config...\n");

    NetReporter::Config cfg;
    cfg.request_timeout = std::chrono::milliseconds(10);
    cfg.max_retries = 1;
    cfg.enable_ipv6 = false;

    // 短超时确保快速失败
    auto start = std::chrono::steady_clock::now();
    auto report = NetReporter::probe(cfg, {"192.0.2.1:3478"});
    auto elapsed = std::chrono::steady_clock::now() - start;

    // 即使失败，也应该在合理时间内返回（最多 ~50ms：1 次重试 * 10ms 超时）
    auto max_expected = std::chrono::seconds(5);  // 留余量
    CHECK(elapsed < max_expected);
    CHECK(report.nat_type == NatType::Unknown);
}

int main() {
    std::printf("=== test_net_report ===\n");

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::printf("WSAStartup failed\n");
        return 1;
    }
#endif

    test_default_values();
    test_to_string_content();
    test_relay_recommendation_symmetric();
    test_relay_recommendation_open_internet();
    test_relay_recommendation_udp_blocked();
    test_relay_recommendation_no_reachable();
    test_default_stun_servers();
    test_probe_graceful_degradation_no_network();
    test_probe_async_returns_future();
    test_nat_type_enum();
    test_udp_firewall_enum();
    test_probe_custom_config();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
