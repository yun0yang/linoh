// test_tcp_fallback.cpp — P0-G2 TCP 兜底降级编排测试
//
// 验证：
//   1. FallbackDecision 枚举和 to_string_view
//   2. FallbackResult 默认构造和 to_string
//   3. FallbackConfig 默认构造
//   4. decide 纯逻辑：Available → UseUdp
//   5. decide: Bad + enable_fec=true → UseUdpWithFec
//   6. decide: Bad + enable_fec=false → UseTcp
//   7. decide: NotAvailable → UseTcp
//   8. orchestrate: UDP Available → UseUdp（不尝试 TCP）
//   9. orchestrate: UDP NotAvailable + TCP 成功 → UseTcp
//  10. orchestrate: UDP NotAvailable + TCP 失败 → UseRelay
//  11. orchestrate: skip_udp_probe + TCP 成功 → UseTcp
//  12. orchestrate: skip_udp_probe + TCP 失败 → UseRelay
//  13. orchestrate: UDP Bad + enable_fec=true → UseUdpWithFec（不尝试 TCP）
//  14. orchestrate: UDP Bad + enable_fec=false + TCP 成功 → UseTcp
//  15. orchestrate: UDP Bad + enable_fec=false + TCP 失败 → UseRelay
//  16. orchestrate: 无 TCP provider + UDP NotAvailable → UseRelay
//  17. orchestrate: 无 UDP provider → UseRelay
//  18. decision_name 兼容方法

#include "linoh/relay/tcp_fallback.hpp"
#include "linoh/net/udp_probe.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh;
using namespace linoh::net;
using namespace linoh::relay;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 辅助函数：构造 mock provider
// ============================================================================

static UdpPingProvider make_udp_success_provider() {
    return [](const std::string &, std::uint16_t, std::chrono::milliseconds) {
        return std::optional<std::chrono::milliseconds>{std::chrono::milliseconds(50)};
    };
}

static UdpPingProvider make_udp_fail_provider() {
    return [](const std::string &, std::uint16_t, std::chrono::milliseconds) {
        return std::optional<std::chrono::milliseconds>{};
    };
}

/// 部分成功的 UDP provider（success_count 次成功）
static UdpPingProvider make_udp_partial_provider(std::uint32_t success_count,
                                                  std::uint32_t total) {
    auto idx = std::make_shared<std::atomic<std::uint32_t>>(0);
    return [success_count, total, idx](const std::string &, std::uint16_t, std::chrono::milliseconds) {
        std::uint32_t i = idx->fetch_add(1);
        if (i < success_count) {
            return std::optional<std::chrono::milliseconds>{std::chrono::milliseconds(50)};
        }
        return std::optional<std::chrono::milliseconds>{};
    };
}

static TcpConnectProvider make_tcp_success_provider() {
    return [](const std::string &, std::uint16_t, std::chrono::milliseconds) {
        return true;
    };
}

static TcpConnectProvider make_tcp_fail_provider() {
    return [](const std::string &, std::uint16_t, std::chrono::milliseconds) {
        return false;
    };
}

// ============================================================================
// 1. FallbackDecision 枚举和 to_string_view
// ============================================================================

static void test_decision_to_string() {
    CHECK(std::string(to_string_view(FallbackDecision::UseUdp)) == "use-udp");
    CHECK(std::string(to_string_view(FallbackDecision::UseUdpWithFec)) == "use-udp-with-fec");
    CHECK(std::string(to_string_view(FallbackDecision::UseTcp)) == "use-tcp");
    CHECK(std::string(to_string_view(FallbackDecision::UseRelay)) == "use-relay");
}

// ============================================================================
// 2. FallbackResult 默认构造和 to_string
// ============================================================================

static void test_result_default_construct() {
    FallbackResult r;
    CHECK(r.decision == FallbackDecision::UseUdp);
    CHECK(r.udp_probe.availability == UdpAvailability::NotAvailable);
    CHECK(r.tcp_attempted == false);
    CHECK(r.tcp_succeeded == false);
    CHECK(r.relay_attempted == false);
    CHECK(r.total_duration.count() == 0);
    CHECK(r.error_msg.empty());
}

static void test_result_to_string() {
    FallbackResult r;
    r.decision = FallbackDecision::UseTcp;
    r.udp_probe.availability = UdpAvailability::NotAvailable;
    r.udp_probe.loss_rate = 1.0;
    r.tcp_attempted = true;
    r.tcp_succeeded = true;

    std::string s = r.to_string();
    CHECK(s.find("decision=use-tcp") != std::string::npos);
    CHECK(s.find("udp=not-available") != std::string::npos);
    CHECK(s.find("tcp_attempted=success") != std::string::npos);
}

// ============================================================================
// 3. FallbackConfig 默认构造
// ============================================================================

static void test_config_default_construct() {
    FallbackConfig c;
    CHECK(c.udp_probe_config.ping_count == 5);
    CHECK(c.enable_fec_on_bad == true);
    CHECK(c.tcp_connect_timeout.count() == 3000);
    CHECK(c.relay_urls.empty());
    CHECK(c.skip_udp_probe == false);
}

// ============================================================================
// 4-7. decide 纯逻辑测试
// ============================================================================

static void test_decide_available() {
    CHECK(TcpFallback::decide(UdpAvailability::Available, true) == FallbackDecision::UseUdp);
    CHECK(TcpFallback::decide(UdpAvailability::Available, false) == FallbackDecision::UseUdp);
}

static void test_decide_bad_with_fec() {
    CHECK(TcpFallback::decide(UdpAvailability::Bad, true) == FallbackDecision::UseUdpWithFec);
}

static void test_decide_bad_without_fec() {
    CHECK(TcpFallback::decide(UdpAvailability::Bad, false) == FallbackDecision::UseTcp);
}

static void test_decide_not_available() {
    CHECK(TcpFallback::decide(UdpAvailability::NotAvailable, true) == FallbackDecision::UseTcp);
    CHECK(TcpFallback::decide(UdpAvailability::NotAvailable, false) == FallbackDecision::UseTcp);
}

// ============================================================================
// 8. orchestrate: UDP Available → UseUdp（不尝试 TCP）
// ============================================================================

static void test_orchestrate_udp_available() {
    FallbackConfig config;
    config.udp_probe_config.ping_count = 5;
    config.udp_probe_config.ping_interval = std::chrono::milliseconds(1);

    auto result = TcpFallback::orchestrate_with_providers(
        "203.0.113.1", 5000, config,
        make_udp_success_provider(),
        make_tcp_success_provider());

    CHECK(result.decision == FallbackDecision::UseUdp);
    CHECK(result.udp_probe.availability == UdpAvailability::Available);
    CHECK(result.tcp_attempted == false);
    CHECK(result.relay_attempted == false);
}

// ============================================================================
// 9. orchestrate: UDP NotAvailable + TCP 成功 → UseTcp
// ============================================================================

static void test_orchestrate_udp_fail_tcp_success() {
    FallbackConfig config;
    config.udp_probe_config.ping_count = 5;
    config.udp_probe_config.ping_interval = std::chrono::milliseconds(1);

    auto result = TcpFallback::orchestrate_with_providers(
        "203.0.113.1", 5000, config,
        make_udp_fail_provider(),
        make_tcp_success_provider());

    CHECK(result.decision == FallbackDecision::UseTcp);
    CHECK(result.udp_probe.availability == UdpAvailability::NotAvailable);
    CHECK(result.tcp_attempted == true);
    CHECK(result.tcp_succeeded == true);
    CHECK(result.relay_attempted == false);
}

// ============================================================================
// 10. orchestrate: UDP NotAvailable + TCP 失败 → UseRelay
// ============================================================================

static void test_orchestrate_udp_fail_tcp_fail() {
    FallbackConfig config;
    config.udp_probe_config.ping_count = 5;
    config.udp_probe_config.ping_interval = std::chrono::milliseconds(1);

    auto result = TcpFallback::orchestrate_with_providers(
        "203.0.113.1", 5000, config,
        make_udp_fail_provider(),
        make_tcp_fail_provider());

    CHECK(result.decision == FallbackDecision::UseRelay);
    CHECK(result.udp_probe.availability == UdpAvailability::NotAvailable);
    CHECK(result.tcp_attempted == true);
    CHECK(result.tcp_succeeded == false);
    CHECK(result.relay_attempted == true);
}

// ============================================================================
// 11. orchestrate: skip_udp_probe + TCP 成功 → UseTcp
// ============================================================================

static void test_orchestrate_skip_udp_tcp_success() {
    FallbackConfig config;
    config.skip_udp_probe = true;

    auto result = TcpFallback::orchestrate_with_providers(
        "203.0.113.1", 5000, config,
        make_udp_success_provider(),  // 不应被调用
        make_tcp_success_provider());

    CHECK(result.decision == FallbackDecision::UseTcp);
    CHECK(result.tcp_attempted == true);
    CHECK(result.tcp_succeeded == true);
    CHECK(result.relay_attempted == false);
    // skip_udp_probe 时 udp_probe 保持默认值（NotAvailable）
    CHECK(result.udp_probe.availability == UdpAvailability::NotAvailable);
}

// ============================================================================
// 12. orchestrate: skip_udp_probe + TCP 失败 → UseRelay
// ============================================================================

static void test_orchestrate_skip_udp_tcp_fail() {
    FallbackConfig config;
    config.skip_udp_probe = true;

    auto result = TcpFallback::orchestrate_with_providers(
        "203.0.113.1", 5000, config,
        make_udp_success_provider(),
        make_tcp_fail_provider());

    CHECK(result.decision == FallbackDecision::UseRelay);
    CHECK(result.tcp_attempted == true);
    CHECK(result.tcp_succeeded == false);
    CHECK(result.relay_attempted == true);
}

// ============================================================================
// 13. orchestrate: UDP Bad + enable_fec=true → UseUdpWithFec（不尝试 TCP）
// ============================================================================

static void test_orchestrate_bad_with_fec() {
    FallbackConfig config;
    config.udp_probe_config.ping_count = 5;
    config.udp_probe_config.ping_interval = std::chrono::milliseconds(1);
    config.enable_fec_on_bad = true;

    // 5 次 ping，2 次成功 → reply_rate=0.4 ∈ (0.3, 0.7) → Bad
    auto result = TcpFallback::orchestrate_with_providers(
        "203.0.113.1", 5000, config,
        make_udp_partial_provider(2, 5),
        make_tcp_success_provider());

    CHECK(result.decision == FallbackDecision::UseUdpWithFec);
    CHECK(result.udp_probe.availability == UdpAvailability::Bad);
    CHECK(result.tcp_attempted == false);
    CHECK(result.relay_attempted == false);
}

// ============================================================================
// 14. orchestrate: UDP Bad + enable_fec=false + TCP 成功 → UseTcp
// ============================================================================

static void test_orchestrate_bad_without_fec_tcp_success() {
    FallbackConfig config;
    config.udp_probe_config.ping_count = 5;
    config.udp_probe_config.ping_interval = std::chrono::milliseconds(1);
    config.enable_fec_on_bad = false;

    auto result = TcpFallback::orchestrate_with_providers(
        "203.0.113.1", 5000, config,
        make_udp_partial_provider(2, 5),
        make_tcp_success_provider());

    CHECK(result.decision == FallbackDecision::UseTcp);
    CHECK(result.udp_probe.availability == UdpAvailability::Bad);
    CHECK(result.tcp_attempted == true);
    CHECK(result.tcp_succeeded == true);
}

// ============================================================================
// 15. orchestrate: UDP Bad + enable_fec=false + TCP 失败 → UseRelay
// ============================================================================

static void test_orchestrate_bad_without_fec_tcp_fail() {
    FallbackConfig config;
    config.udp_probe_config.ping_count = 5;
    config.udp_probe_config.ping_interval = std::chrono::milliseconds(1);
    config.enable_fec_on_bad = false;

    auto result = TcpFallback::orchestrate_with_providers(
        "203.0.113.1", 5000, config,
        make_udp_partial_provider(2, 5),
        make_tcp_fail_provider());

    CHECK(result.decision == FallbackDecision::UseRelay);
    CHECK(result.udp_probe.availability == UdpAvailability::Bad);
    CHECK(result.tcp_attempted == true);
    CHECK(result.tcp_succeeded == false);
    CHECK(result.relay_attempted == true);
}

// ============================================================================
// 16. orchestrate: 无 TCP provider + UDP NotAvailable → UseRelay
// ============================================================================

static void test_orchestrate_no_tcp_provider() {
    FallbackConfig config;
    config.udp_probe_config.ping_count = 5;
    config.udp_probe_config.ping_interval = std::chrono::milliseconds(1);

    auto result = TcpFallback::orchestrate_with_providers(
        "203.0.113.1", 5000, config,
        make_udp_fail_provider(),
        nullptr);  // 无 TCP provider

    CHECK(result.decision == FallbackDecision::UseRelay);
    CHECK(result.tcp_attempted == true);
    CHECK(result.tcp_succeeded == false);
    CHECK(result.relay_attempted == true);
}

// ============================================================================
// 17. orchestrate: 无 UDP provider → UseRelay
// ============================================================================

static void test_orchestrate_no_udp_provider() {
    FallbackConfig config;
    config.udp_probe_config.ping_count = 5;
    config.udp_probe_config.ping_interval = std::chrono::milliseconds(1);

    auto result = TcpFallback::orchestrate_with_providers(
        "203.0.113.1", 5000, config,
        nullptr,  // 无 UDP provider
        make_tcp_success_provider());

    CHECK(result.decision == FallbackDecision::UseRelay);
    CHECK(!result.error_msg.empty());
    CHECK(result.error_msg.find("udp_provider is null") != std::string::npos);
    CHECK(result.relay_attempted == true);
}

// ============================================================================
// 18. decision_name 兼容方法
// ============================================================================

static void test_decision_name_compat() {
    CHECK(std::string(TcpFallback::decision_name(FallbackDecision::UseUdp)) == "use-udp");
    CHECK(std::string(TcpFallback::decision_name(FallbackDecision::UseUdpWithFec)) == "use-udp-with-fec");
    CHECK(std::string(TcpFallback::decision_name(FallbackDecision::UseTcp)) == "use-tcp");
    CHECK(std::string(TcpFallback::decision_name(FallbackDecision::UseRelay)) == "use-relay");
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::printf("=== test_tcp_fallback ===\n");

    test_decision_to_string();
    test_result_default_construct();
    test_result_to_string();
    test_config_default_construct();

    test_decide_available();
    test_decide_bad_with_fec();
    test_decide_bad_without_fec();
    test_decide_not_available();

    test_orchestrate_udp_available();
    test_orchestrate_udp_fail_tcp_success();
    test_orchestrate_udp_fail_tcp_fail();
    test_orchestrate_skip_udp_tcp_success();
    test_orchestrate_skip_udp_tcp_fail();
    test_orchestrate_bad_with_fec();
    test_orchestrate_bad_without_fec_tcp_success();
    test_orchestrate_bad_without_fec_tcp_fail();
    test_orchestrate_no_tcp_provider();
    test_orchestrate_no_udp_provider();

    test_decision_name_compat();

    std::printf("\n=== Results: %d passed, %d failed ===\n", pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
