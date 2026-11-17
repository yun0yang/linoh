// test_udp_probe.cpp — P0-G1 UDP 可用性三态探测测试
//
// 验证：
//   1. UdpAvailability 枚举和 to_string_view
//   2. UdpProbeResult 默认构造和 to_string
//   3. UdpProbeConfig 默认构造（ping/pong 载荷）
//   4. classify 纯逻辑：sent_count=0 → NotAvailable
//   5. classify: loss_rate=0 → Available
//   6. classify: loss_rate=1 → NotAvailable
//   7. classify: loss_rate=0.5 → Bad
//   8. classify: 边界值（available_threshold/bad_threshold）
//   9. probe_with_provider: 全部成功 → Available
//  10. probe_with_provider: 全部失败 → NotAvailable
//  11. probe_with_provider: 部分成功 → Bad
//  12. probe_with_provider: provider null → NotAvailable
//  13. probe_with_provider: RTT 统计正确（min/max/avg）
//  14. probe_with_provider: ping_count=0 → NotAvailable
//  15. probe_with_provider: 自定义阈值生效

#include "linoh/net/udp_probe.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh;
using namespace linoh::net;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 辅助函数：构造 mock UdpPingProvider
// ============================================================================

/// 全部成功的 provider（返回固定 RTT）
static UdpPingProvider make_always_success_provider(std::chrono::milliseconds rtt) {
    return [rtt](const std::string &, std::uint16_t, std::chrono::milliseconds) {
        return std::optional<std::chrono::milliseconds>{rtt};
    };
}

/// 全部失败的 provider（返回 nullopt）
static UdpPingProvider make_always_fail_provider() {
    return [](const std::string &, std::uint16_t, std::chrono::milliseconds) {
        return std::optional<std::chrono::milliseconds>{};
    };
}

/// 部分成功的 provider（前 success_count 次成功，后续失败）
static UdpPingProvider make_partial_provider(std::uint32_t success_count,
                                              std::chrono::milliseconds rtt) {
    auto idx = std::make_shared<std::atomic<std::uint32_t>>(0);
    return [success_count, rtt, idx](const std::string &, std::uint16_t, std::chrono::milliseconds) {
        std::uint32_t i = idx->fetch_add(1);
        if (i < success_count) {
            return std::optional<std::chrono::milliseconds>{rtt};
        }
        return std::optional<std::chrono::milliseconds>{};
    };
}

/// 返回递增 RTT 的 provider（用于验证 min/max/avg 统计）
static UdpPingProvider make_increasing_rtt_provider() {
    auto idx = std::make_shared<std::atomic<std::uint32_t>>(0);
    return [idx](const std::string &, std::uint16_t, std::chrono::milliseconds) {
        std::uint32_t i = idx->fetch_add(1);
        // RTT: 10ms, 20ms, 30ms, 40ms, 50ms
        return std::optional<std::chrono::milliseconds>{std::chrono::milliseconds{10 * (i + 1)}};
    };
}

// ============================================================================
// 1. UdpAvailability 枚举和 to_string_view
// ============================================================================

static void test_availability_to_string() {
    CHECK(std::string(to_string_view(UdpAvailability::Available)) == "available");
    CHECK(std::string(to_string_view(UdpAvailability::Bad)) == "bad");
    CHECK(std::string(to_string_view(UdpAvailability::NotAvailable)) == "not-available");
}

// ============================================================================
// 2. UdpProbeResult 默认构造和 to_string
// ============================================================================

static void test_result_default_construct() {
    UdpProbeResult r;
    CHECK(r.availability == UdpAvailability::NotAvailable);
    CHECK(r.sent_count == 0);
    CHECK(r.received_count == 0);
    CHECK(r.loss_rate == 1.0);
    CHECK(r.min_rtt.count() == 0);
    CHECK(r.max_rtt.count() == 0);
    CHECK(r.avg_rtt.count() == 0);
    CHECK(r.total_duration.count() == 0);
    CHECK(r.error_msg.empty());
}

static void test_result_to_string() {
    UdpProbeResult r;
    r.availability = UdpAvailability::Available;
    r.sent_count = 5;
    r.received_count = 5;
    r.loss_rate = 0.0;
    r.min_rtt = std::chrono::milliseconds(10);
    r.max_rtt = std::chrono::milliseconds(30);
    r.avg_rtt = std::chrono::milliseconds(20);

    std::string s = r.to_string();
    CHECK(s.find("availability=available") != std::string::npos);
    CHECK(s.find("sent=5") != std::string::npos);
    CHECK(s.find("received=5") != std::string::npos);
    CHECK(s.find("loss_rate=0.0%") != std::string::npos);
}

// ============================================================================
// 3. UdpProbeConfig 默认构造
// ============================================================================

static void test_config_default_construct() {
    UdpProbeConfig c;
    CHECK(c.ping_count == 5);
    CHECK(c.ping_interval.count() == 200);
    CHECK(c.recv_timeout.count() == 500);
    CHECK(c.available_threshold == 0.7);
    CHECK(c.bad_threshold == 0.3);
    CHECK(c.ping_payload.size() == 10);  // "LINOH-PING"
    CHECK(c.pong_payload.size() == 10);  // "LINOH-PONG"

    // 验证默认载荷内容
    std::string ping_str(c.ping_payload.begin(), c.ping_payload.end());
    CHECK(ping_str == "LINOH-PING");
    std::string pong_str(c.pong_payload.begin(), c.pong_payload.end());
    CHECK(pong_str == "LINOH-PONG");
}

// ============================================================================
// 4-8. classify 纯逻辑测试
// ============================================================================

static void test_classify_sent_zero() {
    // sent_count=0 → NotAvailable
    CHECK(UdpProber::classify(0.0, 0, 0.7, 0.3) == UdpAvailability::NotAvailable);
    CHECK(UdpProber::classify(1.0, 0, 0.7, 0.3) == UdpAvailability::NotAvailable);
}

static void test_classify_no_loss() {
    // loss_rate=0, reply_rate=1.0 >= 0.7 → Available
    CHECK(UdpProber::classify(0.0, 5, 0.7, 0.3) == UdpAvailability::Available);
}

static void test_classify_full_loss() {
    // loss_rate=1.0, reply_rate=0.0 <= 0.3 → NotAvailable
    CHECK(UdpProber::classify(1.0, 5, 0.7, 0.3) == UdpAvailability::NotAvailable);
}

static void test_classify_half_loss() {
    // loss_rate=0.5, reply_rate=0.5 ∈ (0.3, 0.7) → Bad
    CHECK(UdpProber::classify(0.5, 5, 0.7, 0.3) == UdpAvailability::Bad);
}

static void test_classify_boundary() {
    // 边界值：reply_rate == available_threshold → Available
    // loss_rate = 1 - 0.7 = 0.3（IEEE754: 1.0-0.3 ≈ 0.7000000000000001 >= 0.7 → Available）
    CHECK(UdpProber::classify(0.3, 10, 0.7, 0.3) == UdpAvailability::Available);

    // reply_rate 略低于 bad_threshold → NotAvailable
    // loss_rate = 1 - 0.29 = 0.71（避免浮点精度边界 1.0-0.7≈0.30000000000000004 > 0.3）
    CHECK(UdpProber::classify(0.71, 10, 0.7, 0.3) == UdpAvailability::NotAvailable);

    // reply_rate 略高于 bad_threshold → Bad
    // loss_rate = 1 - 0.32 = 0.68
    CHECK(UdpProber::classify(0.68, 10, 0.7, 0.3) == UdpAvailability::Bad);

    // reply_rate 略低于 available_threshold → Bad
    // loss_rate = 1 - 0.69 = 0.31
    CHECK(UdpProber::classify(0.31, 10, 0.7, 0.3) == UdpAvailability::Bad);
}

static void test_classify_custom_thresholds() {
    // 自定义阈值：available=0.9, bad=0.1
    // reply_rate=0.8 ∈ (0.1, 0.9) → Bad
    CHECK(UdpProber::classify(0.2, 10, 0.9, 0.1) == UdpAvailability::Bad);

    // reply_rate=0.95 >= 0.9 → Available
    CHECK(UdpProber::classify(0.05, 20, 0.9, 0.1) == UdpAvailability::Available);
}

// ============================================================================
// 9. probe_with_provider: 全部成功 → Available
// ============================================================================

static void test_probe_all_success() {
    UdpProbeConfig config;
    config.ping_count = 5;
    config.ping_interval = std::chrono::milliseconds(1);  // 加速测试

    auto result = UdpProber::probe_with_provider(
        "203.0.113.1", 5000, config,
        make_always_success_provider(std::chrono::milliseconds(50)));

    CHECK(result.availability == UdpAvailability::Available);
    CHECK(result.sent_count == 5);
    CHECK(result.received_count == 5);
    CHECK(result.loss_rate == 0.0);
    CHECK(result.min_rtt.count() == 50);
    CHECK(result.max_rtt.count() == 50);
    CHECK(result.avg_rtt.count() == 50);
}

// ============================================================================
// 10. probe_with_provider: 全部失败 → NotAvailable
// ============================================================================

static void test_probe_all_fail() {
    UdpProbeConfig config;
    config.ping_count = 5;
    config.ping_interval = std::chrono::milliseconds(1);

    auto result = UdpProber::probe_with_provider(
        "203.0.113.1", 5000, config,
        make_always_fail_provider());

    CHECK(result.availability == UdpAvailability::NotAvailable);
    CHECK(result.sent_count == 5);
    CHECK(result.received_count == 0);
    CHECK(result.loss_rate == 1.0);
    CHECK(result.min_rtt.count() == 0);
    CHECK(result.max_rtt.count() == 0);
    CHECK(result.avg_rtt.count() == 0);
}

// ============================================================================
// 11. probe_with_provider: 部分成功 → Bad
// ============================================================================

static void test_probe_partial() {
    UdpProbeConfig config;
    config.ping_count = 5;
    config.ping_interval = std::chrono::milliseconds(1);
    // 5 次 ping，2 次成功 → reply_rate=0.4 ∈ (0.3, 0.7) → Bad
    auto result = UdpProber::probe_with_provider(
        "203.0.113.1", 5000, config,
        make_partial_provider(2, std::chrono::milliseconds(50)));

    CHECK(result.availability == UdpAvailability::Bad);
    CHECK(result.sent_count == 5);
    CHECK(result.received_count == 2);
    // loss_rate = 1 - 2/5 = 0.6
    CHECK(std::abs(result.loss_rate - 0.6) < 0.01);
}

// ============================================================================
// 12. probe_with_provider: provider null → NotAvailable
// ============================================================================

static void test_probe_null_provider() {
    UdpProbeConfig config;
    config.ping_count = 3;
    config.ping_interval = std::chrono::milliseconds(1);

    auto result = UdpProber::probe_with_provider(
        "203.0.113.1", 5000, config, nullptr);

    CHECK(result.availability == UdpAvailability::NotAvailable);
    CHECK(!result.error_msg.empty());
    CHECK(result.error_msg.find("provider is null") != std::string::npos);
}

// ============================================================================
// 13. probe_with_provider: RTT 统计正确（min/max/avg）
// ============================================================================

static void test_probe_rtt_stats() {
    UdpProbeConfig config;
    config.ping_count = 5;
    config.ping_interval = std::chrono::milliseconds(1);
    // RTT: 10, 20, 30, 40, 50 ms
    auto result = UdpProber::probe_with_provider(
        "203.0.113.1", 5000, config,
        make_increasing_rtt_provider());

    CHECK(result.availability == UdpAvailability::Available);
    CHECK(result.received_count == 5);
    CHECK(result.min_rtt.count() == 10);
    CHECK(result.max_rtt.count() == 50);
    // avg = (10+20+30+40+50)/5 = 30
    CHECK(result.avg_rtt.count() == 30);
}

// ============================================================================
// 14. probe_with_provider: ping_count=0 → NotAvailable
// ============================================================================

static void test_probe_zero_ping_count() {
    UdpProbeConfig config;
    config.ping_count = 0;
    config.ping_interval = std::chrono::milliseconds(1);

    auto result = UdpProber::probe_with_provider(
        "203.0.113.1", 5000, config,
        make_always_success_provider(std::chrono::milliseconds(50)));

    // sent_count=0 → NotAvailable
    CHECK(result.availability == UdpAvailability::NotAvailable);
    CHECK(result.sent_count == 0);
    CHECK(result.received_count == 0);
    CHECK(result.loss_rate == 1.0);
}

// ============================================================================
// 15. probe_with_provider: 自定义阈值生效
// ============================================================================

static void test_probe_custom_thresholds() {
    UdpProbeConfig config;
    config.ping_count = 10;
    config.ping_interval = std::chrono::milliseconds(1);
    config.available_threshold = 0.9;  // 严格要求 90% 回复率
    config.bad_threshold = 0.1;
    // 10 次 ping，8 次成功 → reply_rate=0.8 < 0.9 → Bad（严格阈值下）
    auto result = UdpProber::probe_with_provider(
        "203.0.113.1", 5000, config,
        make_partial_provider(8, std::chrono::milliseconds(50)));

    CHECK(result.availability == UdpAvailability::Bad);
    CHECK(result.received_count == 8);
}

// ============================================================================
// 16. availability_name 兼容方法
// ============================================================================

static void test_availability_name_compat() {
    CHECK(std::string(UdpProber::availability_name(UdpAvailability::Available)) == "available");
    CHECK(std::string(UdpProber::availability_name(UdpAvailability::Bad)) == "bad");
    CHECK(std::string(UdpProber::availability_name(UdpAvailability::NotAvailable)) == "not-available");
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::printf("=== test_udp_probe ===\n");

    test_availability_to_string();
    test_result_default_construct();
    test_result_to_string();
    test_config_default_construct();

    test_classify_sent_zero();
    test_classify_no_loss();
    test_classify_full_loss();
    test_classify_half_loss();
    test_classify_boundary();
    test_classify_custom_thresholds();

    test_probe_all_success();
    test_probe_all_fail();
    test_probe_partial();
    test_probe_null_provider();
    test_probe_rtt_stats();
    test_probe_zero_ping_count();
    test_probe_custom_thresholds();

    test_availability_name_compat();

    std::printf("\n=== Results: %d passed, %d failed ===\n", pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
