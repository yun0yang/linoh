// test_cgn_detector.cpp — P5-D-3 CGN 穿透策略测试
//
// 验证：
//   1. CgnDetectionResult 结构和 to_string
//   2. CgnStrategy 枚举和字符串转换
//   3. 工具函数：compute_port_mean / stddev / range
//   4. is_ip_consistent
//   5. compute_port_dispersion
//   6. compute_port_confidence
//   7. CgnDetector 非 CGN 网络（端口稳定）
//   8. CgnDetector CGN 网络（端口离散）
//   9. CgnDetector IP 不一致场景
//  10. CgnDetector 超时处理
//  11. CgnDetector 错误处理
//  12. CgnStrategySelector 策略选择
//  13. to_holepunch_strategy 映射
//  14. should_use_relay 判断
//  15. 配置参数生效

#include "linoh/nat/cgn_detector.hpp"

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
using namespace linoh::nat;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 辅助函数：构造 mock STUN 探测 provider
// ============================================================================

static StunProbeProvider make_fixed_provider(const std::string &ip, std::uint16_t port) {
    return [ip, port](const std::string &, std::chrono::milliseconds) {
        return std::async(std::launch::async, [ip, port]() {
            return std::optional<std::pair<std::string, std::uint16_t>>{{ip, port}};
        });
    };
}

static StunProbeProvider make_ports_provider(const std::string &ip,
                                              std::vector<std::uint16_t> ports) {
    auto port_idx = std::make_shared<std::atomic<std::size_t>>(0);
    return [ip, ports, port_idx](const std::string &, std::chrono::milliseconds) {
        return std::async(std::launch::async, [ip, ports, port_idx]() {
            std::size_t idx = port_idx->fetch_add(1);
            std::uint16_t port = (idx < ports.size()) ? ports[idx] : ports.back();
            return std::optional<std::pair<std::string, std::uint16_t>>{{ip, port}};
        });
    };
}

static StunProbeProvider make_multi_ip_provider(
    std::vector<std::pair<std::string, std::uint16_t>> responses) {
    auto idx = std::make_shared<std::atomic<std::size_t>>(0);
    return [responses, idx](const std::string &, std::chrono::milliseconds) {
        return std::async(std::launch::async, [responses, idx]() {
            std::size_t i = idx->fetch_add(1);
            if (i >= responses.size()) i = responses.size() - 1;
            return std::optional<std::pair<std::string, std::uint16_t>>{responses[i]};
        });
    };
}

static StunProbeProvider make_failing_provider() {
    return [](const std::string &, std::chrono::milliseconds) {
        return std::async(std::launch::async, []() {
            return std::optional<std::pair<std::string, std::uint16_t>>{};
        });
    };
}

static StunProbeProvider make_throwing_provider() {
    return [](const std::string &, std::chrono::milliseconds) {
        return std::async(std::launch::async, []() -> std::optional<std::pair<std::string, std::uint16_t>> {
            throw std::runtime_error("stun failed");
        });
    };
}

static StunProbeProvider make_slow_provider(std::chrono::milliseconds delay) {
    return [delay](const std::string &, std::chrono::milliseconds) {
        return std::async(std::launch::async, [delay]() {
            std::this_thread::sleep_for(delay);
            return std::optional<std::pair<std::string, std::uint16_t>>{
                {"203.0.113.1", 5000}};
        });
    };
}

// ============================================================================
// 1. CgnDetectionResult 结构和 to_string
// ============================================================================

static void test_result_default_construct() {
    CgnDetectionResult r;
    CHECK(r.is_cgn == false);
    CHECK(r.carrier_name.empty());
    CHECK(r.observed_port_range_min == 0);
    CHECK(r.observed_port_range_max == 0);
    CHECK(r.port_prediction_confidence == 0.0);
    CHECK(r.observed_ports.empty());
    CHECK(r.observed_ips.empty());
    CHECK(r.detection_duration.count() == 0);
}

static void test_result_to_string() {
    CgnDetectionResult r;
    r.is_cgn = true;
    r.port_prediction_confidence = 0.25;
    r.observed_port_range_min = 10000;
    r.observed_port_range_max = 50000;
    r.observed_ports = {10000, 20000, 30000};
    r.observed_ips = {"203.0.113.1"};

    std::string s = r.to_string();
    CHECK(s.find("is_cgn=true") != std::string::npos);
    CHECK(s.find("confidence=0.25") != std::string::npos);
    CHECK(s.find("port_range=[10000,50000]") != std::string::npos);
}

// ============================================================================
// 2. CgnStrategy 枚举和字符串转换
// ============================================================================

static void test_strategy_name() {
    CHECK(std::string(cgn_strategy_name(CgnStrategy::DirectConnect)) == "direct");
    CHECK(std::string(cgn_strategy_name(CgnStrategy::StandardRfc5389)) == "standard");
    CHECK(std::string(cgn_strategy_name(CgnStrategy::SymmetricNat)) == "symmetric");
    CHECK(std::string(cgn_strategy_name(CgnStrategy::RelayFallback)) == "relay-fallback");
    CHECK(std::string(cgn_strategy_name(CgnStrategy::ParallelTry)) == "parallel-try");
}

// ============================================================================
// 3. 工具函数
// ============================================================================

static void test_compute_port_mean() {
    CHECK(compute_port_mean({1000, 2000, 3000}) == 2000.0);
    CHECK(compute_port_mean({5000}) == 5000.0);
    CHECK(compute_port_mean({}) == 0.0);
    CHECK(compute_port_mean({100, 200, 300, 400}) == 250.0);
}

static void test_compute_port_stddev() {
    // 完全相同的端口 → stddev=0
    CHECK(compute_port_stddev({1000, 1000, 1000}) == 0.0);
    // 单元素 → stddev=0
    CHECK(compute_port_stddev({1000}) == 0.0);
    // 空 → stddev=0
    CHECK(compute_port_stddev({}) == 0.0);
    // 1000 和 2000 → mean=1500, stddev=500
    double s = compute_port_stddev({1000, 2000});
    CHECK(std::abs(s - 500.0) < 1.0);
}

static void test_compute_port_range() {
    CHECK(compute_port_range({1000, 2000, 3000}) == 2000);
    CHECK(compute_port_range({5000}) == 0);
    CHECK(compute_port_range({}) == 0);
    CHECK(compute_port_range({30000, 10000, 20000}) == 20000);
}

static void test_is_ip_consistent() {
    CHECK(is_ip_consistent({"1.1.1.1", "1.1.1.1", "1.1.1.1"}) == true);
    CHECK(is_ip_consistent({"1.1.1.1", "2.2.2.2"}) == false);
    CHECK(is_ip_consistent({}) == true);
    CHECK(is_ip_consistent({"1.1.1.1"}) == true);
}

// ============================================================================
// 4. compute_port_dispersion
// ============================================================================

static void test_port_dispersion_zero() {
    // 完全相同的端口 → dispersion=0
    std::vector<std::uint16_t> same_ports = {1000, 1000, 1000, 1000};
    double d = CgnDetector::compute_port_dispersion(same_ports);
    CHECK(d == 0.0);
}

static void test_port_dispersion_high() {
    // 端口离散度高
    std::vector<std::uint16_t> scattered_ports = {1000, 5000, 10000, 30000, 60000};
    double d = CgnDetector::compute_port_dispersion(scattered_ports);
    CHECK(d > 0.5);  // 高离散度
}

static void test_port_dispersion_low() {
    // 端口离散度低（差值小）
    std::vector<std::uint16_t> close_ports = {1000, 1001, 1002, 1003};
    double d = CgnDetector::compute_port_dispersion(close_ports);
    CHECK(d < 0.1);  // 低离散度
}

// ============================================================================
// 5. compute_port_confidence
// ============================================================================

static void test_port_confidence_high() {
    // 端口完全相同 → 置信度=1.0
    std::vector<std::uint16_t> same_ports = {1000, 1000, 1000, 1000};
    double c = CgnDetector::compute_port_confidence(same_ports);
    CHECK(c == 1.0);
}

static void test_port_confidence_low() {
    // 端口差值大且无规律 → 置信度低
    std::vector<std::uint16_t> random_ports = {1000, 5000, 100, 30000, 12345};
    double c = CgnDetector::compute_port_confidence(random_ports);
    CHECK(c < 0.5);
}

static void test_port_confidence_stable_diff() {
    // 端口差值稳定 → 置信度较高
    std::vector<std::uint16_t> stable_ports = {1000, 1100, 1200, 1300};
    double c = CgnDetector::compute_port_confidence(stable_ports);
    CHECK(c > 0.5);  // 差值稳定，置信度较高
}

// ============================================================================
// 6. CgnDetector 非 CGN 网络（端口稳定）
// ============================================================================

static void test_detect_non_cgn_stable_ports() {
    CgnDetectorConfig config;
    config.stun_servers = {"stun1:3478", "stun2:3478", "stun3:3478"};
    config.total_timeout = std::chrono::milliseconds(500);

    // 所有 STUN 返回相同 IP + 相同端口（Cone NAT）
    CgnDetector detector(config, make_fixed_provider("203.0.113.1", 5000));
    auto result = detector.detect_sync();

    CHECK(result.is_cgn == false);
    CHECK(result.observed_ports.size() == 3);
    CHECK(result.port_prediction_confidence == 1.0);  // 端口完全一致
    CHECK(result.observed_port_range_min == 5000);
    CHECK(result.observed_port_range_max == 5000);
}

static void test_detect_non_cgn_close_ports() {
    CgnDetectorConfig config;
    config.stun_servers = {"stun1:3478", "stun2:3478", "stun3:3478"};
    config.total_timeout = std::chrono::milliseconds(500);

    // 端口接近（1000, 1001, 1002），IP 一致
    CgnDetector detector(config, make_ports_provider("203.0.113.1", {1000, 1001, 1002}));
    auto result = detector.detect_sync();

    CHECK(result.is_cgn == false);
    CHECK(result.observed_ports.size() == 3);
    CHECK(result.port_prediction_confidence > 0.5);  // 置信度高
}

// ============================================================================
// 7. CgnDetector CGN 网络（端口离散）
// ============================================================================

static void test_detect_cgn_scattered_ports() {
    CgnDetectorConfig config;
    config.stun_servers = {"stun1:3478", "stun2:3478", "stun3:3478", "stun4:3478", "stun5:3478"};
    config.total_timeout = std::chrono::milliseconds(500);

    // 端口离散度高（1000, 5000, 10000, 30000, 60000），IP 一致 → CGN
    CgnDetector detector(config, make_ports_provider("203.0.113.1", {1000, 5000, 10000, 30000, 60000}));
    auto result = detector.detect_sync();

    CHECK(result.is_cgn == true);
    CHECK(result.observed_ports.size() == 5);
    CHECK(result.port_prediction_confidence < 0.5);  // 低置信度
    CHECK(result.observed_port_range_max - result.observed_port_range_min > 5000);
}

// ============================================================================
// 8. CgnDetector IP 不一致场景
// ============================================================================

static void test_detect_multi_ip_not_cgn() {
    CgnDetectorConfig config;
    config.stun_servers = {"stun1:3478", "stun2:3478", "stun3:3478"};
    config.total_timeout = std::chrono::milliseconds(500);

    // 不同 STUN 返回不同 IP → 多 NAT 层，非 CGN
    CgnDetector detector(config, make_multi_ip_provider({
        {"203.0.113.1", 5000},
        {"198.51.100.1", 5000},
        {"192.0.2.1", 5000},
    }));
    auto result = detector.detect_sync();

    CHECK(result.is_cgn == false);  // IP 不一致不算 CGN
    CHECK(result.observed_ips.size() == 3);
}

// ============================================================================
// 9. CgnDetector 超时处理
// ============================================================================

static void test_detect_timeout() {
    CgnDetectorConfig config;
    config.stun_servers = {"stun1:3478", "stun2:3478", "stun3:3478"};
    config.total_timeout = std::chrono::milliseconds(100);
    config.request_timeout = std::chrono::milliseconds(200);

    // 所有 STUN 探测都很慢（超过 total_timeout）
    CgnDetector detector(config, make_slow_provider(std::chrono::milliseconds(500)));
    auto result = detector.detect_sync();

    // 应该超时，没有足够的探测结果
    CHECK(result.observed_ports.size() < 3);
    CHECK(result.is_cgn == false);  // 探测结果不足，不判定 CGN
}

// ============================================================================
// 10. CgnDetector 错误处理
// ============================================================================

static void test_detect_all_probes_fail() {
    CgnDetectorConfig config;
    config.stun_servers = {"stun1:3478", "stun2:3478", "stun3:3478"};
    config.total_timeout = std::chrono::milliseconds(500);

    CgnDetector detector(config, make_failing_provider());
    auto result = detector.detect_sync();

    CHECK(result.observed_ports.empty());
    CHECK(result.is_cgn == false);
    CHECK(result.port_prediction_confidence == 0.0);
}

static void test_detect_some_probes_throw() {
    CgnDetectorConfig config;
    config.stun_servers = {"stun1:3478", "stun2:3478", "stun3:3478"};
    config.total_timeout = std::chrono::milliseconds(500);

    // 混合：第一个抛异常，后两个成功
    auto idx = std::make_shared<std::atomic<int>>(0);
    auto provider = [idx](const std::string &, std::chrono::milliseconds) {
        return std::async(std::launch::async, [idx]() -> std::optional<std::pair<std::string, std::uint16_t>> {
            int i = idx->fetch_add(1);
            if (i == 0) {
                throw std::runtime_error("first stun failed");
            }
            return std::optional<std::pair<std::string, std::uint16_t>>{{"203.0.113.1", 5000}};
        });
    };

    CgnDetector detector(config, provider);
    auto result = detector.detect_sync();

    // 应该有 2 个成功的结果（3 个中第一个失败）
    CHECK(result.observed_ports.size() == 2);
    CHECK(result.is_cgn == false);  // 端口一致，非 CGN
}

static void test_detect_insufficient_stun_servers() {
    CgnDetectorConfig config;
    config.stun_servers = {"stun1:3478"};  // 只有 1 个，少于 min_stun_servers
    config.min_stun_servers = 3;
    config.total_timeout = std::chrono::milliseconds(500);

    CgnDetector detector(config, make_fixed_provider("203.0.113.1", 5000));
    auto result = detector.detect_sync();

    // 探测结果不足，不判定 CGN
    CHECK(result.is_cgn == false);
    CHECK(result.port_prediction_confidence == 0.0);
}

// ============================================================================
// 11. CgnStrategySelector 策略选择
// ============================================================================

static void test_select_non_cgn() {
    CgnDetectionResult result;
    result.is_cgn = false;
    result.port_prediction_confidence = 1.0;

    auto strategy = CgnStrategySelector::select(result);
    CHECK(strategy == CgnStrategy::StandardRfc5389);
}

static void test_select_cgn_high_confidence() {
    CgnDetectionResult result;
    result.is_cgn = true;
    result.port_prediction_confidence = 0.8;

    auto strategy = CgnStrategySelector::select(result, 0.7, 0.3);
    CHECK(strategy == CgnStrategy::SymmetricNat);  // 高置信度 → 端口预测
}

static void test_select_cgn_medium_confidence() {
    CgnDetectionResult result;
    result.is_cgn = true;
    result.port_prediction_confidence = 0.5;  // 中置信度

    auto strategy = CgnStrategySelector::select(result, 0.7, 0.3);
    CHECK(strategy == CgnStrategy::ParallelTry);  // 中置信度 → 并行尝试
}

static void test_select_cgn_low_confidence() {
    CgnDetectionResult result;
    result.is_cgn = true;
    result.port_prediction_confidence = 0.1;  // 低置信度

    auto strategy = CgnStrategySelector::select(result, 0.7, 0.3);
    CHECK(strategy == CgnStrategy::RelayFallback);  // 低置信度 → 强制 Relay
}

static void test_select_threshold_boundary() {
    CgnDetectionResult result;
    result.is_cgn = true;
    result.port_prediction_confidence = 0.7;  // 边界值

    auto strategy = CgnStrategySelector::select(result, 0.7, 0.3);
    CHECK(strategy == CgnStrategy::SymmetricNat);  // >= 0.7 → 高置信度

    result.port_prediction_confidence = 0.3;  // 边界值
    strategy = CgnStrategySelector::select(result, 0.7, 0.3);
    CHECK(strategy == CgnStrategy::ParallelTry);  // >= 0.3 但 < 0.7 → 中置信度

    result.port_prediction_confidence = 0.29;  // 低于边界
    strategy = CgnStrategySelector::select(result, 0.7, 0.3);
    CHECK(strategy == CgnStrategy::RelayFallback);  // < 0.3 → 低置信度
}

// ============================================================================
// 12. to_holepunch_strategy 映射
// ============================================================================

static void test_to_holepunch_strategy_mapping() {
    CHECK(CgnStrategySelector::to_holepunch_strategy(CgnStrategy::DirectConnect) == net::HolepunchStrategy::None);
    CHECK(CgnStrategySelector::to_holepunch_strategy(CgnStrategy::StandardRfc5389) == net::HolepunchStrategy::StandardRfc5389);
    CHECK(CgnStrategySelector::to_holepunch_strategy(CgnStrategy::SymmetricNat) == net::HolepunchStrategy::SymmetricNat);
    CHECK(CgnStrategySelector::to_holepunch_strategy(CgnStrategy::RelayFallback) == net::HolepunchStrategy::RelayFallback);
    // ParallelTry 映射为 SymmetricNat（linoh 无并行策略）
    CHECK(CgnStrategySelector::to_holepunch_strategy(CgnStrategy::ParallelTry) == net::HolepunchStrategy::SymmetricNat);
}

// ============================================================================
// 13. should_use_relay 判断
// ============================================================================

static void test_should_use_relay() {
    CgnDetectionResult r;
    r.is_cgn = true;

    // 置信度低于阈值 → 使用 Relay
    r.port_prediction_confidence = 0.2;
    CHECK(r.should_use_relay(0.3) == true);

    // 置信度高于阈值 → 不使用 Relay
    r.port_prediction_confidence = 0.5;
    CHECK(r.should_use_relay(0.3) == false);

    // 非 CGN → 不使用 Relay
    r.is_cgn = false;
    r.port_prediction_confidence = 0.1;
    CHECK(r.should_use_relay(0.3) == false);
}

// ============================================================================
// 14. 配置参数生效
// ============================================================================

static void test_config_threshold_effect() {
    // 测试不同的离散度阈值
    CgnDetectorConfig config;
    config.stun_servers = {"stun1:3478", "stun2:3478", "stun3:3478"};
    config.total_timeout = std::chrono::milliseconds(500);
    config.port_dispersion_threshold = 0.1;  // 严格阈值

    // 端口差值 100, 200, 300 → 离散度较低
    CgnDetector detector(config, make_ports_provider("203.0.113.1", {1000, 1100, 1200}));
    auto result = detector.detect_sync();

    // 端口接近，不应判定为 CGN
    CHECK(result.is_cgn == false);
}

static void test_config_min_stun_servers() {
    CgnDetectorConfig config;
    config.stun_servers = {"stun1:3478", "stun2:3478"};
    config.min_stun_servers = 5;  // 要求至少 5 个 STUN 服务器
    config.total_timeout = std::chrono::milliseconds(500);

    CgnDetector detector(config, make_fixed_provider("203.0.113.1", 5000));
    auto result = detector.detect_sync();

    // 配置的 STUN 服务器数量不足，不判定 CGN
    CHECK(result.is_cgn == false);
}

static void test_default_construct() {
    CgnDetector detector;
    auto result = detector.detect_sync();
    // 默认配置无 STUN 服务器，不判定 CGN
    CHECK(result.is_cgn == false);
}

static void test_async_detect() {
    CgnDetectorConfig config;
    config.stun_servers = {"stun1:3478", "stun2:3478", "stun3:3478"};
    config.total_timeout = std::chrono::milliseconds(500);

    CgnDetector detector(config, make_fixed_provider("203.0.113.1", 5000));
    auto fut = detector.detect_async();
    auto result = fut.get();

    CHECK(result.is_cgn == false);
    CHECK(result.observed_ports.size() == 3);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::printf("=== P5-D-3 CGN Detector Tests ===\n\n");

    std::printf("[1] CgnDetectionResult 结构和 to_string\n");
    test_result_default_construct();
    test_result_to_string();
    std::printf("  pass=%d fail=%d\n\n", pass_count, fail_count);

    auto saved_pass = pass_count;
    auto saved_fail = fail_count;

    std::printf("[2] CgnStrategy 枚举和字符串转换\n");
    test_strategy_name();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[3] 工具函数\n");
    test_compute_port_mean();
    test_compute_port_stddev();
    test_compute_port_range();
    test_is_ip_consistent();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[4] compute_port_dispersion\n");
    test_port_dispersion_zero();
    test_port_dispersion_high();
    test_port_dispersion_low();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[5] compute_port_confidence\n");
    test_port_confidence_high();
    test_port_confidence_low();
    test_port_confidence_stable_diff();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[6] 非 CGN 网络（端口稳定）\n");
    test_detect_non_cgn_stable_ports();
    test_detect_non_cgn_close_ports();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[7] CGN 网络（端口离散）\n");
    test_detect_cgn_scattered_ports();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[8] IP 不一致场景\n");
    test_detect_multi_ip_not_cgn();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[9] 超时处理\n");
    test_detect_timeout();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[10] 错误处理\n");
    test_detect_all_probes_fail();
    test_detect_some_probes_throw();
    test_detect_insufficient_stun_servers();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[11] CgnStrategySelector 策略选择\n");
    test_select_non_cgn();
    test_select_cgn_high_confidence();
    test_select_cgn_medium_confidence();
    test_select_cgn_low_confidence();
    test_select_threshold_boundary();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[12] to_holepunch_strategy 映射\n");
    test_to_holepunch_strategy_mapping();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[13] should_use_relay 判断\n");
    test_should_use_relay();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[14] 配置参数生效\n");
    test_config_threshold_effect();
    test_config_min_stun_servers();
    test_default_construct();
    test_async_detect();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);

    std::printf("=== Summary ===\n");
    std::printf("Total: pass=%d fail=%d\n", pass_count, fail_count);

    return fail_count == 0 ? 0 : 1;
}
