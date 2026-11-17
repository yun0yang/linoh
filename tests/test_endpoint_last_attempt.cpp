// test_endpoint_last_attempt.cpp — P5-D-4 Endpoint Relay 兜底前最后尝试
//
// 验证（plan §3.3.1）：
//   1. Config 默认值：enable_last_attempt_before_relay=true, last_attempt_min_confidence=0.8
//   2. enable_nat_hardening=false → 直接返回 nullopt
//   3. enable_last_attempt_before_relay=false → 返回 nullopt
//   4. PortPredictor 冷启动（confidence=0）→ 返回 nullopt
//   5. confidence < last_attempt_min_confidence → 返回 nullopt
//   6. confidence >= 阈值 + attempt 失败（不可达 remote）→ 返回 nullopt，NatStats 记录失败
//   7. NatStats 记录验证：total=1, success=0
//   8. 自定义 timeout 覆盖 Config.last_attempt_timeout
//
// 注意：测试 6/7 涉及实际 UDP socket 调用，使用 127.0.0.1:1（保留端口）+ 200ms 超时
//       快速失败，确保 CI 稳定性

#include "linoh/endpoint/endpoint.hpp"
#include "linoh/nat/port_predictor.hpp"
#include "linoh/nat/nat_stats.hpp"
#include "linoh/base/key.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace linoh::endpoint;
using namespace linoh::nat;
using namespace linoh::base;
using namespace linoh::net;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// 构造最小可用 Endpoint 配置（避免真实网络连接）
static Endpoint::Config make_ep_cfg() {
    Endpoint::Config cfg{};
    cfg.secret_key = SecretKey::generate();
    cfg.bootstrap.auto_connect = false;
    return cfg;
}

// 构造一个 peer EndpointId
static EndpointId make_peer(std::uint8_t seed) {
    EndpointId id{};
    for (std::size_t i = 0; i < id.size(); ++i) {
        id.data()[i] = static_cast<std::uint8_t>(seed + i);
    }
    return id;
}

// 构造一个 StatsKey（用于 NatStats::record）
static StatsKey make_stats_key() {
    StatsKey key{};
    key.nat_type = NatType::Symmetric;
    key.carrier = "移动";
    key.region = GeoRegion::East;
    return key;
}

// 向 PortPredictor 灌入 5 点等差历史（confidence 高）
static void seed_high_confidence_history(PortPredictor *pp, const EndpointId &peer) {
    auto now = std::chrono::system_clock::now();
    for (int i = 0; i < 5; ++i) {
        pp->record_observation(peer, static_cast<std::uint16_t>(40000 + i * 10),
                               now + std::chrono::milliseconds(i * 1000));
    }
}

// 向 PortPredictor 灌入 2 点历史（confidence=0.5，中等）
static void seed_medium_confidence_history(PortPredictor *pp, const EndpointId &peer) {
    auto now = std::chrono::system_clock::now();
    pp->record_observation(peer, 40000, now);
    pp->record_observation(peer, 40010, now + std::chrono::milliseconds(1000));
}

// ============================================================================
// 测试 1: Config 默认值
// ============================================================================
static void test_config_defaults() {
    std::printf("[test] Config defaults (P5-D-4)...\n");
    Endpoint::Config cfg{};
    CHECK(cfg.enable_last_attempt_before_relay == true);
    CHECK(cfg.last_attempt_min_confidence == 0.8);
    CHECK(cfg.last_attempt_timeout == std::chrono::seconds(2));
}

// ============================================================================
// 测试 2: enable_nat_hardening=false → 直接返回 nullopt
// ============================================================================
static void test_disabled_nat_hardening() {
    std::printf("[test] disabled nat_hardening -> nullopt...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    cfg.enable_nat_hardening = false;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto peer = make_peer(0x01);
    auto key = make_stats_key();
    auto result = ep->try_last_attempt_before_relay(
        peer, "127.0.0.1", 1, 40000, 40010, key, std::chrono::milliseconds(200));
    CHECK(!result.has_value());
}

// ============================================================================
// 测试 3: enable_last_attempt_before_relay=false → 返回 nullopt
// ============================================================================
static void test_disabled_last_attempt_switch() {
    std::printf("[test] disabled last_attempt switch -> nullopt...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    cfg.enable_nat_hardening = true;
    cfg.enable_last_attempt_before_relay = false;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    // 即使 PortPredictor 有高置信度历史，开关关闭也应返回 nullopt
    auto peer = make_peer(0x02);
    seed_high_confidence_history(ep->port_predictor(), peer);
    auto key = make_stats_key();
    auto result = ep->try_last_attempt_before_relay(
        peer, "127.0.0.1", 1, 40000, 40010, key, std::chrono::milliseconds(200));
    CHECK(!result.has_value());
}

// ============================================================================
// 测试 4: PortPredictor 冷启动（confidence=0）→ 返回 nullopt
// ============================================================================
static void test_cold_start_low_confidence() {
    std::printf("[test] cold start (confidence=0) -> nullopt...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto peer = make_peer(0x03);
    // 不灌入任何历史，PortPredictor 冷启动
    auto key = make_stats_key();
    auto result = ep->try_last_attempt_before_relay(
        peer, "127.0.0.1", 1, 40000, 40010, key, std::chrono::milliseconds(200));
    CHECK(!result.has_value());

    // NatStats 不应被记录（提前返回，未触发 attempt）
    auto snap = ep->nat_stats()->query(key);
    CHECK(snap.total == 0);
}

// ============================================================================
// 测试 5: confidence < last_attempt_min_confidence → 返回 nullopt
// ============================================================================
static void test_insufficient_confidence() {
    std::printf("[test] insufficient confidence -> nullopt...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    cfg.last_attempt_min_confidence = 0.8;  // 默认值
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto peer = make_peer(0x04);
    seed_medium_confidence_history(ep->port_predictor(), peer);  // confidence=0.5
    auto key = make_stats_key();

    // 验证 confidence 确实 < 0.8
    auto pred = ep->port_predictor()->predict(peer, 5);
    CHECK(pred.confidence < 0.8);
    CHECK(pred.confidence > 0.0);  // 有历史但不足

    auto result = ep->try_last_attempt_before_relay(
        peer, "127.0.0.1", 1, 40000, 40010, key, std::chrono::milliseconds(200));
    CHECK(!result.has_value());

    // NatStats 不应被记录（confidence 不足，提前返回）
    auto snap = ep->nat_stats()->query(key);
    CHECK(snap.total == 0);
}

// ============================================================================
// 测试 6: confidence >= 阈值 + attempt 失败 → 返回 nullopt，NatStats 记录失败
// ============================================================================
static void test_sufficient_confidence_triggers_attempt() {
    std::printf("[test] sufficient confidence triggers attempt (fails on unreachable)...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto peer = make_peer(0x05);
    seed_high_confidence_history(ep->port_predictor(), peer);  // confidence 高
    auto key = make_stats_key();

    // 验证 confidence >= 0.8
    auto pred = ep->port_predictor()->predict(peer, 5);
    CHECK(pred.confidence >= 0.8);

    // 触发 attempt：remote=127.0.0.1:1（保留端口，无服务）+ 200ms 超时
    // 预期：attempt 失败（no response），返回 nullopt
    auto t0 = std::chrono::steady_clock::now();
    auto result = ep->try_last_attempt_before_relay(
        peer, "127.0.0.1", 1, 40000, 40010, key, std::chrono::milliseconds(200));
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);

    CHECK(!result.has_value());  // attempt 失败
    // 应该在合理时间内返回（200ms 超时 + 少量开销，不超过 3s）
    CHECK(elapsed.count() < 3000);

    // NatStats 应记录 1 条失败
    auto snap = ep->nat_stats()->query(key);
    CHECK(snap.total == 1);
    CHECK(snap.success == 0);
}

// ============================================================================
// 测试 7: NatStats 记录验证（多次调用累加）
// ============================================================================
static void test_nat_stats_records_accumulate() {
    std::printf("[test] NatStats records accumulate...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto peer = make_peer(0x06);
    seed_high_confidence_history(ep->port_predictor(), peer);
    auto key = make_stats_key();

    // 调用 2 次，每次都失败（remote 不可达）
    for (int i = 0; i < 2; ++i) {
        auto result = ep->try_last_attempt_before_relay(
            peer, "127.0.0.1", 1, 40000 + i * 10, 40010 + i * 10, key,
            std::chrono::milliseconds(150));
        CHECK(!result.has_value());
    }

    // NatStats 应记录 2 条失败
    auto snap = ep->nat_stats()->query(key);
    CHECK(snap.total == 2);
    CHECK(snap.success == 0);

    // 查询策略统计：SymmetricNat 应有 2 次失败
    auto strategies = ep->nat_stats()->query_strategies(key);
    bool found_sym = false;
    for (const auto &s : strategies) {
        if (s.strategy == CgnStrategy::SymmetricNat) {
            found_sym = true;
            CHECK(s.total == 2);
            CHECK(s.success == 0);
        }
    }
    CHECK(found_sym);
}

// ============================================================================
// 测试 8: 自定义 timeout 覆盖 Config.last_attempt_timeout
// ============================================================================
static void test_custom_timeout_override() {
    std::printf("[test] custom timeout overrides Config...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    cfg.last_attempt_timeout = std::chrono::seconds(5);  // Config 设大值
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto peer = make_peer(0x07);
    seed_high_confidence_history(ep->port_predictor(), peer);
    auto key = make_stats_key();

    // 调用时传 150ms，应覆盖 Config 的 5s
    auto t0 = std::chrono::steady_clock::now();
    auto result = ep->try_last_attempt_before_relay(
        peer, "127.0.0.1", 1, 40000, 40010, key, std::chrono::milliseconds(150));
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);

    CHECK(!result.has_value());
    // 应在 150ms 超时 + 少量开销内返回，远小于 5s
    CHECK(elapsed.count() < 1000);
}

// ============================================================================
// 测试 9: 默认 timeout=0 时使用 Config.last_attempt_timeout
// ============================================================================
static void test_default_timeout_uses_config() {
    std::printf("[test] default timeout uses Config...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    cfg.last_attempt_timeout = std::chrono::milliseconds(150);  // Config 设小值
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto peer = make_peer(0x08);
    seed_high_confidence_history(ep->port_predictor(), peer);
    auto key = make_stats_key();

    // 调用时不传 timeout（默认 0），应用 Config 的 150ms
    auto t0 = std::chrono::steady_clock::now();
    auto result = ep->try_last_attempt_before_relay(
        peer, "127.0.0.1", 1, 40000, 40010, key, std::chrono::milliseconds(0));
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);

    CHECK(!result.has_value());
    // 应在 150ms 超时 + 少量开销内返回
    CHECK(elapsed.count() < 1000);
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== test_endpoint_last_attempt ===\n");

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::printf("WSAStartup failed\n");
        return 1;
    }
#endif

    test_config_defaults();
    test_disabled_nat_hardening();
    test_disabled_last_attempt_switch();
    test_cold_start_low_confidence();
    test_insufficient_confidence();
    test_sufficient_confidence_triggers_attempt();
    test_nat_stats_records_accumulate();
    test_custom_timeout_override();
    test_default_timeout_uses_config();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);

#ifdef _WIN32
    WSACleanup();
#endif

    return g_fail == 0 ? 0 : 1;
}
