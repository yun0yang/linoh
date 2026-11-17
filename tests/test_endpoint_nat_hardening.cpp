// test_endpoint_nat_hardening.cpp — P5-D-3 Endpoint NAT 穿透强化集成测试
//
// 验证：
//   1. Config.enable_nat_hardening 默认为 true
//   2. Config.enable_nat_hardening 可被覆盖为 false
//   3. Config.port_predictor_config / nat_stats_config 默认值正确
//   4. Endpoint 启用 NAT 强化时 port_predictor()/nat_stats() 非空
//   5. Endpoint 禁用 NAT 强化时 port_predictor()/nat_stats() 为空
//   6. nat_hardening_enabled() 返回正确值
//   7. port_predictor() 返回的预测器可正常 record/predict
//   8. nat_stats() 返回的统计模型可正常 record/query
//   9. 持久化 roundtrip（保存 + 重新加载）
//  10. 向后兼容：禁用 NAT 强化时行为与 v3.5 一致（API 返回 nullptr）
//
// 注意：Endpoint 构造需要 io_context + WSAStartup（Windows）

#include "linoh/endpoint/endpoint.hpp"
#include "linoh/nat/port_predictor.hpp"
#include "linoh/nat/nat_stats.hpp"
#include "linoh/base/key.hpp"

#include <atomic>
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

// ============================================================================
// 测试 1: Config.enable_nat_hardening 默认为 true
// ============================================================================
static void test_config_default_enable_nat_hardening() {
    std::printf("[test] Config.enable_nat_hardening default true...\n");
    Endpoint::Config cfg{};
    CHECK(cfg.enable_nat_hardening == true);
}

// ============================================================================
// 测试 2: Config.enable_nat_hardening 可被覆盖为 false
// ============================================================================
static void test_config_disable_nat_hardening() {
    std::printf("[test] Config.enable_nat_hardening settable to false...\n");
    Endpoint::Config cfg{};
    cfg.enable_nat_hardening = false;
    CHECK(cfg.enable_nat_hardening == false);
}

// ============================================================================
// 测试 3: Config.port_predictor_config 默认值正确
// ============================================================================
static void test_config_port_predictor_defaults() {
    std::printf("[test] Config.port_predictor_config defaults...\n");
    Endpoint::Config cfg{};
    CHECK(cfg.port_predictor_config.max_observations_per_peer == 32);
    CHECK(cfg.port_predictor_config.min_observations_for_advanced == 3);
    CHECK(cfg.port_predictor_config.min_candidates == 5);
    CHECK(cfg.port_predictor_config.max_candidates == 20);
}

// ============================================================================
// 测试 4: Config.nat_stats_config 默认值正确
// ============================================================================
static void test_config_nat_stats_defaults() {
    std::printf("[test] Config.nat_stats_config defaults...\n");
    Endpoint::Config cfg{};
    CHECK(cfg.nat_stats_config.max_records_per_key == 1000);
    CHECK(cfg.nat_stats_config.cold_start_threshold == 10);
    CHECK(cfg.nat_stats_config.weight_success_rate == 0.7);
    CHECK(cfg.nat_stats_config.weight_sample_confidence == 0.3);
}

// ============================================================================
// 测试 5: Endpoint 启用 NAT 强化时 port_predictor()/nat_stats() 非空
// ============================================================================
static void test_endpoint_nat_hardening_enabled() {
    std::printf("[test] Endpoint NAT hardening enabled...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    // enable_nat_hardening 默认 true
    auto ep = Endpoint::make(ctx, std::move(cfg));

    CHECK(ep->nat_hardening_enabled() == true);
    CHECK(ep->port_predictor() != nullptr);
    CHECK(ep->nat_stats() != nullptr);
}

// ============================================================================
// 测试 6: Endpoint 禁用 NAT 强化时 port_predictor()/nat_stats() 为空
// ============================================================================
static void test_endpoint_nat_hardening_disabled() {
    std::printf("[test] Endpoint NAT hardening disabled...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    cfg.enable_nat_hardening = false;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    CHECK(ep->nat_hardening_enabled() == false);
    CHECK(ep->port_predictor() == nullptr);
    CHECK(ep->nat_stats() == nullptr);
}

// ============================================================================
// 测试 7: port_predictor() 返回的预测器可正常 record/predict
// ============================================================================
static void test_port_predictor_functional() {
    std::printf("[test] port_predictor() functional record/predict...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto *pp = ep->port_predictor();
    CHECK(pp != nullptr);

    // 构造 peer EndpointId
    auto peer_key = SecretKey::generate();
    auto peer = peer_key.public_key();

    // 记录 2 次观测
    pp->record_observation(peer, 30000);
    pp->record_observation(peer, 30002);

    // 预测
    auto pred = pp->predict(peer);
    CHECK(!pred.candidates.empty());
    CHECK(pred.observation_count == 2);

    // 观测数查询
    CHECK(pp->observation_count(peer) == 2);
}

// ============================================================================
// 测试 8: nat_stats() 返回的统计模型可正常 record/query
// ============================================================================
static void test_nat_stats_functional() {
    std::printf("[test] nat_stats() functional record/query...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto *ns = ep->nat_stats();
    CHECK(ns != nullptr);

    // 记录 5 次穿透结果
    for (int i = 0; i < 5; ++i) {
        PenetrationRecord r;
        r.nat_type = linoh::net::NatType::Symmetric;
        r.carrier = "移动";
        r.region = GeoRegion::East;
        r.strategy_used = CgnStrategy::SymmetricNat;
        r.success = (i % 2 == 0);
        r.duration = std::chrono::milliseconds(200);
        ns->record(r);
    }

    // 查询
    StatsKey key{linoh::net::NatType::Symmetric, "移动", GeoRegion::East};
    auto snap = ns->query(key);
    CHECK(snap.total == 5);
    CHECK(snap.success == 3);  // i=0,2,4 成功
}

// ============================================================================
// 测试 9: 持久化 roundtrip（保存 + 重新加载）
// ============================================================================
static void test_persistence_roundtrip() {
    std::printf("[test] NAT hardening persistence roundtrip...\n");

    std::string pp_path = "build/test_endpoint_pp_persist.tsv";
    std::string ns_path = "build/test_endpoint_ns_persist.tsv";

    // 清理上次运行的残留文件（方案 A 下 NatStats/PortPredictor 构造函数会自动 load，
    // 若不清理，残留数据会被加载导致 record 后数据翻倍）
    std::remove(pp_path.c_str());
    std::remove(ns_path.c_str());

    // 第一个 Endpoint：记录数据 + 析构保存
    auto peer_key = SecretKey::generate();
    auto peer = peer_key.public_key();

    {
        linoh_asio::io_context ctx;
        auto cfg = make_ep_cfg();
        cfg.port_predictor_config.persistence_path = pp_path;
        cfg.nat_stats_config.persistence_path = ns_path;
        auto ep = Endpoint::make(ctx, std::move(cfg));

        // 记录端口观测
        ep->port_predictor()->record_observation(peer, 40000);
        ep->port_predictor()->record_observation(peer, 40002);
        ep->port_predictor()->record_observation(peer, 40004);

        // 记录 NAT 统计
        for (int i = 0; i < 3; ++i) {
            PenetrationRecord r;
            r.nat_type = linoh::net::NatType::FullCone;
            r.carrier = "电信";
            r.region = GeoRegion::South;
            r.strategy_used = CgnStrategy::StandardRfc5389;
            r.success = true;
            ep->nat_stats()->record(r);
        }

        // 手动保存（析构也会保存，但手动保存便于验证）
        ep->save_nat_hardening_state();
    }

    // 第二个 Endpoint：加载持久化数据
    {
        linoh_asio::io_context ctx;
        auto cfg = make_ep_cfg();
        cfg.port_predictor_config.persistence_path = pp_path;
        cfg.nat_stats_config.persistence_path = ns_path;
        auto ep = Endpoint::make(ctx, std::move(cfg));

        // 验证端口预测器加载了历史
        CHECK(ep->port_predictor()->observation_count(peer) == 3);

        // 验证 NAT 统计加载了记录
        StatsKey key{linoh::net::NatType::FullCone, "电信", GeoRegion::South};
        auto snap = ep->nat_stats()->query(key);
        CHECK(snap.total == 3);
        CHECK(snap.success == 3);
    }
}

// ============================================================================
// 测试 10: 向后兼容 — 禁用 NAT 强化时 API 返回 nullptr
// ============================================================================
static void test_backward_compatibility() {
    std::printf("[test] backward compatibility (v3.5 fallback)...\n");
    linoh_asio::io_context ctx;
    auto cfg = make_ep_cfg();
    cfg.enable_nat_hardening = false;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    // 禁用时 API 返回 nullptr，调用方应回退 v3.5 行为
    CHECK(ep->port_predictor() == nullptr);
    CHECK(ep->nat_stats() == nullptr);
    CHECK(ep->nat_hardening_enabled() == false);

    // save_nat_hardening_state 在禁用时不应崩溃
    ep->save_nat_hardening_state();
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== test_endpoint_nat_hardening ===\n");

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::printf("WSAStartup failed\n");
        return 1;
    }
#endif

    test_config_default_enable_nat_hardening();
    test_config_disable_nat_hardening();
    test_config_port_predictor_defaults();
    test_config_nat_stats_defaults();

    test_endpoint_nat_hardening_enabled();
    test_endpoint_nat_hardening_disabled();

    test_port_predictor_functional();
    test_nat_stats_functional();

    test_persistence_roundtrip();
    test_backward_compatibility();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);

#ifdef _WIN32
    WSACleanup();
#endif

    return g_fail == 0 ? 0 : 1;
}
