// test_server_config.cpp — P2-G6 NAT 阈值远端下发单元测试
//
// 验证：
//   1. NatServerConfig 默认构造（全 nullopt）
//   2. from_json：完整 JSON / 空 JSON / 未知字段 / 类型不匹配 / 部分字段
//   3. to_json：往返一致性（已设置字段）
//   4. merge：全覆盖 / 部分覆盖 / 空覆盖
//   5. apply_to(UdpProbeConfig)：覆盖已下发字段，保留未下发字段
//   6. apply_to(FallbackConfig)
//   7. apply_to(CgnDetectorConfig)
//   8. apply_to(PortPredictorConfig)
//   9. apply_to(IceSessionConfig)
//  10. set_field_count：计数准确
//  11. ServerConfigManager：update / config / 回调 / reset
//  12. 线程安全：并发 update + config 无崩溃

#include "linoh/nat/server_config.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
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
using namespace linoh::net;
using namespace linoh::relay;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 1. NatServerConfig 默认构造（全 nullopt）
// ============================================================================

static void test_default_construct() {
    NatServerConfig cfg;
    CHECK(!cfg.relay_switch_threshold.has_value());
    CHECK(!cfg.p2p_to_relay_switch_threshold.has_value());
    CHECK(!cfg.relay_to_p2p_switch_threshold.has_value());
    CHECK(!cfg.reconnecting_state_timeout.has_value());
    CHECK(!cfg.udp_probe_count.has_value());
    CHECK(!cfg.udp_available_threshold.has_value());
    CHECK(!cfg.udp_bad_threshold.has_value());
    CHECK(!cfg.udp_probe_recv_timeout.has_value());
    CHECK(!cfg.enable_fec_on_bad.has_value());
    CHECK(!cfg.tcp_connect_timeout.has_value());
    CHECK(!cfg.skip_udp_probe.has_value());
    CHECK(!cfg.cgn_port_dispersion_threshold.has_value());
    CHECK(!cfg.cgn_confidence_threshold.has_value());
    CHECK(!cfg.port_predict_min_candidates.has_value());
    CHECK(!cfg.port_predict_max_candidates.has_value());
    CHECK(!cfg.ice_presume_writable_when_fully_relayed.has_value());
    CHECK(!cfg.ice_skip_relay_to_non_relay.has_value());
    CHECK(!cfg.ice_gather_continually.has_value());
    CHECK(!cfg.ice_prioritize_most_likely_pairs.has_value());
    CHECK(cfg.set_field_count() == 0);
}

// ============================================================================
// 2. from_json：完整 JSON
// ============================================================================

static void test_from_json_full() {
    std::string json = R"({
        "relay_switch_threshold": 0.4,
        "p2p_to_relay_switch_threshold": 0.35,
        "relay_to_p2p_switch_threshold": 0.8,
        "reconnecting_state_timeout_ms": 2000,
        "udp_probe_count": 10,
        "udp_available_threshold": 0.8,
        "udp_bad_threshold": 0.2,
        "udp_probe_recv_timeout_ms": 600,
        "enable_fec_on_bad": false,
        "tcp_connect_timeout_ms": 5000,
        "skip_udp_probe": true,
        "cgn_port_dispersion_threshold": 0.6,
        "cgn_confidence_threshold": 0.25,
        "port_predict_min_candidates": 8,
        "port_predict_max_candidates": 30,
        "ice_presume_writable_when_fully_relayed": true,
        "ice_skip_relay_to_non_relay": true,
        "ice_gather_continually": true,
        "ice_prioritize_most_likely_pairs": true
    })";
    NatServerConfig cfg = NatServerConfig::from_json(json);
    CHECK(cfg.relay_switch_threshold.has_value());
    CHECK(*cfg.relay_switch_threshold == 0.4);
    CHECK(*cfg.p2p_to_relay_switch_threshold == 0.35);
    CHECK(*cfg.relay_to_p2p_switch_threshold == 0.8);
    CHECK(*cfg.reconnecting_state_timeout == std::chrono::milliseconds(2000));
    CHECK(*cfg.udp_probe_count == 10);
    CHECK(*cfg.udp_available_threshold == 0.8);
    CHECK(*cfg.udp_bad_threshold == 0.2);
    CHECK(*cfg.udp_probe_recv_timeout == std::chrono::milliseconds(600));
    CHECK(cfg.enable_fec_on_bad.has_value());
    CHECK(*cfg.enable_fec_on_bad == false);
    CHECK(*cfg.tcp_connect_timeout == std::chrono::milliseconds(5000));
    CHECK(*cfg.skip_udp_probe == true);
    CHECK(*cfg.cgn_port_dispersion_threshold == 0.6);
    CHECK(*cfg.cgn_confidence_threshold == 0.25);
    CHECK(*cfg.port_predict_min_candidates == 8);
    CHECK(*cfg.port_predict_max_candidates == 30);
    CHECK(*cfg.ice_presume_writable_when_fully_relayed == true);
    CHECK(*cfg.ice_skip_relay_to_non_relay == true);
    CHECK(*cfg.ice_gather_continually == true);
    CHECK(*cfg.ice_prioritize_most_likely_pairs == true);
    CHECK(cfg.set_field_count() == 19);
}

// ============================================================================
// 3. from_json：空 JSON {}
// ============================================================================

static void test_from_json_empty() {
    NatServerConfig cfg = NatServerConfig::from_json("{}");
    CHECK(cfg.set_field_count() == 0);
    CHECK(!cfg.udp_probe_count.has_value());
}

// ============================================================================
// 4. from_json：未知字段忽略
// ============================================================================

static void test_from_json_unknown_fields() {
    std::string json = R"({"unknown_field": 123, "udp_probe_count": 7, "another": "abc"})";
    NatServerConfig cfg = NatServerConfig::from_json(json);
    CHECK(cfg.set_field_count() == 1);
    CHECK(*cfg.udp_probe_count == 7);
}

// ============================================================================
// 5. from_json：类型不匹配（该字段留 nullopt，不崩溃）
// ============================================================================

static void test_from_json_type_mismatch() {
    // udp_probe_count 期望 number，给 string → 留 nullopt
    std::string json = R"({"udp_probe_count": "abc", "enable_fec_on_bad": "yes"})";
    NatServerConfig cfg = NatServerConfig::from_json(json);
    // 类型不匹配的字段不设置
    CHECK(!cfg.udp_probe_count.has_value());
    // enable_fec_on_bad 期望 bool，给 string "yes" → vtype 不是 "bool"，留 nullopt
    CHECK(!cfg.enable_fec_on_bad.has_value());
}

// ============================================================================
// 6. from_json：部分字段
// ============================================================================

static void test_from_json_partial() {
    std::string json = R"({"udp_probe_count": 8, "skip_udp_probe": true})";
    NatServerConfig cfg = NatServerConfig::from_json(json);
    CHECK(cfg.set_field_count() == 2);
    CHECK(*cfg.udp_probe_count == 8);
    CHECK(*cfg.skip_udp_probe == true);
    CHECK(!cfg.udp_available_threshold.has_value());
}

// ============================================================================
// 7. from_json：非法 JSON（解析失败返回空配置）
// ============================================================================

static void test_from_json_invalid() {
    NatServerConfig cfg = NatServerConfig::from_json("not a json");
    CHECK(cfg.set_field_count() == 0);
    // 非法 JSON 不崩溃
    NatServerConfig cfg2 = NatServerConfig::from_json("{");
    CHECK(cfg2.set_field_count() == 0);
}

// ============================================================================
// 8. to_json：往返一致性
// ============================================================================

static void test_to_json_roundtrip() {
    std::string json = R"({"udp_probe_count":12,"enable_fec_on_bad":false,"skip_udp_probe":true})";
    NatServerConfig cfg = NatServerConfig::from_json(json);
    std::string out = cfg.to_json();
    // 解析回来应一致
    NatServerConfig cfg2 = NatServerConfig::from_json(out);
    CHECK(cfg2.set_field_count() == 3);
    CHECK(*cfg2.udp_probe_count == 12);
    CHECK(*cfg2.enable_fec_on_bad == false);
    CHECK(*cfg2.skip_udp_probe == true);
}

// ============================================================================
// 9. to_json：空配置输出 {}
// ============================================================================

static void test_to_json_empty() {
    NatServerConfig cfg;
    std::string out = cfg.to_json();
    CHECK(out == "{}");
}

// ============================================================================
// 10. merge：全覆盖
// ============================================================================

static void test_merge_full_overwrite() {
    NatServerConfig base;
    base.udp_probe_count = 5;
    base.enable_fec_on_bad = true;
    base.skip_udp_probe = false;

    NatServerConfig override_;
    override_.udp_probe_count = 10;
    override_.enable_fec_on_bad = false;
    override_.skip_udp_probe = true;

    NatServerConfig r = base.merge(override_);
    CHECK(*r.udp_probe_count == 10);
    CHECK(*r.enable_fec_on_bad == false);
    CHECK(*r.skip_udp_probe == true);
}

// ============================================================================
// 11. merge：部分覆盖（未设置字段保留 base）
// ============================================================================

static void test_merge_partial() {
    NatServerConfig base;
    base.udp_probe_count = 5;
    base.enable_fec_on_bad = true;
    base.skip_udp_probe = false;

    NatServerConfig override_;  // 只设置一个
    override_.udp_probe_count = 99;

    NatServerConfig r = base.merge(override_);
    CHECK(*r.udp_probe_count == 99);
    CHECK(*r.enable_fec_on_bad == true);     // 保留 base
    CHECK(*r.skip_udp_probe == false);       // 保留 base
}

// ============================================================================
// 12. merge：空覆盖（override 全 nullopt，base 不变）
// ============================================================================

static void test_merge_empty_override() {
    NatServerConfig base;
    base.udp_probe_count = 5;
    base.enable_fec_on_bad = true;

    NatServerConfig empty;
    NatServerConfig r = base.merge(empty);
    CHECK(*r.udp_probe_count == 5);
    CHECK(*r.enable_fec_on_bad == true);
}

// ============================================================================
// 13. merge：base 空 + override 有值
// ============================================================================

static void test_merge_empty_base() {
    NatServerConfig base;
    NatServerConfig override_;
    override_.udp_probe_count = 7;

    NatServerConfig r = base.merge(override_);
    CHECK(*r.udp_probe_count == 7);
}

// ============================================================================
// 14. apply_to(UdpProbeConfig)
// ============================================================================

static void test_apply_to_udp_probe() {
    UdpProbeConfig base;  // 默认 ping_count=5, available=0.7, bad=0.3, recv_timeout=500ms
    CHECK(base.ping_count == 5);
    CHECK(base.available_threshold == 0.7);

    NatServerConfig cfg;
    cfg.udp_probe_count = 10;
    cfg.udp_available_threshold = 0.8;
    cfg.udp_bad_threshold = 0.2;
    cfg.udp_probe_recv_timeout = std::chrono::milliseconds(600);

    UdpProbeConfig r = cfg.apply_to(base);
    CHECK(r.ping_count == 10);
    CHECK(r.available_threshold == 0.8);
    CHECK(r.bad_threshold == 0.2);
    CHECK(r.recv_timeout == std::chrono::milliseconds(600));
}

// ============================================================================
// 15. apply_to(UdpProbeConfig)：未下发字段保留 base
// ============================================================================

static void test_apply_to_udp_probe_partial() {
    UdpProbeConfig base;
    NatServerConfig cfg;
    cfg.udp_probe_count = 10;  // 只下发一个

    UdpProbeConfig r = cfg.apply_to(base);
    CHECK(r.ping_count == 10);
    CHECK(r.available_threshold == 0.7);  // 保留 base
    CHECK(r.bad_threshold == 0.3);
    CHECK(r.recv_timeout == std::chrono::milliseconds(500));
}

// ============================================================================
// 16. apply_to(FallbackConfig)
// ============================================================================

static void test_apply_to_fallback() {
    FallbackConfig base;  // enable_fec_on_bad=true, tcp_connect_timeout=3000ms, skip_udp_probe=false
    CHECK(base.enable_fec_on_bad == true);

    NatServerConfig cfg;
    cfg.enable_fec_on_bad = false;
    cfg.tcp_connect_timeout = std::chrono::milliseconds(5000);
    cfg.skip_udp_probe = true;

    FallbackConfig r = cfg.apply_to(base);
    CHECK(r.enable_fec_on_bad == false);
    CHECK(r.tcp_connect_timeout == std::chrono::milliseconds(5000));
    CHECK(r.skip_udp_probe == true);
}

// ============================================================================
// 17. apply_to(CgnDetectorConfig)
// ============================================================================

static void test_apply_to_cgn() {
    CgnDetectorConfig base;  // port_dispersion=0.5, confidence=0.3
    NatServerConfig cfg;
    cfg.cgn_port_dispersion_threshold = 0.6;
    cfg.cgn_confidence_threshold = 0.25;

    CgnDetectorConfig r = cfg.apply_to(base);
    CHECK(r.port_dispersion_threshold == 0.6);
    CHECK(r.confidence_threshold == 0.25);
}

// ============================================================================
// 18. apply_to(PortPredictorConfig)
// ============================================================================

static void test_apply_to_port_predictor() {
    PortPredictorConfig base;  // min=5, max=20
    NatServerConfig cfg;
    cfg.port_predict_min_candidates = 8;
    cfg.port_predict_max_candidates = 30;

    PortPredictorConfig r = cfg.apply_to(base);
    CHECK(r.min_candidates == 8);
    CHECK(r.max_candidates == 30);
}

// ============================================================================
// 19. apply_to(IceSessionConfig)
// ============================================================================

static void test_apply_to_ice() {
    IceSessionConfig base;  // 默认全 false
    CHECK(base.presume_writable_when_fully_relayed == false);

    NatServerConfig cfg;
    cfg.ice_presume_writable_when_fully_relayed = true;
    cfg.ice_skip_relay_to_non_relay = true;
    cfg.ice_gather_continually = true;
    cfg.ice_prioritize_most_likely_pairs = true;

    IceSessionConfig r = cfg.apply_to(base);
    CHECK(r.presume_writable_when_fully_relayed == true);
    CHECK(r.skip_relay_to_non_relay_connections == true);
    CHECK(r.gather_continually == true);
    CHECK(r.prioritize_most_likely_candidate_pairs == true);
}

// ============================================================================
// 20. apply_to：空配置（全 nullopt）保留 base 全部默认值
// ============================================================================

static void test_apply_to_empty_keeps_base() {
    NatServerConfig empty;
    UdpProbeConfig udp_base;
    UdpProbeConfig udp_r = empty.apply_to(udp_base);
    CHECK(udp_r.ping_count == 5);
    CHECK(udp_r.available_threshold == 0.7);

    FallbackConfig fb_base;
    FallbackConfig fb_r = empty.apply_to(fb_base);
    CHECK(fb_r.enable_fec_on_bad == true);
    CHECK(fb_r.tcp_connect_timeout == std::chrono::milliseconds(3000));
    CHECK(fb_r.skip_udp_probe == false);

    IceSessionConfig ice_base;
    IceSessionConfig ice_r = empty.apply_to(ice_base);
    CHECK(ice_r.presume_writable_when_fully_relayed == false);
}

// ============================================================================
// 21. ServerConfigManager：update + config 快照
// ============================================================================

static void test_manager_update_config() {
    auto &mgr = ServerConfigManager::instance();
    mgr.reset();
    CHECK(mgr.config().set_field_count() == 0);

    bool ok = mgr.update(R"({"udp_probe_count":15,"skip_udp_probe":true})");
    CHECK(ok == true);
    NatServerConfig cfg = mgr.config();
    CHECK(cfg.set_field_count() == 2);
    CHECK(*cfg.udp_probe_count == 15);
    CHECK(*cfg.skip_udp_probe == true);
}

// ============================================================================
// 22. ServerConfigManager：update 合并语义（增量覆盖）
// ============================================================================

static void test_manager_update_merge() {
    auto &mgr = ServerConfigManager::instance();
    mgr.reset();

    mgr.update(R"({"udp_probe_count":5})");
    CHECK(*mgr.config().udp_probe_count == 5);

    // 第二次 update 增加新字段，保留已有字段
    mgr.update(R"({"skip_udp_probe":true})");
    NatServerConfig cfg = mgr.config();
    CHECK(cfg.set_field_count() == 2);
    CHECK(*cfg.udp_probe_count == 5);      // 保留
    CHECK(*cfg.skip_udp_probe == true);    // 新增
}

// ============================================================================
// 23. ServerConfigManager：回调触发
// ============================================================================

static void test_manager_callback() {
    auto &mgr = ServerConfigManager::instance();
    mgr.reset();

    std::atomic<int> call_count{0};
    std::size_t last_fields = 999;
    mgr.set_changed_callback([&](const NatServerConfig &c) {
        ++call_count;
        last_fields = c.set_field_count();
    });

    mgr.update(R"({"udp_probe_count":3})");
    CHECK(call_count.load() == 1);
    CHECK(last_fields == 1);

    mgr.update(R"({"skip_udp_probe":true})");
    CHECK(call_count.load() == 2);
    CHECK(last_fields == 2);

    mgr.set_changed_callback(nullptr);  // 清理回调避免影响后续测试
}

// ============================================================================
// 24. ServerConfigManager：reset
// ============================================================================

static void test_manager_reset() {
    auto &mgr = ServerConfigManager::instance();
    // 单例可能残留前一个测试（test_manager_callback）下发的字段，
    // 必须先 reset 再 update，才能确保 set_field_count == 1
    mgr.reset();
    mgr.update(R"({"udp_probe_count":99})");
    CHECK(mgr.config().set_field_count() == 1);

    mgr.reset();
    CHECK(mgr.config().set_field_count() == 0);
    CHECK(!mgr.config().udp_probe_count.has_value());
}

// ============================================================================
// 25. ServerConfigManager：空 JSON update 合法
// ============================================================================

static void test_manager_empty_json() {
    auto &mgr = ServerConfigManager::instance();
    mgr.reset();
    mgr.update(R"({"udp_probe_count":5})");
    CHECK(mgr.config().set_field_count() == 1);

    // 空 JSON 不会清除已有配置（merge 语义）
    bool ok = mgr.update("{}");
    CHECK(ok == true);
    CHECK(mgr.config().set_field_count() == 1);  // 保留
    CHECK(*mgr.config().udp_probe_count == 5);
}

// ============================================================================
// 26. 线程安全：并发 update + config 无崩溃
// ============================================================================

static void test_thread_safety() {
    auto &mgr = ServerConfigManager::instance();
    mgr.reset();

    std::atomic<bool> stop{false};
    std::atomic<int> update_count{0};
    std::atomic<int> read_count{0};

    // 写线程：循环 update
    std::thread writer([&]() {
        int i = 0;
        while (!stop.load()) {
            std::string json = R"({"udp_probe_count":)" + std::to_string(i % 100) + "}";
            mgr.update(json);
            ++update_count;
            ++i;
        }
    });

    // 读线程：循环 config 快照
    std::thread reader([&]() {
        while (!stop.load()) {
            NatServerConfig cfg = mgr.config();
            (void)cfg.set_field_count();
            ++read_count;
        }
    });

    // 跑 200ms
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    stop.store(true);
    writer.join();
    reader.join();

    CHECK(update_count.load() > 0);
    CHECK(read_count.load() > 0);
    // 无崩溃即通过
}

// ============================================================================
// 27. set_field_count 准确性
// ============================================================================

static void test_set_field_count() {
    NatServerConfig cfg;
    CHECK(cfg.set_field_count() == 0);

    cfg.udp_probe_count = 5;
    CHECK(cfg.set_field_count() == 1);

    cfg.enable_fec_on_bad = true;
    cfg.skip_udp_probe = false;
    CHECK(cfg.set_field_count() == 3);

    cfg.udp_probe_count.reset();
    CHECK(cfg.set_field_count() == 2);
}

// ============================================================================
// 28. 端到端：from_json → merge → apply_to 链路
// ============================================================================

static void test_end_to_end_chain() {
    // 模拟服务器下发一份完整配置
    std::string server_json = R"({
        "udp_probe_count": 8,
        "udp_available_threshold": 0.75,
        "enable_fec_on_bad": false,
        "tcp_connect_timeout_ms": 4000,
        "ice_presume_writable_when_fully_relayed": true
    })";

    auto &mgr = ServerConfigManager::instance();
    mgr.reset();
    mgr.update(server_json);

    NatServerConfig cfg = mgr.config();
    CHECK(cfg.set_field_count() == 5);

    // 增量下发
    mgr.update(R"({"skip_udp_probe":true})");
    cfg = mgr.config();
    CHECK(cfg.set_field_count() == 6);

    // 应用到 UdpProbeConfig
    UdpProbeConfig udp_base;
    UdpProbeConfig udp_final = cfg.apply_to(udp_base);
    CHECK(udp_final.ping_count == 8);
    CHECK(udp_final.available_threshold == 0.75);

    // 应用到 FallbackConfig
    FallbackConfig fb_base;
    FallbackConfig fb_final = cfg.apply_to(fb_base);
    CHECK(fb_final.enable_fec_on_bad == false);
    CHECK(fb_final.tcp_connect_timeout == std::chrono::milliseconds(4000));
    CHECK(fb_final.skip_udp_probe == true);

    // 应用到 IceSessionConfig
    IceSessionConfig ice_base;
    IceSessionConfig ice_final = cfg.apply_to(ice_base);
    CHECK(ice_final.presume_writable_when_fully_relayed == true);

    mgr.reset();
}

int main() {
    test_default_construct();
    test_from_json_full();
    test_from_json_empty();
    test_from_json_unknown_fields();
    test_from_json_type_mismatch();
    test_from_json_partial();
    test_from_json_invalid();
    test_to_json_roundtrip();
    test_to_json_empty();
    test_merge_full_overwrite();
    test_merge_partial();
    test_merge_empty_override();
    test_merge_empty_base();
    test_apply_to_udp_probe();
    test_apply_to_udp_probe_partial();
    test_apply_to_fallback();
    test_apply_to_cgn();
    test_apply_to_port_predictor();
    test_apply_to_ice();
    test_apply_to_empty_keeps_base();
    test_manager_update_config();
    test_manager_update_merge();
    test_manager_callback();
    test_manager_reset();
    test_manager_empty_json();
    test_thread_safety();
    test_set_field_count();
    test_end_to_end_chain();

    std::printf("test_server_config: %d passed, %d failed\n",
                pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
