// test_config_propagation.cpp — ControlPlane + ConfigDistributor 集成测试（v2.1 Phase 2）
//
// 覆盖：
//   1. ControlPlane.distributor() 访问
//   2. set_orchestrator_pubkey / set_send_config_callback
//   3. HeartbeatPayloadV2 携带 config_epoch
//   4. on_heartbeat_received 更新节点 config_epoch
//   5. tick_once 向邻居传播缓存的 ConfigDelta
//   6. on_config_delta_received 应用到本地
//   7. 端到端：orchestrator → 区域代表 → 邻居
//   8. 落后节点检测（通过心跳 config_epoch）

#include "linoh/control_plane.hpp"
#include "linoh/config_distributor.hpp"
#include "linoh/base/key.hpp"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#define CHECK(cond) do { \
    ++total; \
    if (!(cond)) { \
        std::cerr << "FAIL: " << #cond << " (line " << __LINE__ << ")" << std::endl; \
        ++failed; \
    } \
} while(0)

static int total = 0;
static int failed = 0;

using namespace linoh;
using namespace linoh::base;

// ============================================================================
// 辅助函数
// ============================================================================

static EndpointId make_id(std::uint8_t seed) {
    std::array<uint8_t, 32> bytes{};
    bytes[0] = seed;
    bytes[31] = seed;
    return EndpointId::from_bytes(bytes);
}

static NodeProfile make_profile(std::uint8_t seed, GeoRegion region = GeoRegion::North,
                                 float stability = 0.8f) {
    NodeProfile p;
    p.endpoint_id = make_id(seed);
    p.geo.region = region;
    p.stability.score = stability;
    p.stability.uptime_seconds = 3600;
    p.stability.task_success_rate = 0.95f;
    p.stability.disconnect_count = 1;
    p.compute.gpu_model = "RTX 4090";
    p.compute.vram_mb = 24576;
    p.compute.tflops_fp16 = 165.0f;
    p.network.uplink_bps = 100000000;
    p.network.downlink_bps = 200000000;
    p.network.rtt_ms_avg = 20;
    return p;
}

class VirtualClock {
public:
    TimePoint now() const { return current_; }
    void advance(std::chrono::seconds s) { current_ += s; }
    void set(TimePoint t) { current_ = t; }
private:
    TimePoint current_{std::chrono::system_clock::time_point::min()};
};

/// 构造已签名的 ConfigDelta
/// @param base_version 第一个 entry 的 version，后续 entry 递增
static ConfigDelta make_signed_delta(
    std::uint64_t from_epoch,
    std::uint64_t to_epoch,
    const std::vector<std::pair<std::string, std::string>> &changes,
    const std::vector<std::string> &deletions,
    const SecretKey &orch_key,
    std::uint64_t base_version = 1) {

    ConfigDelta delta;
    delta.from_epoch = from_epoch;
    delta.to_epoch = to_epoch;

    auto now = std::chrono::system_clock::now();
    std::uint64_t ver = base_version;
    for (const auto &[k, v] : changes) {
        ConfigEntry e;
        e.key = k;
        e.value = v;
        e.version = ver++;
        e.updated_at = now;
        delta.changes.push_back(e);
    }
    delta.deletions = deletions;

    auto sig_data = delta.signing_data();
    auto sig = orch_key.sign(sig_data);
    std::memcpy(delta.signature.data(), sig.data(), 64);
    return delta;
}

// ============================================================================
// 1. ControlPlane.distributor() 访问
// ============================================================================

void test_control_plane_distributor_access() {
    std::cout << "[test] ControlPlane.distributor() is accessible" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    ControlPlane cp(cfg);

    ConfigDistributor &dist = cp.distributor();
    CHECK(dist.current_epoch() == 0);

    const ConfigDistributor &cdist = const_cast<const ControlPlane &>(cp).distributor();
    CHECK(cdist.current_epoch() == 0);
}

// ============================================================================
// 2. set_orchestrator_pubkey / set_send_config_callback
// ============================================================================

void test_set_orchestrator_pubkey() {
    std::cout << "[test] set_orchestrator_pubkey stores key" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    ControlPlane cp(cfg);

    auto orch_key = SecretKey::generate();
    cp.set_orchestrator_pubkey(orch_key.public_key());

    // 验证：应用一个合法签名的 delta 应成功
    auto delta = make_signed_delta(0, 1, {{"k1", "v1"}}, {}, orch_key);
    cp.on_config_delta_received(delta, make_id(99));
    CHECK(cp.distributor().current_epoch() == 1);
}

void test_set_send_config_callback() {
    std::cout << "[test] set_send_config_callback stores callback" << std::endl;
    VirtualClock clock;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.heartbeat_interval = std::chrono::seconds(1);
    ControlPlane cp(cfg, [&clock]() { return clock.now(); });

    auto self = make_profile(1);
    auto neighbor = make_profile(2);
    cp.start(self.endpoint_id, self);
    cp.register_node(neighbor);
    cp.registry().add_neighbor(self.endpoint_id, neighbor.endpoint_id);

    std::atomic<int> cb_count{0};
    cp.set_send_config_callback([&](const EndpointId &target, const ConfigDelta &delta) {
        ++cb_count;
    });

    // 无缓存 delta → 不调用 callback
    clock.advance(std::chrono::seconds(2));
    cp.tick_once();
    CHECK(cb_count.load() == 0);
}

// ============================================================================
// 3. HeartbeatPayloadV2 携带 config_epoch
// ============================================================================

void test_heartbeat_includes_config_epoch() {
    std::cout << "[test] heartbeat includes config_epoch" << std::endl;
    VirtualClock clock;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.heartbeat_interval = std::chrono::seconds(5);
    ControlPlane cp(cfg, [&clock]() { return clock.now(); });

    auto orch_key = SecretKey::generate();
    cp.set_orchestrator_pubkey(orch_key.public_key());

    auto self = make_profile(1);
    auto neighbor = make_profile(2);
    cp.start(self.endpoint_id, self);
    cp.register_node(neighbor);
    cp.registry().add_neighbor(self.endpoint_id, neighbor.endpoint_id);

    // 应用一个 delta 使 config_epoch=3
    auto delta = make_signed_delta(0, 3, {{"k1", "v1"}}, {}, orch_key);
    cp.on_config_delta_received(delta, make_id(99));
    CHECK(cp.distributor().current_epoch() == 3);

    std::uint64_t captured_epoch = 0;
    cp.set_send_callback([&](const EndpointId &, const HeartbeatPayloadV2 &hb) {
        captured_epoch = hb.config_epoch;
    });

    clock.advance(std::chrono::seconds(6));
    cp.tick_once();

    CHECK(captured_epoch == 3);
}

// ============================================================================
// 4. on_heartbeat_received 更新节点 config_epoch
// ============================================================================

void test_on_heartbeat_updates_node_config_epoch() {
    std::cout << "[test] on_heartbeat_received updates node config_epoch" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    ControlPlane cp(cfg);

    auto self = make_profile(1);
    cp.start(self.endpoint_id, self);

    auto other = make_profile(2);
    cp.register_node(other);

    // 模拟收到 other 的心跳，携带 config_epoch=5
    HeartbeatPayloadV2 hb;
    hb.sender_id = other.endpoint_id;
    hb.region = GeoRegion::North;
    hb.stability_score = 0.8f;
    hb.config_epoch = 5;
    cp.on_heartbeat_received(hb);

    // 应用一个 delta 使本地 epoch=7
    auto orch_key = SecretKey::generate();
    cp.set_orchestrator_pubkey(orch_key.public_key());
    auto delta = make_signed_delta(0, 7, {{"k1", "v1"}}, {}, orch_key);
    cp.on_config_delta_received(delta, make_id(99));

    // other epoch=5, local epoch=7 → 落后 2
    auto lagging = cp.distributor().lagging_nodes(2);
    CHECK(std::find(lagging.begin(), lagging.end(), other.endpoint_id) != lagging.end());
}

// ============================================================================
// 5. tick_once 向邻居传播缓存的 ConfigDelta
// ============================================================================

void test_tick_once_propagates_delta_to_neighbor() {
    std::cout << "[test] tick_once propagates cached delta to neighbors" << std::endl;
    VirtualClock clock;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.heartbeat_interval = std::chrono::seconds(5);
    ControlPlane cp(cfg, [&clock]() { return clock.now(); });

    auto orch_key = SecretKey::generate();
    cp.set_orchestrator_pubkey(orch_key.public_key());

    auto self = make_profile(1);
    auto neighbor = make_profile(2);
    cp.start(self.endpoint_id, self);
    cp.register_node(neighbor);
    cp.registry().add_neighbor(self.endpoint_id, neighbor.endpoint_id);

    // 应用 delta（缓存）
    auto delta = make_signed_delta(0, 2, {{"k1", "v1"}}, {}, orch_key);
    cp.on_config_delta_received(delta, make_id(99));

    std::atomic<int> push_count{0};
    EndpointId captured_target;
    ConfigDelta captured_delta;
    cp.set_send_config_callback([&](const EndpointId &target, const ConfigDelta &d) {
        ++push_count;
        captured_target = target;
        captured_delta = d;
    });

    clock.advance(std::chrono::seconds(6));
    cp.tick_once();

    CHECK(push_count.load() == 1);
    CHECK(captured_target == neighbor.endpoint_id);
    CHECK(captured_delta.to_epoch == 2);
}

void test_tick_once_no_delta_no_push() {
    std::cout << "[test] tick_once does not push when no cached delta" << std::endl;
    VirtualClock clock;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.heartbeat_interval = std::chrono::seconds(1);
    ControlPlane cp(cfg, [&clock]() { return clock.now(); });

    auto self = make_profile(1);
    auto neighbor = make_profile(2);
    cp.start(self.endpoint_id, self);
    cp.register_node(neighbor);
    cp.registry().add_neighbor(self.endpoint_id, neighbor.endpoint_id);

    std::atomic<int> push_count{0};
    cp.set_send_config_callback([&](const EndpointId &, const ConfigDelta &) {
        ++push_count;
    });

    clock.advance(std::chrono::seconds(2));
    cp.tick_once();
    CHECK(push_count.load() == 0);  // 无缓存 delta
}

// ============================================================================
// 6. on_config_delta_received 应用到本地
// ============================================================================

void test_on_config_delta_received_applies_locally() {
    std::cout << "[test] on_config_delta_received applies delta locally" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    ControlPlane cp(cfg);

    auto orch_key = SecretKey::generate();
    cp.set_orchestrator_pubkey(orch_key.public_key());

    auto delta = make_signed_delta(0, 1, {{"control_plane.heartbeat_interval", "10"}}, {}, orch_key);
    cp.on_config_delta_received(delta, make_id(99));

    CHECK(cp.distributor().current_epoch() == 1);
    CHECK(cp.distributor().get_local("control_plane.heartbeat_interval").has_value());
    CHECK(*cp.distributor().get_local("control_plane.heartbeat_interval") == "10");
}

void test_on_config_delta_received_rejects_bad_signature() {
    std::cout << "[test] on_config_delta_received rejects bad signature" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    ControlPlane cp(cfg);

    auto orch_key = SecretKey::generate();
    auto wrong_key = SecretKey::generate();
    cp.set_orchestrator_pubkey(wrong_key.public_key());  // 错误公钥

    auto delta = make_signed_delta(0, 1, {{"k1", "v1"}}, {}, orch_key);
    cp.on_config_delta_received(delta, make_id(99));

    CHECK(cp.distributor().current_epoch() == 0);  // 验签失败，未应用
}

// ============================================================================
// 7. 端到端：orchestrator → 区域代表 → 邻居
// ============================================================================

void test_end_to_end_propagation() {
    std::cout << "[test] end-to-end: orchestrator → rep → neighbor" << std::endl;
    VirtualClock clock;

    // orchestrator 签名密钥
    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();
    auto orch_id = make_id(200);

    // 区域代表
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.heartbeat_interval = std::chrono::seconds(5);
    ControlPlane rep_cp(cfg, [&clock]() { return clock.now(); });
    auto rep = make_profile(1, GeoRegion::North, 0.95f);
    rep_cp.start(rep.endpoint_id, rep);
    rep_cp.set_orchestrator_pubkey(orch_pub);

    // 邻居节点
    ControlPlane neighbor_cp(cfg, [&clock]() { return clock.now(); });
    auto neighbor = make_profile(2, GeoRegion::North, 0.8f);
    neighbor_cp.start(neighbor.endpoint_id, neighbor);
    neighbor_cp.set_orchestrator_pubkey(orch_pub);

    // 建立邻居关系（双向）
    rep_cp.register_node(neighbor);
    rep_cp.registry().add_neighbor(rep.endpoint_id, neighbor.endpoint_id);

    // orchestrator 签发 delta
    auto delta = make_signed_delta(
        0, 5,
        {{"control_plane.heartbeat_interval", "10"},
         {"control_plane.gossip_fanout", "5"}},
        {}, orch_key);

    // orchestrator → 区域代表（推送 delta）
    rep_cp.on_config_delta_received(delta, orch_id);
    CHECK(rep_cp.distributor().current_epoch() == 5);
    CHECK(*rep_cp.distributor().get_local("control_plane.heartbeat_interval") == "10");

    // 区域代表 → 邻居（通过 tick_once 传播）
    std::atomic<int> push_count{0};
    rep_cp.set_send_config_callback([&](const EndpointId &target, const ConfigDelta &d) {
        ++push_count;
        // 模拟网络传输：邻居收到 delta
        neighbor_cp.on_config_delta_received(d, rep.endpoint_id);
    });

    clock.advance(std::chrono::seconds(6));
    rep_cp.tick_once();

    CHECK(push_count.load() == 1);
    CHECK(neighbor_cp.distributor().current_epoch() == 5);
    CHECK(*neighbor_cp.distributor().get_local("control_plane.heartbeat_interval") == "10");
    CHECK(*neighbor_cp.distributor().get_local("control_plane.gossip_fanout") == "5");
}

void test_end_to_end_multi_hop() {
    std::cout << "[test] end-to-end: multi-hop rep → neighbor1 → neighbor2" << std::endl;
    VirtualClock clock;

    auto orch_key = SecretKey::generate();
    auto orch_pub = orch_key.public_key();
    auto orch_id = make_id(200);

    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.heartbeat_interval = std::chrono::seconds(5);

    // 三节点链：rep → n1 → n2
    ControlPlane rep_cp(cfg, [&clock]() { return clock.now(); });
    auto rep = make_profile(1);
    rep_cp.start(rep.endpoint_id, rep);
    rep_cp.set_orchestrator_pubkey(orch_pub);

    ControlPlane n1_cp(cfg, [&clock]() { return clock.now(); });
    auto n1 = make_profile(2);
    n1_cp.start(n1.endpoint_id, n1);
    n1_cp.set_orchestrator_pubkey(orch_pub);

    ControlPlane n2_cp(cfg, [&clock]() { return clock.now(); });
    auto n2 = make_profile(3);
    n2_cp.start(n2.endpoint_id, n2);
    n2_cp.set_orchestrator_pubkey(orch_pub);

    // 邻居关系：rep-n1, n1-n2
    rep_cp.register_node(n1);
    rep_cp.registry().add_neighbor(rep.endpoint_id, n1.endpoint_id);

    n1_cp.register_node(n2);
    n1_cp.registry().add_neighbor(n1.endpoint_id, n2.endpoint_id);

    // orchestrator → rep
    auto delta = make_signed_delta(0, 3, {{"k1", "v1"}}, {}, orch_key);
    rep_cp.on_config_delta_received(delta, orch_id);

    // rep → n1
    rep_cp.set_send_config_callback([&](const EndpointId &, const ConfigDelta &d) {
        n1_cp.on_config_delta_received(d, rep.endpoint_id);
    });

    clock.advance(std::chrono::seconds(6));
    rep_cp.tick_once();

    CHECK(n1_cp.distributor().current_epoch() == 3);

    // n1 → n2
    n1_cp.set_send_config_callback([&](const EndpointId &, const ConfigDelta &d) {
        n2_cp.on_config_delta_received(d, n1.endpoint_id);
    });

    clock.advance(std::chrono::seconds(6));
    n1_cp.tick_once();

    CHECK(n2_cp.distributor().current_epoch() == 3);
    CHECK(*n2_cp.distributor().get_local("k1") == "v1");
}

// ============================================================================
// 8. 落后节点检测
// ============================================================================

void test_lagging_node_detected_via_heartbeat() {
    std::cout << "[test] lagging node detected via heartbeat config_epoch" << std::endl;
    VirtualClock clock;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.heartbeat_interval = std::chrono::seconds(5);
    ControlPlane cp(cfg, [&clock]() { return clock.now(); });

    auto orch_key = SecretKey::generate();
    cp.set_orchestrator_pubkey(orch_key.public_key());

    auto self = make_profile(1);
    cp.start(self.endpoint_id, self);

    auto n1 = make_profile(2);
    auto n2 = make_profile(3);
    cp.register_node(n1);
    cp.register_node(n2);

    // 本地 epoch=5
    auto delta = make_signed_delta(0, 5, {{"k1", "v1"}}, {}, orch_key);
    cp.on_config_delta_received(delta, make_id(99));

    // n1 心跳携带 config_epoch=5（最新）
    HeartbeatPayloadV2 hb1;
    hb1.sender_id = n1.endpoint_id;
    hb1.config_epoch = 5;
    cp.on_heartbeat_received(hb1);

    // n2 心跳携带 config_epoch=2（落后 3）
    HeartbeatPayloadV2 hb2;
    hb2.sender_id = n2.endpoint_id;
    hb2.config_epoch = 2;
    cp.on_heartbeat_received(hb2);

    auto lagging = cp.distributor().lagging_nodes(2);
    CHECK(lagging.size() == 1);
    CHECK(lagging[0] == n2.endpoint_id);
}

// ============================================================================
// 9. 热更新通知（通过 ControlPlane）
// ============================================================================

void test_hot_update_via_control_plane() {
    std::cout << "[test] hot-update subscription triggered via ControlPlane" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    ControlPlane cp(cfg);

    auto orch_key = SecretKey::generate();
    cp.set_orchestrator_pubkey(orch_key.public_key());

    std::atomic<int> notify_count{0};
    std::string received_value;
    cp.distributor().subscribe("control_plane.", [&](const std::string &,
                                                       const std::string &,
                                                       const std::string &new_val) {
        ++notify_count;
        received_value = new_val;
    });

    auto delta = make_signed_delta(0, 1, {{"control_plane.heartbeat_interval", "15"}}, {}, orch_key);
    cp.on_config_delta_received(delta, make_id(99));

    CHECK(notify_count.load() == 1);
    CHECK(received_value == "15");
}

// ============================================================================
// 10. disabled 控制面不传播配置
// ============================================================================

void test_disabled_control_plane_no_config_push() {
    std::cout << "[test] disabled control plane does not push config" << std::endl;
    VirtualClock clock;
    ControlPlaneConfig cfg;
    cfg.enabled = false;
    cfg.heartbeat_interval = std::chrono::seconds(1);
    ControlPlane cp(cfg, [&clock]() { return clock.now(); });

    auto self = make_profile(1);
    cp.start(self.endpoint_id, self);

    std::atomic<int> push_count{0};
    cp.set_send_config_callback([&](const EndpointId &, const ConfigDelta &) {
        ++push_count;
    });

    clock.advance(std::chrono::seconds(5));
    cp.tick_once();

    CHECK(push_count.load() == 0);
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << " test_config_propagation (v2.1 Phase 2)" << std::endl;
    std::cout << "========================================" << std::endl;

    // 1. distributor 访问
    test_control_plane_distributor_access();

    // 2. 配置接口
    test_set_orchestrator_pubkey();
    test_set_send_config_callback();

    // 3. 心跳携带 config_epoch
    test_heartbeat_includes_config_epoch();

    // 4. 心跳更新节点 config_epoch
    test_on_heartbeat_updates_node_config_epoch();

    // 5. tick_once 传播
    test_tick_once_propagates_delta_to_neighbor();
    test_tick_once_no_delta_no_push();

    // 6. on_config_delta_received
    test_on_config_delta_received_applies_locally();
    test_on_config_delta_received_rejects_bad_signature();

    // 7. 端到端
    test_end_to_end_propagation();
    test_end_to_end_multi_hop();

    // 8. 落后检测
    test_lagging_node_detected_via_heartbeat();

    // 9. 热更新
    test_hot_update_via_control_plane();

    // 10. 禁用控制面
    test_disabled_control_plane_no_config_push();

    std::cout << "========================================" << std::endl;
    std::cout << " Total: " << total << ", Failed: " << failed << std::endl;
    std::cout << "========================================" << std::endl;

    return failed == 0 ? 0 : 1;
}
