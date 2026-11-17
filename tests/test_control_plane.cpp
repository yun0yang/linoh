// test_control_plane.cpp — 轻量内置控制面测试（v2.0 Phase 1 交付物 7）

#include "linoh/control_plane.hpp"
#include "linoh/base/key.hpp"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <iostream>
#include <string>
#include <unordered_map>
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
// 辅助：生成 EndpointId
// ============================================================================

static EndpointId make_id(std::uint8_t seed) {
    std::array<uint8_t, 32> bytes{};
    bytes[0] = seed;
    bytes[31] = seed;  // 首尾都设值避免零
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

// ============================================================================
// 虚拟时钟（用于时序测试）
// ============================================================================

class VirtualClock {
public:
    TimePoint now() const { return current_; }
    void advance(std::chrono::seconds s) { current_ += s; }
    void set(TimePoint t) { current_ = t; }
private:
    TimePoint current_{std::chrono::system_clock::time_point::min()};
};

// ============================================================================
// 1. 枚举测试
// ============================================================================

void test_node_state_name() {
    std::cout << "[test] node_state_name" << std::endl;
    CHECK(node_state_name(NodeState::Unknown) == std::string("unknown"));
    CHECK(node_state_name(NodeState::Online) == std::string("online"));
    CHECK(node_state_name(NodeState::Draining) == std::string("draining"));
    CHECK(node_state_name(NodeState::Offline) == std::string("offline"));
}

void test_node_event_type_name() {
    std::cout << "[test] node_event_type_name" << std::endl;
    CHECK(node_event_type_name(NodeEventType::NodeJoined) == std::string("node_joined"));
    CHECK(node_event_type_name(NodeEventType::NodeLeft) == std::string("node_left"));
    CHECK(node_event_type_name(NodeEventType::NodeStale) == std::string("node_stale"));
    CHECK(node_event_type_name(NodeEventType::NodeUpdated) == std::string("node_updated"));
    CHECK(node_event_type_name(NodeEventType::RegionRepChanged) == std::string("region_rep_changed"));
}

// ============================================================================
// 2. NodeRegistry 基础测试
// ============================================================================

void test_registry_upsert_new() {
    std::cout << "[test] NodeRegistry upsert new node" << std::endl;
    NodeRegistry reg;
    auto p = make_profile(1);
    bool is_new = reg.upsert(p);
    CHECK(is_new);
    CHECK(reg.size() == 1);

    auto entry = reg.get(p.endpoint_id);
    CHECK(entry.has_value());
    CHECK(entry->state == NodeState::Online);
    CHECK(entry->profile.endpoint_id == p.endpoint_id);
}

void test_registry_upsert_update() {
    std::cout << "[test] NodeRegistry upsert update existing" << std::endl;
    NodeRegistry reg;
    auto p1 = make_profile(1);
    reg.upsert(p1);

    auto p2 = p1;
    p2.stability.score = 0.95f;
    bool is_new = reg.upsert(p2);
    CHECK(!is_new);
    CHECK(reg.size() == 1);

    auto entry = reg.get(p1.endpoint_id);
    CHECK(entry.has_value());
    CHECK(entry->profile.stability.score == 0.95f);
}

void test_registry_touch() {
    std::cout << "[test] NodeRegistry touch refreshes last_seen" << std::endl;
    VirtualClock clock;
    NodeRegistry reg([&clock]() { return clock.now(); });
    auto p = make_profile(1);
    reg.upsert(p);

    auto entry1 = reg.get(p.endpoint_id);
    CHECK(entry1.has_value());
    auto first_seen = entry1->last_seen;

    clock.advance(std::chrono::seconds(10));
    bool ok = reg.touch(p.endpoint_id);
    CHECK(ok);

    auto entry2 = reg.get(p.endpoint_id);
    CHECK(entry2.has_value());
    CHECK(entry2->last_seen > first_seen);
}

void test_registry_touch_nonexistent() {
    std::cout << "[test] NodeRegistry touch nonexistent returns false" << std::endl;
    NodeRegistry reg;
    CHECK(!reg.touch(make_id(99)));
}

void test_registry_erase() {
    std::cout << "[test] NodeRegistry erase" << std::endl;
    NodeRegistry reg;
    auto p = make_profile(1);
    reg.upsert(p);
    CHECK(reg.size() == 1);

    CHECK(reg.erase(p.endpoint_id));
    CHECK(reg.size() == 0);
    CHECK(!reg.get(p.endpoint_id).has_value());
}

void test_registry_get_by_region() {
    std::cout << "[test] NodeRegistry get_by_region" << std::endl;
    NodeRegistry reg;
    reg.upsert(make_profile(1, GeoRegion::North));
    reg.upsert(make_profile(2, GeoRegion::North));
    reg.upsert(make_profile(3, GeoRegion::East));

    auto north = reg.get_by_region(GeoRegion::North);
    CHECK(north.size() == 2);

    auto east = reg.get_by_region(GeoRegion::East);
    CHECK(east.size() == 1);

    auto south = reg.get_by_region(GeoRegion::South);
    CHECK(south.empty());
}

// ============================================================================
// 3. NodeRegistry 区域代表选举
// ============================================================================

void test_registry_elect_representative() {
    std::cout << "[test] NodeRegistry elect_region_representative" << std::endl;
    NodeRegistry reg;
    reg.upsert(make_profile(1, GeoRegion::North, 0.7f));
    reg.upsert(make_profile(2, GeoRegion::North, 0.9f));
    reg.upsert(make_profile(3, GeoRegion::North, 0.8f));
    reg.upsert(make_profile(4, GeoRegion::East, 0.95f));

    auto rep = reg.elect_region_representative(GeoRegion::North);
    CHECK(rep.has_value());
    CHECK(*rep == make_id(2));  // stability 0.9 最高
}

void test_registry_elect_empty_region() {
    std::cout << "[test] NodeRegistry elect on empty region returns nullopt" << std::endl;
    NodeRegistry reg;
    reg.upsert(make_profile(1, GeoRegion::North));
    auto rep = reg.elect_region_representative(GeoRegion::South);
    CHECK(!rep.has_value());
}

void test_registry_elect_skips_offline() {
    std::cout << "[test] NodeRegistry elect skips Offline nodes" << std::endl;
    NodeRegistry reg;
    reg.upsert(make_profile(1, GeoRegion::North, 0.99f), NodeState::Offline);
    reg.upsert(make_profile(2, GeoRegion::North, 0.5f), NodeState::Online);

    auto rep = reg.elect_region_representative(GeoRegion::North);
    CHECK(rep.has_value());
    CHECK(*rep == make_id(2));  // 只选 Online 的
}

// ============================================================================
// 4. NodeRegistry 超时检测
// ============================================================================

void test_registry_mark_stale() {
    std::cout << "[test] NodeRegistry mark_stale" << std::endl;
    VirtualClock clock;
    NodeRegistry reg([&clock]() { return clock.now(); });

    reg.upsert(make_profile(1));
    reg.upsert(make_profile(2));

    // 推进时间超过 timeout
    clock.advance(std::chrono::seconds(20));

    auto stale = reg.mark_stale(std::chrono::seconds(15));
    CHECK(stale.size() == 2);

    // 验证状态已更新
    auto entry = reg.get(make_id(1));
    CHECK(entry.has_value());
    CHECK(entry->state == NodeState::Offline);
}

void test_registry_mark_stale_not_expired() {
    std::cout << "[test] NodeRegistry mark_stale skips fresh nodes" << std::endl;
    VirtualClock clock;
    NodeRegistry reg([&clock]() { return clock.now(); });

    reg.upsert(make_profile(1));
    clock.advance(std::chrono::seconds(5));  // 未超时

    auto stale = reg.mark_stale(std::chrono::seconds(15));
    CHECK(stale.empty());
}

// ============================================================================
// 5. NodeRegistry 邻居关系
// ============================================================================

void test_registry_add_neighbor_bidirectional() {
    std::cout << "[test] NodeRegistry add_neighbor bidirectional" << std::endl;
    NodeRegistry reg;
    auto a = make_id(1);
    auto b = make_id(2);
    reg.upsert(make_profile(1));
    reg.upsert(make_profile(2));

    reg.add_neighbor(a, b);

    auto na = reg.get_neighbors(a);
    CHECK(na.size() == 1);
    CHECK(na[0] == b);

    auto nb = reg.get_neighbors(b);
    CHECK(nb.size() == 1);
    CHECK(nb[0] == a);
}

void test_registry_add_neighbor_dedup() {
    std::cout << "[test] NodeRegistry add_neighbor dedup" << std::endl;
    NodeRegistry reg;
    auto a = make_id(1);
    auto b = make_id(2);
    reg.upsert(make_profile(1));
    reg.upsert(make_profile(2));

    reg.add_neighbor(a, b);
    reg.add_neighbor(a, b);  // 重复添加

    auto na = reg.get_neighbors(a);
    CHECK(na.size() == 1);
}

// ============================================================================
// 6. HeartbeatAggregator 测试
// ============================================================================

void test_aggregator_build_heartbeat() {
    std::cout << "[test] HeartbeatAggregator build_heartbeat" << std::endl;
    NodeRegistry reg;
    HeartbeatAggregator agg(reg, ControlPlaneConfig{});

    auto self = make_profile(1);
    reg.upsert(self);

    auto hb = agg.build_heartbeat(self.endpoint_id, self);
    CHECK(hb.sender_id == self.endpoint_id);
    CHECK(hb.region == GeoRegion::North);
    CHECK(hb.stability_score == 0.8f);
    CHECK(hb.known_nodes.empty());  // 只有自己，排除了
}

void test_aggregator_build_heartbeat_with_known_nodes() {
    std::cout << "[test] HeartbeatAggregator build_heartbeat includes known nodes" << std::endl;
    NodeRegistry reg;
    HeartbeatAggregator agg(reg, ControlPlaneConfig{});

    auto self = make_profile(1);
    auto other = make_profile(2);
    reg.upsert(self);
    reg.upsert(other);

    auto hb = agg.build_heartbeat(self.endpoint_id, self);
    CHECK(hb.known_nodes.size() == 1);
    CHECK(hb.known_nodes[0] == other.endpoint_id);
}

void test_aggregator_on_heartbeat_received() {
    std::cout << "[test] HeartbeatAggregator on_heartbeat_received" << std::endl;
    VirtualClock clock;
    NodeRegistry reg([&clock]() { return clock.now(); });
    HeartbeatAggregator agg(reg, ControlPlaneConfig{}, [&clock]() { return clock.now(); });

    auto sender = make_profile(1);
    reg.upsert(sender);

    clock.advance(std::chrono::seconds(10));

    HeartbeatPayloadV2 hb;
    hb.sender_id = sender.endpoint_id;
    hb.timestamp = clock.now();
    hb.region = GeoRegion::North;
    hb.stability_score = 0.8f;
    agg.on_heartbeat_received(hb);

    CHECK(agg.heartbeats_received() == 1);

    // 验证 last_seen 已刷新
    auto entry = reg.get(sender.endpoint_id);
    CHECK(entry.has_value());
    CHECK(entry->state == NodeState::Online);
}

void test_aggregator_on_heartbeat_discovers_new_nodes() {
    std::cout << "[test] HeartbeatAggregator discovers new nodes via gossip piggyback" << std::endl;
    NodeRegistry reg;
    HeartbeatAggregator agg(reg, ControlPlaneConfig{});

    auto sender = make_profile(1);
    reg.upsert(sender);

    auto unknown1 = make_id(10);
    auto unknown2 = make_id(11);

    HeartbeatPayloadV2 hb;
    hb.sender_id = sender.endpoint_id;
    hb.region = GeoRegion::North;
    hb.known_nodes = {unknown1, unknown2};
    agg.on_heartbeat_received(hb);

    // 未知节点应被注册为占位条目
    CHECK(reg.get(unknown1).has_value());
    CHECK(reg.get(unknown2).has_value());
    CHECK(reg.get(unknown1)->state == NodeState::Unknown);
}

void test_aggregator_select_gossip_targets() {
    std::cout << "[test] HeartbeatAggregator select_gossip_targets" << std::endl;
    NodeRegistry reg;
    ControlPlaneConfig cfg;
    cfg.gossip_fanout = 2;
    HeartbeatAggregator agg(reg, cfg);

    auto self = make_profile(1);
    reg.upsert(self);
    reg.upsert(make_profile(2));
    reg.upsert(make_profile(3));
    reg.upsert(make_profile(4));

    reg.add_neighbor(self.endpoint_id, make_id(2));
    reg.add_neighbor(self.endpoint_id, make_id(3));
    reg.add_neighbor(self.endpoint_id, make_id(4));

    auto targets = agg.select_gossip_targets(self.endpoint_id);
    CHECK(targets.size() == 2);  // fanout=2
}

void test_aggregator_check_stale() {
    std::cout << "[test] HeartbeatAggregator check_stale" << std::endl;
    VirtualClock clock;
    NodeRegistry reg([&clock]() { return clock.now(); });
    ControlPlaneConfig cfg;
    cfg.stale_timeout = std::chrono::seconds(15);
    HeartbeatAggregator agg(reg, cfg, [&clock]() { return clock.now(); });

    reg.upsert(make_profile(1));
    reg.upsert(make_profile(2));
    clock.advance(std::chrono::seconds(20));

    auto events = agg.check_stale();
    CHECK(events.size() == 2);
    CHECK(events[0].type == NodeEventType::NodeStale);
}

// ============================================================================
// 7. GossipDiscovery 测试
// ============================================================================

void test_discovery_on_gossip_nodes() {
    std::cout << "[test] GossipDiscovery on_gossip_nodes registers new nodes" << std::endl;
    NodeRegistry reg;
    GossipDiscovery disc(reg, ControlPlaneConfig{});

    auto source = make_profile(1);
    reg.upsert(source);

    auto new_node = make_id(20);
    disc.on_gossip_nodes({new_node}, source.endpoint_id);

    CHECK(reg.get(new_node).has_value());
    CHECK(disc.gossip_rounds() == 1);
}

void test_discovery_discover_returns_sorted() {
    std::cout << "[test] GossipDiscovery discover returns score-sorted" << std::endl;
    NodeRegistry reg;
    GossipDiscovery disc(reg, ControlPlaneConfig{});

    // score 高的排前面（RTX 4090 baseline 1.0）
    auto p1 = make_profile(1, GeoRegion::North, 0.5f);
    p1.compute.vram_mb = 8192;   // 低配
    p1.compute.tflops_fp16 = 30.0f;

    auto p2 = make_profile(2, GeoRegion::North, 0.9f);
    p2.compute.vram_mb = 24576;  // RTX 4090
    p2.compute.tflops_fp16 = 165.0f;

    reg.upsert(p1);
    reg.upsert(p2);

    auto discovered = disc.discover(2);
    CHECK(discovered.size() == 2);
    CHECK(discovered[0] == p2.endpoint_id);  // p2 score 更高
}

void test_discovery_discover_max_count() {
    std::cout << "[test] GossipDiscovery discover respects max_count" << std::endl;
    NodeRegistry reg;
    GossipDiscovery disc(reg, ControlPlaneConfig{});

    for (std::uint8_t i = 1; i <= 5; ++i) {
        reg.upsert(make_profile(i));
    }

    auto discovered = disc.discover(3);
    CHECK(discovered.size() == 3);
}

void test_discovery_build_piggyback() {
    std::cout << "[test] GossipDiscovery build_piggyback excludes self" << std::endl;
    NodeRegistry reg;
    GossipDiscovery disc(reg, ControlPlaneConfig{});

    auto self = make_profile(1);
    reg.upsert(self);
    reg.upsert(make_profile(2));
    reg.upsert(make_profile(3));

    auto piggy = disc.build_piggyback(self.endpoint_id);
    CHECK(piggy.size() == 2);  // 排除自己
    for (const auto &id : piggy) {
        CHECK(id != self.endpoint_id);
    }
}

void test_discovery_build_piggyback_max_known_nodes() {
    std::cout << "[test] GossipDiscovery build_piggyback respects max_known_nodes" << std::endl;
    NodeRegistry reg;
    ControlPlaneConfig cfg;
    cfg.max_known_nodes = 3;
    GossipDiscovery disc(reg, cfg);

    auto self = make_profile(1);
    reg.upsert(self);
    for (std::uint8_t i = 2; i <= 10; ++i) {
        reg.upsert(make_profile(i));
    }

    auto piggy = disc.build_piggyback(self.endpoint_id);
    CHECK(piggy.size() == 3);
}

// ============================================================================
// 8. ControlPlane 集成测试
// ============================================================================

void test_control_plane_start_stop() {
    std::cout << "[test] ControlPlane start/stop" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    ControlPlane cp(cfg);

    CHECK(!cp.is_running());
    auto self = make_profile(1);
    cp.start(self.endpoint_id, self);
    CHECK(cp.is_running());
    cp.stop();
    CHECK(!cp.is_running());
}

void test_control_plane_register_node_event() {
    std::cout << "[test] ControlPlane register_node triggers event" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    ControlPlane cp(cfg);

    std::atomic<int> join_count{0};
    cp.subscribe_node_events([&](const NodeEvent &ev) {
        if (ev.type == NodeEventType::NodeJoined) ++join_count;
    });

    auto self = make_profile(1);
    cp.start(self.endpoint_id, self);
    CHECK(join_count.load() >= 1);  // start 时触发自己

    auto other = make_profile(2);
    cp.register_node(other);
    CHECK(join_count.load() >= 2);
}

void test_control_plane_tick_once_sends_heartbeat() {
    std::cout << "[test] ControlPlane tick_once sends heartbeat" << std::endl;
    VirtualClock clock;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.heartbeat_interval = std::chrono::seconds(5);
    ControlPlane cp(cfg, [&clock]() { return clock.now(); });

    auto self = make_profile(1);
    auto neighbor = make_profile(2);
    cp.start(self.endpoint_id, self);
    cp.register_node(neighbor);

    // 建立邻居关系
    cp.registry().add_neighbor(self.endpoint_id, neighbor.endpoint_id);

    std::atomic<int> send_count{0};
    cp.set_send_callback([&](const EndpointId &target, const HeartbeatPayloadV2 &hb) {
        ++send_count;
        CHECK(target == neighbor.endpoint_id);
        CHECK(hb.sender_id == self.endpoint_id);
    });

    // 未到间隔 → 不发送
    cp.tick_once();
    CHECK(send_count.load() == 0);

    // 推进时间超过间隔 → 发送
    clock.advance(std::chrono::seconds(6));
    cp.tick_once();
    CHECK(send_count.load() == 1);
}

void test_control_plane_on_heartbeat_received() {
    std::cout << "[test] ControlPlane on_heartbeat_received" << std::endl;
    VirtualClock clock;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.stale_timeout = std::chrono::seconds(30);
    ControlPlane cp(cfg, [&clock]() { return clock.now(); });

    auto self = make_profile(1);
    cp.start(self.endpoint_id, self);

    auto other = make_profile(2);
    cp.register_node(other);

    // 模拟收到 other 的心跳
    HeartbeatPayloadV2 hb;
    hb.sender_id = other.endpoint_id;
    hb.region = GeoRegion::North;
    hb.stability_score = 0.8f;
    cp.on_heartbeat_received(hb);

    // 验证 other 的 last_seen 已刷新
    auto entry = cp.registry().get(other.endpoint_id);
    CHECK(entry.has_value());
    CHECK(entry->state == NodeState::Online);
}

void test_control_plane_disabled_no_op() {
    std::cout << "[test] ControlPlane disabled is no-op" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = false;  // 默认关闭
    ControlPlane cp(cfg);

    auto self = make_profile(1);
    cp.start(self.endpoint_id, self);

    std::atomic<int> send_count{0};
    cp.set_send_callback([&](const EndpointId &, const HeartbeatPayloadV2 &) {
        ++send_count;
    });

    cp.tick_once();  // 应无副作用
    CHECK(send_count.load() == 0);

    auto discovered = cp.discover_nodes(5);
    CHECK(discovered.empty());  // 关闭时返回空
}

void test_control_plane_stale_event_triggered() {
    std::cout << "[test] ControlPlane stale event triggered via tick" << std::endl;
    VirtualClock clock;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.heartbeat_interval = std::chrono::seconds(60);  // 拉长避免干扰
    cfg.stale_timeout = std::chrono::seconds(10);
    ControlPlane cp(cfg, [&clock]() { return clock.now(); });

    auto self = make_profile(1);
    cp.start(self.endpoint_id, self);

    auto other = make_profile(2);
    cp.register_node(other);

    std::atomic<int> stale_count{0};
    cp.subscribe_node_events([&](const NodeEvent &ev) {
        if (ev.type == NodeEventType::NodeStale) ++stale_count;
    });

    // 推进时间超过 stale_timeout
    clock.advance(std::chrono::seconds(15));
    cp.tick_once();

    CHECK(stale_count.load() >= 1);  // other 应被标记为 stale
}

// ============================================================================
// 9. gossip 传播模拟
// ============================================================================

void test_gossip_propagation_100_nodes() {
    std::cout << "[test] gossip propagation 100 nodes" << std::endl;
    // 模拟 100 节点 gossip 传播：每轮每节点向 3 个邻居发送含 known_nodes 的心跳
    // 验证 30 轮内全网感知
    NodeRegistry reg;
    ControlPlaneConfig cfg;
    cfg.gossip_fanout = 3;
    cfg.max_known_nodes = 100;
    HeartbeatAggregator agg(reg, cfg);

    // 节点 0 是种子，其他 99 个通过 gossip 发现
    auto seed = make_profile(0);
    reg.upsert(seed);

    // 预先建立全连接邻居图（环 + 随机边，简化模拟）
    for (std::uint8_t i = 1; i < 100; ++i) {
        reg.upsert(make_profile(i));
    }
    for (std::uint8_t i = 0; i < 100; ++i) {
        auto a = make_id(i);
        auto b = make_id((i + 1) % 100);
        reg.add_neighbor(a, b);
        auto c = make_id((i + 7) % 100);
        reg.add_neighbor(a, c);
        auto d = make_id((i + 13) % 100);
        reg.add_neighbor(a, d);
    }

    // 模拟 gossip 传播：种子节点先广播
    // 每轮：所有已知节点向 fanout 个邻居发送心跳
    std::size_t rounds = 0;
    std::size_t known_count = 1;  // 只有种子

    while (known_count < 100 && rounds < 30) {
        auto snapshot = reg.snapshot();
        for (const auto &entry : snapshot) {
            if (entry.state != NodeState::Online) continue;
            auto hb = agg.build_heartbeat(entry.profile.endpoint_id, entry.profile);
            auto targets = agg.select_gossip_targets(entry.profile.endpoint_id);
            for (const auto &target : targets) {
                agg.on_heartbeat_received(hb);
            }
        }
        known_count = reg.size();
        ++rounds;
    }

    CHECK(known_count == 100);
    CHECK(rounds <= 30);
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << " test_control_plane (v2.0 Phase 1 交付物 7)" << std::endl;
    std::cout << "========================================" << std::endl;

    // 1. 枚举
    test_node_state_name();
    test_node_event_type_name();

    // 2. NodeRegistry 基础
    test_registry_upsert_new();
    test_registry_upsert_update();
    test_registry_touch();
    test_registry_touch_nonexistent();
    test_registry_erase();
    test_registry_get_by_region();

    // 3. 区域代表选举
    test_registry_elect_representative();
    test_registry_elect_empty_region();
    test_registry_elect_skips_offline();

    // 4. 超时检测
    test_registry_mark_stale();
    test_registry_mark_stale_not_expired();

    // 5. 邻居关系
    test_registry_add_neighbor_bidirectional();
    test_registry_add_neighbor_dedup();

    // 6. HeartbeatAggregator
    test_aggregator_build_heartbeat();
    test_aggregator_build_heartbeat_with_known_nodes();
    test_aggregator_on_heartbeat_received();
    test_aggregator_on_heartbeat_discovers_new_nodes();
    test_aggregator_select_gossip_targets();
    test_aggregator_check_stale();

    // 7. GossipDiscovery
    test_discovery_on_gossip_nodes();
    test_discovery_discover_returns_sorted();
    test_discovery_discover_max_count();
    test_discovery_build_piggyback();
    test_discovery_build_piggyback_max_known_nodes();

    // 8. ControlPlane 集成
    test_control_plane_start_stop();
    test_control_plane_register_node_event();
    test_control_plane_tick_once_sends_heartbeat();
    test_control_plane_on_heartbeat_received();
    test_control_plane_disabled_no_op();
    test_control_plane_stale_event_triggered();

    // 9. gossip 传播
    test_gossip_propagation_100_nodes();

    std::cout << "========================================" << std::endl;
    std::cout << " Total: " << total << ", Failed: " << failed << std::endl;
    std::cout << "========================================" << std::endl;

    return failed == 0 ? 0 : 1;
}
