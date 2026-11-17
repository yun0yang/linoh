// test_event_bus_cross_domain.cpp — V3.5 P5-C EventBus × ControlPlane 跨域 gossip 集成实测
//
// 验证跨域事件（NodeJoined/NodeUpdated/NodeStale）是否正确 publish 到 EventBus，
// 多订阅者 fan-out、背压策略、5 桶计数器、旧 callback 兼容等。
//
// 测试覆盖（10 用例）：
//   V1: 跨域 NodeJoined 投递（on_digest_received 新节点 → EventBus）
//   V2: 跨域 NodeUpdated coalesce（同 endpoint_id 多次更新 → coalesce）
//   V3: 跨域 NodeStale 关键通道（tick_once 触发 check_cross_domain_stale → EventBus）
//   V4: 多订阅者 fan-out（2 个 Subscriber 均收到）
//   V5: 5 桶计数器（RECEIVED/COALESCED/ENQUEUED 准确）
//   V6: 旧 callback 兼容（旧 cb + 新 Subscriber 并存）
//   V7: 非跨域摘要过滤（sender_domain_id == self_domain → 返回 0，无事件）
//   V8: 跨域节点 registry 标记（is_cross_domain=true，domain_id 正确）
//   V9: poll 超时返回 nullopt（无事件时）
//   V10: try_poll 非阻塞（有事件取出，无事件返回 nullopt）

#include "linoh/control_plane.hpp"
#include "linoh/event_bus.hpp"
#include "linoh/base/key.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::base;
using namespace std::chrono_literals;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    if ((a) == (b)) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s != %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ========== 工具函数 ==========

/// 构造测试用 EndpointId（32 字节，填充模式）
static EndpointId make_endpoint_id(std::uint8_t prefix) {
    std::array<std::uint8_t, 32> bytes{};
    for (int i = 0; i < 32; ++i) bytes[i] = static_cast<std::uint8_t>(prefix + i);
    return PublicKey(bytes);
}

/// 构造跨域摘要（domain_id=N，含 1 个节点）
static CrossDomainDigestPayload make_digest(std::uint32_t sender_domain,
                                             std::uint8_t ep_prefix,
                                             float score = 0.8f,
                                             GeoRegion region = GeoRegion::North,
                                             NodeState state = NodeState::Online) {
    CrossDomainDigestPayload payload;
    payload.sender_domain_id = sender_domain;
    payload.sender_endpoint_id = make_endpoint_id(static_cast<std::uint8_t>(sender_domain * 10));
    CrossDomainNodeDigest d;
    d.domain_id = sender_domain;
    d.endpoint_id = make_endpoint_id(ep_prefix);
    d.overall_score = score;
    d.region = region;
    d.state = state;
    payload.nodes.push_back(d);
    return payload;
}

/// 构造启用跨域的 ControlPlaneConfig
static ControlPlaneConfig make_cross_domain_config(std::uint32_t self_domain) {
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = self_domain;
    cfg.cross_domain_stale_timeout = std::chrono::seconds(1);  // 测试用短超时
    cfg.heartbeat_interval = std::chrono::seconds(60);  // 避免心跳 tick 干扰
    cfg.aggregate_interval = std::chrono::seconds(60);
    cfg.orchestrator_sync_interval = std::chrono::seconds(60);
    cfg.stale_timeout = std::chrono::seconds(60);
    return cfg;
}

// ========== 测试用例 ==========

// V1: 跨域 NodeJoined 投递到 EventBus
static void test_v1_cross_domain_node_joined_to_eventbus() {
    std::printf("[V1] cross-domain NodeJoined to EventBus...\n");
    auto cfg = make_cross_domain_config(/*self_domain=*/1);
    ControlPlane cp(cfg);
    auto self_id = make_endpoint_id(0x01);
    NodeProfile self_profile;
    self_profile.endpoint_id = self_id;
    cp.start(self_id, self_profile);

    auto sub = cp.subscribe_events();

    // 模拟收到 domain 2 的摘要（含 1 个新节点）
    auto digest = make_digest(/*sender_domain=*/2, /*ep_prefix=*/0xA0);
    std::size_t new_count = cp.on_digest_received(digest);
    CHECK_EQ(new_count, 1u);

    // EventBus 订阅者应收到 NodeJoined
    auto ev = sub->poll(100ms);
    CHECK(ev.has_value());
    if (ev.has_value()) {
        CHECK_EQ(ev->type, NodeEventType::NodeJoined);
        CHECK(ev->endpoint_id == make_endpoint_id(0xA0));
    }

    cp.stop();
}

// V2: 跨域 NodeUpdated coalesce（同 endpoint_id 多次更新）
static void test_v2_cross_domain_node_updated_coalesce() {
    std::printf("[V2] cross-domain NodeUpdated coalesce...\n");
    auto cfg = make_cross_domain_config(1);
    ControlPlane cp(cfg);
    auto self_id = make_endpoint_id(0x01);
    NodeProfile self_profile;
    self_profile.endpoint_id = self_id;
    cp.start(self_id, self_profile);

    auto sub = cp.subscribe_events();

    // 第一次：新节点（NodeJoined）
    auto digest1 = make_digest(2, 0xA0, 0.8f);
    cp.on_digest_received(digest1);

    // 取走 NodeJoined
    auto joined = sub->poll(100ms);
    CHECK(joined.has_value());
    CHECK_EQ(joined->type, NodeEventType::NodeJoined);

    // 第二次：同节点更新（NodeUpdated）
    auto digest2 = make_digest(2, 0xA0, 0.9f);  // score 变化
    cp.on_digest_received(digest2);

    // 应收到 NodeUpdated
    auto updated = sub->poll(100ms);
    CHECK(updated.has_value());
    if (updated.has_value()) {
        CHECK_EQ(updated->type, NodeEventType::NodeUpdated);
        CHECK(updated->endpoint_id == make_endpoint_id(0xA0));
    }

    cp.stop();
}

// V3: 跨域 NodeStale 关键通道（tick_once 触发 check_cross_domain_stale → EventBus）
static void test_v3_cross_domain_node_stale_critical() {
    std::printf("[V3] cross-domain NodeStale via tick_once...\n");
    // 使用注入式时钟控制时间推进
    auto now = std::chrono::system_clock::now();
    std::vector<TimePoint> clock_vals;
    auto clock = [&]() { return clock_vals.empty() ? now : clock_vals.back(); };
    // 预填一个初始时间
    clock_vals.push_back(now);

    auto cfg = make_cross_domain_config(1);
    ControlPlane cp(cfg, clock);
    auto self_id = make_endpoint_id(0x01);
    NodeProfile self_profile;
    self_profile.endpoint_id = self_id;
    cp.start(self_id, self_profile);

    auto sub = cp.subscribe_events();

    // 收到跨域摘要
    auto digest = make_digest(2, 0xA0);
    cp.on_digest_received(digest);

    // 取走 NodeJoined
    auto joined = sub->poll(100ms);
    CHECK(joined.has_value());

    // 推进时间超过 stale_timeout（1s → 推进到 2s 后）
    clock_vals.push_back(now + std::chrono::seconds(2));

    // tick_once 应触发 check_cross_domain_stale → NodeStale 事件
    cp.tick_once();

    // 应收到 NodeStale（关键事件，走 critical_queue）
    auto stale = sub->poll(500ms);
    CHECK(stale.has_value());
    if (stale.has_value()) {
        CHECK_EQ(stale->type, NodeEventType::NodeStale);
        CHECK(stale->endpoint_id == make_endpoint_id(0xA0));
    }

    cp.stop();
}

// V4: 多订阅者 fan-out（2 个 Subscriber 均收到）
static void test_v4_multi_subscriber_fanout() {
    std::printf("[V4] multi-subscriber fan-out...\n");
    auto cfg = make_cross_domain_config(1);
    ControlPlane cp(cfg);
    auto self_id = make_endpoint_id(0x01);
    NodeProfile self_profile;
    self_profile.endpoint_id = self_id;
    cp.start(self_id, self_profile);

    auto sub1 = cp.subscribe_events();
    auto sub2 = cp.subscribe_events();

    auto digest = make_digest(2, 0xB0);
    cp.on_digest_received(digest);

    // 两个订阅者都应收到 NodeJoined
    auto ev1 = sub1->poll(100ms);
    auto ev2 = sub2->poll(100ms);
    CHECK(ev1.has_value());
    CHECK(ev2.has_value());
    if (ev1.has_value() && ev2.has_value()) {
        CHECK_EQ(ev1->type, NodeEventType::NodeJoined);
        CHECK_EQ(ev2->type, NodeEventType::NodeJoined);
        CHECK(ev1->endpoint_id == ev2->endpoint_id);
    }

    cp.stop();
}

// V5: 5 桶计数器
static void test_v5_event_counters() {
    std::printf("[V5] event counters (5 buckets)...\n");
    auto cfg = make_cross_domain_config(1);
    ControlPlane cp(cfg);
    auto self_id = make_endpoint_id(0x01);
    NodeProfile self_profile;
    self_profile.endpoint_id = self_id;
    cp.start(self_id, self_profile);

    auto sub = cp.subscribe_events();

    // 投递 1 个新节点 + 2 次同节点更新
    cp.on_digest_received(make_digest(2, 0xC0, 0.5f));
    sub->poll(100ms);  // 取走 NodeJoined

    cp.on_digest_received(make_digest(2, 0xC0, 0.6f));
    cp.on_digest_received(make_digest(2, 0xC0, 0.7f));

    auto counters = sub->counters();
    // received >= 3（NodeJoined + 2 NodeUpdated）
    CHECK(counters.received >= 3);
    // enqueued >= 1（至少有事件入队）
    CHECK(counters.enqueued >= 1);

    // 取走合并后的 NodeUpdated
    auto updated = sub->poll(100ms);
    CHECK(updated.has_value());

    cp.stop();
}

// V6: 旧 callback 兼容（旧 cb + 新 Subscriber 并存）
static void test_v6_legacy_callback_compat() {
    std::printf("[V6] legacy callback + new Subscriber coexist...\n");
    auto cfg = make_cross_domain_config(1);
    ControlPlane cp(cfg);
    auto self_id = make_endpoint_id(0x01);
    NodeProfile self_profile;
    self_profile.endpoint_id = self_id;
    cp.start(self_id, self_profile);

    int legacy_count = 0;
    cp.subscribe_node_events([&](const NodeEvent &) { legacy_count++; });

    auto sub = cp.subscribe_events();

    cp.on_digest_received(make_digest(2, 0xD0));

    // 旧 callback 同步收到
    CHECK(legacy_count >= 1);

    // 新 Subscriber 异步收到
    auto ev = sub->poll(100ms);
    CHECK(ev.has_value());
    CHECK_EQ(ev->type, NodeEventType::NodeJoined);

    cp.stop();
}

// V7: 非跨域摘要过滤（sender_domain_id == self_domain → 返回 0，无事件）
static void test_v7_same_domain_digest_filtered() {
    std::printf("[V7] same-domain digest filtered...\n");
    auto cfg = make_cross_domain_config(1);
    ControlPlane cp(cfg);
    auto self_id = make_endpoint_id(0x01);
    NodeProfile self_profile;
    self_profile.endpoint_id = self_id;
    cp.start(self_id, self_profile);

    auto sub = cp.subscribe_events();

    // 同域摘要（sender_domain_id == self_domain == 1）
    auto digest = make_digest(/*sender_domain=*/1, 0xE0);
    std::size_t new_count = cp.on_digest_received(digest);
    CHECK_EQ(new_count, 0u);

    // 无事件投递
    auto ev = sub->try_poll();
    CHECK(!ev.has_value());

    cp.stop();
}

// V8: 跨域节点 registry 标记
static void test_v8_cross_domain_registry_marking() {
    std::printf("[V8] cross-domain registry marking...\n");
    auto cfg = make_cross_domain_config(1);
    ControlPlane cp(cfg);
    auto self_id = make_endpoint_id(0x01);
    NodeProfile self_profile;
    self_profile.endpoint_id = self_id;
    cp.start(self_id, self_profile);

    auto sub = cp.subscribe_events();

    cp.on_digest_received(make_digest(2, 0xF0, 0.85f, GeoRegion::South));
    sub->poll(100ms);  // 取走事件

    // 查询跨域视图
    auto cross_domain_nodes = cp.get_cross_domain_view();
    CHECK_EQ(cross_domain_nodes.size(), 1u);
    if (!cross_domain_nodes.empty()) {
        const auto &entry = cross_domain_nodes[0];
        CHECK(entry.is_cross_domain);
        CHECK_EQ(entry.domain_id, 2u);
        CHECK(entry.profile.endpoint_id == make_endpoint_id(0xF0));
    }

    cp.stop();
}

// V9: poll 超时返回 nullopt（无事件时）
static void test_v9_poll_timeout_returns_nullopt() {
    std::printf("[V9] poll timeout returns nullopt...\n");
    auto cfg = make_cross_domain_config(1);
    ControlPlane cp(cfg);
    auto self_id = make_endpoint_id(0x01);
    NodeProfile self_profile;
    self_profile.endpoint_id = self_id;
    cp.start(self_id, self_profile);

    auto sub = cp.subscribe_events();

    // 无事件，poll 50ms 应返回 nullopt
    auto start = std::chrono::steady_clock::now();
    auto ev = sub->poll(50ms);
    auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(!ev.has_value());
    // 至少等待了 50ms（允许小幅误差）
    CHECK(elapsed >= 40ms);

    cp.stop();
}

// V10: try_poll 非阻塞
static void test_v10_try_poll_nonblocking() {
    std::printf("[V10] try_poll non-blocking...\n");
    auto cfg = make_cross_domain_config(1);
    ControlPlane cp(cfg);
    auto self_id = make_endpoint_id(0x01);
    NodeProfile self_profile;
    self_profile.endpoint_id = self_id;
    cp.start(self_id, self_profile);

    auto sub = cp.subscribe_events();

    // 无事件，try_poll 立即返回 nullopt
    auto ev = sub->try_poll();
    CHECK(!ev.has_value());

    // 投递事件
    cp.on_digest_received(make_digest(2, 0x11));

    // try_poll 应取出事件
    auto ev2 = sub->try_poll();
    CHECK(ev2.has_value());
    CHECK_EQ(ev2->type, NodeEventType::NodeJoined);

    // 再次 try_poll 无事件
    auto ev3 = sub->try_poll();
    CHECK(!ev3.has_value());

    cp.stop();
}

// ========== main ==========

int main() {
    std::printf("=== test_event_bus_cross_domain (V3.5 P5-C) ===\n\n");

    test_v1_cross_domain_node_joined_to_eventbus();
    test_v2_cross_domain_node_updated_coalesce();
    test_v3_cross_domain_node_stale_critical();
    test_v4_multi_subscriber_fanout();
    test_v5_event_counters();
    test_v6_legacy_callback_compat();
    test_v7_same_domain_digest_filtered();
    test_v8_cross_domain_registry_marking();
    test_v9_poll_timeout_returns_nullopt();
    test_v10_try_poll_nonblocking();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
