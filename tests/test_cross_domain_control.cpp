// test_cross_domain_control.cpp — V3-A 跨域控制面测试（v3.0 Phase 5 方向 A）
//
// M1 阶段：跨域数据结构的默认值与字段定义（不依赖未实现的方法）
// M2 阶段：CrossDomainNodeDigest 编解码 / NodeRegistry 跨域接口 / CrossDomainAggregator
// M3 阶段：ControlPlane 跨域 tick / 跨域代表选举 / 摘要发送 / 超时清理 / control_channel 消息类型
//
// 详见 docs/V3_A_CROSS_DOMAIN_CONTROL.md §9 测试计划

#include "linoh/control_plane.hpp"
#include "linoh/base/key.hpp"
#include "linoh/geo_region.hpp"
#include "linoh/multimodal/control_channel.hpp"
#include "linoh/node_profile.hpp"
#include "linoh/protocol/application_message.hpp"

#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
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

#define CHECK_EQ(a, b) do { \
    ++total; \
    if (!((a) == (b))) { \
        std::cerr << "FAIL: " << #a << " == " << #b \
                  << " (line " << __LINE__ << ")" << std::endl; \
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
// 1. ControlPlaneConfig 跨域字段默认值（M1）
// ============================================================================

void test_config_cross_domain_defaults() {
    std::cout << "[test] ControlPlaneConfig cross_domain defaults" << std::endl;
    ControlPlaneConfig cfg;

    CHECK(cfg.cross_domain_enabled == false);
    CHECK(cfg.domain_id == 0u);
    CHECK(cfg.cross_domain_aggregate_interval == std::chrono::seconds(30));
    CHECK(cfg.cross_domain_ttl == 2);
    CHECK(cfg.max_digest_nodes == 50u);
    CHECK(cfg.cross_domain_stale_timeout == std::chrono::seconds(90));
    CHECK(cfg.peer_domain_reps.empty());
}

void test_config_cross_domain_set() {
    std::cout << "[test] ControlPlaneConfig cross_domain set" << std::endl;
    ControlPlaneConfig cfg;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 42;
    cfg.cross_domain_aggregate_interval = std::chrono::seconds(15);
    cfg.cross_domain_ttl = 3;
    cfg.max_digest_nodes = 100;
    cfg.cross_domain_stale_timeout = std::chrono::seconds(60);
    cfg.peer_domain_reps = {make_id(1), make_id(2)};

    CHECK(cfg.cross_domain_enabled == true);
    CHECK(cfg.domain_id == 42u);
    CHECK(cfg.cross_domain_aggregate_interval == std::chrono::seconds(15));
    CHECK(cfg.cross_domain_ttl == 3);
    CHECK(cfg.max_digest_nodes == 100u);
    CHECK(cfg.cross_domain_stale_timeout == std::chrono::seconds(60));
    CHECK(cfg.peer_domain_reps.size() == 2u);
}

// ============================================================================
// 2. NodeRegistryEntry 跨域字段默认值（M1）
// ============================================================================

void test_registry_entry_cross_domain_defaults() {
    std::cout << "[test] NodeRegistryEntry cross_domain defaults" << std::endl;
    NodeRegistryEntry entry;

    CHECK(entry.domain_id == 0u);
    CHECK(entry.is_cross_domain == false);
    CHECK(entry.is_cross_domain_rep == false);
    CHECK(entry.cached_overall_score < 0.0f);  // -1 = 未设置
}

// ============================================================================
// 3. CrossDomainNodeDigest 默认值与字段（M1）
// ============================================================================

void test_digest_defaults() {
    std::cout << "[test] CrossDomainNodeDigest defaults" << std::endl;
    CrossDomainNodeDigest digest;

    CHECK(digest.domain_id == 0u);
    CHECK(digest.overall_score == 0.0f);
    CHECK(digest.region == GeoRegion::Unknown);
    CHECK(digest.state == NodeState::Unknown);
}

void test_digest_set_fields() {
    std::cout << "[test] CrossDomainNodeDigest set fields" << std::endl;
    CrossDomainNodeDigest digest;
    digest.domain_id = 7;
    digest.endpoint_id = make_id(99);
    digest.overall_score = 0.85f;
    digest.region = GeoRegion::South;
    digest.state = NodeState::Online;

    CHECK(digest.domain_id == 7u);
    CHECK(digest.overall_score == 0.85f);
    CHECK(digest.region == GeoRegion::South);
    CHECK(digest.state == NodeState::Online);
}

void test_digest_serialized_size_constant() {
    std::cout << "[test] CrossDomainNodeDigest kSerializedSize" << std::endl;
    CHECK_EQ(CrossDomainNodeDigest::kSerializedSize, static_cast<std::size_t>(42));
}

// ============================================================================
// 4. CrossDomainDigestPayload 默认值与字段（M1）
// ============================================================================

void test_payload_defaults() {
    std::cout << "[test] CrossDomainDigestPayload defaults" << std::endl;
    CrossDomainDigestPayload payload;

    CHECK(payload.sender_domain_id == 0u);
    CHECK(payload.ttl == 2);
    CHECK(payload.nodes.empty());
}

void test_payload_set_fields() {
    std::cout << "[test] CrossDomainDigestPayload set fields" << std::endl;
    CrossDomainDigestPayload payload;
    payload.sender_domain_id = 5;
    payload.ttl = 1;

    CrossDomainNodeDigest d1;
    d1.domain_id = 5;
    d1.endpoint_id = make_id(1);
    d1.overall_score = 0.9f;
    d1.region = GeoRegion::East;
    d1.state = NodeState::Online;

    CrossDomainNodeDigest d2;
    d2.domain_id = 5;
    d2.endpoint_id = make_id(2);
    d2.overall_score = 0.7f;
    d2.region = GeoRegion::East;
    d2.state = NodeState::Online;

    payload.nodes = {d1, d2};

    CHECK(payload.sender_domain_id == 5u);
    CHECK(payload.ttl == 1);
    CHECK(payload.nodes.size() == 2u);
    CHECK(payload.nodes[0].endpoint_id == make_id(1));
    CHECK(payload.nodes[1].overall_score == 0.7f);
}

// ============================================================================
// 5. 向后兼容验证（M1）
// ============================================================================

void test_backward_compat_disabled_default() {
    std::cout << "[test] backward compat: cross_domain disabled by default" << std::endl;
    ControlPlaneConfig cfg;
    CHECK(cfg.cross_domain_enabled == false);
    CHECK(cfg.domain_id == 0u);
}

// ============================================================================
// 6. 类型可编译性验证（M1）
// ============================================================================

void test_types_compilable() {
    std::cout << "[test] V3-A types compilable" << std::endl;
    CrossDomainNodeDigest d1;
    CrossDomainNodeDigest d2 = d1;
    CrossDomainNodeDigest d3;
    d3 = d1;
    (void)d2; (void)d3;

    CrossDomainDigestPayload p1;
    CrossDomainDigestPayload p2 = p1;
    CrossDomainDigestPayload p3;
    p3 = p1;
    (void)p2; (void)p3;

    SendDigestCallback cb = [](const EndpointId &, const CrossDomainDigestPayload &) {};
    (void)cb;

    CHECK(true);
}

// ============================================================================
// 7. M2: CrossDomainNodeDigest serialize/deserialize 编解码
// ============================================================================

void test_digest_serialize_deserialize() {
    std::cout << "[test] CrossDomainNodeDigest serialize/deserialize roundtrip" << std::endl;
    CrossDomainNodeDigest d;
    d.domain_id = 42;
    d.endpoint_id = make_id(7);
    d.overall_score = 0.75f;
    d.region = GeoRegion::North;
    d.state = NodeState::Online;

    std::uint8_t buf[CrossDomainNodeDigest::kSerializedSize];
    auto written = d.serialize(buf, sizeof(buf));
    CHECK_EQ(written, CrossDomainNodeDigest::kSerializedSize);

    CrossDomainNodeDigest d2;
    auto consumed = CrossDomainNodeDigest::deserialize(buf, written, d2);
    CHECK_EQ(consumed, CrossDomainNodeDigest::kSerializedSize);
    CHECK_EQ(d2.domain_id, 42u);
    CHECK_EQ(d2.endpoint_id, d.endpoint_id);
    CHECK_EQ(d2.overall_score, 0.75f);
    CHECK_EQ(d2.region, GeoRegion::North);
    CHECK_EQ(d2.state, NodeState::Online);
}

void test_digest_serialize_buffer_too_small() {
    std::cout << "[test] CrossDomainNodeDigest serialize buffer too small" << std::endl;
    CrossDomainNodeDigest d;
    std::uint8_t buf[10];  // 不足 42 字节
    auto written = d.serialize(buf, sizeof(buf));
    CHECK_EQ(written, static_cast<std::size_t>(0));  // 失败返回 0
}

void test_digest_serialize_null_buffer() {
    std::cout << "[test] CrossDomainNodeDigest serialize null buffer" << std::endl;
    CrossDomainNodeDigest d;
    auto written = d.serialize(nullptr, 1024);
    CHECK_EQ(written, static_cast<std::size_t>(0));
}

void test_digest_deserialize_buffer_too_small() {
    std::cout << "[test] CrossDomainNodeDigest deserialize buffer too small" << std::endl;
    std::uint8_t buf[10];
    CrossDomainNodeDigest d;
    auto consumed = CrossDomainNodeDigest::deserialize(buf, sizeof(buf), d);
    CHECK_EQ(consumed, static_cast<std::size_t>(0));
}

// ============================================================================
// 8. M2: CrossDomainDigestPayload within_limit
// ============================================================================

void test_payload_within_limit() {
    std::cout << "[test] CrossDomainDigestPayload within_limit" << std::endl;
    CrossDomainDigestPayload p;
    for (int i = 0; i < 50; ++i) {
        CrossDomainNodeDigest d;
        d.endpoint_id = make_id(static_cast<std::uint8_t>(i));
        p.nodes.push_back(d);
    }
    CHECK(p.within_limit(50));
    CHECK(!p.within_limit(49));
}

// ============================================================================
// 9. M2: NodeRegistry 跨域接口
// ============================================================================

void test_registry_upsert_cross_domain_digests() {
    std::cout << "[test] NodeRegistry upsert_cross_domain_digests" << std::endl;
    NodeRegistry reg;
    std::vector<CrossDomainNodeDigest> digests;
    for (int i = 1; i <= 3; ++i) {
        CrossDomainNodeDigest d;
        d.domain_id = 5;  // 跨域
        d.endpoint_id = make_id(static_cast<std::uint8_t>(i));
        d.overall_score = 0.8f;
        d.region = GeoRegion::South;
        d.state = NodeState::Online;
        digests.push_back(d);
    }
    auto new_count = reg.upsert_cross_domain_digests(digests, /*self_domain=*/1);
    CHECK_EQ(new_count, static_cast<std::size_t>(3));
    CHECK_EQ(reg.size(), static_cast<std::size_t>(3));

    // 重复 upsert 不增加新节点
    auto new_count2 = reg.upsert_cross_domain_digests(digests, 1);
    CHECK_EQ(new_count2, static_cast<std::size_t>(0));
}

void test_registry_get_cross_domain_nodes_sorted() {
    std::cout << "[test] NodeRegistry get_cross_domain_nodes sorted" << std::endl;
    NodeRegistry reg;
    std::vector<CrossDomainNodeDigest> digests;
    float scores[] = {0.9f, 0.5f, 0.7f};
    for (int i = 0; i < 3; ++i) {
        CrossDomainNodeDigest d;
        d.domain_id = 5;
        d.endpoint_id = make_id(static_cast<std::uint8_t>(i + 1));
        d.overall_score = scores[i];
        d.state = NodeState::Online;
        digests.push_back(d);
    }
    reg.upsert_cross_domain_digests(digests, 1);

    auto cross_nodes = reg.get_cross_domain_nodes();
    CHECK_EQ(cross_nodes.size(), static_cast<std::size_t>(3));
    // 按 sort_score 降序（跨域节点用 cached_overall_score）
    CHECK(cross_nodes[0].sort_score() > cross_nodes[1].sort_score());
    CHECK(cross_nodes[1].sort_score() > cross_nodes[2].sort_score());
}

void test_registry_elect_cross_domain_rep() {
    std::cout << "[test] NodeRegistry elect_cross_domain_rep" << std::endl;
    NodeRegistry reg;
    float scores[] = {0.9f, 0.5f, 0.7f};
    for (int i = 0; i < 3; ++i) {
        CrossDomainNodeDigest d;
        d.domain_id = 5;
        d.endpoint_id = make_id(static_cast<std::uint8_t>(i + 1));
        d.overall_score = scores[i];
        d.state = NodeState::Online;
        std::vector<CrossDomainNodeDigest> v{d};
        reg.upsert_cross_domain_digests(v, 1);
    }
    auto rep = reg.elect_cross_domain_rep(5);
    CHECK(rep.has_value());
    CHECK_EQ(*rep, make_id(1));  // score=0.9 最高者当选
}

void test_registry_elect_cross_domain_rep_empty() {
    std::cout << "[test] NodeRegistry elect_cross_domain_rep empty domain" << std::endl;
    NodeRegistry reg;
    auto rep = reg.elect_cross_domain_rep(99);  // 不存在的域
    CHECK(!rep.has_value());
}

void test_registry_get_by_domain() {
    std::cout << "[test] NodeRegistry get_by_domain" << std::endl;
    NodeRegistry reg;
    std::vector<CrossDomainNodeDigest> digests;
    for (int i = 1; i <= 2; ++i) {
        CrossDomainNodeDigest d;
        d.domain_id = 5;
        d.endpoint_id = make_id(static_cast<std::uint8_t>(i));
        d.overall_score = 0.8f;
        d.state = NodeState::Online;
        digests.push_back(d);
    }
    CrossDomainNodeDigest d3;
    d3.domain_id = 7;
    d3.endpoint_id = make_id(3);
    d3.overall_score = 0.9f;
    d3.state = NodeState::Online;
    digests.push_back(d3);
    reg.upsert_cross_domain_digests(digests, 1);

    auto domain5 = reg.get_by_domain(5);
    CHECK_EQ(domain5.size(), static_cast<std::size_t>(2));
    auto domain7 = reg.get_by_domain(7);
    CHECK_EQ(domain7.size(), static_cast<std::size_t>(1));
    auto domain9 = reg.get_by_domain(9);
    CHECK_EQ(domain9.size(), static_cast<std::size_t>(0));
}

// ============================================================================
// 10. M2: CrossDomainAggregator
// ============================================================================

void test_aggregator_build_digest() {
    std::cout << "[test] CrossDomainAggregator build_digest" << std::endl;
    NodeRegistry reg;
    ControlPlaneConfig cfg;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 1;
    cfg.max_digest_nodes = 50;

    // 本域节点（is_cross_domain=false）
    for (int i = 1; i <= 3; ++i) {
        reg.upsert(make_profile(static_cast<std::uint8_t>(i), GeoRegion::North, 0.8f));
    }
    // 跨域节点（不应出现在本域摘要中）
    CrossDomainNodeDigest cd;
    cd.domain_id = 2;
    cd.endpoint_id = make_id(99);
    cd.overall_score = 0.9f;
    cd.state = NodeState::Online;
    reg.upsert_cross_domain_digests({cd}, 1);

    CrossDomainAggregator agg(reg, cfg);
    auto payload = agg.build_digest(make_id(1), 1);
    CHECK_EQ(payload.sender_domain_id, 1u);
    CHECK_EQ(payload.sender_endpoint_id, make_id(1));
    CHECK_EQ(payload.nodes.size(), static_cast<std::size_t>(3));  // 仅本域 3 节点
}

void test_aggregator_build_digest_max_nodes_limit() {
    std::cout << "[test] CrossDomainAggregator build_digest max_nodes limit" << std::endl;
    NodeRegistry reg;
    ControlPlaneConfig cfg;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 1;
    cfg.max_digest_nodes = 2;  // 限制 2 个

    for (int i = 1; i <= 5; ++i) {
        reg.upsert(make_profile(static_cast<std::uint8_t>(i), GeoRegion::North, 0.8f));
    }
    CrossDomainAggregator agg(reg, cfg);
    auto payload = agg.build_digest(make_id(1), 1);
    CHECK_EQ(payload.nodes.size(), static_cast<std::size_t>(2));  // 截断到 2
}

void test_aggregator_on_digest_received_same_domain_ignored() {
    std::cout << "[test] CrossDomainAggregator on_digest_received same domain ignored" << std::endl;
    NodeRegistry reg;
    ControlPlaneConfig cfg;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 1;
    CrossDomainAggregator agg(reg, cfg);

    CrossDomainDigestPayload p;
    p.sender_domain_id = 1;  // 同域
    p.ttl = 2;
    CrossDomainNodeDigest d;
    d.domain_id = 1;
    d.endpoint_id = make_id(5);
    p.nodes = {d};

    auto new_count = agg.on_digest_received(p, 1);
    CHECK_EQ(new_count, static_cast<std::size_t>(0));  // 同域不处理
    CHECK_EQ(reg.size(), static_cast<std::size_t>(0));  // 注册表无变化
}

void test_aggregator_on_digest_received_cross_domain() {
    std::cout << "[test] CrossDomainAggregator on_digest_received cross domain" << std::endl;
    NodeRegistry reg;
    ControlPlaneConfig cfg;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 1;
    CrossDomainAggregator agg(reg, cfg);

    CrossDomainDigestPayload p;
    p.sender_domain_id = 2;  // 跨域
    p.ttl = 2;
    CrossDomainNodeDigest d;
    d.domain_id = 2;
    d.endpoint_id = make_id(5);
    d.overall_score = 0.8f;
    d.state = NodeState::Online;
    p.nodes = {d};

    auto new_count = agg.on_digest_received(p, 1);
    CHECK_EQ(new_count, static_cast<std::size_t>(1));  // 1 个新节点
    CHECK_EQ(reg.size(), static_cast<std::size_t>(1));

    // 重复接收不增加
    auto new_count2 = agg.on_digest_received(p, 1);
    CHECK_EQ(new_count2, static_cast<std::size_t>(0));
    CHECK_EQ(reg.size(), static_cast<std::size_t>(1));
}

void test_aggregator_should_forward() {
    std::cout << "[test] CrossDomainAggregator should_forward" << std::endl;
    ControlPlaneConfig cfg;
    NodeRegistry reg;
    CrossDomainAggregator agg(reg, cfg);

    CrossDomainDigestPayload p;
    p.ttl = 2;
    CHECK(agg.should_forward(p));  // ttl > 1

    p.ttl = 1;
    CHECK(!agg.should_forward(p));  // ttl == 1 不转发

    p.ttl = 0;
    CHECK(!agg.should_forward(p));
}

void test_aggregator_select_forward_targets_excludes_source_domain() {
    std::cout << "[test] CrossDomainAggregator select_forward_targets excludes source domain" << std::endl;
    NodeRegistry reg;
    ControlPlaneConfig cfg;
    CrossDomainAggregator agg(reg, cfg);

    // 注册 3 个邻域代表：rep1 属于域 2（来源域），rep2/rep3 属于域 3/4
    std::vector<CrossDomainNodeDigest> reps;
    CrossDomainNodeDigest r1;
    r1.domain_id = 2;
    r1.endpoint_id = make_id(1);
    r1.state = NodeState::Online;
    CrossDomainNodeDigest r2;
    r2.domain_id = 3;
    r2.endpoint_id = make_id(2);
    r2.state = NodeState::Online;
    CrossDomainNodeDigest r3;
    r3.domain_id = 4;
    r3.endpoint_id = make_id(3);
    r3.state = NodeState::Online;
    reg.upsert_cross_domain_digests({r1, r2, r3}, /*self_domain=*/1);

    CrossDomainDigestPayload p;
    p.sender_domain_id = 2;  // 来源域
    p.ttl = 2;

    auto targets = agg.select_forward_targets(p, {make_id(1), make_id(2), make_id(3)});
    // 应排除域 2 的 rep（make_id(1)），保留 make_id(2) 和 make_id(3)
    CHECK_EQ(targets.size(), static_cast<std::size_t>(2));
    CHECK(targets[0] != make_id(1));
    CHECK(targets[1] != make_id(1));
}

// ============================================================================
// 11. M3: control_channel 消息类型（MethodId::CrossDomainDigest / CrossDomainDigestReq）
// ============================================================================

void test_method_id_cross_domain_values() {
    std::cout << "[test] MethodId CrossDomainDigest/CrossDomainDigestReq values" << std::endl;
    // 验证 V3-A 新增的 MethodId 枚举值
    CHECK_EQ(static_cast<std::uint16_t>(linoh::protocol::MethodId::CrossDomainDigest),
             static_cast<std::uint16_t>(0x0050));
    CHECK_EQ(static_cast<std::uint16_t>(linoh::protocol::MethodId::CrossDomainDigestReq),
             static_cast<std::uint16_t>(0x0051));
}

// ============================================================================
// 12. M3: ControlPlane 跨域禁用时 is_cross_domain_rep 返回 false
// ============================================================================

void test_control_plane_cross_domain_disabled() {
    std::cout << "[test] ControlPlane cross_domain disabled -> is_cross_domain_rep false" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = false;  // 跨域关闭

    ControlPlane cp(cfg);
    cp.start(make_id(1), make_profile(1, GeoRegion::North, 0.9f));

    CHECK(!cp.is_cross_domain_rep());  // 跨域关闭，始终 false
    cp.tick_once();                    // 不应崩溃，tick_cross_domain_ no-op
    CHECK(!cp.is_cross_domain_rep());

    cp.stop();
}

// ============================================================================
// 13. M3: ControlPlane 跨域代表选举 - 本节点 score 最高当选
// ============================================================================

void test_control_plane_elect_as_rep() {
    std::cout << "[test] ControlPlane elect as cross_domain rep (highest score)" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 1;
    cfg.cross_domain_aggregate_interval = std::chrono::seconds(30);
    cfg.peer_domain_reps = {make_id(99)};

    // 虚拟时钟
    auto t0 = std::chrono::system_clock::now();
    TimePoint now = t0;
    ClockFunc clock = [&now]() { return now; };

    ControlPlane cp(cfg, clock);
    cp.start(make_id(1), make_profile(1, GeoRegion::North, 0.9f));

    CHECK(!cp.is_cross_domain_rep());  // 初始未选举

    // 推进时间触发选举（>= cross_domain_aggregate_interval）
    now += std::chrono::seconds(31);
    cp.tick_once();

    CHECK(cp.is_cross_domain_rep());  // 本节点 score 最高，当选
    cp.stop();
}

// ============================================================================
// 14. M3: ControlPlane 跨域代表选举 - 本节点 score 较低不当选
// ============================================================================

void test_control_plane_not_rep_lower_score() {
    std::cout << "[test] ControlPlane not rep when lower score" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 1;
    cfg.cross_domain_aggregate_interval = std::chrono::seconds(30);
    // 关键：stale_timeout 必须 > 推进的时间，否则高分节点会被 mark_stale
    // 标记为 Offline 而被选举跳过，导致本节点误当选
    cfg.stale_timeout = std::chrono::seconds(120);

    TimePoint now = std::chrono::system_clock::now();
    ClockFunc clock = [&now]() { return now; };

    ControlPlane cp(cfg, clock);
    // 本节点 stability=0.5（较低）
    cp.start(make_id(1), make_profile(1, GeoRegion::North, 0.5f));

    // 注册另一个本域节点 stability=0.9（更高）
    NodeProfile other = make_profile(2, GeoRegion::North, 0.9f);
    cp.register_node(other);
    // 手动设置其 domain_id（register_node 不设置 domain_id）
    cp.registry().set_domain(make_id(2), cfg.domain_id);

    now += std::chrono::seconds(31);
    cp.tick_once();

    CHECK(!cp.is_cross_domain_rep());  // 本节点 score 较低，不是代表
    cp.stop();
}

// ============================================================================
// 15. M3: ControlPlane 跨域代表发送摘要给邻域代表
// ============================================================================

void test_control_plane_send_digest_as_rep() {
    std::cout << "[test] ControlPlane send digest as rep" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 1;
    cfg.cross_domain_aggregate_interval = std::chrono::seconds(30);
    cfg.peer_domain_reps = {make_id(99)};

    TimePoint now = std::chrono::system_clock::now();
    ClockFunc clock = [&now]() { return now; };

    ControlPlane cp(cfg, clock);
    cp.start(make_id(1), make_profile(1, GeoRegion::North, 0.9f));

    int send_count = 0;
    EndpointId sent_target;
    std::size_t sent_node_count = 0;
    cp.set_send_digest_callback([&](const EndpointId &target,
                                     const CrossDomainDigestPayload &payload) {
        ++send_count;
        sent_target = target;
        sent_node_count = payload.nodes.size();
    });

    now += std::chrono::seconds(31);
    cp.tick_once();

    CHECK_EQ(send_count, 1);  // 发送了 1 次摘要
    CHECK(sent_target == make_id(99));
    CHECK(sent_node_count >= 1);  // 至少包含本节点
    cp.stop();
}

// ============================================================================
// 16. M3: ControlPlane.on_digest_received 集成
// ============================================================================

void test_control_plane_on_digest_received() {
    std::cout << "[test] ControlPlane on_digest_received integration" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 1;

    ControlPlane cp(cfg);
    cp.start(make_id(1), make_profile(1));

    CrossDomainDigestPayload payload;
    payload.sender_domain_id = 2;  // 跨域
    payload.ttl = 2;
    CrossDomainNodeDigest d;
    d.domain_id = 2;
    d.endpoint_id = make_id(5);
    d.overall_score = 0.8f;
    d.state = NodeState::Online;
    payload.nodes = {d};

    auto new_count = cp.on_digest_received(payload);
    CHECK_EQ(new_count, static_cast<std::size_t>(1));

    auto view = cp.get_cross_domain_view();
    CHECK_EQ(view.size(), static_cast<std::size_t>(1));
    CHECK(view[0].is_cross_domain);
    CHECK_EQ(view[0].domain_id, 2u);

    cp.stop();
}

// ============================================================================
// 17. M3: ControlPlane 跨域未启用时 on_digest_received 返回 0
// ============================================================================

void test_control_plane_on_digest_received_disabled() {
    std::cout << "[test] ControlPlane on_digest_received disabled returns 0" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = false;  // 跨域关闭

    ControlPlane cp(cfg);
    cp.start(make_id(1), make_profile(1));

    CrossDomainDigestPayload payload;
    payload.sender_domain_id = 2;
    CrossDomainNodeDigest d;
    d.domain_id = 2;
    d.endpoint_id = make_id(5);
    payload.nodes = {d};

    auto new_count = cp.on_digest_received(payload);
    CHECK_EQ(new_count, static_cast<std::size_t>(0));  // 跨域关闭，不处理

    auto view = cp.get_cross_domain_view();
    CHECK_EQ(view.size(), static_cast<std::size_t>(0));  // 空视图

    cp.stop();
}

// ============================================================================
// 18. M3: ControlPlane 跨域节点超时清理
// ============================================================================

void test_control_plane_cross_domain_stale_cleanup() {
    std::cout << "[test] ControlPlane cross_domain stale cleanup" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 1;
    cfg.cross_domain_aggregate_interval = std::chrono::seconds(30);
    cfg.cross_domain_stale_timeout = std::chrono::seconds(60);

    TimePoint now = std::chrono::system_clock::now();
    ClockFunc clock = [&now]() { return now; };

    ControlPlane cp(cfg, clock);
    cp.start(make_id(1), make_profile(1));

    // 注入跨域节点
    CrossDomainDigestPayload payload;
    payload.sender_domain_id = 2;
    payload.ttl = 2;
    CrossDomainNodeDigest d;
    d.domain_id = 2;
    d.endpoint_id = make_id(5);
    d.overall_score = 0.8f;
    d.state = NodeState::Online;
    payload.nodes = {d};
    cp.on_digest_received(payload);

    CHECK_EQ(cp.get_cross_domain_view().size(), static_cast<std::size_t>(1));

    // 推进时间超过 stale_timeout（60s），触发清理
    now += std::chrono::seconds(91);
    cp.tick_once();  // tick_cross_domain_ 中 check_cross_domain_stale 触发清理

    CHECK_EQ(cp.get_cross_domain_view().size(), static_cast<std::size_t>(0));  // 已清理

    cp.stop();
}

// ============================================================================
// 19. M3: ControlPlane 跨域代表选举 - 确定性（平局取字典序最小）
// ============================================================================

void test_control_plane_elect_deterministic_tie() {
    std::cout << "[test] ControlPlane elect deterministic (tie -> lexicographic min)" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 1;
    cfg.cross_domain_aggregate_interval = std::chrono::seconds(30);

    TimePoint now = std::chrono::system_clock::now();
    ClockFunc clock = [&now]() { return now; };

    // 两个节点 score 相同，平局时应取 EndpointId 字典序最小
    // make_id(1) < make_id(2)，所以 make_id(1) 当选
    ControlPlane cp(cfg, clock);
    cp.start(make_id(1), make_profile(1, GeoRegion::North, 0.8f));

    NodeProfile other = make_profile(2, GeoRegion::North, 0.8f);  // 相同 score
    cp.register_node(other);
    cp.registry().set_domain(make_id(2), cfg.domain_id);

    now += std::chrono::seconds(31);
    cp.tick_once();

    // make_id(1) < make_id(2)，所以本节点(make_id(1))当选
    CHECK(cp.is_cross_domain_rep());

    cp.stop();
}

// ============================================================================
// 20. M4: ControlPlane::get_cross_domain_view 跨域未启用返回空
// ============================================================================

void test_get_cross_domain_view_disabled() {
    std::cout << "[test] get_cross_domain_view disabled returns empty" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = false;  // 跨域未启用
    cfg.domain_id = 0;

    ControlPlane cp(cfg);
    cp.start(make_id(1), make_profile(1));

    // 即使注入跨域摘要，跨域未启用也不处理
    CrossDomainDigestPayload payload;
    payload.sender_domain_id = 2;
    CrossDomainNodeDigest d;
    d.domain_id = 2;
    d.endpoint_id = make_id(5);
    d.overall_score = 0.8f;
    d.state = NodeState::Online;
    payload.nodes = {d};
    cp.on_digest_received(payload);  // 返回 0，不处理

    CHECK_EQ(cp.get_cross_domain_view().size(), static_cast<std::size_t>(0));
    CHECK(!cp.is_cross_domain_rep());  // 跨域未启用，不是代表
    cp.stop();
}

// ============================================================================
// 21. M4: ControlPlane::get_cross_domain_view 返回跨域节点（按 score 降序）
// ============================================================================

void test_get_cross_domain_view_returns_nodes() {
    std::cout << "[test] get_cross_domain_view returns cross_domain nodes sorted" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 1;

    ControlPlane cp(cfg);
    cp.start(make_id(1), make_profile(1));

    // 注入多个跨域节点（不同 score）
    CrossDomainDigestPayload payload;
    payload.sender_domain_id = 2;
    payload.ttl = 2;
    float scores[] = {0.9f, 0.5f, 0.7f};
    for (int i = 0; i < 3; ++i) {
        CrossDomainNodeDigest d;
        d.domain_id = 2;
        d.endpoint_id = make_id(static_cast<std::uint8_t>(i + 10));
        d.overall_score = scores[i];
        d.state = NodeState::Online;
        payload.nodes.push_back(d);
    }
    cp.on_digest_received(payload);

    auto view = cp.get_cross_domain_view();
    CHECK_EQ(view.size(), static_cast<std::size_t>(3));
    // 按 sort_score 降序
    CHECK(view[0].sort_score() > view[1].sort_score());
    CHECK(view[1].sort_score() > view[2].sort_score());
    // 最高 score = 0.9
    CHECK_EQ(view[0].sort_score(), 0.9f);

    cp.stop();
}

// ============================================================================
// 22. M4: get_cross_domain_view 不含本域节点
// ============================================================================

void test_get_cross_domain_view_excludes_local_domain() {
    std::cout << "[test] get_cross_domain_view excludes local domain nodes" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = true;
    cfg.domain_id = 1;

    ControlPlane cp(cfg);
    cp.start(make_id(1), make_profile(1));

    // 注册本域节点（不应出现在跨域视图中）
    NodeProfile local = make_profile(2, GeoRegion::North, 0.9f);
    cp.register_node(local);
    cp.registry().set_domain(make_id(2), cfg.domain_id);

    // 注入跨域节点
    CrossDomainDigestPayload payload;
    payload.sender_domain_id = 2;
    CrossDomainNodeDigest d;
    d.domain_id = 2;
    d.endpoint_id = make_id(10);
    d.overall_score = 0.8f;
    d.state = NodeState::Online;
    payload.nodes = {d};
    cp.on_digest_received(payload);

    auto view = cp.get_cross_domain_view();
    CHECK_EQ(view.size(), static_cast<std::size_t>(1));  // 仅跨域节点
    CHECK(view[0].is_cross_domain);  // 确实是跨域节点
    CHECK(view[0].domain_id == 2u);  // 来自域 2

    cp.stop();
}

// ============================================================================
// 23. M4: is_cross_domain_rep 跨域未启用返回 false
// ============================================================================

void test_is_cross_domain_rep_disabled() {
    std::cout << "[test] is_cross_domain_rep disabled returns false" << std::endl;
    ControlPlaneConfig cfg;
    cfg.enabled = true;
    cfg.cross_domain_enabled = false;
    cfg.domain_id = 0;

    ControlPlane cp(cfg);
    cp.start(make_id(1), make_profile(1, GeoRegion::North, 0.99f));

    CHECK(!cp.is_cross_domain_rep());  // 跨域未启用
    cp.stop();
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << " test_cross_domain_control (V3-A M1+M2+M3+M4)" << std::endl;
    std::cout << "========================================" << std::endl;

    // === M1: 数据结构默认值 ===
    test_config_cross_domain_defaults();
    test_config_cross_domain_set();
    test_registry_entry_cross_domain_defaults();
    test_digest_defaults();
    test_digest_set_fields();
    test_digest_serialized_size_constant();
    test_payload_defaults();
    test_payload_set_fields();
    test_backward_compat_disabled_default();
    test_types_compilable();

    // === M2: 编解码 ===
    test_digest_serialize_deserialize();
    test_digest_serialize_buffer_too_small();
    test_digest_serialize_null_buffer();
    test_digest_deserialize_buffer_too_small();
    test_payload_within_limit();

    // === M2: NodeRegistry 跨域接口 ===
    test_registry_upsert_cross_domain_digests();
    test_registry_get_cross_domain_nodes_sorted();
    test_registry_elect_cross_domain_rep();
    test_registry_elect_cross_domain_rep_empty();
    test_registry_get_by_domain();

    // === M2: CrossDomainAggregator ===
    test_aggregator_build_digest();
    test_aggregator_build_digest_max_nodes_limit();
    test_aggregator_on_digest_received_same_domain_ignored();
    test_aggregator_on_digest_received_cross_domain();
    test_aggregator_should_forward();
    test_aggregator_select_forward_targets_excludes_source_domain();

    // === M3: control_channel 消息类型 ===
    test_method_id_cross_domain_values();

    // === M3: ControlPlane 跨域 tick / 选举 / 发送 / 清理 ===
    test_control_plane_cross_domain_disabled();
    test_control_plane_elect_as_rep();
    test_control_plane_not_rep_lower_score();
    test_control_plane_send_digest_as_rep();
    test_control_plane_on_digest_received();
    test_control_plane_on_digest_received_disabled();
    test_control_plane_cross_domain_stale_cleanup();
    test_control_plane_elect_deterministic_tie();

    // === M4: get_cross_domain_view / is_cross_domain_rep（C-API 包装的核心方法）===
    test_get_cross_domain_view_disabled();
    test_get_cross_domain_view_returns_nodes();
    test_get_cross_domain_view_excludes_local_domain();
    test_is_cross_domain_rep_disabled();

    std::cout << "========================================" << std::endl;
    std::cout << " Total: " << total << ", Failed: " << failed << std::endl;
    std::cout << "========================================" << std::endl;

    return failed == 0 ? 0 : 1;
}
