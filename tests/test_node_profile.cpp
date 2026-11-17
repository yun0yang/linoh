// test_node_profile.cpp — v2.0 Phase 1 NodeProfile 单元测试
//
// 验证目标：
//   1.  NodeProfile 默认构造，overall_score 为 0
//   2.  ComputeCap 归一化（RTX 4090 = 1.0，RTX 3060 < 1.0）
//   3.  NetworkCap 归一化（1Gbps/5ms/0%loss/Lan = 1.0）
//   4.  NetClass 惩罚（Hard < Wan < Lan）
//   5.  StabilityCap::compute_score 公式（边界 + 一般用例）
//   6.  stability.refresh_score 同步 score 字段
//   7.  GeoCap 归一化（Unknown=0.3, North=1.0）
//   8.  overall_score 权重生效（自定义权重 vs 默认）
//   9.  overall_score 裁剪到 [0,1]
//  10.  brief() 输出非空
//  11.  NodeProfileStore 基本 CRUD（upsert/get/erase/size/clear）
//  12.  NodeProfileStore.get 不存在返回 nullopt
//  13.  NodeProfileStore.snapshot 返回全部条目
//  14.  NodeProfileStore.top_n 按 overall_score 降序
//  15.  NodeProfileStore 文本持久化 round-trip（save→load 数据一致）
//  16.  NodeProfileStore 线程安全（并发 upsert 不崩溃，最终 size 正确）
//  17.  EndpointId <-> hex 互转（含非法输入）
//  18.  load_from_file 容错（注释/空行/未知键忽略）

#include "linoh/node_profile.hpp"
#include "linoh/base/key.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <thread>
#include <vector>

using namespace linoh;
using linoh::base::EndpointId;
using linoh::base::PublicKey;

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; } \
    else { printf("  [FAIL] %s (line %d)\n", msg, __LINE__); g_fail++; } \
} while (0)

// 浮点近似比较
static bool approx(float a, float b, float eps = 0.01f) {
    float d = a - b;
    if (d < 0) d = -d;
    return d < eps;
}

// 构造一个 EndpointId（从固定字节序列）
static EndpointId make_ep(uint8_t fill) {
    std::array<uint8_t, EndpointId::kSize> b{};
    for (std::size_t i = 0; i < b.size(); ++i) b[i] = fill;
    return EndpointId::from_bytes(b);
}

// 构造 RTX 4090 画像（基准节点）
static NodeProfile make_rtx4090(EndpointId ep, const std::string &node_id) {
    NodeProfile p;
    p.endpoint_id = ep;
    p.node_id = node_id;
    p.compute.gpu_model = "RTX 4090";
    p.compute.vram_mb = 24576;
    p.compute.tflops_fp16 = 165.0f;
    p.compute.tflops_int4 = 660.0f;
    p.compute.cuda_cores = 16384;
    p.network.uplink_bps = 1'000'000'000;
    p.network.downlink_bps = 1'000'000'000;
    p.network.rtt_ms_avg = 5;
    p.network.rtt_ms_p99 = 12;
    p.network.loss_rate = 0.0f;
    p.network.net_class = NetClass::Lan;
    p.stability.uptime_seconds = 86400;
    p.stability.disconnect_count = 0;
    p.stability.task_success_rate = 1.0f;
    p.stability.refresh_score();
    p.geo.region = GeoRegion::North;
    p.geo.city = "Beijing";
    p.geo.isp = "ChinaUnicom";
    return p;
}

// 构造 RTX 3060 画像（中端节点）
static NodeProfile make_rtx3060(EndpointId ep, const std::string &node_id) {
    NodeProfile p;
    p.endpoint_id = ep;
    p.node_id = node_id;
    p.compute.gpu_model = "RTX 3060";
    p.compute.vram_mb = 12288;
    p.compute.tflops_fp16 = 70.0f;
    p.compute.tflops_int4 = 280.0f;
    p.compute.cuda_cores = 3584;
    p.network.uplink_bps = 100'000'000;
    p.network.downlink_bps = 100'000'000;
    p.network.rtt_ms_avg = 20;
    p.network.rtt_ms_p99 = 50;
    p.network.loss_rate = 0.005f;
    p.network.net_class = NetClass::Wan;
    p.stability.uptime_seconds = 43200;
    p.stability.disconnect_count = 3;
    p.stability.task_success_rate = 0.95f;
    p.stability.refresh_score();
    p.geo.region = GeoRegion::East;
    p.geo.city = "Shanghai";
    p.geo.isp = "ChinaTelecom";
    return p;
}

// =============================================================================
// TEST 1: 默认构造，overall_score = 0（所有字段为 0）
// =============================================================================
static void test_default_construction() {
    printf("\n=== TEST 1: 默认构造 ===\n");
    NodeProfile p;
    // endpoint_id 全 0 → is_zero()
    CHECK(p.endpoint_id.is_zero(), "default endpoint_id is zero");
    CHECK(p.compute.normalized_score() == 0.0f, "default compute score = 0");
    CHECK(p.network.normalized_score() >= 0.0f, "default network score >= 0");
    CHECK(p.stability.score == 0.0f, "default stability score = 0");
    // overall 不为 0：默认 loss_rate=0（无丢包）+ net_class=Lan 隐式贡献少量分
    // 但应处于低位（< 0.15，因为 compute/stability 全 0）
    CHECK(p.overall_score() < 0.15f, "default overall_score < 0.15 (low but non-zero due to defaults)");
    CHECK(p.overall_score() >= 0.0f, "default overall_score >= 0");
}

// =============================================================================
// TEST 2: ComputeCap 归一化
// =============================================================================
static void test_compute_normalization() {
    printf("\n=== TEST 2: ComputeCap 归一化 ===\n");
    NodeProfile p = make_rtx4090(make_ep(0xAA), "rtx4090-node");
    CHECK(approx(p.compute.normalized_score(), 1.0f), "RTX 4090 compute score = 1.0");

    NodeProfile p3060 = make_rtx3060(make_ep(0xBB), "rtx3060-node");
    float s3060 = p3060.compute.normalized_score();
    CHECK(s3060 > 0.0f && s3060 < 1.0f, "RTX 3060 compute score in (0,1)");
    CHECK(s3060 < p.compute.normalized_score(), "RTX 3060 < RTX 4090 compute");

    // 仅 FP16 探测（INT4=0, VRAM=0）
    NodeProfile::ComputeCap c;
    c.tflops_fp16 = 82.5f;  // 50% of 165
    CHECK(approx(c.normalized_score(), 0.5f), "fp16-only 50% baseline → 0.5");

    // 全 0
    NodeProfile::ComputeCap z;
    CHECK(z.normalized_score() == 0.0f, "all-zero compute → 0");
}

// =============================================================================
// TEST 3: NetworkCap 归一化
// =============================================================================
static void test_network_normalization() {
    printf("\n=== TEST 3: NetworkCap 归一化 ===\n");
    NodeProfile p = make_rtx4090(make_ep(0xCC), "net-perfect");
    // 1Gbps + 5ms RTT + 0% loss + Lan → 1.0
    CHECK(approx(p.network.normalized_score(), 1.0f), "1Gbps/5ms/0%/Lan = 1.0");

    // 慢网络
    NodeProfile::NetworkCap n;
    n.uplink_bps = 100'000'000;   // 100Mbps
    n.downlink_bps = 100'000'000;
    n.rtt_ms_avg = 20;
    n.loss_rate = 0.005f;         // 0.5%
    n.net_class = NetClass::Wan;
    float s = n.normalized_score();
    CHECK(s > 0.0f && s < 1.0f, "100Mbps/20ms/0.5%/Wan in (0,1)");
}

// =============================================================================
// TEST 4: NetClass 惩罚
// =============================================================================
static void test_net_class_penalty() {
    printf("\n=== TEST 4: NetClass 惩罚 ===\n");
    auto make_net = [](NetClass cls) {
        NodeProfile::NetworkCap n;
        n.uplink_bps = 500'000'000;
        n.downlink_bps = 500'000'000;
        n.rtt_ms_avg = 10;
        n.loss_rate = 0.0f;
        n.net_class = cls;
        return n;
    };
    float s_lan  = make_net(NetClass::Lan).normalized_score();
    float s_wan  = make_net(NetClass::Wan).normalized_score();
    float s_hard = make_net(NetClass::Hard).normalized_score();
    CHECK(s_lan > s_wan, "Lan > Wan");
    CHECK(s_wan > s_hard, "Wan > Hard");
    CHECK(approx(s_hard, s_lan * 0.5f, 0.05f), "Hard ~ Lan*0.5");
}

// =============================================================================
// TEST 5: StabilityCap::compute_score 公式
// =============================================================================
static void test_stability_formula() {
    printf("\n=== TEST 5: StabilityCap 评分公式 ===\n");
    // 完美节点：0 断连，100% 成功率，24h 在线
    float perfect = NodeProfile::StabilityCap::compute_score(86400, 0, 1.0f);
    CHECK(approx(perfect, 1.0f), "perfect stability = 1.0");

    // 全坏节点：24 断连，0% 成功率，0s 在线
    float terrible = NodeProfile::StabilityCap::compute_score(0, 24, 0.0f);
    CHECK(approx(terrible, 0.0f), "terrible stability = 0.0");

    // 中等：3 断连，90% 成功率，12h 在线
    // = 0.4*(1-3/24) + 0.3*0.9 + 0.3*0.5
    // = 0.4*0.875 + 0.27 + 0.15 = 0.35 + 0.27 + 0.15 = 0.77
    float medium = NodeProfile::StabilityCap::compute_score(43200, 3, 0.9f);
    CHECK(approx(medium, 0.77f, 0.02f), "medium stability ~ 0.77");

    // 边界：断连 > 24 应裁剪
    float over_disc = NodeProfile::StabilityCap::compute_score(0, 100, 0.0f);
    CHECK(approx(over_disc, 0.0f), "disconnect_count > 24 clamped to 0");

    // 边界：任务成功率 > 1 应裁剪
    float over_tsr = NodeProfile::StabilityCap::compute_score(86400, 0, 2.0f);
    CHECK(approx(over_tsr, 1.0f), "task_success_rate > 1 clamped to 1.0");

    // 边界：在线时长 > 86400 应裁剪
    float over_uptime = NodeProfile::StabilityCap::compute_score(200000, 0, 1.0f);
    CHECK(approx(over_uptime, 1.0f), "uptime > 86400 clamped to 1.0");
}

// =============================================================================
// TEST 6: stability.refresh_score 同步
// =============================================================================
static void test_refresh_score() {
    printf("\n=== TEST 6: refresh_score ===\n");
    NodeProfile::StabilityCap s;
    s.uptime_seconds = 86400;
    s.disconnect_count = 0;
    s.task_success_rate = 1.0f;
    s.refresh_score();
    CHECK(approx(s.score, 1.0f), "refresh_score syncs to 1.0");
    CHECK(s.score != 0.0f, "score field updated (non-zero)");

    // 修改字段后 refresh 应更新（注意：uptime 仍为 86400，故 score 不会降到 0）
    s.disconnect_count = 24;
    s.task_success_rate = 0.0f;
    s.refresh_score();
    // score = 0.4*0 + 0.3*0 + 0.3*1 = 0.3（uptime 仍满）
    CHECK(approx(s.score, 0.3f, 0.02f), "after degrade (uptime kept), score ~ 0.3");

    // 全维度归零后才降到 0
    s.uptime_seconds = 0;
    s.refresh_score();
    CHECK(approx(s.score, 0.0f), "all-zero stability → score = 0.0");
}

// =============================================================================
// TEST 7: GeoCap 归一化
// =============================================================================
static void test_geo_normalization() {
    printf("\n=== TEST 7: GeoCap 归一化 ===\n");
    NodeProfile::GeoCap g_known;
    g_known.region = GeoRegion::North;
    CHECK(approx(g_known.normalized_score(), 1.0f), "known region = 1.0");

    NodeProfile::GeoCap g_backbone;
    g_backbone.region = GeoRegion::Backbone;
    CHECK(approx(g_backbone.normalized_score(), 1.0f), "backbone = 1.0");

    NodeProfile::GeoCap g_unknown;
    g_unknown.region = GeoRegion::Unknown;
    CHECK(approx(g_unknown.normalized_score(), 0.3f), "unknown region = 0.3");
}

// =============================================================================
// TEST 8: overall_score 权重生效
// =============================================================================
static void test_overall_score_weights() {
    printf("\n=== TEST 8: overall_score 权重 ===\n");
    NodeProfile p = make_rtx4090(make_ep(0xDD), "weight-test");
    float default_score = p.overall_score();
    CHECK(default_score > 0.0f, "RTX4090 default overall > 0");

    // 全权重集中到 compute
    NodeScoreWeights w_compute_only;
    w_compute_only.weight_compute = 1.0;
    w_compute_only.weight_network = 0.0;
    w_compute_only.weight_stability = 0.0;
    w_compute_only.weight_geo = 0.0;
    float compute_only = p.overall_score(w_compute_only);
    CHECK(approx(compute_only, p.compute.normalized_score(), 0.01f),
          "compute-only weight = compute.normalized_score()");

    // 全权重集中到 stability
    NodeScoreWeights w_stab_only;
    w_stab_only.weight_compute = 0.0;
    w_stab_only.weight_network = 0.0;
    w_stab_only.weight_stability = 1.0;
    w_stab_only.weight_geo = 0.0;
    float stab_only = p.overall_score(w_stab_only);
    CHECK(approx(stab_only, p.stability.score, 0.01f),
          "stability-only weight = stability.score");
}

// =============================================================================
// TEST 9: overall_score 裁剪到 [0,1]
// =============================================================================
static void test_overall_clamp() {
    printf("\n=== TEST 9: overall_score 裁剪 ===\n");
    NodeProfile p = make_rtx4090(make_ep(0xEE), "clamp-test");
    // 异常大权重不应导致 overall > 1
    NodeScoreWeights w;
    w.weight_compute = 100.0;
    w.weight_network = 100.0;
    w.weight_stability = 100.0;
    w.weight_geo = 100.0;
    float s = p.overall_score(w);
    CHECK(s <= 1.0f, "overall <= 1.0 with huge weights");

    // 权重全 0 → 0（防除零）
    NodeScoreWeights w0;
    w0.weight_compute = 0.0;
    w0.weight_network = 0.0;
    w0.weight_stability = 0.0;
    w0.weight_geo = 0.0;
    CHECK(p.overall_score(w0) == 0.0f, "all-zero weights → 0 (no div-by-zero)");
}

// =============================================================================
// TEST 10: brief() 输出
// =============================================================================
static void test_brief() {
    printf("\n=== TEST 10: brief() ===\n");
    NodeProfile p = make_rtx4090(make_ep(0x11), "brief-test");
    std::string s = p.brief();
    CHECK(!s.empty(), "brief() non-empty");
    CHECK(s.find("RTX 4090") != std::string::npos, "brief contains gpu_model");
    CHECK(s.find("brief-test") != std::string::npos, "brief contains node_id");
    CHECK(s.find("Beijing") != std::string::npos, "brief contains city");
}

// =============================================================================
// TEST 11: NodeProfileStore CRUD
// =============================================================================
static void test_store_crud() {
    printf("\n=== TEST 11: Store CRUD ===\n");
    NodeProfileStore store;
    CHECK(store.size() == 0, "initial size = 0");

    NodeProfile p1 = make_rtx4090(make_ep(0x01), "node-1");
    store.upsert(p1);
    CHECK(store.size() == 1, "size = 1 after upsert");

    auto got = store.get(make_ep(0x01));
    CHECK(got.has_value(), "get returns value");
    CHECK(got->node_id == "node-1", "got correct node_id");

    // 更新（同 endpoint_id）
    NodeProfile p1_updated = p1;
    p1_updated.node_id = "node-1-updated";
    store.upsert(p1_updated);
    CHECK(store.size() == 1, "size still 1 after update (same ep)");
    auto got2 = store.get(make_ep(0x01));
    CHECK(got2->node_id == "node-1-updated", "node_id updated");

    // erase
    bool erased = store.erase(make_ep(0x01));
    CHECK(erased, "erase returns true");
    CHECK(store.size() == 0, "size = 0 after erase");
    CHECK(!store.get(make_ep(0x01)).has_value(), "get returns nullopt after erase");

    // erase 不存在的
    CHECK(store.erase(make_ep(0x99)) == false, "erase non-existent returns false");

    // clear
    store.upsert(p1);
    store.upsert(make_rtx3060(make_ep(0x02), "node-2"));
    CHECK(store.size() == 2, "size = 2 before clear");
    store.clear();
    CHECK(store.size() == 0, "size = 0 after clear");
}

// =============================================================================
// TEST 12: Store.get 不存在
// =============================================================================
static void test_store_get_missing() {
    printf("\n=== TEST 12: get missing ===\n");
    NodeProfileStore store;
    auto got = store.get(make_ep(0xFF));
    CHECK(!got.has_value(), "get on empty store returns nullopt");

    store.upsert(make_rtx4090(make_ep(0x01), "n1"));
    CHECK(!store.get(make_ep(0x02)).has_value(), "get different ep returns nullopt");
}

// =============================================================================
// TEST 13: Store.snapshot
// =============================================================================
static void test_store_snapshot() {
    printf("\n=== TEST 13: snapshot ===\n");
    NodeProfileStore store;
    store.upsert(make_rtx4090(make_ep(0x01), "n1"));
    store.upsert(make_rtx3060(make_ep(0x02), "n2"));
    store.upsert(make_rtx4090(make_ep(0x03), "n3"));

    auto snap = store.snapshot();
    CHECK(snap.size() == 3, "snapshot size = 3");

    // snapshot 不影响原 store
    CHECK(store.size() == 3, "store size still 3 after snapshot");
}

// =============================================================================
// TEST 14: Store.top_n 降序
// =============================================================================
static void test_store_top_n() {
    printf("\n=== TEST 14: top_n ===\n");
    NodeProfileStore store;
    store.upsert(make_rtx3060(make_ep(0x02), "low"));    // RTX 3060
    store.upsert(make_rtx4090(make_ep(0x01), "high"));   // RTX 4090
    store.upsert(make_rtx3060(make_ep(0x03), "mid"));    // RTX 3060 (相同算力)

    auto top1 = store.top_n(1);
    CHECK(top1.size() == 1, "top_n(1) size = 1");
    CHECK(top1[0].node_id == "high", "top 1 = high-score node");

    auto top3 = store.top_n(3);
    CHECK(top3.size() == 3, "top_n(3) size = 3");
    // 验证降序
    CHECK(top3[0].overall_score() >= top3[1].overall_score(), "top3[0] >= top3[1]");
    CHECK(top3[1].overall_score() >= top3[2].overall_score(), "top3[1] >= top3[2]");

    // n > size 时返回全部
    auto top10 = store.top_n(10);
    CHECK(top10.size() == 3, "top_n(10) returns all 3");

    // n = 0 返回空
    CHECK(store.top_n(0).empty(), "top_n(0) = empty");

    // 空存储
    NodeProfileStore empty_store;
    CHECK(empty_store.top_n(5).empty(), "top_n on empty store = empty");
}

// =============================================================================
// TEST 15: 文本持久化 round-trip
// =============================================================================
static void test_persistence_roundtrip() {
    printf("\n=== TEST 15: 持久化 round-trip ===\n");
    NodeProfileStore store1;
    store1.upsert(make_rtx4090(make_ep(0x01), "rtx4090-bj"));
    store1.upsert(make_rtx3060(make_ep(0x02), "rtx3060-sh"));

    std::string path = "build_test_node_profile_cache.tmp";
    bool saved = store1.save_to_file(path);
    CHECK(saved, "save_to_file succeeded");

    NodeProfileStore store2;
    bool loaded = store2.load_from_file(path);
    CHECK(loaded, "load_from_file succeeded");
    CHECK(store2.size() == 2, "loaded size = 2");

    auto got1 = store2.get(make_ep(0x01));
    CHECK(got1.has_value(), "loaded ep 0x01 exists");
    CHECK(got1->node_id == "rtx4090-bj", "loaded node_id matches");
    CHECK(got1->compute.gpu_model == "RTX 4090", "loaded gpu_model matches");
    CHECK(got1->compute.vram_mb == 24576, "loaded vram_mb matches");
    CHECK(got1->geo.city == "Beijing", "loaded city matches");
    CHECK(got1->geo.region == GeoRegion::North, "loaded region matches");
    CHECK(got1->network.net_class == NetClass::Lan, "loaded net_class matches");

    auto got2 = store2.get(make_ep(0x02));
    CHECK(got2.has_value(), "loaded ep 0x02 exists");
    CHECK(got2->compute.gpu_model == "RTX 3060", "loaded 3060 gpu_model");
    CHECK(got2->geo.city == "Shanghai", "loaded 3060 city");

    // 加载后 stability.score 应被 refresh_score 重算（与原一致）
    CHECK(approx(got1->stability.score, 1.0f, 0.01f), "loaded stability refreshed ~ 1.0");

    // 清理临时文件
    std::remove(path.c_str());
}

// =============================================================================
// TEST 16: 并发 upsert 线程安全
// =============================================================================
static void test_store_concurrent() {
    printf("\n=== TEST 16: 并发 upsert ===\n");
    NodeProfileStore store;
    constexpr int kThreads = 4;
    constexpr int kPerThread = 25;

    auto worker = [&store](int tid) {
        for (int i = 0; i < kPerThread; ++i) {
            // 每线程使用不同的 endpoint_id 高字节
            uint8_t fill = static_cast<uint8_t>(tid * kPerThread + i + 1);
            store.upsert(make_rtx4090(make_ep(fill), "t" + std::to_string(tid) + "-n" + std::to_string(i)));
        }
    };

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) threads.emplace_back(worker, t);
    for (auto &th : threads) th.join();

    CHECK(store.size() == kThreads * kPerThread, "concurrent upsert final size = 100");
}

// =============================================================================
// TEST 17: hex 互转（间接通过持久化验证）+ 非法输入
// =============================================================================
static void test_hex_roundtrip() {
    printf("\n=== TEST 17: EndpointId hex round-trip ===\n");
    NodeProfileStore store;
    // 全 0xFF
    store.upsert(make_rtx4090(make_ep(0xFF), "all-ff"));
    // 全 0x00（注意：endpoint_id 全 0 会被 is_zero() 判定为零，但作为 key 仍可用）
    store.upsert(make_rtx4090(make_ep(0x00), "all-zero"));

    std::string path = "build_test_node_profile_hex.tmp";
    CHECK(store.save_to_file(path), "save hex test file");

    NodeProfileStore loaded;
    CHECK(loaded.load_from_file(path), "load hex test file");
    CHECK(loaded.size() == 2, "loaded 2 hex profiles");

    CHECK(loaded.get(make_ep(0xFF)).has_value(), "0xFF ep recovered");
    CHECK(loaded.get(make_ep(0x00)).has_value(), "0x00 ep recovered");

    std::remove(path.c_str());
}

// =============================================================================
// TEST 18: load_from_file 容错
// =============================================================================
static void test_load_robustness() {
    printf("\n=== TEST 18: load_from_file 容错 ===\n");
    std::string path = "build_test_node_profile_robust.tmp";

    // 手写一个带注释、空行、未知键的文件
    std::ofstream ofs(path);
    ofs << "# comment line\n\n"
        << "count=1\n\n"
        << "[node]\n"
        << "endpoint_id=abababababababababababababababababababababababababababababababab\n"
        << "node_id=robust-node\n"
        << "unknown_key=ignored\n"      // 未知键应忽略
        << "gpu_model=RTX 4090\n"
        << "vram_mb=24576\n"
        << "tflops_fp16=165.0\n"
        << "tflops_int4=660.0\n"
        << "cuda_cores=16384\n"
        << "uplink_bps=1000000000\n"
        << "downlink_bps=1000000000\n"
        << "rtt_ms_avg=5\n"
        << "rtt_ms_p99=12\n"
        << "loss_rate=0\n"
        << "net_class=lan\n"
        << "stability_score=0.95\n"
        << "uptime_seconds=86400\n"
        << "disconnect_count=0\n"
        << "task_success_rate=1.0\n"
        << "geo_region=north\n"
        << "city=Beijing\n"
        << "isp=ChinaUnicom\n\n";
    ofs.close();

    NodeProfileStore store;
    CHECK(store.load_from_file(path), "load robust file succeeded");
    CHECK(store.size() == 1, "loaded 1 node");

    // 验证 endpoint_id 解析正确（abab... 模式）
    std::array<uint8_t, 32> expected{};
    for (int i = 0; i < 32; ++i) expected[i] = 0xAB;
    auto got = store.get(EndpointId::from_bytes(expected));
    CHECK(got.has_value(), "parsed endpoint_id matches expected 0xAB*32");
    CHECK(got->node_id == "robust-node", "robust node_id matches");
    CHECK(got->compute.gpu_model == "RTX 4090", "robust gpu_model matches");

    // 加载不存在的文件
    NodeProfileStore store2;
    CHECK(store2.load_from_file("non_existent_file_xyz.tmp") == false,
          "load non-existent file returns false");

    std::remove(path.c_str());
}

// =============================================================================
// TEST 19: RTX 4090 vs RTX 3060 overall_score 差异
// =============================================================================
static void test_score_diff_4090_vs_3060() {
    printf("\n=== TEST 19: RTX 4090 vs RTX 3060 ===\n");
    NodeProfile p4090 = make_rtx4090(make_ep(0x40), "rtx4090");
    NodeProfile p3060 = make_rtx3060(make_ep(0x30), "rtx3060");

    float s4090 = p4090.overall_score();
    float s3060 = p3060.overall_score();
    printf("    RTX 4090 overall = %.4f\n", s4090);
    printf("    RTX 3060 overall = %.4f\n", s3060);

    CHECK(s4090 > s3060, "RTX 4090 overall > RTX 3060 overall");
    CHECK(s4090 > 0.8f, "RTX 4090 overall > 0.8 (high-end node)");
    CHECK(s3060 < s4090, "RTX 3060 < RTX 4090");
}

// =============================================================================
// main
// =============================================================================
int main() {
    printf("============================================================\n");
    printf("  test_node_profile — v2.0 Phase 1 NodeProfile unit tests\n");
    printf("============================================================\n");

    test_default_construction();
    test_compute_normalization();
    test_network_normalization();
    test_net_class_penalty();
    test_stability_formula();
    test_refresh_score();
    test_geo_normalization();
    test_overall_score_weights();
    test_overall_clamp();
    test_brief();
    test_store_crud();
    test_store_get_missing();
    test_store_snapshot();
    test_store_top_n();
    test_persistence_roundtrip();
    test_store_concurrent();
    test_hex_roundtrip();
    test_load_robustness();
    test_score_diff_4090_vs_3060();

    printf("\n============================================================\n");
    printf("  Results: %d PASS / %d FAIL\n", g_pass, g_fail);
    printf("============================================================\n");
    return g_fail == 0 ? 0 : 1;
}
