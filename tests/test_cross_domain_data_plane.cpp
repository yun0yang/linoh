// test_cross_domain_data_plane.cpp — V3-B 跨域数据面通道与传输增强测试
//
// 验证目标（V3-B 协议规范 M1-M5）：
//   1. BBR 跨域参数自适应（apply_cross_domain_config / min_rtt_window / probe_rtt_interval / cwnd_gain）
//   2. 跨域 MTU 协商（negotiate_cross_domain：默认 1500 / force_jumbo 9000 / 困难 NAT 1280）
//   3. RelayPool 跨域感知选择（select_for_cross_domain 骨干优先 + 降级链）
//   4. 多路径协同选择器跨域/Relay 权重（RTT 飙升阈值放宽 + Relay 0.7 折扣）
//   5. NodeRegistry 跨域地址缓存（cache / get / resolve / prune）
//   6. Connection 跨域标记与统计（set_cross_domain / cross_domain_stats / congestion_controller）
//
// 编译：build_all.bat 纳入 test_cross_domain_data_plane 目标
// 运行：test_cross_domain_data_plane.exe，输出 PASS/FAIL 汇总

#include "linoh/protocol/bbr_v2.hpp"
#include "linoh/protocol/congestion_controller.hpp"
#include "linoh/protocol/loss_recovery.hpp"
#include "linoh/protocol/multipath_coordinated_selector.hpp"
#include "linoh/net/mtu.hpp"
#include "linoh/net/net_report.hpp"
#include "linoh/nat/relay_pool.hpp"
#include "linoh/control_plane.hpp"
#include "linoh/endpoint/connection.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::protocol;
using namespace linoh::net;
using namespace linoh::nat;
using namespace linoh::base;

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; } \
    else { printf("  [FAIL] %s (line %d)\n", msg, __LINE__); g_fail++; } \
} while (0)

// =============================================================================
// TEST 1: BBR 跨域参数自适应
// =============================================================================
static void test_bbr_cross_domain_config() {
    printf("\n=== TEST 1: BBR 跨域参数自适应 ===\n");

    // 1.1 默认参数（单域）
    BbrV2Controller bbr_default;
    CHECK(bbr_default.is_cross_domain_configured() == false,
          "默认未应用跨域参数");
    CHECK(bbr_default.min_rtt_window_ms() == 10000.0,
          "默认 min_rtt_window = 10s（单域）");
    CHECK(bbr_default.probe_rtt_interval_ms() == 10000.0,
          "默认 probe_rtt_interval = 10s（单域）");
    CHECK(bbr_default.cwnd_gain_multiplier() == 1.0,
          "默认 cwnd_gain_multiplier = 1.0（单域）");

    // 1.2 应用跨域参数（默认值）
    BbrV2Controller bbr;
    BbrCrossDomainConfig cfg;
    bool ok = bbr.apply_cross_domain_config(cfg);
    CHECK(ok == true, "apply_cross_domain_config 返回 true");
    CHECK(bbr.is_cross_domain_configured() == true,
          "应用后 is_cross_domain_configured = true");
    CHECK(bbr.min_rtt_window_ms() == 30000.0,
          "跨域 min_rtt_window = 30s");
    CHECK(bbr.probe_rtt_interval_ms() == 60000.0,
          "跨域 probe_rtt_interval = 60s");
    CHECK(bbr.cwnd_gain_multiplier() == 1.5,
          "跨域 cwnd_gain_multiplier = 1.5（3.0/2.0）");

    // 1.3 自定义跨域参数
    BbrV2Controller bbr2;
    BbrCrossDomainConfig cfg2;
    cfg2.cross_domain_min_rtt_window = std::chrono::seconds(45);
    cfg2.cross_domain_probe_rtt_interval = std::chrono::seconds(90);
    cfg2.cross_domain_cwnd_gain = 4.0;  // multiplier = 2.0
    bbr2.apply_cross_domain_config(cfg2);
    CHECK(bbr2.min_rtt_window_ms() == 45000.0,
          "自定义 min_rtt_window = 45s");
    CHECK(bbr2.probe_rtt_interval_ms() == 90000.0,
          "自定义 probe_rtt_interval = 90s");
    CHECK(bbr2.cwnd_gain_multiplier() == 2.0,
          "自定义 cwnd_gain_multiplier = 2.0（4.0/2.0）");

    // 1.4 安全下限：min_rtt_window < 1s 钳制到 1s
    // 注：字段类型为 std::chrono::seconds，0s（< 1s）触发安全下限钳制到 1000ms
    BbrV2Controller bbr3;
    BbrCrossDomainConfig cfg3;
    cfg3.cross_domain_min_rtt_window = std::chrono::seconds(0);  // 0s < 1s → 钳制
    bbr3.apply_cross_domain_config(cfg3);
    CHECK(bbr3.min_rtt_window_ms() == 1000.0,
          "min_rtt_window 安全下限 = 1s");

    // 1.5 probe_rtt_interval < min_rtt_window 钳制到 min_rtt_window
    BbrV2Controller bbr4;
    BbrCrossDomainConfig cfg4;
    cfg4.cross_domain_min_rtt_window = std::chrono::seconds(30);
    cfg4.cross_domain_probe_rtt_interval = std::chrono::seconds(10);  // < 30s
    bbr4.apply_cross_domain_config(cfg4);
    CHECK(bbr4.probe_rtt_interval_ms() == 30000.0,
          "probe_rtt_interval 钳制到 min_rtt_window = 30s");

    // 1.6 cwnd_gain_multiplier 范围 [0.5, 3.0]
    BbrV2Controller bbr5;
    BbrCrossDomainConfig cfg5;
    cfg5.cross_domain_cwnd_gain = 0.5;  // multiplier = 0.25 → 钳制到 0.5
    bbr5.apply_cross_domain_config(cfg5);
    CHECK(bbr5.cwnd_gain_multiplier() == 0.5,
          "cwnd_gain_multiplier 下限 = 0.5");

    BbrV2Controller bbr6;
    BbrCrossDomainConfig cfg6;
    cfg6.cross_domain_cwnd_gain = 10.0;  // multiplier = 5.0 → 钳制到 3.0
    bbr6.apply_cross_domain_config(cfg6);
    CHECK(bbr6.cwnd_gain_multiplier() == 3.0,
          "cwnd_gain_multiplier 上限 = 3.0");

    // 1.7 NewReno 不支持跨域自适应
    auto newreno = make_congestion_controller(CongestionAlgo::NewReno, nullptr);
    BbrCrossDomainConfig cfg7;
    bool newreno_ok = newreno->apply_cross_domain_config(cfg7);
    CHECK(newreno_ok == false, "NewReno apply_cross_domain_config 返回 false");
    CHECK(newreno->is_cross_domain_configured() == false,
          "NewReno is_cross_domain_configured = false");
}

// =============================================================================
// TEST 2: 跨域 MTU 协商
// =============================================================================
static void test_mtu_cross_domain() {
    printf("\n=== TEST 2: 跨域 MTU 协商 ===\n");

    // 2.1 默认跨域：双方 9000 但不 force_jumbo → 1500
    auto r1 = MtuNegotiator::negotiate_cross_domain(
        MtuConstants::kJumboMtu, MtuConstants::kJumboMtu,
        NatType::OpenInternet, UdpFirewall::Open, false);
    CHECK(r1.negotiated_mtu == 1500,
          "跨域默认 MTU = 1500（不启用 jumbo）");
    CHECK(r1.jumbo_enabled == false,
          "跨域默认 jumbo_enabled = false");

    // 2.2 force_jumbo + 双方 9000 → 9000
    auto r2 = MtuNegotiator::negotiate_cross_domain(
        MtuConstants::kJumboMtu, MtuConstants::kJumboMtu,
        NatType::OpenInternet, UdpFirewall::Open, true);
    CHECK(r2.negotiated_mtu == 9000,
          "force_jumbo + 双方 9000 → 9000");
    CHECK(r2.jumbo_enabled == true,
          "force_jumbo jumbo_enabled = true");

    // 2.3 force_jumbo 但一方 < 9000 → 1500
    auto r3 = MtuNegotiator::negotiate_cross_domain(
        MtuConstants::kJumboMtu, MtuConstants::kStandardMtu,
        NatType::OpenInternet, UdpFirewall::Open, true);
    CHECK(r3.negotiated_mtu == 1500,
          "force_jumbo 但一方 < 9000 → 1500");
    CHECK(r3.jumbo_enabled == false,
          "一方不支持 jumbo → false");

    // 2.4 困难 NAT（Symmetric）→ 1280
    auto r4 = MtuNegotiator::negotiate_cross_domain(
        MtuConstants::kStandardMtu, MtuConstants::kStandardMtu,
        NatType::Symmetric, UdpFirewall::Open, false);
    CHECK(r4.negotiated_mtu == 1280,
          "Symmetric NAT → 1280（最小 MTU）");

    // 2.5 Unknown NAT → 1280
    auto r5 = MtuNegotiator::negotiate_cross_domain(
        MtuConstants::kStandardMtu, MtuConstants::kStandardMtu,
        NatType::Unknown, UdpFirewall::Open, false);
    CHECK(r5.negotiated_mtu == 1280,
          "Unknown NAT → 1280");

    // 2.6 UDP Blocked → 1280
    auto r6 = MtuNegotiator::negotiate_cross_domain(
        MtuConstants::kStandardMtu, MtuConstants::kStandardMtu,
        NatType::OpenInternet, UdpFirewall::Blocked, false);
    CHECK(r6.negotiated_mtu == 1280,
          "UDP Blocked → 1280");

    // 2.7 一方 < 1500 → 取 min
    auto r7 = MtuNegotiator::negotiate_cross_domain(
        1400, MtuConstants::kStandardMtu,
        NatType::OpenInternet, UdpFirewall::Open, false);
    CHECK(r7.negotiated_mtu == 1400,
          "一方 1400 → 取 min(1400, 1500) = 1400");

    // 2.8 FullCone NAT 正常跨域 → 1500
    auto r8 = MtuNegotiator::negotiate_cross_domain(
        MtuConstants::kStandardMtu, MtuConstants::kStandardMtu,
        NatType::FullCone, UdpFirewall::Open, false);
    CHECK(r8.negotiated_mtu == 1500,
          "FullCone NAT 跨域 → 1500");
}

// =============================================================================
// TEST 3: RelayPool 跨域感知选择
// =============================================================================
static void test_relay_pool_cross_domain() {
    printf("\n=== TEST 3: RelayPool 跨域感知选择 ===\n");

    // Mock 探测器：所有 Relay 健康成功
    auto probe = [](const RelayUrl &) {
        HealthProbeResult r;
        r.success = true;
        r.rtt = std::chrono::milliseconds(50);
        return r;
    };

    RelayPoolConfig cfg;
    cfg.local_region = GeoRegion::North;
    RelayPool pool(cfg, probe);

    // 3.1 初始无 Relay，select_for_cross_domain 返回 nullopt
    auto empty = pool.select_for_cross_domain();
    CHECK(!empty.has_value(),
          "空池 select_for_cross_domain = nullopt");

    // 3.2 设置跨域骨干 Relay
    std::vector<RelayUrl> backbone_urls;
    backbone_urls.emplace_back("https://backbone1.example.com/");
    backbone_urls.emplace_back("https://backbone2.example.com/");
    pool.set_cross_domain_backbone_relays(backbone_urls);

    // 3.3 探测使骨干 Relay 健康
    pool.check_all_sync();

    // 3.4 select_for_cross_domain 应返回骨干 Relay
    auto sel = pool.select_for_cross_domain();
    CHECK(sel.has_value(), "有骨干 Relay 时 select_for_cross_domain 返回值");
    if (sel.has_value()) {
        bool is_backbone_url =
            sel->url.url() == "https://backbone1.example.com/" ||
            sel->url.url() == "https://backbone2.example.com/";
        CHECK(is_backbone_url, "选中骨干 Relay URL");
        CHECK(sel->role == RelayRole::Backbone,
              "选中 Relay role = Backbone");
        CHECK(sel->pinned == true,
              "骨干 Relay pinned = true");
    }

    // 3.5 添加区域 Relay（非骨干），验证骨干优先
    pool.add_relay(RelayUrl("https://region1.example.com/"));
    pool.check_all_sync();
    auto sel2 = pool.select_for_cross_domain();
    CHECK(sel2.has_value(), "有骨干+区域时返回值");
    if (sel2.has_value()) {
        CHECK(sel2->role == RelayRole::Backbone,
              "有骨干时优先选骨干（非区域）");
    }

    // 3.6 重复 set_cross_domain_backbone_relays 不重复入池
    std::vector<RelayUrl> dup_urls;
    dup_urls.emplace_back("https://backbone1.example.com/");  // 已存在
    dup_urls.emplace_back("https://backbone3.example.com/");  // 新增
    pool.set_cross_domain_backbone_relays(dup_urls);
    // 池中应包含 backbone1, backbone2, backbone3 + region1（不重复 backbone1）
    auto sel3 = pool.select_for_cross_domain();
    CHECK(sel3.has_value(), "重复设置后仍可选择");
}

// =============================================================================
// TEST 4: 多路径协同选择器跨域/Relay 权重
// =============================================================================
static void test_multipath_cross_domain() {
    printf("\n=== TEST 4: 多路径协同选择器跨域/Relay 权重 ===\n");

    // 4.1 CoordinatedPathInfo 新增字段默认值
    CoordinatedPathInfo info;
    CHECK(info.is_cross_domain == false,
          "CoordinatedPathInfo.is_cross_domain 默认 false");
    CHECK(info.is_relay_path == false,
          "CoordinatedPathInfo.is_relay_path 默认 false");

    // 4.2 PathHealth 新增字段
    MultipathCoordinatedSelector selector(2);
    // 创建两个 BBR 控制器（pacing_rate > 0 用于权重计算）
    RttEstimator rtt;
    rtt.update(10.0, 0.0);
    auto ctrl1 = std::make_unique<BbrV2Controller>();
    ctrl1->set_rtt_estimator(&rtt);
    auto ctrl2 = std::make_unique<BbrV2Controller>();
    ctrl2->set_rtt_estimator(&rtt);

    // 触发 pacing_rate > 0
    ctrl1->on_ack(100000, 1);
    ctrl2->on_ack(100000, 1);

    FourTuple tuple1{};
    tuple1.local_addr.host = "10.0.0.1";
    tuple1.remote_addr.host = "10.0.0.2";
    FourTuple tuple2{};
    tuple2.local_addr.host = "10.0.0.3";
    tuple2.remote_addr.host = "10.0.0.4";

    std::vector<CoordinatedPathInfo> paths;
    paths.push_back({tuple1, ctrl1.get(), std::chrono::microseconds(10000), 0.0,
                     false, false});  // 直连本域
    paths.push_back({tuple2, ctrl2.get(), std::chrono::microseconds(10000), 0.0,
                     false, true});   // Relay 路径
    selector.update_candidates(std::move(paths));

    // 4.3 Relay 路径权重应低于直连路径（0.7 折扣）
    auto health = selector.path_health_stats();
    CHECK(health.size() == 2, "path_health_stats 返回 2 条路径");
    if (health.size() == 2) {
        // 找到 Relay 路径和直连路径
        double direct_weight = 0.0, relay_weight = 0.0;
        for (const auto &h : health) {
            if (h.is_relay_path) relay_weight = h.weight;
            else direct_weight = h.weight;
        }
        CHECK(relay_weight < direct_weight,
              "Relay 路径权重 < 直连路径权重（0.7 折扣）");
        CHECK(health[0].is_relay_path == false || health[1].is_relay_path == true,
              "PathHealth 含 is_relay_path 字段");
    }

    // 4.4 跨域路径 RTT 飙升阈值放宽（5x 而非 3x）
    // 构造跨域路径，baseline=10ms，RTT=40ms（4x baseline）
    // 本域路径 4x baseline 会触发 rtt_spike，跨域路径 4x 不触发（< 5x）
    MultipathCoordinatedSelector selector2(2);
    auto ctrl3 = std::make_unique<BbrV2Controller>();
    ctrl3->set_rtt_estimator(&rtt);
    ctrl3->on_ack(100000, 1);
    auto ctrl4 = std::make_unique<BbrV2Controller>();
    ctrl4->set_rtt_estimator(&rtt);
    ctrl4->on_ack(100000, 1);

    FourTuple tuple3{};
    tuple3.local_addr.host = "10.0.0.5";
    tuple3.remote_addr.host = "10.0.0.6";
    FourTuple tuple4{};
    tuple4.local_addr.host = "10.0.0.7";
    tuple4.remote_addr.host = "10.0.0.8";

    // 第一次 update_candidates：srtt=10ms，建立 baseline=10ms
    // （update_candidates 按 tuple 匹配保留 baseline，故需先建立再触发）
    std::vector<CoordinatedPathInfo> paths_init;
    paths_init.push_back({tuple3, ctrl3.get(), std::chrono::microseconds(10000), 0.0,
                          false, false});  // 本域 baseline=10ms
    paths_init.push_back({tuple4, ctrl4.get(), std::chrono::microseconds(10000), 0.0,
                          true, false});   // 跨域 baseline=10ms
    selector2.update_candidates(std::move(paths_init));

    // 第二次 update_candidates：srtt=40ms（4x baseline），触发 spike 检查
    // 本域：40 > 10*3=30 → rtt_spike；跨域：40 > 10*5=50? 否 → 不触发
    std::vector<CoordinatedPathInfo> paths2;
    paths2.push_back({tuple3, ctrl3.get(), std::chrono::microseconds(40000), 0.0,
                      false, false});  // 本域，4x baseline → rtt_spike
    paths2.push_back({tuple4, ctrl4.get(), std::chrono::microseconds(40000), 0.0,
                      true, false});   // 跨域，4x baseline → 不触发（< 5x）
    selector2.update_candidates(std::move(paths2));

    auto health2 = selector2.path_health_stats();
    CHECK(health2.size() == 2, "跨域测试 path_health_stats 返回 2 条");
    if (health2.size() == 2) {
        // 本域路径应处于退化态（rtt_spike），跨域路径不应退化
        bool local_degraded = false, cross_domain_degraded = false;
        for (const auto &h : health2) {
            if (h.is_cross_domain) cross_domain_degraded = h.is_degraded;
            else local_degraded = h.is_degraded;
        }
        CHECK(local_degraded == true,
              "本域路径 4x baseline → 退化（rtt_spike）");
        CHECK(cross_domain_degraded == false,
              "跨域路径 4x baseline → 不退化（阈值 5x）");
    }
}

// =============================================================================
// TEST 5: NodeRegistry 跨域地址缓存
// =============================================================================
static void test_node_registry_addr_cache() {
    printf("\n=== TEST 5: NodeRegistry 跨域地址缓存 ===\n");

    NodeRegistry registry;

    // 5.1 初始缓存为空
    PublicKey id1;
    std::memset(id1.data(), 0xAB, 32);

    auto empty = registry.get_cross_domain_addr(id1);
    CHECK(!empty.has_value(), "初始缓存 get_cross_domain_addr = nullopt");
    CHECK(registry.cross_domain_addr_cache_size() == 0,
          "初始缓存大小 = 0");

    // 5.2 缓存地址
    EndpointAddr addr;
    addr.add_direct_address(TransportAddr{.host = "10.1.2.3", .port = 9001});
    registry.cache_cross_domain_addr(id1, addr);

    CHECK(registry.cross_domain_addr_cache_size() == 1,
          "缓存后大小 = 1");

    // 5.3 查询缓存命中
    auto cached = registry.get_cross_domain_addr(id1);
    CHECK(cached.has_value(), "get_cross_domain_addr 命中缓存");
    if (cached.has_value()) {
        CHECK(!cached->direct_addresses().empty(),
              "缓存地址含 direct_addresses");
        if (!cached->direct_addresses().empty()) {
            CHECK(cached->direct_addresses()[0].host == "10.1.2.3",
                  "缓存地址 host = 10.1.2.3");
            CHECK(cached->direct_addresses()[0].port == 9001,
                  "缓存地址 port = 9001");
        }
    }

    // 5.4 resolve_cross_domain_addr 缓存命中（无 DNS lookup）
    auto resolved = registry.resolve_cross_domain_addr(id1, nullptr);
    CHECK(resolved.has_value(), "resolve_cross_domain_addr 缓存命中");
    if (resolved.has_value()) {
        CHECK(!resolved->direct_addresses().empty(),
              "resolve 结果含 direct_addresses");
    }

    // 5.5 未缓存的 ID，无 DNS lookup → nullopt
    PublicKey id2;
    std::memset(id2.data(), 0xCD, 32);
    auto not_cached = registry.resolve_cross_domain_addr(id2, nullptr);
    CHECK(!not_cached.has_value(),
          "未缓存 + 无 DNS → resolve 返回 nullopt");

    // 5.6 prune 过期清理
    // prune 语义：age > timeout 才清理（age = duration_cast<seconds>(now - cached_at)）
    // 刚缓存的 age=0s，0 > 0 为 false，故需等待 >1s 使 age 截断为 1s > 0s 触发清理
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    auto pruned = registry.prune_cross_domain_addr_cache(std::chrono::seconds(0));
    CHECK(pruned >= 1, "prune 清理至少 1 条");
    CHECK(registry.cross_domain_addr_cache_size() == 0,
          "prune 后缓存大小 = 0");
}

// =============================================================================
// TEST 6: Connection 跨域标记与统计
// =============================================================================
static void test_connection_cross_domain() {
    printf("\n=== TEST 6: Connection 跨域标记与统计 ===\n");

    // 构造一个 Connection（出站方向）
    endpoint::Connection::Config cfg;
    cfg.alpn = "pp-hidden/1";
    cfg.direction = endpoint::Direction::Outbound;
    cfg.is_cross_domain = false;  // 初始非跨域
    cfg.peer_domain_id = 0;

    auto conn = std::make_shared<endpoint::Connection>(std::move(cfg));

    // 6.1 初始非跨域
    CHECK(conn->is_cross_domain() == false,
          "初始 is_cross_domain = false");
    CHECK(conn->peer_domain_id() == 0,
          "初始 peer_domain_id = 0");

    // 6.2 初始统计全零
    auto stats0 = conn->cross_domain_stats();
    CHECK(stats0.bytes_sent_cross_domain == 0,
          "初始 bytes_sent = 0");
    CHECK(stats0.bytes_received_cross_domain == 0,
          "初始 bytes_received = 0");
    CHECK(stats0.rtt_ms == 0,
          "初始 rtt_ms = 0");

    // 6.3 运行时标记为跨域
    conn->set_cross_domain(true, 42);
    CHECK(conn->is_cross_domain() == true,
          "set_cross_domain 后 is_cross_domain = true");
    CHECK(conn->peer_domain_id() == 42,
          "set_cross_domain 后 peer_domain_id = 42");

    // 6.4 累积跨域字节统计
    conn->add_cross_domain_bytes_sent(1024);
    conn->add_cross_domain_bytes_sent(2048);
    conn->add_cross_domain_bytes_received(4096);

    auto stats1 = conn->cross_domain_stats();
    CHECK(stats1.bytes_sent_cross_domain == 3072,
          "累积 bytes_sent = 3072");
    CHECK(stats1.bytes_received_cross_domain == 4096,
          "累积 bytes_received = 4096");
    CHECK(stats1.peer_domain_id == 42,
          "stats.peer_domain_id = 42");

    // 6.5 更新跨域 RTT
    conn->set_cross_domain_rtt_ms(150);
    auto stats2 = conn->cross_domain_stats();
    CHECK(stats2.rtt_ms == 150,
          "set_cross_domain_rtt_ms 后 rtt_ms = 150");

    // 6.6 非跨域连接不累积统计
    endpoint::Connection::Config cfg2;
    cfg2.alpn = "pp-hidden/1";
    cfg2.direction = endpoint::Direction::Outbound;
    cfg2.is_cross_domain = false;
    auto conn2 = std::make_shared<endpoint::Connection>(std::move(cfg2));
    conn2->add_cross_domain_bytes_sent(9999);  // 应被忽略
    auto stats3 = conn2->cross_domain_stats();
    CHECK(stats3.bytes_sent_cross_domain == 0,
          "非跨域连接 add_cross_domain_bytes_sent 被忽略");

    // 6.7 congestion_controller() 返回非 null
    auto *controller = conn->congestion_controller();
    CHECK(controller != nullptr,
          "congestion_controller() 返回非 null");
    if (controller != nullptr) {
        std::string_view algo = controller->algo_name();
        CHECK(algo == "newreno" || algo == "bbrv2",
              "congestion_controller algo_name 有效");
    }

    // 6.8 取消跨域标记
    conn->set_cross_domain(false);
    CHECK(conn->is_cross_domain() == false,
          "set_cross_domain(false) 后 is_cross_domain = false");
}

// =============================================================================
// main
// =============================================================================
int main() {
    printf("============================================================\n");
    printf("linoh V3-B 跨域数据面通道与传输增强测试\n");
    printf("============================================================\n");

    test_bbr_cross_domain_config();
    test_mtu_cross_domain();
    test_relay_pool_cross_domain();
    test_multipath_cross_domain();
    test_node_registry_addr_cache();
    test_connection_cross_domain();

    printf("\n============================================================\n");
    printf("汇总: %d PASS, %d FAIL\n", g_pass, g_fail);
    printf("============================================================\n");
    return g_fail == 0 ? 0 : 1;
}
