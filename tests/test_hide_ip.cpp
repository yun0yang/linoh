// test_hide_ip.cpp — P2-G8 隐藏 IP 隐私模式单元测试
//
// 验证：
//   1. CandidateFilter 位掩码：单类型 / 多类型组合 / CF_ALL / CF_NONE
//   2. candidate_type_to_filter 映射
//   3. apply_filter：各类型过滤验证
//   4. candidate_filter_name 转字符串
//   5. CandidateCollectorConfig 默认值（enable_srflx=true, candidate_filter=CF_ALL）
//   6. enable_srflx=false：stun_servers 非空也不收集 srflx
//   7. candidate_filter=CF_RELAY：gather 后仅含 Relay
//   8. apply_hide_ip_policy：三重禁用 + G5 联动
//   9. is_hide_ip_policy_applied 审计函数
//  10. 幂等性：多次调用 apply_hide_ip_policy 结果一致

#include "linoh/nat/ice_candidate.hpp"
#include "linoh/nat/hide_ip_policy.hpp"
#include "linoh/relay/tcp_fallback.hpp"
#include "linoh/nat/ice_session.hpp"
#include "linoh/net/path.hpp"

#include <chrono>
#include <cstdio>
#include <future>
#include <optional>
#include <string>
#include <vector>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh;
using namespace linoh::nat;
using namespace linoh::relay;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 辅助：构造指定类型的候选
// ============================================================================

static Candidate make_candidate(CandidateType type, const std::string &ip, std::uint16_t port) {
    net::FourTuple tuple;
    tuple.local_addr.host = ip;
    tuple.local_addr.port = port;
    Candidate c(type, tuple, compute_candidate_priority(type), "found", std::chrono::milliseconds(0));
    return c;
}

static std::vector<Candidate> make_all_types() {
    return {
        make_candidate(CandidateType::Host, "192.168.1.1", 1000),
        make_candidate(CandidateType::ServerReflexive, "1.2.3.4", 2000),
        make_candidate(CandidateType::PeerReflexive, "5.6.7.8", 3000),
        make_candidate(CandidateType::Relay, "9.10.11.12", 4000),
        make_candidate(CandidateType::UPnPPortMapped, "192.168.1.1", 5000),
        make_candidate(CandidateType::Mdns, "local-mdns", 6000),
    };
}

// ============================================================================
// 1. candidate_type_to_filter 映射
// ============================================================================

static void test_type_to_filter_mapping() {
    CHECK(candidate_type_to_filter(CandidateType::Host) == CF_HOST);
    CHECK(candidate_type_to_filter(CandidateType::ServerReflexive) == CF_SERVER_REFLEXIVE);
    CHECK(candidate_type_to_filter(CandidateType::PeerReflexive) == CF_PEER_REFLEXIVE);
    CHECK(candidate_type_to_filter(CandidateType::Relay) == CF_RELAY);
    CHECK(candidate_type_to_filter(CandidateType::UPnPPortMapped) == CF_UPNP);
    CHECK(candidate_type_to_filter(CandidateType::Mdns) == CF_MDNS);
}

// ============================================================================
// 2. CandidateFilter 位掩码值
// ============================================================================

static void test_filter_bit_values() {
    CHECK(CF_NONE == 0);
    CHECK(CF_HOST == 1);
    CHECK(CF_SERVER_REFLEXIVE == 2);
    CHECK(CF_PEER_REFLEXIVE == 4);
    CHECK(CF_RELAY == 8);
    CHECK(CF_UPNP == 16);
    CHECK(CF_MDNS == 32);
    CHECK(CF_ALL == 0x3F);
    // 位掩码组合
    auto combo = static_cast<CandidateFilter>(CF_HOST | CF_RELAY);
    CHECK(static_cast<std::uint16_t>(combo) == (1 | 8));
}

// ============================================================================
// 3. apply_filter: CF_ALL 全保留
// ============================================================================

static void test_apply_filter_all() {
    auto all = make_all_types();
    auto r = apply_filter(all, CF_ALL);
    CHECK(r.size() == 6);
}

// ============================================================================
// 4. apply_filter: CF_NONE 全过滤
// ============================================================================

static void test_apply_filter_none() {
    auto all = make_all_types();
    auto r = apply_filter(all, CF_NONE);
    CHECK(r.empty());
}

// ============================================================================
// 5. apply_filter: 单类型过滤
// ============================================================================

static void test_apply_filter_single_type() {
    auto all = make_all_types();

    auto r_relay = apply_filter(all, CF_RELAY);
    CHECK(r_relay.size() == 1);
    CHECK(r_relay[0].type == CandidateType::Relay);

    auto r_host = apply_filter(all, CF_HOST);
    CHECK(r_host.size() == 1);
    CHECK(r_host[0].type == CandidateType::Host);

    auto r_srflx = apply_filter(all, CF_SERVER_REFLEXIVE);
    CHECK(r_srflx.size() == 1);
    CHECK(r_srflx[0].type == CandidateType::ServerReflexive);
}

// ============================================================================
// 6. apply_filter: 多类型组合
// ============================================================================

static void test_apply_filter_combo() {
    auto all = make_all_types();

    auto r = apply_filter(all, static_cast<CandidateFilter>(CF_HOST | CF_RELAY));
    CHECK(r.size() == 2);
    CHECK(r[0].type == CandidateType::Host);
    CHECK(r[1].type == CandidateType::Relay);

    auto r2 = apply_filter(all, static_cast<CandidateFilter>(CF_HOST | CF_SERVER_REFLEXIVE | CF_RELAY));
    CHECK(r2.size() == 3);
}

// ============================================================================
// 7. apply_filter: 空输入
// ============================================================================

static void test_apply_filter_empty_input() {
    std::vector<Candidate> empty;
    auto r = apply_filter(empty, CF_ALL);
    CHECK(r.empty());
    auto r2 = apply_filter(empty, CF_RELAY);
    CHECK(r2.empty());
}

// ============================================================================
// 8. apply_filter: 保持原顺序
// ============================================================================

static void test_apply_filter_preserves_order() {
    std::vector<Candidate> input = {
        make_candidate(CandidateType::Relay, "1.1.1.1", 100),
        make_candidate(CandidateType::Host, "2.2.2.2", 200),
        make_candidate(CandidateType::Relay, "3.3.3.3", 300),
    };
    auto r = apply_filter(input, CF_RELAY);
    CHECK(r.size() == 2);
    CHECK(r[0].tuple.local_addr.host == "1.1.1.1");
    CHECK(r[1].tuple.local_addr.host == "3.3.3.3");
}

// ============================================================================
// 9. candidate_filter_name 转字符串
// ============================================================================

static void test_filter_name() {
    CHECK(std::string(candidate_filter_name(CF_NONE)) == "none");
    CHECK(std::string(candidate_filter_name(CF_ALL)) == "all");
    CHECK(std::string(candidate_filter_name(CF_HOST)) == "host-only");
    CHECK(std::string(candidate_filter_name(CF_RELAY)) == "relay-only");
    // 组合返回 "mixed"
    auto combo = static_cast<CandidateFilter>(CF_HOST | CF_RELAY);
    CHECK(std::string(candidate_filter_name(combo)) == "mixed");
}

// ============================================================================
// 10. CandidateCollectorConfig 默认值（向后兼容）
// ============================================================================

static void test_collector_config_defaults() {
    CandidateCollectorConfig cfg;
    CHECK(cfg.enable_srflx == true);          // G8 新增，默认 true
    CHECK(cfg.candidate_filter == CF_ALL);    // G8 新增，默认 CF_ALL
    CHECK(cfg.enable_host == true);
    CHECK(cfg.enable_upnp == true);
    CHECK(cfg.enable_mdns == true);
}

// ============================================================================
// 11. enable_srflx=false：gather 不收集 srflx（mock 验证）
// ============================================================================

static void test_enable_srflx_false_skips_stun() {
    CandidateCollectorConfig cfg;
    cfg.enable_srflx = false;
    cfg.stun_servers = {"stun.example.com:3478", "stun2.example.com:3478"};
    cfg.relay_servers = {};  // 不收集 relay，避免 future 超时
    cfg.enable_host = false;  // 禁用 host 避免真实网卡遍历
    cfg.enable_upnp = false;
    cfg.enable_mdns = false;
    cfg.timeout = std::chrono::milliseconds(500);

    std::atomic<int> srflx_call_count{0};
    auto srflx_provider = [&](const std::string &) -> std::future<std::vector<Candidate>> {
        ++srflx_call_count;
        std::promise<std::vector<Candidate>> p;
        p.set_value({});
        return p.get_future();
    };
    auto host_provider = []() -> std::vector<Candidate> { return {}; };
    auto relay_provider = [&](const std::string &) -> std::future<std::vector<Candidate>> {
        std::promise<std::vector<Candidate>> p;
        p.set_value({});
        return p.get_future();
    };
    auto upnp_provider = []() -> std::future<std::optional<Candidate>> {
        std::promise<std::optional<Candidate>> p;
        p.set_value(std::nullopt);
        return p.get_future();
    };
    auto mdns_provider = []() -> std::future<std::optional<Candidate>> {
        std::promise<std::optional<Candidate>> p;
        p.set_value(std::nullopt);
        return p.get_future();
    };

    CandidateCollector collector(cfg, host_provider, srflx_provider,
                                 relay_provider, upnp_provider, mdns_provider);
    auto result = collector.gather_candidates_sync();
    CHECK(srflx_call_count.load() == 0);  // srflx provider 未被调用
}

// ============================================================================
// 12. enable_srflx=true（默认）：gather 调用 srflx provider
// ============================================================================

static void test_enable_srflx_true_calls_stun() {
    CandidateCollectorConfig cfg;
    cfg.enable_srflx = true;  // 默认
    cfg.stun_servers = {"stun.example.com:3478"};
    cfg.relay_servers = {};
    cfg.enable_host = false;
    cfg.enable_upnp = false;
    cfg.enable_mdns = false;
    cfg.timeout = std::chrono::milliseconds(500);

    std::atomic<int> srflx_call_count{0};
    auto srflx_provider = [&](const std::string &) -> std::future<std::vector<Candidate>> {
        ++srflx_call_count;
        std::promise<std::vector<Candidate>> p;
        p.set_value({make_candidate(CandidateType::ServerReflexive, "1.2.3.4", 5678)});
        return p.get_future();
    };
    auto host_provider = []() -> std::vector<Candidate> { return {}; };
    auto relay_provider = [&](const std::string &) -> std::future<std::vector<Candidate>> {
        std::promise<std::vector<Candidate>> p;
        p.set_value({});
        return p.get_future();
    };
    auto upnp_provider = []() -> std::future<std::optional<Candidate>> {
        std::promise<std::optional<Candidate>> p;
        p.set_value(std::nullopt);
        return p.get_future();
    };
    auto mdns_provider = []() -> std::future<std::optional<Candidate>> {
        std::promise<std::optional<Candidate>> p;
        p.set_value(std::nullopt);
        return p.get_future();
    };

    CandidateCollector collector(cfg, host_provider, srflx_provider,
                                 relay_provider, upnp_provider, mdns_provider);
    auto result = collector.gather_candidates_sync();
    CHECK(srflx_call_count.load() == 1);  // srflx provider 被调用 1 次
    // 候选中应含 srflx
    bool has_srflx = false;
    for (const auto &c : result.candidates) {
        if (c.type == CandidateType::ServerReflexive) { has_srflx = true; break; }
    }
    CHECK(has_srflx == true);
}

// ============================================================================
// 13. candidate_filter=CF_RELAY：gather 后仅含 Relay
// ============================================================================

static void test_candidate_filter_relay_only() {
    CandidateCollectorConfig cfg;
    cfg.enable_srflx = false;
    cfg.enable_host = true;   // 收集 host
    cfg.enable_upnp = false;
    cfg.enable_mdns = false;
    cfg.relay_servers = {};
    cfg.candidate_filter = CF_RELAY;  // 仅保留 Relay
    cfg.timeout = std::chrono::milliseconds(500);

    // host provider 返回 host 候选，但应被 filter 过滤掉
    auto host_provider = []() -> std::vector<Candidate> {
        return {make_candidate(CandidateType::Host, "192.168.1.100", 8000)};
    };
    auto srflx_provider = [&](const std::string &) -> std::future<std::vector<Candidate>> {
        std::promise<std::vector<Candidate>> p;
        p.set_value({});
        return p.get_future();
    };
    auto relay_provider = [&](const std::string &) -> std::future<std::vector<Candidate>> {
        std::promise<std::vector<Candidate>> p;
        p.set_value({make_candidate(CandidateType::Relay, "9.9.9.9", 9000)});
        return p.get_future();
    };
    auto upnp_provider = []() -> std::future<std::optional<Candidate>> {
        std::promise<std::optional<Candidate>> p;
        p.set_value(std::nullopt);
        return p.get_future();
    };
    auto mdns_provider = []() -> std::future<std::optional<Candidate>> {
        std::promise<std::optional<Candidate>> p;
        p.set_value(std::nullopt);
        return p.get_future();
    };

    // 需要提供 relay server 才会调用 relay provider
    cfg.relay_servers = {"relay://9.9.9.9:9000"};

    CandidateCollector collector(cfg, host_provider, srflx_provider,
                                 relay_provider, upnp_provider, mdns_provider);
    auto result = collector.gather_candidates_sync();

    // 候选应仅含 Relay（host 被 filter 过滤掉）
    CHECK(result.candidates.size() == 1);
    CHECK(result.candidates[0].type == CandidateType::Relay);
}

// ============================================================================
// 14. apply_hide_ip_to_collector：三重禁用候选收集
// ============================================================================

static void test_apply_hide_ip_to_collector() {
    CandidateCollectorConfig cfg;  // 默认全启用
    CHECK(cfg.enable_host == true);
    CHECK(cfg.enable_srflx == true);

    apply_hide_ip_to_collector(cfg);
    CHECK(cfg.enable_host == false);
    CHECK(cfg.enable_srflx == false);
    CHECK(cfg.enable_upnp == false);
    CHECK(cfg.enable_mdns == false);
    CHECK(cfg.candidate_filter == CF_RELAY);
}

// ============================================================================
// 15. apply_hide_ip_to_fallback：强制 TCP
// ============================================================================

static void test_apply_hide_ip_to_fallback() {
    FallbackConfig cfg;  // 默认 skip_udp_probe=false
    CHECK(cfg.skip_udp_probe == false);

    apply_hide_ip_to_fallback(cfg);
    CHECK(cfg.skip_udp_probe == true);
}

// ============================================================================
// 16. apply_hide_ip_to_ice：G5 联动
// ============================================================================

static void test_apply_hide_ip_to_ice() {
    IceSessionConfig cfg;  // 默认全 false
    CHECK(cfg.presume_writable_when_fully_relayed == false);
    CHECK(cfg.skip_relay_to_non_relay_connections == false);

    apply_hide_ip_to_ice(cfg);
    CHECK(cfg.presume_writable_when_fully_relayed == true);
    CHECK(cfg.skip_relay_to_non_relay_connections == true);
}

// ============================================================================
// 17. apply_hide_ip_policy：聚合三组配置
// ============================================================================

static void test_apply_hide_ip_policy_aggregate() {
    CandidateCollectorConfig collector;
    FallbackConfig fallback;
    IceSessionConfig ice;

    apply_hide_ip_policy(collector, fallback, ice);
    CHECK(is_hide_ip_policy_applied(collector, fallback, ice) == true);
}

// ============================================================================
// 18. is_hide_ip_policy_applied：未应用时返回 false
// ============================================================================

static void test_is_hide_ip_not_applied() {
    CandidateCollectorConfig collector;  // 默认
    FallbackConfig fallback;             // 默认
    IceSessionConfig ice;                // 默认
    CHECK(is_hide_ip_policy_applied(collector, fallback, ice) == false);

    // 仅部分应用
    apply_hide_ip_to_collector(collector);
    CHECK(is_hide_ip_policy_applied(collector, fallback, ice) == false);
}

// ============================================================================
// 19. 幂等性：多次调用结果一致
// ============================================================================

static void test_apply_hide_ip_idempotent() {
    CandidateCollectorConfig collector;
    FallbackConfig fallback;
    IceSessionConfig ice;

    apply_hide_ip_policy(collector, fallback, ice);
    auto collector_filter_1 = collector.candidate_filter;
    auto skip_udp_1 = fallback.skip_udp_probe;
    auto presume_1 = ice.presume_writable_when_fully_relayed;

    apply_hide_ip_policy(collector, fallback, ice);  // 再调一次
    CHECK(collector.candidate_filter == collector_filter_1);
    CHECK(fallback.skip_udp_probe == skip_udp_1);
    CHECK(ice.presume_writable_when_fully_relayed == presume_1);
    CHECK(is_hide_ip_policy_applied(collector, fallback, ice) == true);
}

// ============================================================================
// 20. 审计函数：单个配置检查
// ============================================================================

static void test_audit_functions() {
    CandidateCollectorConfig collector;
    FallbackConfig fallback;
    IceSessionConfig ice;

    CHECK(is_hide_ip_collector_config(collector) == false);
    CHECK(is_hide_ip_fallback_config(fallback) == false);
    CHECK(is_hide_ip_ice_config(ice) == false);

    apply_hide_ip_to_collector(collector);
    CHECK(is_hide_ip_collector_config(collector) == true);

    apply_hide_ip_to_fallback(fallback);
    CHECK(is_hide_ip_fallback_config(fallback) == true);

    apply_hide_ip_to_ice(ice);
    CHECK(is_hide_ip_ice_config(ice) == true);
}

int main() {
    test_type_to_filter_mapping();
    test_filter_bit_values();
    test_apply_filter_all();
    test_apply_filter_none();
    test_apply_filter_single_type();
    test_apply_filter_combo();
    test_apply_filter_empty_input();
    test_apply_filter_preserves_order();
    test_filter_name();
    test_collector_config_defaults();
    test_enable_srflx_false_skips_stun();
    test_enable_srflx_true_calls_stun();
    test_candidate_filter_relay_only();
    test_apply_hide_ip_to_collector();
    test_apply_hide_ip_to_fallback();
    test_apply_hide_ip_to_ice();
    test_apply_hide_ip_policy_aggregate();
    test_is_hide_ip_not_applied();
    test_apply_hide_ip_idempotent();
    test_audit_functions();

    std::printf("test_hide_ip: %d passed, %d failed\n",
                pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
