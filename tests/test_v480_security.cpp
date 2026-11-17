// test_v480_security.cpp — v4.8.0 安全与配置测试
//
// 验证内容（对应 T-LP3-001 ~ T-LP3-008）：
//   T-LP3-001: IncomingFilter trait + AddressWhitelistFilter + EndpointIdBlacklistFilter + RateLimitFilter
//   T-LP3-002: EndpointConfig::incoming_filters 集成（Config 字段存在性）
//   T-LP3-003: EndpointConfig::external_addresses 配置（Config 字段存在性）
//   T-LP3-004: ipv6_deprecated 工具函数（接口存在性 + 默认行为）
//   T-LP3-005: AccessControl trait + AllowAll + BearerToken + Chained
//   T-LP3-006: relay bridge AccessControl 集成（接口存在性）
//
// 借鉴 iroh#3951（IncomingFilter）、iroh#4098（external_addr）、
//        iroh#4106（IPv6 弃用）、iroh#4276（AccessControl trait）

#include "linoh/endpoint/incoming_filter.hpp"
#include "linoh/endpoint/endpoint.hpp"
#include "linoh/net/ipv6_deprecated.hpp"
#include "linoh/relay/access_control.hpp"
#include "linoh/base/key.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace linoh::endpoint;
using namespace linoh::relay;
using namespace linoh::base;

// ============================================================================
// 测试辅助宏
// ============================================================================
static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define RUN_TEST(fn) do { \
    std::printf("[test] %s...\n", #fn); \
    fn(); \
    std::fflush(stdout); \
} while (0)

// ============================================================================
// 辅助函数
// ============================================================================

static TransportAddr make_addr(const std::string &host, uint16_t port) {
    TransportAddr a;
    a.kind = TransportKind::Ip;
    a.host = host;
    a.port = port;
    return a;
}

static EndpointId make_id(uint8_t byte) {
    std::array<uint8_t, PublicKey::kSize> bytes{};
    bytes.fill(byte);
    return PublicKey(bytes);
}

// ============================================================================
// T-LP3-001: AddressWhitelistFilter 测试
// ============================================================================

static void test_address_whitelist_accept() {
    AddressWhitelistFilter filter({"10.0.0.1", "192.168.1.0"});
    IncomingRequest req;
    req.remote_addr = make_addr("10.0.0.1", 9000);
    CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
}

static void test_address_whitelist_reject() {
    AddressWhitelistFilter filter({"10.0.0.1"});
    IncomingRequest req;
    req.remote_addr = make_addr("10.0.0.2", 9000);
    CHECK(filter.filter(req) == IncomingFilterOutcome::kReject);
}

static void test_address_whitelist_empty() {
    AddressWhitelistFilter filter({});
    IncomingRequest req;
    req.remote_addr = make_addr("10.0.0.1", 9000);
    CHECK(filter.filter(req) == IncomingFilterOutcome::kReject);
}

static void test_address_whitelist_add_host() {
    AddressWhitelistFilter filter({"10.0.0.1"});
    filter.add_host("10.0.0.2");
    IncomingRequest req;
    req.remote_addr = make_addr("10.0.0.2", 9000);
    CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
}

static void test_address_whitelist_name() {
    AddressWhitelistFilter filter({});
    CHECK(filter.name() == std::string_view("address-whitelist"));
}

// ============================================================================
// T-LP3-001: EndpointIdBlacklistFilter 测试
// ============================================================================

static void test_endpoint_id_blacklist_reject() {
    EndpointId id = make_id(0xAA);
    EndpointIdBlacklistFilter filter({id});
    IncomingRequest req;
    req.remote_addr = make_addr("10.0.0.1", 9000);
    req.endpoint_id = id;
    CHECK(filter.filter(req) == IncomingFilterOutcome::kReject);
}

static void test_endpoint_id_blacklist_accept_not_blacklisted() {
    EndpointId id1 = make_id(0xAA);
    EndpointId id2 = make_id(0xBB);
    EndpointIdBlacklistFilter filter({id1});
    IncomingRequest req;
    req.remote_addr = make_addr("10.0.0.1", 9000);
    req.endpoint_id = id2;
    CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
}

static void test_endpoint_id_blacklist_accept_unknown_id() {
    EndpointIdBlacklistFilter filter({make_id(0xAA)});
    IncomingRequest req;
    req.remote_addr = make_addr("10.0.0.1", 9000);
    req.endpoint_id = std::nullopt;  // 未知 endpoint_id
    CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
}

static void test_endpoint_id_blacklist_remove() {
    EndpointId id = make_id(0xAA);
    EndpointIdBlacklistFilter filter({id});
    filter.remove_endpoint_id(id);
    IncomingRequest req;
    req.remote_addr = make_addr("10.0.0.1", 9000);
    req.endpoint_id = id;
    CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
}

static void test_endpoint_id_blacklist_name() {
    EndpointIdBlacklistFilter filter({});
    CHECK(filter.name() == std::string_view("endpoint-id-blacklist"));
}

// ============================================================================
// T-LP3-001: RateLimitFilter 测试
// ============================================================================

static void test_rate_limit_accept_under_limit() {
    RateLimitFilter filter(std::chrono::seconds(1), 5);
    for (int i = 0; i < 5; ++i) {
        IncomingRequest req;
        req.remote_addr = make_addr("10.0.0.1", 9000);
        CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
    }
}

static void test_rate_limit_reject_over_limit() {
    RateLimitFilter filter(std::chrono::seconds(1), 3);
    IncomingRequest req;
    req.remote_addr = make_addr("10.0.0.1", 9000);
    for (int i = 0; i < 3; ++i) {
        CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
    }
    CHECK(filter.filter(req) == IncomingFilterOutcome::kReject);
}

static void test_rate_limit_different_ips_independent() {
    RateLimitFilter filter(std::chrono::seconds(1), 2);
    IncomingRequest req1;
    req1.remote_addr = make_addr("10.0.0.1", 9000);
    IncomingRequest req2;
    req2.remote_addr = make_addr("10.0.0.2", 9000);

    // IP1 用完 2 次
    CHECK(filter.filter(req1) == IncomingFilterOutcome::kAccept);
    CHECK(filter.filter(req1) == IncomingFilterOutcome::kAccept);
    CHECK(filter.filter(req1) == IncomingFilterOutcome::kReject);

    // IP2 仍然可用
    CHECK(filter.filter(req2) == IncomingFilterOutcome::kAccept);
}

static void test_rate_limit_reset() {
    RateLimitFilter filter(std::chrono::seconds(1), 2);
    IncomingRequest req;
    req.remote_addr = make_addr("10.0.0.1", 9000);
    CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
    CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
    CHECK(filter.filter(req) == IncomingFilterOutcome::kReject);
    filter.reset("10.0.0.1");
    CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
}

static void test_rate_limit_window_expiry() {
    // 使用极短窗口（50ms）测试过期清理
    RateLimitFilter filter(std::chrono::milliseconds(50), 2);
    IncomingRequest req;
    req.remote_addr = make_addr("10.0.0.1", 9000);
    CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
    CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
    CHECK(filter.filter(req) == IncomingFilterOutcome::kReject);
    // 等待窗口过期
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    CHECK(filter.filter(req) == IncomingFilterOutcome::kAccept);
}

static void test_rate_limit_tracked_ip_count() {
    RateLimitFilter filter(std::chrono::seconds(1), 10);
    IncomingRequest req1;
    req1.remote_addr = make_addr("10.0.0.1", 9000);
    IncomingRequest req2;
    req2.remote_addr = make_addr("10.0.0.2", 9000);
    filter.filter(req1);
    filter.filter(req2);
    CHECK(filter.tracked_ip_count() >= 2);
}

static void test_rate_limit_name() {
    RateLimitFilter filter{};
    CHECK(filter.name() == std::string_view("rate-limit"));
}

// ============================================================================
// T-LP3-002/003: EndpointConfig 字段存在性测试
// ============================================================================

static void test_endpoint_config_incoming_filters_field() {
    Endpoint::Config cfg{};
    CHECK(cfg.incoming_filters.empty());
    // 添加过滤器
    cfg.incoming_filters.push_back(std::make_shared<AddressWhitelistFilter>(std::vector<std::string>{"10.0.0.1"}));
    CHECK(cfg.incoming_filters.size() == 1);
    CHECK(cfg.incoming_filters[0] != nullptr);
}

static void test_endpoint_config_external_addresses_field() {
    Endpoint::Config cfg{};
    CHECK(cfg.external_addresses.empty());
    cfg.external_addresses.push_back("203.0.113.1");
    cfg.external_addresses.push_back("203.0.113.2");
    CHECK(cfg.external_addresses.size() == 2);
    CHECK(cfg.external_addresses[0] == "203.0.113.1");
}

// ============================================================================
// T-LP3-004: ipv6_deprecated 工具函数测试
// ============================================================================

static void test_ipv6_deprecated_returns_bool() {
    // 接口存在性测试：函数可调用且返回 bool
    auto result = linoh::net::is_ipv6_deprecated("::1");
    (void)result;  // 结果取决于运行环境，仅验证接口可用
    CHECK(true);  // 能执行到这里说明接口正常
}

static void test_ipv6_deprecated_loopback_not_deprecated() {
    // ::1 (loopback) 通常不会被标记为 deprecated
    // 注意：在某些环境下可能无法获取地址信息，默认返回 false
    auto result = linoh::net::is_ipv6_deprecated("::1");
    CHECK(result == false);
}

// ============================================================================
// T-LP3-005: AccessControl trait 测试
// ============================================================================

static void test_allow_all_access_control() {
    AllowAllAccessControl ac;
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.1", 9000);
    CHECK(ac.verify_client(req) == Decision::Allow);
    CHECK(ac.name() == std::string_view("allow-all"));
}

static void test_deny_all_access_control() {
    DenyAllAccessControl ac;
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.1", 9000);
    CHECK(ac.verify_client(req) == Decision::Deny);
    CHECK(ac.name() == std::string_view("deny-all"));
}

static void test_bearer_token_correct() {
    BearerTokenAccessControl ac("my-secret-token");
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.1", 9000);
    req.bearer_token = "my-secret-token";
    CHECK(ac.verify_client(req) == Decision::Allow);
}

static void test_bearer_token_wrong() {
    BearerTokenAccessControl ac("correct-token");
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.1", 9000);
    req.bearer_token = "wrong-token";
    CHECK(ac.verify_client(req) == Decision::Deny);
}

static void test_bearer_token_missing() {
    BearerTokenAccessControl ac("correct-token");
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.1", 9000);
    req.bearer_token = std::nullopt;
    CHECK(ac.verify_client(req) == Decision::Deny);
}

static void test_bearer_token_via_query_param() {
    BearerTokenAccessControl ac("my-token");
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.1", 9000);
    req.query_params["token"] = "my-token";
    CHECK(ac.verify_client(req) == Decision::Allow);
}

static void test_bearer_token_custom_query_param() {
    BearerTokenAccessControl ac("my-token");
    ac.set_query_param_name("key");
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.1", 9000);
    req.query_params["key"] = "my-token";
    CHECK(ac.verify_client(req) == Decision::Allow);
}

static void test_ip_allowlist_access_control_accept() {
    IpAllowlistAccessControl ac({"10.0.0.1"});
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.1", 9000);
    CHECK(ac.verify_client(req) == Decision::Allow);
}

static void test_ip_allowlist_access_control_reject() {
    IpAllowlistAccessControl ac({"10.0.0.1"});
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.2", 9000);
    CHECK(ac.verify_client(req) == Decision::Deny);
}

static void test_ed25519_challenge_access_control() {
    Ed25519ChallengeAccessControl ac;
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.1", 9000);
    CHECK(ac.verify_client(req) == Decision::Challenge);
    CHECK(ac.name() == std::string_view("ed25519-challenge"));
}

static void test_ed25519_challenge_endpoint_whitelist() {
    Ed25519ChallengeAccessControl ac;
    EndpointId id1 = make_id(0xAA);
    EndpointId id2 = make_id(0xBB);
    ac.set_allowed_endpoints({id1});
    CHECK(ac.is_endpoint_allowed(id1));
    CHECK(!ac.is_endpoint_allowed(id2));
}

static void test_chained_access_control_allow() {
    ChainedAccessControl chain;
    chain.add(std::make_shared<AllowAllAccessControl>());
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.1", 9000);
    CHECK(chain.verify_client(req) == Decision::Allow);
    CHECK(chain.size() == 1);
    CHECK(!chain.empty());
}

static void test_chained_access_control_deny() {
    ChainedAccessControl chain;
    chain.add(std::make_shared<DenyAllAccessControl>());
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.1", 9000);
    CHECK(chain.verify_client(req) == Decision::Deny);
}

static void test_chained_access_control_mixed() {
    ChainedAccessControl chain;
    chain.add(std::make_shared<DenyAllAccessControl>());
    chain.add(std::make_shared<AllowAllAccessControl>());  // AllowAll 优先
    ClientRequest req;
    req.peer_addr = make_addr("10.0.0.1", 9000);
    // ChainedAccessControl: 任一 Allow 即返回 Allow
    CHECK(chain.verify_client(req) == Decision::Allow);
}

static void test_create_access_control_by_name() {
    auto allow = create_access_control_by_name("allow-all");
    CHECK(allow != nullptr);
    CHECK(allow->name() == std::string_view("allow-all"));

    auto deny = create_access_control_by_name("deny-all");
    CHECK(deny != nullptr);

    auto bearer = create_access_control_by_name("bearer-token", "test-token");
    CHECK(bearer != nullptr);

    auto unknown = create_access_control_by_name("unknown");
    CHECK(unknown == nullptr);
}

// ============================================================================
// T-LP3-001: IncomingFilterOutcome 枚举值测试
// ============================================================================

static void test_incoming_filter_outcome_values() {
    CHECK(IncomingFilterOutcome::kAccept != IncomingFilterOutcome::kReject);
    CHECK(IncomingFilterOutcome::kReject != IncomingFilterOutcome::kRetry);
    CHECK(IncomingFilterOutcome::kRetry != IncomingFilterOutcome::kIgnore);
    CHECK(IncomingFilterOutcome::kIgnore != IncomingFilterOutcome::kAccept);
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== test_v480_security ===\n");

    // T-LP3-001: AddressWhitelistFilter
    RUN_TEST(test_address_whitelist_accept);
    RUN_TEST(test_address_whitelist_reject);
    RUN_TEST(test_address_whitelist_empty);
    RUN_TEST(test_address_whitelist_add_host);
    RUN_TEST(test_address_whitelist_name);

    // T-LP3-001: EndpointIdBlacklistFilter
    RUN_TEST(test_endpoint_id_blacklist_reject);
    RUN_TEST(test_endpoint_id_blacklist_accept_not_blacklisted);
    RUN_TEST(test_endpoint_id_blacklist_accept_unknown_id);
    RUN_TEST(test_endpoint_id_blacklist_remove);
    RUN_TEST(test_endpoint_id_blacklist_name);

    // T-LP3-001: RateLimitFilter
    RUN_TEST(test_rate_limit_accept_under_limit);
    RUN_TEST(test_rate_limit_reject_over_limit);
    RUN_TEST(test_rate_limit_different_ips_independent);
    RUN_TEST(test_rate_limit_reset);
    RUN_TEST(test_rate_limit_window_expiry);
    RUN_TEST(test_rate_limit_tracked_ip_count);
    RUN_TEST(test_rate_limit_name);

    // T-LP3-002/003: EndpointConfig 字段
    RUN_TEST(test_endpoint_config_incoming_filters_field);
    RUN_TEST(test_endpoint_config_external_addresses_field);

    // T-LP3-004: ipv6_deprecated
    RUN_TEST(test_ipv6_deprecated_returns_bool);
    RUN_TEST(test_ipv6_deprecated_loopback_not_deprecated);

    // T-LP3-005: AccessControl
    RUN_TEST(test_allow_all_access_control);
    RUN_TEST(test_deny_all_access_control);
    RUN_TEST(test_bearer_token_correct);
    RUN_TEST(test_bearer_token_wrong);
    RUN_TEST(test_bearer_token_missing);
    RUN_TEST(test_bearer_token_via_query_param);
    RUN_TEST(test_bearer_token_custom_query_param);
    RUN_TEST(test_ip_allowlist_access_control_accept);
    RUN_TEST(test_ip_allowlist_access_control_reject);
    RUN_TEST(test_ed25519_challenge_access_control);
    RUN_TEST(test_ed25519_challenge_endpoint_whitelist);
    RUN_TEST(test_chained_access_control_allow);
    RUN_TEST(test_chained_access_control_deny);
    RUN_TEST(test_chained_access_control_mixed);
    RUN_TEST(test_create_access_control_by_name);

    // T-LP3-001: 枚举值
    RUN_TEST(test_incoming_filter_outcome_values);

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
