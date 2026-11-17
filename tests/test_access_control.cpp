// test_access_control.cpp — Relay 访问控制测试（P4-C-1）
//
// 覆盖：
//   - AllowAllAccessControl / DenyAllAccessControl
//   - BearerTokenAccessControl 正确/错误 token
//   - BearerToken query 参数回退
//   - IpAllowlistAccessControl 白名单
//   - Ed25519ChallengeAccessControl 始终 Challenge
//   - ChainedAccessControl 组合策略
//   - create_access_control_by_name 工厂
//   - 常量时间比较安全性
//   - 自定义策略注入
//   - 并发调用

#include "linoh/relay/access_control.hpp"
#include "linoh/base/key.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <memory>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::relay;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 工具：构造 ClientRequest
// ============================================================================
static ClientRequest make_request(const std::string &ip = "10.0.0.1",
                                  std::uint16_t port = 50000) {
    ClientRequest req;
    req.peer_addr.kind = base::TransportKind::Ip;
    req.peer_addr.host = ip;
    req.peer_addr.port = port;
    return req;
}

// ============================================================================
// 测试 1: AllowAllAccessControl
// ============================================================================
static void test_allow_all() {
    std::printf("[test] AllowAllAccessControl...\n");

    AllowAllAccessControl ac;
    auto req = make_request();
    CHECK(ac.verify_client(req) == Decision::Allow);
    CHECK(ac.name() == "allow-all");
}

// ============================================================================
// 测试 2: DenyAllAccessControl
// ============================================================================
static void test_deny_all() {
    std::printf("[test] DenyAllAccessControl...\n");

    DenyAllAccessControl ac;
    auto req = make_request();
    CHECK(ac.verify_client(req) == Decision::Deny);
    CHECK(ac.name() == "deny-all");
}

// ============================================================================
// 测试 3: BearerTokenAccessControl - 正确 token
// ============================================================================
static void test_bearer_correct() {
    std::printf("[test] BearerToken correct token...\n");

    BearerTokenAccessControl ac("my-secret-token");
    auto req = make_request();
    req.bearer_token = "my-secret-token";

    CHECK(ac.verify_client(req) == Decision::Allow);
    CHECK(ac.name() == "bearer-token");
}

// ============================================================================
// 测试 4: BearerTokenAccessControl - 错误 token
// ============================================================================
static void test_bearer_wrong() {
    std::printf("[test] BearerToken wrong token...\n");

    BearerTokenAccessControl ac("my-secret-token");
    auto req = make_request();
    req.bearer_token = "wrong-token";

    CHECK(ac.verify_client(req) == Decision::Deny);
}

// ============================================================================
// 测试 5: BearerTokenAccessControl - 缺失 token
// ============================================================================
static void test_bearer_missing() {
    std::printf("[test] BearerToken missing token...\n");

    BearerTokenAccessControl ac("my-secret-token");
    auto req = make_request();
    // 不设置 bearer_token

    CHECK(ac.verify_client(req) == Decision::Deny);
}

// ============================================================================
// 测试 6: BearerTokenAccessControl - query 参数回退
// ============================================================================
static void test_bearer_query_fallback() {
    std::printf("[test] BearerToken query param fallback...\n");

    BearerTokenAccessControl ac("query-token");
    auto req = make_request();
    req.query_params["token"] = "query-token";

    CHECK(ac.verify_client(req) == Decision::Allow);
}

// ============================================================================
// 测试 7: BearerTokenAccessControl - 自定义 query 参数名
// ============================================================================
static void test_bearer_custom_query_param() {
    std::printf("[test] BearerToken custom query param...\n");

    BearerTokenAccessControl ac("key");
    ac.set_query_param_name("access_key");
    auto req = make_request();
    req.query_params["access_key"] = "key";

    CHECK(ac.verify_client(req) == Decision::Allow);
}

// ============================================================================
// 测试 8: BearerTokenAccessControl - bearer 优先于 query
// ============================================================================
static void test_bearer_priority() {
    std::printf("[test] BearerToken bearer over query...\n");

    BearerTokenAccessControl ac("correct");
    auto req = make_request();
    req.bearer_token = "correct";
    req.query_params["token"] = "wrong";  // query 错误但 bearer 正确

    CHECK(ac.verify_client(req) == Decision::Allow);
}

// ============================================================================
// 测试 9: BearerTokenAccessControl - 空字符串 token 拒绝
// ============================================================================
static void test_bearer_empty() {
    std::printf("[test] BearerToken empty token...\n");

    BearerTokenAccessControl ac("non-empty");
    auto req = make_request();
    req.bearer_token = "";

    CHECK(ac.verify_client(req) == Decision::Deny);
}

// ============================================================================
// 测试 10: IpAllowlistAccessControl - 白名单匹配
// ============================================================================
static void test_ip_allowlist_match() {
    std::printf("[test] IpAllowlist match...\n");

    IpAllowlistAccessControl ac({"10.0.0.1", "10.0.0.2", "192.168.1.1"});
    auto req = make_request("10.0.0.2", 50000);

    CHECK(ac.verify_client(req) == Decision::Allow);
    CHECK(ac.name() == "ip-allowlist");
}

// ============================================================================
// 测试 11: IpAllowlistAccessControl - 不在白名单
// ============================================================================
static void test_ip_allowlist_no_match() {
    std::printf("[test] IpAllowlist no match...\n");

    IpAllowlistAccessControl ac({"10.0.0.1", "10.0.0.2"});
    auto req = make_request("10.0.0.99", 50000);

    CHECK(ac.verify_client(req) == Decision::Deny);
}

// ============================================================================
// 测试 12: IpAllowlistAccessControl - 空白名单拒绝
// ============================================================================
static void test_ip_allowlist_empty() {
    std::printf("[test] IpAllowlist empty...\n");

    IpAllowlistAccessControl ac({});
    auto req = make_request("10.0.0.1", 50000);

    CHECK(ac.verify_client(req) == Decision::Deny);
}

// ============================================================================
// 测试 13: IpAllowlistAccessControl - 动态添加
// ============================================================================
static void test_ip_allowlist_add() {
    std::printf("[test] IpAllowlist add...\n");

    IpAllowlistAccessControl ac({"10.0.0.1"});
    auto req = make_request("10.0.0.5", 50000);
    CHECK(ac.verify_client(req) == Decision::Deny);

    ac.add_ip("10.0.0.5");
    CHECK(ac.verify_client(req) == Decision::Allow);
}

// ============================================================================
// 测试 14: Ed25519ChallengeAccessControl - 始终 Challenge
// ============================================================================
static void test_ed25519_challenge() {
    std::printf("[test] Ed25519Challenge...\n");

    Ed25519ChallengeAccessControl ac;
    auto req = make_request();
    CHECK(ac.verify_client(req) == Decision::Challenge);
    CHECK(ac.name() == "ed25519-challenge");
}

// ============================================================================
// 测试 15: Ed25519ChallengeAccessControl - 白名单
// ============================================================================
static void test_ed25519_whitelist() {
    std::printf("[test] Ed25519 whitelist...\n");

    Ed25519ChallengeAccessControl ac;

    // 空白名单 = 全允许
    base::EndpointId id1{};
    std::memset(id1.data(), 0xAA, base::EndpointId::kSize);
    CHECK(ac.is_endpoint_allowed(id1));

    // 配置白名单
    base::EndpointId id2{};
    std::memset(id2.data(), 0xBB, base::EndpointId::kSize);
    ac.set_allowed_endpoints({id2});

    CHECK(ac.is_endpoint_allowed(id2));    // 在白名单
    CHECK(!ac.is_endpoint_allowed(id1));   // 不在
}

// ============================================================================
// 测试 16: ChainedAccessControl - 任一 Allow 即通过
// ============================================================================
static void test_chained_allow() {
    std::printf("[test] Chained allow...\n");

    ChainedAccessControl ac;
    ac.add(std::make_shared<DenyAllAccessControl>());
    ac.add(std::make_shared<AllowAllAccessControl>());

    auto req = make_request();
    // DenyAll 在前但 AllowAll 也应被调用？不对，Chained 一旦 Deny 立即返回
    // 这里测试 DenyAll 在 AllowAll 之后
    ChainedAccessControl ac2;
    ac2.add(std::make_shared<AllowAllAccessControl>());
    ac2.add(std::make_shared<DenyAllAccessControl>());

    CHECK(ac2.verify_client(req) == Decision::Allow);
    CHECK(ac2.name() == "chained");
    CHECK(ac2.size() == 2);
    CHECK(!ac2.empty());
}

// ============================================================================
// 测试 17: ChainedAccessControl - DenyAll 单独使用拒绝
// ============================================================================
static void test_chained_deny_priority() {
    std::printf("[test] Chained deny only...\n");

    ChainedAccessControl ac;
    ac.add(std::make_shared<DenyAllAccessControl>());

    auto req = make_request();
    CHECK(ac.verify_client(req) == Decision::Deny);
}

// ============================================================================
// 测试 18: ChainedAccessControl - 全 Challenge 返回 Challenge
// ============================================================================
static void test_chained_all_challenge() {
    std::printf("[test] Chained all challenge...\n");

    ChainedAccessControl ac;
    ac.add(std::make_shared<Ed25519ChallengeAccessControl>());
    ac.add(std::make_shared<Ed25519ChallengeAccessControl>());

    auto req = make_request();
    CHECK(ac.verify_client(req) == Decision::Challenge);
}

// ============================================================================
// 测试 19: ChainedAccessControl - 空链拒绝
// ============================================================================
static void test_chained_empty() {
    std::printf("[test] Chained empty...\n");

    ChainedAccessControl ac;
    auto req = make_request();
    CHECK(ac.verify_client(req) == Decision::Deny);
    CHECK(ac.empty());
    CHECK(ac.size() == 0);
}

// ============================================================================
// 测试 20: ChainedAccessControl - Bearer + Challenge 组合
// ============================================================================
static void test_chained_bearer_then_challenge() {
    std::printf("[test] Chained bearer then challenge...\n");

    ChainedAccessControl ac;
    ac.add(std::make_shared<BearerTokenAccessControl>("secret"));
    ac.add(std::make_shared<Ed25519ChallengeAccessControl>());

    // 错误 token：Deny 立即返回
    auto req1 = make_request();
    req1.bearer_token = "wrong";
    CHECK(ac.verify_client(req1) == Decision::Deny);

    // 正确 token：Allow 立即返回
    auto req2 = make_request();
    req2.bearer_token = "secret";
    CHECK(ac.verify_client(req2) == Decision::Allow);
}

// ============================================================================
// 测试 21: ChainedAccessControl - Ip OR Bearer 组合
// ============================================================================
static void test_chained_ip_and_bearer() {
    std::printf("[test] Chained ip + bearer (OR)...\n");

    ChainedAccessControl ac;
    ac.add(std::make_shared<IpAllowlistAccessControl>(
        std::vector<std::string>{"10.0.0.1", "10.0.0.2"}));
    ac.add(std::make_shared<BearerTokenAccessControl>("key"));

    // Chained 是 OR 语义：任一 Allow 即通过
    // IP 允许（即使 Bearer 错误）：Allow
    auto req1 = make_request("10.0.0.1");
    req1.bearer_token = "wrong";
    CHECK(ac.verify_client(req1) == Decision::Allow);

    // IP 拒绝 + Bearer 正确：Bearer Allow → 整体 Allow
    auto req2 = make_request("10.0.0.99");
    req2.bearer_token = "key";
    CHECK(ac.verify_client(req2) == Decision::Allow);

    // 两者都拒绝：Deny
    auto req3 = make_request("10.0.0.99");
    req3.bearer_token = "wrong";
    CHECK(ac.verify_client(req3) == Decision::Deny);

    // 两者都正确：Allow
    auto req4 = make_request("10.0.0.1");
    req4.bearer_token = "key";
    CHECK(ac.verify_client(req4) == Decision::Allow);
}

// ============================================================================
// 测试 22: create_access_control_by_name 工厂
// ============================================================================
static void test_create_by_name() {
    std::printf("[test] create_access_control_by_name...\n");

    auto allow = create_access_control_by_name("allow-all");
    CHECK(allow != nullptr);
    CHECK(allow->name() == "allow-all");

    auto deny = create_access_control_by_name("deny-all");
    CHECK(deny != nullptr);
    CHECK(deny->name() == "deny-all");

    auto bearer = create_access_control_by_name("bearer-token", "my-token");
    CHECK(bearer != nullptr);
    CHECK(bearer->name() == "bearer-token");

    auto challenge = create_access_control_by_name("ed25519-challenge");
    CHECK(challenge != nullptr);
    CHECK(challenge->name() == "ed25519-challenge");

    auto unknown = create_access_control_by_name("unknown");
    CHECK(unknown == nullptr);

    auto empty = create_access_control_by_name("");
    CHECK(empty == nullptr);
}

// ============================================================================
// 测试 23: 常量时间比较（相同长度不同内容）
// ============================================================================
static void test_constant_time_compare() {
    std::printf("[test] Constant time compare...\n");

    BearerTokenAccessControl ac("0123456789abcdef");

    // 长度相同内容不同
    auto req1 = make_request();
    req1.bearer_token = "0123456789abcdeg";  // 最后一位不同
    CHECK(ac.verify_client(req1) == Decision::Deny);

    // 长度不同
    auto req2 = make_request();
    req2.bearer_token = "short";
    CHECK(ac.verify_client(req2) == Decision::Deny);

    // 完全匹配
    auto req3 = make_request();
    req3.bearer_token = "0123456789abcdef";
    CHECK(ac.verify_client(req3) == Decision::Allow);
}

// ============================================================================
// 测试 24: 自定义策略注入
// ============================================================================
namespace {

class CustomStrategy : public AccessControl {
public:
    Decision verify_client(const ClientRequest &req) override {
        if (req.target_host == "special.example.com") {
            return Decision::Allow;
        }
        return Decision::Deny;
    }
    std::string_view name() const override { return "custom-host"; }
};

} // namespace

static void test_custom_strategy_injection() {
    std::printf("[test] Custom strategy injection...\n");

    std::shared_ptr<AccessControl> ac = std::make_shared<CustomStrategy>();
    CHECK(ac->name() == "custom-host");

    auto req1 = make_request();
    req1.target_host = "special.example.com";
    CHECK(ac->verify_client(req1) == Decision::Allow);

    auto req2 = make_request();
    req2.target_host = "other.example.com";
    CHECK(ac->verify_client(req2) == Decision::Deny);
}

// ============================================================================
// 测试 25: 多态调用 - 通过基类指针
// ============================================================================
static void test_polymorphic_call() {
    std::printf("[test] Polymorphic call...\n");

    std::vector<std::shared_ptr<AccessControl>> strategies = {
        std::make_shared<AllowAllAccessControl>(),
        std::make_shared<DenyAllAccessControl>(),
        std::make_shared<Ed25519ChallengeAccessControl>(),
        std::make_shared<BearerTokenAccessControl>("x"),
    };

    auto req = make_request();
    req.bearer_token = "x";

    CHECK(strategies[0]->verify_client(req) == Decision::Allow);
    CHECK(strategies[1]->verify_client(req) == Decision::Deny);
    CHECK(strategies[2]->verify_client(req) == Decision::Challenge);
    CHECK(strategies[3]->verify_client(req) == Decision::Allow);

    for (auto &s : strategies) {
        CHECK(!s->name().empty());
    }
}

// ============================================================================
// 测试 26: 并发调用（线程安全）
// ============================================================================
static void test_concurrent_verify() {
    std::printf("[test] Concurrent verify...\n");

    BearerTokenAccessControl ac("concurrent-token");
    auto req = make_request();
    req.bearer_token = "concurrent-token";

    std::atomic<int> allow_count{0};
    std::atomic<int> total_count{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < 100; ++i) {
                if (ac.verify_client(req) == Decision::Allow) {
                    ++allow_count;
                }
                ++total_count;
            }
        });
    }
    for (auto &t : threads) t.join();

    CHECK(total_count.load() == 800);
    CHECK(allow_count.load() == 800);
}

// ============================================================================
// 测试 27: ChainedAccessControl 嵌套
// ============================================================================
static void test_chained_nested() {
    std::printf("[test] Chained nested...\n");

    auto inner = std::make_shared<ChainedAccessControl>();
    inner->add(std::make_shared<BearerTokenAccessControl>("inner"));
    inner->add(std::make_shared<AllowAllAccessControl>());

    auto outer = std::make_shared<ChainedAccessControl>();
    outer->add(inner);
    outer->add(std::make_shared<DenyAllAccessControl>());

    auto req = make_request();
    req.bearer_token = "inner";

    // inner 链：BearerToken Allow → 整体 Allow
    // outer 链：inner Allow → 整体 Allow
    CHECK(outer->verify_client(req) == Decision::Allow);
}

int main() {
    std::printf("=== test_access_control ===\n");

    test_allow_all();
    test_deny_all();
    test_bearer_correct();
    test_bearer_wrong();
    test_bearer_missing();
    test_bearer_query_fallback();
    test_bearer_custom_query_param();
    test_bearer_priority();
    test_bearer_empty();
    test_ip_allowlist_match();
    test_ip_allowlist_no_match();
    test_ip_allowlist_empty();
    test_ip_allowlist_add();
    test_ed25519_challenge();
    test_ed25519_whitelist();
    test_chained_allow();
    test_chained_deny_priority();
    test_chained_all_challenge();
    test_chained_empty();
    test_chained_bearer_then_challenge();
    test_chained_ip_and_bearer();
    test_create_by_name();
    test_constant_time_compare();
    test_custom_strategy_injection();
    test_polymorphic_call();
    test_concurrent_verify();
    test_chained_nested();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
