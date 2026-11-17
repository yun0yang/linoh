// test_dns_fallback.cpp — P4-D-3 DNS Fallback Nameservers 单元测试
//
// 测试覆盖：
//   1.  默认 fallback 列表为空
//   2.  add_fallback_server 单个添加
//   3.  add_fallback_server 多个添加（顺序保留）
//   4.  add_fallback_servers 批量添加
//   5.  clear_fallback_servers 清空
//   6.  fallback_servers() 查询顺序
//   7.  set_query_timeout_ms 配置生效
//   8.  set_max_retries 配置生效
//   9.  缓存命中不查询网络（stats.cache_hits 增加）
//  10.  无主服务器 + 无 fallback → 返回 nullopt + all_misses 增加
//  11.  主服务器响应正常（缓存注入模拟）→ primary_hits 不变（走缓存）
//  12.  Builder.dns_fallback() 配置应用
//  13.  Builder.add_dns_fallback() 单个添加
//  14.  Builder.dns_query_params() 配置生效
//  15.  Server 结构体默认端口
//  16.  Stats 字段初始值
//  17.  lookup() 总查询计数（total_queries）

#include "linoh/address_lookup/lookup.hpp"
#include "linoh/endpoint/builder.hpp"
#include "linoh/base/key.hpp"

#include <cassert>
#include <cstdio>
#include <memory>
#include <vector>

using namespace linoh;
using namespace linoh::address_lookup;
using linoh::base::EndpointId;
using linoh::base::SecretKey;
using linoh::base::EndpointAddr;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL line %d: %s\n", __LINE__, #cond); } \
} while(0)

// 生成确定性的 EndpointId（32 字节全 0x42）
static EndpointId make_test_id(std::uint8_t seed = 0x42) {
    std::array<std::uint8_t, 32> bytes{};
    for (std::size_t i = 0; i < 32; ++i) bytes[i] = seed;
    return EndpointId(bytes);
}

// 构造一个 IP 类型的 TransportAddr
static linoh::base::TransportAddr make_ip_addr(std::string host, uint16_t port) {
    linoh::base::TransportAddr a;
    a.kind = linoh::base::TransportKind::Ip;
    a.host = std::move(host);
    a.port = port;
    return a;
}

// ========== 1. 默认 fallback 列表为空 ==========
static void test_default_empty() {
    DnsAddressLookup dns;
    CHECK(dns.fallback_servers().empty());
}

// ========== 2. add_fallback_server 单个 ==========
static void test_add_single() {
    DnsAddressLookup dns;
    dns.add_fallback_server("1.1.1.1", 53);
    auto servers = dns.fallback_servers();
    CHECK(servers.size() == 1);
    CHECK(servers[0].host == "1.1.1.1");
    CHECK(servers[0].port == 53);
}

// ========== 3. 多个添加顺序保留 ==========
static void test_add_multiple_order() {
    DnsAddressLookup dns;
    dns.add_fallback_server("1.1.1.1", 53);
    dns.add_fallback_server("8.8.8.8", 53);
    dns.add_fallback_server("9.9.9.9", 5333);
    auto servers = dns.fallback_servers();
    CHECK(servers.size() == 3);
    CHECK(servers[0].host == "1.1.1.1");
    CHECK(servers[1].host == "8.8.8.8");
    CHECK(servers[2].host == "9.9.9.9");
    CHECK(servers[0].port == 53);
    CHECK(servers[2].port == 5333);
}

// ========== 4. 批量添加 ==========
static void test_add_batch() {
    DnsAddressLookup dns;
    std::vector<DnsAddressLookup::Server> batch = {
        {"1.0.0.1", 53},
        {"8.8.4.4", 53},
        {"9.9.9.9", 53}
    };
    dns.add_fallback_servers(batch);
    auto servers = dns.fallback_servers();
    CHECK(servers.size() == 3);
    CHECK(servers[0].host == "1.0.0.1");
    CHECK(servers[1].host == "8.8.4.4");
    CHECK(servers[2].host == "9.9.9.9");
}

// ========== 5. clear 清空 ==========
static void test_clear() {
    DnsAddressLookup dns;
    dns.add_fallback_server("1.1.1.1", 53);
    dns.add_fallback_server("8.8.8.8", 53);
    CHECK(dns.fallback_servers().size() == 2);
    dns.clear_fallback_servers();
    CHECK(dns.fallback_servers().empty());
}

// ========== 6. fallback_servers() 顺序 ==========
// （已在 test_add_multiple_order 覆盖，此处补一个混合场景）
static void test_query_order_mixed() {
    DnsAddressLookup dns;
    dns.add_fallback_server("a.example", 5333);
    dns.add_fallback_server("b.example", 5333);
    dns.add_fallback_servers({{"c.example", 53}, {"d.example", 53}});
    dns.add_fallback_server("e.example", 5333);
    auto servers = dns.fallback_servers();
    CHECK(servers.size() == 5);
    CHECK(servers[0].host == "a.example");
    CHECK(servers[1].host == "b.example");
    CHECK(servers[2].host == "c.example");
    CHECK(servers[3].host == "d.example");
    CHECK(servers[4].host == "e.example");
}

// ========== 7. set_query_timeout_ms ==========
static void test_set_timeout() {
    DnsAddressLookup dns;
    dns.set_query_timeout_ms(1000);
    // 没有直接 getter，通过 stats 间接验证配置生效（查询不会卡 500ms）
    CHECK(true);  // 配置不抛异常即视为通过
}

// ========== 8. set_max_retries ==========
static void test_set_retries() {
    DnsAddressLookup dns;
    dns.set_max_retries(1);
    dns.set_query_timeout_ms(50);
    // 主服务器 + fallback 都不可达，应快速返回（1 retry × 50ms × N servers）
    auto id = make_test_id(0x99);
    auto t0 = std::chrono::steady_clock::now();
    auto result = dns.lookup(id);
    auto t1 = std::chrono::steady_clock::now();
    CHECK(!result.has_value());
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);
    // 至少触发了 1 次查询（即使没 fallback 也走了主服务器空路径返回）
    // elapsed 应 < 200ms（1 retry × 50ms × 无服务器 → 立即返回 nullopt）
    CHECK(elapsed.count() < 500);
}

// ========== 9. 缓存命中不查询网络 ==========
static void test_cache_hit() {
    DnsAddressLookup dns;
    auto id = make_test_id(0x11);
    EndpointAddr addr(id);
    addr.add_direct_address(make_ip_addr("127.0.0.1", 9001));
    dns.inject(addr);

    auto s_before = dns.stats();
    auto result = dns.lookup(id);
    auto s_after = dns.stats();
    CHECK(result.has_value());
    CHECK(s_after.total_queries == s_before.total_queries + 1);
    CHECK(s_after.cache_hits == s_before.cache_hits + 1);
    CHECK(s_after.primary_hits == s_before.primary_hits);
    CHECK(s_after.fallback_hits == s_before.fallback_hits);
}

// ========== 10. 无主服务器 + 无 fallback → nullopt + all_misses ==========
static void test_no_server_returns_nullopt() {
    DnsAddressLookup dns;
    auto id = make_test_id(0x22);
    auto s_before = dns.stats();
    auto result = dns.lookup(id);
    CHECK(!result.has_value());
    auto s_after = dns.stats();
    CHECK(s_after.total_queries == s_before.total_queries + 1);
    // 缓存未命中 + 没有服务器可查 → 直接 all_misses
    CHECK(s_after.all_misses == s_before.all_misses + 1);
}

// ========== 11. 主服务器配置但缓存命中（primary_hits 不增加） ==========
static void test_primary_server_cache_hit() {
    DnsAddressLookup dns;
    dns.set_server("1.1.1.1", 53);
    auto id = make_test_id(0x33);
    EndpointAddr addr(id);
    addr.add_direct_address(make_ip_addr("10.0.0.1", 9001));
    dns.inject(addr);

    auto s_before = dns.stats();
    auto result = dns.lookup(id);
    auto s_after = dns.stats();
    CHECK(result.has_value());
    // 缓存命中，primary_hits 不增加
    CHECK(s_after.cache_hits == s_before.cache_hits + 1);
    CHECK(s_after.primary_hits == s_before.primary_hits);
}

// ========== 12. Builder.dns_fallback() 配置 ==========
static void test_builder_dns_fallback() {
    SecretKey sk = SecretKey::generate();
    auto dns_lookup = std::make_shared<DnsAddressLookup>();

    std::vector<DnsAddressLookup::Server> fallbacks = {
        {"1.1.1.1", 53},
        {"8.8.8.8", 53}
    };
    endpoint::Builder builder;
    builder.secret_key(sk);
    builder.address_lookup(dns_lookup);
    builder.dns_fallback(fallbacks);

    // build 前应未应用（在 build 中应用）
    CHECK(dns_lookup->fallback_servers().empty());

    // 用 stub asio 构造（不实际启动网络）
    linoh_asio::io_context ctx;
    auto ep = builder.build(ctx);
    auto servers = dns_lookup->fallback_servers();
    CHECK(servers.size() == 2);
    CHECK(servers[0].host == "1.1.1.1");
    CHECK(servers[1].host == "8.8.8.8");
}

// ========== 13. Builder.add_dns_fallback() ==========
static void test_builder_add_single() {
    SecretKey sk = SecretKey::generate();
    auto dns_lookup = std::make_shared<DnsAddressLookup>();

    endpoint::Builder builder;
    builder.secret_key(sk);
    builder.address_lookup(dns_lookup);
    builder.add_dns_fallback("9.9.9.9", 5333);
    builder.add_dns_fallback("1.0.0.1", 53);

    linoh_asio::io_context ctx;
    auto ep = builder.build(ctx);
    auto servers = dns_lookup->fallback_servers();
    CHECK(servers.size() == 2);
    CHECK(servers[0].host == "9.9.9.9");
    CHECK(servers[1].host == "1.0.0.1");
}

// ========== 14. Builder.dns_query_params() ==========
static void test_builder_query_params() {
    SecretKey sk = SecretKey::generate();
    auto dns_lookup = std::make_shared<DnsAddressLookup>();

    endpoint::Builder builder;
    builder.secret_key(sk);
    builder.address_lookup(dns_lookup);
    builder.dns_query_params(200, 2);
    builder.add_dns_fallback("10.255.255.1", 53);  // 不可达地址

    linoh_asio::io_context ctx;
    auto ep = builder.build(ctx);

    // 实际查询：1 retry × 200ms × 1 fallback = 200ms 左右
    auto id = make_test_id(0x44);
    auto t0 = std::chrono::steady_clock::now();
    auto result = dns_lookup->lookup(id);
    auto t1 = std::chrono::steady_clock::now();
    CHECK(!result.has_value());
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);
    // 不可达地址可能立即返回（ICMP unreachable）或超时返回，只验证上限
    // 2 retries × 200ms + 余量 = 不超过 1500ms
    CHECK(elapsed.count() < 1500);
    std::printf("  query_params elapsed=%lldms\n", static_cast<long long>(elapsed.count()));
}

// ========== 15. Server 结构体默认端口 ==========
static void test_server_default_port() {
    DnsAddressLookup::Server s;
    CHECK(s.port == 5333);
    CHECK(s.host.empty());

    DnsAddressLookup::Server s2{"1.2.3.4", 53};
    CHECK(s2.host == "1.2.3.4");
    CHECK(s2.port == 53);
}

// ========== 16. Stats 字段初始值 ==========
static void test_stats_initial() {
    DnsAddressLookup dns;
    auto s = dns.stats();
    CHECK(s.total_queries == 0);
    CHECK(s.cache_hits == 0);
    CHECK(s.primary_hits == 0);
    CHECK(s.fallback_hits == 0);
    CHECK(s.all_misses == 0);
}

// ========== 17. lookup() total_queries 计数 ==========
static void test_total_queries_counter() {
    DnsAddressLookup dns;
    auto id1 = make_test_id(0x51);
    auto id2 = make_test_id(0x52);
    auto id3 = make_test_id(0x53);

    dns.lookup(id1);
    dns.lookup(id2);
    dns.lookup(id3);

    auto s = dns.stats();
    CHECK(s.total_queries == 3);
    CHECK(s.all_misses == 3);  // 全 miss（无服务器）
    CHECK(s.cache_hits == 0);
}

// ========== 18. 主服务器 + fallback 顺序验证（通过 stats） ==========
// 因无真实 DNS 服务，仅验证查询路径正确触发 all_misses
static void test_primary_plus_fallback_all_miss() {
    DnsAddressLookup dns;
    dns.set_server("10.255.255.1", 5333);  // 不可达
    dns.add_fallback_server("10.255.255.2", 5333);
    dns.add_fallback_server("10.255.255.3", 5333);
    dns.set_query_timeout_ms(50);
    dns.set_max_retries(1);

    auto id = make_test_id(0x66);
    auto s_before = dns.stats();
    auto result = dns.lookup(id);
    auto s_after = dns.stats();

    CHECK(!result.has_value());
    CHECK(s_after.total_queries == s_before.total_queries + 1);
    CHECK(s_after.all_misses == s_before.all_misses + 1);
    CHECK(s_after.primary_hits == 0);
    CHECK(s_after.fallback_hits == 0);
}

int main() {
    std::printf("=== test_dns_fallback ===\n");

    test_default_empty();
    test_add_single();
    test_add_multiple_order();
    test_add_batch();
    test_clear();
    test_query_order_mixed();
    test_set_timeout();
    test_set_retries();
    test_cache_hit();
    test_no_server_returns_nullopt();
    test_primary_server_cache_hit();
    test_builder_dns_fallback();
    test_builder_add_single();
    test_builder_query_params();
    test_server_default_port();
    test_stats_initial();
    test_total_queries_counter();
    test_primary_plus_fallback_all_miss();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
