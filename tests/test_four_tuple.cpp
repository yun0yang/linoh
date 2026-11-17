// test_four_tuple.cpp — P4-A-1 FourTuple 路径标识单元测试
//
// 测试覆盖：
//   1. FourTuple 默认构造与字段访问
//   2. to_string() 格式（ip/relay/custom 三种 TransportKind）
//   3. operator== / operator!= 比较
//   4. to_bytes() / from_bytes() 往返
//   5. from_bytes() 失败场景（数据不足、host 超长）
//   6. FourTuple::Hash 用于 unordered_map
//   7. Path 集成：构造时 four_tuple.remote_addr 已初始化
//   8. Path::set_local_addr() 后四元组完整
//   9. PathMigrationManager 关联 FourTuple（generate/record/validate）
//  10. validated_tuples() 查询
//  11. has_challenge_for_tuple() 防重复打洞

#include "linoh/net/path.hpp"
#include "linoh/protocol/path_migration.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

using namespace linoh;
using namespace linoh::net;
using namespace linoh::protocol;
using linoh::base::TransportAddr;
using linoh::base::TransportKind;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL line %d: %s\n", __LINE__, #cond); } \
} while(0)

static TransportAddr make_ip(std::string host, uint16_t port) {
    TransportAddr a;
    a.kind = TransportKind::Ip;
    a.host = std::move(host);
    a.port = port;
    return a;
}

static TransportAddr make_relay(std::string host, uint16_t port) {
    TransportAddr a;
    a.kind = TransportKind::Relay;
    a.host = std::move(host);
    a.port = port;
    return a;
}

// ========== 1. 默认构造与字段访问 ==========
static void test_default_construct() {
    FourTuple t;
    CHECK(t.local_addr.host.empty());
    CHECK(t.local_addr.port == 0);
    CHECK(t.remote_addr.host.empty());
    CHECK(t.remote_addr.port == 0);
    CHECK(t.local_addr.kind == TransportKind::Ip);
    CHECK(t.remote_addr.kind == TransportKind::Ip);
}

// ========== 2. to_string 格式 ==========
static void test_to_string_ip() {
    FourTuple t;
    t.local_addr = make_ip("192.168.1.1", 12345);
    t.remote_addr = make_ip("10.0.0.1", 54321);
    std::string s = t.to_string();
    CHECK(s.find("ip:192.168.1.1:12345") != std::string::npos);
    CHECK(s.find("ip:10.0.0.1:54321") != std::string::npos);
    CHECK(s.find(" -> ") != std::string::npos);
}

static void test_to_string_relay() {
    FourTuple t;
    t.local_addr = make_ip("127.0.0.1", 9001);
    t.remote_addr = make_relay("relay.example.com", 443);
    std::string s = t.to_string();
    CHECK(s.find("relay:relay.example.com:443") != std::string::npos);
}

static void test_to_string_custom() {
    FourTuple t;
    t.local_addr.kind = TransportKind::Custom;
    t.local_addr.host = "/dev/ttyUSB0";
    t.local_addr.port = 0;
    t.remote_addr = make_ip("127.0.0.1", 9999);
    std::string s = t.to_string();
    CHECK(s.find("custom:/dev/ttyUSB0:0") != std::string::npos);
}

// ========== 3. operator== / operator!= ==========
static void test_equality() {
    FourTuple a, b;
    a.local_addr = make_ip("1.2.3.4", 100);
    a.remote_addr = make_ip("5.6.7.8", 200);
    b = a;
    CHECK(a == b);
    CHECK(!(a != b));

    b.remote_addr.port = 201;
    CHECK(a != b);
    CHECK(!(a == b));

    b = a;
    b.local_addr.host = "1.2.3.5";
    CHECK(a != b);
}

// ========== 4. to_bytes / from_bytes 往返 ==========
static void test_bytes_roundtrip() {
    FourTuple t;
    t.local_addr = make_ip("192.168.1.100", 12345);
    t.remote_addr = make_ip("10.20.30.40", 54321);

    auto bytes = t.to_bytes();
    CHECK(!bytes.empty());

    auto parsed = FourTuple::from_bytes(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    CHECK(parsed.has_value());
    CHECK(parsed->local_addr.host == "192.168.1.100");
    CHECK(parsed->local_addr.port == 12345);
    CHECK(parsed->local_addr.kind == TransportKind::Ip);
    CHECK(parsed->remote_addr.host == "10.20.30.40");
    CHECK(parsed->remote_addr.port == 54321);
    CHECK(parsed->remote_addr.kind == TransportKind::Ip);
    CHECK(*parsed == t);
}

static void test_bytes_roundtrip_relay() {
    FourTuple t;
    t.local_addr = make_ip("127.0.0.1", 9001);
    t.remote_addr = make_relay("relay.iroh.link", 443);

    auto bytes = t.to_bytes();
    auto parsed = FourTuple::from_bytes(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    CHECK(parsed.has_value());
    CHECK(parsed->remote_addr.kind == TransportKind::Relay);
    CHECK(parsed->remote_addr.host == "relay.iroh.link");
    CHECK(parsed->remote_addr.port == 443);
    CHECK(*parsed == t);
}

// ========== 5. from_bytes 失败场景 ==========
static void test_from_bytes_empty() {
    auto parsed = FourTuple::from_bytes(std::span<const std::uint8_t>{});
    CHECK(!parsed.has_value());
}

static void test_from_bytes_truncated() {
    // 只有 1 字节
    std::uint8_t data[] = {0x05};
    auto parsed = FourTuple::from_bytes(std::span<const std::uint8_t>(data, 1));
    CHECK(!parsed.has_value());
}

static void test_from_bytes_only_local() {
    // 只够解析 local_addr，不够 remote_addr
    FourTuple t;
    t.local_addr = make_ip("1.1.1.1", 100);
    auto bytes = t.to_bytes();
    // 截断最后 5 字节（remote_addr 至少需要 1+0+2+1=4 字节）
    bytes.resize(bytes.size() - 5);
    auto parsed = FourTuple::from_bytes(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    CHECK(!parsed.has_value());
}

static void test_from_bytes_corrupt_kind() {
    FourTuple t;
    t.local_addr = make_ip("1.1.1.1", 100);
    t.remote_addr = make_ip("2.2.2.2", 200);
    auto bytes = t.to_bytes();
    // 篡改 local_addr 的 kind 字节为非法值（0xFF）
    // 布局：host_len(1) + host(N) + port(2) + kind(1) = 1+7+2+1=11 字节
    // kind 字节位于偏移 10
    bytes[10] = 0xFF;
    auto parsed = FourTuple::from_bytes(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    // 解析成功（kind 作为 uint8_t 强转），但 kind 值不是预期
    CHECK(parsed.has_value());
    CHECK(parsed->local_addr.kind != TransportKind::Ip);
}

// ========== 6. FourTuple::Hash 用于 unordered_map ==========
static void test_hash_unordered_map() {
    std::unordered_map<FourTuple, int, FourTuple::Hash> map;

    FourTuple t1;
    t1.local_addr = make_ip("1.1.1.1", 100);
    t1.remote_addr = make_ip("2.2.2.2", 200);

    FourTuple t2;
    t2.local_addr = make_ip("3.3.3.3", 300);
    t2.remote_addr = make_ip("4.4.4.4", 400);

    FourTuple t3 = t1;  // 与 t1 相同

    map[t1] = 100;
    map[t2] = 200;

    CHECK(map.size() == 2);
    CHECK(map[t1] == 100);
    CHECK(map[t2] == 200);
    CHECK(map[t3] == 100);  // t3 == t1

    map[t3] = 150;
    CHECK(map.size() == 2);
    CHECK(map[t1] == 150);
}

// ========== 7. Path 集成：构造时 four_tuple.remote_addr 已初始化 ==========
static void test_path_init_remote() {
    TransportAddr remote = make_ip("9.9.9.9", 8888);
    Path p("udp", remote);
    CHECK(p.four_tuple().remote_addr.host == "9.9.9.9");
    CHECK(p.four_tuple().remote_addr.port == 8888);
    CHECK(p.four_tuple().local_addr.host.empty());  // 尚未设置
    CHECK(p.four_tuple().local_addr.port == 0);
}

// ========== 8. Path::set_local_addr 后四元组完整 ==========
static void test_path_set_local() {
    TransportAddr remote = make_ip("9.9.9.9", 8888);
    Path p("udp", remote);

    TransportAddr local = make_ip("127.0.0.1", 12345);
    p.set_local_addr(local);

    CHECK(p.four_tuple().local_addr.host == "127.0.0.1");
    CHECK(p.four_tuple().local_addr.port == 12345);
    CHECK(p.four_tuple().remote_addr.host == "9.9.9.9");
    CHECK(p.four_tuple().remote_addr.port == 8888);

    std::string s = p.four_tuple().to_string();
    CHECK(s.find("ip:127.0.0.1:12345") != std::string::npos);
    CHECK(s.find("ip:9.9.9.9:8888") != std::string::npos);

    // addr() 仍返回原对端地址（向后兼容）
    CHECK(p.addr().host == "9.9.9.9");
    CHECK(p.addr().port == 8888);
}

// ========== 9. PathMigrationManager 关联 FourTuple ==========
static void test_path_migration_with_tuple() {
    PathMigrationManager mgr;

    FourTuple t1;
    t1.local_addr = make_ip("127.0.0.1", 5000);
    t1.remote_addr = make_ip("1.1.1.1", 9999);

    // 生成并记录带四元组的挑战
    auto challenge = mgr.generate_challenge_with_tuple(t1);
    mgr.record_challenge_sent_with_tuple(challenge, 0.0, t1);

    // 验证 has_challenge_for_tuple
    CHECK(mgr.has_challenge_for_tuple(t1));

    FourTuple t2;
    t2.local_addr = make_ip("127.0.0.1", 5001);
    t2.remote_addr = make_ip("2.2.2.2", 9999);
    CHECK(!mgr.has_challenge_for_tuple(t2));

    // 验证 PATH_RESPONSE 匹配
    PathResponseFrame resp;
    resp.data = challenge.data;
    int idx = mgr.validate_response(resp);
    CHECK(idx == 0);

    // mark_path_validated_with_tuple 应返回关联的四元组
    auto validated_tuple = mgr.mark_path_validated_with_tuple(idx);
    CHECK(validated_tuple.has_value());
    CHECK(*validated_tuple == t1);

    // 验证后 has_challenge_for_tuple 应返回 false（已 validated）
    CHECK(!mgr.has_challenge_for_tuple(t1));
}

// ========== 10. validated_tuples 查询 ==========
static void test_validated_tuples() {
    PathMigrationManager mgr;

    FourTuple t1, t2, t3;
    t1.local_addr = make_ip("127.0.0.1", 1001);
    t1.remote_addr = make_ip("1.1.1.1", 2001);
    t2.local_addr = make_ip("127.0.0.1", 1002);
    t2.remote_addr = make_ip("2.2.2.2", 2002);
    t3.local_addr = make_ip("127.0.0.1", 1003);
    t3.remote_addr = make_ip("3.3.3.3", 2003);

    // 全部记录但只验证前两个
    auto c1 = mgr.generate_challenge_with_tuple(t1);
    mgr.record_challenge_sent_with_tuple(c1, 0.0, t1);
    auto c2 = mgr.generate_challenge_with_tuple(t2);
    mgr.record_challenge_sent_with_tuple(c2, 0.0, t2);
    auto c3 = mgr.generate_challenge_with_tuple(t3);
    mgr.record_challenge_sent_with_tuple(c3, 0.0, t3);

    PathResponseFrame r1; r1.data = c1.data;
    PathResponseFrame r2; r2.data = c2.data;
    mgr.mark_path_validated_with_tuple(mgr.validate_response(r1));
    mgr.mark_path_validated_with_tuple(mgr.validate_response(r2));

    auto validated = mgr.validated_tuples();
    CHECK(validated.size() == 2);

    // 顺序应按 push 顺序（t1 在 t2 之前）
    bool found_t1 = false, found_t2 = false;
    for (const auto &t : validated) {
        if (t == t1) found_t1 = true;
        if (t == t2) found_t2 = true;
    }
    CHECK(found_t1);
    CHECK(found_t2);
}

// ========== 11. 旧 API 兼容性（无四元组） ==========
static void test_legacy_api_without_tuple() {
    PathMigrationManager mgr;

    // 旧 API 调用
    auto challenge = mgr.generate_challenge();
    mgr.record_challenge_sent(challenge, 0.0);

    // mark_path_validated_with_tuple 应返回 nullopt（无关联四元组）
    PathResponseFrame resp;
    resp.data = challenge.data;
    int idx = mgr.validate_response(resp);
    CHECK(idx == 0);

    auto result = mgr.mark_path_validated_with_tuple(idx);
    CHECK(!result.has_value());

    // validated_tuples 应为空
    auto validated = mgr.validated_tuples();
    CHECK(validated.empty());

    // has_challenge_for_tuple 应返回 false（旧挑战没关联四元组）
    FourTuple any_tuple;
    CHECK(!mgr.has_challenge_for_tuple(any_tuple));
}

// ========== 12. 混合调用：旧+新 ==========
static void test_mixed_legacy_and_new() {
    PathMigrationManager mgr;

    // 旧挑战
    auto c1 = mgr.generate_challenge();
    mgr.record_challenge_sent(c1, 0.0);

    // 新挑战带四元组
    FourTuple t;
    t.local_addr = make_ip("127.0.0.1", 7000);
    t.remote_addr = make_ip("7.7.7.7", 7001);
    auto c2 = mgr.generate_challenge_with_tuple(t);
    mgr.record_challenge_sent_with_tuple(c2, 0.0, t);

    // 两个 pending 挑战
    CHECK(mgr.pending_challenges().size() == 2);

    // 验证只带四元组的能查到
    CHECK(mgr.has_challenge_for_tuple(t));

    // 全部验证
    PathResponseFrame r1; r1.data = c1.data;
    PathResponseFrame r2; r2.data = c2.data;
    auto i1 = mgr.validate_response(r1);
    auto i2 = mgr.validate_response(r2);
    CHECK(i1 >= 0);
    CHECK(i2 >= 0);
    CHECK(i1 != i2);

    mgr.mark_path_validated(i1);
    mgr.mark_path_validated_with_tuple(i2);

    // validated_tuples 只包含带四元组的
    auto validated = mgr.validated_tuples();
    CHECK(validated.size() == 1);
    CHECK(validated[0] == t);
}

int main() {
    std::printf("=== test_four_tuple ===\n");

    test_default_construct();
    test_to_string_ip();
    test_to_string_relay();
    test_to_string_custom();
    test_equality();
    test_bytes_roundtrip();
    test_bytes_roundtrip_relay();
    test_from_bytes_empty();
    test_from_bytes_truncated();
    test_from_bytes_only_local();
    test_from_bytes_corrupt_kind();
    test_hash_unordered_map();
    test_path_init_remote();
    test_path_set_local();
    test_path_migration_with_tuple();
    test_validated_tuples();
    test_legacy_api_without_tuple();
    test_mixed_legacy_and_new();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
