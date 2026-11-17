// test_mtu.cpp — P5-B-4 MTU 协商 + Jumbo Frame 测试
//
// 验证：
//   - MtuConstants 常量
//   - is_jumbo / is_valid_mtu / clamp_mtu / mtu_name
//   - MtuNegotiator::negotiate：
//     - 双方 9000 + OpenInternet → 9000 (jumbo_enabled=true)
//     - 双方 9000 + FullCone → 9000
//     - 双方 9000 + RestrictedCone → 1500 (不允许 jumbo)
//     - 双方 9000 + PortRestrictedCone → 1500
//     - 双方 9000 + Symmetric → 1280
//     - 双方 9000 + Unknown → 1280
//     - local 9000 + remote 1280 → 1280
//     - local 1280 + remote 9000 → 1280
//     - local 1500 + remote 1500 + OpenInternet → 1500
//     - UDP Blocked → 1280
//     - 边界值：local=0 → 钳制为 1280
//     - 边界值：local=99999（截断）→ 钳制为 9000
//   - PmtuDiscovery::infer_mtu_from_addr：
//     - 私网 10.x → 9000
//     - 私网 192.168.x → 9000
//     - 私网 172.16.x ~ 172.31.x → 9000
//     - 公网 8.8.8.8 → 1500
//     - 公网 1.1.1.1 → 1500
//     - IPv6 fe80::1 → 1280
//     - IPv6 [::1] → 1280
//   - PmtuDiscovery::discover：路径 PMTU 取两端最小值

#include "linoh/net/mtu.hpp"

#include <cstdio>
#include <cstdint>
#include <string>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh;
using net::MtuConstants;
using net::MtuNegotiator;
using net::MtuNegotiationResult;
using net::NetReport;
using net::PmtuDiscovery;
using net::PmtuResult;
using net::NatType;
using net::UdpFirewall;
using net::FourTuple;
using base::TransportAddr;
using base::TransportKind;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 辅助构造 FourTuple
// ============================================================================
static FourTuple make_tuple(const std::string &local_ip, std::uint16_t local_port,
                              const std::string &remote_ip, std::uint16_t remote_port) {
    FourTuple t;
    t.local_addr.kind = TransportKind::Ip;
    t.local_addr.host = local_ip;
    t.local_addr.port = local_port;
    t.remote_addr.kind = TransportKind::Ip;
    t.remote_addr.host = remote_ip;
    t.remote_addr.port = remote_port;
    return t;
}

// ============================================================================
// 常量测试
// ============================================================================

static void test_constants() {
    CHECK(MtuConstants::kMinMtu      == 1280);
    CHECK(MtuConstants::kStandardMtu == 1500);
    CHECK(MtuConstants::kJumboMtu    == 9000);
    CHECK(MtuConstants::kMaxMtu      == 9000);
}

// ============================================================================
// is_jumbo / is_valid_mtu / clamp_mtu / mtu_name
// ============================================================================

static void test_is_jumbo() {
    CHECK(!net::is_jumbo(1279));
    CHECK(!net::is_jumbo(1280));
    CHECK(!net::is_jumbo(1500));
    CHECK(!net::is_jumbo(8999));
    CHECK(net::is_jumbo(9000));
}

static void test_is_valid_mtu() {
    CHECK(!net::is_valid_mtu(0));
    CHECK(!net::is_valid_mtu(1279));
    CHECK(net::is_valid_mtu(1280));
    CHECK(net::is_valid_mtu(1500));
    CHECK(net::is_valid_mtu(9000));
    CHECK(!net::is_valid_mtu(9001));
    CHECK(!net::is_valid_mtu(65535));
}

static void test_clamp_mtu() {
    CHECK(net::clamp_mtu(0)     == 1280);
    CHECK(net::clamp_mtu(1279)  == 1280);
    CHECK(net::clamp_mtu(1280)  == 1280);
    CHECK(net::clamp_mtu(1500)  == 1500);
    CHECK(net::clamp_mtu(9000)  == 9000);
    CHECK(net::clamp_mtu(9001)  == 9000);
    CHECK(net::clamp_mtu(65535) == 9000);
}

static void test_mtu_name() {
    CHECK(net::mtu_name(9000) == "jumbo(9000)");
    CHECK(net::mtu_name(1500) == "standard(1500)");
    CHECK(net::mtu_name(1280) == "minimum(1280)");
    CHECK(net::mtu_name(100)  == "invalid(100)");
}

// ============================================================================
// MtuNegotiator::negotiate
// ============================================================================

static void test_negotiate_both_jumbo_open_internet() {
    auto r = MtuNegotiator::negotiate(9000, 9000, NatType::OpenInternet);
    CHECK(r.negotiated_mtu == 9000);
    CHECK(r.jumbo_enabled == true);
}

static void test_negotiate_both_jumbo_full_cone() {
    auto r = MtuNegotiator::negotiate(9000, 9000, NatType::FullCone);
    CHECK(r.negotiated_mtu == 9000);
    CHECK(r.jumbo_enabled == true);
}

static void test_negotiate_both_jumbo_restricted_cone() {
    auto r = MtuNegotiator::negotiate(9000, 9000, NatType::RestrictedCone);
    // RestrictedCone 不允许 jumbo，降级到 1500
    CHECK(r.negotiated_mtu == 1500);
    CHECK(r.jumbo_enabled == false);
}

static void test_negotiate_both_jumbo_port_restricted() {
    auto r = MtuNegotiator::negotiate(9000, 9000, NatType::PortRestrictedCone);
    CHECK(r.negotiated_mtu == 1500);
    CHECK(r.jumbo_enabled == false);
}

static void test_negotiate_both_jumbo_symmetric() {
    auto r = MtuNegotiator::negotiate(9000, 9000, NatType::Symmetric);
    // Symmetric → 保守 1280
    CHECK(r.negotiated_mtu == 1280);
    CHECK(r.jumbo_enabled == false);
}

static void test_negotiate_both_jumbo_unknown() {
    auto r = MtuNegotiator::negotiate(9000, 9000, NatType::Unknown);
    CHECK(r.negotiated_mtu == 1280);
    CHECK(r.jumbo_enabled == false);
}

static void test_negotiate_mixed_local_jumbo_remote_min() {
    auto r = MtuNegotiator::negotiate(9000, 1280, NatType::OpenInternet);
    CHECK(r.negotiated_mtu == 1280);
    CHECK(r.jumbo_enabled == false);
}

static void test_negotiate_mixed_local_min_remote_jumbo() {
    auto r = MtuNegotiator::negotiate(1280, 9000, NatType::OpenInternet);
    CHECK(r.negotiated_mtu == 1280);
    CHECK(r.jumbo_enabled == false);
}

static void test_negotiate_both_standard() {
    auto r = MtuNegotiator::negotiate(1500, 1500, NatType::OpenInternet);
    CHECK(r.negotiated_mtu == 1500);
    CHECK(r.jumbo_enabled == false);
}

static void test_negotiate_udp_blocked() {
    auto r = MtuNegotiator::negotiate(9000, 9000, NatType::OpenInternet, UdpFirewall::Blocked);
    CHECK(r.negotiated_mtu == 1280);
    CHECK(r.jumbo_enabled == false);
}

static void test_negotiate_udp_blocked_overrides_fullcone() {
    auto r = MtuNegotiator::negotiate(9000, 9000, NatType::FullCone, UdpFirewall::Blocked);
    CHECK(r.negotiated_mtu == 1280);
}

static void test_negotiate_local_zero_clamped() {
    // local=0 钳制为 1280，与 remote=9000 取 min → 1280
    auto r = MtuNegotiator::negotiate(0, 9000, NatType::OpenInternet);
    CHECK(r.negotiated_mtu == 1280);
    CHECK(r.jumbo_enabled == false);
}

static void test_negotiate_local_too_large_clamped() {
    // local=99999 截断为 uint16_t = 34463，再钳制为 9000
    // remote=9000 + OpenInternet → 9000
    auto r = MtuNegotiator::negotiate(99999, 9000, NatType::OpenInternet);
    CHECK(r.negotiated_mtu == 9000);
    CHECK(r.jumbo_enabled == true);
}

static void test_negotiate_reason_not_empty() {
    auto r1 = MtuNegotiator::negotiate(9000, 9000, NatType::OpenInternet);
    CHECK(!r1.reason.empty());

    auto r2 = MtuNegotiator::negotiate(9000, 9000, NatType::Symmetric);
    CHECK(!r2.reason.empty());

    auto r3 = MtuNegotiator::negotiate(1500, 1500, NatType::OpenInternet);
    CHECK(!r3.reason.empty());
}

// ============================================================================
// PmtuDiscovery::infer_mtu_from_addr
// ============================================================================

static void test_infer_private_10() {
    CHECK(PmtuDiscovery::infer_mtu_from_addr("10.0.0.1") == 9000);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("10.1.2.3") == 9000);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("10.255.255.255") == 9000);
}

static void test_infer_private_192_168() {
    CHECK(PmtuDiscovery::infer_mtu_from_addr("192.168.0.1") == 9000);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("192.168.1.100") == 9000);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("192.168.99.99") == 9000);
}

static void test_infer_private_172_16_to_31() {
    // 172.16.x.x ~ 172.31.x.x 是私网
    CHECK(PmtuDiscovery::infer_mtu_from_addr("172.16.0.1") == 9000);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("172.20.10.5") == 9000);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("172.31.255.255") == 9000);
}

static void test_infer_public_172_not_private() {
    // 172.15.x.x 和 172.32.x.x 不是私网（公网）
    CHECK(PmtuDiscovery::infer_mtu_from_addr("172.15.0.1") == 1500);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("172.32.0.1") == 1500);
}

static void test_infer_public_ipv4() {
    CHECK(PmtuDiscovery::infer_mtu_from_addr("8.8.8.8") == 1500);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("1.1.1.1") == 1500);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("203.0.113.10") == 1500);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("192.0.2.114") == 1500);
}

static void test_infer_ipv6() {
    CHECK(PmtuDiscovery::infer_mtu_from_addr("fe80::1") == 1280);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("::1") == 1280);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("2001:db8::1") == 1280);
    CHECK(PmtuDiscovery::infer_mtu_from_addr("[::1]") == 1280);
}

static void test_infer_empty() {
    CHECK(PmtuDiscovery::infer_mtu_from_addr("") == 1280);
}

// ============================================================================
// PmtuDiscovery::discover
// ============================================================================

static void test_discover_private_to_private() {
    auto path = make_tuple("10.0.0.1", 1000, "10.0.0.2", 2000);
    auto r = PmtuDiscovery::discover(path);
    CHECK(r.success == true);
    CHECK(r.discovered_mtu == 9000);
}

static void test_discover_private_to_public() {
    auto path = make_tuple("10.0.0.1", 1000, "8.8.8.8", 2000);
    auto r = PmtuDiscovery::discover(path);
    CHECK(r.success == true);
    CHECK(r.discovered_mtu == 1500);  // 取两端最小值
}

static void test_discover_public_to_public() {
    auto path = make_tuple("1.1.1.1", 1000, "8.8.8.8", 2000);
    auto r = PmtuDiscovery::discover(path);
    CHECK(r.success == true);
    CHECK(r.discovered_mtu == 1500);
}

static void test_discover_ipv6_path() {
    // 用 IPv6 主机名（含 ':'）
    FourTuple t;
    t.local_addr.kind = TransportKind::Ip;
    t.local_addr.host = "fe80::1";
    t.local_addr.port = 1000;
    t.remote_addr.kind = TransportKind::Ip;
    t.remote_addr.host = "fe80::2";
    t.remote_addr.port = 2000;
    auto r = PmtuDiscovery::discover(t);
    CHECK(r.success == true);
    CHECK(r.discovered_mtu == 1280);
}

// ============================================================================
// NetReport 便捷重载测试
// ============================================================================

static void test_negotiate_overload_net_report() {
    NetReport r;
    r.nat_type = NatType::OpenInternet;
    r.udp_firewall = UdpFirewall::Open;
    auto res = MtuNegotiator::negotiate(9000, 9000, r);
    CHECK(res.negotiated_mtu == 9000);
    CHECK(res.jumbo_enabled == true);

    r.nat_type = NatType::Symmetric;
    res = MtuNegotiator::negotiate(9000, 9000, r);
    CHECK(res.negotiated_mtu == 1280);
}

// ============================================================================
// 完整组合测试：3 NAT × 3 MTU 组合
// ============================================================================

static void test_negotiate_full_matrix() {
    // 行：NAT 类型；列：(local_mtu, remote_mtu) 组合
    struct Case { NatType nat; std::uint16_t lm, rm; std::uint16_t expected; bool jumbo; };
    Case cases[] = {
        // 双方 jumbo
        {NatType::OpenInternet,       9000, 9000, 9000, true},
        {NatType::FullCone,            9000, 9000, 9000, true},
        {NatType::RestrictedCone,      9000, 9000, 1500, false},  // 降级
        {NatType::PortRestrictedCone,  9000, 9000, 1500, false},  // 降级
        {NatType::Symmetric,           9000, 9000, 1280, false},
        {NatType::Unknown,             9000, 9000, 1280, false},
        // 一方 standard 一方 jumbo
        {NatType::OpenInternet,        9000, 1500, 1500, false},
        {NatType::OpenInternet,        1500, 9000, 1500, false},
        // 双方 standard
        {NatType::OpenInternet,        1500, 1500, 1500, false},
        {NatType::RestrictedCone,      1500, 1500, 1500, false},
        {NatType::Symmetric,           1500, 1500, 1280, false},  // Symmetric 强制 1280
        // 双方 minimum
        {NatType::OpenInternet,        1280, 1280, 1280, false},
    };
    for (auto &c : cases) {
        auto r = MtuNegotiator::negotiate(c.lm, c.rm, c.nat);
        CHECK(r.negotiated_mtu == c.expected);
        CHECK(r.jumbo_enabled == c.jumbo);
    }
}

int main() {
    std::printf("=== test_mtu ===\n");

    test_constants();
    test_is_jumbo();
    test_is_valid_mtu();
    test_clamp_mtu();
    test_mtu_name();

    test_negotiate_both_jumbo_open_internet();
    test_negotiate_both_jumbo_full_cone();
    test_negotiate_both_jumbo_restricted_cone();
    test_negotiate_both_jumbo_port_restricted();
    test_negotiate_both_jumbo_symmetric();
    test_negotiate_both_jumbo_unknown();
    test_negotiate_mixed_local_jumbo_remote_min();
    test_negotiate_mixed_local_min_remote_jumbo();
    test_negotiate_both_standard();
    test_negotiate_udp_blocked();
    test_negotiate_udp_blocked_overrides_fullcone();
    test_negotiate_local_zero_clamped();
    test_negotiate_local_too_large_clamped();
    test_negotiate_reason_not_empty();

    test_infer_private_10();
    test_infer_private_192_168();
    test_infer_private_172_16_to_31();
    test_infer_public_172_not_private();
    test_infer_public_ipv4();
    test_infer_ipv6();
    test_infer_empty();

    test_discover_private_to_private();
    test_discover_private_to_public();
    test_discover_public_to_public();
    test_discover_ipv6_path();

    test_negotiate_overload_net_report();

    test_negotiate_full_matrix();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
