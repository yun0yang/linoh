// test_dual_stack.cpp — P5-D-4 IPv6/IPv4 跨栈双栈测试
//
// 覆盖：
//   - 地址族工具（is_ipv4/is_ipv6/parse/format）
//   - NAT64 地址合成（RFC 6052 WKP + 自定义前缀）
//   - 6to4 隧道合成（RFC 3056）
//   - LocalStackCapability 推断
//   - DualStackConnector 地址选择
//   - 工具函数

#include "linoh/nat/dual_stack.hpp"

#include <cassert>
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

static int total = 0;
static int failed = 0;

using namespace linoh::nat;

// ============================================================================
// 1. 地址族工具测试
// ============================================================================

void test_address_family_detection() {
    std::cout << "[test] address family detection" << std::endl;

    // IPv4
    CHECK(is_ipv4_address("192.168.1.1"));
    CHECK(is_ipv4_address("10.0.0.1"));
    CHECK(is_ipv4_address("8.8.8.8"));
    CHECK(!is_ipv4_address("::1"));
    CHECK(!is_ipv4_address("2001:db8::1"));
    CHECK(!is_ipv4_address("64:ff9b::1.2.3.4"));

    // IPv6
    CHECK(is_ipv6_address("::1"));
    CHECK(is_ipv6_address("2001:db8::1"));
    CHECK(is_ipv6_address("64:ff9b::"));
    CHECK(is_ipv6_address("fe80::1"));
    CHECK(is_ipv6_address("2002:c000:0204::"));
    CHECK(!is_ipv6_address("192.168.1.1"));
}

void test_parse_ipv4() {
    std::cout << "[test] parse_ipv4" << std::endl;

    auto r1 = parse_ipv4("192.168.1.1");
    CHECK(r1.has_value());
    CHECK((*r1)[0] == 192);
    CHECK((*r1)[1] == 168);
    CHECK((*r1)[2] == 1);
    CHECK((*r1)[3] == 1);

    auto r2 = parse_ipv4("0.0.0.0");
    CHECK(r2.has_value());
    CHECK((*r2)[0] == 0);

    auto r3 = parse_ipv4("255.255.255.255");
    CHECK(r3.has_value());
    CHECK((*r3)[0] == 255);

    // 错误情况
    CHECK(!parse_ipv4("256.1.1.1").has_value());  // 越界
    CHECK(!parse_ipv4("1.2.3").has_value());      // 段数不足
    CHECK(!parse_ipv4("1.2.3.4.5").has_value());  // 段数过多
    CHECK(!parse_ipv4("a.b.c.d").has_value());    // 非数字
    CHECK(!parse_ipv4("").has_value());           // 空
    CHECK(!parse_ipv4("1.2.3.").has_value());     // 尾部空
    CHECK(!parse_ipv4(".1.2.3").has_value());     // 头部空
}

void test_format_ipv4() {
    std::cout << "[test] format_ipv4" << std::endl;

    std::array<std::uint8_t, 4> b1{192, 168, 1, 1};
    CHECK(format_ipv4(b1) == "192.168.1.1");

    std::array<std::uint8_t, 4> b2{0, 0, 0, 0};
    CHECK(format_ipv4(b2) == "0.0.0.0");

    std::array<std::uint8_t, 4> b3{255, 255, 255, 255};
    CHECK(format_ipv4(b3) == "255.255.255.255");

    // round-trip
    CHECK(format_ipv4(*parse_ipv4("8.8.4.4")) == "8.8.4.4");
    CHECK(format_ipv4(*parse_ipv4("172.16.254.1")) == "172.16.254.1");
}

void test_parse_ipv6_basic() {
    std::cout << "[test] parse_ipv6 basic" << std::endl;

    // ::1 loopback
    auto r1 = parse_ipv6("::1");
    CHECK(r1.has_value());
    // 前 14 字节为 0，最后一字节为 1
    for (int i = 0; i < 14; ++i) CHECK((*r1)[i] == 0);
    CHECK((*r1)[15] == 1);

    // 2001:db8::1
    auto r2 = parse_ipv6("2001:db8::1");
    CHECK(r2.has_value());
    CHECK((*r2)[0] == 0x20);
    CHECK((*r2)[1] == 0x01);
    CHECK((*r2)[2] == 0x0d);
    CHECK((*r2)[3] == 0xb8);
    for (int i = 4; i < 14; ++i) CHECK((*r2)[i] == 0);
    CHECK((*r2)[15] == 1);

    // 全 0
    auto r3 = parse_ipv6("::");
    CHECK(r3.has_value());
    for (int i = 0; i < 16; ++i) CHECK((*r3)[i] == 0);

    // 完整格式
    auto r4 = parse_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001");
    CHECK(r4.has_value());
    CHECK((*r4)[15] == 1);
}

void test_parse_ipv6_invalid() {
    std::cout << "[test] parse_ipv6 invalid" << std::endl;

    CHECK(!parse_ipv6("").has_value());
    CHECK(!parse_ipv6("192.168.1.1").has_value());  // IPv4
    // 多个 ::
    CHECK(!parse_ipv6("::1::2").has_value());
}

void test_format_ipv6() {
    std::cout << "[test] format_ipv6" << std::endl;

    // ::1
    std::array<std::uint8_t, 16> b1{};
    b1[15] = 1;
    CHECK(format_ipv6(b1) == "::1");

    // 2001:db8::1
    std::array<std::uint8_t, 16> b2{};
    b2[0] = 0x20; b2[1] = 0x01;
    b2[2] = 0x0d; b2[3] = 0xb8;
    b2[15] = 1;
    CHECK(format_ipv6(b2) == "2001:db8::1");

    // 全 0
    std::array<std::uint8_t, 16> b3{};
    CHECK(format_ipv6(b3) == "::");

    // round-trip
    CHECK(format_ipv6(*parse_ipv6("2001:db8::1")) == "2001:db8::1");
    CHECK(format_ipv6(*parse_ipv6("::1")) == "::1");
    CHECK(format_ipv6(*parse_ipv6("::")) == "::");
}

// ============================================================================
// 2. NAT64 地址合成测试
// ============================================================================

void test_nat64_wkp_synthesize() {
    std::cout << "[test] NAT64 WKP synthesize" << std::endl;

    // 64:ff9b::1.2.3.4
    auto r1 = synthesize_nat64_address("1.2.3.4");
    CHECK(r1.has_value());
    auto parsed = parse_ipv6(*r1);
    CHECK(parsed.has_value());
    // 前 12 字节 = WKP
    CHECK((*parsed)[0] == 0x00);
    CHECK((*parsed)[1] == 0x64);
    CHECK((*parsed)[2] == 0xff);
    CHECK((*parsed)[3] == 0x9b);
    for (int i = 4; i < 12; ++i) CHECK((*parsed)[i] == 0);
    // 后 4 字节 = IPv4
    CHECK((*parsed)[12] == 1);
    CHECK((*parsed)[13] == 2);
    CHECK((*parsed)[14] == 3);
    CHECK((*parsed)[15] == 4);

    // 192.168.1.1
    auto r2 = synthesize_nat64_address("192.168.1.1");
    CHECK(r2.has_value());
    auto p2 = parse_ipv6(*r2);
    CHECK(p2.has_value());
    CHECK((*p2)[12] == 192);
    CHECK((*p2)[13] == 168);
    CHECK((*p2)[14] == 1);
    CHECK((*p2)[15] == 1);
}

void test_nat64_extract() {
    std::cout << "[test] NAT64 extract IPv4" << std::endl;

    // 正常 case
    auto synth = synthesize_nat64_address("8.8.8.8");
    CHECK(synth.has_value());
    auto extracted = extract_ipv4_from_nat64(*synth);
    CHECK(extracted.has_value());
    CHECK(*extracted == "8.8.8.8");

    // 192.168.100.200
    auto s2 = synthesize_nat64_address("192.168.100.200");
    CHECK(s2.has_value());
    auto e2 = extract_ipv4_from_nat64(*s2);
    CHECK(e2.has_value());
    CHECK(*e2 == "192.168.100.200");

    // 非 NAT64 地址（普通 IPv6）
    CHECK(!extract_ipv4_from_nat64("::1").has_value());
    CHECK(!extract_ipv4_from_nat64("2001:db8::1").has_value());

    // 自定义前缀
    Nat64Prefix custom;
    custom.bytes = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0};
    auto s3 = synthesize_nat64_address("10.0.0.1", custom);
    CHECK(s3.has_value());
    auto e3 = extract_ipv4_from_nat64(*s3, custom);
    CHECK(e3.has_value());
    CHECK(*e3 == "10.0.0.1");

    // WKP 提取自定义前缀地址应失败
    CHECK(!extract_ipv4_from_nat64(*s3).has_value());
}

void test_nat64_invalid_input() {
    std::cout << "[test] NAT64 invalid input" << std::endl;

    // 无效 IPv4
    CHECK(!synthesize_nat64_address("256.1.1.1").has_value());
    CHECK(!synthesize_nat64_address("").has_value());
    CHECK(!synthesize_nat64_address("abc.def.ghi.jkl").has_value());
    CHECK(!synthesize_nat64_address("::1").has_value());

    // 无效 NAT64 IPv6
    CHECK(!extract_ipv4_from_nat64("not an ip").has_value());
    CHECK(!extract_ipv4_from_nat64("").has_value());
}

void test_nat64_prefix_struct() {
    std::cout << "[test] Nat64Prefix struct" << std::endl;

    Nat64Prefix default_prefix{};
    CHECK(default_prefix.is_wkp());
    CHECK(default_prefix.prefix_bits == 96);

    Nat64Prefix custom{};
    custom.bytes = {0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    CHECK(!custom.is_wkp());

    // 等于
    Nat64Prefix p1{};
    Nat64Prefix p2{};
    CHECK(p1 == p2);

    Nat64Prefix p3{};
    p3.bytes[0] = 0xff;
    CHECK(!(p1 == p3));
}

// ============================================================================
// 3. 6to4 隧道测试
// ============================================================================

void test_6to4_synthesize() {
    std::cout << "[test] 6to4 synthesize" << std::endl;

    // 192.0.2.4 → 2002:c000:0204::
    auto r1 = synthesize_6to4_address("192.0.2.4");
    CHECK(r1.has_value());
    auto parsed = parse_ipv6(*r1);
    CHECK(parsed.has_value());
    CHECK((*parsed)[0] == 0x20);
    CHECK((*parsed)[1] == 0x02);
    CHECK((*parsed)[2] == 0xc0);  // 192
    CHECK((*parsed)[3] == 0x00);  // 0
    CHECK((*parsed)[4] == 0x02);  // 2
    CHECK((*parsed)[5] == 0x04);  // 4
    for (int i = 6; i < 16; ++i) CHECK((*parsed)[i] == 0);

    // 10.0.0.1 → 2002:0a00:0001::
    auto r2 = synthesize_6to4_address("10.0.0.1");
    CHECK(r2.has_value());
    auto p2 = parse_ipv6(*r2);
    CHECK(p2.has_value());
    CHECK((*p2)[0] == 0x20);
    CHECK((*p2)[1] == 0x02);
    CHECK((*p2)[2] == 0x0a);  // 10
    CHECK((*p2)[3] == 0x00);
    CHECK((*p2)[4] == 0x00);
    CHECK((*p2)[5] == 0x01);
}

void test_6to4_detection() {
    std::cout << "[test] 6to4 detection" << std::endl;

    // 6to4 地址
    auto s1 = synthesize_6to4_address("192.0.2.4");
    CHECK(s1.has_value());
    CHECK(is_6to4_address(*s1));

    // 非 6to4
    CHECK(!is_6to4_address("::1"));
    CHECK(!is_6to4_address("2001:db8::1"));
    CHECK(!is_6to4_address("64:ff9b::"));
    CHECK(!is_6to4_address("192.168.1.1"));

    // 边界：2001:: 不是 6to4
    CHECK(!is_6to4_address("2001::"));
    // 2003:: 不是 6to4
    CHECK(!is_6to4_address("2003::"));
}

void test_6to4_extract() {
    std::cout << "[test] 6to4 extract IPv4" << std::endl;

    auto s1 = synthesize_6to4_address("172.16.254.1");
    CHECK(s1.has_value());
    auto e1 = extract_ipv4_from_6to4(*s1);
    CHECK(e1.has_value());
    CHECK(*e1 == "172.16.254.1");

    // 非 6to4 地址
    CHECK(!extract_ipv4_from_6to4("::1").has_value());
    CHECK(!extract_ipv4_from_6to4("2001:db8::1").has_value());
    CHECK(!extract_ipv4_from_6to4("192.168.1.1").has_value());
}

void test_6to4_invalid_input() {
    std::cout << "[test] 6to4 invalid input" << std::endl;

    CHECK(!synthesize_6to4_address("").has_value());
    CHECK(!synthesize_6to4_address("256.1.1.1").has_value());
    CHECK(!synthesize_6to4_address("::1").has_value());
}

// ============================================================================
// 4. LocalStackCapability 测试
// ============================================================================

void test_local_stack_infer_mode() {
    std::cout << "[test] LocalStackCapability infer_mode" << std::endl;

    LocalStackCapability dual;
    dual.supports_ipv4 = true;
    dual.supports_ipv6 = true;
    CHECK(dual.infer_mode() == DualStackMode::DualStack);

    LocalStackCapability v4only;
    v4only.supports_ipv4 = true;
    CHECK(v4only.infer_mode() == DualStackMode::IPv4Only);

    LocalStackCapability v6only;
    v6only.supports_ipv6 = true;
    CHECK(v6only.infer_mode() == DualStackMode::IPv6Only);

    LocalStackCapability nat64;
    nat64.supports_ipv6 = true;
    nat64.supports_nat64 = true;
    CHECK(nat64.infer_mode() == DualStackMode::NAT64);

    LocalStackCapability dns64;
    dns64.supports_ipv6 = true;
    dns64.supports_dns64 = true;
    CHECK(dns64.infer_mode() == DualStackMode::DNS64);

    // NAT64 优先于 DNS64
    LocalStackCapability both;
    both.supports_ipv6 = true;
    both.supports_nat64 = true;
    both.supports_dns64 = true;
    CHECK(both.infer_mode() == DualStackMode::NAT64);

    // 双栈优先于 NAT64
    LocalStackCapability dual_nat64;
    dual_nat64.supports_ipv4 = true;
    dual_nat64.supports_ipv6 = true;
    dual_nat64.supports_nat64 = true;
    CHECK(dual_nat64.infer_mode() == DualStackMode::DualStack);

    // 无栈（P5-D-3 边界修复：双栈均不支持时返回 Disabled，而非 IPv4Only）
    LocalStackCapability none;
    CHECK(none.infer_mode() == DualStackMode::Disabled);
}

void test_local_stack_to_string() {
    std::cout << "[test] LocalStackCapability to_string" << std::endl;

    LocalStackCapability cap;
    cap.supports_ipv4 = true;
    cap.supports_ipv6 = true;
    cap.ipv4_addresses.push_back("192.168.1.1");
    cap.ipv6_addresses.push_back("::1");

    std::string s = cap.to_string();
    CHECK(s.find("ipv4=yes") != std::string::npos);
    CHECK(s.find("ipv6=yes") != std::string::npos);
    CHECK(s.find("192.168.1.1") != std::string::npos);
    CHECK(s.find("::1") != std::string::npos);
    CHECK(s.find("dual-stack") != std::string::npos);
}

// ============================================================================
// 5. DualStackConnector 测试
// ============================================================================

void test_connector_default_construct() {
    std::cout << "[test] DualStackConnector default construct" << std::endl;

    DualStackConnector c;
    CHECK(c.config().enable_nat64 == true);
    CHECK(c.config().enable_6to4 == false);
    CHECK(c.config().enable_dns64 == false);
    CHECK(c.config().nat64_prefix.is_wkp());
}

void test_connector_injected_detector() {
    std::cout << "[test] DualStackConnector injected detector" << std::endl;

    // 注入 mock 检测器
    LocalStackCapability mock;
    mock.supports_ipv4 = true;
    mock.supports_ipv6 = false;

    DualStackConfig cfg;
    DualStackConnector c(cfg, [mock]() { return mock; });

    auto result = c.detect_local_stack();
    CHECK(result.supports_ipv4 == true);
    CHECK(result.supports_ipv6 == false);
    CHECK(result.infer_mode() == DualStackMode::IPv4Only);
}

void test_connector_translate_no_change() {
    std::cout << "[test] DualStackConnector translate no change" << std::endl;

    // 本机双栈 → 无需转换
    LocalStackCapability dual;
    dual.supports_ipv4 = true;
    dual.supports_ipv6 = true;

    DualStackConnector c;
    auto r1 = c.translate_address("192.168.1.1", dual);
    CHECK(r1.has_value());
    CHECK(*r1 == "192.168.1.1");

    auto r2 = c.translate_address("::1", dual);
    CHECK(r2.has_value());
    CHECK(*r2 == "::1");
}

void test_connector_translate_nat64() {
    std::cout << "[test] DualStackConnector translate NAT64" << std::endl;

    // 本机 IPv6-only，对端 IPv4 → NAT64
    LocalStackCapability v6only;
    v6only.supports_ipv6 = true;

    DualStackConnector c;
    auto r = c.translate_address("1.2.3.4", v6only);
    CHECK(r.has_value());
    // 应为 NAT64 合成地址
    auto extracted = extract_ipv4_from_nat64(*r);
    CHECK(extracted.has_value());
    CHECK(*extracted == "1.2.3.4");
}

void test_connector_translate_nat64_disabled() {
    std::cout << "[test] DualStackConnector translate NAT64 disabled" << std::endl;

    LocalStackCapability v6only;
    v6only.supports_ipv6 = true;

    DualStackConfig cfg;
    cfg.enable_nat64 = false;
    DualStackConnector c(cfg);

    auto r = c.translate_address("1.2.3.4", v6only);
    CHECK(!r.has_value());
}

void test_connector_translate_6to4() {
    std::cout << "[test] DualStackConnector translate 6to4" << std::endl;

    // 本机 IPv4-only，对端 6to4 地址 → 提取 IPv4
    LocalStackCapability v4only;
    v4only.supports_ipv4 = true;

    DualStackConfig cfg;
    cfg.enable_6to4 = true;
    DualStackConnector c(cfg);

    // 先合成 6to4
    auto s6 = synthesize_6to4_address("192.0.2.4");
    CHECK(s6.has_value());

    auto r = c.translate_address(*s6, v4only);
    CHECK(r.has_value());
    CHECK(*r == "192.0.2.4");
}

void test_connector_translate_6to4_disabled() {
    std::cout << "[test] DualStackConnector translate 6to4 disabled" << std::endl;

    LocalStackCapability v4only;
    v4only.supports_ipv4 = true;

    DualStackConnector c;  // 默认 enable_6to4=false

    auto s6 = synthesize_6to4_address("192.0.2.4");
    CHECK(s6.has_value());

    auto r = c.translate_address(*s6, v4only);
    CHECK(!r.has_value());
}

void test_connector_translate_6to4_non_6to4_addr() {
    std::cout << "[test] DualStackConnector 6to4 non-6to4 address" << std::endl;

    LocalStackCapability v4only;
    v4only.supports_ipv4 = true;

    DualStackConfig cfg;
    cfg.enable_6to4 = true;
    DualStackConnector c(cfg);

    // 非 6to4 的 IPv6 地址，无法通过 6to4 转换
    auto r = c.translate_address("2001:db8::1", v4only);
    CHECK(!r.has_value());
}

void test_connector_select_best_dualstack() {
    std::cout << "[test] select_best dualstack" << std::endl;

    LocalStackCapability dual;
    dual.supports_ipv4 = true;
    dual.supports_ipv6 = true;

    DualStackConnector c;
    std::vector<std::string> candidates = {"192.168.1.1", "2001:db8::1"};

    auto r = c.select_best_address(candidates, dual);
    CHECK(r.has_value());
    // IPv6 优先
    CHECK(r->address == "2001:db8::1");
    CHECK(r->mode == DualStackMode::DualStack);
}

void test_connector_select_best_v4_only_local() {
    std::cout << "[test] select_best v4-only local" << std::endl;

    LocalStackCapability v4only;
    v4only.supports_ipv4 = true;

    DualStackConnector c;
    std::vector<std::string> candidates = {"192.168.1.1", "10.0.0.1"};

    auto r = c.select_best_address(candidates, v4only);
    CHECK(r.has_value());
    CHECK(r->address == "192.168.1.1");
    CHECK(r->mode == DualStackMode::IPv4Only);
}

void test_connector_select_best_v6_only_local() {
    std::cout << "[test] select_best v6-only local" << std::endl;

    LocalStackCapability v6only;
    v6only.supports_ipv6 = true;

    DualStackConnector c;
    std::vector<std::string> candidates = {"::1", "2001:db8::1"};

    auto r = c.select_best_address(candidates, v6only);
    CHECK(r.has_value());
    CHECK(r->address == "::1");
    CHECK(r->mode == DualStackMode::IPv6Only);
}

void test_connector_select_best_nat64() {
    std::cout << "[test] select_best NAT64" << std::endl;

    // 本机 IPv6-only，对端只有 IPv4 → NAT64
    LocalStackCapability v6only;
    v6only.supports_ipv6 = true;

    DualStackConnector c;
    std::vector<std::string> candidates = {"192.168.1.1", "10.0.0.1"};

    auto r = c.select_best_address(candidates, v6only);
    CHECK(r.has_value());
    CHECK(r->mode == DualStackMode::NAT64);
    // 应为 NAT64 合成地址
    auto extracted = extract_ipv4_from_nat64(r->address);
    CHECK(extracted.has_value());
    CHECK(*extracted == "192.168.1.1");
}

void test_connector_select_best_6to4() {
    std::cout << "[test] select_best 6to4" << std::endl;

    // 本机 IPv4-only，对端只有 IPv6 6to4 地址
    LocalStackCapability v4only;
    v4only.supports_ipv4 = true;

    DualStackConfig cfg;
    cfg.enable_6to4 = true;
    DualStackConnector c(cfg);

    auto s6 = synthesize_6to4_address("192.0.2.4");
    CHECK(s6.has_value());
    std::vector<std::string> candidates = {*s6};

    auto r = c.select_best_address(candidates, v4only);
    CHECK(r.has_value());
    CHECK(r->address == "192.0.2.4");
}

void test_connector_select_best_no_candidates() {
    std::cout << "[test] select_best no candidates" << std::endl;

    LocalStackCapability dual;
    dual.supports_ipv4 = true;
    dual.supports_ipv6 = true;

    DualStackConnector c;
    std::vector<std::string> empty;

    auto r = c.select_best_address(empty, dual);
    CHECK(!r.has_value());
}

void test_connector_select_best_no_compatible() {
    std::cout << "[test] select_best no compatible" << std::endl;

    // 本机 IPv4-only，对端只有非 6to4 的 IPv6 地址
    LocalStackCapability v4only;
    v4only.supports_ipv4 = true;

    DualStackConfig cfg;
    cfg.enable_6to4 = true;
    DualStackConnector c(cfg);

    std::vector<std::string> candidates = {"2001:db8::1", "fe80::1"};

    auto r = c.select_best_address(candidates, v4only);
    CHECK(!r.has_value());
}

void test_connector_select_best_v4_local_no_v6_remote() {
    std::cout << "[test] select_best v4 local no v6 remote" << std::endl;

    // 本机双栈，对端只有 IPv4
    LocalStackCapability dual;
    dual.supports_ipv4 = true;
    dual.supports_ipv6 = true;

    DualStackConnector c;
    std::vector<std::string> candidates = {"192.168.1.1"};

    auto r = c.select_best_address(candidates, dual);
    CHECK(r.has_value());
    CHECK(r->address == "192.168.1.1");
    CHECK(r->mode == DualStackMode::DualStack);
}

// ============================================================================
// 6. 工具函数测试
// ============================================================================

void test_filter_functions() {
    std::cout << "[test] filter functions" << std::endl;

    std::vector<std::string> addrs = {
        "192.168.1.1",
        "::1",
        "10.0.0.1",
        "2001:db8::1"
    };

    auto v4 = filter_ipv4(addrs);
    CHECK(v4.size() == 2);
    CHECK(v4[0] == "192.168.1.1");
    CHECK(v4[1] == "10.0.0.1");

    auto v6 = filter_ipv6(addrs);
    CHECK(v6.size() == 2);
    CHECK(v6[0] == "::1");
    CHECK(v6[1] == "2001:db8::1");
}

void test_has_functions() {
    std::cout << "[test] has functions" << std::endl;

    std::vector<std::string> v4only = {"192.168.1.1", "10.0.0.1"};
    CHECK(has_ipv4(v4only));
    CHECK(!has_ipv6(v4only));

    std::vector<std::string> v6only = {"::1", "2001:db8::1"};
    CHECK(!has_ipv4(v6only));
    CHECK(has_ipv6(v6only));

    std::vector<std::string> mixed = {"192.168.1.1", "::1"};
    CHECK(has_ipv4(mixed));
    CHECK(has_ipv6(mixed));

    std::vector<std::string> empty;
    CHECK(!has_ipv4(empty));
    CHECK(!has_ipv6(empty));
}

// ============================================================================
// 7. DualStackMode 枚举测试
// ============================================================================

void test_dual_stack_mode_name() {
    std::cout << "[test] dual_stack_mode_name" << std::endl;

    CHECK(std::string(dual_stack_mode_name(DualStackMode::IPv4Only)) == "ipv4-only");
    CHECK(std::string(dual_stack_mode_name(DualStackMode::IPv6Only)) == "ipv6-only");
    CHECK(std::string(dual_stack_mode_name(DualStackMode::DualStack)) == "dual-stack");
    CHECK(std::string(dual_stack_mode_name(DualStackMode::NAT64)) == "nat64");
    CHECK(std::string(dual_stack_mode_name(DualStackMode::DNS64)) == "dns64");
    // P5-D-3 边界修复：新增 Disabled 模式
    CHECK(std::string(dual_stack_mode_name(DualStackMode::Disabled)) == "disabled");
}

// ============================================================================
// 8. 配置测试
// ============================================================================

void test_dual_stack_config_defaults() {
    std::cout << "[test] DualStackConfig defaults" << std::endl;

    DualStackConfig cfg;
    CHECK(cfg.enable_nat64 == true);
    CHECK(cfg.enable_6to4 == false);
    CHECK(cfg.enable_dns64 == false);
    CHECK(cfg.nat64_prefix.is_wkp());
    CHECK(cfg.happy_eyeballs_delay == std::chrono::milliseconds(250));
}

void test_dual_stack_config_custom() {
    std::cout << "[test] DualStackConfig custom" << std::endl;

    DualStackConfig cfg;
    cfg.enable_nat64 = false;
    cfg.enable_6to4 = true;
    cfg.enable_dns64 = true;
    cfg.nat64_prefix.bytes = {0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    cfg.happy_eyeballs_delay = std::chrono::milliseconds(100);

    CHECK(cfg.enable_nat64 == false);
    CHECK(cfg.enable_6to4 == true);
    CHECK(cfg.enable_dns64 == true);
    CHECK(!cfg.nat64_prefix.is_wkp());
    CHECK(cfg.happy_eyeballs_delay == std::chrono::milliseconds(100));
}

// ============================================================================
// 9. 边界情况测试
// ============================================================================

void test_edge_cases() {
    std::cout << "[test] edge cases" << std::endl;

    // 0.0.0.0
    auto r1 = synthesize_nat64_address("0.0.0.0");
    CHECK(r1.has_value());
    CHECK(*r1 == "64:ff9b::");  // 后 32 位为 0

    // 255.255.255.255
    auto r2 = synthesize_nat64_address("255.255.255.255");
    CHECK(r2.has_value());
    auto e2 = extract_ipv4_from_nat64(*r2);
    CHECK(e2.has_value());
    CHECK(*e2 == "255.255.255.255");

    // 0.0.0.0 的 6to4
    auto r3 = synthesize_6to4_address("0.0.0.0");
    CHECK(r3.has_value());
    CHECK(is_6to4_address(*r3));
    auto e3 = extract_ipv4_from_6to4(*r3);
    CHECK(e3.has_value());
    CHECK(*e3 == "0.0.0.0");

    // 255.255.255.255 的 6to4
    auto r4 = synthesize_6to4_address("255.255.255.255");
    CHECK(r4.has_value());
    CHECK(is_6to4_address(*r4));

    // 空地址列表
    LocalStackCapability cap;
    cap.supports_ipv4 = true;
    DualStackConnector c;
    std::vector<std::string> empty;
    CHECK(!c.select_best_address(empty, cap).has_value());

    // 全部为无效地址
    std::vector<std::string> invalid = {"not_an_ip", "abc", ""};
    CHECK(!c.select_best_address(invalid, cap).has_value());
}

// ============================================================================
// 10. 综合 round-trip 测试
// ============================================================================

void test_nat64_round_trip_many() {
    std::cout << "[test] NAT64 round-trip many addresses" << std::endl;

    std::vector<std::string> addrs = {
        "1.1.1.1", "8.8.8.8", "8.8.4.4",
        "192.168.0.1", "10.0.0.1", "172.16.0.1",
        "223.255.255.255", "0.0.0.0", "127.0.0.1"
    };

    for (const auto &a : addrs) {
        auto synth = synthesize_nat64_address(a);
        CHECK(synth.has_value());
        auto extract = extract_ipv4_from_nat64(*synth);
        CHECK(extract.has_value());
        CHECK(*extract == a);
    }
}

void test_6to4_round_trip_many() {
    std::cout << "[test] 6to4 round-trip many addresses" << std::endl;

    std::vector<std::string> addrs = {
        "1.1.1.1", "8.8.8.8", "192.0.2.4",
        "172.16.254.1", "10.0.0.1"
    };

    for (const auto &a : addrs) {
        auto synth = synthesize_6to4_address(a);
        CHECK(synth.has_value());
        CHECK(is_6to4_address(*synth));
        auto extract = extract_ipv4_from_6to4(*synth);
        CHECK(extract.has_value());
        CHECK(*extract == a);
    }
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << " test_dual_stack (P5-D-4)" << std::endl;
    std::cout << "========================================" << std::endl;

    // 1. 地址族工具
    test_address_family_detection();
    test_parse_ipv4();
    test_format_ipv4();
    test_parse_ipv6_basic();
    test_parse_ipv6_invalid();
    test_format_ipv6();

    // 2. NAT64
    test_nat64_wkp_synthesize();
    test_nat64_extract();
    test_nat64_invalid_input();
    test_nat64_prefix_struct();

    // 3. 6to4
    test_6to4_synthesize();
    test_6to4_detection();
    test_6to4_extract();
    test_6to4_invalid_input();

    // 4. LocalStackCapability
    test_local_stack_infer_mode();
    test_local_stack_to_string();

    // 5. DualStackConnector
    test_connector_default_construct();
    test_connector_injected_detector();
    test_connector_translate_no_change();
    test_connector_translate_nat64();
    test_connector_translate_nat64_disabled();
    test_connector_translate_6to4();
    test_connector_translate_6to4_disabled();
    test_connector_translate_6to4_non_6to4_addr();
    test_connector_select_best_dualstack();
    test_connector_select_best_v4_only_local();
    test_connector_select_best_v6_only_local();
    test_connector_select_best_nat64();
    test_connector_select_best_6to4();
    test_connector_select_best_no_candidates();
    test_connector_select_best_no_compatible();
    test_connector_select_best_v4_local_no_v6_remote();

    // 6. 工具函数
    test_filter_functions();
    test_has_functions();

    // 7. 枚举
    test_dual_stack_mode_name();

    // 8. 配置
    test_dual_stack_config_defaults();
    test_dual_stack_config_custom();

    // 9. 边界情况
    test_edge_cases();

    // 10. 综合 round-trip
    test_nat64_round_trip_many();
    test_6to4_round_trip_many();

    std::cout << "========================================" << std::endl;
    std::cout << " Total: " << total << ", Failed: " << failed << std::endl;
    std::cout << "========================================" << std::endl;

    return failed == 0 ? 0 : 1;
}
