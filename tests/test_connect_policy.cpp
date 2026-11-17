// test_connect_policy.cpp — v4.0.1 M19 连接策略直连优先单元测试
//
// 测试覆盖：
//   1. ConnectDecision 枚举值校验 + to_string
//   2. ConnectPolicy 默认值 + 常量校验
//   3. default_relaxed 工厂方法
//   4. strict_direct 工厂方法
//   5. control_channel 工厂方法
//   6. for_alpn 工厂方法（pp-hidden/1 → strict_direct）
//   7. for_alpn 工厂方法（ctrl/1 → control_channel）
//   8. for_alpn 工厂方法（其他模态 → default_relaxed）
//   9. decide 高置信度 → DirectOnly
//  10. decide 中置信度（非强制直连）→ DirectWithRelay
//  11. decide 低置信度（非强制直连）→ RelayOnly
//  12. decide 强制直连 + 高置信度 → DirectOnly
//  13. decide 强制直连 + 中置信度 → DirectOnly
//  14. decide 强制直连 + 低置信度 + relay_fallback → RelayOnly
//  15. decide 强制直连 + 低置信度 + 无 relay_fallback → DirectOnly（宁可失败）
//  16. decide 置信度夹紧（>1.0 / <0.0）
//  17. decide 边界值（恰好 0.7 / 0.3）
//  18. encode 字节布局（默认宽松策略）
//  19. encode 字节布局（强制直连 + ALPN）
//  20. encode/decode 往返（default_relaxed）
//  21. encode/decode 往返（strict_direct with alpn）
//  22. encode/decode 往返（control_channel）
//  23. decode 数据不足返回 false
//  24. decode 版本不匹配返回 false
//  25. decode flags 保留位忽略
//  26. decode alpn 长度越界返回 false
//  27. to_string 输出格式
//  28. operator== 相等比较
//  29. cgn_confidence_threshold 序列化往返
//  30. 长_ALPN（接近 255）往返

#include "linoh/protocol/connect_policy.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    if ((a) == (b)) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s != %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ========== 测试用例 ==========

// 1. ConnectDecision 枚举值 + to_string
static void test_connect_decision_enum() {
    std::printf("[test] ConnectDecision enum + to_string...\n");
    CHECK_EQ(static_cast<std::uint8_t>(ConnectDecision::DirectOnly),      0u);
    CHECK_EQ(static_cast<std::uint8_t>(ConnectDecision::DirectWithRelay), 1u);
    CHECK_EQ(static_cast<std::uint8_t>(ConnectDecision::RelayOnly),       2u);

    CHECK(std::strcmp(to_string(ConnectDecision::DirectOnly), "DirectOnly") == 0);
    CHECK(std::strcmp(to_string(ConnectDecision::DirectWithRelay), "DirectWithRelay") == 0);
    CHECK(std::strcmp(to_string(ConnectDecision::RelayOnly), "RelayOnly") == 0);
}

// 2. ConnectPolicy 默认值 + 常量
static void test_connect_policy_defaults() {
    std::printf("[test] ConnectPolicy defaults + constants...\n");
    ConnectPolicy p;
    CHECK(!p.require_direct);                         // 默认 false
    CHECK_EQ(p.direct_timeout_ms, 5000u);             // 默认 5000ms
    CHECK(p.relay_fallback);                          // 默认 true
    CHECK_EQ(p.alpn.size(), 0u);                      // 默认空
    CHECK_EQ(p.cgn_confidence_threshold, ConnectPolicy::kLowConfidenceThreshold);

    // 常量校验
    CHECK_EQ(ConnectPolicy::kCurrentVersion, 1u);
    CHECK_EQ(ConnectPolicy::kMinEncodedSize, 9u);
    CHECK_EQ(ConnectPolicy::kMaxAlpnLen, 255u);
    CHECK_EQ(ConnectPolicy::kHighConfidenceThreshold, 0.7);
    CHECK_EQ(ConnectPolicy::kLowConfidenceThreshold, 0.3);
}

// 3. default_relaxed 工厂方法
static void test_factory_default_relaxed() {
    std::printf("[test] default_relaxed factory...\n");
    auto p = ConnectPolicy::default_relaxed();
    CHECK(!p.require_direct);
    CHECK_EQ(p.direct_timeout_ms, 5000u);
    CHECK(p.relay_fallback);
    CHECK_EQ(p.alpn.size(), 0u);
    CHECK_EQ(p.cgn_confidence_threshold, 0.3);
}

// 4. strict_direct 工厂方法
static void test_factory_strict_direct() {
    std::printf("[test] strict_direct factory...\n");
    auto p = ConnectPolicy::strict_direct("pp-hidden/1");
    CHECK(p.require_direct);
    CHECK_EQ(p.direct_timeout_ms, 10000u);  // 关键数据：10s
    CHECK(!p.relay_fallback);               // 强制直连，无 Relay 兜底
    CHECK_EQ(p.alpn, std::string("pp-hidden/1"));
    CHECK_EQ(p.cgn_confidence_threshold, 0.3);
}

// 5. control_channel 工厂方法
static void test_factory_control_channel() {
    std::printf("[test] control_channel factory...\n");
    auto p = ConnectPolicy::control_channel();
    CHECK(!p.require_direct);
    CHECK_EQ(p.direct_timeout_ms, 3000u);   // 控制面：3s 快速
    CHECK(p.relay_fallback);                // 控制面必须可达
    CHECK_EQ(p.alpn, std::string("ctrl/1"));
}

// 6. for_alpn: pp-hidden/1 → strict_direct
static void test_for_alpn_hidden() {
    std::printf("[test] for_alpn(pp-hidden/1) → strict_direct...\n");
    auto p = ConnectPolicy::for_alpn("pp-hidden/1");
    CHECK(p.require_direct);
    CHECK_EQ(p.direct_timeout_ms, 10000u);
    CHECK(!p.relay_fallback);
    CHECK_EQ(p.alpn, std::string("pp-hidden/1"));

    // pp-llm/1 也应走 strict_direct（兼容别名）
    auto p2 = ConnectPolicy::for_alpn("pp-llm/1");
    CHECK(p2.require_direct);
    CHECK_EQ(p2.alpn, std::string("pp-llm/1"));
}

// 7. for_alpn: ctrl/1 → control_channel
static void test_for_alpn_ctrl() {
    std::printf("[test] for_alpn(ctrl/1) → control_channel...\n");
    auto p = ConnectPolicy::for_alpn("ctrl/1");
    CHECK(!p.require_direct);
    CHECK_EQ(p.direct_timeout_ms, 3000u);
    CHECK(p.relay_fallback);
    CHECK_EQ(p.alpn, std::string("ctrl/1"));
}

// 8. for_alpn: 其他模态 → default_relaxed
static void test_for_alpn_other() {
    std::printf("[test] for_alpn(other) → default_relaxed...\n");
    auto p = ConnectPolicy::for_alpn("pp-img/1");
    CHECK(!p.require_direct);
    CHECK_EQ(p.direct_timeout_ms, 5000u);
    CHECK(p.relay_fallback);
    CHECK_EQ(p.alpn, std::string("pp-img/1"));

    auto p2 = ConnectPolicy::for_alpn("pp-video/1");
    CHECK(!p2.require_direct);
    CHECK_EQ(p2.alpn, std::string("pp-video/1"));
}

// 9. decide 高置信度 → DirectOnly
static void test_decide_high_confidence() {
    std::printf("[test] decide high confidence → DirectOnly...\n");
    auto p = ConnectPolicy::default_relaxed();
    CHECK_EQ(p.decide(0.7), ConnectDecision::DirectOnly);
    CHECK_EQ(p.decide(0.85), ConnectDecision::DirectOnly);
    CHECK_EQ(p.decide(1.0), ConnectDecision::DirectOnly);
}

// 10. decide 中置信度（非强制直连）→ DirectWithRelay
static void test_decide_mid_confidence_relaxed() {
    std::printf("[test] decide mid confidence (relaxed) → DirectWithRelay...\n");
    auto p = ConnectPolicy::default_relaxed();
    CHECK_EQ(p.decide(0.3), ConnectDecision::DirectWithRelay);
    CHECK_EQ(p.decide(0.5), ConnectDecision::DirectWithRelay);
    CHECK_EQ(p.decide(0.69), ConnectDecision::DirectWithRelay);
}

// 11. decide 低置信度（非强制直连）→ RelayOnly
static void test_decide_low_confidence_relaxed() {
    std::printf("[test] decide low confidence (relaxed) → RelayOnly...\n");
    auto p = ConnectPolicy::default_relaxed();
    CHECK_EQ(p.decide(0.0), ConnectDecision::RelayOnly);
    CHECK_EQ(p.decide(0.1), ConnectDecision::RelayOnly);
    CHECK_EQ(p.decide(0.29), ConnectDecision::RelayOnly);
}

// 12. decide 强制直连 + 高置信度 → DirectOnly
static void test_decide_strict_high() {
    std::printf("[test] decide strict + high → DirectOnly...\n");
    auto p = ConnectPolicy::strict_direct("pp-hidden/1");
    CHECK_EQ(p.decide(0.7), ConnectDecision::DirectOnly);
    CHECK_EQ(p.decide(0.9), ConnectDecision::DirectOnly);
}

// 13. decide 强制直连 + 中置信度 → DirectOnly
static void test_decide_strict_mid() {
    std::printf("[test] decide strict + mid → DirectOnly...\n");
    auto p = ConnectPolicy::strict_direct("pp-hidden/1");
    CHECK_EQ(p.decide(0.3), ConnectDecision::DirectOnly);
    CHECK_EQ(p.decide(0.5), ConnectDecision::DirectOnly);
    CHECK_EQ(p.decide(0.69), ConnectDecision::DirectOnly);
}

// 14. decide 强制直连 + 低置信度 + relay_fallback → RelayOnly
static void test_decide_strict_low_with_fallback() {
    std::printf("[test] decide strict + low + fallback → RelayOnly...\n");
    // strict_direct 默认 relay_fallback=false，需要手动开启
    auto p = ConnectPolicy::strict_direct("pp-hidden/1");
    p.relay_fallback = true;
    CHECK_EQ(p.decide(0.0), ConnectDecision::RelayOnly);
    CHECK_EQ(p.decide(0.1), ConnectDecision::RelayOnly);
    CHECK_EQ(p.decide(0.29), ConnectDecision::RelayOnly);
}

// 15. decide 强制直连 + 低置信度 + 无 relay_fallback → DirectOnly
static void test_decide_strict_low_no_fallback() {
    std::printf("[test] decide strict + low + no fallback → DirectOnly...\n");
    auto p = ConnectPolicy::strict_direct("pp-hidden/1");
    // relay_fallback=false（strict_direct 默认）
    CHECK_EQ(p.decide(0.0), ConnectDecision::DirectOnly);
    CHECK_EQ(p.decide(0.1), ConnectDecision::DirectOnly);
    CHECK_EQ(p.decide(0.29), ConnectDecision::DirectOnly);
}

// 16. decide 置信度夹紧（>1.0 / <0.0）
static void test_decide_clamp() {
    std::printf("[test] decide clamp confidence...\n");
    auto p = ConnectPolicy::default_relaxed();
    CHECK_EQ(p.decide(-0.5), ConnectDecision::RelayOnly);    // 夹紧到 0.0
    CHECK_EQ(p.decide(2.0), ConnectDecision::DirectOnly);    // 夹紧到 1.0
    CHECK_EQ(p.decide(100.0), ConnectDecision::DirectOnly);
}

// 17. decide 边界值（恰好 0.7 / 0.3）
static void test_decide_boundary() {
    std::printf("[test] decide boundary values...\n");
    auto p = ConnectPolicy::default_relaxed();
    // 0.7 边界：≥0.7 → DirectOnly
    CHECK_EQ(p.decide(0.7), ConnectDecision::DirectOnly);
    // 0.3 边界：≥0.3 → DirectWithRelay
    CHECK_EQ(p.decide(0.3), ConnectDecision::DirectWithRelay);
    // 0.29 → RelayOnly
    CHECK_EQ(p.decide(0.29), ConnectDecision::RelayOnly);
}

// 18. encode 字节布局（默认宽松策略）
static void test_encode_layout_default() {
    std::printf("[test] encode layout (default_relaxed)...\n");
    auto p = ConnectPolicy::default_relaxed();
    auto buf = p.encode();

    // 最小长度：9 字节（alpn 为空）
    CHECK_EQ(buf.size(), ConnectPolicy::kMinEncodedSize);
    CHECK_EQ(buf.size(), 9u);

    // offset 0: version = 1
    CHECK_EQ(buf[0], 1u);

    // offset 1: flags = 0x02（require_direct=false, relay_fallback=true）
    CHECK_EQ(buf[1], 0x02);

    // offset 2-5: direct_timeout_ms = 5000 (小端序)
    CHECK_EQ(buf[2], static_cast<std::uint8_t>(5000 & 0xFF));        // 0x88
    CHECK_EQ(buf[3], static_cast<std::uint8_t>((5000 >> 8) & 0xFF)); // 0x13
    CHECK_EQ(buf[4], 0u);
    CHECK_EQ(buf[5], 0u);

    // offset 6: alpn_len = 0
    CHECK_EQ(buf[6], 0u);

    // offset 7-8: cgn_confidence_threshold_x100 = 30 (0.3 × 100)
    CHECK_EQ(buf[7], 30u);
    CHECK_EQ(buf[8], 0u);
}

// 19. encode 字节布局（强制直连 + ALPN）
static void test_encode_layout_strict() {
    std::printf("[test] encode layout (strict_direct)...\n");
    auto p = ConnectPolicy::strict_direct("pp-hidden/1");
    auto buf = p.encode();

    // 长度：9 + 11 (alpn 长度) = 20
    CHECK_EQ(buf.size(), 9u + 11u);

    // offset 0: version = 1
    CHECK_EQ(buf[0], 1u);

    // offset 1: flags = 0x01（require_direct=true, relay_fallback=false）
    CHECK_EQ(buf[1], 0x01);

    // offset 2-5: direct_timeout_ms = 10000 (小端序)
    CHECK_EQ(buf[2], static_cast<std::uint8_t>(10000 & 0xFF));        // 0x10
    CHECK_EQ(buf[3], static_cast<std::uint8_t>((10000 >> 8) & 0xFF)); // 0x27
    CHECK_EQ(buf[4], 0u);
    CHECK_EQ(buf[5], 0u);

    // offset 6: alpn_len = 11
    CHECK_EQ(buf[6], 11u);

    // offset 7-17: alpn = "pp-hidden/1"
    CHECK(std::memcmp(buf.data() + 7, "pp-hidden/1", 11) == 0);

    // offset 18-19: cgn_confidence_threshold_x100 = 30
    CHECK_EQ(buf[18], 30u);
    CHECK_EQ(buf[19], 0u);
}

// 20. encode/decode 往返（default_relaxed）
static void test_roundtrip_default() {
    std::printf("[test] roundtrip default_relaxed...\n");
    auto p = ConnectPolicy::default_relaxed();
    auto buf = p.encode();

    ConnectPolicy decoded;
    bool ok = ConnectPolicy::decode(buf, decoded);
    CHECK(ok);
    CHECK_EQ(decoded.require_direct, p.require_direct);
    CHECK_EQ(decoded.direct_timeout_ms, p.direct_timeout_ms);
    CHECK_EQ(decoded.relay_fallback, p.relay_fallback);
    CHECK_EQ(decoded.alpn, p.alpn);
    // 浮点阈值容差比较（×100 量化误差 ≤ 0.005）
    CHECK(decoded.cgn_confidence_threshold >= 0.29 && decoded.cgn_confidence_threshold <= 0.31);
}

// 21. encode/decode 往返（strict_direct with alpn）
static void test_roundtrip_strict() {
    std::printf("[test] roundtrip strict_direct with alpn...\n");
    auto p = ConnectPolicy::strict_direct("pp-hidden/1");
    auto buf = p.encode();

    ConnectPolicy decoded;
    bool ok = ConnectPolicy::decode(buf, decoded);
    CHECK(ok);
    CHECK_EQ(decoded.require_direct, true);
    CHECK_EQ(decoded.direct_timeout_ms, 10000u);
    CHECK_EQ(decoded.relay_fallback, false);
    CHECK_EQ(decoded.alpn, std::string("pp-hidden/1"));
}

// 22. encode/decode 往返（control_channel）
static void test_roundtrip_control() {
    std::printf("[test] roundtrip control_channel...\n");
    auto p = ConnectPolicy::control_channel();
    auto buf = p.encode();

    ConnectPolicy decoded;
    bool ok = ConnectPolicy::decode(buf, decoded);
    CHECK(ok);
    CHECK_EQ(decoded.require_direct, false);
    CHECK_EQ(decoded.direct_timeout_ms, 3000u);
    CHECK_EQ(decoded.relay_fallback, true);
    CHECK_EQ(decoded.alpn, std::string("ctrl/1"));
}

// 23. decode 数据不足返回 false
static void test_decode_short() {
    std::printf("[test] decode short buffer...\n");
    std::vector<std::uint8_t> short_buf(8, 0);  // 8 < 9
    ConnectPolicy decoded;
    CHECK(!ConnectPolicy::decode(short_buf, decoded));

    std::vector<std::uint8_t> empty;
    CHECK(!ConnectPolicy::decode(empty, decoded));

    // 刚好 9 字节（alpn_len=0）应成功
    auto p = ConnectPolicy::default_relaxed();
    auto buf = p.encode();
    CHECK_EQ(buf.size(), 9u);
    CHECK(ConnectPolicy::decode(buf, decoded));
}

// 24. decode 版本不匹配返回 false
static void test_decode_bad_version() {
    std::printf("[test] decode bad version...\n");
    auto p = ConnectPolicy::default_relaxed();
    auto buf = p.encode();
    buf[0] = 99;  // 非法 version
    ConnectPolicy decoded;
    CHECK(!ConnectPolicy::decode(buf, decoded));
}

// 25. decode flags 保留位忽略
static void test_decode_flags_reserved_ignored() {
    std::printf("[test] decode flags reserved bits ignored...\n");
    auto p = ConnectPolicy::default_relaxed();
    auto buf = p.encode();
    buf[1] |= 0xFC;  // 设置 bit2-7 保留位
    ConnectPolicy decoded;
    CHECK(ConnectPolicy::decode(buf, decoded));
    // require_direct=false, relay_fallback=true（保留位不影响）
    CHECK_EQ(decoded.require_direct, false);
    CHECK_EQ(decoded.relay_fallback, true);
}

// 26. decode alpn 长度越界返回 false
static void test_decode_alpn_out_of_range() {
    std::printf("[test] decode alpn length out of range...\n");
    auto p = ConnectPolicy::strict_direct("pp-hidden/1");
    auto buf = p.encode();
    // 篡改 alpn_len 为 255（实际数据不足）
    buf[6] = 255;
    ConnectPolicy decoded;
    CHECK(!ConnectPolicy::decode(buf, decoded));
}

// 27. to_string 输出格式
static void test_to_string() {
    std::printf("[test] to_string...\n");
    auto p = ConnectPolicy::strict_direct("pp-hidden/1");
    auto s = p.to_string();
    CHECK(s.find("ConnectPolicy") != std::string::npos);
    CHECK(s.find("require_direct=true") != std::string::npos);
    CHECK(s.find("direct_timeout_ms=10000") != std::string::npos);
    CHECK(s.find("relay_fallback=false") != std::string::npos);
    CHECK(s.find("pp-hidden/1") != std::string::npos);
}

// 28. operator== 相等比较
static void test_equality() {
    std::printf("[test] operator==...\n");
    auto p1 = ConnectPolicy::default_relaxed();
    auto p2 = ConnectPolicy::default_relaxed();
    CHECK(p1 == p2);

    auto p3 = ConnectPolicy::strict_direct("pp-hidden/1");
    CHECK(!(p1 == p3));

    auto p4 = ConnectPolicy::strict_direct("pp-hidden/1");
    CHECK(p3 == p4);

    // 修改一个字段后不相等
    p2.direct_timeout_ms = 9999;
    CHECK(!(p1 == p2));
}

// 29. cgn_confidence_threshold 序列化往返
static void test_threshold_roundtrip() {
    std::printf("[test] cgn_confidence_threshold roundtrip...\n");
    ConnectPolicy p = ConnectPolicy::default_relaxed();
    p.cgn_confidence_threshold = 0.5;
    auto buf = p.encode();

    ConnectPolicy decoded;
    CHECK(ConnectPolicy::decode(buf, decoded));
    // 0.5 × 100 = 50，量化无误差
    CHECK_EQ(decoded.cgn_confidence_threshold, 0.5);

    // 测试 0.0 和 1.0 边界
    p.cgn_confidence_threshold = 0.0;
    buf = p.encode();
    CHECK(ConnectPolicy::decode(buf, decoded));
    CHECK_EQ(decoded.cgn_confidence_threshold, 0.0);

    p.cgn_confidence_threshold = 1.0;
    buf = p.encode();
    CHECK(ConnectPolicy::decode(buf, decoded));
    CHECK_EQ(decoded.cgn_confidence_threshold, 1.0);
}

// 30. 长 ALPN（接近 255）往返
static void test_long_alpn_roundtrip() {
    std::printf("[test] long alpn (near 255) roundtrip...\n");
    ConnectPolicy p;
    p.require_direct = false;
    p.direct_timeout_ms = 5000;
    p.relay_fallback = true;
    p.alpn = std::string(250, 'x');  // 250 字节 ALPN
    p.cgn_confidence_threshold = 0.3;

    auto buf = p.encode();
    CHECK_EQ(buf.size(), 9u + 250u);

    ConnectPolicy decoded;
    CHECK(ConnectPolicy::decode(buf, decoded));
    CHECK_EQ(decoded.alpn.size(), 250u);
    CHECK_EQ(decoded.alpn, p.alpn);
}

// ========== main ==========

int main() {
    std::printf("=== test_connect_policy (v4.0.1 M19) ===\n");

    test_connect_decision_enum();
    test_connect_policy_defaults();
    test_factory_default_relaxed();
    test_factory_strict_direct();
    test_factory_control_channel();
    test_for_alpn_hidden();
    test_for_alpn_ctrl();
    test_for_alpn_other();
    test_decide_high_confidence();
    test_decide_mid_confidence_relaxed();
    test_decide_low_confidence_relaxed();
    test_decide_strict_high();
    test_decide_strict_mid();
    test_decide_strict_low_with_fallback();
    test_decide_strict_low_no_fallback();
    test_decide_clamp();
    test_decide_boundary();
    test_encode_layout_default();
    test_encode_layout_strict();
    test_roundtrip_default();
    test_roundtrip_strict();
    test_roundtrip_control();
    test_decode_short();
    test_decode_bad_version();
    test_decode_flags_reserved_ignored();
    test_decode_alpn_out_of_range();
    test_to_string();
    test_equality();
    test_threshold_roundtrip();
    test_long_alpn_roundtrip();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
