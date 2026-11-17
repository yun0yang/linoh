// test_static_shape_v1603.cpp — v1.6.0.3 (P2) 静态形状协商单元测试
//
// 测试覆盖：
//   1. ShapeDescriptor 默认值 + valid
//   2. padded_bytes 计算
//   3. serialize/parse 往返
//   4. negotiate 取双方 max
//   5. negotiate dtype 不一致失败
//   6. negotiate 无效描述符失败
//   7. padded_bytes 查询
//   8. reset 清除协商
//   9. fill_padding_zero 填充
//  10. 不同 dtype 字节数

#include "linoh/multimodal/static_shape.hpp"

#include <cstdio>
#include <cstring>

using namespace linoh::multimodal;
using namespace linoh::multimodal::ep;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ============================================================================
// TEST 1: ShapeDescriptor 默认值 + valid
// ============================================================================

static void test_shape_descriptor_default() {
    std::printf("[test] ShapeDescriptor default + valid...\n");
    ShapeDescriptor d;
    CHECK(!d.valid());  // 默认全 0，无效
    d.max_tokens = 1024;
    d.hidden_dim = 4096;
    CHECK(d.valid());
    d.expert_count = 8;
    CHECK(d.valid());
}

// ============================================================================
// TEST 2: padded_bytes 计算
// ============================================================================

static void test_padded_bytes() {
    std::printf("[test] padded_bytes calculation...\n");
    ShapeDescriptor d;
    d.dtype = TensorDType::F32;
    d.max_tokens = 1024;
    d.hidden_dim = 4096;
    d.expert_count = 1;
    // 1024 * 4096 * 4 = 16777216
    CHECK_EQ(d.padded_bytes(), static_cast<std::uint64_t>(16777216));

    ShapeDescriptor d2;
    d2.dtype = TensorDType::F16;
    d2.max_tokens = 100;
    d2.hidden_dim = 512;
    // 100 * 512 * 2 = 102400
    CHECK_EQ(d2.padded_bytes(), static_cast<std::uint64_t>(102400));
}

// ============================================================================
// TEST 3: serialize/parse 往返
// ============================================================================

static void test_serialize_parse() {
    std::printf("[test] serialize/parse round-trip...\n");
    ShapeDescriptor d;
    d.dtype = TensorDType::BF16;
    d.max_tokens = 2048;
    d.hidden_dim = 8192;
    d.expert_count = 4;

    auto buf = d.serialize();
    CHECK_EQ(buf.size(), static_cast<std::size_t>(13));

    ShapeDescriptor parsed;
    bool ok = ShapeDescriptor::parse(buf, parsed);
    CHECK(ok);
    CHECK(parsed.dtype == TensorDType::BF16);
    CHECK_EQ(parsed.max_tokens, static_cast<std::uint32_t>(2048));
    CHECK_EQ(parsed.hidden_dim, static_cast<std::uint32_t>(8192));
    CHECK_EQ(parsed.expert_count, static_cast<std::uint32_t>(4));
}

// ============================================================================
// TEST 4: negotiate 取双方 max
// ============================================================================

static void test_negotiate_max() {
    std::printf("[test] negotiate takes max...\n");
    TensorShapeNegotiator n;
    ShapeDescriptor local{TensorDType::F32, 1024, 4096, 1};
    ShapeDescriptor remote{TensorDType::F32, 2048, 2048, 8};
    bool ok = n.negotiate(local, remote);
    CHECK(ok);
    CHECK(n.is_negotiated());

    auto cur = n.current();
    CHECK(cur.has_value());
    CHECK_EQ(cur->max_tokens, static_cast<std::uint32_t>(2048));
    CHECK_EQ(cur->hidden_dim, static_cast<std::uint32_t>(4096));
    CHECK_EQ(cur->expert_count, static_cast<std::uint32_t>(8));
}

// ============================================================================
// TEST 5: negotiate dtype 不一致失败
// ============================================================================

static void test_negotiate_dtype_mismatch() {
    std::printf("[test] negotiate dtype mismatch fails...\n");
    TensorShapeNegotiator n;
    ShapeDescriptor local{TensorDType::F32, 1024, 4096, 1};
    ShapeDescriptor remote{TensorDType::F16, 2048, 2048, 8};
    bool ok = n.negotiate(local, remote);
    CHECK(!ok);
    CHECK(!n.is_negotiated());
    CHECK_EQ(n.padded_bytes(), static_cast<std::uint64_t>(0));
}

// ============================================================================
// TEST 6: negotiate 无效描述符
// ============================================================================

static void test_negotiate_invalid() {
    std::printf("[test] negotiate invalid descriptor...\n");
    TensorShapeNegotiator n;
    ShapeDescriptor local{TensorDType::F32, 0, 4096, 1};  // max_tokens=0 无效
    ShapeDescriptor remote{TensorDType::F32, 2048, 2048, 8};
    bool ok = n.negotiate(local, remote);
    CHECK(!ok);
}

// ============================================================================
// TEST 7: padded_bytes 查询
// ============================================================================

static void test_negotiated_padded_bytes() {
    std::printf("[test] negotiated padded_bytes...\n");
    TensorShapeNegotiator n;
    ShapeDescriptor local{TensorDType::F32, 1024, 4096, 1};
    ShapeDescriptor remote{TensorDType::F32, 2048, 4096, 1};
    n.negotiate(local, remote);
    // max = 2048 * 4096 * 4 = 33554432
    CHECK_EQ(n.padded_bytes(), static_cast<std::uint64_t>(33554432));
}

// ============================================================================
// TEST 8: reset
// ============================================================================

static void test_reset() {
    std::printf("[test] reset clears negotiation...\n");
    TensorShapeNegotiator n;
    ShapeDescriptor local{TensorDType::F32, 1024, 4096, 1};
    ShapeDescriptor remote{TensorDType::F32, 1024, 4096, 1};
    n.negotiate(local, remote);
    CHECK(n.is_negotiated());
    n.reset();
    CHECK(!n.is_negotiated());
    CHECK_EQ(n.padded_bytes(), static_cast<std::uint64_t>(0));
}

// ============================================================================
// TEST 9: fill_padding_zero
// ============================================================================

static void test_fill_padding_zero() {
    std::printf("[test] fill_padding_zero...\n");
    std::uint8_t buf[100];
    std::memset(buf, 0xFF, 100);
    TensorShapeNegotiator::fill_padding_zero(buf, 30, 100);
    // 前 30 字节保持 0xFF
    CHECK_EQ(buf[0], static_cast<int>(0xFF));
    CHECK_EQ(buf[29], static_cast<int>(0xFF));
    // 30-99 应该清零
    CHECK_EQ(buf[30], static_cast<int>(0));
    CHECK_EQ(buf[99], static_cast<int>(0));
}

// ============================================================================
// TEST 10: 不同 dtype 字节数
// ============================================================================

static void test_dtype_sizes() {
    std::printf("[test] dtype sizes...\n");
    ShapeDescriptor d;
    d.max_tokens = 100;
    d.hidden_dim = 100;
    d.dtype = TensorDType::F32;
    CHECK_EQ(d.padded_bytes(), static_cast<std::uint64_t>(40000));
    d.dtype = TensorDType::F16;
    CHECK_EQ(d.padded_bytes(), static_cast<std::uint64_t>(20000));
    d.dtype = TensorDType::I8;
    CHECK_EQ(d.padded_bytes(), static_cast<std::uint64_t>(10000));
    d.dtype = TensorDType::I64;
    CHECK_EQ(d.padded_bytes(), static_cast<std::uint64_t>(80000));
}

// ============================================================================
// TEST 11: parse 边界（数据不足）
// ============================================================================

static void test_parse_short() {
    std::printf("[test] parse short data...\n");
    std::uint8_t short_buf[10] = {0};
    ShapeDescriptor out;
    CHECK(!ShapeDescriptor::parse(short_buf, out));
}

// ============================================================================
// TEST 12: parse dtype 超出范围
// ============================================================================

static void test_parse_bad_dtype() {
    std::printf("[test] parse bad dtype...\n");
    std::uint8_t buf[13] = {};
    buf[0] = 200;  // 超出 TensorDType 枚举范围
    ShapeDescriptor out;
    CHECK(!ShapeDescriptor::parse(buf, out));
}

int main() {
    std::printf("=== test_static_shape_v1603 ===\n");
    test_shape_descriptor_default();
    test_padded_bytes();
    test_serialize_parse();
    test_negotiate_max();
    test_negotiate_dtype_mismatch();
    test_negotiate_invalid();
    test_negotiated_padded_bytes();
    test_reset();
    test_fill_padding_zero();
    test_dtype_sizes();
    test_parse_short();
    test_parse_bad_dtype();
    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
