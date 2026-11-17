// test_empty_alpn_guard.cpp — v1.7.0.5 P4 (C3) Empty ALPN 连接防御测试
//
// 借鉴 iroh #4427 (v1.0.3): 连接入口拒绝空 ALPN
//
// 测试策略：
//   - C-API linoh_endpoint_connect_with_alpn 传入空字符串 alpn="" 时
//     若 ep->alpn 也为空则拒绝（但 ep->alpn 在 create 时强制非空，故回退到 ep->alpn）
//   - 直接测试 Endpoint::connect 需要 io_context + socket，较重
//   - 这里采用 C-API 路径，验证：
//       1. alpn="" 且 ep->alpn 非空 → 回退到 ep->alpn，连接建立（非空 ALPN 路径）
//       2. alpn="ctrl/1" → 正常使用传入 alpn
//       3. alpn=nullptr → 回退到 ep->alpn（向后兼容）
//
// 注：无法在单元测试中构造"ep->alpn 为空"的场景（linoh_endpoint_create 拒绝），
//     所以 C3 的 C-API 防御分支（ep->alpn 也为空）在正常流程下不可达，
//     属于防御性编程。测试主要验证正常路径不受影响。

#include "linoh/linoh_c.h"

#include <cstdio>
#include <cstring>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 测试 1: linoh_endpoint_create 要求非空 alpn
// ============================================================================

static void test_create_requires_alpn() {
    std::printf("[test] create requires alpn...\n");

    linoh_endpoint_config_t cfg{};
    cfg.alpn = "";  // 空 alpn
    cfg.udp_port = 0;  // 随机端口

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    CHECK(ep == nullptr);  // 应被拒绝
    if (ep) linoh_endpoint_free(ep);
}

// ============================================================================
// 测试 2: 有效 alpn 创建 endpoint 成功
// ============================================================================

static void test_create_with_valid_alpn() {
    std::printf("[test] create with valid alpn...\n");

    linoh_endpoint_config_t cfg{};
    cfg.alpn = "ctrl/1";
    cfg.udp_port = 0;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    CHECK(ep != nullptr);
    if (ep) linoh_endpoint_free(ep);
}

// ============================================================================
// 测试 3: connect_with_alpn 传入非空 alpn 正常工作
// ============================================================================

static void test_connect_with_nonempty_alpn() {
    std::printf("[test] connect with nonempty alpn...\n");

    linoh_endpoint_config_t cfg{};
    cfg.alpn = "ctrl/1";
    cfg.udp_port = 0;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    if (!ep) {
        ++g_fail;
        std::printf("FAIL: endpoint create failed (line %d)\n", __LINE__);
        return;
    }

    linoh_connection_t *conn = linoh_endpoint_connect_with_alpn(
        ep, "127.0.0.1", 1, "pp-hidden/1");
    CHECK(conn != nullptr);

    linoh_endpoint_free(ep);
}

// ============================================================================
// 测试 4: connect_with_alpn 传入 nullptr alpn 回退到 ep->alpn
// ============================================================================

static void test_connect_with_null_alpn_fallback() {
    std::printf("[test] connect with null alpn fallback...\n");

    linoh_endpoint_config_t cfg{};
    cfg.alpn = "ctrl/1";
    cfg.udp_port = 0;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    if (!ep) {
        ++g_fail;
        std::printf("FAIL: endpoint create failed (line %d)\n", __LINE__);
        return;
    }

    linoh_connection_t *conn = linoh_endpoint_connect_with_alpn(
        ep, "127.0.0.1", 1, nullptr);
    CHECK(conn != nullptr);

    linoh_endpoint_free(ep);
}

// ============================================================================
// 测试 5: connect_with_alpn 传入空字符串 alpn 回退到 ep->alpn
// ============================================================================

static void test_connect_with_empty_string_alpn_fallback() {
    std::printf("[test] connect with empty string alpn fallback...\n");

    linoh_endpoint_config_t cfg{};
    cfg.alpn = "ctrl/1";
    cfg.udp_port = 0;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    if (!ep) {
        ++g_fail;
        std::printf("FAIL: endpoint create failed (line %d)\n", __LINE__);
        return;
    }

    linoh_connection_t *conn = linoh_endpoint_connect_with_alpn(
        ep, "127.0.0.1", 1, "");
    CHECK(conn != nullptr);

    linoh_endpoint_free(ep);
}

// ============================================================================
// 测试 6: connect (无 alpn 参数版本) 回退到 ep->alpn
// ============================================================================

static void test_connect_no_alpn_arg() {
    std::printf("[test] connect no alpn arg...\n");

    linoh_endpoint_config_t cfg{};
    cfg.alpn = "ctrl/1";
    cfg.udp_port = 0;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    if (!ep) {
        ++g_fail;
        std::printf("FAIL: endpoint create failed (line %d)\n", __LINE__);
        return;
    }

    linoh_connection_t *conn = linoh_endpoint_connect(ep, "127.0.0.1", 1);
    CHECK(conn != nullptr);

    linoh_endpoint_free(ep);
}

// ============================================================================
// 测试 7: connect 无效 host 返回 nullptr
// ============================================================================

static void test_connect_invalid_host() {
    std::printf("[test] connect invalid host...\n");

    linoh_endpoint_config_t cfg{};
    cfg.alpn = "ctrl/1";
    cfg.udp_port = 0;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    if (!ep) {
        ++g_fail;
        std::printf("FAIL: endpoint create failed (line %d)\n", __LINE__);
        return;
    }

    linoh_connection_t *conn = linoh_endpoint_connect_with_alpn(
        ep, "not.an.ip.address", 1, "ctrl/1");
    CHECK(conn == nullptr);

    linoh_endpoint_free(ep);
}

// ============================================================================
// 测试 8: connect null endpoint 返回 nullptr
// ============================================================================

static void test_connect_null_endpoint() {
    std::printf("[test] connect null endpoint...\n");

    linoh_connection_t *conn = linoh_endpoint_connect_with_alpn(
        nullptr, "127.0.0.1", 1, "ctrl/1");
    CHECK(conn == nullptr);
}

// ============================================================================
// 测试 9: connect null host 返回 nullptr
// ============================================================================

static void test_connect_null_host() {
    std::printf("[test] connect null host...\n");

    linoh_endpoint_config_t cfg{};
    cfg.alpn = "ctrl/1";
    cfg.udp_port = 0;

    linoh_endpoint_t *ep = linoh_endpoint_create(&cfg);
    if (!ep) {
        ++g_fail;
        std::printf("FAIL: endpoint create failed (line %d)\n", __LINE__);
        return;
    }

    linoh_connection_t *conn = linoh_endpoint_connect_with_alpn(
        ep, nullptr, 1, "ctrl/1");
    CHECK(conn == nullptr);

    linoh_endpoint_free(ep);
}

int main() {
    std::printf("=== test_empty_alpn_guard (v1.7.0.5 P4 C3, iroh #4427) ===\n");

    test_create_requires_alpn();
    test_create_with_valid_alpn();
    test_connect_with_nonempty_alpn();
    test_connect_with_null_alpn_fallback();
    test_connect_with_empty_string_alpn_fallback();
    test_connect_no_alpn_arg();
    test_connect_invalid_host();
    test_connect_null_endpoint();
    test_connect_null_host();

    std::printf("\n=== Results: %d PASSED, %d FAILED ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
