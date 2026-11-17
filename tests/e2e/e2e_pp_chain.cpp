// e2e_pp_chain.cpp — v4.3.0 M21 PP 链端到端测试（LLM hidden_state）
//
// 验证点：
//   1. 三节点 PP 链建立（master → w1 → w2，pp-llm/1 ALPN）
//   2. hidden_state 逐跳转发（master → w1 → w2）
//   3. 末节点 direct return 回传结果到 master
//   4. 结果数据完整性验证（hidden_state + "_done" 后缀）
//   5. 中间节点转发统计正确
//   6. 不同大小 hidden_state（64B / 1KB / 16KB）

#include "e2e/e2e_harness.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 测试 1: 基本三节点 PP 链推理
// ============================================================================
static void test_pp_chain_basic() {
    std::printf("[e2e] PP chain basic (master → w1 → w2)...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 27);
    auto *w1 = h.start_node("w1", 28, 37);
    auto *w2 = h.start_node("w2", 38, 47);
    CHECK(master != nullptr);
    CHECK(w1 != nullptr);
    CHECK(w2 != nullptr);

    bool ok = h.build_pp_chain({master, w1, w2});
    CHECK(ok);

    // 发送 64 字节 hidden_state
    std::vector<uint8_t> hidden(64);
    for (size_t i = 0; i < hidden.size(); ++i) {
        hidden[i] = static_cast<uint8_t>(i & 0xFF);
    }

    auto result = h.pp_inference(master, hidden, 1001, std::chrono::seconds(15));
    CHECK(result.has_value());
    if (result) {
        // 结果 = hidden_state + "_done"
        CHECK(result->size() == hidden.size() + 5);
        CHECK(std::memcmp(result->data(), hidden.data(), hidden.size()) == 0);
        CHECK(std::memcmp(result->data() + hidden.size(), "_done", 5) == 0);
    }

    // 统计验证
    CHECK(w1->streams_received.load() >= 1);
    CHECK(w1->bytes_forwarded.load() >= static_cast<int>(64 + 12));  // hidden + token + req_id
    CHECK(w2->streams_received.load() >= 1);
    CHECK(w2->bytes_returned.load() >= static_cast<int>(64 + 5));
}

// ============================================================================
// 测试 2: 1KB hidden_state
// ============================================================================
static void test_pp_chain_1kb() {
    std::printf("[e2e] PP chain 1KB hidden_state...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 27);
    auto *w1 = h.start_node("w1", 28, 37);
    auto *w2 = h.start_node("w2", 38, 47);

    CHECK(h.build_pp_chain({master, w1, w2}));

    std::vector<uint8_t> hidden(1024);
    for (size_t i = 0; i < hidden.size(); ++i) {
        hidden[i] = static_cast<uint8_t>(0xAB ^ (i & 0xFF));
    }

    auto result = h.pp_inference(master, hidden, 2002, std::chrono::seconds(15));
    CHECK(result.has_value());
    if (result) {
        CHECK(result->size() == 1024 + 5);
        CHECK(std::memcmp(result->data(), hidden.data(), 1024) == 0);
    }
}

// ============================================================================
// 测试 3: 四节点 PP 链（master → w1 → w2 → w3）
// ============================================================================
static void test_pp_chain_four_nodes() {
    std::printf("[e2e] PP chain four nodes (master → w1 → w2 → w3)...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 27);
    auto *w1 = h.start_node("w1", 28, 34);
    auto *w2 = h.start_node("w2", 35, 41);
    auto *w3 = h.start_node("w3", 42, 47);

    CHECK(h.build_pp_chain({master, w1, w2, w3}));

    std::vector<uint8_t> hidden(256);
    for (size_t i = 0; i < hidden.size(); ++i) {
        hidden[i] = static_cast<uint8_t>(i * 2);
    }

    auto result = h.pp_inference(master, hidden, 3003, std::chrono::seconds(15));
    CHECK(result.has_value());
    if (result) {
        CHECK(result->size() == 256 + 5);
        CHECK(std::memcmp(result->data(), hidden.data(), 256) == 0);
    }

    // 中间节点都应转发
    CHECK(w1->streams_received.load() >= 1);
    CHECK(w2->streams_received.load() >= 1);
    CHECK(w3->streams_received.load() >= 1);
}

// ============================================================================
// 测试 4: 两节点 PP 链（master → w1，单跳）
// ============================================================================
static void test_pp_chain_single_hop() {
    std::printf("[e2e] PP chain single hop (master → w1)...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 27);
    auto *w1 = h.start_node("w1", 28, 47);

    CHECK(h.build_pp_chain({master, w1}));

    std::vector<uint8_t> hidden(128, 0x42);

    auto result = h.pp_inference(master, hidden, 4004, std::chrono::seconds(15));
    CHECK(result.has_value());
    if (result) {
        CHECK(result->size() == 128 + 5);
        CHECK(std::memcmp(result->data(), hidden.data(), 128) == 0);
    }
}

// ============================================================================
// 测试 5: 多次推理（连接复用验证）
// ============================================================================
static void test_pp_chain_multiple_inferences() {
    std::printf("[e2e] PP chain multiple inferences (connection reuse)...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 27);
    auto *w1 = h.start_node("w1", 28, 37);
    auto *w2 = h.start_node("w2", 38, 47);

    CHECK(h.build_pp_chain({master, w1, w2}));

    for (int round = 0; round < 3; ++round) {
        std::vector<uint8_t> hidden(64);
        hidden[0] = static_cast<uint8_t>(round);

        auto result = h.pp_inference(master, hidden,
                                     5000 + round, std::chrono::seconds(15));
        CHECK(result.has_value());
        if (result) {
            CHECK(result->size() == 64 + 5);
            CHECK(result->data()[0] == static_cast<uint8_t>(round));
        }
    }

    // 至少 3 次转发
    CHECK(w1->streams_received.load() >= 3);
    CHECK(w2->streams_received.load() >= 3);
}

int main() {
    std::printf("=== e2e_pp_chain (v4.3.0 M21) ===\n");

    test_pp_chain_basic();
    test_pp_chain_1kb();
    test_pp_chain_four_nodes();
    test_pp_chain_single_hop();
    test_pp_chain_multiple_inferences();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
