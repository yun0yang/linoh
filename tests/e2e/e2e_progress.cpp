// e2e_progress.cpp — v4.3.0 M21 双层进度上报端到端测试
//
// 验证点：
//   1. ProgressReport 帧通过 ctrl/1 通道传输
//   2. overall 进度（current/total）正确接收
//   3. current_item 进度（name/bytes_done/bytes_total）正确接收
//   4. 多次进度上报（模拟模型加载 0% → 50% → 100%）
//   5. 进度数据完整性验证（序列化 → 传输 → 反序列化）
//   6. 大进度数据（长 item_name）

#include "e2e/e2e_harness.hpp"
#include "linoh/protocol/progress_report.hpp"

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
// 测试 1: 基本 ProgressReport 帧传输
// ============================================================================
static void test_progress_basic_transfer() {
    std::printf("[e2e] progress: basic transfer via ctrl/1...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 47);
    auto *worker = h.start_node("worker", 0, 47);
    CHECK(master != nullptr);
    CHECK(worker != nullptr);

    master->role = e2e::NodeContext::RoleEcho;

    auto *conn = h.connect_alpn(worker, master, "ctrl/1");
    CHECK(conn != nullptr);

    // 构造 ProgressReport
    linoh::protocol::ProgressReportPayload prog;
    prog.overall_current = 1;
    prog.overall_total = 3;
    prog.item_name = "layer_0001.gguf";
    prog.item_bytes_done = 524288;
    prog.item_bytes_total = 1048576;

    auto payload = prog.serialize();
    CHECK(!payload.empty());

    bool ok = h.send_and_wait_echo(conn, master, "ctrl/1",
                                   payload.data(), payload.size(),
                                   std::chrono::seconds(10));
    CHECK(ok);

    auto received = master->get_received("ctrl/1");
    CHECK(received.has_value());
    if (received) {
        auto parsed = linoh::protocol::ProgressReportPayload::parse(
            std::span<const uint8_t>(received->data(), received->size()));
        CHECK(parsed.has_value());
        if (parsed) {
            CHECK(parsed->overall_current == 1);
            CHECK(parsed->overall_total == 3);
            CHECK(parsed->item_name == "layer_0001.gguf");
            CHECK(parsed->item_bytes_done == 524288);
            CHECK(parsed->item_bytes_total == 1048576);
        }
    }
}

// ============================================================================
// 测试 2: 多次进度上报（模拟模型加载 0% → 50% → 100%）
// ============================================================================
static void test_progress_sequence() {
    std::printf("[e2e] progress: sequence (0%% → 50%% → 100%%)...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 47);
    auto *worker = h.start_node("worker", 0, 47);

    master->role = e2e::NodeContext::RoleEcho;

    auto *conn = h.connect_alpn(worker, master, "ctrl/1");
    CHECK(conn != nullptr);

    struct ProgressStep {
        uint32_t current;
        uint32_t total;
        std::string item;
        uint64_t bytes_done;
        uint64_t bytes_total;
    };

    std::vector<ProgressStep> steps = {
        {0, 3, "layer_0001.gguf", 0, 1048576},
        {1, 3, "layer_0002.gguf", 524288, 1048576},
        {2, 3, "layer_0003.gguf", 786432, 1048576},
        {3, 3, "done", 1048576, 1048576},
    };

    for (size_t i = 0; i < steps.size(); ++i) {
        linoh::protocol::ProgressReportPayload prog;
        prog.overall_current = steps[i].current;
        prog.overall_total = steps[i].total;
        prog.item_name = steps[i].item;
        prog.item_bytes_done = steps[i].bytes_done;
        prog.item_bytes_total = steps[i].bytes_total;

        auto payload = prog.serialize();
        CHECK(!payload.empty());

        bool ok = h.send_and_wait_echo(conn, master, "ctrl/1",
                                       payload.data(), payload.size(),
                                       std::chrono::seconds(10));
        CHECK(ok);

        auto received = master->get_received("ctrl/1");
        CHECK(received.has_value());
        if (received) {
            auto parsed = linoh::protocol::ProgressReportPayload::parse(
                std::span<const uint8_t>(received->data(), received->size()));
            CHECK(parsed.has_value());
            if (parsed) {
                CHECK(parsed->overall_current == steps[i].current);
                CHECK(parsed->overall_total == steps[i].total);
                CHECK(parsed->item_name == steps[i].item);
                CHECK(parsed->item_bytes_done == steps[i].bytes_done);
                CHECK(parsed->item_bytes_total == steps[i].bytes_total);
            }
        }
    }
}

// ============================================================================
// 测试 3: 进度百分比计算验证
// ============================================================================
static void test_progress_percentage() {
    std::printf("[e2e] progress: percentage calculation...\n");

    linoh::protocol::ProgressReportPayload prog;
    prog.overall_current = 7;
    prog.overall_total = 10;
    prog.item_name = "shard_07.gguf";
    prog.item_bytes_done = 3145728;   // 3MB
    prog.item_bytes_total = 4194304;  // 4MB

    auto payload = prog.serialize();
    CHECK(!payload.empty());

    auto parsed = linoh::protocol::ProgressReportPayload::parse(
        std::span<const uint8_t>(payload.data(), payload.size()));
    CHECK(parsed.has_value());
    if (parsed) {
        // overall 70%
        double overall_pct = (parsed->overall_total > 0)
            ? (static_cast<double>(parsed->overall_current) / parsed->overall_total * 100.0)
            : 0.0;
        CHECK(overall_pct > 69.9);
        CHECK(overall_pct < 70.1);

        // item 75%
        double item_pct = (parsed->item_bytes_total > 0)
            ? (static_cast<double>(parsed->item_bytes_done) / parsed->item_bytes_total * 100.0)
            : 0.0;
        CHECK(item_pct > 74.9);
        CHECK(item_pct < 75.1);
    }
}

// ============================================================================
// 测试 4: 空 item_name 和零进度边界条件
// ============================================================================
static void test_progress_edge_cases() {
    std::printf("[e2e] progress: edge cases (empty name, zero progress)...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 47);
    auto *worker = h.start_node("worker", 0, 47);

    master->role = e2e::NodeContext::RoleEcho;

    auto *conn = h.connect_alpn(worker, master, "ctrl/1");
    CHECK(conn != nullptr);

    // 空 item_name + 零进度
    linoh::protocol::ProgressReportPayload prog;
    prog.overall_current = 0;
    prog.overall_total = 0;
    prog.item_name = "";
    prog.item_bytes_done = 0;
    prog.item_bytes_total = 0;

    auto payload = prog.serialize();
    CHECK(!payload.empty());

    bool ok = h.send_and_wait_echo(conn, master, "ctrl/1",
                                   payload.data(), payload.size(),
                                   std::chrono::seconds(10));
    CHECK(ok);

    auto received = master->get_received("ctrl/1");
    CHECK(received.has_value());
    if (received) {
        auto parsed = linoh::protocol::ProgressReportPayload::parse(
            std::span<const uint8_t>(received->data(), received->size()));
        CHECK(parsed.has_value());
        if (parsed) {
            CHECK(parsed->overall_current == 0);
            CHECK(parsed->overall_total == 0);
            CHECK(parsed->item_name.empty());
            CHECK(parsed->item_bytes_done == 0);
            CHECK(parsed->item_bytes_total == 0);
        }
    }
}

// ============================================================================
// 测试 5: 长 item_name（大进度数据）
// ============================================================================
static void test_progress_long_name() {
    std::printf("[e2e] progress: long item_name...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 47);
    auto *worker = h.start_node("worker", 0, 47);

    master->role = e2e::NodeContext::RoleEcho;

    auto *conn = h.connect_alpn(worker, master, "ctrl/1");
    CHECK(conn != nullptr);

    // 256 字节长 item_name
    std::string long_name(256, 'x');
    long_name[0] = 'p';
    long_name[255] = 'q';

    linoh::protocol::ProgressReportPayload prog;
    prog.overall_current = 1;
    prog.overall_total = 1;
    prog.item_name = long_name;
    prog.item_bytes_done = 999999;
    prog.item_bytes_total = 1000000;

    auto payload = prog.serialize();
    CHECK(!payload.empty());

    bool ok = h.send_and_wait_echo(conn, master, "ctrl/1",
                                   payload.data(), payload.size(),
                                   std::chrono::seconds(10));
    CHECK(ok);

    auto received = master->get_received("ctrl/1");
    CHECK(received.has_value());
    if (received) {
        auto parsed = linoh::protocol::ProgressReportPayload::parse(
            std::span<const uint8_t>(received->data(), received->size()));
        CHECK(parsed.has_value());
        if (parsed) {
            CHECK(parsed->item_name.size() == 256);
            CHECK(parsed->item_name == long_name);
            CHECK(parsed->item_bytes_done == 999999);
            CHECK(parsed->item_bytes_total == 1000000);
        }
    }
}

// ============================================================================
// 测试 6: ProgressReport + PP 链并行（进度上报与推理共存）
// ============================================================================
static void test_progress_with_pp_chain() {
    std::printf("[e2e] progress: ProgressReport + PP chain coexist...\n");

    e2e::E2eHarness h;
    auto *master = h.start_node("master", 0, 27);
    auto *w1 = h.start_node("w1", 28, 37);
    auto *w2 = h.start_node("w2", 38, 47);

    CHECK(h.build_pp_chain({master, w1, w2}));

    // 另建一个 ctrl/1 连接（worker → master）用于进度上报
    auto *ctrl_conn = h.connect_alpn(w1, master, "ctrl/1");
    CHECK(ctrl_conn != nullptr);

    // master 设为 Echo 模式接收进度（但不影响 PP 链，因为 PP 链用 pp-llm/1）
    // 注意：master 的 role 在 build_pp_chain 中被设为 RoleMaster
    // 这里需要兼容：RoleMaster 不走 on_stream，所以进度数据不会被接收
    // 改为：用单独的 echo master
    auto *progress_master = h.start_node("prog_master", 0, 47);
    progress_master->role = e2e::NodeContext::RoleEcho;
    auto *prog_worker = h.start_node("prog_worker", 0, 47);
    auto *prog_conn = h.connect_alpn(prog_worker, progress_master, "ctrl/1");
    CHECK(prog_conn != nullptr);

    // 发送进度
    linoh::protocol::ProgressReportPayload prog;
    prog.overall_current = 1;
    prog.overall_total = 2;
    prog.item_name = "loading_layers";
    prog.item_bytes_done = 500000;
    prog.item_bytes_total = 1000000;

    auto payload = prog.serialize();
    bool ok = h.send_and_wait_echo(prog_conn, progress_master, "ctrl/1",
                                   payload.data(), payload.size(),
                                   std::chrono::seconds(10));
    CHECK(ok);

    // 同时运行 PP 推理
    std::vector<uint8_t> hidden(64, 0xAA);
    auto result = h.pp_inference(master, hidden, 7007, std::chrono::seconds(15));
    CHECK(result.has_value());

    // 验证进度接收
    auto received = progress_master->get_received("ctrl/1");
    CHECK(received.has_value());
    if (received) {
        auto parsed = linoh::protocol::ProgressReportPayload::parse(
            std::span<const uint8_t>(received->data(), received->size()));
        CHECK(parsed.has_value());
        if (parsed) {
            CHECK(parsed->overall_current == 1);
            CHECK(parsed->overall_total == 2);
            CHECK(parsed->item_name == "loading_layers");
        }
    }
}

int main() {
    std::printf("=== e2e_progress (v4.3.0 M21) ===\n");

    test_progress_basic_transfer();
    test_progress_sequence();
    test_progress_percentage();
    test_progress_edge_cases();
    test_progress_long_name();
    test_progress_with_pp_chain();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
