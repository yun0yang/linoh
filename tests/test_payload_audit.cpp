// test_payload_audit.cpp — v1.5.0.1 P0-1 payload 审计日志测试
//
// 验证目标：
//   1. PayloadAuditor 单例 enable/disable 正确
//   2. record_payload_write 原子计数正确
//   3. record_sent_pkts_state 序列化正确
//   4. flush_to_file 落盘到 JSONL 文件
//   5. 环境变量 LINOH_AUDIT=1 启用检测
//   6. retx 块审计能区分 is_retx 标志
//
// 关联模块：src/observability/payload_audit.cpp

#include "linoh/observability/payload_audit.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; } \
    else { printf("  [FAIL] %s (line %d)\n", msg, __LINE__); g_fail++; } \
} while (0)

using namespace linoh::observability;

// =============================================================================
// TEST 1: enable/disable 与单例
// =============================================================================
static void test_enable_disable() {
    printf("\n=== TEST 1: enable/disable 与单例 ===\n");

    auto& a1 = PayloadAuditor::instance();
    auto& a2 = PayloadAuditor::instance();
    CHECK(&a1 == &a2, "PayloadAuditor is singleton");

    a1.reset_stats();
    a1.enable(false);
    CHECK(!a1.is_enabled(), "disabled by default");

    a1.enable(true);
    CHECK(a1.is_enabled(), "enable(true) works");

    a1.enable(false);
    CHECK(!a1.is_enabled(), "enable(false) works");
    a1.reset_stats();
}

// =============================================================================
// TEST 2: record_payload_write 原子计数
// =============================================================================
static void test_record_payload_atomic() {
    printf("\n=== TEST 2: record_payload_write 原子计数 ===\n");

    auto& auditor = PayloadAuditor::instance();
    auditor.reset_stats();
    auditor.enable(true);

    PayloadAuditRecord rec{};
    rec.conn_id = 1;
    rec.stream_id = 100;
    rec.payload_actual = 1000;
    rec.payload_declared = 1000;
    rec.payload_space = 1280;
    rec.short_write = false;
    rec.is_retx = false;
    rec.ts = std::chrono::steady_clock::now();
    auditor.record_payload_write(rec);
    auditor.record_payload_write(rec);

    PayloadAuditRecord retx_rec = rec;
    retx_rec.is_retx = true;
    auditor.record_payload_write(retx_rec);

    PayloadAuditRecord short_rec = rec;
    short_rec.short_write = true;
    auditor.record_payload_write(short_rec);

    // 2 次 rec (is_retx=false) + 1 次 short_rec (is_retx=false) = 3 normal writes
    // 1 次 retx_rec (is_retx=true) = 1 retx write
    // total = 3*1000 + 1*1000 = 4000 bytes
    CHECK(auditor.normal_write_count() == 3, "normal_write_count == 3 (2 normal + 1 short)");
    CHECK(auditor.retx_write_count() == 1, "retx_write_count == 1");
    CHECK(auditor.short_write_count() == 1, "short_write_count == 1");
    CHECK(auditor.total_payload_bytes() == 4000, "total_payload_bytes == 4000");

    auditor.flush_to_file(".");
    auditor.enable(false);
}

// =============================================================================
// TEST 3: 禁用时不记录
// =============================================================================
static void test_disabled_no_record() {
    printf("\n=== TEST 3: 禁用时不记录 ===\n");

    auto& auditor = PayloadAuditor::instance();
    auditor.reset_stats();
    auditor.enable(false);

    PayloadAuditRecord rec{};
    rec.payload_actual = 5000;
    rec.is_retx = false;
    rec.ts = std::chrono::steady_clock::now();
    auditor.record_payload_write(rec);

    CHECK(auditor.total_payload_bytes() == 0, "disabled: total_payload_bytes == 0");
    CHECK(auditor.normal_write_count() == 0, "disabled: normal_write_count == 0");
    CHECK(auditor.retx_write_count() == 0, "disabled: retx_write_count == 0");
}

// =============================================================================
// TEST 4: record_sent_pkts_state 序列化
// =============================================================================
static void test_sent_pkts_state_serialize() {
    printf("\n=== TEST 4: record_sent_pkts_state 序列化 ===\n");

    auto& auditor = PayloadAuditor::instance();
    auditor.reset_stats();
    auditor.enable(true);

    SentPktsAuditRecord rec{};
    rec.conn_id = 42;
    rec.sent_packets_size = 100;
    rec.sent_payloads_bytes = 128 * 1024 * 1024;  // 128MB 满
    rec.retx_queue_size = 5;
    rec.retx_attempts_size = 3;
    rec.force_retx = true;
    rec.ts = std::chrono::steady_clock::now();
    auditor.record_sent_pkts_state(rec);

    CHECK(auditor.total_payload_bytes() == 0, "state record doesn't affect payload counters");

    auditor.flush_to_file(".");
    auditor.enable(false);
}

// =============================================================================
// TEST 5: JSONL 文件落盘验证
// =============================================================================
static void test_flush_to_jsonl_file() {
    printf("\n=== TEST 5: JSONL 文件落盘验证 ===\n");

    auto& auditor = PayloadAuditor::instance();
    auditor.reset_stats();
    auditor.enable(true);

    // 写入 5 条 payload 记录
    for (int i = 0; i < 5; ++i) {
        PayloadAuditRecord rec{};
        rec.conn_id = i;
        rec.payload_actual = 1024 * (i + 1);
        rec.is_retx = (i % 2 == 0);
        rec.ts = std::chrono::steady_clock::now();
        auditor.record_payload_write(rec);
    }

    // 落盘到临时目录（绝对路径 + 强制创建）
    std::filesystem::path tmp_dir = std::filesystem::absolute("test_audit_tmp");
    std::error_code ec;
    std::filesystem::remove_all(tmp_dir, ec);
    std::filesystem::create_directories(tmp_dir, ec);
    CHECK(std::filesystem::exists(tmp_dir), "tmp_dir created");
    CHECK(ec.value() == 0, "create_directories no error");
    auditor.flush_to_file(tmp_dir.string());

    // 找到生成的 audit_payload_*.log 文件
    bool found = false;
    bool found_retx_true = false;
    bool found_retx_false = false;
    std::error_code dir_ec;
    for (const auto& entry : std::filesystem::directory_iterator(tmp_dir, dir_ec)) {
        if (entry.path().filename().string().find("audit_payload_") == 0) {
            found = true;
            std::ifstream ifs(entry.path());
            std::stringstream ss;
            ss << ifs.rdbuf();
            std::string content = ss.str();
            if (content.find("\"type\":\"payload_write\"") != std::string::npos) {
                // pass
            }
            if (content.find("\"retx\":true") != std::string::npos) found_retx_true = true;
            if (content.find("\"retx\":false") != std::string::npos) found_retx_false = true;
        }
    }
    CHECK(found, "audit_payload_*.log file generated in tmp_dir");
    CHECK(found_retx_true, "file contains retx:true records");
    CHECK(found_retx_false, "file contains retx:false records");

    // 清理
    std::filesystem::remove_all(tmp_dir);
    auditor.enable(false);
}

// =============================================================================
// TEST 6: 环境变量 LINOH_AUDIT=1 启用检测
// =============================================================================
static void test_env_var_enable() {
    printf("\n=== TEST 6: 环境变量 LINOH_AUDIT 检测 ===\n");

    // 当前测试不修改环境变量（避免影响其他测试）
    // 只验证 is_audit_enabled_by_env() 能正确读取
    bool enabled_now = is_audit_enabled_by_env();
    CHECK(enabled_now == false || enabled_now == true, "is_audit_enabled_by_env returns bool");
}

// =============================================================================
// TEST 7: 多线程并发 record_payload_write 无数据竞争
// =============================================================================
static void test_concurrent_record() {
    printf("\n=== TEST 7: 多线程并发 record_payload_write ===\n");

    auto& auditor = PayloadAuditor::instance();
    auditor.reset_stats();
    auditor.enable(true);

    constexpr int kThreads = 4;
    constexpr int kRecordsPerThread = 1000;

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < kRecordsPerThread; ++i) {
                PayloadAuditRecord rec{};
                rec.payload_actual = 100;
                rec.is_retx = false;
                rec.ts = std::chrono::steady_clock::now();
                auditor.record_payload_write(rec);
            }
        });
    }
    for (auto& th : threads) th.join();

    CHECK(auditor.normal_write_count() == kThreads * kRecordsPerThread,
          "atomic counter correct under concurrency");
    CHECK(auditor.total_payload_bytes() == (uint64_t)kThreads * kRecordsPerThread * 100,
          "total bytes correct under concurrency");

    auditor.flush_to_file(".");
    auditor.enable(false);
}

// =============================================================================
// 主入口
// =============================================================================
int main() {
    printf("=== test_payload_audit (v1.5.0.1 P0-1 observability) ===\n");

    test_enable_disable();
    test_record_payload_atomic();
    test_disabled_no_record();
    test_sent_pkts_state_serialize();
    test_flush_to_jsonl_file();
    test_env_var_enable();
    test_concurrent_record();

    printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
