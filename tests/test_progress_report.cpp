// test_progress_report.cpp — v4.3.0 M21 双层进度上报 payload 单元测试
//
// 测试覆盖：
//   默认构造 / wire_size / serialize+parse 往返 / serialize_into append
//   parse 数据不足 / parse name_len 越界 / percent 计算 / 零除保护
//   长 item_name / 超长截断 / operator== / ApplicationMessage 集成 / 常量

#include "linoh/protocol/progress_report.hpp"
#include "linoh/protocol/application_message.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <optional>
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

// ========== 默认构造 + 常量 ==========

// 1. 默认构造
static void test_default_construct() {
    std::printf("[test] default construct...\n");
    ProgressReportPayload p;
    CHECK_EQ(p.overall_current, 0u);
    CHECK_EQ(p.overall_total, 0u);
    CHECK(p.item_name.empty());
    CHECK_EQ(p.item_bytes_done, 0u);
    CHECK_EQ(p.item_bytes_total, 0u);
}

// 2. 常量值
static void test_constants() {
    std::printf("[test] constants...\n");
    CHECK_EQ(kProgressReportMaxItemNameLen, 512u);
    CHECK_EQ(kProgressReportMinWireSize, 26u);
}

// ========== wire_size ==========

// 3. wire_size 计算（空 item_name）
static void test_wire_size_empty_name() {
    std::printf("[test] wire_size empty name...\n");
    ProgressReportPayload p;
    CHECK_EQ(p.wire_size(), 26u);  // 4+4+2+0+8+8
}

// 4. wire_size 计算（有 item_name）
static void test_wire_size_with_name() {
    std::printf("[test] wire_size with name...\n");
    ProgressReportPayload p;
    p.item_name = "layer_0028.gguf";  // 15 bytes
    CHECK_EQ(p.wire_size(), 26u + 15u);  // 41
}

// ========== serialize + parse 往返 ==========

// 5. serialize/parse 往返（空 item_name）
static void test_roundtrip_empty_name() {
    std::printf("[test] roundtrip empty name...\n");
    ProgressReportPayload p;
    p.overall_current = 3;
    p.overall_total = 10;
    p.item_name = "";
    p.item_bytes_done = 0;
    p.item_bytes_total = 0;
    auto wire = p.serialize();
    CHECK_EQ(wire.size(), p.wire_size());
    auto parsed = ProgressReportPayload::parse(wire);
    CHECK(parsed.has_value());
    CHECK(parsed->operator==(p));
}

// 6. serialize/parse 往返（有 item_name）
static void test_roundtrip_with_name() {
    std::printf("[test] roundtrip with name...\n");
    ProgressReportPayload p;
    p.overall_current = 5;
    p.overall_total = 20;
    p.item_name = "layer_0028.gguf";
    p.item_bytes_done = 805306368;   // ~768MB
    p.item_bytes_total = 1610612736; // ~1.5GB
    auto wire = p.serialize();
    auto parsed = ProgressReportPayload::parse(wire);
    CHECK(parsed.has_value());
    CHECK(parsed->operator==(p));
}

// 7. serialize/parse 往返（大数值边界）
static void test_roundtrip_large_values() {
    std::printf("[test] roundtrip large values...\n");
    ProgressReportPayload p;
    p.overall_current = 0xFFFFFFFF;  // uint32 max
    p.overall_total = 0xFFFFFFFF;
    p.item_name = "big_tensor";
    p.item_bytes_done = 0xFFFFFFFFFFFFFFFFULL;  // uint64 max
    p.item_bytes_total = 0xFFFFFFFFFFFFFFFFULL;
    auto wire = p.serialize();
    auto parsed = ProgressReportPayload::parse(wire);
    CHECK(parsed.has_value());
    CHECK(parsed->operator==(p));
}

// ========== serialize_into ==========

// 8. serialize_into append 行为
static void test_serialize_into_append() {
    std::printf("[test] serialize_into append...\n");
    ProgressReportPayload p;
    p.overall_current = 1;
    p.overall_total = 5;
    p.item_name = "shard_3";
    p.item_bytes_done = 100;
    p.item_bytes_total = 1000;

    std::vector<std::uint8_t> existing = {0xAA, 0xBB, 0xCC};
    std::size_t written = p.serialize_into(existing);
    CHECK_EQ(written, p.wire_size());
    CHECK_EQ(existing.size(), 3u + p.wire_size());
    // 原有数据保留
    CHECK_EQ(existing[0], 0xAA);
    CHECK_EQ(existing[1], 0xBB);
    CHECK_EQ(existing[2], 0xCC);
    // 解析附加部分
    auto parsed = ProgressReportPayload::parse(
        std::span<const std::uint8_t>(existing.data() + 3, p.wire_size()));
    CHECK(parsed.has_value());
    CHECK(parsed->operator==(p));
}

// ========== parse 错误处理 ==========

// 9. parse 数据不足返回 nullopt
static void test_parse_short_data() {
    std::printf("[test] parse short data...\n");
    std::vector<std::uint8_t> short_data(25, 0);  // < 26B
    CHECK(!ProgressReportPayload::parse(short_data));
    CHECK(!ProgressReportPayload::parse({}));  // 空
}

// 10. parse name_len 超出数据返回 nullopt
static void test_parse_name_len_overflow() {
    std::printf("[test] parse name_len overflow...\n");
    // 构造 wire：overall(8B) + name_len=100(2B) + 仅 10B 数据（不够 100+16）
    std::vector<std::uint8_t> wire(20, 0);
    wire[8] = 100;  // name_len=100 (LE low byte)
    wire[9] = 0;    // name_len high byte
    CHECK(!ProgressReportPayload::parse(wire));
}

// 11. parse name_len 正好匹配数据
static void test_parse_name_len_exact() {
    std::printf("[test] parse name_len exact fit...\n");
    ProgressReportPayload p;
    p.overall_current = 1;
    p.overall_total = 2;
    p.item_name = "abc";  // 3 bytes
    p.item_bytes_done = 50;
    p.item_bytes_total = 100;
    auto wire = p.serialize();
    auto parsed = ProgressReportPayload::parse(wire);
    CHECK(parsed.has_value());
    CHECK(parsed->operator==(p));
}

// ========== percent 计算 ==========

// 12. overall_percent 计算
static void test_overall_percent() {
    std::printf("[test] overall_percent...\n");
    ProgressReportPayload p;
    p.overall_current = 3;
    p.overall_total = 10;
    CHECK(std::fabs(p.overall_percent() - 0.3) < 1e-9);
    p.overall_current = 10;
    p.overall_total = 10;
    CHECK(std::fabs(p.overall_percent() - 1.0) < 1e-9);
    p.overall_current = 0;
    p.overall_total = 10;
    CHECK(std::fabs(p.overall_percent() - 0.0) < 1e-9);
}

// 13. overall_total=0 时 overall_percent=0
static void test_overall_percent_zero_total() {
    std::printf("[test] overall_percent zero total...\n");
    ProgressReportPayload p;
    p.overall_current = 5;
    p.overall_total = 0;  // 未知
    CHECK(std::fabs(p.overall_percent() - 0.0) < 1e-9);
}

// 14. item_percent 计算
static void test_item_percent() {
    std::printf("[test] item_percent...\n");
    ProgressReportPayload p;
    p.item_bytes_done = 500;
    p.item_bytes_total = 1000;
    CHECK(std::fabs(p.item_percent() - 0.5) < 1e-9);
    p.item_bytes_done = 1000;
    p.item_bytes_total = 1000;
    CHECK(std::fabs(p.item_percent() - 1.0) < 1e-9);
}

// 15. item_bytes_total=0 时 item_percent=0
static void test_item_percent_zero_total() {
    std::printf("[test] item_percent zero total...\n");
    ProgressReportPayload p;
    p.item_bytes_done = 500;
    p.item_bytes_total = 0;  // 未知大小
    CHECK(std::fabs(p.item_percent() - 0.0) < 1e-9);
}

// ========== item_name 边界 ==========

// 16. 长 item_name（接近 512B 上限）
static void test_long_item_name() {
    std::printf("[test] long item name (512 bytes)...\n");
    ProgressReportPayload p;
    p.overall_current = 1;
    p.overall_total = 2;
    p.item_name = std::string(512, 'x');  // 正好 512B（v4.3.0 上限）
    p.item_bytes_done = 0;
    p.item_bytes_total = 100;
    auto wire = p.serialize();
    CHECK_EQ(wire.size(), 26u + 512u);  // 538
    auto parsed = ProgressReportPayload::parse(wire);
    CHECK(parsed.has_value());
    CHECK(parsed->operator==(p));
}

// 17. 超长 item_name 截断（serialize 时截断到 512）
static void test_oversized_item_name_truncated() {
    std::printf("[test] oversized item name truncated to 512...\n");
    ProgressReportPayload p;
    p.overall_current = 1;
    p.overall_total = 2;
    p.item_name = std::string(600, 'y');  // 600B，超过 512
    p.item_bytes_done = 0;
    p.item_bytes_total = 100;
    auto wire = p.serialize();
    // serialize 截断到 512B
    CHECK_EQ(wire.size(), 26u + 512u);  // 538，不是 26+600
    auto parsed = ProgressReportPayload::parse(wire);
    CHECK(parsed.has_value());
    CHECK_EQ(parsed->item_name.size(), 512u);
    // 解析出的 name 是截断后的前 512 个 'y'
    CHECK(parsed->item_name == std::string(512, 'y'));
    // 与原 payload 不相等（原 600B vs 截断 512B）
    CHECK(!parsed->operator==(p));
}

// ========== operator== ==========

// 18. operator== 相等
static void test_operator_eq() {
    std::printf("[test] operator== equal...\n");
    ProgressReportPayload a, b;
    a.overall_current = 5;
    a.overall_total = 10;
    a.item_name = "test";
    a.item_bytes_done = 100;
    a.item_bytes_total = 200;
    b = a;
    CHECK(a == b);
}

// 19. operator!= 不等
static void test_operator_neq() {
    std::printf("[test] operator!= not equal...\n");
    ProgressReportPayload a, b;
    a.overall_current = 5;
    b.overall_current = 6;
    CHECK(a != b);

    ProgressReportPayload c, d;
    c.item_name = "a";
    d.item_name = "b";
    CHECK(c != d);
}

// ========== ApplicationMessage 集成 ==========

// 20. ApplicationMessage Notification（MethodId::ProgressReport）
static void test_application_message_integration() {
    std::printf("[test] ApplicationMessage ProgressReport notification...\n");
    ProgressReportPayload p;
    p.overall_current = 7;
    p.overall_total = 48;  // 48 层模型
    p.item_name = "layer_0028.gguf";
    p.item_bytes_done = 805306368;
    p.item_bytes_total = 1610612736;

    auto payload_bytes = p.serialize();
    auto msg = ApplicationMessage::notification(
        MethodId::ProgressReport, payload_bytes);

    CHECK(msg.is_notification());
    CHECK(msg.method_id == MethodId::ProgressReport);
    CHECK_EQ(msg.request_id, 0u);  // Notification request_id=0

    // 序列化/解析 ApplicationMessage
    auto wire = msg.serialize();
    ApplicationMessage parsed_msg;
    std::size_t consumed = ApplicationMessage::parse(wire, parsed_msg);
    CHECK(consumed > 0);
    CHECK(parsed_msg.method_id == MethodId::ProgressReport);
    CHECK(parsed_msg.is_notification());

    // 从 ApplicationMessage payload 解析 ProgressReportPayload
    auto parsed_p = ProgressReportPayload::parse(
        std::span<const std::uint8_t>(parsed_msg.payload.data(),
                                        parsed_msg.payload.size()));
    CHECK(parsed_p.has_value());
    CHECK(parsed_p->operator==(p));
}

// 21. MethodId 枚举值校验
static void test_method_id_value() {
    std::printf("[test] MethodId::ProgressReport value...\n");
    CHECK_EQ(static_cast<std::uint16_t>(MethodId::ProgressReport), 0x0065u);
    // 与 AddrInfoAnnounce 不冲突
    CHECK(MethodId::ProgressReport != MethodId::AddrInfoAnnounce);
    CHECK(MethodId::ProgressReport != MethodId::CapabilitiesAck);
}

// ========== 综合场景 ==========

// 22. 综合：模型加载进度场景
static void test_e2e_model_load_progress() {
    std::printf("[test] E2E model load progress scenario...\n");
    // 模拟 win-worker 下载 48 个 shard，当前下载第 28 个
    ProgressReportPayload p;
    p.overall_current = 27;       // 已完成 27 个
    p.overall_total = 48;         // 总 48 个
    p.item_name = "layer_0028.gguf";
    p.item_bytes_done = 1207959552;   // 1.125 GB
    p.item_bytes_total = 1610612736;  // 1.5 GB

    // 进度计算
    CHECK(std::fabs(p.overall_percent() - (27.0 / 48.0)) < 1e-9);
    CHECK(std::fabs(p.item_percent() - (1207959552.0 / 1610612736.0)) < 1e-9);

    // 序列化 → ApplicationMessage → 解析 → 还原
    auto wire = p.serialize();
    auto msg = ApplicationMessage::notification(MethodId::ProgressReport, wire);
    auto msg_wire = msg.serialize();

    ApplicationMessage parsed_msg;
    ApplicationMessage::parse(msg_wire, parsed_msg);
    auto parsed_p = ProgressReportPayload::parse(
        std::span<const std::uint8_t>(parsed_msg.payload.data(),
                                        parsed_msg.payload.size()));
    CHECK(parsed_p.has_value());
    CHECK(parsed_p->operator==(p));
    CHECK_EQ(parsed_p->overall_current, 27u);
    CHECK_EQ(parsed_p->overall_total, 48u);
    CHECK(parsed_p->item_name == "layer_0028.gguf");
}

// 23. 综合：merged.gguf 合并进度场景
static void test_e2e_merge_progress() {
    std::printf("[test] E2E merged.gguf merge progress...\n");
    ProgressReportPayload p;
    p.overall_current = 15;
    p.overall_total = 48;
    p.item_name = "merging_layer_15";
    p.item_bytes_done = 0;         // 合并不跟踪字节
    p.item_bytes_total = 0;        // 未知

    CHECK(std::fabs(p.overall_percent() - (15.0 / 48.0)) < 1e-9);
    CHECK(std::fabs(p.item_percent() - 0.0) < 1e-9);  // bytes_total=0

    auto wire = p.serialize();
    auto parsed = ProgressReportPayload::parse(wire);
    CHECK(parsed.has_value());
    CHECK(parsed->operator==(p));
}

int main() {
    std::printf("=== test_progress_report ===\n\n");

    // 默认 + 常量
    test_default_construct();
    test_constants();

    // wire_size
    test_wire_size_empty_name();
    test_wire_size_with_name();

    // 往返
    test_roundtrip_empty_name();
    test_roundtrip_with_name();
    test_roundtrip_large_values();

    // serialize_into
    test_serialize_into_append();

    // parse 错误
    test_parse_short_data();
    test_parse_name_len_overflow();
    test_parse_name_len_exact();

    // percent
    test_overall_percent();
    test_overall_percent_zero_total();
    test_item_percent();
    test_item_percent_zero_total();

    // item_name 边界
    test_long_item_name();
    test_oversized_item_name_truncated();

    // operator
    test_operator_eq();
    test_operator_neq();

    // ApplicationMessage 集成
    test_application_message_integration();
    test_method_id_value();

    // 综合
    test_e2e_model_load_progress();
    test_e2e_merge_progress();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
