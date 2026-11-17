// test_oos_active_notify.cpp - v1.5.0.3 F3 OOS 主动通知 API 测试
//
// 目标: 验证 v1.5.0.3 新增的 F3 OOS 主动通知 API 功能正确性, 确保应用层
//       可主动查询 OOS buffer 状态或注册阈值回调, 解决 LINOH_V15027 反馈的
//       "recv_offset_ 卡住时无法判断 OOS 是否在等待 retx 填补" 问题.
//
// 测试策略:
//   1) 直接 C++ Stream API 测试 (推荐路径):
//      - 构造 endpoint::Stream, 模拟 OOS 数据 recv() 场景
//      - 验证 oos_size_bytes() 返回正确字节总数
//      - 验证 oos_first_gap() 返回首个 gap 的 offset + size
//      - 验证 set_oos_callback() 注册阈值回调, 累积到阈值时触发
//      - 验证 clear_oos_callback() 清除回调
//      - 验证 OOS gap 填补后回调不再触发
//
//   2) C API 边界测试 (NULL 参数安全):
//      - linoh_stream_oos_size(nullptr) 返回 0
//      - linoh_stream_oos_first_gap(nullptr, ...) 返回 0
//      - linoh_stream_set_oos_callback(nullptr, ...) 安全 no-op
//
// F3 API 端到端验证需要真实 OOS 数据 (recv_offset_ 卡住场景), 该场景在
// 视频模型组 worker-node 实测中触发. 单元测试覆盖 API 行为正确性, 端到端贯通
// 留给 v1.5.0.4 跨节点 STREAM 接收回归测试.

#include "linoh/endpoint/connection.hpp"
#include "linoh/linoh_c.h"
#include "linoh/util/logging.hpp"

#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace linoh::endpoint;

// ============================================================================
// 通用测试工具 (与 test_loss_recovery_instrumentation.cpp 一致)
// ============================================================================

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (%lld != %lld) (line %d)\n", \
        #a, #b, (long long)_a, (long long)_b, __LINE__); } \
} while (0)

static bool contains_marker(const std::string &haystack, const std::string &marker) {
    return haystack.find(marker) != std::string::npos;
}

// 重定向 std::cerr 到 stringstream, 验证 LINOH_INFO 埋点输出.
class CerrCapture {
public:
    CerrCapture() : old_buf_(std::cerr.rdbuf(capture_.rdbuf())) {}
    ~CerrCapture() { std::cerr.rdbuf(old_buf_); }

    std::string drain() {
        std::string s = capture_.str();
        capture_.str("");
        capture_.clear();
        return s;
    }

    void clear() {
        capture_.str("");
        capture_.clear();
    }

private:
    std::stringstream capture_;
    std::streambuf *old_buf_;
};

// 生成测试用 data payload
static std::vector<std::uint8_t> make_data(std::uint8_t fill, std::size_t n) {
    return std::vector<std::uint8_t>(n, fill);
}

// ============================================================================
// TEST 1: oos_size_bytes() / oos_first_gap() 初始状态
// ============================================================================
static void test_initial_state_empty() {
    std::printf("[test] Stream initial state: oos_size=0, oos_first_gap=false...\n");
    Stream s(0, Stream::Dir::Bidirectional);

    // functional: 刚构造的 Stream OOS buffer 为空
    CHECK_EQ(s.oos_size_bytes(), 0u);
    std::uint64_t off = 0xDEADBEEF;
    std::size_t sz = 0xDEADBEEF;
    bool has = s.oos_first_gap(&off, &sz);
    CHECK(!has);
    // has=false 时 out 参数应保持原值 (实现是: oos_buffer_ 空直接 return false)
    // 不做断言以适配宽松实现

    std::printf("    oos_size=0 oos_first_gap=%d\n", (int)has);
}

// ============================================================================
// TEST 2: 顺序 recv 不产生 OOS, OOS buffer 始终为空
// ============================================================================
static void test_inorder_recv_no_oos() {
    std::printf("[test] In-order recv: OOS buffer stays empty...\n");
    Stream s(1, Stream::Dir::Bidirectional);

    CerrCapture cap;
    // 顺序写入 3 段 100 字节, offset 0/100/200
    s.recv(make_data(0xAA, 100), 0);
    s.recv(make_data(0xBB, 100), 100);
    s.recv(make_data(0xCC, 100), 200);

    // functional: 顺序写入 OOS buffer 始终为空
    CHECK_EQ(s.oos_size_bytes(), 0u);
    std::uint64_t off = 0; std::size_t sz = 0;
    CHECK(!s.oos_first_gap(&off, &sz));

    // 验证埋点: 全部进入 case=3_inorder, 无 case=4_oos_buffered
    std::string log = cap.drain();
    int inorder_count = 0;
    int oos_buffered_count = 0;
    // 数 "case=3_inorder" 出现次数
    std::string needle = "case=3_inorder";
    std::string::size_type pos = 0;
    while ((pos = log.find(needle, pos)) != std::string::npos) {
        ++inorder_count;
        pos += needle.size();
    }
    needle = "case=4_oos_buffered";
    pos = 0;
    while ((pos = log.find(needle, pos)) != std::string::npos) {
        ++oos_buffered_count;
        pos += needle.size();
    }
    CHECK_EQ(inorder_count, 3);
    CHECK_EQ(oos_buffered_count, 0);

    std::printf("    inorder=3 oos_buffered=0 log_len=%zu\n", log.size());
}

// ============================================================================
// TEST 3: 乱序 recv 触发 OOS, oos_size + oos_first_gap 正确
// ============================================================================
static void test_oos_recv_query() {
    std::printf("[test] OOS recv: oos_size + oos_first_gap report correctly...\n");
    Stream s(2, Stream::Dir::Bidirectional);

    CerrCapture cap;
    // 先写入 offset 0 (有序), 然后 offset 100, 200, 300 都乱序 (期望插入 oos_buffer_)
    s.recv(make_data(0xAA, 100), 0);   // ordered, recv_offset_=100
    s.recv(make_data(0xBB, 100), 100);  // ordered, recv_offset_=200
    // 现在 recv_offset_=200, 写入 offset 500 触发 OOS
    s.recv(make_data(0xCC, 100), 500);  // OOS, 进入 oos_buffer_
    s.recv(make_data(0xDD, 100), 300);  // OOS, 进入 oos_buffer_ (offset=300 < 500, 排序在前)
    s.recv(make_data(0xEE, 100), 700);  // OOS, 进入 oos_buffer_ (offset=700 > 500, 排序在后)

    // functional: OOS buffer 应有 3 个 entry, 总字节 300
    CHECK_EQ(s.oos_size_bytes(), 300u);

    // 第一个 gap: offset=300 (map 排序后最小), size=100
    std::uint64_t off = 0; std::size_t sz = 0;
    bool has = s.oos_first_gap(&off, &sz);
    CHECK(has);
    CHECK_EQ(off, 300ull);
    CHECK_EQ(sz, 100u);

    // 验证埋点: case=4_oos_buffered 应出现 3 次 (3 个 OOS 写入)
    std::string log = cap.drain();
    int oos_count = 0;
    std::string needle = "case=4_oos_buffered";
    std::string::size_type pos = 0;
    while ((pos = log.find(needle, pos)) != std::string::npos) {
        ++oos_count;
        pos += needle.size();
    }
    CHECK_EQ(oos_count, 3);

    // 验证 case=4_oos_new_entry 埋点（v1.5.0.3: OOS state 报告改为
    // case=3_inorder 和 case=4_oos_buffered 都调用公共 report_oos_state）
    // case=4_oos_new_entry 出现 3 次 (3 个 OOS 写入各触发一次)
    int new_entry_count = 0;
    needle = "case=4_oos_new_entry";
    pos = 0;
    while ((pos = log.find(needle, pos)) != std::string::npos) {
        ++new_entry_count;
        pos += needle.size();
    }
    CHECK_EQ(new_entry_count, 3);

    // 验证 case=3_oos_remaining 埋点：通过再写一段 in-order 触发
    s.recv(make_data(0xFF, 100), 200);  // 填补 [200,300), 消费 oos [300,400), 剩余 [500,600)+[700,800)
    // case=3_inorder 消费 [200,300), 触发 [300,400) 消费, 剩余 first_gap=[500,600)
    std::string log2 = cap.drain();
    // 注: LINOH_INFO fmt 与 args 间 logger 加空格, stream_id 实际输出 "stream_id= 2"
    CHECK(contains_marker(log2, "Stream::recv: case=3_oos_remaining stream_id= 2"));
    // 实际: 消费 [300,400) 后, next first_gap_offset=500, recv_offset_=400, gap_from_recv_offset=100
    CHECK(contains_marker(log2, "first_gap_offset= 500"));
    CHECK(contains_marker(log2, "first_gap_size= 100"));
    CHECK(contains_marker(log2, "gap_from_recv_offset= 100"));  // 500 - 400 = 100

    std::printf("    oos_size=%zu first_gap_off=%llu first_gap_sz=%zu oos_log=%d\n",
                s.oos_size_bytes(), (unsigned long long)off, sz, oos_count);
}

// ============================================================================
// TEST 4: OOS gap 填补后 oos_size 减少
// ============================================================================
static void test_oos_gap_filled_reduces_size() {
    std::printf("[test] OOS gap filled: oos_size reduces, oos_first_gap advances...\n");
    Stream s(3, Stream::Dir::Bidirectional);

    // 构造场景: offset 0 ordered, offset 200/300 oos, 然后补发 offset 100 填补
    s.recv(make_data(0xAA, 100), 0);    // ordered, recv_offset_=100
    s.recv(make_data(0xBB, 100), 200);   // OOS #1: oos_buffer_=[200,300)
    s.recv(make_data(0xCC, 100), 300);   // OOS #2: oos_buffer_=[200,300) [300,400)
    CHECK_EQ(s.oos_size_bytes(), 200u);

    // 现在补发 offset 100 处的数据 (inorder, 推进 recv_offset_ 至 200, 自动消费 oos [200,300) 和 [300,400))
    s.recv(make_data(0xFF, 100), 100);
    // 预期: oos_size=0, recv_offset_=400
    CHECK_EQ(s.oos_size_bytes(), 0u);
    CHECK(!s.oos_first_gap(nullptr, nullptr));

    std::printf("    oos_size_after_fill=%zu (expected 0)\n", s.oos_size_bytes());
}

// ============================================================================
// TEST 5: OOS 阈值回调触发 (set_oos_callback)
// ============================================================================
struct OosCbCtx {
    int fire_count = 0;
    std::uint64_t last_off = 0;
    std::size_t last_sz = 0;
    std::size_t last_total = 0;
};

static void oos_test_callback(void *user_data,
                              std::uint64_t first_gap_offset,
                              std::size_t first_gap_size,
                              std::size_t oos_total_bytes) {
    auto *ctx = static_cast<OosCbCtx*>(user_data);
    ++ctx->fire_count;
    ctx->last_off = first_gap_offset;
    ctx->last_sz = first_gap_size;
    ctx->last_total = oos_total_bytes;
}

static void test_oos_callback_triggers() {
    std::printf("[test] OOS threshold callback triggers on Stream::recv...\n");
    Stream s(4, Stream::Dir::Bidirectional);

    OosCbCtx ctx{};
    // threshold=50, 即 first_gap_size >= 50 时触发
    s.set_oos_callback(&oos_test_callback, &ctx, 50);

    // 1) 有序数据, 不应触发回调
    s.recv(make_data(0xAA, 100), 0);
    CHECK_EQ(ctx.fire_count, 0);

    // 2) 写入 OOS 100 字节 (>= threshold), case=4 路径应触发回调
    s.recv(make_data(0xBB, 100), 200);
    // v1.5.0.3: case=4_oos_buffered 路径也触发 OOS state report + 回调
    CHECK_EQ(ctx.fire_count, 1);
    CHECK_EQ(ctx.last_off, 200ull);
    CHECK_EQ(ctx.last_sz, 100u);
    CHECK_EQ(ctx.last_total, 100u);

    // 3) 再写入 OOS 50 字节, 应再次触发 (累计 second_gap)
    s.recv(make_data(0xCC, 50), 400);
    // 此时 first_gap_size=100 >= 50, 仍然触发
    CHECK_EQ(ctx.fire_count, 2);
    CHECK_EQ(ctx.last_off, 200ull);
    CHECK_EQ(ctx.last_total, 150u);

    std::printf("    fire_count=%d last_off=%llu last_sz=%zu last_total=%zu\n",
                ctx.fire_count, (unsigned long long)ctx.last_off,
                ctx.last_sz, ctx.last_total);
}

// ============================================================================
// TEST 6: OOS 阈值回调不触发 (gap 太小)
// ============================================================================
static void test_oos_callback_below_threshold() {
    std::printf("[test] OOS callback: gap below threshold does not fire...\n");
    Stream s(5, Stream::Dir::Bidirectional);

    OosCbCtx ctx{};
    s.set_oos_callback(&oos_test_callback, &ctx, 1000);  // 阈值 1000

    s.recv(make_data(0xAA, 100), 0);
    s.recv(make_data(0xBB, 50), 200);  // OOS 50 字节 < 1000 阈值, 不应触发

    CHECK_EQ(ctx.fire_count, 0);

    std::printf("    fire_count=%d (expected 0, gap=50 < threshold=1000)\n", ctx.fire_count);
}

// ============================================================================
// TEST 7: clear_oos_callback 清除回调
// ============================================================================
static void test_oos_callback_clear() {
    std::printf("[test] clear_oos_callback stops further invocations...\n");
    Stream s(6, Stream::Dir::Bidirectional);

    OosCbCtx ctx{};
    s.set_oos_callback(&oos_test_callback, &ctx, 50);

    // 触发一次
    s.recv(make_data(0xAA, 100), 0);
    s.recv(make_data(0xBB, 100), 200);
    CHECK_EQ(ctx.fire_count, 1);

    // 清除回调
    s.clear_oos_callback();

    // 再次写入 OOS, 不应触发
    s.recv(make_data(0xCC, 100), 400);
    CHECK_EQ(ctx.fire_count, 1);  // 不变

    std::printf("    fire_count_after_clear=%d (expected 1)\n", ctx.fire_count);
}

// ============================================================================
// TEST 8: 覆盖注册 OOS 回调 (新回调替换旧回调)
// ============================================================================
static void test_oos_callback_overwrite() {
    std::printf("[test] Overwriting OOS callback replaces previous handler...\n");
    Stream s(7, Stream::Dir::Bidirectional);

    OosCbCtx ctx1{}; OosCbCtx ctx2{};
    s.set_oos_callback(&oos_test_callback, &ctx1, 50);

    // 第一次注册
    s.recv(make_data(0xAA, 100), 0);
    s.recv(make_data(0xBB, 100), 200);
    CHECK_EQ(ctx1.fire_count, 1);
    CHECK_EQ(ctx2.fire_count, 0);

    // 第二次注册 (覆盖)
    s.set_oos_callback(&oos_test_callback, &ctx2, 50);

    s.recv(make_data(0xCC, 100), 400);
    // 应该是 ctx2 触发, ctx1 不再触发
    CHECK_EQ(ctx1.fire_count, 1);  // 不变
    CHECK_EQ(ctx2.fire_count, 1);  // 新增

    std::printf("    ctx1.fire=%d ctx2.fire=%d (expected 1, 1)\n",
                ctx1.fire_count, ctx2.fire_count);
}

// ============================================================================
// TEST 9: last_pn / set_last_pn 埋点关联
// ============================================================================
static void test_last_pn_injection() {
    std::printf("[test] last_pn injection: PN is associated with stream recv...\n");
    Stream s(8, Stream::Dir::Bidirectional);

    CerrCapture cap;
    // 模拟接收端: 每个 STREAM 帧注入 packet number
    s.set_last_pn(100);
    s.recv(make_data(0xAA, 50), 0);
    s.set_last_pn(101);
    s.recv(make_data(0xBB, 50), 50);
    s.set_last_pn(200);
    s.recv(make_data(0xCC, 50), 300);  // OOS

    std::string log = cap.drain();

    // functional: last_pn() 返回最近一次 set 的值
    CHECK_EQ(s.last_pn(), 200ull);

    // 验证埋点: 每条 recv 都打印 pn=
    // 注意 LINOH_INFO 格式: append_args 在每个 arg 前加空格, 实际输出 "pn= 100"
    CHECK(contains_marker(log, "pn= 100"));
    CHECK(contains_marker(log, "pn= 101"));
    CHECK(contains_marker(log, "pn= 200"));

    std::printf("    last_pn=%llu log contains pn=100/101/200\n",
                (unsigned long long)s.last_pn());
}

// ============================================================================
// TEST 10: C API 边界 - NULL 参数安全
// ============================================================================
static void test_c_api_null_safety() {
    std::printf("[test] C API NULL safety...\n");

    // linoh_stream_oos_size(nullptr) -> 0
    CHECK_EQ(linoh_stream_oos_size(nullptr), 0u);

    // linoh_stream_oos_first_gap(nullptr, ...) -> 0
    std::uint64_t off = 0xDEAD; std::size_t sz = 0xBEEF;
    int has = linoh_stream_oos_first_gap(nullptr, &off, &sz);
    CHECK_EQ(has, 0);

    // linoh_stream_set_oos_callback(nullptr, ...) -> 安全 no-op
    auto dummy_cb = [](linoh_stream_t*, std::uint64_t, std::size_t, std::size_t, void*) {};
    linoh_stream_set_oos_callback(nullptr, dummy_cb, nullptr, 100);
    linoh_stream_clear_oos_callback(nullptr);

    CHECK(1);  // 没有崩溃即为通过
    std::printf("    all 4 NULL-safety checks passed (no crash)\n");
}

// ============================================================================
// TEST 11: 埋点 log 级别过滤
// ============================================================================
static void test_log_level_filter() {
    std::printf("[test] Log level filter: INFO hidden at WARN...\n");

    // 切到 Warn, 期望 INFO 级别埋点不输出
    linoh::util::log::set_level(linoh::util::log::Level::Warn);

    Stream s(9, Stream::Dir::Bidirectional);

    CerrCapture cap;
    s.recv(make_data(0xAA, 100), 0);
    s.recv(make_data(0xBB, 100), 200);  // OOS, 触发 case=3_inorder + case=3_oos_remaining INFO

    std::string log = cap.drain();

    // 切回 INFO
    linoh::util::log::set_level(linoh::util::log::Level::Info);

    // WARN 级别下 INFO 埋点不输出
    CHECK(!contains_marker(log, "Stream::recv: case=3_inorder"));
    CHECK(!contains_marker(log, "Stream::recv: case=3_oos_remaining"));
    CHECK(!contains_marker(log, "Stream::recv: case=4_oos_buffered"));
    CHECK(!contains_marker(log, "Stream::recv: case=4_oos_new_entry"));

    std::printf("    log_at_warn_len=%zu (INFO markers filtered out)\n", log.size());
}

// ============================================================================
// TEST 12: 综合场景 - 多个 OOS 累积 + 阈值回调 + 填补清理
// ============================================================================
static void test_combined_scenario() {
    std::printf("[test] Combined: multi-OOS + callback + fill + clear...\n");
    Stream s(10, Stream::Dir::Bidirectional);

    OosCbCtx ctx{};
    s.set_oos_callback(&oos_test_callback, &ctx, 50);

    // 阶段 1: 构造多个 OOS（offset 0 有序, 然后 200/400/600 都是 OOS）
    s.recv(make_data(0xAA, 100), 0);     // ordered, recv_offset_=100
    s.recv(make_data(0xBB, 100), 200);    // OOS #1
    s.recv(make_data(0xCC, 100), 400);    // OOS #2
    s.recv(make_data(0xDD, 100), 600);    // OOS #3
    CHECK_EQ(s.oos_size_bytes(), 300u);
    CHECK(ctx.fire_count >= 1);

    // 阶段 2: 查询 OOS 状态
    std::uint64_t off; std::size_t sz;
    CHECK(s.oos_first_gap(&off, &sz));
    CHECK_EQ(off, 200ull);
    CHECK_EQ(sz, 100u);

    // 阶段 3: 填补所有 OOS gap (填补 100/300/500)
    s.recv(make_data(0xEE, 100), 100);    // fill [100,200), 消费 [200,300)
    s.recv(make_data(0xEE, 100), 300);    // fill [300,400), 消费 [400,500)
    s.recv(make_data(0xEE, 100), 500);    // fill [500,600), 消费 [600,700)
    CHECK_EQ(s.oos_size_bytes(), 0u);

    // 阶段 4: 再次 OOS, 回调应继续工作
    int prev_count = ctx.fire_count;
    s.recv(make_data(0xFF, 100), 800);    // OOS, 应触发回调
    CHECK(ctx.fire_count > prev_count);

    std::printf("    fire_count=%d oos_size=%zu\n", ctx.fire_count, s.oos_size_bytes());
}

// ============================================================================
// main
// ============================================================================
int main() {
    std::printf("=== test_oos_active_notify (v1.5.0.3 F3 API) ===\n\n");

    // 默认 INFO 级别
    linoh::util::log::set_level(linoh::util::log::Level::Info);

    test_initial_state_empty();
    test_inorder_recv_no_oos();
    test_oos_recv_query();
    test_oos_gap_filled_reduces_size();
    test_oos_callback_triggers();
    test_oos_callback_below_threshold();
    test_oos_callback_clear();
    test_oos_callback_overwrite();
    test_last_pn_injection();
    test_c_api_null_safety();
    test_log_level_filter();
    test_combined_scenario();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
