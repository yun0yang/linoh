// test_stream_range_lifecycle_v1511.cpp — v1.5.0.11 StreamRange 完整生命周期一致性
//
// 验证 v1.5.0.10 ISSUE T10 反馈根因分析（LINOH_V1510_T10_FEEDBACK.md）：
//   v1.5.0.10 master 端 OOS_PN 反查命中率 0.4%（20/4842），retx_by_oos_pn_total=0。
//   排查方向：StreamRange 注册→清理链路是否完整。
//
// v1.5.0.11 新增 3 个计数器验证生命周期一致性：
//   - stream_range_add_total_:    on_packet_sent 累加（按 stream_ranges.size()）
//   - stream_range_remove_total_: mark_acked/mark_lost 累加（仅 in-flight 时）
//   - active_size = add_total - remove_total（导出方法）
//
// 测试矩阵（5 用例）：
//   1. 完整生命周期：注册 5 个 range → ACK 3 个 → 活跃 = 2
//   2. 一致性不变量：active_size = add_total - remove_total（多次随机顺序下仍成立）
//   3. 混合 mark_acked + mark_lost：活跃计数在两条路径上均正确清理
//   4. 跨多 PN 注册：每个 PN 多个 range 累加正确
//   5. 重置/重连场景：fresh LossDetector 初始值归零
//
// 测试基线：v1.5.0.10 (commit 6bd9ed2)
// 目标版本：v1.5.0.11 (ISSUE T10 修复)

#include "linoh/base/key.hpp"
#include "linoh/endpoint/connection.hpp"
#include "linoh/endpoint/state_machine.hpp"
#include "linoh/protocol/loss_recovery.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/util/bytes.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <span>
#include <string>
#include <vector>

using namespace linoh;
using namespace linoh::endpoint;
using namespace linoh::protocol;

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

#define CHECK_GE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a >= _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s >= %s (%lld < %lld) (line %d)\n", \
        #a, #b, (long long)_a, (long long)_b, __LINE__); } \
} while (0)

// ============================================================================
// TEST 1: 完整生命周期：注册 5 个 range → ACK 3 个 → 活跃 = 2
//   验证 v1.5.0.11 StreamRange 生命周期最基础的不变量：
//     active_size = add_total - remove_total
// ============================================================================
static void test_v1511_lifecycle_basic_invariant() {
    std::printf("[test] v1.5.0.11 StreamRange lifecycle: 5 added, 3 acked, 2 active...\n");

    LossDetector ld;
    CHECK_EQ(ld.stream_range_add_total_for_test(), 0ull);
    CHECK_EQ(ld.stream_range_remove_total_for_test(), 0ull);
    CHECK_EQ(ld.stream_range_active_size_for_test(), 0ull);

    // 注册 5 个 range（分布在 3 个 PN）
    std::vector<StreamRange> r1 = {
        {.stream_id = 1, .offset = 0,   .payload_bytes = 100},
        {.stream_id = 1, .offset = 100, .payload_bytes = 100},
    };
    ld.on_packet_sent(1, 0.0, 1500, true, r1);

    std::vector<StreamRange> r2 = {
        {.stream_id = 2, .offset = 0, .payload_bytes = 200},
    };
    ld.on_packet_sent(2, 0.0, 1500, true, r2);

    std::vector<StreamRange> r3 = {
        {.stream_id = 1, .offset = 200, .payload_bytes = 100},
        {.stream_id = 3, .offset = 0,   .payload_bytes = 100},
    };
    ld.on_packet_sent(3, 0.0, 1500, true, r3);

    CHECK_EQ(ld.stream_range_add_total_for_test(), 5ull);
    CHECK_EQ(ld.stream_range_remove_total_for_test(), 0ull);
    CHECK_EQ(ld.stream_range_active_size_for_test(), 5ull);

    // ACK 3 个 PN（PN=1 含 2 range，PN=2 含 1 range → 共清理 3）
    ld.mark_acked(1);
    ld.mark_acked(2);

    CHECK_EQ(ld.stream_range_add_total_for_test(), 5ull);
    CHECK_EQ(ld.stream_range_remove_total_for_test(), 3ull);
    CHECK_EQ(ld.stream_range_active_size_for_test(), 2ull);  // 5-3=2

    // 再 ACK PN=3 → 活跃 = 0
    ld.mark_acked(3);
    CHECK_EQ(ld.stream_range_active_size_for_test(), 0ull);

    std::printf("    basic invariant verified (5 added -> 3 removed -> 2 active -> 0)\n");
}

// ============================================================================
// TEST 2: 一致性不变量在乱序 ACK 下仍成立
//   验证 v1.5.0.11 active_size = add_total - remove_total 不依赖 ACK 顺序
// ============================================================================
static void test_v1511_lifecycle_invariant_random_order() {
    std::printf("[test] v1.5.0.11 lifecycle invariant under random ACK order...\n");

    LossDetector ld;
    // 注册 10 个 PN 各 1 个 range
    for (uint64_t pn = 1; pn <= 10; ++pn) {
        std::vector<StreamRange> r = {
            {.stream_id = 1, .offset = (pn-1)*100, .payload_bytes = 100}
        };
        ld.on_packet_sent(pn, 0.0, 1500, true, r);
    }
    CHECK_EQ(ld.stream_range_add_total_for_test(), 10ull);
    CHECK_EQ(ld.stream_range_active_size_for_test(), 10ull);

    // 乱序 ACK：6, 2, 9, 1, 5
    std::vector<uint64_t> ack_order = {6, 2, 9, 1, 5};
    for (uint64_t pn : ack_order) {
        ld.mark_acked(pn);
        // 每次 ACK 后不变量：active = add - remove
        auto expected_active = ld.stream_range_add_total_for_test()
                             - ld.stream_range_remove_total_for_test();
        CHECK_EQ(ld.stream_range_active_size_for_test(), expected_active);
    }
    // ACK 5 个 → 活跃 5 个
    CHECK_EQ(ld.stream_range_remove_total_for_test(), 5ull);
    CHECK_EQ(ld.stream_range_active_size_for_test(), 5ull);

    // 再乱序 ACK 剩余 5 个：3, 4, 7, 8, 10
    std::vector<uint64_t> ack_order_2 = {3, 4, 7, 8, 10};
    for (uint64_t pn : ack_order_2) {
        ld.mark_acked(pn);
    }
    CHECK_EQ(ld.stream_range_active_size_for_test(), 0ull);

    std::printf("    invariant holds under random ACK order (active = add - remove)\n");
}

// ============================================================================
// TEST 3: 混合 mark_acked + mark_lost：活跃计数在两条路径上均正确清理
//   验证 v1.5.0.11 mark_lost 同样会累加 remove_total
// ============================================================================
static void test_v1511_lifecycle_acked_vs_lost() {
    std::printf("[test] v1.5.0.11 lifecycle: mixed mark_acked + mark_lost paths...\n");

    LossDetector ld;
    // 4 个 PN
    for (uint64_t pn = 1; pn <= 4; ++pn) {
        std::vector<StreamRange> r = {
            {.stream_id = 1, .offset = (pn-1)*100, .payload_bytes = 100}
        };
        ld.on_packet_sent(pn, 0.0, 1500, true, r);
    }
    CHECK_EQ(ld.stream_range_active_size_for_test(), 4ull);

    // 路径 1：ACK PN=1
    ld.mark_acked(1);
    CHECK_EQ(ld.stream_range_remove_total_for_test(), 1ull);
    CHECK_EQ(ld.stream_range_active_size_for_test(), 3ull);

    // 路径 2：PN=2 触发 mark_lost（通过 OOS_PN 命中反查）
    //   stream_id=1 匹配已注册范围，offset=150 命中 PN=2 的 [100,200) 范围
    //   （PN=2 offset=(2-1)*100=100, payload=100）
    std::vector<OosPnEntry> entries = {{.offset = 150, .first_seen_ms = 100.0}};
    auto lost = ld.on_oos_pn_received(1, entries);
    CHECK_GE(lost.size(), 1ull);  // 至少一个 PN 被标记 lost
    // mark_lost 也应清理 stream_ranges
    CHECK_EQ(ld.stream_range_remove_total_for_test(), 2ull);
    CHECK_EQ(ld.stream_range_active_size_for_test(), 2ull);

    // 剩余 PN=3, PN=4 走 ACK
    ld.mark_acked(3);
    ld.mark_acked(4);
    CHECK_EQ(ld.stream_range_active_size_for_test(), 0ull);

    std::printf("    mixed ack+lost paths verified (acked + lost both clean stream_ranges)\n");
}

// ============================================================================
// TEST 4: 跨多 PN 注册：每个 PN 多个 range 累加正确
//   验证 v1.5.0.11 on_packet_sent 中按 stream_ranges.size() 累加 add_total 的正确性
// ============================================================================
static void test_v1511_lifecycle_multi_range_per_pn() {
    std::printf("[test] v1.5.0.11 multi-range per PN add_total累加...\n");

    LossDetector ld;
    // PN=1: 3 range, PN=2: 5 range, PN=3: 2 range
    std::vector<StreamRange> r1 = {
        {.stream_id = 1, .offset = 0,   .payload_bytes = 100},
        {.stream_id = 1, .offset = 100, .payload_bytes = 100},
        {.stream_id = 2, .offset = 0,   .payload_bytes = 200},
    };
    ld.on_packet_sent(1, 0.0, 1500, true, r1);

    std::vector<StreamRange> r2;
    for (uint64_t i = 0; i < 5; ++i) {
        r2.push_back({.stream_id = 3, .offset = i*100, .payload_bytes = 100});
    }
    ld.on_packet_sent(2, 0.0, 1500, true, r2);

    std::vector<StreamRange> r3 = {
        {.stream_id = 1, .offset = 200, .payload_bytes = 100},
        {.stream_id = 4, .offset = 0,   .payload_bytes = 50},
    };
    ld.on_packet_sent(3, 0.0, 1500, true, r3);

    CHECK_EQ(ld.stream_range_add_total_for_test(), 10ull);  // 3+5+2=10
    CHECK_EQ(ld.stream_range_active_size_for_test(), 10ull);

    // ACK 全部
    ld.mark_acked(1);
    CHECK_EQ(ld.stream_range_remove_total_for_test(), 3ull);
    CHECK_EQ(ld.stream_range_active_size_for_test(), 7ull);

    ld.mark_acked(2);
    CHECK_EQ(ld.stream_range_remove_total_for_test(), 8ull);
    CHECK_EQ(ld.stream_range_active_size_for_test(), 2ull);

    ld.mark_acked(3);
    CHECK_EQ(ld.stream_range_remove_total_for_test(), 10ull);
    CHECK_EQ(ld.stream_range_active_size_for_test(), 0ull);

    std::printf("    multi-range per PN verified (3+5+2=10 add, ACK 3+5+2=10 remove)\n");
}

// ============================================================================
// TEST 5: 重置/重连场景：fresh LossDetector 初始值归零
//   验证 v1.5.0.11 不同 LossDetector 实例间计数器隔离（无静态污染）
// ============================================================================
static void test_v1511_lifecycle_fresh_detector_isolation() {
    std::printf("[test] v1.5.0.11 fresh LossDetector isolation (no static pollution)...\n");

    // 第一个 detector：注册一些 range
    {
        LossDetector ld1;
        std::vector<StreamRange> r = {
            {.stream_id = 1, .offset = 0, .payload_bytes = 100},
            {.stream_id = 2, .offset = 0, .payload_bytes = 200},
        };
        ld1.on_packet_sent(1, 0.0, 1500, true, r);
        CHECK_EQ(ld1.stream_range_add_total_for_test(), 2ull);
        CHECK_EQ(ld1.stream_range_active_size_for_test(), 2ull);
    }  // ld1 析构

    // 第二个 detector：初始值必须为 0
    LossDetector ld2;
    CHECK_EQ(ld2.stream_range_add_total_for_test(), 0ull);
    CHECK_EQ(ld2.stream_range_remove_total_for_test(), 0ull);
    CHECK_EQ(ld2.stream_range_active_size_for_test(), 0ull);

    // 第一个 detector 析构后再创建第三个
    {
        LossDetector ld3;
        std::vector<StreamRange> r = {
            {.stream_id = 5, .offset = 0, .payload_bytes = 50},
        };
        ld3.on_packet_sent(99, 0.0, 1500, true, r);
        CHECK_EQ(ld3.stream_range_add_total_for_test(), 1ull);
    }

    // ld2 仍应保持 0
    CHECK_EQ(ld2.stream_range_add_total_for_test(), 0ull);
    CHECK_EQ(ld2.stream_range_active_size_for_test(), 0ull);

    std::printf("    fresh detector isolation verified (no static pollution)\n");
}

int main() {
    std::printf("=== test_stream_range_lifecycle_v1511 ===\n");
    std::printf("v1.5.0.11 StreamRange lifecycle consistency (ISSUE T10 register-clean chain)\n\n");

    test_v1511_lifecycle_basic_invariant();
    test_v1511_lifecycle_invariant_random_order();
    test_v1511_lifecycle_acked_vs_lost();
    test_v1511_lifecycle_multi_range_per_pn();
    test_v1511_lifecycle_fresh_detector_isolation();

    std::printf("\n=== Result: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
