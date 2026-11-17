// test_oos_complete_overlap_v1709.cpp — v1.7.0.9 insert_oos_merged 完全覆盖崩溃修复测试
//
// 验证 Stream::insert_oos_merged 在 prev entry 完全覆盖当前 data 时不崩溃。
//
// 根因（v1.7.0.9 bug）:
//   connection.cpp insert_oos_merged step 1（与前 entry 合并）:
//     skip_from_prev = prev_end - data_begin
//   当 prev_end >= data_end（prev 完全覆盖 data）时:
//     skip_from_prev >= merged.size()
//     merged.begin() + skip_from_prev 越界 -> vector::insert 触发 std::length_error
//
// 修复: 钳制 skip_from_prev 到 [0, merged.size()]，并用 if 保护 insert。
//
// 测试矩阵（5 用例）:
//   1. prev 完全覆盖 data（prev_end > data_end）—— 修复前必崩溃
//   2. prev_end == data_end（边界完全覆盖）—— 修复前边界 UB
//   3. prev 部分覆盖 data（prev_end 在 data 内）—— 正常合并回归
//   4. prev 紧邻 data（prev_end == data_begin）—— skip_from_prev=0 回归
//   5. 复现崩溃日志场景：prev offset=10555 size=4218, data offset=14716 size=57
//
// 编译: cl /std:c++20 /EHsc /permissive- /O2 /utf-8 /MD /I. /Iinclude tests\test_oos_complete_overlap_v1709.cpp

#include "linoh/endpoint/connection.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <span>
#include <vector>

using namespace linoh::endpoint;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    auto _va = (a); auto _vb = (b); \
    if (_va == _vb) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (%llu != %llu) (line %d)\n", \
        #a, #b, (unsigned long long)_va, (unsigned long long)_vb, __LINE__); } \
} while (0)

// ============================================================================
// 辅助：生成填充字节的 vector
// ============================================================================
static std::vector<std::uint8_t> make_data(std::size_t n, std::uint8_t fill) {
    return std::vector<std::uint8_t>(n, fill);
}

// ============================================================================
// 用例 1: prev 完全覆盖 data（prev_end > data_end）
//   prev: [100, 200)  size=100
//   data: [150, 180)  size=30
//   prev_end=200 > data_end=180 -> skip_from_prev=50 > merged.size()=30
//   修复前: 越界崩溃。修复后: merged 被丢弃，entry=[100,200) 内容=prev
// ============================================================================
static void test1_complete_overlap_strict() {
    std::printf("[test] 1. prev完全覆盖data (prev_end > data_end)...\n");

    Stream s(1, Stream::Dir::Bidirectional);
    s.set_last_pn(10);

    auto prev_data = make_data(100, 0xAA);  // [100,200)
    s.insert_oos_merged(100, std::span<const std::uint8_t>(prev_data));

    auto new_data = make_data(30, 0xBB);    // [150,180)
    s.insert_oos_merged(150, std::span<const std::uint8_t>(new_data));

    const auto &buf = s.oos_buffer_for_test();
    CHECK_EQ(buf.size(), 1u);

    auto it = buf.find(100);
    CHECK(it != buf.end());
    if (it != buf.end()) {
        CHECK_EQ(it->second.size(), 100u);  // prev 的 100 字节
        CHECK_EQ(it->second[0], 0xAA);       // 内容是 prev 的
        CHECK_EQ(it->second[99], 0xAA);
    }

    std::printf("[OK] 1. no crash, entry=[100,200) size=100\n\n");
}

// ============================================================================
// 用例 2: prev_end == data_end（边界完全覆盖）
//   prev: [100, 200)  size=100
//   data: [150, 200)  size=50
//   prev_end=200 == data_end=200 -> skip_from_prev=50 == merged.size()=50
//   修复前: merged.begin()+50 == end, insert 空范围（UB 边界）
//   修复后: skip_from_prev=50 == merged.size(), if 保护跳过 insert
// ============================================================================
static void test2_complete_overlap_boundary() {
    std::printf("[test] 2. prev_end == data_end (边界完全覆盖)...\n");

    Stream s(2, Stream::Dir::Bidirectional);
    s.set_last_pn(20);

    auto prev_data = make_data(100, 0xCC);  // [100,200)
    s.insert_oos_merged(100, std::span<const std::uint8_t>(prev_data));

    auto new_data = make_data(50, 0xDD);    // [150,200)
    s.insert_oos_merged(150, std::span<const std::uint8_t>(new_data));

    const auto &buf = s.oos_buffer_for_test();
    CHECK_EQ(buf.size(), 1u);

    auto it = buf.find(100);
    CHECK(it != buf.end());
    if (it != buf.end()) {
        CHECK_EQ(it->second.size(), 100u);
        CHECK_EQ(it->second[0], 0xCC);
    }

    std::printf("[OK] 2. no crash, entry=[100,200) size=100\n\n");
}

// ============================================================================
// 用例 3: prev 部分覆盖 data（prev_end 在 data 内）
//   prev: [100, 150)  size=50
//   data: [120, 200)  size=80
//   prev_end=150 > data_begin=120 -> skip_from_prev=30 < merged.size()=80
//   正常合并: new_merged = prev[100,150) + data[150,200)
//   entry=[100,200) size=100, 前50字节=0xEE, 后50字节=0xFF
// ============================================================================
static void test3_partial_overlap() {
    std::printf("[test] 3. prev部分覆盖data (prev_end在data内)...\n");

    Stream s(3, Stream::Dir::Bidirectional);
    s.set_last_pn(30);

    auto prev_data = make_data(50, 0xEE);   // [100,150)
    s.insert_oos_merged(100, std::span<const std::uint8_t>(prev_data));

    auto new_data = make_data(80, 0xFF);    // [120,200)
    s.insert_oos_merged(120, std::span<const std::uint8_t>(new_data));

    const auto &buf = s.oos_buffer_for_test();
    CHECK_EQ(buf.size(), 1u);

    auto it = buf.find(100);
    CHECK(it != buf.end());
    if (it != buf.end()) {
        CHECK_EQ(it->second.size(), 100u);  // 50(prev) + 50(data tail)
        CHECK_EQ(it->second[0], 0xEE);       // prev 部分
        CHECK_EQ(it->second[49], 0xEE);
        CHECK_EQ(it->second[50], 0xFF);      // data 尾部
        CHECK_EQ(it->second[99], 0xFF);
    }

    std::printf("[OK] 3. merged entry=[100,200) size=100\n\n");
}

// ============================================================================
// 用例 4: prev 紧邻 data（prev_end == data_begin）
//   prev: [100, 150)  size=50
//   data: [150, 200)  size=50
//   prev_end=150 == data_begin=150 -> skip_from_prev=0
//   正常合并: new_merged = prev + data
//   entry=[100,200) size=100
// ============================================================================
static void test4_adjacent_no_overlap() {
    std::printf("[test] 4. prev紧邻data (prev_end == data_begin)...\n");

    Stream s(4, Stream::Dir::Bidirectional);
    s.set_last_pn(40);

    auto prev_data = make_data(50, 0x11);   // [100,150)
    s.insert_oos_merged(100, std::span<const std::uint8_t>(prev_data));

    auto new_data = make_data(50, 0x22);    // [150,200)
    s.insert_oos_merged(150, std::span<const std::uint8_t>(new_data));

    const auto &buf = s.oos_buffer_for_test();
    CHECK_EQ(buf.size(), 1u);

    auto it = buf.find(100);
    CHECK(it != buf.end());
    if (it != buf.end()) {
        CHECK_EQ(it->second.size(), 100u);
        CHECK_EQ(it->second[0], 0x11);
        CHECK_EQ(it->second[49], 0x11);
        CHECK_EQ(it->second[50], 0x22);
        CHECK_EQ(it->second[99], 0x22);
    }

    std::printf("[OK] 4. merged entry=[100,200) size=100\n\n");
}

// ============================================================================
// 用例 5: 复现崩溃日志场景
//   prev: offset=10555 size=4218 (end=14773)
//   data: offset=14716 size=57  (end=14773)
//   skip_from_prev = 14773 - 14716 = 57 = merged.size()
//   修复前: insert 越界/length_error 崩溃
//   修复后: 不崩溃，entry=[10555,14773) size=4218
// ============================================================================
static void test5_crash_repro() {
    std::printf("[test] 5. 复现崩溃日志场景 (offset=10555/14716)...\n");

    Stream s(5, Stream::Dir::Bidirectional);
    s.set_last_pn(50);

    auto prev_data = make_data(4218, 0x0A);  // [10555, 14773)
    s.insert_oos_merged(10555, std::span<const std::uint8_t>(prev_data));

    auto new_data = make_data(57, 0x0B);     // [14716, 14773)
    s.insert_oos_merged(14716, std::span<const std::uint8_t>(new_data));

    const auto &buf = s.oos_buffer_for_test();
    CHECK_EQ(buf.size(), 1u);

    auto it = buf.find(10555);
    CHECK(it != buf.end());
    if (it != buf.end()) {
        CHECK_EQ(it->second.size(), 4218u);  // prev 的数据，data 被完全覆盖丢弃
        CHECK_EQ(it->second[0], 0x0A);
        CHECK_EQ(it->second[4217], 0x0A);
    }

    std::printf("[OK] 5. no crash, entry=[10555,14773) size=4218\n\n");
}

// ============================================================================
// main
// ============================================================================
int main() {
    std::printf("=== test_oos_complete_overlap_v1709 ===\n");
    std::printf("linoh v1.7.0.9 insert_oos_merged complete-overlap fix\n\n");

    test1_complete_overlap_strict();
    test2_complete_overlap_boundary();
    test3_partial_overlap();
    test4_adjacent_no_overlap();
    test5_crash_repro();

    std::printf("=== Results: %d PASS / %d FAIL ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
