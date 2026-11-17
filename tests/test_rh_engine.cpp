// test_rh_engine.cpp — v2.2 Phase 3 P3-D RecursiveHalving 算法引擎单元测试
//
// 验证 P3-D 交付物：
//   1. is_power_of_two / pad_to_power_of_two
//   2. bit_reverse
//   3. reduce_scatter_steps / all_gather_steps / total_steps
//   4. phase_of 阶段判定
//   5. reduce_scatter_step 步级通信信息（partner / send / recv offset）
//   6. reduce_scatter_result_idx（bit reversal）
//   7. all_gather_step 步级通信信息
//   8. all_reduce_step 统一接口
//   9. N=4 完整 ReduceScatter 模拟（验证每节点拥有正确 chunk）
//  10. N=8 完整 ReduceScatter 模拟
//  11. N=4 完整 AllReduce 模拟（ReduceScatter + AllGather）
//  12. 通信量预估
//  13. 步信息不变量（send_length 与 recv_length 模式）
//  14. 非二次幂 padding

#include "linoh/multimodal/rh_engine.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

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

#define CHECK_HAS(opt) do { \
    if ((opt).has_value()) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s has value (line %d)\n", #opt, __LINE__); } \
} while (0)

// ============================================================================
// 辅助函数
// ============================================================================

/// uint64 转字节（小端序）
static std::vector<std::uint8_t> make_u64_val(std::uint64_t val) {
    std::vector<std::uint8_t> data(8);
    for (int i = 0; i < 8; ++i) {
        data[i] = static_cast<std::uint8_t>((val >> (i * 8)) & 0xFF);
    }
    return data;
}

/// 从字节读取 uint64（小端序）
static std::uint64_t read_u64(const std::uint8_t* data) {
    std::uint64_t val = 0;
    std::memcpy(&val, data, 8);
    return val;
}

/// 对两个字节范围执行 SUM 规约（uint64 元素）
static void reduce_sum_inplace(std::uint8_t* dst, const std::uint8_t* src, std::size_t len) {
    for (std::size_t i = 0; i < len; i += 8) {
        std::uint64_t a = read_u64(dst + i);
        std::uint64_t b = read_u64(src + i);
        std::uint64_t sum = a + b;
        std::memcpy(dst + i, &sum, 8);
    }
}

// ============================================================================
// TEST 1: is_power_of_two / pad_to_power_of_two
// ============================================================================
static void test_power_of_two_utils() {
    std::printf("[test] is_power_of_two / pad_to_power_of_two...\n");

    CHECK(RHEngine::is_power_of_two(1));
    CHECK(RHEngine::is_power_of_two(2));
    CHECK(RHEngine::is_power_of_two(4));
    CHECK(RHEngine::is_power_of_two(8));
    CHECK(RHEngine::is_power_of_two(16));
    CHECK(!RHEngine::is_power_of_two(0));
    CHECK(!RHEngine::is_power_of_two(3));
    CHECK(!RHEngine::is_power_of_two(5));
    CHECK(!RHEngine::is_power_of_two(6));
    CHECK(!RHEngine::is_power_of_two(7));

    CHECK_EQ(RHEngine::pad_to_power_of_two(1), static_cast<std::size_t>(1));
    CHECK_EQ(RHEngine::pad_to_power_of_two(2), static_cast<std::size_t>(2));
    CHECK_EQ(RHEngine::pad_to_power_of_two(3), static_cast<std::size_t>(4));
    CHECK_EQ(RHEngine::pad_to_power_of_two(4), static_cast<std::size_t>(4));
    CHECK_EQ(RHEngine::pad_to_power_of_two(5), static_cast<std::size_t>(8));
    CHECK_EQ(RHEngine::pad_to_power_of_two(7), static_cast<std::size_t>(8));
    CHECK_EQ(RHEngine::pad_to_power_of_two(8), static_cast<std::size_t>(8));
    CHECK_EQ(RHEngine::pad_to_power_of_two(9), static_cast<std::size_t>(16));
}

// ============================================================================
// TEST 2: bit_reverse
// ============================================================================
static void test_bit_reverse() {
    std::printf("[test] bit_reverse...\n");

    // 2 bits
    CHECK_EQ(RHEngine::bit_reverse(0, 2), static_cast<std::size_t>(0));  // 00 → 00
    CHECK_EQ(RHEngine::bit_reverse(1, 2), static_cast<std::size_t>(2));  // 01 → 10
    CHECK_EQ(RHEngine::bit_reverse(2, 2), static_cast<std::size_t>(1));  // 10 → 01
    CHECK_EQ(RHEngine::bit_reverse(3, 2), static_cast<std::size_t>(3));  // 11 → 11

    // 3 bits
    CHECK_EQ(RHEngine::bit_reverse(0, 3), static_cast<std::size_t>(0));  // 000 → 000
    CHECK_EQ(RHEngine::bit_reverse(1, 3), static_cast<std::size_t>(4));  // 001 → 100
    CHECK_EQ(RHEngine::bit_reverse(2, 3), static_cast<std::size_t>(2));  // 010 → 010
    CHECK_EQ(RHEngine::bit_reverse(3, 3), static_cast<std::size_t>(6));  // 011 → 110
    CHECK_EQ(RHEngine::bit_reverse(4, 3), static_cast<std::size_t>(1));  // 100 → 001
    CHECK_EQ(RHEngine::bit_reverse(5, 3), static_cast<std::size_t>(5));  // 101 → 101
    CHECK_EQ(RHEngine::bit_reverse(6, 3), static_cast<std::size_t>(3));  // 110 → 011
    CHECK_EQ(RHEngine::bit_reverse(7, 3), static_cast<std::size_t>(7));  // 111 → 111

    // 双重反转 = 原值
    for (std::size_t v = 0; v < 8; ++v) {
        CHECK_EQ(RHEngine::bit_reverse(RHEngine::bit_reverse(v, 3), 3), v);
    }
}

// ============================================================================
// TEST 3: 步数计算
// ============================================================================
static void test_step_counts() {
    std::printf("[test] step counts...\n");

    CHECK_EQ(RHEngine::reduce_scatter_steps(1), static_cast<std::size_t>(0));
    CHECK_EQ(RHEngine::reduce_scatter_steps(2), static_cast<std::size_t>(1));
    CHECK_EQ(RHEngine::reduce_scatter_steps(4), static_cast<std::size_t>(2));
    CHECK_EQ(RHEngine::reduce_scatter_steps(8), static_cast<std::size_t>(3));
    CHECK_EQ(RHEngine::reduce_scatter_steps(16), static_cast<std::size_t>(4));

    CHECK_EQ(RHEngine::all_gather_steps(4), static_cast<std::size_t>(2));
    CHECK_EQ(RHEngine::all_gather_steps(8), static_cast<std::size_t>(3));

    CHECK_EQ(RHEngine::total_steps(4), static_cast<std::size_t>(4));
    CHECK_EQ(RHEngine::total_steps(8), static_cast<std::size_t>(6));
}

// ============================================================================
// TEST 4: phase_of 阶段判定
// ============================================================================
static void test_phase_of() {
    std::printf("[test] phase_of...\n");

    // N=4: rs_steps=2, total=4
    CHECK_EQ(static_cast<int>(RHEngine::phase_of(0, 4)), static_cast<int>(RHPhase::ReduceScatter));
    CHECK_EQ(static_cast<int>(RHEngine::phase_of(1, 4)), static_cast<int>(RHPhase::ReduceScatter));
    CHECK_EQ(static_cast<int>(RHEngine::phase_of(2, 4)), static_cast<int>(RHPhase::AllGather));
    CHECK_EQ(static_cast<int>(RHEngine::phase_of(3, 4)), static_cast<int>(RHPhase::AllGather));
    CHECK_EQ(static_cast<int>(RHEngine::phase_of(4, 4)), static_cast<int>(RHPhase::Done));

    // N=8: rs_steps=3, total=6
    CHECK_EQ(static_cast<int>(RHEngine::phase_of(0, 8)), static_cast<int>(RHPhase::ReduceScatter));
    CHECK_EQ(static_cast<int>(RHEngine::phase_of(2, 8)), static_cast<int>(RHPhase::ReduceScatter));
    CHECK_EQ(static_cast<int>(RHEngine::phase_of(3, 8)), static_cast<int>(RHPhase::AllGather));
    CHECK_EQ(static_cast<int>(RHEngine::phase_of(5, 8)), static_cast<int>(RHPhase::AllGather));
    CHECK_EQ(static_cast<int>(RHEngine::phase_of(6, 8)), static_cast<int>(RHPhase::Done));
}

// ============================================================================
// TEST 5: reduce_scatter_step 通信信息
// ============================================================================
static void test_reduce_scatter_step() {
    std::printf("[test] reduce_scatter_step...\n");

    // N=4, msg=32 bytes, chunk_size=8
    // step 0: partner = rank XOR 1
    //   rank 0, partner 1: keep_lower=true (bit 0 = 0)
    //     active [0,4), mid=2. send [2,4)=offset 16 len 16, recv [0,2)=offset 0 len 16
    auto s = RHEngine::reduce_scatter_step(0, 0, 4, 32);
    CHECK(s.valid);
    CHECK_EQ(s.partner_rank, static_cast<std::size_t>(1));
    CHECK(s.keep_lower);
    CHECK_EQ(s.send_offset, static_cast<std::size_t>(16));
    CHECK_EQ(s.send_length, static_cast<std::size_t>(16));
    CHECK_EQ(s.recv_offset, static_cast<std::size_t>(0));
    CHECK_EQ(s.recv_length, static_cast<std::size_t>(16));

    // rank 1, partner 0: keep_lower=false (bit 0 = 1)
    //   send [0,2)=offset 0 len 16, recv [2,4)=offset 16 len 16
    s = RHEngine::reduce_scatter_step(1, 0, 4, 32);
    CHECK(s.valid);
    CHECK_EQ(s.partner_rank, static_cast<std::size_t>(0));
    CHECK(!s.keep_lower);
    CHECK_EQ(s.send_offset, static_cast<std::size_t>(0));
    CHECK_EQ(s.send_length, static_cast<std::size_t>(16));
    CHECK_EQ(s.recv_offset, static_cast<std::size_t>(16));
    CHECK_EQ(s.recv_length, static_cast<std::size_t>(16));

    // step 1: partner = rank XOR 2
    //   rank 0, partner 2: keep_lower=true (bit 1 = 0)
    //     active [0,2), mid=1. send [1,2)=offset 8 len 8, recv [0,1)=offset 0 len 8
    s = RHEngine::reduce_scatter_step(0, 1, 4, 32);
    CHECK(s.valid);
    CHECK_EQ(s.partner_rank, static_cast<std::size_t>(2));
    CHECK(s.keep_lower);
    CHECK_EQ(s.send_offset, static_cast<std::size_t>(8));
    CHECK_EQ(s.send_length, static_cast<std::size_t>(8));
    CHECK_EQ(s.recv_offset, static_cast<std::size_t>(0));
    CHECK_EQ(s.recv_length, static_cast<std::size_t>(8));

    // rank 1, partner 3: keep_lower=true (bit 1 of rank 1 (01) = 0)
    //   After step 0: rank 1 kept upper [2,4) (bit 0 = 1)
    //   active [2,4), active_size=2, mid=3
    //   keep lower [2,3): send upper [3,4)=offset 24 len 8, recv [2,3)=offset 16 len 8
    s = RHEngine::reduce_scatter_step(1, 1, 4, 32);
    CHECK(s.valid);
    CHECK_EQ(s.partner_rank, static_cast<std::size_t>(3));
    CHECK(s.keep_lower);
    CHECK_EQ(s.send_offset, static_cast<std::size_t>(24));
    CHECK_EQ(s.send_length, static_cast<std::size_t>(8));
    CHECK_EQ(s.recv_offset, static_cast<std::size_t>(16));
    CHECK_EQ(s.recv_length, static_cast<std::size_t>(8));
}

// ============================================================================
// TEST 6: reduce_scatter_result_idx（bit reversal）
// ============================================================================
static void test_reduce_scatter_result_idx() {
    std::printf("[test] reduce_scatter_result_idx (bit reversal)...\n");

    // N=4 (2 bits)
    CHECK_EQ(RHEngine::reduce_scatter_result_idx(0, 4), static_cast<std::size_t>(0));  // 00→00
    CHECK_EQ(RHEngine::reduce_scatter_result_idx(1, 4), static_cast<std::size_t>(2));  // 01→10
    CHECK_EQ(RHEngine::reduce_scatter_result_idx(2, 4), static_cast<std::size_t>(1));  // 10→01
    CHECK_EQ(RHEngine::reduce_scatter_result_idx(3, 4), static_cast<std::size_t>(3));  // 11→11

    // N=8 (3 bits)
    CHECK_EQ(RHEngine::reduce_scatter_result_idx(0, 8), static_cast<std::size_t>(0));  // 000→000
    CHECK_EQ(RHEngine::reduce_scatter_result_idx(1, 8), static_cast<std::size_t>(4));  // 001→100
    CHECK_EQ(RHEngine::reduce_scatter_result_idx(2, 8), static_cast<std::size_t>(2));  // 010→010
    CHECK_EQ(RHEngine::reduce_scatter_result_idx(3, 8), static_cast<std::size_t>(6));  // 011→110
    CHECK_EQ(RHEngine::reduce_scatter_result_idx(4, 8), static_cast<std::size_t>(1));  // 100→001
    CHECK_EQ(RHEngine::reduce_scatter_result_idx(5, 8), static_cast<std::size_t>(5));  // 101→101
    CHECK_EQ(RHEngine::reduce_scatter_result_idx(6, 8), static_cast<std::size_t>(3));  // 110→011
    CHECK_EQ(RHEngine::reduce_scatter_result_idx(7, 8), static_cast<std::size_t>(7));  // 111→111
}

// ============================================================================
// TEST 7: all_gather_step 通信信息
// ============================================================================
static void test_all_gather_step() {
    std::printf("[test] all_gather_step...\n");

    // N=4, msg=32, chunk_size=8
    // After ReduceScatter: rank 0 has chunk 0 (offset 0, 8 bytes)
    // AllGather step 0: rev_step = 1, partner = rank XOR 2
    //   rank 0, partner 2: is_upper=false (bit 1 = 0)
    //     active_start=0, active_size=1
    //     send [0, 8), recv [8, 16)
    auto s = RHEngine::all_gather_step(0, 0, 4, 32);
    CHECK(s.valid);
    CHECK_EQ(s.partner_rank, static_cast<std::size_t>(2));
    CHECK_EQ(s.send_offset, static_cast<std::size_t>(0));
    CHECK_EQ(s.send_length, static_cast<std::size_t>(8));
    CHECK_EQ(s.recv_offset, static_cast<std::size_t>(8));
    CHECK_EQ(s.recv_length, static_cast<std::size_t>(8));

    // AllGather step 1: rev_step = 0, partner = rank XOR 1
    //   rank 0, partner 1: is_upper=false (bit 0 = 0)
    //     active_start=0, active_size=2
    //     send [0, 16), recv [16, 32)
    s = RHEngine::all_gather_step(0, 1, 4, 32);
    CHECK(s.valid);
    CHECK_EQ(s.partner_rank, static_cast<std::size_t>(1));
    CHECK_EQ(s.send_offset, static_cast<std::size_t>(0));
    CHECK_EQ(s.send_length, static_cast<std::size_t>(16));
    CHECK_EQ(s.recv_offset, static_cast<std::size_t>(16));
    CHECK_EQ(s.recv_length, static_cast<std::size_t>(16));
}

// ============================================================================
// TEST 8: all_reduce_step 统一接口
// ============================================================================
static void test_all_reduce_step() {
    std::printf("[test] all_reduce_step (unified)...\n");

    // N=4, total_steps=4
    // step 0,1 = ReduceScatter; step 2,3 = AllGather
    auto s0 = RHEngine::all_reduce_step(0, 0, 4, 32);
    auto rs0 = RHEngine::reduce_scatter_step(0, 0, 4, 32);
    CHECK(s0.valid);
    CHECK_EQ(s0.partner_rank, rs0.partner_rank);
    CHECK_EQ(s0.send_offset, rs0.send_offset);

    auto s2 = RHEngine::all_reduce_step(0, 2, 4, 32);
    auto ag0 = RHEngine::all_gather_step(0, 0, 4, 32);
    CHECK(s2.valid);
    CHECK_EQ(s2.partner_rank, ag0.partner_rank);
    CHECK_EQ(s2.send_offset, ag0.send_offset);
}

// ============================================================================
// TEST 9: N=4 完整 ReduceScatter 模拟
// ============================================================================
static void test_reduce_scatter_n4_simulation() {
    std::printf("[test] N=4 RecursiveHalving ReduceScatter simulation...\n");

    const std::size_t N = 4;
    const std::size_t msg_size = 32;  // 4 chunks × 8 bytes
    const std::size_t chunk_size = msg_size / N;  // 8

    // 每节点 32 字节数据（4 个 uint64）
    // node 0: [1, 2, 3, 4]
    // node 1: [10, 20, 30, 40]
    // node 2: [100, 200, 300, 400]
    // node 3: [1000, 2000, 3000, 4000]
    // SUM: [1111, 2222, 3333, 4444]
    std::vector<std::vector<std::uint8_t>> data(N);
    for (std::size_t i = 0; i < N; ++i) {
        data[i].resize(msg_size, 0);
        for (std::size_t j = 0; j < N; ++j) {
            std::uint64_t val = (i + 1) * (j + 1) * (j == 0 ? 1 : (j == 1 ? 2 : (j == 2 ? 3 : 4))) / (j + 1);
            // Simplified: node i, chunk j = (i+1) * (j+1) * factor
        }
    }
    // Direct assignment for clarity
    auto set_chunk = [&](std::size_t node, std::size_t chunk, std::uint64_t val) {
        std::memcpy(data[node].data() + chunk * chunk_size, &val, 8);
    };
    set_chunk(0, 0, 1); set_chunk(0, 1, 2); set_chunk(0, 2, 3); set_chunk(0, 3, 4);
    set_chunk(1, 0, 10); set_chunk(1, 1, 20); set_chunk(1, 2, 30); set_chunk(1, 3, 40);
    set_chunk(2, 0, 100); set_chunk(2, 1, 200); set_chunk(2, 2, 300); set_chunk(2, 3, 400);
    set_chunk(3, 0, 1000); set_chunk(3, 1, 2000); set_chunk(3, 2, 3000); set_chunk(3, 3, 4000);

    std::size_t steps = RHEngine::reduce_scatter_steps(N);
    CHECK_EQ(steps, static_cast<std::size_t>(2));

    for (std::size_t step = 0; step < steps; ++step) {
        // 收集所有发送
        std::vector<std::vector<std::uint8_t>> send_buf(N);
        std::vector<RHStepInfo> infos(N);
        for (std::size_t rank = 0; rank < N; ++rank) {
            auto info = RHEngine::reduce_scatter_step(rank, step, N, msg_size);
            infos[rank] = info;
            send_buf[rank].assign(data[rank].begin() + info.send_offset,
                                   data[rank].begin() + info.send_offset + info.send_length);
        }
        // 执行接收并规约
        for (std::size_t rank = 0; rank < N; ++rank) {
            std::size_t partner = infos[rank].partner_rank;
            // 接收 partner 发来的数据，规约到 recv_offset
            reduce_sum_inplace(data[rank].data() + infos[rank].recv_offset,
                               send_buf[partner].data(),
                               infos[rank].recv_length);
        }
    }

    // 验证：每节点拥有 result_idx 对应的 chunk
    // rank 0 → chunk 0 (SUM=1111)
    // rank 1 → chunk 2 (SUM=3333)
    // rank 2 → chunk 1 (SUM=2222)
    // rank 3 → chunk 3 (SUM=4444)
    std::uint64_t expected[4] = {1111, 2222, 3333, 4444};

    for (std::size_t rank = 0; rank < N; ++rank) {
        std::size_t idx = RHEngine::reduce_scatter_result_idx(rank, N);
        std::uint64_t val = read_u64(data[rank].data() + idx * chunk_size);
        CHECK_EQ(val, expected[idx]);
    }
}

// ============================================================================
// TEST 10: N=8 完整 ReduceScatter 模拟
// ============================================================================
static void test_reduce_scatter_n8_simulation() {
    std::printf("[test] N=8 RecursiveHalving ReduceScatter simulation...\n");

    const std::size_t N = 8;
    const std::size_t msg_size = 64;  // 8 chunks × 8 bytes
    const std::size_t chunk_size = msg_size / N;  // 8

    std::vector<std::vector<std::uint8_t>> data(N, std::vector<std::uint8_t>(msg_size, 0));
    // node i, chunk j = (i+1) * (j+1)
    for (std::size_t i = 0; i < N; ++i) {
        for (std::size_t j = 0; j < N; ++j) {
            std::uint64_t val = (i + 1) * (j + 1);
            std::memcpy(data[i].data() + j * chunk_size, &val, 8);
        }
    }
    // SUM chunk j = (1+2+...+8) * (j+1) = 36 * (j+1)

    std::size_t steps = RHEngine::reduce_scatter_steps(N);
    CHECK_EQ(steps, static_cast<std::size_t>(3));

    for (std::size_t step = 0; step < steps; ++step) {
        std::vector<std::vector<std::uint8_t>> send_buf(N);
        std::vector<RHStepInfo> infos(N);
        for (std::size_t rank = 0; rank < N; ++rank) {
            auto info = RHEngine::reduce_scatter_step(rank, step, N, msg_size);
            infos[rank] = info;
            send_buf[rank].assign(data[rank].begin() + info.send_offset,
                                   data[rank].begin() + info.send_offset + info.send_length);
        }
        for (std::size_t rank = 0; rank < N; ++rank) {
            std::size_t partner = infos[rank].partner_rank;
            reduce_sum_inplace(data[rank].data() + infos[rank].recv_offset,
                               send_buf[partner].data(),
                               infos[rank].recv_length);
        }
    }

    // 验证
    for (std::size_t rank = 0; rank < N; ++rank) {
        std::size_t idx = RHEngine::reduce_scatter_result_idx(rank, N);
        std::uint64_t val = read_u64(data[rank].data() + idx * chunk_size);
        std::uint64_t exp = 36 * (idx + 1);
        CHECK_EQ(val, exp);
    }
}

// ============================================================================
// TEST 11: N=4 完整 AllReduce 模拟（ReduceScatter + AllGather）
// ============================================================================
static void test_all_reduce_n4_simulation() {
    std::printf("[test] N=4 RecursiveHalving AllReduce full simulation...\n");

    const std::size_t N = 4;
    const std::size_t msg_size = 32;
    const std::size_t chunk_size = msg_size / N;

    std::vector<std::vector<std::uint8_t>> data(N, std::vector<std::uint8_t>(msg_size, 0));
    auto set_chunk = [&](std::size_t node, std::size_t chunk, std::uint64_t val) {
        std::memcpy(data[node].data() + chunk * chunk_size, &val, 8);
    };
    set_chunk(0, 0, 1); set_chunk(0, 1, 2); set_chunk(0, 2, 3); set_chunk(0, 3, 4);
    set_chunk(1, 0, 10); set_chunk(1, 1, 20); set_chunk(1, 2, 30); set_chunk(1, 3, 40);
    set_chunk(2, 0, 100); set_chunk(2, 1, 200); set_chunk(2, 2, 300); set_chunk(2, 3, 400);
    set_chunk(3, 0, 1000); set_chunk(3, 1, 2000); set_chunk(3, 2, 3000); set_chunk(3, 3, 4000);

    std::size_t total = RHEngine::total_steps(N);
    CHECK_EQ(total, static_cast<std::size_t>(4));

    for (std::size_t step = 0; step < total; ++step) {
        auto phase = RHEngine::phase_of(step, N);
        std::vector<std::vector<std::uint8_t>> send_buf(N);
        std::vector<RHStepInfo> infos(N);

        for (std::size_t rank = 0; rank < N; ++rank) {
            RHStepInfo info;
            if (phase == RHPhase::ReduceScatter) {
                info = RHEngine::reduce_scatter_step(rank, step, N, msg_size);
            } else {
                info = RHEngine::all_gather_step(rank, step - RHEngine::reduce_scatter_steps(N), N, msg_size);
            }
            infos[rank] = info;
            send_buf[rank].assign(data[rank].begin() + info.send_offset,
                                   data[rank].begin() + info.send_offset + info.send_length);
        }

        for (std::size_t rank = 0; rank < N; ++rank) {
            std::size_t partner = infos[rank].partner_rank;
            if (phase == RHPhase::ReduceScatter) {
                // 规约
                reduce_sum_inplace(data[rank].data() + infos[rank].recv_offset,
                                   send_buf[partner].data(),
                                   infos[rank].recv_length);
            } else {
                // AllGather：直接复制（不规约）
                std::memcpy(data[rank].data() + infos[rank].recv_offset,
                           send_buf[partner].data(),
                           infos[rank].recv_length);
            }
        }
    }

    // 验证：所有节点拥有 [1111, 2222, 3333, 4444]
    for (std::size_t rank = 0; rank < N; ++rank) {
        CHECK_EQ(read_u64(data[rank].data() + 0), static_cast<std::uint64_t>(1111));
        CHECK_EQ(read_u64(data[rank].data() + 8), static_cast<std::uint64_t>(2222));
        CHECK_EQ(read_u64(data[rank].data() + 16), static_cast<std::uint64_t>(3333));
        CHECK_EQ(read_u64(data[rank].data() + 24), static_cast<std::uint64_t>(4444));
    }
}

// ============================================================================
// TEST 12: 通信量预估
// ============================================================================
static void test_communication_volume() {
    std::printf("[test] communication volume...\n");

    // all_reduce_bytes_per_node = msg × (1 - 1/N)
    CHECK_EQ(RHEngine::all_reduce_bytes_per_node(4, 1024), static_cast<std::size_t>(768));   // 1024 - 256
    CHECK_EQ(RHEngine::all_reduce_bytes_per_node(8, 1024), static_cast<std::size_t>(896));   // 1024 - 128
    CHECK_EQ(RHEngine::all_reduce_bytes_per_node(2, 1024), static_cast<std::size_t>(512));   // 1024 - 512

    // reduce_scatter = all_reduce / 2
    CHECK_EQ(RHEngine::reduce_scatter_bytes_per_node(4, 1024), static_cast<std::size_t>(384));
    CHECK_EQ(RHEngine::all_gather_bytes_per_node(4, 1024), static_cast<std::size_t>(384));
}

// ============================================================================
// TEST 13: 步信息不变量 — send_length 递减
// ============================================================================
static void test_send_length_decreasing() {
    std::printf("[test] invariant: send_length decreasing in ReduceScatter...\n");

    const std::size_t N = 8;
    const std::size_t msg_size = 64;
    std::size_t prev_len = msg_size;

    for (std::size_t step = 0; step < RHEngine::reduce_scatter_steps(N); ++step) {
        auto info = RHEngine::reduce_scatter_step(0, step, N, msg_size);
        CHECK(info.valid);
        CHECK(info.send_length < prev_len);  // 严格递减
        CHECK_EQ(info.send_length, info.recv_length);  // 发送=接收
        prev_len = info.send_length;
    }
}

// ============================================================================
// TEST 14: 步信息不变量 — AllGather send_length 递增
// ============================================================================
static void test_send_length_increasing_allgather() {
    std::printf("[test] invariant: send_length increasing in AllGather...\n");

    const std::size_t N = 8;
    const std::size_t msg_size = 64;
    std::size_t prev_len = 0;

    for (std::size_t step = 0; step < RHEngine::all_gather_steps(N); ++step) {
        auto info = RHEngine::all_gather_step(0, step, N, msg_size);
        CHECK(info.valid);
        CHECK(info.send_length > prev_len);  // 严格递增
        CHECK_EQ(info.send_length, info.recv_length);
        prev_len = info.send_length;
    }

    // 最后一步应有 msg/2
    auto last = RHEngine::all_gather_step(0, RHEngine::all_gather_steps(N) - 1, N, msg_size);
    CHECK_EQ(last.send_length, msg_size / 2);
}

// ============================================================================
// TEST 15: 不变量 — partner 互斥（rank 的 partner 的 partner = rank）
// ============================================================================
static void test_partner_symmetry() {
    std::printf("[test] invariant: partner symmetry...\n");

    const std::size_t N = 8;
    const std::size_t msg_size = 64;

    for (std::size_t step = 0; step < RHEngine::reduce_scatter_steps(N); ++step) {
        for (std::size_t rank = 0; rank < N; ++rank) {
            auto info = RHEngine::reduce_scatter_step(rank, step, N, msg_size);
            auto partner_info = RHEngine::reduce_scatter_step(info.partner_rank, step, N, msg_size);
            CHECK_EQ(partner_info.partner_rank, rank);  // partner 的 partner = 自己
        }
    }
}

// ============================================================================
// TEST 16: 不变量 — send/recv 范围互补（rank 发送的范围 = partner 接收的范围）
// ============================================================================
static void test_send_recv_complementary() {
    std::printf("[test] invariant: send/recv complementary...\n");

    const std::size_t N = 8;
    const std::size_t msg_size = 64;

    for (std::size_t step = 0; step < RHEngine::reduce_scatter_steps(N); ++step) {
        for (std::size_t rank = 0; rank < N; ++rank) {
            auto info = RHEngine::reduce_scatter_step(rank, step, N, msg_size);
            auto partner_info = RHEngine::reduce_scatter_step(info.partner_rank, step, N, msg_size);
            // rank 发送的范围 = partner 接收的范围
            CHECK_EQ(info.send_offset, partner_info.recv_offset);
            CHECK_EQ(info.send_length, partner_info.recv_length);
            // rank 接收的范围 = partner 发送的范围
            CHECK_EQ(info.recv_offset, partner_info.send_offset);
            CHECK_EQ(info.recv_length, partner_info.send_length);
        }
    }
}

// ============================================================================
// TEST 17: N=2 最小 AllReduce
// ============================================================================
static void test_all_reduce_n2_minimal() {
    std::printf("[test] N=2 minimal AllReduce...\n");

    const std::size_t N = 2;
    const std::size_t msg_size = 16;  // 2 chunks × 8 bytes
    const std::size_t chunk_size = 8;

    std::vector<std::vector<std::uint8_t>> data(N, std::vector<std::uint8_t>(msg_size, 0));
    std::uint64_t v0[] = {5, 10};
    std::uint64_t v1[] = {15, 25};
    std::memcpy(data[0].data(), v0, 16);
    std::memcpy(data[1].data(), v1, 16);
    // SUM = [20, 35]

    std::size_t total = RHEngine::total_steps(N);
    CHECK_EQ(total, static_cast<std::size_t>(2));

    for (std::size_t step = 0; step < total; ++step) {
        auto phase = RHEngine::phase_of(step, N);
        std::vector<std::vector<std::uint8_t>> send_buf(N);
        std::vector<RHStepInfo> infos(N);

        for (std::size_t rank = 0; rank < N; ++rank) {
            RHStepInfo info;
            if (phase == RHPhase::ReduceScatter) {
                info = RHEngine::reduce_scatter_step(rank, step, N, msg_size);
            } else {
                info = RHEngine::all_gather_step(rank, step - RHEngine::reduce_scatter_steps(N), N, msg_size);
            }
            infos[rank] = info;
            send_buf[rank].assign(data[rank].begin() + info.send_offset,
                                   data[rank].begin() + info.send_offset + info.send_length);
        }

        for (std::size_t rank = 0; rank < N; ++rank) {
            std::size_t partner = infos[rank].partner_rank;
            if (phase == RHPhase::ReduceScatter) {
                reduce_sum_inplace(data[rank].data() + infos[rank].recv_offset,
                                   send_buf[partner].data(), infos[rank].recv_length);
            } else {
                std::memcpy(data[rank].data() + infos[rank].recv_offset,
                           send_buf[partner].data(), infos[rank].recv_length);
            }
        }
    }

    CHECK_EQ(read_u64(data[0].data()), static_cast<std::uint64_t>(20));
    CHECK_EQ(read_u64(data[0].data() + 8), static_cast<std::uint64_t>(35));
    CHECK_EQ(read_u64(data[1].data()), static_cast<std::uint64_t>(20));
    CHECK_EQ(read_u64(data[1].data() + 8), static_cast<std::uint64_t>(35));
}

// ============================================================================
// main
// ============================================================================
int main() {
    std::printf("=== RecursiveHalving Engine Unit Tests (P3-D) ===\n\n");

    test_power_of_two_utils();
    test_bit_reverse();
    test_step_counts();
    test_phase_of();
    test_reduce_scatter_step();
    test_reduce_scatter_result_idx();
    test_all_gather_step();
    test_all_reduce_step();
    test_reduce_scatter_n4_simulation();
    test_reduce_scatter_n8_simulation();
    test_all_reduce_n4_simulation();
    test_communication_volume();
    test_send_length_decreasing();
    test_send_length_increasing_allgather();
    test_partner_symmetry();
    test_send_recv_complementary();
    test_all_reduce_n2_minimal();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
