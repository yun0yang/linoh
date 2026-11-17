// test_pe_engine.cpp — v2.2 Phase 3 P3-E PairwiseExchange 算法引擎单元测试
//
// 验证 P3-E 交付物：
//   1. is_power_of_two / pad_to_power_of_two
//   2. total_steps / partner_at_step
//   3. send_chunk_indices / recv_chunk_indices
//   4. held_chunk_indices（持有分片追踪）
//   5. 通信量预估
//   6. N=4 完整 AllToAll 模拟（验证每节点收到正确分片）
//   7. N=8 完整 AllToAll 模拟
//   8. 不变量：send/recv 互补（rank 发送 = partner 接收）
//   9. 不变量：每步交换后持有的分片来源翻倍
//  10. N=2 最小 AllToAll

#include "linoh/multimodal/pe_engine.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
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

// ============================================================================
// 辅助函数
// ============================================================================

/// uint64 转字节（小端序）
static void set_u64(std::uint8_t* dst, std::uint64_t val) {
    std::memcpy(dst, &val, 8);
}

static std::uint64_t read_u64(const std::uint8_t* src) {
    std::uint64_t val;
    std::memcpy(&val, src, 8);
    return val;
}

/// 将 vector 转为 set 便于比较
static std::set<std::size_t> to_set(const std::vector<std::size_t>& v) {
    return std::set<std::size_t>(v.begin(), v.end());
}

// ============================================================================
// TEST 1: is_power_of_two / pad_to_power_of_two
// ============================================================================
static void test_power_of_two_utils() {
    std::printf("[test] is_power_of_two / pad_to_power_of_two...\n");

    CHECK(PEEngine::is_power_of_two(1));
    CHECK(PEEngine::is_power_of_two(2));
    CHECK(PEEngine::is_power_of_two(4));
    CHECK(PEEngine::is_power_of_two(8));
    CHECK(!PEEngine::is_power_of_two(0));
    CHECK(!PEEngine::is_power_of_two(3));
    CHECK(!PEEngine::is_power_of_two(6));

    CHECK_EQ(PEEngine::pad_to_power_of_two(1), static_cast<std::size_t>(1));
    CHECK_EQ(PEEngine::pad_to_power_of_two(3), static_cast<std::size_t>(4));
    CHECK_EQ(PEEngine::pad_to_power_of_two(5), static_cast<std::size_t>(8));
    CHECK_EQ(PEEngine::pad_to_power_of_two(8), static_cast<std::size_t>(8));
}

// ============================================================================
// TEST 2: total_steps / partner_at_step
// ============================================================================
static void test_steps_and_partner() {
    std::printf("[test] total_steps / partner_at_step...\n");

    CHECK_EQ(PEEngine::total_steps(1), static_cast<std::size_t>(0));
    CHECK_EQ(PEEngine::total_steps(2), static_cast<std::size_t>(1));
    CHECK_EQ(PEEngine::total_steps(4), static_cast<std::size_t>(2));
    CHECK_EQ(PEEngine::total_steps(8), static_cast<std::size_t>(3));

    // partner = rank XOR (1 << step)
    CHECK_EQ(PEEngine::partner_at_step(0, 0), static_cast<std::size_t>(1));
    CHECK_EQ(PEEngine::partner_at_step(1, 0), static_cast<std::size_t>(0));
    CHECK_EQ(PEEngine::partner_at_step(0, 1), static_cast<std::size_t>(2));
    CHECK_EQ(PEEngine::partner_at_step(2, 1), static_cast<std::size_t>(0));
    CHECK_EQ(PEEngine::partner_at_step(5, 2), static_cast<std::size_t>(1));  // 5 XOR 4 = 1
}

// ============================================================================
// TEST 3: send_chunk_indices / recv_chunk_indices
// ============================================================================
static void test_send_recv_chunk_indices() {
    std::printf("[test] send_chunk_indices / recv_chunk_indices...\n");

    // N=4, rank 0 (00)
    // step 0: partner=1, send dest bit0=1 → {1,3}, recv dest bit0=0 → {0,2}
    auto send0 = PEEngine::send_chunk_indices(0, 0, 4);
    CHECK_EQ(send0.size(), static_cast<std::size_t>(2));
    CHECK((to_set(send0) == std::set<std::size_t>{1, 3}));

    auto recv0 = PEEngine::recv_chunk_indices(0, 0, 4);
    CHECK_EQ(recv0.size(), static_cast<std::size_t>(2));
    CHECK((to_set(recv0) == std::set<std::size_t>{0, 2}));

    // step 1: partner=2, send dest bit1=1 & bit0=0 → {2}, recv dest bit1=0 & bit0=0 → {0}
    auto send1 = PEEngine::send_chunk_indices(0, 1, 4);
    CHECK_EQ(send1.size(), static_cast<std::size_t>(1));
    CHECK_EQ(send1[0], static_cast<std::size_t>(2));

    auto recv1 = PEEngine::recv_chunk_indices(0, 1, 4);
    CHECK_EQ(recv1.size(), static_cast<std::size_t>(1));
    CHECK_EQ(recv1[0], static_cast<std::size_t>(0));

    // N=8, rank 0 (000)
    // step 0: send dest bit0=1 → {1,3,5,7}, recv → {0,2,4,6}
    auto s8_0 = PEEngine::send_chunk_indices(0, 0, 8);
    CHECK_EQ(s8_0.size(), static_cast<std::size_t>(4));
    CHECK((to_set(s8_0) == std::set<std::size_t>{1, 3, 5, 7}));

    // step 1: send dest bit1=1 & bit0=0 → {2,6}, recv → {0,4}
    auto s8_1 = PEEngine::send_chunk_indices(0, 1, 8);
    CHECK_EQ(s8_1.size(), static_cast<std::size_t>(2));
    CHECK((to_set(s8_1) == std::set<std::size_t>{2, 6}));

    // step 2: send dest bit2=1 & bits0-1=0 → {4}, recv → {0}
    auto s8_2 = PEEngine::send_chunk_indices(0, 2, 8);
    CHECK_EQ(s8_2.size(), static_cast<std::size_t>(1));
    CHECK_EQ(s8_2[0], static_cast<std::size_t>(4));
}

// ============================================================================
// TEST 4: held_chunk_indices
// ============================================================================
static void test_held_chunk_indices() {
    std::printf("[test] held_chunk_indices...\n");

    // 初始状态（step_after = SIZE_MAX）：持有所有 dest
    auto init = PEEngine::held_chunk_indices(0, static_cast<std::size_t>(-1), 4);
    CHECK_EQ(init.size(), static_cast<std::size_t>(4));
    CHECK((to_set(init) == std::set<std::size_t>{0, 1, 2, 3}));

    // step_after = 0：持有 dest bit0 = rank's bit0
    // rank 0: dest bit0=0 → {0, 2}
    auto h0 = PEEngine::held_chunk_indices(0, 0, 4);
    CHECK_EQ(h0.size(), static_cast<std::size_t>(2));
    CHECK((to_set(h0) == std::set<std::size_t>{0, 2}));

    // rank 1: dest bit0=1 → {1, 3}
    auto h1 = PEEngine::held_chunk_indices(1, 0, 4);
    CHECK_EQ(h1.size(), static_cast<std::size_t>(2));
    CHECK((to_set(h1) == std::set<std::size_t>{1, 3}));

    // step_after = 1 (final for N=4): rank 0 → {0}
    auto h2 = PEEngine::held_chunk_indices(0, 1, 4);
    CHECK_EQ(h2.size(), static_cast<std::size_t>(1));
    CHECK_EQ(h2[0], static_cast<std::size_t>(0));

    // N=8, rank 3 (011), step_after=1: bits 0-1 = 11 → dest {3, 7}
    auto h8 = PEEngine::held_chunk_indices(3, 1, 8);
    CHECK_EQ(h8.size(), static_cast<std::size_t>(2));
    CHECK((to_set(h8) == std::set<std::size_t>{3, 7}));
}

// ============================================================================
// TEST 5: 通信量预估
// ============================================================================
static void test_communication_volume() {
    std::printf("[test] communication volume...\n");

    // all_to_all_bytes_per_node = (N-1) * msg / N
    CHECK_EQ(PEEngine::all_to_all_bytes_per_node(4, 1024), static_cast<std::size_t>(768));  // 3*256
    CHECK_EQ(PEEngine::all_to_all_bytes_per_node(8, 1024), static_cast<std::size_t>(896));  // 7*128
    CHECK_EQ(PEEngine::all_to_all_bytes_per_node(2, 1024), static_cast<std::size_t>(512));  // 1*512

    // step_bytes: step s = N/2^(s+1) * chunk_size
    CHECK_EQ(PEEngine::step_bytes(0, 4, 1024), static_cast<std::size_t>(512));  // 2*256
    CHECK_EQ(PEEngine::step_bytes(1, 4, 1024), static_cast<std::size_t>(256));  // 1*256
    CHECK_EQ(PEEngine::step_bytes(0, 8, 1024), static_cast<std::size_t>(512));  // 4*128
    CHECK_EQ(PEEngine::step_bytes(2, 8, 1024), static_cast<std::size_t>(128));  // 1*128
}

// ============================================================================
// AllToAll 模拟辅助函数（多源集合追踪）
// ============================================================================
//
// PairwiseExchange AllToAll 语义：每节点 i 持有 N 份分片 C[i][0..N-1]，
// C[i][j] 是节点 i 发给节点 j 的数据。最终节点 j 拥有 [C[0][j], ..., C[N-1][j]]。
//
// 关键点：算法每步后，rank 对持有的每个 dest 拥有**多个来源**的 chunk
// （step 0 后 2 个来源，step s 后 2^(s+1) 个来源），因此模拟必须用集合追踪来源，
// 不能用单值覆盖（原测试的 bug：node_data[rank][dest] 单值会丢失多源数据）。
//
// held[rank][dest] = rank 当前持有的、目标为 dest 的 chunk 来源集合
// 初始: held[rank][dest] = {rank}（仅自己的 chunk）
// 每步: 对 recv dest 合并 partner 的来源；对 send dest 清空（已发出）
// 终态: held[rank][rank] = {0,1,...,N-1}（所有来源），其他 dest 为空
//
// 同时追踪值（source -> value）以验证数据正确路由。
static bool simulate_all_to_all(std::size_t N,
                                 std::uint64_t base,
                                 std::size_t &out_steps,
                                 std::size_t &out_send_recv_complementary_fails) {
    // held_src[rank][dest] = 来源集合
    std::vector<std::vector<std::set<std::size_t>>> held_src(N,
        std::vector<std::set<std::size_t>>(N));
    // held_val[rank][dest] = source -> value 映射（验证数据完整性）
    std::vector<std::vector<std::map<std::size_t, std::uint64_t>>> held_val(N,
        std::vector<std::map<std::size_t, std::uint64_t>>(N));

    auto make_value = [&](std::size_t src, std::size_t dest) {
        return (src + 1) * base + dest;
    };

    // 初始化: rank 持有自己的 chunk for every dest
    for (std::size_t rank = 0; rank < N; ++rank) {
        for (std::size_t dest = 0; dest < N; ++dest) {
            held_src[rank][dest].insert(rank);
            held_val[rank][dest][rank] = make_value(rank, dest);
        }
    }

    out_steps = PEEngine::total_steps(N);
    out_send_recv_complementary_fails = 0;

    for (std::size_t step = 0; step < out_steps; ++step) {
        // 快照: 每节点本步要发送的 (dest -> {source -> value})
        std::vector<std::vector<std::map<std::size_t, std::uint64_t>>> snap(N,
            std::vector<std::map<std::size_t, std::uint64_t>>(N));
        for (std::size_t rank = 0; rank < N; ++rank) {
            auto dests = PEEngine::send_chunk_indices(rank, step, N);
            for (std::size_t d : dests) snap[rank][d] = held_val[rank][d];
        }

        // 执行交换
        for (std::size_t rank = 0; rank < N; ++rank) {
            std::size_t partner = PEEngine::partner_at_step(rank, step);
            auto recv_dests = PEEngine::recv_chunk_indices(rank, step, N);
            auto partner_send_dests = PEEngine::send_chunk_indices(partner, step, N);

            // 不变量: rank 的 recv dests == partner 的 send dests
            if (to_set(recv_dests) != to_set(partner_send_dests)) {
                ++out_send_recv_complementary_fails;
            }

            // 接收: 对 recv_dests 中的每个 dest，合并 partner 的来源和值
            for (std::size_t d : recv_dests) {
                for (const auto &kv : snap[partner][d]) {
                    held_src[rank][d].insert(kv.first);
                    held_val[rank][d][kv.first] = kv.second;
                }
            }
            // 发送: 清空 send dests（rank 不再持有这些 dest 的 chunk）
            auto send_dests = PEEngine::send_chunk_indices(rank, step, N);
            for (std::size_t d : send_dests) {
                held_src[rank][d].clear();
                held_val[rank][d].clear();
            }
        }
    }

    // 验证终态: rank 持有所有 N 个来源 for dest=rank，值正确；其他 dest 为空
    for (std::size_t rank = 0; rank < N; ++rank) {
        if (held_src[rank][rank].size() != N) return false;
        if (held_val[rank][rank].size() != N) return false;
        for (std::size_t s = 0; s < N; ++s) {
            if (held_src[rank][rank].count(s) == 0) return false;
            auto it = held_val[rank][rank].find(s);
            if (it == held_val[rank][rank].end()) return false;
            if (it->second != make_value(s, rank)) return false;
        }
        for (std::size_t dest = 0; dest < N; ++dest) {
            if (dest != rank) {
                if (!held_src[rank][dest].empty()) return false;
                if (!held_val[rank][dest].empty()) return false;
            }
        }
    }
    return true;
}

// ============================================================================
// TEST 6: N=4 完整 AllToAll 模拟（多源追踪）
// ============================================================================
static void test_all_to_all_n4_simulation() {
    std::printf("[test] N=4 PairwiseExchange AllToAll simulation...\n");

    const std::size_t N = 4;
    std::size_t steps = 0, comp_fails = 0;
    bool ok = simulate_all_to_all(N, 100, steps, comp_fails);

    CHECK_EQ(steps, PEEngine::total_steps(N));
    CHECK_EQ(steps, static_cast<std::size_t>(2));
    CHECK_EQ(comp_fails, static_cast<std::size_t>(0));  // send/recv 互补不变量
    CHECK(ok);
}

// ============================================================================
// TEST 7: N=8 完整 AllToAll 模拟（多源追踪）
// ============================================================================
static void test_all_to_all_n8_simulation() {
    std::printf("[test] N=8 PairwiseExchange AllToAll simulation...\n");

    const std::size_t N = 8;
    std::size_t steps = 0, comp_fails = 0;
    bool ok = simulate_all_to_all(N, 1000, steps, comp_fails);

    CHECK_EQ(steps, PEEngine::total_steps(N));
    CHECK_EQ(steps, static_cast<std::size_t>(3));
    CHECK_EQ(comp_fails, static_cast<std::size_t>(0));
    CHECK(ok);
}

// ============================================================================
// TEST 8: 不变量 — send/recv 互补（rank 发送 = partner 接收）
// ============================================================================
static void test_send_recv_complementary() {
    std::printf("[test] invariant: send/recv complementary...\n");

    for (std::size_t N : {2, 4, 8}) {
        std::size_t steps = PEEngine::total_steps(N);
        for (std::size_t step = 0; step < steps; ++step) {
            for (std::size_t rank = 0; rank < N; ++rank) {
                std::size_t partner = PEEngine::partner_at_step(rank, step);
                auto send = PEEngine::send_chunk_indices(rank, step, N);
                auto partner_recv = PEEngine::recv_chunk_indices(partner, step, N);
                CHECK(to_set(send) == to_set(partner_recv));

                auto recv = PEEngine::recv_chunk_indices(rank, step, N);
                auto partner_send = PEEngine::send_chunk_indices(partner, step, N);
                CHECK(to_set(recv) == to_set(partner_send));
            }
        }
    }
}

// ============================================================================
// TEST 9: 不变量 — 每步 send + recv = 当前持有
// ============================================================================
static void test_send_plus_recv_equals_held() {
    std::printf("[test] invariant: send + recv = held (before step)...\n");

    for (std::size_t N : {2, 4, 8}) {
        std::size_t steps = PEEngine::total_steps(N);
        for (std::size_t step = 0; step < steps; ++step) {
            for (std::size_t rank = 0; rank < N; ++rank) {
                auto send = PEEngine::send_chunk_indices(rank, step, N);
                auto recv = PEEngine::recv_chunk_indices(rank, step, N);
                // step 之前持有的分片
                std::size_t prev_step = (step == 0) ? static_cast<std::size_t>(-1) : step - 1;
                auto held = PEEngine::held_chunk_indices(rank, prev_step, N);

                std::set<std::size_t> combined;
                for (auto d : send) combined.insert(d);
                for (auto d : recv) combined.insert(d);
                CHECK(combined == to_set(held));
                // send 和 recv 不相交
                std::set<std::size_t> send_set = to_set(send);
                std::set<std::size_t> recv_set = to_set(recv);
                for (auto d : send_set) {
                    CHECK(recv_set.find(d) == recv_set.end());
                }
            }
        }
    }
}

// ============================================================================
// TEST 10: N=2 最小 AllToAll（多源追踪）
// ============================================================================
static void test_all_to_all_n2_minimal() {
    std::printf("[test] N=2 minimal AllToAll...\n");

    const std::size_t N = 2;
    std::size_t steps = 0, comp_fails = 0;
    bool ok = simulate_all_to_all(N, 10, steps, comp_fails);

    CHECK_EQ(steps, PEEngine::total_steps(N));
    CHECK_EQ(steps, static_cast<std::size_t>(1));
    CHECK_EQ(comp_fails, static_cast<std::size_t>(0));
    CHECK(ok);

    // 额外验证 N=2 的具体值（base=10）:
    //   初始: node0 持有 [10, 11], node1 持有 [20, 21]
    //   终态: node0 持有 [10 (from 0), 20 (from 1)], node1 持有 [11 (from 0), 21 (from 1)]
    // simulate_all_to_all 内部已验证 held_val[rank][rank] 的值，此处通过返回值确认
}

// ============================================================================
// TEST 11: 不变量 — 最终每节点只持有自己的目标分片
// ============================================================================
static void test_final_held_is_own_dest() {
    std::printf("[test] invariant: final held = own dest only...\n");

    for (std::size_t N : {2, 4, 8}) {
        std::size_t last_step = PEEngine::total_steps(N) - 1;
        for (std::size_t rank = 0; rank < N; ++rank) {
            auto held = PEEngine::held_chunk_indices(rank, last_step, N);
            CHECK_EQ(held.size(), static_cast<std::size_t>(1));
            CHECK_EQ(held[0], rank);  // 最终只持有自己的 dest
        }
    }
}

// ============================================================================
// main
// ============================================================================
int main() {
    std::printf("=== PairwiseExchange Engine Unit Tests (P3-E) ===\n\n");

    test_power_of_two_utils();
    test_steps_and_partner();
    test_send_recv_chunk_indices();
    test_held_chunk_indices();
    test_communication_volume();
    test_all_to_all_n4_simulation();
    test_all_to_all_n8_simulation();
    test_send_recv_complementary();
    test_send_plus_recv_equals_held();
    test_all_to_all_n2_minimal();
    test_final_held_is_own_dest();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
