// test_ring_engine.cpp — Ring 算法引擎单元测试（v2.2 Phase 3 / P3-B）
//
// 验证 P3-B 交付物：
//   1. build_ring 拓扑正确性（next/prev 邻居）
//   2. rank_of 节点定位
//   3. total_steps / phase_of 阶段判定
//   4. compute_chunk_index AllReduce 分片索引（阶段 1 + 阶段 2）
//   5. 索引匹配不变量：sender send_idx == receiver recv_idx
//   6. all_gather_chunk_index / reduce_scatter_chunk_index
//   7. N=4 完整 AllReduce 模拟（验证最终结果正确性）
//   8. 非二次幂 N=6 场景
//   9. 通信量预估
//
// 测试策略：纯算法验证，不依赖网络 IO，通过模拟分片收发验证最终规约结果

#include "linoh/multimodal/ring_engine.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <numeric>
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

#define CHECK_GE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a >= _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s >= %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ============================================================================
// 辅助函数
// ============================================================================

/// 构造 N 个节点的 bit position 列表（bit 0, 1, 2, ...）
static std::vector<std::uint64_t> make_participants(std::size_t N) {
    std::vector<std::uint64_t> bits(N);
    for (std::size_t i = 0; i < N; ++i) bits[i] = static_cast<std::uint64_t>(1) << i;
    return bits;
}

/// 将数据分 N 份（等分）
static std::vector<std::vector<std::uint8_t>>
split_chunks(const std::vector<std::uint8_t>& data, std::size_t N) {
    std::vector<std::vector<std::uint8_t>> chunks(N);
    std::size_t chunk_size = data.size() / N;
    for (std::size_t i = 0; i < N; ++i) {
        chunks[i].assign(data.begin() + i * chunk_size,
                         data.begin() + (i + 1) * chunk_size);
    }
    return chunks;
}

/// uint64 数组转字节（小端序）
static std::vector<std::uint8_t>
make_u64_array(std::initializer_list<std::uint64_t> vals) {
    std::vector<std::uint8_t> data;
    data.reserve(vals.size() * 8);
    for (auto v : vals) {
        for (int i = 0; i < 8; ++i) {
            data.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
        }
    }
    return data;
}

/// 从 vector<uint64> 构造字节数组（小端序）—— 前向声明，定义在后方
static std::vector<std::uint8_t>
make_u64_array_vals(const std::vector<std::uint64_t>& vals);

/// RingPhase 相等比较辅助函数（避免与 RingEngine::phase_of 命名冲突）
static bool phase_of(RingPhase expected, RingPhase actual) noexcept {
    return expected == actual;
}

/// 从字节读取 uint64（小端序）
static std::uint64_t read_u64(const std::vector<std::uint8_t>& data, std::size_t offset) {
    std::uint64_t val = 0;
    if (offset + 8 <= data.size()) {
        std::memcpy(&val, data.data() + offset, 8);
    }
    return val;
}

/// 对两个 chunk 执行 SUM 规约（uint64 元素）
static std::vector<std::uint8_t>
reduce_sum(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
    std::vector<std::uint8_t> result(a.size());
    for (std::size_t i = 0; i < a.size(); i += 8) {
        std::uint64_t va = read_u64(a, i);
        std::uint64_t vb = read_u64(b, i);
        std::uint64_t sum = va + vb;
        for (int j = 0; j < 8; ++j) {
            result[i + j] = static_cast<std::uint8_t>((sum >> (j * 8)) & 0xFF);
        }
    }
    return result;
}

// ============================================================================
// TEST 1: build_ring 拓扑正确性
// ============================================================================
static void test_build_ring() {
    std::printf("[test] build_ring topology...\n");

    // 4 节点环
    {
        auto bits = make_participants(4);
        auto ring = RingEngine::build_ring(bits);

        CHECK_EQ(ring.size(), static_cast<std::size_t>(4));
        CHECK_EQ(ring[bits[0]].next, bits[1]);  // 0 -> 1
        CHECK_EQ(ring[bits[0]].prev, bits[3]);  // 0 <- 3
        CHECK_EQ(ring[bits[1]].next, bits[2]);  // 1 -> 2
        CHECK_EQ(ring[bits[1]].prev, bits[0]);  // 1 <- 0
        CHECK_EQ(ring[bits[2]].next, bits[3]);  // 2 -> 3
        CHECK_EQ(ring[bits[2]].prev, bits[1]);  // 2 <- 1
        CHECK_EQ(ring[bits[3]].next, bits[0]);  // 3 -> 0
        CHECK_EQ(ring[bits[3]].prev, bits[2]);  // 3 <- 2
    }

    // 2 节点最小环
    {
        auto bits = make_participants(2);
        auto ring = RingEngine::build_ring(bits);
        CHECK_EQ(ring[bits[0]].next, bits[1]);
        CHECK_EQ(ring[bits[0]].prev, bits[1]);  // 2 节点环：next == prev
        CHECK_EQ(ring[bits[1]].next, bits[0]);
        CHECK_EQ(ring[bits[1]].prev, bits[0]);
    }

    // 1 节点（退化）
    {
        auto bits = make_participants(1);
        auto ring = RingEngine::build_ring(bits);
        CHECK_EQ(ring.size(), static_cast<std::size_t>(1));
        CHECK_EQ(ring[bits[0]].next, bits[0]);  // 自环
        CHECK_EQ(ring[bits[0]].prev, bits[0]);
    }

    // 空列表
    {
        auto ring = RingEngine::build_ring({});
        CHECK_EQ(ring.size(), static_cast<std::size_t>(0));
    }
}

// ============================================================================
// TEST 2: rank_of 节点定位
// ============================================================================
static void test_rank_of() {
    std::printf("[test] rank_of...\n");

    auto bits = make_participants(4);
    CHECK_EQ(RingEngine::rank_of(bits, bits[0]), static_cast<std::size_t>(0));
    CHECK_EQ(RingEngine::rank_of(bits, bits[3]), static_cast<std::size_t>(3));
    CHECK_EQ(RingEngine::rank_of(bits, 0), SIZE_MAX);  // bit 0 不在列表
    CHECK_EQ(RingEngine::rank_of(bits, 999), SIZE_MAX);
    CHECK_EQ(RingEngine::rank_of({}, 1), SIZE_MAX);
}

// ============================================================================
// TEST 3: total_steps / phase_of
// ============================================================================
static void test_steps_and_phase() {
    std::printf("[test] total_steps / phase_of...\n");

    CHECK_EQ(RingEngine::total_steps(1), static_cast<std::size_t>(0));
    CHECK_EQ(RingEngine::total_steps(2), static_cast<std::size_t>(2));
    CHECK_EQ(RingEngine::total_steps(4), static_cast<std::size_t>(6));
    CHECK_EQ(RingEngine::total_steps(8), static_cast<std::size_t>(14));
    CHECK_EQ(RingEngine::total_steps(6), static_cast<std::size_t>(10));

    CHECK_EQ(RingEngine::all_gather_steps(4), static_cast<std::size_t>(3));
    CHECK_EQ(RingEngine::reduce_scatter_steps(4), static_cast<std::size_t>(3));

    // N=4 阶段判定：step 0..2 = ReduceScatter, step 3..5 = AllGather, step 6 = Done
    CHECK(phase_of(RingPhase::ReduceScatter, RingEngine::phase_of(0, 4)));
    CHECK(phase_of(RingPhase::ReduceScatter, RingEngine::phase_of(2, 4)));
    CHECK(phase_of(RingPhase::AllGather, RingEngine::phase_of(3, 4)));
    CHECK(phase_of(RingPhase::AllGather, RingEngine::phase_of(5, 4)));
    CHECK(phase_of(RingPhase::Done, RingEngine::phase_of(6, 4)));
}

// ============================================================================
// TEST 4: 索引匹配不变量 — sender.send_idx == receiver.recv_idx
// 这是 Ring 算法正确性的关键不变量：节点 r 发送的分片必须等于
// 节点 r+1 接收的分片（否则数据错位）
// ============================================================================
static void test_index_matching_invariant() {
    std::printf("[test] index matching invariant (sender.send_idx == receiver.recv_idx)...\n");

    // 测试 N=2,4,6,8
    for (std::size_t N : {2, 4, 6, 8}) {
        auto bits = make_participants(N);
        std::size_t total = RingEngine::total_steps(N);

        for (std::size_t step = 0; step < total; ++step) {
            for (std::size_t rank = 0; rank < N; ++rank) {
                auto sender_idx = RingEngine::compute_chunk_index(rank, step, N);
                std::size_t next_rank = (rank + 1) % N;
                auto receiver_idx = RingEngine::compute_chunk_index(next_rank, step, N);

                CHECK_EQ(sender_idx.send_idx, receiver_idx.recv_idx);
            }
        }
    }
}

// ============================================================================
// TEST 5: N=4 完整 AllReduce 模拟（验证最终规约结果）
// 模拟 4 节点 Ring AllReduce，验证每步收发和最终结果正确性
// ============================================================================
static void test_all_reduce_n4_simulation() {
    std::printf("[test] N=4 Ring AllReduce full simulation...\n");

    const std::size_t N = 4;
    auto bits = make_participants(N);

    // 每节点 4 个 uint64（32 字节），分 4 份各 8 字节
    // 节点 0: [1, 2, 3, 4]
    // 节点 1: [10, 20, 30, 40]
    // 节点 2: [100, 200, 300, 400]
    // 节点 3: [1000, 2000, 3000, 4000]
    // 期望 AllReduce SUM 结果: [1111, 2222, 3333, 4444]
    std::vector<std::vector<std::vector<std::uint8_t>>> node_chunks(N);
    node_chunks[0] = split_chunks(make_u64_array({1, 2, 3, 4}), N);
    node_chunks[1] = split_chunks(make_u64_array({10, 20, 30, 40}), N);
    node_chunks[2] = split_chunks(make_u64_array({100, 200, 300, 400}), N);
    node_chunks[3] = split_chunks(make_u64_array({1000, 2000, 3000, 4000}), N);

    std::size_t total = RingEngine::total_steps(N);
    CHECK_EQ(total, static_cast<std::size_t>(6));

    // 模拟每一步：先计算所有发送，再统一投递并规约（避免同步骤内顺序依赖）
    for (std::size_t step = 0; step < total; ++step) {
        auto phase = RingEngine::phase_of(step, N);

        // 收集本步所有发送数据
        std::vector<std::vector<std::uint8_t>> send_data(N);
        std::vector<RingChunkIndex> indices(N);
        for (std::size_t rank = 0; rank < N; ++rank) {
            indices[rank] = RingEngine::compute_chunk_index(rank, step, N);
            send_data[rank] = node_chunks[rank][indices[rank].send_idx];
        }

        // 投递并规约/覆盖
        for (std::size_t rank = 0; rank < N; ++rank) {
            std::size_t prev_rank = (rank - 1 + N) % N;
            const auto& received = send_data[prev_rank];
            std::size_t recv_idx = indices[rank].recv_idx;

            if (phase == RingPhase::ReduceScatter) {
                // 阶段 1：规约
                node_chunks[rank][recv_idx] = reduce_sum(node_chunks[rank][recv_idx], received);
            } else {
                // 阶段 2：覆盖（已规约结果直接传播）
                node_chunks[rank][recv_idx] = received;
            }
        }
    }

    // 验证：所有节点应拥有 [1111, 2222, 3333, 4444]
    for (std::size_t rank = 0; rank < N; ++rank) {
        std::vector<std::uint8_t> full_result;
        for (std::size_t c = 0; c < N; ++c) {
            full_result.insert(full_result.end(),
                               node_chunks[rank][c].begin(),
                               node_chunks[rank][c].end());
        }
        CHECK_EQ(read_u64(full_result, 0), static_cast<std::uint64_t>(1111));
        CHECK_EQ(read_u64(full_result, 8), static_cast<std::uint64_t>(2222));
        CHECK_EQ(read_u64(full_result, 16), static_cast<std::uint64_t>(3333));
        CHECK_EQ(read_u64(full_result, 24), static_cast<std::uint64_t>(4444));
    }
}

// ============================================================================
// TEST 6: N=8 Ring AllReduce 步数与通信量验证
// ============================================================================
static void test_all_reduce_n8() {
    std::printf("[test] N=8 Ring AllReduce steps and volume...\n");

    const std::size_t N = 8;
    CHECK_EQ(RingEngine::total_steps(N), static_cast<std::size_t>(14));

    // 通信量：2*(N-1)*msg/N = 2*7*msg/8 = 1.75*msg
    std::size_t msg = 8192;
    std::size_t expected = 2 * 7 * (msg / 8);  // 14336
    CHECK_EQ(RingEngine::all_reduce_bytes_per_node(N, msg), expected);

    // 验证所有 14 步的索引都在 [0, N) 范围内
    for (std::size_t step = 0; step < 14; ++step) {
        for (std::size_t rank = 0; rank < N; ++rank) {
            auto idx = RingEngine::compute_chunk_index(rank, step, N);
            CHECK(idx.send_idx < N);
            CHECK(idx.recv_idx < N);
        }
    }
}

// ============================================================================
// TEST 7: 非二次幂 N=6 Ring AllReduce
// ============================================================================
static void test_all_reduce_n6() {
    std::printf("[test] N=6 (non-power-of-2) Ring AllReduce...\n");

    const std::size_t N = 6;
    CHECK_EQ(RingEngine::total_steps(N), static_cast<std::size_t>(10));

    auto bits = make_participants(N);

    // 每节点 6 个 uint64（48 字节），分 6 份
    std::vector<std::vector<std::vector<std::uint8_t>>> node_chunks(N);
    for (std::size_t i = 0; i < N; ++i) {
        std::vector<std::uint64_t> vals;
        for (std::size_t j = 0; j < N; ++j) vals.push_back((i + 1) * (j + 1));
        node_chunks[i] = split_chunks(make_u64_array_vals(vals), N);
    }

    std::size_t total = RingEngine::total_steps(N);

    for (std::size_t step = 0; step < total; ++step) {
        auto phase = RingEngine::phase_of(step, N);
        std::vector<std::vector<std::uint8_t>> send_data(N);
        std::vector<RingChunkIndex> indices(N);
        for (std::size_t rank = 0; rank < N; ++rank) {
            indices[rank] = RingEngine::compute_chunk_index(rank, step, N);
            send_data[rank] = node_chunks[rank][indices[rank].send_idx];
        }
        for (std::size_t rank = 0; rank < N; ++rank) {
            std::size_t prev_rank = (rank - 1 + N) % N;
            const auto& received = send_data[prev_rank];
            std::size_t recv_idx = indices[rank].recv_idx;
            if (phase == RingPhase::ReduceScatter) {
                node_chunks[rank][recv_idx] = reduce_sum(node_chunks[rank][recv_idx], received);
            } else {
                node_chunks[rank][recv_idx] = received;
            }
        }
    }

    // 期望结果：每 chunk 的 SUM = sum of (i+1)*(j+1) for i in 0..5 = (j+1)*21
    for (std::size_t rank = 0; rank < N; ++rank) {
        std::vector<std::uint8_t> full_result;
        for (std::size_t c = 0; c < N; ++c) {
            full_result.insert(full_result.end(),
                               node_chunks[rank][c].begin(),
                               node_chunks[rank][c].end());
        }
        for (std::size_t j = 0; j < N; ++j) {
            std::uint64_t expected = (j + 1) * 21;  // 21 = 1+2+3+4+5+6
            CHECK_EQ(read_u64(full_result, j * 8), expected);
        }
    }
}

// 辅助：从 vector<uint64> 构造字节数组
static std::vector<std::uint8_t>
make_u64_array_vals(const std::vector<std::uint64_t>& vals) {
    std::vector<std::uint8_t> data;
    data.reserve(vals.size() * 8);
    for (auto v : vals) {
        for (int i = 0; i < 8; ++i) {
            data.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
        }
    }
    return data;
}

// ============================================================================
// TEST 8: AllGather-only 模拟（N=4）
// ============================================================================
static void test_all_gather_n4() {
    std::printf("[test] N=4 Ring AllGather-only...\n");

    const std::size_t N = 4;
    std::size_t total = RingEngine::all_gather_steps(N);
    CHECK_EQ(total, static_cast<std::size_t>(3));

    // 每节点 1 个 chunk，模拟环形收集
    std::vector<std::vector<std::uint8_t>> node_data(N);
    for (std::size_t i = 0; i < N; ++i) {
        node_data[i] = make_u64_array({(i + 1) * 100});  // 100, 200, 300, 400
    }

    // 每节点维护 N 个 slot（初始只有 own chunk，其余空）
    std::vector<std::vector<std::vector<std::uint8_t>>> slots(N, std::vector<std::vector<std::uint8_t>>(N));
    for (std::size_t i = 0; i < N; ++i) slots[i][i] = node_data[i];

    for (std::size_t step = 0; step < total; ++step) {
        // 收集本步发送
        std::vector<std::vector<std::uint8_t>> send_data(N);
        std::vector<RingChunkIndex> indices(N);
        for (std::size_t rank = 0; rank < N; ++rank) {
            indices[rank] = RingEngine::all_gather_chunk_index(rank, step, N);
            send_data[rank] = slots[rank][indices[rank].send_idx];
        }
        // 投递
        for (std::size_t rank = 0; rank < N; ++rank) {
            std::size_t prev_rank = (rank - 1 + N) % N;
            slots[rank][indices[rank].recv_idx] = send_data[prev_rank];
        }
    }

    // 验证：所有节点应拥有 [100, 200, 300, 400]
    for (std::size_t rank = 0; rank < N; ++rank) {
        std::vector<std::uint8_t> full;
        for (std::size_t c = 0; c < N; ++c) {
            full.insert(full.end(), slots[rank][c].begin(), slots[rank][c].end());
        }
        CHECK_EQ(read_u64(full, 0), static_cast<std::uint64_t>(100));
        CHECK_EQ(read_u64(full, 8), static_cast<std::uint64_t>(200));
        CHECK_EQ(read_u64(full, 16), static_cast<std::uint64_t>(300));
        CHECK_EQ(read_u64(full, 24), static_cast<std::uint64_t>(400));
    }
}

// ============================================================================
// TEST 9: ReduceScatter-only 模拟（N=4）
// ============================================================================
static void test_reduce_scatter_n4() {
    std::printf("[test] N=4 Ring ReduceScatter-only...\n");

    const std::size_t N = 4;
    std::size_t total = RingEngine::reduce_scatter_steps(N);
    CHECK_EQ(total, static_cast<std::size_t>(3));

    // 节点 i 数据：[(i+1)*1, (i+1)*2, (i+1)*3, (i+1)*4]
    std::vector<std::vector<std::vector<std::uint8_t>>> node_chunks(N);
    for (std::size_t i = 0; i < N; ++i) {
        node_chunks[i] = split_chunks(
            make_u64_array({(i + 1) * 1, (i + 1) * 2, (i + 1) * 3, (i + 1) * 4}), N);
    }

    for (std::size_t step = 0; step < total; ++step) {
        std::vector<std::vector<std::uint8_t>> send_data(N);
        std::vector<RingChunkIndex> indices(N);
        for (std::size_t rank = 0; rank < N; ++rank) {
            indices[rank] = RingEngine::reduce_scatter_chunk_index(rank, step, N);
            send_data[rank] = node_chunks[rank][indices[rank].send_idx];
        }
        for (std::size_t rank = 0; rank < N; ++rank) {
            std::size_t prev_rank = (rank - 1 + N) % N;
            std::size_t recv_idx = indices[rank].recv_idx;
            node_chunks[rank][recv_idx] = reduce_sum(node_chunks[rank][recv_idx], send_data[prev_rank]);
        }
    }

    // 验证：节点 r 拥有 chunk[r] 的完整规约结果
    // chunk[r] SUM = sum of (i+1)*(r+1) for i in 0..3 = (r+1)*10
    for (std::size_t rank = 0; rank < N; ++rank) {
        std::size_t result_idx = RingEngine::reduce_scatter_result_idx(rank);
        std::uint64_t expected = (rank + 1) * 10;  // 10 = 1+2+3+4
        CHECK_EQ(read_u64(node_chunks[rank][result_idx], 0), expected);
    }
}

// ============================================================================
// TEST 10: 通信量预估
// ============================================================================
static void test_communication_volume() {
    std::printf("[test] communication volume estimates...\n");

    // N=4, msg=4KB: AllReduce = 2*3*1KB = 6KB
    CHECK_EQ(RingEngine::all_reduce_bytes_per_node(4, 4096), static_cast<std::size_t>(6144));
    // N=4, msg=4KB: AllGather = 3*1KB = 3KB
    CHECK_EQ(RingEngine::all_gather_bytes_per_node(4, 4096), static_cast<std::size_t>(3072));
    // N=4, msg=4KB: ReduceScatter = 3*1KB = 3KB
    CHECK_EQ(RingEngine::reduce_scatter_bytes_per_node(4, 4096), static_cast<std::size_t>(3072));

    // N=1 退化
    CHECK_EQ(RingEngine::all_reduce_bytes_per_node(1, 4096), static_cast<std::size_t>(0));
    CHECK_EQ(RingEngine::all_gather_bytes_per_node(1, 4096), static_cast<std::size_t>(0));

    // N=8, msg=8KB: AllReduce = 2*7*1KB = 14KB
    CHECK_EQ(RingEngine::all_reduce_bytes_per_node(8, 8192), static_cast<std::size_t>(14336));
}

// ============================================================================
// TEST 11: 边界值 — N=2 最小环
// ============================================================================
static void test_n2_minimal() {
    std::printf("[test] N=2 minimal ring...\n");

    const std::size_t N = 2;
    CHECK_EQ(RingEngine::total_steps(N), static_cast<std::size_t>(2));

    // step 0 = ReduceScatter, step 1 = AllGather
    CHECK(phase_of(RingPhase::ReduceScatter, RingEngine::phase_of(0, 2)));
    CHECK(phase_of(RingPhase::AllGather, RingEngine::phase_of(1, 2)));

    // rank 0, step 0: send_idx=(0-0-1+2)%2=1, recv_idx=(0-0-2+2)%2=0
    auto idx0 = RingEngine::compute_chunk_index(0, 0, 2);
    CHECK_EQ(idx0.send_idx, static_cast<std::size_t>(1));
    CHECK_EQ(idx0.recv_idx, static_cast<std::size_t>(0));

    // rank 0, step 1: j=0, send_idx=(0-0+2)%2=0, recv_idx=(0-0-1+2)%2=1
    auto idx1 = RingEngine::compute_chunk_index(0, 1, 2);
    CHECK_EQ(idx1.send_idx, static_cast<std::size_t>(0));
    CHECK_EQ(idx1.recv_idx, static_cast<std::size_t>(1));
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== Ring Engine Unit Tests (P3-B) ===\n\n");

    test_build_ring();
    test_rank_of();
    test_steps_and_phase();
    test_index_matching_invariant();
    test_all_reduce_n4_simulation();
    test_all_reduce_n8();
    test_all_reduce_n6();
    test_all_gather_n4();
    test_reduce_scatter_n4();
    test_communication_volume();
    test_n2_minimal();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
