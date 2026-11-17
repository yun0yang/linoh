// test_tree_engine.cpp — v2.2 Phase 3 P3-C Tree 算法引擎单元测试
//
// 验证 P3-C 交付物：
//   1. total_steps 步数计算（⌈log₂N⌉）
//   2. recv_step_of 接收步数判定（= MSB 位置）
//   3. parent_of 父节点计算
//   4. children_of 子节点列表
//   5. node_role 角色判定（Root/Internal/Leaf）
//   6. send_target_at_step / recv_source_at_step 步级调度
//   7. build_binomial_tree 拓扑构建（默认 root + 任意 root）
//   8. N=4/8 完整 Broadcast 模拟（验证所有节点收到数据）
//   9. N=5 非二次幂场景
//  10. AllGather 模拟（每节点贡献不同数据，验证全收集）
//  11. 通信量预估
//  12. 虚拟 rank 映射（to_virtual / to_real）
//
// 测试策略：纯算法验证，不依赖网络 IO，通过模拟发送/接收验证数据传播正确性

#include "linoh/multimodal/tree_engine.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
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

#define CHECK_HAS(opt) do { \
    if ((opt).has_value()) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s has value (line %d)\n", #opt, __LINE__); } \
} while (0)

#define CHECK_NO(opt) do { \
    if (!(opt).has_value()) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s should be nullopt (line %d)\n", #opt, __LINE__); } \
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

/// uint64 转字节（小端序）
static std::vector<std::uint8_t> make_u64(std::uint64_t val) {
    std::vector<std::uint8_t> data(8);
    for (int i = 0; i < 8; ++i) {
        data[i] = static_cast<std::uint8_t>((val >> (i * 8)) & 0xFF);
    }
    return data;
}

/// 从字节读取 uint64（小端序）
static std::uint64_t read_u64(const std::vector<std::uint8_t>& data, std::size_t offset = 0) {
    std::uint64_t val = 0;
    if (offset + 8 <= data.size()) {
        std::memcpy(&val, data.data() + offset, 8);
    }
    return val;
}

// ============================================================================
// TEST 1: total_steps 步数计算
// ============================================================================
static void test_total_steps() {
    std::printf("[test] total_steps (ceil log2 N)...\n");

    CHECK_EQ(TreeEngine::total_steps(1), static_cast<std::size_t>(0));   // 2^0=1, 不需要发送
    CHECK_EQ(TreeEngine::total_steps(2), static_cast<std::size_t>(1));   // 2^1
    CHECK_EQ(TreeEngine::total_steps(4), static_cast<std::size_t>(2));   // 2^2
    CHECK_EQ(TreeEngine::total_steps(8), static_cast<std::size_t>(3));   // 2^3
    CHECK_EQ(TreeEngine::total_steps(16), static_cast<std::size_t>(4));  // 2^4

    // 非二次幂
    CHECK_EQ(TreeEngine::total_steps(3), static_cast<std::size_t>(2));   // ⌈log₂3⌉=2
    CHECK_EQ(TreeEngine::total_steps(5), static_cast<std::size_t>(3));   // ⌈log₂5⌉=3
    CHECK_EQ(TreeEngine::total_steps(7), static_cast<std::size_t>(3));   // ⌈log₂7⌉=3
    CHECK_EQ(TreeEngine::total_steps(9), static_cast<std::size_t>(4));   // ⌈log₂9⌉=4
}

// ============================================================================
// TEST 2: recv_step_of 接收步数（= MSB 位置）
// ============================================================================
static void test_recv_step_of() {
    std::printf("[test] recv_step_of (MSB position)...\n");

    // root (vrank=0) 不接收
    CHECK_NO(TreeEngine::recv_step_of(0));

    // vrank=1 (binary 1): MSB=0, recv at step 0
    CHECK_EQ(TreeEngine::recv_step_of(1).value(), static_cast<std::size_t>(0));
    // vrank=2 (binary 10): MSB=1, recv at step 1
    CHECK_EQ(TreeEngine::recv_step_of(2).value(), static_cast<std::size_t>(1));
    // vrank=3 (binary 11): MSB=1, recv at step 1
    CHECK_EQ(TreeEngine::recv_step_of(3).value(), static_cast<std::size_t>(1));
    // vrank=4 (binary 100): MSB=2, recv at step 2
    CHECK_EQ(TreeEngine::recv_step_of(4).value(), static_cast<std::size_t>(2));
    // vrank=7 (binary 111): MSB=2, recv at step 2
    CHECK_EQ(TreeEngine::recv_step_of(7).value(), static_cast<std::size_t>(2));
    // vrank=8 (binary 1000): MSB=3, recv at step 3
    CHECK_EQ(TreeEngine::recv_step_of(8).value(), static_cast<std::size_t>(3));
}

// ============================================================================
// TEST 3: parent_of 父节点计算
// ============================================================================
static void test_parent_of() {
    std::printf("[test] parent_of...\n");

    // root 无父节点
    CHECK_NO(TreeEngine::parent_of(0));

    // vrank=1: parent=0 (1 - 2^0 = 0)
    CHECK_EQ(TreeEngine::parent_of(1).value(), static_cast<std::size_t>(0));
    // vrank=2: parent=0 (2 - 2^1 = 0)
    CHECK_EQ(TreeEngine::parent_of(2).value(), static_cast<std::size_t>(0));
    // vrank=3: parent=1 (3 - 2^1 = 1)
    CHECK_EQ(TreeEngine::parent_of(3).value(), static_cast<std::size_t>(1));
    // vrank=4: parent=0 (4 - 2^2 = 0)
    CHECK_EQ(TreeEngine::parent_of(4).value(), static_cast<std::size_t>(0));
    // vrank=5: parent=1 (5 - 2^2 = 1)
    CHECK_EQ(TreeEngine::parent_of(5).value(), static_cast<std::size_t>(1));
    // vrank=6: parent=2 (6 - 2^2 = 2)
    CHECK_EQ(TreeEngine::parent_of(6).value(), static_cast<std::size_t>(2));
    // vrank=7: parent=3 (7 - 2^2 = 3)
    CHECK_EQ(TreeEngine::parent_of(7).value(), static_cast<std::size_t>(3));
}

// ============================================================================
// TEST 4: children_of 子节点列表
// ============================================================================
static void test_children_of() {
    std::printf("[test] children_of...\n");

    // N=8, vrank=0 (root): children = {1, 2, 4} (steps 0,1,2)
    auto c0 = TreeEngine::children_of(0, 8);
    CHECK_EQ(c0.size(), static_cast<std::size_t>(3));
    CHECK_EQ(c0[0], static_cast<std::size_t>(1));
    CHECK_EQ(c0[1], static_cast<std::size_t>(2));
    CHECK_EQ(c0[2], static_cast<std::size_t>(4));

    // vrank=1 (internal): first_send=1, children = {3, 5} (steps 1,2)
    auto c1 = TreeEngine::children_of(1, 8);
    CHECK_EQ(c1.size(), static_cast<std::size_t>(2));
    CHECK_EQ(c1[0], static_cast<std::size_t>(3));
    CHECK_EQ(c1[1], static_cast<std::size_t>(5));

    // vrank=2 (internal): first_send=2, children = {6} (step 2)
    auto c2 = TreeEngine::children_of(2, 8);
    CHECK_EQ(c2.size(), static_cast<std::size_t>(1));
    CHECK_EQ(c2[0], static_cast<std::size_t>(6));

    // vrank=3 (internal): first_send=2, children = {7} (step 2)
    auto c3 = TreeEngine::children_of(3, 8);
    CHECK_EQ(c3.size(), static_cast<std::size_t>(1));
    CHECK_EQ(c3[0], static_cast<std::size_t>(7));

    // vrank=4 (leaf): first_send=3, 但 total_steps=3, 无子节点
    auto c4 = TreeEngine::children_of(4, 8);
    CHECK(c4.empty());

    // vrank=7 (leaf): 无子节点
    auto c7 = TreeEngine::children_of(7, 8);
    CHECK(c7.empty());

    // N=5: vrank=0 children = {1, 2, 4} (4 < 5)
    auto c0_5 = TreeEngine::children_of(0, 5);
    CHECK_EQ(c0_5.size(), static_cast<std::size_t>(3));
    CHECK_EQ(c0_5[0], static_cast<std::size_t>(1));
    CHECK_EQ(c0_5[1], static_cast<std::size_t>(2));
    CHECK_EQ(c0_5[2], static_cast<std::size_t>(4));

    // N=5: vrank=1 children = {3} (5 >= 5, 排除)
    auto c1_5 = TreeEngine::children_of(1, 5);
    CHECK_EQ(c1_5.size(), static_cast<std::size_t>(1));
    CHECK_EQ(c1_5[0], static_cast<std::size_t>(3));
}

// ============================================================================
// TEST 5: node_role 角色判定
// ============================================================================
static void test_node_role() {
    std::printf("[test] node_role...\n");

    CHECK_EQ(static_cast<int>(TreeEngine::node_role(0, 8)),
             static_cast<int>(TreeNodeRole::Root));
    CHECK_EQ(static_cast<int>(TreeEngine::node_role(1, 8)),
             static_cast<int>(TreeNodeRole::Internal));
    CHECK_EQ(static_cast<int>(TreeEngine::node_role(2, 8)),
             static_cast<int>(TreeNodeRole::Internal));
    CHECK_EQ(static_cast<int>(TreeEngine::node_role(3, 8)),
             static_cast<int>(TreeNodeRole::Internal));
    CHECK_EQ(static_cast<int>(TreeEngine::node_role(4, 8)),
             static_cast<int>(TreeNodeRole::Leaf));
    CHECK_EQ(static_cast<int>(TreeEngine::node_role(7, 8)),
             static_cast<int>(TreeNodeRole::Leaf));

    // N=2: vrank=0=Root, vrank=1=Leaf
    CHECK_EQ(static_cast<int>(TreeEngine::node_role(0, 2)),
             static_cast<int>(TreeNodeRole::Root));
    CHECK_EQ(static_cast<int>(TreeEngine::node_role(1, 2)),
             static_cast<int>(TreeNodeRole::Leaf));
}

// ============================================================================
// TEST 6: send_target_at_step 步级发送目标
// ============================================================================
static void test_send_target_at_step() {
    std::printf("[test] send_target_at_step...\n");

    // N=8, step 0: senders = {0}, targets = {1}
    CHECK_EQ(TreeEngine::send_target_at_step(0, 0, 8).value(), static_cast<std::size_t>(1));
    CHECK_NO(TreeEngine::send_target_at_step(1, 0, 8));  // 1 >= 2^0=1, 无数据
    CHECK_NO(TreeEngine::send_target_at_step(2, 0, 8));

    // N=8, step 1: senders = {0,1}, targets = {2,3}
    CHECK_EQ(TreeEngine::send_target_at_step(0, 1, 8).value(), static_cast<std::size_t>(2));
    CHECK_EQ(TreeEngine::send_target_at_step(1, 1, 8).value(), static_cast<std::size_t>(3));
    CHECK_NO(TreeEngine::send_target_at_step(2, 1, 8));  // 2 >= 2^1=2

    // N=8, step 2: senders = {0,1,2,3}, targets = {4,5,6,7}
    CHECK_EQ(TreeEngine::send_target_at_step(0, 2, 8).value(), static_cast<std::size_t>(4));
    CHECK_EQ(TreeEngine::send_target_at_step(1, 2, 8).value(), static_cast<std::size_t>(5));
    CHECK_EQ(TreeEngine::send_target_at_step(2, 2, 8).value(), static_cast<std::size_t>(6));
    CHECK_EQ(TreeEngine::send_target_at_step(3, 2, 8).value(), static_cast<std::size_t>(7));
    CHECK_NO(TreeEngine::send_target_at_step(4, 2, 8));  // 4 >= 2^2=4

    // N=5, step 2: vrank=0→4 (4<5), vrank=1→5 (5>=5 无效)
    CHECK_EQ(TreeEngine::send_target_at_step(0, 2, 5).value(), static_cast<std::size_t>(4));
    CHECK_NO(TreeEngine::send_target_at_step(1, 2, 5));  // 1+4=5 >= 5
}

// ============================================================================
// TEST 7: recv_source_at_step 步级接收来源
// ============================================================================
static void test_recv_source_at_step() {
    std::printf("[test] recv_source_at_step...\n");

    // root 不接收
    CHECK_NO(TreeEngine::recv_source_at_step(0, 0, 8));
    CHECK_NO(TreeEngine::recv_source_at_step(0, 1, 8));

    // vrank=1 在 step 0 接收，来源=0
    CHECK_EQ(TreeEngine::recv_source_at_step(1, 0, 8).value(), static_cast<std::size_t>(0));
    CHECK_NO(TreeEngine::recv_source_at_step(1, 1, 8));  // 不在 step 1 接收

    // vrank=2 在 step 1 接收，来源=0
    CHECK_EQ(TreeEngine::recv_source_at_step(2, 1, 8).value(), static_cast<std::size_t>(0));
    CHECK_NO(TreeEngine::recv_source_at_step(2, 0, 8));

    // vrank=3 在 step 1 接收，来源=1
    CHECK_EQ(TreeEngine::recv_source_at_step(3, 1, 8).value(), static_cast<std::size_t>(1));

    // vrank=4 在 step 2 接收，来源=0
    CHECK_EQ(TreeEngine::recv_source_at_step(4, 2, 8).value(), static_cast<std::size_t>(0));
    // vrank=5 在 step 2 接收，来源=1
    CHECK_EQ(TreeEngine::recv_source_at_step(5, 2, 8).value(), static_cast<std::size_t>(1));
    // vrank=6 在 step 2 接收，来源=2
    CHECK_EQ(TreeEngine::recv_source_at_step(6, 2, 8).value(), static_cast<std::size_t>(2));
    // vrank=7 在 step 2 接收，来源=3
    CHECK_EQ(TreeEngine::recv_source_at_step(7, 2, 8).value(), static_cast<std::size_t>(3));
}

// ============================================================================
// TEST 8: build_binomial_tree 拓扑构建（默认 root=0）
// ============================================================================
static void test_build_binomial_tree_default_root() {
    std::printf("[test] build_binomial_tree (default root=0)...\n");

    auto bits = make_participants(8);
    auto tree = TreeEngine::build_binomial_tree(bits, 0);

    CHECK_EQ(tree.size(), static_cast<std::size_t>(8));

    // root (bit 0) children = {bit 1, bit 2, bit 4}
    auto& root_children = tree[bits[0]];
    CHECK_EQ(root_children.size(), static_cast<std::size_t>(3));
    CHECK_EQ(root_children[0], bits[1]);
    CHECK_EQ(root_children[1], bits[2]);
    CHECK_EQ(root_children[2], bits[4]);

    // bit 1 children = {bit 3, bit 5}
    auto& b1_children = tree[bits[1]];
    CHECK_EQ(b1_children.size(), static_cast<std::size_t>(2));
    CHECK_EQ(b1_children[0], bits[3]);
    CHECK_EQ(b1_children[1], bits[5]);

    // bit 2 children = {bit 6}
    auto& b2_children = tree[bits[2]];
    CHECK_EQ(b2_children.size(), static_cast<std::size_t>(1));
    CHECK_EQ(b2_children[0], bits[6]);

    // bit 3 children = {bit 7}
    auto& b3_children = tree[bits[3]];
    CHECK_EQ(b3_children.size(), static_cast<std::size_t>(1));
    CHECK_EQ(b3_children[0], bits[7]);

    // bit 4,5,6,7 无子节点
    CHECK(tree[bits[4]].empty());
    CHECK(tree[bits[5]].empty());
    CHECK(tree[bits[6]].empty());
    CHECK(tree[bits[7]].empty());
}

// ============================================================================
// TEST 9: build_binomial_tree 任意 root（root_rank=3）
// ============================================================================
static void test_build_binomial_tree_arbitrary_root() {
    std::printf("[test] build_binomial_tree (root_rank=3)...\n");

    auto bits = make_participants(8);
    auto tree = TreeEngine::build_binomial_tree(bits, 3);

    CHECK_EQ(tree.size(), static_cast<std::size_t>(8));

    // root=3, virtual_rank = real_rank XOR 3
    // real 3 → virtual 0 (root)
    // real 0 → virtual 3
    // real 1 → virtual 2
    // real 2 → virtual 1
    // real 4 → virtual 7
    // real 5 → virtual 6
    // real 6 → virtual 5
    // real 7 → virtual 4

    // root (real 3) virtual=0, children virtual = {1,2,4} → real = {2,1,7}
    auto& root_children = tree[bits[3]];
    CHECK_EQ(root_children.size(), static_cast<std::size_t>(3));
    // virtual 1 → real 2, virtual 2 → real 1, virtual 4 → real 7
    CHECK_EQ(root_children[0], bits[2]);
    CHECK_EQ(root_children[1], bits[1]);
    CHECK_EQ(root_children[2], bits[7]);
}

// ============================================================================
// TEST 10: N=4 完整 Broadcast 模拟
// ============================================================================
static void test_broadcast_n4_simulation() {
    std::printf("[test] N=4 Tree Broadcast full simulation...\n");

    const std::size_t N = 4;
    std::vector<std::uint64_t> data(N, 0);  // 每节点持有的数据（0=无数据）
    data[0] = 42;  // root 持有数据

    std::size_t steps = TreeEngine::total_steps(N);
    CHECK_EQ(steps, static_cast<std::size_t>(2));

    for (std::size_t step = 0; step < steps; ++step) {
        // 收集本步所有发送
        std::vector<std::pair<std::size_t, std::size_t>> sends;  // (sender, target)
        for (std::size_t v = 0; v < N; ++v) {
            if (data[v] == 0) continue;  // 无数据不能发送
            auto target = TreeEngine::send_target_at_step(v, step, N);
            if (target.has_value()) {
                sends.emplace_back(v, target.value());
            }
        }
        // 执行发送（目标接收数据）
        for (auto& [sender, target] : sends) {
            data[target] = data[sender];
        }
    }

    // 验证：所有节点持有 42
    for (std::size_t i = 0; i < N; ++i) {
        CHECK_EQ(data[i], static_cast<std::uint64_t>(42));
    }
}

// ============================================================================
// TEST 11: N=8 完整 Broadcast 模拟
// ============================================================================
static void test_broadcast_n8_simulation() {
    std::printf("[test] N=8 Tree Broadcast full simulation...\n");

    const std::size_t N = 8;
    std::vector<std::uint64_t> data(N, 0);
    data[0] = 999;  // root 持有数据

    std::size_t steps = TreeEngine::total_steps(N);
    CHECK_EQ(steps, static_cast<std::size_t>(3));

    for (std::size_t step = 0; step < steps; ++step) {
        std::vector<std::pair<std::size_t, std::size_t>> sends;
        for (std::size_t v = 0; v < N; ++v) {
            if (data[v] == 0) continue;
            auto target = TreeEngine::send_target_at_step(v, step, N);
            if (target.has_value()) {
                sends.emplace_back(v, target.value());
            }
        }
        for (auto& [sender, target] : sends) {
            data[target] = data[sender];
        }
    }

    for (std::size_t i = 0; i < N; ++i) {
        CHECK_EQ(data[i], static_cast<std::uint64_t>(999));
    }
}

// ============================================================================
// TEST 12: N=5 非二次幂 Broadcast 模拟
// ============================================================================
static void test_broadcast_n5_simulation() {
    std::printf("[test] N=5 (non-power-of-2) Tree Broadcast...\n");

    const std::size_t N = 5;
    std::vector<std::uint64_t> data(N, 0);
    data[0] = 777;

    std::size_t steps = TreeEngine::total_steps(N);
    CHECK_EQ(steps, static_cast<std::size_t>(3));

    for (std::size_t step = 0; step < steps; ++step) {
        std::vector<std::pair<std::size_t, std::size_t>> sends;
        for (std::size_t v = 0; v < N; ++v) {
            if (data[v] == 0) continue;
            auto target = TreeEngine::send_target_at_step(v, step, N);
            if (target.has_value()) {
                sends.emplace_back(v, target.value());
            }
        }
        for (auto& [sender, target] : sends) {
            data[target] = data[sender];
        }
    }

    for (std::size_t i = 0; i < N; ++i) {
        CHECK_EQ(data[i], static_cast<std::uint64_t>(777));
    }
}

// ============================================================================
// TEST 13: N=2 最小 Broadcast
// ============================================================================
static void test_broadcast_n2_minimal() {
    std::printf("[test] N=2 minimal Tree Broadcast...\n");

    const std::size_t N = 2;
    std::vector<std::uint64_t> data(N, 0);
    data[0] = 1;

    std::size_t steps = TreeEngine::total_steps(N);
    CHECK_EQ(steps, static_cast<std::size_t>(1));

    for (std::size_t step = 0; step < steps; ++step) {
        for (std::size_t v = 0; v < N; ++v) {
            if (data[v] == 0) continue;
            auto target = TreeEngine::send_target_at_step(v, step, N);
            if (target.has_value()) {
                data[target.value()] = data[v];
            }
        }
    }

    CHECK_EQ(data[0], static_cast<std::uint64_t>(1));
    CHECK_EQ(data[1], static_cast<std::uint64_t>(1));
}

// ============================================================================
// TEST 14: AllGather 模拟（每节点贡献不同数据，验证全收集）
// AllGather via Tree: 先 Reduce 到 root（反向 tree），再 Broadcast（正向 tree）
// 简化版：直接用 Broadcast 逻辑，root 广播所有数据
// ============================================================================
static void test_all_gather_simulation() {
    std::printf("[test] Tree AllGather simulation (each node contributes)...\n");

    const std::size_t N = 8;
    // 每节点初始有自己的数据
    std::vector<std::vector<std::uint64_t>> node_data(N);
    for (std::size_t i = 0; i < N; ++i) {
        node_data[i] = {(i + 1) * 10};  // node 0: [10], node 1: [20], ...
    }

    // AllGather via Tree: 先沿树向上 gather 到 root，再沿树向下 broadcast
    // 简化模拟：root 收集所有数据后广播
    // Phase 1: Gather（反向 step，从叶子到 root）
    std::vector<std::vector<std::uint64_t>> gathered(N);
    for (std::size_t i = 0; i < N; ++i) gathered[i] = node_data[i];

    std::size_t steps = TreeEngine::total_steps(N);
    // 反向遍历 steps：叶子先发送给父节点
    for (std::size_t rev = 0; rev < steps; ++rev) {
        std::size_t step = steps - 1 - rev;
        // 收集本步所有接收（反向 = 接收方发送给父节点... 实际 Tree gather 更复杂）
        // 简化：每步，有数据的节点向父节点合并
        std::vector<std::vector<std::uint64_t>> new_gathered = gathered;
        for (std::size_t v = 0; v < N; ++v) {
            if (v == 0) continue;  // root 不发送
            auto recv_step = TreeEngine::recv_step_of(v);
            if (recv_step.has_value() && recv_step.value() == step) {
                auto parent = TreeEngine::parent_of(v);
                if (parent.has_value()) {
                    // 合并 v 的数据到 parent
                    for (auto val : gathered[v]) {
                        new_gathered[parent.value()].push_back(val);
                    }
                }
            }
        }
        gathered = new_gathered;
    }

    // root 应有所有数据
    CHECK_EQ(gathered[0].size(), N);
    // 排序验证（gather 顺序可能不同，但内容一致）
    auto sorted_root = gathered[0];
    std::sort(sorted_root.begin(), sorted_root.end());
    for (std::size_t i = 0; i < N; ++i) {
        CHECK_EQ(sorted_root[i], static_cast<std::uint64_t>((i + 1) * 10));
    }

    // Phase 2: Broadcast（正向 step，root 广播）
    std::vector<std::vector<std::uint64_t>> broadcast_data(N);
    broadcast_data[0] = gathered[0];  // root 有全量数据

    for (std::size_t step = 0; step < steps; ++step) {
        std::vector<std::pair<std::size_t, std::size_t>> sends;
        for (std::size_t v = 0; v < N; ++v) {
            if (broadcast_data[v].empty()) continue;
            auto target = TreeEngine::send_target_at_step(v, step, N);
            if (target.has_value()) {
                sends.emplace_back(v, target.value());
            }
        }
        for (auto& [sender, target] : sends) {
            broadcast_data[target] = broadcast_data[sender];
        }
    }

    // 所有节点应有全量数据
    for (std::size_t i = 0; i < N; ++i) {
        CHECK_EQ(broadcast_data[i].size(), N);
        auto sorted = broadcast_data[i];
        std::sort(sorted.begin(), sorted.end());
        for (std::size_t j = 0; j < N; ++j) {
            CHECK_EQ(sorted[j], static_cast<std::uint64_t>((j + 1) * 10));
        }
    }
}

// ============================================================================
// TEST 15: 通信量预估
// ============================================================================
static void test_communication_volume() {
    std::printf("[test] communication volume estimates...\n");

    // root_send_count = ⌈log₂N⌉
    CHECK_EQ(TreeEngine::root_send_count(8), static_cast<std::size_t>(3));
    CHECK_EQ(TreeEngine::root_send_count(4), static_cast<std::size_t>(2));
    CHECK_EQ(TreeEngine::root_send_count(2), static_cast<std::size_t>(1));

    // total_send_count = N - 1
    CHECK_EQ(TreeEngine::total_send_count(8), static_cast<std::size_t>(7));
    CHECK_EQ(TreeEngine::total_send_count(4), static_cast<std::size_t>(3));
    CHECK_EQ(TreeEngine::total_send_count(2), static_cast<std::size_t>(1));
    CHECK_EQ(TreeEngine::total_send_count(1), static_cast<std::size_t>(0));

    // broadcast_bytes_per_node = (N-1) * msg / N
    CHECK_EQ(TreeEngine::broadcast_bytes_per_node(8, 1024), static_cast<std::size_t>(896));  // 7*1024/8
    CHECK_EQ(TreeEngine::broadcast_bytes_per_node(4, 1024), static_cast<std::size_t>(768));  // 3*1024/4
}

// ============================================================================
// TEST 16: 虚拟 rank 映射
// ============================================================================
static void test_virtual_rank_mapping() {
    std::printf("[test] virtual rank mapping (to_virtual / to_real)...\n");

    // XOR 性质：to_real(to_virtual(r, root), root) == r
    for (std::size_t root = 0; root < 8; ++root) {
        for (std::size_t r = 0; r < 8; ++r) {
            std::size_t v = TreeEngine::to_virtual(r, root);
            CHECK_EQ(TreeEngine::to_real(v, root), r);
        }
    }

    // root 映射到 0
    CHECK_EQ(TreeEngine::to_virtual(3, 3), static_cast<std::size_t>(0));
    CHECK_EQ(TreeEngine::to_virtual(5, 5), static_cast<std::size_t>(0));
    CHECK_EQ(TreeEngine::to_virtual(0, 0), static_cast<std::size_t>(0));
}

// ============================================================================
// TEST 17: first_send_step 首个发送步
// ============================================================================
static void test_first_send_step() {
    std::printf("[test] first_send_step...\n");

    // root (vrank=0): first_send = 0
    CHECK_EQ(TreeEngine::first_send_step(0, 8).value(), static_cast<std::size_t>(0));

    // vrank=1: recv_step=0, first_send=1
    CHECK_EQ(TreeEngine::first_send_step(1, 8).value(), static_cast<std::size_t>(1));

    // vrank=2: recv_step=1, first_send=2
    CHECK_EQ(TreeEngine::first_send_step(2, 8).value(), static_cast<std::size_t>(2));

    // vrank=3: recv_step=1, first_send=2
    CHECK_EQ(TreeEngine::first_send_step(3, 8).value(), static_cast<std::size_t>(2));

    // vrank=4 (leaf, 无子节点): nullopt
    CHECK_NO(TreeEngine::first_send_step(4, 8));

    // vrank=7 (leaf): nullopt
    CHECK_NO(TreeEngine::first_send_step(7, 8));
}

// ============================================================================
// TEST 18: 不变量验证 — 每个非 root 节点恰好有一个父节点
// ============================================================================
static void test_invariant_single_parent() {
    std::printf("[test] invariant: each non-root node has exactly one parent...\n");

    for (std::size_t N : {2, 4, 5, 8, 16}) {
        for (std::size_t v = 1; v < N; ++v) {
            auto parent = TreeEngine::parent_of(v);
            CHECK_HAS(parent);
            CHECK(parent.value() < v);  // 父节点 virtual rank < 子节点
        }
        CHECK_NO(TreeEngine::parent_of(0));  // root 无父节点
    }
}

// ============================================================================
// TEST 19: 不变量验证 — 树无环（parent 链最终到达 root）
// ============================================================================
static void test_invariant_no_cycle() {
    std::printf("[test] invariant: no cycle (parent chain reaches root)...\n");

    for (std::size_t N : {2, 4, 8, 16}) {
        for (std::size_t v = 1; v < N; ++v) {
            std::size_t cur = v;
            std::size_t hops = 0;
            while (cur != 0 && hops < 64) {
                auto parent = TreeEngine::parent_of(cur);
                CHECK_HAS(parent);
                cur = parent.value();
                ++hops;
            }
            CHECK_EQ(cur, static_cast<std::size_t>(0));  // 最终到达 root
            CHECK(hops <= TreeEngine::total_steps(N));   // 跳数 <= ⌈log₂N⌉
        }
    }
}

// ============================================================================
// TEST 20: 不变量验证 — 子节点总数 = N - 1
// ============================================================================
static void test_invariant_children_count() {
    std::printf("[test] invariant: total children = N - 1...\n");

    for (std::size_t N : {2, 4, 5, 8, 16}) {
        std::size_t total_children = 0;
        for (std::size_t v = 0; v < N; ++v) {
            total_children += TreeEngine::children_of(v, N).size();
        }
        CHECK_EQ(total_children, N - 1);  // 每个非 root 节点是一个子节点
    }
}

// ============================================================================
// TEST 21: Broadcast 字节流模拟（验证大消息传播）
// ============================================================================
static void test_broadcast_byte_stream() {
    std::printf("[test] Tree Broadcast byte stream (large message)...\n");

    const std::size_t N = 8;
    const std::size_t msg_size = 256;  // 256 字节消息

    // root 持有 256 字节消息（每字节 = 0xAA）
    std::vector<std::vector<std::uint8_t>> data(N);
    data[0].assign(msg_size, 0xAA);

    std::size_t steps = TreeEngine::total_steps(N);
    for (std::size_t step = 0; step < steps; ++step) {
        std::vector<std::pair<std::size_t, std::size_t>> sends;
        for (std::size_t v = 0; v < N; ++v) {
            if (data[v].empty()) continue;
            auto target = TreeEngine::send_target_at_step(v, step, N);
            if (target.has_value()) {
                sends.emplace_back(v, target.value());
            }
        }
        for (auto& [sender, target] : sends) {
            data[target] = data[sender];
        }
    }

    // 所有节点应有 256 字节 0xAA
    for (std::size_t i = 0; i < N; ++i) {
        CHECK_EQ(data[i].size(), msg_size);
        for (std::size_t j = 0; j < msg_size; ++j) {
            CHECK_EQ(data[i][j], static_cast<std::uint8_t>(0xAA));
        }
    }
}

// ============================================================================
// TEST 22: Broadcast 任意 root 模拟（root_rank=5, N=8）
// ============================================================================
static void test_broadcast_arbitrary_root() {
    std::printf("[test] Tree Broadcast arbitrary root (root_rank=5, N=8)...\n");

    const std::size_t N = 8;
    const std::size_t root_rank = 5;

    // virtual rank 0 = real rank 5
    std::vector<std::uint64_t> data(N, 0);
    data[root_rank] = 555;  // root 持有数据

    std::size_t steps = TreeEngine::total_steps(N);
    for (std::size_t step = 0; step < steps; ++step) {
        std::vector<std::pair<std::size_t, std::size_t>> sends;
        for (std::size_t real = 0; real < N; ++real) {
            if (data[real] == 0) continue;
            std::size_t vrank = TreeEngine::to_virtual(real, root_rank);
            auto target_v = TreeEngine::send_target_at_step(vrank, step, N);
            if (target_v.has_value()) {
                std::size_t target_real = TreeEngine::to_real(target_v.value(), root_rank);
                sends.emplace_back(real, target_real);
            }
        }
        for (auto& [sender, target] : sends) {
            data[target] = data[sender];
        }
    }

    for (std::size_t i = 0; i < N; ++i) {
        CHECK_EQ(data[i], static_cast<std::uint64_t>(555));
    }
}

// ============================================================================
// main
// ============================================================================
int main() {
    std::printf("=== Tree Engine Unit Tests (P3-C) ===\n\n");

    test_total_steps();
    test_recv_step_of();
    test_parent_of();
    test_children_of();
    test_node_role();
    test_send_target_at_step();
    test_recv_source_at_step();
    test_build_binomial_tree_default_root();
    test_build_binomial_tree_arbitrary_root();
    test_broadcast_n4_simulation();
    test_broadcast_n8_simulation();
    test_broadcast_n5_simulation();
    test_broadcast_n2_minimal();
    test_all_gather_simulation();
    test_communication_volume();
    test_virtual_rank_mapping();
    test_first_send_step();
    test_invariant_single_parent();
    test_invariant_no_cycle();
    test_invariant_children_count();
    test_broadcast_byte_stream();
    test_broadcast_arbitrary_root();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
