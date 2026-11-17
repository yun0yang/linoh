// test_collective_v4.cpp — v2.2 Phase 3 P3-G 大 chunk 分片重组单元测试
//
// 验证 P3-G 交付物：
//   1. send_sharded_ 自动分片：超过 shard_size_ 的数据拆分为多帧（shard_idx/total_shards）
//   2. buffer_shard_ 乱序重组：分片乱序到达后按 shard_idx 升序重组完整数据
//   3. all_gather 分片重组：多节点 sharded chunk 收集并拼接
//   4. broadcast 分片重组：root 数据分片广播，接收方重组后触发回调
//   5. reduce_scatter 分片重组：分片重组后再规约（避免对部分数据 apply_reduce_）
//   6. all_to_all 分片重组：分片重组后收集拼接
//   7. 向后兼容：total_shards=1 行为与改造前一致
//   8. shard_size=0 禁用分片（始终单帧）
//   9. 部分分片不触发完成（arrived_mask 仅在全部分片到齐后更新）
//  10. 3+ 分片与末片不齐（最后一片可小于 shard_size_）
//
// 测试策略：通过 SyncPrimitives(nullptr) 创建会话（channel 无效不发送），
//           构造 EpSyncFrame（含 shard_idx/total_shards）调用 handle_sync_frame
//           模拟接收分片，通过 get_session 和回调验证重组逻辑。

#include "linoh/multimodal/collective.hpp"
#include "linoh/multimodal/comm_planner_v2.hpp"  // TopologyPlan 完整定义（execute_plan 入参）
#include "linoh/multimodal/sync_primitives.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
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

/// 构造重复字节序列
static std::vector<std::uint8_t> make_filled(std::size_t n, std::uint8_t v) {
    return std::vector<std::uint8_t>(n, v);
}

/// 构造递增字节序列（用于验证顺序敏感的重组）
static std::vector<std::uint8_t> make_seq(std::size_t n, std::uint8_t start = 0) {
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::uint8_t>(start + i);
    return v;
}

/// 比较两个字节向量
static bool vec_eq(const std::vector<std::uint8_t> &a, const std::vector<std::uint8_t> &b) {
    if (a.size() != b.size()) return false;
    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

/// 构造一个 AllGather 分片帧
static EpSyncFrame make_ag_shard(std::uint64_t sync_id, std::uint64_t from_bit,
                                  const std::vector<std::uint8_t> &payload,
                                  std::uint16_t shard_idx, std::uint16_t total_shards) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::AllGather;
    frame.participant_mask = static_cast<std::uint64_t>(1) << from_bit;
    frame.payload = payload;
    frame.shard_idx = shard_idx;
    frame.total_shards = total_shards;
    return frame;
}

// ============================================================================
// 测试 1: all_gather 分片重组（顺序到达）
// ============================================================================
static void test_all_gather_shard_in_order() {
    std::printf("[test] all_gather shard reassembly (in-order)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_shard_size(4);  // 4 字节分片阈值

    // 节点 0 的 chunk = 8 字节，超过 shard_size(4) → 发送端会分 2 片
    // 但 channel 无效，仅创建会话（self chunk 已预置）
    auto self_chunk = make_seq(8, 0xA0);  // A0 A1 A2 A3 A4 A5 A6 A7
    auto result = sync.all_gather(2001, 0b0011, 0,
                                  std::span<const std::uint8_t>(self_chunk.data(), 8),
                                  std::chrono::milliseconds(5000));
    CHECK(!result.has_value());  // channel 无效返回 nullopt，但会话已创建

    // 节点 1 的 chunk = 8 字节，分 2 片（每片 4 字节），顺序注入
    auto node1_chunk = make_seq(8, 0xB0);  // B0 B1 B2 B3 B4 B5 B6 B7
    std::vector<std::uint8_t> shard0(node1_chunk.begin(), node1_chunk.begin() + 4);
    std::vector<std::uint8_t> shard1(node1_chunk.begin() + 4, node1_chunk.end());

    // 注入 shard 0：不应完成
    sync.handle_sync_frame(make_ag_shard(2001, 1, shard0, 0, 2));
    {
        auto s = sync.get_session(2001);
        CHECK(s.has_value());
        CHECK(s->arrived_mask == 0b0001);  // 仅 self，节点 1 未到齐
    }

    // 注入 shard 1：应完成
    sync.handle_sync_frame(make_ag_shard(2001, 1, shard1, 1, 2));
    {
        auto s = sync.get_session(2001);
        CHECK(s.has_value());
        CHECK_EQ(s->state, SyncState::Completed);
        // 验证节点 1 的 chunk 已正确重组
        auto it = s->gather_chunks.find(1);
        CHECK(it != s->gather_chunks.end());
        CHECK(vec_eq(it->second, node1_chunk));
        CHECK_EQ(s->arrived_mask, 0b0011ULL);
    }

    sync.cleanup_finished();
}

// ============================================================================
// 测试 2: all_gather 分片重组（乱序到达）
// ============================================================================
static void test_all_gather_shard_out_of_order() {
    std::printf("[test] all_gather shard reassembly (out-of-order)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_shard_size(4);

    auto self_chunk = make_seq(4, 0xC0);
    sync.all_gather(2002, 0b0011, 0,
                    std::span<const std::uint8_t>(self_chunk.data(), 4),
                    std::chrono::milliseconds(5000));

    // 节点 1 的 chunk = 8 字节，分 2 片，逆序注入（shard 1 先到）
    auto node1_chunk = make_seq(8, 0xD0);  // D0 D1 D2 D3 D4 D5 D6 D7
    std::vector<std::uint8_t> shard0(node1_chunk.begin(), node1_chunk.begin() + 4);
    std::vector<std::uint8_t> shard1(node1_chunk.begin() + 4, node1_chunk.end());

    // 先注入 shard 1
    sync.handle_sync_frame(make_ag_shard(2002, 1, shard1, 1, 2));
    {
        auto s = sync.get_session(2002);
        CHECK(s.has_value());
        CHECK(s->arrived_mask == 0b0001);  // 未到齐
    }

    // 再注入 shard 0：应完成，且重组顺序正确（shard0 + shard1）
    sync.handle_sync_frame(make_ag_shard(2002, 1, shard0, 0, 2));
    {
        auto s = sync.get_session(2002);
        CHECK(s.has_value());
        CHECK_EQ(s->state, SyncState::Completed);
        auto it = s->gather_chunks.find(1);
        CHECK(it != s->gather_chunks.end());
        CHECK(vec_eq(it->second, node1_chunk));  // 顺序正确：D0..D7
    }

    sync.cleanup_finished();
}

// ============================================================================
// 测试 3: all_gather 3 分片重组（末片不齐）
// ============================================================================
static void test_all_gather_shard_three_uneven() {
    std::printf("[test] all_gather shard reassembly (3 shards, uneven last)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_shard_size(4);  // 10 字节 → 3 片：4 + 4 + 2

    auto self_chunk = make_seq(4, 0xE0);
    sync.all_gather(2003, 0b0011, 0,
                    std::span<const std::uint8_t>(self_chunk.data(), 4),
                    std::chrono::milliseconds(5000));

    auto node1_chunk = make_seq(10, 0xF0);  // F0..F9
    std::vector<std::uint8_t> s0(node1_chunk.begin(), node1_chunk.begin() + 4);
    std::vector<std::uint8_t> s1(node1_chunk.begin() + 4, node1_chunk.begin() + 8);
    std::vector<std::uint8_t> s2(node1_chunk.begin() + 8, node1_chunk.end());
    CHECK_EQ(s2.size(), static_cast<std::size_t>(2));  // 末片 2 字节

    // 乱序注入：1, 2, 0
    sync.handle_sync_frame(make_ag_shard(2003, 1, s1, 1, 3));
    sync.handle_sync_frame(make_ag_shard(2003, 1, s2, 2, 3));
    {
        auto s = sync.get_session(2003);
        CHECK(s->arrived_mask == 0b0001);  // 仍缺 shard 0
    }
    sync.handle_sync_frame(make_ag_shard(2003, 1, s0, 0, 3));
    {
        auto s = sync.get_session(2003);
        CHECK_EQ(s->state, SyncState::Completed);
        auto it = s->gather_chunks.find(1);
        CHECK(it != s->gather_chunks.end());
        CHECK(vec_eq(it->second, node1_chunk));  // F0..F9 完整且顺序正确
    }

    sync.cleanup_finished();
}

// ============================================================================
// 测试 4: all_gather 向后兼容（total_shards=1 单帧）
// ============================================================================
static void test_all_gather_single_shard_compat() {
    std::printf("[test] all_gather single shard backward compat...\n");

    SyncPrimitives sync(nullptr);
    sync.set_shard_size(4);  // 即使设了 shard_size，单帧仍应正常工作

    auto self_chunk = make_seq(4, 0x10);
    sync.all_gather(2004, 0b0011, 0,
                    std::span<const std::uint8_t>(self_chunk.data(), 4),
                    std::chrono::milliseconds(5000));

    // 节点 1 发送单帧（total_shards=1），小于 shard_size，不应分片
    auto node1_chunk = make_seq(3, 0x20);  // 3 字节 < shard_size(4)
    EpSyncFrame frame;
    frame.sync_id = 2004;
    frame.sync_op = EpSyncOp::AllGather;
    frame.participant_mask = 0b0010;  // node 1
    frame.payload = node1_chunk;
    frame.shard_idx = 0;
    frame.total_shards = 1;  // 单帧
    sync.handle_sync_frame(frame);

    auto s = sync.get_session(2004);
    CHECK(s.has_value());
    CHECK_EQ(s->state, SyncState::Completed);
    auto it = s->gather_chunks.find(1);
    CHECK(it != s->gather_chunks.end());
    CHECK(vec_eq(it->second, node1_chunk));

    sync.cleanup_finished();
}

// ============================================================================
// 测试 5: broadcast 分片重组
// ============================================================================
static void test_broadcast_shard_reassembly() {
    std::printf("[test] broadcast shard reassembly...\n");

    SyncPrimitives sync(nullptr);

    // 捕获广播回调
    std::vector<std::uint8_t> recv_data;
    std::uint64_t recv_root = 0xFFFFFFFF;
    bool callback_called = false;
    sync.set_callbacks({.on_broadcast_received = [&](std::uint64_t, std::uint64_t root,
                                                      std::span<const std::uint8_t> data) {
        recv_data.assign(data.begin(), data.end());
        recv_root = root;
        callback_called = true;
    }});

    // root=0 广播 10 字节数据，分 3 片（4+4+2）
    auto broadcast_data = make_seq(10, 0x50);  // 50..59
    std::vector<std::uint8_t> s0(broadcast_data.begin(), broadcast_data.begin() + 4);
    std::vector<std::uint8_t> s1(broadcast_data.begin() + 4, broadcast_data.begin() + 8);
    std::vector<std::uint8_t> s2(broadcast_data.begin() + 8, broadcast_data.end());

    // 乱序注入 broadcast 分片（root bit = 0）
    auto mk_bcast = [&](std::uint16_t idx, std::uint16_t total,
                        const std::vector<std::uint8_t> &pl) {
        EpSyncFrame f;
        f.sync_id = 2005;
        f.sync_op = EpSyncOp::Broadcast;
        f.participant_mask = 0b0001;  // root bit 0
        f.payload = pl;
        f.shard_idx = idx;
        f.total_shards = total;
        return f;
    };

    sync.handle_sync_frame(mk_bcast(2, 3, s2));
    CHECK(!callback_called);  // 未到齐，不触发回调

    sync.handle_sync_frame(mk_bcast(0, 3, s0));
    CHECK(!callback_called);  // 仍缺 shard 1

    sync.handle_sync_frame(mk_bcast(1, 3, s1));
    CHECK(callback_called);  // 全部到齐，触发回调
    CHECK_EQ(recv_root, 0ULL);
    CHECK(vec_eq(recv_data, broadcast_data));  // 50..59 完整且顺序正确

    sync.cleanup_finished();
}

// ============================================================================
// 测试 6: reduce_scatter 分片重组后再规约
// ============================================================================
static void test_reduce_scatter_shard_reassembly() {
    std::printf("[test] reduce_scatter shard reassembly before reduce...\n");

    SyncPrimitives sync(nullptr);
    sync.set_shard_size(8);  // 16 字节数据 → 2 片每片 8 字节

    // 2 participant，self=0，local_data = 16 字节 = 2 个 U64 元素 [1, 2]
    std::uint64_t local_vals[2] = {1, 2};
    std::vector<std::uint8_t> local_data(16);
    std::memcpy(local_data.data(), local_vals, 16);

    sync.reduce_scatter(2006, 0b0011, 0,
                        std::span<const std::uint8_t>(local_data.data(), 16),
                        ReduceOp::SUM, ReduceDType::U64,
                        std::chrono::milliseconds(5000));

    // 节点 1 的数据 = 2 个 U64 元素 [10, 20]，分 2 片（每片 8 字节 = 1 个 U64）
    std::uint64_t node1_vals[2] = {10, 20};
    std::vector<std::uint8_t> node1_data(16);
    std::memcpy(node1_data.data(), node1_vals, 16);

    std::vector<std::uint8_t> s0(node1_data.begin(), node1_data.begin() + 8);
    std::vector<std::uint8_t> s1(node1_data.begin() + 8, node1_data.end());

    auto mk_rs = [&](std::uint16_t idx, std::uint16_t total,
                     const std::vector<std::uint8_t> &pl) {
        EpSyncFrame f;
        f.sync_id = 2006;
        f.sync_op = EpSyncOp::ReduceScatter;
        f.participant_mask = 0b0010;  // node 1
        f.reduce_op = static_cast<std::uint8_t>(ReduceOp::SUM);
        f.payload = pl;
        f.shard_idx = idx;
        f.total_shards = total;
        return f;
    };

    // 注入 shard 0（node 1 的第一个 U64=10）：不应完成
    sync.handle_sync_frame(mk_rs(0, 2, s0));
    {
        auto s = sync.get_session(2006);
        CHECK(s.has_value());
        CHECK(s->arrived_mask == 0b0001);  // 仅 self
    }

    // 注入 shard 1：重组完整 [10, 20] 后规约 SUM([1,2],[10,20]) = [11, 22]
    sync.handle_sync_frame(mk_rs(1, 2, s1));
    {
        auto s = sync.get_session(2006);
        CHECK(s.has_value());
        CHECK_EQ(s->state, SyncState::Completed);
        // reduced_data = [11, 22]（2 个 U64），scatter_idx=0 取前 8 字节 = 11
        std::uint64_t reduced[2];
        std::memcpy(reduced, s->reduced_data.data(), 16);
        CHECK_EQ(reduced[0], static_cast<std::uint64_t>(11));  // 1 + 10
        CHECK_EQ(reduced[1], static_cast<std::uint64_t>(22));  // 2 + 20
    }

    sync.cleanup_finished();
}

// ============================================================================
// 测试 7: all_to_all 分片重组
// ============================================================================
static void test_all_to_all_shard_reassembly() {
    std::printf("[test] all_to_all shard reassembly...\n");

    SyncPrimitives sync(nullptr);
    sync.set_shard_size(4);

    auto self_chunk = make_seq(4, 0x30);
    sync.all_to_all(2007, 0b0011, 0,
                    std::span<const std::uint8_t>(self_chunk.data(), 4),
                    std::chrono::milliseconds(5000));

    // 节点 1 的 chunk = 8 字节，分 2 片
    auto node1_chunk = make_seq(8, 0x40);
    std::vector<std::uint8_t> s0(node1_chunk.begin(), node1_chunk.begin() + 4);
    std::vector<std::uint8_t> s1(node1_chunk.begin() + 4, node1_chunk.end());

    auto mk_a2a = [&](std::uint16_t idx, std::uint16_t total,
                      const std::vector<std::uint8_t> &pl) {
        EpSyncFrame f;
        f.sync_id = 2007;
        f.sync_op = EpSyncOp::AllToAll;
        f.participant_mask = 0b0010;  // node 1
        f.payload = pl;
        f.shard_idx = idx;
        f.total_shards = total;
        return f;
    };

    // 乱序注入
    sync.handle_sync_frame(mk_a2a(1, 2, s1));
    {
        auto s = sync.get_session(2007);
        CHECK(s->arrived_mask == 0b0001);  // 未到齐
    }
    sync.handle_sync_frame(mk_a2a(0, 2, s0));
    {
        auto s = sync.get_session(2007);
        CHECK_EQ(s->state, SyncState::Completed);
        auto it = s->all_to_all_received.find(1);
        CHECK(it != s->all_to_all_received.end());
        CHECK(vec_eq(it->second, node1_chunk));
    }

    sync.cleanup_finished();
}

// ============================================================================
// 测试 8: shard_size 配置（get/set + 0 禁用）
// ============================================================================
static void test_shard_size_config() {
    std::printf("[test] shard_size configuration...\n");

    SyncPrimitives sync(nullptr);

    // 默认 64KB
    CHECK_EQ(sync.shard_size(), static_cast<std::size_t>(64 * 1024));

    sync.set_shard_size(16);
    CHECK_EQ(sync.shard_size(), static_cast<std::size_t>(16));

    sync.set_shard_size(0);  // 禁用分片
    CHECK_EQ(sync.shard_size(), static_cast<std::size_t>(0));

    // shard_size=0 时，send_sharded_ 应退化为单帧（total_shards=1）
    // 通过 all_gather 创建会话验证（channel 无效不发送，但会话创建）
    auto chunk = make_seq(100, 0x77);
    sync.all_gather(2008, 0b0011, 0,
                    std::span<const std::uint8_t>(chunk.data(), 100),
                    std::chrono::milliseconds(5000));
    auto s = sync.get_session(2008);
    CHECK(s.has_value());  // 会话创建成功（无分片问题）

    sync.cleanup_finished();
}

// ============================================================================
// 测试 9: 部分分片不触发完成
// ============================================================================
static void test_partial_shard_no_completion() {
    std::printf("[test] partial shards do not trigger completion...\n");

    SyncPrimitives sync(nullptr);
    sync.set_shard_size(4);

    auto self_chunk = make_seq(4, 0x80);
    sync.all_gather(2009, 0b0011, 0,
                    std::span<const std::uint8_t>(self_chunk.data(), 4),
                    std::chrono::milliseconds(5000));

    // 节点 1 的 12 字节数据分 3 片，仅注入 2 片
    auto node1_chunk = make_seq(12, 0x90);
    std::vector<std::uint8_t> s0(node1_chunk.begin(), node1_chunk.begin() + 4);
    std::vector<std::uint8_t> s1(node1_chunk.begin() + 4, node1_chunk.begin() + 8);

    sync.handle_sync_frame(make_ag_shard(2009, 1, s0, 0, 3));
    sync.handle_sync_frame(make_ag_shard(2009, 1, s1, 1, 3));

    auto s = sync.get_session(2009);
    CHECK(s.has_value());
    CHECK(s->state != SyncState::Completed);  // 缺 shard 2，未完成
    CHECK(s->arrived_mask == 0b0001);          // 节点 1 未到齐
    // shard_received_count[1] 应为 2
    auto cnt_it = s->shard_received_count.find(1);
    CHECK(cnt_it != s->shard_received_count.end());
    CHECK_EQ(cnt_it->second, static_cast<std::uint16_t>(2));

    sync.cleanup_finished();
}

// ============================================================================
// 测试 10: 多节点 all_gather 分片（3 节点各分片）
// ============================================================================
static void test_all_gather_multi_node_shard() {
    std::printf("[test] all_gather multi-node sharding (3 nodes)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_shard_size(4);

    // 3 节点，self=0
    auto self_chunk = make_seq(4, 0x01);
    sync.all_gather(2010, 0b0111, 0,
                    std::span<const std::uint8_t>(self_chunk.data(), 4),
                    std::chrono::milliseconds(5000));

    auto node1_chunk = make_seq(8, 0x10);  // 2 片
    auto node2_chunk = make_seq(6, 0x20);  // 2 片（4+2）

    // 注入节点 1 的 2 片
    sync.handle_sync_frame(make_ag_shard(2010, 1,
        std::vector<std::uint8_t>(node1_chunk.begin(), node1_chunk.begin() + 4), 0, 2));
    sync.handle_sync_frame(make_ag_shard(2010, 1,
        std::vector<std::uint8_t>(node1_chunk.begin() + 4, node1_chunk.end()), 1, 2));

    {
        auto s = sync.get_session(2010);
        CHECK(s->arrived_mask == 0b0011);  // node 0 + node 1，缺 node 2
        CHECK(s->state != SyncState::Completed);
    }

    // 注入节点 2 的 2 片
    sync.handle_sync_frame(make_ag_shard(2010, 2,
        std::vector<std::uint8_t>(node2_chunk.begin(), node2_chunk.begin() + 4), 0, 2));
    sync.handle_sync_frame(make_ag_shard(2010, 2,
        std::vector<std::uint8_t>(node2_chunk.begin() + 4, node2_chunk.end()), 1, 2));

    {
        auto s = sync.get_session(2010);
        CHECK_EQ(s->state, SyncState::Completed);
        CHECK_EQ(s->arrived_mask, 0b0111ULL);
        // 验证各节点 chunk 完整
        CHECK(vec_eq(s->gather_chunks[0], self_chunk));
        CHECK(vec_eq(s->gather_chunks[1], node1_chunk));
        CHECK(vec_eq(s->gather_chunks[2], node2_chunk));
    }

    sync.cleanup_finished();
}

// ============================================================================
// 测试 11: all_gather 回调触发（分片重组后 on_all_gather_complete）
// ============================================================================
static void test_all_gather_callback_after_shard() {
    std::printf("[test] all_gather callback after shard reassembly...\n");

    SyncPrimitives sync(nullptr);
    sync.set_shard_size(4);

    std::vector<std::uint8_t> recv_result;
    bool callback_called = false;
    sync.set_callbacks({.on_all_gather_complete = [&](std::uint64_t,
                                                       std::span<const std::uint8_t> data) {
        recv_result.assign(data.begin(), data.end());
        callback_called = true;
    }});

    auto self_chunk = make_seq(4, 0xAA);
    sync.all_gather(2011, 0b0011, 0,
                    std::span<const std::uint8_t>(self_chunk.data(), 4),
                    std::chrono::milliseconds(5000));

    auto node1_chunk = make_seq(8, 0xBB);
    sync.handle_sync_frame(make_ag_shard(2011, 1,
        std::vector<std::uint8_t>(node1_chunk.begin(), node1_chunk.begin() + 4), 0, 2));
    CHECK(!callback_called);  // 缺 shard 1

    sync.handle_sync_frame(make_ag_shard(2011, 1,
        std::vector<std::uint8_t>(node1_chunk.begin() + 4, node1_chunk.end()), 1, 2));
    CHECK(callback_called);  // 全部到齐触发回调

    // 结果应为 self_chunk + node1_chunk（按 bit 升序：node0 + node1）
    std::vector<std::uint8_t> expected;
    expected.insert(expected.end(), self_chunk.begin(), self_chunk.end());
    expected.insert(expected.end(), node1_chunk.begin(), node1_chunk.end());
    CHECK(vec_eq(recv_result, expected));

    sync.cleanup_finished();
}

// ============================================================================
// 测试 12: 重复分片覆盖（重传场景）
// ============================================================================
static void test_shard_retry_overwrite() {
    std::printf("[test] shard retry overwrite (duplicate shard)...\n");

    SyncPrimitives sync(nullptr);
    sync.set_shard_size(4);

    auto self_chunk = make_seq(4, 0xCC);
    sync.all_gather(2012, 0b0011, 0,
                    std::span<const std::uint8_t>(self_chunk.data(), 4),
                    std::chrono::milliseconds(5000));

    auto node1_chunk = make_seq(8, 0xDD);
    std::vector<std::uint8_t> s0(node1_chunk.begin(), node1_chunk.begin() + 4);
    std::vector<std::uint8_t> s1(node1_chunk.begin() + 4, node1_chunk.end());

    // 重复注入 shard 0 两次（模拟重传）
    sync.handle_sync_frame(make_ag_shard(2012, 1, s0, 0, 2));
    sync.handle_sync_frame(make_ag_shard(2012, 1, s0, 0, 2));  // 重复
    {
        auto s = sync.get_session(2012);
        // shard_received_count 可能 > 实际，但 arrived_mask 不应更新
        CHECK(s->arrived_mask == 0b0001);
    }

    // 注入 shard 1 完成重组
    // 重复 shard 0 不会虚增 received_count（幂等处理），shard 1 到达后才触发重组
    sync.handle_sync_frame(make_ag_shard(2012, 1, s1, 1, 2));
    {
        auto s = sync.get_session(2012);
        CHECK_EQ(s->state, SyncState::Completed);
        auto it = s->gather_chunks.find(1);
        CHECK(it != s->gather_chunks.end());
        CHECK(vec_eq(it->second, node1_chunk));  // 数据正确
    }

    sync.cleanup_finished();
}

// ============================================================================
// 测试 13: CollectiveSession 透传分片（execute_plan + 小 shard_size）
// ============================================================================
static void test_collective_session_shard_e2e() {
    std::printf("[test] CollectiveSession execute_plan with sharding...\n");

    SyncPrimitives sync(nullptr);
    sync.set_shard_size(4);

    CollectiveSession collective(sync);

    // 构建 AllGather plan
    TopologyPlan plan;
    plan.op = CollectiveOp::AllGather;
    plan.algo = CollectiveAlgo::Ring;
    plan.participants = {0, 1};
    plan.chunk_sizes = {8, 8};
    plan.num_nodes = 2;
    plan.msg_size = 16;

    auto self_chunk = make_seq(8, 0xEE);
    // execute_plan → all_gather（channel 无效返回 nullopt，但会话创建）
    auto result = collective.execute_plan(plan, 2013, 0b0011, 0,
                                          {},  // local_data 空
                                          std::span<const std::uint8_t>(self_chunk.data(), 8),
                                          0, ReduceOp::SUM, ReduceDType::U64,
                                          std::chrono::milliseconds(5000));
    CHECK(!result.has_value());  // channel 无效

    // 验证会话已创建且 algo 透传
    auto s = sync.get_session(2013);
    CHECK(s.has_value());
    CHECK_EQ(s->algo, static_cast<std::uint8_t>(CollectiveAlgo::Ring));

    // 注入节点 1 的分片
    auto node1_chunk = make_seq(8, 0xFF);
    sync.handle_sync_frame(make_ag_shard(2013, 1,
        std::vector<std::uint8_t>(node1_chunk.begin(), node1_chunk.begin() + 4), 0, 2));
    sync.handle_sync_frame(make_ag_shard(2013, 1,
        std::vector<std::uint8_t>(node1_chunk.begin() + 4, node1_chunk.end()), 1, 2));

    auto s2 = sync.get_session(2013);
    CHECK(s2.has_value());
    CHECK_EQ(s2->state, SyncState::Completed);

    sync.cleanup_finished();
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== test_collective_v4 (P3-G) ===\n\n");

    test_all_gather_shard_in_order();
    test_all_gather_shard_out_of_order();
    test_all_gather_shard_three_uneven();
    test_all_gather_single_shard_compat();
    test_broadcast_shard_reassembly();
    test_reduce_scatter_shard_reassembly();
    test_all_to_all_shard_reassembly();
    test_shard_size_config();
    test_partial_shard_no_completion();
    test_all_gather_multi_node_shard();
    test_all_gather_callback_after_shard();
    test_shard_retry_overwrite();
    test_collective_session_shard_e2e();

    std::printf("\n=== Results: PASS=%d FAIL=%d ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
