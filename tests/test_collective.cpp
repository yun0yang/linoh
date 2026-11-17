// test_collective.cpp — v2.1 Phase 2 集合通信原语单元测试
//
// 验证 v2.1 Phase 2 交付物：
//   1. CollectiveSession 构造 + 配置访问
//   2. AllGather 帧接收 + chunk 收集 + 完成回调（4 节点）
//   3. AllGather 2 节点（最小 ring）
//   4. AllGather 被动会话（无主动发起）
//   5. AllGather 超时处理
//   6. Broadcast 帧接收 + 回调
//   7. Broadcast root 校验
//   8. Broadcast 被动接收
//   9. CollectiveSession::all_gather 委托验证
//  10. CollectiveSession::broadcast 委托验证
//  11. CollectiveOp / CollectiveAlgo 转字符串
//  12. handle_sync_frame 路由 AllGather/Broadcast
//  13. SyncSession 字段扩展验证（gather_chunks/root_node_id）
//  14. all_gather channel=nullptr 失败处理
//  15. broadcast channel=nullptr 失败处理
//  16. all_gather 超大 chunk 拒绝
//
// 测试策略：
//   - SyncPrimitives 构造传入 nullptr（不依赖真实 EpChannel）
//   - all_gather/broadcast 发送路径返回 false（channel 无效），但可验证参数校验
//   - 通过 handle_sync_frame 模拟接收帧，测试接收逻辑和回调
//   - 不依赖真实 QUIC 连接

#include "linoh/multimodal/collective.hpp"
#include "linoh/multimodal/ep_frames.hpp"
#include "linoh/multimodal/sync_primitives.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

using namespace linoh;
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

#define CHECK_NE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a != _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s != %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ============================================================================
// 辅助函数
// ============================================================================

/// 模拟接收 AllGather 帧
static void simulate_recv_all_gather(SyncPrimitives &sync, std::uint64_t sync_id,
                                       std::uint64_t from_bit,
                                       std::span<const std::uint8_t> data) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::AllGather;
    frame.participant_mask = static_cast<std::uint64_t>(1) << from_bit;
    frame.payload.assign(data.begin(), data.end());
    sync.handle_sync_frame(frame);
}

/// 模拟接收 Broadcast 帧
static void simulate_recv_broadcast(SyncPrimitives &sync, std::uint64_t sync_id,
                                     std::uint64_t root_bit,
                                     std::span<const std::uint8_t> data) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::Broadcast;
    frame.participant_mask = static_cast<std::uint64_t>(1) << root_bit;
    frame.payload.assign(data.begin(), data.end());
    sync.handle_sync_frame(frame);
}

/// 构造测试数据
static std::vector<std::uint8_t> make_data(std::initializer_list<std::uint8_t> vals) {
    return std::vector<std::uint8_t>(vals);
}

/// 构造大 chunk（超过 4KB 限制）
static std::vector<std::uint8_t> make_large_chunk(std::size_t size) {
    return std::vector<std::uint8_t>(size, 0xAA);
}

// ============================================================================
// TEST 1: CollectiveSession 构造 + 配置访问
// ============================================================================

static void test_construction() {
    std::printf("[test] CollectiveSession construction + config access...\n");

    SyncPrimitives sync(nullptr);
    CollectiveSession collective(sync);

    // 默认配置检查
    CHECK_EQ(collective.config().default_timeout, std::chrono::seconds(30));
    CHECK_EQ(collective.config().default_reduce_op, ReduceOp::SUM);
    CHECK_EQ(collective.config().default_reduce_dtype, ReduceDType::U64);
    CHECK_EQ(collective.config().default_algo, CollectiveAlgo::Ring);

    // 更新配置
    CollectiveConfig new_config;
    new_config.default_timeout = std::chrono::seconds(60);
    new_config.default_reduce_op = ReduceOp::MAX;
    collective.set_config(new_config);
    CHECK_EQ(collective.config().default_timeout, std::chrono::seconds(60));
    CHECK_EQ(collective.config().default_reduce_op, ReduceOp::MAX);

    // sync_primitives 引用访问
    CHECK_EQ(&collective.sync_primitives(), &sync);
}

// ============================================================================
// TEST 2: AllGather 帧接收 + chunk 收集 + 完成回调（4 节点）
// ============================================================================

static void test_all_gather_4_nodes() {
    std::printf("[test] all_gather 4 nodes (chunk collection + completion)...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> gather_complete{false};
    std::vector<std::uint8_t> gathered_result;

    sync.set_callbacks({
        .on_all_gather_complete = [&](std::uint64_t sync_id, std::span<const std::uint8_t> result) {
            if (sync_id == 1001) {
                gather_complete = true;
                gathered_result.assign(result.begin(), result.end());
            }
        }
    });

    // 模拟发起方会话：节点 0 发起 all_gather，participant_mask=0b1111
    // 由于 channel=nullptr，all_gather 发送失败返回 nullopt，但会话已创建
    // 这里直接通过 handle_sync_frame 模拟接收其他节点 chunk
    auto chunk0 = make_data({0x10, 0x20});
    auto chunk1 = make_data({0x30, 0x40});
    auto chunk2 = make_data({0x50, 0x60});
    auto chunk3 = make_data({0x70, 0x80});

    // 先手动创建会话（模拟发起方），participant_mask=0b1111，self_node_id=0
    // 通过 all_gather API 创建会话（会因 channel 无效返回 nullopt，但会话已入 sessions_）
    auto result = sync.all_gather(1001, 0b1111, 0,
                                   std::span<const std::uint8_t>(chunk0.data(), chunk0.size()),
                                   std::chrono::milliseconds(100));
    // channel 无效，返回 nullopt，但会话已创建并预置 chunk0
    CHECK(!result.has_value());

    // 检查会话已创建
    auto session = sync.get_session(1001);
    CHECK(session.has_value());
    CHECK_EQ(session->participant_mask, static_cast<std::uint64_t>(0b1111));
    CHECK_EQ(session->gather_chunk_size, static_cast<std::size_t>(2));
    CHECK_EQ(session->gather_chunks.size(), static_cast<std::size_t>(1));  // 仅自身 chunk0
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0b0001));  // bit 0 已到达

    // 模拟接收节点 1 的 chunk
    simulate_recv_all_gather(sync, 1001, 1,
                             std::span<const std::uint8_t>(chunk1.data(), chunk1.size()));
    session = sync.get_session(1001);
    CHECK(session.has_value());
    CHECK_EQ(session->gather_chunks.size(), static_cast<std::size_t>(2));
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0b0011));
    CHECK(!gather_complete.load());  // 未全部到齐

    // 模拟接收节点 2 的 chunk
    simulate_recv_all_gather(sync, 1001, 2,
                             std::span<const std::uint8_t>(chunk2.data(), chunk2.size()));
    session = sync.get_session(1001);
    CHECK(session.has_value());
    CHECK_EQ(session->gather_chunks.size(), static_cast<std::size_t>(3));
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0b0111));
    CHECK(!gather_complete.load());

    // 模拟接收节点 3 的 chunk（全部到齐）
    simulate_recv_all_gather(sync, 1001, 3,
                             std::span<const std::uint8_t>(chunk3.data(), chunk3.size()));

    CHECK(gather_complete.load());
    // 结果应为 chunk0 + chunk1 + chunk2 + chunk3（按 bit 升序）
    CHECK_EQ(gathered_result.size(), static_cast<std::size_t>(8));
    CHECK_EQ(gathered_result[0], static_cast<std::uint8_t>(0x10));
    CHECK_EQ(gathered_result[1], static_cast<std::uint8_t>(0x20));
    CHECK_EQ(gathered_result[2], static_cast<std::uint8_t>(0x30));
    CHECK_EQ(gathered_result[3], static_cast<std::uint8_t>(0x40));
    CHECK_EQ(gathered_result[4], static_cast<std::uint8_t>(0x50));
    CHECK_EQ(gathered_result[5], static_cast<std::uint8_t>(0x60));
    CHECK_EQ(gathered_result[6], static_cast<std::uint8_t>(0x70));
    CHECK_EQ(gathered_result[7], static_cast<std::uint8_t>(0x80));
}

// ============================================================================
// TEST 3: AllGather 2 节点（最小 ring）
// ============================================================================

static void test_all_gather_2_nodes() {
    std::printf("[test] all_gather 2 nodes (minimal ring)...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> gather_complete{false};
    sync.set_callbacks({
        .on_all_gather_complete = [&](std::uint64_t sync_id, std::span<const std::uint8_t>) {
            if (sync_id == 2001) gather_complete = true;
        }
    });

    auto chunk0 = make_data({0xAA});
    auto chunk1 = make_data({0xBB});

    // 节点 0 发起 all_gather，participant_mask=0b0011
    auto result = sync.all_gather(2001, 0b0011, 0,
                                   std::span<const std::uint8_t>(chunk0.data(), chunk0.size()),
                                   std::chrono::milliseconds(100));
    CHECK(!result.has_value());

    // 模拟接收节点 1 的 chunk
    simulate_recv_all_gather(sync, 2001, 1,
                             std::span<const std::uint8_t>(chunk1.data(), chunk1.size()));

    CHECK(gather_complete.load());
    auto session = sync.get_session(2001);
    if (session.has_value()) {
        CHECK_EQ(session->state, SyncState::Completed);
        CHECK_EQ(session->gather_chunks.size(), static_cast<std::size_t>(2));
    }
}

// ============================================================================
// TEST 4: AllGather 被动会话（无主动发起）
// ============================================================================

static void test_all_gather_passive() {
    std::printf("[test] all_gather passive session (no initiator)...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> callback_called{false};
    sync.set_callbacks({
        .on_all_gather_complete = [&](std::uint64_t, std::span<const std::uint8_t>) {
            callback_called = true;
        }
    });

    auto chunk = make_data({0x01, 0x02, 0x03});

    // 被动接收 AllGather 帧（无主动发起会话）
    simulate_recv_all_gather(sync, 3001, 2,
                             std::span<const std::uint8_t>(chunk.data(), chunk.size()));

    // 被动会话被创建，但因 participant_mask 不完整（仅为发送方 bit），不触发 complete
    auto session = sync.get_session(3001);
    CHECK(session.has_value());
    CHECK_EQ(session->state, SyncState::Waiting);
    CHECK_EQ(session->gather_chunks.size(), static_cast<std::size_t>(1));
    CHECK(!callback_called.load());  // 被动会话不触发 complete
}

// ============================================================================
// TEST 5: AllGather 超时处理
// ============================================================================

static void test_all_gather_timeout() {
    std::printf("[test] all_gather timeout...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> timeout_called{false};
    sync.set_callbacks({
        .on_sync_timeout = [&](std::uint64_t sync_id) {
            if (sync_id == 4001) timeout_called = true;
        }
    });

    auto chunk0 = make_data({0xCC});

    // 节点 0 发起 all_gather，participant_mask=0b1111，但只有自身到达
    // channel 无效时 all_gather 立即返回 nullopt，会话已创建（Waiting 状态，deadline=now+50ms）
    auto result = sync.all_gather(4001, 0b1111, 0,
                                   std::span<const std::uint8_t>(chunk0.data(), chunk0.size()),
                                   std::chrono::milliseconds(50));
    CHECK(!result.has_value());

    // 会话应存在（Waiting 状态）
    auto session = sync.get_session(4001);
    CHECK(session.has_value());
    CHECK_EQ(session->state, SyncState::Waiting);

    // 等待超时（50ms + 余量）
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    // 触发超时检测（check_timeouts 标记 TimedOut 并触发回调，但不删除会话）
    sync.check_timeouts();

    CHECK(timeout_called.load());
    // 会话标记为 TimedOut，需 cleanup_finished 实际删除
    auto timed_session = sync.get_session(4001);
    CHECK(timed_session.has_value());
    CHECK_EQ(timed_session->state, SyncState::TimedOut);
    sync.cleanup_finished();
    CHECK(!sync.get_session(4001).has_value());
}

// ============================================================================
// TEST 6: Broadcast 帧接收 + 回调
// ============================================================================

static void test_broadcast_recv() {
    std::printf("[test] broadcast frame receive + callback...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> broadcast_received{false};
    std::uint64_t recv_root = 0xFF;
    std::vector<std::uint8_t> recv_data;

    sync.set_callbacks({
        .on_broadcast_received = [&](std::uint64_t sync_id, std::uint64_t root_node_id,
                                      std::span<const std::uint8_t> data) {
            if (sync_id == 5001) {
                broadcast_received = true;
                recv_root = root_node_id;
                recv_data.assign(data.begin(), data.end());
            }
        }
    });

    auto data = make_data({0xDE, 0xAD, 0xBE, 0xEF});

    // 模拟接收 root=0 的广播
    simulate_recv_broadcast(sync, 5001, 0,
                            std::span<const std::uint8_t>(data.data(), data.size()));

    CHECK(broadcast_received.load());
    CHECK_EQ(recv_root, static_cast<std::uint64_t>(0));
    CHECK_EQ(recv_data.size(), static_cast<std::size_t>(4));
    CHECK_EQ(recv_data[0], static_cast<std::uint8_t>(0xDE));
    CHECK_EQ(recv_data[1], static_cast<std::uint8_t>(0xAD));
    CHECK_EQ(recv_data[2], static_cast<std::uint8_t>(0xBE));
    CHECK_EQ(recv_data[3], static_cast<std::uint8_t>(0xEF));

    // 会话应被创建并标记完成
    auto session = sync.get_session(5001);
    CHECK(session.has_value());
    CHECK_EQ(session->root_node_id, static_cast<std::uint64_t>(0));
    CHECK_EQ(session->state, SyncState::Completed);
    CHECK_EQ(session->local_data.size(), static_cast<std::size_t>(4));
}

// ============================================================================
// TEST 7: Broadcast root 校验（root 不在 participant_mask 中）
// ============================================================================

static void test_broadcast_root_validation() {
    std::printf("[test] broadcast root validation...\n");

    SyncPrimitives sync(nullptr);

    auto data = make_data({0x42});

    // root=5 不在 participant_mask=0b0011 中
    bool result = sync.broadcast(6001, 0b0011, 5,
                                  std::span<const std::uint8_t>(data.data(), data.size()));
    CHECK(!result);  // root 非法，返回 false

    // 会话不应被创建
    auto session = sync.get_session(6001);
    CHECK(!session.has_value());
}

// ============================================================================
// TEST 8: Broadcast 被动接收（无主动发起）
// ============================================================================

static void test_broadcast_passive() {
    std::printf("[test] broadcast passive receive...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<int> recv_count{0};
    sync.set_callbacks({
        .on_broadcast_received = [&](std::uint64_t, std::uint64_t, std::span<const std::uint8_t>) {
            ++recv_count;
        }
    });

    auto data1 = make_data({0x11});
    auto data2 = make_data({0x22});

    // 被动接收两个不同 sync_id 的广播
    simulate_recv_broadcast(sync, 7001, 0,
                            std::span<const std::uint8_t>(data1.data(), data1.size()));
    simulate_recv_broadcast(sync, 7002, 1,
                            std::span<const std::uint8_t>(data2.data(), data2.size()));

    CHECK_EQ(recv_count.load(), 2);

    // 两个会话都应被创建
    CHECK(sync.get_session(7001).has_value());
    CHECK(sync.get_session(7002).has_value());
    CHECK_EQ(sync.get_session(7001)->root_node_id, static_cast<std::uint64_t>(0));
    CHECK_EQ(sync.get_session(7002)->root_node_id, static_cast<std::uint64_t>(1));
}

// ============================================================================
// TEST 9: CollectiveSession::all_gather 委托验证
// ============================================================================

static void test_collective_all_gather() {
    std::printf("[test] CollectiveSession::all_gather delegation...\n");

    SyncPrimitives sync(nullptr);
    CollectiveSession collective(sync);

    // 设置自定义超时（短超时便于测试）
    CollectiveConfig config;
    config.default_timeout = std::chrono::milliseconds(50);
    collective.set_config(config);

    auto chunk = make_data({0x99});

    // channel=nullptr，all_gather 立即返回 nullopt（不阻塞）
    // 但会话已创建，deadline = now + config_.default_timeout（50ms）
    auto result = collective.all_gather(8001, 0b0011, 0,
                                         std::span<const std::uint8_t>(chunk.data(), chunk.size()));

    CHECK(!result.has_value());

    // 验证会话已创建且使用了配置的 50ms 超时
    auto session = sync.get_session(8001);
    CHECK(session.has_value());
    auto now = std::chrono::steady_clock::now();
    auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        session->deadline - now).count();
    // deadline 在未来且不超过 50ms（已过去极短时间）
    CHECK(remaining_ms > 0 && remaining_ms <= 50);

    // 等待超时后清理
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    sync.check_timeouts();
    sync.cleanup_finished();
    CHECK(!sync.get_session(8001).has_value());
}

// ============================================================================
// TEST 10: CollectiveSession::broadcast 委托验证
// ============================================================================

static void test_collective_broadcast() {
    std::printf("[test] CollectiveSession::broadcast delegation...\n");

    SyncPrimitives sync(nullptr);
    CollectiveSession collective(sync);

    auto data = make_data({0x55});

    // channel=nullptr，broadcast 应返回 false
    bool result = collective.broadcast(9001, 0b1111, 0,
                                        std::span<const std::uint8_t>(data.data(), data.size()));
    CHECK(!result);

    // root 非法也应返回 false
    result = collective.broadcast(9002, 0b0011, 5,
                                   std::span<const std::uint8_t>(data.data(), data.size()));
    CHECK(!result);
}

// ============================================================================
// TEST 11: CollectiveOp / CollectiveAlgo 转字符串
// ============================================================================

static void test_enum_to_string() {
    std::printf("[test] CollectiveOp/CollectiveAlgo to string...\n");

    CHECK_EQ(std::string(collective_op_name(CollectiveOp::Barrier)), std::string("barrier"));
    CHECK_EQ(std::string(collective_op_name(CollectiveOp::AllReduce)), std::string("all_reduce"));
    CHECK_EQ(std::string(collective_op_name(CollectiveOp::AllGather)), std::string("all_gather"));
    CHECK_EQ(std::string(collective_op_name(CollectiveOp::Broadcast)), std::string("broadcast"));
    CHECK_EQ(std::string(collective_op_name(CollectiveOp::ReduceScatter)), std::string("reduce_scatter"));
    CHECK_EQ(std::string(collective_op_name(CollectiveOp::AllToAll)), std::string("all_to_all"));

    CHECK_EQ(std::string(collective_algo_name(CollectiveAlgo::Ring)), std::string("ring"));
    CHECK_EQ(std::string(collective_algo_name(CollectiveAlgo::Tree)), std::string("tree"));
    CHECK_EQ(std::string(collective_algo_name(CollectiveAlgo::RecursiveHalving)), std::string("recursive_halving"));
    CHECK_EQ(std::string(collective_algo_name(CollectiveAlgo::PairwiseExchange)), std::string("pairwise_exchange"));
}

// ============================================================================
// TEST 12: handle_sync_frame 路由 AllGather/Broadcast
// ============================================================================

static void test_handle_sync_frame_routing() {
    std::printf("[test] handle_sync_frame routing AllGather/Broadcast...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> all_gather_called{false};
    std::atomic<bool> broadcast_called{false};

    sync.set_callbacks({
        .on_all_gather_complete = [&](std::uint64_t, std::span<const std::uint8_t>) {
            all_gather_called = true;
        },
        .on_broadcast_received = [&](std::uint64_t, std::uint64_t, std::span<const std::uint8_t>) {
            broadcast_called = true;
        }
    });

    // 构造 AllGather 帧并通过 handle_sync_frame 路由
    EpSyncFrame ag_frame;
    ag_frame.sync_id = 11001;
    ag_frame.sync_op = EpSyncOp::AllGather;
    ag_frame.participant_mask = 0b0001;
    ag_frame.payload = make_data({0x01});
    sync.handle_sync_frame(ag_frame);

    // AllGather 被动会话不触发 complete（participant_mask 不完整）
    CHECK(!all_gather_called.load());

    // 构造 Broadcast 帧并通过 handle_sync_frame 路由
    EpSyncFrame bc_frame;
    bc_frame.sync_id = 11002;
    bc_frame.sync_op = EpSyncOp::Broadcast;
    bc_frame.participant_mask = 0b0010;
    bc_frame.payload = make_data({0x02});
    sync.handle_sync_frame(bc_frame);

    CHECK(broadcast_called.load());
}

// ============================================================================
// TEST 13: SyncSession 字段扩展验证
// ============================================================================

static void test_sync_session_fields() {
    std::printf("[test] SyncSession extended fields (gather_chunks/root_node_id)...\n");

    SyncPrimitives sync(nullptr);

    // AllGather 创建会话后检查 gather_chunks 字段
    auto chunk = make_data({0xAA, 0xBB});
    sync.all_gather(12001, 0b0011, 0,
                     std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                     std::chrono::milliseconds(100));

    auto session = sync.get_session(12001);
    CHECK(session.has_value());
    CHECK_EQ(session->gather_chunk_size, static_cast<std::size_t>(2));
    CHECK_EQ(session->gather_chunks.count(0), static_cast<std::size_t>(1));  // bit 0 存在
    CHECK_EQ(session->gather_chunks[0].size(), static_cast<std::size_t>(2));
    CHECK_EQ(session->gather_chunks[0][0], static_cast<std::uint8_t>(0xAA));
    CHECK_EQ(session->root_node_id, static_cast<std::uint64_t>(0));  // 默认值

    // Broadcast 创建会话后检查 root_node_id 字段
    auto data = make_data({0xCC});
    sync.broadcast(12002, 0b0111, 2,
                    std::span<const std::uint8_t>(data.data(), data.size()));

    auto bc_session = sync.get_session(12002);
    CHECK(bc_session.has_value());
    CHECK_EQ(bc_session->root_node_id, static_cast<std::uint64_t>(2));
    CHECK_EQ(bc_session->local_data.size(), static_cast<std::size_t>(1));
    CHECK_EQ(bc_session->local_data[0], static_cast<std::uint8_t>(0xCC));
}

// ============================================================================
// TEST 14: all_gather channel=nullptr 失败处理
// ============================================================================

static void test_all_gather_null_channel() {
    std::printf("[test] all_gather null channel failure...\n");

    SyncPrimitives sync(nullptr);

    auto chunk = make_data({0x01});

    // channel=nullptr，应返回 nullopt
    auto result = sync.all_gather(13001, 0b0011, 0,
                                   std::span<const std::uint8_t>(chunk.data(), chunk.size()));
    CHECK(!result.has_value());

    // participant_mask=0 也应返回 nullopt
    result = sync.all_gather(13002, 0, 0,
                              std::span<const std::uint8_t>(chunk.data(), chunk.size()));
    CHECK(!result.has_value());

    // self_node_id 不在 participant_mask 中也应返回 nullopt
    result = sync.all_gather(13003, 0b0011, 5,
                              std::span<const std::uint8_t>(chunk.data(), chunk.size()));
    CHECK(!result.has_value());
}

// ============================================================================
// TEST 15: broadcast channel=nullptr 失败处理
// ============================================================================

static void test_broadcast_null_channel() {
    std::printf("[test] broadcast null channel failure...\n");

    SyncPrimitives sync(nullptr);

    auto data = make_data({0x02});

    // channel=nullptr，应返回 false
    bool result = sync.broadcast(14001, 0b0111, 0,
                                  std::span<const std::uint8_t>(data.data(), data.size()));
    CHECK(!result);

    // participant_mask=0 也应返回 false
    result = sync.broadcast(14002, 0, 0,
                             std::span<const std::uint8_t>(data.data(), data.size()));
    CHECK(!result);
}

// ============================================================================
// TEST 16: all_gather 超大 chunk 拒绝
// ============================================================================

static void test_all_gather_oversized_chunk() {
    std::printf("[test] all_gather oversized chunk rejection...\n");

    SyncPrimitives sync(nullptr);

    // 构造超过 4KB 的 chunk
    auto large_chunk = make_large_chunk(EpSyncFrame::kMaxPayloadLen + 1);

    auto result = sync.all_gather(15001, 0b0011, 0,
                                   std::span<const std::uint8_t>(large_chunk.data(), large_chunk.size()),
                                   std::chrono::milliseconds(100));
    CHECK(!result.has_value());

    // 会话不应被创建
    CHECK(!sync.get_session(15001).has_value());

    // broadcast 同样拒绝超大 payload
    bool bc_result = sync.broadcast(15002, 0b0111, 0,
                                     std::span<const std::uint8_t>(large_chunk.data(), large_chunk.size()));
    CHECK(!bc_result);
    CHECK(!sync.get_session(15002).has_value());
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== v2.1 Phase 2 Collective Primitives Unit Tests ===\n\n");

    test_construction();
    test_all_gather_4_nodes();
    test_all_gather_2_nodes();
    test_all_gather_passive();
    test_all_gather_timeout();
    test_broadcast_recv();
    test_broadcast_root_validation();
    test_broadcast_passive();
    test_collective_all_gather();
    test_collective_broadcast();
    test_enum_to_string();
    test_handle_sync_frame_routing();
    test_sync_session_fields();
    test_all_gather_null_channel();
    test_broadcast_null_channel();
    test_all_gather_oversized_chunk();

    std::printf("\n=== Test Summary ===\n");
    std::printf("PASS: %d\n", g_pass);
    std::printf("FAIL: %d\n", g_fail);
    std::printf("Total: %d\n", g_pass + g_fail);

    return g_fail == 0 ? 0 : 1;
}
