// test_collective_v2.cpp — v2.1 Phase 2 M2 集合通信原语单元测试
//
// 验证 v2.1 Phase 2 M2 交付物（ReduceScatter + AllToAll）：
//   1. ReduceScatter 4 节点 SUM（规约 + 分片提取验证）
//   2. ReduceScatter 2 节点（最小 ring）
//   3. ReduceScatter MAX 操作
//   4. ReduceScatter 被动会话
//   5. ReduceScatter 超时处理
//   6. ReduceScatter 参数校验（空数据/不能整除/self不在mask/超大payload）
//   7. AllToAll 4 节点（chunk 收集 + 拼接）
//   8. AllToAll 2 节点
//   9. AllToAll 被动会话
//  10. AllToAll 超时处理
//  11. AllToAll 参数校验
//  12. CollectiveSession::reduce_scatter 委托验证
//  13. CollectiveSession::all_to_all 委托验证
//  14. handle_sync_frame 路由 ReduceScatter/AllToAll
//  15. SyncSession 字段扩展验证（scatter_chunk_index/all_to_all_received）
//  16. EpSyncOp ReduceScatter/AllToAll 帧编解码
//
// 测试策略：
//   - SyncPrimitives 构造传入 nullptr（不依赖真实 EpChannel）
//   - reduce_scatter/all_to_all 发送路径返回 nullopt（channel 无效），但可验证参数校验
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

#define CHECK_GE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a >= _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s >= %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ============================================================================
// 辅助函数
// ============================================================================

static std::vector<std::uint8_t> make_data(std::initializer_list<std::uint8_t> vals) {
    return std::vector<std::uint8_t>(vals);
}

/// 构造 N 个 uint64 拼接的数据（小端序）
static std::vector<std::uint8_t> make_u64_array(std::initializer_list<std::uint64_t> vals) {
    std::vector<std::uint8_t> data;
    data.reserve(vals.size() * 8);
    for (auto v : vals) {
        std::uint64_t val = v;
        for (int i = 0; i < 8; ++i) {
            data.push_back(static_cast<std::uint8_t>((val >> (i * 8)) & 0xFF));
        }
    }
    return data;
}

/// 从 byte span 指定偏移读取一个 uint64（小端序）
static std::uint64_t read_u64(const std::vector<std::uint8_t> &data, std::size_t offset) {
    std::uint64_t val = 0;
    if (offset + 8 <= data.size()) {
        std::memcpy(&val, data.data() + offset, 8);
    }
    return val;
}

/// 模拟接收 ReduceScatter 帧
static void simulate_recv_reduce_scatter(SyncPrimitives &sync, std::uint64_t sync_id,
                                          std::uint64_t from_bit,
                                          std::span<const std::uint8_t> data,
                                          std::uint8_t reduce_op = 0) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::ReduceScatter;
    frame.participant_mask = static_cast<std::uint64_t>(1) << from_bit;
    frame.reduce_op = reduce_op;
    frame.payload.assign(data.begin(), data.end());
    sync.handle_sync_frame(frame);
}

/// 模拟接收 AllToAll 帧
static void simulate_recv_all_to_all(SyncPrimitives &sync, std::uint64_t sync_id,
                                      std::uint64_t from_bit,
                                      std::span<const std::uint8_t> data) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::AllToAll;
    frame.participant_mask = static_cast<std::uint64_t>(1) << from_bit;
    frame.payload.assign(data.begin(), data.end());
    sync.handle_sync_frame(frame);
}

// ============================================================================
// TEST 1: ReduceScatter 4 节点 SUM（规约 + 分片提取验证）
// ============================================================================

static void test_reduce_scatter_4_nodes_sum() {
    std::printf("[test] reduce_scatter 4 nodes SUM (reduce + scatter)...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> scatter_complete{false};
    std::vector<std::uint8_t> scattered_result;

    sync.set_callbacks({
        .on_reduce_scatter_complete = [&](std::uint64_t sync_id, std::span<const std::uint8_t> result) {
            if (sync_id == 21001) {
                scatter_complete = true;
                scattered_result.assign(result.begin(), result.end());
            }
        }
    });

    // 4 节点，每个节点 32 字节（4 个 uint64），N=4，chunk_size=8
    auto data0 = make_u64_array({1, 2, 3, 4});
    auto data1 = make_u64_array({10, 20, 30, 40});
    auto data2 = make_u64_array({100, 200, 300, 400});
    auto data3 = make_u64_array({1000, 2000, 3000, 4000});

    // 节点 0 发起 reduce_scatter，participant_mask=0b1111
    auto result = sync.reduce_scatter(21001, 0b1111, 0,
                                       std::span<const std::uint8_t>(data0.data(), data0.size()),
                                       ReduceOp::SUM, ReduceDType::U64,
                                       std::chrono::milliseconds(100));
    // channel 无效，返回 nullopt，但会话已创建
    CHECK(!result.has_value());

    // 验证会话初始状态
    auto session = sync.get_session(21001);
    CHECK(session.has_value());
    CHECK_EQ(session->participant_mask, static_cast<std::uint64_t>(0b1111));
    CHECK_EQ(session->scatter_chunk_index, static_cast<std::uint32_t>(0));  // 节点 0 -> idx 0
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0b0001));
    CHECK_EQ(session->reduced_data.size(), static_cast<std::size_t>(32));

    // 模拟接收节点 1/2/3 的数据
    simulate_recv_reduce_scatter(sync, 21001, 1,
        std::span<const std::uint8_t>(data1.data(), data1.size()), 0);  // SUM=0
    simulate_recv_reduce_scatter(sync, 21001, 2,
        std::span<const std::uint8_t>(data2.data(), data2.size()), 0);
    simulate_recv_reduce_scatter(sync, 21001, 3,
        std::span<const std::uint8_t>(data3.data(), data3.size()), 0);

    // 全部到齐，触发回调
    CHECK(scatter_complete.load());
    CHECK_EQ(scattered_result.size(), static_cast<std::size_t>(32));

    // 验证规约结果：SUM = [1111, 2222, 3333, 4444]
    CHECK_EQ(read_u64(scattered_result, 0), static_cast<std::uint64_t>(1111));
    CHECK_EQ(read_u64(scattered_result, 8), static_cast<std::uint64_t>(2222));
    CHECK_EQ(read_u64(scattered_result, 16), static_cast<std::uint64_t>(3333));
    CHECK_EQ(read_u64(scattered_result, 24), static_cast<std::uint64_t>(4444));

    // 验证分片提取：节点 0 应获取 scatter_idx=0 的分片 = uint64 1111
    // （发起方 channel 无效时不会返回分片，但 scatter_chunk_index 已记录）
    CHECK_EQ(session->scatter_chunk_index, static_cast<std::uint32_t>(0));
}

// ============================================================================
// TEST 2: ReduceScatter 2 节点（最小 ring）
// ============================================================================

static void test_reduce_scatter_2_nodes() {
    std::printf("[test] reduce_scatter 2 nodes (minimal)...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> complete{false};
    sync.set_callbacks({
        .on_reduce_scatter_complete = [&](std::uint64_t sync_id, std::span<const std::uint8_t>) {
            if (sync_id == 22001) complete = true;
        }
    });

    // 2 节点，每个节点 16 字节（2 个 uint64），N=2，chunk_size=8
    auto data0 = make_u64_array({5, 10});
    auto data1 = make_u64_array({15, 25});

    auto result = sync.reduce_scatter(22001, 0b0011, 0,
                                       std::span<const std::uint8_t>(data0.data(), data0.size()),
                                       ReduceOp::SUM, ReduceDType::U64,
                                       std::chrono::milliseconds(100));
    CHECK(!result.has_value());

    // 节点 1 的 scatter_idx 应为 1
    auto session = sync.get_session(22001);
    CHECK(session.has_value());
    CHECK_EQ(session->scatter_chunk_index, static_cast<std::uint32_t>(0));

    simulate_recv_reduce_scatter(sync, 22001, 1,
        std::span<const std::uint8_t>(data1.data(), data1.size()), 0);

    CHECK(complete.load());
    // SUM = [20, 35]
    auto s = sync.get_session(22001);
    if (s.has_value()) {
        CHECK_EQ(s->state, SyncState::Completed);
        CHECK_EQ(read_u64(s->reduced_data, 0), static_cast<std::uint64_t>(20));
        CHECK_EQ(read_u64(s->reduced_data, 8), static_cast<std::uint64_t>(35));
    }
}

// ============================================================================
// TEST 3: ReduceScatter MAX 操作
// ============================================================================

static void test_reduce_scatter_max() {
    std::printf("[test] reduce_scatter MAX operation...\n");

    SyncPrimitives sync(nullptr);

    std::vector<std::uint8_t> result_data;
    sync.set_callbacks({
        .on_reduce_scatter_complete = [&](std::uint64_t sync_id, std::span<const std::uint8_t> result) {
            if (sync_id == 23001) result_data.assign(result.begin(), result.end());
        }
    });

    // 4 节点 MAX，每个节点 16 字节（2 个 uint64），N=4，chunk_size=4
    auto data0 = make_u64_array({10, 20});
    auto data1 = make_u64_array({50, 5});
    auto data2 = make_u64_array({30, 100});
    auto data3 = make_u64_array({5, 50});

    sync.reduce_scatter(23001, 0b1111, 0,
                         std::span<const std::uint8_t>(data0.data(), data0.size()),
                         ReduceOp::MAX, ReduceDType::U64,
                         std::chrono::milliseconds(100));

    // MAX=1
    simulate_recv_reduce_scatter(sync, 23001, 1,
        std::span<const std::uint8_t>(data1.data(), data1.size()), 1);  // MAX=1
    simulate_recv_reduce_scatter(sync, 23001, 2,
        std::span<const std::uint8_t>(data2.data(), data2.size()), 1);
    simulate_recv_reduce_scatter(sync, 23001, 3,
        std::span<const std::uint8_t>(data3.data(), data3.size()), 1);

    // MAX = [50, 100]
    CHECK_EQ(result_data.size(), static_cast<std::size_t>(16));
    CHECK_EQ(read_u64(result_data, 0), static_cast<std::uint64_t>(50));
    CHECK_EQ(read_u64(result_data, 8), static_cast<std::uint64_t>(100));
}

// ============================================================================
// TEST 4: ReduceScatter 被动会话
// ============================================================================

static void test_reduce_scatter_passive() {
    std::printf("[test] reduce_scatter passive session...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> callback_called{false};
    sync.set_callbacks({
        .on_reduce_scatter_complete = [&](std::uint64_t, std::span<const std::uint8_t>) {
            callback_called = true;
        }
    });

    auto data = make_u64_array({42});

    // 被动接收 ReduceScatter 帧（无主动发起会话）
    simulate_recv_reduce_scatter(sync, 24001, 2,
        std::span<const std::uint8_t>(data.data(), data.size()), 0);

    // 被动会话被创建但不触发 complete
    auto session = sync.get_session(24001);
    CHECK(session.has_value());
    CHECK_EQ(session->state, SyncState::Reducing);
    CHECK(!callback_called.load());
}

// ============================================================================
// TEST 5: ReduceScatter 超时处理
// ============================================================================

static void test_reduce_scatter_timeout() {
    std::printf("[test] reduce_scatter timeout...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> timeout_called{false};
    sync.set_callbacks({
        .on_sync_timeout = [&](std::uint64_t sync_id) {
            if (sync_id == 25001) timeout_called = true;
        }
    });

    auto data0 = make_u64_array({1, 2});

    auto result = sync.reduce_scatter(25001, 0b1111, 0,
                                       std::span<const std::uint8_t>(data0.data(), data0.size()),
                                       ReduceOp::SUM, ReduceDType::U64,
                                       std::chrono::milliseconds(50));
    CHECK(!result.has_value());

    auto session = sync.get_session(25001);
    CHECK(session.has_value());
    CHECK_EQ(session->state, SyncState::Reducing);

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    sync.check_timeouts();

    CHECK(timeout_called.load());
    auto timed = sync.get_session(25001);
    CHECK(timed.has_value());
    CHECK_EQ(timed->state, SyncState::TimedOut);
    sync.cleanup_finished();
    CHECK(!sync.get_session(25001).has_value());
}

// ============================================================================
// TEST 6: ReduceScatter 参数校验
// ============================================================================

static void test_reduce_scatter_validation() {
    std::printf("[test] reduce_scatter parameter validation...\n");

    SyncPrimitives sync(nullptr);

    auto data = make_u64_array({1, 2, 3, 4});  // 32 字节

    // 空数据
    auto r = sync.reduce_scatter(26001, 0b1111, 0, {}, ReduceOp::SUM, ReduceDType::U64,
                                  std::chrono::milliseconds(100));
    CHECK(!r.has_value());
    CHECK(!sync.get_session(26001).has_value());

    // 长度不能被 participant 数整除（3 字节，N=4，3%4!=0）
    auto bad_data = make_data({0x01, 0x02, 0x03});
    r = sync.reduce_scatter(26002, 0b1111, 0,
                             std::span<const std::uint8_t>(bad_data.data(), bad_data.size()),
                             ReduceOp::SUM, ReduceDType::U64,
                             std::chrono::milliseconds(100));
    CHECK(!r.has_value());
    CHECK(!sync.get_session(26002).has_value());

    // self 不在 participant_mask 中
    r = sync.reduce_scatter(26003, 0b0011, 5,
                             std::span<const std::uint8_t>(data.data(), data.size()),
                             ReduceOp::SUM, ReduceDType::U64,
                             std::chrono::milliseconds(100));
    CHECK(!r.has_value());
    CHECK(!sync.get_session(26003).has_value());

    // participant_mask=0
    r = sync.reduce_scatter(26004, 0, 0,
                             std::span<const std::uint8_t>(data.data(), data.size()),
                             ReduceOp::SUM, ReduceDType::U64,
                             std::chrono::milliseconds(100));
    CHECK(!r.has_value());
    CHECK(!sync.get_session(26004).has_value());

    // 超大 payload
    std::vector<std::uint8_t> large(EpSyncFrame::kMaxPayloadLen + 1, 0xAA);
    r = sync.reduce_scatter(26005, 0b1111, 0,
                             std::span<const std::uint8_t>(large.data(), large.size()),
                             ReduceOp::SUM, ReduceDType::U64,
                             std::chrono::milliseconds(100));
    CHECK(!r.has_value());
    CHECK(!sync.get_session(26005).has_value());
}

// ============================================================================
// TEST 7: AllToAll 4 节点（chunk 收集 + 拼接）
// ============================================================================

static void test_all_to_all_4_nodes() {
    std::printf("[test] all_to_all 4 nodes (chunk collection + concat)...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> complete{false};
    std::vector<std::uint8_t> concat_result;
    std::uint64_t recv_from_mask = 0;

    sync.set_callbacks({
        .on_all_to_all_complete = [&](std::uint64_t sync_id, std::uint64_t from_mask,
                                        std::span<const std::uint8_t> data) {
            if (sync_id == 27001) {
                complete = true;
                recv_from_mask = from_mask;
                concat_result.assign(data.begin(), data.end());
            }
        }
    });

    auto chunk0 = make_data({0xA0, 0xA1});
    auto chunk1 = make_data({0xB0, 0xB1});
    auto chunk2 = make_data({0xC0, 0xC1});
    auto chunk3 = make_data({0xD0, 0xD1});

    // 节点 0 发起 all_to_all
    auto result = sync.all_to_all(27001, 0b1111, 0,
                                   std::span<const std::uint8_t>(chunk0.data(), chunk0.size()),
                                   std::chrono::milliseconds(100));
    CHECK(!result.has_value());

    // 验证会话初始状态
    auto session = sync.get_session(27001);
    CHECK(session.has_value());
    CHECK_EQ(session->participant_mask, static_cast<std::uint64_t>(0b1111));
    CHECK_EQ(session->all_to_all_received.size(), static_cast<std::size_t>(1));  // 仅自身
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0b0001));

    // 模拟接收其他节点
    simulate_recv_all_to_all(sync, 27001, 1,
        std::span<const std::uint8_t>(chunk1.data(), chunk1.size()));
    simulate_recv_all_to_all(sync, 27001, 2,
        std::span<const std::uint8_t>(chunk2.data(), chunk2.size()));
    simulate_recv_all_to_all(sync, 27001, 3,
        std::span<const std::uint8_t>(chunk3.data(), chunk3.size()));

    CHECK(complete.load());
    CHECK_EQ(recv_from_mask, static_cast<std::uint64_t>(0b1111));
    // 结果按 bit 升序拼接：chunk0 + chunk1 + chunk2 + chunk3
    CHECK_EQ(concat_result.size(), static_cast<std::size_t>(8));
    CHECK_EQ(concat_result[0], static_cast<std::uint8_t>(0xA0));
    CHECK_EQ(concat_result[1], static_cast<std::uint8_t>(0xA1));
    CHECK_EQ(concat_result[2], static_cast<std::uint8_t>(0xB0));
    CHECK_EQ(concat_result[3], static_cast<std::uint8_t>(0xB1));
    CHECK_EQ(concat_result[4], static_cast<std::uint8_t>(0xC0));
    CHECK_EQ(concat_result[5], static_cast<std::uint8_t>(0xC1));
    CHECK_EQ(concat_result[6], static_cast<std::uint8_t>(0xD0));
    CHECK_EQ(concat_result[7], static_cast<std::uint8_t>(0xD1));
}

// ============================================================================
// TEST 8: AllToAll 2 节点
// ============================================================================

static void test_all_to_all_2_nodes() {
    std::printf("[test] all_to_all 2 nodes...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> complete{false};
    sync.set_callbacks({
        .on_all_to_all_complete = [&](std::uint64_t sync_id, std::uint64_t, std::span<const std::uint8_t>) {
            if (sync_id == 28001) complete = true;
        }
    });

    auto chunk0 = make_data({0xAA});
    auto chunk1 = make_data({0xBB});

    auto result = sync.all_to_all(28001, 0b0011, 0,
                                   std::span<const std::uint8_t>(chunk0.data(), chunk0.size()),
                                   std::chrono::milliseconds(100));
    CHECK(!result.has_value());

    simulate_recv_all_to_all(sync, 28001, 1,
        std::span<const std::uint8_t>(chunk1.data(), chunk1.size()));

    CHECK(complete.load());
    auto session = sync.get_session(28001);
    if (session.has_value()) {
        CHECK_EQ(session->state, SyncState::Completed);
        CHECK_EQ(session->all_to_all_received.size(), static_cast<std::size_t>(2));
    }
}

// ============================================================================
// TEST 9: AllToAll 被动会话
// ============================================================================

static void test_all_to_all_passive() {
    std::printf("[test] all_to_all passive session...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> callback_called{false};
    sync.set_callbacks({
        .on_all_to_all_complete = [&](std::uint64_t, std::uint64_t, std::span<const std::uint8_t>) {
            callback_called = true;
        }
    });

    auto chunk = make_data({0x01, 0x02, 0x03});

    // 被动接收 AllToAll 帧
    simulate_recv_all_to_all(sync, 29001, 2,
        std::span<const std::uint8_t>(chunk.data(), chunk.size()));

    auto session = sync.get_session(29001);
    CHECK(session.has_value());
    CHECK_EQ(session->state, SyncState::Waiting);
    CHECK_EQ(session->all_to_all_received.size(), static_cast<std::size_t>(1));
    CHECK(!callback_called.load());
}

// ============================================================================
// TEST 10: AllToAll 超时处理
// ============================================================================

static void test_all_to_all_timeout() {
    std::printf("[test] all_to_all timeout...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> timeout_called{false};
    sync.set_callbacks({
        .on_sync_timeout = [&](std::uint64_t sync_id) {
            if (sync_id == 30001) timeout_called = true;
        }
    });

    auto chunk0 = make_data({0xCC});

    auto result = sync.all_to_all(30001, 0b1111, 0,
                                   std::span<const std::uint8_t>(chunk0.data(), chunk0.size()),
                                   std::chrono::milliseconds(50));
    CHECK(!result.has_value());

    auto session = sync.get_session(30001);
    CHECK(session.has_value());
    CHECK_EQ(session->state, SyncState::Waiting);

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    sync.check_timeouts();

    CHECK(timeout_called.load());
    auto timed = sync.get_session(30001);
    CHECK(timed.has_value());
    CHECK_EQ(timed->state, SyncState::TimedOut);
    sync.cleanup_finished();
    CHECK(!sync.get_session(30001).has_value());
}

// ============================================================================
// TEST 11: AllToAll 参数校验
// ============================================================================

static void test_all_to_all_validation() {
    std::printf("[test] all_to_all parameter validation...\n");

    SyncPrimitives sync(nullptr);

    auto chunk = make_data({0x01});

    // participant_mask=0
    auto r = sync.all_to_all(31001, 0, 0,
                              std::span<const std::uint8_t>(chunk.data(), chunk.size()));
    CHECK(!r.has_value());
    CHECK(!sync.get_session(31001).has_value());

    // self 不在 participant_mask 中
    r = sync.all_to_all(31002, 0b0011, 5,
                         std::span<const std::uint8_t>(chunk.data(), chunk.size()));
    CHECK(!r.has_value());
    CHECK(!sync.get_session(31002).has_value());

    // 超大 payload
    std::vector<std::uint8_t> large(EpSyncFrame::kMaxPayloadLen + 1, 0xBB);
    r = sync.all_to_all(31003, 0b1111, 0,
                         std::span<const std::uint8_t>(large.data(), large.size()));
    CHECK(!r.has_value());
    CHECK(!sync.get_session(31003).has_value());
}

// ============================================================================
// TEST 12: CollectiveSession::reduce_scatter 委托验证
// ============================================================================

static void test_collective_reduce_scatter() {
    std::printf("[test] CollectiveSession::reduce_scatter delegation...\n");

    SyncPrimitives sync(nullptr);
    CollectiveSession collective(sync);

    CollectiveConfig config;
    config.default_timeout = std::chrono::milliseconds(50);
    collective.set_config(config);

    auto data = make_u64_array({1, 2});

    // channel=nullptr，返回 nullopt，但会话已创建
    auto result = collective.reduce_scatter(32001, 0b0011, 0,
                                             std::span<const std::uint8_t>(data.data(), data.size()));
    CHECK(!result.has_value());

    // 验证使用了配置的 50ms 超时
    auto session = sync.get_session(32001);
    CHECK(session.has_value());
    auto now = std::chrono::steady_clock::now();
    auto remaining_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        session->deadline - now).count();
    CHECK(remaining_ms > 0 && remaining_ms <= 50);

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    sync.check_timeouts();
    sync.cleanup_finished();
    CHECK(!sync.get_session(32001).has_value());
}

// ============================================================================
// TEST 13: CollectiveSession::all_to_all 委托验证
// ============================================================================

static void test_collective_all_to_all() {
    std::printf("[test] CollectiveSession::all_to_all delegation...\n");

    SyncPrimitives sync(nullptr);
    CollectiveSession collective(sync);

    auto chunk = make_data({0x99});

    // channel=nullptr，返回 nullopt
    auto result = collective.all_to_all(33001, 0b0011, 0,
                                         std::span<const std::uint8_t>(chunk.data(), chunk.size()));
    CHECK(!result.has_value());

    // 验证会话已创建
    auto session = sync.get_session(33001);
    CHECK(session.has_value());
    CHECK_EQ(session->participant_mask, static_cast<std::uint64_t>(0b0011));
    CHECK_EQ(session->all_to_all_received.size(), static_cast<std::size_t>(1));
}

// ============================================================================
// TEST 14: handle_sync_frame 路由 ReduceScatter/AllToAll
// ============================================================================

static void test_handle_sync_frame_routing_v2() {
    std::printf("[test] handle_sync_frame routing ReduceScatter/AllToAll...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> rs_called{false};
    std::atomic<bool> a2a_called{false};

    sync.set_callbacks({
        .on_reduce_scatter_complete = [&](std::uint64_t, std::span<const std::uint8_t>) {
            rs_called = true;
        },
        .on_all_to_all_complete = [&](std::uint64_t, std::uint64_t, std::span<const std::uint8_t>) {
            a2a_called = true;
        }
    });

    // ReduceScatter 被动会话不触发 complete
    EpSyncFrame rs_frame;
    rs_frame.sync_id = 34001;
    rs_frame.sync_op = EpSyncOp::ReduceScatter;
    rs_frame.participant_mask = 0b0001;
    rs_frame.payload = make_data({0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    sync.handle_sync_frame(rs_frame);
    CHECK(!rs_called.load());  // 被动会话不触发
    CHECK(sync.get_session(34001).has_value());

    // AllToAll 被动会话不触发 complete
    EpSyncFrame a2a_frame;
    a2a_frame.sync_id = 34002;
    a2a_frame.sync_op = EpSyncOp::AllToAll;
    a2a_frame.participant_mask = 0b0010;
    a2a_frame.payload = make_data({0x02});
    sync.handle_sync_frame(a2a_frame);
    CHECK(!a2a_called.load());
    CHECK(sync.get_session(34002).has_value());
}

// ============================================================================
// TEST 15: SyncSession 字段扩展验证
// ============================================================================

static void test_sync_session_fields_v2() {
    std::printf("[test] SyncSession extended fields (scatter_chunk_index/all_to_all_received)...\n");

    SyncPrimitives sync(nullptr);

    // ReduceScatter 创建会话后检查 scatter_chunk_index
    auto data = make_u64_array({1, 2, 3, 4});
    sync.reduce_scatter(35001, 0b1111, 0,
                         std::span<const std::uint8_t>(data.data(), data.size()),
                         ReduceOp::SUM, ReduceDType::U64,
                         std::chrono::milliseconds(100));

    auto session = sync.get_session(35001);
    CHECK(session.has_value());
    CHECK_EQ(session->scatter_chunk_index, static_cast<std::uint32_t>(0));  // 节点 0 -> idx 0
    CHECK_EQ(session->reduce_op, ReduceOp::SUM);
    CHECK_EQ(session->reduce_dtype, ReduceDType::U64);
    CHECK_EQ(session->reduced_data.size(), static_cast<std::size_t>(32));

    // 节点 2 发起 reduce_scatter，scatter_idx 应为 2
    sync.reduce_scatter(35002, 0b1111, 2,
                         std::span<const std::uint8_t>(data.data(), data.size()),
                         ReduceOp::MAX, ReduceDType::U64,
                         std::chrono::milliseconds(100));
    auto session2 = sync.get_session(35002);
    CHECK(session2.has_value());
    CHECK_EQ(session2->scatter_chunk_index, static_cast<std::uint32_t>(2));  // 节点 2 -> idx 2
    CHECK_EQ(session2->reduce_op, ReduceOp::MAX);

    // AllToAll 创建会话后检查 all_to_all_received
    auto chunk = make_data({0xAA, 0xBB});
    sync.all_to_all(35003, 0b0111, 1,
                     std::span<const std::uint8_t>(chunk.data(), chunk.size()),
                     std::chrono::milliseconds(100));
    auto session3 = sync.get_session(35003);
    CHECK(session3.has_value());
    CHECK_EQ(session3->all_to_all_received.size(), static_cast<std::size_t>(1));
    CHECK_EQ(session3->all_to_all_received.count(1), static_cast<std::size_t>(1));  // bit 1 存在
    CHECK_EQ(session3->all_to_all_received[1].size(), static_cast<std::size_t>(2));
    CHECK_EQ(session3->all_to_all_received[1][0], static_cast<std::uint8_t>(0xAA));
}

// ============================================================================
// TEST 16: EpSyncOp ReduceScatter/AllToAll 帧编解码
// ============================================================================

static void test_ep_sync_frame_reduce_scatter_all_to_all_codec() {
    std::printf("[test] EP_SYNC_FRAME ReduceScatter/AllToAll encode/decode...\n");

    // ReduceScatter 编解码
    {
        EpSyncFrame frame;
        frame.sync_id = 36001;
        frame.sync_op = EpSyncOp::ReduceScatter;
        frame.participant_mask = 0b0100;  // 发送方 bit 2
        frame.reduce_op = 1;  // MAX
        frame.payload = make_data({0x11, 0x22, 0x33});

        auto encoded = encode_sync_frame(frame);
        CHECK_GE(encoded.size(), 1u);
        CHECK_EQ(encoded[0], static_cast<std::uint8_t>(EpFrameType::SYNC));

        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->sync_id, frame.sync_id);
            CHECK_EQ(decoded->sync_op, EpSyncOp::ReduceScatter);
            CHECK_EQ(decoded->participant_mask, frame.participant_mask);
            CHECK_EQ(decoded->reduce_op, frame.reduce_op);
            CHECK_EQ(decoded->payload.size(), frame.payload.size());
            CHECK(std::memcmp(decoded->payload.data(), frame.payload.data(), frame.payload.size()) == 0);
        }
    }

    // AllToAll 编解码
    {
        EpSyncFrame frame;
        frame.sync_id = 36002;
        frame.sync_op = EpSyncOp::AllToAll;
        frame.participant_mask = 0b1000;  // 发送方 bit 3
        frame.payload = make_data({0x44, 0x55, 0x66, 0x77});

        auto encoded = encode_sync_frame(frame);
        CHECK_GE(encoded.size(), 1u);

        auto decoded = decode_sync_frame(std::span<const std::uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        if (decoded) {
            CHECK_EQ(decoded->sync_id, frame.sync_id);
            CHECK_EQ(decoded->sync_op, EpSyncOp::AllToAll);
            CHECK_EQ(decoded->participant_mask, frame.participant_mask);
            CHECK_EQ(decoded->payload.size(), frame.payload.size());
            CHECK(std::memcmp(decoded->payload.data(), frame.payload.data(), frame.payload.size()) == 0);
        }
    }

    // ep_sync_op_name 转字符串
    CHECK_EQ(std::string(ep_sync_op_name(EpSyncOp::ReduceScatter)), std::string("reduce_scatter"));
    CHECK_EQ(std::string(ep_sync_op_name(EpSyncOp::AllToAll)), std::string("all_to_all"));
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== v2.1 Phase 2 M2 Collective Primitives (ReduceScatter/AllToAll) Unit Tests ===\n\n");

    test_reduce_scatter_4_nodes_sum();
    test_reduce_scatter_2_nodes();
    test_reduce_scatter_max();
    test_reduce_scatter_passive();
    test_reduce_scatter_timeout();
    test_reduce_scatter_validation();
    test_all_to_all_4_nodes();
    test_all_to_all_2_nodes();
    test_all_to_all_passive();
    test_all_to_all_timeout();
    test_all_to_all_validation();
    test_collective_reduce_scatter();
    test_collective_all_to_all();
    test_handle_sync_frame_routing_v2();
    test_sync_session_fields_v2();
    test_ep_sync_frame_reduce_scatter_all_to_all_codec();

    std::printf("\n=== Test Summary ===\n");
    std::printf("PASS: %d\n", g_pass);
    std::printf("FAIL: %d\n", g_fail);
    std::printf("Total: %d\n", g_pass + g_fail);

    return g_fail == 0 ? 0 : 1;
}
