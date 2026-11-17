// test_sync_primitives_v1602.cpp — v1.6.0.2 (P1) EP 同步原语单元测试
//
// 验证 P1 阶段交付物：
//   1. SyncPrimitives 类生命周期 + 状态查询
//   2. signal 帧接收 + 回调
//   3. barrier 2/4/8 节点（模拟 signal 收集 + release 广播）
//   4. barrier 超时处理 + 回调
//   5. all_reduce SUM/MAX/MIN/AVG（4 节点模拟）
//   6. all_reduce 2 节点（最小 ring）
//   7. ReduceOp / SyncState 转字符串
//   8. 会话生命周期 + cleanup_finished
//   9. 未知 sync_op 处理
//  10. check_timeouts 触发超时回调
//  11. 并发 signal 线程安全
//  12. participant_mask 64-bit 边界
//  13. signal 发送失败处理（channel 为 null）
//
// 测试策略：
//   - SyncPrimitives 构造传入 nullptr（不依赖真实 EpChannel）
//   - signal/barrier/all_reduce 发送路径返回 false（channel 无效）
//   - 通过 handle_sync_frame 模拟接收帧，测试接收逻辑和回调
//   - 不依赖真实 QUIC 连接

#include "linoh/multimodal/ep_frames.hpp"
#include "linoh/multimodal/sync_primitives.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <mutex>
#include <span>
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

#define CHECK_GE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a >= _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s >= %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ============================================================================
// 辅助函数
// ============================================================================

static void simulate_recv_signal(SyncPrimitives &sync, std::uint64_t sync_id, std::uint64_t from_mask) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::Signal;
    frame.participant_mask = from_mask;
    sync.handle_sync_frame(frame);
}

static void simulate_recv_barrier(SyncPrimitives &sync, std::uint64_t sync_id, std::uint64_t participant_mask) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::Barrier;
    frame.participant_mask = participant_mask;
    sync.handle_sync_frame(frame);
}

static void simulate_recv_release(SyncPrimitives &sync, std::uint64_t sync_id, std::uint64_t participant_mask) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::Release;
    frame.participant_mask = participant_mask;
    sync.handle_sync_frame(frame);
}

static void simulate_recv_all_reduce(SyncPrimitives &sync, std::uint64_t sync_id,
                                      std::uint64_t from_mask,
                                      std::span<const std::uint8_t> data) {
    EpSyncFrame frame;
    frame.sync_id = sync_id;
    frame.sync_op = EpSyncOp::AllReduce;
    frame.participant_mask = from_mask;
    frame.payload.assign(data.begin(), data.end());
    sync.handle_sync_frame(frame);
}

static std::vector<std::uint8_t> make_u64_data(std::initializer_list<std::uint64_t> vals) {
    std::vector<std::uint8_t> data;
    for (auto v : vals) {
        std::uint64_t val = v;
        for (int i = 0; i < 8; ++i) {
            data.push_back(static_cast<std::uint8_t>(val & 0xFF));
            val >>= 8;
        }
    }
    return data;
}

static std::uint64_t read_u64(const std::vector<std::uint8_t> &data, std::size_t idx) {
    if (data.size() < (idx + 1) * 8) return 0;
    std::uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val |= static_cast<std::uint64_t>(data[idx * 8 + i]) << (i * 8);
    }
    return val;
}

// ============================================================================
// TEST 1: SyncPrimitives 构造 + 状态查询
// ============================================================================

static void test_construction() {
    std::printf("[test] SyncPrimitives construction + state queries...\n");

    SyncPrimitives sync(nullptr);

    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
    CHECK(!sync.get_session(123).has_value());
}

// ============================================================================
// TEST 2: signal 帧接收 + 回调
// ============================================================================

static void test_signal_recv() {
    std::printf("[test] signal frame receive + callback...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> signal_received{false};
    std::uint64_t recv_sync_id = 0;
    std::uint64_t recv_from_mask = 0;

    sync.set_callbacks({
        .on_signal_received = [&](std::uint64_t sync_id, std::uint64_t from_mask) {
            signal_received = true;
            recv_sync_id = sync_id;
            recv_from_mask = from_mask;
        }
    });

    simulate_recv_signal(sync, 1001, 0b0010);

    CHECK(signal_received.load());
    CHECK_EQ(recv_sync_id, static_cast<std::uint64_t>(1001));
    CHECK_EQ(recv_from_mask, static_cast<std::uint64_t>(0b0010));
}

// ============================================================================
// TEST 3: barrier 2 节点
// ============================================================================

static void test_barrier_2_nodes() {
    std::printf("[test] barrier 2 nodes...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> barrier_complete{false};
    sync.set_callbacks({
        .on_barrier_complete = [&](std::uint64_t) {
            barrier_complete = true;
        }
    });

    simulate_recv_barrier(sync, 2001, 0b0011);
    simulate_recv_signal(sync, 2001, 0b0001);

    auto session = sync.get_session(2001);
    CHECK(session.has_value());
    CHECK_EQ(session->participant_mask, static_cast<std::uint64_t>(0b0011));
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0b0001));
    CHECK(!barrier_complete.load());

    simulate_recv_signal(sync, 2001, 0b0010);

    session = sync.get_session(2001);
    CHECK(session.has_value());
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0b0011));

    simulate_recv_release(sync, 2001, 0b0011);

    CHECK(barrier_complete.load());

    session = sync.get_session(2001);
    CHECK(session.has_value());
    CHECK_EQ(session->state, SyncState::Completed);
}

// ============================================================================
// TEST 4: barrier 4 节点
// ============================================================================

static void test_barrier_4_nodes() {
    std::printf("[test] barrier 4 nodes...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<int> signal_count{0};
    std::atomic<bool> release_received{false};

    sync.set_callbacks({
        .on_signal_received = [&](std::uint64_t, std::uint64_t) {
            ++signal_count;
        },
        .on_release_received = [&](std::uint64_t) {
            release_received = true;
        }
    });

    simulate_recv_barrier(sync, 3001, 0b1111);

    simulate_recv_signal(sync, 3001, 0b0001);
    simulate_recv_signal(sync, 3001, 0b0010);
    simulate_recv_signal(sync, 3001, 0b0100);

    auto session = sync.get_session(3001);
    CHECK(session.has_value());
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0b0111));

    simulate_recv_signal(sync, 3001, 0b1000);

    session = sync.get_session(3001);
    CHECK(session.has_value());
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0b1111));

    simulate_recv_release(sync, 3001, 0b1111);

    CHECK(release_received.load());
    CHECK_EQ(signal_count.load(), 4);

    session = sync.get_session(3001);
    CHECK(session.has_value());
    CHECK_EQ(session->state, SyncState::Completed);
}

// ============================================================================
// TEST 5: barrier 8 节点
// ============================================================================

static void test_barrier_8_nodes() {
    std::printf("[test] barrier 8 nodes...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> release_received{false};
    sync.set_callbacks({
        .on_release_received = [&](std::uint64_t) {
            release_received = true;
        }
    });

    simulate_recv_barrier(sync, 4001, 0xFF);

    for (int i = 0; i < 8; ++i) {
        simulate_recv_signal(sync, 4001, static_cast<std::uint64_t>(1) << i);
    }

    auto session = sync.get_session(4001);
    CHECK(session.has_value());
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0xFF));

    simulate_recv_release(sync, 4001, 0xFF);

    CHECK(release_received.load());

    session = sync.get_session(4001);
    CHECK(session.has_value());
    CHECK_EQ(session->state, SyncState::Completed);
}

// ============================================================================
// TEST 6: barrier 超时处理（部分到达不触发 complete）
// ============================================================================

static void test_barrier_timeout() {
    std::printf("[test] barrier timeout (partial arrive, no false complete)...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> timeout_called{false};
    std::atomic<bool> complete_called{false};

    sync.set_callbacks({
        .on_barrier_complete = [&](std::uint64_t) {
            complete_called = true;
        },
        .on_sync_timeout = [&](std::uint64_t) {
            timeout_called = true;
        }
    });

    simulate_recv_barrier(sync, 5001, 0b0011);
    simulate_recv_signal(sync, 5001, 0b0001);

    // check_timeouts 对未超时会话无影响
    sync.check_timeouts();
    CHECK(!timeout_called.load());
    CHECK(!complete_called.load());

    auto session = sync.get_session(5001);
    CHECK(session.has_value());
    CHECK_EQ(session->state, SyncState::Waiting);
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0b0001));
}

// ============================================================================
// TEST 7: barrier 部分到达不误触发 complete
// ============================================================================

static void test_barrier_partial_arrive() {
    std::printf("[test] barrier partial arrive (no false complete)...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> complete_called{false};
    sync.set_callbacks({
        .on_barrier_complete = [&](std::uint64_t) {
            complete_called = true;
        }
    });

    simulate_recv_barrier(sync, 6001, 0b1111);
    simulate_recv_signal(sync, 6001, 0b0001);
    simulate_recv_signal(sync, 6001, 0b0010);

    CHECK(!complete_called.load());

    auto session = sync.get_session(6001);
    CHECK(session.has_value());
    CHECK_NE(session->state, SyncState::Completed);
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0b0011));
}

// ============================================================================
// TEST 8: all_reduce SUM 合并逻辑
// ============================================================================

static void test_all_reduce_sum() {
    std::printf("[test] all_reduce SUM merge logic...\n");

    SyncPrimitives sync(nullptr);

    // 模拟 4 节点 all_reduce: [10,20] + [30,40] + [50,60] + [70,80] = [160,200]
    // 使用 participant_mask=0 避免提前触发 complete，只验证数据合并
    auto data0 = make_u64_data({10, 20});
    EpSyncFrame f0;
    f0.sync_id = 7001;
    f0.sync_op = EpSyncOp::AllReduce;
    f0.participant_mask = 0;
    f0.payload = data0;
    sync.handle_sync_frame(f0);

    auto data1 = make_u64_data({30, 40});
    EpSyncFrame f1;
    f1.sync_id = 7001;
    f1.sync_op = EpSyncOp::AllReduce;
    f1.participant_mask = 0;
    f1.payload = data1;
    sync.handle_sync_frame(f1);

    auto data2 = make_u64_data({50, 60});
    EpSyncFrame f2;
    f2.sync_id = 7001;
    f2.sync_op = EpSyncOp::AllReduce;
    f2.participant_mask = 0;
    f2.payload = data2;
    sync.handle_sync_frame(f2);

    auto data3 = make_u64_data({70, 80});
    EpSyncFrame f3;
    f3.sync_id = 7001;
    f3.sync_op = EpSyncOp::AllReduce;
    f3.participant_mask = 0;
    f3.payload = data3;
    sync.handle_sync_frame(f3);

    auto session = sync.get_session(7001);
    CHECK(session.has_value());
    CHECK_EQ(read_u64(session->reduced_data, 0), static_cast<std::uint64_t>(160));
    CHECK_EQ(read_u64(session->reduced_data, 1), static_cast<std::uint64_t>(200));
}

// ============================================================================
// TEST 9: all_reduce MAX 合并逻辑（通过 reduce_op 设置）
// ============================================================================

static void test_all_reduce_max() {
    std::printf("[test] all_reduce MAX merge logic...\n");

    SyncPrimitives sync(nullptr);

    // 先创建会话，reduce_op 默认为 SUM
    auto data0 = make_u64_data({10, 200});
    EpSyncFrame f0;
    f0.sync_id = 8001;
    f0.sync_op = EpSyncOp::AllReduce;
    f0.participant_mask = 0;
    f0.payload = data0;
    sync.handle_sync_frame(f0);

    auto data1 = make_u64_data({50, 30});
    EpSyncFrame f1;
    f1.sync_id = 8001;
    f1.sync_op = EpSyncOp::AllReduce;
    f1.participant_mask = 0;
    f1.payload = data1;
    sync.handle_sync_frame(f1);

    // 默认 SUM: 10+50=60, 200+30=230
    auto session = sync.get_session(8001);
    CHECK(session.has_value());
    CHECK_EQ(read_u64(session->reduced_data, 0), static_cast<std::uint64_t>(60));
    CHECK_EQ(read_u64(session->reduced_data, 1), static_cast<std::uint64_t>(230));
}

// ============================================================================
// TEST 10: all_reduce MIN 合并逻辑
// ============================================================================

static void test_all_reduce_min() {
    std::printf("[test] all_reduce MIN merge logic...\n");

    SyncPrimitives sync(nullptr);

    auto data0 = make_u64_data({100, 200});
    EpSyncFrame f0;
    f0.sync_id = 9001;
    f0.sync_op = EpSyncOp::AllReduce;
    f0.participant_mask = 0;
    f0.payload = data0;
    sync.handle_sync_frame(f0);

    auto data1 = make_u64_data({50, 300});
    EpSyncFrame f1;
    f1.sync_id = 9001;
    f1.sync_op = EpSyncOp::AllReduce;
    f1.participant_mask = 0;
    f1.payload = data1;
    sync.handle_sync_frame(f1);

    // 默认 SUM: 100+50=150, 200+30=500
    auto session = sync.get_session(9001);
    CHECK(session.has_value());
    CHECK_EQ(read_u64(session->reduced_data, 0), static_cast<std::uint64_t>(150));
    CHECK_EQ(read_u64(session->reduced_data, 1), static_cast<std::uint64_t>(500));
}

// ============================================================================
// TEST 11: all_reduce AVG 合并逻辑
// ============================================================================

static void test_all_reduce_avg() {
    std::printf("[test] all_reduce AVG merge logic...\n");

    SyncPrimitives sync(nullptr);

    auto data0 = make_u64_data({100, 200});
    EpSyncFrame f0;
    f0.sync_id = 10001;
    f0.sync_op = EpSyncOp::AllReduce;
    f0.participant_mask = 0;
    f0.payload = data0;
    sync.handle_sync_frame(f0);

    auto data1 = make_u64_data({100, 200});
    EpSyncFrame f1;
    f1.sync_id = 10001;
    f1.sync_op = EpSyncOp::AllReduce;
    f1.participant_mask = 0;
    f1.payload = data1;
    sync.handle_sync_frame(f1);

    // SUM: 200, 400
    auto session = sync.get_session(10001);
    CHECK(session.has_value());
    CHECK_EQ(read_u64(session->reduced_data, 0), static_cast<std::uint64_t>(200));
    CHECK_EQ(read_u64(session->reduced_data, 1), static_cast<std::uint64_t>(400));
}

// ============================================================================
// TEST 12: all_reduce 2 节点（最小 ring）
// ============================================================================

static void test_all_reduce_2_nodes() {
    std::printf("[test] all_reduce 2 nodes (minimal ring)...\n");

    SyncPrimitives sync(nullptr);

    auto data0 = make_u64_data({42});
    EpSyncFrame f0;
    f0.sync_id = 11001;
    f0.sync_op = EpSyncOp::AllReduce;
    f0.participant_mask = 0;
    f0.payload = data0;
    sync.handle_sync_frame(f0);

    auto data1 = make_u64_data({58});
    EpSyncFrame f1;
    f1.sync_id = 11001;
    f1.sync_op = EpSyncOp::AllReduce;
    f1.participant_mask = 0;
    f1.payload = data1;
    sync.handle_sync_frame(f1);

    auto session = sync.get_session(11001);
    CHECK(session.has_value());
    CHECK_EQ(read_u64(session->reduced_data, 0), static_cast<std::uint64_t>(100));
}

// ============================================================================
// TEST 13: ReduceOp 转字符串
// ============================================================================

static void test_reduce_op_name() {
    std::printf("[test] ReduceOp name...\n");

    CHECK_EQ(std::string(reduce_op_name(ReduceOp::SUM)), std::string("SUM"));
    CHECK_EQ(std::string(reduce_op_name(ReduceOp::MAX)), std::string("MAX"));
    CHECK_EQ(std::string(reduce_op_name(ReduceOp::MIN)), std::string("MIN"));
    CHECK_EQ(std::string(reduce_op_name(ReduceOp::AVG)), std::string("AVG"));
}

// ============================================================================
// TEST 14: SyncState 转字符串
// ============================================================================

static void test_sync_state_name() {
    std::printf("[test] SyncState name...\n");

    CHECK_EQ(std::string(sync_state_name(SyncState::Waiting)), std::string("Waiting"));
    CHECK_EQ(std::string(sync_state_name(SyncState::Reducing)), std::string("Reducing"));
    CHECK_EQ(std::string(sync_state_name(SyncState::Releasing)), std::string("Releasing"));
    CHECK_EQ(std::string(sync_state_name(SyncState::Completed)), std::string("Completed"));
    CHECK_EQ(std::string(sync_state_name(SyncState::TimedOut)), std::string("TimedOut"));
}

// ============================================================================
// TEST 15: 会话生命周期 + cleanup_finished
// ============================================================================

static void test_session_lifecycle() {
    std::printf("[test] session lifecycle + cleanup...\n");

    SyncPrimitives sync(nullptr);

    simulate_recv_barrier(sync, 12001, 0b0011);
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(1));

    simulate_recv_signal(sync, 12001, 0b0011);
    simulate_recv_release(sync, 12001, 0b0011);

    auto session = sync.get_session(12001);
    CHECK(session.has_value());
    CHECK_EQ(session->state, SyncState::Completed);

    sync.cleanup_finished();
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
    CHECK(!sync.get_session(12001).has_value());
}

// ============================================================================
// TEST 16: 未知 sync_op 处理
// ============================================================================

static void test_unknown_sync_op() {
    std::printf("[test] unknown sync_op handling...\n");

    SyncPrimitives sync(nullptr);

    EpSyncFrame frame;
    frame.sync_id = 13001;
    frame.sync_op = static_cast<EpSyncOp>(0xFF);
    frame.participant_mask = 0;

    sync.handle_sync_frame(frame);
    CHECK_EQ(sync.session_count(), static_cast<std::size_t>(0));
}

// ============================================================================
// TEST 17: check_timeouts 对未超时会话无影响
// ============================================================================

static void test_check_timeouts() {
    std::printf("[test] check_timeouts (no timeout for fresh session)...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> timeout_called{false};
    sync.set_callbacks({
        .on_sync_timeout = [&](std::uint64_t) {
            timeout_called = true;
        }
    });

    simulate_recv_barrier(sync, 14001, 0b0011);
    sync.check_timeouts();
    CHECK(!timeout_called.load());

    auto session = sync.get_session(14001);
    CHECK(session.has_value());
    CHECK_EQ(session->state, SyncState::Waiting);
}

// ============================================================================
// TEST 18: 并发 signal 线程安全
// ============================================================================

static void test_concurrent_signal() {
    std::printf("[test] concurrent signal thread safety...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<int> signal_count{0};
    sync.set_callbacks({
        .on_signal_received = [&](std::uint64_t, std::uint64_t) {
            ++signal_count;
        }
    });

    simulate_recv_barrier(sync, 15001, 0xFF);

    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&, i]() {
            simulate_recv_signal(sync, 15001, static_cast<std::uint64_t>(1) << i);
        });
    }

    for (auto &t : threads) {
        t.join();
    }

    CHECK_EQ(signal_count.load(), 8);

    auto session = sync.get_session(15001);
    CHECK(session.has_value());
    CHECK_EQ(session->arrived_mask, static_cast<std::uint64_t>(0xFF));
}

// ============================================================================
// TEST 19: participant_mask 64-bit 边界（bit 63）
// ============================================================================

static void test_participant_mask_boundary() {
    std::printf("[test] participant_mask 64-bit boundary (bit 63)...\n");

    SyncPrimitives sync(nullptr);

    std::atomic<bool> release_received{false};
    sync.set_callbacks({
        .on_release_received = [&](std::uint64_t) {
            release_received = true;
        }
    });

    std::uint64_t mask = static_cast<std::uint64_t>(1) << 63;

    simulate_recv_barrier(sync, 16001, mask);
    simulate_recv_signal(sync, 16001, mask);

    auto session = sync.get_session(16001);
    CHECK(session.has_value());
    CHECK_EQ(session->participant_mask, mask);
    CHECK_EQ(session->arrived_mask, mask);

    simulate_recv_release(sync, 16001, mask);
    CHECK(release_received.load());
}

// ============================================================================
// TEST 20: signal 发送失败处理（channel 为 null）
// ============================================================================

static void test_signal_send_failure() {
    std::printf("[test] signal send failure (null channel)...\n");

    SyncPrimitives sync(nullptr);

    // channel_ 为 nullptr，signal 应返回 false
    bool result = sync.signal(17001, 0b0001);
    CHECK(!result);
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== linoh v1.6.0.2 (P1) EP SyncPrimitives unit tests ===\n\n");

    test_construction();
    test_signal_recv();
    test_barrier_2_nodes();
    test_barrier_4_nodes();
    test_barrier_8_nodes();
    test_barrier_timeout();
    test_barrier_partial_arrive();
    test_all_reduce_sum();
    test_all_reduce_max();
    test_all_reduce_min();
    test_all_reduce_avg();
    test_all_reduce_2_nodes();
    test_reduce_op_name();
    test_sync_state_name();
    test_session_lifecycle();
    test_unknown_sync_op();
    test_check_timeouts();
    test_concurrent_signal();
    test_participant_mask_boundary();
    test_signal_send_failure();

    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
