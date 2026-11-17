// test_control_channel.cpp — P5-A-2 控制信道隔离单元测试
//
// 测试覆盖：
//   1.  HeartbeatPayload 序列化/反序列化（默认值）
//   2.  HeartbeatPayload 自定义值往返一致性
//   3.  HeartbeatPayload::parse 长度不足返回 0
//   4.  RpcResponse 默认值
//   5.  RpcPriority 枚举值
//   6.  ControlChannel 构造（空连接）
//   7.  ControlChannel is_valid（空连接 → false）
//   8.  ControlChannel 移动构造
//   9.  ControlChannel 移动赋值
//  10.  default_timeout_ms 按优先级返回正确值
//  11.  priority_name 返回正确名称
//  12.  stats 初始值全 0
//  13.  send_heartbeat 空连接不崩溃 + stats 不增加
//  14.  send_notification 空连接不崩溃 + stats 不增加
//  15.  notify_drain 空连接返回 future，get() 不崩溃
//  16.  call_rpc 空连接返回失败 RpcResponse
//  17.  start_heartbeat_thread + stop_heartbeat_thread（短间隔）
//  18.  heartbeat 线程重复启动不崩溃
//  19.  stats 累计（多次 record 后统计正确）
//  20.  HeartbeatPayload 字段边界值（最大值）

#include "linoh/multimodal/control_channel.hpp"
#include "linoh/multimodal/channel.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <thread>

using namespace linoh;
using namespace linoh::multimodal;
using linoh::protocol::MethodId;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL line %d: %s\n", __LINE__, #cond); } \
} while(0)

// ========== 1. HeartbeatPayload 默认值序列化 ==========
static void test_heartbeat_default() {
    HeartbeatPayload hb;
    auto bytes = hb.serialize();
    CHECK(bytes.size() == 25);

    HeartbeatPayload parsed;
    auto consumed = HeartbeatPayload::parse(bytes, parsed);
    CHECK(consumed == 25);
    CHECK(parsed.node_id == 0);
    CHECK(parsed.timestamp_ms == 0);
    CHECK(parsed.state == 0);
    CHECK(parsed.active_streams == 0);
    CHECK(parsed.pending_rpcs == 0);
}

// ========== 2. HeartbeatPayload 自定义值往返 ==========
static void test_heartbeat_roundtrip() {
    HeartbeatPayload hb;
    hb.node_id = 0xABCDEF0123456789ULL;
    hb.timestamp_ms = 1700000000000ULL;
    hb.state = 3;
    hb.active_streams = 42;
    hb.pending_rpcs = 7;

    auto bytes = hb.serialize();
    CHECK(bytes.size() == 25);

    HeartbeatPayload parsed;
    auto consumed = HeartbeatPayload::parse(bytes, parsed);
    CHECK(consumed == 25);
    CHECK(parsed.node_id == 0xABCDEF0123456789ULL);
    CHECK(parsed.timestamp_ms == 1700000000000ULL);
    CHECK(parsed.state == 3);
    CHECK(parsed.active_streams == 42);
    CHECK(parsed.pending_rpcs == 7);
}

// ========== 3. parse 长度不足返回 0 ==========
static void test_heartbeat_parse_short() {
    HeartbeatPayload parsed;
    std::vector<std::uint8_t> short_data(10, 0xAA);
    auto consumed = HeartbeatPayload::parse(short_data, parsed);
    CHECK(consumed == 0);

    // 空数据
    std::vector<std::uint8_t> empty;
    consumed = HeartbeatPayload::parse(empty, parsed);
    CHECK(consumed == 0);

    // 正好少 1 字节
    std::vector<std::uint8_t> almost(24, 0);
    consumed = HeartbeatPayload::parse(almost, parsed);
    CHECK(consumed == 0);
}

// ========== 4. RpcResponse 默认值 ==========
static void test_rpc_response_default() {
    RpcResponse resp;
    CHECK(resp.ok == false);
    CHECK(resp.payload.empty());
    CHECK(resp.error_msg.empty());
    CHECK(resp.elapsed.count() == 0);
}

// ========== 5. RpcPriority 枚举值 ==========
static void test_rpc_priority_values() {
    CHECK(static_cast<int>(RpcPriority::P0_Emergency) == 0);
    CHECK(static_cast<int>(RpcPriority::P1_Normal) == 1);
    CHECK(static_cast<int>(RpcPriority::P2_Low) == 2);
}

// ========== 6. ControlChannel 构造（空连接） ==========
static void test_construct_null() {
    ControlChannel ctrl(nullptr);
    CHECK(ctrl.is_valid() == false);
}

// ========== 7. is_valid 空连接 ==========
static void test_is_valid_null() {
    ControlChannel ctrl(nullptr);
    CHECK(ctrl.is_valid() == false);
    CHECK(ctrl.connection() == nullptr);
}

// ========== 8. ControlChannel 移动构造 ==========
static void test_move_construct() {
    ControlChannel ctrl1(nullptr);
    ControlChannel ctrl2(std::move(ctrl1));
    CHECK(ctrl2.is_valid() == false);
    CHECK(ctrl2.connection() == nullptr);
}

// ========== 9. ControlChannel 移动赋值 ==========
static void test_move_assign() {
    ControlChannel ctrl1(nullptr);
    ControlChannel ctrl2(nullptr);
    ctrl2 = std::move(ctrl1);
    CHECK(ctrl2.is_valid() == false);
}

// ========== 10. default_timeout_ms ==========
static void test_default_timeout() {
    CHECK(ControlChannel::default_timeout_ms(RpcPriority::P0_Emergency) == 5000);
    CHECK(ControlChannel::default_timeout_ms(RpcPriority::P1_Normal) == 30000);
    CHECK(ControlChannel::default_timeout_ms(RpcPriority::P2_Low) == 120000);
}

// ========== 11. priority_name ==========
static void test_priority_name() {
    CHECK(std::string(ControlChannel::priority_name(RpcPriority::P0_Emergency)) == "P0_Emergency");
    CHECK(std::string(ControlChannel::priority_name(RpcPriority::P1_Normal)) == "P1_Normal");
    CHECK(std::string(ControlChannel::priority_name(RpcPriority::P2_Low)) == "P2_Low");
}

// ========== 12. stats 初始值 ==========
static void test_stats_initial() {
    ControlChannel ctrl(nullptr);
    auto s = ctrl.stats();
    CHECK(s.p0_calls == 0);
    CHECK(s.p1_calls == 0);
    CHECK(s.p2_calls == 0);
    CHECK(s.heartbeats == 0);
    CHECK(s.drain_notifies == 0);
    CHECK(s.rpc_failures == 0);
    CHECK(s.rpc_timeouts == 0);
}

// ========== 13. send_heartbeat 空连接不崩溃 ==========
static void test_send_heartbeat_null() {
    ControlChannel ctrl(nullptr);
    HeartbeatPayload hb;
    ctrl.send_heartbeat(hb);  // 不应崩溃
    auto s = ctrl.stats();
    // send_heartbeat 内部 record_heartbeat 在 conn_ 检查前已调用
    CHECK(s.heartbeats == 1);
    // 心跳不算 RPC 调用，空连接时直接 return，rpc_failures 不增加
    CHECK(s.rpc_failures == 0);
}

// ========== 14. send_notification 空连接不崩溃 ==========
static void test_send_notification_null() {
    ControlChannel ctrl(nullptr);
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
    ctrl.send_notification(MethodId::LoadModel, payload, RpcPriority::P1_Normal);
    auto s = ctrl.stats();
    CHECK(s.p1_calls == 1);
    CHECK(s.rpc_failures == 1);
}

// ========== 15. notify_drain 空连接 ==========
static void test_notify_drain_null() {
    ControlChannel ctrl(nullptr);
    auto fut = ctrl.notify_drain("test reason");
    fut.get();  // 不应崩溃
    auto s = ctrl.stats();
    CHECK(s.drain_notifies == 1);
}

// ========== 16. call_rpc 空连接 ==========
static void test_call_rpc_null() {
    ControlChannel ctrl(nullptr);
    std::vector<std::uint8_t> payload = {0xAA, 0xBB};
    auto fut = ctrl.call_rpc(MethodId::LoadModel, payload, RpcPriority::P0_Emergency);
    auto resp = fut.get();
    CHECK(resp.ok == false);
    CHECK(!resp.error_msg.empty());
    auto s = ctrl.stats();
    CHECK(s.p0_calls == 1);
    CHECK(s.rpc_failures == 1);
}

// ========== 17. start/stop heartbeat thread ==========
static void test_heartbeat_thread_start_stop() {
    ControlChannel ctrl(nullptr);
    ctrl.start_heartbeat_thread(50, 200);  // 50ms 间隔
    std::this_thread::sleep_for(std::chrono::milliseconds(180));  // 等 3 个周期
    ctrl.stop_heartbeat_thread();
    auto s = ctrl.stats();
    // 至少发送过 1 次心跳（即使失败）
    CHECK(s.heartbeats >= 1);
}

// ========== 18. heartbeat 线程重复启动 ==========
static void test_heartbeat_thread_duplicate_start() {
    ControlChannel ctrl(nullptr);
    ctrl.start_heartbeat_thread(50, 200);
    ctrl.start_heartbeat_thread(50, 200);  // 重复启动应被忽略
    ctrl.stop_heartbeat_thread();
    // 不崩溃即视为通过
    CHECK(true);
}

// ========== 19. stats 累计 ==========
static void test_stats_accumulate() {
    ControlChannel ctrl(nullptr);

    // 多次调用不同优先级的 API
    std::vector<std::uint8_t> payload = {0x01};
    ctrl.send_notification(MethodId::Heartbeat, payload, RpcPriority::P0_Emergency);
    ctrl.send_notification(MethodId::Heartbeat, payload, RpcPriority::P1_Normal);
    ctrl.send_notification(MethodId::Heartbeat, payload, RpcPriority::P2_Low);
    ctrl.send_notification(MethodId::Heartbeat, payload, RpcPriority::P0_Emergency);

    auto s = ctrl.stats();
    CHECK(s.p0_calls == 2);
    CHECK(s.p1_calls == 1);
    CHECK(s.p2_calls == 1);
    // 每次都因 conn_ 空而失败
    CHECK(s.rpc_failures == 4);
}

// ========== 20. HeartbeatPayload 边界值 ==========
static void test_heartbeat_boundary() {
    HeartbeatPayload hb;
    hb.node_id = 0xFFFFFFFFFFFFFFFFULL;  // 最大 u64
    hb.timestamp_ms = 0xFFFFFFFFFFFFFFFFULL;
    hb.state = 0xFF;
    hb.active_streams = 0xFFFFFFFF;
    hb.pending_rpcs = 0xFFFFFFFF;

    auto bytes = hb.serialize();
    CHECK(bytes.size() == 25);

    HeartbeatPayload parsed;
    auto consumed = HeartbeatPayload::parse(bytes, parsed);
    CHECK(consumed == 25);
    CHECK(parsed.node_id == 0xFFFFFFFFFFFFFFFFULL);
    CHECK(parsed.timestamp_ms == 0xFFFFFFFFFFFFFFFFULL);
    CHECK(parsed.state == 0xFF);
    CHECK(parsed.active_streams == 0xFFFFFFFF);
    CHECK(parsed.pending_rpcs == 0xFFFFFFFF);
}

// ========== 21. 心跳超时回调触发（连续 miss） ==========
static void test_heartbeat_timeout_callback() {
    ControlChannel ctrl(nullptr);
    std::atomic<bool> callback_called{false};
    ctrl.on_heartbeat_timeout = [&callback_called]() {
        callback_called.store(true, std::memory_order_release);
    };
    // 间隔 10ms，超时 1ms（强制立即 miss，3 次后触发）
    ctrl.start_heartbeat_thread(10, 1);
    // 等待足够时间让心跳线程触发超时
    for (int i = 0; i < 50 && !callback_called.load(std::memory_order_acquire); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    ctrl.stop_heartbeat_thread();
    CHECK(callback_called.load(std::memory_order_acquire) == true);
}

// ========== 22. notify_drain payload 格式（reason 字符串 + \0） ==========
static void test_notify_drain_stats_only() {
    // 此测试仅验证统计计数，不验证实际网络发送
    ControlChannel ctrl(nullptr);
    auto fut1 = ctrl.notify_drain("OOM");
    fut1.get();
    auto fut2 = ctrl.notify_drain("layer conflict");
    fut2.get();
    auto s = ctrl.stats();
    CHECK(s.drain_notifies == 2);
}

int main() {
    std::printf("=== test_control_channel ===\n");

    test_heartbeat_default();
    test_heartbeat_roundtrip();
    test_heartbeat_parse_short();
    test_rpc_response_default();
    test_rpc_priority_values();
    test_construct_null();
    test_is_valid_null();
    test_move_construct();
    test_move_assign();
    test_default_timeout();
    test_priority_name();
    test_stats_initial();
    test_send_heartbeat_null();
    test_send_notification_null();
    test_notify_drain_null();
    test_call_rpc_null();
    test_heartbeat_thread_start_stop();
    test_heartbeat_thread_duplicate_start();
    test_stats_accumulate();
    test_heartbeat_boundary();
    test_heartbeat_timeout_callback();
    test_notify_drain_stats_only();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
