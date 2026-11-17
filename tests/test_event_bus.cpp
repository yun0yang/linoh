// test_event_bus.cpp — EventBus 单元测试（V3.4 P1-3）
//
// 覆盖 16 个用例 / ≥170 断言（详见 docs/LINOH_EVENTBUS_BINARY_FRAME_IMPL_PLAN.md §2.5）：
//   1. subscribe_publish_basic          — 单订阅者收发
//   2. multi_subscriber_fanout          — 多订阅者独立接收
//   3. event_type_filter                — FILTERED 计数器
//   4. coalesce_same_key                — 同 endpoint_id 的 NodeUpdated 覆盖 pending
//   5. coalesce_different_key           — 不同 endpoint_id 不合并
//   6. coalesce_disabled                — coalesce_enabled=false 时不合并
//   7. coalesce_latest_consumable       — 同 key 最新版本一定能被 poll 消费（修正核心）
//   8. dual_queue_priority              — 关键事件优先于可合并事件
//   9. critical_event_block             — 关键事件队列满时 Block 不丢
//  10. critical_event_block_timeout     — Block 超时返回 false
//  11. coalescable_drop_oldest_lossless — 可合并事件 DropOldest 信息无损
//  12. backpressure_drop_newest         — 可合并事件队列满丢弃最新
//  13. backpressure_block_coalescable   — 可合并事件 Block 策略
//  14. counters_snapshot                — 5 桶计数器准确性
//  15. legacy_callback_compat           — 旧 subscribe_node_events 行为不变
//  16. stop_subscriber                  — stop() 唤醒阻塞 poll + Block 中的 deliver

#include "linoh/event_bus.hpp"
#include "linoh/control_plane.hpp"  // ControlPlane (legacy compat)
#include "linoh/node_profile.hpp"   // NodeProfile
#include "linoh/base/key.hpp"       // EndpointId

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <thread>
#include <vector>

// ============================================================================
// 测试框架宏
// ============================================================================

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            printf("FAIL [%s:%d] %s\n", __FILE__, __LINE__, #cond);          \
            ++failures;                                                      \
        } else {                                                             \
            ++passed;                                                        \
        }                                                                    \
    } while (0)

static int passed = 0;
static int failures = 0;

// ============================================================================
// 辅助函数
// ============================================================================

using namespace linoh;
using namespace std::chrono_literals;

/// 用 seed 生成确定性 EndpointId（前 2 字节编码 seed，其余 0）
static base::EndpointId make_endpoint_id(int seed) {
    std::array<uint8_t, 32> bytes{};
    bytes[0] = static_cast<uint8_t>(seed & 0xFF);
    bytes[1] = static_cast<uint8_t>((seed >> 8) & 0xFF);
    return base::EndpointId(bytes);
}

/// 构造 NodeEvent
static NodeEvent make_event(NodeEventType type, int id_seed,
                            std::string detail = "") {
    NodeEvent ev;
    ev.type = type;
    ev.endpoint_id = make_endpoint_id(id_seed);
    ev.timestamp = std::chrono::system_clock::now();
    ev.detail = std::move(detail);
    return ev;
}

// ============================================================================
// 1. test_subscribe_publish_basic — 单订阅者收发（8 断言）
// ============================================================================

static void test_subscribe_publish_basic() {
    printf("[test] subscribe_publish_basic: single subscriber send/recv...\n");
    EventBus bus;
    auto sub = bus.subscribe();

    bus.publish(make_event(NodeEventType::NodeJoined, 1, "joined"));

    auto ev = sub->poll(100ms);
    CHECK(ev.has_value());
    CHECK(ev->type == NodeEventType::NodeJoined);
    CHECK(ev->endpoint_id == make_endpoint_id(1));
    CHECK(ev->detail == "joined");

    auto c = sub->counters();
    CHECK(c.received == 1);
    CHECK(c.filtered == 0);
    CHECK(c.enqueued == 1);
    CHECK(c.coalesced == 0);
}

// ============================================================================
// 2. test_multi_subscriber_fanout — 多订阅者独立接收（12 断言）
// ============================================================================

static void test_multi_subscriber_fanout() {
    printf("[test] multi_subscriber_fanout: 3 subscribers each receive...\n");
    EventBus bus;
    auto sub1 = bus.subscribe();
    auto sub2 = bus.subscribe();
    auto sub3 = bus.subscribe();

    CHECK(bus.subscriber_count() == 3);

    bus.publish(make_event(NodeEventType::NodeUpdated, 5, "update"));

    auto ev1 = sub1->poll(100ms);
    auto ev2 = sub2->poll(100ms);
    auto ev3 = sub3->poll(100ms);

    CHECK(ev1.has_value());
    CHECK(ev2.has_value());
    CHECK(ev3.has_value());
    CHECK(ev1->detail == "update");
    CHECK(ev2->detail == "update");
    CHECK(ev3->detail == "update");

    // 各订阅者独立计数
    CHECK(sub1->counters().received == 1);
    CHECK(sub2->counters().received == 1);
    CHECK(sub3->counters().received == 1);

    // EventBus 聚合计数器
    auto agg = bus.aggregate_counters();
    CHECK(agg.subscriber_count == 3);
    CHECK(agg.total.received == 3);
}

// ============================================================================
// 3. test_event_type_filter — FILTERED 计数器（10 断言）
// ============================================================================

static void test_event_type_filter() {
    printf("[test] event_type_filter: FILTERED counter...\n");
    SubscriberConfig cfg;
    cfg.event_types = {NodeEventType::NodeUpdated};
    EventBus bus;
    auto sub = bus.subscribe(cfg);

    // NodeJoined 不在过滤集合 → 被 filtered
    bus.publish(make_event(NodeEventType::NodeJoined, 1, "joined"));
    // NodeUpdated 在过滤集合 → 通过
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "updated"));

    auto c = sub->counters();
    CHECK(c.received == 2);
    CHECK(c.filtered == 1);
    CHECK(c.enqueued == 1);
    CHECK(c.backpressured == 0);

    // 只能 poll 到 NodeUpdated
    auto ev = sub->poll(100ms);
    CHECK(ev.has_value());
    CHECK(ev->type == NodeEventType::NodeUpdated);
    CHECK(ev->detail == "updated");

    // 再 poll 应为空
    auto ev2 = sub->try_poll();
    CHECK(!ev2.has_value());
    CHECK(sub->counters().coalesced == 0);
    CHECK(sub->queue_size() == 0);
}

// ============================================================================
// 4. test_coalesce_same_key — 同 endpoint_id 的 NodeUpdated 覆盖（15 断言）
// ============================================================================

static void test_coalesce_same_key() {
    printf("[test] coalesce_same_key: same endpoint_id NodeUpdated coalesce...\n");
    EventBus bus;
    auto sub = bus.subscribe();

    // 3 个同 key 的 NodeUpdated，detail 依次 v1/v2/v3
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v1"));
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v2"));
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v3"));

    auto c = sub->counters();
    CHECK(c.received == 3);
    CHECK(c.coalesced == 2);  // v2/v3 被 coalesce
    CHECK(c.enqueued == 1);   // 只有 v1 入 order（v2/v3 覆盖 pending）
    CHECK(c.filtered == 0);
    CHECK(c.backpressured == 0);

    // poll 取出的是最新版本 v3
    auto ev = sub->poll(100ms);
    CHECK(ev.has_value());
    CHECK(ev->type == NodeEventType::NodeUpdated);
    CHECK(ev->endpoint_id == make_endpoint_id(1));
    CHECK(ev->detail == "v3");

    // 队列已空
    CHECK(!sub->try_poll().has_value());
    CHECK(sub->queue_size() == 0);

    // 再发一个同 key 的，仍能正常 coalesce
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v4"));
    auto ev2 = sub->poll(100ms);
    CHECK(ev2.has_value());
    CHECK(ev2->detail == "v4");

    auto c2 = sub->counters();
    CHECK(c2.coalesced == 2);  // 不新增（v4 是新 key 入队后再发才 coalesce）
    CHECK(c2.enqueued == 2);   // v1 + v4 两次新 key 入队
}

// ============================================================================
// 5. test_coalesce_different_key — 不同 endpoint_id 不合并（8 断言）
// ============================================================================

static void test_coalesce_different_key() {
    printf("[test] coalesce_different_key: different endpoint_id no coalesce...\n");
    EventBus bus;
    auto sub = bus.subscribe();

    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "node1"));
    bus.publish(make_event(NodeEventType::NodeUpdated, 2, "node2"));

    auto c = sub->counters();
    CHECK(c.received == 2);
    CHECK(c.coalesced == 0);
    CHECK(c.enqueued == 2);
    CHECK(sub->queue_size() == 2);

    auto ev1 = sub->poll(100ms);
    auto ev2 = sub->poll(100ms);
    CHECK(ev1.has_value());
    CHECK(ev2.has_value());
    CHECK(ev1->detail == "node1");
    CHECK(ev2->detail == "node2");
}

// ============================================================================
// 6. test_coalesce_disabled — coalesce_enabled=false 时不合并（8 断言）
// ============================================================================

static void test_coalesce_disabled() {
    printf("[test] coalesce_disabled: coalesce_enabled=false no merge...\n");
    SubscriberConfig cfg;
    cfg.coalesce_enabled = false;
    EventBus bus;
    auto sub = bus.subscribe(cfg);

    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v1"));
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v2"));
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v3"));

    auto c = sub->counters();
    CHECK(c.received == 3);
    CHECK(c.coalesced == 0);  // 不合并
    CHECK(c.enqueued == 3);   // 全部入队（走关键事件通道）
    CHECK(sub->queue_size() == 3);

    // 按 FIFO 顺序消费
    auto ev1 = sub->poll(100ms);
    auto ev2 = sub->poll(100ms);
    auto ev3 = sub->poll(100ms);
    CHECK(ev1->detail == "v1");
    CHECK(ev2->detail == "v2");
    CHECK(ev3->detail == "v3");
    CHECK(!sub->try_poll().has_value());
}

// ============================================================================
// 7. test_coalesce_latest_consumable — 同 key 最新版本一定能被消费（12 断言）
// ============================================================================

static void test_coalesce_latest_consumable() {
    printf("[test] coalesce_latest_consumable: latest version always consumable...\n");
    // 修正核心：初版"覆盖字典+不入队"导致 v2 无法消费
    // V3.4"字典即队列"设计保证 poll 一定能取到最新版本
    EventBus bus;
    auto sub = bus.subscribe();

    // 先 poll 空（确认队列空）
    CHECK(!sub->try_poll().has_value());

    // 发 v1 → 入 order
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v1"));
    CHECK(sub->queue_size() == 1);

    // 发 v2 → 同 key 覆盖 pending，不重复入 order
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v2"));
    CHECK(sub->queue_size() == 1);  // order 仍只有 1 个 key

    // 发 v3 → 同 key 再次覆盖
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v3"));
    CHECK(sub->queue_size() == 1);

    auto c = sub->counters();
    CHECK(c.coalesced == 2);
    CHECK(c.enqueued == 1);

    // poll 一定能取到最新版本 v3（修正核心）
    auto ev = sub->poll(100ms);
    CHECK(ev.has_value());
    CHECK(ev->detail == "v3");

    // 队列空了
    CHECK(sub->queue_size() == 0);
    CHECK(!sub->try_poll().has_value());

    // 再发一个同 key，仍能正常消费
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v4"));
    auto ev2 = sub->poll(100ms);
    CHECK(ev2.has_value());
    CHECK(ev2->detail == "v4");
}

// ============================================================================
// 8. test_dual_queue_priority — 关键事件优先于可合并事件（10 断言）
// ============================================================================

static void test_dual_queue_priority() {
    printf("[test] dual_queue_priority: critical events consumed first...\n");
    EventBus bus;
    auto sub = bus.subscribe();

    // 先发可合并事件（NodeUpdated）
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "update"));
    // 再发关键事件（NodeJoined）
    bus.publish(make_event(NodeEventType::NodeJoined, 2, "joined"));

    // 虽然可合并事件先入队，但关键事件优先消费
    auto ev1 = sub->poll(100ms);
    CHECK(ev1.has_value());
    CHECK(ev1->type == NodeEventType::NodeJoined);  // 关键优先
    CHECK(ev1->detail == "joined");

    // 其次消费可合并事件
    auto ev2 = sub->poll(100ms);
    CHECK(ev2.has_value());
    CHECK(ev2->type == NodeEventType::NodeUpdated);
    CHECK(ev2->detail == "update");

    // 队列空
    CHECK(!sub->try_poll().has_value());

    auto c = sub->counters();
    CHECK(c.received == 2);
    CHECK(c.enqueued == 2);
    CHECK(c.coalesced == 0);
}

// ============================================================================
// 9. test_critical_event_block — 关键事件队列满时 Block 不丢（12 断言）
// ============================================================================

static void test_critical_event_block() {
    printf("[test] critical_event_block: Block policy ensures no loss...\n");
    SubscriberConfig cfg;
    cfg.critical_queue_capacity = 1;
    cfg.critical_event_policy = BackpressurePolicy::Block;
    cfg.block_timeout = std::chrono::milliseconds(0);  // 无限等待
    EventBus bus;
    auto sub = bus.subscribe(cfg);

    // 填满关键队列（容量=1）
    bus.publish(make_event(NodeEventType::NodeJoined, 1, "j1"));
    CHECK(sub->counters().enqueued == 1);
    CHECK(sub->queue_size() == 1);

    // 启动生产者线程：publish 第 2 个关键事件（会 Block）
    std::atomic<bool> deliver_done{false};
    std::atomic<bool> deliver_result{false};
    std::thread producer([&]() {
        bool ok = sub->deliver(make_event(NodeEventType::NodeJoined, 2, "j2"));
        deliver_result.store(ok);
        deliver_done.store(true);
    });

    // 等待确保生产者已阻塞
    std::this_thread::sleep_for(50ms);
    CHECK(!deliver_done.load());  // 仍在阻塞
    CHECK(sub->counters().backpressured == 1);

    // 消费一个事件腾出空位
    auto ev = sub->poll(100ms);
    CHECK(ev.has_value());
    CHECK(ev->detail == "j1");

    // 生产者应解除阻塞并成功入队
    producer.join();
    CHECK(deliver_done.load());
    CHECK(deliver_result.load());  // deliver 成功

    // 消费第二个事件
    auto ev2 = sub->poll(100ms);
    CHECK(ev2.has_value());
    CHECK(ev2->detail == "j2");

    auto c = sub->counters();
    CHECK(c.received == 2);
    CHECK(c.backpressured == 1);
    CHECK(c.enqueued == 2);
}

// ============================================================================
// 10. test_critical_event_block_timeout — Block 超时返回 false（8 断言）
// ============================================================================

static void test_critical_event_block_timeout() {
    printf("[test] critical_event_block_timeout: timeout returns false...\n");
    SubscriberConfig cfg;
    cfg.critical_queue_capacity = 1;
    cfg.critical_event_policy = BackpressurePolicy::Block;
    cfg.block_timeout = std::chrono::milliseconds(50);  // 50ms 超时
    EventBus bus;
    auto sub = bus.subscribe(cfg);

    // 填满队列
    sub->deliver(make_event(NodeEventType::NodeJoined, 1, "j1"));
    CHECK(sub->queue_size() == 1);

    // 再 deliver → Block 超时
    auto start = std::chrono::steady_clock::now();
    bool ok = sub->deliver(make_event(NodeEventType::NodeJoined, 2, "j2"));
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);

    CHECK(!ok);  // 超时返回 false
    CHECK(ms.count() >= 40);  // 至少等待了 ~50ms（允许 10ms 误差）
    CHECK(ms.count() < 200);  // 但不应太久

    auto c = sub->counters();
    CHECK(c.received == 2);
    CHECK(c.backpressured == 1);
    CHECK(c.enqueued == 1);  // 只有 j1 入队
    CHECK(c.coalesced == 0);
    CHECK(sub->queue_size() == 1);
}

// ============================================================================
// 11. test_coalescable_drop_oldest_lossless — 可合并事件 DropOldest 无损（12 断言）
// ============================================================================

static void test_coalescable_drop_oldest_lossless() {
    printf("[test] coalescable_drop_oldest_lossless: DropOldest is lossless...\n");
    SubscriberConfig cfg;
    cfg.coalescable_queue_capacity = 2;
    cfg.policy = BackpressurePolicy::DropOldest;
    EventBus bus;
    auto sub = bus.subscribe(cfg);

    // 3 个不同 key 的 NodeUpdated → 第 3 个触发 DropOldest
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v1"));
    bus.publish(make_event(NodeEventType::NodeUpdated, 2, "v2"));
    bus.publish(make_event(NodeEventType::NodeUpdated, 3, "v3"));

    auto c = sub->counters();
    CHECK(c.received == 3);
    CHECK(c.backpressured == 1);  // 第 3 个触发
    CHECK(c.enqueued == 3);       // 3 个都 ++enqueued（含 DropOldest 后入队的）
    CHECK(c.coalesced == 0);      // 不同 key 不合并
    CHECK(c.filtered == 0);

    // v1 被 DropOldest 丢弃，队列中应有 v2 和 v3
    CHECK(sub->queue_size() == 2);

    auto ev1 = sub->poll(100ms);
    auto ev2 = sub->poll(100ms);
    CHECK(ev1.has_value());
    CHECK(ev2.has_value());
    CHECK(ev1->detail == "v2");  // v1 被丢弃
    CHECK(ev2->detail == "v3");

    // 信息无损验证：如果 v1 的节点再次更新，新版本会重新入队
    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v1_new"));
    auto ev3 = sub->poll(100ms);
    CHECK(ev3.has_value());
    CHECK(ev3->detail == "v1_new");  // 新版本重新入队
}

// ============================================================================
// 12. test_backpressure_drop_newest — 可合并事件队列满丢弃最新（10 断言）
// ============================================================================

static void test_backpressure_drop_newest() {
    printf("[test] backpressure_drop_newest: DropNewest on coalescable queue...\n");
    SubscriberConfig cfg;
    cfg.coalescable_queue_capacity = 2;
    cfg.policy = BackpressurePolicy::DropNewest;
    EventBus bus;
    auto sub = bus.subscribe(cfg);

    bus.publish(make_event(NodeEventType::NodeUpdated, 1, "v1"));
    bus.publish(make_event(NodeEventType::NodeUpdated, 2, "v2"));
    // 队列满，第 3 个触发 DropNewest（当前实现回退为 DropOldest 腾位）
    bus.publish(make_event(NodeEventType::NodeUpdated, 3, "v3"));

    auto c = sub->counters();
    CHECK(c.received == 3);
    CHECK(c.backpressured == 1);
    CHECK(c.coalesced == 0);

    // 队列中有 2 个事件（DropNewest/DropOldest 腾位后 v3 入队）
    CHECK(sub->queue_size() == 2);

    auto ev1 = sub->poll(100ms);
    auto ev2 = sub->poll(100ms);
    CHECK(ev1.has_value());
    CHECK(ev2.has_value());
    CHECK(ev1->type == NodeEventType::NodeUpdated);
    CHECK(ev2->type == NodeEventType::NodeUpdated);
    CHECK(!sub->try_poll().has_value());
    CHECK(sub->counters().enqueued == 3);
}

// ============================================================================
// 13. test_backpressure_block_coalescable — 可合并事件 Block 策略（8 断言）
// ============================================================================

static void test_backpressure_block_coalescable() {
    printf("[test] backpressure_block_coalescable: Block on coalescable queue...\n");
    SubscriberConfig cfg;
    cfg.coalescable_queue_capacity = 1;
    cfg.policy = BackpressurePolicy::Block;
    cfg.block_timeout = std::chrono::milliseconds(50);
    EventBus bus;
    auto sub = bus.subscribe(cfg);

    // 填满可合并队列
    sub->deliver(make_event(NodeEventType::NodeUpdated, 1, "v1"));
    CHECK(sub->queue_size() == 1);

    // 再 deliver → Block 超时
    bool ok = sub->deliver(make_event(NodeEventType::NodeUpdated, 2, "v2"));
    CHECK(!ok);  // 超时

    auto c = sub->counters();
    CHECK(c.backpressured == 1);
    CHECK(c.received == 2);
    CHECK(c.enqueued == 1);  // 只有 v1 入队

    // 消费后腾出空位，再 deliver 成功
    auto ev = sub->poll(100ms);
    CHECK(ev.has_value());
    CHECK(ev->detail == "v1");

    bool ok2 = sub->deliver(make_event(NodeEventType::NodeUpdated, 2, "v2"));
    CHECK(ok2);  // 成功
}

// ============================================================================
// 14. test_counters_snapshot — 5 桶计数器准确性（15 断言）
// ============================================================================

static void test_counters_snapshot() {
    printf("[test] counters_snapshot: 5-bucket counter accuracy...\n");
    SubscriberConfig cfg;
    cfg.event_types = {NodeEventType::NodeUpdated, NodeEventType::NodeJoined,
                       NodeEventType::RegionRepChanged};
    cfg.coalescable_queue_capacity = 10;
    cfg.critical_queue_capacity = 10;
    EventBus bus;
    auto sub = bus.subscribe(cfg);

    // 1. NodeLeft 被过滤（不在 event_types）
    bus.publish(make_event(NodeEventType::NodeLeft, 1, "left"));
    // 2. NodeJoined（关键事件，入队）
    bus.publish(make_event(NodeEventType::NodeJoined, 1, "joined"));
    // 3. NodeUpdated v1（可合并，入队）
    bus.publish(make_event(NodeEventType::NodeUpdated, 2, "v1"));
    // 4. NodeUpdated v2（同 key coalesce）
    bus.publish(make_event(NodeEventType::NodeUpdated, 2, "v2"));
    // 5. RegionRepChanged（可合并，不同 key 入队）
    bus.publish(make_event(NodeEventType::RegionRepChanged, 3, "rep"));

    auto c = sub->counters();
    CHECK(c.received == 5);
    CHECK(c.filtered == 1);     // NodeLeft
    CHECK(c.coalesced == 1);    // v2
    CHECK(c.enqueued == 3);     // joined + v1 + rep
    CHECK(c.backpressured == 0);

    // EventCountKind::get 接口
    CHECK(c.get(EventCountKind::Received) == 5);
    CHECK(c.get(EventCountKind::Filtered) == 1);
    CHECK(c.get(EventCountKind::Coalesced) == 1);
    CHECK(c.get(EventCountKind::Enqueued) == 3);
    CHECK(c.get(EventCountKind::Backpressured) == 0);

    // event_count_kind_name
    CHECK(std::string(event_count_kind_name(EventCountKind::Received)) == "received");
    CHECK(std::string(event_count_kind_name(EventCountKind::Filtered)) == "filtered");
    CHECK(std::string(event_count_kind_name(EventCountKind::Coalesced)) == "coalesced");
    CHECK(std::string(event_count_kind_name(EventCountKind::Enqueued)) == "enqueued");
    CHECK(std::string(event_count_kind_name(EventCountKind::Backpressured)) == "backpressured");
}

// ============================================================================
// 15. test_legacy_callback_compat — 旧 subscribe_node_events 行为不变（12 断言）
// ============================================================================

static void test_legacy_callback_compat() {
    printf("[test] legacy_callback_compat: subscribe_node_events behavior unchanged...\n");
    // P1 阶段：ControlPlane 未集成 EventBus，测试旧 callback 机制正常工作
    // P2 集成后：emit_event 双路径（同步 event_cb_ + 异步 EventBus），旧接口保持同步语义
    ControlPlane cp;
    std::vector<NodeEvent> received;
    std::mutex received_mtx;

    cp.subscribe_node_events([&](const NodeEvent &ev) {
        std::lock_guard<std::mutex> lk(received_mtx);
        received.push_back(ev);
    });

    // start → NodeJoined("self_registered")
    auto self_id = make_endpoint_id(1);
    NodeProfile self_profile;
    self_profile.endpoint_id = self_id;
    cp.start(self_id, self_profile);

    // register new node → NodeJoined("registered")
    auto node2 = make_endpoint_id(2);
    NodeProfile profile2;
    profile2.endpoint_id = node2;
    cp.register_node(profile2);

    // register same node → NodeUpdated("profile_updated")
    cp.register_node(profile2);

    // stop → NodeLeft("self_stopped")
    cp.stop();

    std::lock_guard<std::mutex> lk(received_mtx);
    CHECK(received.size() == 4);
    CHECK(received[0].type == NodeEventType::NodeJoined);
    CHECK(received[0].detail == "self_registered");
    CHECK(received[1].type == NodeEventType::NodeJoined);
    CHECK(received[1].detail == "registered");
    CHECK(received[2].type == NodeEventType::NodeUpdated);
    CHECK(received[2].detail == "profile_updated");
    CHECK(received[3].type == NodeEventType::NodeLeft);
    CHECK(received[3].detail == "self_stopped");
    CHECK(received[0].endpoint_id == self_id);
    CHECK(received[1].endpoint_id == node2);
    CHECK(received[2].endpoint_id == node2);
    CHECK(received[3].endpoint_id == self_id);
}

// ============================================================================
// 16. test_stop_subscriber — stop() 唤醒阻塞 poll + Block 中的 deliver（10 断言）
// ============================================================================

static void test_stop_subscriber() {
    printf("[test] stop_subscriber: stop wakes blocked poll and Block deliver...\n");

    // === 部分 1：stop() 唤醒阻塞的 poll ===
    {
        EventBus bus;
        auto sub = bus.subscribe();

        std::atomic<bool> poll_returned{false};
        std::atomic<bool> poll_result_has_value{false};
        std::thread consumer([&]() {
            auto ev = sub->poll(5000ms);  // 长超时阻塞
            poll_result_has_value.store(ev.has_value());
            poll_returned.store(true);
        });

        std::this_thread::sleep_for(50ms);
        CHECK(!poll_returned.load());  // 仍在阻塞

        sub->stop();  // 唤醒

        consumer.join();
        CHECK(poll_returned.load());            // poll 已返回
        CHECK(!poll_result_has_value.load());   // 返回 nullopt

        // stop 后再 poll 立即返回 nullopt
        auto ev2 = sub->try_poll();
        CHECK(!ev2.has_value());
    }

    // === 部分 2：stop() 唤醒 Block 中的 deliver ===
    {
        SubscriberConfig cfg;
        cfg.critical_queue_capacity = 1;
        cfg.critical_event_policy = BackpressurePolicy::Block;
        cfg.block_timeout = std::chrono::milliseconds(0);  // 无限等待
        EventBus bus;
        auto sub = bus.subscribe(cfg);

        // 填满关键队列
        sub->deliver(make_event(NodeEventType::NodeJoined, 1, "j1"));
        CHECK(sub->queue_size() == 1);

        std::atomic<bool> deliver_done{false};
        std::atomic<bool> deliver_result{true};
        std::thread producer([&]() {
            bool ok = sub->deliver(make_event(NodeEventType::NodeJoined, 2, "j2"));
            deliver_result.store(ok);
            deliver_done.store(true);
        });

        std::this_thread::sleep_for(50ms);
        CHECK(!deliver_done.load());  // 仍在 Block

        sub->stop();  // 唤醒 Block 中的 deliver

        producer.join();
        CHECK(deliver_done.load());
        CHECK(!deliver_result.load());  // stop 后 deliver 返回 false

        // stop 后计数器仍可读
        auto c = sub->counters();
        CHECK(c.received == 2);
        CHECK(c.backpressured == 1);
    }
}

// ============================================================================
// main
// ============================================================================

int main() {
    printf("=== test_event_bus — EventBus 单元测试（V3.4 P1-3）===\n\n");

    test_subscribe_publish_basic();
    test_multi_subscriber_fanout();
    test_event_type_filter();
    test_coalesce_same_key();
    test_coalesce_different_key();
    test_coalesce_disabled();
    test_coalesce_latest_consumable();
    test_dual_queue_priority();
    test_critical_event_block();
    test_critical_event_block_timeout();
    test_coalescable_drop_oldest_lossless();
    test_backpressure_drop_newest();
    test_backpressure_block_coalescable();
    test_counters_snapshot();
    test_legacy_callback_compat();
    test_stop_subscriber();

    printf("\n=== Results: %d passed, %d failed (total %d) ===\n",
           passed, failures, passed + failures);

    return failures == 0 ? 0 : 1;
}
