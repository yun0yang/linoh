// test_traffic_priority.cpp — v4.0.5 M23 流量优先级 QoS 单元测试
//
// 测试覆盖：
//   1. TrafficPriority 枚举值校验 + to_string
//   2. kTrafficPriorityCount 常量
//   3. priority_for_alpn 各 ALPN 映射
//   4. priority_for_alpn 未知 ALPN 降级 Low
//   5. PriorityConfig 默认值 + 常量
//   6. PriorityConfig default_weights 工厂
//   7. PriorityConfig strict_priority 工厂
//   8. PriorityConfig balanced 工厂
//   9. PriorityConfig llm_inference_priority 工厂
//  10. PriorityConfig weight_of
//  11. PriorityConfig set_weight + 夹紧
//  12. PriorityConfig encode 字节布局
//  13. PriorityConfig encode/decode 往返 default_weights
//  14. PriorityConfig encode/decode 往返 strict_priority
//  15. PriorityConfig encode/decode 往返 balanced
//  16. PriorityConfig encode/decode 往返 llm_inference_priority
//  17. PriorityConfig decode 短数据返回 false
//  18. PriorityConfig decode version 不匹配返回 false
//  19. PriorityConfig decode 权重越界返回 false
//  20. PriorityConfig to_string 输出格式
//  21. WeightedFairQueue 默认构造
//  22. WeightedFairQueue enqueue + dequeue 单项
//  23. WeightedFairQueue 同优先级 FIFO 顺序
//  24. WeightedFairQueue 优先级抢占（Critical 先于 Low）
//  25. WeightedFairQueue WFQ 防饿死（Low 最终出队）
//  26. WeightedFairQueue 严格优先级模式（Low 饿死）
//  27. WeightedFairQueue enqueue_for_alpn
//  28. WeightedFairQueue peek 不移除
//  29. WeightedFairQueue size / size_of / empty
//  30. WeightedFairQueue clear
//  31. WeightedFairQueue stats 累计
//  32. WeightedFairQueue set_config 运行时调整
//  33. WeightedFairQueue reset_deficit
//  34. WeightedFairQueue dequeue 空队列返回 nullopt
//  35. WeightedFairQueue e2e 混合优先级场景
//  36. WeightedFairQueue 防饿死统计触发

#include "linoh/protocol/traffic_priority.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    if ((a) == (b)) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s != %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ========== 辅助函数 ==========

static QueueItem make_item(TrafficPriority p, std::uint64_t id, std::size_t sz = 1) {
    QueueItem item;
    item.priority = p;
    item.item_id = id;
    item.size = sz;
    item.data.assign(sz, 0xAB);
    return item;
}

// ========== TrafficPriority 枚举 ==========

// 1. TrafficPriority 枚举值 + to_string
static void test_priority_enum() {
    std::printf("[test] TrafficPriority enum + to_string...\n");
    CHECK_EQ(static_cast<std::uint8_t>(TrafficPriority::Critical), 0u);
    CHECK_EQ(static_cast<std::uint8_t>(TrafficPriority::High),     1u);
    CHECK_EQ(static_cast<std::uint8_t>(TrafficPriority::Medium),   2u);
    CHECK_EQ(static_cast<std::uint8_t>(TrafficPriority::Low),      3u);

    CHECK(std::strcmp(to_string(TrafficPriority::Critical), "Critical") == 0);
    CHECK(std::strcmp(to_string(TrafficPriority::High),     "High") == 0);
    CHECK(std::strcmp(to_string(TrafficPriority::Medium),   "Medium") == 0);
    CHECK(std::strcmp(to_string(TrafficPriority::Low),      "Low") == 0);
}

// 2. kTrafficPriorityCount
static void test_priority_count() {
    std::printf("[test] kTrafficPriorityCount...\n");
    CHECK_EQ(kTrafficPriorityCount, 4u);
}

// 3. priority_for_alpn 各 ALPN 映射
static void test_priority_for_alpn() {
    std::printf("[test] priority_for_alpn mappings...\n");
    CHECK_EQ(priority_for_alpn("ctrl/1"),      TrafficPriority::Critical);
    CHECK_EQ(priority_for_alpn("pp-hidden/1"), TrafficPriority::High);
    CHECK_EQ(priority_for_alpn("pp-llm/1"),    TrafficPriority::High);  // 兼容别名
    CHECK_EQ(priority_for_alpn("pp-audio/1"),  TrafficPriority::Medium);
    CHECK_EQ(priority_for_alpn("pp-img/1"),    TrafficPriority::Low);
    CHECK_EQ(priority_for_alpn("pp-video/1"),  TrafficPriority::Low);
    CHECK_EQ(priority_for_alpn("pp-multi/1"),  TrafficPriority::Low);
}

// 4. priority_for_alpn 未知 ALPN 降级 Low
static void test_priority_for_unknown_alpn() {
    std::printf("[test] priority_for_alpn unknown → Low...\n");
    CHECK_EQ(priority_for_alpn(""),            TrafficPriority::Low);
    CHECK_EQ(priority_for_alpn("unknown/1"),   TrafficPriority::Low);
    CHECK_EQ(priority_for_alpn("pp-data/1"),   TrafficPriority::Low);
}

// ========== PriorityConfig ==========

// 5. PriorityConfig 默认值 + 常量
static void test_config_defaults() {
    std::printf("[test] PriorityConfig defaults + constants...\n");
    PriorityConfig p;
    CHECK(p.enable_wfq);                                       // 默认启用 WFQ
    CHECK_EQ(p.critical_weight, PriorityConfig::kDefaultCriticalWeight);  // 8
    CHECK_EQ(p.high_weight,     PriorityConfig::kDefaultHighWeight);      // 4
    CHECK_EQ(p.medium_weight,   PriorityConfig::kDefaultMediumWeight);    // 2
    CHECK_EQ(p.low_weight,      PriorityConfig::kDefaultLowWeight);       // 1
    CHECK_EQ(p.quantum, 1u);

    CHECK_EQ(PriorityConfig::kCurrentVersion, 1u);
    CHECK_EQ(PriorityConfig::kEncodedSize, 11u);
    CHECK_EQ(PriorityConfig::kMinWeight, 1u);
    CHECK_EQ(PriorityConfig::kMaxWeight, 1000u);
    CHECK_EQ(PriorityConfig::kDefaultCriticalWeight, 8u);
    CHECK_EQ(PriorityConfig::kDefaultHighWeight, 4u);
    CHECK_EQ(PriorityConfig::kDefaultMediumWeight, 2u);
    CHECK_EQ(PriorityConfig::kDefaultLowWeight, 1u);
}

// 6. default_weights 工厂
static void test_factory_default_weights() {
    std::printf("[test] default_weights factory...\n");
    auto p = PriorityConfig::default_weights();
    CHECK(p.enable_wfq);
    CHECK_EQ(p.critical_weight, 8u);
    CHECK_EQ(p.high_weight, 4u);
    CHECK_EQ(p.medium_weight, 2u);
    CHECK_EQ(p.low_weight, 1u);
}

// 7. strict_priority 工厂
static void test_factory_strict_priority() {
    std::printf("[test] strict_priority factory...\n");
    auto p = PriorityConfig::strict_priority();
    CHECK(!p.enable_wfq);  // 禁用 WFQ
    // 权重保持默认
    CHECK_EQ(p.critical_weight, 8u);
    CHECK_EQ(p.high_weight, 4u);
    CHECK_EQ(p.medium_weight, 2u);
    CHECK_EQ(p.low_weight, 1u);
}

// 8. balanced 工厂
static void test_factory_balanced() {
    std::printf("[test] balanced factory...\n");
    auto p = PriorityConfig::balanced();
    CHECK(p.enable_wfq);
    CHECK_EQ(p.critical_weight, 4u);
    CHECK_EQ(p.high_weight, 4u);
    CHECK_EQ(p.medium_weight, 4u);
    CHECK_EQ(p.low_weight, 4u);
}

// 9. llm_inference_priority 工厂
static void test_factory_llm_priority() {
    std::printf("[test] llm_inference_priority factory...\n");
    auto p = PriorityConfig::llm_inference_priority();
    CHECK(p.enable_wfq);
    CHECK_EQ(p.critical_weight, 4u);
    CHECK_EQ(p.high_weight, 8u);     // hidden_state 最高
    CHECK_EQ(p.medium_weight, 2u);
    CHECK_EQ(p.low_weight, 1u);
}

// 10. weight_of
static void test_weight_of() {
    std::printf("[test] weight_of...\n");
    auto p = PriorityConfig::default_weights();
    CHECK_EQ(p.weight_of(TrafficPriority::Critical), 8u);
    CHECK_EQ(p.weight_of(TrafficPriority::High),     4u);
    CHECK_EQ(p.weight_of(TrafficPriority::Medium),   2u);
    CHECK_EQ(p.weight_of(TrafficPriority::Low),      1u);
}

// 11. set_weight + 夹紧
static void test_set_weight() {
    std::printf("[test] set_weight + clamp...\n");
    PriorityConfig p;
    p.set_weight(TrafficPriority::Critical, 100);
    CHECK_EQ(p.critical_weight, 100u);

    p.set_weight(TrafficPriority::High, 0);  // 低于最小值，夹紧到 1
    CHECK_EQ(p.high_weight, 1u);

    p.set_weight(TrafficPriority::Medium, 2000);  // 超过最大值，夹紧到 1000
    CHECK_EQ(p.medium_weight, 1000u);

    p.set_weight(TrafficPriority::Low, 50);
    CHECK_EQ(p.low_weight, 50u);
}

// 12. encode 字节布局
static void test_encode_layout() {
    std::printf("[test] encode byte layout...\n");
    auto p = PriorityConfig::default_weights();
    auto bytes = p.encode();
    CHECK_EQ(bytes.size(), PriorityConfig::kEncodedSize);  // 11
    CHECK_EQ(bytes[0], PriorityConfig::kCurrentVersion);   // version=1
    CHECK_EQ(bytes[1], 0x01);                              // enable_wfq=true
    // critical_weight=8 (小端)
    CHECK_EQ(bytes[2], 8u);
    CHECK_EQ(bytes[3], 0u);
    // high_weight=4
    CHECK_EQ(bytes[4], 4u);
    CHECK_EQ(bytes[5], 0u);
    // medium_weight=2
    CHECK_EQ(bytes[6], 2u);
    CHECK_EQ(bytes[7], 0u);
    // low_weight=1
    CHECK_EQ(bytes[8], 1u);
    CHECK_EQ(bytes[9], 0u);
    // quantum=1
    CHECK_EQ(bytes[10], 1u);

    // strict_priority: enable_wfq=false
    auto sp = PriorityConfig::strict_priority().encode();
    CHECK_EQ(sp[1], 0x00);
}

// 13-16. encode/decode 往返
static void test_encode_decode_roundtrip() {
    std::printf("[test] encode/decode roundtrip...\n");
    auto configs = {
        PriorityConfig::default_weights(),
        PriorityConfig::strict_priority(),
        PriorityConfig::balanced(),
        PriorityConfig::llm_inference_priority(),
    };
    for (auto &orig : configs) {
        auto bytes = orig.encode();
        PriorityConfig decoded;
        CHECK(PriorityConfig::decode(bytes, decoded));
        CHECK(orig == decoded);
    }

    // 自定义权重往返
    PriorityConfig custom;
    custom.enable_wfq = false;
    custom.critical_weight = 100;
    custom.high_weight = 50;
    custom.medium_weight = 25;
    custom.low_weight = 5;
    custom.quantum = 3;
    auto bytes = custom.encode();
    PriorityConfig decoded;
    CHECK(PriorityConfig::decode(bytes, decoded));
    CHECK(custom == decoded);
}

// 17. decode 短数据
static void test_decode_short_data() {
    std::printf("[test] decode short data...\n");
    std::vector<std::uint8_t> short_data(PriorityConfig::kEncodedSize - 1, 0);
    PriorityConfig p;
    CHECK(!PriorityConfig::decode(short_data, p));

    std::vector<std::uint8_t> empty;
    CHECK(!PriorityConfig::decode(empty, p));
}

// 18. decode version 不匹配
static void test_decode_bad_version() {
    std::printf("[test] decode bad version...\n");
    auto bytes = PriorityConfig::default_weights().encode();
    bytes[0] = 99;  // 错误 version
    PriorityConfig p;
    CHECK(!PriorityConfig::decode(bytes, p));
}

// 19. decode 权重越界
static void test_decode_weight_out_of_range() {
    std::printf("[test] decode weight out of range...\n");
    auto bytes = PriorityConfig::default_weights().encode();
    // critical_weight 设置为 0（小于 kMinWeight=1）
    bytes[2] = 0;
    bytes[3] = 0;
    PriorityConfig p;
    CHECK(!PriorityConfig::decode(bytes, p));

    // 恢复并测试超过 kMaxWeight=1000
    auto bytes2 = PriorityConfig::default_weights().encode();
    bytes2[2] = 0xE8;  // 1000 = 0x03E8
    bytes2[3] = 0x03;
    // 1000 是合法的（边界值）
    PriorityConfig p2;
    CHECK(PriorityConfig::decode(bytes2, p2));
    CHECK_EQ(p2.critical_weight, 1000u);

    // 1001 越界
    bytes2[2] = 0xE9;  // 1001 = 0x03E9
    PriorityConfig p3;
    CHECK(!PriorityConfig::decode(bytes2, p3));
}

// 20. to_string 输出格式
static void test_config_to_string() {
    std::printf("[test] config to_string...\n");
    auto p = PriorityConfig::default_weights();
    auto s = p.to_string();
    CHECK(s.find("wfq=on") != std::string::npos);
    CHECK(s.find("8:4:2:1") != std::string::npos);
    CHECK(s.find("quantum=1") != std::string::npos);

    auto sp = PriorityConfig::strict_priority().to_string();
    CHECK(sp.find("wfq=off") != std::string::npos);
}

// ========== WeightedFairQueue ==========

// 21. 默认构造
static void test_wfq_default_construct() {
    std::printf("[test] WeightedFairQueue default construct...\n");
    WeightedFairQueue q;
    CHECK(q.empty());
    CHECK_EQ(q.size(), 0u);
    auto cfg = q.config();
    CHECK(cfg.enable_wfq);
    CHECK_EQ(cfg.critical_weight, 8u);
}

// 22. enqueue + dequeue 单项
static void test_wfq_single_item() {
    std::printf("[test] enqueue + dequeue single item...\n");
    WeightedFairQueue q;
    q.enqueue(make_item(TrafficPriority::High, 42));
    CHECK(!q.empty());
    CHECK_EQ(q.size(), 1u);
    auto item = q.dequeue();
    CHECK(item.has_value());
    CHECK_EQ(item->item_id, 42u);
    CHECK_EQ(item->priority, TrafficPriority::High);
    CHECK(q.empty());
}

// 23. 同优先级 FIFO 顺序
static void test_wfq_same_priority_fifo() {
    std::printf("[test] same priority FIFO...\n");
    WeightedFairQueue q;
    for (std::uint64_t i = 1; i <= 5; ++i) {
        q.enqueue(make_item(TrafficPriority::Low, i));
    }
    for (std::uint64_t expected = 1; expected <= 5; ++expected) {
        auto item = q.dequeue();
        CHECK(item.has_value());
        CHECK_EQ(item->item_id, expected);
    }
    CHECK(q.empty());
}

// 24. 优先级抢占（Critical 先于 Low）
static void test_wfq_priority_preemption() {
    std::printf("[test] priority preemption (Critical before Low)...\n");
    WeightedFairQueue q;
    // 入队顺序：Low 先入，Critical 后入
    q.enqueue(make_item(TrafficPriority::Low, 1));
    q.enqueue(make_item(TrafficPriority::Low, 2));
    q.enqueue(make_item(TrafficPriority::Critical, 100));
    q.enqueue(make_item(TrafficPriority::Critical, 101));

    // 第一个出队的应该是 Critical（即使 Low 先入）
    auto first = q.dequeue();
    CHECK(first.has_value());
    CHECK_EQ(first->priority, TrafficPriority::Critical);
    CHECK_EQ(first->item_id, 100u);

    auto second = q.dequeue();
    CHECK(second.has_value());
    CHECK_EQ(second->priority, TrafficPriority::Critical);
    CHECK_EQ(second->item_id, 101u);
}

// 25. WFQ 防饿死（Low 最终出队）
static void test_wfq_starvation_avoidance() {
    std::printf("[test] WFQ starvation avoidance (Low eventually dequeues)...\n");
    WeightedFairQueue q;
    // 持续入队 Critical 和 Low，验证 Low 也能出队
    for (int i = 0; i < 10; ++i) {
        q.enqueue(make_item(TrafficPriority::Critical, static_cast<std::uint64_t>(i)));
        q.enqueue(make_item(TrafficPriority::Low, static_cast<std::uint64_t>(1000 + i)));
    }

    int critical_count = 0;
    int low_count = 0;
    while (auto item = q.dequeue()) {
        if (item->priority == TrafficPriority::Critical) ++critical_count;
        else if (item->priority == TrafficPriority::Low) ++low_count;
    }
    // Critical 和 Low 都应该出队（Low 不会被饿死）
    CHECK(critical_count > 0);
    CHECK(low_count > 0);
    CHECK_EQ(critical_count + low_count, 20);
}

// 26. 严格优先级模式（Low 饿死）
static void test_wfq_strict_priority_starvation() {
    std::printf("[test] strict priority mode (Low starves)...\n");
    WeightedFairQueue q(PriorityConfig::strict_priority());
    // 持续入队 Critical 和 Low
    for (int i = 0; i < 5; ++i) {
        q.enqueue(make_item(TrafficPriority::Critical, static_cast<std::uint64_t>(i)));
        q.enqueue(make_item(TrafficPriority::Low, static_cast<std::uint64_t>(1000 + i)));
    }

    // 严格优先级：先出完所有 Critical
    int critical_count = 0;
    int low_count = 0;
    // 只出队前 5 个（应该全是 Critical）
    for (int i = 0; i < 5; ++i) {
        auto item = q.dequeue();
        CHECK(item.has_value());
        CHECK_EQ(item->priority, TrafficPriority::Critical);
        ++critical_count;
    }
    // 剩余 5 个 Low
    while (auto item = q.dequeue()) {
        CHECK_EQ(item->priority, TrafficPriority::Low);
        ++low_count;
    }
    CHECK_EQ(critical_count, 5);
    CHECK_EQ(low_count, 5);
}

// 27. enqueue_for_alpn
static void test_wfq_enqueue_for_alpn() {
    std::printf("[test] enqueue_for_alpn...\n");
    WeightedFairQueue q;
    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03};
    q.enqueue_for_alpn("ctrl/1", data, 1);
    q.enqueue_for_alpn("pp-hidden/1", data, 2);
    q.enqueue_for_alpn("pp-video/1", data, 3);

    CHECK_EQ(q.size_of(TrafficPriority::Critical), 1u);
    CHECK_EQ(q.size_of(TrafficPriority::High), 1u);
    CHECK_EQ(q.size_of(TrafficPriority::Low), 1u);

    auto first = q.dequeue();
    CHECK(first.has_value());
    CHECK_EQ(first->priority, TrafficPriority::Critical);  // ctrl/1 先出
    CHECK_EQ(first->item_id, 1u);
}

// 28. peek 不移除
static void test_wfq_peek() {
    std::printf("[test] peek...\n");
    WeightedFairQueue q;
    q.enqueue(make_item(TrafficPriority::High, 10));
    q.enqueue(make_item(TrafficPriority::Low, 20));

    auto peeked = q.peek();
    CHECK(peeked.has_value());
    // peek 不移除，size 不变
    CHECK_EQ(q.size(), 2u);

    // 实际出队（High 先出）
    auto item = q.dequeue();
    CHECK(item.has_value());
    CHECK_EQ(item->priority, TrafficPriority::High);
}

// 29. size / size_of / empty
static void test_wfq_size_operations() {
    std::printf("[test] size / size_of / empty...\n");
    WeightedFairQueue q;
    CHECK(q.empty());
    CHECK_EQ(q.size(), 0u);

    q.enqueue(make_item(TrafficPriority::Critical, 1));
    q.enqueue(make_item(TrafficPriority::Critical, 2));
    q.enqueue(make_item(TrafficPriority::High, 3));
    q.enqueue(make_item(TrafficPriority::Low, 4));

    CHECK(!q.empty());
    CHECK_EQ(q.size(), 4u);
    CHECK_EQ(q.size_of(TrafficPriority::Critical), 2u);
    CHECK_EQ(q.size_of(TrafficPriority::High), 1u);
    CHECK_EQ(q.size_of(TrafficPriority::Medium), 0u);
    CHECK_EQ(q.size_of(TrafficPriority::Low), 1u);
}

// 30. clear
static void test_wfq_clear() {
    std::printf("[test] clear...\n");
    WeightedFairQueue q;
    q.enqueue(make_item(TrafficPriority::Critical, 1));
    q.enqueue(make_item(TrafficPriority::High, 2));
    q.enqueue(make_item(TrafficPriority::Low, 3));

    CHECK_EQ(q.size(), 3u);
    q.clear();
    CHECK(q.empty());
    CHECK_EQ(q.size(), 0u);

    // clear 后仍可继续入队
    q.enqueue(make_item(TrafficPriority::Medium, 4));
    CHECK_EQ(q.size(), 1u);
    auto item = q.dequeue();
    CHECK(item.has_value());
    CHECK_EQ(item->item_id, 4u);
}

// 31. stats 累计
static void test_wfq_stats() {
    std::printf("[test] stats accumulation...\n");
    WeightedFairQueue q;
    q.enqueue(make_item(TrafficPriority::Critical, 1, 100));
    q.enqueue(make_item(TrafficPriority::Critical, 2, 200));
    q.enqueue(make_item(TrafficPriority::Low, 3, 50));

    auto s_before = q.stats();
    CHECK_EQ(s_before.total_enqueued, 3u);
    CHECK_EQ(s_before.total_bytes_enqueued, 350u);
    CHECK_EQ(s_before.per_priority[0].enqueued, 2u);  // Critical
    CHECK_EQ(s_before.per_priority[0].bytes_enqueued, 300u);
    CHECK_EQ(s_before.per_priority[3].enqueued, 1u);  // Low
    CHECK_EQ(s_before.per_priority[3].bytes_enqueued, 50u);

    // 出队 2 个
    q.dequeue();
    q.dequeue();

    auto s_after = q.stats();
    CHECK_EQ(s_after.total_dequeued, 2u);
    CHECK_EQ(s_after.total_bytes_dequeued, 300u);  // 100+200 (Critical 先出)
    CHECK_EQ(s_after.per_priority[0].dequeued, 2u);
    CHECK_EQ(s_after.per_priority[0].bytes_dequeued, 300u);
}

// 32. set_config 运行时调整
static void test_wfq_set_config() {
    std::printf("[test] set_config runtime adjust...\n");
    WeightedFairQueue q;
    q.enqueue(make_item(TrafficPriority::Low, 1));

    auto new_cfg = PriorityConfig::balanced();
    q.set_config(new_cfg);
    auto current = q.config();
    CHECK(current == new_cfg);

    // 队列内容保留
    CHECK_EQ(q.size(), 1u);
    auto item = q.dequeue();
    CHECK(item.has_value());
    CHECK_EQ(item->item_id, 1u);
}

// 33. reset_deficit
static void test_wfq_reset_deficit() {
    std::printf("[test] reset_deficit...\n");
    WeightedFairQueue q;
    // 入队并出队一些，累积 deficit
    q.enqueue(make_item(TrafficPriority::Critical, 1));
    q.enqueue(make_item(TrafficPriority::Critical, 2));
    q.dequeue();

    // reset_deficit 不应影响队列内容
    q.reset_deficit();
    CHECK_EQ(q.size(), 1u);
    auto item = q.dequeue();
    CHECK(item.has_value());
    CHECK_EQ(item->item_id, 2u);
}

// 34. dequeue 空队列返回 nullopt
static void test_wfq_dequeue_empty() {
    std::printf("[test] dequeue empty queue...\n");
    WeightedFairQueue q;
    auto item = q.dequeue();
    CHECK(!item.has_value());

    // 入队后清空，再出队
    q.enqueue(make_item(TrafficPriority::High, 1));
    q.clear();
    auto item2 = q.dequeue();
    CHECK(!item2.has_value());
}

// 35. e2e 混合优先级场景
static void test_wfq_e2e_mixed() {
    std::printf("[test] e2e mixed priority scenario...\n");
    WeightedFairQueue q(PriorityConfig::llm_inference_priority());

    // 模拟推理链路：控制指令 + hidden_state + 视频
    q.enqueue_for_alpn("ctrl/1",       {0x01}, 1001);  // Critical
    q.enqueue_for_alpn("pp-hidden/1",  {0x02}, 1002);  // High
    q.enqueue_for_alpn("pp-video/1",   {0x03}, 1003);  // Low
    q.enqueue_for_alpn("ctrl/1",       {0x04}, 1004);  // Critical
    q.enqueue_for_alpn("pp-hidden/1",  {0x05}, 1005);  // High

    // 出队顺序：Critical 优先
    auto first = q.dequeue();
    CHECK(first.has_value());
    CHECK_EQ(first->priority, TrafficPriority::Critical);

    auto second = q.dequeue();
    CHECK(second.has_value());
    CHECK_EQ(second->priority, TrafficPriority::Critical);

    // High 应在 Low 之前
    auto third = q.dequeue();
    CHECK(third.has_value());
    CHECK_EQ(third->priority, TrafficPriority::High);

    // 剩余 High 和 Low
    auto fourth = q.dequeue();
    CHECK(fourth.has_value());
    // High 优先于 Low
    CHECK_EQ(fourth->priority, TrafficPriority::High);

    auto fifth = q.dequeue();
    CHECK(fifth.has_value());
    CHECK_EQ(fifth->priority, TrafficPriority::Low);

    CHECK(q.empty());

    // 验证统计
    auto s = q.stats();
    CHECK_EQ(s.total_enqueued, 5u);
    CHECK_EQ(s.total_dequeued, 5u);
}

// 36. 防饿死统计触发
static void test_wfq_starvation_stats() {
    std::printf("[test] starvation avoided stats...\n");
    WeightedFairQueue q;
    // Critical 和 Low 同时入队，WFQ 会让 Low 在 Critical 高压下仍能出队
    for (int i = 0; i < 20; ++i) {
        q.enqueue(make_item(TrafficPriority::Critical, static_cast<std::uint64_t>(i)));
        q.enqueue(make_item(TrafficPriority::Low, static_cast<std::uint64_t>(1000 + i)));
    }
    // 全部出队
    int low_count = 0;
    while (auto item = q.dequeue()) {
        if (item->priority == TrafficPriority::Low) ++low_count;
    }
    CHECK(low_count > 0);

    auto s = q.stats();
    // 防饿死统计应该 > 0（Low 在 Critical 队列非空时出队）
    CHECK(s.starvation_avoided_count > 0);
}

// ========== 主函数 ==========

int main() {
    std::printf("=== test_traffic_priority ===\n\n");

    test_priority_enum();
    test_priority_count();
    test_priority_for_alpn();
    test_priority_for_unknown_alpn();
    test_config_defaults();
    test_factory_default_weights();
    test_factory_strict_priority();
    test_factory_balanced();
    test_factory_llm_priority();
    test_weight_of();
    test_set_weight();
    test_encode_layout();
    test_encode_decode_roundtrip();
    test_decode_short_data();
    test_decode_bad_version();
    test_decode_weight_out_of_range();
    test_config_to_string();
    test_wfq_default_construct();
    test_wfq_single_item();
    test_wfq_same_priority_fifo();
    test_wfq_priority_preemption();
    test_wfq_starvation_avoidance();
    test_wfq_strict_priority_starvation();
    test_wfq_enqueue_for_alpn();
    test_wfq_peek();
    test_wfq_size_operations();
    test_wfq_clear();
    test_wfq_stats();
    test_wfq_set_config();
    test_wfq_reset_deficit();
    test_wfq_dequeue_empty();
    test_wfq_e2e_mixed();
    test_wfq_starvation_stats();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
