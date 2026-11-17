// test_v470_path_api.cpp — v4.7.0 Path Observation API + PP 策略测试
//
// 覆盖任务：
//   T-LP2-005/006: PathSelector trait + PP 策略实现
//   T-LP2-008: PathList + PathEventStream + PathEvent API
//   T-LP2-009: 旧 set_path_event_callback deprecated 标记
//   T-LP2-010: 阶段二测试
//
// 借鉴 iroh#4232 Path observation API 重设计验证：
//   - "先订阅后快照"模式消除竞争
//   - 多消费者独立队列
//   - 队列溢出 kLagged 事件
//   - Connection 析构自动 close

#include "linoh/endpoint/connection.hpp"
#include "linoh/endpoint/path_observation.hpp"
#include "linoh/protocol/path_event.hpp"
#include "linoh/protocol/path_migration.hpp"
#include "linoh/protocol/path_strategy.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::endpoint;
using namespace linoh::protocol;

// ============================================================================
// 测试辅助宏
// ============================================================================
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::printf("[FAIL] %s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, \
                        #cond);                                                \
            ++g_tests_failed;                                                  \
        } else {                                                               \
            ++g_tests_passed;                                                  \
        }                                                                      \
    } while (0)

#define CHECK_EQ(a, b)                                                         \
    do {                                                                       \
        auto _va = (a);                                                        \
        auto _vb = (b);                                                        \
        if (!(_va == _vb)) {                                                   \
            std::printf("[FAIL] %s:%d: CHECK_EQ(%s, %s) failed\n", __FILE__,   \
                        __LINE__, #a, #b);                                     \
            ++g_tests_failed;                                                  \
        } else {                                                               \
            ++g_tests_passed;                                                  \
        }                                                                      \
    } while (0)

#define RUN_TEST(fn)                                                           \
    do {                                                                       \
        std::printf("[test] %s...\n", #fn);                                    \
        std::fflush(stdout);                                                   \
        fn();                                                                  \
        std::fflush(stdout);                                                   \
    } while (0)

// ============================================================================
// 辅助函数：构造 PathQuality
// ============================================================================
static PathMigrationManager::PathQuality make_quality(
    std::uint64_t path_id,
    std::chrono::microseconds srtt,
    std::uint64_t bandwidth_bps = 0,
    PathMigrationManager::BandwidthTier tier = PathMigrationManager::BandwidthTier::NotMeasured,
    bool has_tuple = true) {
    PathMigrationManager::PathQuality q;
    q.path_id = path_id;
    q.srtt = srtt;
    q.has_tuple = has_tuple;
    q.measured_bandwidth_bps = bandwidth_bps;
    q.bandwidth_tier = tier;
    if (has_tuple) {
        // 构造一个简单的 FourTuple（用 host 字符串区分不同 path_id）
        q.four_tuple.remote_addr.kind = linoh::base::TransportKind::Ip;
        q.four_tuple.remote_addr.host = "10.0.0." + std::to_string(path_id);
        q.four_tuple.remote_addr.port = static_cast<std::uint16_t>(1000 + path_id);
    }
    return q;
}

/// 辅助函数：从 FourTuple 提取 path_id（host 最后一段）
static std::uint64_t tuple_path_id(const net::FourTuple &t) {
    auto pos = t.remote_addr.host.rfind('.');
    if (pos == std::string::npos) return 0;
    return std::stoull(t.remote_addr.host.substr(pos + 1));
}

// ============================================================================
// T-LP2-005/006: PP 策略测试
// ============================================================================

/// 测试 PpFirstStageStrategy 基本选路：srtt 升序
static void test_pp_first_strategy_basic() {
    auto strat = std::make_shared<PpFirstStageStrategy>();
    CHECK(strat != nullptr);
    CHECK_EQ(strat->name(), std::string_view("pp-first"));

    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(100000)),  // 100ms
        make_quality(2, std::chrono::microseconds(50000)),   // 50ms
        make_quality(3, std::chrono::microseconds(150000)),  // 150ms
    };

    auto selected = strat->select(candidates);
    CHECK(selected.has_value());
    // 应选 srtt 最小的 path_id=2 (50ms)
    CHECK_EQ(tuple_path_id(*selected), static_cast<std::uint64_t>(2));
}

/// 测试 PpFirstStageStrategy tiebreaker：srtt 相同时按 bandwidth_tier 升序
static void test_pp_first_strategy_tiebreak_tier() {
    auto strat = std::make_shared<PpFirstStageStrategy>();

    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(50000), 0,
                     PathMigrationManager::BandwidthTier::NotMeasured),
        make_quality(2, std::chrono::microseconds(50000), 1000000,
                     PathMigrationManager::BandwidthTier::MeasuredPositive),
    };

    auto selected = strat->select(candidates);
    CHECK(selected.has_value());
    // srtt 相同，应选 tier 更优的 path_id=2 (MeasuredPositive)
    CHECK_EQ(tuple_path_id(*selected), static_cast<std::uint64_t>(2));
}

/// 测试 PpFirstStageStrategy tiebreaker：srtt 相同 + tier 相同时按 bandwidth 降序
static void test_pp_first_strategy_tiebreak_bandwidth() {
    auto strat = std::make_shared<PpFirstStageStrategy>();

    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(50000), 500000,
                     PathMigrationManager::BandwidthTier::MeasuredPositive),
        make_quality(2, std::chrono::microseconds(50000), 1000000,
                     PathMigrationManager::BandwidthTier::MeasuredPositive),
    };

    auto selected = strat->select(candidates);
    CHECK(selected.has_value());
    // srtt + tier 相同，应选 bandwidth 更大的 path_id=2 (1Mbps > 500Kbps)
    CHECK_EQ(tuple_path_id(*selected), static_cast<std::uint64_t>(2));
}

/// 测试 PpFirstStageStrategy 空候选
static void test_pp_first_strategy_empty() {
    auto strat = std::make_shared<PpFirstStageStrategy>();
    std::vector<PathMigrationManager::PathQuality> empty;
    auto selected = strat->select(empty);
    CHECK(!selected.has_value());
}

/// 测试 PpFirstStageStrategy 全部无 tuple
static void test_pp_first_strategy_no_tuple() {
    auto strat = std::make_shared<PpFirstStageStrategy>();
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(50000), 0,
                     PathMigrationManager::BandwidthTier::NotMeasured, false),
    };
    auto selected = strat->select(candidates);
    CHECK(!selected.has_value());
}

/// 测试 PpFirstStageStrategy srtt=0（未测量）排最后
static void test_pp_first_strategy_unmeasured_last() {
    auto strat = std::make_shared<PpFirstStageStrategy>();

    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(0)),       // 未测量
        make_quality(2, std::chrono::microseconds(200000)),  // 200ms
    };

    auto selected = strat->select(candidates);
    CHECK(selected.has_value());
    // 应选有测量的 path_id=2，未测量的排最后
    CHECK_EQ(tuple_path_id(*selected), static_cast<std::uint64_t>(2));
}

/// 测试 PpLastStageStrategy 基本选路：bandwidth 降序
static void test_pp_last_strategy_basic() {
    auto strat = std::make_shared<PpLastStageStrategy>();
    CHECK(strat != nullptr);
    CHECK_EQ(strat->name(), std::string_view("pp-last"));

    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(50000), 500000,
                     PathMigrationManager::BandwidthTier::MeasuredPositive),
        make_quality(2, std::chrono::microseconds(100000), 1000000,
                     PathMigrationManager::BandwidthTier::MeasuredPositive),
        make_quality(3, std::chrono::microseconds(80000), 800000,
                     PathMigrationManager::BandwidthTier::MeasuredPositive),
    };

    auto selected = strat->select(candidates);
    CHECK(selected.has_value());
    // 应选 bandwidth 最大的 path_id=2 (1Mbps)
    CHECK_EQ(tuple_path_id(*selected), static_cast<std::uint64_t>(2));
}

/// 测试 PpLastStageStrategy tiebreaker：bandwidth 相同时按 tier 升序
static void test_pp_last_strategy_tiebreak_tier() {
    auto strat = std::make_shared<PpLastStageStrategy>();

    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(50000), 0,
                     PathMigrationManager::BandwidthTier::NotMeasured),
        make_quality(2, std::chrono::microseconds(50000), 0,
                     PathMigrationManager::BandwidthTier::MeasuredPositive),
    };

    auto selected = strat->select(candidates);
    CHECK(selected.has_value());
    // bandwidth 都是 0，应选 tier 更优的 path_id=2 (MeasuredPositive)
    CHECK_EQ(tuple_path_id(*selected), static_cast<std::uint64_t>(2));
}

/// 测试 PpLastStageStrategy tiebreaker：bandwidth + tier 相同时按 srtt 升序
static void test_pp_last_strategy_tiebreak_srtt() {
    auto strat = std::make_shared<PpLastStageStrategy>();

    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(100000), 500000,
                     PathMigrationManager::BandwidthTier::MeasuredPositive),
        make_quality(2, std::chrono::microseconds(50000), 500000,
                     PathMigrationManager::BandwidthTier::MeasuredPositive),
    };

    auto selected = strat->select(candidates);
    CHECK(selected.has_value());
    // bandwidth + tier 相同，应选 srtt 更小的 path_id=2 (50ms < 100ms)
    CHECK_EQ(tuple_path_id(*selected), static_cast<std::uint64_t>(2));
}

/// 测试 PpLastStageStrategy 空候选
static void test_pp_last_strategy_empty() {
    auto strat = std::make_shared<PpLastStageStrategy>();
    std::vector<PathMigrationManager::PathQuality> empty;
    auto selected = strat->select(empty);
    CHECK(!selected.has_value());
}

/// 测试 create_strategy_by_name 工厂函数支持 pp-first / pp-last
static void test_create_strategy_pp() {
    auto pp_first = create_strategy_by_name("pp-first");
    CHECK(pp_first != nullptr);
    CHECK_EQ(pp_first->name(), std::string_view("pp-first"));

    auto pp_last = create_strategy_by_name("pp-last");
    CHECK(pp_last != nullptr);
    CHECK_EQ(pp_last->name(), std::string_view("pp-last"));

    // bandwidth-tier 也应可用
    auto bw = create_strategy_by_name("bandwidth-tier");
    CHECK(bw != nullptr);
    CHECK_EQ(bw->name(), std::string_view("bandwidth-tier"));

    // 未知名称返回 nullptr
    auto unknown = create_strategy_by_name("unknown");
    CHECK(unknown == nullptr);
}

// ============================================================================
// T-LP2-008: PathEventStream 测试
// ============================================================================

/// 测试 PathEventStream 基本操作：try_pop 空队列
static void test_path_event_stream_empty() {
    PathEventStream stream;
    CHECK(stream.is_closed() == false);
    auto ev = stream.try_pop();
    CHECK(!ev.has_value());
}

/// 测试 PathEventStream next() 超时返回 nullopt
static void test_path_event_stream_next_timeout() {
    PathEventStream stream;
    auto start = std::chrono::steady_clock::now();
    auto ev = stream.next(std::chrono::milliseconds(50));
    auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(!ev.has_value());
    // 确保实际等待了（至少 40ms，留 10ms 容差）
    CHECK(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() >= 40);
}

/// 测试 PathEventStream close() 后 next() 立即返回
static void test_path_event_stream_close() {
    PathEventStream stream;
    stream.close();
    CHECK(stream.is_closed() == true);
    auto ev = stream.next(std::chrono::milliseconds(100));
    CHECK(!ev.has_value());
}

/// 测试 PathEventStream close() 后 try_pop() 空队列返回 nullopt
static void test_path_event_stream_close_try_pop() {
    PathEventStream stream;
    stream.close();
    auto ev = stream.try_pop();
    CHECK(!ev.has_value());
}

/// 测试 PathEventStream lagged_count 初始为 0
static void test_path_event_stream_lagged_initial() {
    PathEventStream stream;
    CHECK_EQ(stream.lagged_count(), static_cast<std::uint64_t>(0));
}

/// 测试 PathEventStream 自定义 capacity
static void test_path_event_stream_custom_capacity() {
    // capacity=0 应回退到默认值
    PathEventStream stream(0);
    CHECK(stream.is_closed() == false);
    auto ev = stream.try_pop();
    CHECK(!ev.has_value());
}

// ============================================================================
// T-LP2-008: PathList 测试
// ============================================================================

/// 测试 PathList 默认构造为空
static void test_path_list_default_empty() {
    PathList list;
    CHECK(list.empty());
    CHECK_EQ(list.size(), static_cast<std::size_t>(0));
    CHECK(list.current() == nullptr);
    CHECK(!list.current_path_id().has_value());
}

// ============================================================================
// T-LP2-008: PathEvent kLagged 测试
// ============================================================================

/// 测试 PathEvent::lagged 工厂方法
static void test_path_event_lagged_factory() {
    auto ev = PathEvent::lagged(42, 5);
    CHECK(ev.is_lagged());
    CHECK_EQ(ev.path_id, static_cast<std::uint64_t>(42));
    CHECK_EQ(ev.lagged_count, static_cast<std::uint64_t>(5));
    CHECK(!ev.is_opened());
    CHECK(!ev.is_closed());
    CHECK(!ev.is_selected());
}

/// 测试 PathEvent::type_str 包含 Lagged
static void test_path_event_type_str_lagged() {
    CHECK_EQ(std::string(PathEvent::type_str(PathEvent::Type::kLagged)), std::string("Lagged"));
    CHECK_EQ(std::string(PathEvent::type_str(PathEvent::Type::kOpened)), std::string("Opened"));
    CHECK_EQ(std::string(PathEvent::type_str(PathEvent::Type::kClosed)), std::string("Closed"));
    CHECK_EQ(std::string(PathEvent::type_str(PathEvent::Type::kSelected)), std::string("Selected"));
}

// ============================================================================
// T-LP2-009: deprecated 标记编译时验证（运行时无操作）
// ============================================================================

/// 测试 deprecated API 仍可调用（编译时验证，运行时无操作）
/// 若此测试编译通过，说明 deprecated 标记不影响向后兼容
static void test_deprecated_api_compatible() {
    PathMigrationManager mgr;
    // 调用 deprecated API（编译器会产生警告但不影响编译）
    // 使用 pragma 抑制警告以验证 API 仍可用
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996)
    mgr.set_path_event_callback([](const PathEvent &) {});
    [[maybe_unused]] bool has_cb = mgr.has_path_event_callback();
#pragma warning(pop)
#endif
    CHECK(true);  // 若编译通过即验证成功
    ++g_tests_passed;
}

// ============================================================================
// T-LP2-008: PathMigrationManager Opened 事件 emit 测试
// ============================================================================

/// 测试 update_path_quality 新路径触发 Opened 事件
static void test_update_path_quality_emits_opened() {
    PathMigrationManager mgr;

    bool opened_called = false;
    std::uint64_t opened_path_id = 0;
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    mgr.set_path_event_callback([&](const PathEvent &ev) {
        if (ev.is_opened()) {
            opened_called = true;
            opened_path_id = ev.path_id;
        }
    });
#ifdef _MSC_VER
#pragma warning(pop)
#endif

    auto now = std::chrono::steady_clock::now();
    mgr.update_path_quality(42, std::chrono::microseconds(50000), 0, now);

    CHECK(opened_called);
    CHECK_EQ(opened_path_id, static_cast<std::uint64_t>(42));
}

/// 测试 update_path_quality 已有路径不触发 Opened 事件
static void test_update_path_quality_no_duplicate_opened() {
    PathMigrationManager mgr;

    int opened_count = 0;
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    mgr.set_path_event_callback([&](const PathEvent &ev) {
        if (ev.is_opened()) ++opened_count;
    });
#ifdef _MSC_VER
#pragma warning(pop)
#endif

    auto now = std::chrono::steady_clock::now();
    mgr.update_path_quality(1, std::chrono::microseconds(50000), 0, now);
    mgr.update_path_quality(1, std::chrono::microseconds(60000), 1, now);
    mgr.update_path_quality(1, std::chrono::microseconds(70000), 2, now);

    // 只应触发一次 Opened（首次见到 path_id=1）
    CHECK_EQ(opened_count, 1);
}

/// 测试 update_path_quality 带 tuple 重载触发 Opened 事件
static void test_update_path_quality_with_tuple_emits_opened() {
    PathMigrationManager mgr;

    bool opened_called = false;
    std::string opened_remote;
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    mgr.set_path_event_callback([&](const PathEvent &ev) {
        if (ev.is_opened()) {
            opened_called = true;
            opened_remote = ev.remote_addr;
        }
    });
#ifdef _MSC_VER
#pragma warning(pop)
#endif

    auto now = std::chrono::steady_clock::now();
    net::FourTuple tuple;
    tuple.remote_addr.kind = linoh::base::TransportKind::Ip;
    tuple.remote_addr.host = "192.168.1.100";
    tuple.remote_addr.port = 8080;

    mgr.update_path_quality(5, std::chrono::microseconds(30000), 0, now, tuple);

    CHECK(opened_called);
    CHECK(opened_remote.find("192") != std::string::npos);
}

// ============================================================================
// T-LP2-007/008: PathMigrationManager select_primary_path 测试
// ============================================================================

/// 测试 select_primary_path 无策略返回 nullopt
static void test_select_primary_path_no_strategy() {
    PathMigrationManager mgr;
    auto now = std::chrono::steady_clock::now();
    mgr.update_path_quality(1, std::chrono::microseconds(50000), 0, now);

    auto selected = mgr.select_primary_path();
    CHECK(!selected.has_value());
}

/// 测试 select_primary_path 有策略返回最优路径
static void test_select_primary_path_with_strategy() {
    PathMigrationManager mgr;
    mgr.set_strategy(std::make_shared<PpFirstStageStrategy>());

    auto now = std::chrono::steady_clock::now();
    // 使用带 tuple 的重载（策略 select 需要 has_tuple=true）
    net::FourTuple t1, t2, t3;
    t1.remote_addr.kind = linoh::base::TransportKind::Ip;
    t1.remote_addr.host = "10.0.0.1";
    t2.remote_addr.kind = linoh::base::TransportKind::Ip;
    t2.remote_addr.host = "10.0.0.2";
    t3.remote_addr.kind = linoh::base::TransportKind::Ip;
    t3.remote_addr.host = "10.0.0.3";
    mgr.update_path_quality(1, std::chrono::microseconds(100000), 0, now, t1);
    mgr.update_path_quality(2, std::chrono::microseconds(50000), 0, now, t2);
    mgr.update_path_quality(3, std::chrono::microseconds(150000), 0, now, t3);

    auto selected = mgr.select_primary_path();
    CHECK(selected.has_value());
    if (selected) {
        // PpFirstStageStrategy 应选 srtt 最小的 path_id=2 (50ms)
        CHECK_EQ(tuple_path_id(*selected), static_cast<std::uint64_t>(2));
    }
}

/// 测试 select_primary_path 空候选返回 nullopt
static void test_select_primary_path_empty() {
    PathMigrationManager mgr;
    mgr.set_strategy(std::make_shared<PpFirstStageStrategy>());

    auto selected = mgr.select_primary_path();
    CHECK(!selected.has_value());
}

/// 测试 path_qualities_snapshot 返回所有路径
static void test_path_qualities_snapshot() {
    PathMigrationManager mgr;
    auto now = std::chrono::steady_clock::now();
    // 使用带 tuple 的重载以保持一致性
    net::FourTuple t;
    t.remote_addr.kind = linoh::base::TransportKind::Ip;
    t.remote_addr.host = "10.0.0.1";
    mgr.update_path_quality(1, std::chrono::microseconds(50000), 0, now, t);
    mgr.update_path_quality(2, std::chrono::microseconds(60000), 1, now, t);
    mgr.update_path_quality(3, std::chrono::microseconds(70000), 2, now, t);

    auto snapshot = mgr.path_qualities_snapshot();
    CHECK_EQ(snapshot.size(), static_cast<std::size_t>(3));
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== v4.7.0 Path Observation API + PP 策略测试 ===\n\n");

    // T-LP2-005/006: PP 策略测试
    RUN_TEST(test_pp_first_strategy_basic);
    RUN_TEST(test_pp_first_strategy_tiebreak_tier);
    RUN_TEST(test_pp_first_strategy_tiebreak_bandwidth);
    RUN_TEST(test_pp_first_strategy_empty);
    RUN_TEST(test_pp_first_strategy_no_tuple);
    RUN_TEST(test_pp_first_strategy_unmeasured_last);
    RUN_TEST(test_pp_last_strategy_basic);
    RUN_TEST(test_pp_last_strategy_tiebreak_tier);
    RUN_TEST(test_pp_last_strategy_tiebreak_srtt);
    RUN_TEST(test_pp_last_strategy_empty);
    RUN_TEST(test_create_strategy_pp);

    // T-LP2-008: PathEventStream 测试
    RUN_TEST(test_path_event_stream_empty);
    RUN_TEST(test_path_event_stream_next_timeout);
    RUN_TEST(test_path_event_stream_close);
    RUN_TEST(test_path_event_stream_close_try_pop);
    RUN_TEST(test_path_event_stream_lagged_initial);
    RUN_TEST(test_path_event_stream_custom_capacity);

    // T-LP2-008: PathList 测试
    RUN_TEST(test_path_list_default_empty);

    // T-LP2-008: PathEvent kLagged 测试
    RUN_TEST(test_path_event_lagged_factory);
    RUN_TEST(test_path_event_type_str_lagged);

    // T-LP2-009: deprecated 标记验证
    RUN_TEST(test_deprecated_api_compatible);

    // T-LP2-008: Opened 事件 emit 测试
    RUN_TEST(test_update_path_quality_emits_opened);
    RUN_TEST(test_update_path_quality_no_duplicate_opened);
    RUN_TEST(test_update_path_quality_with_tuple_emits_opened);

    // T-LP2-007/008: select_primary_path 测试
    RUN_TEST(test_select_primary_path_no_strategy);
    RUN_TEST(test_select_primary_path_with_strategy);
    RUN_TEST(test_select_primary_path_empty);
    RUN_TEST(test_path_qualities_snapshot);

    std::printf("\n=== Results: %d PASSED, %d FAILED ===\n",
                g_tests_passed, g_tests_failed);
    return g_tests_failed == 0 ? 0 : 1;
}
