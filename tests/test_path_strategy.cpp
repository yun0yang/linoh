// test_path_strategy.cpp — 可配置 PathSelectionStrategy 测试（P4-B-3）
//
// 覆盖：
//   - RttBasedStrategy 选 RTT 最小
//   - PreferDirectStrategy 优先直连
//   - PreferRelayStrategy 优先 Relay
//   - 自定义策略注入
//   - create_strategy_by_name 工厂
//   - 空候选、全未测量、混合类型等边界场景

#include "linoh/protocol/path_strategy.hpp"
#include "linoh/protocol/path_migration.hpp"
#include "linoh/base/endpoint_addr.hpp"
#include "linoh/net/path.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <memory>
#include <thread>

using namespace linoh;
using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 工具：构造 PathQuality
// ============================================================================
static PathMigrationManager::PathQuality make_quality(
    std::uint64_t path_id,
    std::chrono::microseconds srtt,
    const std::string &local_ip,
    std::uint16_t local_port,
    const std::string &remote_ip,
    std::uint16_t remote_port,
    base::TransportKind kind = base::TransportKind::Ip) {

    PathMigrationManager::PathQuality q{};
    q.path_id = path_id;
    q.srtt = srtt;
    q.has_tuple = true;

    q.four_tuple.local_addr.kind = kind;
    q.four_tuple.local_addr.host = local_ip;
    q.four_tuple.local_addr.port = local_port;

    q.four_tuple.remote_addr.kind = kind;
    q.four_tuple.remote_addr.host = remote_ip;
    q.four_tuple.remote_addr.port = remote_port;

    return q;
}

// ============================================================================
// 测试 1: RttBasedStrategy - 空候选返回 nullopt
// ============================================================================
static void test_rtt_empty_candidates() {
    std::printf("[test] RttBasedStrategy empty candidates...\n");

    RttBasedStrategy s;
    std::vector<PathMigrationManager::PathQuality> candidates;
    auto result = s.select(candidates);
    CHECK(!result.has_value());
    CHECK(s.name() == "rtt");
}

// ============================================================================
// 测试 2: RttBasedStrategy - 选 RTT 最小
// ============================================================================
static void test_rtt_select_min() {
    std::printf("[test] RttBasedStrategy select minimum RTT...\n");

    RttBasedStrategy s;
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(50000), "10.0.0.1", 1000, "1.1.1.1", 2000),
        make_quality(2, std::chrono::microseconds(20000), "10.0.0.1", 1001, "1.1.1.1", 2000),
        make_quality(3, std::chrono::microseconds(80000), "10.0.0.1", 1002, "1.1.1.1", 2000),
    };

    auto result = s.select(candidates);
    CHECK(result.has_value());
    CHECK(result->remote_addr.host == "1.1.1.1");
    CHECK(result->local_addr.port == 1001);  // RTT 最小的路径
}

// ============================================================================
// 测试 3: RttBasedStrategy - 全部 srtt=0 返回 nullopt
// ============================================================================
static void test_rtt_all_unmeasured() {
    std::printf("[test] RttBasedStrategy all unmeasured...\n");

    RttBasedStrategy s;
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(0), "10.0.0.1", 1000, "1.1.1.1", 2000),
        make_quality(2, std::chrono::microseconds(0), "10.0.0.1", 1001, "1.1.1.1", 2000),
    };

    auto result = s.select(candidates);
    CHECK(!result.has_value());  // 全未测量，保守不选
}

// ============================================================================
// 测试 4: RttBasedStrategy - 部分未测量，选已测量的最小
// ============================================================================
static void test_rtt_partial_unmeasured() {
    std::printf("[test] RttBasedStrategy partial unmeasured...\n");

    RttBasedStrategy s;
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(0), "10.0.0.1", 1000, "1.1.1.1", 2000),
        make_quality(2, std::chrono::microseconds(30000), "10.0.0.1", 1001, "1.1.1.1", 2000),
        make_quality(3, std::chrono::microseconds(0), "10.0.0.1", 1002, "1.1.1.1", 2000),
    };

    auto result = s.select(candidates);
    CHECK(result.has_value());
    CHECK(result->local_addr.port == 1001);  // 唯一已测量的
}

// ============================================================================
// 测试 5: RttBasedStrategy - has_tuple=false 的候选被跳过
// ============================================================================
static void test_rtt_skip_no_tuple() {
    std::printf("[test] RttBasedStrategy skip no-tuple...\n");

    RttBasedStrategy s;
    PathMigrationManager::PathQuality q1{};
    q1.path_id = 1;
    q1.srtt = std::chrono::microseconds(10000);
    q1.has_tuple = false;  // 没有 tuple

    auto q2 = make_quality(2, std::chrono::microseconds(20000),
                           "10.0.0.1", 1001, "1.1.1.1", 2000);

    std::vector<PathMigrationManager::PathQuality> candidates = {q1, q2};

    auto result = s.select(candidates);
    CHECK(result.has_value());
    CHECK(result->local_addr.port == 1001);
}

// ============================================================================
// 测试 6: PreferDirectStrategy - 空候选
// ============================================================================
static void test_prefer_direct_empty() {
    std::printf("[test] PreferDirectStrategy empty...\n");

    PreferDirectStrategy s;
    std::vector<PathMigrationManager::PathQuality> candidates;
    auto result = s.select(candidates);
    CHECK(!result.has_value());
    CHECK(s.name() == "prefer-direct");
}

// ============================================================================
// 测试 7: PreferDirectStrategy - 优先直连
// ============================================================================
static void test_prefer_direct_selects_direct() {
    std::printf("[test] PreferDirectStrategy selects direct...\n");

    PreferDirectStrategy s;
    // Relay RTT 更小，但应选直连
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(10000), "10.0.0.1", 1000, "relay.example.com", 9000, base::TransportKind::Relay),
        make_quality(2, std::chrono::microseconds(50000), "10.0.0.1", 1001, "1.1.1.1", 2000, base::TransportKind::Ip),
    };

    auto result = s.select(candidates);
    CHECK(result.has_value());
    CHECK(result->remote_addr.kind == base::TransportKind::Ip);
    CHECK(result->remote_addr.host == "1.1.1.1");
}

// ============================================================================
// 测试 8: PreferDirectStrategy - 直连全失败回退到 Relay
// ============================================================================
static void test_prefer_direct_fallback_to_relay() {
    std::printf("[test] PreferDirectStrategy fallback to relay...\n");

    PreferDirectStrategy s;
    // 直连 srtt=0（未测量），Relay 有测量
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(0), "10.0.0.1", 1000, "1.1.1.1", 2000, base::TransportKind::Ip),
        make_quality(2, std::chrono::microseconds(30000), "10.0.0.1", 1001, "relay.example.com", 9000, base::TransportKind::Relay),
    };

    auto result = s.select(candidates);
    CHECK(result.has_value());
    CHECK(result->remote_addr.kind == base::TransportKind::Relay);
    CHECK(result->remote_addr.host == "relay.example.com");
}

// ============================================================================
// 测试 9: PreferRelayStrategy - 优先 Relay
// ============================================================================
static void test_prefer_relay_selects_relay() {
    std::printf("[test] PreferRelayStrategy selects relay...\n");

    PreferRelayStrategy s;
    // 直连 RTT 更小，但应选 Relay
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(10000), "10.0.0.1", 1000, "1.1.1.1", 2000, base::TransportKind::Ip),
        make_quality(2, std::chrono::microseconds(50000), "10.0.0.1", 1001, "relay.example.com", 9000, base::TransportKind::Relay),
    };

    auto result = s.select(candidates);
    CHECK(result.has_value());
    CHECK(result->remote_addr.kind == base::TransportKind::Relay);
    CHECK(result->remote_addr.host == "relay.example.com");
    CHECK(s.name() == "prefer-relay");
}

// ============================================================================
// 测试 10: PreferRelayStrategy - Relay 全失败回退到直连
// ============================================================================
static void test_prefer_relay_fallback_to_direct() {
    std::printf("[test] PreferRelayStrategy fallback to direct...\n");

    PreferRelayStrategy s;
    // Relay srtt=0（未测量），直连有测量
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(20000), "10.0.0.1", 1000, "1.1.1.1", 2000, base::TransportKind::Ip),
        make_quality(2, std::chrono::microseconds(0), "10.0.0.1", 1001, "relay.example.com", 9000, base::TransportKind::Relay),
    };

    auto result = s.select(candidates);
    CHECK(result.has_value());
    CHECK(result->remote_addr.kind == base::TransportKind::Ip);
    CHECK(result->remote_addr.host == "1.1.1.1");
}

// ============================================================================
// 测试 11: create_strategy_by_name 工厂
// ============================================================================
static void test_create_strategy_by_name() {
    std::printf("[test] create_strategy_by_name...\n");

    auto rtt = create_strategy_by_name("rtt");
    CHECK(rtt != nullptr);
    CHECK(rtt->name() == "rtt");

    auto direct = create_strategy_by_name("prefer-direct");
    CHECK(direct != nullptr);
    CHECK(direct->name() == "prefer-direct");

    auto relay = create_strategy_by_name("prefer-relay");
    CHECK(relay != nullptr);
    CHECK(relay->name() == "prefer-relay");

    auto unknown = create_strategy_by_name("unknown");
    CHECK(unknown == nullptr);

    auto empty = create_strategy_by_name("");
    CHECK(empty == nullptr);
}

// ============================================================================
// 测试 12: 自定义策略注入
// ============================================================================
namespace {

/// 自定义策略：总是选 path_id 最大的路径
class CustomMaxIdStrategy : public PathSelectionStrategy {
public:
    std::optional<net::FourTuple> select(
        const std::vector<PathMigrationManager::PathQuality> &candidates) override {
        if (candidates.empty()) return std::nullopt;

        auto best = candidates.begin();
        for (auto it = candidates.begin() + 1; it != candidates.end(); ++it) {
            if (it->path_id > best->path_id) {
                best = it;
            }
        }

        if (!best->has_tuple) return std::nullopt;
        return best->four_tuple;
    }

    std::string_view name() const override { return "custom-max-id"; }
};

} // namespace

static void test_custom_strategy_injection() {
    std::printf("[test] Custom strategy injection...\n");

    std::shared_ptr<PathSelectionStrategy> s = std::make_shared<CustomMaxIdStrategy>();
    CHECK(s->name() == "custom-max-id");

    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(10000), "10.0.0.1", 1000, "1.1.1.1", 2000),
        make_quality(5, std::chrono::microseconds(50000), "10.0.0.1", 1001, "2.2.2.2", 3000),
        make_quality(3, std::chrono::microseconds(30000), "10.0.0.1", 1002, "3.3.3.3", 4000),
    };

    auto result = s->select(candidates);
    CHECK(result.has_value());
    CHECK(result->remote_addr.host == "2.2.2.2");  // path_id=5 最大
}

// ============================================================================
// 测试 13: 多策略对比 - 同一组候选，不同策略选不同路径
// ============================================================================
static void test_strategies_select_differently() {
    std::printf("[test] Strategies select differently...\n");

    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(10000), "10.0.0.1", 1000, "1.1.1.1", 2000, base::TransportKind::Ip),
        make_quality(2, std::chrono::microseconds(20000), "10.0.0.1", 1001, "relay.example.com", 9000, base::TransportKind::Relay),
    };

    RttBasedStrategy rtt;
    PreferDirectStrategy direct;
    PreferRelayStrategy relay;

    auto r1 = rtt.select(candidates);
    auto r2 = direct.select(candidates);
    auto r3 = relay.select(candidates);

    CHECK(r1.has_value());
    CHECK(r2.has_value());
    CHECK(r3.has_value());

    // RttBased 选 RTT 最小（直连，10000us）
    CHECK(r1->remote_addr.host == "1.1.1.1");

    // PreferDirect 选直连
    CHECK(r2->remote_addr.host == "1.1.1.1");

    // PreferRelay 选 Relay
    CHECK(r3->remote_addr.host == "relay.example.com");
}

// ============================================================================
// 测试 14: 同类路径内按 RTT 排序
// ============================================================================
static void test_same_kind_rtt_order() {
    std::printf("[test] Same kind RTT order...\n");

    PreferDirectStrategy s;
    // 3 个直连，RTT 不同
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(80000), "10.0.0.1", 1000, "1.1.1.1", 2000),
        make_quality(2, std::chrono::microseconds(20000), "10.0.0.1", 1001, "2.2.2.2", 3000),
        make_quality(3, std::chrono::microseconds(50000), "10.0.0.1", 1002, "3.3.3.3", 4000),
    };

    auto result = s.select(candidates);
    CHECK(result.has_value());
    CHECK(result->remote_addr.host == "2.2.2.2");  // RTT 最小
    CHECK(result->local_addr.port == 1001);
}

// ============================================================================
// 测试 15: 单个候选
// ============================================================================
static void test_single_candidate() {
    std::printf("[test] Single candidate...\n");

    RttBasedStrategy s;
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(10000), "10.0.0.1", 1000, "1.1.1.1", 2000),
    };

    auto result = s.select(candidates);
    CHECK(result.has_value());
    CHECK(result->remote_addr.host == "1.1.1.1");
}

// ============================================================================
// 测试 16: 混合 TransportKind 候选（Ip + Relay + Custom）
// ============================================================================
static void test_mixed_kinds() {
    std::printf("[test] Mixed TransportKind candidates...\n");

    RttBasedStrategy rtt;
    // Custom 类型 RTT 最小
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(50000), "10.0.0.1", 1000, "1.1.1.1", 2000, base::TransportKind::Ip),
        make_quality(2, std::chrono::microseconds(10000), "10.0.0.1", 1001, "custom.example.com", 9000, base::TransportKind::Custom),
        make_quality(3, std::chrono::microseconds(20000), "10.0.0.1", 1002, "relay.example.com", 9001, base::TransportKind::Relay),
    };

    auto result = rtt.select(candidates);
    CHECK(result.has_value());
    // RttBased 不区分 kind，选 RTT 最小
    CHECK(result->remote_addr.kind == base::TransportKind::Custom);
    CHECK(result->remote_addr.host == "custom.example.com");
}

// ============================================================================
// 测试 17: PreferDirect - Custom 类型作为最后回退
// ============================================================================
static void test_prefer_direct_custom_fallback() {
    std::printf("[test] PreferDirect custom fallback...\n");

    PreferDirectStrategy s;
    // 只有 Relay（未测量）和 Custom，应回退到 Custom
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(0), "10.0.0.1", 1000, "relay.example.com", 9000, base::TransportKind::Relay),
        make_quality(2, std::chrono::microseconds(30000), "10.0.0.1", 1001, "custom.example.com", 9001, base::TransportKind::Custom),
    };

    auto result = s.select(candidates);
    CHECK(result.has_value());
    // Relay 未测量，回退到 Custom
    CHECK(result->remote_addr.kind == base::TransportKind::Custom);
}

// ============================================================================
// 测试 18: 并发调用策略 select（线程安全）
// ============================================================================
static void test_concurrent_select() {
    std::printf("[test] Concurrent select...\n");

    RttBasedStrategy s;
    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(50000), "10.0.0.1", 1000, "1.1.1.1", 2000),
        make_quality(2, std::chrono::microseconds(20000), "10.0.0.1", 1001, "2.2.2.2", 3000),
        make_quality(3, std::chrono::microseconds(80000), "10.0.0.1", 1002, "3.3.3.3", 4000),
    };

    std::atomic<int> correct_count{0};
    std::atomic<int> total_count{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < 100; ++i) {
                auto r = s.select(candidates);
                ++total_count;
                if (r && r->remote_addr.host == "2.2.2.2") {
                    ++correct_count;
                }
            }
        });
    }
    for (auto &t : threads) t.join();

    CHECK(total_count.load() == 800);
    CHECK(correct_count.load() == 800);  // 全部应选 RTT 最小的
}

// ============================================================================
// 测试 19: 多态调用 - 通过基类指针
// ============================================================================
static void test_polymorphic_call() {
    std::printf("[test] Polymorphic call via base pointer...\n");

    std::vector<std::shared_ptr<PathSelectionStrategy>> strategies = {
        std::make_shared<RttBasedStrategy>(),
        std::make_shared<PreferDirectStrategy>(),
        std::make_shared<PreferRelayStrategy>(),
    };

    std::vector<PathMigrationManager::PathQuality> candidates = {
        make_quality(1, std::chrono::microseconds(10000), "10.0.0.1", 1000, "1.1.1.1", 2000, base::TransportKind::Ip),
        make_quality(2, std::chrono::microseconds(20000), "10.0.0.1", 1001, "relay.example.com", 9000, base::TransportKind::Relay),
    };

    // 通过基类指针多态调用
    for (auto &s : strategies) {
        auto r = s->select(candidates);
        CHECK(r.has_value());
        CHECK(!s->name().empty());
    }

    // 验证不同策略选不同路径
    auto r1 = strategies[0]->select(candidates);  // RttBased
    auto r2 = strategies[1]->select(candidates);  // PreferDirect
    auto r3 = strategies[2]->select(candidates);  // PreferRelay

    CHECK(r1->remote_addr.host == "1.1.1.1");
    CHECK(r2->remote_addr.host == "1.1.1.1");
    CHECK(r3->remote_addr.host == "relay.example.com");
}

int main() {
    std::printf("=== test_path_strategy ===\n");

    test_rtt_empty_candidates();
    test_rtt_select_min();
    test_rtt_all_unmeasured();
    test_rtt_partial_unmeasured();
    test_rtt_skip_no_tuple();
    test_prefer_direct_empty();
    test_prefer_direct_selects_direct();
    test_prefer_direct_fallback_to_relay();
    test_prefer_relay_selects_relay();
    test_prefer_relay_fallback_to_direct();
    test_create_strategy_by_name();
    test_custom_strategy_injection();
    test_strategies_select_differently();
    test_same_kind_rtt_order();
    test_single_candidate();
    test_mixed_kinds();
    test_prefer_direct_custom_fallback();
    test_concurrent_select();
    test_polymorphic_call();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
