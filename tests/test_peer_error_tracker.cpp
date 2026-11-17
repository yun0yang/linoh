// =============================================================================
// test_peer_error_tracker.cpp — v3.8.0 安全与故障自动化：per-peer 错误计数降级单测
//
// 覆盖：
//   - 基础错误记录与统计查询
//   - 降级阈值判定（达到 max_errors 自动降级）
//   - 不同错误类型记录与 last_error_type 跟踪
//   - reset 清空窗口 + 降级标记（保留 total_errors）
//   - enabled=false 向后兼容（所有方法 no-op）
//   - clear_degraded 冷却机制（冷却内拒绝 / 冷却后清除）
//   - 滑动窗口过期清理（窗口外错误不计入降级判定）
//   - clear_all / peer_count / degraded_count 查询
//   - update_config 运行时配置变更
//   - 未知 peer 默认返回值
//   - 多 peer 独立性
//   - 多线程并发安全
// =============================================================================

#include "linoh/endpoint/peer_error_tracker.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

using namespace linoh::endpoint;
using namespace linoh::base;
using namespace std::chrono_literals;

// =============================================================================
// 辅助
// =============================================================================

namespace {

/// 从整数构造 EndpointId（每字节填同一值，便于区分 peer）
EndpointId make_peer(std::uint8_t v) {
    std::array<std::uint8_t, EndpointId::kSize> bytes{};
    bytes.fill(v);
    return EndpointId{bytes};
}

/// 自定义配置工厂（duration 用 milliseconds 以支持亚秒窗口测试）
PeerErrorTrackerConfig make_config(std::size_t max_errors,
                                   std::chrono::milliseconds window,
                                   bool enabled = true,
                                   std::chrono::milliseconds cooldown = std::chrono::seconds(300)) {
    PeerErrorTrackerConfig cfg;
    cfg.max_errors_per_peer = max_errors;
    cfg.error_window = window;
    cfg.enabled = enabled;
    cfg.degrade_cooldown = cooldown;
    return cfg;
}

int test_count = 0;
int test_passed = 0;

#define RUN_TEST(name)                                                        \
    do {                                                                      \
        ++test_count;                                                         \
        std::cout << "  [test] " #name " ... ";                               \
        name();                                                               \
        ++test_passed;                                                        \
        std::cout << "OK\n";                                                  \
    } while (0)

}  // namespace

// =============================================================================
// 基础错误记录与统计
// =============================================================================

void test_record_single_error_stats() {
    PeerErrorTracker t{make_config(5, std::chrono::seconds(60))};
    auto p = make_peer(1);
    t.record_error(p, ErrorType::SendFailed);

    auto s = t.get_stats(p);
    assert(s.current_window_errors == 1);
    assert(s.total_errors == 1);
    assert(s.last_error_type.has_value());
    assert(*s.last_error_type == ErrorType::SendFailed);
    assert(s.last_error_time.has_value());
    assert(!s.degraded);
}

void test_record_multiple_errors_stats() {
    PeerErrorTracker t{make_config(5, std::chrono::seconds(60))};
    auto p = make_peer(2);
    for (int i = 0; i < 3; ++i) {
        t.record_error(p, ErrorType::Timeout);
    }
    auto s = t.get_stats(p);
    assert(s.current_window_errors == 3);
    assert(s.total_errors == 3);
}

void test_total_errors_accumulates_across_windows() {
    // 短窗口验证 total_errors 不随窗口清理
    PeerErrorTracker t{make_config(10, std::chrono::seconds(1))};
    auto p = make_peer(3);
    t.record_error(p, ErrorType::StreamError);
    t.record_error(p, ErrorType::StreamError);
    // 等待窗口过期
    std::this_thread::sleep_for(1500ms);
    // 再记录一条（触发 prune）
    t.record_error(p, ErrorType::Timeout);

    auto s = t.get_stats(p);
    assert(s.total_errors == 3);  // 累计不清理
    // 当前窗口只有最新一条
    assert(s.current_window_errors == 1);
}

// =============================================================================
// 降级阈值判定
// =============================================================================

void test_below_threshold_not_degraded() {
    PeerErrorTracker t{make_config(5, std::chrono::seconds(60))};
    auto p = make_peer(10);
    for (int i = 0; i < 4; ++i) {  // max-1
        t.record_error(p, ErrorType::ConnectFailed);
    }
    assert(!t.should_degrade(p));
}

void test_at_threshold_degraded() {
    PeerErrorTracker t{make_config(5, std::chrono::seconds(60))};
    auto p = make_peer(11);
    for (int i = 0; i < 5; ++i) {  // 恰好达到 max
        t.record_error(p, ErrorType::ConnectFailed);
    }
    assert(t.should_degrade(p));
}

void test_above_threshold_degraded() {
    PeerErrorTracker t{make_config(5, std::chrono::seconds(60))};
    auto p = make_peer(12);
    for (int i = 0; i < 8; ++i) {  // 超过 max
        t.record_error(p, ErrorType::HandshakeFailed);
    }
    assert(t.should_degrade(p));
}

void test_degraded_flag_in_stats() {
    PeerErrorTracker t{make_config(3, std::chrono::seconds(60))};
    auto p = make_peer(13);
    for (int i = 0; i < 3; ++i) {
        t.record_error(p, ErrorType::SendFailed);
    }
    auto s = t.get_stats(p);
    assert(s.degraded);
}

void test_degrade_only_once() {
    // 已降级后再记录错误，degraded_at 不应刷新（仅首次降级时间戳）
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60))};
    auto p = make_peer(14);
    t.record_error(p, ErrorType::Timeout);
    t.record_error(p, ErrorType::Timeout);  // 达到阈值，降级

    auto s1 = t.get_stats(p);
    assert(s1.degraded);

    // 再记录错误
    std::this_thread::sleep_for(50ms);
    t.record_error(p, ErrorType::Timeout);
    auto s2 = t.get_stats(p);
    assert(s2.degraded);
    assert(s2.total_errors == 3);
}

// =============================================================================
// 不同错误类型
// =============================================================================

void test_different_error_types_tracked() {
    PeerErrorTracker t{make_config(10, std::chrono::seconds(60))};
    auto p = make_peer(20);
    t.record_error(p, ErrorType::ConnectFailed);
    t.record_error(p, ErrorType::HandshakeFailed);
    t.record_error(p, ErrorType::SendFailed);
    t.record_error(p, ErrorType::StreamError);
    t.record_error(p, ErrorType::Timeout);

    auto s = t.get_stats(p);
    assert(s.current_window_errors == 5);
    assert(s.total_errors == 5);
    assert(*s.last_error_type == ErrorType::Timeout);
}

void test_error_type_name_all() {
    assert(std::string(error_type_name(ErrorType::ConnectFailed)) == "ConnectFailed");
    assert(std::string(error_type_name(ErrorType::HandshakeFailed)) == "HandshakeFailed");
    assert(std::string(error_type_name(ErrorType::SendFailed)) == "SendFailed");
    assert(std::string(error_type_name(ErrorType::StreamError)) == "StreamError");
    assert(std::string(error_type_name(ErrorType::Timeout)) == "Timeout");
}

// =============================================================================
// reset
// =============================================================================

void test_reset_clears_window_and_degraded() {
    PeerErrorTracker t{make_config(3, std::chrono::seconds(60))};
    auto p = make_peer(30);
    for (int i = 0; i < 3; ++i) {
        t.record_error(p, ErrorType::SendFailed);
    }
    assert(t.should_degrade(p));

    t.reset(p);

    assert(!t.should_degrade(p));
    auto s = t.get_stats(p);
    assert(s.current_window_errors == 0);
    assert(!s.degraded);
}

void test_reset_preserves_total_errors() {
    PeerErrorTracker t{make_config(3, std::chrono::seconds(60))};
    auto p = make_peer(31);
    for (int i = 0; i < 3; ++i) {
        t.record_error(p, ErrorType::SendFailed);
    }
    t.reset(p);
    auto s = t.get_stats(p);
    assert(s.total_errors == 3);  // 累计保留
}

void test_reset_unknown_peer_no_crash() {
    PeerErrorTracker t{make_config(3, std::chrono::seconds(60))};
    auto p = make_peer(32);  // 从未记录
    t.reset(p);  // 不应崩溃
    assert(!t.should_degrade(p));
}

void test_reset_then_record_again() {
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60))};
    auto p = make_peer(33);
    t.record_error(p, ErrorType::Timeout);
    t.record_error(p, ErrorType::Timeout);
    assert(t.should_degrade(p));
    t.reset(p);
    assert(!t.should_degrade(p));
    // 重新记录
    t.record_error(p, ErrorType::Timeout);
    assert(!t.should_degrade(p));  // 仅 1 条，未达阈值
    t.record_error(p, ErrorType::Timeout);
    assert(t.should_degrade(p));
}

// =============================================================================
// enabled=false 向后兼容
// =============================================================================

void test_disabled_record_no_op() {
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60), false)};
    auto p = make_peer(40);
    t.record_error(p, ErrorType::SendFailed);
    t.record_error(p, ErrorType::SendFailed);
    assert(!t.should_degrade(p));
    assert(t.peer_count() == 0);
}

void test_disabled_get_stats_returns_default() {
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60), false)};
    auto p = make_peer(41);
    t.record_error(p, ErrorType::SendFailed);
    auto s = t.get_stats(p);
    assert(s.current_window_errors == 0);
    assert(s.total_errors == 0);
    assert(!s.last_error_type.has_value());
    assert(!s.degraded);
}

void test_disabled_clear_degraded_returns_false() {
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60), false)};
    auto p = make_peer(42);
    assert(!t.clear_degraded(p));
}

void test_disabled_reset_no_op() {
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60), false)};
    auto p = make_peer(43);
    t.reset(p);  // 不应崩溃
}

// =============================================================================
// clear_degraded 冷却机制
// =============================================================================

void test_clear_degraded_within_cooldown() {
    // 短冷却 200ms
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60), true, std::chrono::seconds(1))};
    auto p = make_peer(50);
    t.record_error(p, ErrorType::SendFailed);
    t.record_error(p, ErrorType::SendFailed);
    assert(t.should_degrade(p));

    // 冷却内清除 → false
    assert(!t.clear_degraded(p));
    assert(t.should_degrade(p));  // 仍降级
}

void test_clear_degraded_after_cooldown() {
    // 短冷却 100ms 便于测试
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60), true,
                                   std::chrono::milliseconds(100))};
    auto p = make_peer(51);
    t.record_error(p, ErrorType::SendFailed);
    t.record_error(p, ErrorType::SendFailed);
    assert(t.should_degrade(p));

    std::this_thread::sleep_for(150ms);
    assert(t.clear_degraded(p));
    assert(!t.should_degrade(p));
}

void test_clear_degraded_clears_window() {
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60), true,
                                   std::chrono::milliseconds(100))};
    auto p = make_peer(52);
    t.record_error(p, ErrorType::SendFailed);
    t.record_error(p, ErrorType::SendFailed);

    std::this_thread::sleep_for(150ms);
    t.clear_degraded(p);

    auto s = t.get_stats(p);
    assert(s.current_window_errors == 0);
    assert(!s.degraded);
    assert(s.total_errors == 2);  // 累计保留
}

void test_clear_degraded_unknown_peer() {
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60))};
    auto p = make_peer(53);  // 从未记录
    assert(!t.clear_degraded(p));
}

void test_clear_degraded_not_degraded_returns_true() {
    PeerErrorTracker t{make_config(5, std::chrono::seconds(60))};
    auto p = make_peer(54);
    t.record_error(p, ErrorType::SendFailed);  // 仅 1 条，未降级
    assert(t.clear_degraded(p));  // 未降级直接返回 true
}

// =============================================================================
// 滑动窗口过期
// =============================================================================

void test_window_expiration_removes_old_errors() {
    PeerErrorTracker t{make_config(5, std::chrono::milliseconds(200))};
    auto p = make_peer(60);
    t.record_error(p, ErrorType::Timeout);
    t.record_error(p, ErrorType::Timeout);

    std::this_thread::sleep_for(300ms);
    // 触发 prune（record_error 内部调用）
    t.record_error(p, ErrorType::Timeout);

    auto s = t.get_stats(p);
    assert(s.current_window_errors == 1);  // 仅最新一条在窗口内
    assert(s.total_errors == 3);
}

void test_window_expiration_undegrades_below_threshold() {
    // 记录 2 条（未达阈值 5），窗口过期后 should_degrade 返回 false
    PeerErrorTracker t{make_config(5, std::chrono::milliseconds(200))};
    auto p = make_peer(61);
    t.record_error(p, ErrorType::Timeout);
    t.record_error(p, ErrorType::Timeout);
    assert(!t.should_degrade(p));  // 未达阈值

    std::this_thread::sleep_for(300ms);
    // should_degrade 内部不清理，但统计窗口内数量为 0
    assert(!t.should_degrade(p));
}

void test_degraded_stays_after_window_expires() {
    // 已降级的 peer，即使窗口过期，degraded 标记仍保持（需 clear_degraded 清除）
    PeerErrorTracker t{make_config(2, std::chrono::milliseconds(200))};
    auto p = make_peer(62);
    t.record_error(p, ErrorType::Timeout);
    t.record_error(p, ErrorType::Timeout);
    assert(t.should_degrade(p));

    std::this_thread::sleep_for(300ms);
    // 窗口外，但 degraded 标记仍 true
    assert(t.should_degrade(p));
}

// =============================================================================
// clear_all / peer_count / degraded_count
// =============================================================================

void test_clear_all() {
    PeerErrorTracker t{make_config(3, std::chrono::seconds(60))};
    t.record_error(make_peer(70), ErrorType::SendFailed);
    t.record_error(make_peer(71), ErrorType::SendFailed);
    t.record_error(make_peer(72), ErrorType::SendFailed);
    assert(t.peer_count() == 3);

    t.clear_all();
    assert(t.peer_count() == 0);
    assert(t.degraded_count() == 0);
}

void test_peer_count() {
    PeerErrorTracker t{make_config(5, std::chrono::seconds(60))};
    assert(t.peer_count() == 0);
    t.record_error(make_peer(80), ErrorType::SendFailed);
    assert(t.peer_count() == 1);
    t.record_error(make_peer(81), ErrorType::SendFailed);
    assert(t.peer_count() == 2);
    // 同一 peer 多次记录不增加计数
    t.record_error(make_peer(80), ErrorType::SendFailed);
    assert(t.peer_count() == 2);
}

void test_degraded_count() {
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60))};
    t.record_error(make_peer(90), ErrorType::SendFailed);
    t.record_error(make_peer(90), ErrorType::SendFailed);  // 降级
    t.record_error(make_peer(91), ErrorType::SendFailed);  // 未降级
    assert(t.degraded_count() == 1);

    t.record_error(make_peer(91), ErrorType::SendFailed);  // 降级
    assert(t.degraded_count() == 2);
}

// =============================================================================
// update_config
// =============================================================================

void test_update_config_new_threshold() {
    PeerErrorTracker t{make_config(5, std::chrono::seconds(60))};
    auto p = make_peer(100);
    for (int i = 0; i < 3; ++i) {
        t.record_error(p, ErrorType::Timeout);
    }
    assert(!t.should_degrade(p));  // 3 < 5

    // 降低阈值到 3
    t.update_config(make_config(3, std::chrono::seconds(60)));
    // 此时已记录 3 条，should_degrade 检查窗口内数量 >= 3
    assert(t.should_degrade(p));
}

void test_update_config_increase_threshold() {
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60))};
    auto p = make_peer(101);
    t.record_error(p, ErrorType::Timeout);
    t.record_error(p, ErrorType::Timeout);
    assert(t.should_degrade(p));  // 已降级

    // 提高阈值不会自动解除降级（degraded 标记需 clear_degraded 清除）
    t.update_config(make_config(10, std::chrono::seconds(60)));
    assert(t.should_degrade(p));  // 仍降级（标记未清）

    // 但新 peer 按新阈值判定
    auto p2 = make_peer(102);
    for (int i = 0; i < 5; ++i) {
        t.record_error(p2, ErrorType::Timeout);
    }
    assert(!t.should_degrade(p2));  // 5 < 10
}

void test_update_config_disable_runtime() {
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60))};
    auto p = make_peer(103);
    t.record_error(p, ErrorType::Timeout);
    t.record_error(p, ErrorType::Timeout);
    assert(t.should_degrade(p));

    // 运行时禁用
    t.update_config(make_config(2, std::chrono::seconds(60), false));
    assert(!t.should_degrade(p));  // 禁用后不降级
    auto s = t.get_stats(p);
    assert(s.current_window_errors == 0);  // 禁用后返回默认
}

void test_config_accessor() {
    PeerErrorTrackerConfig cfg;
    cfg.max_errors_per_peer = 7;
    cfg.error_window = std::chrono::seconds(120);
    PeerErrorTracker t{cfg};
    assert(t.config().max_errors_per_peer == 7);
    assert(t.config().error_window == std::chrono::seconds(120));
    assert(t.config().enabled);
}

// =============================================================================
// 未知 peer 默认返回值
// =============================================================================

void test_unknown_peer_stats_default() {
    PeerErrorTracker t{make_config(5, std::chrono::seconds(60))};
    auto p = make_peer(200);
    auto s = t.get_stats(p);
    assert(s.current_window_errors == 0);
    assert(s.total_errors == 0);
    assert(!s.last_error_type.has_value());
    assert(!s.last_error_time.has_value());
    assert(!s.degraded);
}

void test_unknown_peer_should_degrade_false() {
    PeerErrorTracker t{make_config(5, std::chrono::seconds(60))};
    assert(!t.should_degrade(make_peer(201)));
}

// =============================================================================
// 多 peer 独立性
// =============================================================================

void test_multiple_peers_independent() {
    PeerErrorTracker t{make_config(3, std::chrono::seconds(60))};
    auto p1 = make_peer(210);
    auto p2 = make_peer(211);

    // p1 降级
    t.record_error(p1, ErrorType::SendFailed);
    t.record_error(p1, ErrorType::SendFailed);
    t.record_error(p1, ErrorType::SendFailed);
    assert(t.should_degrade(p1));

    // p2 仅 1 条，不降级
    t.record_error(p2, ErrorType::SendFailed);
    assert(!t.should_degrade(p2));

    // reset p1 不影响 p2
    t.reset(p1);
    assert(!t.should_degrade(p1));
    auto s2 = t.get_stats(p2);
    assert(s2.current_window_errors == 1);
}

void test_multiple_peers_degraded_count() {
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60))};
    auto p1 = make_peer(220);
    auto p2 = make_peer(221);
    auto p3 = make_peer(222);

    t.record_error(p1, ErrorType::Timeout);
    t.record_error(p1, ErrorType::Timeout);  // p1 降级
    t.record_error(p2, ErrorType::Timeout);
    t.record_error(p2, ErrorType::Timeout);  // p2 降级
    t.record_error(p3, ErrorType::Timeout);  // p3 未降级

    assert(t.degraded_count() == 2);
    assert(t.peer_count() == 3);
}

// =============================================================================
// 多线程并发安全
// =============================================================================

void test_concurrent_record_and_query() {
    PeerErrorTracker t{make_config(100, std::chrono::seconds(60))};
    auto p = make_peer(250);

    std::atomic<int> done{0};
    std::vector<std::thread> threads;

    // 4 个线程并发 record_error
    for (int tid = 0; tid < 4; ++tid) {
        threads.emplace_back([&t, p, tid, &done]() {
            for (int i = 0; i < 25; ++i) {
                t.record_error(p, static_cast<ErrorType>(tid % 5));
            }
            ++done;
        });
    }
    // 2 个线程并发 should_degrade + get_stats
    for (int i = 0; i < 2; ++i) {
        threads.emplace_back([&t, p, &done]() {
            for (int j = 0; j < 100; ++j) {
                (void)t.should_degrade(p);
                (void)t.get_stats(p);
            }
            ++done;
        });
    }

    for (auto &th : threads) th.join();
    assert(done.load() == 6);

    auto s = t.get_stats(p);
    assert(s.total_errors == 100);  // 4 * 25
    assert(t.should_degrade(p));    // 100 >= 100
}

void test_concurrent_multiple_peers() {
    PeerErrorTracker t{make_config(10, std::chrono::seconds(60))};
    std::vector<std::thread> threads;
    std::atomic<int> total_degraded{0};

    for (int tid = 0; tid < 8; ++tid) {
        threads.emplace_back([&t, tid, &total_degraded]() {
            auto p = make_peer(static_cast<std::uint8_t>(tid));
            for (int i = 0; i < 15; ++i) {  // 每个peer 15条 > 10 阈值
                t.record_error(p, ErrorType::SendFailed);
            }
            if (t.should_degrade(p)) ++total_degraded;
        });
    }
    for (auto &th : threads) th.join();

    assert(total_degraded.load() == 8);
    assert(t.peer_count() == 8);
    assert(t.degraded_count() == 8);
}

// =============================================================================
// 集成场景
// =============================================================================

void test_integration_lifecycle() {
    // 模拟真实生命周期：错误累积 → 降级 → 冷却 → 恢复 → 重新累积
    PeerErrorTracker t{make_config(3, std::chrono::seconds(60), true,
                                   std::chrono::milliseconds(100))};
    auto p = make_peer(255);

    // 阶段 1：累积错误到降级
    t.record_error(p, ErrorType::ConnectFailed);
    t.record_error(p, ErrorType::HandshakeFailed);
    assert(!t.should_degrade(p));
    t.record_error(p, ErrorType::Timeout);
    assert(t.should_degrade(p));

    // 阶段 2：冷却后恢复
    std::this_thread::sleep_for(150ms);
    assert(t.clear_degraded(p));
    assert(!t.should_degrade(p));

    // 阶段 3：成功通信后 reset
    t.reset(p);
    auto s = t.get_stats(p);
    assert(s.current_window_errors == 0);
    assert(s.total_errors == 3);  // 累计保留

    // 阶段 4：重新累积（从 0 开始）
    t.record_error(p, ErrorType::SendFailed);
    assert(!t.should_degrade(p));
    assert(t.get_stats(p).current_window_errors == 1);
}

void test_integration_disabled_to_enabled() {
    // 启动时禁用，运行时启用
    PeerErrorTracker t{make_config(2, std::chrono::seconds(60), false)};
    auto p = make_peer(256);

    // 禁用期间记录无效
    t.record_error(p, ErrorType::SendFailed);
    t.record_error(p, ErrorType::SendFailed);
    assert(!t.should_degrade(p));

    // 启用后重新记录才生效
    t.update_config(make_config(2, std::chrono::seconds(60), true));
    t.record_error(p, ErrorType::SendFailed);
    t.record_error(p, ErrorType::SendFailed);
    assert(t.should_degrade(p));
}

// =============================================================================
// main
// =============================================================================

int main() {
    std::cout << "=== test_peer_error_tracker ===\n";

    std::cout << "-- 基础错误记录与统计\n";
    RUN_TEST(test_record_single_error_stats);
    RUN_TEST(test_record_multiple_errors_stats);
    RUN_TEST(test_total_errors_accumulates_across_windows);

    std::cout << "-- 降级阈值判定\n";
    RUN_TEST(test_below_threshold_not_degraded);
    RUN_TEST(test_at_threshold_degraded);
    RUN_TEST(test_above_threshold_degraded);
    RUN_TEST(test_degraded_flag_in_stats);
    RUN_TEST(test_degrade_only_once);

    std::cout << "-- 不同错误类型\n";
    RUN_TEST(test_different_error_types_tracked);
    RUN_TEST(test_error_type_name_all);

    std::cout << "-- reset\n";
    RUN_TEST(test_reset_clears_window_and_degraded);
    RUN_TEST(test_reset_preserves_total_errors);
    RUN_TEST(test_reset_unknown_peer_no_crash);
    RUN_TEST(test_reset_then_record_again);

    std::cout << "-- enabled=false 向后兼容\n";
    RUN_TEST(test_disabled_record_no_op);
    RUN_TEST(test_disabled_get_stats_returns_default);
    RUN_TEST(test_disabled_clear_degraded_returns_false);
    RUN_TEST(test_disabled_reset_no_op);

    std::cout << "-- clear_degraded 冷却机制\n";
    RUN_TEST(test_clear_degraded_within_cooldown);
    RUN_TEST(test_clear_degraded_after_cooldown);
    RUN_TEST(test_clear_degraded_clears_window);
    RUN_TEST(test_clear_degraded_unknown_peer);
    RUN_TEST(test_clear_degraded_not_degraded_returns_true);

    std::cout << "-- 滑动窗口过期\n";
    RUN_TEST(test_window_expiration_removes_old_errors);
    RUN_TEST(test_window_expiration_undegrades_below_threshold);
    RUN_TEST(test_degraded_stays_after_window_expires);

    std::cout << "-- clear_all / peer_count / degraded_count\n";
    RUN_TEST(test_clear_all);
    RUN_TEST(test_peer_count);
    RUN_TEST(test_degraded_count);

    std::cout << "-- update_config\n";
    RUN_TEST(test_update_config_new_threshold);
    RUN_TEST(test_update_config_increase_threshold);
    RUN_TEST(test_update_config_disable_runtime);
    RUN_TEST(test_config_accessor);

    std::cout << "-- 未知 peer 默认返回值\n";
    RUN_TEST(test_unknown_peer_stats_default);
    RUN_TEST(test_unknown_peer_should_degrade_false);

    std::cout << "-- 多 peer 独立性\n";
    RUN_TEST(test_multiple_peers_independent);
    RUN_TEST(test_multiple_peers_degraded_count);

    std::cout << "-- 多线程并发安全\n";
    RUN_TEST(test_concurrent_record_and_query);
    RUN_TEST(test_concurrent_multiple_peers);

    std::cout << "-- 集成场景\n";
    RUN_TEST(test_integration_lifecycle);
    RUN_TEST(test_integration_disabled_to_enabled);

    std::cout << "\n[OK] test_peer_error_tracker passed: " << test_passed << "/"
              << test_count << " tests\n";
    return 0;
}
