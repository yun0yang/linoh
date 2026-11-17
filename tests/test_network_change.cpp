// test_network_change.cpp — P2-G7 网络切换重建单元测试
//
// 验证：
//   1. NetworkType 枚举 + to_string
//   2. detect_network_type() 不崩溃（返回合理值）
//   3. NetworkChangeEvent: is_actual_change + to_string
//   4. NetworkChangeTracker::debounce_event 纯逻辑
//   5. NetworkChangeTracker: 去抖动 + 类型变化触发（注入式）
//   6. NetworkChangeTracker: 同类型不触发
//   7. NetworkRebuilder: decide_after_probe 纯决策
//   8. NetworkRebuilder: decide_after_holepunch 纯决策
//   9. NetworkRebuilder: decide_after_fallback 纯决策
//  10. NetworkRebuilder: rebuild() 全流程（mock providers）
//  11. NetworkRebuilder: NotAvailable 跳 Step5
//  12. NetworkRebuildStats: 计数器准确性
//  13. OldConnectionGraceManager: grace 期行为

#include "linoh/net/route_monitor.hpp"
#include "linoh/net/network_rebuilder.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh;
using namespace linoh::net;
using namespace linoh::relay;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 1. NetworkType 枚举 + to_string
// ============================================================================

static void test_network_type_enum() {
    CHECK(std::string(to_string(NetworkType::Unknown)) == "unknown");
    CHECK(std::string(to_string(NetworkType::WiFi)) == "wifi");
    CHECK(std::string(to_string(NetworkType::Cellular)) == "cellular");
    CHECK(std::string(to_string(NetworkType::Ethernet)) == "ethernet");
    CHECK(std::string(to_string(NetworkType::Loopback)) == "loopback");
}

// ============================================================================
// 2. detect_network_type() 不崩溃
// ============================================================================

static void test_detect_network_type() {
    NetworkType t = detect_network_type();
    // 测试环境应至少返回一个有效值（Ethernet/WiFi/Loopback/Unknown 均合法）
    CHECK(t == NetworkType::Unknown || t == NetworkType::WiFi ||
          t == NetworkType::Cellular || t == NetworkType::Ethernet ||
          t == NetworkType::Loopback);
}

// ============================================================================
// 3. NetworkChangeEvent
// ============================================================================

static void test_network_change_event() {
    NetworkChangeEvent ev;
    ev.from = NetworkType::WiFi;
    ev.to = NetworkType::Cellular;
    CHECK(ev.is_actual_change() == true);

    ev.to = NetworkType::WiFi;
    CHECK(ev.is_actual_change() == false);

    ev.to = NetworkType::Cellular;
    std::string s = ev.to_string();
    CHECK(s.find("wifi") != std::string::npos);
    CHECK(s.find("cellular") != std::string::npos);
    CHECK(s.find("true") != std::string::npos);  // actual_change=true
}

// ============================================================================
// 4. NetworkChangeTracker::debounce_event 纯逻辑
// ============================================================================

static void test_debounce_event_pure() {
    // 类型变化 → 触发
    auto r1 = NetworkChangeTracker::debounce_event(
        NetworkType::WiFi, NetworkType::Cellular, RouteEvent::DefaultRouteChanged);
    CHECK(r1.has_value());
    CHECK(r1->from == NetworkType::WiFi);
    CHECK(r1->to == NetworkType::Cellular);
    CHECK(r1->is_actual_change() == true);

    // 同类型 → 不触发
    auto r2 = NetworkChangeTracker::debounce_event(
        NetworkType::WiFi, NetworkType::WiFi, RouteEvent::DefaultRouteChanged);
    CHECK(!r2.has_value());

    // Unknown → WiFi 触发
    auto r3 = NetworkChangeTracker::debounce_event(
        NetworkType::Unknown, NetworkType::WiFi, RouteEvent::InterfaceUp);
    CHECK(r3.has_value());
    CHECK(r3->from == NetworkType::Unknown);
    CHECK(r3->to == NetworkType::WiFi);
}

// ============================================================================
// 5. NetworkChangeTracker: 去抖动 + 类型变化触发（注入式）
// ============================================================================

static void test_tracker_type_change_triggers() {
    // 使用注入式 type_provider，enable_route_monitor=false（测试模式）
    NetworkChangeTracker::Config cfg;
    cfg.enable_route_monitor = false;
    cfg.fallback_to_poller = false;  // 关闭轮询器，避免 DefaultRoutePoller 干扰
    cfg.debounce_window = std::chrono::milliseconds(100);  // 短窗口加速测试

    // 可变类型提供者：start 时返回 Unknown，切换标志后返回 Cellular
    // start() 会把 last_triggered_type_ 初始化为 type_provider_() 的当前值，
    // 所以必须让 type_provider 在 start 时与注入后返回不同值才能触发类型变化。
    std::atomic<bool> switched{false};
    auto type_provider = [&]() {
        return switched.load() ? NetworkType::Cellular : NetworkType::Unknown;
    };
    NetworkChangeTracker tracker(cfg, type_provider);

    std::atomic<int> callback_count{0};
    NetworkType received_to = NetworkType::Unknown;
    tracker.start([&](const NetworkChangeEvent &ev) {
        ++callback_count;
        received_to = ev.to;
    });
    // start 时 current_type_=Unknown, last_triggered_type_=Unknown

    // 切换网络类型并注入事件，触发去抖动
    switched.store(true);
    tracker.inject_event(RouteEvent::DefaultRouteChanged);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Unknown → Cellular 应触发回调
    CHECK(callback_count.load() >= 1);
    CHECK(received_to == NetworkType::Cellular);

    tracker.stop();
}

// ============================================================================
// 6. NetworkChangeTracker: 同类型不触发
// ============================================================================

static void test_tracker_same_type_no_trigger() {
    NetworkChangeTracker::Config cfg;
    cfg.enable_route_monitor = false;
    cfg.fallback_to_poller = false;  // 关闭轮询器，避免干扰
    cfg.debounce_window = std::chrono::milliseconds(100);

    // type_provider 始终返回 Ethernet
    auto type_provider = []() { return NetworkType::Ethernet; };
    NetworkChangeTracker tracker(cfg, type_provider);

    std::atomic<int> callback_count{0};
    tracker.start([&](const NetworkChangeEvent &) {
        ++callback_count;
    });

    // start 时 current_type=Ethernet, last_triggered=Ethernet
    // 注入事件后探测仍为 Ethernet → 同类型不触发
    tracker.inject_event(RouteEvent::DefaultRouteChanged);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    CHECK(callback_count.load() == 0);

    tracker.stop();
}

// ============================================================================
// 7. NetworkChangeTracker: 多次注入去抖动合并
// ============================================================================

static void test_tracker_debounce_merge() {
    NetworkChangeTracker::Config cfg;
    cfg.enable_route_monitor = false;
    cfg.fallback_to_poller = false;  // 关闭轮询器，避免干扰
    cfg.debounce_window = std::chrono::milliseconds(200);

    // 可变类型：start 时返回 Unknown，切换后返回 WiFi（模拟网络切换）
    std::atomic<bool> switched{false};
    auto type_provider = [&]() {
        return switched.load() ? NetworkType::WiFi : NetworkType::Unknown;
    };
    NetworkChangeTracker tracker(cfg, type_provider);

    std::atomic<int> callback_count{0};
    tracker.start([&](const NetworkChangeEvent &) {
        ++callback_count;
    });

    // 切换网络类型，短时间内连续注入 3 个事件，去抖动后应只触发 1 次
    switched.store(true);
    tracker.inject_event(RouteEvent::InterfaceUp);
    tracker.inject_event(RouteEvent::InterfaceDown);
    tracker.inject_event(RouteEvent::DefaultRouteChanged);
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    CHECK(callback_count.load() <= 1);  // 至多 1 次（合并）

    tracker.stop();
}

// ============================================================================
// 8. NetworkRebuilder: decide_after_probe 纯决策
// ============================================================================

static void test_decide_after_probe() {
    CHECK(NetworkRebuilder::decide_after_probe(UdpAvailability::Available) ==
          RebuildStep::Step3_Gather);
    CHECK(NetworkRebuilder::decide_after_probe(UdpAvailability::Bad) ==
          RebuildStep::Step3_Gather);  // Bad 也走打洞（+FEC）
    CHECK(NetworkRebuilder::decide_after_probe(UdpAvailability::NotAvailable) ==
          RebuildStep::Step5_Fallback);  // 直接降级
}

// ============================================================================
// 9. NetworkRebuilder: decide_after_holepunch 纯决策
// ============================================================================

static void test_decide_after_holepunch() {
    HolepunchResult success;
    success.success = true;
    CHECK(NetworkRebuilder::decide_after_holepunch(success) == RebuildStep::Done);

    HolepunchResult failure;
    failure.success = false;
    CHECK(NetworkRebuilder::decide_after_holepunch(failure) == RebuildStep::Step5_Fallback);
}

// ============================================================================
// 10. NetworkRebuilder: decide_after_fallback 纯决策
// ============================================================================

static void test_decide_after_fallback() {
    // UseTcp → Degraded
    FallbackResult tcp_ok;
    tcp_ok.decision = FallbackDecision::UseTcp;
    CHECK(NetworkRebuilder::decide_after_fallback(tcp_ok) == RebuildOutcome::Degraded);

    // UseRelay → Degraded
    FallbackResult relay_ok;
    relay_ok.decision = FallbackDecision::UseRelay;
    CHECK(NetworkRebuilder::decide_after_fallback(relay_ok) == RebuildOutcome::Degraded);

    // UseRelay + relay_attempted + error → Failed
    FallbackResult relay_fail;
    relay_fail.decision = FallbackDecision::UseRelay;
    relay_fail.relay_attempted = true;
    relay_fail.error_msg = "relay connection failed";
    CHECK(NetworkRebuilder::decide_after_fallback(relay_fail) == RebuildOutcome::Failed);

    // UseUdp → Degraded（实际上不会走到 Step5 后返回 UseUdp，但逻辑上算 Degraded）
    FallbackResult udp_ok;
    udp_ok.decision = FallbackDecision::UseUdp;
    CHECK(NetworkRebuilder::decide_after_fallback(udp_ok) == RebuildOutcome::Degraded);
}

// ============================================================================
// 11. NetworkRebuilder: rebuild() 全流程 - 打洞成功
// ============================================================================

static void test_rebuild_holepunch_success() {
    NetworkRebuildConfig cfg;
    cfg.timeout = std::chrono::seconds(5);

    auto udp_probe = []() {
        UdpProbeResult r;
        r.availability = UdpAvailability::Available;
        return r;
    };
    auto gather = []() { return true; };
    auto holepunch = []() {
        HolepunchResult r;
        r.success = true;
        return r;
    };
    auto fallback = []() {
        FallbackResult r;
        r.decision = FallbackDecision::UseRelay;
        return r;
    };

    NetworkRebuilder rebuilder(cfg, udp_probe, gather, holepunch, fallback);
    auto result = rebuilder.rebuild();

    CHECK(result.outcome == RebuildOutcome::Success);
    CHECK(result.last_step == RebuildStep::Done);
    CHECK(result.udp_probe_result.availability == UdpAvailability::Available);
    CHECK(result.holepunch_result.success == true);
    CHECK(rebuilder.stats().succeeded.load() == 1);
    CHECK(rebuilder.stats().total.load() == 1);
}

// ============================================================================
// 12. NetworkRebuilder: NotAvailable 跳 Step5
// ============================================================================

static void test_rebuild_not_available_skip_to_step5() {
    auto udp_probe = []() {
        UdpProbeResult r;
        r.availability = UdpAvailability::NotAvailable;
        return r;
    };
    auto gather = []() { return true; };
    auto holepunch = []() {
        HolepunchResult r;
        r.success = false;
        return r;
    };
    auto fallback = []() {
        FallbackResult r;
        r.decision = FallbackDecision::UseTcp;
        return r;
    };

    NetworkRebuilder rebuilder({}, udp_probe, gather, holepunch, fallback);
    auto result = rebuilder.rebuild();

    CHECK(result.outcome == RebuildOutcome::Degraded);
    CHECK(result.last_step == RebuildStep::Done);
    // gather 和 holepunch 不应被调用（NotAvailable 跳过）
    // 验证：udp_probe_result 记录了 NotAvailable
    CHECK(result.udp_probe_result.availability == UdpAvailability::NotAvailable);
    CHECK(rebuilder.stats().degraded.load() == 1);
}

// ============================================================================
// 13. NetworkRebuilder: 打洞失败 → Step5 降级
// ============================================================================

static void test_rebuild_holepunch_fail_then_degrade() {
    auto udp_probe = []() {
        UdpProbeResult r;
        r.availability = UdpAvailability::Available;
        return r;
    };
    auto gather = []() { return true; };
    auto holepunch = []() {
        HolepunchResult r;
        r.success = false;
        return r;
    };
    auto fallback = []() {
        FallbackResult r;
        r.decision = FallbackDecision::UseRelay;
        return r;
    };

    NetworkRebuilder rebuilder({}, udp_probe, gather, holepunch, fallback);
    auto result = rebuilder.rebuild();

    CHECK(result.outcome == RebuildOutcome::Degraded);
    CHECK(result.holepunch_result.success == false);
    CHECK(rebuilder.stats().degraded.load() == 1);
}

// ============================================================================
// 14. NetworkRebuilder: 全部失败 → Disconnected
// ============================================================================

static void test_rebuild_all_fail_disconnected() {
    auto udp_probe = []() {
        UdpProbeResult r;
        r.availability = UdpAvailability::NotAvailable;
        return r;
    };
    auto gather = []() { return false; };
    auto holepunch = []() {
        HolepunchResult r;
        r.success = false;
        return r;
    };
    auto fallback = []() {
        FallbackResult r;
        r.decision = FallbackDecision::UseRelay;
        r.relay_attempted = true;
        r.error_msg = "all relays failed";
        return r;
    };

    NetworkRebuilder rebuilder({}, udp_probe, gather, holepunch, fallback);
    auto result = rebuilder.rebuild();

    CHECK(result.outcome == RebuildOutcome::Failed);
    CHECK(result.last_step == RebuildStep::Disconnected);
    CHECK(rebuilder.stats().failed.load() == 1);
}

// ============================================================================
// 15. NetworkRebuilder: gather 失败 → Step5
// ============================================================================

static void test_rebuild_gather_fail_skip_to_step5() {
    auto udp_probe = []() {
        UdpProbeResult r;
        r.availability = UdpAvailability::Available;
        return r;
    };
    auto gather = []() { return false; };  // gather 失败
    auto holepunch = []() {
        HolepunchResult r;
        r.success = true;  // 即使打洞会成功，也不应被调用
        return r;
    };
    auto fallback = []() {
        FallbackResult r;
        r.decision = FallbackDecision::UseTcp;
        return r;
    };

    NetworkRebuilder rebuilder({}, udp_probe, gather, holepunch, fallback);
    auto result = rebuilder.rebuild();

    CHECK(result.outcome == RebuildOutcome::Degraded);
    // holepunch_result 应为默认值（未被调用）
    CHECK(result.holepunch_result.success == false);
}

// ============================================================================
// 16. NetworkRebuildStats: 计数器准确性
// ============================================================================

static void test_rebuild_stats_accuracy() {
    auto udp_probe = []() {
        UdpProbeResult r;
        r.availability = UdpAvailability::Available;
        return r;
    };
    auto gather = []() { return true; };
    auto holepunch = []() {
        HolepunchResult r;
        r.success = true;
        return r;
    };
    auto fallback = []() {
        FallbackResult r;
        r.decision = FallbackDecision::UseRelay;
        return r;
    };

    NetworkRebuilder rebuilder({}, udp_probe, gather, holepunch, fallback);
    CHECK(rebuilder.stats().total.load() == 0);
    CHECK(rebuilder.stats().succeeded.load() == 0);

    rebuilder.rebuild();
    rebuilder.rebuild();
    rebuilder.rebuild();

    CHECK(rebuilder.stats().total.load() == 3);
    CHECK(rebuilder.stats().succeeded.load() == 3);
    CHECK(rebuilder.stats().degraded.load() == 0);
    CHECK(rebuilder.stats().failed.load() == 0);
    CHECK(rebuilder.stats().total_duration_ms.load() >= 0);
}

// ============================================================================
// 17. NetworkRebuildStats: reset
// ============================================================================

static void test_rebuild_stats_reset() {
    NetworkRebuildStats stats;
    stats.total.store(10);
    stats.succeeded.store(5);
    stats.degraded.store(3);
    stats.failed.store(2);
    stats.total_duration_ms.store(1000);

    stats.reset();
    CHECK(stats.total.load() == 0);
    CHECK(stats.succeeded.load() == 0);
    CHECK(stats.degraded.load() == 0);
    CHECK(stats.failed.load() == 0);
    CHECK(stats.total_duration_ms.load() == 0);
}

// ============================================================================
// 18. OldConnectionGraceManager: grace 期行为
// ============================================================================

static void test_grace_manager_basic() {
    OldConnectionGraceManager mgr(std::chrono::milliseconds(200));
    CHECK(mgr.state() == GraceState::Inactive);
    CHECK(!mgr.is_in_grace());
    CHECK(!mgr.is_closed());

    std::atomic<bool> closed{false};
    mgr.enter_grace([&]() { closed.store(true); });
    CHECK(mgr.is_in_grace() == true);
    CHECK(mgr.state() == GraceState::InGrace);

    // 等待 grace 结束
    mgr.wait_grace_end();
    CHECK(closed.load() == true);
    CHECK(mgr.is_closed() == true);
    CHECK(mgr.state() == GraceState::Closed);
}

// ============================================================================
// 19. OldConnectionGraceManager: force_close
// ============================================================================

static void test_grace_manager_force_close() {
    OldConnectionGraceManager mgr(std::chrono::seconds(10));  // 长 grace
    std::atomic<bool> closed{false};
    mgr.enter_grace([&]() { closed.store(true); });
    CHECK(mgr.is_in_grace() == true);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    mgr.force_close();
    CHECK(closed.load() == true);
    CHECK(mgr.is_closed() == true);
}

// ============================================================================
// 20. RebuildStep 转字符串
// ============================================================================

static void test_rebuild_step_to_string() {
    CHECK(std::string(to_string(RebuildStep::Idle)) == "idle");
    CHECK(std::string(to_string(RebuildStep::Step1_Reset)) == "step1-reset");
    CHECK(std::string(to_string(RebuildStep::Step2_Probe)) == "step2-probe");
    CHECK(std::string(to_string(RebuildStep::Step3_Gather)) == "step3-gather");
    CHECK(std::string(to_string(RebuildStep::Step4_Punch)) == "step4-punch");
    CHECK(std::string(to_string(RebuildStep::Step5_Fallback)) == "step5-fallback");
    CHECK(std::string(to_string(RebuildStep::Done)) == "done");
    CHECK(std::string(to_string(RebuildStep::Disconnected)) == "disconnected");
}

// ============================================================================
// 21. RebuildOutcome 转字符串
// ============================================================================

static void test_rebuild_outcome_to_string() {
    CHECK(std::string(to_string(RebuildOutcome::Success)) == "success");
    CHECK(std::string(to_string(RebuildOutcome::Degraded)) == "degraded");
    CHECK(std::string(to_string(RebuildOutcome::Failed)) == "failed");
    CHECK(std::string(to_string(RebuildOutcome::Timeout)) == "timeout");
}

// ============================================================================
// 22. GraceState 转字符串
// ============================================================================

static void test_grace_state_to_string() {
    CHECK(std::string(to_string(GraceState::Inactive)) == "inactive");
    CHECK(std::string(to_string(GraceState::InGrace)) == "in-grace");
    CHECK(std::string(to_string(GraceState::Closed)) == "closed");
}

// ============================================================================
// 23. NetworkRebuildResult: is_success
// ============================================================================

static void test_rebuild_result_is_success() {
    NetworkRebuildResult r;
    r.outcome = RebuildOutcome::Success;
    CHECK(r.is_success() == true);

    r.outcome = RebuildOutcome::Degraded;
    CHECK(r.is_success() == true);

    r.outcome = RebuildOutcome::Failed;
    CHECK(r.is_success() == false);

    r.outcome = RebuildOutcome::Timeout;
    CHECK(r.is_success() == false);
}

int main() {
    test_network_type_enum();
    test_detect_network_type();
    test_network_change_event();
    test_debounce_event_pure();
    test_tracker_type_change_triggers();
    test_tracker_same_type_no_trigger();
    test_tracker_debounce_merge();
    test_decide_after_probe();
    test_decide_after_holepunch();
    test_decide_after_fallback();
    test_rebuild_holepunch_success();
    test_rebuild_not_available_skip_to_step5();
    test_rebuild_holepunch_fail_then_degrade();
    test_rebuild_all_fail_disconnected();
    test_rebuild_gather_fail_skip_to_step5();
    test_rebuild_stats_accuracy();
    test_rebuild_stats_reset();
    test_grace_manager_basic();
    test_grace_manager_force_close();
    test_rebuild_step_to_string();
    test_rebuild_outcome_to_string();
    test_grace_state_to_string();
    test_rebuild_result_is_success();

    std::printf("test_network_change: %d passed, %d failed\n",
                pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
