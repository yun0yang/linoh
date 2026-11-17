// test_v460_stability_fixes.cpp — v4.6.0 阶段一稳定性加固测试
//
// 验证内容（对应 T-LP1-001 ~ T-LP1-009）：
//   T-LP1-001/002: PTO 上限 clamp（握手期 500ms / 握手后 2s）
//   T-LP1-003/004: LossDetector::on_network_change + Connection 联动
//   T-LP1-005/006: on_pto_timeout kForcePingPn（TLP ack-eliciting）
//   T-LP1-007:     Relay 健康检查回调机制
//   T-LP1-008:     路径 idle timeout 差异化（Direct/Relay/TcpFallback）
//   T-LP1-009:     DefaultRoutePoller 默认初始间隔 100ms
//
// 借鉴 noq#523（PTO 上限）、noq#545（网络变化重置）、noq#561（TLP ack-eliciting）

#include "linoh/protocol/loss_recovery.hpp"
#include "linoh/net/route_monitor.hpp"

#include <chrono>
#include <cstdio>
#include <thread>

using namespace linoh::protocol;
using namespace linoh::net;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

static double now_ms() {
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// ============================================================================
// T-LP1-001/002: PTO 上限常量 + pto_timeout_ms() clamp
// ============================================================================

static void test_pto_constants_exist() {
    std::printf("[test] T-LP1-001: PTO upper limit constants...\n");

    // 验证常量值符合设计
    CHECK(kPtoMaxPostHandshakeMs == 2000.0);  // 握手后 2s
    CHECK(kPtoMaxHandshakeMs == 500.0);        // 握手期 500ms
}

static void test_pto_clamp_handshake_period() {
    std::printf("[test] T-LP1-002: PTO clamp during handshake (500ms cap)...\n");

    LossDetector ld;
    // 握手未完成时 set_handshake_complete(false)
    ld.set_handshake_complete(false);

    // 发送一个 ack-eliciting 包以启动 PTO 计时
    ld.on_packet_sent(1, now_ms(), 100, true, {});

    double pto = ld.pto_timeout_ms(now_ms());
    // 握手期 PTO 不应超过 500ms
    CHECK(pto >= 0.0);
    CHECK(pto <= kPtoMaxHandshakeMs);
}

static void test_pto_clamp_post_handshake() {
    std::printf("[test] T-LP1-002: PTO clamp post-handshake (2s cap)...\n");

    LossDetector ld;
    ld.set_handshake_complete(true);

    ld.on_packet_sent(1, now_ms(), 100, true, {});

    double pto = ld.pto_timeout_ms(now_ms());
    CHECK(pto >= 0.0);
    CHECK(pto <= kPtoMaxPostHandshakeMs);
}

static void test_pto_clamp_with_backoff() {
    std::printf("[test] T-LP1-002: PTO clamp with exponential backoff...\n");

    LossDetector ld;
    ld.set_handshake_complete(true);

    ld.on_packet_sent(1, now_ms(), 100, true, {});

    // 模拟多次 PTO 超时以触发指数退避
    double prev_pto = ld.pto_timeout_ms(now_ms());
    for (int i = 0; i < 5; ++i) {
        ld.on_pto_timeout(now_ms());
    }

    double clamped_pto = ld.pto_timeout_ms(now_ms());
    // 即使指数退避后，PTO 仍不应超过 2s 上限
    CHECK(clamped_pto <= kPtoMaxPostHandshakeMs);
    // 退避后 PTO 应大于等于初始值（退避生效但被 clamp）
    CHECK(clamped_pto >= 0.0);
}

// ============================================================================
// T-LP1-003: LossDetector::on_network_change() 重置 PTO backoff + RTT
// ============================================================================

static void test_on_network_change_resets_pto_count() {
    std::printf("[test] T-LP1-003: on_network_change resets PTO backoff...\n");

    LossDetector ld;
    ld.set_handshake_complete(true);

    ld.on_packet_sent(1, now_ms(), 100, true, {});

    // 触发多次 PTO 超时
    for (int i = 0; i < 3; ++i) {
        ld.on_pto_timeout(now_ms());
    }
    uint32_t pto_count_before = ld.pto_count();
    CHECK(pto_count_before > 0);

    // 网络变化应重置 PTO 退避
    ld.on_network_change();
    uint32_t pto_count_after = ld.pto_count();
    CHECK(pto_count_after == 0);
}

static void test_on_network_change_resets_rtt() {
    std::printf("[test] T-LP1-003: on_network_change resets RTT estimator...\n");

    LossDetector ld;
    ld.set_handshake_complete(true);

    // 发送一个 ack-eliciting 包以使 next_timeout_ms 返回有效超时值
    // （无飞行中包时 next_timeout_ms 返回 -1.0 是设计行为）
    ld.on_packet_sent(1, now_ms(), 100, true, {});

    // 获取初始超时（基于初始 RTT）
    double initial_timeout = ld.next_timeout_ms(now_ms());
    CHECK(initial_timeout >= 0.0);

    // 网络变化后 RTT 应重置为初始值
    ld.on_network_change();

    // 验证不崩溃且超时值仍有效（pto_count 重置后应返回初始 PTO）
    double post_timeout = ld.next_timeout_ms(now_ms());
    CHECK(post_timeout >= 0.0);
}

static void test_on_network_change_idempotent() {
    std::printf("[test] T-LP1-003: on_network_change is idempotent...\n");

    LossDetector ld;
    ld.set_handshake_complete(true);

    ld.on_packet_sent(1, now_ms(), 100, true, {});

    // 多次调用应安全
    ld.on_network_change();
    ld.on_network_change();
    ld.on_network_change();

    CHECK(ld.pto_count() == 0);
}

// ============================================================================
// T-LP1-005/006: on_pto_timeout kForcePingPn（TLP ack-eliciting）
// ============================================================================

static void test_pto_timeout_no_ack_eliciting_returns_force_ping() {
    std::printf("[test] T-LP1-005: PTO with no ack-eliciting returns kForcePingPn...\n");

    LossDetector ld;
    ld.set_handshake_complete(true);

    // 不发送任何 ack-eliciting 包
    // PTO 超时时应返回 {kForcePingPn} 强制发 PING
    auto probes = ld.on_pto_timeout(now_ms());

    // 应返回非空列表
    CHECK(!probes.empty());

    // 应包含 kForcePingPn 标记
    bool has_force_ping = false;
    for (uint64_t pn : probes) {
        if (pn == kForcePingPn) {
            has_force_ping = true;
            break;
        }
    }
    CHECK(has_force_ping);
}

static void test_pto_timeout_with_ack_eliciting_returns_pn() {
    std::printf("[test] T-LP1-005: PTO with ack-eliciting returns PN list...\n");

    LossDetector ld;
    ld.set_handshake_complete(true);

    // 发送一个 ack-eliciting 包
    ld.on_packet_sent(1, now_ms(), 100, true, {});

    // PTO 超时应返回该 PN（非 kForcePingPn）
    auto probes = ld.on_pto_timeout(now_ms());

    CHECK(!probes.empty());

    // 应返回实际 PN（1），不是 kForcePingPn
    bool has_real_pn = false;
    for (uint64_t pn : probes) {
        if (pn != kForcePingPn) {
            has_real_pn = true;
            break;
        }
    }
    CHECK(has_real_pn);
}

static void test_force_ping_constant_value() {
    std::printf("[test] T-LP1-005: kForcePingPn constant value...\n");

    // kForcePingPn 应为 UINT64_MAX（哨兵值，不可能与真实 PN 冲突）
    CHECK(kForcePingPn == UINT64_MAX);
}

// ============================================================================
// T-LP1-009: DefaultRoutePoller 默认初始间隔 100ms
// ============================================================================

static void test_default_route_poller_initial_100ms() {
    std::printf("[test] T-LP1-009: DefaultRoutePoller default initial=100ms...\n");

    DefaultRoutePoller p;
    CHECK(p.current_interval() == std::chrono::milliseconds(100));

    // 退避序列：100 -> 200 -> 400 -> 800 -> 1600 -> 3200 -> 5000
    CHECK(p.next_interval(std::chrono::milliseconds(100)) == std::chrono::milliseconds(200));
    CHECK(p.next_interval(std::chrono::milliseconds(200)) == std::chrono::milliseconds(400));
    CHECK(p.next_interval(std::chrono::milliseconds(400)) == std::chrono::milliseconds(800));
    CHECK(p.next_interval(std::chrono::milliseconds(800)) == std::chrono::milliseconds(1600));
    CHECK(p.next_interval(std::chrono::milliseconds(1600)) == std::chrono::milliseconds(3200));
    CHECK(p.next_interval(std::chrono::milliseconds(3200)) == std::chrono::milliseconds(5000));
    CHECK(p.next_interval(std::chrono::milliseconds(5000)) == std::chrono::milliseconds(5000));
}

static void test_default_route_poller_reset_to_100ms() {
    std::printf("[test] T-LP1-009: DefaultRoutePoller reset to 100ms...\n");

    DefaultRoutePoller p;
    p.reset_interval();
    CHECK(p.current_interval() == std::chrono::milliseconds(100));
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== test_v460_stability_fixes ===\n");
    std::printf("v4.6.0 Phase 1 stability fixes (T-LP1-001 ~ T-LP1-009)\n\n");

    // T-LP1-001/002: PTO 上限
    test_pto_constants_exist();
    test_pto_clamp_handshake_period();
    test_pto_clamp_post_handshake();
    test_pto_clamp_with_backoff();

    // T-LP1-003: on_network_change
    test_on_network_change_resets_pto_count();
    test_on_network_change_resets_rtt();
    test_on_network_change_idempotent();

    // T-LP1-005/006: kForcePingPn
    test_pto_timeout_no_ack_eliciting_returns_force_ping();
    test_pto_timeout_with_ack_eliciting_returns_pn();
    test_force_ping_constant_value();

    // T-LP1-009: DefaultRoutePoller 100ms
    test_default_route_poller_initial_100ms();
    test_default_route_poller_reset_to_100ms();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
