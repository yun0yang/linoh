// test_v500_bidir_holepunch.cpp — v5.0.0 T-LP4-004 双向打洞协调器测试
//
// 验证内容：
//   - 多轮打洞状态管理（start_round / abort / mark_succeeded / mark_failed）
//   - PATH_CHALLENGE 跟踪（record_challenge_sent / record_response）
//   - relay 反射地址更新（update_relay_observed_addr）
//   - 双向端口预测（predict_bidirectional_ports）
//   - 超时检测（check_timeout）
//   - 历史轮次清理（prune_history）
//
// 借鉴 iroh 1.0.0-rc.1 noq#672 — Hard-NAT 双向打洞 + Simplified Round Handling

#include "linoh/net/bidirectional_holepuncher.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

using namespace linoh::net;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 轮次管理测试
// ============================================================================

static void test_start_round_basic() {
    std::printf("[test] T-LP4-004: start_round basic...\n");

    BidirectionalHolepuncher hp;
    CHECK(!hp.is_active());
    CHECK(hp.total_rounds() == 0);

    std::vector<std::uint16_t> candidates{50000, 50001, 50002};
    auto id = hp.start_round(candidates);

    CHECK(id == 1);
    CHECK(hp.is_active());
    CHECK(hp.total_rounds() == 1);

    auto current = hp.current_round();
    CHECK(current.has_value());
    CHECK(current->round_id == 1);
    CHECK(current->status == RoundStatus::Active);
    CHECK(current->candidate_ports.size() == 3);
    CHECK(current->candidate_ports[0] == 50000);
}

static void test_new_round_aborts_previous() {
    std::printf("[test] T-LP4-004: new round aborts previous...\n");

    BidirectionalHolepuncher hp;

    hp.start_round({50000, 50001});
    CHECK(hp.is_active());

    hp.start_round({60000, 60001});
    CHECK(hp.is_active());
    CHECK(hp.total_rounds() == 2);

    auto current = hp.current_round();
    CHECK(current.has_value());
    CHECK(current->round_id == 2);

    auto history = hp.history_rounds();
    CHECK(history.size() == 1);
    CHECK(history[0].round_id == 1);
    CHECK(history[0].status == RoundStatus::Aborted);
}

static void test_abort_current_round() {
    std::printf("[test] T-LP4-004: abort current round...\n");

    BidirectionalHolepuncher hp;
    hp.start_round({40000});
    CHECK(hp.is_active());

    hp.abort_current_round();
    CHECK(!hp.is_active());

    auto history = hp.history_rounds();
    CHECK(history.size() == 1);
    CHECK(history[0].status == RoundStatus::Aborted);
}

static void test_mark_succeeded() {
    std::printf("[test] T-LP4-004: mark_succeeded...\n");

    BidirectionalHolepuncher hp;
    hp.start_round({50000, 50001, 50002});
    CHECK(hp.is_active());

    hp.mark_succeeded(50001);
    CHECK(!hp.is_active());

    auto success = hp.successful_round();
    CHECK(success.has_value());
    CHECK(success->round_id == 1);
    CHECK(success->status == RoundStatus::Succeeded);
    CHECK(success->responded_ports.back() == 50001);
}

static void test_mark_failed() {
    std::printf("[test] T-LP4-004: mark_failed...\n");

    BidirectionalHolepuncher hp;
    hp.start_round({50000});
    CHECK(hp.is_active());

    hp.mark_failed();
    CHECK(!hp.is_active());

    auto history = hp.history_rounds();
    CHECK(history.size() == 1);
    CHECK(history[0].status == RoundStatus::Failed);
}

// ============================================================================
// PATH_CHALLENGE 跟踪测试
// ============================================================================

static void test_record_challenge_sent() {
    std::printf("[test] T-LP4-004: record_challenge_sent...\n");

    BidirectionalHolepuncher hp;
    hp.start_round({50000, 50001});

    // 首次发送 — 应返回 true
    CHECK(hp.record_challenge_sent(50000));
    // 重复发送 — 应返回 false
    CHECK(!hp.record_challenge_sent(50000));
    // 不同端口 — 应返回 true
    CHECK(hp.record_challenge_sent(50001));

    auto current = hp.current_round();
    CHECK(current.has_value());
    CHECK(current->sent_challenge_ports.size() == 2);
}

static void test_record_response_match() {
    std::printf("[test] T-LP4-004: record_response match...\n");

    BidirectionalHolepuncher hp;
    hp.start_round({50000, 50001});

    hp.record_challenge_sent(50000);
    hp.record_challenge_sent(50001);

    // 匹配已发送的端口
    CHECK(hp.record_response(50000));
    CHECK(hp.record_response(50001));

    // 未发送的端口 — 不匹配
    CHECK(!hp.record_response(59999));

    auto current = hp.current_round();
    CHECK(current.has_value());
    CHECK(current->responded_ports.size() == 2);
}

static void test_challenge_no_active_round() {
    std::printf("[test] T-LP4-004: challenge with no active round...\n");

    BidirectionalHolepuncher hp;
    // 无活跃轮次
    CHECK(!hp.record_challenge_sent(50000));
    CHECK(!hp.record_response(50000));
}

// ============================================================================
// relay 反射地址测试
// ============================================================================

static void test_update_relay_observed_addr() {
    std::printf("[test] T-LP4-004: update_relay_observed_addr...\n");

    BidirectionalHolepuncher hp;
    hp.start_round({50000});

    hp.update_relay_observed_addr("203.0.113.42", 54321);

    auto current = hp.current_round();
    CHECK(current.has_value());
    CHECK(current->relay_observed_host == "203.0.113.42");
    CHECK(current->relay_observed_port == 54321);
}

// ============================================================================
// 双向端口预测测试
// ============================================================================

static void test_predict_bidirectional_ports() {
    std::printf("[test] T-LP4-004: predict_bidirectional_ports...\n");

    // 本端观测：30000, 30002 (delta=2)
    // 对端观测：50000, 50005 (delta=5)
    auto [predicted_remote, predicted_local] =
        BidirectionalHolepuncher::predict_bidirectional_ports(
            30000, 30002, 50000, 50005, 5);

    CHECK(!predicted_remote.empty());
    CHECK(!predicted_local.empty());
    CHECK(predicted_remote.size() == 5);
    CHECK(predicted_local.size() == 5);

    // 对端端口预测应基于 50000, 50005 (delta=5)
    // 第一个预测 = 50005 + 5 = 50010
    CHECK(predicted_remote[0] == 50010);

    // 本端端口预测应基于 30000, 30002 (delta=2)
    // 第一个预测 = 30002 + 2 = 30004
    CHECK(predicted_local[0] == 30004);
}

static void test_predict_bidirectional_same_delta() {
    std::printf("[test] T-LP4-004: predict_bidirectional same delta...\n");

    // 双方端口增量相同
    auto [predicted_remote, predicted_local] =
        BidirectionalHolepuncher::predict_bidirectional_ports(
            40000, 40001, 60000, 60001, 3);

    CHECK(predicted_remote.size() == 3);
    CHECK(predicted_local.size() == 3);

    // delta=1，预测 = last + 1
    CHECK(predicted_remote[0] == 60002);
    CHECK(predicted_local[0] == 40002);
}

// ============================================================================
// 超时检测测试
// ============================================================================

static void test_check_timeout() {
    std::printf("[test] T-LP4-004: check_timeout...\n");

    BidirectionalHolepuncher hp;
    hp.start_round({50000});

    // 短超时 — 等待后应触发
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    bool timed_out = hp.check_timeout(std::chrono::milliseconds(50));
    CHECK(timed_out);
    CHECK(!hp.is_active());

    auto history = hp.history_rounds();
    CHECK(history.size() == 1);
    CHECK(history[0].status == RoundStatus::Failed);
}

static void test_check_timeout_not_expired() {
    std::printf("[test] T-LP4-004: check_timeout not expired...\n");

    BidirectionalHolepuncher hp;
    hp.start_round({50000});

    // 长超时 — 不应触发
    bool timed_out = hp.check_timeout(std::chrono::seconds(10));
    CHECK(!timed_out);
    CHECK(hp.is_active());
}

// ============================================================================
// 历史轮次清理测试
// ============================================================================

static void test_prune_history() {
    std::printf("[test] T-LP4-004: prune_history...\n");

    BidirectionalHolepuncher hp;

    // 创建超过 kMaxHistoryRounds 的轮次
    for (std::size_t i = 0; i < BidirectionalHolepuncher::kMaxHistoryRounds + 5; ++i) {
        hp.start_round({static_cast<std::uint16_t>(50000 + i)});
        // 立即中止（变为历史轮次）
        hp.abort_current_round();
    }

    // 再开一个活跃轮次
    hp.start_round({60000});

    auto history = hp.history_rounds();
    // 历史轮次应不超过 kMaxHistoryRounds
    CHECK(history.size() <= BidirectionalHolepuncher::kMaxHistoryRounds);
    CHECK(hp.is_active());
}

// ============================================================================
// 多轮打洞场景测试
// ============================================================================

static void test_multi_round_scenario() {
    std::printf("[test] T-LP4-004: multi-round scenario...\n");

    BidirectionalHolepuncher hp;

    // 轮次 1：初始候选
    hp.start_round({50000, 50001});
    hp.record_challenge_sent(50000);
    hp.record_challenge_sent(50001);

    // 超时，轮次 1 失败
    hp.mark_failed();

    // 轮次 2：新地址到来，开启新轮
    hp.start_round({51000, 51001, 51002});
    hp.update_relay_observed_addr("203.0.113.50", 55555);
    hp.record_challenge_sent(51000);

    // 收到 PATH_RESPONSE — 成功
    CHECK(hp.record_response(51000));
    hp.mark_succeeded(51000);

    CHECK(!hp.is_active());

    auto success = hp.successful_round();
    CHECK(success.has_value());
    CHECK(success->round_id == 2);
    CHECK(success->status == RoundStatus::Succeeded);
    CHECK(success->relay_observed_host == "203.0.113.50");
    CHECK(success->relay_observed_port == 55555);

    auto history = hp.history_rounds();
    CHECK(history.size() == 2);
    CHECK(history[0].round_id == 1);
    CHECK(history[0].status == RoundStatus::Failed);
    CHECK(history[1].round_id == 2);
    CHECK(history[1].status == RoundStatus::Succeeded);
}

// ============================================================================
// HolepunchRound::to_string 测试
// ============================================================================

static void test_round_to_string() {
    std::printf("[test] T-LP4-004: HolepunchRound::to_string...\n");

    HolepunchRound r;
    r.round_id = 42;
    r.status = RoundStatus::Active;
    r.start_time = std::chrono::steady_clock::now();
    r.candidate_ports = {50000, 50001};
    r.sent_challenge_ports = {50000};
    r.relay_observed_host = "203.0.113.1";
    r.relay_observed_port = 12345;

    auto s = r.to_string();
    CHECK(s.find("Round#42") != std::string::npos);
    CHECK(s.find("Active") != std::string::npos);
    CHECK(s.find("candidates=2") != std::string::npos);
    CHECK(s.find("sent=1") != std::string::npos);
    CHECK(s.find("relay_obs=203.0.113.1:12345") != std::string::npos);
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== v5.0.0 T-LP4-004 Bidirectional Holepuncher Tests ===\n\n");

    test_start_round_basic();
    test_new_round_aborts_previous();
    test_abort_current_round();
    test_mark_succeeded();
    test_mark_failed();

    test_record_challenge_sent();
    test_record_response_match();
    test_challenge_no_active_round();

    test_update_relay_observed_addr();

    test_predict_bidirectional_ports();
    test_predict_bidirectional_same_delta();

    test_check_timeout();
    test_check_timeout_not_expired();

    test_prune_history();

    test_multi_round_scenario();

    test_round_to_string();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
