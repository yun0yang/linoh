// test_ice_optimizations.cpp — P0-G5 ICE 优化项测试
//
// 验证：
//   1. IceSessionConfig 4 个新字段默认值（全 false）
//   2. G5-1: presume_writable_when_fully_relayed=true，全 relay 对 → Succeeded
//   3. G5-1: 一端 relay 一端 direct → 不跳过（经 checker 检查）
//   4. G5-1: 开关 false → 不跳过
//   5. G5-2: skip_relay_to_non_relay_connections=true，relay↔direct 对被过滤
//   6. G5-2: relay↔relay 和 direct↔direct 对保留
//   7. G5-2: 开关 false → 不过滤
//   8. G5-3: regather_candidates 合并新候选 + 去重
//   9. G5-3: regather_candidates 重建候选对
//  10. G5-4: sort_pairs_by_priority_with_history 高历史命中率排前
//  11. G5-4: history_weight=0 退化为优先级排序
//  12. G5-4: 无历史记录（默认 0.5）保持优先级相对顺序

#include "linoh/nat/ice_session.hpp"

#include <chrono>
#include <cstdio>
#include <future>
#include <utility>
#include <vector>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh;
using namespace linoh::nat;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 辅助函数
// ============================================================================

/// 构造测试用 Candidate
static Candidate make_candidate(CandidateType type, const std::string &host,
                                std::uint16_t port) {
    net::FourTuple tup;
    tup.local_addr.kind = base::TransportKind::Ip;
    tup.local_addr.host = host;
    tup.local_addr.port = port;
    tup.remote_addr.kind = base::TransportKind::Ip;
    tup.remote_addr.host = host;
    tup.remote_addr.port = port;
    std::uint32_t prio = compute_candidate_priority(type);
    std::string found = make_foundation(type, host, port);
    return Candidate(type, tup, prio, found);
}

/// 立即返回失败的 checker（避免测试中 STUN 阻塞）
static ConnectivityChecker make_fail_checker() {
    return [](const CandidatePair &, std::chrono::milliseconds)
           -> std::future<std::pair<bool, std::chrono::milliseconds>> {
        std::promise<std::pair<bool, std::chrono::milliseconds>> p;
        p.set_value({false, std::chrono::milliseconds(0)});
        return p.get_future();
    };
}

/// 短超时配置（避免测试卡住）
static IceSessionConfig short_timeout_config() {
    IceSessionConfig cfg;
    cfg.timeout = std::chrono::milliseconds(500);
    cfg.request_timeout = std::chrono::milliseconds(100);
    cfg.max_parallel_checks = 2;
    return cfg;
}

// ============================================================================
// 测试用例
// ============================================================================

static void test_config_defaults() {
    IceSessionConfig cfg;
    CHECK(cfg.presume_writable_when_fully_relayed == false);
    CHECK(cfg.skip_relay_to_non_relay_connections == false);
    CHECK(cfg.gather_continually == false);
    CHECK(cfg.prioritize_most_likely_candidate_pairs == false);
}

// G5-1: 全 relay 候选对跳过检查标记 Succeeded
static void test_g5_1_fully_relayed_presume_writable() {
    auto local_relay = make_candidate(CandidateType::Relay, "10.0.0.1", 9000);
    auto remote_relay = make_candidate(CandidateType::Relay, "10.0.0.2", 9001);

    auto cfg = short_timeout_config();
    cfg.presume_writable_when_fully_relayed = true;

    IceSession session({local_relay}, {remote_relay}, cfg, make_fail_checker());
    bool ok = session.start_connectivity_checks_sync();

    auto succeeded = session.succeeded_pairs();
    CHECK(succeeded.size() == 1);
    CHECK(succeeded[0].local.type == CandidateType::Relay);
    CHECK(succeeded[0].remote.type == CandidateType::Relay);
    (void)ok;
}

// G5-1: 一端 relay 一端 direct → 不跳过（经 checker 检查，失败）
static void test_g5_1_mixed_not_presumed() {
    auto local_relay = make_candidate(CandidateType::Relay, "10.0.0.1", 9000);
    auto remote_host = make_candidate(CandidateType::Host, "192.168.1.2", 9001);

    auto cfg = short_timeout_config();
    cfg.presume_writable_when_fully_relayed = true;

    IceSession session({local_relay}, {remote_host}, cfg, make_fail_checker());
    session.start_connectivity_checks_sync();

    auto succeeded = session.succeeded_pairs();
    CHECK(succeeded.empty());  // relay↔direct 不跳过，checker 失败 → 无 Succeeded
}

// G5-1: 开关 false → 不跳过（全 relay 对也经 checker 检查，失败）
static void test_g5_1_disabled() {
    auto local_relay = make_candidate(CandidateType::Relay, "10.0.0.1", 9000);
    auto remote_relay = make_candidate(CandidateType::Relay, "10.0.0.2", 9001);

    auto cfg = short_timeout_config();
    cfg.presume_writable_when_fully_relayed = false;  // 关闭

    IceSession session({local_relay}, {remote_relay}, cfg, make_fail_checker());
    session.start_connectivity_checks_sync();

    auto succeeded = session.succeeded_pairs();
    CHECK(succeeded.empty());  // 开关关闭，全 relay 对也经 checker（失败）
}

// G5-2: skip_relay_to_non_relay_connections=true，relay↔direct 对被过滤
static void test_g5_2_filter_relay_direct() {
    auto local_host = make_candidate(CandidateType::Host, "192.168.1.1", 9000);
    auto local_relay = make_candidate(CandidateType::Relay, "10.0.0.1", 9002);
    auto remote_host = make_candidate(CandidateType::Host, "192.168.1.2", 9001);
    auto remote_relay = make_candidate(CandidateType::Relay, "10.0.0.2", 9003);

    auto cfg = short_timeout_config();
    cfg.skip_relay_to_non_relay_connections = true;

    IceSession session({local_host, local_relay}, {remote_host, remote_relay},
                       cfg, make_fail_checker());
    auto pairs = session.candidate_pairs();
    // 只保留 host↔host 和 relay↔relay，过滤 host↔relay 和 relay↔host
    CHECK(pairs.size() == 2);
}

// G5-2: 开关 false → 不过滤（4 个候选对全保留）
static void test_g5_2_no_filter() {
    auto local_host = make_candidate(CandidateType::Host, "192.168.1.1", 9000);
    auto local_relay = make_candidate(CandidateType::Relay, "10.0.0.1", 9002);
    auto remote_host = make_candidate(CandidateType::Host, "192.168.1.2", 9001);
    auto remote_relay = make_candidate(CandidateType::Relay, "10.0.0.2", 9003);

    auto cfg = short_timeout_config();
    cfg.skip_relay_to_non_relay_connections = false;

    IceSession session({local_host, local_relay}, {remote_host, remote_relay},
                       cfg, make_fail_checker());
    auto pairs = session.candidate_pairs();
    CHECK(pairs.size() == 4);  // 2 local × 2 remote = 4
}

// G5-3: regather_candidates 合并新候选 + 去重
static void test_g5_3_regather_merge_dedup() {
    auto local1 = make_candidate(CandidateType::Host, "192.168.1.1", 9000);
    auto remote1 = make_candidate(CandidateType::Host, "192.168.1.2", 9001);

    auto cfg = short_timeout_config();
    IceSession session({local1}, {remote1}, cfg, make_fail_checker());
    CHECK(session.candidate_pairs().size() == 1);

    // regather：新增 1 个 + 重复 1 个（去重）
    auto local2 = make_candidate(CandidateType::Host, "192.168.1.1", 9005);
    session.regather_candidates({local2, local1}, {remote1});

    // local 候选应有 2 个（local1 + local2，local1 重复被去重）
    // remote 候选 1 个（remote1 重复被去重）
    // 候选对 = 2 local × 1 remote = 2
    CHECK(session.candidate_pairs().size() == 2);
}

// G5-3: regather_candidates 重建候选对（应用 G5-2 过滤）
static void test_g5_3_regather_applies_filter() {
    auto local_host = make_candidate(CandidateType::Host, "192.168.1.1", 9000);
    auto remote_host = make_candidate(CandidateType::Host, "192.168.1.2", 9001);

    auto cfg = short_timeout_config();
    cfg.skip_relay_to_non_relay_connections = true;
    IceSession session({local_host}, {remote_host}, cfg, make_fail_checker());
    CHECK(session.candidate_pairs().size() == 1);

    // regather 新增 relay 候选（与 host 配对会被 G5-2 过滤）
    auto local_relay = make_candidate(CandidateType::Relay, "10.0.0.1", 9002);
    session.regather_candidates({local_relay}, {});

    // local: host + relay, remote: host
    // 候选对: host↔host（保留）+ relay↔host（过滤）= 1
    CHECK(session.candidate_pairs().size() == 1);
}

// G5-4: sort_pairs_by_priority_with_history 高历史命中率排前
static void test_g5_4_history_weight_sort() {
    std::vector<CandidatePair> pairs(2);
    pairs[0].priority = 100;  // 低优先级
    pairs[1].priority = 200;  // 高优先级

    // pair[0] 历史命中率 1.0，pair[1] 历史命中率 0.0
    // weight=1.0 时完全按历史排序 → pair[0] 应排前
    sort_pairs_by_priority_with_history(
        pairs,
        [](const CandidatePair &p) -> double {
            return p.priority == 100 ? 1.0 : 0.0;
        },
        1.0);

    CHECK(pairs[0].priority == 100);  // 高历史命中率排前
    CHECK(pairs[1].priority == 200);
}

// G5-4: history_weight=0 退化为优先级排序
static void test_g5_4_weight_zero_degrades() {
    std::vector<CandidatePair> pairs(2);
    pairs[0].priority = 100;
    pairs[1].priority = 200;

    sort_pairs_by_priority_with_history(
        pairs,
        [](const CandidatePair &p) -> double {
            return p.priority == 100 ? 1.0 : 0.0;  // 历史偏向低优先级
        },
        0.0);  // weight=0 → 完全按 priority

    CHECK(pairs[0].priority == 200);  // 高优先级排前
    CHECK(pairs[1].priority == 100);
}

// G5-4: 无历史记录（默认 0.5）保持优先级相对顺序
static void test_g5_4_neutral_history() {
    std::vector<CandidatePair> pairs(3);
    pairs[0].priority = 100;
    pairs[1].priority = 300;
    pairs[2].priority = 200;

    sort_pairs_by_priority_with_history(
        pairs,
        [](const CandidatePair &) -> double { return 0.5; },  // 中性
        0.3);

    // history 相同时，退化为 priority 排序（降序）
    CHECK(pairs[0].priority == 300);
    CHECK(pairs[1].priority == 200);
    CHECK(pairs[2].priority == 100);
}

int main() {
    test_config_defaults();
    test_g5_1_fully_relayed_presume_writable();
    test_g5_1_mixed_not_presumed();
    test_g5_1_disabled();
    test_g5_2_filter_relay_direct();
    test_g5_2_no_filter();
    test_g5_3_regather_merge_dedup();
    test_g5_3_regather_applies_filter();
    test_g5_4_history_weight_sort();
    test_g5_4_weight_zero_degrades();
    test_g5_4_neutral_history();

    std::printf("test_ice_optimizations: %d passed, %d failed\n",
                pass_count, fail_count);
    return fail_count == 0 ? 0 : 1;
}
