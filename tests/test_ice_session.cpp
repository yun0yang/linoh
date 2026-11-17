// test_ice_session.cpp — P5-D-2 ICE 连接检查 + 提名测试
//
// 验证：
//   1. IceRole / CandidatePairState 枚举和字符串转换
//   2. compute_pair_priority 公式（RFC 8445 §6.1.2.3）
//   3. CandidatePair 结构和比较
//   4. form_candidate_pairs 候选对形成
//   5. 地址族兼容性过滤（IPv4/IPv6）
//   6. 连接检查状态机（Waiting → InProgress → Succeeded/Failed）
//   7. 并行检查
//   8. Controlling 提名最高优先级成功对
//   9. Controlled 接受提名
//  10. 触发检查（triggered check）
//  11. 动态添加候选
//  12. 提名策略（优先级 vs 延迟）
//  13. 错误处理
//  14. 工具函数

#include "linoh/nat/ice_session.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#define CHECK(cond) do { \
    if (!(cond)) { \
        std::printf("FAIL line %d: %s\n", __LINE__, #cond); \
        ++fail_count; \
    } else { ++pass_count; } \
} while (0)

using namespace linoh;
using namespace linoh::nat;
using namespace linoh::base;
using namespace linoh::net;

static int pass_count = 0;
static int fail_count = 0;

// ============================================================================
// 辅助函数
// ============================================================================

static Candidate make_host(const std::string &ip, std::uint16_t port = 0) {
    TransportAddr local;
    local.kind = TransportKind::Ip;
    local.host = ip;
    local.port = port;
    TransportAddr remote = local;

    FourTuple tuple;
    tuple.local_addr = local;
    tuple.remote_addr = remote;

    Candidate c;
    c.type = CandidateType::Host;
    c.tuple = tuple;
    c.priority = compute_candidate_priority(CandidateType::Host);
    c.foundation = make_foundation(CandidateType::Host, ip, port);
    return c;
}

static Candidate make_srflx(const std::string &public_ip, std::uint16_t public_port) {
    TransportAddr local;
    local.kind = TransportKind::Ip;
    local.host = public_ip;
    local.port = public_port;
    TransportAddr remote = local;

    FourTuple tuple;
    tuple.local_addr = local;
    tuple.remote_addr = remote;

    Candidate c;
    c.type = CandidateType::ServerReflexive;
    c.tuple = tuple;
    c.priority = compute_candidate_priority(CandidateType::ServerReflexive);
    c.foundation = make_foundation(CandidateType::ServerReflexive, public_ip, public_port);
    return c;
}

static Candidate make_relay(const std::string &host, std::uint16_t port) {
    TransportAddr addr;
    addr.kind = TransportKind::Relay;
    addr.host = host;
    addr.port = port;

    FourTuple tuple;
    tuple.local_addr = addr;
    tuple.remote_addr = addr;

    Candidate c;
    c.type = CandidateType::Relay;
    c.tuple = tuple;
    c.priority = compute_candidate_priority(CandidateType::Relay);
    c.foundation = make_foundation(CandidateType::Relay, host, port);
    c.is_relayed = true;
    return c;
}

static ConnectivityChecker make_always_success_checker(std::chrono::milliseconds rtt = std::chrono::milliseconds(50)) {
    return [rtt](const CandidatePair &,
                 std::chrono::milliseconds) {
        return std::async(std::launch::async, [rtt]() {
            std::this_thread::sleep_for(rtt);
            return std::make_pair(true, rtt);
        });
    };
}

static ConnectivityChecker make_always_fail_checker() {
    return [](const CandidatePair &,
              std::chrono::milliseconds) {
        return std::async(std::launch::async, []() {
            return std::make_pair(false, std::chrono::milliseconds(0));
        });
    };
}

static ConnectivityChecker make_selective_checker(
    std::function<bool(const CandidatePair &)> pred,
    std::chrono::milliseconds rtt = std::chrono::milliseconds(50)) {
    return [pred, rtt](const CandidatePair &pair,
                       std::chrono::milliseconds) {
        return std::async(std::launch::async, [pair, pred, rtt]() {
            std::this_thread::sleep_for(rtt);
            bool ok = pred(pair);
            return std::make_pair(ok, ok ? rtt : std::chrono::milliseconds(0));
        });
    };
}

// ============================================================================
// 1. IceRole / CandidatePairState 枚举和字符串转换
// ============================================================================

static void test_ice_role_name() {
    CHECK(std::string(ice_role_name(IceRole::Controlling)) == "controlling");
    CHECK(std::string(ice_role_name(IceRole::Controlled)) == "controlled");
}

static void test_pair_state_name() {
    CHECK(std::string(pair_state_name(CandidatePairState::Waiting)) == "waiting");
    CHECK(std::string(pair_state_name(CandidatePairState::InProgress)) == "in-progress");
    CHECK(std::string(pair_state_name(CandidatePairState::Succeeded)) == "succeeded");
    CHECK(std::string(pair_state_name(CandidatePairState::Failed)) == "failed");
    CHECK(std::string(pair_state_name(CandidatePairState::Frozen)) == "frozen");
}

// ============================================================================
// 2. compute_pair_priority 公式（RFC 8445 §6.1.2.3）
// ============================================================================

static void test_pair_priority_basic() {
    // Controlling: pair_priority = (2^32) * min(G, D) + 2 * max(G, D) + (G > D ? 1 : 0)
    std::uint32_t local = 1000;
    std::uint32_t remote = 500;
    std::uint64_t prio = compute_pair_priority(local, remote, IceRole::Controlling);

    // G=1000, D=500
    // min=500, max=1000, G>D → 1
    std::uint64_t expected = (1ULL << 32) * 500 + 2 * 1000 + 1;
    CHECK(prio == expected);
}

static void test_pair_priority_controlled_role() {
    // Controlled: tie_breaker = (G > D ? 0 : 1)
    std::uint32_t local = 1000;
    std::uint32_t remote = 500;
    std::uint64_t prio_ctrl = compute_pair_priority(local, remote, IceRole::Controlling);
    std::uint64_t prio_ctrld = compute_pair_priority(local, remote, IceRole::Controlled);

    // Controlling: tie=1, Controlled: tie=0
    CHECK(prio_ctrl == prio_ctrld + 1);
}

static void test_pair_priority_local_less() {
    // G < D 的情况
    std::uint32_t local = 500;
    std::uint32_t remote = 1000;
    std::uint64_t prio = compute_pair_priority(local, remote, IceRole::Controlling);

    // min=500, max=1000, G<D → 0
    std::uint64_t expected = (1ULL << 32) * 500 + 2 * 1000 + 0;
    CHECK(prio == expected);
}

static void test_pair_priority_equal() {
    // G == D 的情况
    std::uint32_t local = 1000;
    std::uint32_t remote = 1000;
    std::uint64_t prio = compute_pair_priority(local, remote, IceRole::Controlling);

    // min=1000, max=1000, G>D → 0 (相等不算大于)
    std::uint64_t expected = (1ULL << 32) * 1000 + 2 * 1000 + 0;
    CHECK(prio == expected);
}

static void test_pair_priority_ordering() {
    // 高 local + 高 remote → 高 pair priority
    std::uint64_t high_high = compute_pair_priority(1000, 1000, IceRole::Controlling);
    std::uint64_t high_low = compute_pair_priority(1000, 100, IceRole::Controlling);
    std::uint64_t low_high = compute_pair_priority(100, 1000, IceRole::Controlling);
    std::uint64_t low_low = compute_pair_priority(100, 100, IceRole::Controlling);

    CHECK(high_high > high_low);
    CHECK(high_high > low_high);
    CHECK(high_high > low_low);
    CHECK(high_low > low_low);
    CHECK(low_high > low_low);

    // high_low vs low_high：min 都是 100，max 都是 1000，但 Controlling 角色下
    // high_low (G>D): tie=1
    // low_high (G<D): tie=0
    CHECK(high_low > low_high);
}

// ============================================================================
// 3. CandidatePair 结构和比较
// ============================================================================

static void test_candidate_pair_default_construct() {
    CandidatePair pair;
    CHECK(pair.priority == 0);
    CHECK(pair.state == CandidatePairState::Waiting);
    CHECK(pair.nominated == false);
    CHECK(pair.rtt.count() == 0);
    CHECK(pair.request_count == 0);
}

static void test_candidate_pair_full_construct() {
    Candidate local = make_host("192.168.1.1", 5000);
    Candidate remote = make_host("10.0.0.1", 6000);
    CandidatePair pair(local, remote);
    CHECK(pair.local == local);
    CHECK(pair.remote == remote);
}

static void test_candidate_pair_operator_less() {
    Candidate local1 = make_host("1.1.1.1");
    Candidate local2 = make_host("2.2.2.2");
    Candidate remote = make_host("3.3.3.3");

    CandidatePair p1(local1, remote);
    p1.priority = 1000;
    CandidatePair p2(local2, remote);
    p2.priority = 500;

    // priority 高的排前面（< 表示排序时在前）
    CHECK(p1 < p2);
}

static void test_candidate_pair_operator_equal() {
    Candidate local = make_host("1.1.1.1", 100);
    Candidate remote = make_host("2.2.2.2", 200);

    CandidatePair p1(local, remote);
    CandidatePair p2(local, remote);
    CHECK(p1 == p2);
}

static void test_candidate_pair_to_string() {
    Candidate local = make_host("192.168.1.1", 5000);
    Candidate remote = make_srflx("203.0.113.1", 12345);
    CandidatePair pair(local, remote);
    pair.state = CandidatePairState::Succeeded;
    pair.rtt = std::chrono::milliseconds(75);
    pair.nominated = true;

    std::string s = pair.to_string();
    CHECK(s.find("state=succeeded") != std::string::npos);
    CHECK(s.find("rtt=75ms") != std::string::npos);
    CHECK(s.find("nominated=true") != std::string::npos);
}

// ============================================================================
// 4. form_candidate_pairs 候选对形成
// ============================================================================

static void test_form_pairs_basic() {
    std::vector<Candidate> locals = {
        make_host("192.168.1.1", 5000),
        make_host("192.168.1.2", 5000),
    };
    std::vector<Candidate> remotes = {
        make_host("10.0.0.1", 6000),
    };

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config);

    auto pairs = session.candidate_pairs();
    CHECK(pairs.size() == 2);  // 2 locals × 1 remote = 2 pairs
}

static void test_form_pairs_cross_product() {
    std::vector<Candidate> locals = {
        make_host("1.1.1.1"),
        make_host("2.2.2.2"),
    };
    std::vector<Candidate> remotes = {
        make_host("3.3.3.3"),
        make_host("4.4.4.4"),
        make_host("5.5.5.5"),
    };

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config);

    auto pairs = session.candidate_pairs();
    CHECK(pairs.size() == 6);  // 2 × 3 = 6
}

static void test_form_pairs_sorted_by_priority() {
    // Host 优先级 > Srflx > Relay
    std::vector<Candidate> locals = {
        make_relay("relay.example.com", 9002),  // 低
        make_host("1.1.1.1"),                   // 高
        make_srflx("203.0.113.1", 12345),       // 中
    };
    std::vector<Candidate> remotes = {
        make_host("2.2.2.2"),
    };

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config);

    auto pairs = session.candidate_pairs();
    CHECK(pairs.size() == 3);
    // 按优先级降序：Host > Srflx > Relay
    CHECK(pairs[0].local.type == CandidateType::Host);
    CHECK(pairs[1].local.type == CandidateType::ServerReflexive);
    CHECK(pairs[2].local.type == CandidateType::Relay);
}

// ============================================================================
// 5. 地址族兼容性过滤
// ============================================================================

static void test_form_pairs_ipv4_ipv6_filter() {
    std::vector<Candidate> locals = {
        make_host("192.168.1.1"),       // IPv4
        make_host("fd00::1"),           // IPv6
    };
    std::vector<Candidate> remotes = {
        make_host("10.0.0.1"),          // IPv4
        make_host("fd00::2"),           // IPv6
    };

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config);

    auto pairs = session.candidate_pairs();
    // 应该有 2 对（IPv4-IPv4 + IPv6-IPv6），过滤掉 IPv4-IPv6 和 IPv6-IPv4
    CHECK(pairs.size() == 2);
}

static void test_form_pairs_all_ipv4() {
    std::vector<Candidate> locals = {
        make_host("1.1.1.1"),
        make_host("2.2.2.2"),
        make_host("3.3.3.3"),
    };
    std::vector<Candidate> remotes = {
        make_host("4.4.4.4"),
        make_host("5.5.5.5"),
    };

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config);

    auto pairs = session.candidate_pairs();
    CHECK(pairs.size() == 6);  // 3 × 2 = 6（全部 IPv4 兼容）
}

// ============================================================================
// 6. 连接检查状态机
// ============================================================================

static void test_check_state_machine_success() {
    std::vector<Candidate> locals = {make_host("1.1.1.1")};
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(500);
    config.request_timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config, make_always_success_checker());

    bool ok = session.start_connectivity_checks_sync();
    CHECK(ok == true);

    auto succeeded = session.succeeded_pairs();
    CHECK(succeeded.size() == 1);
    CHECK(succeeded[0].state == CandidatePairState::Succeeded);
    CHECK(succeeded[0].rtt.count() > 0);
}

static void test_check_state_machine_failure() {
    std::vector<Candidate> locals = {make_host("1.1.1.1")};
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(500);
    config.request_timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config, make_always_fail_checker());

    bool ok = session.start_connectivity_checks_sync();
    CHECK(ok == false);

    auto failed = session.failed_pairs();
    CHECK(failed.size() == 1);
    CHECK(failed[0].state == CandidatePairState::Failed);
}

static void test_check_mixed_success_failure() {
    std::vector<Candidate> locals = {
        make_host("1.1.1.1"),  // 会成功
        make_host("3.3.3.3"),  // 会失败
    };
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    // 局部地址 1.1.1.1 的候选对成功，3.3.3.3 失败
    auto checker = make_selective_checker([](const CandidatePair &pair) {
        return pair.local.tuple.local_addr.host == "1.1.1.1";
    });

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(500);
    config.request_timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config, checker);

    bool ok = session.start_connectivity_checks_sync();
    CHECK(ok == true);

    auto succeeded = session.succeeded_pairs();
    auto failed = session.failed_pairs();
    CHECK(succeeded.size() == 1);
    CHECK(failed.size() == 1);
}

// ============================================================================
// 7. 并行检查
// ============================================================================

static void test_parallel_checks() {
    std::vector<Candidate> locals;
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};
    for (int i = 0; i < 5; ++i) {
        locals.push_back(make_host("1.1.1." + std::to_string(i + 1)));
    }

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(1000);
    config.request_timeout = std::chrono::milliseconds(200);
    config.max_parallel_checks = 5;
    IceSession session(locals, remotes, config, make_always_success_checker(std::chrono::milliseconds(100)));

    auto start = std::chrono::steady_clock::now();
    bool ok = session.start_connectivity_checks_sync();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    CHECK(ok == true);
    // 5 个候选对并行，每个 100ms，总计应接近 100ms 而非 500ms
    CHECK(elapsed.count() < 400);  // 容忍调度开销
}

// ============================================================================
// 8. Controlling 提名最高优先级成功对
// ============================================================================

static void test_controlling_nominate_best() {
    std::vector<Candidate> locals = {
        make_host("1.1.1.1"),            // 高优先级
        make_srflx("203.0.113.1", 12345),  // 中优先级
        make_relay("relay.com", 9002),   // 低优先级
    };
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    IceSessionConfig config;
    config.role = IceRole::Controlling;
    config.timeout = std::chrono::milliseconds(500);
    config.request_timeout = std::chrono::milliseconds(100);
    config.enable_nomination = true;
    config.nominate_by_priority = true;
    IceSession session(locals, remotes, config, make_always_success_checker());

    bool ok = session.start_connectivity_checks_sync();
    CHECK(ok == true);

    auto nominated = session.nominated_pair();
    CHECK(nominated.has_value());
    CHECK(nominated->nominated == true);
    // 应提名最高优先级成功的候选对（Host）
    CHECK(nominated->local.type == CandidateType::Host);
}

static void test_controlling_no_nomination_when_disabled() {
    std::vector<Candidate> locals = {make_host("1.1.1.1")};
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    IceSessionConfig config;
    config.role = IceRole::Controlling;
    config.timeout = std::chrono::milliseconds(500);
    config.request_timeout = std::chrono::milliseconds(100);
    config.enable_nomination = false;  // 禁用自动提名
    IceSession session(locals, remotes, config, make_always_success_checker());

    bool ok = session.start_connectivity_checks_sync();
    CHECK(ok == true);

    auto nominated = session.nominated_pair();
    CHECK(!nominated.has_value());  // 禁用提名，应无提名
}

// ============================================================================
// 9. Controlled 接受提名
// ============================================================================

static void test_controlled_no_auto_nominate() {
    std::vector<Candidate> locals = {make_host("1.1.1.1")};
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    IceSessionConfig config;
    config.role = IceRole::Controlled;  // Controlled 角色
    config.timeout = std::chrono::milliseconds(500);
    config.request_timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config, make_always_success_checker());

    bool ok = session.start_connectivity_checks_sync();
    CHECK(ok == true);

    // Controlled 角色不应自动提名
    auto nominated = session.nominated_pair();
    CHECK(!nominated.has_value());
}

static void test_controlled_accept_manual_nominate() {
    std::vector<Candidate> locals = {make_host("1.1.1.1")};
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    IceSessionConfig config;
    config.role = IceRole::Controlled;
    config.timeout = std::chrono::milliseconds(500);
    config.request_timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config, make_always_success_checker());

    session.start_connectivity_checks_sync();

    // Controlled 接收对端提名（手动调用）
    auto succeeded = session.succeeded_pairs();
    CHECK(!succeeded.empty());

    bool ok = session.nominate_pair(succeeded[0]);
    CHECK(ok == true);

    auto nominated = session.nominated_pair();
    CHECK(nominated.has_value());
}

// ============================================================================
// 10. 触发检查（triggered check）
// ============================================================================

static void test_trigger_check_existing_pair() {
    std::vector<Candidate> locals = {make_host("1.1.1.1")};
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config, make_always_fail_checker());

    // 先跑一轮让所有对 Failed
    session.start_connectivity_checks_sync();
    auto failed = session.failed_pairs();
    CHECK(!failed.empty());

    // 触发检查：Failed 状态应转为 Waiting
    session.trigger_check(failed[0]);

    auto pairs = session.candidate_pairs();
    bool has_waiting = false;
    for (const auto &p : pairs) {
        if (p.state == CandidatePairState::Waiting) {
            has_waiting = true;
            break;
        }
    }
    CHECK(has_waiting);
}

static void test_trigger_check_new_pair() {
    std::vector<Candidate> locals = {make_host("1.1.1.1")};
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config, make_always_fail_checker());

    auto pairs_before = session.candidate_pairs();
    CHECK(pairs_before.size() == 1);

    // 触发检查一个不存在的候选对
    Candidate new_local = make_host("3.3.3.3");
    Candidate new_remote = make_host("4.4.4.4");
    CandidatePair new_pair(new_local, new_remote);
    session.trigger_check(new_pair);

    auto pairs_after = session.candidate_pairs();
    CHECK(pairs_after.size() == 2);  // 新增 1 对
}

// ============================================================================
// 11. 动态添加候选
// ============================================================================

static void test_add_local_candidate() {
    std::vector<Candidate> locals = {make_host("1.1.1.1")};
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config);

    CHECK(session.candidate_pairs().size() == 1);

    session.add_local_candidate(make_host("3.3.3.3"));
    CHECK(session.candidate_pairs().size() == 2);
}

static void test_add_remote_candidate() {
    std::vector<Candidate> locals = {make_host("1.1.1.1")};
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config);

    CHECK(session.candidate_pairs().size() == 1);

    session.add_remote_candidate(make_host("4.4.4.4"));
    CHECK(session.candidate_pairs().size() == 2);
}

// ============================================================================
// 12. 提名策略（优先级 vs 延迟）
// ============================================================================

static void test_nominate_by_rtt() {
    std::vector<Candidate> locals = {
        make_host("1.1.1.1"),  // 优先级高，但延迟长
        make_srflx("203.0.113.1", 12345),  // 优先级中，但延迟短
    };
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    // Host 候选对延迟 200ms，Srflx 候选对延迟 50ms
    auto checker = make_selective_checker(
        [](const CandidatePair &) { return true; },
        std::chrono::milliseconds(10));

    // 用自定义 checker 让不同候选对有不同 RTT
    auto custom_checker = [](const CandidatePair &pair,
                              std::chrono::milliseconds) {
        return std::async(std::launch::async, [pair]() {
            std::chrono::milliseconds rtt;
            if (pair.local.type == CandidateType::Host) {
                rtt = std::chrono::milliseconds(200);
                std::this_thread::sleep_for(std::chrono::milliseconds(20));  // 加速测试
            } else {
                rtt = std::chrono::milliseconds(50);
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            return std::make_pair(true, rtt);
        });
    };

    IceSessionConfig config;
    config.role = IceRole::Controlling;
    config.timeout = std::chrono::milliseconds(1000);
    config.request_timeout = std::chrono::milliseconds(500);
    config.nominate_by_priority = false;  // 按延迟提名
    IceSession session(locals, remotes, config, custom_checker);

    bool ok = session.start_connectivity_checks_sync();
    CHECK(ok == true);

    auto nominated = session.nominated_pair();
    CHECK(nominated.has_value());
    // 按 RTT 提名，应选 Srflx（50ms < 200ms）
    CHECK(nominated->local.type == CandidateType::ServerReflexive);
}

// ============================================================================
// 13. 错误处理
// ============================================================================

static void test_checker_exception() {
    std::vector<Candidate> locals = {make_host("1.1.1.1")};
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    auto throwing_checker = [](const CandidatePair &,
                                std::chrono::milliseconds) {
        return std::async(std::launch::async, []() -> std::pair<bool, std::chrono::milliseconds> {
            throw std::runtime_error("checker failed");
        });
    };

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(500);
    config.request_timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config, throwing_checker);

    bool ok = session.start_connectivity_checks_sync();
    CHECK(ok == false);

    auto failed = session.failed_pairs();
    CHECK(failed.size() == 1);
}

static void test_empty_candidates() {
    std::vector<Candidate> locals;
    std::vector<Candidate> remotes;

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config);

    CHECK(session.candidate_pairs().empty());

    bool ok = session.start_connectivity_checks_sync();
    CHECK(ok == false);
}

// ============================================================================
// 14. 工具函数
// ============================================================================

static void test_sort_pairs_by_priority() {
    std::vector<CandidatePair> pairs;
    CandidatePair p1;
    p1.priority = 100;
    CandidatePair p2;
    p2.priority = 500;
    CandidatePair p3;
    p3.priority = 300;

    pairs = {p1, p2, p3};
    sort_pairs_by_priority(pairs);

    CHECK(pairs[0].priority == 500);
    CHECK(pairs[1].priority == 300);
    CHECK(pairs[2].priority == 100);
}

static void test_sort_pairs_by_rtt() {
    std::vector<CandidatePair> pairs;
    CandidatePair p1; p1.rtt = std::chrono::milliseconds(200);
    CandidatePair p2; p2.rtt = std::chrono::milliseconds(50);
    CandidatePair p3; p3.rtt = std::chrono::milliseconds(150);

    pairs = {p1, p2, p3};
    sort_pairs_by_rtt(pairs);

    CHECK(pairs[0].rtt.count() == 50);
    CHECK(pairs[1].rtt.count() == 150);
    CHECK(pairs[2].rtt.count() == 200);
}

static void test_count_pairs_by_state() {
    std::vector<CandidatePair> pairs;
    CandidatePair p1; p1.state = CandidatePairState::Waiting;
    CandidatePair p2; p2.state = CandidatePairState::Succeeded;
    CandidatePair p3; p3.state = CandidatePairState::Succeeded;
    CandidatePair p4; p4.state = CandidatePairState::Failed;
    CandidatePair p5; p5.state = CandidatePairState::InProgress;
    CandidatePair p6; p6.state = CandidatePairState::Frozen;
    pairs = {p1, p2, p3, p4, p5, p6};

    auto cnt = count_pairs_by_state(pairs);
    CHECK(cnt.waiting == 1);
    CHECK(cnt.succeeded == 2);
    CHECK(cnt.failed == 1);
    CHECK(cnt.in_progress == 1);
    CHECK(cnt.frozen == 1);
}

static void test_reset_session() {
    std::vector<Candidate> locals = {make_host("1.1.1.1")};
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(500);
    config.request_timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config, make_always_success_checker());

    session.start_connectivity_checks_sync();
    CHECK(session.is_completed() == true);

    session.reset();
    CHECK(session.is_completed() == false);
    CHECK(session.candidate_pairs().empty());
    CHECK(!session.nominated_pair().has_value());
}

static void test_nominate_non_succeeded_fails() {
    std::vector<Candidate> locals = {make_host("1.1.1.1")};
    std::vector<Candidate> remotes = {make_host("2.2.2.2")};

    IceSessionConfig config;
    config.timeout = std::chrono::milliseconds(500);
    config.request_timeout = std::chrono::milliseconds(100);
    IceSession session(locals, remotes, config, make_always_fail_checker());

    session.start_connectivity_checks_sync();

    // 尝试手动提名 Failed 的候选对，应失败
    auto failed = session.failed_pairs();
    CHECK(!failed.empty());
    bool ok = session.nominate_pair(failed[0]);
    CHECK(ok == false);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::printf("=== P5-D-2 ICE Session Tests ===\n\n");

    std::printf("[1] IceRole / CandidatePairState 枚举和字符串转换\n");
    test_ice_role_name();
    test_pair_state_name();
    std::printf("  pass=%d fail=%d\n\n", pass_count, fail_count);

    auto saved_pass = pass_count;
    auto saved_fail = fail_count;

    std::printf("[2] compute_pair_priority 公式\n");
    test_pair_priority_basic();
    test_pair_priority_controlled_role();
    test_pair_priority_local_less();
    test_pair_priority_equal();
    test_pair_priority_ordering();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[3] CandidatePair 结构和比较\n");
    test_candidate_pair_default_construct();
    test_candidate_pair_full_construct();
    test_candidate_pair_operator_less();
    test_candidate_pair_operator_equal();
    test_candidate_pair_to_string();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[4] form_candidate_pairs 候选对形成\n");
    test_form_pairs_basic();
    test_form_pairs_cross_product();
    test_form_pairs_sorted_by_priority();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[5] 地址族兼容性过滤\n");
    test_form_pairs_ipv4_ipv6_filter();
    test_form_pairs_all_ipv4();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[6] 连接检查状态机\n");
    test_check_state_machine_success();
    test_check_state_machine_failure();
    test_check_mixed_success_failure();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[7] 并行检查\n");
    test_parallel_checks();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[8] Controlling 提名最高优先级成功对\n");
    test_controlling_nominate_best();
    test_controlling_no_nomination_when_disabled();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[9] Controlled 接受提名\n");
    test_controlled_no_auto_nominate();
    test_controlled_accept_manual_nominate();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[10] 触发检查\n");
    test_trigger_check_existing_pair();
    test_trigger_check_new_pair();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[11] 动态添加候选\n");
    test_add_local_candidate();
    test_add_remote_candidate();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[12] 提名策略（优先级 vs 延迟）\n");
    test_nominate_by_rtt();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[13] 错误处理\n");
    test_checker_exception();
    test_empty_candidates();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[14] 工具函数\n");
    test_sort_pairs_by_priority();
    test_sort_pairs_by_rtt();
    test_count_pairs_by_state();
    test_reset_session();
    test_nominate_non_succeeded_fails();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);

    std::printf("=== Summary ===\n");
    std::printf("Total: pass=%d fail=%d\n", pass_count, fail_count);

    return fail_count == 0 ? 0 : 1;
}
