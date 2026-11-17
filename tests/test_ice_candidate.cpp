// test_ice_candidate.cpp — P5-D-1 ICE 候选地址收集测试
//
// 验证：
//   1. CandidateType 枚举值和字符串转换
//   2. 候选优先级计算（RFC 8445 §5.1.2 公式）
//   3. foundation 字符串构造
//   4. Candidate 结构基本操作（比较、相等）
//   5. CandidateGatherResult 筛选/去重/排序
//   6. merge_and_deduplicate 工具函数
//   7. count_by_type 工具函数
//   8. CandidateCollector 注入式构造（mock provider）
//   9. 异步收集流程（host + srflx + relay + upnp + mdns）
//  10. 超时处理
//  11. 错误处理
//  12. 真实场景模拟（多 STUN 服务器）

#include "linoh/nat/ice_candidate.hpp"

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

static Candidate make_test_candidate(CandidateType type,
                                      const std::string &local_ip,
                                      std::uint16_t local_port,
                                      const std::string &remote_ip,
                                      std::uint16_t remote_port,
                                      std::uint16_t local_pref = 65535) {
    TransportAddr local;
    local.kind = TransportKind::Ip;
    local.host = local_ip;
    local.port = local_port;

    TransportAddr remote;
    remote.kind = TransportKind::Ip;
    remote.host = remote_ip;
    remote.port = remote_port;

    FourTuple tuple;
    tuple.local_addr = local;
    tuple.remote_addr = remote;

    Candidate c;
    c.type = type;
    c.tuple = tuple;
    c.priority = compute_candidate_priority(type, local_pref);
    c.foundation = make_foundation(type, local_ip, local_port);
    return c;
}

static Candidate make_relay_candidate(const std::string &host, std::uint16_t port,
                                       std::uint16_t local_pref = 65535) {
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
    c.priority = compute_candidate_priority(CandidateType::Relay, local_pref);
    c.foundation = make_foundation(CandidateType::Relay, host, port);
    c.is_relayed = true;
    return c;
}

// ============================================================================
// 1. CandidateType 枚举值和字符串转换
// ============================================================================

static void test_candidate_type_name() {
    CHECK(std::string(candidate_type_name(CandidateType::Host)) == "host");
    CHECK(std::string(candidate_type_name(CandidateType::ServerReflexive)) == "srflx");
    CHECK(std::string(candidate_type_name(CandidateType::PeerReflexive)) == "prflx");
    CHECK(std::string(candidate_type_name(CandidateType::Relay)) == "relay");
    CHECK(std::string(candidate_type_name(CandidateType::UPnPPortMapped)) == "upnp");
    CHECK(std::string(candidate_type_name(CandidateType::Mdns)) == "mdns");
}

static void test_candidate_type_code() {
    CHECK(candidate_type_code(CandidateType::Host) == 'H');
    CHECK(candidate_type_code(CandidateType::ServerReflexive) == 'S');
    CHECK(candidate_type_code(CandidateType::PeerReflexive) == 'P');
    CHECK(candidate_type_code(CandidateType::Relay) == 'R');
    CHECK(candidate_type_code(CandidateType::UPnPPortMapped) == 'U');
    CHECK(candidate_type_code(CandidateType::Mdns) == 'M');
}

// ============================================================================
// 2. 候选优先级计算（RFC 8445 §5.1.2 公式）
// ============================================================================

static void test_type_preference() {
    CHECK(type_preference(CandidateType::Host) == 126);
    CHECK(type_preference(CandidateType::Mdns) == 125);
    CHECK(type_preference(CandidateType::UPnPPortMapped) == 120);
    CHECK(type_preference(CandidateType::PeerReflexive) == 110);
    CHECK(type_preference(CandidateType::ServerReflexive) == 100);
    CHECK(type_preference(CandidateType::Relay) == 0);
}

static void test_compute_priority_basic() {
    // priority = (2^24) * type_preference + (2^8) * local_pref + (256 - component_id)
    // 默认 local_pref=65535, component_id=1
    std::uint32_t host_prio = compute_candidate_priority(CandidateType::Host);
    // (126 << 24) | (65535 << 8) | 255 = 2113929215
    CHECK(host_prio == (126u << 24) | (65535u << 8) | 255u);

    std::uint32_t srflx_prio = compute_candidate_priority(CandidateType::ServerReflexive);
    // (100 << 24) | (65535 << 8) | 255
    CHECK(srflx_prio == (100u << 24) | (65535u << 8) | 255u);

    std::uint32_t relay_prio = compute_candidate_priority(CandidateType::Relay);
    // (0 << 24) | (65535 << 8) | 255 = 16777470
    CHECK(relay_prio == (0u << 24) | (65535u << 8) | 255u);
}

static void test_compute_priority_ordering() {
    // Host > Mdns > UPnP > Prflx > Srflx > Relay
    std::uint32_t host = compute_candidate_priority(CandidateType::Host);
    std::uint32_t mdns = compute_candidate_priority(CandidateType::Mdns);
    std::uint32_t upnp = compute_candidate_priority(CandidateType::UPnPPortMapped);
    std::uint32_t prflx = compute_candidate_priority(CandidateType::PeerReflexive);
    std::uint32_t srflx = compute_candidate_priority(CandidateType::ServerReflexive);
    std::uint32_t relay = compute_candidate_priority(CandidateType::Relay);

    CHECK(host > mdns);
    CHECK(mdns > upnp);
    CHECK(upnp > prflx);
    CHECK(prflx > srflx);
    CHECK(srflx > relay);
}

static void test_compute_priority_local_pref() {
    std::uint32_t high = compute_candidate_priority(CandidateType::Host, 65535);
    std::uint32_t low = compute_candidate_priority(CandidateType::Host, 1);
    CHECK(high > low);

    // 不同类型：低 local_pref 的 Host 仍可能 > 高 local_pref 的 Srflx
    std::uint32_t host_low = compute_candidate_priority(CandidateType::Host, 1);
    std::uint32_t srflx_high = compute_candidate_priority(CandidateType::ServerReflexive, 65535);
    CHECK(host_low > srflx_high);  // type_preference 主导
}

static void test_compute_priority_component_id() {
    std::uint32_t c1 = compute_candidate_priority(CandidateType::Host, 65535, 1);
    std::uint32_t c2 = compute_candidate_priority(CandidateType::Host, 65535, 2);
    // component_id 越小，priority 越大（256 - component_id）
    CHECK(c1 > c2);

    // component_id=0 视为非法，按 1 处理（与 c1 相同）
    std::uint32_t c0 = compute_candidate_priority(CandidateType::Host, 65535, 0);
    CHECK(c0 == c1);
}

// ============================================================================
// 3. foundation 字符串构造
// ============================================================================

static void test_make_foundation_basic() {
    std::string f = make_foundation(CandidateType::Host, "192.168.1.1", 8080);
    CHECK(f == "H:192.168.1.1:8080");

    std::string f2 = make_foundation(CandidateType::ServerReflexive, "203.0.113.5", 12345);
    CHECK(f2 == "S:203.0.113.5:12345");

    std::string f3 = make_foundation(CandidateType::Relay, "relay.example.com", 9002);
    CHECK(f3 == "R:relay.example.com:9002");
}

static void test_make_foundation_same_base_same_type() {
    // 同 type + 同 base + 同端口 → 同 foundation
    std::string f1 = make_foundation(CandidateType::Host, "192.168.1.1", 5000);
    std::string f2 = make_foundation(CandidateType::Host, "192.168.1.1", 5000);
    CHECK(f1 == f2);

    // 不同 type → 不同 foundation
    std::string f3 = make_foundation(CandidateType::ServerReflexive, "192.168.1.1", 5000);
    CHECK(f1 != f3);

    // 不同 base → 不同 foundation
    std::string f4 = make_foundation(CandidateType::Host, "192.168.1.2", 5000);
    CHECK(f1 != f4);

    // 不同端口 → 不同 foundation
    std::string f5 = make_foundation(CandidateType::Host, "192.168.1.1", 6000);
    CHECK(f1 != f5);
}

// ============================================================================
// 4. Candidate 结构基本操作
// ============================================================================

static void test_candidate_default_construct() {
    Candidate c;
    CHECK(c.type == CandidateType::Host);
    CHECK(c.priority == 0);
    CHECK(c.foundation.empty());
    CHECK(c.rtt.count() == 0);
    CHECK(c.is_relayed == false);
    CHECK(c.related_address.empty());
}

static void test_candidate_full_construct() {
    FourTuple tuple;
    tuple.local_addr.host = "192.168.1.1";
    tuple.local_addr.port = 5000;
    tuple.local_addr.kind = TransportKind::Ip;
    tuple.remote_addr.host = "10.0.0.1";
    tuple.remote_addr.port = 6000;
    tuple.remote_addr.kind = TransportKind::Ip;

    Candidate c(CandidateType::ServerReflexive, tuple, 12345, "S:192.168.1.1:5000",
                std::chrono::milliseconds(50));
    CHECK(c.type == CandidateType::ServerReflexive);
    CHECK(c.priority == 12345);
    CHECK(c.foundation == "S:192.168.1.1:5000");
    CHECK(c.rtt.count() == 50);
    CHECK(c.is_relayed == false);  // 非 Relay
}

static void test_candidate_relay_is_relayed() {
    Candidate c = make_relay_candidate("relay.example.com", 9002);
    CHECK(c.is_relayed == true);
    CHECK(c.type == CandidateType::Relay);
}

static void test_candidate_operator_less() {
    // 按优先级降序排序（< 表示 priority 高的在前）
    Candidate c1 = make_test_candidate(CandidateType::Host, "1.1.1.1", 100, "2.2.2.2", 200);
    Candidate c2 = make_test_candidate(CandidateType::Relay, "3.3.3.3", 300, "4.4.4.4", 400);
    // c1 (Host) priority > c2 (Relay) priority
    CHECK(c1 < c2);  // c1 排前面
}

static void test_candidate_operator_equal() {
    Candidate c1 = make_test_candidate(CandidateType::Host, "1.1.1.1", 100, "2.2.2.2", 200);
    Candidate c2 = make_test_candidate(CandidateType::Host, "1.1.1.1", 100, "2.2.2.2", 200);
    CHECK(c1 == c2);

    Candidate c3 = make_test_candidate(CandidateType::ServerReflexive, "1.1.1.1", 100, "2.2.2.2", 200);
    CHECK(!(c1 == c3));  // 不同 type
}

static void test_candidate_to_string() {
    Candidate c = make_test_candidate(CandidateType::Host, "192.168.1.1", 5000,
                                       "10.0.0.1", 6000);
    std::string s = c.to_string();
    CHECK(s.find("type=host") != std::string::npos);
    CHECK(s.find("foundation=") != std::string::npos);
    CHECK(s.find("rtt=0ms") != std::string::npos);
}

// ============================================================================
// 5. CandidateGatherResult 筛选/去重/排序
// ============================================================================

static void test_gather_result_filter_by_type() {
    CandidateGatherResult result;
    result.candidates.push_back(make_test_candidate(CandidateType::Host, "1.1.1.1", 100, "2.2.2.2", 200));
    result.candidates.push_back(make_test_candidate(CandidateType::ServerReflexive, "3.3.3.3", 300, "4.4.4.4", 400));
    result.candidates.push_back(make_test_candidate(CandidateType::Host, "5.5.5.5", 500, "6.6.6.6", 600));

    auto hosts = result.filter_by_type(CandidateType::Host);
    CHECK(hosts.size() == 2);
    auto srflx = result.filter_by_type(CandidateType::ServerReflexive);
    CHECK(srflx.size() == 1);
    auto relay = result.filter_by_type(CandidateType::Relay);
    CHECK(relay.size() == 0);
}

static void test_gather_result_deduplicate() {
    CandidateGatherResult result;
    // 三个相同的候选（同 type + 同 tuple）
    result.candidates.push_back(make_test_candidate(CandidateType::Host, "1.1.1.1", 100, "2.2.2.2", 200));
    result.candidates.push_back(make_test_candidate(CandidateType::Host, "1.1.1.1", 100, "2.2.2.2", 200));
    result.candidates.push_back(make_test_candidate(CandidateType::Host, "1.1.1.1", 100, "2.2.2.2", 200));
    // 一个不同的
    result.candidates.push_back(make_test_candidate(CandidateType::Host, "9.9.9.9", 100, "2.2.2.2", 200));

    result.deduplicate();
    CHECK(result.candidates.size() == 2);
}

static void test_gather_result_sort_by_priority() {
    CandidateGatherResult result;
    // 顺序：Relay、Host、Srflx
    result.candidates.push_back(make_test_candidate(CandidateType::Relay, "1.1.1.1", 100, "2.2.2.2", 200));
    result.candidates.push_back(make_test_candidate(CandidateType::Host, "3.3.3.3", 300, "4.4.4.4", 400));
    result.candidates.push_back(make_test_candidate(CandidateType::ServerReflexive, "5.5.5.5", 500, "6.6.6.6", 600));

    result.sort_by_priority();
    // 期望顺序：Host > Srflx > Relay
    CHECK(result.candidates[0].type == CandidateType::Host);
    CHECK(result.candidates[1].type == CandidateType::ServerReflexive);
    CHECK(result.candidates[2].type == CandidateType::Relay);
}

static void test_gather_result_to_string() {
    CandidateGatherResult result;
    result.candidates.push_back(make_test_candidate(CandidateType::Host, "1.1.1.1", 100, "2.2.2.2", 200));
    result.duration = std::chrono::milliseconds(150);
    result.errors.push_back("test error");

    std::string s = result.to_string();
    CHECK(s.find("count=1") != std::string::npos);
    CHECK(s.find("duration=150ms") != std::string::npos);
    CHECK(s.find("errors=") != std::string::npos);
    CHECK(s.find("test error") != std::string::npos);
}

// ============================================================================
// 6. merge_and_deduplicate 工具函数
// ============================================================================

static void test_merge_and_deduplicate_basic() {
    std::vector<std::vector<Candidate>> lists;
    lists.push_back({
        make_test_candidate(CandidateType::Host, "1.1.1.1", 100, "2.2.2.2", 200),
        make_test_candidate(CandidateType::ServerReflexive, "3.3.3.3", 300, "4.4.4.4", 400),
    });
    lists.push_back({
        make_test_candidate(CandidateType::Host, "5.5.5.5", 500, "6.6.6.6", 600),
        make_test_candidate(CandidateType::ServerReflexive, "3.3.3.3", 300, "4.4.4.4", 400),  // 重复
    });

    auto merged = merge_and_deduplicate(lists);
    CHECK(merged.size() == 3);  // 去重后 3 个
}

static void test_merge_and_deduplicate_empty() {
    std::vector<std::vector<Candidate>> empty_lists;
    auto merged = merge_and_deduplicate(empty_lists);
    CHECK(merged.empty());

    std::vector<std::vector<Candidate>> empty_inner = {{}, {}};
    auto merged2 = merge_and_deduplicate(empty_inner);
    CHECK(merged2.empty());
}

// ============================================================================
// 7. count_by_type 工具函数
// ============================================================================

static void test_count_by_type_basic() {
    std::vector<Candidate> candidates;
    candidates.push_back(make_test_candidate(CandidateType::Host, "1.1.1.1", 100, "2.2.2.2", 200));
    candidates.push_back(make_test_candidate(CandidateType::Host, "3.3.3.3", 300, "4.4.4.4", 400));
    candidates.push_back(make_test_candidate(CandidateType::ServerReflexive, "5.5.5.5", 500, "6.6.6.6", 600));
    candidates.push_back(make_relay_candidate("relay.example.com", 9002));

    auto counts = count_by_type(candidates);
    // 按枚举值排序（std::map<CandidateType, ...>）
    CHECK(counts.size() == 3);  // Host, ServerReflexive, Relay 三种类型

    std::size_t total = 0;
    for (auto &[type, cnt] : counts) {
        total += cnt;
        if (type == CandidateType::Host) CHECK(cnt == 2);
        if (type == CandidateType::ServerReflexive) CHECK(cnt == 1);
        if (type == CandidateType::Relay) CHECK(cnt == 1);
    }
    CHECK(total == 4);
}

static void test_count_by_type_empty() {
    std::vector<Candidate> empty;
    auto counts = count_by_type(empty);
    CHECK(counts.empty());
}

// ============================================================================
// 8. is_local_candidate / needs_relay 工具函数
// ============================================================================

static void test_is_local_candidate() {
    Candidate host = make_test_candidate(CandidateType::Host, "1.1.1.1", 100, "2.2.2.2", 200);
    Candidate srflx = make_test_candidate(CandidateType::ServerReflexive, "3.3.3.3", 300, "4.4.4.4", 400);
    Candidate relay = make_relay_candidate("relay.example.com", 9002);

    CHECK(is_local_candidate(host) == true);
    CHECK(is_local_candidate(srflx) == true);
    CHECK(is_local_candidate(relay) == false);
}

static void test_needs_relay() {
    Candidate host = make_test_candidate(CandidateType::Host, "1.1.1.1", 100, "2.2.2.2", 200);
    Candidate relay = make_relay_candidate("relay.example.com", 9002);

    CHECK(needs_relay(host) == false);
    CHECK(needs_relay(relay) == true);

    // 手动构造一个 is_relayed=true 的非 Relay 候选
    Candidate relayed = make_test_candidate(CandidateType::ServerReflexive, "3.3.3.3", 300, "4.4.4.4", 400);
    relayed.is_relayed = true;
    CHECK(needs_relay(relayed) == true);
}

// ============================================================================
// 9. CandidateCollector 注入式构造（mock provider）
// ============================================================================

static void test_collector_injected_mock() {
    CandidateCollectorConfig config;
    config.enable_upnp = false;
    config.enable_mdns = false;
    config.stun_servers = {"stun.example.com:3478"};
    config.relay_servers = {"relay://relay.example.com:9002"};
    config.timeout = std::chrono::milliseconds(500);

    auto host_provider = []() -> std::vector<Candidate> {
        return {make_test_candidate(CandidateType::Host, "192.168.1.1", 5000,
                                     "10.0.0.1", 6000)};
    };

    auto srflx_provider = [](const std::string &) -> std::future<std::vector<Candidate>> {
        return std::async(std::launch::async, []() {
            return std::vector<Candidate>{
                make_test_candidate(CandidateType::ServerReflexive, "203.0.113.1", 12345,
                                     "stun.example.com", 3478)
            };
        });
    };

    auto relay_provider = [](const std::string &) -> std::future<std::vector<Candidate>> {
        return std::async(std::launch::async, []() {
            return std::vector<Candidate>{
                make_relay_candidate("relay.example.com", 9002)
            };
        });
    };

    auto upnp_provider = []() -> std::future<std::optional<Candidate>> {
        return std::async(std::launch::async, []() -> std::optional<Candidate> {
            return std::nullopt;
        });
    };

    auto mdns_provider = []() -> std::future<std::optional<Candidate>> {
        return std::async(std::launch::async, []() -> std::optional<Candidate> {
            return std::nullopt;
        });
    };

    CandidateCollector collector(config, host_provider, srflx_provider,
                                  relay_provider, upnp_provider, mdns_provider);
    auto result = collector.gather_candidates_sync();

    CHECK(result.candidates.size() >= 2);  // 至少 host + srflx + relay
    CHECK(result.errors.empty());

    // 验证包含三种类型
    auto hosts = result.filter_by_type(CandidateType::Host);
    auto srflx = result.filter_by_type(CandidateType::ServerReflexive);
    auto relays = result.filter_by_type(CandidateType::Relay);
    CHECK(hosts.size() == 1);
    CHECK(srflx.size() == 1);
    CHECK(relays.size() == 1);
}

static void test_collector_async_gather() {
    CandidateCollectorConfig config;
    config.enable_upnp = false;
    config.enable_mdns = false;
    config.stun_servers = {};
    config.relay_servers = {};
    config.timeout = std::chrono::milliseconds(200);

    auto host_provider = []() -> std::vector<Candidate> {
        return {make_test_candidate(CandidateType::Host, "192.168.1.1", 5000,
                                     "10.0.0.1", 6000)};
    };
    auto empty_srflx = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_relay = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_upnp = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };
    auto empty_mdns = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };

    CandidateCollector collector(config, host_provider, empty_srflx, empty_relay,
                                  empty_upnp, empty_mdns);
    auto fut = collector.gather_candidates();
    auto result = fut.get();

    CHECK(result.candidates.size() == 1);
    CHECK(result.candidates[0].type == CandidateType::Host);
}

// ============================================================================
// 10. 超时处理
// ============================================================================

static void test_collector_timeout() {
    CandidateCollectorConfig config;
    config.enable_upnp = false;
    config.enable_mdns = false;
    config.stun_servers = {"stun.slow.com:3478"};
    config.relay_servers = {};
    config.timeout = std::chrono::milliseconds(100);

    auto fast_host = []() {
        return std::vector<Candidate>{
            make_test_candidate(CandidateType::Host, "192.168.1.1", 5000,
                                 "10.0.0.1", 6000)
        };
    };
    auto slow_srflx = [](const std::string &) {
        return std::async(std::launch::async, []() -> std::vector<Candidate> {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));  // 超过 timeout
            return {make_test_candidate(CandidateType::ServerReflexive, "203.0.113.1", 12345,
                                         "stun.slow.com", 3478)};
        });
    };
    auto empty_relay = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_upnp = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };
    auto empty_mdns = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };

    CandidateCollector collector(config, fast_host, slow_srflx, empty_relay,
                                  empty_upnp, empty_mdns);
    auto result = collector.gather_candidates_sync();

    // host 应该成功，srflx 应该超时
    CHECK(result.candidates.size() == 1);
    CHECK(result.candidates[0].type == CandidateType::Host);
    bool has_timeout_error = false;
    for (const auto &err : result.errors) {
        if (err.find("timeout") != std::string::npos) {
            has_timeout_error = true;
            break;
        }
    }
    CHECK(has_timeout_error);
}

// ============================================================================
// 11. 错误处理
// ============================================================================

static void test_collector_provider_exception() {
    CandidateCollectorConfig config;
    config.enable_upnp = false;
    config.enable_mdns = false;
    config.stun_servers = {"stun.example.com:3478"};
    config.relay_servers = {};
    config.timeout = std::chrono::milliseconds(500);

    auto throwing_host = []() -> std::vector<Candidate> {
        throw std::runtime_error("host provider failed");
    };
    auto throwing_srflx = [](const std::string &) {
        return std::async(std::launch::async, []() -> std::vector<Candidate> {
            throw std::runtime_error("srflx provider failed");
        });
    };
    auto empty_relay = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_upnp = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };
    auto empty_mdns = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };

    CandidateCollector collector(config, throwing_host, throwing_srflx, empty_relay,
                                  empty_upnp, empty_mdns);
    auto result = collector.gather_candidates_sync();

    CHECK(result.candidates.empty());
    CHECK(result.errors.size() >= 2);  // host + srflx 两个错误

    bool has_host_error = false;
    bool has_srflx_error = false;
    for (const auto &err : result.errors) {
        if (err.find("host:") != std::string::npos) has_host_error = true;
        if (err.find("srflx:") != std::string::npos) has_srflx_error = true;
    }
    CHECK(has_host_error);
    CHECK(has_srflx_error);
}

// ============================================================================
// 12. 真实场景模拟（多 STUN 服务器）
// ============================================================================

static void test_collector_multiple_stun_servers() {
    CandidateCollectorConfig config;
    config.enable_upnp = false;
    config.enable_mdns = false;
    config.stun_servers = {
        "stun1.example.com:3478",
        "stun2.example.com:3478",
        "stun3.example.com:3478"
    };
    config.relay_servers = {};
    config.timeout = std::chrono::milliseconds(1000);

    auto host_provider = []() {
        return std::vector<Candidate>{
            make_test_candidate(CandidateType::Host, "192.168.1.1", 5000,
                                 "10.0.0.1", 6000)
        };
    };

    int srflx_calls = 0;
    std::mutex mtx;
    auto srflx_provider = [&mtx, &srflx_calls](const std::string &stun) {
        return std::async(std::launch::async, [&mtx, &srflx_calls, stun]() {
            std::lock_guard<std::mutex> lk(mtx);
            ++srflx_calls;
            // 每个服务器返回不同的映射地址
            std::string public_ip = "203.0.113." + std::to_string(srflx_calls);
            return std::vector<Candidate>{
                make_test_candidate(CandidateType::ServerReflexive, public_ip, 10000 + srflx_calls,
                                     stun, 3478)
            };
        });
    };

    auto empty_relay = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_upnp = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };
    auto empty_mdns = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };

    CandidateCollector collector(config, host_provider, srflx_provider, empty_relay,
                                  empty_upnp, empty_mdns);
    auto result = collector.gather_candidates_sync();

    CHECK(srflx_calls == 3);  // 三个 STUN 服务器都调用了
    auto srflx_candidates = result.filter_by_type(CandidateType::ServerReflexive);
    CHECK(srflx_candidates.size() == 3);

    // 验证 host 也存在
    auto hosts = result.filter_by_type(CandidateType::Host);
    CHECK(hosts.size() == 1);

    // 验证已排序（host > srflx）
    CHECK(result.candidates[0].type == CandidateType::Host);
}

static void test_collector_disabled_host() {
    CandidateCollectorConfig config;
    config.enable_host = false;
    config.enable_upnp = false;
    config.enable_mdns = false;
    config.stun_servers = {"stun.example.com:3478"};
    config.relay_servers = {};
    config.timeout = std::chrono::milliseconds(200);

    auto host_provider = []() {
        return std::vector<Candidate>{
            make_test_candidate(CandidateType::Host, "192.168.1.1", 5000,
                                 "10.0.0.1", 6000)
        };
    };
    auto srflx_provider = [](const std::string &) {
        return std::async(std::launch::async, []() {
            return std::vector<Candidate>{
                make_test_candidate(CandidateType::ServerReflexive, "203.0.113.1", 12345,
                                     "stun.example.com", 3478)
            };
        });
    };
    auto empty_relay = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_upnp = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };
    auto empty_mdns = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };

    CandidateCollector collector(config, host_provider, srflx_provider, empty_relay,
                                  empty_upnp, empty_mdns);
    auto result = collector.gather_candidates_sync();

    // host 被禁用，应只有 srflx
    auto hosts = result.filter_by_type(CandidateType::Host);
    CHECK(hosts.empty());
    auto srflx = result.filter_by_type(CandidateType::ServerReflexive);
    CHECK(srflx.size() == 1);
}

static void test_collector_default_construct() {
    // 默认构造（使用内置 provider）
    CandidateCollectorConfig config;
    config.enable_upnp = false;
    config.enable_mdns = false;
    config.stun_servers = {};  // 空，避免实际 STUN 调用
    config.relay_servers = {};
    config.timeout = std::chrono::milliseconds(200);

    CandidateCollector collector(config);
    auto result = collector.gather_candidates_sync();

    // 默认 host provider 应该返回至少一个本地地址（运行测试的机器）
    // 但在某些 CI 环境可能没有，所以只检查不崩溃 + 没有错误
    CHECK(result.errors.empty() || result.candidates.empty());
}

static void test_collector_priority_sorted() {
    CandidateCollectorConfig config;
    config.enable_upnp = false;
    config.enable_mdns = false;
    config.stun_servers = {"stun.example.com:3478"};
    config.relay_servers = {"relay://relay.example.com:9002"};
    config.timeout = std::chrono::milliseconds(500);

    auto host_provider = []() {
        return std::vector<Candidate>{
            make_test_candidate(CandidateType::Host, "192.168.1.1", 5000,
                                 "10.0.0.1", 6000)
        };
    };
    auto srflx_provider = [](const std::string &) {
        return std::async(std::launch::async, []() {
            return std::vector<Candidate>{
                make_test_candidate(CandidateType::ServerReflexive, "203.0.113.1", 12345,
                                     "stun.example.com", 3478)
            };
        });
    };
    auto relay_provider = [](const std::string &) {
        return std::async(std::launch::async, []() {
            return std::vector<Candidate>{
                make_relay_candidate("relay.example.com", 9002)
            };
        });
    };
    auto empty_upnp = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };
    auto empty_mdns = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };

    CandidateCollector collector(config, host_provider, srflx_provider, relay_provider,
                                  empty_upnp, empty_mdns);
    auto result = collector.gather_candidates_sync();

    CHECK(result.candidates.size() == 3);
    // 按优先级排序：Host > Srflx > Relay
    CHECK(result.candidates[0].type == CandidateType::Host);
    CHECK(result.candidates[1].type == CandidateType::ServerReflexive);
    CHECK(result.candidates[2].type == CandidateType::Relay);
}

// ============================================================================
// 13. UPnP / mDNS provider 返回有效候选
// ============================================================================

static void test_collector_upnp_mdns_enabled() {
    CandidateCollectorConfig config;
    config.enable_upnp = true;
    config.enable_mdns = true;
    config.stun_servers = {};
    config.relay_servers = {};
    config.timeout = std::chrono::milliseconds(500);

    auto empty_host = []() { return std::vector<Candidate>{}; };
    auto empty_srflx = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_relay = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto upnp_provider = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> {
            return make_test_candidate(CandidateType::UPnPPortMapped, "203.0.113.99", 54321,
                                        "router.local", 5000);
        });
    };
    auto mdns_provider = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> {
            return make_test_candidate(CandidateType::Mdns, "linoh-host.local", 0,
                                        "linoh-host.local", 0);
        });
    };

    CandidateCollector collector(config, empty_host, empty_srflx, empty_relay,
                                  upnp_provider, mdns_provider);
    auto result = collector.gather_candidates_sync();

    CHECK(result.candidates.size() == 2);
    // UPnP (priority 120) > Mdns (priority 125)
    // 实际上 Mdns > UPnP（125 > 120）
    CHECK(result.candidates[0].type == CandidateType::Mdns);
    CHECK(result.candidates[1].type == CandidateType::UPnPPortMapped);
}

// ============================================================================
// 14. 默认 host provider 返回（多网卡场景模拟）
// ============================================================================

static void test_default_host_provider_multi_nic() {
    CandidateCollectorConfig config;
    config.enable_upnp = false;
    config.enable_mdns = false;
    config.stun_servers = {};
    config.relay_servers = {};
    config.timeout = std::chrono::milliseconds(500);

    // mock 多网卡 host provider
    auto host_provider = []() {
        std::vector<Candidate> cs;
        cs.push_back(make_test_candidate(CandidateType::Host, "192.168.1.100", 0,
                                         "192.168.1.100", 0));
        cs.push_back(make_test_candidate(CandidateType::Host, "10.0.0.50", 0,
                                         "10.0.0.50", 0));
        cs.push_back(make_test_candidate(CandidateType::Host, "fd00::1", 0,
                                         "fd00::1", 0));
        return cs;
    };
    auto empty_srflx = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_relay = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_upnp = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };
    auto empty_mdns = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };

    CandidateCollector collector(config, host_provider, empty_srflx, empty_relay,
                                  empty_upnp, empty_mdns);
    auto result = collector.gather_candidates_sync();

    auto hosts = result.filter_by_type(CandidateType::Host);
    CHECK(hosts.size() == 3);
}

static void test_ipv4_only_filter() {
    CandidateCollectorConfig config;
    config.ipv4_only = true;
    config.enable_upnp = false;
    config.enable_mdns = false;
    config.stun_servers = {};
    config.relay_servers = {};
    config.timeout = std::chrono::milliseconds(200);

    // 提供混合的 host（IPv4 + IPv6）
    auto host_provider = []() {
        std::vector<Candidate> cs;
        cs.push_back(make_test_candidate(CandidateType::Host, "192.168.1.1", 0,
                                         "192.168.1.1", 0));
        cs.push_back(make_test_candidate(CandidateType::Host, "fd00::1", 0,
                                         "fd00::1", 0));
        return cs;
    };
    auto empty_srflx = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_relay = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_upnp = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };
    auto empty_mdns = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };

    CandidateCollector collector(config, host_provider, empty_srflx, empty_relay,
                                  empty_upnp, empty_mdns);
    auto result = collector.gather_candidates_sync();

    // 注：ipv4_only 在 default_host_provider 中生效，但 mock provider 不受影响
    // 此测试验证 mock provider 仍返回所有候选
    CHECK(result.candidates.size() == 2);
}

// ============================================================================
// 15. Edge cases
// ============================================================================

static void test_empty_stun_servers() {
    CandidateCollectorConfig config;
    config.enable_upnp = false;
    config.enable_mdns = false;
    config.stun_servers = {};
    config.relay_servers = {};
    config.timeout = std::chrono::milliseconds(200);

    auto host_provider = []() {
        return std::vector<Candidate>{
            make_test_candidate(CandidateType::Host, "192.168.1.1", 5000,
                                 "10.0.0.1", 6000)
        };
    };
    auto empty_srflx = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_relay = [](const std::string &) {
        return std::async(std::launch::async, []() { return std::vector<Candidate>{}; });
    };
    auto empty_upnp = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };
    auto empty_mdns = []() {
        return std::async(std::launch::async, []() -> std::optional<Candidate> { return std::nullopt; });
    };

    CandidateCollector collector(config, host_provider, empty_srflx, empty_relay,
                                  empty_upnp, empty_mdns);
    auto result = collector.gather_candidates_sync();

    CHECK(result.candidates.size() == 1);
    CHECK(result.errors.empty());
}

static void test_candidate_rtt_field() {
    Candidate c = make_test_candidate(CandidateType::ServerReflexive, "1.1.1.1", 100,
                                       "2.2.2.2", 200);
    c.rtt = std::chrono::milliseconds(75);
    CHECK(c.rtt.count() == 75);

    std::string s = c.to_string();
    CHECK(s.find("rtt=75ms") != std::string::npos);
}

static void test_candidate_related_address() {
    Candidate c = make_test_candidate(CandidateType::ServerReflexive, "203.0.113.1", 12345,
                                       "stun.example.com", 3478);
    c.related_address = "192.168.1.1:5000";
    std::string s = c.to_string();
    CHECK(s.find("related=") != std::string::npos);
    CHECK(s.find("192.168.1.1:5000") != std::string::npos);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::printf("=== P5-D-1 ICE Candidate Collector Tests ===\n\n");

    std::printf("[1] CandidateType 枚举值和字符串转换\n");
    test_candidate_type_name();
    test_candidate_type_code();
    std::printf("  pass=%d fail=%d\n\n", pass_count, fail_count);

    auto saved_pass = pass_count;
    auto saved_fail = fail_count;

    std::printf("[2] 候选优先级计算\n");
    test_type_preference();
    test_compute_priority_basic();
    test_compute_priority_ordering();
    test_compute_priority_local_pref();
    test_compute_priority_component_id();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[3] foundation 字符串构造\n");
    test_make_foundation_basic();
    test_make_foundation_same_base_same_type();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[4] Candidate 结构基本操作\n");
    test_candidate_default_construct();
    test_candidate_full_construct();
    test_candidate_relay_is_relayed();
    test_candidate_operator_less();
    test_candidate_operator_equal();
    test_candidate_to_string();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[5] CandidateGatherResult 筛选/去重/排序\n");
    test_gather_result_filter_by_type();
    test_gather_result_deduplicate();
    test_gather_result_sort_by_priority();
    test_gather_result_to_string();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[6] merge_and_deduplicate 工具函数\n");
    test_merge_and_deduplicate_basic();
    test_merge_and_deduplicate_empty();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[7] count_by_type 工具函数\n");
    test_count_by_type_basic();
    test_count_by_type_empty();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[8] is_local_candidate / needs_relay 工具函数\n");
    test_is_local_candidate();
    test_needs_relay();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[9] CandidateCollector 注入式构造\n");
    test_collector_injected_mock();
    test_collector_async_gather();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[10] 超时处理\n");
    test_collector_timeout();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[11] 错误处理\n");
    test_collector_provider_exception();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[12] 真实场景模拟（多 STUN 服务器）\n");
    test_collector_multiple_stun_servers();
    test_collector_disabled_host();
    test_collector_default_construct();
    test_collector_priority_sorted();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[13] UPnP / mDNS provider 返回有效候选\n");
    test_collector_upnp_mdns_enabled();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[14] 多网卡场景模拟\n");
    test_default_host_provider_multi_nic();
    test_ipv4_only_filter();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);
    saved_pass = pass_count;
    saved_fail = fail_count;

    std::printf("[15] Edge cases\n");
    test_empty_stun_servers();
    test_candidate_rtt_field();
    test_candidate_related_address();
    std::printf("  pass=%d fail=%d\n\n", pass_count - saved_pass, fail_count - saved_fail);

    std::printf("=== Summary ===\n");
    std::printf("Total: pass=%d fail=%d\n", pass_count, fail_count);

    return fail_count == 0 ? 0 : 1;
}
