// test_multipath_role_hash.cpp — W2.2 FEC 冗余块路径分集测试
//（linoh 独立项目优化方案 W2.2；MultipathStripSelector 组件级增强）
//
// 覆盖：
//   T1 默认 RoundRobin 行为不变（轮转 + 计数）
//   T2 RoleHash：同 flow 数据/冗余稳定异轨（n>=2 全 flow 断言）
//   T3 RoleHash：不同 flow 分散（多流覆盖多轨）
//   T4 skip_path：故障倒换（移除数据轨后该流两类块重选、流不断）
//   T5 单候选退化：无分集但不出错
//   T6 RoundRobin 下 select_for_flow 等价轮转

#include "linoh/protocol/multipath_selector.hpp"

#include <cstdio>
#include <set>

using namespace linoh;
using namespace linoh::protocol;

static int g_pass = 0, g_fail = 0;
#define CHECK(c) do { if (c) ++g_pass; else { ++g_fail; \
    std::printf("FAIL: %s (line %d)\n", #c, __LINE__); } } while (0)

static std::vector<net::FourTuple> make_paths(int n) {
    std::vector<net::FourTuple> v;
    for (int i = 0; i < n; ++i) {
        net::FourTuple t{};
        t.local_addr.port = static_cast<std::uint16_t>(10000 + i);
        t.remote_addr.port = static_cast<std::uint16_t>(20000 + i);
        v.push_back(t);
    }
    return v;
}

int main() {
    std::printf("=== multipath role-hash diversity tests ===\n");

    // T1: 默认 RoundRobin 不变
    {
        MultipathStripSelector s;
        s.update_candidates(make_paths(3));
        CHECK(s.policy() == StripPolicy::RoundRobin);
        auto p1 = s.select_next_for_send();
        auto p2 = s.select_next_for_send();
        CHECK(p1.has_value() && p2.has_value() && *p1 != *p2);
        CHECK(s.total_selections() == 2);
        std::printf("[T1] default round-robin unchanged\n");
    }

    // T2: RoleHash 同 flow 数据/冗余异轨（n=2..5，64 个 flow 全断言）
    {
        for (int n = 2; n <= 5; ++n) {
            MultipathStripSelector s;
            s.update_candidates(make_paths(n));
            s.set_policy(StripPolicy::RoleHash);
            int diverged = 0;
            for (std::uint64_t flow = 1; flow <= 64; ++flow) {
                auto d = s.select_for_flow(flow, false);
                auto r = s.select_for_flow(flow, true);
                CHECK(d.has_value() && r.has_value());
                if (*d != *r) ++diverged;
            }
            CHECK(diverged == 64);  // n>=2 时必然全异轨
            std::printf("[T2] n=%d: 64/64 flows data/redundancy diverged\n", n);
        }
    }

    // T3: 不同 flow 分散（64 流 n=4，至少 3 轨被数据块使用）
    {
        MultipathStripSelector s;
        s.update_candidates(make_paths(4));
        s.set_policy(StripPolicy::RoleHash);
        std::set<std::uint16_t> used_ports;
        for (std::uint64_t flow = 1; flow <= 64; ++flow) {
            auto d = s.select_for_flow(flow, false);
            used_ports.insert(d->local_addr.port);
        }
        CHECK(used_ports.size() >= 3);
        std::printf("[T3] flows spread over %zu/4 paths\n", used_ports.size());
    }

    // T4: skip_path 故障倒换（移除数据轨后流仍可发）
    {
        MultipathStripSelector s;
        auto paths = make_paths(3);
        s.update_candidates(paths);
        s.set_policy(StripPolicy::RoleHash);
        auto d0 = s.select_for_flow(7, false);
        CHECK(d0.has_value());
        s.skip_path(*d0);            // 数据轨故障
        CHECK(s.candidate_count() == 2);
        auto d1 = s.select_for_flow(7, false);
        CHECK(d1.has_value() && *d1 != *d0);  // 重选到存活轨
        auto r1 = s.select_for_flow(7, true);
        CHECK(r1.has_value());                 // 冗余仍可发
        std::printf("[T4] failover after skip_path: stream continues\n");
    }

    // T5: 单候选退化
    {
        MultipathStripSelector s;
        s.update_candidates(make_paths(1));
        s.set_policy(StripPolicy::RoleHash);
        auto d = s.select_for_flow(42, false);
        auto r = s.select_for_flow(42, true);
        CHECK(d.has_value() && r.has_value() && *d == *r);  // 同轨（无分集不出错）
        std::printf("[T5] single-candidate degrade ok\n");
    }

    // T6: RoundRobin 策略下 select_for_flow 等价轮转
    {
        MultipathStripSelector s;
        s.update_candidates(make_paths(2));
        auto a = s.select_for_flow(1, false);
        auto b = s.select_for_flow(1, true);
        CHECK(a.has_value() && b.has_value() && *a != *b);  // 轮转推进
        std::printf("[T6] select_for_flow degrades to round-robin\n");
    }

    std::printf("=== %d PASS / %d FAIL ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
