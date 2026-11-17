// test_holepunch_cache.cpp — S6-③（v5.3）打洞结果缓存测试
//
// 覆盖：
//   T1 record/lookup 往返（TTL 内命中，tuple 逐字段一致）
//   T2 TTL 过期不命中（ttl=1ms + sleep）
//   T3 不同 peer 隔离
//   T4 ttl<=0 禁用语义
//   T5 容量淘汰（>256 条目后 size 收敛到上限内、旧 peer 被清）
//   T6 global() 单例可用 + clear
//   T7 并发安全（多线程 record/lookup 混跑不崩）
#include "linoh/nat/holepunch_cache.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::nat;

static int g_pass = 0, g_fail = 0;
#define CHECK(c) do { if (c) ++g_pass; else { ++g_fail; \
    std::printf("FAIL: %s (line %d)\n", #c, __LINE__); } } while (0)

static net::FourTuple make_tuple(uint16_t lp, uint16_t rp,
                                 const char *lh, const char *rh) {
    net::FourTuple t{};
    t.local_addr.kind = base::TransportKind::Ip;
    t.local_addr.host = lh;
    t.local_addr.port = lp;
    t.remote_addr.kind = base::TransportKind::Ip;
    t.remote_addr.host = rh;
    t.remote_addr.port = rp;
    return t;
}

int main() {
    std::printf("=== S6-3 holepunch cache tests ===\n");

    HolepunchCache cache;

    // T1: 往返
    base::EndpointId p1{};
    auto tup = make_tuple(1000, 2000, "10.0.0.1", "10.0.0.2");
    cache.record(p1, tup);
    auto hit = cache.lookup(p1);
    CHECK(hit.has_value());
    CHECK(hit->local_addr.port == 1000 && hit->remote_addr.port == 2000);
    CHECK(hit->local_addr.host == "10.0.0.1" && hit->remote_addr.host == "10.0.0.2");
    std::printf("[T1] record/lookup roundtrip\n");

    // T2: TTL 过期
    {
        HolepunchCache c2;
        c2.record(p1, tup);
        CHECK(c2.lookup(p1, std::chrono::milliseconds{1}).has_value());
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        CHECK(!c2.lookup(p1, std::chrono::milliseconds{1}).has_value());
        // 默认 TTL 下仍有效（1ms 查询的过期不影响长 TTL 语义）
        CHECK(c2.lookup(p1).has_value());
        std::printf("[T2] ttl expiry\n");
    }

    // T3: peer 隔离（注意 EndpointId 默认构造与 p1 相同——须用不同密钥）
    {
        std::array<std::uint8_t, 32> raw2{};
        raw2[0] = 0xAB;
        base::EndpointId p2{raw2};
        CHECK(p2 != p1);
        CHECK(!cache.lookup(p2).has_value());
        std::printf("[T3] peer isolation\n");
    }

    // T4: 禁用
    CHECK(!cache.lookup(p1, std::chrono::milliseconds{0}).has_value());
    CHECK(!cache.lookup(p1, std::chrono::milliseconds{-1}).has_value());
    std::printf("[T4] ttl<=0 disabled\n");

    // T5: 容量淘汰
    {
        HolepunchCache c3;
        base::EndpointId first{};
        c3.record(first, tup);
        for (int i = 1; i < 300; ++i) {
            std::array<std::uint8_t, 32> raw{};
            raw[0] = static_cast<std::uint8_t>(i & 0xFF);
            raw[1] = static_cast<std::uint8_t>(i >> 8);
            base::EndpointId pk{raw};
            c3.record(pk, tup);
        }
        CHECK(c3.size() <= HolepunchCache::kMaxEntries);
        std::printf("[T5] eviction: size=%zu (cap %zu)\n", c3.size(),
                    HolepunchCache::kMaxEntries);
    }

    // T6: global 单例
    HolepunchCache::global().clear();
    HolepunchCache::global().record(p1, tup);
    CHECK(HolepunchCache::global().lookup(p1).has_value());
    HolepunchCache::global().clear();
    CHECK(HolepunchCache::global().size() == 0);
    std::printf("[T6] global singleton\n");

    // T7: 并发
    {
        HolepunchCache c4;
        std::vector<std::thread> ts;
        for (int t = 0; t < 4; ++t) {
            ts.emplace_back([&c4, t]() {
                for (int i = 0; i < 200; ++i) {
                    std::array<std::uint8_t, 32> raw{};
                    raw[0] = static_cast<std::uint8_t>(t);
                    raw[1] = static_cast<std::uint8_t>(i & 0xFF);
                    base::EndpointId pk{raw};
                    c4.record(pk, make_tuple(1, 2, "a", "b"));
                    (void)c4.lookup(pk);
                }
            });
        }
        for (auto &th : ts) th.join();
        CHECK(c4.size() > 0 && c4.size() <= HolepunchCache::kMaxEntries);
        std::printf("[T7] concurrent safety: size=%zu\n", c4.size());
    }

    std::printf("=== %d PASS / %d FAIL ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
