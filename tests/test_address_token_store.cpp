// test_address_token_store.cpp — P4-A-2 全局 AddressTokenStore 单元测试
//
// 测试覆盖：
//   1. 单例 instance() 返回相同引用
//   2. store_token + take_token 基本往返
//   3. take_token 一次性使用（取出后不可再取）
//   4. count_tokens 查询不取出
//   5. 按 peer_addr 隔离（不同地址不互相影响）
//   6. TTL 过期：take_token 跳过过期 token
//   7. cleanup_expired 主动清理
//   8. 容量限制 kMaxTokensPerPeer（FIFO 淘汰最旧）
//   9. clear() 清空
//  10. total_tokens 统计
//  11. 空 token 拒绝存储
//  12. 多线程并发安全

#include "linoh/tls/address_token_store.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::tls;
using linoh::base::TransportAddr;
using linoh::base::TransportKind;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL line %d: %s\n", __LINE__, #cond); } \
} while(0)

static TransportAddr make_addr(std::string host, uint16_t port) {
    TransportAddr a;
    a.kind = TransportKind::Ip;
    a.host = std::move(host);
    a.port = port;
    return a;
}

static std::vector<std::uint8_t> make_token(std::uint8_t seed, std::size_t len = 32) {
    std::vector<std::uint8_t> t(len);
    for (std::size_t i = 0; i < len; ++i) t[i] = seed + static_cast<std::uint8_t>(i);
    return t;
}

// 每个测试前 clear，避免相互污染
static void reset_store() {
    AddressTokenStore::instance().clear();
}

// ========== 1. 单例 ==========
static void test_singleton() {
    reset_store();
    auto& a = AddressTokenStore::instance();
    auto& b = AddressTokenStore::instance();
    CHECK(&a == &b);
}

// ========== 2. store + take 往返 ==========
static void test_store_take_roundtrip() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    TransportAddr peer = make_addr("1.1.1.1", 9000);
    auto token = make_token(0xAA);
    store.store_token(token, peer);

    auto got = store.take_token(peer);
    CHECK(got.has_value());
    CHECK(got->size() == token.size());
    CHECK(got->front() == 0xAA);
    CHECK(got->back() == 0xAA + 31);
}

// ========== 3. take 一次性 ==========
static void test_take_is_one_shot() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    TransportAddr peer = make_addr("2.2.2.2", 9001);
    store.store_token(make_token(0xBB), peer);

    auto t1 = store.take_token(peer);
    CHECK(t1.has_value());

    auto t2 = store.take_token(peer);
    CHECK(!t2.has_value());  // 已取出，无剩余
}

// ========== 4. count_tokens ==========
static void test_count_tokens() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    TransportAddr peer = make_addr("3.3.3.3", 9002);
    CHECK(store.count_tokens(peer) == 0);

    store.store_token(make_token(1), peer);
    store.store_token(make_token(2), peer);
    store.store_token(make_token(3), peer);
    CHECK(store.count_tokens(peer) == 3);

    // take 后减少
    store.take_token(peer);
    CHECK(store.count_tokens(peer) == 2);
}

// ========== 5. peer 隔离 ==========
static void test_peer_isolation() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    TransportAddr peer_a = make_addr("4.4.4.4", 9003);
    TransportAddr peer_b = make_addr("5.5.5.5", 9004);

    store.store_token(make_token(0xA1), peer_a);
    store.store_token(make_token(0xB1), peer_b);

    auto ta = store.take_token(peer_a);
    CHECK(ta.has_value());
    CHECK(ta->front() == 0xA1);

    auto tb = store.take_token(peer_b);
    CHECK(tb.has_value());
    CHECK(tb->front() == 0xB1);

    // peer_a 已取走，peer_b 也取走后都为空
    CHECK(!store.take_token(peer_a).has_value());
    CHECK(!store.take_token(peer_b).has_value());
}

// ========== 6. TTL 过期 ==========
static void test_ttl_expired() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    TransportAddr peer = make_addr("6.6.6.6", 9005);
    // 立即过期（1ns）
    store.store_token(make_token(0xCC), peer, std::chrono::nanoseconds(1));

    // 等待过期
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    auto got = store.take_token(peer);
    CHECK(!got.has_value());  // 已过期
}

static void test_ttl_not_yet_expired() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    TransportAddr peer = make_addr("7.7.7.7", 9006);
    // 长 TTL
    store.store_token(make_token(0xDD), peer, std::chrono::seconds(3600));

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    auto got = store.take_token(peer);
    CHECK(got.has_value());
    CHECK(got->front() == 0xDD);
}

// ========== 7. cleanup_expired ==========
static void test_cleanup_expired() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    TransportAddr peer_a = make_addr("8.8.8.8", 9007);
    TransportAddr peer_b = make_addr("9.9.9.9", 9008);

    // 3 个过期 + 1 个未过期
    store.store_token(make_token(1), peer_a, std::chrono::nanoseconds(1));
    store.store_token(make_token(2), peer_a, std::chrono::nanoseconds(1));
    store.store_token(make_token(3), peer_b, std::chrono::nanoseconds(1));
    store.store_token(make_token(4), peer_b, std::chrono::seconds(3600));

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    std::size_t removed = store.cleanup_expired();
    CHECK(removed == 3);
    CHECK(store.count_tokens(peer_a) == 0);
    CHECK(store.count_tokens(peer_b) == 1);
}

// ========== 8. 容量限制 FIFO ==========
static void test_capacity_limit() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    TransportAddr peer = make_addr("10.10.10.10", 9009);

    // 存 kMaxTokensPerPeer + 5 个，前 5 个应被 FIFO 淘汰
    for (std::size_t i = 0; i < AddressTokenStore::kMaxTokensPerPeer + 5; ++i) {
        store.store_token(make_token(static_cast<std::uint8_t>(i)), peer);
    }

    CHECK(store.count_tokens(peer) == AddressTokenStore::kMaxTokensPerPeer);

    // 取出第一个应是第 5 个（前 5 个被淘汰）
    auto first = store.take_token(peer);
    CHECK(first.has_value());
    CHECK(first->front() == 5);  // seed=5 的 token
}

// ========== 9. clear ==========
static void test_clear() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    TransportAddr peer = make_addr("11.11.11.11", 9010);
    store.store_token(make_token(0xEE), peer);
    CHECK(store.total_tokens() == 1);

    store.clear();
    CHECK(store.total_tokens() == 0);
    CHECK(store.count_tokens(peer) == 0);
}

// ========== 10. total_tokens ==========
static void test_total_tokens() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    CHECK(store.total_tokens() == 0);

    TransportAddr p1 = make_addr("12.12.12.12", 9011);
    TransportAddr p2 = make_addr("13.13.13.13", 9012);
    store.store_token(make_token(1), p1);
    store.store_token(make_token(2), p1);
    store.store_token(make_token(3), p2);
    CHECK(store.total_tokens() == 3);

    store.take_token(p1);
    CHECK(store.total_tokens() == 2);
}

// ========== 11. 空 token 拒绝 ==========
static void test_empty_token_rejected() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    TransportAddr peer = make_addr("14.14.14.14", 9013);
    std::vector<std::uint8_t> empty_token;
    store.store_token(empty_token, peer);

    CHECK(store.count_tokens(peer) == 0);
    CHECK(store.total_tokens() == 0);
}

// ========== 12. 多线程并发 ==========
static void test_concurrent_access() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    TransportAddr peer = make_addr("15.15.15.15", 9014);

    constexpr int kProducers = 4;
    constexpr int kConsumers = 4;
    constexpr int kOpsPerThread = 50;

    std::atomic<int> produced{0};
    std::atomic<int> consumed{0};

    std::vector<std::thread> threads;

    // 生产者：每个线程存 50 个 token
    for (int i = 0; i < kProducers; ++i) {
        threads.emplace_back([&, i]() {
            for (int j = 0; j < kOpsPerThread; ++j) {
                store.store_token(make_token(static_cast<std::uint8_t>(i * 100 + j)), peer);
                produced.fetch_add(1);
            }
        });
    }

    // 消费者：每个线程取 50 次
    for (int i = 0; i < kConsumers; ++i) {
        threads.emplace_back([&]() {
            for (int j = 0; j < kOpsPerThread; ++j) {
                auto t = store.take_token(peer);
                if (t.has_value()) consumed.fetch_add(1);
            }
        });
    }

    for (auto& t : threads) t.join();

    CHECK(produced.load() == kProducers * kOpsPerThread);  // 200
    // consumed <= produced（部分可能因 FIFO 淘汰丢失）
    CHECK(consumed.load() <= produced.load());
    CHECK(consumed.load() > 0);

    // 剩余 = produced - consumed - 被淘汰的
    // 由于 FIFO 限制 kMaxTokensPerPeer=8，会淘汰大量，但 consumed 应大于 0
    std::printf("  concurrent: produced=%d consumed=%d\n",
                produced.load(), consumed.load());
}

// ========== 13. 不同 kind 的地址隔离 ==========
static void test_kind_isolation() {
    reset_store();
    auto& store = AddressTokenStore::instance();

    TransportAddr ip_addr;
    ip_addr.kind = TransportKind::Ip;
    ip_addr.host = "1.2.3.4";
    ip_addr.port = 9999;

    TransportAddr relay_addr;
    relay_addr.kind = TransportKind::Relay;
    relay_addr.host = "1.2.3.4";  // 相同 host:port
    relay_addr.port = 9999;

    store.store_token(make_token(0xAA), ip_addr);
    store.store_token(make_token(0xBB), relay_addr);

    auto t1 = store.take_token(ip_addr);
    CHECK(t1.has_value());
    CHECK(t1->front() == 0xAA);

    auto t2 = store.take_token(relay_addr);
    CHECK(t2.has_value());
    CHECK(t2->front() == 0xBB);
}

int main() {
    std::printf("=== test_address_token_store ===\n");

    test_singleton();
    test_store_take_roundtrip();
    test_take_is_one_shot();
    test_count_tokens();
    test_peer_isolation();
    test_ttl_expired();
    test_ttl_not_yet_expired();
    test_cleanup_expired();
    test_capacity_limit();
    test_clear();
    test_total_tokens();
    test_empty_token_rejected();
    test_concurrent_access();
    test_kind_isolation();

    std::printf("\n<Result>PASS=%d FAIL=%d</Result>\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
