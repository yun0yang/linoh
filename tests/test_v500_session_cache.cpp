// test_v500_session_cache.cpp — v5.0.0 T-LP4-003 Session Cache 测试
//
// 验证内容：
//   - store/lookup 基本往返
//   - TTL 过期判定（本地 TTL + ticket lifetime）
//   - remove 主动移除
//   - cleanup_expired 批量清理
//   - 容量限制（kMaxEntries 满后移除最旧）
//   - 线程安全（多线程并发 store/lookup）
//   - ticket 与 endpoint_id 绑定

#include "linoh/endpoint/session_cache.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

using namespace linoh::endpoint;
using namespace linoh::protocol;
using linoh::base::EndpointId;
using linoh::base::PublicKey;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

static EndpointId make_id(uint8_t byte) {
    std::array<uint8_t, PublicKey::kSize> bytes{};
    bytes.fill(byte);
    return PublicKey(bytes);
}

static SessionTicketFrame make_ticket(uint64_t lifetime = 3600) {
    SessionTicketFrame t;
    t.ticket_lifetime = lifetime;
    t.ticket_age_add = 0x12345678;
    t.ticket_nonce = {0x01, 0x02, 0x03};
    t.ticket = {0xAA, 0xBB, 0xCC, 0xDD};
    return t;
}

// ============================================================================
// 基本功能测试
// ============================================================================

static void test_store_lookup_basic() {
    std::printf("[test] T-LP4-003: store/lookup basic roundtrip...\n");

    SessionCache cache;
    auto id = make_id(0x01);
    auto ticket = make_ticket();

    cache.store(id, ticket);
    CHECK(cache.size() == 1);

    auto result = cache.lookup(id);
    CHECK(result.has_value());
    CHECK(result->ticket_lifetime == 3600);
    CHECK(result->ticket_age_add == 0x12345678);
    // 注意：CHECK 宏无法直接处理花括号初始化列表（逗号被预处理器识别为参数分隔符）
    const std::vector<uint8_t> expected_nonce{0x01, 0x02, 0x03};
    CHECK(result->ticket_nonce == expected_nonce);
}

static void test_lookup_nonexistent() {
    std::printf("[test] T-LP4-003: lookup nonexistent returns nullopt...\n");

    SessionCache cache;
    auto id = make_id(0x02);

    auto result = cache.lookup(id);
    CHECK(!result.has_value());
    CHECK(cache.size() == 0);
}

static void test_store_overwrite() {
    std::printf("[test] T-LP4-003: store overwrites existing ticket...\n");

    SessionCache cache;
    auto id = make_id(0x03);

    auto t1 = make_ticket(3600);
    cache.store(id, t1);

    auto t2 = make_ticket(7200);
    t2.ticket_age_add = 0xDEADBEEF;
    cache.store(id, t2);

    CHECK(cache.size() == 1);

    auto result = cache.lookup(id);
    CHECK(result.has_value());
    CHECK(result->ticket_lifetime == 7200);
    CHECK(result->ticket_age_add == 0xDEADBEEF);
}

// ============================================================================
// TTL 过期测试
// ============================================================================

static void test_ttl_expiration() {
    std::printf("[test] T-LP4-003: TTL expiration...\n");

    // 使用极短 TTL（100ms）测试过期
    SessionCache cache(std::chrono::milliseconds(100));
    auto id = make_id(0x04);
    auto ticket = make_ticket(3600);  // ticket lifetime 1h，但 cache TTL 100ms

    cache.store(id, ticket);
    CHECK(cache.lookup(id).has_value());  // 立即查询应该有

    // 等待 150ms 超过 TTL
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    auto result = cache.lookup(id);
    CHECK(!result.has_value());  // 过期后应返回 nullopt
}

static void test_ticket_lifetime_expiration() {
    std::printf("[test] T-LP4-003: ticket lifetime expiration...\n");

    // cache TTL 设为很长，但 ticket lifetime 设为极短
    SessionCache cache(std::chrono::seconds(3600));
    auto id = make_id(0x05);
    auto ticket = make_ticket(0);  // lifetime=0，立即过期

    cache.store(id, ticket);

    auto result = cache.lookup(id);
    // lifetime=0 的 ticket 应立即视为过期
    CHECK(!result.has_value());
}

// ============================================================================
// remove 测试
// ============================================================================

static void test_remove() {
    std::printf("[test] T-LP4-003: remove ticket...\n");

    SessionCache cache;
    auto id1 = make_id(0x06);
    auto id2 = make_id(0x07);

    cache.store(id1, make_ticket());
    cache.store(id2, make_ticket());
    CHECK(cache.size() == 2);

    cache.remove(id1);
    CHECK(cache.size() == 1);
    CHECK(!cache.lookup(id1).has_value());
    CHECK(cache.lookup(id2).has_value());

    // remove 不存在的条目不应出错
    cache.remove(make_id(0xFF));
    CHECK(cache.size() == 1);
}

// ============================================================================
// cleanup_expired 测试
// ============================================================================

static void test_cleanup_expired() {
    std::printf("[test] T-LP4-003: cleanup_expired...\n");

    SessionCache cache(std::chrono::milliseconds(100));

    // 存储 5 个 ticket
    for (uint8_t i = 0x10; i < 0x15; ++i) {
        cache.store(make_id(i), make_ticket());
    }
    CHECK(cache.size() == 5);

    // 等待过期
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // 存入一个新 ticket（未过期）
    cache.store(make_id(0x20), make_ticket());
    CHECK(cache.size() == 6);  // 5 过期 + 1 新

    std::size_t removed = cache.cleanup_expired();
    CHECK(removed == 5);
    CHECK(cache.size() == 1);
    CHECK(cache.lookup(make_id(0x20)).has_value());
}

// ============================================================================
// 容量限制测试
// ============================================================================

static void test_capacity_limit() {
    std::printf("[test] T-LP4-003: capacity limit (kMaxEntries)...\n");

    SessionCache cache(std::chrono::seconds(3600));

    // 填满到容量上限（kMaxEntries=1024，需要超过 256 个唯一 ID）
    // 用 i 的低 16 位填充 bytes[0..1] 生成唯一 ID
    for (std::size_t i = 0; i < SessionCache::kMaxEntries; ++i) {
        std::array<uint8_t, PublicKey::kSize> bytes{};
        bytes[0] = static_cast<uint8_t>(i & 0xFF);
        bytes[1] = static_cast<uint8_t>((i >> 8) & 0xFF);
        cache.store(PublicKey(bytes), make_ticket());
    }
    CHECK(cache.size() == SessionCache::kMaxEntries);

    // 超容量存储：应移除最旧条目（用全新 ID 触发淘汰）
    std::array<uint8_t, PublicKey::kSize> extra_bytes{};
    extra_bytes[0] = 0xFF;
    extra_bytes[1] = 0xFF;
    extra_bytes[2] = 0x01;
    cache.store(PublicKey(extra_bytes), make_ticket(7200));
    // size 不应超过 kMaxEntries
    CHECK(cache.size() <= SessionCache::kMaxEntries);
}

// ============================================================================
// endpoint_id 绑定测试
// ============================================================================

static void test_endpoint_id_binding() {
    std::printf("[test] T-LP4-003: ticket bound to endpoint_id...\n");

    SessionCache cache;
    auto id1 = make_id(0x30);
    auto id2 = make_id(0x31);

    auto t1 = make_ticket();
    t1.ticket_age_add = 0xAAA;
    cache.store(id1, t1);

    auto t2 = make_ticket();
    t2.ticket_age_add = 0xBBB;
    cache.store(id2, t2);

    // 不同 endpoint_id 查询到不同 ticket
    auto r1 = cache.lookup(id1);
    auto r2 = cache.lookup(id2);
    CHECK(r1.has_value());
    CHECK(r2.has_value());
    CHECK(r1->ticket_age_add == 0xAAA);
    CHECK(r2->ticket_age_add == 0xBBB);
}

// ============================================================================
// lookup_full 测试（含时间戳）
// ============================================================================

static void test_lookup_full() {
    std::printf("[test] T-LP4-003: lookup_full returns timestamp...\n");

    SessionCache cache;
    auto id = make_id(0x40);
    auto ticket = make_ticket();

    auto before = std::chrono::steady_clock::now();
    cache.store(id, ticket);
    auto after = std::chrono::steady_clock::now();

    auto result = cache.lookup_full(id);
    CHECK(result.has_value());
    CHECK(result->stored_at >= before);
    CHECK(result->stored_at <= after);
    CHECK(result->server_endpoint_id == id);
    CHECK(result->ticket.ticket_lifetime == 3600);
}

// ============================================================================
// set_ttl 动态修改测试
// ============================================================================

static void test_set_ttl() {
    std::printf("[test] T-LP4-003: set_ttl changes expiration...\n");

    SessionCache cache(std::chrono::seconds(3600));
    auto id = make_id(0x50);
    cache.store(id, make_ticket());

    // 初始 TTL 长，应该能查到
    CHECK(cache.lookup(id).has_value());

    // 修改 TTL 为极短
    cache.set_ttl(std::chrono::milliseconds(50));
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    // 现在 TTL 短，应该过期
    CHECK(!cache.lookup(id).has_value());
}

// ============================================================================
// 线程安全测试
// ============================================================================

static void test_thread_safety() {
    std::printf("[test] T-LP4-003: thread safety (concurrent store/lookup)...\n");

    SessionCache cache(std::chrono::seconds(3600));
    std::atomic<int> success_count{0};

    // 4 个写线程 + 4 个读线程，并发运行
    std::vector<std::thread> threads;

    // 写线程
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&cache, t, &success_count]() {
            for (int i = 0; i < 100; ++i) {
                uint8_t byte = static_cast<uint8_t>((t * 100 + i) & 0xFF);
                cache.store(make_id(byte), make_ticket());
                success_count++;
            }
        });
    }

    // 读线程
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&cache]() {
            for (int i = 0; i < 100; ++i) {
                cache.lookup(make_id(static_cast<uint8_t>(i & 0xFF)));
            }
        });
    }

    for (auto &th : threads) {
        th.join();
    }

    CHECK(success_count.load() == 400);
    // 缓存不应为空（由于 ID 范围 0-255，最终最多 256 条）
    CHECK(cache.size() > 0);
    CHECK(cache.size() <= 256);
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== v5.0.0 T-LP4-003 Session Cache Tests ===\n\n");

    test_store_lookup_basic();
    test_lookup_nonexistent();
    test_store_overwrite();

    test_ttl_expiration();
    test_ticket_lifetime_expiration();

    test_remove();

    test_cleanup_expired();

    test_capacity_limit();

    test_endpoint_id_binding();

    test_lookup_full();

    test_set_ttl();

    test_thread_safety();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
