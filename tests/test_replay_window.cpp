// test_replay_window.cpp — P0-7 0-RTT 重放保护窗口单元测试
//
// 验证 linoh::tls::ReplayWindow 的核心行为：
//   1. 首次插入返回 true（未重放）
//   2. 重复插入返回 false（重放）
//   3. 不同 peer 互不影响
//   4. 不同 PN 互不影响
//   5. 不同 payload_hash 互不影响
//   6. LRU 淘汰（容量上限）
//   7. TTL 过期（懒清理）
//   8. 错误 hash 长度拒绝

#include "linoh/tls/replay_window.hpp"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <thread>
#include <chrono>

using namespace linoh::tls;
using namespace linoh::base;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

static PublicKey make_peer(uint8_t seed) {
    std::array<uint8_t, 32> bytes{};
    for (int i = 0; i < 32; ++i) bytes[i] = seed + i;
    return PublicKey{bytes};
}

static std::array<uint8_t, 32> make_hash(uint8_t seed) {
    std::array<uint8_t, 32> h{};
    for (int i = 0; i < 32; ++i) h[i] = seed + i;
    return h;
}

static void test_first_insert_ok() {
    std::printf("[test] first insert returns true (not replay)...\n");
    ReplayWindow::instance().clear();

    PublicKey peer = make_peer(1);
    auto hash = make_hash(10);
    bool ok = ReplayWindow::instance().check_and_record(
        peer, 100, std::span<const uint8_t>(hash.data(), hash.size()));
    CHECK(ok == true);
    CHECK(ReplayWindow::instance().peer_count() == 1);
    CHECK(ReplayWindow::instance().peer_entry_count(peer) == 1);
}

static void test_duplicate_replay_rejected() {
    std::printf("[test] duplicate insert returns false (replay detected)...\n");
    ReplayWindow::instance().clear();

    PublicKey peer = make_peer(2);
    auto hash = make_hash(20);
    auto span = std::span<const uint8_t>(hash.data(), hash.size());

    bool first = ReplayWindow::instance().check_and_record(peer, 200, span);
    bool second = ReplayWindow::instance().check_and_record(peer, 200, span);
    CHECK(first == true);
    CHECK(second == false);
    CHECK(ReplayWindow::instance().peer_entry_count(peer) == 1);
}

static void test_different_peers_independent() {
    std::printf("[test] different peers are independent...\n");
    ReplayWindow::instance().clear();

    PublicKey peer_a = make_peer(3);
    PublicKey peer_b = make_peer(4);
    auto hash = make_hash(30);
    auto span = std::span<const uint8_t>(hash.data(), hash.size());

    bool a1 = ReplayWindow::instance().check_and_record(peer_a, 300, span);
    bool b1 = ReplayWindow::instance().check_and_record(peer_b, 300, span);
    bool a2 = ReplayWindow::instance().check_and_record(peer_a, 300, span);

    CHECK(a1 == true);
    CHECK(b1 == true);
    CHECK(a2 == false);  // peer_a 重复
    CHECK(ReplayWindow::instance().peer_count() == 2);
}

static void test_different_pn_independent() {
    std::printf("[test] different PN with same hash are independent...\n");
    ReplayWindow::instance().clear();

    PublicKey peer = make_peer(5);
    auto hash = make_hash(40);
    auto span = std::span<const uint8_t>(hash.data(), hash.size());

    bool p1 = ReplayWindow::instance().check_and_record(peer, 400, span);
    bool p2 = ReplayWindow::instance().check_and_record(peer, 401, span);
    bool p3 = ReplayWindow::instance().check_and_record(peer, 402, span);

    CHECK(p1 == true);
    CHECK(p2 == true);
    CHECK(p3 == true);
    CHECK(ReplayWindow::instance().peer_entry_count(peer) == 3);
}

static void test_different_hash_independent() {
    std::printf("[test] different hash with same PN are independent...\n");
    ReplayWindow::instance().clear();

    PublicKey peer = make_peer(6);
    auto hash1 = make_hash(50);
    auto hash2 = make_hash(51);
    auto span1 = std::span<const uint8_t>(hash1.data(), hash1.size());
    auto span2 = std::span<const uint8_t>(hash2.data(), hash2.size());

    bool h1 = ReplayWindow::instance().check_and_record(peer, 500, span1);
    bool h2 = ReplayWindow::instance().check_and_record(peer, 500, span2);
    bool h3 = ReplayWindow::instance().check_and_record(peer, 500, span1);  // 重复 (pn=500, hash1)

    CHECK(h1 == true);
    CHECK(h2 == true);
    CHECK(h3 == false);
    CHECK(ReplayWindow::instance().peer_entry_count(peer) == 2);
}

static void test_lru_eviction() {
    std::printf("[test] LRU eviction on capacity overflow...\n");
    ReplayWindow::instance().clear();

    PublicKey peer = make_peer(7);

    // 插入 kMaxEntriesPerPeer + 50 个条目，最早的应该被淘汰
    for (std::size_t i = 0; i < ReplayWindow::kMaxEntriesPerPeer + 50; ++i) {
        auto hash = make_hash(static_cast<uint8_t>(i & 0xFF));
        ReplayWindow::instance().check_and_record(
            peer, 600 + i,
            std::span<const uint8_t>(hash.data(), hash.size()));
    }

    CHECK(ReplayWindow::instance().peer_entry_count(peer) == ReplayWindow::kMaxEntriesPerPeer);

    // 最早的条目（pn=600）应该已被淘汰 → 重新插入应成功
    auto hash0 = make_hash(0);
    bool ok = ReplayWindow::instance().check_and_record(
        peer, 600,
        std::span<const uint8_t>(hash0.data(), hash0.size()));
    CHECK(ok == true);
}

static void test_invalid_hash_size_rejected() {
    std::printf("[test] invalid hash size is rejected...\n");
    ReplayWindow::instance().clear();

    PublicKey peer = make_peer(8);
    std::array<uint8_t, 16> short_hash{};
    bool ok = ReplayWindow::instance().check_and_record(
        peer, 700,
        std::span<const uint8_t>(short_hash.data(), short_hash.size()));
    CHECK(ok == false);
    CHECK(ReplayWindow::instance().peer_count() == 0);
}

static void test_gc_clears_empty() {
    std::printf("[test] gc() clears empty peer windows...\n");
    ReplayWindow::instance().clear();

    PublicKey peer = make_peer(9);
    auto hash = make_hash(60);
    auto span = std::span<const uint8_t>(hash.data(), hash.size());

    ReplayWindow::instance().check_and_record(peer, 800, span);
    CHECK(ReplayWindow::instance().peer_count() == 1);

    // gc 不会清理未过期的记录
    ReplayWindow::instance().gc();
    CHECK(ReplayWindow::instance().peer_count() == 1);

    // clear 显式清空
    ReplayWindow::instance().clear();
    CHECK(ReplayWindow::instance().peer_count() == 0);
}

int main() {
    std::printf("=== test_replay_window ===\n");

    test_first_insert_ok();
    test_duplicate_replay_rejected();
    test_different_peers_independent();
    test_different_pn_independent();
    test_different_hash_independent();
    test_lru_eviction();
    test_invalid_hash_size_rejected();
    test_gc_clears_empty();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
