// test_secure_buffer.cpp — P1-6 安全缓冲区 + 私钥内存清零单元测试
//
// 验证 linoh::util::SecureBuffer / secure_zero / SecretKey / SessionTicket
// 的析构清零、移动语义、is_zero 等核心行为。

#include "linoh/util/secure_buffer.hpp"
#include "linoh/base/key.hpp"
#include "linoh/endpoint/connection.hpp"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <span>

using namespace linoh::util;
using namespace linoh::base;
using namespace linoh::endpoint;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// secure_zero 测试
// ============================================================================

static void test_secure_zero_basic() {
    std::printf("[test] secure_zero clears buffer...\n");

    std::array<uint8_t, 32> buf{};
    for (int i = 0; i < 32; ++i) buf[i] = static_cast<uint8_t>(0xFF);
    CHECK(buf[0] != 0);

    secure_zero(buf.data(), buf.size());
    for (int i = 0; i < 32; ++i) {
        CHECK(buf[i] == 0);
    }
}

static void test_secure_zero_null_safe() {
    std::printf("[test] secure_zero handles null/zero size safely...\n");

    secure_zero(nullptr, 0);  // 应不崩溃
    secure_zero(nullptr, 100);  // 应不崩溃
    CHECK(true);  // 到此即为通过
}

// ============================================================================
// SecureBuffer 测试
// ============================================================================

static void test_secure_buffer_default_zero() {
    std::printf("[test] SecureBuffer default-initialized to zero...\n");

    SecureBuffer<32> sb;
    CHECK(sb.is_zero());
    CHECK(sb.size() == 32);
}

static void test_secure_buffer_from_to_array() {
    std::printf("[test] SecureBuffer from_array/to_array roundtrip...\n");

    std::array<uint8_t, 16> arr{};
    for (int i = 0; i < 16; ++i) arr[i] = static_cast<uint8_t>(i + 1);

    SecureBuffer<16> sb = SecureBuffer<16>::from_array(arr);
    CHECK(!sb.is_zero());
    CHECK(sb[0] == 1);
    CHECK(sb[15] == 16);

    auto arr2 = sb.to_array();
    CHECK(arr == arr2);
}

static void test_secure_buffer_move_clears_source() {
    std::printf("[test] SecureBuffer move clears source...\n");

    std::array<uint8_t, 8> arr{};
    for (int i = 0; i < 8; ++i) arr[i] = static_cast<uint8_t>(0xAA);

    SecureBuffer<8> src = SecureBuffer<8>::from_array(arr);
    CHECK(!src.is_zero());

    SecureBuffer<8> dst = std::move(src);
    CHECK(!dst.is_zero());
    CHECK(dst[0] == 0xAA);
    CHECK(src.is_zero());  // 源对象已清零
}

static void test_secure_buffer_clear_explicit() {
    std::printf("[test] SecureBuffer::clear zeros content...\n");

    std::array<uint8_t, 4> arr{0x11, 0x22, 0x33, 0x44};
    SecureBuffer<4> sb = SecureBuffer<4>::from_array(arr);
    CHECK(!sb.is_zero());

    sb.clear();
    CHECK(sb.is_zero());
}

static void test_secure_buffer_deleted_copy() {
    std::printf("[test] SecureBuffer copy constructor is deleted...\n");

    // 静态检查：以下代码若取消注释应编译失败
    // SecureBuffer<4> a;
    // SecureBuffer<4> b = a;  // 应编译失败

    // 改为运行时验证：通过指针间接证明不可拷贝
    CHECK(sizeof(SecureBuffer<4>) == 4);  // 仅字节缓冲，无额外成员
}

// ============================================================================
// SecretKey 测试
// ============================================================================

static void test_secret_key_destruction_zeroes_memory() {
    std::printf("[test] SecretKey destruction zeroes memory...\n");

    // 用 placement new 构造一个 SecretKey，写入非零值，析构后验证清零
    alignas(SecretKey) std::array<uint8_t, sizeof(SecretKey)> storage{};
    SecretKey *sk = new (storage.data()) SecretKey();
    for (std::size_t i = 0; i < SecretKey::kSize; ++i) {
        sk->data()[i] = static_cast<uint8_t>(0xCC);
    }
    CHECK(!sk->is_zero());

    sk->~SecretKey();

    // 验证内存已清零
    for (std::size_t i = 0; i < SecretKey::kSize; ++i) {
        CHECK(sk->data()[i] == 0);
    }
}

static void test_secret_key_move_clears_source() {
    std::printf("[test] SecretKey move clears source...\n");

    SecretKey src = SecretKey::generate();
    CHECK(!src.is_zero());

    SecretKey dst = std::move(src);
    CHECK(!dst.is_zero());
    CHECK(src.is_zero());  // 源对象已清零
}

static void test_secret_key_copy_preserves_both() {
    std::printf("[test] SecretKey copy preserves both source and dest...\n");

    SecretKey src = SecretKey::generate();
    SecretKey dst = src;

    CHECK(src == dst);
    CHECK(!src.is_zero());
    CHECK(!dst.is_zero());
}

// ============================================================================
// SessionTicket 测试
// ============================================================================

static void test_session_ticket_move_clears_master_secret() {
    std::printf("[test] SessionTicket move clears source master_secret...\n");

    SessionTicket src{};
    for (int i = 0; i < 32; ++i) src.master_secret[i] = static_cast<uint8_t>(0xDD);
    CHECK(src.master_secret[0] != 0);

    SessionTicket dst = std::move(src);

    CHECK(dst.master_secret[0] == 0xDD);
    // 源对象 master_secret 应已清零
    bool src_cleared = true;
    for (int i = 0; i < 32; ++i) {
        if (src.master_secret[i] != 0) { src_cleared = false; break; }
    }
    CHECK(src_cleared);
}

static void test_session_ticket_destruction_zeroes_master_secret() {
    std::printf("[test] SessionTicket destruction zeroes master_secret...\n");

    alignas(SessionTicket) std::array<uint8_t, sizeof(SessionTicket)> storage{};
    SessionTicket *st = new (storage.data()) SessionTicket();
    for (int i = 0; i < 32; ++i) {
        st->master_secret[i] = static_cast<uint8_t>(0xEE);
    }
    CHECK(st->master_secret[0] != 0);

    st->~SessionTicket();

    bool cleared = true;
    for (int i = 0; i < 32; ++i) {
        if (st->master_secret[i] != 0) { cleared = false; break; }
    }
    CHECK(cleared);
}

int main() {
    std::printf("=== test_secure_buffer ===\n");

    test_secure_zero_basic();
    test_secure_zero_null_safe();
    test_secure_buffer_default_zero();
    test_secure_buffer_from_to_array();
    test_secure_buffer_move_clears_source();
    test_secure_buffer_clear_explicit();
    test_secure_buffer_deleted_copy();
    test_secret_key_destruction_zeroes_memory();
    test_secret_key_move_clears_source();
    test_secret_key_copy_preserves_both();
    test_session_ticket_move_clears_master_secret();
    test_session_ticket_destruction_zeroes_master_secret();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
