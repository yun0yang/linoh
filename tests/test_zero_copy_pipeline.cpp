// test_zero_copy_pipeline.cpp — v3.3.0 突破2: Zero-Copy 传输管道测试
//
// 覆盖范围：
//   1. ApplicationMessage::serialize_into / serialize_to / wire_size / total_wire_size
//   2. Stream::write_ref (swap fast path + append fallback)
//   3. Stream::write_scatter_ref (单 part swap fast path + 多 part append)
//   4. 零拷贝统计计数 (zero_copy_writes_ / total_writes_ / hit_rate)
//   5. 与 serialize() 对比一致性
//   6. 端到端零拷贝路径（serialize_into + write_ref）

#include "linoh/protocol/application_message.hpp"
#include "linoh/endpoint/connection.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace linoh;

// 简单断言宏（参考既有测试风格）
#define CHECK(cond) do { if (!(cond)) { \
    fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    ++g_failed; } else { ++g_passed; } } while (0)

static int g_passed = 0;
static int g_failed = 0;

// ========== ApplicationMessage 零拷贝序列化 ==========

// 测试 1: wire_size / total_wire_size 一致性
static void test_wire_size() {
    printf("[test] wire_size / total_wire_size...\n");
    std::vector<std::uint8_t> payload(1024, 0xAB);
    auto msg = protocol::ApplicationMessage::request(42, protocol::MethodId::ForwardPP, payload);

    CHECK(msg.wire_size() == protocol::ApplicationMessage::kHeaderSize + 1024);
    CHECK(protocol::ApplicationMessage::total_wire_size(1024) ==
          protocol::ApplicationMessage::kHeaderSize + 1024);
    CHECK(protocol::ApplicationMessage::total_wire_size(0) ==
          protocol::ApplicationMessage::kHeaderSize);
    CHECK(msg.wire_size() == msg.total_wire_size(msg.payload.size()));
}

// 测试 2: serialize_into 与 serialize() 输出一致
static void test_serialize_into_matches_serialize() {
    printf("[test] serialize_into matches serialize()...\n");
    std::vector<std::uint8_t> payload(256, 0x5A);
    auto msg = protocol::ApplicationMessage::request(100, protocol::MethodId::ResultPP, payload);

    auto ref = msg.serialize();  // 旧接口
    std::vector<std::uint8_t> into;
    std::size_t n = msg.serialize_into(into);  // 新接口

    CHECK(n == ref.size());
    CHECK(into.size() == ref.size());
    CHECK(std::memcmp(into.data(), ref.data(), ref.size()) == 0);
}

// 测试 3: serialize_into append 到非空 vector
static void test_serialize_into_append() {
    printf("[test] serialize_into append to non-empty vector...\n");
    std::vector<std::uint8_t> payload(64, 0xCC);
    auto msg = protocol::ApplicationMessage::notification(protocol::MethodId::Heartbeat, payload);

    std::vector<std::uint8_t> prefix = {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> out = prefix;  // 已有 3 字节

    std::size_t n = msg.serialize_into(out);

    CHECK(n == msg.wire_size());
    CHECK(out.size() == prefix.size() + msg.wire_size());
    // 前缀保留
    CHECK(out[0] == 0x01 && out[1] == 0x02 && out[2] == 0x03);
    // 序列化内容正确（从 offset 3 开始）
    auto ref = msg.serialize();
    CHECK(std::memcmp(out.data() + 3, ref.data(), ref.size()) == 0);
}

// 测试 4: serialize_into 多次 append（拼接多条消息）
static void test_serialize_into_multi_append() {
    printf("[test] serialize_into multi-append (batch messages)...\n");
    std::vector<std::uint8_t> payload1(32, 0xA1);
    std::vector<std::uint8_t> payload2(64, 0xA2);
    auto msg1 = protocol::ApplicationMessage::request(1, protocol::MethodId::ForwardPP, payload1);
    auto msg2 = protocol::ApplicationMessage::request(2, protocol::MethodId::ResultPP, payload2);

    std::vector<std::uint8_t> batch;
    batch.reserve(msg1.wire_size() + msg2.wire_size());
    std::size_t n1 = msg1.serialize_into(batch);
    std::size_t n2 = msg2.serialize_into(batch);

    CHECK(n1 == msg1.wire_size());
    CHECK(n2 == msg2.wire_size());
    CHECK(batch.size() == msg1.wire_size() + msg2.wire_size());

    // 解析验证第一条
    protocol::ApplicationMessage parsed1;
    std::size_t consumed1 = protocol::ApplicationMessage::parse(
        std::span<const std::uint8_t>(batch.data(), batch.size()), parsed1);
    CHECK(consumed1 == msg1.wire_size());
    CHECK(parsed1.request_id == 1);
    CHECK(parsed1.method_id == protocol::MethodId::ForwardPP);

    // 解析验证第二条
    protocol::ApplicationMessage parsed2;
    std::size_t consumed2 = protocol::ApplicationMessage::parse(
        std::span<const std::uint8_t>(batch.data() + consumed1, batch.size() - consumed1), parsed2);
    CHECK(consumed2 == msg2.wire_size());
    CHECK(parsed2.request_id == 2);
    CHECK(parsed2.method_id == protocol::MethodId::ResultPP);
}

// 测试 5: serialize_to 写入预分配 buffer
static void test_serialize_to_preallocated() {
    printf("[test] serialize_to preallocated buffer...\n");
    std::vector<std::uint8_t> payload(128, 0x77);
    auto msg = protocol::ApplicationMessage::response(55, protocol::MethodId::LoadModelAck, payload);

    std::vector<std::uint8_t> buf(msg.wire_size());
    std::size_t n = msg.serialize_to(std::span<std::uint8_t>(buf.data(), buf.size()));

    CHECK(n == msg.wire_size());
    auto ref = msg.serialize();
    CHECK(std::memcmp(buf.data(), ref.data(), ref.size()) == 0);
}

// 测试 6: serialize_to 容量不足返回 0
static void test_serialize_to_insufficient() {
    printf("[test] serialize_to insufficient capacity returns 0...\n");
    std::vector<std::uint8_t> payload(256, 0x33);
    auto msg = protocol::ApplicationMessage::request(1, protocol::MethodId::ForwardPP, payload);

    // 容量不足（只给 header 大小）
    std::vector<std::uint8_t> buf(protocol::ApplicationMessage::kHeaderSize);
    std::size_t n = msg.serialize_to(std::span<std::uint8_t>(buf.data(), buf.size()));
    CHECK(n == 0);

    // 容量刚好
    std::vector<std::uint8_t> buf2(msg.wire_size());
    n = msg.serialize_to(std::span<std::uint8_t>(buf2.data(), buf2.size()));
    CHECK(n == msg.wire_size());
}

// 测试 7: serialize_to 空 payload
static void test_serialize_to_empty_payload() {
    printf("[test] serialize_to empty payload...\n");
    std::vector<std::uint8_t> empty_payload;
    auto msg = protocol::ApplicationMessage::notification(
        protocol::MethodId::Heartbeat,
        std::span<const std::uint8_t>(empty_payload.data(), empty_payload.size()));

    std::vector<std::uint8_t> buf(msg.wire_size());
    std::size_t n = msg.serialize_to(std::span<std::uint8_t>(buf.data(), buf.size()));

    CHECK(n == protocol::ApplicationMessage::kHeaderSize);
    auto ref = msg.serialize();
    CHECK(std::memcmp(buf.data(), ref.data(), ref.size()) == 0);
}

// ========== Stream::write_ref 零拷贝接口 ==========

// 测试 8: write_ref swap fast path（send_ 空时 O(1)）
static void test_write_ref_swap_fast_path() {
    printf("[test] write_ref swap fast path (send_ empty)...\n");
    endpoint::Stream s(1, endpoint::Stream::Dir::Bidirectional);

    std::vector<std::uint8_t> wire(1024, 0xDE);
    auto *ptr_before = wire.data();  // 记录原始指针

    s.write_ref(std::move(wire));

    // fast path 命中：send_ 应接管 wire 的内存
    CHECK(s.zero_copy_writes() == 1);
    CHECK(s.total_writes() == 1);
    CHECK(s.zero_copy_hit_rate() == 1.0);
    CHECK(s.send_readable_size() == 1024);
    // swap 后 send_.data() 应等于原 wire.data()（真零拷贝，指针未变）
    CHECK(s.send_buffer().data() == ptr_before);
    // wire 应被清空
    CHECK(wire.empty());
}

// 测试 9: write_ref append fallback（send_ 非空时）
static void test_write_ref_append_fallback() {
    printf("[test] write_ref append fallback (send_ non-empty)...\n");
    endpoint::Stream s(1, endpoint::Stream::Dir::Bidirectional);

    // 先写入一些数据
    std::vector<std::uint8_t> first(100, 0x11);
    s.write_ref(std::move(first));  // fast path
    CHECK(s.zero_copy_writes() == 1);

    // 再写入 — 此时 send_ 非空，走 fallback
    std::vector<std::uint8_t> second(200, 0x22);
    s.write_ref(std::move(second));

    CHECK(s.zero_copy_writes() == 1);  // 仍是 1（第二次未命中 fast path）
    CHECK(s.total_writes() == 2);
    CHECK(s.zero_copy_hit_rate() == 0.5);
    CHECK(s.send_readable_size() == 300);

    // 验证内容正确
    const auto *p = s.send_readable_data();
    for (std::size_t i = 0; i < 100; ++i) CHECK(p[i] == 0x11);
    for (std::size_t i = 100; i < 300; ++i) CHECK(p[i] == 0x22);
}

// 测试 10: write_ref consume 后再写命中 fast path
static void test_write_ref_consume_then_fast_path() {
    printf("[test] write_ref consume-then-write fast path...\n");
    endpoint::Stream s(1, endpoint::Stream::Dir::Bidirectional);

    // 写入并消费
    std::vector<std::uint8_t> first(100, 0x33);
    s.write_ref(std::move(first));
    CHECK(s.zero_copy_writes() == 1);

    s.consume_send(100);  // 消费全部
    CHECK(s.send_readable_size() == 0);
    // 注：consume_send 后 send_read_pos_ != 0，send_ 非空，不满足 fast path 条件

    // 清空 send 后再写
    s.clear_send();
    CHECK(s.send_readable_size() == 0);

    std::vector<std::uint8_t> second(200, 0x44);
    s.write_ref(std::move(second));

    // clear_send 后 send_ 为空 + send_read_pos_==0 → 命中 fast path
    CHECK(s.zero_copy_writes() == 2);
    CHECK(s.total_writes() == 2);
    CHECK(s.send_readable_size() == 200);
}

// 测试 11: write_ref 空 vector 不计数
static void test_write_ref_empty_no_count() {
    printf("[test] write_ref empty vector no count...\n");
    endpoint::Stream s(1, endpoint::Stream::Dir::Bidirectional);

    std::vector<std::uint8_t> empty;
    s.write_ref(std::move(empty));

    CHECK(s.zero_copy_writes() == 0);
    CHECK(s.total_writes() == 0);
    CHECK(s.send_readable_size() == 0);
}

// 测试 12: write_ref closed stream 拒绝
static void test_write_ref_closed_stream() {
    printf("[test] write_ref closed stream rejected...\n");
    endpoint::Stream s(1, endpoint::Stream::Dir::Bidirectional);
    s.close();

    std::vector<std::uint8_t> wire(100, 0x55);
    s.write_ref(std::move(wire));

    CHECK(s.total_writes() == 0);
    CHECK(s.send_readable_size() == 0);
    // wire 应被清空（所有权语义一致）
    CHECK(wire.empty());
}

// ========== Stream::write_scatter_ref ==========

// 测试 13: write_scatter_ref 单 part swap fast path
static void test_write_scatter_ref_single_swap() {
    printf("[test] write_scatter_ref single part swap fast path...\n");
    endpoint::Stream s(1, endpoint::Stream::Dir::Bidirectional);

    std::vector<std::vector<std::uint8_t>> parts;
    parts.push_back(std::vector<std::uint8_t>(500, 0x66));

    s.write_scatter_ref(std::move(parts));

    CHECK(s.zero_copy_writes() == 1);  // 单 part swap 命中
    CHECK(s.total_writes() == 1);
    CHECK(s.send_readable_size() == 500);
    CHECK(parts.empty());
}

// 测试 14: write_scatter_ref 多 part append
static void test_write_scatter_ref_multi_append() {
    printf("[test] write_scatter_ref multi part append...\n");
    endpoint::Stream s(1, endpoint::Stream::Dir::Bidirectional);

    std::vector<std::vector<std::uint8_t>> parts;
    parts.push_back(std::vector<std::uint8_t>(100, 0x77));
    parts.push_back(std::vector<std::uint8_t>(200, 0x88));
    parts.push_back(std::vector<std::uint8_t>(300, 0x99));

    s.write_scatter_ref(std::move(parts));

    // 多 part → fallback，不命中 swap fast path
    CHECK(s.zero_copy_writes() == 0);
    CHECK(s.total_writes() == 1);
    CHECK(s.send_readable_size() == 600);

    const auto *p = s.send_readable_data();
    for (std::size_t i = 0; i < 100; ++i) CHECK(p[i] == 0x77);
    for (std::size_t i = 100; i < 300; ++i) CHECK(p[i] == 0x88);
    for (std::size_t i = 300; i < 600; ++i) CHECK(p[i] == 0x99);
    CHECK(parts.empty());
}

// 测试 15: write_scatter_ref 空 parts 不计数
static void test_write_scatter_ref_empty_no_count() {
    printf("[test] write_scatter_ref empty parts no count...\n");
    endpoint::Stream s(1, endpoint::Stream::Dir::Bidirectional);

    std::vector<std::vector<std::uint8_t>> parts;  // 空
    s.write_scatter_ref(std::move(parts));

    CHECK(s.total_writes() == 0);
    CHECK(s.send_readable_size() == 0);
}

// ========== 旧接口统计计数 ==========

// 测试 16: write / write_scatter 计数（非零拷贝路径）
static void test_write_count_legacy() {
    printf("[test] write / write_scatter count legacy...\n");
    endpoint::Stream s(1, endpoint::Stream::Dir::Bidirectional);

    std::vector<std::uint8_t> data(100, 0xAA);
    s.write(std::span<const std::uint8_t>(data.data(), data.size()));

    CHECK(s.total_writes() == 1);
    CHECK(s.zero_copy_writes() == 0);  // write 不命中零拷贝
    CHECK(s.zero_copy_hit_rate() == 0.0);

    std::vector<std::span<const std::uint8_t>> parts = {
        std::span<const std::uint8_t>(data.data(), 50),
        std::span<const std::uint8_t>(data.data() + 50, 50)};
    s.write_scatter(parts);

    CHECK(s.total_writes() == 2);
    CHECK(s.zero_copy_writes() == 0);
}

// ========== 端到端零拷贝路径 ==========

// 测试 17: 端到端 serialize_into + write_ref（消除 2 次拷贝）
static void test_e2e_serialize_into_write_ref() {
    printf("[test] e2e serialize_into + write_ref (zero-copy)...\n");
    // 模拟推理 hidden_state 发送
    std::vector<std::uint8_t> hidden_state(4096, 0xBEEF & 0xFF);
    auto msg = protocol::ApplicationMessage::request(
        999, protocol::MethodId::ForwardPP,
        std::span<const std::uint8_t>(hidden_state.data(), hidden_state.size()));

    endpoint::Stream s(1, endpoint::Stream::Dir::Bidirectional);

    // 零拷贝路径：预分配 + serialize_into + write_ref
    std::vector<std::uint8_t> wire;
    wire.reserve(msg.wire_size());
    msg.serialize_into(wire);
    s.write_ref(std::move(wire));  // send_ 空时 O(1) swap

    CHECK(s.zero_copy_writes() == 1);
    CHECK(s.total_writes() == 1);
    CHECK(s.send_readable_size() == msg.wire_size());

    // 解析验证内容正确
    auto *data = s.send_readable_data();
    protocol::ApplicationMessage parsed;
    std::size_t consumed = protocol::ApplicationMessage::parse(
        std::span<const std::uint8_t>(data, s.send_readable_size()), parsed);
    CHECK(consumed == msg.wire_size());
    CHECK(parsed.request_id == 999);
    CHECK(parsed.method_id == protocol::MethodId::ForwardPP);
    CHECK(parsed.payload.size() == 4096);
    CHECK(std::memcmp(parsed.payload.data(), hidden_state.data(), 4096) == 0);
}

// 测试 18: 对比旧路径 vs 新路径输出一致
static void test_new_path_matches_old_path() {
    printf("[test] new path (serialize_into+write_ref) matches old path (serialize+write)...\n");
    std::vector<std::uint8_t> payload(512, 0x42);
    auto msg = protocol::ApplicationMessage::request(
        777, protocol::MethodId::ResultPP,
        std::span<const std::uint8_t>(payload.data(), payload.size()));

    // 旧路径
    endpoint::Stream s_old(1, endpoint::Stream::Dir::Bidirectional);
    auto wire_old = msg.serialize();
    s_old.write(std::span<const std::uint8_t>(wire_old.data(), wire_old.size()));

    // 新路径
    endpoint::Stream s_new(2, endpoint::Stream::Dir::Bidirectional);
    std::vector<std::uint8_t> wire_new;
    wire_new.reserve(msg.wire_size());
    msg.serialize_into(wire_new);
    s_new.write_ref(std::move(wire_new));

    // 两者输出完全一致
    CHECK(s_old.send_readable_size() == s_new.send_readable_size());
    CHECK(std::memcmp(s_old.send_readable_data(), s_new.send_readable_data(),
                      s_old.send_readable_size()) == 0);

    // 新路径命中零拷贝
    CHECK(s_new.zero_copy_writes() == 1);
    CHECK(s_old.zero_copy_writes() == 0);
}

// 测试 19: write_ref 多次连续调用（batch 发送）
static void test_write_ref_batch() {
    printf("[test] write_ref batch (clear_send between writes)...\n");
    endpoint::Stream s(1, endpoint::Stream::Dir::Bidirectional);

    for (int i = 0; i < 5; ++i) {
        // 每次都清空 send，确保命中 fast path
        if (i > 0) {
            s.consume_send(s.send_readable_size());
            s.clear_send();
        }
        std::vector<std::uint8_t> wire(100, static_cast<std::uint8_t>(i));
        s.write_ref(std::move(wire));
    }

    // 5 次都应命中 fast path
    CHECK(s.zero_copy_writes() == 5);
    CHECK(s.total_writes() == 5);
    CHECK(s.zero_copy_hit_rate() == 1.0);
}

// 测试 20: 大 payload 零拷贝（模拟 hidden_state 64KB）
static void test_write_ref_large_payload() {
    printf("[test] write_ref large payload (64KB hidden_state)...\n");
    std::size_t large_size = 64 * 1024;
    std::vector<std::uint8_t> large(large_size);
    for (std::size_t i = 0; i < large_size; ++i) large[i] = static_cast<std::uint8_t>(i & 0xFF);

    auto msg = protocol::ApplicationMessage::request(
        1, protocol::MethodId::ForwardPP,
        std::span<const std::uint8_t>(large.data(), large.size()));

    endpoint::Stream s(1, endpoint::Stream::Dir::Bidirectional);

    std::vector<std::uint8_t> wire;
    wire.reserve(msg.wire_size());
    msg.serialize_into(wire);
    auto *ptr = wire.data();  // 记录指针，验证 swap 后不变
    s.write_ref(std::move(wire));

    CHECK(s.zero_copy_writes() == 1);
    CHECK(s.send_buffer().data() == ptr);  // 真零拷贝，指针未变
    CHECK(s.send_readable_size() == msg.wire_size());
}

int main() {
    printf("=== test_zero_copy_pipeline (v3.3.0 突破2) ===\n\n");

    test_wire_size();
    test_serialize_into_matches_serialize();
    test_serialize_into_append();
    test_serialize_into_multi_append();
    test_serialize_to_preallocated();
    test_serialize_to_insufficient();
    test_serialize_to_empty_payload();

    test_write_ref_swap_fast_path();
    test_write_ref_append_fallback();
    test_write_ref_consume_then_fast_path();
    test_write_ref_empty_no_count();
    test_write_ref_closed_stream();

    test_write_scatter_ref_single_swap();
    test_write_scatter_ref_multi_append();
    test_write_scatter_ref_empty_no_count();

    test_write_count_legacy();

    test_e2e_serialize_into_write_ref();
    test_new_path_matches_old_path();
    test_write_ref_batch();
    test_write_ref_large_payload();

    printf("\n=== Summary: %d passed, %d failed ===\n", g_passed, g_failed);
    return g_failed == 0 ? 0 : 1;
}
