// test_stream_fin_half_close.cpp — A9 fix: Stream FIN-only 半关闭验证
//
// 验证 RFC 9000 §3.2：发送 FIN 只关闭发送方向，接收方向必须保持可用。
//
// Bug 场景（修复前）：
//   1. linoh_stream_finish → send_finished_=true
//   2. build_1rtt_packet FIN-only 分支调用 st->close()
//   3. close() 设置 closed_=true + recv_.clear() + recv_read_pos_=0
//   4. 对端发来数据 → recv() 检查 closed_=true → 丢弃
//   5. readable_size()=0 → 应用层读不到数据
//
// 修复后：
//   1. linoh_stream_finish → send_finished_=true
//   2. build_1rtt_packet FIN-only 分支调用 st->close_send()
//   3. close_send() 只清 send 侧 + send_closed_=true，不动 recv
//   4. 对端发来数据 → recv() 检查 closed_=false → 正常写入 recv_
//   5. readable_size()>0 → 应用层可读

#include "linoh/endpoint/connection.hpp"
#include "linoh/util/bytes.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace linoh;
using namespace linoh::endpoint;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (%lld != %lld) (line %d)\n", \
        #a, #b, (long long)_a, (long long)_b, __LINE__); } \
} while (0)

// ============================================================================
// TEST 1: close_send() 只半关闭发送方向，recv 保持可用
// ============================================================================
static void test_close_send_preserves_recv() {
    std::printf("[test] close_send() preserves recv direction...\n");

    Stream st(1, Stream::Dir::Bidirectional);

    // 写入一些发送数据
    std::vector<std::uint8_t> send_data = {1, 2, 3, 4, 5};
    st.write(send_data);
    CHECK_EQ(st.send_readable_size(), 5ull);

    // 调用 close_send()（模拟 FIN-only 帧发送后）
    st.close_send();

    // 发送方向已关闭
    CHECK(st.send_closed() == true);
    CHECK(st.send_readable_size() == 0);  // send_ 已清空

    // 接收方向仍可用（核心断言）
    CHECK(st.is_closed() == false);       // 未完全关闭
    CHECK(st.readable_size() == 0);       // 初始无数据，但 recv_ 缓冲区可用

    // recv 写入数据（模拟对端发来 JOIN_ACK）
    std::vector<std::uint8_t> recv_data = {0xA1, 0xB2, 0xC3, 0xD4};
    st.recv(recv_data);

    // 验证 recv 方向正常工作
    CHECK(st.readable_size() == 4);       // 收到 4 字节
    auto readable = st.read(4);
    CHECK(readable.size() == 4);
    CHECK(readable[0] == 0xA1);
    CHECK(readable[3] == 0xD4);

    // consume 后继续可读
    st.consume(2);
    CHECK(st.readable_size() == 2);

    // 再次 recv 仍可用（offset=4 接在之前 4 字节之后）
    std::vector<std::uint8_t> more_data = {0xE5, 0xF6};
    st.recv(more_data, 4);
    CHECK(st.readable_size() == 4);  // 2 剩余 + 2 新增

    std::printf("    close_send() preserves recv: OK\n");
}

// ============================================================================
// TEST 2: close_send() 后 write() 被拒绝（发送方向已关闭）
// ============================================================================
static void test_write_rejected_after_close_send() {
    std::printf("[test] write() rejected after close_send()...\n");

    Stream st(2, Stream::Dir::Bidirectional);

    st.close_send();

    // write 应被拒绝（send_closed_）
    std::vector<std::uint8_t> data = {1, 2, 3};
    st.write(data);
    CHECK(st.send_readable_size() == 0);  // 未写入

    // write_scatter 也应被拒绝
    std::vector<std::span<const std::uint8_t>> parts = {data};
    st.write_scatter(parts);
    CHECK(st.send_readable_size() == 0);  // 未写入

    std::printf("    write rejected after close_send: OK\n");
}

// ============================================================================
// TEST 3: close() 完全关闭，recv 也被拒绝（与 close_send 区分）
// ============================================================================
static void test_close_rejects_both_directions() {
    std::printf("[test] close() rejects both directions...\n");

    Stream st(3, Stream::Dir::Bidirectional);

    // 先 recv 一些数据
    std::vector<std::uint8_t> recv_data = {1, 2, 3};
    st.recv(recv_data);
    CHECK(st.readable_size() == 3);

    // 完全关闭
    st.close();

    CHECK(st.is_closed() == true);
    CHECK(st.readable_size() == 0);  // recv_ 被清空

    // close 后 recv 被拒绝
    std::vector<std::uint8_t> more_data = {4, 5, 6};
    st.recv(more_data);
    CHECK(st.readable_size() == 0);  // 被拒绝

    std::printf("    close rejects both directions: OK\n");
}

// ============================================================================
// TEST 4: FIN-only 场景模拟 — finish_send + close_send 后 recv 可用
// ============================================================================
static void test_fin_only_scenario() {
    std::printf("[test] FIN-only scenario: finish_send + close_send, recv still works...\n");

    Stream st(4, Stream::Dir::Bidirectional);

    // 模拟应用层写入 + finish
    std::vector<std::uint8_t> payload = {'H', 'e', 'l', 'l', 'o'};
    st.write(payload);
    st.finish_send();  // linoh_stream_finish → send_finished_=true
    CHECK(st.send_finished() == true);
    CHECK(st.send_closed() == false);  // FIN 帧尚未发送

    // 模拟 build_1rtt_packet 排空 send 缓冲
    st.consume_send(5);
    CHECK(st.send_readable_size() == 0);

    // 模拟 FIN-only 分支触发
    // 条件: send_finished() && send_readable_size()==0 && !send_closed()
    if (st.send_finished() && st.send_readable_size() == 0 && !st.send_closed()) {
        st.close_send();  // FIN-only 帧已发送
    }

    CHECK(st.send_closed() == true);
    CHECK(st.is_closed() == false);  // 核心断言：未完全关闭

    // 对端发来响应数据（如 JOIN_ACK）
    std::vector<std::uint8_t> ack = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    st.recv(ack);

    // 应用层可读到响应
    CHECK(st.readable_size() == 6);
    auto resp = st.read(6);
    CHECK(resp.size() == 6);
    CHECK(resp[0] == 0x00);
    CHECK(resp[5] == 0x05);

    std::printf("    FIN-only scenario recv works: OK\n");
}

int main() {
    std::printf("=== test_stream_fin_half_close (A9 fix) ===\n");
    test_close_send_preserves_recv();
    test_write_rejected_after_close_send();
    test_close_rejects_both_directions();
    test_fin_only_scenario();
    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
