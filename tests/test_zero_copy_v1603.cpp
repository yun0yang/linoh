// test_zero_copy_v1603.cpp — v1.6.0.3 (P2) 零拷贝路径单元测试
//
// 测试覆盖：
//   1. ZeroCopySender 构造 + is_valid
//   2. ZeroCopySender acquire_buffer
//   3. ZeroCopySender send_dispatch（无 channel 时失败）
//   4. ZeroCopySender send_combine（无 channel 时失败）
//   5. ZeroCopySender padding 填充
//   6. ZeroCopySender stats 统计
//   7. ZeroCopyReceiver 构造
//   8. ZeroCopyReceiver handle_dispatch_frame
//   9. ZeroCopyReceiver handle_combine_frame
//  10. ZeroCopyReceiver 回调
//  11. ZeroCopyReceiver pool 耗尽
//  12. ZeroCopyReceiver stats 统计
//  13. Stream::write_scatter 多段拼接
//  14. Stream::write_scatter 空输入
//  15. Stream::write_scatter 单段等价 write

#include "linoh/multimodal/buffer_pool.hpp"
#include "linoh/multimodal/ep_frames.hpp"
#include "linoh/multimodal/zero_copy.hpp"
#include "linoh/multimodal/static_shape.hpp"
#include "linoh/endpoint/connection.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace linoh;
using namespace linoh::multimodal;
using namespace linoh::multimodal::ep;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

#define CHECK_EQ(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a == _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s == %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

#define CHECK_GE(a, b) do { \
    auto _a = (a); auto _b = (b); \
    if (_a >= _b) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s >= %s (line %d)\n", #a, #b, __LINE__); } \
} while (0)

// ============================================================================
// TEST 1: ZeroCopySender 构造 + is_valid
// ============================================================================

static void test_sender_construction() {
    std::printf("[test] ZeroCopySender construction...\n");
    StaticBufferPool pool(4, 1024);
    ZeroCopySender sender(&pool, nullptr);
    CHECK(!sender.is_valid());  // channel 为 null

    ZeroCopySender sender2(&pool, nullptr);
    CHECK(!sender2.is_valid());
}

// ============================================================================
// TEST 2: ZeroCopySender acquire_buffer
// ============================================================================

static void test_sender_acquire_buffer() {
    std::printf("[test] ZeroCopySender acquire_buffer...\n");
    StaticBufferPool pool(2, 512);
    ZeroCopySender sender(&pool, nullptr);
    auto buf = sender.acquire_buffer();
    CHECK(buf.valid());
    CHECK_EQ(buf.size(), static_cast<std::size_t>(512));
}

// ============================================================================
// TEST 3: ZeroCopySender send_dispatch 无 channel 失败
// ============================================================================

static void test_sender_dispatch_no_channel() {
    std::printf("[test] ZeroCopySender send_dispatch no channel fails...\n");
    StaticBufferPool pool(2, 256);
    TensorShapeNegotiator neg;
    ZeroCopySender sender(&pool, nullptr, &neg);

    auto buf = sender.acquire_buffer();
    CHECK(buf.valid());
    std::memset(buf.data_ptr(), 0xAB, 100);
    bool ok = sender.send_dispatch(1, 0, 10, std::move(buf), 100);
    CHECK(!ok);  // channel 为 null

    auto stats = sender.stats();
    CHECK_GE(stats.pool_exhaust_total, static_cast<std::uint64_t>(1));
}

// ============================================================================
// TEST 4: ZeroCopySender send_combine 无 channel 失败
// ============================================================================

static void test_sender_combine_no_channel() {
    std::printf("[test] ZeroCopySender send_combine no channel fails...\n");
    StaticBufferPool pool(2, 256);
    ZeroCopySender sender(&pool, nullptr);

    auto buf = sender.acquire_buffer();
    bool ok = sender.send_combine(1, 0, 10, std::move(buf), 50);
    CHECK(!ok);
}

// ============================================================================
// TEST 5: ZeroCopySender padding 填充
// ============================================================================

static void test_sender_padding() {
    std::printf("[test] ZeroCopySender padding fill...\n");
    StaticBufferPool pool(1, 256);
    TensorShapeNegotiator neg;
    ShapeDescriptor local{TensorDType::F32, 8, 8, 1};  // 8*8*4=256 bytes
    ShapeDescriptor remote{TensorDType::F32, 8, 8, 1};
    neg.negotiate(local, remote);
    CHECK_EQ(neg.padded_bytes(), static_cast<std::uint64_t>(256));

    ZeroCopySender sender(&pool, nullptr, &neg);
    auto buf = sender.acquire_buffer();
    CHECK(buf.valid());
    // 填充前 100 字节为 0xAB
    std::memset(buf.data_ptr(), 0xAB, 100);
    // 剩余部分应被 padding 清零（通过 send_internal_ 中的 fill_padding_）
    // 由于无 channel，send_dispatch 会失败，但 padding 已填充
    sender.send_dispatch(1, 0, 10, std::move(buf), 100);

    auto stats = sender.stats();
    CHECK_GE(stats.padding_fill_total, static_cast<std::uint64_t>(1));
}

// ============================================================================
// TEST 6: ZeroCopySender stats 统计
// ============================================================================

static void test_sender_stats() {
    std::printf("[test] ZeroCopySender stats...\n");
    StaticBufferPool pool(2, 256);
    ZeroCopySender sender(&pool, nullptr);

    auto buf1 = sender.acquire_buffer();
    sender.send_dispatch(1, 0, 10, std::move(buf1), 50);  // 失败（无 channel）

    auto buf2 = sender.acquire_buffer();
    sender.send_combine(2, 0, 10, std::move(buf2), 50);  // 失败

    auto stats = sender.stats();
    CHECK_GE(stats.pool_exhaust_total, static_cast<std::uint64_t>(2));
}

// ============================================================================
// TEST 7: ZeroCopyReceiver 构造
// ============================================================================

static void test_receiver_construction() {
    std::printf("[test] ZeroCopyReceiver construction...\n");
    StaticBufferPool pool(4, 1024);
    ZeroCopyReceiver receiver(&pool);
    auto stats = receiver.stats();
    CHECK_EQ(stats.recv_total, static_cast<std::uint64_t>(0));
}

// ============================================================================
// TEST 8: ZeroCopyReceiver handle_dispatch_frame
// ============================================================================

static void test_receiver_handle_dispatch() {
    std::printf("[test] ZeroCopyReceiver handle_dispatch_frame...\n");
    StaticBufferPool pool(2, 1024);
    ZeroCopyReceiver receiver(&pool);

    std::uint64_t recv_tensor_id = 0;
    std::size_t recv_bytes = 0;
    receiver.set_callback([&](std::uint64_t tid, BorrowedBuffer buf, std::size_t bytes) {
        recv_tensor_id = tid;
        recv_bytes = bytes;
    });

    EpDispatchFrame frame;
    frame.tensor_id = 5001;
    frame.expert_id = 3;
    frame.token_cnt = 100;
    frame.payload.resize(256);
    std::memset(frame.payload.data(), 0xCD, 256);

    bool ok = receiver.handle_dispatch_frame(frame);
    CHECK(ok);
    CHECK_EQ(recv_tensor_id, static_cast<std::uint64_t>(5001));
    CHECK_EQ(recv_bytes, static_cast<std::size_t>(256));

    auto stats = receiver.stats();
    CHECK_EQ(stats.recv_total, static_cast<std::uint64_t>(1));
    CHECK_EQ(stats.recv_bytes, static_cast<std::uint64_t>(256));
}

// ============================================================================
// TEST 9: ZeroCopyReceiver handle_combine_frame
// ============================================================================

static void test_receiver_handle_combine() {
    std::printf("[test] ZeroCopyReceiver handle_combine_frame...\n");
    StaticBufferPool pool(2, 1024);
    ZeroCopyReceiver receiver(&pool);

    EpCombineFrame frame;
    frame.tensor_id = 6001;
    frame.expert_id = 5;
    frame.token_cnt = 50;
    frame.payload.resize(128);

    bool ok = receiver.handle_combine_frame(frame);
    CHECK(ok);
}

// ============================================================================
// TEST 10: ZeroCopyReceiver 回调接收数据
// ============================================================================

static void test_receiver_callback_data() {
    std::printf("[test] ZeroCopyReceiver callback data...\n");
    StaticBufferPool pool(1, 512);
    ZeroCopyReceiver receiver(&pool);

    std::vector<std::uint8_t> recv_data;
    receiver.set_callback([&](std::uint64_t, BorrowedBuffer buf, std::size_t bytes) {
        recv_data.assign(buf.data().begin(), buf.data().begin() + bytes);
    });

    EpDispatchFrame frame;
    frame.tensor_id = 7001;
    frame.payload = {0x11, 0x22, 0x33, 0x44, 0x55};
    receiver.handle_dispatch_frame(frame);

    CHECK_EQ(recv_data.size(), static_cast<std::size_t>(5));
    CHECK_EQ(recv_data[0], static_cast<int>(0x11));
    CHECK_EQ(recv_data[4], static_cast<int>(0x55));
}

// ============================================================================
// TEST 11: ZeroCopyReceiver pool 耗尽
// ============================================================================

static void test_receiver_pool_exhaust() {
    std::printf("[test] ZeroCopyReceiver pool exhaust...\n");
    StaticBufferPool pool(1, 256);
    ZeroCopyReceiver receiver(&pool);

    // 先 acquire 占用唯一的 buffer
    auto held = pool.acquire();

    EpDispatchFrame frame;
    frame.tensor_id = 8001;
    frame.payload.resize(100);

    bool ok = receiver.handle_dispatch_frame(frame);
    CHECK(!ok);  // pool 耗尽

    auto stats = receiver.stats();
    CHECK_GE(stats.pool_exhaust_total, static_cast<std::uint64_t>(1));
}

// ============================================================================
// TEST 12: ZeroCopyReceiver stats
// ============================================================================

static void test_receiver_stats() {
    std::printf("[test] ZeroCopyReceiver stats...\n");
    StaticBufferPool pool(4, 1024);
    ZeroCopyReceiver receiver(&pool);

    for (int i = 0; i < 3; ++i) {
        EpDispatchFrame frame;
        frame.tensor_id = 9001 + i;
        frame.payload.resize(100);
        receiver.handle_dispatch_frame(frame);
    }

    auto stats = receiver.stats();
    CHECK_EQ(stats.recv_total, static_cast<std::uint64_t>(3));
    CHECK_EQ(stats.recv_bytes, static_cast<std::uint64_t>(300));
}

// ============================================================================
// TEST 13: Stream::write_scatter 多段拼接
// ============================================================================

static void test_stream_write_scatter() {
    std::printf("[test] Stream::write_scatter multi-part...\n");
    endpoint::Stream stream(1, endpoint::Stream::Dir::Bidirectional);

    std::vector<std::uint8_t> part1 = {1, 2, 3, 4};
    std::vector<std::uint8_t> part2 = {5, 6, 7};
    std::vector<std::uint8_t> part3 = {8, 9, 10, 11, 12};

    std::vector<std::span<const std::uint8_t>> parts = {
        std::span<const std::uint8_t>(part1),
        std::span<const std::uint8_t>(part2),
        std::span<const std::uint8_t>(part3)
    };
    stream.write_scatter(parts);

    auto &send_buf = stream.send_buffer();
    CHECK_EQ(send_buf.size(), static_cast<std::size_t>(12));
    CHECK_EQ(send_buf[0], static_cast<int>(1));
    CHECK_EQ(send_buf[3], static_cast<int>(4));
    CHECK_EQ(send_buf[4], static_cast<int>(5));
    CHECK_EQ(send_buf[6], static_cast<int>(7));
    CHECK_EQ(send_buf[7], static_cast<int>(8));
    CHECK_EQ(send_buf[11], static_cast<int>(12));
}

// ============================================================================
// TEST 14: Stream::write_scatter 空输入
// ============================================================================

static void test_stream_write_scatter_empty() {
    std::printf("[test] Stream::write_scatter empty...\n");
    endpoint::Stream stream(2, endpoint::Stream::Dir::Bidirectional);

    std::vector<std::span<const std::uint8_t>> empty_parts;
    stream.write_scatter(empty_parts);

    CHECK_EQ(stream.send_buffer().size(), static_cast<std::size_t>(0));
}

// ============================================================================
// TEST 15: Stream::write_scatter 单段等价 write
// ============================================================================

static void test_stream_write_scatter_single() {
    std::printf("[test] Stream::write_scatter single == write...\n");
    endpoint::Stream s1(3, endpoint::Stream::Dir::Bidirectional);
    endpoint::Stream s2(4, endpoint::Stream::Dir::Bidirectional);

    std::vector<std::uint8_t> data = {0xAA, 0xBB, 0xCC, 0xDD};

    s1.write(std::span<const std::uint8_t>(data));
    std::vector<std::span<const std::uint8_t>> parts = {
        std::span<const std::uint8_t>(data)
    };
    s2.write_scatter(parts);

    CHECK_EQ(s1.send_buffer().size(), s2.send_buffer().size());
    CHECK_EQ(s1.send_buffer()[0], s2.send_buffer()[0]);
    CHECK_EQ(s1.send_buffer()[3], s2.send_buffer()[3]);
}

// ============================================================================
// TEST 16: Stream::write_scatter 与 write 混合
// ============================================================================

static void test_stream_write_scatter_mixed() {
    std::printf("[test] Stream::write_scatter mixed with write...\n");
    endpoint::Stream stream(5, endpoint::Stream::Dir::Bidirectional);

    std::vector<std::uint8_t> first = {1, 2};
    stream.write(std::span<const std::uint8_t>(first));

    std::vector<std::uint8_t> part_a = {3, 4};
    std::vector<std::uint8_t> part_b = {5, 6, 7};
    std::vector<std::span<const std::uint8_t>> parts = {
        std::span<const std::uint8_t>(part_a),
        std::span<const std::uint8_t>(part_b)
    };
    stream.write_scatter(parts);

    CHECK_EQ(stream.send_buffer().size(), static_cast<std::size_t>(7));
    CHECK_EQ(stream.send_buffer()[0], static_cast<int>(1));
    CHECK_EQ(stream.send_buffer()[6], static_cast<int>(7));
}

int main() {
    std::printf("=== test_zero_copy_v1603 ===\n");
    test_sender_construction();
    test_sender_acquire_buffer();
    test_sender_dispatch_no_channel();
    test_sender_combine_no_channel();
    test_sender_padding();
    test_sender_stats();
    test_receiver_construction();
    test_receiver_handle_dispatch();
    test_receiver_handle_combine();
    test_receiver_callback_data();
    test_receiver_pool_exhaust();
    test_receiver_stats();
    test_stream_write_scatter();
    test_stream_write_scatter_empty();
    test_stream_write_scatter_single();
    test_stream_write_scatter_mixed();
    std::printf("\n=== Results: %d PASS, %d FAIL ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
