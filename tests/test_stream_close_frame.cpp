// test_stream_close_frame.cpp — P0-3/P0-4 STREAM 帧和 CONNECTION_CLOSE 帧解析测试
//
// 验证 packet.cpp 的 parse_frames 正确解析 STREAM 帧和 CONNECTION_CLOSE 帧，
// 并且后续帧能被正确切分（不再被并入前一帧的 data）。
//
// 测试覆盖：
//   1. STREAM 帧基本解析（无 OFF/LEN/FIN）
//   2. STREAM 帧带 OFF + LEN + FIN
//   3. STREAM 帧无 LEN（data 占满剩余）
//   4. STREAM 帧后跟 PADDING/HANDSHAKE_DONE 等帧（多帧共存）
//   5. CONNECTION_CLOSE 帧基本解析（error_code + reason）
//   6. CONNECTION_CLOSE 帧 frame_type 字段
//   7. APPLICATION_CLOSE（0x1d）无 frame_type

#include "linoh/protocol/packet.hpp"
#include "linoh/util/varint.hpp"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <vector>

using namespace linoh::protocol;
using linoh::util::varint_encode_vec;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// 辅助：构造 payload
static std::vector<uint8_t> build_payload(std::initializer_list<uint8_t> bytes) {
    return std::vector<uint8_t>(bytes);
}

static void test_stream_frame_basic() {
    std::printf("[test] STREAM frame basic (no OFF/LEN/FIN)...\n");

    // type=0x08 (no flags), stream_id=5 (1B varint), data="hello"
    std::vector<uint8_t> payload;
    payload.push_back(0x08);  // type
    auto sid = varint_encode_vec(5);
    payload.insert(payload.end(), sid.begin(), sid.end());
    payload.push_back('h');
    payload.push_back('e');
    payload.push_back('l');
    payload.push_back('l');
    payload.push_back('o');

    auto frames = PacketParser::parse_frames(std::span<const uint8_t>(payload.data(), payload.size()));
    CHECK(frames.size() == 1);
    CHECK(static_cast<uint8_t>(frames[0].type) == 0x08);
    // f.data 应包含 stream_id + data
    CHECK(frames[0].data.size() == 1 + 5);  // sid(1) + "hello"(5)
    CHECK(frames[0].data[0] == 5);  // stream_id
}

static void test_stream_frame_all_flags() {
    std::printf("[test] STREAM frame with OFF+LEN+FIN...\n");

    // type=0x0f (OFF+LEN+FIN), stream_id=3, offset=100, length=4, data="test"
    std::vector<uint8_t> payload;
    payload.push_back(0x0f);
    auto sid = varint_encode_vec(3);
    payload.insert(payload.end(), sid.begin(), sid.end());
    auto off = varint_encode_vec(100);
    payload.insert(payload.end(), off.begin(), off.end());
    auto len = varint_encode_vec(4);
    payload.insert(payload.end(), len.begin(), len.end());
    payload.push_back('t');
    payload.push_back('e');
    payload.push_back('s');
    payload.push_back('t');

    auto frames = PacketParser::parse_frames(std::span<const uint8_t>(payload.data(), payload.size()));
    CHECK(frames.size() == 1);
    CHECK(static_cast<uint8_t>(frames[0].type) == 0x0f);
    // f.data = stream_id + offset + length + data
    // sid(1) + offset(2, 100=0x64) + length(1, 4) + "test"(4) = 8
    CHECK(frames[0].data.size() == 1 + 2 + 1 + 4);
}

static void test_stream_frame_no_len() {
    std::printf("[test] STREAM frame without LEN bit (data fills remaining)...\n");

    // type=0x09 (OFF only), stream_id=1, offset=0, data="abc"
    std::vector<uint8_t> payload;
    payload.push_back(0x09);
    auto sid = varint_encode_vec(1);
    payload.insert(payload.end(), sid.begin(), sid.end());
    auto off = varint_encode_vec(0);
    payload.insert(payload.end(), off.begin(), off.end());
    payload.push_back('a');
    payload.push_back('b');
    payload.push_back('c');

    auto frames = PacketParser::parse_frames(std::span<const uint8_t>(payload.data(), payload.size()));
    CHECK(frames.size() == 1);
    CHECK(static_cast<uint8_t>(frames[0].type) == 0x09);
    // f.data = sid(1) + offset(1) + "abc"(3) = 5
    CHECK(frames[0].data.size() == 5);
}

static void test_stream_then_handshake_done() {
    std::printf("[test] STREAM frame followed by HANDSHAKE_DONE (multi-frame)...\n");

    // type=0x0b (OFF+LEN), stream_id=2, offset=0, length=3, data="abc"
    // then type=0x1e (HANDSHAKE_DONE, no payload)
    std::vector<uint8_t> payload;
    payload.push_back(0x0b);
    auto sid = varint_encode_vec(2);
    payload.insert(payload.end(), sid.begin(), sid.end());
    auto off = varint_encode_vec(0);
    payload.insert(payload.end(), off.begin(), off.end());
    auto len = varint_encode_vec(3);
    payload.insert(payload.end(), len.begin(), len.end());
    payload.push_back('a');
    payload.push_back('b');
    payload.push_back('c');
    payload.push_back(0x1e);  // HANDSHAKE_DONE

    auto frames = PacketParser::parse_frames(std::span<const uint8_t>(payload.data(), payload.size()));
    CHECK(frames.size() == 2);
    CHECK(static_cast<uint8_t>(frames[0].type) == 0x0b);
    CHECK(static_cast<uint8_t>(frames[1].type) == 0x1e);
    // 第一帧 data 应不含 HANDSHAKE_DONE 字节
    CHECK(frames[0].data.size() == 1 + 1 + 1 + 3);  // sid + off + len + "abc"
}

static void test_connection_close_basic() {
    std::printf("[test] CONNECTION_CLOSE basic (error_code + reason)...\n");

    // type=0x1c, error_code=10 (1B), frame_type=0x08 (1B), reason_length=5, reason="error"
    std::vector<uint8_t> payload;
    payload.push_back(0x1c);
    auto ec = varint_encode_vec(10);
    payload.insert(payload.end(), ec.begin(), ec.end());
    auto ft = varint_encode_vec(0x08);
    payload.insert(payload.end(), ft.begin(), ft.end());
    auto rl = varint_encode_vec(5);
    payload.insert(payload.end(), rl.begin(), rl.end());
    payload.push_back('e');
    payload.push_back('r');
    payload.push_back('r');
    payload.push_back('o');
    payload.push_back('r');

    auto frames = PacketParser::parse_frames(std::span<const uint8_t>(payload.data(), payload.size()));
    CHECK(frames.size() == 1);
    CHECK(static_cast<uint8_t>(frames[0].type) == 0x1c);
    // f.data = error_code + frame_type + reason_length + reason
    // ec(1) + ft(1) + rl(1) + "error"(5) = 8
    CHECK(frames[0].data.size() == 8);
}

static void test_connection_close_no_reason() {
    std::printf("[test] CONNECTION_CLOSE without reason...\n");

    // type=0x1c, error_code=0, frame_type=0, reason_length=0
    std::vector<uint8_t> payload;
    payload.push_back(0x1c);
    payload.push_back(0);  // error_code
    payload.push_back(0);  // frame_type
    payload.push_back(0);  // reason_length

    auto frames = PacketParser::parse_frames(std::span<const uint8_t>(payload.data(), payload.size()));
    CHECK(frames.size() == 1);
    CHECK(static_cast<uint8_t>(frames[0].type) == 0x1c);
    CHECK(frames[0].data.size() == 3);
}

static void test_application_close() {
    std::printf("[test] APPLICATION_CLOSE (0x1d) no frame_type field...\n");

    // type=0x1d, error_code=5 (1B), reason_length=3, reason="bye"
    std::vector<uint8_t> payload;
    payload.push_back(0x1d);
    auto ec = varint_encode_vec(5);
    payload.insert(payload.end(), ec.begin(), ec.end());
    auto rl = varint_encode_vec(3);
    payload.insert(payload.end(), rl.begin(), rl.end());
    payload.push_back('b');
    payload.push_back('y');
    payload.push_back('e');

    auto frames = PacketParser::parse_frames(std::span<const uint8_t>(payload.data(), payload.size()));
    CHECK(frames.size() == 1);
    CHECK(static_cast<uint8_t>(frames[0].type) == 0x1d);
    // f.data = error_code + reason_length + reason (NO frame_type)
    // ec(1) + rl(1) + "bye"(3) = 5
    CHECK(frames[0].data.size() == 5);
}

static void test_close_then_padding() {
    std::printf("[test] CONNECTION_CLOSE followed by PADDING...\n");

    // type=0x1c, error_code=0, frame_type=0, reason_length=0, then PADDING(0x00)
    // 注意：PADDING 帧遇到 0x00 会立即返回（RFC 9000: PADDING = 剩余全 0）
    std::vector<uint8_t> payload;
    payload.push_back(0x1c);
    payload.push_back(0);  // error_code
    payload.push_back(0);  // frame_type
    payload.push_back(0);  // reason_length
    payload.push_back(0x00);  // PADDING

    auto frames = PacketParser::parse_frames(std::span<const uint8_t>(payload.data(), payload.size()));
    // PADDING 帧会使 parse_frames 立即返回，所以只有 1 帧
    CHECK(frames.size() == 1);
    CHECK(static_cast<uint8_t>(frames[0].type) == 0x1c);
}

int main() {
    std::printf("=== test_stream_close_frame ===\n");

    test_stream_frame_basic();
    test_stream_frame_all_flags();
    test_stream_frame_no_len();
    test_stream_then_handshake_done();
    test_connection_close_basic();
    test_connection_close_no_reason();
    test_application_close();
    test_close_then_padding();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
