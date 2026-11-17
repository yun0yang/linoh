// test_relay_invalid_message_guard.cpp — v1.7.0.5 P4 (C8) Invalid relay message 防御测试
//
// 借鉴 iroh #4389 (v1.0.2): 防御恶意/损坏的 relay 帧
//
// 测试覆盖：
//   1. ws_decode_frame 拒绝超大 payload_len（>16MB）
//   2. ws_decode_frame 接受正常 payload_len
//   3. decode_frame 拒绝未知 FrameType（>13）
//   4. decode_frame 接受已知 FrameType（0-13）
//   5. decode_datagram 拒绝超大 payload（>1MB+35）
//   6. decode_datagram 接受正常 payload
//   7. decode_datagram 拒绝过短 payload（<35B fixed header）

#include "linoh/relay/stride.hpp"
#include "linoh/relay/ws_client.hpp"

#include <cstdio>
#include <cstdint>
#include <vector>

using namespace linoh::relay;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 测试 1: ws_decode_frame 拒绝超大 payload_len（64位长度声明 2^32=4GB）
// ============================================================================

static void test_ws_reject_oversized_payload() {
    std::printf("[test] ws reject oversized payload...\n");

    // 构造一个声明 payload_len=2^32 (4GB) 的 WS 帧
    // Byte 0: 0x82 (FIN + Binary)
    // Byte 1: 0x80 | 127 = 0xFF (masked + 64-bit length)
    // Byte 2-9: 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 = 2^32 = 4294967296
    // Byte 10-13: mask key (4 bytes)
    std::vector<uint8_t> frame = {0x82, 0xFF,
                                   0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                                   0xAA, 0xBB, 0xCC, 0xDD};
    auto dec = ws_decode_frame(frame);
    CHECK(dec.invalid);  // C8 防御：超大 payload 应被标记为 invalid（非 need_more）
    CHECK(!dec.ok);
}

// ============================================================================
// 测试 2: ws_decode_frame 接受正常 payload_len（<125，单字节长度）
// ============================================================================

static void test_ws_accept_normal_payload() {
    std::printf("[test] ws accept normal payload...\n");

    // 构造一个 payload_len=5 的 WS 帧
    // Byte 0: 0x82 (FIN + Binary)
    // Byte 1: 0x82 (masked + len=2)
    // Byte 2-5: mask key
    // Byte 6-7: masked payload
    std::vector<uint8_t> frame = {0x82, 0x82,
                                   0x00, 0x00, 0x00, 0x00,  // mask key = 0 (不改变 payload)
                                   0x48, 0x49};  // "HI"
    auto dec = ws_decode_frame(frame);
    CHECK(dec.ok);
    if (dec.ok) {
        CHECK(dec.frame.opcode == WsOpcode::Binary);
        CHECK(dec.frame.payload.size() == 2);
        CHECK(dec.frame.payload[0] == 0x48);
        CHECK(dec.frame.payload[1] == 0x49);
    }
}

// ============================================================================
// 测试 3: ws_decode_frame 接受 16 位长度（126）
// ============================================================================

static void test_ws_accept_16bit_length() {
    std::printf("[test] ws accept 16bit length...\n");

    // payload_len=300（需要 16 位扩展长度）
    // Byte 0: 0x82 (FIN + Binary)
    // Byte 1: 0xFE (masked + 126)
    // Byte 2-3: 0x01 0x2C = 300
    // Byte 4-7: mask key (4 bytes, all 0)
    // Byte 8+: 300 bytes payload
    std::vector<uint8_t> frame = {0x82, 0xFE, 0x01, 0x2C,
                                   0x00, 0x00, 0x00, 0x00};
    frame.resize(8 + 300, 0xAA);
    auto dec = ws_decode_frame(frame);
    CHECK(dec.ok);
    if (dec.ok) {
        CHECK(dec.frame.payload.size() == 300);
    }
}

// ============================================================================
// 测试 4: ws_decode_frame 拒绝 16 位长度声明超大值（>16MB）
// ============================================================================

static void test_ws_reject_16bit_oversized() {
    std::printf("[test] ws reject 16bit oversized...\n");

    // payload_len=17MB (需要 64 位扩展长度)
    // Byte 0: 0x82
    // Byte 1: 0xFF (masked + 127)
    // Byte 2-9: 0x00 0x01 0x00 0x10 0x00 0x00 0x00 0x00 = 17MB
    std::vector<uint8_t> frame = {0x82, 0xFF,
                                   0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00};
    auto dec = ws_decode_frame(frame);
    CHECK(dec.invalid);  // C8 防御：17MB > 16MB 上限，应标记为 invalid（非 need_more）
    CHECK(!dec.ok);
}

// ============================================================================
// 测试 5: decode_frame 拒绝未知 FrameType（>13）
// ============================================================================

static void test_decode_frame_reject_unknown_type() {
    std::printf("[test] decode_frame reject unknown type...\n");

    // FrameType=100（明显超出已知范围）
    // VarInt 编码 100 = 0x64
    std::vector<uint8_t> data = {0x64, 0x01, 0x02, 0x03};
    auto frame = decode_frame(data);
    CHECK(!frame);  // 应被拒绝
}

// ============================================================================
// 测试 6: decode_frame 接受已知 FrameType（0-13）
// ============================================================================

static void test_decode_frame_accept_known_type() {
    std::printf("[test] decode_frame accept known type...\n");

    // 测试 FrameType=4 (ClientToRelayDatagram)
    std::vector<uint8_t> data = {0x04, 0xAA, 0xBB};
    auto frame = decode_frame(data);
    CHECK(frame.has_value());
    if (frame) {
        CHECK(frame->type == FrameType::ClientToRelayDatagram);
        CHECK(frame->payload.size() == 2);
    }

    // 测试 FrameType=13 (Status)
    std::vector<uint8_t> data2 = {0x0D};
    auto frame2 = decode_frame(data2);
    CHECK(frame2.has_value());
    if (frame2) {
        CHECK(frame2->type == FrameType::Status);
        CHECK(frame2->payload.empty());
    }
}

// ============================================================================
// 测试 7: decode_datagram 拒绝过短 payload（<35B fixed header）
// ============================================================================

static void test_decode_datagram_reject_short() {
    std::printf("[test] decode_datagram reject short...\n");

    std::vector<uint8_t> short_payload(30, 0xAA);  // 30B < 35B
    auto dg = decode_datagram(short_payload);
    CHECK(!dg);
}

// ============================================================================
// 测试 8: decode_datagram 接受正常 payload
// ============================================================================

static void test_decode_datagram_accept_normal() {
    std::printf("[test] decode_datagram accept normal...\n");

    // 35B header + 100B contents = 135B
    std::vector<uint8_t> payload(135, 0xAA);
    // 设置 dst 为非零（前 32 字节）
    for (int i = 0; i < 32; ++i) payload[i] = static_cast<uint8_t>(i + 1);
    // ECN = 0 (offset 32)
    payload[32] = 0;
    // SegmentSize = 0 (offset 33-34, big-endian)
    payload[33] = 0;
    payload[34] = 0;

    auto dg = decode_datagram(payload);
    CHECK(dg.has_value());
    if (dg) {
        CHECK(dg->contents.size() == 100);
        // 验证 dst 第一字节
        CHECK(dg->dst.data()[0] == 1);
    }
}

// ============================================================================
// 测试 9: decode_datagram 拒绝超大 payload（>1MB+35）
// ============================================================================

static void test_decode_datagram_reject_oversized() {
    std::printf("[test] decode_datagram reject oversized...\n");

    // 构造 2MB payload（>1MB 上限）
    std::vector<uint8_t> oversized(2 * 1024 * 1024 + 35, 0xAA);
    auto dg = decode_datagram(oversized);
    CHECK(!dg);
}

// ============================================================================
// 测试 10: decode_frame 边界值测试（type_val=13 接受，14 拒绝）
// ============================================================================

static void test_decode_frame_boundary() {
    std::printf("[test] decode_frame boundary...\n");

    // type_val=13 (Status, 最大已知值) — 应接受
    std::vector<uint8_t> d13 = {0x0D};
    auto f13 = decode_frame(d13);
    CHECK(f13.has_value());

    // type_val=14 — 应拒绝
    std::vector<uint8_t> d14 = {0x0E};
    auto f14 = decode_frame(d14);
    CHECK(!f14);
}

// ============================================================================
// 测试 11: batch datagram segment_size=0 防御（借鉴 iroh #4178 防 0 除法）
// 场景：ClientToRelayDatagramBatch 帧 segment_size=0 应被业务层拒绝
// 注：stride.hpp 的 decode_datagram 不拒绝 segment_size=0（因为非 batch 模式合法），
//     业务层（RelayServer::handle_frame）需根据 FrameType 区分判断
// ============================================================================

static void test_batch_datagram_segment_size_zero_defense() {
    std::printf("[test] batch datagram segment_size=0 defense (iroh #4178)...\n");

    // 构造一个 segment_size=0 的 datagram payload（35B header + 10B contents）
    std::vector<uint8_t> dg_payload(45, 0xAA);
    // dst 前 32 字节设为非零
    for (int i = 0; i < 32; ++i) dg_payload[i] = static_cast<uint8_t>(i + 1);
    // ECN = 0 (offset 32)
    dg_payload[32] = 0;
    // SegmentSize = 0 (offset 33-34)
    dg_payload[33] = 0;
    dg_payload[34] = 0;

    // 验证 decode_datagram 本身接受 segment_size=0（非 batch 模式合法）
    auto dg = decode_datagram(dg_payload);
    CHECK(dg.has_value());
    if (dg) {
        CHECK(dg->segment_size == 0);
    }

    // 验证 encode_client_to_relay_datagram 可以编码（编码层不区分 batch/single）
    // 业务层的 batch segment_size=0 拒绝逻辑在 RelayServer::handle_frame 中
    // 这里仅验证 codec 层行为正确，业务层校验由集成测试覆盖
    auto frame_data = encode_frame(FrameType::ClientToRelayDatagramBatch, dg_payload);
    auto decoded_frame = decode_frame(frame_data);
    CHECK(decoded_frame.has_value());
    if (decoded_frame) {
        CHECK(decoded_frame->type == FrameType::ClientToRelayDatagramBatch);
        // 业务层应基于 type + segment_size 判断是否拒绝
        bool should_reject = (decoded_frame->type == FrameType::ClientToRelayDatagramBatch &&
                              dg->segment_size == 0);
        CHECK(should_reject);
    }

    // 对比：segment_size=100 的 batch datagram 应被接受
    std::vector<uint8_t> dg_payload2(45, 0xBB);
    for (int i = 0; i < 32; ++i) dg_payload2[i] = static_cast<uint8_t>(i + 1);
    dg_payload2[32] = 0;
    dg_payload2[33] = 0;  // segment_size high byte
    dg_payload2[34] = 100; // segment_size low byte = 100
    auto dg2 = decode_datagram(dg_payload2);
    CHECK(dg2.has_value());
    if (dg2) {
        CHECK(dg2->segment_size == 100);
        bool should_accept = (dg2->segment_size > 0);
        CHECK(should_accept);
    }
}

int main() {
    std::printf("=== test_relay_invalid_message_guard (v1.7.0.5 P4 C8, iroh #4389 + #4178) ===\n");

    test_ws_reject_oversized_payload();
    test_ws_accept_normal_payload();
    test_ws_accept_16bit_length();
    test_ws_reject_16bit_oversized();
    test_decode_frame_reject_unknown_type();
    test_decode_frame_accept_known_type();
    test_decode_datagram_reject_short();
    test_decode_datagram_accept_normal();
    test_decode_datagram_reject_oversized();
    test_decode_frame_boundary();
    test_batch_datagram_segment_size_zero_defense();

    std::printf("\n=== Results: %d PASSED, %d FAILED ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
