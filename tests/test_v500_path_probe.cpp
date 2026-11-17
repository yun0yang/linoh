// test_v500_path_probe.cpp — v5.0.0 T-LP4-005 relay PathChallenge 转发测试
//
// 验证内容：
//   - PathProbe 结构体编解码正确性（含/不含反射地址）
//   - PathChallengeForward / PathChallengeDeliver 帧编解码
//   - decode_frame 对新帧类型（14/15）的识别
//   - kMaxKnownFrameType 更新后旧帧仍正常工作
//   - 畸形输入的安全拒绝
//
// 借鉴 iroh 1.0.0-rc.1 noq#672 — Hard-NAT 双向打洞辅助

#include "linoh/relay/stride.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

using namespace linoh::relay;
using linoh::base::PublicKey;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// PathProbe 编解码测试
// ============================================================================

static void test_path_probe_encode_decode_basic() {
    std::printf("[test] T-LP4-005: PathProbe basic encode/decode...\n");

    PathProbe pp;
    // 设置目标 endpoint
    std::array<uint8_t, PublicKey::kSize> dst_bytes{};
    for (std::size_t i = 0; i < PublicKey::kSize; ++i) dst_bytes[i] = static_cast<uint8_t>(i);
    std::memcpy(pp.dst.data(), dst_bytes.data(), PublicKey::kSize);
    // 设置 challenge data
    pp.challenge_data = {0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78};
    // 无反射地址（Client → Relay 方向）

    auto encoded = encode_path_probe(pp);
    CHECK(!encoded.empty());
    // 固定头：32 (EndpointId) + 8 (challenge) + 1 (host_len) + 0 (host) + 2 (port) = 43
    CHECK(encoded.size() == 43);

    auto decoded = decode_path_probe(
        std::span<const uint8_t>(encoded.data(), encoded.size()));
    CHECK(decoded.has_value());
    CHECK(std::memcmp(decoded->dst.data(), pp.dst.data(), PublicKey::kSize) == 0);
    CHECK(decoded->challenge_data == pp.challenge_data);
    CHECK(decoded->observed_host.empty());
    CHECK(decoded->observed_port == 0);
}

static void test_path_probe_encode_decode_with_addr() {
    std::printf("[test] T-LP4-005: PathProbe with observed address...\n");

    PathProbe pp;
    std::array<uint8_t, PublicKey::kSize> src_bytes{};
    src_bytes.fill(0xAB);
    std::memcpy(pp.dst.data(), src_bytes.data(), PublicKey::kSize);
    pp.challenge_data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    pp.observed_host = "203.0.113.42";
    pp.observed_port = 54321;

    auto encoded = encode_path_probe(pp);
    CHECK(!encoded.empty());

    auto decoded = decode_path_probe(
        std::span<const uint8_t>(encoded.data(), encoded.size()));
    CHECK(decoded.has_value());
    CHECK(std::memcmp(decoded->dst.data(), pp.dst.data(), PublicKey::kSize) == 0);
    CHECK(decoded->challenge_data == pp.challenge_data);
    CHECK(decoded->observed_host == "203.0.113.42");
    CHECK(decoded->observed_port == 54321);
}

static void test_path_probe_empty_challenge() {
    std::printf("[test] T-LP4-005: PathProbe with zero challenge data...\n");

    PathProbe pp;
    // challenge_data 全零（默认值）
    auto encoded = encode_path_probe(pp);
    auto decoded = decode_path_probe(
        std::span<const uint8_t>(encoded.data(), encoded.size()));
    CHECK(decoded.has_value());
    // challenge_data 全零
    bool all_zero = true;
    for (auto b : decoded->challenge_data) {
        if (b != 0) { all_zero = false; break; }
    }
    CHECK(all_zero);
}

static void test_path_probe_decode_malformed() {
    std::printf("[test] T-LP4-005: PathProbe rejects malformed input...\n");

    // 空数据
    CHECK(!decode_path_probe({}));

    // 过短（< 41 字节固定头）
    std::vector<uint8_t> short_data(40, 0xFF);
    auto short_span = std::span<const uint8_t>(short_data.data(), short_data.size());
    CHECK(!decode_path_probe(short_span));

    // host_len 超限
    std::vector<uint8_t> bad_host_len(43, 0);
    bad_host_len[40] = 255;  // host_len = 255 > kMaxObservedHostLen (64)
    auto bad_span = std::span<const uint8_t>(bad_host_len.data(), bad_host_len.size());
    CHECK(!decode_path_probe(bad_span));

    // host_len 声称有数据但实际不足
    std::vector<uint8_t> truncated(43, 0);
    truncated[40] = 10;  // host_len = 10，但后面只有 2 字节（port）
    auto trunc_span = std::span<const uint8_t>(truncated.data(), truncated.size());
    CHECK(!decode_path_probe(trunc_span));
}

// ============================================================================
// 帧编解码测试
// ============================================================================

static void test_path_challenge_forward_frame() {
    std::printf("[test] T-LP4-005: PathChallengeForward frame encode/decode...\n");

    PathProbe pp;
    std::array<uint8_t, PublicKey::kSize> dst_bytes{};
    dst_bytes.fill(0xCD);
    std::memcpy(pp.dst.data(), dst_bytes.data(), PublicKey::kSize);
    pp.challenge_data = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};

    auto frame = encode_path_challenge_forward(pp);
    CHECK(!frame.empty());

    // 解码帧
    auto decoded = decode_frame(std::span<const uint8_t>(frame.data(), frame.size()));
    CHECK(decoded.has_value());
    CHECK(decoded->type == FrameType::PathChallengeForward);

    // 解码 payload
    auto probe = decode_path_probe(
        std::span<const uint8_t>(decoded->payload.data(), decoded->payload.size()));
    CHECK(probe.has_value());
    CHECK(std::memcmp(probe->dst.data(), pp.dst.data(), PublicKey::kSize) == 0);
    CHECK(probe->challenge_data == pp.challenge_data);
}

static void test_path_challenge_deliver_frame() {
    std::printf("[test] T-LP4-005: PathChallengeDeliver frame encode/decode...\n");

    PathProbe pp;
    std::array<uint8_t, PublicKey::kSize> src_bytes{};
    src_bytes.fill(0xEF);
    std::memcpy(pp.dst.data(), src_bytes.data(), PublicKey::kSize);
    pp.challenge_data = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    pp.observed_host = "198.51.100.7";
    pp.observed_port = 9999;

    auto frame = encode_path_challenge_deliver(pp);
    CHECK(!frame.empty());

    auto decoded = decode_frame(std::span<const uint8_t>(frame.data(), frame.size()));
    CHECK(decoded.has_value());
    CHECK(decoded->type == FrameType::PathChallengeDeliver);

    auto probe = decode_path_probe(
        std::span<const uint8_t>(decoded->payload.data(), decoded->payload.size()));
    CHECK(probe.has_value());
    CHECK(probe->observed_host == "198.51.100.7");
    CHECK(probe->observed_port == 9999);
}

// ============================================================================
// decode_frame 兼容性测试
// ============================================================================

static void test_decode_frame_accepts_new_types() {
    std::printf("[test] T-LP4-005: decode_frame accepts new frame types 14/15...\n");

    // 构造 type=14 的空帧
    PathProbe empty_pp;
    auto forward = encode_path_challenge_forward(empty_pp);
    auto dec1 = decode_frame(std::span<const uint8_t>(forward.data(), forward.size()));
    CHECK(dec1.has_value());
    CHECK(dec1->type == FrameType::PathChallengeForward);

    // 构造 type=15 的空帧
    auto deliver = encode_path_challenge_deliver(empty_pp);
    auto dec2 = decode_frame(std::span<const uint8_t>(deliver.data(), deliver.size()));
    CHECK(dec2.has_value());
    CHECK(dec2->type == FrameType::PathChallengeDeliver);
}

static void test_decode_frame_rejects_unknown() {
    std::printf("[test] T-LP4-005: decode_frame rejects unknown types > 15...\n");

    // 手动构造 type=16 的帧（超过 kMaxKnownFrameType=15）
    std::vector<uint8_t> bad_frame;
    // varint encode 16 = 0x10
    bad_frame.push_back(0x10);
    bad_frame.push_back(0x00);  // empty payload

    auto dec = decode_frame(std::span<const uint8_t>(bad_frame.data(), bad_frame.size()));
    CHECK(!dec.has_value());
}

static void test_decode_frame_legacy_types_still_work() {
    std::printf("[test] T-LP4-005: legacy frame types (0-13) still work...\n");

    // Ping 帧 (type=9)
    std::vector<uint8_t> ping_frame;
    ping_frame.push_back(0x09);  // varint 9
    std::array<uint8_t, 8> ping_data{1, 2, 3, 4, 5, 6, 7, 8};
    ping_frame.insert(ping_frame.end(), ping_data.begin(), ping_data.end());

    auto dec = decode_frame(std::span<const uint8_t>(ping_frame.data(), ping_frame.size()));
    CHECK(dec.has_value());
    CHECK(dec->type == FrameType::Ping);
    CHECK(dec->payload.size() == 8);
}

// ============================================================================
// IPv6 反射地址测试
// ============================================================================

static void test_path_probe_ipv6_address() {
    std::printf("[test] T-LP4-005: PathProbe with IPv6 observed address...\n");

    PathProbe pp;
    pp.challenge_data = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    pp.observed_host = "2001:db8::1";
    pp.observed_port = 443;

    auto encoded = encode_path_probe(pp);
    auto decoded = decode_path_probe(
        std::span<const uint8_t>(encoded.data(), encoded.size()));
    CHECK(decoded.has_value());
    CHECK(decoded->observed_host == "2001:db8::1");
    CHECK(decoded->observed_port == 443);
}

// ============================================================================
// 往返一致性测试
// ============================================================================

static void test_path_probe_roundtrip_multiple() {
    std::printf("[test] T-LP4-005: PathProbe roundtrip multiple probes...\n");

    for (int i = 0; i < 10; ++i) {
        PathProbe pp;
        std::array<uint8_t, PublicKey::kSize> dst{};
        dst.fill(static_cast<uint8_t>(i));
        std::memcpy(pp.dst.data(), dst.data(), PublicKey::kSize);
        pp.challenge_data.fill(static_cast<uint8_t>(i * 17));
        pp.observed_host = "10.0.0." + std::to_string(i);
        pp.observed_port = static_cast<uint16_t>(1000 + i);

        auto encoded = encode_path_probe(pp);
        auto decoded = decode_path_probe(
            std::span<const uint8_t>(encoded.data(), encoded.size()));
        CHECK(decoded.has_value());
        CHECK(std::memcmp(decoded->dst.data(), pp.dst.data(), PublicKey::kSize) == 0);
        CHECK(decoded->challenge_data == pp.challenge_data);
        CHECK(decoded->observed_host == pp.observed_host);
        CHECK(decoded->observed_port == pp.observed_port);
    }
}

// ============================================================================
// 主函数
// ============================================================================

int main() {
    std::printf("=== v5.0.0 T-LP4-005 Path Probe (relay PATH_CHALLENGE forward) Tests ===\n\n");

    test_path_probe_encode_decode_basic();
    test_path_probe_encode_decode_with_addr();
    test_path_probe_empty_challenge();
    test_path_probe_decode_malformed();

    test_path_challenge_forward_frame();
    test_path_challenge_deliver_frame();

    test_decode_frame_accepts_new_types();
    test_decode_frame_rejects_unknown();
    test_decode_frame_legacy_types_still_work();

    test_path_probe_ipv6_address();
    test_path_probe_roundtrip_multiple();

    std::printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
