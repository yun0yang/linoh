// test_ack_loss_recovery.cpp — ACK 帧 + 丢包检测 + RTT 估算 + 拥塞控制 集成测试

#include "linoh/protocol/ack.hpp"
#include "linoh/protocol/loss_recovery.hpp"
#include "linoh/util/varint.hpp"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <vector>

using namespace linoh::protocol;

// ============================================================================
// Helper macros & functions
// ============================================================================
#define TEST(name) printf("  [TEST] %s ... ", name)
#define PASS() printf("PASSED\n")
#define FAIL(msg) printf("FAILED: %s\n", msg); return 1

static int test_count = 0;
static int pass_count = 0;

/// Compare two vectors of uint64_t for equality.
static bool vec_eq(const std::vector<uint64_t> &a, const std::vector<uint64_t> &b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// ============================================================================
// 1. ACK Frame 编解码 roundtrip
// ============================================================================
static int test_ack_encode_decode_simple() {
    TEST("ACK encode/decode simple (consecutive PNs)");

    AckFrame frame;
    frame.type = 0x02;
    frame.largest_acked = 10;
    frame.ack_delay_us = 8000; // 8ms
    frame.first_ack_range = 3; // PNs 10,9,8,7

    auto encoded = encode_ack_frame(frame);
    auto decoded = decode_ack_frame(encoded);

    assert(decoded.has_value());
    assert(decoded->type == 0x02);
    assert(decoded->largest_acked == 10);
    assert(decoded->first_ack_range == 3);
    assert(decoded->ack_delay_us == 8000);
    assert(decoded->ack_ranges.empty());

    PASS();
    test_count++; pass_count++;
    return 0;
}

// ============================================================================
// 2. ACK Frame from_acked_pns → roundtrip
// ============================================================================
static int test_ack_from_acked_pns() {
    TEST("ACK from_acked_pns roundtrip");

    std::vector<uint64_t> acked_pns = {0, 1, 2, 3, 10, 11, 12, 20, 21};

    auto frame = AckFrame::from_acked_pns(acked_pns, 0, 0x02);
    assert(frame.largest_acked == 21);
    assert(frame.first_ack_range == 1); // [20, 21] → first_ack_range = 1

    auto encoded = encode_ack_frame(frame);
    auto decoded = decode_ack_frame(encoded);
    assert(decoded.has_value());

    auto recovered_pns = acked_pns_from_frame(*decoded);
    std::sort(recovered_pns.begin(), recovered_pns.end());

    assert(vec_eq(recovered_pns, acked_pns));

    PASS();
    test_count++; pass_count++;
    return 0;
}

// ============================================================================
// 3. ACK Frame with ranges (gaps)
// ============================================================================
static int test_ack_with_ranges() {
    TEST("ACK with gap ranges roundtrip");

    std::vector<uint64_t> acked_pns = {5, 6, 7, 8, 15, 16, 17, 25, 26};

    auto frame = AckFrame::from_acked_pns(acked_pns, 5000, 0x02);
    assert(frame.largest_acked == 26);
    assert(frame.first_ack_range == 1);

    auto encoded = encode_ack_frame(frame);
    auto decoded = decode_ack_frame(encoded);
    assert(decoded.has_value());

    auto recovered_pns = acked_pns_from_frame(*decoded);
    std::sort(recovered_pns.begin(), recovered_pns.end());

    assert(vec_eq(recovered_pns, acked_pns));

    PASS();
    test_count++; pass_count++;
    return 0;
}

// ============================================================================
// 4. ACK_ECN frame (type 0x03)
// ============================================================================
static int test_ack_ecn() {
    TEST("ACK_ECN frame with ECN counts");

    AckFrame frame;
    frame.type = 0x03;
    frame.largest_acked = 5;
    frame.ack_delay_us = 0;
    frame.first_ack_range = 5;
    frame.ect0_count = 3;
    frame.ect1_count = 1;
    frame.ce_count = 0;

    auto encoded = encode_ack_frame(frame);
    auto decoded = decode_ack_frame(encoded);

    assert(decoded.has_value());
    assert(decoded->type == 0x03);
    assert(decoded->largest_acked == 5);
    assert(decoded->ect0_count == 3);
    assert(decoded->ect1_count == 1);
    assert(decoded->ce_count == 0);

    PASS();
    test_count++; pass_count++;
    return 0;
}

// ============================================================================
// 5. RTT Estimator
// ============================================================================
static int test_rtt_estimator() {
    TEST("RTT Estimator (SRTT + RTTVAR + RTO)");

    RttEstimator rtt;

    // Initial state
    assert(rtt.srtt_ms() == 100.0);
    assert(rtt.rto_ms() >= 200.0);

    // First sample
    rtt.update(50.0, 0.0);
    assert(rtt.srtt_ms() == 50.0);
    assert(rtt.rttvar_ms() == 25.0);

    // Second sample with ack_delay
    rtt.update(80.0, 10.0);
    double expected_srtt = 50.0 * 0.875 + 70.0 * 0.125;
    assert(std::abs(rtt.srtt_ms() - expected_srtt) < 0.1);

    // RTO bounds
    assert(rtt.rto_ms() >= 200.0);
    assert(rtt.rto_ms() <= 60000.0);

    PASS();
    test_count++; pass_count++;
    return 0;
}

// ============================================================================
// 6. Loss Detector — Packet threshold
// ============================================================================
static int test_loss_detector_pn_threshold() {
    TEST("Loss Detector — PN threshold detection");

    LossDetector ld;

    for (uint64_t pn = 0; pn <= 10; ++pn) {
        ld.on_packet_sent(pn, 0.0, 1200, true);
    }

    std::vector<uint64_t> acked = {8, 9, 10};
    auto lost = ld.on_ack_received(acked, 100.0);

    assert(lost.size() >= 3);

    PASS();
    test_count++; pass_count++;
    return 0;
}

// ============================================================================
// 7. NewReno Controller
// ============================================================================
static int test_newreno_controller() {
    TEST("NewReno Controller (cwnd + ssthresh)");

    NewRenoController cc;

    assert(cc.cwnd_bytes() == 12000);

    cc.on_ack(1200);
    assert(cc.cwnd_bytes() > 12000);

    uint64_t prev_cwnd = cc.cwnd_bytes();
    cc.on_loss();
    assert(cc.cwnd_bytes() < prev_cwnd * 2);

    cc.on_rto();
    assert(cc.cwnd_bytes() == 2400);

    assert(cc.can_send(100));
    assert(!cc.can_send(5000));

    PASS();
    test_count++; pass_count++;
    return 0;
}

// ============================================================================
// 8. acked_pns_from_frame — comprehensive roundtrip
// ============================================================================
static int test_acked_pns_comprehensive() {
    TEST("acked_pns_from_frame comprehensive roundtrip");

    std::vector<uint64_t> pns;
    for (uint64_t i = 100; i <= 110; ++i) pns.push_back(i);
    for (uint64_t i = 200; i <= 205; ++i) pns.push_back(i);
    pns.push_back(300);

    auto frame = AckFrame::from_acked_pns(pns, 0, 0x02);
    auto encoded = encode_ack_frame(frame);
    auto decoded = decode_ack_frame(encoded);
    assert(decoded.has_value());

    auto recovered = acked_pns_from_frame(*decoded);
    std::sort(recovered.begin(), recovered.end());

    assert(vec_eq(recovered, pns));

    PASS();
    test_count++; pass_count++;
    return 0;
}

// ============================================================================
// 9. Loss Detector — in-flight tracking
// ============================================================================
static int test_loss_detector_inflight() {
    TEST("Loss Detector — in-flight tracking");

    LossDetector ld;

    for (uint64_t pn = 0; pn < 5; ++pn) {
        ld.on_packet_sent(pn, pn * 10.0, 1200, true);
    }

    assert(ld.in_flight_count() == 5);
    assert(ld.in_flight_bytes() == 6000);

    std::vector<uint64_t> acked = {0, 1, 2};
    ld.on_ack_received(acked, 100.0);

    assert(ld.in_flight_count() == 2);
    assert(ld.in_flight_bytes() == 2400);

    PASS();
    test_count++; pass_count++;
    return 0;
}

// ============================================================================
// 10. Empty ACK frame
// ============================================================================
static int test_ack_empty() {
    TEST("Empty ACK frame");

    std::vector<uint64_t> empty_pns;
    auto frame = AckFrame::from_acked_pns(empty_pns, 0, 0x02);
    assert(frame.largest_acked == 0);
    assert(frame.first_ack_range == 0);
    assert(frame.ack_ranges.empty());

    auto encoded = encode_ack_frame(frame);
    auto decoded = decode_ack_frame(encoded);
    assert(decoded.has_value());
    assert(decoded->largest_acked == 0);

    auto recovered = acked_pns_from_frame(*decoded);
    assert(recovered.empty());

    PASS();
    test_count++; pass_count++;
    return 0;
}

// ============================================================================
// 11. RttEstimator reset
// ============================================================================
static int test_rtt_reset() {
    TEST("RttEstimator reset");

    RttEstimator rtt;
    rtt.update(50.0, 0.0);
    assert(rtt.srtt_ms() == 50.0);

    rtt.reset();
    assert(rtt.srtt_ms() == 100.0);

    PASS();
    test_count++; pass_count++;
    return 0;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("=== Phase 3: ACK + Loss Recovery + RTT + NewReno Tests ===\n\n");

    int failures = 0;
    failures += test_ack_encode_decode_simple();
    failures += test_ack_from_acked_pns();
    failures += test_ack_with_ranges();
    failures += test_ack_ecn();
    failures += test_rtt_estimator();
    failures += test_loss_detector_pn_threshold();
    failures += test_newreno_controller();
    failures += test_acked_pns_comprehensive();
    failures += test_loss_detector_inflight();
    failures += test_ack_empty();
    failures += test_rtt_reset();

    printf("\n=== Results: %d/%d tests passed ===\n", pass_count, test_count);
    return failures > 0 ? 1 : 0;
}
