/// @file test_phase4_integration.cpp
/// Phase 4 集成测试：Flow Control + Path Migration + Result<T,E> + Connection 状态机

#include "linoh/protocol/flow_control.hpp"
#include "linoh/protocol/path_migration.hpp"
#include "linoh/protocol/ack.hpp"
#include "linoh/util/result.hpp"
#include "linoh/util/varint.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>

using namespace linoh::protocol;
using namespace linoh::util;

// ============================================================================
// Helper macros
// ============================================================================
#define TEST(name) printf("  [TEST] %s ... ", name)
#define PASS() do { printf("PASSED\n"); return 0; } while(0)
#define FAIL(msg) do { printf("FAILED: %s\n", msg); return 1; } while(0)

static bool vec_eq(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) {
    if (a.size() != b.size()) return false;
    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

// ============================================================================
// Flow Control Frame Tests
// ============================================================================

static int test_max_data_roundtrip() {
    TEST("MAX_DATA encode/decode roundtrip");
    MaxDataFrame frame;
    frame.maximum_data = 1 << 20;  // 1 MB

    auto encoded = encode_max_data(frame);
    // encoded = [type=0x10] + [VarInt maximum_data]
    // Skip type byte for decode
    auto decoded = decode_max_data(std::span<const uint8_t>(encoded.data() + 1, encoded.size() - 1));
    if (!decoded) FAIL("decode failed");
    if (decoded->maximum_data != frame.maximum_data) FAIL("value mismatch");
    PASS();
}

static int test_max_stream_data_roundtrip() {
    TEST("MAX_STREAM_DATA encode/decode roundtrip");
    MaxStreamDataFrame frame;
    frame.stream_id = 4;
    frame.maximum_stream_data = 1 << 18;  // 256 KB

    auto encoded = encode_max_stream_data(frame);
    auto decoded = decode_max_stream_data(std::span<const uint8_t>(encoded.data() + 1, encoded.size() - 1));
    if (!decoded) FAIL("decode failed");
    if (decoded->stream_id != frame.stream_id) FAIL("stream_id mismatch");
    if (decoded->maximum_stream_data != frame.maximum_stream_data) FAIL("window mismatch");
    PASS();
}

static int test_max_streams_roundtrip() {
    TEST("MAX_STREAMS_BIDI encode/decode roundtrip");
    MaxStreamsFrame frame;
    frame.maximum_streams = 100;
    frame.bidirectional = true;

    auto encoded = encode_max_streams(frame);
    if (encoded[0] != 0x12) FAIL("type byte should be 0x12 for bidi");
    auto decoded = decode_max_streams(encoded[0], std::span<const uint8_t>(encoded.data() + 1, encoded.size() - 1));
    if (!decoded) FAIL("decode failed");
    if (decoded->maximum_streams != frame.maximum_streams) FAIL("count mismatch");
    if (!decoded->bidirectional) FAIL("should be bidi");

    // Test uni variant
    frame.bidirectional = false;
    auto encoded2 = encode_max_streams(frame);
    if (encoded2[0] != 0x13) FAIL("type byte should be 0x13 for uni");
    auto decoded2 = decode_max_streams(encoded2[0], std::span<const uint8_t>(encoded2.data() + 1, encoded2.size() - 1));
    if (!decoded2) FAIL("decode failed");
    if (decoded2->bidirectional) FAIL("should be uni");
    PASS();
}

static int test_data_blocked_roundtrip() {
    TEST("DATA_BLOCKED encode/decode roundtrip");
    DataBlockedFrame frame;
    frame.maximum_data = 1 << 20;

    auto encoded = encode_data_blocked(frame);
    auto decoded = decode_data_blocked(std::span<const uint8_t>(encoded.data() + 1, encoded.size() - 1));
    if (!decoded) FAIL("decode failed");
    if (decoded->maximum_data != frame.maximum_data) FAIL("value mismatch");
    PASS();
}

static int test_stream_data_blocked_roundtrip() {
    TEST("STREAM_DATA_BLOCKED encode/decode roundtrip");
    StreamDataBlockedFrame frame;
    frame.stream_id = 8;
    frame.maximum_stream_data = 65536;

    auto encoded = encode_stream_data_blocked(frame);
    auto decoded = decode_stream_data_blocked(std::span<const uint8_t>(encoded.data() + 1, encoded.size() - 1));
    if (!decoded) FAIL("decode failed");
    if (decoded->stream_id != frame.stream_id) FAIL("stream_id mismatch");
    if (decoded->maximum_stream_data != frame.maximum_stream_data) FAIL("window mismatch");
    PASS();
}

static int test_streams_blocked_roundtrip() {
    TEST("STREAMS_BLOCKED encode/decode roundtrip");
    StreamsBlockedFrame frame;
    frame.maximum_streams = 50;
    frame.bidirectional = true;

    auto encoded = encode_streams_blocked(frame);
    if (encoded[0] != 0x16) FAIL("type should be 0x16 for bidi");
    auto decoded = decode_streams_blocked(encoded[0], std::span<const uint8_t>(encoded.data() + 1, encoded.size() - 1));
    if (!decoded) FAIL("decode failed");
    if (decoded->maximum_streams != frame.maximum_streams) FAIL("count mismatch");

    // Test uni variant
    frame.bidirectional = false;
    auto encoded2 = encode_streams_blocked(frame);
    if (encoded2[0] != 0x17) FAIL("type should be 0x17 for uni");
    PASS();
}

// ============================================================================
// FlowController Tests
// ============================================================================

static int test_flow_controller_initial_state() {
    TEST("FlowController initial state");
    FlowController fc;

    if (fc.remote_conn_window() != FlowController::kDefaultConnWindow) FAIL("initial conn window");
    if (fc.local_conn_window() != FlowController::kDefaultConnWindow) FAIL("local conn window");
    if (fc.conn_send_capacity() != FlowController::kDefaultConnWindow) FAIL("initial send capacity");
    if (fc.local_max_bidi_streams() != FlowController::kDefaultMaxBidiStreams) FAIL("bidi streams");
    if (fc.local_max_uni_streams() != FlowController::kDefaultMaxUniStreams) FAIL("uni streams");
    PASS();
}

static int test_flow_controller_conn_window() {
    TEST("FlowController connection-level window");
    FlowController fc;

    // Send 100KB, then 200KB
    fc.on_conn_bytes_sent(100000);
    if (fc.conn_send_capacity() != FlowController::kDefaultConnWindow - 100000) FAIL("capacity after 100KB");

    fc.on_remote_max_data(2 << 20);  // expand to 2MB
    if (fc.remote_conn_window() != 2 << 20) FAIL("window expansion");

    // Send more data
    fc.on_conn_bytes_sent(200000);
    // total sent = 300000, window = 2MB
    if (fc.conn_send_capacity() != (2 << 20) - 300000) FAIL("capacity after expansion");
    PASS();
}

static int test_flow_controller_stream_window() {
    TEST("FlowController stream-level window");
    FlowController fc;

    fc.on_remote_max_stream_data(0, 1 << 18);  // stream 0: 256KB
    if (fc.remote_stream_window(0) != (1 << 18)) FAIL("stream 0 window");

    fc.on_remote_max_stream_data(4, 1 << 17);  // stream 4: 128KB
    if (fc.remote_stream_window(4) != (1 << 17)) FAIL("stream 4 window");

    // Stream capacity with conn-level constraint
    uint64_t cap = fc.stream_send_capacity(4, 0);
    if (cap != std::min<uint64_t>(1 << 17, fc.conn_send_capacity())) FAIL("stream send capacity");
    PASS();
}

static int test_flow_controller_stream_count() {
    TEST("FlowController stream count management");
    FlowController fc;

    fc.on_remote_max_bidi_streams(10);
    fc.on_remote_max_uni_streams(5);

    if (!fc.can_open_bidi_stream(9)) FAIL("can open bidi at 9/10");
    if (fc.can_open_bidi_stream(10)) FAIL("cannot open bidi at 10/10");
    if (!fc.can_open_uni_stream(4)) FAIL("can open uni at 4/5");
    if (fc.can_open_uni_stream(5)) FAIL("cannot open uni at 5/5");
    PASS();
}

static int test_flow_controller_should_send_max_data() {
    TEST("FlowController should_send_max_data");
    FlowController fc;

    // Initially: recv = 0, window = 1MB, 0 < 1MB/2 → false
    if (fc.should_send_max_data()) FAIL("should not send initially");

    // Receive 600KB (> 1MB/2)
    fc.on_conn_bytes_recv(600000);
    if (!fc.should_send_max_data()) FAIL("should send after receiving > 50%");
    PASS();
}

// ============================================================================
// Path Migration Frame Tests
// ============================================================================

static int test_path_challenge_roundtrip() {
    TEST("PATH_CHALLENGE encode/decode roundtrip");
    PathChallengeFrame frame;
    frame.data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    auto encoded = encode_path_challenge(frame);
    // encoded = [type=0x1a] + [8 bytes data]
    if (encoded.size() != 9) FAIL("encoded size should be 9");
    if (encoded[0] != 0x1a) FAIL("type byte");

    auto decoded = decode_path_challenge(std::span<const uint8_t>(encoded.data() + 1, 8));
    if (!decoded) FAIL("decode failed");
    if (decoded->data != frame.data) FAIL("data mismatch");
    PASS();
}

static int test_path_response_roundtrip() {
    TEST("PATH_RESPONSE encode/decode roundtrip");
    PathResponseFrame frame;
    frame.data = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};

    auto encoded = encode_path_response(frame);
    if (encoded.size() != 9) FAIL("encoded size should be 9");
    if (encoded[0] != 0x1b) FAIL("type byte");

    auto decoded = decode_path_response(std::span<const uint8_t>(encoded.data() + 1, 8));
    if (!decoded) FAIL("decode failed");
    if (decoded->data != frame.data) FAIL("data mismatch");
    PASS();
}

static int test_new_connection_id_roundtrip() {
    TEST("NEW_CONNECTION_ID encode/decode roundtrip");
    NewConnectionIdFrame frame;
    frame.sequence_number = 5;
    frame.retire_prior_to = 2;
    frame.connection_id_length = 8;
    frame.connection_id = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    for (int i = 0; i < 16; ++i) frame.stateless_reset_token[i] = static_cast<uint8_t>(i);

    auto encoded = encode_new_connection_id(frame);
    if (encoded[0] != 0x18) FAIL("type byte");

    auto decoded = decode_new_connection_id(std::span<const uint8_t>(encoded.data() + 1, encoded.size() - 1));
    if (!decoded) FAIL("decode failed");
    if (decoded->sequence_number != frame.sequence_number) FAIL("seq mismatch");
    if (decoded->retire_prior_to != frame.retire_prior_to) FAIL("retire mismatch");
    if (decoded->connection_id_length != frame.connection_id_length) FAIL("cid_len mismatch");
    if (decoded->connection_id != frame.connection_id) FAIL("cid mismatch");
    if (decoded->stateless_reset_token != frame.stateless_reset_token) FAIL("token mismatch");
    PASS();
}

static int test_retire_connection_id_roundtrip() {
    TEST("RETIRE_CONNECTION_ID encode/decode roundtrip");
    RetireConnectionIdFrame frame;
    frame.sequence_number = 42;

    auto encoded = encode_retire_connection_id(frame);
    if (encoded[0] != 0x19) FAIL("type byte");

    auto decoded = decode_retire_connection_id(std::span<const uint8_t>(encoded.data() + 1, encoded.size() - 1));
    if (!decoded) FAIL("decode failed");
    if (decoded->sequence_number != frame.sequence_number) FAIL("seq mismatch");
    PASS();
}

// ============================================================================
// PathMigrationManager Tests
// ============================================================================

static int test_path_migration_challenge_response() {
    TEST("PathMigrationManager challenge-response validation");
    PathMigrationManager mgr;

    auto challenge = mgr.generate_challenge();
    mgr.record_challenge_sent(challenge, 100.0);

    // Create matching response
    PathResponseFrame response;
    response.data = challenge.data;
    int idx = mgr.validate_response(response);
    if (idx < 0) FAIL("response should match challenge");

    // Create non-matching response
    PathResponseFrame wrong_response;
    wrong_response.data = {0, 0, 0, 0, 0, 0, 0, 0};
    int idx2 = mgr.validate_response(wrong_response);
    if (idx2 >= 0) FAIL("wrong response should not match");

    // Mark validated
    mgr.mark_path_validated(idx);
    PASS();
}

static int test_path_migration_cid_management() {
    TEST("PathMigrationManager CID management");
    PathMigrationManager mgr;

    // Add CID entries
    ConnectionIdEntry entry1;
    entry1.sequence_number = 0;
    entry1.cid = ConnectionId::generate();
    mgr.add_cid(entry1);

    ConnectionIdEntry entry2;
    entry2.sequence_number = 1;
    entry2.cid = ConnectionId::generate();
    mgr.add_cid(entry2);

    if (mgr.active_cid_count() != 2) FAIL("should have 2 active CIDs");

    auto next = mgr.next_available_cid();
    if (!next) FAIL("should have available CID");
    if (next->sequence_number != 0) FAIL("first available CID should be seq 0");

    // Retire CID 0
    mgr.retire_cid(0);
    if (mgr.active_cid_count() != 1) FAIL("should have 1 active CID after retire");

    auto next2 = mgr.next_available_cid();
    if (!next2) FAIL("should still have available CID");
    if (next2->sequence_number != 1) FAIL("next available CID should be seq 1");
    PASS();
}

// ============================================================================
// Result<T, ErrorCode> Tests
// ============================================================================

static int test_result_success() {
    TEST("Result<T,E> success case");
    Result<int> r(42);
    if (!r.is_ok()) FAIL("should be ok");
    if (r.is_err()) FAIL("should not be err");
    if (r.value() != 42) FAIL("value should be 42");
    PASS();
}

static int test_result_error() {
    TEST("Result<T,E> error case");
    Result<int> r(ConnectionError::StreamLimitError, "too many streams");
    if (r.is_ok()) FAIL("should not be ok");
    if (!r.is_err()) FAIL("should be err");
    if (r.error().value() != static_cast<uint16_t>(ConnectionError::StreamLimitError)) FAIL("error code");
    PASS();
}

static int test_result_value_or() {
    TEST("Result<T,E> value_or");
    Result<int> ok(42);
    if (ok.value_or(0) != 42) FAIL("value_or on ok");

    Result<int> err(ConnectionError::InternalError);
    if (err.value_or(99) != 99) FAIL("value_or on err");
    PASS();
}

static int test_result_void() {
    TEST("ResultVoid success and error");
    ResultVoid ok;
    if (!ok.is_ok()) FAIL("default should be ok");

    ResultVoid err(CryptoError::DecryptionFailed, "bad key");
    if (err.is_ok()) FAIL("should be err");
    if (err.error().value() != static_cast<uint16_t>(CryptoError::DecryptionFailed)) FAIL("error code");
    PASS();
}

static int test_error_code_constructors() {
    TEST("ErrorCode from various enums");
    ErrorCode ce(ConnectionError::IdleTimeout, "30s timeout");
    if (ce.value() != static_cast<uint16_t>(ConnectionError::IdleTimeout)) FAIL("ConnectionError code");

    ErrorCode se(StreamError::StreamReset, "RST_STREAM");
    if (se.value() != static_cast<uint16_t>(StreamError::StreamReset)) FAIL("StreamError code");

    ErrorCode pe(ProtocolError::InvalidFrame, "bad frame");
    if (pe.value() != static_cast<uint16_t>(ProtocolError::InvalidFrame)) FAIL("ProtocolError code");

    ErrorCode cr(CryptoError::InvalidSignature, "sig mismatch");
    if (cr.value() != static_cast<uint16_t>(CryptoError::InvalidSignature)) FAIL("CryptoError code");
    PASS();
}

// ============================================================================
// Comprehensive roundtrip tests
// ============================================================================

static int test_flow_control_varint_large_values() {
    TEST("Flow control with large VarInt values");
    // Test with values requiring 4-byte and 8-byte VarInt encoding
    MaxDataFrame frame;
    frame.maximum_data = 1ULL << 40;  // ~1TB

    auto encoded = encode_max_data(frame);
    auto decoded = decode_max_data(std::span<const uint8_t>(encoded.data() + 1, encoded.size() - 1));
    if (!decoded) FAIL("decode failed");
    if (decoded->maximum_data != frame.maximum_data) FAIL("large value mismatch");

    MaxStreamDataFrame sframe;
    sframe.stream_id = 1000;
    sframe.maximum_stream_data = 1ULL << 30;  // ~1GB

    auto sencoded = encode_max_stream_data(sframe);
    auto sdecoded = decode_max_stream_data(std::span<const uint8_t>(sencoded.data() + 1, sencoded.size() - 1));
    if (!sdecoded) FAIL("decode failed");
    if (sdecoded->maximum_stream_data != sframe.maximum_stream_data) FAIL("large stream window mismatch");
    PASS();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("\n=== Phase 4 Integration Tests ===\n\n");
    int total = 0, passed = 0;

    auto run = [&](int (*test_fn)()) {
        total++;
        if (test_fn() == 0) passed++;
    };

    // Flow Control Frame Tests
    printf("--- Flow Control Frame Tests ---\n");
    run(test_max_data_roundtrip);
    run(test_max_stream_data_roundtrip);
    run(test_max_streams_roundtrip);
    run(test_data_blocked_roundtrip);
    run(test_stream_data_blocked_roundtrip);
    run(test_streams_blocked_roundtrip);

    // FlowController Tests
    printf("\n--- FlowController Tests ---\n");
    run(test_flow_controller_initial_state);
    run(test_flow_controller_conn_window);
    run(test_flow_controller_stream_window);
    run(test_flow_controller_stream_count);
    run(test_flow_controller_should_send_max_data);

    // Path Migration Frame Tests
    printf("\n--- Path Migration Frame Tests ---\n");
    run(test_path_challenge_roundtrip);
    run(test_path_response_roundtrip);
    run(test_new_connection_id_roundtrip);
    run(test_retire_connection_id_roundtrip);

    // PathMigrationManager Tests
    printf("\n--- PathMigrationManager Tests ---\n");
    run(test_path_migration_challenge_response);
    run(test_path_migration_cid_management);

    // Result<T,E> Tests
    printf("\n--- Result<T,ErrorCode> Tests ---\n");
    run(test_result_success);
    run(test_result_error);
    run(test_result_value_or);
    run(test_result_void);
    run(test_error_code_constructors);

    // Comprehensive Tests
    printf("\n--- Comprehensive Tests ---\n");
    run(test_flow_control_varint_large_values);

    printf("\n=== Results: %d/%d PASSED ===\n", passed, total);
    return passed == total ? 0 : 1;
}
