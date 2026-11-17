// test_hw_accel_v1605.cpp - P4 hardware accel layer unit tests (v1.6.0.5)
//
// Covers:
//   - CudaBuffer handle basics (construct/valid/as_span/reset)
//   - CudaBufferAllocator stub (allocate/free/stats/export_ipc)
//   - NvlinkTransport type/name/readiness/mock_mode/can_connect
//   - NvlinkTransport send_gpu/recv_gpu mock (memcpy round-trip)
//   - NvlinkTransport send_multicast mock
//   - NvlinkTransport stats / reset_stats
//   - CudaIpcTransport type/name/readiness/mock_mode
//   - CudaIpcTransport send_gpu/recv_gpu mock
//   - CudaIpcTransport export_for_peer / open_for_peer
//   - CudaIpcTransport stats
//   - TransportSelector register/unregister/priority/duplicate
//   - TransportSelector select (priority NVLink > CUDA_IPC > nullptr)
//   - TransportSelector cache (preselect/invalidate/invalidate_all)
//   - TransportSelector has_hw_accel / has_hw_accel_for
//   - TransportSelector list_transports / aggregate_stats
//   - EpCommPlan.transport_hint field + serialize round-trip
//   - to_string(Type)
//   - concurrent select thread safety

#include "linoh/net/cuda_buffer.hpp"
#include "linoh/net/hw_accel.hpp"
#include "linoh/net/nvlink_transport.hpp"
#include "linoh/net/cuda_ipc_transport.hpp"
#include "linoh/net/transport_selector.hpp"
#include "linoh/multimodal/comm_planner.hpp"
#include "linoh/multimodal/ep_channel.hpp"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace {

// Simple test framework (same style as test_comm_planner_v1604.cpp)
int g_pass = 0;
int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::cerr << "FAIL: " #cond \
        << " @ line " << __LINE__ << std::endl; } \
} while(0)

#define CHECK_EQ(a, b) do { \
    if ((a) == (b)) { ++g_pass; } \
    else { ++g_fail; std::cerr << "FAIL: " #a " == " #b \
        << " (got " << (a) << " vs " << (b) << ")" \
        << " @ line " << __LINE__ << std::endl; } \
} while(0)

using namespace linoh::net;
using namespace linoh::multimodal::ep;

// ============================================================================
// CudaBuffer tests
// ============================================================================

void test_cuda_buffer_default() {
    CudaBuffer buf;
    CHECK(!buf.valid());
    CHECK(buf.ptr == nullptr);
    CHECK(buf.size == 0);
    CHECK(buf.capacity == 0);
    CHECK(!buf.owns_memory);
}

void test_cuda_buffer_view() {
    std::uint8_t data[64];
    CudaBuffer buf(data, 64, BufferLocation::REGULAR_HOST);
    CHECK(buf.valid());
    CHECK_EQ(buf.size, 64u);
    CHECK_EQ(buf.capacity, 64u);
    CHECK(!buf.owns_memory);
    auto span = buf.as_span();
    CHECK_EQ(span.size(), 64u);
}

void test_cuda_buffer_reset() {
    auto *alloc = default_cuda_allocator();
    auto buf = alloc->allocate(128, BufferLocation::REGULAR_HOST);
    CHECK(buf.valid());
    CHECK(buf.owns_memory);
    buf.reset();
    CHECK(!buf.valid());
    CHECK(!buf.owns_memory);
}

// ============================================================================
// CudaBufferAllocator stub tests
// ============================================================================

void test_allocator_stub_basic() {
    auto *alloc = default_cuda_allocator();
    CHECK(!alloc->is_real_cuda());
    CHECK(std::string(alloc->name()) == "stub");

    auto buf = alloc->allocate(256, BufferLocation::REGULAR_HOST);
    CHECK(buf.valid());
    CHECK_EQ(buf.size, 256u);
    CHECK(buf.owns_memory);
    alloc->free(buf);
    CHECK(!buf.valid());
}

void test_allocator_stub_zero() {
    auto *alloc = default_cuda_allocator();
    auto buf = alloc->allocate(0);
    CHECK(!buf.valid());
    auto s = alloc->stats();
    CHECK(s.alloc_failures >= 1);
}

void test_allocator_stub_stats() {
    auto *alloc = default_cuda_allocator();
    auto s0 = alloc->stats();
    auto buf = alloc->allocate(100);
    auto s1 = alloc->stats();
    CHECK(s1.alloc_count > s0.alloc_count);
    alloc->free(buf);
    auto s2 = alloc->stats();
    CHECK(s2.free_count > s1.free_count);
}

void test_allocator_export_ipc() {
    auto *alloc = default_cuda_allocator();
    auto buf = alloc->allocate(64, BufferLocation::DEVICE, 0);
    CHECK(buf.valid());
    bool ok = alloc->export_ipc(buf);
    CHECK(ok);
    CHECK(buf.device_handle.valid);
    alloc->free(buf);
}

// ============================================================================
// NvlinkTransport tests
// ============================================================================

void test_nvlink_type_name() {
    NvlinkTransport t;
    CHECK(t.type() == HwAccelTransport::Type::NVLINK);
    CHECK(t.name() == "nvlink");
}

void test_nvlink_not_ready_default() {
    NvlinkTransport t;
    CHECK(!t.is_ready());
    CHECK(!t.is_mock_mode());
}

void test_nvlink_mock_mode() {
    NvlinkTransport t;
    bool prev = t.set_mock_mode(true);
    CHECK(!prev);
    CHECK(t.is_mock_mode());
    CHECK(t.is_ready());
}

void test_nvlink_can_connect_default() {
    NvlinkTransport t;
    CHECK(!t.can_connect(42));
}

void test_nvlink_can_connect_mock() {
    NvlinkTransport t;
    t.set_mock_mode(true);
    CHECK(t.can_connect(42));
    CHECK(!t.can_connect(0));
}

void test_nvlink_send_recv_mock() {
    NvlinkTransport t;
    t.set_mock_mode(true);

    std::uint8_t send_data[128];
    for (int i = 0; i < 128; ++i) send_data[i] = static_cast<std::uint8_t>(i);
    CudaBuffer send_buf(send_data, 128);

    auto sent = t.send_gpu(100, send_buf);
    CHECK_EQ(sent, 128u);

    std::uint8_t recv_data[128] = {};
    CudaBuffer recv_buf(recv_data, 128);
    auto recvd = t.recv_gpu(100, recv_buf);
    CHECK_EQ(recvd, 128u);

    CHECK(std::memcmp(send_data, recv_data, 128) == 0);
}

void test_nvlink_send_not_ready() {
    NvlinkTransport t;
    std::uint8_t data[64];
    CudaBuffer buf(data, 64);
    auto sent = t.send_gpu(100, buf);
    CHECK_EQ(sent, 0u);
    auto s = t.stats();
    CHECK(s.send_failures >= 1);
}

void test_nvlink_recv_no_data() {
    NvlinkTransport t;
    t.set_mock_mode(true);
    std::uint8_t data[64] = {};
    CudaBuffer buf(data, 64);
    auto recvd = t.recv_gpu(999, buf);
    CHECK_EQ(recvd, 0u);
    auto s = t.stats();
    CHECK(s.recv_failures >= 1);
}

void test_nvlink_multicast_mock() {
    NvlinkTransport t;
    t.set_mock_mode(true);

    std::uint8_t send_data[64];
    for (int i = 0; i < 64; ++i) send_data[i] = 0xAA;
    CudaBuffer send_buf(send_data, 64);

    std::vector<NodeId> peers = {10, 20, 30};
    auto sent = t.send_multicast(peers, send_buf);
    CHECK_EQ(sent, 64u);

    // Each peer should have the data.
    for (auto peer : peers) {
        std::uint8_t recv_data[64] = {};
        CudaBuffer recv_buf(recv_data, 64);
        auto recvd = t.recv_gpu(peer, recv_buf);
        CHECK_EQ(recvd, 64u);
        CHECK(recv_data[0] == 0xAA);
    }
}

void test_nvlink_multicast_empty() {
    NvlinkTransport t;
    t.set_mock_mode(true);
    std::uint8_t data[32];
    CudaBuffer buf(data, 32);
    std::vector<NodeId> empty_peers;
    auto sent = t.send_multicast(empty_peers, buf);
    CHECK_EQ(sent, 0u);
}

void test_nvlink_stats() {
    NvlinkTransport t;
    t.set_mock_mode(true);
    std::uint8_t data[32];
    CudaBuffer buf(data, 32);
    t.send_gpu(1, buf);

    auto s = t.stats();
    CHECK_EQ(s.send_total, 1u);
    CHECK_EQ(s.send_bytes, 32u);
    CHECK(s.mock_mode);
}

void test_nvlink_reset_stats() {
    NvlinkTransport t;
    t.set_mock_mode(true);
    std::uint8_t data[16];
    CudaBuffer buf(data, 16);
    t.send_gpu(1, buf);

    t.reset_stats();
    auto s = t.stats();
    CHECK_EQ(s.send_total, 0u);
    CHECK_EQ(s.send_bytes, 0u);
}

void test_nvlink_supports_multicast() {
    NvlinkTransport t;
    CHECK(t.supports_multicast());
}

// ============================================================================
// CudaIpcTransport tests
// ============================================================================

void test_cuda_ipc_type_name() {
    CudaIpcTransport t;
    CHECK(t.type() == HwAccelTransport::Type::CUDA_IPC);
    CHECK(t.name() == "cuda-ipc");
}

void test_cuda_ipc_not_ready_default() {
    CudaIpcTransport t;
    CHECK(!t.is_ready());
}

void test_cuda_ipc_mock_mode() {
    CudaIpcTransport t;
    t.set_mock_mode(true);
    CHECK(t.is_mock_mode());
    CHECK(t.is_ready());
    CHECK(t.can_connect(42));
    CHECK(!t.can_connect(0));
}

void test_cuda_ipc_send_recv_mock() {
    CudaIpcTransport t;
    t.set_mock_mode(true);

    std::uint8_t send_data[64];
    for (int i = 0; i < 64; ++i) send_data[i] = 0xBB;
    CudaBuffer send_buf(send_data, 64);

    auto sent = t.send_gpu(200, send_buf);
    CHECK_EQ(sent, 64u);

    std::uint8_t recv_data[64] = {};
    CudaBuffer recv_buf(recv_data, 64);
    auto recvd = t.recv_gpu(200, recv_buf);
    CHECK_EQ(recvd, 64u);
    CHECK(recv_data[0] == 0xBB);
}

void test_cuda_ipc_no_multicast() {
    CudaIpcTransport t;
    CHECK(!t.supports_multicast());
}

void test_cuda_ipc_export_open() {
    CudaIpcTransport t;
    t.set_mock_mode(true);

    std::uint8_t data[48];
    CudaBuffer buf(data, 48, BufferLocation::DEVICE, 0);
    bool ok = t.export_for_peer(300, buf);
    CHECK(ok);

    auto view = t.open_for_peer(300, buf.device_handle, 48);
    CHECK(view.valid());
    CHECK(!view.owns_memory);
}

void test_cuda_ipc_stats() {
    CudaIpcTransport t;
    t.set_mock_mode(true);
    std::uint8_t data[16];
    CudaBuffer buf(data, 16);
    t.send_gpu(1, buf);

    auto s = t.stats();
    CHECK_EQ(s.send_total, 1u);
    CHECK_EQ(s.send_bytes, 16u);
    CHECK_EQ(s.multicast_total, 0u);
}

void test_cuda_ipc_close_peer() {
    CudaIpcTransport t;
    t.set_mock_mode(true);
    std::uint8_t data[32];
    CudaBuffer buf(data, 32);
    t.send_gpu(50, buf);
    t.close_peer(50);

    // After close, recv should fail.
    std::uint8_t recv[32] = {};
    CudaBuffer rbuf(recv, 32);
    auto recvd = t.recv_gpu(50, rbuf);
    CHECK_EQ(recvd, 0u);
}

// ============================================================================
// TransportSelector tests
// ============================================================================

void test_selector_empty() {
    TransportSelector sel;
    CHECK(!sel.has_hw_accel());
    CHECK(sel.select(42) == nullptr);
    CHECK_EQ(sel.transport_count(), 0u);
}

void test_selector_register_nvlink() {
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);
    CHECK(sel.register_transport(nvlink, 100));
    CHECK_EQ(sel.transport_count(), 1u);
    CHECK(sel.has_hw_accel());
}

void test_selector_register_duplicate() {
    TransportSelector sel;
    auto t1 = NvlinkTransport::create();
    auto t2 = NvlinkTransport::create();
    CHECK(sel.register_transport(t1, 100));
    CHECK(!sel.register_transport(t2, 100));
    CHECK_EQ(sel.transport_count(), 1u);
}

void test_selector_priority() {
    TransportSelector sel;
    auto ipc = CudaIpcTransport::create();
    ipc->set_mock_mode(true);
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);

    // Register in reverse priority order.
    sel.register_transport(ipc, 50);
    sel.register_transport(nvlink, 100);

    // select() should return NVLink (higher priority).
    auto t = sel.select(42);
    CHECK(t != nullptr);
    CHECK(t->type() == HwAccelTransport::Type::NVLINK);
}

void test_selector_fallback_nullptr() {
    TransportSelector sel;
    // Register but don't enable mock mode.
    auto nvlink = NvlinkTransport::create();
    sel.register_transport(nvlink, 100);
    // Not ready, so select should return nullptr.
    CHECK(sel.select(42) == nullptr);
    CHECK(!sel.has_hw_accel());
}

void test_selector_unregister() {
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);
    sel.register_transport(nvlink, 100);
    CHECK(sel.has_hw_accel());
    sel.unregister_transport(HwAccelTransport::Type::NVLINK);
    CHECK(!sel.has_hw_accel());
    CHECK_EQ(sel.transport_count(), 0u);
}

void test_selector_cache() {
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);
    sel.register_transport(nvlink, 100);

    // First call: cache miss.
    auto t1 = sel.select(42);
    CHECK(t1 != nullptr);
    CHECK_EQ(sel.cache_size(), 1u);

    // Second call: cache hit.
    auto t2 = sel.select(42);
    CHECK(t2 == t1);

    // Invalidate.
    sel.invalidate(42);
    CHECK_EQ(sel.cache_size(), 0u);
}

void test_selector_invalidate_all() {
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);
    sel.register_transport(nvlink, 100);
    sel.select(1);
    sel.select(2);
    sel.select(3);
    CHECK_EQ(sel.cache_size(), 3u);
    sel.invalidate_all();
    CHECK_EQ(sel.cache_size(), 0u);
}

void test_selector_preselect() {
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);
    sel.register_transport(nvlink, 100);

    std::vector<NodeId> peers = {10, 20, 30};
    sel.preselect(peers);
    CHECK_EQ(sel.cache_size(), 3u);
    CHECK(sel.has_hw_accel_for(10));
    CHECK(sel.has_hw_accel_for(20));
    CHECK(sel.has_hw_accel_for(30));
}

void test_selector_list_transports() {
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);
    auto ipc = CudaIpcTransport::create();
    ipc->set_mock_mode(true);
    sel.register_transport(nvlink, 100);
    sel.register_transport(ipc, 50);

    auto list = sel.list_transports();
    CHECK_EQ(list.size(), 2u);
    // Sorted by priority desc: NVLink first.
    CHECK(list[0].type == HwAccelTransport::Type::NVLINK);
    CHECK(list[1].type == HwAccelTransport::Type::CUDA_IPC);
    CHECK(list[0].priority == 100);
    CHECK(list[1].priority == 50);
    CHECK(list[0].ready);
    CHECK(list[1].ready);
}

void test_selector_aggregate_stats() {
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);
    sel.register_transport(nvlink, 100);

    std::uint8_t data[32];
    CudaBuffer buf(data, 32);
    nvlink->send_gpu(1, buf);

    auto stats = sel.aggregate_stats();
    CHECK_EQ(stats.size(), 1u);
    CHECK(stats[0].send_total >= 1);
}

// ============================================================================
// EpCommPlan transport_hint tests
// ============================================================================

void test_comm_plan_transport_hint_default() {
    EpCommPlan plan;
    CHECK(plan.transport_hint == EpCommPlan::TransportHint::QUIC_UDP);
}

void test_comm_plan_transport_hint_set() {
    EpCommPlan plan;
    plan.plan_id = 1;
    plan.routing_hash = 42;
    plan.sync_id = 100;
    plan.total_tokens = 10;
    plan.max_tokens_per_expert = 5;
    plan.min_tokens_per_expert = 2;
    plan.load_imbalance_ratio = 2.5;
    plan.load_balanced = false;
    plan.shape.dtype = static_cast<linoh::multimodal::TensorDType>(1);
    plan.shape.max_tokens = 32;
    plan.shape.hidden_dim = 4096;
    plan.shape.expert_count = 8;
    plan.dst_nodes = {100, 200, 300};
    plan.expert_ids = {1, 2, 3};
    plan.transport_hint = EpCommPlan::TransportHint::NVLINK;
    auto data = CommPlanner::serialize(plan);
    EpCommPlan restored;
    bool ok = CommPlanner::deserialize(data, restored);
    CHECK(ok);
    CHECK(restored.transport_hint == EpCommPlan::TransportHint::NVLINK);
}

void test_comm_plan_transport_hint_cuda_ipc() {
    EpCommPlan plan;
    plan.plan_id = 2;
    plan.routing_hash = 99;
    plan.sync_id = 200;
    plan.total_tokens = 20;
    plan.shape.dtype = static_cast<linoh::multimodal::TensorDType>(1);
    plan.shape.max_tokens = 64;
    plan.shape.hidden_dim = 2048;
    plan.shape.expert_count = 4;
    plan.dst_nodes = {10, 20};
    plan.expert_ids = {0, 1};
    plan.transport_hint = EpCommPlan::TransportHint::CUDA_IPC;
    auto data = CommPlanner::serialize(plan);
    EpCommPlan restored;
    bool ok = CommPlanner::deserialize(data, restored);
    CHECK(ok);
    CHECK(restored.transport_hint == EpCommPlan::TransportHint::CUDA_IPC);
}

// ============================================================================
// to_string(Type) tests
// ============================================================================

void test_to_string_type() {
    CHECK(std::string(to_string(HwAccelTransport::Type::NVLINK)) == "nvlink");
    CHECK(std::string(to_string(HwAccelTransport::Type::CUDA_IPC)) == "cuda-ipc");
    CHECK(std::string(to_string(HwAccelTransport::Type::RDMA)) == "rdma");
}

// ============================================================================
// build_has_real_cuda test
// ============================================================================

void test_build_has_real_cuda() {
    // In current build (no CUDA SDK), should be false.
    CHECK(!build_has_real_cuda());
}

// ============================================================================
// Concurrent select thread safety
// ============================================================================

void test_selector_concurrent_select() {
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);
    sel.register_transport(nvlink, 100);

    // Pre-select all peers to populate cache, then concurrently read.
    std::vector<NodeId> all_peers;
    for (int t = 0; t < 8; ++t) {
        for (int i = 0; i < 200; ++i) {
            all_peers.push_back(static_cast<NodeId>(t * 1000 + i));
        }
    }
    sel.preselect(all_peers);

    std::atomic<int> success_count{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&sel, &success_count, t]() {
            for (int i = 0; i < 200; ++i) {
                NodeId peer = static_cast<NodeId>(t * 1000 + i);
                auto transport = sel.select(peer);
                if (transport != nullptr) {
                    ++success_count;
                }
            }
        });
    }
    for (auto &th : threads) th.join();
    // Allow for rare cache contention; should be near 1600.
    CHECK(success_count.load() > 1500);
}

// ============================================================================
// EpChannel hw integration tests (P4)
// ============================================================================

void test_ep_channel_hw_no_selector() {
    // EpChannel without selector: has_hw_accel() returns false
    EpChannel channel(nullptr);
    CHECK(!channel.has_hw_accel());
}

void test_ep_channel_hw_set_selector() {
    EpChannel channel(nullptr);
    TransportSelector sel;
    channel.set_hw_accel(&sel);
    CHECK(channel.has_hw_accel());
    channel.set_hw_accel(nullptr);
    CHECK(!channel.has_hw_accel());
}

void test_ep_channel_hw_dispatch_no_selector_fallback() {
    // No selector + no conn -> send_dispatch_hw returns false (record fallback + send_failure)
    EpChannel channel(nullptr);
    std::uint8_t data[16] = {};
    CudaBuffer buf(data, 16);
    bool ok = channel.send_dispatch_hw(42, 1, 1, 1, buf);
    CHECK(!ok);
    auto s = channel.stats();
    // fallback to QUIC attempted but conn is null -> send_failure
    CHECK(s.hw_fallback_to_quic >= 1);
    CHECK(s.send_failures >= 1);
}

void test_ep_channel_hw_dispatch_invalid_buf() {
    EpChannel channel(nullptr);
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);
    sel.register_transport(nvlink, 100);
    channel.set_hw_accel(&sel);

    // Invalid buffer -> hw path fails, fallback also fails (conn null)
    CudaBuffer empty_buf;
    bool ok = channel.send_dispatch_hw(42, 1, 1, 1, empty_buf);
    CHECK(!ok);
    auto s = channel.stats();
    CHECK(s.hw_failures == 0);  // hw not attempted (buf invalid)
    CHECK(s.hw_fallback_to_quic >= 1);
}

void test_ep_channel_hw_dispatch_via_nvlink_mock() {
    // With selector + nvlink mock + valid buffer: hw path succeeds
    // (conn null but we don't reach QUIC fallback)
    EpChannel channel(nullptr);
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);
    sel.register_transport(nvlink, 100);
    channel.set_hw_accel(&sel);

    std::uint8_t data[32];
    for (int i = 0; i < 32; ++i) data[i] = static_cast<std::uint8_t>(i);
    CudaBuffer buf(data, 32);

    bool ok = channel.send_dispatch_hw(42, 1, 1, 1, buf);
    CHECK(ok);
    auto s = channel.stats();
    CHECK_EQ(s.hw_dispatch_sent, 1u);
    CHECK_EQ(s.hw_bytes_sent, 32u);
    CHECK_EQ(s.hw_fallback_to_quic, 0u);

    // Verify data was actually transmitted via mock (recv on peer 42)
    std::uint8_t recv_data[32] = {};
    CudaBuffer recv_buf(recv_data, 32);
    auto recvd = nvlink->recv_gpu(42, recv_buf);
    CHECK_EQ(recvd, 32u);
    CHECK(std::memcmp(data, recv_data, 32) == 0);
}

void test_ep_channel_hw_combine_via_nvlink_mock() {
    EpChannel channel(nullptr);
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);
    sel.register_transport(nvlink, 100);
    channel.set_hw_accel(&sel);

    std::uint8_t data[64];
    for (int i = 0; i < 64; ++i) data[i] = 0x55;
    CudaBuffer buf(data, 64);

    bool ok = channel.send_combine_hw(42, 1, 1, 1, buf);
    CHECK(ok);
    auto s = channel.stats();
    CHECK_EQ(s.hw_combine_sent, 1u);
    CHECK_EQ(s.hw_bytes_sent, 64u);
}

void test_ep_channel_hw_dispatch_fallback_when_nvlink_not_ready() {
    // NVLink registered but not ready (mock_mode=false): hw select returns nullptr,
    // fallback to QUIC (which fails because conn is null)
    EpChannel channel(nullptr);
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    // Don't enable mock_mode -> not ready
    sel.register_transport(nvlink, 100);
    channel.set_hw_accel(&sel);

    std::uint8_t data[16];
    CudaBuffer buf(data, 16);
    bool ok = channel.send_dispatch_hw(42, 1, 1, 1, buf);
    CHECK(!ok);
    auto s = channel.stats();
    CHECK_EQ(s.hw_dispatch_sent, 0u);
    CHECK(s.hw_fallback_to_quic >= 1);
    CHECK(s.send_failures >= 1);
}

void test_ep_channel_hw_dispatch_cuda_ipc_mock() {
    // Use CudaIpcTransport instead of NVLink
    EpChannel channel(nullptr);
    TransportSelector sel;
    auto ipc = CudaIpcTransport::create();
    ipc->set_mock_mode(true);
    sel.register_transport(ipc, 50);
    channel.set_hw_accel(&sel);

    std::uint8_t data[16];
    for (int i = 0; i < 16; ++i) data[i] = static_cast<std::uint8_t>(0xAB);
    CudaBuffer buf(data, 16);

    bool ok = channel.send_dispatch_hw(99, 1, 1, 1, buf);
    CHECK(ok);
    auto s = channel.stats();
    CHECK_EQ(s.hw_dispatch_sent, 1u);
    CHECK_EQ(s.hw_bytes_sent, 16u);
}

void test_ep_channel_hw_multiple_dispatches() {
    EpChannel channel(nullptr);
    TransportSelector sel;
    auto nvlink = NvlinkTransport::create();
    nvlink->set_mock_mode(true);
    sel.register_transport(nvlink, 100);
    channel.set_hw_accel(&sel);

    // 5 dispatches to peer 1, 3 to peer 2
    std::uint8_t data[8] = {};
    CudaBuffer buf(data, 8);
    for (int i = 0; i < 5; ++i) {
        CHECK(channel.send_dispatch_hw(1, 1, 1, 1, buf));
    }
    for (int i = 0; i < 3; ++i) {
        CHECK(channel.send_dispatch_hw(2, 1, 1, 1, buf));
    }
    auto s = channel.stats();
    CHECK_EQ(s.hw_dispatch_sent, 8u);
    CHECK_EQ(s.hw_bytes_sent, 64u);
    CHECK_EQ(s.hw_fallback_to_quic, 0u);
}

// ============================================================================
// Main
// ============================================================================

int test_main() {
    std::cout << "=== v1.6.0.5 P4 Hardware Accel Layer Tests ===" << std::endl;

    // CudaBuffer
    test_cuda_buffer_default();
    test_cuda_buffer_view();
    test_cuda_buffer_reset();

    // Allocator
    test_allocator_stub_basic();
    test_allocator_stub_zero();
    test_allocator_stub_stats();
    test_allocator_export_ipc();

    // NvlinkTransport
    test_nvlink_type_name();
    test_nvlink_not_ready_default();
    test_nvlink_mock_mode();
    test_nvlink_can_connect_default();
    test_nvlink_can_connect_mock();
    test_nvlink_send_recv_mock();
    test_nvlink_send_not_ready();
    test_nvlink_recv_no_data();
    test_nvlink_multicast_mock();
    test_nvlink_multicast_empty();
    test_nvlink_stats();
    test_nvlink_reset_stats();
    test_nvlink_supports_multicast();

    // CudaIpcTransport
    test_cuda_ipc_type_name();
    test_cuda_ipc_not_ready_default();
    test_cuda_ipc_mock_mode();
    test_cuda_ipc_send_recv_mock();
    test_cuda_ipc_no_multicast();
    test_cuda_ipc_export_open();
    test_cuda_ipc_stats();
    test_cuda_ipc_close_peer();

    // TransportSelector
    test_selector_empty();
    test_selector_register_nvlink();
    test_selector_register_duplicate();
    test_selector_priority();
    test_selector_fallback_nullptr();
    test_selector_unregister();
    test_selector_cache();
    test_selector_invalidate_all();
    test_selector_preselect();
    test_selector_list_transports();
    test_selector_aggregate_stats();

    // EpCommPlan transport_hint
    test_comm_plan_transport_hint_default();
    test_comm_plan_transport_hint_set();
    test_comm_plan_transport_hint_cuda_ipc();

    // Misc
    test_to_string_type();
    test_build_has_real_cuda();

    // Concurrent
    test_selector_concurrent_select();

    // EpChannel hw integration (P4)
    test_ep_channel_hw_no_selector();
    test_ep_channel_hw_set_selector();
    test_ep_channel_hw_dispatch_no_selector_fallback();
    test_ep_channel_hw_dispatch_invalid_buf();
    test_ep_channel_hw_dispatch_via_nvlink_mock();
    test_ep_channel_hw_combine_via_nvlink_mock();
    test_ep_channel_hw_dispatch_fallback_when_nvlink_not_ready();
    test_ep_channel_hw_dispatch_cuda_ipc_mock();
    test_ep_channel_hw_multiple_dispatches();

    std::cout << "=== Results: " << g_pass << " PASS, "
              << g_fail << " FAIL ===" << std::endl;
    return g_fail == 0 ? 0 : 1;
}

} // namespace

int main() {
    return test_main();
}
