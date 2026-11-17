// hw_accel.cpp - Hardware-accelerated transport implementations (v1.6.0.5 / P4)
//
// Stub Mock strategy:
//   * No CUDA SDK required to build. Default state: ready_=false,
//     can_connect()=false. After set_mock_mode(true): ready_=true,
//     can_connect()=true, send_gpu/recv_gpu use host memcpy to simulate
//     GPU-to-GPU transfers via an in-process per-peer buffer map.
//   * Real NVLink / CUDA IPC implementation is guarded by LINOH_WITH_CUDA
//     and left as documented comments only (no CUDA SDK in current env).
//   * Statistics are updated under mu_ for thread safety.

#include "linoh/net/hw_accel.hpp"
#include "linoh/net/nvlink_transport.hpp"
#include "linoh/net/cuda_ipc_transport.hpp"
#include "linoh/util/logging.hpp"

#include <atomic>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace linoh::net {

// ============================================================================
// Helpers
// ============================================================================

namespace {

/// Validate a CudaBuffer for send/recv operations.
bool valid_buffer(const CudaBuffer &buf) {
    return buf.ptr != nullptr && buf.size > 0;
}

/// Copy `size` bytes from src to dst and return bytes copied.
std::size_t copy_buffer(void *dst, const void *src, std::size_t size) {
    if (dst == nullptr || src == nullptr || size == 0) return 0;
    std::memcpy(dst, src, size);
    return size;
}

} // namespace

// ============================================================================
// to_string(Type)
// ============================================================================

const char *to_string(HwAccelTransport::Type t) noexcept {
    switch (t) {
        case HwAccelTransport::Type::NVLINK:   return "nvlink";
        case HwAccelTransport::Type::CUDA_IPC: return "cuda-ipc";
        case HwAccelTransport::Type::RDMA:     return "rdma";
    }
    return "unknown";
}

// ============================================================================
// NvlinkTransport
// ============================================================================

NvlinkTransport::NvlinkTransport()
    : mock_mode_(false)
    , gpu_count_(0)
    , nvlink_version_(0)
    , bandwidth_gbps_(0.0)
    , send_total_(0)
    , recv_total_(0)
    , send_bytes_(0)
    , recv_bytes_(0)
    , send_failures_(0)
    , recv_failures_(0)
    , multicast_total_(0)
    , multicast_bytes_(0)
    , latency_sum_us_(0.0)
    , latency_count_(0) {
    // Without CUDA, we start in non-ready mock-capable mode.
    // With CUDA, probe_topology_() would be called here.
#ifndef LINOH_WITH_CUDA
    LINOH_INFO("NvlinkTransport: built without CUDA (stub mock available)");
#else
    probe_topology_();
#endif
}

NvlinkTransport::~NvlinkTransport() = default;

std::shared_ptr<NvlinkTransport> NvlinkTransport::create() {
    return std::make_shared<NvlinkTransport>();
}

bool NvlinkTransport::is_ready() const noexcept {
    // noexcept + lock_guard 会在锁失败时抛 system_error → std::terminate。
    // 改用 try_lock：锁失败时安全降级为"未就绪"。
    std::unique_lock<std::mutex> lock(mu_, std::try_to_lock);
    if (!lock.owns_lock()) return false;
    return mock_mode_ || (gpu_count_ > 0);
}

bool NvlinkTransport::is_mock_mode() const noexcept {
    std::unique_lock<std::mutex> lock(mu_, std::try_to_lock);
    if (!lock.owns_lock()) return false;
    return mock_mode_;
}

bool NvlinkTransport::set_mock_mode(bool enabled) {
    std::lock_guard<std::mutex> lock(mu_);
    bool prev = mock_mode_;
    mock_mode_ = enabled;
    LINOH_INFO("NvlinkTransport: mock_mode=", enabled,
               " (prev=", prev, ")");
    return prev;
}

bool NvlinkTransport::can_connect(NodeId peer) const {
    // LINOH_WITH_CUDA real path:
    //   Query NVML for the local device's NVLink lane state to the peer's
    //   device. Use nvmlDeviceGetNvLinkState for each link and verify peer
    //   UUID matches. Returns true only if at least one active NVLink lane
    //   reaches the peer device.
    //
    // Stub mock path:
    //   Returns true iff transport is ready (mock mode enabled). A zero
    //   peer id is treated as unreachable.
    if (!is_ready()) return false;
    if (peer == 0) return false;
    return true;
}

bool NvlinkTransport::supports_multicast() const noexcept {
    // NVLink supports multicast via CU_MEM_HANDLE_TYPE_MULTICAST (real CUDA).
    // In mock mode we simulate multicast via per-peer memcpy.
    return true;
}

std::size_t NvlinkTransport::send_gpu(NodeId peer, const CudaBuffer &buf) {
    std::lock_guard<std::mutex> lock(mu_);
    ++send_total_;

    if (!mock_mode_ && gpu_count_ == 0) {
        ++send_failures_;
        LINOH_WARN("NvlinkTransport::send_gpu: not ready, peer=", peer);
        return 0;
    }
    if (!valid_buffer(buf)) {
        ++send_failures_;
        LINOH_WARN("NvlinkTransport::send_gpu: invalid buffer, peer=", peer);
        return 0;
    }
    if (peer == 0) {
        ++send_failures_;
        LINOH_WARN("NvlinkTransport::send_gpu: empty peer node id");
        return 0;
    }

#ifdef LINOH_WITH_CUDA
    // Real CUDA path:
    //   1. Resolve peer node id to a local CUDA device index.
    //   2. Select the active NVLink lane to that device.
    //   3. Issue cudaMemcpyDeviceToDevice(dst_dev_ptr, buf.ptr, buf.size).
    //   4. Synchronize the stream and check cudaSuccess.
    return real_send_(peer, buf);
#else
    // Stub mock path: memcpy buf.ptr into mock_queues_[peer].
    auto &q = mock_queues_[peer];
    q.resize(buf.size);
    std::size_t copied = copy_buffer(q.data(), buf.ptr, buf.size);
    if (copied != buf.size) {
        ++send_failures_;
        LINOH_ERROR("NvlinkTransport::send_gpu: memcpy mismatch, copied=",
                    copied, " expected=", buf.size);
        return 0;
    }
    send_bytes_ += copied;
    return copied;
#endif
}

std::size_t NvlinkTransport::recv_gpu(NodeId peer, CudaBuffer &buf) {
    std::lock_guard<std::mutex> lock(mu_);
    ++recv_total_;

    if (!mock_mode_ && gpu_count_ == 0) {
        ++recv_failures_;
        LINOH_WARN("NvlinkTransport::recv_gpu: not ready, peer=", peer);
        return 0;
    }
    if (!valid_buffer(buf)) {
        ++recv_failures_;
        LINOH_WARN("NvlinkTransport::recv_gpu: invalid buffer, peer=", peer);
        return 0;
    }
    if (peer == 0) {
        ++recv_failures_;
        LINOH_WARN("NvlinkTransport::recv_gpu: empty peer node id");
        return 0;
    }

#ifdef LINOH_WITH_CUDA
    // Real CUDA path: wait on NVLink receive completion for registered buffer.
    return real_recv_(peer, buf);
#else
    // Stub mock path: memcpy mock_queues_[peer] into buf.ptr.
    auto it = mock_queues_.find(peer);
    if (it == mock_queues_.end() || it->second.empty()) {
        ++recv_failures_;
        LINOH_WARN("NvlinkTransport::recv_gpu: no buffered data from peer=", peer);
        return 0;
    }
    const auto &q = it->second;
    if (q.size() > buf.size) {
        ++recv_failures_;
        LINOH_WARN("NvlinkTransport::recv_gpu: dst buffer too small, need=",
                   q.size(), " have=", buf.size);
        return 0;
    }
    std::size_t copied = copy_buffer(buf.ptr, q.data(), q.size());
    if (copied != q.size()) {
        ++recv_failures_;
        LINOH_ERROR("NvlinkTransport::recv_gpu: memcpy mismatch, copied=",
                    copied, " expected=", q.size());
        return 0;
    }
    recv_bytes_ += copied;
    // Clear the queue after recv (one-shot consumption).
    mock_queues_.erase(it);
    return copied;
#endif
}

std::size_t NvlinkTransport::send_multicast(const std::vector<NodeId> &peers,
                                            const CudaBuffer &buf) {
    std::lock_guard<std::mutex> lock(mu_);
    ++multicast_total_;

    if (!mock_mode_ && gpu_count_ == 0) {
        ++send_failures_;
        LINOH_WARN("NvlinkTransport::send_multicast: not ready");
        return 0;
    }
    if (!valid_buffer(buf)) {
        ++send_failures_;
        LINOH_WARN("NvlinkTransport::send_multicast: invalid buffer");
        return 0;
    }
    if (peers.empty()) {
        ++send_failures_;
        LINOH_WARN("NvlinkTransport::send_multicast: empty peer list");
        return 0;
    }

    // LINOH_WITH_CUDA real path:
    //   Use NVSwitch multicast or grouped cudaMemcpyAsync with a multicast
    //   target set to fan out a single copy to multiple devices.
    //
    // Stub mock path: iterate peers and per-node memcpy into mock_queues_.
    bool all_ok = true;
    std::size_t total_bytes = 0;
    for (const auto &peer : peers) {
        if (peer == 0) {
            ++send_failures_;
            all_ok = false;
            continue;
        }
        auto &q = mock_queues_[peer];
        q.resize(buf.size);
        std::size_t copied = copy_buffer(q.data(), buf.ptr, buf.size);
        if (copied != buf.size) {
            ++send_failures_;
            all_ok = false;
            continue;
        }
        total_bytes += copied;
    }
    send_bytes_ += total_bytes;
    multicast_bytes_ += total_bytes;
    // Return per-peer bytes (multicast counts once).
    return all_ok ? buf.size : 0;
}

HwAccelTransport::Stats NvlinkTransport::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    Stats s;
    s.send_total = send_total_;
    s.recv_total = recv_total_;
    s.send_bytes = send_bytes_;
    s.recv_bytes = recv_bytes_;
    s.send_failures = send_failures_;
    s.recv_failures = recv_failures_;
    s.multicast_total = multicast_total_;
    s.multicast_bytes = multicast_bytes_;
    s.avg_latency_us = (latency_count_ > 0)
        ? (latency_sum_us_ / static_cast<double>(latency_count_))
        : 0.0;
    s.mock_mode = mock_mode_;
    return s;
}

void NvlinkTransport::reset_stats() {
    std::lock_guard<std::mutex> lock(mu_);
    send_total_ = 0;
    recv_total_ = 0;
    send_bytes_ = 0;
    recv_bytes_ = 0;
    send_failures_ = 0;
    recv_failures_ = 0;
    multicast_total_ = 0;
    multicast_bytes_ = 0;
    latency_sum_us_ = 0.0;
    latency_count_ = 0;
}

int NvlinkTransport::gpu_count() const noexcept {
    std::unique_lock<std::mutex> lock(mu_, std::try_to_lock);
    if (!lock.owns_lock()) return 0;
    return gpu_count_;
}

int NvlinkTransport::nvlink_version() const noexcept {
    std::unique_lock<std::mutex> lock(mu_, std::try_to_lock);
    if (!lock.owns_lock()) return 0;
    return nvlink_version_;
}

double NvlinkTransport::aggregate_bandwidth_gbps() const noexcept {
    std::unique_lock<std::mutex> lock(mu_, std::try_to_lock);
    if (!lock.owns_lock()) return 0.0;
    return bandwidth_gbps_;
}

void NvlinkTransport::probe_topology_() {
    // LINOH_WITH_CUDA real path:
    //   1. Call nvmlDeviceGetCount(&gpu_count_).
    //   2. For each device, query nvmlDeviceGetNvLinkState for each link.
    //   3. Determine nvlink_version_ from device compute capability.
    //   4. Calculate aggregate bandwidth (links * per-link bandwidth).
    // Without CUDA SDK this is a no-op; gpu_count_ stays 0.
}

std::size_t NvlinkTransport::real_send_(NodeId peer, const CudaBuffer &buf) {
    // Real CUDA implementation (compiled only with LINOH_WITH_CUDA).
    // Placeholder: would call cudaMemcpyDeviceToDevice.
    (void)peer;
    (void)buf;
    return 0;
}

std::size_t NvlinkTransport::real_recv_(NodeId peer, CudaBuffer &buf) {
    // Real CUDA implementation (compiled only with LINOH_WITH_CUDA).
    (void)peer;
    (void)buf;
    return 0;
}

// ============================================================================
// CudaIpcTransport
// ============================================================================

CudaIpcTransport::CudaIpcTransport()
    : mock_mode_(false)
    , gpu_count_(0)
    , send_total_(0)
    , recv_total_(0)
    , send_bytes_(0)
    , recv_bytes_(0)
    , send_failures_(0)
    , recv_failures_(0)
    , latency_sum_us_(0.0)
    , latency_count_(0) {
#ifndef LINOH_WITH_CUDA
    LINOH_INFO("CudaIpcTransport: built without CUDA (stub mock available)");
#endif
}

CudaIpcTransport::~CudaIpcTransport() = default;

std::shared_ptr<CudaIpcTransport> CudaIpcTransport::create() {
    return std::make_shared<CudaIpcTransport>();
}

bool CudaIpcTransport::is_ready() const noexcept {
    std::unique_lock<std::mutex> lock(mu_, std::try_to_lock);
    if (!lock.owns_lock()) return false;
    return mock_mode_ || (gpu_count_ > 0);
}

bool CudaIpcTransport::is_mock_mode() const noexcept {
    std::unique_lock<std::mutex> lock(mu_, std::try_to_lock);
    if (!lock.owns_lock()) return false;
    return mock_mode_;
}

bool CudaIpcTransport::set_mock_mode(bool enabled) {
    std::lock_guard<std::mutex> lock(mu_);
    bool prev = mock_mode_;
    mock_mode_ = enabled;
    LINOH_INFO("CudaIpcTransport: mock_mode=", enabled,
               " (prev=", prev, ")");
    return prev;
}

bool CudaIpcTransport::can_connect(NodeId peer) const {
    // LINOH_WITH_CUDA real path:
    //   Resolve peer to a CUDA IPC handle. CUDA IPC requires the two
    //   processes to be on the same physical node. Verify by checking
    //   that the IPC handle advertised by peer is openable from this
    //   process via cudaIpcOpenMemHandle().
    //
    // Stub mock path:
    //   Returns true iff ready and peer is non-zero.
    if (!is_ready()) return false;
    if (peer == 0) return false;
    return true;
}

std::size_t CudaIpcTransport::send_gpu(NodeId peer, const CudaBuffer &buf) {
    std::lock_guard<std::mutex> lock(mu_);
    ++send_total_;

    if (!mock_mode_ && gpu_count_ == 0) {
        ++send_failures_;
        LINOH_WARN("CudaIpcTransport::send_gpu: not ready, peer=", peer);
        return 0;
    }
    if (!valid_buffer(buf)) {
        ++send_failures_;
        LINOH_WARN("CudaIpcTransport::send_gpu: invalid buffer, peer=", peer);
        return 0;
    }
    if (peer == 0) {
        ++send_failures_;
        LINOH_WARN("CudaIpcTransport::send_gpu: empty peer node id");
        return 0;
    }

#ifdef LINOH_WITH_CUDA
    // Real CUDA path:
    //   1. Export source GPU memory via cudaIpcGetMemHandle(&handle, buf.ptr).
    //   2. Serialize handle and pass to peer (via ctrl/1 channel).
    //   3. Peer opens via cudaIpcOpenMemHandle(&peer_ptr, handle, ...).
    //   4. cudaMemcpyAsync(peer_ptr, buf.ptr, buf.size, D2D) + sync.
    return real_send_(peer, buf);
#else
    // Stub mock path: memcpy buf.ptr into mock_shm_[peer].
    auto &q = mock_shm_[peer];
    q.resize(buf.size);
    std::size_t copied = copy_buffer(q.data(), buf.ptr, buf.size);
    if (copied != buf.size) {
        ++send_failures_;
        LINOH_ERROR("CudaIpcTransport::send_gpu: memcpy mismatch, copied=",
                    copied, " expected=", buf.size);
        return 0;
    }
    send_bytes_ += copied;
    return copied;
#endif
}

std::size_t CudaIpcTransport::recv_gpu(NodeId peer, CudaBuffer &buf) {
    std::lock_guard<std::mutex> lock(mu_);
    ++recv_total_;

    if (!mock_mode_ && gpu_count_ == 0) {
        ++recv_failures_;
        LINOH_WARN("CudaIpcTransport::recv_gpu: not ready, peer=", peer);
        return 0;
    }
    if (!valid_buffer(buf)) {
        ++recv_failures_;
        LINOH_WARN("CudaIpcTransport::recv_gpu: invalid buffer, peer=", peer);
        return 0;
    }
    if (peer == 0) {
        ++recv_failures_;
        LINOH_WARN("CudaIpcTransport::recv_gpu: empty peer node id");
        return 0;
    }

#ifdef LINOH_WITH_CUDA
    // Real CUDA path: open IPC handle and cudaMemcpyAsync.
    return real_recv_(peer, buf);
#else
    // Stub mock path: memcpy mock_shm_[peer] into buf.ptr.
    auto it = mock_shm_.find(peer);
    if (it == mock_shm_.end() || it->second.empty()) {
        ++recv_failures_;
        LINOH_WARN("CudaIpcTransport::recv_gpu: no buffered data from peer=", peer);
        return 0;
    }
    const auto &q = it->second;
    if (q.size() > buf.size) {
        ++recv_failures_;
        LINOH_WARN("CudaIpcTransport::recv_gpu: dst buffer too small, need=",
                   q.size(), " have=", buf.size);
        return 0;
    }
    std::size_t copied = copy_buffer(buf.ptr, q.data(), q.size());
    if (copied != q.size()) {
        ++recv_failures_;
        LINOH_ERROR("CudaIpcTransport::recv_gpu: memcpy mismatch, copied=",
                    copied, " expected=", q.size());
        return 0;
    }
    recv_bytes_ += copied;
    mock_shm_.erase(it);
    return copied;
#endif
}

HwAccelTransport::Stats CudaIpcTransport::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    Stats s;
    s.send_total = send_total_;
    s.recv_total = recv_total_;
    s.send_bytes = send_bytes_;
    s.recv_bytes = recv_bytes_;
    s.send_failures = send_failures_;
    s.recv_failures = recv_failures_;
    s.multicast_total = 0;  // CUDA IPC does not support multicast
    s.multicast_bytes = 0;
    s.avg_latency_us = (latency_count_ > 0)
        ? (latency_sum_us_ / static_cast<double>(latency_count_))
        : 0.0;
    s.mock_mode = mock_mode_;
    return s;
}

void CudaIpcTransport::reset_stats() {
    std::lock_guard<std::mutex> lock(mu_);
    send_total_ = 0;
    recv_total_ = 0;
    send_bytes_ = 0;
    recv_bytes_ = 0;
    send_failures_ = 0;
    recv_failures_ = 0;
    latency_sum_us_ = 0.0;
    latency_count_ = 0;
}

bool CudaIpcTransport::export_for_peer(NodeId peer, CudaBuffer &buf) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!valid_buffer(buf)) return false;
    if (peer == 0) return false;

#ifdef LINOH_WITH_CUDA
    return real_export_(peer, buf);
#else
    // Stub: mark device_handle as "exported" (set valid flag only).
    buf.device_handle.valid = true;
    // Cache a copy in mock_shm_ so recv_gpu can fetch it.
    auto &q = mock_shm_[peer];
    q.resize(buf.size);
    std::memcpy(q.data(), buf.ptr, buf.size);
    return true;
#endif
}

CudaBuffer CudaIpcTransport::open_for_peer(NodeId peer,
                                           const DeviceHandle &handle,
                                           std::size_t size,
                                           int device_id) {
    std::lock_guard<std::mutex> lock(mu_);
    if (peer == 0 || size == 0 || !handle.valid) {
        return CudaBuffer{};
    }

#ifdef LINOH_WITH_CUDA
    return real_open_(peer, handle, size, device_id);
#else
    // Stub: return a non-owning view over mock_shm_[peer].
    auto it = mock_shm_.find(peer);
    if (it == mock_shm_.end() || it->second.size() < size) {
        return CudaBuffer{};
    }
    CudaBuffer view(it->second.data(), size, BufferLocation::REGULAR_HOST, -1);
    view.owns_memory = false;
    return view;
#endif
}

void CudaIpcTransport::close_peer(NodeId peer) {
    std::lock_guard<std::mutex> lock(mu_);
    mock_shm_.erase(peer);
    peer_cache_.erase(peer);
}

std::size_t CudaIpcTransport::peer_count() const noexcept {
    std::unique_lock<std::mutex> lock(mu_, std::try_to_lock);
    if (!lock.owns_lock()) return 0;
    return peer_cache_.size();
}

bool CudaIpcTransport::real_export_(NodeId peer, CudaBuffer &buf) {
    // Real CUDA implementation (compiled only with LINOH_WITH_CUDA).
    (void)peer;
    (void)buf;
    return false;
}

CudaBuffer CudaIpcTransport::real_open_(NodeId peer,
                                         const DeviceHandle &handle,
                                         std::size_t size,
                                         int device_id) {
    // Real CUDA implementation (compiled only with LINOH_WITH_CUDA).
    (void)peer;
    (void)handle;
    (void)size;
    (void)device_id;
    return CudaBuffer{};
}

} // namespace linoh::net
