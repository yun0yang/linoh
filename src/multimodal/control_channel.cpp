// control_channel.cpp — 控制信道隔离实现（P5-A-2）
//
// 实现 ControlChannel 类，封装 ctrl_conn 上的 RPC 调用，提供优先级分级 API。

#include "linoh/multimodal/control_channel.hpp"

#include <cstring>
#include <sstream>
#include <utility>

#include "linoh/util/logging.hpp"

namespace linoh::multimodal {

// ============================================================================
// HeartbeatPayload 序列化/反序列化
// ============================================================================

// 布局：node_id(8) + timestamp_ms(8) + state(1) + active_streams(4) + pending_rpcs(4) = 25 字节
static constexpr std::size_t kHeartbeatPayloadSize = 25;

std::vector<std::uint8_t> HeartbeatPayload::serialize() const {
    std::vector<std::uint8_t> buf;
    buf.reserve(kHeartbeatPayloadSize);
    // 小端序写入
    auto put_u64 = [&](std::uint64_t v) {
        for (int i = 0; i < 8; ++i) buf.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
    };
    auto put_u32 = [&](std::uint32_t v) {
        for (int i = 0; i < 4; ++i) buf.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
    };
    put_u64(node_id);
    put_u64(timestamp_ms);
    buf.push_back(state);
    put_u32(active_streams);
    put_u32(pending_rpcs);
    return buf;
}

std::size_t HeartbeatPayload::parse(std::span<const std::uint8_t> data, HeartbeatPayload &out) {
    if (data.size() < kHeartbeatPayloadSize) return 0;
    auto get_u64 = [&](std::size_t off) -> std::uint64_t {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= static_cast<std::uint64_t>(data[off + i]) << (i * 8);
        }
        return v;
    };
    auto get_u32 = [&](std::size_t off) -> std::uint32_t {
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            v |= static_cast<std::uint32_t>(data[off + i]) << (i * 8);
        }
        return v;
    };
    out.node_id        = get_u64(0);
    out.timestamp_ms   = get_u64(8);
    out.state          = data[16];
    out.active_streams = get_u32(17);
    out.pending_rpcs   = get_u32(21);
    return kHeartbeatPayloadSize;
}

// ============================================================================
// ControlChannel 构造/析构/移动
// ============================================================================

ControlChannel::ControlChannel(std::shared_ptr<endpoint::Connection> ctrl_conn)
    : conn_(std::move(ctrl_conn)),
      task_pool_(std::make_unique<util::TaskPool>(2)) {
    LINOH_INFO("ControlChannel: created (conn_id=%llu)",
               conn_ ? static_cast<unsigned long long>(conn_->id()) : 0ULL);
}

ControlChannel::~ControlChannel() {
    stop_heartbeat_thread();

    // v1.7.0.7 C13: 等待所有异步 RPC 任务完成，避免 UAF
    // call_rpc 用 std::async 启动的异步任务会捕获 this 并访问 record_failure 等成员，
    // 必须在析构完成前确保这些任务都已退出。
    {
        std::unique_lock<std::mutex> lk(async_rpc_mu_);
        async_rpc_cv_.wait(lk, [this] { return pending_async_rpcs_.load() == 0; });
    }

    LINOH_INFO("ControlChannel: destroyed");
}

ControlChannel::ControlChannel(ControlChannel &&other) noexcept
    : conn_(std::move(other.conn_)),
      heartbeat_thread_(std::move(other.heartbeat_thread_)),
      heartbeat_running_(other.heartbeat_running_.exchange(false)),
      heartbeat_stop_(other.heartbeat_stop_.exchange(false)),
      hb_interval_ms_(other.hb_interval_ms_),
      hb_timeout_ms_(other.hb_timeout_ms_),
      hb_miss_count_(other.hb_miss_count_.exchange(0)),
      last_pong_time_(std::move(other.last_pong_time_)),
      stats_mu_(),
      stats_(),
      task_pool_(std::make_unique<util::TaskPool>(2)) {  // mp-P10: 新建线程池（不转移 other 的池）
    // v1.7.0.7 H9: 锁 other.stats_mu_ 再移动 other.stats_，避免与并发读取 stats_ 的线程竞争
    //   根因：原实现在初始化列表中 std::move(other.stats_) 无锁保护，
    //   若 other 正在被其他线程读取 stats_（如 call_rpc 中 record_failure），
    //   移动操作会导致数据竞争（UB）
    std::lock_guard<std::mutex> lk(other.stats_mu_);
    stats_ = std::move(other.stats_);
}

ControlChannel &ControlChannel::operator=(ControlChannel &&other) noexcept {
    if (this != &other) {
        stop_heartbeat_thread();
        // v1.7.0.7 C13: 移动前等待当前对象的所有异步 RPC 完成
        // （异步任务捕获的是 this 指针，移动后访问 stats_ 等成员会出错）
        {
            std::unique_lock<std::mutex> lk(async_rpc_mu_);
            async_rpc_cv_.wait(lk, [this] { return pending_async_rpcs_.load() == 0; });
        }
        conn_ = std::move(other.conn_);
        heartbeat_thread_ = std::move(other.heartbeat_thread_);
        heartbeat_running_.store(other.heartbeat_running_.exchange(false));
        heartbeat_stop_.store(other.heartbeat_stop_.exchange(false));
        hb_interval_ms_ = other.hb_interval_ms_;
        hb_timeout_ms_ = other.hb_timeout_ms_;
        hb_miss_count_.store(other.hb_miss_count_.exchange(0));
        last_pong_time_ = std::move(other.last_pong_time_);
        // mp-P10: 重建线程池（旧池在 unique_ptr 赋值时自动 stop+join，此时 pending==0 已保证）
        task_pool_ = std::make_unique<util::TaskPool>(2);
        // v1.7.0.7 H9: 同时锁 this->stats_mu_ 和 other.stats_mu_，避免移动 stats_ 时数据竞争
        //   根因：原实现只锁 this->stats_mu_，未锁 other.stats_mu_，
        //   若 other 正在被并发读取 stats_，std::move(other.stats_) 是 UB
        //   用 std::lock 同时锁两个互斥量避免死锁
        std::lock(stats_mu_, other.stats_mu_);
        std::lock_guard<std::mutex> lk1(stats_mu_, std::adopt_lock);
        std::lock_guard<std::mutex> lk2(other.stats_mu_, std::adopt_lock);
        stats_ = std::move(other.stats_);
    }
    return *this;
}

// ============================================================================
// RPC API
// ============================================================================

std::future<RpcResponse> ControlChannel::call_rpc(
    protocol::MethodId method,
    std::span<const std::uint8_t> payload,
    RpcPriority priority,
    std::chrono::milliseconds timeout) {

    record_call(priority);

    // 默认超时按优先级
    std::uint32_t timeout_ms = static_cast<std::uint32_t>(timeout.count());
    if (timeout_ms == 0) {
        timeout_ms = default_timeout_ms(priority);
    }

    // v1.7.0.7 C13: 捕获 conn_ + self，并增加 pending_async_rpcs_ 计数器，
    // 析构时等待所有异步任务完成，避免访问已释放的成员导致 UAF。
    // mp-P10 (v1.7.0.9): std::async → task_pool_->push，复用固定线程池
    auto conn = conn_;
    auto self = this;
    pending_async_rpcs_.fetch_add(1);

    return task_pool_->push([conn, method, payload, timeout_ms, self]() {
        // RAII 守卫：任务退出时递减计数器并通知析构线程
        struct AsyncRpcGuard {
            ControlChannel *ch;
            ~AsyncRpcGuard() {
                if (ch) {
                    if (ch->pending_async_rpcs_.fetch_sub(1) == 1) {
                        std::lock_guard<std::mutex> lk(ch->async_rpc_mu_);
                        ch->async_rpc_cv_.notify_all();
                    }
                }
            }
        } guard{self};

        RpcResponse resp;
        auto t0 = std::chrono::steady_clock::now();
        try {
            if (!conn) {
                resp.ok = false;
                resp.error_msg = "connection is null";
                if (self) self->record_failure();
                return resp;
            }
            auto fut = conn->call(method, payload, timeout_ms);
            auto raw = fut.get();
            auto t1 = std::chrono::steady_clock::now();
            resp.ok = true;
            resp.payload = std::move(raw);
            resp.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);
        } catch (const std::exception &e) {
            auto t1 = std::chrono::steady_clock::now();
            resp.ok = false;
            resp.error_msg = e.what();
            resp.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0);
            if (self) {
                self->record_failure();
                // 简单判定：包含 "timeout" 关键字视为超时
                if (resp.error_msg.find("timeout") != std::string::npos ||
                    resp.error_msg.find("timed out") != std::string::npos) {
                    self->record_timeout();
                }
            }
        }
        return resp;
    });
}

void ControlChannel::send_notification(
    protocol::MethodId method,
    std::span<const std::uint8_t> payload,
    RpcPriority priority) {

    record_call(priority);
    if (!conn_) {
        record_failure();
        return;
    }
    try {
        conn_->notify(method, payload);
    } catch (const std::exception &e) {
        LINOH_ERROR("ControlChannel::send_notification failed: %s", e.what());
        record_failure();
    }
}

void ControlChannel::send_heartbeat(const HeartbeatPayload &payload) {
    record_heartbeat();
    if (!conn_) return;
    auto bytes = payload.serialize();
    try {
        // 心跳用 Notification（无响应）
        conn_->notify(protocol::MethodId::Heartbeat, std::span<const std::uint8_t>(bytes.data(), bytes.size()));
        // 更新 last_pong_time（发送即视为本端活动）
        last_pong_time_ = std::chrono::steady_clock::now();
        hb_miss_count_.store(0, std::memory_order_release);
    } catch (const std::exception &e) {
        LINOH_ERROR("ControlChannel::send_heartbeat failed: %s", e.what());
        record_failure();
    }
}

std::future<void> ControlChannel::notify_drain(std::string_view reason) {
    record_drain_notify();
    // P0 紧急：用 Notification 立即发送，不等待响应
    // payload 格式：reason 字符串（以 \0 结尾）
    std::vector<std::uint8_t> payload;
    payload.reserve(reason.size() + 1);
    for (char c : reason) payload.push_back(static_cast<std::uint8_t>(c));
    payload.push_back(0);

    auto conn = conn_;
    // mp-P10 (v1.7.0.9): std::async → task_pool_->push，复用固定线程池
    return task_pool_->push([conn, payload = std::move(payload)]() {
        if (!conn) return;
        try {
            conn->notify(protocol::MethodId::Drain,
                         std::span<const std::uint8_t>(payload.data(), payload.size()));
        } catch (const std::exception &e) {
            LINOH_ERROR("ControlChannel::notify_drain failed: %s", e.what());
        }
    });
}

// ============================================================================
// V3-A: 跨域控制面消息接口实现
// ============================================================================

void ControlChannel::send_cross_domain_digest(std::span<const std::uint8_t> payload) {
    // V3-A: 跨域节点摘要用 Notification（无响应），P1 优先级
    // 复用 send_notification 的统计/错误处理逻辑
    send_notification(protocol::MethodId::CrossDomainDigest, payload, RpcPriority::P1_Normal);
}

std::future<RpcResponse> ControlChannel::request_cross_domain_digest(std::uint32_t self_domain) {
    // V3-A: 跨域摘要请求用 Request（有响应），P1 优先级
    // payload 格式：self_domain（4 字节小端序）
    std::vector<std::uint8_t> payload(4);
    payload[0] = static_cast<std::uint8_t>(self_domain & 0xFF);
    payload[1] = static_cast<std::uint8_t>((self_domain >> 8) & 0xFF);
    payload[2] = static_cast<std::uint8_t>((self_domain >> 16) & 0xFF);
    payload[3] = static_cast<std::uint8_t>((self_domain >> 24) & 0xFF);

    return call_rpc(protocol::MethodId::CrossDomainDigestReq,
                    std::span<const std::uint8_t>(payload.data(), payload.size()),
                    RpcPriority::P1_Normal);
}

// ============================================================================
// 心跳线程
// ============================================================================

void ControlChannel::start_heartbeat_thread(
    std::uint32_t interval_ms, std::uint32_t timeout_ms) {
    if (heartbeat_running_.load(std::memory_order_acquire)) {
        LINOH_WARN("ControlChannel: heartbeat thread already running");
        return;
    }
    hb_interval_ms_ = interval_ms;
    hb_timeout_ms_ = timeout_ms;
    hb_miss_count_.store(0, std::memory_order_release);
    heartbeat_stop_.store(false, std::memory_order_release);
    last_pong_time_ = std::chrono::steady_clock::now();
    heartbeat_running_.store(true, std::memory_order_release);
    heartbeat_thread_ = std::thread([this]() { this->heartbeat_loop(); });
    LINOH_INFO("ControlChannel: heartbeat thread started (interval=%ums, timeout=%ums)",
               interval_ms, timeout_ms);
}

void ControlChannel::stop_heartbeat_thread() {
    if (!heartbeat_running_.load(std::memory_order_acquire)) return;
    heartbeat_stop_.store(true, std::memory_order_release);
    heartbeat_cv_.notify_all();
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    heartbeat_running_.store(false, std::memory_order_release);
    LINOH_INFO("ControlChannel: heartbeat thread stopped");
}

void ControlChannel::heartbeat_loop() {
    while (!heartbeat_stop_.load(std::memory_order_acquire)) {
        std::unique_lock<std::mutex> lk(heartbeat_mu_);
        heartbeat_cv_.wait_for(lk, std::chrono::milliseconds(hb_interval_ms_),
                               [this]() { return heartbeat_stop_.load(std::memory_order_acquire); });
        if (heartbeat_stop_.load(std::memory_order_acquire)) break;

        // 构造心跳 payload
        HeartbeatPayload hb;
        hb.node_id = 0;  // 上层可在调用 send_heartbeat 时覆盖
        hb.timestamp_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        hb.state = 0;
        hb.active_streams = conn_ ? static_cast<std::uint32_t>(conn_->rpc_in_flight_count()) : 0;
        hb.pending_rpcs = hb.active_streams;
        send_heartbeat(hb);

        // 检查 PONG 超时
        auto now = std::chrono::steady_clock::now();
        auto since_pong = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_pong_time_);
        if (since_pong.count() > static_cast<std::int64_t>(hb_timeout_ms_)) {
            std::uint32_t misses = hb_miss_count_.fetch_add(1, std::memory_order_acq_rel) + 1;
            LINOH_WARN("ControlChannel: heartbeat miss #%u (since last pong=%lldms)",
                       misses, static_cast<long long>(since_pong.count()));
            // mp-L2 (v1.7.0.8): 使用可配置 hb_max_misses_ 替代硬编码 3
            if (misses >= hb_max_misses_) {
                LINOH_ERROR("ControlChannel: heartbeat timeout (",
                            hb_max_misses_, " consecutive misses)");
                if (on_heartbeat_timeout) {
                    try { on_heartbeat_timeout(); } catch (...) {}
                }
                // 重置 miss 计数，避免持续触发
                hb_miss_count_.store(0, std::memory_order_release);
                last_pong_time_ = now;
            }
        }
    }
}

// ============================================================================
// 状态查询
// ============================================================================

ControlChannelStats ControlChannel::stats() const {
    std::lock_guard<std::mutex> lk(stats_mu_);
    return stats_;
}

bool ControlChannel::is_valid() const noexcept {
    return conn_ != nullptr;
}

std::uint32_t ControlChannel::default_timeout_ms(RpcPriority p) noexcept {
    switch (p) {
        case RpcPriority::P0_Emergency: return 5000;    // 5s
        case RpcPriority::P1_Normal:     return 30000;  // 30s
        case RpcPriority::P2_Low:        return 120000; // 120s
    }
    return 30000;
}

const char *ControlChannel::priority_name(RpcPriority p) noexcept {
    switch (p) {
        case RpcPriority::P0_Emergency: return "P0_Emergency";
        case RpcPriority::P1_Normal:    return "P1_Normal";
        case RpcPriority::P2_Low:       return "P2_Low";
    }
    return "Unknown";
}

// ============================================================================
// 内部统计
// ============================================================================

void ControlChannel::record_call(RpcPriority p) {
    std::lock_guard<std::mutex> lk(stats_mu_);
    switch (p) {
        case RpcPriority::P0_Emergency: ++stats_.p0_calls; break;
        case RpcPriority::P1_Normal:    ++stats_.p1_calls; break;
        case RpcPriority::P2_Low:       ++stats_.p2_calls; break;
    }
}

void ControlChannel::record_failure() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.rpc_failures;
}

void ControlChannel::record_timeout() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.rpc_timeouts;
}

void ControlChannel::record_heartbeat() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.heartbeats;
}

void ControlChannel::record_drain_notify() {
    std::lock_guard<std::mutex> lk(stats_mu_);
    ++stats_.drain_notifies;
}

}  // namespace linoh::multimodal
