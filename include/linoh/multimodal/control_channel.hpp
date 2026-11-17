// control_channel.hpp — 控制信道隔离（P5-A-2）
//
// 借鉴 Sunshine 控制信道用 ENet reliable、数据信道用 raw UDP 的分离思想：
//   - 控制信道在 P5-A-1 已经通过独立 ALPN（ctrl/1）+ 独立连接（ctrl_conn）
//     与数据信道物理隔离，数据拥塞不会阻塞控制 RPC
//   - 本文件在 ctrl_conn 之上提供高层封装，进一步做 RPC 优先级分级：
//       P0 紧急  — drain / load-model / assign-team（短超时 + notify 即发）
//       P1 普通  — 状态查询 / 心跳上报（标准超时）
//       P2 低优  — 日志上报 / 统计上报（notify 异步，无响应等待）
//   - 心跳用独立 stream（每次调用新开 stream，避免与 RPC stream 池争用）
//   - drain 紧急通知用 notify()（无需响应，立即发送）
//
// 设计原则：
//   - 不重写底层 RPC（Connection::call/notify/respond 已完备）
//   - 仅做高层 API 封装 + 优先级映射 + 统计计数
//   - 优先级通过 MethodId 本身语义区分（Drain=0x22 永远是 P0）
//     同时在 ControlChannelStats 中按优先级统计调用次数
//   - 公共 API 不依赖 Connection 内部实现细节，便于后续 Connection 演进
//
// 与 P5-A-1 的关系：
//   - connect_multimodal() 返回 MultimodalConnectionPair（ctrl_conn + data_conn）
//   - 用户用 ctrl_conn 构造 ControlChannel，用 data_conn 跑数据流
//   - ControlChannel 不持有 data_conn，纯控制面

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "linoh/endpoint/connection.hpp"
#include "linoh/protocol/application_message.hpp"
#include "linoh/util/task_pool.hpp"

namespace linoh::multimodal {

/// RPC 优先级（P5-A-2）
enum class RpcPriority : std::uint8_t {
    P0_Emergency = 0,  // 紧急：drain / load-model / assign-team
    P1_Normal     = 1,  // 普通：状态查询 / 心跳
    P2_Low        = 2,  // 低优：日志 / 统计上报
};

/// RPC 响应封装
struct RpcResponse {
    bool ok{false};                       // true=Response，false=ErrorResponse
    std::vector<std::uint8_t> payload;    // 响应 payload
    std::string error_msg;                // 错误信息（ok=false 时有效）
    std::chrono::milliseconds elapsed{0}; // 调用耗时
};

/// 心跳 payload（简单结构，可扩展）
struct HeartbeatPayload {
    std::uint64_t node_id{0};        // 节点 ID
    std::uint64_t timestamp_ms{0};   // 发送时刻（epoch ms）
    std::uint8_t  state{0};          // 节点状态码（应用层定义）
    std::uint32_t active_streams{0}; // 当前活跃 stream 数
    std::uint32_t pending_rpcs{0};   // 待处理 RPC 数

    /// 序列化为字节流（小端序）
    std::vector<std::uint8_t> serialize() const;
    /// 从字节流反序列化，返回消费字节数，0=失败
    static std::size_t parse(std::span<const std::uint8_t> data, HeartbeatPayload &out);
};

/// 控制信道统计
struct ControlChannelStats {
    std::uint64_t p0_calls{0};      // P0 紧急 RPC 次数
    std::uint64_t p1_calls{0};      // P1 普通 RPC 次数
    std::uint64_t p2_calls{0};      // P2 低优 RPC 次数
    std::uint64_t heartbeats{0};    // 心跳发送次数
    std::uint64_t drain_notifies{0}; // drain 紧急通知次数
    std::uint64_t rpc_failures{0};  // RPC 失败次数（超时/异常）
    std::uint64_t rpc_timeouts{0};  // RPC 超时次数
};

/// 控制信道（独立连接，独立 stream 池）
///
/// 用法：
///   auto pair = endpoint.connect_multimodal(addr, ChannelType::LLM_HIDDEN).get();
///   ControlChannel ctrl(pair.ctrl_conn);
///   ctrl.start_heartbeat(10000, 30000);  // 10s 间隔，30s 超时
///   auto fut = ctrl.notify_drain("layer conflict");
///   auto resp = ctrl.call_rpc(MethodId::LoadModel, payload, RpcPriority::P0_Emergency).get();
class ControlChannel {
public:
    /// 构造 ControlChannel
    /// \param ctrl_conn 控制连接（必须已 Established）
    explicit ControlChannel(std::shared_ptr<endpoint::Connection> ctrl_conn);

    ~ControlChannel();

    // 不可拷贝（持有 stream 池和统计状态）
    ControlChannel(const ControlChannel &) = delete;
    ControlChannel &operator=(const ControlChannel &) = delete;
    // 可移动
    ControlChannel(ControlChannel &&) noexcept;
    ControlChannel &operator=(ControlChannel &&) noexcept;

    // ====================================================================
    // RPC API
    // ====================================================================

    /// 发送 RPC 请求（Request 消息，等待响应）
    /// \param method  方法枚举（如 LoadModel / Drain）
    /// \param payload 二进制 payload
    /// \param priority 优先级（影响超时默认值和统计）
    /// \param timeout  超时（默认按优先级：P0=5s, P1=30s, P2=120s）
    /// \return future，调用方 get() 等待 RpcResponse
    std::future<RpcResponse> call_rpc(
        protocol::MethodId method,
        std::span<const std::uint8_t> payload,
        RpcPriority priority = RpcPriority::P1_Normal,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(0));

    /// 发送通知（Notification 消息，无响应）
    /// 适用于 P2 日志/统计上报、P0 drain 紧急通知
    void send_notification(
        protocol::MethodId method,
        std::span<const std::uint8_t> payload,
        RpcPriority priority = RpcPriority::P2_Low);

    /// 心跳上报（独立 stream，不占用 RPC stream 池）
    void send_heartbeat(const HeartbeatPayload &payload);

    /// 紧急 drain 通知（P0 优先级，notify 立即发送，不等待响应）
    /// \param reason drain 原因（如 "layer conflict", "OOM", "manual"）
    /// \return future<void>，发送完成时置位（不等待对端响应）
    std::future<void> notify_drain(std::string_view reason);

    // ====================================================================
    // V3-A: 跨域控制面消息接口
    // ====================================================================
    //
    // 跨域节点摘要通过 ctrl/1 ALPN 通道传输（复用既有控制连接，不新增 ALPN/端口）。
    // 消息类型：MethodId::CrossDomainDigest（Notification）/ CrossDomainDigestReq（Request）。
    //
    // 职责分离：
    //   - ControlChannel 只负责字节流传输（序列化由上层 control_plane 处理）
    //   - 不依赖 control_plane.hpp 的 CrossDomainDigestPayload 结构（避免循环依赖）
    //
    // 上层用法（ControlPlane 的 send_digest_cb_ 回调内）：
    //   auto bytes = serialize_cross_domain_digest(payload);  // control_plane 层序列化
    //   ctrl.send_cross_domain_digest(bytes);                 // 字节流发送
    //
    // 接收侧（request_handler 中）：
    //   if (msg.method_id == MethodId::CrossDomainDigest) {
    //     auto payload = deserialize_cross_domain_digest(msg.payload);
    //     cp.on_digest_received(payload);
    //   }

    /// 发送跨域节点摘要（V3-A，Notification，P1 优先级）
    /// \param payload 已序列化的跨域摘要字节流（由 control_plane 层序列化）
    ///
    /// 说明：
    ///   - 使用 Notification 消息类型（无响应，request_id=0）
    ///   - 走 ctrl_conn 的 stream 池，与心跳/RPC 复用连接
    ///   - P1 优先级（普通），不抢占 P0 紧急 drain
    void send_cross_domain_digest(std::span<const std::uint8_t> payload);

    /// 请求跨域节点摘要（V3-A，Request，P1 优先级）
    /// \param self_domain 本域 ID（用于请求载荷）
    /// \return future，调用方 get() 等待 RpcResponse（payload 为对方响应的摘要字节流）
    ///
    /// 说明：
    ///   - 新加入的跨域代表主动拉取邻域摘要（加速收敛）
    ///   - 使用 Request 消息类型（有响应，request_id>0）
    ///   - 超时按 P1 默认值（30s）
    std::future<RpcResponse> request_cross_domain_digest(std::uint32_t self_domain);

    // ====================================================================
    // 心跳线程管理
    // ====================================================================

    /// 启动后台心跳线程
    /// \param interval_ms 心跳间隔（默认 10s）
    /// \param timeout_ms  超时阈值（默认 30s，连续 miss 触发 on_heartbeat_timeout）
    void start_heartbeat_thread(
        std::uint32_t interval_ms = 10000,
        std::uint32_t timeout_ms = 30000);

    /// 停止心跳线程
    void stop_heartbeat_thread();

    /// 心跳超时回调（连续 miss 触发，由上层决定是否 close ctrl_conn）
    std::function<void()> on_heartbeat_timeout;

    // ====================================================================
    // 状态查询
    // ====================================================================

    /// 获取统计
    ControlChannelStats stats() const;

    /// 当前 ctrl_conn 是否有效（非空且未关闭）
    bool is_valid() const noexcept;

    /// 底层 Connection（用于高级用法，如注册 request_handler）
    std::shared_ptr<endpoint::Connection> connection() const noexcept { return conn_; }

    /// 优先级默认超时（ms）
    static std::uint32_t default_timeout_ms(RpcPriority p) noexcept;

    /// 优先级名称（用于日志）
    static const char *priority_name(RpcPriority p) noexcept;

private:
    std::shared_ptr<endpoint::Connection> conn_;
    mutable std::mutex mu_;

    // 心跳线程
    std::thread heartbeat_thread_;
    std::atomic<bool> heartbeat_running_{false};
    std::atomic<bool> heartbeat_stop_{false};
    std::mutex heartbeat_mu_;
    std::condition_variable heartbeat_cv_;
    std::uint32_t hb_interval_ms_{10000};
    std::uint32_t hb_timeout_ms_{30000};
    // mp-L2 (v1.7.0.8): heartbeat miss 阈值可配置（原硬编码 3）。
    //   不同部署场景对心跳灵敏度需求不同：弱网环境需更高容忍（如 5），
    //   强网环境需更快发现死连接（如 2）。默认 3 兼容原行为。
    std::uint32_t hb_max_misses_{3};
    std::atomic<std::uint32_t> hb_miss_count_{0};
    std::chrono::steady_clock::time_point last_pong_time_;

    // 统计
    mutable std::mutex stats_mu_;
    ControlChannelStats stats_;

    // v1.7.0.7 C13: 异步 RPC 生命周期管理
    // call_rpc 用 std::async 启动异步任务并捕获 this，若 ControlChannel 析构时异步任务仍在运行，
    // 会访问已释放的成员（record_failure/record_timeout）导致 UAF。
    // 用 atomic 计数器 + cv 在析构时等待所有异步任务完成。
    std::atomic<std::uint32_t> pending_async_rpcs_{0};
    std::mutex async_rpc_mu_;
    std::condition_variable async_rpc_cv_;

    // mp-P10 (v1.7.0.9): 固定线程池替代 std::async，避免每次 RPC 创建/销毁线程
    //   声明在成员末尾 → 析构时最先析构 → stop+join worker 时其他成员仍有效
    //   默认 2 线程：控制面 RPC 并发量低（drain/load-model/状态查询），2 线程足够
    //   P0 紧急 notify_drain 也走池，FIFO 队列中 notify 帧很小，延迟可忽略
    std::unique_ptr<util::TaskPool> task_pool_;

    /// 心跳主循环
    void heartbeat_loop();

    /// 内部：按优先级统计调用
    void record_call(RpcPriority p);
    void record_failure();
    void record_timeout();
    void record_heartbeat();
    void record_drain_notify();
};

}  // namespace linoh::multimodal
