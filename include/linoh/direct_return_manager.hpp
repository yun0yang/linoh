// direct_return_manager.hpp — Direct Return Path 管理器（v3.2.0）
//
// PP 链末节点 RESULT 直连回传 MASTER 的核心管理类。
// 绕过逐跳反向中继，末节点推理完成后直接通过 P2P 直连 STREAM 将 RESULT 回传 MASTER。
//
// 设计要点：
//   - 持有 Endpoint*（非拥有，由调用方管理生命周期），用于 dial + accept handler
//   - ReturnStreamPool：master_endpoint → shared_ptr<Connection>，同一 MASTER 多次推理复用连接
//   - ReturnSlot 表：stream_token → promise<result>，MASTER 端路由匹配
//   - req_id ↔ stream_token 双向映射：支持逐跳反向结果按 req_id 注入竞速
//   - stream_token = fnv1a_64(req_id || timestamp_ms) 取低 32 位
//   - return stream 走 pp-llm/1 ALPN（与 hidden_state 共用，不新增端口/ALPN）
//   - 自动降级（P1）：直连 route_result_ 与逐跳反向 inject_hop_by_hop_result 竞速同一 promise，
//     任一先到达取走 ReturnSlot 即胜出，另一路径自然丢弃；dial 失败/超时由上层注入逐跳反向
//
// 生命周期：
//   MASTER 端：
//     1. 构造 DirectReturnManager(endpoint)
//     2. register_inbound_handler() — 监听 pp-llm/1 的入站 stream
//     3. 每次 PP 推理：register_return_slot(req_id) → stream_token
//     4. ForwardPP 携带 ReturnAddress(master_endpoint, stream_token)
//     5. await_return_result(stream_token, timeout) → future<result>
//
//   末节点端：
//     1. 构造 DirectReturnManager(endpoint)
//     2. 收到 ForwardPP[HasReturnAddress] 后提取 ReturnAddress
//     3. open_return_stream(master_endpoint, stream_token) → stream
//     4. 推理完成后 send_result_direct(stream, stream_token, result, combined)
//     5. 失败时降级为逐跳反向（调用方处理）

#pragma once

#include <linoh/endpoint/endpoint.hpp>
#include <linoh/endpoint/connection.hpp>
#include <linoh/protocol/application_message.hpp>
#include <linoh/protocol/return_address.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace linoh {

/// Direct Return Path 管理器（v3.2.0）
///
/// 管理 PP 链末节点到 MASTER 的直连回传通道。
/// 线程安全：所有公开方法可并发调用（内部 mutex 保护）。
class DirectReturnManager {
public:
    /// \param endpoint 本节点 Endpoint（非拥有，调用方保证生命周期长于本对象）
    explicit DirectReturnManager(endpoint::Endpoint *endpoint);

    ~DirectReturnManager();

    // 不可拷贝
    DirectReturnManager(const DirectReturnManager &) = delete;
    DirectReturnManager &operator=(const DirectReturnManager &) = delete;

    // ========================================================================
    // MASTER 端 API
    // ========================================================================

    /// 注册 pp-llm/1 入站 stream handler，监听末节点直连回传的 ResultPP
    ///
    /// 流程：
    ///   1. 在 Endpoint 上注册 accept handler（覆盖式，故需配合 set_fallback_accept_handler）
    ///   2. 入站连接 alpn=="pp-llm/1" 时接管：accept_stream 后读取 ApplicationMessage
    ///   3. 若为 ResultPP[DirectReturn=1]，解析 payload 头部 stream_token，路由到 ReturnSlot
    ///   4. alpn!="pp-llm/1" 时调用 fallback_accept_handler_（若已设置），否则忽略
    ///
    /// \note 必须在 Endpoint 开始接受连接前调用
    /// \note 若 MASTER 端已有其他 ALPN 的 accept handler，应先调用 set_fallback_accept_handler
    void register_inbound_handler();

    /// 设置非 pp-llm/1 ALPN 的入站连接回退处理器（链式 accept handler）
    ///
    /// register_inbound_handler() 会覆盖 Endpoint 的 accept handler，其他 ALPN 的
    /// 入站连接会进入 fallback。调用方应将原有的 accept handler 传入此处，以保留
    /// 对 ctrl/1、pp-hidden/1 等其他 ALPN 的处理能力。
    ///
    /// \note 应在 register_inbound_handler() 之前调用
    void set_fallback_accept_handler(std::function<void(endpoint::Incoming)> h) {
        fallback_accept_handler_ = std::move(h);
    }

    /// 注册一个 return slot，预分配 stream_token
    ///
    /// \param req_id PP 推理请求 ID
    /// \return stream_token（写入 ForwardPP.ReturnAddress，末节点据此回传）
    ///
    /// stream_token = fnv1a_64(req_id || timestamp_ms) 取低 32 位
    std::uint32_t register_return_slot(std::uint64_t req_id);

    /// 等待直连回传的 RESULT
    ///
    /// \param stream_token register_return_slot() 返回的 token
    /// \param timeout 超时（超时后调用方应降级等待逐跳反向 RESULT）
    /// \return future，get() 返回结果字节流（仅 result payload，不含 stream_token 头部）
    ///
    /// \note 调用方应同时监听直连和逐跳反向两条路径，任一到达即取消另一
    std::future<std::vector<std::uint8_t>> await_return_result(
        std::uint32_t stream_token,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(30000));

    /// 取消并清理 return slot（推理取消或逐跳反向先到达时调用）
    void cancel_return_slot(std::uint32_t stream_token);

    /// 注入逐跳反向 ResultPP（P1 自动降级核心入口）
    ///
    /// 当 MASTER 通过 PP 反向链路（ApplicationApi::forward_pp 的 future）收到逐跳反向
    /// ResultPP 时，调用本方法将结果注入 DirectReturnManager 的竞速 promise。
    ///
    /// 竞速语义：
    ///   - 若直连 return stream 尚未到达（ReturnSlot 仍在），本方法取走 slot 并 set_value，
    ///     逐跳反向胜出（自动降级）；返回 true
    ///   - 若直连已先到达（slot 已被 route_result_ 取走），本方法找不到 slot，返回 false
    ///     （直连胜出，逐跳反向结果丢弃）
    ///
    /// \param req_id PP 推理请求 ID（与 register_return_slot 时一致）
    /// \param result_payload 逐跳反向 ResultPP 的 result 字节流
    /// \return true=逐跳反向胜出（注入成功），false=直连已胜出或 slot 不存在
    ///
    /// \note 线程安全，可在任意线程调用（通常在 forward_pp future 完成回调中）
    /// \note 上层典型用法：
    ///   \code
    ///   auto token = mgr.register_return_slot(req_id);
    ///   auto fut = mgr.await_return_result(token, 30s);
    ///   // 异步等待逐跳反向（降级路径）
    ///   std::thread([&]() {
    ///       auto resp = api.forward_pp(hidden).get();  // 逐跳反向
    ///       mgr.inject_hop_by_hop_result(req_id, resp);  // 注入竞速
    ///   }).detach();
    ///   auto result = fut.get();  // 任一路径到达即返回
    ///   \endcode
    bool inject_hop_by_hop_result(std::uint64_t req_id,
                                  std::span<const std::uint8_t> result_payload);

    /// 获取本节点 EndpointId（Ed25519 公钥，用于构造 ReturnAddress）
    std::array<std::uint8_t, 32> local_endpoint_id() const;

    // ========================================================================
    // 末节点端 API
    // ========================================================================

    /// 打开到 MASTER 的直连 return STREAM
    ///
    /// 流程：
    ///   1. 查 ReturnStreamPool 是否已有到 master_endpoint 的 pp-llm/1 连接
    ///   2. 无则 dial master_endpoint（ALPN=pp-llm/1，复用 NAT 穿透 + RelayPool）
    ///   3. 在连接上 open_stream(Bidirectional)
    ///   4. 返回 stream 供 send_result_direct() 使用
    ///
    /// \param master_endpoint MASTER 的 Ed25519 公钥（从 ForwardPP.ReturnAddress 提取）
    /// \param stream_token MASTER 预分配的 return stream 标识
    /// \param timeout dial 超时（默认 5s，超时返回 nullptr 触发降级）
    /// \return 成功返回 stream 指针，失败返回 nullptr（dial 失败 / 超时）
    std::shared_ptr<endpoint::Stream> open_return_stream(
        const std::array<std::uint8_t, 32> &master_endpoint,
        std::uint32_t stream_token,
        std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

    /// 通过直连 STREAM 发送 ResultPP（DirectReturn=1）
    ///
    /// \param return_stream open_return_stream() 返回的 stream
    /// \param stream_token MASTER 预分配的标识（写入 payload 头部供 MASTER 路由）
    /// \param result_payload 推理结果字节流
    /// \param combined 是否为末节点最终结果（对应原 combined=true 语义）
    /// \return true=发送成功，false=stream 已关闭
    ///
    /// payload 格式：[stream_token(4B, LE)][result_payload]
    /// 消息封装：ApplicationMessage(ResultPP, flags=DirectReturn)
    bool send_result_direct(
        std::shared_ptr<endpoint::Stream> return_stream,
        std::uint32_t stream_token,
        std::span<const std::uint8_t> result_payload,
        bool combined);

    /// P3-1: 通过直连 STREAM 发送分片大 ResultPP（DirectReturn|ResultShard）
    ///
    /// 将大 result_payload 按 shard_size 切分为多个独立 ApplicationMessage 发送，
    /// 每个 shard 的 payload 格式：
    ///   [stream_token(4B,LE)][shard_idx(2B,LE)][total_shards(2B,LE)][result_chunk]
    /// 每个 shard < MTU，独立完整可 parse，MASTER 端按 stream_token 累积重组。
    ///
    /// \param return_stream open_return_stream() 返回的 stream
    /// \param stream_token MASTER 预分配的标识
    /// \param result_payload 大结果字节流
    /// \param combined 是否为末节点最终结果
    /// \param shard_size 每 shard 最大 payload 字节（建议 1024，确保 < MTU）
    /// \return true=全部发送成功，false=stream 已关闭或发送失败
    bool send_result_direct_sharded(
        std::shared_ptr<endpoint::Stream> return_stream,
        std::uint32_t stream_token,
        std::span<const std::uint8_t> result_payload,
        bool combined,
        std::size_t shard_size = 1024);

    /// 释放 return stream 连接池中的空闲连接（空闲 > 60s 的连接 close）
    /// \note 由调用方定期调用（如每 30s），或由析构函数自动清理
    void cleanup_idle_connections();

    // ========================================================================
    // 统计信息
    // ========================================================================

    struct Stats {
        std::uint64_t return_streams_opened{0};    // open_return_stream 成功次数
        std::uint64_t return_streams_failed{0};    // open_return_stream 失败次数
        std::uint64_t results_sent_direct{0};      // send_result_direct 成功次数
        std::uint64_t results_received{0};         // MASTER 端收到 RESULT 次数（直连+逐跳竞速合计）
        std::uint64_t direct_return_won{0};        // P1: 直连 return stream 竞优胜出次数
        std::uint64_t hop_by_hop_won{0};           // P1: 逐跳反向竞优胜出次数（自动降级成功）
        std::uint64_t fallback_invoked{0};         // P1: inject_hop_by_hop_result 被调用次数
        std::uint64_t return_slots_registered{0};  // register_return_slot 次数
        std::uint64_t return_slots_cancelled{0};   // cancel_return_slot 次数
        std::uint64_t pool_hits{0};                // 连接池命中次数
        std::uint64_t pool_misses{0};              // 连接池未命中（需 dial）次数
        std::uint64_t idle_connections_cleaned{0}; // 空闲连接清理次数
    };

    Stats stats() const;

    /// P2-1: 统计 JSON 序列化（用于 orchestrator 监控上报）
    /// \return JSON 字符串，包含所有 Stats 字段
    /// \note 线程安全
    std::string stats_json() const;

    /// \internal stream_token 生成（暴露供单元测试与诊断使用）
    /// 规则：fnv1a_64(req_id(8B,LE) || timestamp_ms(8B,LE)) 取低 32 位
    static std::uint32_t compute_stream_token(std::uint64_t req_id,
                                              std::uint64_t timestamp_ms);

private:
    endpoint::Endpoint *endpoint_;

    // === ReturnStreamPool：master_endpoint → Connection 条目 ===
    struct PoolEntry {
        std::shared_ptr<endpoint::Connection> conn;
        std::chrono::steady_clock::time_point last_used;
    };
    std::mutex pool_mu_;
    std::unordered_map<base::EndpointId, PoolEntry> connection_pool_;
    using PoolKey = base::EndpointId;

    /// 从连接池获取或建立到 master_endpoint 的 pp-llm/1 连接
    /// \return 连接指针，失败返回 nullptr
    std::shared_ptr<endpoint::Connection> get_or_dial_connection_(
        const std::array<std::uint8_t, 32> &master_endpoint,
        std::chrono::milliseconds timeout);

    // === ReturnSlot 表（MASTER 端）===
    struct ReturnSlot {
        std::uint64_t req_id{0};
        std::uint32_t token{0};  // P1: 反向查 req_id_to_token_ 用，便于清理
        std::promise<std::vector<std::uint8_t>> promise;
        std::chrono::steady_clock::time_point created_at;
        // P3-1: 分片重组缓冲
        std::uint16_t total_shards{0};       // 期望 shard 总数（首个 shard 到达时确定）
        std::uint16_t received_shards{0};    // 已收到 shard 数
        std::vector<std::vector<std::uint8_t>> shard_chunks;  // 按 shard_idx 存放
    };
    std::mutex slots_mu_;
    std::unordered_map<std::uint32_t, std::unique_ptr<ReturnSlot>> return_slots_;
    /// P1: req_id → stream_token 反向映射，供 inject_hop_by_hop_result 按 req_id 定位 slot
    std::unordered_map<std::uint64_t, std::uint32_t> req_id_to_token_;

    /// P1: 原子取走 ReturnSlot（直连/逐跳竞速的唯一入口）
    /// 从 return_slots_ move 出 slot 并 erase，同步清理 req_id_to_token_。
    /// \return slot 指针（已被另一路径取走时返回 nullptr）
    std::unique_ptr<ReturnSlot> take_slot_(std::uint32_t stream_token);

    /// 入站 stream 处理回调（MASTER 端）
    void handle_inbound_stream_(std::shared_ptr<endpoint::Stream> stream,
                                 std::shared_ptr<endpoint::Connection> conn);

    /// 解析 ResultPP[DirectReturn] 并路由到 ReturnSlot（直连路径）
    /// \param stream_token payload 头部的 token
    /// \param result_payload 结果字节流（已剥离 stream_token 头部）
    /// \param is_shard 是否为分片结果（P3-1）
    /// \param shard_idx 分片序号（is_shard=true 时有效）
    /// \param total_shards 分片总数（is_shard=true 时有效）
    void route_result_(std::uint32_t stream_token,
                       std::span<const std::uint8_t> result_payload,
                       bool is_shard = false,
                       std::uint16_t shard_idx = 0,
                       std::uint16_t total_shards = 0);

    /// 非 pp-llm/1 ALPN 的入站连接回退处理器
    std::function<void(endpoint::Incoming)> fallback_accept_handler_;

    // === 统计 ===
    mutable std::mutex stats_mu_;
    Stats stats_;

    /// fnv1a_64 哈希（stream_token 生成，转发到 public compute_stream_token）
    static std::uint32_t compute_stream_token_(std::uint64_t req_id,
                                                std::uint64_t timestamp_ms) {
        return compute_stream_token(req_id, timestamp_ms);
    }

    /// 空闲连接超时阈值
    static constexpr std::chrono::seconds kIdleTimeout{60};
};

}  // namespace linoh
