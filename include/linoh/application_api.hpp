// application_api.hpp — linoh 语义封装层（P1-3 + P1-9）
//
// 在 Connection 的 call/notify/respond 之上提供具名方法，让上层（win-worker、
// node-agent）调用代码从"拼装字节流"简化为"调用具名方法"。
//
// 设计原则（借鉴 qt-easy-tier DaemonApi）：
//   1. 薄封装：每个方法 1-3 行，直接转发到 Connection
//   2. 持有 shared_ptr<Connection>：保证生命周期
//   3. 不引入新依赖：纯头文件
//
// 用法：
//   auto conn = std::make_shared<Connection>(cfg);
//   ApplicationApi api(conn);
//
//   // 同步 future 版本（P1-3）
//   auto fut = api.forward_pp(hidden_state);
//   auto result = fut.get();  // 阻塞等待响应
//
//   // 异步回调版本（P1-9）：高并发场景避免线程阻塞
//   api.forward_pp_async(hidden_state,
//       [](std::vector<std::uint8_t> resp) { /* 成功 */ },
//       [](std::string err) { /* 失败 */ });

#pragma once

#include <linoh/endpoint/connection.hpp>
#include <linoh/protocol/application_message.hpp>
#include <linoh/protocol/return_address.hpp>
#include <linoh/protocol/capabilities.hpp>  // V3.5 P5-A: CapabilitiesProbe/Ack

#include <cstdint>
#include <exception>
#include <future>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace linoh {

/// 语义封装层：把 ApplicationMessage 的 method_id 转成具名方法
class ApplicationApi {
public:
    explicit ApplicationApi(std::shared_ptr<endpoint::Connection> conn)
        : conn_(std::move(conn)) {}

    // ========== 推理相关（请求-响应） ==========

    /// 转发 hidden_state 给下一跳节点
    /// \param hidden_state hidden_state 字节流
    /// \param timeout_ms 超时（默认 120s，覆盖 PP 推理往返）
    /// \return future，get() 返回下一跳的 hidden_state 字节流
    std::future<std::vector<std::uint8_t>> forward_pp(
        std::span<const std::uint8_t> hidden_state,
        std::uint32_t timeout_ms = 120000) {
        return conn_->call(protocol::MethodId::ForwardPP, hidden_state, timeout_ms);
    }

    /// 便捷重载：从 vector 构造
    std::future<std::vector<std::uint8_t>> forward_pp(
        const std::vector<std::uint8_t> &hidden_state,
        std::uint32_t timeout_ms = 120000) {
        return conn_->call(protocol::MethodId::ForwardPP,
                           std::span<const std::uint8_t>(hidden_state.data(),
                                                          hidden_state.size()),
                           timeout_ms);
    }

    /// 取消推理
    std::future<std::vector<std::uint8_t>> cancel_inference(
        std::uint32_t inference_id,
        std::uint32_t timeout_ms = 10000) {
        std::vector<std::uint8_t> payload(4);
        payload[0] = static_cast<std::uint8_t>((inference_id >> 24) & 0xFF);
        payload[1] = static_cast<std::uint8_t>((inference_id >> 16) & 0xFF);
        payload[2] = static_cast<std::uint8_t>((inference_id >> 8) & 0xFF);
        payload[3] = static_cast<std::uint8_t>(inference_id & 0xFF);
        return conn_->call(protocol::MethodId::CancelInference,
                           std::span<const std::uint8_t>(payload.data(), payload.size()),
                           timeout_ms);
    }

    // ========== 节点管理（请求-响应） ==========

    /// WORKER → MASTER：加入集群
    /// \param node_info_json 节点信息 JSON（device_id/layer_range 等）
    std::future<std::vector<std::uint8_t>> join(
        const std::string &node_info_json,
        std::uint32_t timeout_ms = 30000) {
        std::vector<std::uint8_t> payload(node_info_json.begin(), node_info_json.end());
        return conn_->call(protocol::MethodId::Join,
                           std::span<const std::uint8_t>(payload.data(), payload.size()),
                           timeout_ms);
    }

    /// 加载模型分层
    /// \param model_id 模型标识（如 "Qwen3.5-122B-A10B-Q4_K_XL"）
    /// \param layer_start 起始层（含）
    /// \param layer_end 结束层（含）
    std::future<std::vector<std::uint8_t>> load_model(
        const std::string &model_id,
        std::uint32_t layer_start,
        std::uint32_t layer_end,
        std::uint32_t timeout_ms = 60000) {
        // payload = model_id + '\0' + layer_start(4B BE) + layer_end(4B BE)
        std::vector<std::uint8_t> payload;
        payload.insert(payload.end(), model_id.begin(), model_id.end());
        payload.push_back(0x00);  // null terminator
        payload.push_back(static_cast<std::uint8_t>((layer_start >> 24) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((layer_start >> 16) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((layer_start >> 8) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>(layer_start & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((layer_end >> 24) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((layer_end >> 16) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((layer_end >> 8) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>(layer_end & 0xFF));
        return conn_->call(protocol::MethodId::LoadModel,
                           std::span<const std::uint8_t>(payload.data(), payload.size()),
                           timeout_ms);
    }

    /// 驱逐节点（由 orchestrator 调用）
    std::future<std::vector<std::uint8_t>> drain(
        std::uint32_t timeout_ms = 10000) {
        std::vector<std::uint8_t> empty_payload;
        return conn_->call(protocol::MethodId::Drain,
                           std::span<const std::uint8_t>(empty_payload.data(), 0),
                           timeout_ms);
    }

    // ========== 通知（单向，无响应） ==========

    /// 状态变更通知
    /// \param state_str 新状态字符串（如 "ACTIVE"/"DRAINING"/"INACTIVE"）
    void notify_state_change(const std::string &state_str) {
        std::vector<std::uint8_t> payload(state_str.begin(), state_str.end());
        conn_->notify(protocol::MethodId::StateChange,
                      std::span<const std::uint8_t>(payload.data(), payload.size()));
    }

    /// 错误上报
    void notify_error(const std::string &error_msg) {
        std::vector<std::uint8_t> payload(error_msg.begin(), error_msg.end());
        conn_->notify(protocol::MethodId::ErrorReport,
                      std::span<const std::uint8_t>(payload.data(), payload.size()));
    }

    // ========== 心跳 ==========

    /// 启动应用层心跳（Established 后调用）
    void start_heartbeat(std::uint32_t interval_ms = 10000,
                         std::uint32_t timeout_ms = 30000) {
        conn_->start_heartbeat(interval_ms, timeout_ms);
    }

    /// 停止心跳
    void stop_heartbeat() {
        conn_->stop_heartbeat();
    }

    /// 注册心跳超时回调
    void on_heartbeat_timeout(std::function<void()> h) {
        conn_->on_heartbeat_timeout_ = std::move(h);
    }

    // ========== 底层访问（高级用法） ==========

    /// 获取底层 Connection
    std::shared_ptr<endpoint::Connection> connection() const { return conn_; }

    // ====================================================================
    // P1-9: 异步回调版本（2026-07-19 新增）
    //
    // 在 future 版本之上提供回调包装，避免高并发场景下调用方阻塞。
    // 设计：
    //   - 每个请求-响应方法都有对应的 *_async 版本
    //   - 返回 std::future<void>，调用方可选 .get() 等待回调完成
    //   - 回调在独立线程执行（std::async），不阻塞调用方
    //   - 异常被捕获，调用 on_error
    //
    // 用法：
    //   api.forward_pp_async(hidden_state,
    //       [](std::vector<std::uint8_t> resp) { /* 成功 */ },
    //       [](std::string err) { /* 失败 */ });
    // ====================================================================

    /// 异步版本：转发 hidden_state
    /// \param on_success 成功回调，参数为响应 payload
    /// \param on_error 失败回调，参数为错误信息
    /// \return future<void>，调用方可选 .get() 等待回调完成
    template<typename OnSuccess, typename OnError>
    std::future<void> forward_pp_async(
        std::span<const std::uint8_t> hidden_state,
        OnSuccess on_success,
        OnError on_error,
        std::uint32_t timeout_ms = 120000) {
        std::vector<std::uint8_t> payload(hidden_state.begin(), hidden_state.end());
        return std::async(std::launch::async,
            [conn = conn_, payload = std::move(payload),
             on_success = std::move(on_success),
             on_error = std::move(on_error),
             timeout_ms]() mutable {
                try {
                    auto fut = conn->call(protocol::MethodId::ForwardPP,
                        std::span<const std::uint8_t>(payload.data(), payload.size()),
                        timeout_ms);
                    auto result = fut.get();
                    on_success(std::move(result));
                } catch (const std::exception &e) {
                    on_error(std::string(e.what()));
                } catch (...) {
                    on_error(std::string("unknown exception"));
                }
            });
    }

    /// 异步版本：转发 hidden_state（vector 重载）
    template<typename OnSuccess, typename OnError>
    std::future<void> forward_pp_async(
        const std::vector<std::uint8_t> &hidden_state,
        OnSuccess on_success,
        OnError on_error,
        std::uint32_t timeout_ms = 120000) {
        return forward_pp_async(
            std::span<const std::uint8_t>(hidden_state.data(), hidden_state.size()),
            std::move(on_success), std::move(on_error), timeout_ms);
    }

    /// 异步版本：加入集群
    template<typename OnSuccess, typename OnError>
    std::future<void> join_async(
        const std::string &node_info_json,
        OnSuccess on_success,
        OnError on_error,
        std::uint32_t timeout_ms = 30000) {
        std::vector<std::uint8_t> payload(node_info_json.begin(), node_info_json.end());
        return std::async(std::launch::async,
            [conn = conn_, payload = std::move(payload),
             on_success = std::move(on_success),
             on_error = std::move(on_error),
             timeout_ms]() mutable {
                try {
                    auto fut = conn->call(protocol::MethodId::Join,
                        std::span<const std::uint8_t>(payload.data(), payload.size()),
                        timeout_ms);
                    auto result = fut.get();
                    on_success(std::move(result));
                } catch (const std::exception &e) {
                    on_error(std::string(e.what()));
                } catch (...) {
                    on_error(std::string("unknown exception"));
                }
            });
    }

    /// 异步版本：加载模型分层
    template<typename OnSuccess, typename OnError>
    std::future<void> load_model_async(
        const std::string &model_id,
        std::uint32_t layer_start,
        std::uint32_t layer_end,
        OnSuccess on_success,
        OnError on_error,
        std::uint32_t timeout_ms = 60000) {
        std::vector<std::uint8_t> payload;
        payload.insert(payload.end(), model_id.begin(), model_id.end());
        payload.push_back(0x00);
        payload.push_back(static_cast<std::uint8_t>((layer_start >> 24) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((layer_start >> 16) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((layer_start >> 8) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>(layer_start & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((layer_end >> 24) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((layer_end >> 16) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>((layer_end >> 8) & 0xFF));
        payload.push_back(static_cast<std::uint8_t>(layer_end & 0xFF));
        return std::async(std::launch::async,
            [conn = conn_, payload = std::move(payload),
             on_success = std::move(on_success),
             on_error = std::move(on_error),
             timeout_ms]() mutable {
                try {
                    auto fut = conn->call(protocol::MethodId::LoadModel,
                        std::span<const std::uint8_t>(payload.data(), payload.size()),
                        timeout_ms);
                    auto result = fut.get();
                    on_success(std::move(result));
                } catch (const std::exception &e) {
                    on_error(std::string(e.what()));
                } catch (...) {
                    on_error(std::string("unknown exception"));
                }
            });
    }

    /// 异步版本：驱逐节点
    template<typename OnSuccess, typename OnError>
    std::future<void> drain_async(
        OnSuccess on_success,
        OnError on_error,
        std::uint32_t timeout_ms = 10000) {
        return std::async(std::launch::async,
            [conn = conn_,
             on_success = std::move(on_success),
             on_error = std::move(on_error),
             timeout_ms]() mutable {
                try {
                    auto fut = conn->call(protocol::MethodId::Drain,
                        std::span<const std::uint8_t>(), timeout_ms);
                    auto result = fut.get();
                    on_success(std::move(result));
                } catch (const std::exception &e) {
                    on_error(std::string(e.what()));
                } catch (...) {
                    on_error(std::string("unknown exception"));
                }
            });
    }

    /// 异步版本：取消推理
    template<typename OnSuccess, typename OnError>
    std::future<void> cancel_inference_async(
        std::uint32_t inference_id,
        OnSuccess on_success,
        OnError on_error,
        std::uint32_t timeout_ms = 10000) {
        std::vector<std::uint8_t> payload(4);
        payload[0] = static_cast<std::uint8_t>((inference_id >> 24) & 0xFF);
        payload[1] = static_cast<std::uint8_t>((inference_id >> 16) & 0xFF);
        payload[2] = static_cast<std::uint8_t>((inference_id >> 8) & 0xFF);
        payload[3] = static_cast<std::uint8_t>(inference_id & 0xFF);
        return std::async(std::launch::async,
            [conn = conn_, payload = std::move(payload),
             on_success = std::move(on_success),
             on_error = std::move(on_error),
             timeout_ms]() mutable {
                try {
                    auto fut = conn->call(protocol::MethodId::CancelInference,
                        std::span<const std::uint8_t>(payload.data(), payload.size()),
                        timeout_ms);
                    auto result = fut.get();
                    on_success(std::move(result));
                } catch (const std::exception &e) {
                    on_error(std::string(e.what()));
                } catch (...) {
                    on_error(std::string("unknown exception"));
                }
            });
    }

    // ========== Direct Return Path 能力探测（v3.2.0）==========
    //
    // PP 链建立时 MASTER 探测各 worker 是否支持 Direct Return（RESULT 直连回传）。
    // 全链支持时 ForwardPP 携带 ReturnAddress，末节点推理完成后直连 MASTER 回传。
    // 任一节点不支持则降级为逐跳反向（向后兼容）。
    //
    // 这组方法通过现有 ctrl/1 连接走 RPC（conn_->call/respond），不需要 Endpoint。

    /// MASTER → WORKER：探测是否支持 Direct Return
    /// \param timeout_ms 超时（默认 5s，跨域可调大）
    /// \return future，get() 返回 ReturnAddrAckPayload 编码的字节流，
    ///         调用方用 ReturnAddrAckPayload::decode() 解析
    ///
    /// 用法（MASTER 端）：
    ///   auto fut = api.probe_direct_return();
    ///   auto resp = fut.get();  // 等待 WORKER 响应
    ///   protocol::ReturnAddrAckPayload ack;
    ///   if (protocol::ReturnAddrAckPayload::decode(resp, ack) && ack.supported) {
    ///       // worker 支持 Direct Return，记录 endpoint_id
    ///   }
    std::future<std::vector<std::uint8_t>> probe_direct_return(
        std::uint32_t timeout_ms = 5000) {
        std::vector<std::uint8_t> empty_payload;
        return conn_->call(protocol::MethodId::ReturnAddrProbe,
                           std::span<const std::uint8_t>(empty_payload.data(),
                                                          empty_payload.size()),
                           timeout_ms);
    }

    /// WORKER → MASTER：响应 Direct Return 能力探测
    /// \param req_id 对应 ReturnAddrProbe 的 request_id（由 request_handler 提供）
    /// \param supported 本节点是否支持 Direct Return
    /// \param worker_endpoint 本节点 EndpointId（Ed25519 公钥，supported=true 时有效）
    ///
    /// 用法（WORKER 端 request_handler 中）：
    ///   conn->set_request_handler([](const ApplicationMessage &msg) {
    ///       if (msg.method_id == MethodId::ReturnAddrProbe) {
    ///           api.respond_return_addr_probe(msg.request_id, true, local_endpoint_id);
    ///       }
    ///   });
    void respond_return_addr_probe(
        std::uint32_t req_id,
        bool supported,
        const std::array<std::uint8_t, 32> &worker_endpoint) {
        protocol::ReturnAddrAckPayload ack;
        ack.supported = supported;
        ack.version = 0x0100;
        ack.worker_endpoint = worker_endpoint;
        auto payload = ack.encode();
        conn_->respond(req_id, protocol::MethodId::ReturnAddrAck,
                       std::span<const std::uint8_t>(payload.data(),
                                                      payload.size()));
    }

    // ========================================================================
    // V3.5 P5-A: 统一节点能力探测（CapabilitiesProbe/Ack）
    //
    // 借鉴 probe_direct_return 模式，基于 Connection::call/respond。
    // 涵盖所有新 flag 能力（HasReturnAddress/DirectReturn/ResultShard/
    // HasSessionId/ZstdCompressed），替代分散探测。
    // 与 ReturnAddrProbe 并存：新节点优先用 CapabilitiesProbe。
    // ========================================================================

    /// MASTER → WORKER：发起统一能力探测
    ///
    /// \param timeout_ms 超时（默认 5000ms），超时后 future.get 抛异常
    /// \return future，get() 返回 CapabilitiesAckPayload 编码的字节流（39B），
    ///         调用方用 CapabilitiesAckPayload::decode() 解析
    ///
    /// 用法（MASTER 端）：
    ///   auto fut = api.probe_capabilities();
    ///   auto resp = fut.get();  // 等待 WORKER 响应（超时抛异常）
    ///   protocol::CapabilitiesAckPayload ack;
    ///   if (protocol::CapabilitiesAckPayload::decode(resp, ack) && ack.supported) {
    ///       auto caps = ack.to_node_capabilities();
    ///       // caps.supports_session_id() / caps.supports_zstd_compression() ...
    ///   } else {
    ///       // 旧节点或不支持，降级 mask=0（所有新 flag 不使用）
    ///   }
    std::future<std::vector<std::uint8_t>> probe_capabilities(
        std::uint32_t timeout_ms = 5000) {
        std::vector<std::uint8_t> empty_payload;
        return conn_->call(protocol::MethodId::CapabilitiesProbe,
                           std::span<const std::uint8_t>(empty_payload.data(),
                                                          empty_payload.size()),
                           timeout_ms);
    }

    /// WORKER → MASTER：响应统一能力探测
    ///
    /// \param req_id 对应 CapabilitiesProbe 的 request_id（由 request_handler 提供）
    /// \param supported 本节点是否支持能力探测（false=旧节点降级）
    /// \param capabilities_mask 能力位掩码（kCap* 组合）
    /// \param peer_endpoint 本节点 EndpointId（Ed25519 公钥，supported=true 时有效）
    ///
    /// 用法（WORKER 端 request_handler 中）：
    ///   conn->set_request_handler([](const ApplicationMessage &msg) {
    ///       if (msg.method_id == MethodId::CapabilitiesProbe) {
    ///           uint32_t mask = kCapHasSessionId | kCapZstdCompressed;
    ///           api.respond_capabilities_probe(msg.request_id, true, mask, local_ep);
    ///       }
    ///   });
    void respond_capabilities_probe(
        std::uint32_t req_id,
        bool supported,
        std::uint32_t capabilities_mask,
        const std::array<std::uint8_t, 32> &peer_endpoint) {
        protocol::CapabilitiesAckPayload ack;
        ack.supported = supported;
        ack.version = protocol::CapabilitiesAckPayload::kCurrentVersion;
        ack.capabilities_mask = capabilities_mask;
        ack.peer_endpoint = peer_endpoint;
        auto payload = ack.encode();
        conn_->respond(req_id, protocol::MethodId::CapabilitiesAck,
                       std::span<const std::uint8_t>(payload.data(),
                                                      payload.size()));
    }

private:
    std::shared_ptr<endpoint::Connection> conn_;
};

} // namespace linoh
