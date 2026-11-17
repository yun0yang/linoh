// connection_internal.hpp — P4-D-1 Connection 类内部拆分
//
// 将 Connection 的内部逻辑按职责分为 3 个组件：
//   - ConnectionState:  状态机 + TLS 1.3 + KeyUpdate
//   - StreamManager:    流管理 + RPC stream 池
//   - PacketBuilder:    包构建 + ACK + 加密
//
// 设计原则：
//   1. 公共 API 0 改动（Connection 的公共方法签名不变）
//   2. 内部类作为 Connection 的友元，直接访问其私有成员
//   3. 内部类不持有数据，仅提供分组的方法接口
//   4. 实现代码按职责拆分到独立 .cpp 文件，降低单文件复杂度
//
// 借鉴：iroh PR #4267/#4268 — RemoteStateActor 拆分
//
// 文件分布：
//   src/endpoint/connection.cpp           — 构造/析构 + handle_packet + 委托
//   src/endpoint/connection_state.cpp     — ConnectionState 实现
//   src/endpoint/stream_manager.cpp       — StreamManager 实现
//   src/endpoint/packet_builder.cpp       — PacketBuilder 实现
//   src/endpoint/session_ticket.cpp       — SessionTicket 方法
//   src/endpoint/stream.cpp               — Stream 类方法

#pragma once

#include "linoh/endpoint/connection.hpp"
#include "linoh/endpoint/state_machine.hpp"
#include "linoh/protocol/application_message.hpp"
#include "linoh/tls/key_schedule.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace linoh::endpoint::internal {

/// 连接状态管理组件（P4-D-1）
///
/// 负责：状态机转换、TLS 1.3 握手驱动、KeyUpdate、会话票据、空闲超时。
/// 不持有数据，直接操作 Connection 的私有成员（通过 friend）。
class ConnectionState {
public:
    explicit ConnectionState(Connection *conn) : conn_(conn) {}

    // === 状态机 ===
    ConnState state() const;
    bool is_closed() const;
    void transition_to(ConnState new_state);

    // === TLS 1.3 握手 ===
    bool tls13_enabled() const;
    bool tls13_active() const;
    util::ResultVoid start_handshake(double now_ms);
    bool check_handshake_timeout(double now_ms) const;
    std::vector<std::uint8_t> take_handshake_flight();
    void feed_handshake(std::span<const std::uint8_t> bytes);
    void on_handshake_completed();
    void finalize_tls13();
    void force_psk_established();

    // === 会话票据 + 0-RTT ===
    std::optional<SessionTicket> save_session() const;
    bool is_resumed() const;
    void queue_early_data(std::span<const std::uint8_t> data);

    // === KeyUpdate（P1-5）===
    std::uint8_t key_phase() const;
    bool trigger_key_update();
    bool should_rotate_keys() const;
    std::uint64_t packets_sent_since_rotate() const;
    bool rotate_keys();

    // === 关闭 ===
    void close(std::uint16_t error_code, std::string reason, Connection::CloseMode mode);
    void close_immediate(std::uint16_t error_code, std::string reason);
    void trigger_on_close_once();
    void on_close_impl();

    // === 空闲/保活 ===
    bool check_idle_timeout(double now_ms);
    bool needs_keepalive(double now_ms) const;
    void record_activity(double now_ms);
    void request_ping();

private:
    Connection *conn_;
};

/// 流管理组件（P4-D-1）
///
/// 负责：双向流创建/接受/关闭、RPC stream 池复用、request_id→stream 映射。
/// 不持有数据，直接操作 Connection 的私有成员（通过 friend）。
class StreamManager {
public:
    explicit StreamManager(Connection *conn) : conn_(conn) {}

    // === 流生命周期 ===
    std::shared_ptr<Stream> open_stream();
    util::Result<std::shared_ptr<Stream>> try_open_stream();
    util::Result<std::shared_ptr<Stream>> try_accept_stream();
    std::shared_ptr<Stream> accept_stream();
    void send_stream(std::uint64_t stream_id, std::span<const std::uint8_t> data);
    void finish_stream(std::uint64_t stream_id);
    std::uint64_t next_local_stream_id(bool bidi);

    // === 回调 ===
    void on_stream(std::function<void(std::shared_ptr<Stream>)> h);
    std::mutex &stream_mutex();

    // === RPC Stream 池（P1-1）===
    static constexpr std::size_t kRpcStreamPoolMax = Connection::kRpcStreamPoolMax;

    std::shared_ptr<Stream> acquire_rpc_stream();
    void release_rpc_stream(std::shared_ptr<Stream> stream);
    void register_request_stream(std::uint32_t request_id,
                                  std::shared_ptr<Stream> stream);
    std::shared_ptr<Stream> take_request_stream(std::uint32_t request_id);
    std::size_t rpc_stream_pool_size() const;
    std::size_t rpc_in_flight_count() const;

private:
    Connection *conn_;
};

/// 包构建组件（P4-D-1）
///
/// 负责：1-RTT/0-RTT 包构建、ACK 帧构建、AEAD 加密/解密、RTT 更新、丢包检测。
/// 不持有数据，直接操作 Connection 的私有成员（通过 friend）。
class PacketBuilder {
public:
    explicit PacketBuilder(Connection *conn) : conn_(conn) {}

    // === 包构建 ===
    std::size_t build_1rtt_packet(std::span<std::uint8_t> out);
    std::size_t build_0rtt_packet(std::span<std::uint8_t> out);
    std::vector<std::uint8_t> build_ack_data();

    // === AEAD 加密/解密 ===
    util::Bytes encrypt_packet(std::span<const std::uint8_t> header,
                                std::span<const std::uint8_t> payload);
    std::optional<util::Bytes> decrypt_packet(std::span<const std::uint8_t> header,
                                               std::span<const std::uint8_t> cipher);

    // === RTT + 丢包检测 ===
    void update_rtt(double rtt_ms);
    void handle_ack_frame(const protocol::AckFrame &ack);
    std::vector<std::uint64_t> pending_retransmits() const;

private:
    Connection *conn_;
};

} // namespace linoh::endpoint::internal
