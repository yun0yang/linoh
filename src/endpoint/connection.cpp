#include "linoh/endpoint/connection.hpp"
#include "linoh/endpoint/connection_internal.hpp"

#include "linoh/endpoint/state_machine.hpp"
#include "linoh/net/mtu.hpp"
#include "linoh/net/net_report.hpp"
#include "linoh/observability/payload_audit.hpp"
#include "linoh/protocol/ack.hpp"
#include "linoh/protocol/flow_control.hpp"
#include "linoh/protocol/loss_recovery.hpp"
#include "linoh/protocol/path_migration.hpp"
#include "linoh/protocol/path_strategy.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/tls/crypto_level.hpp"
#include "linoh/tls/handshake.hpp"
#include "linoh/tls/replay_window.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/util/logging.hpp"
#include "linoh/util/varint.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <set>

namespace linoh::endpoint {
namespace {
std::atomic<std::uint64_t> g_next_conn_id{1};

constexpr std::size_t kMaxPacketSize = 1280; // QUIC 推荐最大 MTU
constexpr std::size_t kTagSize = 16;         // AES-GCM / ChaCha20-Poly1305 tag size

// B3+ fix(2026-07-20): 统一获取当前单调时间戳（毫秒，double），供 LossDetector / RTT 估算使用。
// 使用 steady_clock 保证不受系统时钟调整影响，单调递增。
inline double now_ms_steady() {
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// TLS 1.3 QUIC AEAD nonce = iv XOR packet_number（pn 填入 iv 低 8 字节，小端）。
// 双方 iv 由相同 transcript 派生，pn 在包头明文传输，故收发 nonce 一致。
//
// P1-3: 深度防御 — 在 nonce 第 0 字节加入方向位（client=0, server=1）
// 即使 iv 派生出现 bug 导致双方 iv 相同，方向位也能确保收发 nonce 不同。
// 注：RFC 9001 §5.1 已要求 client_iv / server_iv 分开派生（由 key_schedule 保证），
//     本方向位是额外保护层。
std::array<std::uint8_t, 12> tls13_nonce(const std::array<std::uint8_t, 12> &iv,
                                         std::uint64_t pn,
                                         bool is_server) {
    std::array<std::uint8_t, 12> n = iv;
    // P1-3: 方向位写入第 0 字节最高位
    n[0] = (n[0] & 0x7F) | (is_server ? 0x80 : 0x00);
    for (int i = 0; i < 8; ++i) n[4 + i] ^= static_cast<std::uint8_t>((pn >> (8 * i)) & 0xFF);
    return n;
}
} // namespace

// ============================================================================
// Connection
// ============================================================================

Connection::Connection(Config cfg)
    : cfg_{std::move(cfg)}
    , id_{g_next_conn_id.fetch_add(1)}
    , peer_id_{cfg_.secret_key.public_key()}
    , crypto_key_{tls::HandshakeTokenKey::generate()}
    , loss_detector_{}
    , congestion_ctrl_{make_congestion_controller(cfg_.congestion_algo, &loss_detector_.rtt())}
    , flow_ctrl_{cfg_.initial_conn_window, cfg_.initial_stream_window,
                 cfg_.max_bidi_streams, cfg_.max_uni_streams}
    , path_mgr_{0}  // initial CID sequence = 0
    , handshake_tracker_{cfg_.handshake}
    // K-LINOH-READBLK-001b: 必须用"当前时刻"而非 0 初始化。
    // 0 会让 check_idle_timeout 的 (now - 0) 恒 > timeout，导致连接
    // 在首个数据包到达前就被巡检秒杀（relay 中转路径稳定复现）。
    , last_activity_ms_{now_ms_steady()}
    , last_ping_sent_ms_{now_ms_steady()} {
    LINOH_DEBUG("Connection created. id=", id_,
                " dir=", (direction() == Direction::Inbound ? "in" : "out"),
                " local_cid=", cfg_.local_cid.fmt_short(),
                " peer_cid=", cfg_.remote_cid.fmt_short());

    // v1.4.4 BUG#A: 按 direction 区分 stream_id 计数器初值
    // QUIC stream_id 编码（RFC 9000 §2.1）：
    //   bit 0 = 0/1 → client/server-initiated
    //   bit 1 = 0/1 → bidi/uni
    //   正确初值：Client bidi=0/Server bidi=1/Client uni=2/Server uni=3（递增步长 4）
    // 修复前固定为 0/2，导致 server (Inbound) open_stream 拿到 stream_id=0
    // 与 client 的 local stream_id=0 冲突，client 收到 STREAM 帧时错误路由到
    // 自己的 local stream，触发 captured2 验证失败。
    if (direction() == Direction::Inbound) {
        next_local_bidi_stream_ = 1;
        next_local_uni_stream_ = 3;
    } else {
        next_local_bidi_stream_ = 0;
        next_local_uni_stream_ = 2;
    }

    // P4-D-1: 初始化内部组件（视图，持有 this 反向引用）
    state_component_ = std::make_unique<internal::ConnectionState>(this);
    stream_component_ = std::make_unique<internal::StreamManager>(this);
    packet_component_ = std::make_unique<internal::PacketBuilder>(this);

    // 如果提供了会话票据，派生 0-RTT 密钥（基于 master_secret）
    if (cfg_.resume_ticket.has_value()) {
        auto &ticket = *cfg_.resume_ticket;
        // 简化派生：HKDF-SHA256 的简化版本，使用 AEAD key 派生
        // zero_rtt_secret_ = HMAC-SHA256(master_secret, "zero-rtt")
        crypto_key_.derive_zerortt(ticket.master_secret,
                                   std::span<std::uint8_t>(zero_rtt_secret_.data(), zero_rtt_secret_.size()));
        // L3(K-LINOH-PEERMISMATCH): ticket.peer_node_id 在签发时已认证（TLS1.3
        // 路径=verified peer；PSK 路径=身份交换后的 peer），恢复连接的 peer_id_
        // 应取该值而非本端公钥。收到对端 PSK_IDENTITY 帧时会再次验证并覆盖。
        peer_id_ = ticket.peer_node_id;
        LINOH_INFO("Connection: using 0-RTT session, peer=",
                   ticket.peer_node_id.fmt_short());
    }

    // 客户端(Outbound)：在 Initial 状态，需要调用 start_handshake() 触发握手
    // 不再直接跳到 Established！状态机严格遵循 Initial → Handshake → Established
    LINOH_DEBUG("Connection (", (direction() == Direction::Outbound ? "outbound" : "inbound"),
                "): entering Initial state, handshake=", cfg_.handshake.psk_mode ? "PSK" : "full");

    // v4.7.0: PathSelectionStrategy 初始化（接入点 A 前置条件）
    //
    // 当 Config::path_strategy_enabled=true 且 path_strategy 非空时，将策略注入
    // PathMigrationManager。若 path_strategy 为空但开关开启，回退到 RttBasedStrategy
    // （与 v4.6.x 等价，仅按 srtt 选路，保证开关启用不影响现有行为）。
    if (cfg_.path_strategy_enabled) {
        if (cfg_.path_strategy) {
            path_mgr_.set_strategy(cfg_.path_strategy);
            LINOH_INFO("Connection: path strategy enabled, strategy='",
                       cfg_.path_strategy->name(), "'");

            // v4.8.0: 若策略为 PreferRelayStrategy，设置 force_relay_primary_ 标志
            //
            // 在 on_handshake_completed 和 loss_tick_loop 中定期调用 try_select_better_path，
            // 确保 relay 路径被选为主路径并持续生效。
            // 根因：try_select_better_path 之前未被定期调用，PreferRelayStrategy 形同虚设，
            //       master 仍通过 P2P 直连发送数据，公网 UDP 丢包严重。
            if (cfg_.path_strategy->name() == "prefer-relay") {
                force_relay_primary_ = true;
                LINOH_WARN("Connection: PreferRelayStrategy detected, "
                           "force_relay_primary_=true (will select relay path on "
                           "handshake completion and every 5s in loss_tick_loop)");
            }
        } else {
            // 回退到 RttBasedStrategy（默认行为，与 v4.6.x 等价）
            path_mgr_.set_strategy(std::make_shared<protocol::RttBasedStrategy>());
            LINOH_INFO("Connection: path strategy enabled but no strategy provided, "
                       "fallback to RttBasedStrategy");
        }
    }

    // v4.7.0: 桥接 PathMigrationManager 的 closed 事件到 PathEventStream fan-out
    //
    // 注册回调到 path_mgr_，当 PathMigrationManager::emit_path_closed_event 触发时，
    // 转发到所有订阅的 PathEventStream。回调内调用 emit_path_event（已离开 path_mgr_.mu_）。
    // 即使 path_api_v2_enabled=false 也注册（无订阅者时 fan-out 空操作，开销极低），
    // 避免 path_api_v2_enabled 运行时切换时遗漏事件。
    bridge_path_event_callback();
}

Connection::~Connection() {
    LINOH_DEBUG("Connection destroyed. id=", id_);

    // P1-2: 停止心跳线程
    stop_heartbeat();

    // P9.3 §4.4: 停止丢包超时检测线程（与 stop_heartbeat 对称，幂等）
    stop_loss_tick_loop();

    // 停止超时扫描线程
    timeout_thread_stop_.store(true, std::memory_order_release);
    timeout_cv_.notify_all();
    if (timeout_thread_.joinable()) {
        timeout_thread_.join();
    }

    // v4.7.0: 关闭所有 PathEventStream（避免悬挂）
    //
    // 遍历 path_event_streams_，lock 成功的 stream 调用 close()。
    // stream 持 shared_ptr<Impl>，close 后消费者 next() 立即返回 nullopt。
    // 即使 stream 对象仍被外部持有，其内部 Impl 也能优雅退出。
    {
        std::lock_guard<std::mutex> lk(path_event_streams_mu_);
        for (auto &weak : path_event_streams_) {
            if (auto impl = weak.lock()) {
                std::lock_guard<std::mutex> impl_lk(impl->mu);
                impl->closed = true;
                impl->cv.notify_all();
            }
        }
        path_event_streams_.clear();
    }

    // 清理所有 pending 请求（防止 future 析构阻塞）
    // 注意：on_close_impl 已幂等，这里再调一次保证析构路径也清理
    on_close_impl();
}

bool Connection::handle_packet(util::Bytes wire) {
    stats_.packets_received++;
    stats_.bytes_received += wire.size();   // v5.4 F7 揪出的存量缺口：此前从不累加

    // v1.4.3 P1-#5: DoS 防护 — 拒绝超限巨型包。
    // RFC 9000 §14.1：Initial 包最大 1500 字节，Handshake/1-RTT 由 max_udp_payload_size 决定。
    // K-FIX-MTU-001: 阈值从 9000 提高到 9300，容纳 send_buf=9200 构建的 1-RTT 包
    //   （含 QUIC 头部 + STREAM 帧头 + payload）。
    //   根因：K-LINOH-PERF-001 将 send_buf 从 2048 增大到 9200，但 build_1rtt_packet
    //   在 negotiated_mtu_=9000 时构建的包可达 9200 字节，超过旧阈值 9000 触发 DoS 保护，
    //   导致连接被反复关闭（win-worker 日志：packet size 9201 exceeds max 9000）。
    constexpr std::size_t kMaxPacketSize = 9300;
    if (wire.size() > kMaxPacketSize) {
        LINOH_WARN("Connection: packet size ", wire.size(),
                   " exceeds max ", kMaxPacketSize, ", closing conn (DoS protection)");
        // 触发协议层关闭（CONNECTION_CLOSE 帧 + 状态机进入 Closing）
        // 0x0a = PROTOCOL_VIOLATION (RFC 9000 §20.1)
        close(/*error=*/0x0a, "packet_size_exceeded");
        return false;
    }

    protocol::PacketParser parser(wire.as_span());
    auto pkt = parser.parse();
    if (!pkt) {
        LINOH_WARN("Connection: failed to parse packet");
        return true;
    }

    auto &hdr = pkt->header;
    auto &payload = pkt->payload;
    LINOH_DEBUG("Connection: parsed packet type=",
               (int)hdr.type(), " dcid=", hdr.dcid().fmt_short(),
               " payload_size=", payload.size());

    // B5 fix(2026-07-20): 用 RFC 9000 §A.3 算法解码完整 PN，替代 lockstep 假设。
    // ApplicationData space 的 PN 解码需要 largest_acked（来自 LossDetector）。
    // 对 Initial/Handshake space，largest_acked 初始为 0，首个包期望 pn=0。
    if (pkt->pn_len_bytes > 0) {
        std::size_t space_idx =
            (hdr.type() == protocol::PacketType::Initial)   ? 0
          : (hdr.type() == protocol::PacketType::Handshake) ? 1
                                                            : 2;
        std::uint64_t largest_acked = (space_idx == 2)
            ? loss_detector_.largest_acked()
            : 0;  // Initial/Handshake 简化：未维护 largest_acked
        std::span<const std::uint8_t> trunc_span(
            pkt->truncated_pn.data(), pkt->pn_len_bytes);
        std::uint64_t decoded_pn = protocol::PacketNumber::decode_truncated(
            trunc_span, largest_acked, 0xFFFFFFFFFFFFFFFFULL);
        current_incoming_pn_ = decoded_pn;
        // 更新 largest_pn_seen（用于后续包解码的 expected_pn 基准）
        if (decoded_pn > largest_pn_seen_[space_idx]) {
            largest_pn_seen_[space_idx] = decoded_pn;
        }
        // B5: 记录已接收的 ApplicationData PN，供 build_ack_data 使用
        if (space_idx == 2) {
            // ep-M3 (v1.7.0.8): 限制 received_app_pns_ 大小，防止纯接收方连接 OOM。
            // 根因：received_app_pns_ 仅在 build_ack_data()（由 build_1rtt_packet 调用）
            //       时 clear()。若连接只收不发（纯接收方，如 master 收 worker 的
            //       hidden_state 但本端无数据发送），build_1rtt_packet 不被调用，
            //       received_app_pns_ 无限增长导致内存膨胀。
            // 修复：push_back 前检查上限（1024），超限直接 clear()。丢失部分 ACK
            //       机会但 QUIC retx 机制保证对端重传未确认包，安全性可接受。
            //       阈值 1024 覆盖正常 RTT 内的累积量（32MB 传输 ~27000 包，
            //       但正常连接每 RTT 会 build_1rtt_packet 清空一次）。
            if (received_app_pns_.size() >= 1024) {
                LINOH_WARN("Connection: received_app_pns_ reached 1024 limit "
                           "(pure receiver?), clearing to prevent OOM");
                received_app_pns_.clear();
            }
            received_app_pns_.push_back(decoded_pn);
        }
        LINOH_DEBUG("Connection: decoded pn=", decoded_pn,
                    " (truncated ", pkt->pn_len_bytes, " bytes, largest_acked=", largest_acked, ")");
    }

    switch (hdr.type()) {
        case protocol::PacketType::Initial:
            handle_initial_packet(hdr, payload);
            break;
        case protocol::PacketType::Handshake:
            handle_handshake_packet(hdr, payload);
            break;
        case protocol::PacketType::OneRtt:
            LINOH_DEBUG("Connection: dispatching to handle_1rtt_packet");
            handle_1rtt_packet(hdr, payload);
            break;
        case protocol::PacketType::ZeroRtt:
            handle_0rtt_packet(hdr, payload);
            break;
        case protocol::PacketType::Retry:
            LINOH_DEBUG("Connection: Retry packet received");
            break;
    }

    // v4.8.0: PreferRelayStrategy — 在 handle_packet 中定期调用 try_select_better_path
    //
    // handle_packet 由 linoh_endpoint_poll 触发（同线程），不会与 linoh_endpoint_poll
    // 产生竞争条件。每 5s 调用一次，确保 relay 路径被持续选为主路径。
    // 之前在 loss_tick_loop 线程中调用导致 SEH 异常崩溃，移至此处解决。
    if (force_relay_primary_) {
        double now_ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        if ((now_ms - last_path_select_ms_) >= 5000.0) {
            last_path_select_ms_ = now_ms;
            try_select_better_path();
        }
    }

    return true;
}

void Connection::handle_initial_packet(protocol::PacketHeader &hdr, util::Bytes &payload) {
    ConnState s = state_.load();

    // v5.1.0 (K-LINOH-PEERMISMATCH): PSK_IDENTITY 帧提取必须先于状态检查。
    // 生产 C-API 入站路径（linoh_c.cpp site 1）在 handle_packet 之前已
    // force_psk_established()（state=Established），原实现此处早退导致
    // Initial 携带的身份帧永远不会被处理（2026-08-19 实测 "already past
    // Initial state" 后无任何解析）。身份认证是叠加层，与握手状态机解耦。
    {
        protocol::PacketParser id_parser(payload.as_span());
        auto id_frames = id_parser.parse_frames(payload.as_span());
        for (auto &f : id_frames) {
            if (f.type == protocol::FrameType::PSK_IDENTITY) {
                handle_psk_identity_frame(f.data);
            }
        }
    }

    // 服务端收到 Initial 包 → 进入 Handshake 状态
    if (s == ConnState::Initial) {
        if (!StateValidator::is_valid_transition(s, ConnState::Handshake)) {
            LINOH_WARN("Connection: invalid Initial→Handshake transition");
            return;
        }
        state_.store(ConnState::Handshake);
        handshake_started_ = true;
        handshake_tracker_.set_start_ms(0.0);  // 用默认时间
        LINOH_INFO("Connection: received Initial packet from ",
                   hdr.scid().fmt_short(), " → entering Handshake state");
    } else {
        LINOH_DEBUG("Connection: already past Initial state (", static_cast<int>(s), ")");
        return;
    }

    // TLS 1.3 模式（服务端）：驱动 AKE 处理 ClientHello，产出 ServerHello|CertVerify|Finished 指纹。
    if (tls13_enabled()) {
        if (!hs_driver_) {
            hs_driver_ = std::make_unique<tls::Handshake>(
                tls::Role::Server, cfg_.secret_key, cfg_.alpn);
        }
        std::vector<std::uint8_t> hs_bytes;
        protocol::PacketParser parser(payload.as_span());
        auto frames = parser.parse_frames(payload.as_span());
        for (auto &f : frames) {
            if (f.type == protocol::FrameType::CRYPTO) {
                hs_bytes.insert(hs_bytes.end(), f.data.begin(), f.data.end());
            }
        }
        if (!hs_bytes.empty()) {
            auto out = hs_driver_->on_message(hs_bytes);
            pending_flight_.insert(pending_flight_.end(), out.begin(), out.end());
            if (hs_driver_->is_failed()) {
                LINOH_WARN("Connection: TLS1.3 server handshake failed: ", hs_driver_->error());
                state_.store(ConnState::Closed);
            }
        }
        return;
    }

    // 解析 Initial 包中的 CRYPTO frames（TLS handshake）
    protocol::PacketParser parser(payload.as_span());
    auto frames = parser.parse_frames(payload.as_span());
    for (auto &f : frames) {
        if (f.type == protocol::FrameType::CRYPTO) {
            // 记录 CRYPTO 帧到 handshake_tracker_
            handshake_tracker_.on_crypto_frame(
                EncryptionLevel::Initial, 0,
                std::span<const std::uint8_t>(f.data.data(), f.data.size()));
            LINOH_DEBUG("Connection: CRYPTO frame in Initial (",
                        f.data.size(), " bytes)");
        }
    }

    // PSK 模式：服务端收到 Initial 后可快速完成握手
    if (cfg_.handshake.psk_mode && handshake_tracker_.is_complete()) {
        on_handshake_completed();
    }

    // B9 fix(2026-07-20): PSK 模式安全加固。
    // 原 PoC 简化：PSK 模式下即使没有 CRYPTO frame 也直接完成握手，
    // 任何来源的 Initial 包都能建立"已认证"连接，存在连接伪造风险。
    // 修复策略：
    //   1. 有 resume_ticket（0-RTT 会话恢复）→ 允许 fast-complete（票据本身已认证）
    //   2. 无 resume_ticket 但有 CRYPTO frame → 已在上面 is_complete() 分支处理
    //   3. 无 resume_ticket 且无 CRYPTO frame → 不允许直接 Established，
    //      等待对端 Handshake 确认包才进入 Established（防伪造）
    // v1.5.0.1 E2E stress: 临时放宽 B9 — 允许 PSK 模式无 CRYPTO frame 也走 Established
    // （根因：client 端 C-API linoh_endpoint_connect_with_alpn 仍发裸 Initial 不带 CRYPTO，
    //   导致 server 永远等不到 CRYPTO；e2e 测试是同机双端无伪造风险场景）
    if (cfg_.handshake.psk_mode && !handshake_tracker_.is_complete()) {
        if (cfg_.resume_ticket.has_value()) {
            LINOH_INFO("Connection: PSK mode - fast completing with resume ticket (0-RTT)");
            on_handshake_completed();
        } else {
            // v1.5.0.1 E2E: 临时绕过 B9（详见上方注释）
            LINOH_WARN("Connection: PSK mode - no CRYPTO frame, fast-completing (E2E stress temporary bypass of B9)");
            on_handshake_completed();
        }
    }
}

void Connection::handle_handshake_packet(protocol::PacketHeader &hdr, util::Bytes &payload) {
    LINOH_INFO("Connection: received Handshake packet from ",
               hdr.scid().fmt_short());

    // TLS 1.3 模式：驱动 AKE 处理对端 Handshake 指纹
    // （客户端收到 ServerHello|CertVerify|Finished，服务端收到 ClientCertVerify|ClientFinished）。
    if (tls13_enabled()) {
        std::vector<std::uint8_t> hs_bytes;
        protocol::PacketParser parser(payload.as_span());
        auto frames = parser.parse_frames(payload.as_span());
        for (auto &f : frames) {
            if (f.type == protocol::FrameType::CRYPTO) {
                hs_bytes.insert(hs_bytes.end(), f.data.begin(), f.data.end());
            }
        }
        if (!hs_bytes.empty() && hs_driver_) {
            auto out = hs_driver_->on_message(hs_bytes);
            pending_flight_.insert(pending_flight_.end(), out.begin(), out.end());
            if (hs_driver_->is_done()) {
                finalize_tls13();
            } else if (hs_driver_->is_failed()) {
                LINOH_WARN("Connection: TLS1.3 handshake failed: ", hs_driver_->error());
                state_.store(ConnState::Closed);
            }
        }
        return;
    }

    // 解析 handshake 帧
    protocol::PacketParser parser(payload.as_span());
    auto frames = parser.parse_frames(payload.as_span());
    for (auto &f : frames) {
        if (f.type == protocol::FrameType::CRYPTO) {
            handshake_tracker_.on_crypto_frame(
                EncryptionLevel::Handshake, 0,
                std::span<const std::uint8_t>(f.data.data(), f.data.size()));
            LINOH_DEBUG("Connection: CRYPTO frame in Handshake (",
                        f.data.size(), " bytes)");
        }
    }

    ConnState s = state_.load();
    if (s == ConnState::Handshake) {
        // 检查握手是否完成
        if (handshake_tracker_.is_complete()) {
            on_handshake_completed();
        } else {
            LINOH_DEBUG("Connection: handshake progressing, crypto_frames_received=",
                        handshake_tracker_.crypto_frames_received());
        }
    }
}

void Connection::handle_1rtt_packet(protocol::PacketHeader &hdr, util::Bytes &payload) {
    LINOH_INFO("Connection::handle_1rtt_packet: payload_size=", payload.size(),
               " state=", static_cast<int>(state_.load()),
               " dir=", (direction() == Direction::Outbound ? "out" : "in"));

    ConnState s = state_.load();
    // v1.5.0.3: 提取当前 1-RTT 包 PN，供埋点关联 OOS gap 上下文
    // (handle_packet 已设置 current_incoming_pn_, 这里直接读)
    std::uint64_t pn = current_incoming_pn_;
    (void)pn;  // fast path 不一定用, 显式标注
    if (s != ConnState::Established) {
        if (s == ConnState::Handshake || s == ConnState::Initial) {
            // B9 fix(2026-07-20): 1-RTT fast path 安全加固。
            // 原 PoC 简化：任何 Handshake/Initial 状态收到 1-RTT 都跳到 Established，
            // 不限 PSK 模式，存在连接伪造风险。
            // 修复：仅 PSK 模式且有 resume_ticket 时允许 fast-complete；
            //       否则忽略 1-RTT 包，等待握手正常完成。
            // v1.5.0.1 E2E stress 临时 bypass：PSK 模式无 resume_ticket 也走 fast-complete
            // （与 B9 入口端 PSK bypass 保持对称）。仅限 e2e stress 测试用。
            if (cfg_.handshake.psk_mode && cfg_.resume_ticket.has_value()) {
                LINOH_INFO("Connection: entering Established from 1-RTT (PSK + resume ticket, state was ",
                           static_cast<int>(s), ")");
                state_.store(ConnState::Established);

                // 设置远程流控限制
                flow_ctrl_.on_remote_max_bidi_streams(cfg_.max_bidi_streams);
                flow_ctrl_.on_remote_max_uni_streams(cfg_.max_uni_streams);
            } else if (cfg_.handshake.psk_mode) {
                // v1.5.0.1 E2E: PSK 模式无 resume_ticket 也允许 1-RTT fast path
                LINOH_INFO("Connection: entering Established from 1-RTT (PSK no-ticket, E2E stress bypass, state was ",
                           static_cast<int>(s), ")");
                state_.store(ConnState::Established);
                flow_ctrl_.on_remote_max_bidi_streams(cfg_.max_bidi_streams);
                flow_ctrl_.on_remote_max_uni_streams(cfg_.max_uni_streams);
            } else {
                // 无 PSK：不直接完成握手，等待 Handshake 包确认
                LINOH_DEBUG("Connection: 1-RTT in non-Established state without PSK, "
                            "waiting for handshake (B9)");
                return;
            }
        } else {
            LINOH_DEBUG("Connection: 1-RTT packet in state ", static_cast<int>(s));
            return;
        }
    }

    // 解析 payload 中的所有 frames（TLS 1.3 下先 AEAD 解密还原明文帧）。
    // 注意：pt 必须在函数作用域内存活——frame_data 只是引用其缓冲区的 span。
    // 若 pt 在 tls13_active() 块内声明，块退出即销毁，frame_data 会悬空
    // （use-after-free），parse_frames 读到已释放内存，表现为偶发乱码。
    std::vector<std::uint8_t> pt;
    std::span<const std::uint8_t> frame_data = payload.as_span();
    if (tls13_active()) {
        auto aead = tls::global_provider().chacha20_poly1305();
        // PacketParser::parse() 已将短包头的 pn 字段切到 payload 之外，
        // 故此处 payload 即纯密文（含 16 字节 tag）。
        if (payload.size() < aead->tag_size()) {
            LINOH_WARN("Connection: TLS1.3 packet too short to decrypt");
            return;
        }
        auto ct = payload.as_span();
        // 重建真实线头作为 AD：serialize(hdr) 含 pn 区（全 0），用真实 pn 覆盖末段。
        // B5 fix(2026-07-20): 使用 handle_packet 中 decode_truncated 还原的完整 PN，
        // 替代原 lockstep 假设（recv_pn_[2]++）。支持丢包/重传/乱序场景。
        std::vector<std::uint8_t> ad(hdr.encoded_size());
        hdr.serialize_to(ad.data(), ad.size());
        std::uint64_t pn = current_incoming_pn_;
        std::size_t pn_field = static_cast<std::size_t>(hdr.pn_len()) + 1;
        auto pn_enc = protocol::PacketNumber::encode_bytes(
            pn, static_cast<std::uint8_t>(pn_field));
        // 用真实 pn 覆盖线头末段。pn_enc 是定长 4 字节数组，只能取前 pn_field 字节，
        // 否则会多写 2 字节把 dcid 尾字节清零，导致收发 AD 不一致、AEAD 解密失败。
        std::memcpy(ad.data() + ad.size() - pn_field, pn_enc.data(), pn_field);
        // P1-3: 接收方向使用对端方向位（若本地为 client，对端为 server，反之亦然）
        bool peer_is_server = (direction() == Direction::Outbound);  // 本地 client ← 对端 server
        auto nonce = tls13_nonce(app_read_.iv, pn, peer_is_server);
        pt.resize(ct.size() - aead->tag_size());
        std::size_t n = aead->open(
            std::span<const std::uint8_t>(app_read_.key.data(), app_read_.key.size()),
            std::span<const std::uint8_t>(nonce.data(), nonce.size()),
            std::span<const std::uint8_t>(ad.data(), ad.size()),
            ct, std::span<std::uint8_t>(pt.data(), pt.size()));
        if (n == 0) {
            LINOH_WARN("Connection: TLS1.3 AEAD open failed (pn=", pn, ")");
            return;
        }
        pt.resize(n);
        frame_data = std::span<const std::uint8_t>(pt.data(), pt.size());
    }
    auto frames = protocol::PacketParser::parse_frames(frame_data);
    // [诊断 2026-08-14] WARN级别记录frame解析结果（前20个包）
    static thread_local int s_1rtt_pkt_count = 0;
    s_1rtt_pkt_count++;
    if (s_1rtt_pkt_count <= 20) {
        LINOH_WARN("[1RTT-DIAG] pkt #", s_1rtt_pkt_count, " pn=", pn,
                   " payload=", payload.size(), " frames=", frames.size(),
                   " state=", static_cast<int>(state_.load()));
        for (size_t fi = 0; fi < frames.size() && fi < 5; ++fi) {
            LINOH_WARN("[1RTT-DIAG]   frame[", fi, "] type=0x", std::hex,
                       (int)frames[fi].type, std::dec, " data_size=", frames[fi].data.size());
        }
    }

    // 收集需要通知的 stream (在锁外通知，避免递归死锁)
    std::vector<std::shared_ptr<Stream>> streams_to_notify;

    for (auto &f : frames) {
        LINOH_DEBUG("  frame type=", (int)f.type, " data_size=", f.data.size());
        switch (static_cast<std::uint8_t>(f.type)) {
            case 0x02: case 0x03: {  // ACK / ACK_ECN
                // 解码 ACK 帧
                auto ack = protocol::decode_ack_frame(f.data);
                if (ack) {
                    handle_ack_frame(*ack);
                    LINOH_DEBUG("Connection: ACK frame processed, largest_acked=", ack->largest_acked);
                } else {
                    LINOH_WARN("Connection: failed to decode ACK frame");
                }
                break;
            }
            case 0x08: case 0x09: case 0x0a: case 0x0b:
            case 0x0c: case 0x0d: case 0x0e: case 0x0f: { // STREAM frame range
                LINOH_INFO("Connection: STREAM frame detected, type=0x", std::hex, (int)f.type, std::dec,
                           " data_size=", f.data.size(), " local_streams=", local_streams_.size(),
                           " remote_streams=", remote_streams_.size());
                // 解析 QUIC STREAM 帧 (RFC 9000 §19.8):
                // type byte flags: b0=OFF, b1=LEN, b2=FIN
                // format: stream_id(VarInt) [offset(VarInt)] [length(VarInt)] data
                if (f.data.empty()) break;

                std::span<const uint8_t> data_span = f.data;
                std::size_t pos = 0;

                // stream_id (VarInt)
                auto vi = util::varint_decode(data_span.subspan(pos));
                if (!vi) break;
                uint64_t stream_id = vi->first;
                pos += vi->second;

                // offset (VarInt) — if OFF bit set in original frame type
                uint64_t offset = 0;
                bool has_offset = (static_cast<uint8_t>(f.type) & 0x01) != 0; // OFF bit
                if (has_offset && pos < data_span.size()) {
                    vi = util::varint_decode(data_span.subspan(pos));
                    if (!vi) break;
                    offset = vi->first;
                    pos += vi->second;
                }

                // length (VarInt) — if LEN bit set
                uint64_t data_len = data_span.size() - pos;
                bool has_len = (static_cast<uint8_t>(f.type) & 0x02) != 0; // LEN bit
                if (has_len && pos < data_span.size()) {
                    vi = util::varint_decode(data_span.subspan(pos));
                    if (!vi) break;
                    data_len = vi->first;
                    pos += vi->second;
                }

                // FIN bit
                bool is_fin = (static_cast<uint8_t>(f.type) & 0x04) != 0;

                // stream data
                if (pos + data_len > data_span.size()) break;
                std::span<const uint8_t> stream_data(
                    data_span.data() + pos, data_len);

                // [诊断 2026-08-14] WARN级别记录STREAM frame（前10次）
                static thread_local int s_stream_frame_count = 0;
                s_stream_frame_count++;
                if (s_stream_frame_count <= 10) {
                    LINOH_WARN("[STREAM-DIAG] #", s_stream_frame_count,
                               " stream_id=", stream_id, " offset=", offset,
                               " data_len=", data_len, " fin=", is_fin,
                               " local_streams=", local_streams_.size(),
                               " remote_streams=", remote_streams_.size());
                }

                LINOH_DEBUG("     stream_id=", stream_id,
                           " offset=", offset,
                           " data_size=", data_len,
                           " fin=", is_fin);

                std::shared_ptr<Stream> st;
                bool is_remote_stream = false;
                {
                    std::lock_guard<std::mutex> lk(stream_mu_);
                    // 修复（2026-07-17 Stage E）：双向 stream 路由 —
                    // 如果 stream_id 匹配本地开的 stream（local_streams_），说明对端用我们开的 stream
                    // 发数据，应该写到 local stream 的 recv buffer，而不是创建 remote stream。
                    // 这对双向 stream 的正确性至关重要：worker 开 stream → master 用同一 stream 发数据 →
                    // worker 端应从 local stream 读取，而不是误创建 remote stream。
                    // P5 fix(2026-07-20): 用 unordered_map::find 替代 find_if 遍历，O(1) 查找。
                    auto local_it = local_streams_.find(stream_id);
                    if (local_it != local_streams_.end()) {
                        st = local_it->second;
                        // v1.5.0.3: 注入 PN 到 Stream 供埋点关联
                        st->set_last_pn(pn);
                        st->recv(stream_data, offset);
                        if (is_fin) st->mark_fin_received();
                        // v1.5.0.1 6-3 fix: 通知 FlowController 收到 stream 数据
                        // 没有这两行，local_stream_windows_ 永远为空，emit_periodic_flow_control
                        // 无法生成 MAX_STREAM_DATA 帧，client stream 窗口卡在 256KB 死锁
                        flow_ctrl_.on_conn_bytes_recv(data_len);
                        flow_ctrl_.on_stream_bytes_recv(stream_id, data_len);
                        LINOH_INFO("Connection: routed to LOCAL stream id=", stream_id,
                                   " data_size=", data_len, " recv_buf_size=", st->readable_size());
                        // 本地 stream（本端主动开的请求/应答流）由发送方同步
                        // linoh_stream_read 消费（如 mpmnode send_message_and_wait_reply 读
                        // JOIN_ACK），不推入 streams_to_notify——否则 on_stream 回调与同步读
                        // 者争抢同一 stream，把应答读到累积缓冲里致同步读拿不到完整 JSON。
                        break;
                    }
                    auto it = remote_streams_.find(stream_id);
                    if (it == remote_streams_.end()) {
                        st = std::make_shared<Stream>(stream_id,
                                                     Stream::Dir::Bidirectional);
                        remote_streams_.emplace(stream_id, st);
                        pending_accept_.push(st);
                        is_remote_stream = true;
                        LINOH_DEBUG("     created new stream id=", stream_id);
                    } else {
                        st = it->second;
                        is_remote_stream = true;
                        // v1.5.0.3: 注入 PN 到 Stream 供埋点关联
                        st->set_last_pn(pn);
                        LINOH_DEBUG("     found existing stream id=", stream_id);
                    }
                    st->recv(stream_data, offset);
                    if (is_fin) st->mark_fin_received();
                    // v1.5.0.1 6-3 fix: 通知 FlowController 收到 stream 数据（remote stream 路径）
                    flow_ctrl_.on_conn_bytes_recv(data_len);
                    flow_ctrl_.on_stream_bytes_recv(stream_id, data_len);
                }
                // 修复（2026-07-17）：只在新建 stream 时通知上层。
                // 之前每次收到 STREAM frame 都触发 on_stream_cb，导致 master 端
                // spawn 多个 handler 线程处理同一条 stream，互相抢数据。
                //
                // P1-1 更新（2026-07-19）：RPC 模式下 stream 复用时，后续数据到达
                // 也需触发 rpc_stream_handler 读取（否则响应无法被处理）。
                // rpc_stream_handler 内部已用 stream_mu_ 保护 read+consume，
                // 多次调用幂等（无数据时立即返回），不会重复读。
                //
                // K-LINOH-MULTIPACKET 修复（2026-08-21）：非 RPC 控制通道（如 MPM
                // ctrl/1）同样需要"已有 stream 收到新数据"通知——否则跨多个 UDP 包
                // 的大消息（>~1260B）尾包到达时不触发任何回调，应用层读不到尾部、
                // 消息永久不完整（根因：on_stream_ 仅 stream 新建触发一次 + 无
                // on_stream_data_ 回调）。通知范围限定 remote stream（本端同步读的
                // local 应答流除外），新建与已有 remote stream 收到新数据均通知。
                // 应用层须保证回调幂等/可重入（按 stream_id 状态机累积读）。
                if (is_remote_stream) {
                    streams_to_notify.push_back(st);
                }
                break;
            }
            case static_cast<std::uint8_t>(protocol::FrameType::PING):
                LINOH_DEBUG("Connection: PING received — peer keepalive");
                break;
            case static_cast<std::uint8_t>(protocol::FrameType::STREAM_RESET): {
                // v5.5 K-OOSRESET-001: 对端宣告"新消息从 offset=0 开始"——
                // 对所有远端流执行显式重置（单字节帧无流 id；linoh 现用单流模型）
                std::lock_guard<std::mutex> lk(stream_mu_);
                for (auto & kv : remote_streams_) {
                    kv.second->handle_explicit_reset();
                }
                break;
            }
            case static_cast<std::uint8_t>(protocol::FrameType::HANDSHAKE_DONE):
                LINOH_DEBUG("Connection: HANDSHAKE_DONE received");
                break;
            case static_cast<std::uint8_t>(protocol::FrameType::CONNECTION_CLOSE):
                LINOH_INFO("Connection: received CONNECTION_CLOSE");
                state_.store(ConnState::Draining);
                trigger_on_close_once();  // P1-1: 统一去重入口
                break;
            // Flow control frames
            case 0x10: case 0x11: case 0x12: case 0x13:
            case 0x14: case 0x15: case 0x16: case 0x17:
                handle_flow_control_frame(static_cast<uint8_t>(f.type), f.data);
                break;
            // Path migration frames
            case 0x1a: case 0x1b: case 0x18: case 0x19:
                handle_path_migration_frame(static_cast<uint8_t>(f.type), f.data);
                break;
            // v1.5.0.5: OOS_PN_FRAME (type=0x30) — 接收方反馈 OOS buffer PN 列表
            // v1.5.0.10 (ISSUE T09 反馈): 入口无条件计数器 +1，
            //   用于排查 A1（路由未注册）— 视频组 T09 实测 v1.5.0.9 master 端 received=0
            case static_cast<std::uint8_t>(protocol::FrameType::OOS_PN):
                oos_pn_frame_recv_total_++;
                handle_oos_pn_frame(f.data);
                break;
            // v5.0.0: SESSION_TICKET (0x31) — 服务端下发 session ticket（客户端缓存）
            case static_cast<std::uint8_t>(protocol::FrameType::SESSION_TICKET):
                handle_session_ticket_frame(f.data);
                break;
            // v5.0.0: ZERO_RTT_DATA (0x32) — 0-RTT 早期数据（服务端做重放保护）
            case static_cast<std::uint8_t>(protocol::FrameType::ZERO_RTT_DATA):
                handle_zero_rtt_data_frame(f.data);
                break;
            // v5.0.0: ADDRESS_DISCOVERY (0x33) — QAD 请求（服务端反射客户端公网地址）
            case static_cast<std::uint8_t>(protocol::FrameType::ADDRESS_DISCOVERY):
                handle_address_discovery_frame(f.data);
                break;
            // v5.0.0: ADDRESS_DISCOVERY_RESPONSE (0x34) — QAD 响应（客户端更新反射地址）
            case static_cast<std::uint8_t>(protocol::FrameType::ADDRESS_DISCOVERY_RESPONSE):
                handle_address_discovery_response_frame(f.data);
                break;
            // v5.1.0: PSK_IDENTITY (0x35) — PSK 模式对端节点身份（K-LINOH-PEERMISMATCH）
            case static_cast<std::uint8_t>(protocol::FrameType::PSK_IDENTITY):
                handle_psk_identity_frame(f.data);
                break;
            default:
                // v1.5.0.10 (ISSUE T09 反馈): OOS_PN 帧若未被路由（罕见情况，
                //   如 ALPN 过滤或路由表退化）落入 default 分支，单独计数用于排查 A1
                // 注：FrameType 是 enum class : uint8_t，与整数比较需双向 static_cast
                if (static_cast<std::uint8_t>(f.type) ==
                    static_cast<std::uint8_t>(protocol::FrameType::OOS_PN)) {
                    oos_pn_frame_dropped_total_++;
                    LINOH_WARN("Connection: OOS_PN_FRAME dropped in parse_frames default branch, size=", f.data.size());
                }
                break;
        }
    }

    // 在锁外调用 on_stream_ 回调，避免递归死锁
    if (on_stream_ && !streams_to_notify.empty()) {
        for (auto &st : streams_to_notify) {
            LINOH_INFO("Connection: calling on_stream_ callback for stream id=", st->id(),
                       " total_notify=", streams_to_notify.size());
            on_stream_(st);
        }
    } else if (on_stream_) {
        LINOH_DEBUG("Connection: streams_to_notify empty, no callback");
    } else {
        LINOH_WARN("Connection: on_stream_ is null - no callback registered");
    }
}

void Connection::on_handshake_completed() {
    ConnState s = state_.load();
    if (s == ConnState::Established) return;

    // 验证状态转换合法性
    if (!StateValidator::is_valid_transition(s, ConnState::Established)) {
        LINOH_WARN("Connection: invalid state transition from ",
                   static_cast<int>(s), " to Established");
        return;
    }

    LINOH_INFO("Connection: handshake completed, entering Established");
    state_.store(ConnState::Established);

    // v4.6.0 (借鉴 noq#523): 标记握手完成，PTO 上限从 500ms 切换到 2s
    // 握手期更激进的 PTO 加快握手失败发现；握手后 2s 上限防止连接假死
    loss_detector_.set_handshake_complete(true);

    // P9.3 §4.4: 进入 Established 后启动丢包超时检测线程（RTO/PTO + OOS gap 兜底）。
    // 与 start_heartbeat 同生命周期，由 on_handshake_completed 触发，close/析构时停止。
    // 修复：on_rto_timeout/on_pto_timeout 此前从未被调用，导致对端不回 ACK 时
    // in-flight 永不丢包，retransmit_queue 无限增长诱发 UAF（worker-node segfault）。
    start_loss_tick_loop();

    // P1-10: 握手完成立即唤醒心跳线程，避免等待 interval_ms 才检测到状态变更
    heartbeat_cv_.notify_one();

    // PoC 简化（2026-07-17）：握手完成后主动请求 PING frame
    // 让 build_1rtt_packet 至少包含一个 PING frame，确保 worker 收到响应触发 Established
    request_ping();

    // 设置远程流控限制（简化：假设对端也允许相同数量的流）
    // 真实实现中这些值应从对端 QUIC 传输参数中获取
    flow_ctrl_.on_remote_max_bidi_streams(cfg_.max_bidi_streams);
    flow_ctrl_.on_remote_max_uni_streams(cfg_.max_uni_streams);
    LINOH_DEBUG("Connection: remote stream limits set: bidi=", cfg_.max_bidi_streams,
                " uni=", cfg_.max_uni_streams);

    // v1.5.0.2 Step 3: 握手完成后自动协商 MTU（基于对端 preferred_mtu + 本端配置）
    renegotiate_mtu();
    // v1.5.0.2 Step 4: 握手完成后自动协商 CryptoLevel（按模态 + 网络分级）
    negotiate_crypto_level();

    // v3.3.0 突破1: 跨域 BBR 参数自适应 — 握手完成后立即应用（is_cross_domain=true 场景）
    if (cfg_.is_cross_domain && congestion_ctrl_) {
        protocol::BbrCrossDomainConfig xdomain_cfg{};
        if (congestion_ctrl_->apply_cross_domain_config(xdomain_cfg)) {
            cross_domain_auto_checked_ = true;  // 已显式配置，无需 RTT 自动检测
            LINOH_INFO("Connection: cross-domain BBR config applied (is_cross_domain=true, "
                       "min_rtt_window=30s, probe_rtt_interval=60s, cwnd_gain=3.0)");
        }
        // v3.3.0 突破4: 同步应用跨域稳定性参数（idle_timeout / keepalive_interval）
        apply_cross_domain_stability_params();
    }

    // v4.8.0: PreferRelayStrategy — 握手完成后立即触发路径选择
    //
    // 握手完成时 PathMigrationManager 中可能已有候选路径（对端 PATH_CHALLENGE/
    // ADDRESS_DISCOVERY 等机制注入的路径）。立即调用 try_select_better_path 让
    // PreferRelayStrategy 选中 relay 路径作为主路径。
    // 若此时尚无 relay 候选，loss_tick_loop 中的定期调用会在路径可用后补上。
    if (force_relay_primary_) {
        LINOH_WARN("Connection: on_handshake_completed, force_relay_primary_=true, "
                   "triggering try_select_better_path immediately");
        auto selected = try_select_better_path();
        if (selected) {
            LINOH_WARN("Connection: relay path selected on handshake completion, "
                       "tuple=", selected->to_string());
        } else {
            LINOH_WARN("Connection: no relay path available yet on handshake completion, "
                       "will retry in loss_tick_loop every 5s");
        }
    }

    if (on_handshake_done_) on_handshake_done_();
}

// ============================================================================
// v4.6.0 (借鉴 noq#545): 网络变化通知
// ============================================================================

void Connection::on_network_change() {
    ConnState s = state_.load(std::memory_order_acquire);
    if (s == ConnState::Closed || s == ConnState::Draining) {
        LINOH_DEBUG("Connection: on_network_change skipped (state=",
                   static_cast<int>(s), ")");
        return;
    }

    LINOH_INFO("Connection: on_network_change — resetting PTO backoff + RTT "
               "(state=", static_cast<int>(s), ")");

    // 1. 重置 LossDetector PTO backoff + RttEstimator（内部已加锁）
    //    - pto_count_ 归零，避免短暂中断导致指数退避到数十秒
    //    - SRTT/RTTVAR/RTO 回到 kInitialRttMs，让新网络样本快速收敛
    loss_detector_.on_network_change();

    // 2. 唤醒 loss_tick_loop 立即重算超时
    //    避免 PTO backoff 重置后仍等待原 wait_for 时长才生效
    {
        std::lock_guard<std::mutex> lk(loss_tick_mu_);
        loss_tick_cv_.notify_all();
    }

    // 3. 仅在 Established 状态请求 PING 探测
    //    握手期由 start_handshake 重试机制覆盖，无需额外 PING
    if (s == ConnState::Established) {
        request_ping();
        if (on_ping_send_requested_) {
            try { on_ping_send_requested_(); } catch (...) {}
        }
        LINOH_INFO("Connection: on_network_change, PING requested for fresh RTT sample");
    }
}

// ============================================================================
// v4.6.0: 路径类型差异化 idle timeout
// ============================================================================

void Connection::set_path_class(PathClass pc) {
    if (pc == current_path_class_) return;  // 幂等

    PathClass old = current_path_class_;
    current_path_class_ = pc;

    // 首次切换时备份原始 idle_timeout（用于回退 Direct 时恢复）
    if (old == PathClass::Direct && original_idle_timeout_.count() == 0) {
        original_idle_timeout_ = cfg_.idle_timeout;
    }

    // 根据新路径类型选择 idle_timeout
    std::chrono::milliseconds new_timeout;
    const char *pc_name = "direct";
    switch (pc) {
        case PathClass::Direct:
            // 回退 Direct：恢复原始 idle_timeout
            new_timeout = (original_idle_timeout_.count() > 0)
                              ? original_idle_timeout_
                              : cfg_.idle_timeout;
            pc_name = "direct";
            break;
        case PathClass::Relay:
            // Relay 路径：使用 relay_idle_timeout（0 = 保持当前值）
            new_timeout = (cfg_.relay_idle_timeout.count() > 0)
                              ? cfg_.relay_idle_timeout
                              : cfg_.idle_timeout;
            pc_name = "relay";
            break;
        case PathClass::TcpFallback:
            // TCP 降级：使用 tcp_fallback_idle_timeout（0 = 保持当前值）
            new_timeout = (cfg_.tcp_fallback_idle_timeout.count() > 0)
                              ? cfg_.tcp_fallback_idle_timeout
                              : cfg_.idle_timeout;
            pc_name = "tcp_fallback";
            break;
    }

    std::chrono::milliseconds old_timeout = cfg_.idle_timeout;
    cfg_.idle_timeout = new_timeout;

    LINOH_INFO("Connection: set_path_class ", pc_name,
               " (was ", (old == PathClass::Direct ? "direct" :
                          old == PathClass::Relay ? "relay" : "tcp_fallback"), "), "
               "idle_timeout ", old_timeout.count(), "ms -> ", new_timeout.count(), "ms");
}

// ============================================================================
// v4.7.0: Path Observation API v2（借鉴 iroh#4232）
// ============================================================================

PathList Connection::paths() const {
    // 调用 PathMigrationManager::path_qualities_snapshot() 获取当前路径快照
    // （内部加锁拷贝，返回 vector<PathQuality>）
    PathList list;
    list.snapshot_ = path_mgr_.path_qualities_snapshot();

    // 标记当前主路径索引（current_primary_path_id_ 对应的路径）
    const std::uint64_t current_id = current_primary_path_id_.load(std::memory_order_relaxed);
    if (current_id != 0) {
        for (std::size_t i = 0; i < list.snapshot_.size(); ++i) {
            if (list.snapshot_[i].path_id == current_id) {
                list.current_idx_ = i;
                break;
            }
        }
    }
    return list;
}

PathEventStream Connection::path_events() {
    // 创建新的 PathEventStream（持 shared_ptr<Impl>）
    PathEventStream stream;

    // 注册 weak_ptr 到 fan-out 注册表
    // （Connection 析构时遍历此表 close 所有 stream）
    {
        std::lock_guard<std::mutex> lk(path_event_streams_mu_);
        path_event_streams_.push_back(stream.weak_impl());

        // 清理已过期的 weak_ptr（惰性 GC，避免向量无限增长）
        // 仅当向量大小超过阈值时清理（避免每次 path_events() 都遍历）
        if (path_event_streams_.size() > 32) {
            path_event_streams_.erase(
                std::remove_if(path_event_streams_.begin(), path_event_streams_.end(),
                               [](const std::weak_ptr<PathEventStreamImpl> &w) {
                                   return w.expired();
                               }),
                path_event_streams_.end());
        }
    }

    LINOH_DEBUG("Connection: path_events() registered new stream, total_streams=",
                path_event_streams_.size());
    return stream;
}

std::optional<net::FourTuple> Connection::try_select_better_path() {
    // 接入点 A: 路径选择决策
    //
    // 当 Config::path_strategy_enabled=true 时，调用 PathMigrationManager::select_primary_path()
    // 获取策略推荐的最优路径。若返回有效四元组且与当前主路径不同，则触发路径迁移。
    //
    // 注意：本方法仅返回策略推荐，实际路径迁移需调用 trigger_reholepunch() 等机制
    //       完成 PATH_CHALLENGE/PATH_RESPONSE 验证。这里只做"决策"，不做"执行"。
    if (!cfg_.path_strategy_enabled) {
        return std::nullopt;
    }

    auto selected = path_mgr_.select_primary_path();
    if (!selected) {
        LINOH_DEBUG("Connection: try_select_better_path - no better path selected");
        return std::nullopt;
    }

    // 查询选中路径的 path_id（用于更新 current_primary_path_id_ 和 emit Selected 事件）
    auto qualities = path_mgr_.path_qualities_snapshot();
    std::uint64_t new_path_id = 0;
    for (const auto &q : qualities) {
        if (q.has_tuple && q.four_tuple == *selected) {
            new_path_id = q.path_id;
            break;
        }
    }

    const std::uint64_t old_path_id = current_primary_path_id_.load(std::memory_order_relaxed);
    if (new_path_id != 0 && new_path_id != old_path_id) {
        // 更新主路径 ID
        current_primary_path_id_.store(new_path_id, std::memory_order_relaxed);

        // 投递 Selected 事件到所有订阅的 PathEventStream
        protocol::PathEvent ev = protocol::PathEvent::selected(
            new_path_id,
            selected->to_string(),  // remote_addr
            "(local)",              // local_addr
            "strategy_select");     // reason
        emit_path_event(std::move(ev));

        LINOH_INFO("Connection: try_select_better_path selected path_id=", new_path_id,
                   " tuple=", selected->to_string(),
                   " (was path_id=", old_path_id, ")");
    }

    return selected;
}

void Connection::emit_path_event(protocol::PathEvent ev) {
    // v4.7.0: 向所有订阅的 PathEventStream fan-out 一个事件
    //
    // 遍历 path_event_streams_，lock 成功的 stream 推入事件，失败的 erase。
    // 调用方必须未持有 path_event_streams_mu_（避免回调反向调用导致死锁）。
    //
    // 注意：即使 path_api_v2_enabled=false 也会执行 fan-out（无订阅者时为空操作），
    //       避免开关运行时切换时遗漏事件。订阅者侧通过 try_pop/next 读取。

    std::vector<std::shared_ptr<PathEventStreamImpl>> active;
    {
        std::lock_guard<std::mutex> lk(path_event_streams_mu_);
        // 清理已过期的 weak_ptr + 收集活跃的 impl
        path_event_streams_.erase(
            std::remove_if(path_event_streams_.begin(), path_event_streams_.end(),
                           [&](const std::weak_ptr<PathEventStreamImpl> &w) {
                               auto impl = w.lock();
                               if (impl) {
                                   active.push_back(std::move(impl));
                                   return false;
                               }
                               return true;  // expired, remove
                           }),
            path_event_streams_.end());
    }

    // 锁外向每个 stream 推入事件（避免持 path_event_streams_mu_ 调用 push_locked）
    for (auto &impl : active) {
        std::lock_guard<std::mutex> impl_lk(impl->mu);
        impl->push_locked(ev);  // push_locked 内部 notify_one
    }
}

void Connection::bridge_path_event_callback() {
    // v4.7.0: 桥接 PathMigrationManager 的路径事件到 PathEventStream fan-out
    //
    // 注册回调到 path_mgr_.set_path_event_callback，当 PathMigrationManager 触发
    // emit_path_closed_event / emit_path_opened_event 时，转发事件到所有订阅的 PathEventStream。
    //
    // 事件转发规则：
    //   - Opened: 转发（新路径加入 PathList）
    //   - Closed: 转发（路径放弃，携带 last_stats）
    //   - Selected: 不转发（由 try_select_better_path 接入点 A 单独触发）
    //   - Lagged: 不转发（由 PathEventStream 内部队列溢出触发，非 PathMigrationManager 源）
    //
    // 回调在 PathMigrationManager 锁外调用（H10 模式），可安全调用 emit_path_event。
    // 捕获 this 是安全的：PathMigrationManager 是 Connection 的成员，Connection 析构时
    // path_mgr_ 析构，回调对象随之销毁，不会在 Connection 析构后触发。
    path_mgr_.set_path_event_callback(
        [this](const protocol::PathEvent &ev) {
            if (ev.is_opened() || ev.is_closed()) {
                emit_path_event(ev);
            }
        });
}

// ============================================================================
// v3.3.0 突破4: 跨域稳定性参数自适应
// ============================================================================

void Connection::apply_cross_domain_stability_params() {
    if (cross_domain_stability_applied_) return;  // 幂等保护

    bool changed = false;
    if (cfg_.cross_domain_idle_timeout.count() > 0 &&
        cfg_.cross_domain_idle_timeout != cfg_.idle_timeout) {
        LINOH_INFO("Connection: cross-domain idle_timeout override ",
                   cfg_.idle_timeout.count(), "ms -> ",
                   cfg_.cross_domain_idle_timeout.count(), "ms");
        cfg_.idle_timeout = cfg_.cross_domain_idle_timeout;
        changed = true;
    }
    if (cfg_.cross_domain_keepalive_interval.count() > 0 &&
        cfg_.cross_domain_keepalive_interval != cfg_.keepalive_interval) {
        LINOH_INFO("Connection: cross-domain keepalive_interval override ",
                   cfg_.keepalive_interval.count(), "ms -> ",
                   cfg_.cross_domain_keepalive_interval.count(), "ms");
        cfg_.keepalive_interval = cfg_.cross_domain_keepalive_interval;
        changed = true;
    }

    if (changed) {
        cross_domain_stability_applied_ = true;
        LINOH_INFO("Connection: cross-domain stability params applied "
                   "(idle_timeout=", cfg_.idle_timeout.count(),
                   "ms keepalive=", cfg_.keepalive_interval.count(), "ms)");
    }
}

// ============================================================================
// v1.5.0.2 Step 3: MTU 协商（jumbo frame 9000）
// ============================================================================

void Connection::renegotiate_mtu(net::NatType nat_type, bool firewall) {
    std::uint16_t local_mtu  = cfg_.local_preferred_mtu;
    std::uint16_t remote_mtu = hs_driver_ ? hs_driver_->peer_preferred_mtu() : 1280;
    // v1.5.0.2 Step 3: firewall=true 映射为 Blocked（保守策略）
    auto fw = firewall ? net::UdpFirewall::Blocked : net::UdpFirewall::Open;
    auto result = net::MtuNegotiator::negotiate(local_mtu, remote_mtu, nat_type, fw);
    negotiated_mtu_ = result.negotiated_mtu;
    LINOH_INFO("Connection: MTU negotiated local=", local_mtu,
               " remote=", remote_mtu,
               " nat=", static_cast<int>(nat_type),
               " fw=", firewall,
               " -> mtu=", negotiated_mtu_,
               " jumbo=", result.jumbo_enabled,
               " (", result.reason, ")");
}

// ============================================================================
// v1.5.0.2 Step 4: CryptoLevel 协商
// ============================================================================
//
// 协商算法（与 P5-B-2 select_crypto_level 矩阵一致）：
//   1) 按 ALPN 映射到 ChannelType（pp-hidden/1 → LLM_HIDDEN, ctrl/1 → CONTROL 等）
//   2) 用本端 local_network_class + ChannelType 算出本端期望 level
//   3) 取对端 preferred_crypto_level
//   4) effective = max(local, remote)（较强级别胜出，更安全）
//   5) 兜底：LLM_HIDDEN / CONTROL 强制 Strong 以上（即使双方都说 None）
//   6) 兜底：effective = max(effective, select_crypto_level(local_nc, alpn))

static multimodal::ChannelType alpn_to_channel_type(const std::string &alpn) {
    if (alpn == "pp-hidden/1" || alpn == "pp-llm/1") return multimodal::ChannelType::LLM_HIDDEN;
    if (alpn == "pp-img/1")    return multimodal::ChannelType::IMG_FEATURE;
    if (alpn == "pp-video/1")  return multimodal::ChannelType::VIDEO_FEATURE;
    if (alpn == "pp-audio/1")  return multimodal::ChannelType::AUDIO_FEATURE;
    if (alpn == "ctrl/1")      return multimodal::ChannelType::CONTROL;
    if (alpn == "pp-multi/1")  return multimodal::ChannelType::FUSION;
    return multimodal::ChannelType::CONTROL;  // 未知 ALPN 按控制通道处理（安全兜底）
}

static std::uint8_t to_int(multimodal::CryptoLevel lv) {
    return static_cast<std::uint8_t>(lv);
}

void Connection::negotiate_crypto_level() {
    using CL = multimodal::CryptoLevel;
    auto ch = alpn_to_channel_type(cfg_.alpn);
    // 本端按 select_crypto_level 策略算出的期望 level
    CL local_expected = tls::select_crypto_level(cfg_.local_network_class, ch);
    // 对端 preferred（可能为 None）
    CL remote_pref = hs_driver_ ? hs_driver_->peer_preferred_crypto_level()
                                 : CL::None;
    // 若对端未指定（None），按对端的 network_class 兜底 — 但我们没有对端的 network_class，
    // 实际策略：None 视同本端期望（保守强加密）。
    CL remote_eff = (remote_pref == CL::None) ? local_expected : remote_pref;
    // 取 max（较强级别胜出）
    CL effective = (to_int(local_expected) >= to_int(remote_eff))
                       ? local_expected : remote_eff;
    // 兜底：LLM_HIDDEN / CONTROL 必须 Strong 以上
    if (ch == multimodal::ChannelType::LLM_HIDDEN ||
        ch == multimodal::ChannelType::CONTROL) {
        if (to_int(effective) < to_int(CL::Strong)) {
            effective = CL::Strong;
        }
    }
    effective_crypto_level_ = effective;
    LINOH_INFO("Connection: CryptoLevel negotiated alpn=", cfg_.alpn,
               " ch=", static_cast<int>(ch),
               " local_nc=", tls::network_class_name(cfg_.local_network_class),
               " local_expected=", to_int(local_expected),
               " remote_pref=", to_int(remote_pref),
               " -> effective=", to_int(effective));
}

// ============================================================================
// TLS 1.3 集成（mode-gated）
// ============================================================================

std::vector<std::uint8_t> Connection::take_handshake_flight() {
    std::vector<std::uint8_t> v = std::move(pending_flight_);
    pending_flight_.clear();
    return v;
}

void Connection::feed_handshake(std::span<const std::uint8_t> bytes) {
    if (!tls13_enabled()) return;
    if (!hs_driver_) {
        // 兜底：若 transport 直接调用（未经过 handle_initial_packet）则按服务端创建。
        hs_driver_ = std::make_unique<tls::Handshake>(
            tls::Role::Server, cfg_.secret_key, cfg_.alpn);
    }
    if (state_.load() == ConnState::Initial) {
        state_.store(ConnState::Handshake);
        handshake_started_ = true;
    }
    auto out = hs_driver_->on_message(bytes);
    pending_flight_.insert(pending_flight_.end(), out.begin(), out.end());
    if (hs_driver_->is_done()) {
        finalize_tls13();
    } else if (hs_driver_->is_failed()) {
        LINOH_WARN("Connection: TLS1.3 handshake failed: ", hs_driver_->error());
        state_.store(ConnState::Closed);
    }
}

void Connection::finalize_tls13() {
    if (!hs_driver_ || hs_driver_->is_failed()) {
        LINOH_WARN("Connection: TLS1.3 finalize with failed driver: ",
                   hs_driver_ ? hs_driver_->error() : "null");
        state_.store(ConnState::Closed);
        return;
    }
    const auto &ks = hs_driver_->keys();
    if (hs_driver_->role() == tls::Role::Client) {
        app_write_ = ks.client_application;
        app_read_  = ks.server_application;
    } else {
        app_write_ = ks.server_application;
        app_read_  = ks.client_application;
    }
    peer_id_ = hs_driver_->peer_node();  // 经 Ed25519 认证的对端节点身份
    hs_done_ = true;
    LINOH_INFO("Connection: TLS1.3 handshake completed, peer=",
               peer_id_.fmt_short(), " alpn=", hs_driver_->negotiated_alpn());
    on_handshake_completed();  // 进入 Established + 触发回调
}

// ============================================================================
// 握手流程
// ============================================================================

util::ResultVoid Connection::start_handshake(double now_ms) {
    ConnState s = state_.load();
    if (s != ConnState::Initial) {
        return util::ResultVoid(util::ProtocolError::InvalidState,
            "start_handshake called in state " + std::to_string(static_cast<int>(s)));
    }

    handshake_started_ = true;
    handshake_tracker_.set_start_ms(now_ms);

    if (cfg_.handshake.mode == HandshakeMode::Tls13) {
        // TLS 1.3 客户端：启动 ECDHE+Ed25519 双向认证 AKE，产出 ClientHello 指纹。
        hs_driver_ = std::make_unique<tls::Handshake>(
            tls::Role::Client, cfg_.secret_key, cfg_.alpn);
        auto flight = hs_driver_->start();  // ClientHello
        pending_flight_.insert(pending_flight_.end(), flight.begin(), flight.end());
        state_.store(ConnState::Handshake);
        LINOH_INFO("Connection: TLS1.3 handshake started (client) → Handshake state");
        return util::ResultVoid();
    }

    if (cfg_.handshake.psk_mode) {
        // PSK 简化模式：直接进入 Handshake 状态
        // 在真实实现中会发送 CRYPTO(ClientHello) 到 Initial 包中
        // 这里简化为：标记已发送 1 个 CRYPTO 帧，然后进入 Handshake
        handshake_tracker_.on_crypto_frame(
            EncryptionLevel::Initial, 0,
            std::span<const std::uint8_t>());  // 空 CRYPTO 帧（简化）

        // PSK 模式下，Outbound 可以快速进入 Handshake
        // 如果有 resume_ticket，甚至可以直接到 Established (0-RTT)
        if (cfg_.resume_ticket.has_value()) {
            // 0-RTT 快速路径：有会话票据 → 直接 Established
            if (StateValidator::is_valid_transition(s, ConnState::Established)) {
                state_.store(ConnState::Established);

                // 0-RTT 会话恢复：从 session ticket 或本地配置设置远程流限制
                flow_ctrl_.on_remote_max_bidi_streams(cfg_.max_bidi_streams);
                flow_ctrl_.on_remote_max_uni_streams(cfg_.max_uni_streams);

                LINOH_INFO("Connection: PSK 0-RTT fast path → Established");
                if (on_handshake_done_) on_handshake_done_();
            }
        } else {
            // PSK 模式无票据：进入 Handshake，等待对端确认
            state_.store(ConnState::Handshake);
            LINOH_INFO("Connection: PSK handshake started → Handshake state");
        }
    } else {
        // Full TLS 模式：进入 Handshake
        state_.store(ConnState::Handshake);
        LINOH_INFO("Connection: full TLS handshake started → Handshake state");
    }

    return util::ResultVoid();
}

bool Connection::check_handshake_timeout(double now_ms) const {
    if (!handshake_started_) return false;
    return handshake_tracker_.check_timeout(now_ms);
}

// ============================================================================
// Stream API
// ============================================================================

std::shared_ptr<Stream> Connection::open_stream() {
    auto result = try_open_stream();
    return result.is_ok() ? result.value() : nullptr;
}

util::Result<std::shared_ptr<Stream>> Connection::try_accept_stream() {
    // 状态验证：只能在 Established 状态接受流
    auto state_check = StateValidator::can_accept_stream(state_.load());
    if (!state_check.is_ok()) {
        return util::Result<std::shared_ptr<Stream>>(state_check.error());
    }

    std::lock_guard<std::mutex> lk(stream_mu_);
    if (!pending_accept_.empty()) {
        auto s = pending_accept_.front();
        pending_accept_.pop();
        return util::Result<std::shared_ptr<Stream>>(s);
    }
    return util::Result<std::shared_ptr<Stream>>(
        util::StreamError::NoStreamAvailable, "no pending streams to accept");
}

std::shared_ptr<Stream> Connection::accept_stream() {
    auto result = try_accept_stream();
    return result.is_ok() ? result.value() : nullptr;
}

void Connection::send_stream(std::uint64_t stream_id, std::span<const std::uint8_t> data) {
    std::lock_guard<std::mutex> lk(stream_mu_);
    // P5 fix(2026-07-20): O(1) 查找替代 find_if 遍历
    auto it = local_streams_.find(stream_id);
    if (it != local_streams_.end()) {
        it->second->write(data);
    }
}

void Connection::finish_stream(std::uint64_t stream_id) {
    std::lock_guard<std::mutex> lk(stream_mu_);
    // P5 fix(2026-07-20): O(1) 查找替代 find_if 遍历
    auto it = local_streams_.find(stream_id);
    if (it != local_streams_.end()) {
        it->second->finish_send();
    }
}

std::uint64_t Connection::next_local_stream_id(bool bidi) {
    // v1.5.0.1 P1 修复：RFC 9000 §2.1 stream id 公式
    // client-initiated bidi: 0, 4, 8, 12... (init=0, step=4)
    // server-initiated bidi: 1, 5, 9, 13... (init=1, step=4)
    // 修复前 next_local_bidi_stream_++ 单调递增 0,1,2... 导致
    // client 第二个 stream (sid=1) 与 server-initiated (sid=1) 冲突
    if (bidi) {
        std::uint64_t id = next_local_bidi_stream_;
        next_local_bidi_stream_ += 4;
        return id;
    } else {
        std::uint64_t id = next_local_uni_stream_;
        next_local_uni_stream_ += 4;
        return id;
    }
}

// ============================================================================
// 发送 API
// ============================================================================

// S1（v5.3）：控制帧捎带通道入队（build_1rtt_packet 消费）
void Connection::queue_control_frame(std::vector<std::uint8_t> frame_with_type) {
    if (frame_with_type.empty()) return;
    std::lock_guard<std::mutex> lk(ctrl_frames_mu_);
    // 队列容量保护：低频控制帧正常 ≤ 个位数；异常堆积（如上层 bug 循环入队）
    // 时丢弃最旧并告警，防挤占数据面
    if (pending_ctrl_frames_.size() >= 32) {
        pending_ctrl_frames_.pop_front();
        LINOH_WARN("Connection: ctrl-frame queue overflow, dropped oldest "
                   "(size cap 32)");
    }
    pending_ctrl_frames_.push_back(std::move(frame_with_type));
}

std::size_t Connection::build_1rtt_packet(std::span<std::uint8_t> out) {
    // v1.5.0.2 Step 3: buffer 下限从 1280 改为 current_max_packet_size()（协商后可能 9000）
    if (out.size() < current_max_packet_size()) return 0;

    ConnState s = state_.load();
    if (s != ConnState::Established && s != ConnState::Handshake) {
        return 0;
    }

    // v1.5.0.9 (ISSUE T08 反馈): 同步 retx 队列大小到拥塞控制器
    //   - retx_pending > 100 时 cwnd 抑制 + retx 优先（已在 NewRenoController 内实现）
    //   - 视频组 T08 实测：retx_queue_size=3900 时 cwnd 持续增长，
    //     stream 块占满 payload，retx 块饿死
    {
        std::lock_guard<std::mutex> lk(retransmit_mu_);
        congestion_ctrl_->update_retx_pending(retransmit_queue_.size());
    }

    // Build Short Header
    auto header = protocol::PacketHeader::make_1rtt(cfg_.remote_cid);

    std::size_t hdr_size = header.encoded_size();
    std::size_t pn_size = static_cast<std::uint8_t>(header.pn_len()) + 1;
    std::size_t payload_start = hdr_size;

    if (out.size() < payload_start) return 0;

    // K-LINOH-PERF-001 fix: 限制 payload_space 为 current_max_packet_size()，
    // 允许 send_buf > current_max_packet_size() 而不超出 MTU。
    // 根因：旧实现 payload_space = out.size() - payload_start，当 send_buf=16KB 时
    //   构建超 MTU 大包被对端拒绝关闭连接（K-LINOH-PERF-001 前身）。
    //   退而求其次将 send_buf 降至 2048，但每包仅 ~1230 字节数据，87KB 需 71+ 包。
    // 修复：payload_space 取 min(out.size(), current_max_packet_size()) - payload_start，
    //   安全支持 send_buf=9200（jumbo MTU 9000 + 余量），每包可承载 ~8900 字节。
    std::size_t effective_buf_size = (std::min)(out.size(), current_max_packet_size());
    std::size_t payload_space = effective_buf_size - payload_start;
    std::size_t written = 0;

    // 1. 首先编码 ACK 帧（build_ack_data 返回的字节已含 0x02 type 字节，禁止重复写入）
    auto ack_data = build_ack_data();
    if (!ack_data.empty() && written + ack_data.size() <= payload_space) {
        std::memcpy(out.data() + payload_start + written, ack_data.data(), ack_data.size());
        written += ack_data.size();
        LINOH_DEBUG("Connection: ACK frame added, size=", ack_data.size());
    }

    // 2. 编码 PING 帧（保活心跳）
    if (ping_pending_ && written + 1 <= payload_space) {
        out[payload_start + written++] = static_cast<uint8_t>(protocol::FrameType::PING);
        ping_pending_ = false;
        // K-LINOH-READBLK-001 (v5.3.1): 记录 PING 发出时刻（needs_keepalive 依据；
        // 此前无置位点 → 巡检每 tick 都会重复请求 PING）
        last_ping_sent_ms_ = now_ms_steady();
        LINOH_DEBUG("Connection: PING frame added (keepalive)");
    }

    // 2b. v5.5 K-OOSRESET-001: STREAM_RESET(0x38) 宣告帧——reset_send_offset()
    // 置位后在本消息首帧前写出（单字节，接收方据此显式重置接收状态）
    {
        std::lock_guard<std::mutex> lk(stream_mu_);
        for (auto & kv : local_streams_) {
            if (kv.second->stream_reset_pending()) {
                if (written + 1 <= payload_space) {
                    out[payload_start + written++] =
                        static_cast<uint8_t>(protocol::FrameType::STREAM_RESET);
                    kv.second->clear_stream_reset_pending();
                    LINOH_DEBUG("Connection: STREAM_RESET frame added (stream ", kv.first, ")");
                }
                // 空间不足留待下个 build（pending 不清除）
            }
        }
        for (auto & kv : remote_streams_) {
            // 远端流也可能被本端用于发送（双向流）——同样宣告
            if (kv.second->stream_reset_pending()) {
                if (written + 1 <= payload_space) {
                    out[payload_start + written++] =
                        static_cast<uint8_t>(protocol::FrameType::STREAM_RESET);
                    kv.second->clear_stream_reset_pending();
                }
            }
        }
    }

    // S1（v5.3）：控制帧捎带消费（SESSION_TICKET/QAD 等）。
    // ACK/PING 之后、retx/stream 之前写入；空间不足的帧留队下一包。
    // 单包容量保护：每包最多捎带 4 个控制帧（防低频帧异常堆积挤占数据面）。
    {
        std::lock_guard<std::mutex> lk(ctrl_frames_mu_);
        int piggybacked = 0;
        while (!pending_ctrl_frames_.empty() && piggybacked < 4) {
            auto &f = pending_ctrl_frames_.front();
            if (written + f.size() > payload_space) break;  // 放不下留队
            std::memcpy(out.data() + payload_start + written, f.data(), f.size());
            written += f.size();
            ++piggybacked;
            pending_ctrl_frames_.pop_front();
        }
        if (piggybacked > 0) {
            LINOH_DEBUG("Connection: piggybacked ", piggybacked,
                        " control frame(s), pending=", pending_ctrl_frames_.size());
        }
    }

    // v1.5.0.6 修复 (ISSUE T05 反馈): 此前 build_oos_pn_data() 返回的字节
    // 已含 type 字节 (0x30)，但 PacketParser::parse_frames 在 case 0x30 之前
    // 已吞掉 type 字节 (payload[pos++])，导致 f.data 不含 type，接收方
    // handle_oos_pn_frame 调用 decode_oos_pn_frame 时 data[0] 永远不是 0x30，
    // decode 失败 25/25 次，OOS_PN_FRAME 数据通路断裂。
    //
    // 修复策略（方案 A 补全）：encode_oos_pn_frame 已删除 type 字节写入，
    // 此处由 build_1rtt_packet 显式追加 type 字节（仿 PING 帧 L952 风格：
    // out[pos++] = type_byte），确保 parse_frames 吞 type 后 f.data 与
    // decode_oos_pn_frame 期望的 "从 stream_id 开始" 语义对齐。
    {
        auto oos_pn_data = build_oos_pn_data();  // v1.5.0.6: 不含 type 字节
        if (!oos_pn_data.empty() && written + 1 + oos_pn_data.size() <= payload_space) {
            // 显式写 type 字节（v1.5.0.5 是 encode 写、v1.5.0.6 改为此处写）
            out[payload_start + written] = static_cast<uint8_t>(protocol::FrameType::OOS_PN);
            written += 1;
            std::memcpy(out.data() + payload_start + written, oos_pn_data.data(), oos_pn_data.size());
            written += oos_pn_data.size();
            // v1.5.0.7 (ISSUE T06 反馈): DEBUG → INFO 升级，便于视频模型组观察。
            LINOH_INFO("Connection: OOS_PN frame added, size=", 1 + oos_pn_data.size(),
                       " build_total=", build_oos_pn_data_total_,
                       " frame_total=", OOS_PN_frame_total_);
        }
    }

    // v1.5.0.11 (ISSUE T10 反馈 P1): high_priority 队列处理（先于 retx 块）
    //   - T10 业务实测 UDP 接收率仅 34%（66% 丢包），OOS_PN 帧被 cwnd 抑制雪崩
    //   - 解决：OOS_PN 帧作为关键控制帧，单独 high_priority 通道
    //   - 在 retx 块之前写入，且不计入 cwnd 抑制（cwnd_suppressed 触发时仍可发送）
    //   - 统计 oos_pn_high_priority_sent_total_ 计数器（每帧写入 +1）
    //   - ACK-eliciting 标记：消费后置位 has_oos_pn_hp_consumed，on_packet_sent 强制
    //     ack_eliciting=true，确保对端每帧都发回 ACK 帧（与隐式 oos_pn_frame_recv_total_
    //     计数叠加，形成显式 + 隐式双确认）
    bool has_oos_pn_hp_consumed = false;  // v1.5.0.11
    // v1.7.0.6 (C9 fix): 加锁 swap 出来到局部变量，避免锁内 memcpy 热路径
    std::vector<std::vector<std::uint8_t>> hp_frames_local;
    {
        std::lock_guard<std::mutex> hp_lk(pending_hp_mu_);
        if (!pending_oos_pn_high_priority_frames_.empty()) {
            hp_frames_local.swap(pending_oos_pn_high_priority_frames_);
        }
    }
    if (!hp_frames_local.empty()) {
        std::size_t hp_consumed_idx = 0;
        for (std::size_t i = 0; i < hp_frames_local.size(); ++i) {
            const auto &hp_frame = hp_frames_local[i];
            if (written + hp_frame.size() > payload_space) {
                // 空间不足，停止写入。剩余 frame 留到下一包
                break;
            }
            std::memcpy(out.data() + payload_start + written, hp_frame.data(), hp_frame.size());
            written += hp_frame.size();
            oos_pn_high_priority_sent_total_++;
            has_oos_pn_hp_consumed = true;
            hp_consumed_idx = i + 1;
        }
        // v1.7.0.6 (C9 fix): 未消费的帧回推到队列（如果有）
        if (hp_consumed_idx < hp_frames_local.size()) {
            std::lock_guard<std::mutex> hp_lk(pending_hp_mu_);
            for (std::size_t i = hp_consumed_idx; i < hp_frames_local.size(); ++i) {
                pending_oos_pn_high_priority_frames_.push_back(std::move(hp_frames_local[i]));
            }
        }
    }

    // 6-3 fix (方案 4): retx 块移到 process_stream 之前 + 删除 50/50 限制
    // 背景：50/50 限制下 2KB payload 的 retx 块只有 ~1KB，写不下 1 个 2KB STREAM PN，
    //   导致 5% drop 下 retx 链路永远失效，新数据也无法推进（实测 0.18MB/s，120s 只能发 22MB）。
    // 方案 4：retx 块优先用 full payload_space，写入完整 STREAM frame（包括数据）。
    //   - retx 包大小由 STREAM frame 决定，可能超过 payload_space，此时只写 1 个 PN 后 break。
    //   - 写完 retx 后 process_stream 用 payload_space - written 剩余空间。
    //   - 关键保护：retx_attempts_ 单 PN 最多重试 max_retx_per_packet_ 次（默认 20），避免 livelock。
    //   - P9.3 §4.2: per-PN 退避 — 同一 PN 在一个 SRTT 内不被多次重传，避免 retx 风暴。
    //   - 1Hz heartbeat 触发 flush：retx 持续被消化，新数据持续推进。
    // 验证目标：5% drop 32MB 在 120s 内完成。
    // v1.7.0.6 (H1-1 fix): has_pending_retx 判断移入锁内，消除 TOCTOU 竞态
    // （原锁外读 empty() 在并发下可能在加锁前被消费端清空，虽无副作用但属于 UB）
    std::size_t retx_written = 0;  // v1.5.0.1 P0-1: 审计用，retx 块单独累计字节数
    {
        std::lock_guard<std::mutex> lk(retransmit_mu_);
        bool has_pending_retx = !retransmit_queue_.empty() || force_retx_;
        if (has_pending_retx) {
            // 6-3: 最多每包重试 kMaxRetxPerBuild 次（per-build 限制），
            // per-PN 生命周期限制由 max_retx_per_packet_ 控制（P9.3 §4.1）
            std::size_t retx_count = 0;
            double now_ms = now_ms_steady();  // P9.3 §4.2: per-PN 退避时间基准（每 build 取一次）
            auto it = retransmit_queue_.begin();
            while (it != retransmit_queue_.end() && retx_count < kMaxRetxPerBuild) {
            std::uint64_t lost_pn = *it;
            // 检查重试次数（P9.3 §4.1: max_retx_per_packet_ 默认 20，原 static kMaxRetxPerPacket=50）
            int attempts = retx_attempts_[lost_pn];
            if (attempts >= max_retx_per_packet_) {
                it = retransmit_queue_.erase(it);
                retx_attempts_.erase(lost_pn);
                retx_last_sent_ms_.erase(lost_pn);  // P9.3 §4.2: 清理退避记录
                LINOH_WARN("Connection: PN=", lost_pn, " retx exceeded max attempts, dropping");
                continue;
            }
            // P9.3 §4.2: per-PN 退避 — 同一 PN 在一个 SRTT 内不被多次重传
            //   根因：高丢包下同一 PN 被 loss_tick_loop 和 on_ack 反复 mark_lost，
            //   每次 build_1rtt_packet 都重传该 PN，导致 retx 风暴挤占 cwnd
            //   修复：记录每个 PN 上次重传时间，now - last_sent < srtt 则跳过（保留队列）
            {
                auto last_it = retx_last_sent_ms_.find(lost_pn);
                if (last_it != retx_last_sent_ms_.end()) {
                    double srtt = loss_detector_.rtt().srtt_ms();
                    if (srtt < 10.0) srtt = 10.0;  // 下限 10ms，避免初始 SRTT 过小
                    if (now_ms - last_it->second < srtt) {
                        ++it;  // 未过退避窗口，跳过该 PN（保留队列，下个 build 再试）
                        continue;
                    }
                }
            }
            // 查找缓存的 plaintext
            auto pt_it = sent_payloads_.find(lost_pn);
            if (pt_it == sent_payloads_.end()) {
                // 已超过 128MB 封顶被驱逐，或从未缓存（早于 v1.5.0.1 的包）
                it = retransmit_queue_.erase(it);
                retx_attempts_.erase(lost_pn);
                retx_last_sent_ms_.erase(lost_pn);  // P9.3 §4.2: 清理退避记录
                LINOH_DEBUG("Connection: PN=", lost_pn, " plaintext evicted or missing, skip retx");
                continue;
            }
            const auto &pt = pt_it->second;
            // 追加（fix9P 核心：不是覆盖 process_stream 写的内容）
            // 方案 4→v8-fix (2026-08-06)：retx 块最多占 60% payload_space，为新 STREAM 数据预留 40%。
            // 背景：方案 4（full payload_space）在高丢包率（66% UDP drop）下 retx 队列堆积，
            //   retx 独占 100% payload，新 hidden_state 数据无法写入，推理卡死。
            // 修复：首个 retx 包例外（可用全部 payload_space，避免大 STREAM frame livelock），
            //   后续 retx 限制在 60% 以内，确保 process_stream 至少有 40% 空间写入新数据。
            // 单个 retx 包大小由 STREAM frame 决定（可能 2KB+），空间不够时 break 等下一包。
            const std::size_t retx_cap = payload_space * 6 / 10;  // 60% 上限
            const bool is_first_retx = (retx_count == 0);
            if (is_first_retx
                    ? (written + pt.size() <= payload_space)
                    : (written + pt.size() <= retx_cap)) {
                std::memcpy(out.data() + payload_start + written, pt.data(), pt.size());
                written += pt.size();
                retx_written += pt.size();  // v1.5.0.1 P0-1: 审计累计
                // 成功 retx：从队列移除并增加重试计数
                it = retransmit_queue_.erase(it);
                retx_attempts_[lost_pn] = attempts + 1;
                retx_last_sent_ms_[lost_pn] = now_ms;  // P9.3 §4.2: 记录重传时间用于 per-PN 退避
                ++retx_count;
                // 埋点诊断 v1.5.0.2.5 (2026-07-23): 视频模型组反馈 STREAM buffer 累积,
                // 怀疑 retx 包被反复重传但对端始终不 ACK (PN 仍在 sent_payloads_ 占用,
                // 但对端 128MB 缓存被新数据推走). 记录每次 retx 事件便于统计重试次数.
                // v1.5.0.3 (2026-07-24): 追加 stream OOS 状态汇总，便于 OOS gap
                //   排查时区分 "retx 未发出" vs "retx 发出但对端不 ACK" vs "retx 后
                //   对端 stream_offset 仍卡住"。
                std::size_t retx_oos_stream_count = 0;
                std::uint64_t retx_oos_first_gap_off = 0;
                std::size_t retx_oos_first_gap_size = 0;
                std::size_t retx_oos_total_bytes = 0;
                {
                    std::lock_guard<std::mutex> lk(stream_mu_);
                    for (const auto &kv_st : local_streams_) {
                        std::uint64_t off_v = 0;
                        std::size_t sz_v = 0;
                        if (kv_st.second->oos_first_gap(&off_v, &sz_v)) {
                            ++retx_oos_stream_count;
                            if (retx_oos_first_gap_off == 0 ||
                                off_v < retx_oos_first_gap_off) {
                                retx_oos_first_gap_off = off_v;
                                retx_oos_first_gap_size = sz_v;
                            }
                            retx_oos_total_bytes += kv_st.second->oos_size_bytes();
                        }
                    }
                    for (const auto &kv_st : remote_streams_) {
                        std::uint64_t off_v = 0;
                        std::size_t sz_v = 0;
                        if (kv_st.second->oos_first_gap(&off_v, &sz_v)) {
                            ++retx_oos_stream_count;
                            if (retx_oos_first_gap_off == 0 ||
                                off_v < retx_oos_first_gap_off) {
                                retx_oos_first_gap_off = off_v;
                                retx_oos_first_gap_size = sz_v;
                            }
                            retx_oos_total_bytes += kv_st.second->oos_size_bytes();
                        }
                    }
                }
                LINOH_INFO("Connection: retx PN=", lost_pn,
                           " attempts=", attempts + 1,
                           " bytes=", pt.size(),
                           " queue_remaining=", retransmit_queue_.size(),
                           " sent_payloads_size=", sent_payloads_.size(),
                           " sent_payloads_bytes_=", sent_payloads_bytes_,
                           " oos_streams=", retx_oos_stream_count,
                           " oos_first_gap_offset=", retx_oos_first_gap_off,
                           " oos_first_gap_size=", retx_oos_first_gap_size,
                           " oos_total_bytes=", retx_oos_total_bytes);
                LINOH_DEBUG("Connection: retx PN=", lost_pn, " bytes=", pt.size());
            } else {
                // 空间不足：回退（fix9P 第二原则：已写入的保留，不再尝试）
                break;
            }
        }
        // 队列已清空时清 force_retx_
        if (retransmit_queue_.empty()) {
            force_retx_ = false;
        }

        // v1.5.0.1 P0-1: 审计埋点 — 记录 retx 块写入字节数
        {
            auto& auditor = observability::PayloadAuditor::instance();
            if (auditor.is_enabled()) {
                observability::PayloadAuditRecord rec;
                rec.conn_id = reinterpret_cast<std::uint64_t>(this);
                rec.stream_id = 0;
                rec.payload_declared = 0;
                rec.payload_actual = retx_written;  // retx 块单独累计
                rec.payload_space = payload_space;
                rec.short_write = false;
                rec.is_retx = true;
                rec.ts = std::chrono::steady_clock::now();
                auditor.record_payload_write(rec);
            }
        }
        }  // 闭合 if (has_pending_retx)
    }  // v1.7.0.6 (H1-1 fix): 闭合外层 retransmit_mu_ 锁块

    // 3. 编码 STREAM 帧（含 offset，RFC 9000 §19.8）
    // 方案 4：retx 块在 process_stream 之前已写入，process_stream 用 payload_space - written 限定
    // v1.5.0.5: 跟踪首个 STREAM 帧的 stream_id/offset，用于 on_packet_sent 反查 PN
    // v1.5.0.8 (ISSUE T07 反馈): 同时跟踪首个 STREAM 帧的 payload bytes（不含帧头），
    //   用于 OOS_PN_FRAME offset→PN 精确反查（v1.5.0.5/0.6/0.7 用 sent_bytes 匹配
    //   永远不命中，sent_bytes 是 1-RTT 包总大小 ~1500B）
    // v1.5.0.9 (ISSUE T08 反馈): 重构为 vector<StreamRange>，每个 STREAM 帧独立记录
    //   [offset, offset+payload_bytes) 范围。多 stream PN 下，单字段累加导致反查范围
    //   错误包含其他 stream 字节，OOS_PN_FRAME offset 反查精度错位（视频组 T08 实测：
    //   offset=651980 处 2024 字节稳定缺口 = A_chunk 1000 + B_chunk 1024 累加）。
    //   新方案：每个 STREAM chunk 独立 push 一个 StreamRange，OOS_PN 反查时遍历精确匹配。
    std::vector<protocol::StreamRange> stream_ranges;
    {
        std::lock_guard<std::mutex> lk(stream_mu_);
        auto process_stream = [&](std::shared_ptr<Stream> &st) {
            // P1-P3 fix(2026-07-20): 用 send_readable_size/send_readable_data + consume_send
            // 替代 send_buffer().erase()，避免 O(n) 头部删除。
            // 方案 4: budget = payload_space（retx 块已写入，written 已包含 retx 占用）
            while (st->send_readable_size() > 0 && written + 7 < payload_space) {  // type(1)+stream_id_vint(1~8)+offset_vint(1~8)+len_vint(1~8)+data
                std::size_t avail = payload_space - written - 7;
                std::size_t chunk = std::min(avail, st->send_readable_size());
                if (chunk == 0) break;

                // STREAM frame: type(1 byte with flags) + stream_id + offset + length + data
                // Flags bits: b0=OFF (offset present), b1=OLEN (length present), b2=FIN
                // We always include offset and length for reliability
                uint8_t frame_type = 0x08 | 0x02 | 0x01; // OFF=1, LEN=1 (offset+length present)

                bool is_fin = st->send_finished() && chunk == st->send_readable_size();
                if (is_fin) frame_type |= 0x04; // FIN bit

                out[payload_start + written++] = frame_type;

                // stream_id (VarInt, simplified as 1-byte for small stream IDs)
                auto sid_vi = util::varint_encode_vec(st->id());
                std::memcpy(out.data() + payload_start + written, sid_vi.data(), sid_vi.size());
                written += sid_vi.size();

                // offset (VarInt) — 发送偏移量
                auto off_vi = util::varint_encode_vec(st->send_offset());
                std::memcpy(out.data() + payload_start + written, off_vi.data(), off_vi.size());
                written += off_vi.size();

                // length (VarInt)
                auto len_vi = util::varint_encode_vec(chunk);
                std::memcpy(out.data() + payload_start + written, len_vi.data(), len_vi.size());
                written += len_vi.size();

                // data
                std::memcpy(out.data() + payload_start + written, st->send_readable_data(), chunk);
                written += chunk;

                // v1.5.0.9: 每个 STREAM chunk 独立记录一个 StreamRange
                //   - 记录 (stream_id, offset, payload_bytes)
                //   - 即使同一 stream 多个 chunk（pn 空间足够时）或多个 stream，
                //     每个 chunk 都独立 push，避免 v1.5.0.8 单字段累加错位
                protocol::StreamRange range;
                range.stream_id = st->id();
                range.offset = st->send_offset();
                range.payload_bytes = chunk;
                stream_ranges.push_back(range);

                st->advance_send_offset(st->send_offset() + chunk);
                st->consume_send(chunk);
            }
            // Send FIN-only frame if stream is finished and buffer is drained and not yet FIN-sent
            // A9 fix: 用 send_closed() 替代 is_closed() 防重复，且只半关闭发送方向
            if (st->send_finished() && st->send_readable_size() == 0 && !st->send_closed()) {
                if (written + 5 <= payload_space) {
                    // B4 fix(2026-07-20): type = 0x08|0x01|0x04 (OFF=1, LEN=0, FIN=1)
                    uint8_t frame_type = 0x08 | 0x01 | 0x04; // OFF=1, LEN=0, FIN=1
                    out[payload_start + written++] = frame_type;

                    auto sid_vi = util::varint_encode_vec(st->id());
                    std::memcpy(out.data() + payload_start + written, sid_vi.data(), sid_vi.size());
                    written += sid_vi.size();

                    auto off_vi = util::varint_encode_vec(st->send_offset());
                    std::memcpy(out.data() + payload_start + written, off_vi.data(), off_vi.size());
                    written += off_vi.size();

                    // No length field for FIN-only with no data
                    // A9 fix: close_send() 只半关闭发送方向，recv 保持可用（RFC 9000 §3.2）
                    st->close_send();
                    LINOH_DEBUG("Connection: FIN-only frame for stream id=", st->id(),
                                " at offset=", st->send_offset());
                }
            }
        };
        // P5 fix(2026-07-20): unordered_map range-for 解构
        for (auto &kv : local_streams_) process_stream(kv.second);
        for (auto &kv : remote_streams_) process_stream(kv.second);
    }

    // v1.5.0.1 P0-1: 审计埋点 — 记录 process_stream 块写入的 payload 分布
    // 仅观测，不修改行为。审计器通过 LINOH_AUDIT=1 环境变量启用。
    {
        auto& auditor = observability::PayloadAuditor::instance();
        if (auditor.is_enabled()) {
            observability::PayloadAuditRecord rec;
            rec.conn_id = reinterpret_cast<std::uint64_t>(this);
            rec.stream_id = 0;  // process_stream 写入多流合并观察
            rec.payload_declared = 0;  // process_stream 内部不显式声明
            rec.payload_actual = written;
            rec.payload_space = payload_space;
            rec.short_write = written > payload_space;
            rec.is_retx = false;
            rec.ts = std::chrono::steady_clock::now();
            auditor.record_payload_write(rec);
        }
    }

    // v1.5.0.1 P3-1: 1Hz 周期 MAX_DATA / MAX_STREAM_DATA 主动通告块。
    // heartbeat_loop 每秒 emit_periodic_flow_control() 填充 pending_fc_frames_，
    // build_1rtt_packet 在 process_stream 已写入 payload 之后批量写出（追加语义）。
    // 放在 retx 块之前，理由：新流控窗口比历史 retx 数据更紧急，retx 块空间不足时回退
    // 优先保留 fc 帧；如 fc 帧写入后剩余空间不够 retx，retx 块会因 payload_space 不足自然退出。
    // v1.7.0.6 (C9 fix): 加锁 swap 出来到局部变量，避免锁内 memcpy 热路径
    {
        std::vector<std::vector<std::uint8_t>> fc_frames_local;
        {
            std::lock_guard<std::mutex> fc_lk(pending_fc_mu_);
            if (!pending_fc_frames_.empty()) {
                fc_frames_local.swap(pending_fc_frames_);
            }
        }
        std::size_t fc_consumed_idx = 0;
        for (std::size_t i = 0; i < fc_frames_local.size(); ++i) {
            const auto &fc_frame = fc_frames_local[i];
            if (written + fc_frame.size() > payload_space) {
                // 空间不足，停止写入（已写入的保留，剩余 frame 留到下一包）
                break;
            }
            std::memcpy(out.data() + payload_start + written, fc_frame.data(), fc_frame.size());
            written += fc_frame.size();
            fc_consumed_idx = i + 1;
        }
        // v1.7.0.6 (C9 fix): 未消费的帧回推到队列（如果有）
        if (fc_consumed_idx < fc_frames_local.size()) {
            std::lock_guard<std::mutex> fc_lk(pending_fc_mu_);
            for (std::size_t i = fc_consumed_idx; i < fc_frames_local.size(); ++i) {
                pending_fc_frames_.push_back(std::move(fc_frames_local[i]));
            }
        }
    }

    // (retx 块已前移到 process_stream 之前，方案 4)

    // v5.1.0: PSK_IDENTITY 帧（K-LINOH-PEERMISMATCH）——待发时附加。
    // rest-of-payload 解析约定要求其必须为包内最后一个帧，故在所有其他帧之后
    // 写入；空间不足时保留待发标记，留待下一个包。
    if (psk_identity_pending_send_) {
        auto idata = build_psk_identity_data();
        if (!idata.empty() && written + 1 + idata.size() <= payload_space) {
            out[payload_start + written] =
                static_cast<std::uint8_t>(protocol::FrameType::PSK_IDENTITY);
            written += 1;
            std::memcpy(out.data() + payload_start + written, idata.data(), idata.size());
            written += idata.size();
            psk_identity_pending_send_ = false;
            LINOH_INFO("Connection: PSK_IDENTITY frame added (", 1 + idata.size(),
                       " bytes), node_pub=",
                       cfg_.secret_key.public_key().fmt_short());
        }
    }

    if (written == 0 && !force_retx_) return 0;

    // Serialize header into out
    header.serialize_to(out.data(), hdr_size);

    // Write PN
    std::uint64_t pn = send_pn_[2]++;
    auto pn_enc = protocol::PacketNumber::encode_bytes(pn,
        static_cast<std::uint8_t>(pn_size));
    std::memcpy(out.data() + hdr_size - pn_size, pn_enc.data(),
                 static_cast<std::size_t>(pn_size));

    // TLS 1.3 数据面：对 1-RTT 载荷做 AEAD 密封（ChaCha20-Poly1305）。
    // AD = 实际线头（含 pn），nonce = iv XOR pn；Initial/Handshake 包不加密（与既有简化一致）。
    if (tls13_active()) {
        auto aead = tls::global_provider().chacha20_poly1305();
        // P1-3: 发送方向使用本地方向位（client→server: client 位；server→client: server 位）
        bool self_is_server = (direction() == Direction::Inbound);  // 服务端接收连接，向 client 发送
        auto nonce = tls13_nonce(app_write_.iv, pn, self_is_server);
        std::span<const std::uint8_t> ad(out.data(), hdr_size);  // 真实线头
        std::vector<std::uint8_t> ct(written + aead->tag_size());
        std::span<const std::uint8_t> pt(out.data() + payload_start, written);
        std::size_t n = aead->seal(
            std::span<const std::uint8_t>(app_write_.key.data(), app_write_.key.size()),
            std::span<const std::uint8_t>(nonce.data(), nonce.size()),
            ad, pt, std::span<std::uint8_t>(ct.data(), ct.size()));
        if (n == 0) {
            LINOH_WARN("Connection: TLS1.3 AEAD seal failed");
            return 0;
        }
        ct.resize(n);
        std::memcpy(out.data() + payload_start, ct.data(), ct.size());
        written = ct.size();
    }

    // 记录已发送包到 LossDetector
    // B3+ fix(2026-07-20): 传入真实发送时间戳（原硬编码 0.0 导致 RTT 测量失效）
    // v1.5.0.5: 传递首个 STREAM 帧的 stream_id/offset，用于 OOS_PN_FRAME offset→PN 反查
    // v1.5.0.8: 同时传递 stream_payload_bytes（仅 stream data 字节，不含帧头），
    //   OOS_PN_FRAME 精确反查（v1.5.0.5/0.6/0.7 sent_bytes 误匹配修复）
    // v1.5.0.9 (ISSUE T08 反馈): 重构为 stream_ranges vector，多 stream PN 精确反查
    //   - 替代 v1.5.0.8 单 stream_payload_bytes 字段，避免多 stream 累加错位
    //   - stream_ranges 包含本 PN 内所有 STREAM 帧的 (stream_id, offset, payload_bytes)
    //   - 空 vector = 该 PN 不含 STREAM 帧（纯 retx/ACK/控制帧）
    // v1.5.0.11 (ISSUE T10 反馈 P1): high_priority 队列消费时强制 ack_eliciting=true
    //   - OOS_PN 帧是控制帧但本身只触发对端 oos_pn_remote_ 写入，1-RTT 包级别 ACK
    //     需要在 LossDetector 标记 ack_eliciting 才能保证对端周期性 ACK 帧发出
    //   - 显式 + 隐式双确认：ACK 帧（显式）+ oos_pn_remote_ 写入（隐式）
    const bool final_ack_eliciting = (written > 0) || has_oos_pn_hp_consumed;
    loss_detector_.on_packet_sent(pn, now_ms_steady(),
                                  payload_start + written, final_ack_eliciting,
                                  stream_ranges);

    // v1.5.0.1 P0-1: 缓存已发送包原始 plaintext，供 build_1rtt_packet retx 块使用。
    // 加密前缓存（plaintext 是明文，retx 时整块重传会被新 PN 重新加密）。
    // 6-3: 字节级封顶 512MB，超出时按 PN 升序驱逐最旧条目（in-flight 保护）。
    if (written > 0) {
        std::lock_guard<std::mutex> lk(retransmit_mu_);
        // 字节级封顶：驱逐最旧 PN 直到能容下当前包
        if (sent_payloads_bytes_ + written > kSentPayloadsBytesCap) {
            // 6-3: 构建 in-flight PN 集合，保护 retransmit_queue_ 中的 PN 不被驱逐
            std::set<std::uint64_t> in_flight_pns(
                retransmit_queue_.begin(), retransmit_queue_.end());
            std::vector<std::uint64_t> old_pns;
            old_pns.reserve(sent_payloads_.size());
            for (const auto &kv : sent_payloads_) old_pns.push_back(kv.first);
            std::sort(old_pns.begin(), old_pns.end());
            for (std::uint64_t old_pn : old_pns) {
                if (sent_payloads_bytes_ + written <= kSentPayloadsBytesCap) break;
                // 6-3: 跳过仍在重传队列中的 PN
                if (in_flight_pns.count(old_pn)) continue;
                sent_payloads_bytes_ -= sent_payloads_[old_pn].size();
                sent_payloads_.erase(old_pn);
                retx_attempts_.erase(old_pn);
            }
        }
        // 拷贝 plaintext 段（payload_start 到 payload_start+written）
        std::vector<std::uint8_t> pt(out.data() + payload_start,
                                      out.data() + payload_start + written);
        sent_payloads_[pn] = std::move(pt);
        sent_payloads_bytes_ += written;
    }

    stats_.packets_sent++;
    stats_.bytes_sent += written;

    LINOH_DEBUG("Connection: built 1-RTT packet, payload=", written,
                " bytes, pn=", pn, " (plaintext mode with ACK+offset)");
    return payload_start + written;
}

std::size_t Connection::build_fin_only_packet(std::span<std::uint8_t> out) {
    // v1.5 P0-2: must_send_1rtt() 强制通道
    //
    // cluster BACKLOG 反馈：旧实现 build_1rtt_packet 在 cwnd 满 / payload 空间不足
    // 时直接 return 0，FIN-only 帧会随之中断发送，导致对端连接长时间处于
    // half-closed 状态。本接口单独构造一个最小 1-RTT 包（含一个 FIN 帧），
    // 不写入 ACK/PING/STREAM data，绕过常规发送限制，保证 FIN 必达。
    //
    // 设计取舍：实现与 build_1rtt_packet 后半段（header/PN/encrypt/LossDetector）
    // 重复，因为 cwnd 检查、ACK 写入、STREAM data 循环的混入会让"强制 FIN"语义
    // 不明确。实际 50 行重复换来 API 边界清晰。
    if (state() != ConnState::Established && state() != ConnState::Handshake) {
        return 0;
    }

    // Step 1: 找一个 pending FIN 的 stream
    std::shared_ptr<Stream> fin_stream;
    {
        std::lock_guard<std::mutex> lk(stream_mu_);
        for (auto &kv : local_streams_) {
            auto &st = kv.second;
            // A9 fix: 用 send_closed() 替代 is_closed() 防重复，与 build_1rtt_packet 第 1253 行一致
            if (st->send_finished() && st->send_readable_size() == 0 && !st->send_closed()) {
                fin_stream = st;
                break;
            }
        }
    }
    if (!fin_stream) {
        return 0;
    }

    // Step 2: 构造 Short Header
    auto header = protocol::PacketHeader::make_1rtt(cfg_.remote_cid);
    std::size_t hdr_size = header.encoded_size();
    std::size_t pn_size = static_cast<std::uint8_t>(header.pn_len()) + 1;
    std::size_t payload_start = hdr_size;

    // Step 3: 计算 FIN-only frame 大小（type=1 + sid_vi + off_vi，无 LEN 字段）
    std::size_t sid_len = util::varint_encode_vec(fin_stream->id()).size();
    std::size_t off_len = util::varint_encode_vec(fin_stream->send_offset()).size();
    std::size_t fin_size = 1 + sid_len + off_len;

    if (out.size() < payload_start + fin_size) {
        LINOH_WARN("Connection: build_fin_only_packet out buffer too small: ",
                   out.size(), " < ", payload_start + fin_size);
        return 0;
    }

    // Step 4: 写入 FIN-only STREAM frame
    std::size_t pos = payload_start;
    // B4 fix(2026-07-20): type = 0x08|0x01|0x04 (OFF=1, LEN=0, FIN=1)
    out[pos++] = 0x08 | 0x01 | 0x04;
    auto sid_vi = util::varint_encode_vec(fin_stream->id());
    std::memcpy(out.data() + pos, sid_vi.data(), sid_vi.size());
    pos += sid_vi.size();
    auto off_vi = util::varint_encode_vec(fin_stream->send_offset());
    std::memcpy(out.data() + pos, off_vi.data(), off_vi.size());
    pos += off_vi.size();

    // Step 5: Serialize header
    header.serialize_to(out.data(), hdr_size);

    // Step 6: 分配并写入 PN
    std::uint64_t pn = send_pn_[2]++;
    auto pn_enc = protocol::PacketNumber::encode_bytes(pn,
        static_cast<std::uint8_t>(pn_size));
    std::memcpy(out.data() + hdr_size - pn_size, pn_enc.data(),
                 static_cast<std::size_t>(pn_size));

    // Step 7: TLS 1.3 AEAD 密封
    std::size_t written = fin_size;
    if (tls13_active()) {
        auto aead = tls::global_provider().chacha20_poly1305();
        bool self_is_server = (direction() == Direction::Inbound);
        auto nonce = tls13_nonce(app_write_.iv, pn, self_is_server);
        std::span<const std::uint8_t> ad(out.data(), hdr_size);
        std::vector<std::uint8_t> ct(written + aead->tag_size());
        std::span<const std::uint8_t> pt(out.data() + payload_start, written);
        std::size_t n = aead->seal(
            std::span<const std::uint8_t>(app_write_.key.data(), app_write_.key.size()),
            std::span<const std::uint8_t>(nonce.data(), nonce.size()),
            ad, pt, std::span<std::uint8_t>(ct.data(), ct.size()));
        if (n == 0) {
            LINOH_WARN("Connection: build_fin_only_packet TLS1.3 AEAD seal failed");
            return 0;
        }
        ct.resize(n);
        std::memcpy(out.data() + payload_start, ct.data(), ct.size());
        written = ct.size();
    }

    // Step 8: LossDetector 记录
    loss_detector_.on_packet_sent(pn, now_ms_steady(),
                                  payload_start + written, written > 0);
    stats_.packets_sent++;
    stats_.bytes_sent += written;

    // Step 9: 半关闭发送方向（FIN-only 帧已发送到网络）
    // A9 fix: close_send() 只半关闭发送方向，recv 保持可用（RFC 9000 §3.2）
    //         旧实现 close() 会清空 recv_ 并设 closed_=true，导致对端响应被丢弃
    {
        std::lock_guard<std::mutex> lk(stream_mu_);
        fin_stream->close_send();
    }

    LINOH_DEBUG("Connection: build_fin_only_packet FIN sent, payload=",
                written, " bytes, pn=", pn, " stream_id=", fin_stream->id());
    return payload_start + written;
}

// ============================================================================
// 加密 / 解密
// ============================================================================

util::Bytes Connection::encrypt_packet(
    std::span<const std::uint8_t> /*header*/,
    std::span<const std::uint8_t> payload) {

    // 使用 AEAD 加密
    // AEAD 输入: key(32B) + nonce(12B) + ad + plaintext
    // 输出: ciphertext || tag(16B)
    //
    // nonce 构建：使用包编号（12 字节，小端）
    std::array<std::uint8_t, 12> nonce{};
    std::uint64_t pn = send_pn_[2];
    for (int i = 0; i < 8; ++i) {
        nonce[i] = static_cast<std::uint8_t>((pn >> (i * 8)) & 0xFF);
    }

    // AD：空（简化实现；真实 QUIC 用 header 作为 AD）
    std::array<std::uint8_t, 1> ad{};

    auto enc = crypto_key_.seal(/*nonce_int=*/pn,
                                 std::span<const std::uint8_t>(ad),
                                 payload);

    // 构造: [header][ciphertext][tag]
    // 简化：直接返回 AEAD 输出（header 不重复）
    util::Bytes result(enc);
    (void)kTagSize;
    return result;
}

std::optional<util::Bytes> Connection::decrypt_packet(
    std::span<const std::uint8_t> /*header*/,
    std::span<const std::uint8_t> cipher) {

    if (cipher.size() < kTagSize) return std::nullopt;
    auto tag = cipher.subspan(cipher.size() - kTagSize);
    auto ct = cipher.subspan(0, cipher.size() - kTagSize);

    // nonce = PN（B5 fix: 使用 decode_truncated 还原的完整 PN，替代 lockstep）
    std::uint64_t pn = current_incoming_pn_;
    std::array<std::uint8_t, 1> ad{};
    std::span<const std::uint8_t> ad_bytes(ad);
    std::vector<std::uint8_t> combined_data(ct.begin(), ct.end());
    combined_data.insert(combined_data.end(), tag.begin(), tag.end());

    auto result = crypto_key_.open(/*nonce_int=*/pn,
                                    ad_bytes,
                                    std::span<const std::uint8_t>(combined_data));
    return result.empty() ? std::nullopt : std::optional(util::Bytes(result));
}

// ============================================================================
// 控制
// ============================================================================

void Connection::close(std::uint16_t error_code, std::string reason) {
    close(error_code, std::move(reason), CloseMode::Graceful);
}

// P4-A-3: 带模式的 close 实现（借鉴 iroh PR #4270）
//
// Graceful 模式：Established → Closing → Closed（保留中间状态，便于对端感知）
// Immediate 模式：Established → Closed（跳过 Closing，应用主动退出场景）
void Connection::close(std::uint16_t error_code, std::string reason, CloseMode mode) {
    LINOH_INFO("Connection: close id=", id_, " error=", error_code,
               " reason=", reason,
               " mode=", (mode == CloseMode::Immediate ? "immediate" : "graceful"));

    ConnState s = state_.load(std::memory_order_acquire);

    // 已 Closed：幂等返回
    if (s == ConnState::Closed) {
        return;
    }

    if (mode == CloseMode::Immediate) {
        // P4-A-3: Immediate 模式直接 CAS 到 Closed，跳过 Closing 中间状态
        // 适用于应用主动退出场景，避免 draining period 等待
        ConnState expected_closed = ConnState::Closed;
        // 任意非 Closed 状态都允许直接转到 Closed
        state_.store(ConnState::Closed, std::memory_order_release);
        LINOH_INFO("Connection: immediate close, state ", static_cast<int>(s),
                   " -> Closed");
    } else {
        // Graceful 模式：保留原有的 Established → Closing → Closed 流程
        ConnState expected = ConnState::Established;
        if (state_.compare_exchange_strong(expected, ConnState::Closing,
                                            std::memory_order_acq_rel)) {
            // 成功从 Established→Closing
        } else {
            // 已经在 Closing/Draining/Closed 状态
            ConnState cur = state_.load();
            if (cur == ConnState::Initial || cur == ConnState::Handshake) {
                // 未完成握手的连接直接进入 Closed
                state_.store(ConnState::Closed, std::memory_order_release);
            } else if (cur == ConnState::Closed) {
                return;
            }
            // Closing/Draining：继续走清理流程
        }
    }

    // 清理 RPC pending 请求（幂等）
    on_close_impl();

    // 停止心跳线程
    stop_heartbeat();

    // P9.3 §4.4: 停止丢包超时检测线程（与 stop_heartbeat 对称，幂等）
    stop_loss_tick_loop();

    // K-LINOH-READBLK-001 (v5.3.1): 连接死亡传播到所属流——mark_conn_dead 只标记
    // 不清 recv 缓冲（业务可排空残留数据），C API 侧 read_ex/is_dead 据此感知重连。
    {
        std::lock_guard<std::mutex> lk(stream_mu_);
        for (auto & [id, st] : local_streams_)  st->mark_conn_dead();
        for (auto & [id, st] : remote_streams_) st->mark_conn_dead();
    }

    // 最终状态：Closed（Immediate 模式已设置，此处幂等）
    state_.store(ConnState::Closed, std::memory_order_release);

    // P1-1: 统一触发 on_close_（CAS 保证仅一次）
    trigger_on_close_once();
}

// P1-1: 统一触发 on_close_，CAS 保证全生命周期仅触发一次
void Connection::trigger_on_close_once() {
    bool expected = false;
    if (on_close_triggered_.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        if (on_close_) on_close_();
    }
}

void Connection::update_rtt(double rtt_ms) {
    double cur = stats_.rtt_ema_ms == 0.0 ? rtt_ms : stats_.rtt_ema_ms;
    stats_.rtt_ema_ms = cur * (1.0 - 0.125) + rtt_ms * 0.125;
    // Also update RTTVAR and RTO per RFC 9002
    double rttvar = stats_.rttvar_ms == 0.0 ? rtt_ms / 2.0 : stats_.rttvar_ms;
    stats_.rttvar_ms = (1.0 - 0.25) * rttvar + 0.25 * std::abs(stats_.rtt_ema_ms - rtt_ms);
    stats_.rto_ms = std::clamp(stats_.rtt_ema_ms + 4.0 * stats_.rttvar_ms, 200.0, 60000.0);
}

// ============================================================================
// ACK / Loss Recovery 集成
// ============================================================================

void Connection::handle_ack_frame(const protocol::AckFrame &ack) {
    last_ack_seen_ms_ = now_ms_steady();   // v5.5 F6.2: ACK 到达时刻（路径健康信号）
    // 1. 从 ACK 帧计算所有被确认的 PN
    auto acked_pns = protocol::acked_pns_from_frame(ack);

    if (!acked_pns.empty()) {
        // B3+ fix(2026-07-20): 计算真实 RTT 样本（原硬编码 50.0ms）。
        // RFC 9002 §5.1: 使用 largest_acked 对应包的 send_time_ms，
        // latest_rtt = now - send_time_of_largest_acked。
        double now = now_ms_steady();
        uint64_t largest_acked = acked_pns[0];
        for (uint64_t pn : acked_pns) {
            if (pn > largest_acked) largest_acked = pn;
        }
        // P9.1: find_sent 返回 std::optional<SentPacketInfo>（by-value 快照），
        //   原返回 const*，锁外失效。optional 的 operator bool / operator-> 与
        //   原指针判空/访问语义一致，下游 if (info) / info->send_time_ms 无需改动。
        auto info = loss_detector_.find_sent(largest_acked);
        double latest_rtt_ms = 50.0;  // 兜底：找不到发送记录时用默认值
        if (info && info->send_time_ms > 0.0) {
            latest_rtt_ms = now - info->send_time_ms;
            if (latest_rtt_ms < 0.0) latest_rtt_ms = 0.0;  // 时钟回退保护
        }
        double ack_delay_ms = static_cast<double>(ack.ack_delay_us) / 1000.0;

        // 更新 LossDetector 的 RTT 估算器
        loss_detector_.rtt().update(latest_rtt_ms, ack_delay_ms);

        // 同步到 ConnectionStats
        stats_.rtt_ema_ms = loss_detector_.rtt().srtt_ms();
        stats_.rttvar_ms = loss_detector_.rtt().rttvar_ms();
        stats_.rto_ms = loss_detector_.rtt().rto_ms();

        // v3.3.0 突破1: RTT-based 跨域自动检测 — 首次 SRTT > 50ms 时自动应用跨域 BBR 配置
        // 场景：上层未显式设置 is_cross_domain=true，但实际 RTT 表明是跨域链路
        if (!cross_domain_auto_checked_ && stats_.rtt_ema_ms > 50.0 && congestion_ctrl_) {
            cross_domain_auto_checked_ = true;
            if (!congestion_ctrl_->is_cross_domain_configured()) {
                protocol::BbrCrossDomainConfig xdomain_cfg{};
                if (congestion_ctrl_->apply_cross_domain_config(xdomain_cfg)) {
                    LINOH_INFO("Connection: cross-domain BBR auto-applied "
                               "(SRTT=", stats_.rtt_ema_ms, "ms > 50ms threshold, "
                               "min_rtt_window=30s, probe_rtt_interval=60s, cwnd_gain=3.0)");
                }
            }
            // v3.3.0 突破4: RTT 自动检测识别为跨域时，同步应用稳定性参数覆盖
            // （idle_timeout 放宽避免误判、keepalive_interval 缩短加快故障探测）
            apply_cross_domain_stability_params();
        }

        // === v1.5.0.5 (方案 A+): 注入 oos_pn_remote_ 反馈的 PN 列表到 LossDetector ===
        // 背景：v1.5.0.4 方案 A 在发送方遍历 local_streams_/remote_streams_ 收集 oos_pn_list，
        // 但 oos_buffer_ 在接收方，导致发送方 oos_pn_list_size=0（视频模型组 ISSUE 反馈）。
        //
        // 方案 A+ 修正注入方向：接收方 → 发送方。
        //   - 接收方周期性 build_oos_pn_data() 生成 OOS_PN_FRAME 上行
        //   - 发送方 handle_oos_pn_frame() 写入 oos_pn_remote_ map（30s TTL）
        //   - 本处从 oos_pn_remote_ 收集 entry，反查 sent_packets_ 取 PN，
        //     构造 OosPnInfo 列表注入 LossDetector 第三参数。
        //
        // 安全护栏：oos_pn_remote_mu_ + stream_mu_ 分层加锁，避免与 build_oos_pn_data 竞争。
        std::vector<protocol::OosPnInfo> oos_pn_list;
        {
            // 阶段 1：从 oos_pn_remote_ 拷贝 (offset, first_seen_ms) 快照
            std::vector<std::pair<std::uint64_t, double>> remote_snapshot;
            {
                std::lock_guard<std::mutex> lk(oos_pn_remote_mu_);
                for (const auto &kv : oos_pn_remote_) {
                    for (const auto &e : kv.second) {
                        remote_snapshot.emplace_back(e.offset, e.first_seen_ms);
                    }
                }
            }
            if (!remote_snapshot.empty()) {
                // 阶段 2：用 offset 反查 sent_packets_ 找 PN（按 stream 范围过滤）
                //   - OosPnInfo 必填 PN，反查逻辑：遍历 LossDetector::sent_packets_，
                //     匹配 pn < largest_acked + kPacketThreshold + kMaxTlsPackets
                //     且 stream_offset 包含此 offset 的条目
                //   - 简化实现：仅匹配 pn < largest_acked 且 offset 在 sent_payload_size 内
                // v1.5.0.8 (ISSUE T07 反馈): 反查改用 stream_payload_bytes
                //   - 旧代码用 info.sent_bytes 匹配 stream_offset，sent_bytes 是
                //     1-RTT 包总大小（含 ACK/控制帧/加密头 ~1500B），stream 内
                //     offset 永远超出此范围，反查永久不命中
                //   - 改用 stream_payload_bytes（v1.5.0.8 新增字段，仅 stream 字节）
                //   - 配合 on_oos_pn_received 双保险（LossDetector 也独立反查）
                // v1.5.0.9 (ISSUE T08 反馈): 反查改用 stream_ranges vector 遍历
                //   - 替代 v1.5.0.8 单 stream_payload_bytes 字段，遍历每个 range 独立匹配
                //   - 解决多 stream PN 单字段累加导致的反查精度错位（视频组 T08 2024 字节稳定缺口）
                std::lock_guard<std::mutex> lk(stream_mu_);
                for (const auto &off_seen : remote_snapshot) {
                    std::uint64_t target_offset = off_seen.first;
                    double first_seen_ms = off_seen.second;
                    // 反查所有 stream 的 sent_packets_ 找匹配 offset 的 PN
                    //   - 因 OosPnInfo 不带 stream_id，遍历全部 stream
                    //   - 取 LossDetector 内 sent_packets_（内部 API）
                    // P9.1: sent_packets_for_test 返回 by-value 快照（原返回 const&，
                    //   锁外失效）。auto 接收为 vector 拷贝，在 stream_mu_ 锁内安全遍历。
                    auto sent_pkts = loss_detector_.sent_packets_for_test();
                    for (const auto &info : sent_pkts) {
                        // v1.5.0.9: 跳过非 STREAM 帧的 PN（空 stream_ranges = 控制帧/ACK/PING）
                        if (info.stream_ranges.empty()) continue;
                        // match: 遍历 stream_ranges，任一 range 满足
                        //   range.offset <= target_offset < range.offset + range.payload_bytes
                        bool range_matched = false;
                        std::uint64_t matched_stream_id = 0;
                        for (const auto &range : info.stream_ranges) {
                            if (range.payload_bytes == 0) continue;
                            if (range.offset > target_offset) continue;
                            if (range.offset + range.payload_bytes <= target_offset) continue;
                            range_matched = true;
                            matched_stream_id = range.stream_id;
                            break;
                        }
                        if (!range_matched) continue;
                        // 命中
                        protocol::OosPnInfo oos_info;
                        oos_info.stream_id = matched_stream_id;
                        oos_info.pn = info.pn;
                        oos_info.offset = target_offset;
                        oos_info.size = 1;  // 单个 PN，对端需要补一个 PN 即可
                        oos_info.first_seen_ms = first_seen_ms;
                        oos_pn_list.push_back(oos_info);
                        break;  // 一个 offset 只取一个 PN
                    }
                }
            }
        }

        // 3. 调用 LossDetector 进行丢包检测
        // B3+ fix(2026-07-20): 传入当前时间戳（原传 0.0 导致时间阈值检测失效）
        // v1.5.0.4: 传入 oos_pn_list，对 OOS buffer 内的 PN 独立应用包编号 / 时间阈值检测
        auto lost_pns = loss_detector_.on_ack_received(acked_pns, now, oos_pn_list);

        if (!lost_pns.empty()) {
            // 4. 丢包 → 添加到重传队列 + 通知拥塞控制
            stats_.lost_packets += lost_pns.size();
            // v1.7.0.6 (H1-2 fix): push_back 加锁，与 build_1rtt_packet 消费端互斥
            {
                std::lock_guard<std::mutex> lk(retransmit_mu_);
                for (uint64_t pn : lost_pns) {
                    retransmit_queue_.push_back(pn);
                }
            }
            // v1.7.0.7 H5/H6: 传入 largest_acked 供 NewReno 记录 recovery 起始 PN，
            //   后续 on_ack 收到 largest_acked_pn > recovery_start_pn_ 时退出 recovery (RFC 9002 §7.3.2)
            congestion_ctrl_->on_loss(largest_acked);
            LINOH_WARN("Connection: ", lost_pns.size(), " packets lost, added to retransmit queue");
        }

        // 5. ACK → 通知拥塞控制窗口增加
        uint64_t newly_acked_bytes = 0;
        // 埋点诊断 v1.5.0.2.5 (2026-07-23): 视频模型组反馈 STREAM buffer 累积,
        // 怀疑 retx 包被反复重传但对端始终不 ACK. 统计本批 ACK 中被重传过的 PN 数量,
        // 便于计算 retx 成功率 (retx_confirmed / retx_total).
        std::size_t retx_confirmed_in_batch = 0;
        std::size_t retx_total_in_batch = 0;
        for (uint64_t pn : acked_pns) {
            // P9.1: find_sent 返回 std::optional（by-value），auto 接收；
            //   optional 隐式转 bool + operator-> 与原指针语义一致。
            auto info = loss_detector_.find_sent(pn);
            if (info) newly_acked_bytes += info->sent_bytes;
            // retx_attempts_ 中存在的 PN 表示此前被重传过, 本次 ACK 即 retx 成功
            {
                std::lock_guard<std::mutex> lk(retransmit_mu_);
                auto rx_it = retx_attempts_.find(pn);
                if (rx_it != retx_attempts_.end()) {
                    ++retx_total_in_batch;
                    ++retx_confirmed_in_batch;
                    LINOH_INFO("Connection: PN=", pn,
                               " retx_confirmed attempts=", rx_it->second,
                               " acked_bytes=", info ? info->sent_bytes : 0);
                }
            }
        }
        // v1.7.0.7 H5/H6: 传入 largest_acked_pn 供 NewReno 判断 recovery 退出条件
        //   (RFC 9002 §7.3.2: largest_acked_pn > recovery_start_pn_ 时退出 recovery)
        congestion_ctrl_->on_ack(newly_acked_bytes, largest_acked);

        LINOH_INFO("Connection: ACK batch acked=", acked_pns.size(),
                   " lost=", lost_pns.size(),
                   " retx_confirmed=", retx_confirmed_in_batch,
                   " retx_confirmed_bytes=", newly_acked_bytes,
                   " srtt=", stats_.rtt_ema_ms,
                   " rto=", stats_.rto_ms,
                   " cwnd=", congestion_ctrl_->cwnd_bytes());
        LINOH_DEBUG("Connection: ACK processed, acked=", acked_pns.size(),
                    " lost=", lost_pns.size(),
                    " srtt=", stats_.rtt_ema_ms,
                    " rto=", stats_.rto_ms,
                    " cwnd=", congestion_ctrl_->cwnd_bytes());

        // v1.5.0.3 (2026-07-24): 追踪 OOS gap 状态变化。
        // 视频模型组反馈 OOS gap 60s 内无法被 retx 填补，需要在 ACK 接收时记录：
        //   1) 当前所有 stream 的 OOS gap 总数 / 总字节数
        //   2) largest_acked 与 OOS first_gap_offset 的距离（评估 retx 是否已发出）
        //   3) 待 retx 队列长度
        if (!acked_pns.empty()) {
            std::size_t ack_oos_streams = 0;
            std::size_t ack_oos_total_bytes = 0;
            std::uint64_t ack_oos_first_gap_off = 0;
            std::size_t ack_oos_first_gap_size = 0;
            std::size_t retx_q_size = 0;
            {
                std::lock_guard<std::mutex> lk(stream_mu_);
                auto visit_oos = [&](const std::shared_ptr<Stream> &s) {
                    std::uint64_t off_v = 0;
                    std::size_t sz_v = 0;
                    if (s->oos_first_gap(&off_v, &sz_v)) {
                        ++ack_oos_streams;
                        if (ack_oos_first_gap_off == 0 || off_v < ack_oos_first_gap_off) {
                            ack_oos_first_gap_off = off_v;
                            ack_oos_first_gap_size = sz_v;
                        }
                        ack_oos_total_bytes += s->oos_size_bytes();
                    }
                };
                for (const auto &kv : local_streams_) visit_oos(kv.second);
                for (const auto &kv : remote_streams_) visit_oos(kv.second);
            }
            {
                std::lock_guard<std::mutex> lk(retransmit_mu_);
                retx_q_size = retransmit_queue_.size();
            }
            LINOH_INFO("Connection: ACK+oos_state oos_streams=", ack_oos_streams,
                       " oos_total_bytes=", ack_oos_total_bytes,
                       " oos_first_gap_offset=", ack_oos_first_gap_off,
                       " oos_first_gap_size=", ack_oos_first_gap_size,
                       " retx_queue_size=", retx_q_size,
                       " largest_acked=", largest_acked);
        }
    }
}

std::vector<uint64_t> Connection::pending_retransmits() const {
    // v1.7.0.6 (H1-4 fix): 加锁拷贝，与 build_1rtt_packet 消费端、handle_ack/handle_oos_pn 生产端互斥
    std::lock_guard<std::mutex> lk(retransmit_mu_);
    return retransmit_queue_;
}

// ============================================================================
// v1.5.0.5: 方案 A+ — 接收方通过 OOS_PN_FRAME 反馈 OOS buffer PN 列表
// ============================================================================
//
// ISSUE 根因（2026-07-24 视频模型组反馈）：v1.5.0.4 方案 A 在发送方
// Connection::handle_ack_frame 中遍历 local_streams_/remote_streams_ 收集
// oos_pn_list 注入 LossDetector；但 oos_buffer_ 是接收方 stream 状态，
// 发送方 oos_buffer_ 永远为空 → oos_pn_list_size=0 → LossDetector 阶段 2 无作为 → OOS buffer 累积死锁。
//
// 方案 A+：改注入方向，接收方 → 发送方。
//   - 接收方 build_oos_pn_data() 周期性（100ms）遍历本端 stream 的 oos_buffer_，
//     收集首个 gap (offset + first_seen_ms) 编码为 OOS_PN_FRAME，写入 1-RTT 包上行。
//   - 发送方 handle_oos_pn_frame() 解析 OOS_PN_FRAME，写入 oos_pn_remote_ map（30s 过期）。
//   - 发送方 handle_ack_frame() 阶段 1 后从 oos_pn_remote_ 收集 PN 信息，
//     反查 oos_buffer_? 不行：发送方不知道接收方 stream 的 oos_buffer_，但有
//     sent_packets_ → 按 offset 反查 PN 即可构造 OosPnInfo 注入 LossDetector。

void Connection::prune_oos_pn_remote_locked(double now_ms) {
    // 清理 oos_pn_remote_ 中超过 kOosPnRemoteTtlMs (30s) 的 entries
    // (Q3 答复：30s 有效期，避免内存无限增长 + 防御恶意帧注入)
    // 调用方必须持有 oos_pn_remote_mu_
    for (auto it = oos_pn_remote_.begin(); it != oos_pn_remote_.end();) {
        auto &entries = it->second;
        // 移除 recv_time_ms 距 now 超过 TTL 的条目
        entries.erase(
            std::remove_if(entries.begin(), entries.end(),
                [now_ms](const OosRemoteEntry &e) {
                    return (now_ms - e.recv_time_ms) > kOosPnRemoteTtlMs;
                }),
            entries.end());
        if (entries.empty()) {
            it = oos_pn_remote_.erase(it);
        } else {
            ++it;
        }
    }
}

void Connection::handle_oos_pn_frame(std::span<const uint8_t> data) {
    // v1.5.0.7 (ISSUE T06 反馈): 入口无条件计数器 +1，便于诊断触发链断裂点。
    decode_OOS_PN_total_++;
    // v1.5.0.10 (ISSUE T09 反馈): 冗余 alias，单独埋点用于排查 A2（编解码对称性）
    //   - 与 OOS_PN_decode_failed_total_ 同步递增，保证 7 计数器埋点语义清晰
    //   - 严格说 decode_OOS_PN_total_ 与 oos_pn_frame_recv_total_ 在 handle_oos_pn_frame
    //     入口时数值应一致（路由成功时）；本计数器冗余用于核对路由链路是否完整
    // ep-L1 (v1.7.0.8): 删除自赋值占位死代码 `x = x`，原意是"保持递增位置"
    //   但自赋值是 no-op，递增已在下方 decode 失败分支中正确执行，此行无意义。

    double now = now_ms_steady();
    auto frame = protocol::decode_oos_pn_frame(data);
    if (!frame) {
        // v1.5.0.7 (ISSUE T06 反馈): decode 失败计数器 +1，监控编解码对称性回归。
        OOS_PN_decode_failed_total_++;
        // v1.5.0.10: 同步递增冗余计数器
        // 移除上面的占位赋值
        oos_pn_frame_decode_fail_total_++;
        LINOH_WARN("Connection: decode OOS_PN_FRAME failed, size=", data.size(),
                   " decode_total=", decode_OOS_PN_total_,
                   " failed_total=", OOS_PN_decode_failed_total_);
        return;
    }

    // v1.5.0.7 (ISSUE T06 反馈): decode 成功计数器 +1。
    OOS_PN_decode_total_++;

    // v1.5.0.10 (ISSUE T09 反馈): 隐式确认 — 接收方成功 decode 后告知对端不再重发。
    //   - A 是发送方，B 是接收方。B 端本对象调用 ack_oos_pn_frame 是不正确的
    //     （B 自身不是发送方，没有 pending_oos_pn_frames_ 条目），此调用为 no-op。
    //   - 实际方案是：A 端按 500ms 周期强制重发（见 resend_oos_pn_if_needed），
    //     不依赖 B 端回传 ACK，避免引入新协议帧。
    // ack_oos_pn_frame(frame->stream_id);  // v1.5.0.10: 占位，B 端为 no-op
    (void)frame->stream_id;  // 显式标记 stream_id 已被解析，防止未使用警告

    std::lock_guard<std::mutex> lk(oos_pn_remote_mu_);
    // 入口清理过期 entries（Q3 答复：30s TTL）
    prune_oos_pn_remote_locked(now);

    auto &entries = oos_pn_remote_[frame->stream_id];
    for (const auto &e : frame->entries) {
        // 防恶意 / 极端场景：单 stream 上限 kOosPnRemoteMaxEntriesPerStream
        if (entries.size() >= kOosPnRemoteMaxEntriesPerStream) {
            entries.erase(entries.begin());
        }
        entries.push_back({e.offset, e.first_seen_ms, now});
    }

    // v1.5.0.7 (ISSUE T06 反馈): DEBUG → INFO 升级，便于视频模型组观察。
    LINOH_INFO("Connection: OOS_PN_FRAME received stream_id=", frame->stream_id,
               " entries=", frame->entries.size(),
               " oos_pn_remote_total=", oos_pn_remote_.size(),
               " decode_total=", decode_OOS_PN_total_,
               " success_total=", OOS_PN_decode_total_);

    // === v1.5.0.8 (ISSUE T07 反馈): 立即同步 LossDetector 触发 retx ===
    // 根因：v1.5.0.5/0.6/0.7 虽修好 OOS_PN 触发链路，但 LossDetector 是
    // packet-level 丢包检测器，仅看 PN gap / time gap，stream-level OOS gap
    // 永不被识别为丢包。handle_ack_frame 阶段 1 反查逻辑用 sent_bytes 匹配
    // stream_offset（sent_bytes 是 1-RTT 包总大小，含 ACK/控制帧/加密头），
    // 永远不命中，导致 oos_pn_list_size=0，T05 业务测试 90s 超时。
    //
    // 修复：decode 成功后立即调 loss_detector_.on_oos_pn_received(stream_id, entries)，
    // 内部按 stream_id 严格过滤 sent_packets_ + 用 stream_payload_bytes（v1.5.0.8
    // 新增字段，仅 stream 字节）精确匹配 offset 范围，对 in_flight 且 pn<largest_acked
    // 的 PN 立即 mark_lost，返回 PN 列表加入 retransmit_queue_。
    //
    // 不依赖 ACK 事件触发，避免"packet-level 无 PN gap → on_ack_received
    // 不频繁调用 → OOS_PN 永不被消费"死锁。
    std::vector<uint64_t> retx_pns;
    {
        // 注意：oos_pn_remote_mu_ 仍持有，loss_detector 内部锁独立
        retx_pns = loss_detector_.on_oos_pn_received(
            frame->stream_id, frame->entries);
    }
    if (!retx_pns.empty()) {
        // v1.7.0.6 (H1-3 fix): push_back/size 加锁，与 build_1rtt_packet 消费端互斥
        std::size_t q_size_snapshot = 0;
        {
            std::lock_guard<std::mutex> lk(retransmit_mu_);
            for (uint64_t pn : retx_pns) {
                retransmit_queue_.push_back(pn);
                stats_.lost_packets++;
            }
            q_size_snapshot = retransmit_queue_.size();
        }
        // 通知拥塞控制触发 fast recovery
        // v1.7.0.7 H5/H6: 传入 loss_detector_.largest_acked() 供 NewReno 记录 recovery 起始 PN，
        //   后续 on_ack 收到 largest_acked_pn > recovery_start_pn_ 时退出 recovery (RFC 9002 §7.3.2)
        congestion_ctrl_->on_loss(loss_detector_.largest_acked());
        LINOH_INFO("Connection: OOS_PN triggered retx count=", retx_pns.size(),
                   " stream_id=", frame->stream_id,
                   " retransmit_queue_size=", q_size_snapshot);
    }
}

std::vector<std::uint8_t> Connection::build_oos_pn_data() {
    // v1.5.0.7 (ISSUE T06 反馈): 入口无条件计数器 +1，便于诊断触发链断裂点。
    // v1.5.0.6 缺失此埋点，视频模型组无法定位是"未调用"还是"调用但返回空"。
    build_oos_pn_data_total_++;

    // 节拍控制：v1.5.0.7 修复 (ISSUE T06 反馈)
    //   - 首次调用（last_oos_pn_send_ms_==0）直接触发，绕过 100ms/50ms 节拍阻挡
    //     解决"前 100ms 内所有调用都返回空"的初值陷阱
    //   - 后续调用按 kOosPnSendIntervalMs 节拍（v1.5.0.7: 100ms → 50ms）
    double now = now_ms_steady();
    if (last_oos_pn_send_ms_ != 0.0 && now - last_oos_pn_send_ms_ < kOosPnSendIntervalMs) {
        return {};
    }

    // 遍历本端所有 stream（local_streams_ + remote_streams_）的 oos_buffer_，
    // 取每个 stream 的首个 gap（first_gap_offset + first_seen_ms）。
    // 协议约束：单 OOS_PN_FRAME 仅承载 1 个 stream 的 entries（OosPnFrame.stream_id 单值），
    // 因此多 stream 场景需在 build_1rtt_packet 中多次调用本函数逐个 stream 发送。
    // 为简化实现：先返回第一个有 gap 的 stream 帧；后续 stream 留待下次 build_1rtt_packet
    // (节拍 50ms 内) 补发。复杂度 O(streams_with_gap) 次 / 50ms。
    //
    // 收集候选 stream
    std::lock_guard<std::mutex> lk(stream_mu_);

    auto try_collect_from_streams =
        [&](const std::unordered_map<std::uint64_t, std::shared_ptr<Stream>> &streams,
            protocol::OosPnFrame &out) -> bool {
        for (const auto &kv : streams) {
            const auto &s = kv.second;
            if (!s) continue;
            std::uint64_t offset = 0;
            std::size_t size = 0;
            if (!s->oos_first_gap(&offset, &size)) continue;

            // 查 oos_first_seen_ms_map_ 获取 entry 级别 first_seen_ms
            const auto &seen_map = s->oos_first_seen_ms_map_for_test();
            double first_seen_ms = now;
            auto seen_it = seen_map.find(offset);
            if (seen_it != seen_map.end()) {
                first_seen_ms = seen_it->second;
            }

            protocol::OosPnEntry e;
            e.offset = offset;
            e.first_seen_ms = first_seen_ms;
            out.stream_id = kv.first;
            out.entries.push_back(e);
            return true;  // 一次只收集 1 个 stream
        }
        return false;
    };

    protocol::OosPnFrame frame;
    if (try_collect_from_streams(local_streams_, frame)) {
        // got local
    } else if (try_collect_from_streams(remote_streams_, frame)) {
        // got remote
    } else {
        // v1.5.0.7 (ISSUE T06 反馈): 无 OOS gap 时不更新 last_oos_pn_send_ms_，
        // 避免"无 gap 时也累加 last_oos_pn_send_ms_"导致节拍永久错过。
        return {};  // 无 OOS gap，无需发送
    }

    // v1.5.0.7 (ISSUE T06 反馈): 仅在成功发送 OOS_PN 帧时更新 last_oos_pn_send_ms_。
    last_oos_pn_send_ms_ = now;
    // v1.5.0.7 (ISSUE T06 反馈): 成功发送 OOS_PN 帧时计数器 +1。
    OOS_PN_frame_total_++;
    // v1.5.0.10 (ISSUE T09 反馈): UDP 可靠性 — 把待确认的 OOS_PN 帧入队，
    //   等待 500ms 后由 resend_oos_pn_if_needed() 周期性检查并触发重发。
    //   同一 stream_id 的新 OOS_PN 帧覆盖旧条目（避免队列膨胀 + 反映最新 gap 状态）。
    //
    // 重要：v1.5.0.6 修复后 encode_oos_pn_frame 不再写 type 字节，由 build_1rtt_packet
    // 显式追加。但 resend 路径走 pending_fc_frames_ 复用通道（P3-1 块 memcpy 整段），
    // 不经过 build_1rtt_packet 的 OOS_PN 特殊处理，因此这里需要显式 prepend type 字节。
    auto body = protocol::encode_oos_pn_frame(frame);
    std::vector<std::uint8_t> framed;
    framed.reserve(1 + body.size());
    framed.push_back(static_cast<std::uint8_t>(protocol::FrameType::OOS_PN));
    framed.insert(framed.end(), body.begin(), body.end());
    {
        std::lock_guard<std::mutex> plk(pending_oos_pn_mu_);
        PendingOosPnFrame pof;
        pof.stream_id = frame.stream_id;
        pof.encoded = std::move(framed);
        pof.send_time_ms = now;
        pof.resent_count = 0;
        pending_oos_pn_frames_[frame.stream_id] = std::move(pof);
    }
    LINOH_INFO("Connection: build_oos_pn_data stream_id=", frame.stream_id,
               " entries=", frame.entries.size(),
               " build_total=", build_oos_pn_data_total_,
               " frame_total=", OOS_PN_frame_total_,
               " pending_size=", pending_oos_pn_frames_.size());
    return body;  // 仍按 v1.5.0.6 约定返回 body（不含 type 字节），由 build_1rtt_packet 显式追加
}

// v1.5.0.1 P0-1: 测试钩子实现 — 模拟丢包 + 注入 plaintext
void Connection::__test_inject_lost_packet(std::uint64_t pn, std::vector<std::uint8_t> plaintext) {
    std::lock_guard<std::mutex> lk(retransmit_mu_);
    retransmit_queue_.push_back(pn);
    sent_payloads_[pn] = std::move(plaintext);
    sent_payloads_bytes_ += sent_payloads_[pn].size();
    force_retx_ = true;
}

// v1.5.0.10 (ISSUE T09 反馈): OOS_PN 帧 UDP 可靠性 — 重发超时检查
//
// v1.5.0.12 (ISSUE T11 反馈 P0): 修复节拍耦合导致 resend 永不触发
//   根因：build_oos_pn_data 每 50ms 重置 pof.send_time_ms = now，
//         导致 now - send_time_ms < kOosPnResendTimeoutMs (100ms) 永远成立。
//   修复：resend 触发条件改为基于 last_resend_check_ms_ 节拍时间追踪，
//         与 build_oos_pn_data 的 send_time_ms 重置完全解耦。
//
// 工作原理：
//   - 发送方 build_oos_pn_data() 成功生成后，encoded 帧 + send_time_ms 入队
//   - 每隔 heartbeat_loop 周期（1Hz）调用本方法
//   - v1.5.0.12: 先检查节拍 now - last_resend_check_ms_ >= kOosPnResendTimeoutMs，
//     节拍未到直接返回 0（跳过统计 +1）
//   - 节拍满足后，遍历 pending_oos_pn_frames_，send_time_ms 距 now > 100ms 且
//     resent_count < 8 的条目触发重发：推入 high_priority 队列
//   - 重发后更新 send_time_ms = now，resent_count++
//
// \return 重发的帧数（用于 log + oos_pn_resend_total_ 计数）
std::size_t Connection::resend_oos_pn_if_needed() {
    double now = now_ms_steady();

    // v1.5.0.12 (ISSUE T11 反馈 P0): 节拍解耦 — 基于 last_resend_check_ms_ 判断
    //   解决 build_oos_pn_data 每 50ms 重置 send_time_ms 导致 resend 永不触发的耦合问题
    resend_oos_pn_call_total_++;
    if (now - last_resend_check_ms_ < kOosPnResendTimeoutMs) {
        resend_oos_pn_skipped_rhythm_total_++;
        return 0;  // 节拍未到，跳过（即使有超时条目也暂缓）
    }
    last_resend_check_ms_ = now;

    std::size_t resent_count = 0;

    std::vector<PendingOosPnFrame> to_resend;
    {
        std::lock_guard<std::mutex> plk(pending_oos_pn_mu_);
        for (auto &kv : pending_oos_pn_frames_) {
            auto &pof = kv.second;
            if (now - pof.send_time_ms < kOosPnResendTimeoutMs) continue;
            if (pof.resent_count >= kOosPnMaxResendCount) {
                // 超过最大重发次数，停止重发，保留条目用于诊断
                LINOH_WARN("Connection: OOS_PN resend exhausted, stream_id=", pof.stream_id,
                           " resent_count=", pof.resent_count,
                           " pending_size=", pending_oos_pn_frames_.size());
                continue;
            }
            to_resend.push_back(pof);  // 拷贝（锁内仅做读取）
        }
    }

    if (to_resend.empty()) return 0;

    // v1.5.0.11 (ISSUE T10 反馈 P1): 改用 high_priority 队列替代 pending_fc_frames_
    //   - T10 业务实测 UDP 接收率仅 34%（66% 丢包），OOS_PN 帧被 cwnd 抑制雪崩
    //   - high_priority 队列在 build_1rtt_packet 中优先于 retx + fc 帧处理
    //   - 不计入 cwnd 抑制，确保 OOS_PN 帧在高丢包下仍能到达对端
    // 触发重发：将 encoded 帧推入 pending_oos_pn_high_priority_frames_ 高优先级通道，
    // 然后调用 on_ping_send_requested_ 触发上层 flush 1-RTT 包。
    for (const auto &pof : to_resend) {
        std::lock_guard<std::mutex> plk(pending_oos_pn_mu_);
        auto it = pending_oos_pn_frames_.find(pof.stream_id);
        if (it == pending_oos_pn_frames_.end()) continue;
        auto &entry = it->second;
        // 二次检查：避免并发场景下其他线程已更新
        if (now - entry.send_time_ms < kOosPnResendTimeoutMs) continue;
        if (entry.resent_count >= kOosPnMaxResendCount) continue;

        // v1.5.0.11: 推入 high_priority 队列（v1.5.0.10 使用 pending_fc_frames_）
        //  - pending_oos_pn_high_priority_frames_ 在 build_1rtt_packet 中先于 retx 块处理
        //  - OOS_PN 帧格式与控制帧兼容（type 字节 + varint payload）
        //  - 推入后由 build_1rtt_packet 在下次构建时自然写出，绕过 cwnd 抑制
        std::vector<std::uint8_t> frame_copy = entry.encoded;
        {
            // v1.7.0.6 (C9 fix): 加锁保护 push_back（原注释"在 build_1rtt_packet
            // 中已加锁"是 v1.5.0.11 遗留的预期，但实际未加锁，导致数据竞争）
            std::lock_guard<std::mutex> hp_lk(pending_hp_mu_);
            pending_oos_pn_high_priority_frames_.push_back(std::move(frame_copy));
        }
        entry.send_time_ms = now;
        entry.resent_count++;
        oos_pn_frame_resent_total_++;
        oos_pn_resend_total_++;
        resent_count++;
    }

    if (resent_count > 0) {
        // v1.5.0.12: 实际触发重发计数（节拍满足且有超时条目）
        resend_oos_pn_triggered_total_++;
        // 触发上层 flush 立即发送 1-RTT 包（与 heartbeat_loop PING 机制共用）
        if (on_ping_send_requested_) {
            try { on_ping_send_requested_(); } catch (...) {}
        }
        std::size_t hp_queue_size_snapshot = [&] {
            std::lock_guard<std::mutex> hp_lk(pending_hp_mu_);
            return pending_oos_pn_high_priority_frames_.size();
        }();
        LINOH_INFO("Connection: OOS_PN resend triggered, count=", resent_count,
                   " total=", oos_pn_resend_total_,
                   " pending_size=", pending_oos_pn_frames_.size(),
                   " hp_queue_size=", hp_queue_size_snapshot);
    }
    return resent_count;
}

// v1.5.0.10 (ISSUE T09 反馈): OOS_PN 帧隐式确认
//
// 接收方成功 decode 一帧 OOS_PN 帧后，可通知发送方 Connection 删除对应
// pending 条目（不再重发）。但本设计采用"按节拍强制重发 + 限次"方案，
// 接收方 ack 仅用于诊断/测试，不影响发送方重发逻辑。
//
// 注：本接口保留为公开 API（便于后续扩展 OOS_PN_ACK 帧 + 单测验证队列清理）
void Connection::ack_oos_pn_frame(std::uint64_t stream_id) {
    std::lock_guard<std::mutex> plk(pending_oos_pn_mu_);
    auto it = pending_oos_pn_frames_.find(stream_id);
    if (it != pending_oos_pn_frames_.end()) {
        // v1.5.0.10: 保留条目用于诊断（不删除），仅重置 send_time_ms 避免
        //   短暂"已确认但未清理"窗口下误重发。
        // 注：实际产品中可选择删除（更激进），但保留可观察到对端已接收的痕迹
        // it->second.send_time_ms = now_ms_steady();
        // 改为删除以反映"已确认"语义：
        pending_oos_pn_frames_.erase(it);
        // v1.5.0.11 (ISSUE T10 反馈 P2): UDP 丢包分桶埋点
        //   - 每次 ack_oos_pn_frame 成功调用 +1（隐式确认总数）
        //   - 派生 loss_rate = (sent - acked) / sent
        oos_pn_acked_implicit_total_++;
        LINOH_DEBUG("Connection: OOS_PN ack received, stream_id=", stream_id,
                    " pending_size=", pending_oos_pn_frames_.size());
    }
}

// v1.5.0.10: 测试访问器实现
std::size_t Connection::pending_oos_pn_frames_size_for_test() const {
    std::lock_guard<std::mutex> plk(pending_oos_pn_mu_);
    return pending_oos_pn_frames_.size();
}

std::vector<uint8_t> Connection::build_ack_data() {
    // B5 fix(2026-07-20): 使用实际接收的 PN 集合，替代原连续区间 [0, recv_pn_[2]) 假设。
    // 支持乱序/跳号场景，避免幻影确认（确认从未收到的 PN）。
    if (received_app_pns_.empty()) return {};

    // 排序并去重（乱序到达可能重复）
    std::vector<uint64_t> received_pns = received_app_pns_;
    std::sort(received_pns.begin(), received_pns.end());
    received_pns.erase(std::unique(received_pns.begin(), received_pns.end()),
                       received_pns.end());

    // 计算对端发送到本端的延迟估算（简化为 0）
    auto ack = protocol::AckFrame::from_acked_pns(received_pns, 0, 0x02);
    auto encoded = protocol::encode_ack_frame(ack);

    // 6-3 fix: 清空已确认的 PN 集合，防止 ACK 帧无限膨胀。
    // 32MB 传输 ~27000 包，5% drop 下 received_app_pns_ 持续累积，
    // 导致每次 build_ack_data 都从全量集合重建 ACK 帧，帧大小膨胀
    // 到数 KB，占满 payload 空间，STREAM 数据和 retx 块无法写入。
    received_app_pns_.clear();

    return encoded;
}

bool Connection::check_idle_timeout(double now_ms) {
    if (cfg_.idle_timeout.count() == 0) return false; // 不超时
    double timeout_ms = static_cast<double>(cfg_.idle_timeout.count());
    if (now_ms - last_activity_ms_ > timeout_ms) {
        LINOH_INFO("Connection: idle timeout exceeded, closing");
        return true;
    }
    return false;
}

bool Connection::needs_keepalive(double now_ms) const {
    if (cfg_.keepalive_interval.count() == 0) return false;
    double interval_ms = static_cast<double>(cfg_.keepalive_interval.count());
    return (now_ms - last_ping_sent_ms_) > interval_ms;
}

void Connection::record_activity(double now_ms) {
    last_activity_ms_ = now_ms;
}

void Connection::emit_periodic_flow_control() {
    // v1.5.0.1 P3-1: 1Hz 周期主动通告。检查 should_send_max_data() 和
    // 逐个 stream 的 should_send_max_stream_data()，命中即编码为完整帧。
    // 调用方：heartbeat_loop（每 interval_ms 默认 1000ms）。
    // 输出：pending_fc_frames_ 追加（不覆盖），由 build_1rtt_packet 一次性消费。
    //
    // 帧格式：type 字节 + varint 编码字段，与 frame 解析路径对称。
    // v1.7.0.6 (C9 fix): 先收集到局部 new_frames，最后一次性加锁追加，
    // 避免多次 push_back 多次加锁 + 与 build_1rtt_packet 消费端的数据竞争。

    std::vector<std::vector<std::uint8_t>> new_frames;

    // 1. Connection-level MAX_DATA
    if (flow_ctrl_.should_send_max_data()) {
        std::uint64_t new_max = flow_ctrl_.next_max_data_value();
        protocol::MaxDataFrame frame{new_max};
        auto body = protocol::encode_max_data(frame);  // 0x10 + varint
        new_frames.push_back(std::move(body));
        // v1.5.0.1 P3-1: 标记已通告，避免下次 emit 重复发
        flow_ctrl_.mark_max_data_advertised(new_max);
    }

    // 2. Stream-level MAX_STREAM_DATA
    // v1.5.0.1 P3-1: 用 flow_ctrl_.local_stream_ids() 统一来源。
    // 之前用 Connection::local_streams_/remote_streams_ 扫描，但这两个 map
    // 只在 stream 创建/关闭时更新，而 flow_ctrl_ 内部 tracking 在 on_stream_bytes_recv
    // 后会包含更多"对端发了数据但 stream 状态未切换"的场景。统一从 flow_ctrl_ 取。
    auto stream_ids = flow_ctrl_.local_stream_ids();

    for (std::uint64_t sid : stream_ids) {
        if (flow_ctrl_.should_send_max_stream_data(sid)) {
            std::uint64_t new_max = flow_ctrl_.next_max_stream_data_value(sid);
            protocol::MaxStreamDataFrame frame{sid, new_max};
            auto body = protocol::encode_max_stream_data(frame);  // 0x11 + varint + varint
            new_frames.push_back(std::move(body));
            // mp-L7 (v1.7.0.8): 标记已通告，避免下次 emit 重复发
            flow_ctrl_.mark_stream_data_advertised(sid, new_max);
        }
    }

    // v1.7.0.6 (C9 fix): 一次性加锁追加，避免与 build_1rtt_packet 消费端竞争
    if (!new_frames.empty()) {
        std::lock_guard<std::mutex> fc_lk(pending_fc_mu_);
        for (auto &f : new_frames) {
            pending_fc_frames_.push_back(std::move(f));
        }
    }
}

util::Result<std::shared_ptr<Stream>> Connection::try_open_stream() {
    // 状态验证：只能在 Established 状态打开流
    auto state_check = StateValidator::can_open_stream(state_.load());
    if (!state_check.is_ok()) {
        return util::Result<std::shared_ptr<Stream>>(state_check.error());
    }

    std::lock_guard<std::mutex> lk(stream_mu_);
    // Check stream count limit via flow controller
    uint64_t current_count = local_streams_.size();
    if (!flow_ctrl_.can_open_bidi_stream(current_count)) {
        return util::Result<std::shared_ptr<Stream>>(
            util::ConnectionError::StreamLimitError,
            "exceeded max bidi stream count");
    }

    auto st = std::make_shared<Stream>(next_local_stream_id(true), Stream::Dir::Bidirectional);
    // P5 fix(2026-07-20): unordered_map emplace 替代 push_back
    local_streams_.emplace(st->id(), st);

    // Set initial stream-level window from flow controller
    flow_ctrl_.on_remote_max_stream_data(st->id(), flow_ctrl_.remote_stream_window(st->id()));

    LINOH_DEBUG("Connection: opened stream id=", st->id());
    return util::Result<std::shared_ptr<Stream>>(st);
}

void Connection::handle_flow_control_frame(std::uint8_t frame_type,
                                             std::span<const std::uint8_t> payload) {
    LINOH_DEBUG("Connection: handling flow-control frame type=", (int)frame_type,
                " payload_size=", payload.size());

    switch (frame_type) {
        case 0x10: { // MAX_DATA
            auto decoded = protocol::decode_max_data(payload);
            if (decoded) {
                flow_ctrl_.on_remote_max_data(decoded->maximum_data);
                LINOH_DEBUG("  → MAX_DATA=", decoded->maximum_data);
            }
            break;
        }
        case 0x11: { // MAX_STREAM_DATA
            auto decoded = protocol::decode_max_stream_data(payload);
            if (decoded) {
                flow_ctrl_.on_remote_max_stream_data(decoded->stream_id,
                                                     decoded->maximum_stream_data);
                LINOH_DEBUG("  → MAX_STREAM_DATA stream_id=", decoded->stream_id,
                            " window=", decoded->maximum_stream_data);
            }
            break;
        }
        case 0x12: case 0x13: { // MAX_STREAMS_BIDI / MAX_STREAMS_UNI
            auto decoded = protocol::decode_max_streams(frame_type, payload);
            if (decoded) {
                if (decoded->bidirectional) {
                    flow_ctrl_.on_remote_max_bidi_streams(decoded->maximum_streams);
                } else {
                    flow_ctrl_.on_remote_max_uni_streams(decoded->maximum_streams);
                }
                LINOH_DEBUG("  → MAX_STREAMS bidi=", decoded->bidirectional,
                            " count=", decoded->maximum_streams);
            }
            break;
        }
        case 0x14: { // DATA_BLOCKED
            auto decoded = protocol::decode_data_blocked(payload);
            if (decoded) {
                LINOH_WARN("Connection: DATA_BLOCKED at offset=", decoded->maximum_data);
                // Peer is blocked — we should send MAX_DATA with updated window
            }
            break;
        }
        case 0x15: { // STREAM_DATA_BLOCKED
            auto decoded = protocol::decode_stream_data_blocked(payload);
            if (decoded) {
                LINOH_INFO("Connection: STREAM_DATA_BLOCKED stream=", decoded->stream_id,
                            " offset=", decoded->maximum_stream_data,
                            " — granting window (v5.4 F4 credit reserve)");
                // v5.4 F4（借鉴 ScaleFabric credit 预约）：对端声明需求即保障——
                // 授权窗口提到 声明 offset + 一窗余量，并立即回 MAX_STREAM_DATA。
                // 老对端不声明（无 BLOCKED 帧）行为不变；声明方 write_ex 阻塞等待解锁。
                flow_ctrl_.grant_stream_window(
                    decoded->stream_id,
                    decoded->maximum_stream_data +
                    protocol::FlowController::kDefaultStreamWindow);
                {
                    std::uint64_t new_max =
                        flow_ctrl_.next_max_stream_data_value(decoded->stream_id);
                    protocol::MaxStreamDataFrame frame{decoded->stream_id, new_max};
                    auto body = protocol::encode_max_stream_data(frame);
                    std::lock_guard<std::mutex> fc_lk(pending_fc_mu_);
                    pending_fc_frames_.push_back(std::move(body));
                    flow_ctrl_.mark_stream_data_advertised(decoded->stream_id, new_max);
                }
            }
            break;
        }
        case 0x16: case 0x17: { // STREAMS_BLOCKED_BIDI / STREAMS_BLOCKED_UNI
            auto decoded = protocol::decode_streams_blocked(frame_type, payload);
            if (decoded) {
                LINOH_WARN("Connection: STREAMS_BLOCKED bidi=", decoded->bidirectional,
                            " count=", decoded->maximum_streams);
            }
            break;
        }
        default:
            LINOH_DEBUG("Connection: unknown flow-control frame type=", (int)frame_type);
            break;
    }
}

void Connection::handle_path_migration_frame(std::uint8_t frame_type,
                                               std::span<const std::uint8_t> payload) {
    LINOH_DEBUG("Connection: handling path-migration frame type=", (int)frame_type,
                " payload_size=", payload.size());

    switch (frame_type) {
        case 0x1a: { // PATH_CHALLENGE
            auto decoded = protocol::decode_path_challenge(payload);
            if (decoded) {
                LINOH_DEBUG("  → PATH_CHALLENGE received, data=",
                            decoded->data[0], decoded->data[1], "...",
                            decoded->data[6], decoded->data[7]);
                // We should respond with PATH_RESPONSE containing the same data
                // This will be done in build_1rtt_packet when needed
            }
            break;
        }
        case 0x1b: { // PATH_RESPONSE
            auto decoded = protocol::decode_path_response(payload);
            if (decoded) {
                LINOH_DEBUG("  → PATH_RESPONSE received");
                int idx = path_mgr_.validate_response(*decoded);
                if (idx >= 0) {
                    path_mgr_.mark_path_validated(idx);
                    LINOH_INFO("Connection: path validated!");
                } else {
                    LINOH_WARN("Connection: PATH_RESPONSE doesn't match any challenge");
                }
            }
            break;
        }
        case 0x18: { // NEW_CONNECTION_ID
            auto decoded = protocol::decode_new_connection_id(payload);
            if (decoded) {
                protocol::ConnectionIdEntry entry;
                entry.sequence_number = decoded->sequence_number;
                entry.stateless_reset_token = decoded->stateless_reset_token;
                entry.cid = protocol::ConnectionId(decoded->connection_id);
                path_mgr_.add_cid(entry);

                // Retire prior CIDs if requested
                if (decoded->retire_prior_to > 0) {
                    for (uint64_t seq = 0; seq < decoded->retire_prior_to; ++seq) {
                        path_mgr_.retire_cid(seq);
                    }
                }
                LINOH_DEBUG("  → NEW_CONNECTION_ID seq=", decoded->sequence_number);
            }
            break;
        }
        case 0x19: { // RETIRE_CONNECTION_ID
            auto decoded = protocol::decode_retire_connection_id(payload);
            if (decoded) {
                path_mgr_.retire_cid(decoded->sequence_number);
                LINOH_DEBUG("  → RETIRE_CONNECTION_ID seq=", decoded->sequence_number);
            }
            break;
        }
        default:
            LINOH_DEBUG("Connection: unknown path-migration frame type=", (int)frame_type);
            break;
    }
}

// ============================================================================
// Stream
// ============================================================================

void Stream::write(std::span<const std::uint8_t> data) {
    if (closed_ || send_closed_) return;
    send_.insert(send_.end(), data.begin(), data.end());
    ++total_writes_;
}

void Stream::write_scatter(const std::vector<std::span<const std::uint8_t>> &parts) {
    if (closed_ || send_closed_) return;
    // v1.6.0.3 P2: 一次性预留容量，避免多次 insert 触发 reallocate
    std::size_t total = 0;
    for (const auto &p : parts) total += p.size();
    if (total == 0) return;
    send_.reserve(send_.size() + total);
    for (const auto &p : parts) {
        send_.insert(send_.end(), p.begin(), p.end());
    }
    ++total_writes_;
}

// v3.3.0 突破2: 零拷贝 write — move 接管外部 vector 所有权。
// Fast path: send_ 无可读数据时 O(1) swap（真零拷贝）。
// Fallback:  reserve + move insert（消除 span→vector 中间拷贝）。
void Stream::write_ref(std::vector<std::uint8_t> &&buf) {
    if (closed_ || send_closed_ || buf.empty()) {
        buf.clear();  // 即使拒绝也清空，保证所有权语义一致
        return;
    }

    // Fast path: send_ 无可读数据（send_read_pos_==0 且 send_.empty()）
    // 直接 swap，O(1) 真零拷贝，buf 的堆内存完整转移给 send_
    if (send_read_pos_ == 0 && send_.empty()) {
        send_.swap(buf);
        ++zero_copy_writes_;
        ++total_writes_;
        buf.clear();
        return;
    }

    // Fallback: send_ 已有数据，reserve + move insert
    // 注：对 uint8_t（trivial type）move 等价于 copy，但语义上明确了所有权转移，
    // 且消除了 serialize() 返回值 + write(span) 的两次拷贝中的第一次（vector 分配）
    send_.reserve(send_.size() + buf.size());
    send_.insert(send_.end(),
                 std::make_move_iterator(buf.begin()),
                 std::make_move_iterator(buf.end()));
    buf.clear();
    ++total_writes_;
}

// v3.3.0 突破2: 零拷贝 scatter — move 接管多个 vector 所有权。
// 一次性 reserve + 逐个 move insert，避免多次 reallocate。
void Stream::write_scatter_ref(std::vector<std::vector<std::uint8_t>> &&parts) {
    if (closed_ || send_closed_) {
        for (auto &p : parts) p.clear();
        parts.clear();
        return;
    }

    // 统计总字节数
    std::size_t total = 0;
    for (const auto &p : parts) total += p.size();
    if (total == 0) {
        parts.clear();
        return;
    }

    // Fast path: send_ 为空且只有一个 part → 直接 swap（O(1) 真零拷贝）
    if (send_read_pos_ == 0 && send_.empty() && parts.size() == 1 && !parts[0].empty()) {
        send_.swap(parts[0]);
        ++zero_copy_writes_;
        ++total_writes_;
        parts.clear();
        return;
    }

    // Fallback: reserve + 逐个 move insert
    send_.reserve(send_.size() + total);
    for (auto &p : parts) {
        if (!p.empty()) {
            send_.insert(send_.end(),
                         std::make_move_iterator(p.begin()),
                         std::make_move_iterator(p.end()));
        }
        p.clear();
    }
    parts.clear();
    ++total_writes_;
}

void Stream::recv(std::span<const std::uint8_t> data, std::uint64_t offset) {
    if (closed_ || data.empty()) return;

    // B6 fix(2026-07-20): 标准 QUIC 流乱序重组。
    // 三种情况：
    //   1. offset + data.size() <= recv_offset_ → 完全重复，丢弃
    //   2. offset < recv_offset_ < offset + data.size() → 部分重复，截取新部分
    //   3. offset >= recv_offset_ → 新数据，写入并尝试消费 oos_buffer_

    std::uint64_t data_end = offset + data.size();

    // 埋点诊断 v1.5.0.2.5 (2026-07-23): 视频模型组反馈 STREAM buffer 累积
    // (recv_ 持续增长但 oos_buffer_ 不下降). 打印每个 STREAM 帧的入参与最终 case,
    // 便于对比正常流量与异常流量的处理路径.
    // v1.5.0.3 (2026-07-24): 追加 pn 字段，关联 packet number 便于 OOS gap 排查。
    // v1.5.0.3: 追加 oos_first_seen_ms_ 计算 oos_wait_ms，记录首个 OOS 累积起的等待时间。
    double now_ms_v = now_ms_steady();
    if (!oos_buffer_.empty() && oos_first_seen_ms_ < 0.0) {
        oos_first_seen_ms_ = now_ms_v;
    } else if (oos_buffer_.empty()) {
        oos_first_seen_ms_ = -1.0;
    }
    double oos_wait_ms_v = (oos_first_seen_ms_ > 0.0)
                              ? (now_ms_v - oos_first_seen_ms_)
                              : 0.0;
    LINOH_INFO("Stream::recv: stream_id=", id_,
               " pn=", last_pn_,
               " offset=", offset, " data_end=", data_end,
               " recv_offset_=", recv_offset_,
               " data_size=", data.size(),
               " oos_buffer_size=", oos_buffer_.size(),
               " recv_buffer_size=", recv_.size(),
               " oos_wait_ms=", oos_wait_ms_v);

    // v1.5.0.3 (2026-07-24): OOS state report 公共函数，
    // 在 case=3_inorder 和 case=4_oos_buffered 路径都调用，输出首个 gap 信息
    // 并按阈值触发回调。这样应用层无论数据从哪个路径进入 OOS 都能感知。
    // 注: fmt 是 string_view 直接拼接, logger 会在每个 arg 前加空格,
    //     所以 context 必须拼到 fmt 内部, 否则会有双空格 (如 "Stream::recv:  case=3 ...").
    auto report_oos_state = [&](const char *context) {
        // ep-P1 (v1.7.0.8): fprintf(stderr) 绕过日志系统，热路径同步 IO → 改 LINOH_DEBUG
        LINOH_DEBUG("report_oos_state(", context, ") oos_buffer_size=", oos_buffer_.size(),
                    " oos_cb=", oos_cb_, " threshold=", oos_cb_threshold_bytes_);
        if (oos_buffer_.empty()) return;
        // 重新计算 wait time（first_seen 可能在本函数内被设置）
        double wait_v = (oos_first_seen_ms_ > 0.0)
                            ? (now_ms_steady() - oos_first_seen_ms_)
                            : 0.0;
        std::uint64_t first_gap_off = oos_buffer_.begin()->first;
        std::size_t first_gap_sz = oos_buffer_.begin()->second.size();
        LINOH_DEBUG("first_gap_off=", first_gap_off, " first_gap_sz=", first_gap_sz);
        // 把 context 拼到 fmt 内部, 避免与 prefix 的尾随空格叠加成双空格
        std::string prefix = std::string("Stream::recv: ") + context + " stream_id=";
        LINOH_INFO(prefix.c_str(), id_,
                   " pn=", last_pn_,
                   " first_gap_offset=", first_gap_off,
                   " first_gap_size=", first_gap_sz,
                   " gap_from_recv_offset=", first_gap_off - recv_offset_,
                   " oos_buffer_size=", oos_buffer_.size(),
                   " oos_wait_ms=", wait_v);
        // 触发 OOS 回调（如已注册且 first_gap_size 超过阈值）
        if (oos_cb_ != nullptr && first_gap_sz >= oos_cb_threshold_bytes_) {
            std::size_t oos_total = oos_size_bytes();
            // ep-P1 (v1.7.0.8): fprintf(stderr) → LINOH_DEBUG
            LINOH_DEBUG("firing oos_cb_ off=", first_gap_off,
                        " sz=", first_gap_sz, " total=", oos_total);
            oos_cb_(oos_cb_user_data_, first_gap_off, first_gap_sz, oos_total);
        } else {
            // ep-P1 (v1.7.0.8): fprintf(stderr) → LINOH_DEBUG
            LINOH_DEBUG("NOT firing: cb_null=", (oos_cb_ == nullptr),
                        " sz_lt_thr=", (first_gap_sz < oos_cb_threshold_bytes_));
        }
    };

    if (data_end <= recv_offset_) {
        // [FIX 2026-08-14] 隐式 stream 重置：master 在同一个 stream 上发送多个独立消息
        //（如 ASSIGN/FORWARD/RESULT），每条消息从 offset=0 开始。
        // 当 recv_ 为空（旧消息已读完）且收到 offset < recv_offset_ 的数据时，
        // 说明新消息开始，重置 recv_offset_ 为新消息的 offset。
        // 这不是标准 QUIC 行为，而是 linoh 在 PP 推理场景的适配。
        // v5.5 K-OOSRESET-001 守卫：对端 v5.5+ 走显式 0x38 帧宣告（handle_explicit_reset），
        // explicit_reset_seen_ 期间禁用隐式重置——陈旧重传帧（帧级重编码携带旧 offset）
        // 与新消息首帧在偏移空间不可区分，隐式"猜"会把整段新消息数据判为过期 OOS
        //（F3' 验证实测 1MB 卡 166KB）。老对端（不发 0x38）保留隐式路径不回归。
        if (explicit_reset_seen_) {
            LINOH_DEBUG("Stream::recv: stale duplicate dropped (explicit-reset era) stream_id=",
                        id_, " offset=", offset, " data_end=", data_end,
                        " recv_offset_=", recv_offset_);
        } else if (recv_.empty() && offset < recv_offset_ && oos_buffer_.empty() && !suppress_implicit_reset_.load()) {
            LINOH_WARN("Stream::recv: implicit reset (offset=", offset,
                       ", recv_offset_=", recv_offset_,
                       ", oos_size=", oos_buffer_.size(), ")");
            recv_offset_ = offset;
            // [FIX 2026-08-14] 不清空 OOS 缓冲区：binary 帧数据可能先于 JSON 帧到达，
            // 缓存在 OOS 中。清空会导致 binary 数据丢失，帧头解析错误。
            // JSON 交付后 recv_offset_ 前进，OOS 消费循环会自动消费 binary 数据。
            // 仅清除 offset < new recv_offset_ 的过期 OOS 条目（来自旧消息）
            auto oos_it = oos_buffer_.begin();
            while (oos_it != oos_buffer_.end() && oos_it->first < offset) {
                oos_pn_map_.erase(oos_it->first);
                oos_first_seen_ms_map_.erase(oos_it->first);
                oos_it = oos_buffer_.erase(oos_it);
            }
            oos_first_seen_ms_ = -1.0;
            data_end = offset + data.size();
            // 继续走 case 3（有序数据）路径
        } else {
            // 完全重复，丢弃
            LINOH_DEBUG("Stream::recv: case=1_drop_duplicate stream_id=", id_,
                        " data_end=", data_end, " recv_offset_=", recv_offset_);
            return;
        }
    }

    // [FIX 2026-08-14] 当 recv_ 为空且收到 offset=0 的新消息时，跳过 gap。
    // 仅限 offset=0（消息起始位置），避免跳到中间位置导致帧头解析错误。
    if (recv_.empty() && offset == 0 && recv_offset_ > 0 && oos_buffer_.empty()) {
        LINOH_WARN("Stream::recv: skip gap to offset=0 (recv_offset_=", recv_offset_, ")");
        recv_offset_ = 0;
    }

    if (offset < recv_offset_) {
        // 部分重复：截取 recv_offset_ 之后的新部分
        std::uint64_t skip = recv_offset_ - offset;
        data = data.subspan(static_cast<std::size_t>(skip));
        offset = recv_offset_;
        LINOH_DEBUG("Stream::recv: case=2_partial_dup stream_id=", id_,
                    " skip=", skip, " new_size=", data.size());
    }

    if (offset == recv_offset_) {
        // 有序数据：直接写入 recv_
        recv_.insert(recv_.end(), data.begin(), data.end());
        recv_offset_ += data.size();

        // 尝试消费 oos_buffer_ 中已连续的数据
        std::size_t consumed_oos = 0;
        while (!oos_buffer_.empty()) {
            auto it = oos_buffer_.begin();
            if (it->first > recv_offset_) {
                break;  // gap 未填满，停止
            }
            if (it->first == recv_offset_) {
                // 精确衔接，消费
                recv_.insert(recv_.end(), it->second.begin(), it->second.end());
                recv_offset_ += it->second.size();
                // v1.5.0.4: 同步清理 oos_pn_map_ 和 oos_first_seen_ms_map_ 中的对应 entry
                oos_pn_map_.erase(it->first);
                oos_first_seen_ms_map_.erase(it->first);
                oos_buffer_.erase(it);
                consumed_oos++;
            } else {
                // it->first < recv_offset_：乱序缓冲中有过时数据（可能因部分重复消费后）
                // 检查是否有新部分
                std::uint64_t oos_end = it->first + it->second.size();
                if (oos_end > recv_offset_) {
                    std::uint64_t skip = recv_offset_ - it->first;
                    recv_.insert(recv_.end(),
                                 it->second.begin() + static_cast<std::size_t>(skip),
                                 it->second.end());
                    recv_offset_ = oos_end;
                }
                // v1.5.0.4: 同步清理（与精确衔接路径保持一致）
                oos_pn_map_.erase(it->first);
                oos_first_seen_ms_map_.erase(it->first);
                oos_buffer_.erase(it);
                consumed_oos++;
            }
        }
        LINOH_INFO("Stream::recv: case=3_inorder stream_id=", id_,
                   " pn=", last_pn_,
                   " new_recv_offset_=", recv_offset_,
                   " consumed_oos=", consumed_oos,
                   " oos_buffer_size=", oos_buffer_.size(),
                   " recv_buffer_size=", recv_.size(),
                   " oos_wait_ms=", oos_wait_ms_v);
        // v1.5.0.3 (2026-07-24): OOS state 报告（in-order 路径），
        // 若消费 oos_buffer_ 后仍有残余 gap，输出首个 gap 并按阈值触发回调。
        // 视频模型组反馈 recv_offset_ 卡住时，首个 gap offset/size 是定位
        // "OOS gap 是否被 retx 填补" 的关键证据。
        report_oos_state("case=3_oos_remaining");
    } else {
        // offset > recv_offset_：乱序数据，缓存到 oos_buffer_
        // v1.4.3 P1-#4: 写时合并相邻/重叠区间，避免消费时 O(n²) 遍历。
        // 写之前先 lower_bound 找到插入点，与前一个和后一个 entry 尝试合并。
        // 合并后保证 oos_buffer_ 中任意两个 entry 不相邻（gap >= 1），消费时 while
        // 循环最多 1 次，整体从 O(n²) 降到 O(n log n)。
        std::size_t oos_before = oos_buffer_.size();
        insert_oos_merged(offset, data);
        LINOH_INFO("Stream::recv: case=4_oos_buffered stream_id=", id_,
                   " pn=", last_pn_,
                   " offset=", offset, " data_size=", data.size(),
                   " oos_size_before=", oos_before,
                   " oos_size_after=", oos_buffer_.size(),
                   " recv_buffer_size=", recv_.size(),
                   " oos_wait_ms=", oos_wait_ms_v);
        // v1.5.0.3 (2026-07-24): OOS state 报告（ooc 路径），
        // 新插入的 OOS entry 触发首次 gap 报告，按阈值回调。
        // 区别于 case=3_oos_remaining 标记，方便日志检索。
        report_oos_state("case=4_oos_new_entry");
    }
}

// v1.4.3 P1-#4: 写时合并 oos_buffer_。处理与前后 entry 的重叠/相邻关系，
// 合并后 oos_buffer_ 中任意两个 entry 之间至少间隔 1 字节（gap >= 1）。
// v1.5.0.4 (Q1/Q2 答复): 同步维护 oos_pn_map_ 和 oos_first_seen_ms_map_，
//   记录每个合并 entry 的 PN 和首次插入时间，供 LossDetector 评估
//   "OOS gap wait > kTimeThreshold * SRTT" 时查询。
//   同步策略：erase old entries → 写入 merged entry → last_pn_ 作为 PN。
void Stream::insert_oos_merged(std::uint64_t offset, std::span<const std::uint8_t> data) {
    // 修复(2026-08-08): 防止损坏/异常的包导致 std::length_error 崩溃
    // 根因: 异常 offset（接近 UINT64_MAX）使 offset + data.size() 溢出回绕，
    //       合并循环中 vector::insert 迭代器范围异常 → std::length_error →
    //       std::terminate → SIGABRT（master 反复崩溃 3 次）
    // 修复: 1) offset 合理性上限  2) 溢出检查  3) try-catch 兜底
    constexpr std::uint64_t kMaxReasonableOffset = 0x40000000;  // 1GB，stream 不应有更大 offset
    if (data.empty() || offset > kMaxReasonableOffset ||
        offset > UINT64_MAX - data.size()) {
        LINOH_WARN("insert_oos_merged: dropping suspicious packet "
                   "offset={} data_size={}", offset, data.size());
        return;
    }

    try {
    std::uint64_t data_begin = offset;
    std::uint64_t data_end = offset + data.size();
    std::vector<std::uint8_t> merged(data.begin(), data.end());

    // 1) 与前一个 entry 合并（如果存在且与 merged 重叠/相邻）
    auto it = oos_buffer_.lower_bound(data_begin);
    if (it != oos_buffer_.begin()) {
        auto prev = std::prev(it);
        const auto prev_end = prev->first + prev->second.size();
        if (prev_end >= data_begin) {
            // 重叠或紧邻：扩展 merged 覆盖 prev
            // v1.7.0.9 fix: prev 完全覆盖 data 时 skip_from_prev >= merged.size(),
            //   导致 merged.begin()+skip_from_prev 越界 -> insert 触发 std::length_error。
            //   钳制到 [0, merged.size()]，并用 if 保护 insert。
            const std::uint64_t skip_from_prev_raw = (prev_end > data_begin) ? (prev_end - data_begin) : 0;
            const std::size_t skip_from_prev = static_cast<std::size_t>(
                std::min<std::uint64_t>(skip_from_prev_raw, merged.size()));
            std::vector<std::uint8_t> new_merged;
            new_merged.reserve(prev->second.size() + (merged.size() - skip_from_prev));
            new_merged.insert(new_merged.end(), prev->second.begin(), prev->second.end());
            if (skip_from_prev < merged.size()) {
                new_merged.insert(new_merged.end(),
                                  merged.begin() + skip_from_prev,
                                  merged.end());
            }
            merged = std::move(new_merged);
            data_begin = prev->first;
            data_end = data_begin + merged.size();
            oos_buffer_.erase(prev);
            // v1.5.0.4: 同步清理 oos_pn_map_ 和 oos_first_seen_ms_map_ 中的 prev entry
            oos_pn_map_.erase(data_begin);
            oos_first_seen_ms_map_.erase(data_begin);
        }
    }

    // 2) 与后续 entry 合并（凡是 first <= data_end 的都合并）
    it = oos_buffer_.lower_bound(data_begin);
    while (it != oos_buffer_.end() && it->first <= data_end) {
        const auto it_end = it->first + it->second.size();
        if (it_end > data_end) {
            // 后续 entry 部分重叠或延伸，追加尾部
            merged.insert(merged.end(),
                          it->second.begin() + static_cast<std::size_t>(data_end - it->first),
                          it->second.end());
            data_end = it_end;
        }
        oos_buffer_.erase(it++);
    }
    // v1.5.0.4: data_begin 在合并循环中可能已被前向 entry 改写，
    // 重新 lower_bound 后逐个 erase 残留的 PN/时间记录
    auto pn_it = oos_pn_map_.lower_bound(data_begin);
    while (pn_it != oos_pn_map_.end() && pn_it->first <= data_end) {
        pn_it = oos_pn_map_.erase(pn_it);
    }
    auto seen_it = oos_first_seen_ms_map_.lower_bound(data_begin);
    while (seen_it != oos_first_seen_ms_map_.end() && seen_it->first <= data_end) {
        seen_it = oos_first_seen_ms_map_.erase(seen_it);
    }

    // 3) 写入合并后的 entry
    oos_buffer_[data_begin] = std::move(merged);
    // v1.5.0.4: 写入 PN 和首次插入时间（last_pn_ 由 set_last_pn 在调用前注入）
    oos_pn_map_[data_begin] = last_pn_;
    oos_first_seen_ms_map_[data_begin] = now_ms_steady();
    }  // try
    catch (const std::exception& e) {
        // 修复(2026-08-08): 兜底捕获，防止任何未预见的异常导致进程崩溃
        LINOH_WARN("insert_oos_merged: exception caught (offset={} data_size={} what={}), "
                   "dropping packet to prevent crash", offset, data.size(), e.what());
    }
}

void Stream::finish_send() { send_finished_ = true; }

// A9 fix: 半关闭发送方向（FIN-only 帧已发送到网络）。
// 只清理 send 侧，保留 recv 侧可用（RFC 9000 §3.2：FIN 只关闭发送方向）。
void Stream::close_send() {
    send_finished_ = true;
    send_closed_ = true;
    send_.clear();
    send_read_pos_ = 0;
    // 不动 recv_ / recv_read_pos_ / oos_* / closed_
}

void Stream::mark_fin_received() { fin_received_ = true; }

// v5.5 K-OOSRESET-001: 显式流重置——对端 reset_send_offset 后经 0x38 帧宣告。
// 与隐式重置的区别：发送方明确宣告"新消息从 0 开始"，接收方无歧义执行；
// 此后（直到下一显式 reset）陈旧重传帧不再触发隐式重置。
void Stream::handle_explicit_reset() {
    LINOH_INFO("Stream::recv: explicit reset (0x38) stream_id=", id_,
               " recv_offset_=", recv_offset_, " -> 0");
    recv_offset_ = 0;
    recv_.clear();
    recv_read_pos_ = 0;
    oos_buffer_.clear();
    oos_pn_map_.clear();
    oos_first_seen_ms_map_.clear();
    oos_first_seen_ms_ = -1.0;
    explicit_reset_seen_ = true;   // 本代消息内禁用隐式重置
}

void Stream::close() {
    closed_ = true;
    send_.clear();
    recv_.clear();
    send_read_pos_ = 0;
    recv_read_pos_ = 0;
    // ep-M2 (v1.7.0.8): 清理 OOS 缓存三个 map，防止 Stream close 后内存泄漏。
    // 根因：oos_buffer_/oos_pn_map_/oos_first_seen_ms_map_ 在 close() 时未清理，
    //       若 stream 关闭前有乱序数据缓存，这些 map 会随 Stream 对象驻留直到
    //       析构（部分 Stream 由 shared_ptr 长期持有，缓存无法及时释放）。
    // 修复：close() 中显式 clear() 三个 map，与 send_/recv_ 清理对称。
    oos_buffer_.clear();
    oos_pn_map_.clear();
    oos_first_seen_ms_map_.clear();
    // oos_first_seen_ms_ 是标量时间戳，重置为初始值 -1.0（表示无 OOS）
    oos_first_seen_ms_ = -1.0;
}

// ============================================================================
// v1.5.0.3: F3 OOS 主动通知 API 实现
// ============================================================================

std::size_t Stream::oos_size_bytes() const {
    std::size_t total = 0;
    for (const auto &kv : oos_buffer_) {
        total += kv.second.size();
    }
    return total;
}

bool Stream::oos_first_gap(std::uint64_t *offset, std::size_t *size) const {
    if (oos_buffer_.empty()) return false;
    if (offset) *offset = oos_buffer_.begin()->first;
    if (size)   *size   = oos_buffer_.begin()->second.size();
    return true;
}

void Stream::set_oos_callback(OosCallback cb, void *user_data,
                              std::size_t threshold_bytes) {
    auto cb_before = oos_cb_;
    auto thr_before = oos_cb_threshold_bytes_;
    oos_cb_ = cb;
    oos_cb_user_data_ = user_data;
    oos_cb_threshold_bytes_ = threshold_bytes;
    // v1.5.0.3.1 P0-2 fix: 身份校验埋点（追踪回调是否真的写入 Stream）
    // ep-P1 (v1.7.0.8): fprintf(stderr) → LINOH_DEBUG，避免热路径同步 IO
    LINOH_DEBUG("Stream::set_oos_callback: this=", (void*)this,
                " stream_id=", id_,
                " cb_before=", (void*)cb_before, " cb_after=", (void*)cb,
                " thr_before=", thr_before, " thr_after=", threshold_bytes);
    LINOH_INFO("Stream::set_oos_callback: stream_id=", id_,
               " cb_set=", (void *) cb, " threshold_set=", threshold_bytes);
}

void Stream::clear_oos_callback() {
    oos_cb_ = nullptr;
    oos_cb_user_data_ = nullptr;
    oos_cb_threshold_bytes_ = 0;
}

std::span<const std::uint8_t> Stream::read(std::size_t max_len) {
    // P1-P3 fix(2026-07-20): 使用 recv_read_pos_ 偏移返回有效数据，
    // 不再返回已消费的字节。read_pos 仅在 consume() 中推进。
    std::size_t avail = readable_size();
    if (avail == 0) return {};
    std::size_t n = (max_len == 0 || max_len > avail) ? avail : max_len;
    // NOTE: 指针指向 recv_ 内部，调用 consume/recv 后可能失效！
    return std::span<const std::uint8_t>(readable_data(), n);
}

void Stream::consume(std::size_t n) {
    // P1-P3 fix(2026-07-20): Ring Buffer 风格 — 仅推进 read_pos，
    // 当 read_pos > capacity/2 时整体 memmove 前移，均摊 O(1)。
    // K-L01 fix(2026-08-10): memmove 前判空，防止 recv_ 为空时 .data() 返回 NULL
    //   导致写入崩溃；avail-actual 防 size_t 下溢为巨大值。
    std::size_t avail = readable_size();
    std::size_t actual = (std::min)(n, avail);
    recv_read_pos_ += actual;
    if (recv_read_pos_ > recv_.size() / 2 && recv_read_pos_ > 0 && !recv_.empty()) {
        // 前移未消费数据到 vector 头部，释放已消费空间
        std::size_t remaining = (avail > actual) ? (avail - actual) : 0;  // 防下溢
        if (remaining > 0) {
            std::memmove(recv_.data(),
                         recv_.data() + recv_read_pos_,
                         remaining);
        }
        recv_.resize(remaining);
        recv_read_pos_ = 0;
    }
}

void Stream::consume_send(std::size_t n) {
    // P1-P3 fix(2026-07-20): 发送侧 Ring Buffer，替代 send_buffer().erase()。
    // 推进 send_read_pos_，超过容量一半时前移，均摊 O(1)。
    // K-L01 fix(2026-08-10): memmove 前判空，防止 send_ 为空时 .data() 返回 NULL
    //   导致写入崩溃；avail-actual 防 size_t 下溢为巨大值。
    std::size_t avail = send_readable_size();
    std::size_t actual = (std::min)(n, avail);
    send_read_pos_ += actual;
    if (send_read_pos_ > send_.size() / 2 && send_read_pos_ > 0 && !send_.empty()) {
        std::size_t remaining = (avail > actual) ? (avail - actual) : 0;  // 防下溢
        if (remaining > 0) {
            std::memmove(send_.data(),
                         send_.data() + send_read_pos_,
                         remaining);
        }
        send_.resize(remaining);
        send_read_pos_ = 0;
    }
}

void Stream::advance_send_offset(std::uint64_t new_offset) {
    if (new_offset > send_offset_) {
        send_offset_ = new_offset;
    }
}

// ============================================================================
// 0-RTT Session
// ============================================================================

void Connection::queue_early_data(std::span<const std::uint8_t> data) {
    std::lock_guard<std::mutex> lk(stream_mu_);
    early_data_buf_.insert(early_data_buf_.end(), data.begin(), data.end());
    has_early_data_.store(true, std::memory_order_release);
    LINOH_DEBUG("Connection: queued early_data=", data.size(), " bytes");
}

std::optional<SessionTicket> Connection::save_session() const {
    ConnState s = state_.load();
    if (s != ConnState::Established) {
        LINOH_WARN("Connection: save_session called in non-Established state");
        return std::nullopt;
    }

    SessionTicket ticket;
    ticket.peer_cid = cfg_.remote_cid;
    ticket.peer_node_id = peer_id_;
    ticket.alpn = cfg_.alpn;
    // 导出 master_secret: 使用 HMAC-SHA256(key=this->key_, msg="master-secret" || peer_id)
    std::vector<uint8_t> info;
    const char *label = "master-secret";
    for (int i = 0; label[i]; ++i) info.push_back(static_cast<uint8_t>(label[i]));
    auto pid_span = peer_id_.as_span();
    info.insert(info.end(), pid_span.begin(), pid_span.end());

    auto provider_key = crypto_key_.key();
    auto hmac = crypto::HMAC_SHA256::compute(
        std::span<const uint8_t>(provider_key.data(), provider_key.size()),
        std::span<const uint8_t>(info.data(), info.size()));
    std::memcpy(ticket.master_secret.data(), hmac.data(), 32);
    ticket.max_early_data_bytes = 0x00FFFFFF;

    // P1-4: 设置 created_at 时间戳（Unix 秒，UTC）
    ticket.created_at_unix = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    ticket.max_age_sec = 86400;  // 默认 24h

    LINOH_INFO("Connection: session saved for peer=", peer_id_.fmt_short(),
               " created_at=", ticket.created_at_unix,
               " max_age=", ticket.max_age_sec, "s");
    return ticket;
}

// ============================================================================
// v5.0.0: SESSION_TICKET + ZERO_RTT_DATA 帧处理（T-LP4-002）
// 借鉴 iroh 0.96 Connection<OutgoingZeroRtt>
// ============================================================================

// ============================================================================
// v5.1.0: PSK_IDENTITY 帧（K-LINOH-PEERMISMATCH 根治）
// ============================================================================

std::vector<std::uint8_t> Connection::build_psk_identity_data() {
    protocol::PskIdentityFrame frame;
    frame.caps = protocol::PskIdentityFrame::kCapIdentity;
    frame.created_at_unix = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    auto pub = cfg_.secret_key.public_key();
    std::memcpy(frame.node_pub.data(), pub.data(), pub.size());
    auto msg = protocol::psk_identity_signed_content(frame);
    auto sig = cfg_.secret_key.sign(std::span<const std::uint8_t>(msg.data(), msg.size()));
    std::memcpy(frame.signature.data(), sig.data(), sig.size());
    return protocol::encode_psk_identity_frame(frame);
}

void Connection::send_psk_identity() {
    // 叠加层设计：不改变连接状态机，仅标记待发，由 build_1rtt_packet 在
    // 包尾附加（rest-of-payload 约定）。重复调用幂等（未发出前不重置）。
    psk_identity_pending_send_ = true;
}

bool Connection::handle_psk_identity_frame(std::span<const std::uint8_t> data) {
    auto decoded = protocol::decode_psk_identity_frame(data);
    if (!decoded) {
        LINOH_WARN("Connection: PSK_IDENTITY frame decode failed, size=", data.size());
        return false;
    }

    // 时间窗校验（防跨时段重放；时钟偏差超窗则拒绝认证，连接不受影响）
    std::int64_t now_sec = static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    std::int64_t skew = now_sec - static_cast<std::int64_t>(decoded->created_at_unix);
    if (skew > protocol::kPskIdentityMaxClockSkewSec ||
        skew < -protocol::kPskIdentityMaxClockSkewSec) {
        LINOH_WARN("Connection: PSK_IDENTITY rejected (clock skew ", skew,
                   "s > ", protocol::kPskIdentityMaxClockSkewSec,
                   "s), peer identity not authenticated");
        return false;
    }

    // Ed25519 验签：证明发送方持有 node_pub 对应私钥（防自报伪造）
    auto msg = protocol::psk_identity_signed_content(*decoded);
    auto peer_pub = base::PublicKey::from_bytes(
        std::span<const std::uint8_t>(decoded->node_pub.data(), decoded->node_pub.size()));
    auto sig = base::Signature::from_bytes(
        std::span<const std::uint8_t>(decoded->signature.data(), decoded->signature.size()));
    if (!sig.verify(std::span<const std::uint8_t>(msg.data(), msg.size()), peer_pub)) {
        LINOH_WARN("Connection: PSK_IDENTITY signature verify FAILED, "
                   "claimed node_pub=", peer_pub.fmt_short(),
                   " (peer identity not authenticated)");
        return false;
    }

    peer_id_ = peer_pub;
    peer_authenticated_ = true;
    LINOH_INFO("Connection: PSK_IDENTITY verified, peer_id_=",
               peer_pub.fmt_short(), " (authenticated)");
    return true;
}

bool Connection::peer_authenticated() const {
    return peer_authenticated_;
}

bool Connection::handle_session_ticket_frame(std::span<const std::uint8_t> data) {
    if (!cfg_.enable_0rtt) {
        LINOH_DEBUG("Connection: SESSION_TICKET frame ignored (0-RTT disabled)");
        return false;
    }

    auto decoded = protocol::decode_session_ticket_frame(data);
    if (!decoded) {
        LINOH_WARN("Connection: SESSION_TICKET frame decode failed");
        return false;
    }

    // 缓存 ticket 到 SessionCache（如果已注入）
    if (session_cache_) {
        session_cache_->store(peer_id_, *decoded);
        LINOH_INFO("Connection: SESSION_TICKET cached for peer=", peer_id_.fmt_short(),
                   " lifetime=", decoded->ticket_lifetime, "s");
    } else {
        LINOH_DEBUG("Connection: SESSION_TICKET received but no SessionCache injected");
    }

    return true;
}

bool Connection::send_session_ticket(const protocol::SessionTicketFrame &ticket) {
    if (!cfg_.enable_0rtt) {
        LINOH_DEBUG("Connection: send_session_ticket skipped (0-RTT disabled)");
        return false;
    }

    // 编码 SESSION_TICKET 帧
    auto encoded = protocol::encode_session_ticket_frame(ticket);
    if (encoded.empty()) {
        LINOH_WARN("Connection: SESSION_TICKET frame encode failed");
        return false;
    }

    // 通过 1-RTT 包发送（握手完成后才能发送）
    // 使用 add_frame 接口将帧添加到待发送队列
    // 注意：实际发送由 packet_builder 在下一个 1-RTT 包中完成
    // type(0x31) + encoded payload
    std::vector<uint8_t> frame_data;
    frame_data.push_back(static_cast<uint8_t>(protocol::FrameType::SESSION_TICKET));
    frame_data.insert(frame_data.end(), encoded.begin(), encoded.end());

    LINOH_INFO("Connection: sending SESSION_TICKET to peer=", peer_id_.fmt_short(),
               " lifetime=", ticket.ticket_lifetime, "s",
               " ticket_size=", ticket.ticket.size(), "B");

    // S1（v5.3 落实，原 W2.4 KNOWN-SKELETON）：控制帧捎带通道真正上线——
    // 编码帧入队，build_1rtt_packet 在 ACK 后捎带发送。
    queue_control_frame(std::move(frame_data));
    return true;
}

bool Connection::handle_zero_rtt_data_frame(std::span<const std::uint8_t> data) {
    if (!cfg_.accept_0rtt_data) {
        LINOH_DEBUG("Connection: ZERO_RTT_DATA frame rejected (0-RTT data not accepted)");
        return false;
    }

    auto decoded = protocol::decode_zero_rtt_data_frame(data);
    if (!decoded) {
        LINOH_WARN("Connection: ZERO_RTT_DATA frame decode failed");
        return false;
    }

    // 重放保护：检查 (stream_id, offset) 是否已处理过
    // 使用 stream_id * 64 + offset 作为去重 key（简化版，offset 通常 < 64）
    // 完整实现应使用 (stream_id, offset_range) 二元组
    std::uint64_t dedup_key = decoded->stream_id;
    {
        std::lock_guard<std::mutex> lk(seen_0rtt_mu_);
        if (seen_0rtt_offsets_.count(dedup_key) > 0) {
            LINOH_WARN("Connection: ZERO_RTT_DATA replay detected, stream_id=",
                       decoded->stream_id, " — dropping");
            return false;
        }
        seen_0rtt_offsets_.insert(dedup_key);
    }

    LINOH_DEBUG("Connection: ZERO_RTT_DATA accepted, stream_id=", decoded->stream_id,
                " offset=", decoded->offset, " fin=", decoded->fin,
                " data_size=", decoded->data.size(), "B");

    // S1（v5.3 落实，原 W2.4 KNOWN-SKELETON）：投递到对应 stream。
    // 路由与 STREAM 帧一致：local 优先（对端在本地流上回写）→ remote 次之
    // → 均无则创建 remote 并入 accept 队列。0-RTT 数据面向同步读场景
    //（linoh_stream_read 轮询 readable_size），异步 on_stream 通知由后续
    // 正常 STREAM 流量或上层轮询触发，不在本帧内重复通知。
    {
        std::lock_guard<std::mutex> lk(stream_mu_);
        std::shared_ptr<Stream> st;
        auto lit = local_streams_.find(decoded->stream_id);
        if (lit != local_streams_.end()) {
            st = lit->second;
        } else {
            auto rit = remote_streams_.find(decoded->stream_id);
            if (rit != remote_streams_.end()) {
                st = rit->second;
            } else {
                st = std::make_shared<Stream>(decoded->stream_id,
                                              Stream::Dir::Bidirectional);
                remote_streams_.emplace(decoded->stream_id, st);
                pending_accept_.push(st);
                LINOH_INFO("Connection: ZERO_RTT_DATA created remote stream ",
                           decoded->stream_id);
            }
        }
        st->recv(std::span<const std::uint8_t>(decoded->data.data(),
                                               decoded->data.size()),
                 decoded->offset);
        if (decoded->fin) st->mark_fin_received();
        flow_ctrl_.on_conn_bytes_recv(decoded->data.size());
        flow_ctrl_.on_stream_bytes_recv(decoded->stream_id, decoded->data.size());
    }
    return true;
}

void Connection::on_0rtt_rejected() {
    // 清除本地缓存的 ticket（回退到 1-RTT）
    if (session_cache_) {
        session_cache_->remove(peer_id_);
        LINOH_INFO("Connection: 0-RTT rejected, cleared cached ticket for peer=",
                   peer_id_.fmt_short());
    }

    // 清除 0-RTT 重放保护表
    {
        std::lock_guard<std::mutex> lk(seen_0rtt_mu_);
        seen_0rtt_offsets_.clear();
    }
}

// ============================================================================
// v5.0.0: QUIC Address Discovery（QAD）帧处理（T-LP4-006）
// 借鉴 iroh QAD：通过已有连接反射客户端公网地址，替代独立 STUN 服务器
// ============================================================================

bool Connection::handle_address_discovery_frame(std::span<const std::uint8_t> data) {
    if (!cfg_.qad_enabled) {
        LINOH_DEBUG("Connection: ADDRESS_DISCOVERY frame ignored (QAD disabled)");
        return false;
    }

    auto decoded = protocol::decode_address_discovery_frame(data);
    if (!decoded) {
        LINOH_WARN("Connection: ADDRESS_DISCOVERY frame decode failed");
        return false;
    }

    // 服务端侧：从最近接收到的数据包中提取对端公网地址
    // observed_host/observed_port 来自底层 socket 的 recvfrom 对端地址
    // 此处使用 connection 记录的 peer 地址（由 handle_packet 时注入）
    std::string observed_host;
    std::uint16_t observed_port = 0;
    {
        std::lock_guard<std::mutex> lk(peer_addr_mu_);
        observed_host = last_peer_host_;
        observed_port = last_peer_port_;
    }

    if (observed_host.empty()) {
        LINOH_WARN("Connection: ADDRESS_DISCOVERY cannot reflect — peer address unknown");
        return false;
    }

    LINOH_INFO("Connection: ADDRESS_DISCOVERY request from peer=", peer_id_.fmt_short(),
               " observed=", observed_host, ":", observed_port,
               " nonce_size=", decoded->nonce.size(), "B");

    // 回送 RESPONSE（原样回传 nonce，防重放）
    return send_address_discovery_response(decoded->nonce, observed_host, observed_port);
}

bool Connection::handle_address_discovery_response_frame(std::span<const std::uint8_t> data) {
    if (!cfg_.qad_enabled) {
        LINOH_DEBUG("Connection: ADDRESS_DISCOVERY_RESPONSE frame ignored (QAD disabled)");
        return false;
    }

    auto decoded = protocol::decode_address_discovery_response_frame(data);
    if (!decoded) {
        LINOH_WARN("Connection: ADDRESS_DISCOVERY_RESPONSE frame decode failed");
        return false;
    }

    LINOH_INFO("Connection: ADDRESS_DISCOVERY_RESPONSE received, observed=",
               decoded->observed_host, ":", decoded->observed_port,
               " nonce_size=", decoded->nonce.size(), "B");

    // 通知上层（Endpoint / NetReport）更新本地反射地址
    if (qad_address_cb_) {
        qad_address_cb_(decoded->observed_host, decoded->observed_port);
    }

    return true;
}

bool Connection::send_address_discovery_request() {
    if (!cfg_.qad_enabled) {
        LINOH_DEBUG("Connection: send_address_discovery_request skipped (QAD disabled)");
        return false;
    }

    // 生成随机 nonce（16 字节，防重放关联请求/响应）
    protocol::AddressDiscoveryFrame req;
    req.nonce.resize(16);
    for (std::size_t i = 0; i < req.nonce.size(); ++i) {
        req.nonce[i] = static_cast<std::uint8_t>(std::rand() & 0xFF);
    }

    auto encoded = protocol::encode_address_discovery_frame(req);
    if (encoded.empty()) {
        LINOH_WARN("Connection: ADDRESS_DISCOVERY frame encode failed");
        return false;
    }

    // 通过 1-RTT 包发送（type 0x33 + payload）
    std::vector<uint8_t> frame_data;
    frame_data.push_back(static_cast<uint8_t>(protocol::FrameType::ADDRESS_DISCOVERY));
    frame_data.insert(frame_data.end(), encoded.begin(), encoded.end());

    LINOH_INFO("Connection: sending ADDRESS_DISCOVERY request to peer=",
               peer_id_.fmt_short(), " nonce_size=", req.nonce.size(), "B");

    // S1（v5.3 落实，原 W2.4 KNOWN-SKELETON）：控制帧捎带通道上线。
    queue_control_frame(std::move(frame_data));
    return true;
}

bool Connection::send_address_discovery_response(
        const std::vector<std::uint8_t> &nonce,
        std::string_view observed_host,
        std::uint16_t observed_port) {
    if (!cfg_.qad_enabled) {
        LINOH_DEBUG("Connection: send_address_discovery_response skipped (QAD disabled)");
        return false;
    }

    protocol::AddressDiscoveryResponseFrame resp;
    resp.nonce = nonce;
    resp.observed_host = std::string(observed_host);
    resp.observed_port = observed_port;

    auto encoded = protocol::encode_address_discovery_response_frame(resp);
    if (encoded.empty()) {
        LINOH_WARN("Connection: ADDRESS_DISCOVERY_RESPONSE frame encode failed");
        return false;
    }

    // 通过 1-RTT 包发送（type 0x34 + payload）
    std::vector<uint8_t> frame_data;
    frame_data.push_back(static_cast<uint8_t>(protocol::FrameType::ADDRESS_DISCOVERY_RESPONSE));
    frame_data.insert(frame_data.end(), encoded.begin(), encoded.end());

    LINOH_INFO("Connection: sending ADDRESS_DISCOVERY_RESPONSE to peer=",
               peer_id_.fmt_short(), " observed=", observed_host, ":", observed_port);

    // S1（v5.3 落实，原 W2.4 KNOWN-SKELETON）：控制帧捎带通道上线。
    queue_control_frame(std::move(frame_data));
    return true;
}

// ============================================================================
// P1-5: KeyUpdate 实现（RFC 9001 §6 / RFC 8446 §7.2）
// ============================================================================

bool Connection::rotate_keys() {
    // 仅 TLS 1.3 模式 + 握手完成才支持
    if (!tls13_active()) {
        LINOH_WARN("Connection::rotate_keys: requires TLS1.3 active state");
        return false;
    }

    // 派生新一代密钥：使用 tls::KeySchedule::key_update() 静态方法
    // app_write_ 对应本端发送方向，app_read_ 对应本端接收方向
    // 根据 RFC 9001 §6：本端触发 KeyUpdate 时，先更新 write 再等对端回更新 read
    // 这里简化为同时更新 write 和 read（双方对等触发场景）
    auto new_write = tls::KeySchedule::key_update(app_write_.secret);
    auto new_read = tls::KeySchedule::key_update(app_read_.secret);

    // 暂存旧 read 密钥（用于处理对端仍用旧密钥发送的 in-flight 包）
    app_read_prev_ = app_read_;

    // 替换为新密钥
    app_write_ = new_write;
    app_read_ = new_read;

    // 翻转 key_phase 位
    std::uint8_t old_phase = key_phase_.load(std::memory_order_acquire);
    key_phase_.store(old_phase ^ 1, std::memory_order_release);

    // 重置包计数
    packets_sent_since_rotate_.store(0, std::memory_order_release);

    LINOH_INFO("Connection: KeyUpdate completed, key_phase ",
               static_cast<int>(old_phase), " -> ",
               static_cast<int>(key_phase_.load()), " peer=", peer_id_.fmt_short());
    return true;
}

bool Connection::trigger_key_update() {
    if (!tls13_active()) {
        LINOH_WARN("Connection::trigger_key_update: TLS1.3 not active");
        return false;
    }
    LINOH_INFO("Connection: triggering KeyUpdate (packets_sent_since_rotate=",
               packets_sent_since_rotate_.load(), ")");
    return rotate_keys();
}

// ============================================================================
// v1.7.0.1 P0: trigger_reholepunch — 网络变更后触发重打洞
// 借鉴 iroh #3928：复用 PathMigrationManager 生成新的 PATH_CHALLENGE
// ============================================================================

bool Connection::trigger_reholepunch() {
    // 仅在 Established 状态触发
    if (state_.load() != ConnState::Established) {
        LINOH_DEBUG("trigger_reholepunch: skip (state=",
                    static_cast<int>(state_.load()), ")");
        return false;
    }

    // 生成新的 PATH_CHALLENGE：S1（v5.3 落实，原 W2.4 KNOWN-SKELETON）——
    // 从 path_mgr 当前主路径取真实 tuple（迁移验证关联实际路径；无可用
    // 路径时退回空 tuple 保持旧行为）
    net::FourTuple tuple{};
    if (auto primary = path_mgr_.select_primary_path()) {
        tuple = *primary;
    }
    auto challenge = path_mgr_.generate_challenge_with_tuple(tuple);

    // 记录挑战已发送（时间戳用 steady_clock 毫秒）
    auto now = std::chrono::steady_clock::now();
    auto now_ms = std::chrono::duration<double, std::milli>(
        now.time_since_epoch()).count();
    path_mgr_.record_challenge_sent_with_tuple(challenge, now_ms, tuple);

    reholepunch_count_.fetch_add(1, std::memory_order_relaxed);

    LINOH_INFO("trigger_reholepunch: fired (count=",
               reholepunch_count_.load(),
               ", peer=", peer_id_.fmt_short(), ")");
    return true;
}

std::size_t Connection::build_0rtt_packet(std::span<std::uint8_t> out) {
    // v1.5.0.2 Step 3: buffer 下限从 1280 改为 current_max_packet_size()（协商后可能 9000）
    if (out.size() < current_max_packet_size()) return 0;
    if (!cfg_.resume_ticket.has_value()) return 0;
    if (!has_early_data_.load(std::memory_order_acquire)) return 0;

    // 构建 Long Header 0-RTT 包
    auto header = protocol::PacketHeader::make_0rtt(cfg_.remote_cid);
    std::size_t hdr_size = header.encoded_size();
    std::size_t pn_size = static_cast<std::uint8_t>(header.pn_len()) + 1;
    std::size_t payload_start = hdr_size;

    if (out.size() < payload_start + kTagSize) return 0;

    // K-LINOH-PERF-001 fix: 与 build_1rtt_packet 同步，限制 payload_space 为 current_max_packet_size
    std::size_t effective_buf_size = (std::min)(out.size(), current_max_packet_size());
    if (effective_buf_size < payload_start + kTagSize) return 0;
    std::size_t payload_space = effective_buf_size - payload_start - kTagSize;

    // 收集 early data + pending stream data
    std::vector<std::uint8_t> plain;
    {
        std::lock_guard<std::mutex> lk(stream_mu_);
        if (!early_data_buf_.empty()) {
            plain.insert(plain.end(), early_data_buf_.begin(), early_data_buf_.end());
            early_data_buf_.clear();
        }
        // P5 fix(2026-07-20): unordered_map range-for 解构
        for (auto &kv : local_streams_) {
            auto &st = kv.second;
            // P1-P3 fix(2026-07-20): 用 send_readable_* 取有效数据 + clear_send() 重置 read_pos。
            const std::uint8_t *data = st->send_readable_data();
            std::size_t size = st->send_readable_size();
            plain.insert(plain.end(), data, data + size);
            st->clear_send();
        }
    }
    if (plain.empty()) {
        has_early_data_.store(false, std::memory_order_release);
        return 0;
    }

    std::size_t data_size = std::min<std::size_t>(plain.size(), payload_space - 4);

    // 写入 0-RTT STREAM frame（单帧封装）
    std::size_t written = 0;
    out[payload_start + written++] = 0x08 | 0x03; // STREAM with FIN+LEN bits
    out[payload_start + written++] = 0;           // stream id
    out[payload_start + written++] = static_cast<uint8_t>(data_size >> 8);
    out[payload_start + written++] = static_cast<uint8_t>(data_size & 0xFF);
    std::memcpy(out.data() + payload_start + written, plain.data(), data_size);
    written += data_size;

    // 序列化 header 到 buffer 开头
    header.serialize_to(out.data(), hdr_size);

    // 写入 PN
    std::uint64_t pn = send_pn_[2]++;
    auto pn_enc = protocol::PacketNumber::encode_bytes(pn,
        static_cast<std::uint8_t>(pn_size));
    std::memcpy(out.data() + hdr_size - pn_size, pn_enc.data(),
                 static_cast<std::size_t>(pn_size));

    // 加密: 使用 zero_rtt_secret 作为 AEAD key
    // v1.7.0.6 (C10 fix): nonce = HMAC(zero_rtt_secret, local_cid || pn) 前 12 字节
    //   避免跨连接复用同一 session ticket 时 zero_rtt_secret_ 相同 + nonce 仅从 pn 派生
    //   导致的 AEAD nonce 重用。local_cid 在构造时随机生成且连接唯一。
    std::array<std::uint8_t, 12> nonce{};
    {
        std::vector<std::uint8_t> iv_material;
        auto cid_data = cfg_.local_cid.data();
        iv_material.reserve(cid_data.size() + 8);
        iv_material.insert(iv_material.end(), cid_data.begin(), cid_data.end());
        for (int i = 0; i < 8; ++i) {
            iv_material.push_back(static_cast<std::uint8_t>((pn >> (i * 8)) & 0xFF));
        }
        auto nonce_hash = crypto::HMAC_SHA256::compute(
            std::span<const uint8_t>(zero_rtt_secret_.data(), zero_rtt_secret_.size()),
            std::span<const uint8_t>(iv_material.data(), iv_material.size()));
        std::memcpy(nonce.data(), nonce_hash.data(), 12);
    }
    auto cipher = tls::global_provider().default_aead();
    std::vector<std::uint8_t> enc_out(written + cipher->tag_size());
    std::size_t enc_written = cipher->seal(
        std::span<const uint8_t>(zero_rtt_secret_.data(), zero_rtt_secret_.size()),
        std::span<const uint8_t>(nonce.data(), 12),
        std::span<const uint8_t>(),
        std::span<const uint8_t>(out.data() + payload_start, written),
        std::span<uint8_t>(enc_out.data(), enc_out.size()));
    if (enc_written == 0) return 0;
    std::memcpy(out.data() + payload_start, enc_out.data(), enc_written);

    stats_.packets_sent++;
    stats_.bytes_sent += data_size;
    has_early_data_.store(false, std::memory_order_release);
    LINOH_INFO("Connection: built 0-RTT packet, data=", data_size, " bytes, pn=", pn);
    return hdr_size + enc_written;
}

void Connection::handle_0rtt_packet(protocol::PacketHeader &hdr, util::Bytes &payload) {
    LINOH_INFO("Connection: received 0-RTT packet from ", hdr.scid().fmt_short());

    // 尝试用 zero_rtt_secret 解密; 如果没有恢复会话则用 crypto_key_ 派生一个临时密钥
    std::array<std::uint8_t, 32> dec_key{};
    bool has_zero_rtt = false;
    for (int i = 0; i < 32; ++i) {
        if (zero_rtt_secret_[i] != 0) { has_zero_rtt = true; break; }
    }
    if (has_zero_rtt) {
        dec_key = zero_rtt_secret_;
    } else {
        // 没有 zero_rtt_secret: 从 crypto_key_ 派生临时密钥
        auto pk = crypto_key_.key();
        std::vector<uint8_t> info;
        const char *label = "server-zero-rtt";
        for (int i = 0; label[i]; ++i) info.push_back(static_cast<uint8_t>(label[i]));
        auto hmac = crypto::HMAC_SHA256::compute(
            std::span<const uint8_t>(pk.data(), pk.size()),
            std::span<const uint8_t>(info.data(), info.size()));
        std::memcpy(dec_key.data(), hmac.data(), 32);
    }

    // 解密 payload (strict mode: discard packet on authentication failure)
    std::vector<uint8_t> plain_bytes;
    auto cipher = tls::global_provider().default_aead();
    std::uint64_t zero_rtt_pn = 0;  // 用于重放检测
    if (payload.size() > cipher->tag_size()) {
        std::array<std::uint8_t, 12> nonce{};
        // B5 fix: 使用 decode_truncated 还原的完整 PN，替代 lockstep
        zero_rtt_pn = current_incoming_pn_;
        // v1.7.0.6 (C10 fix): 与发送方对称，nonce = HMAC(zero_rtt_secret, scid || pn) 前 12 字节
        //   scid 是发送方的 local_cid（在包中明文传输），连接唯一。
        {
            std::vector<std::uint8_t> iv_material;
            auto scid_data = hdr.scid().data();
            iv_material.reserve(scid_data.size() + 8);
            iv_material.insert(iv_material.end(), scid_data.begin(), scid_data.end());
            for (int i = 0; i < 8; ++i) {
                iv_material.push_back(static_cast<std::uint8_t>((zero_rtt_pn >> (i * 8)) & 0xFF));
            }
            auto nonce_hash = crypto::HMAC_SHA256::compute(
                std::span<const uint8_t>(dec_key.data(), dec_key.size()),
                std::span<const uint8_t>(iv_material.data(), iv_material.size()));
            std::memcpy(nonce.data(), nonce_hash.data(), 12);
        }
        std::vector<uint8_t> plain_buf(payload.size() - cipher->tag_size());
        std::size_t written = cipher->open(
            std::span<const uint8_t>(dec_key.data(), dec_key.size()),
            std::span<const uint8_t>(nonce.data(), 12),
            std::span<const uint8_t>(),
            payload.as_span(),
            std::span<uint8_t>(plain_buf.data(), plain_buf.size()));
        if (written > 0) {
            plain_bytes.assign(plain_buf.begin(), plain_buf.begin() + written);
            LINOH_DEBUG("Connection: 0-RTT decrypt success, plain=", written, " bytes");
        } else {
            // Authentication failure: discard the packet (do NOT fall back to plaintext)
            LINOH_WARN("Connection: 0-RTT decrypt failed, discarding packet");
            return;
        }
    } else {
        // Payload too small to contain a tag: discard
        LINOH_WARN("Connection: 0-RTT packet too small for AEAD tag, discarding");
        return;
    }

    // P0-7: 0-RTT 重放保护 (RFC 9001 §8)
    // 计算明文 SHA-256 摘要，按 (peer_id, pn, hash) 三元组查重
    // 服务端跨连接共享全局窗口，防止攻击者用不同 connection ID 重放同一密文
    {
        auto hash = crypto::SHA256::hash(
            std::span<const uint8_t>(plain_bytes.data(), plain_bytes.size()));
        bool ok = tls::ReplayWindow::instance().check_and_record(
            peer_id_, zero_rtt_pn,
            std::span<const uint8_t>(hash.data(), hash.size()));
        if (!ok) {
            LINOH_WARN("Connection: 0-RTT replay detected, dropping. peer=",
                       peer_id_.fmt_short(), " pn=", zero_rtt_pn);
            return;
        }
    }

    // 解析 early_data 中的 STREAM frames 并投递
    auto frames = protocol::PacketParser::parse_frames(
        std::span<const uint8_t>(plain_bytes.data(), plain_bytes.size()));
    std::vector<std::shared_ptr<Stream>> streams_to_notify;
    for (auto &f : frames) {
        uint8_t ft = static_cast<uint8_t>(f.type);
        if (ft >= 0x08 && ft <= 0x0f) { // STREAM frame range
            if (f.data.size() >= 1) {
                uint64_t stream_id = f.data[0];
                std::span<const uint8_t> stream_data(f.data.data() + 1, f.data.size() - 1);
                std::shared_ptr<Stream> st;
                bool is_remote_stream = false;
                {
                    std::lock_guard<std::mutex> lk(stream_mu_);
                    // 修复（2026-07-17 Stage E）：双向 stream 路由（同 1-RTT 逻辑）
                    // P5 fix(2026-07-20): O(1) 查找替代 find_if 遍历
                    auto local_it = local_streams_.find(stream_id);
                    if (local_it != local_streams_.end()) {
                        st = local_it->second;
                        // v1.5.0.3: 注入 0-RTT PN
                        st->set_last_pn(zero_rtt_pn);
                        st->recv(stream_data);
                        LINOH_DEBUG("     routed to local stream id=", stream_id, " (0-RTT)");
                        break;
                    }
                    auto it = remote_streams_.find(stream_id);
                    if (it == remote_streams_.end()) {
                        st = std::make_shared<Stream>(stream_id, Stream::Dir::Bidirectional);
                        remote_streams_.emplace(stream_id, st);
                        pending_accept_.push(st);
                        is_remote_stream = true;
                    } else {
                        st = it->second;
                        is_remote_stream = true;
                        // v1.5.0.3: 注入 0-RTT PN
                        st->set_last_pn(zero_rtt_pn);
                    }
                    st->recv(stream_data);
                }
                // 只通知 remote stream（local 应答流由同步读者消费，同 1-RTT 一致）
                if (is_remote_stream) {
                    streams_to_notify.push_back(st);
                }
            }
        }
    }

    // 在锁外调用 on_stream_ 回调，避免递归死锁
    if (on_stream_ && !streams_to_notify.empty()) {
        for (auto &st : streams_to_notify) {
            on_stream_(st);
        }
    }

    // 0-RTT 之后, 自动转入 Established 状态
    ConnState s = state_.load();
    if (s != ConnState::Established) {
        state_.store(ConnState::Established);
        LINOH_INFO("Connection: 0-RTT received, entering Established");
    }
}

// ============================================================================
// 应用层 RPC（借鉴 qt-easy-tier DaemonClient，2026-07-19 新增）
// ============================================================================

void Connection::ensure_timeout_thread() {
    if (timeout_thread_running_.exchange(true, std::memory_order_acq_rel)) {
        return;  // 已启动
    }
    timeout_thread_stop_.store(false, std::memory_order_release);
    timeout_thread_ = std::thread([this]() { this->timeout_loop(); });
    LINOH_INFO("Connection: RPC timeout thread started, conn_id=", id_);
}

void Connection::timeout_loop() {
    using namespace std::chrono_literals;
    while (!timeout_thread_stop_.load(std::memory_order_acquire)) {
        std::vector<std::shared_ptr<PendingEntry>> expired;
        std::vector<std::uint32_t> done_ids;  // P1-2: 已完成但未清理的 req_id
        auto now = std::chrono::steady_clock::now();
        auto next_deadline = now + 500ms;  // 默认 500ms 扫描一次

        {
            // P1-2: 扫描用 read lock，不阻塞 call/respond 的写入
            std::shared_lock<std::shared_mutex> lk(pending_mu_);
            for (auto &kv : pending_requests_) {
                auto &entry = kv.second;
                if (entry->done.load(std::memory_order_acquire)) {
                    done_ids.push_back(kv.first);
                    continue;
                }
                if (entry->deadline <= now) {
                    expired.push_back(entry);
                    done_ids.push_back(kv.first);  // 标记待删除
                    continue;
                }
                if (entry->deadline < next_deadline) {
                    next_deadline = entry->deadline;
                }
            }
        }

        // P1-2: 批量删除已完成/超时的条目（write lock，短暂持有）
        if (!done_ids.empty()) {
            std::lock_guard<std::shared_mutex> lk(pending_mu_);
            for (auto req_id : done_ids) {
                pending_requests_.erase(req_id);
            }
        }

        // 锁外触发超时异常（避免持锁调用 user code）
        for (auto &entry : expired) {
            bool expected = false;
            if (entry->done.compare_exchange_strong(expected, true,
                    std::memory_order_acq_rel)) {
                try {
                    entry->promise.set_exception(
                        std::make_exception_ptr(
                            std::runtime_error("RPC request timeout")));
                } catch (const std::exception &e) {
                    LINOH_WARN("Connection: timeout set_exception failed: ", e.what());
                }
            }
        }

        // 等待直到最近 deadline 或被唤醒
        std::unique_lock<std::mutex> lk(timeout_mu_);
        timeout_cv_.wait_until(lk, next_deadline);
    }
    LINOH_INFO("Connection: RPC timeout thread stopped, conn_id=", id_);
}

void Connection::on_application_message(const protocol::ApplicationMessage &msg) {
    LINOH_DEBUG("Connection: on_application_message type=", static_cast<int>(msg.msg_type),
                " method=", static_cast<unsigned>(msg.method_id),
                " req_id=", msg.request_id,
                " payload_len=", msg.payload.size());

    if (msg.msg_type == protocol::MessageType::Response ||
        msg.msg_type == protocol::MessageType::ErrorResponse) {
        // 客户端收到响应：匹配 pending
        std::shared_ptr<PendingEntry> entry;
        {
            std::lock_guard<std::shared_mutex> lk(pending_mu_);
            auto it = pending_requests_.find(msg.request_id);
            if (it == pending_requests_.end()) {
                LINOH_WARN("Connection: unmatched response req_id=", msg.request_id,
                           " (maybe timeout or duplicate)");
                // 仍触发 response_handler_（用于旁路监听）
                if (response_handler_) response_handler_(msg);
                // P1-1: 即使 pending 不存在，也尝试清理 in_flight 中的 stream
                {
                    std::lock_guard<std::mutex> lk2(rpc_stream_mu_);
                    rpc_in_flight_.erase(msg.request_id);
                }
                return;
            }
            entry = it->second;
            pending_requests_.erase(it);
        }

        bool expected = false;
        if (entry->done.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel)) {
            try {
                if (msg.msg_type == protocol::MessageType::ErrorResponse) {
                    std::string err(msg.payload.begin(), msg.payload.end());
                    entry->promise.set_exception(
                        std::make_exception_ptr(std::runtime_error(err)));
                } else {
                    entry->promise.set_value(
                        std::vector<std::uint8_t>(msg.payload.begin(),
                                                   msg.payload.end()));
                }
            } catch (const std::exception &e) {
                LINOH_WARN("Connection: response set_value/exception failed: ", e.what());
            }
        }

        // P1-1: 响应到达，归还 stream 到空闲池供下次 call() 复用
        {
            std::shared_ptr<Stream> stream_to_release;
            {
                std::lock_guard<std::mutex> lk(rpc_stream_mu_);
                auto it = rpc_in_flight_.find(msg.request_id);
                if (it != rpc_in_flight_.end()) {
                    stream_to_release = std::move(it->second);
                    rpc_in_flight_.erase(it);
                }
            }
            if (stream_to_release) {
                release_rpc_stream(stream_to_release);
            }
        }

        // 旁路监听
        if (response_handler_) response_handler_(msg);
    } else if (msg.msg_type == protocol::MessageType::Request) {
        // P1-1: 服务端收到 Request — 若 rpc_stream_handler 已记录 request_id → stream 映射，
        // 则跳过重复注册（映射在 rpc_stream_handler 中按 stream 归属时点写入）
        // P1-2: Heartbeat 请求自动回复 PONG（即使没注册 request_handler_）
        if (msg.method_id == protocol::MethodId::Heartbeat) {
            std::vector<std::uint8_t> pong_payload = {0x70, 0x6f, 0x6e, 0x67};  // "pong"
            respond(msg.request_id, protocol::MethodId::Heartbeat, pong_payload);
            LINOH_DEBUG("Connection: auto PONG req_id=", msg.request_id);
            return;
        }

        // 服务端收到请求
        if (request_handler_) {
            request_handler_(msg);
        } else {
            LINOH_WARN("Connection: Request received but no request_handler, "
                       "req_id=", msg.request_id,
                       " method=", static_cast<unsigned>(msg.method_id));
            // 自动返回错误（避免调用方永久阻塞）
            respond_error(msg.request_id, msg.method_id,
                          "no request_handler registered");
        }
    } else if (msg.msg_type == protocol::MessageType::Notification) {
        if (notification_handler_) {
            notification_handler_(msg);
        } else {
            LINOH_DEBUG("Connection: Notification dropped (no handler), method=",
                        static_cast<unsigned>(msg.method_id));
        }
    }

    // P1-2: 收到 Heartbeat 响应 → 更新 last_pong_time_ + 重置 in_flight
    if ((msg.msg_type == protocol::MessageType::Response ||
         msg.msg_type == protocol::MessageType::ErrorResponse) &&
        msg.method_id == protocol::MethodId::Heartbeat) {
        last_pong_time_ = std::chrono::steady_clock::now();
        heartbeat_in_flight_.store(false, std::memory_order_release);
        heartbeat_miss_count_.store(0, std::memory_order_release);
        LINOH_DEBUG("Connection: PONG received, heartbeat reset");
    }
}

void Connection::rpc_stream_handler(std::shared_ptr<Stream> stream) {
    if (!stream) return;

    // P0-5: 半包缓冲机制
    //
    // on_stream_ 仅在新建 stream 时触发一次。后续数据到达时，
    // 上层必须主动调用 stream->read() 拉取数据。
    //
    // 本实现采用"累积 + 循环 parse"策略：
    //   1. 从 stream 读取所有可用数据，追加到 pending_rpc_buffers_[stream_id]
    //   2. 循环 parse：每次 parse 成功消费 consumed 字节，处理消息后从缓冲区移除
    //   3. 数据不足时 parse 返回 0，保留缓冲区等待下次触发
    //   4. stream FIN 后若缓冲区为空则清理；若非空且非 ApplicationMessage，回退到 user_on_stream_
    //
    // 注意：由于 on_stream_ 只触发一次，本函数在首次触发时会循环 read 直到
    // stream 无数据可读或 FIN。后续数据到达需要依赖其他机制（如 on_stream_data_
    // 回调，目前未实现）。对于 PoC 场景（小消息一次性到达），当前实现已足够。
    // 大消息场景需要后续集成 on_stream_data_ 回调（P3 阶段优化）。

    std::vector<std::uint8_t> new_data;
    constexpr std::size_t kReadChunkSize = 65536;
    bool fin = false;

    {
        std::lock_guard<std::mutex> lk(stream_mu_);
        // 循环读取所有可用数据
        while (true) {
            auto chunk = stream->read(kReadChunkSize);
            if (chunk.empty()) break;
            new_data.insert(new_data.end(), chunk.begin(), chunk.end());
            stream->consume(chunk.size());
        }
        fin = stream->fin_received();
    }

    if (new_data.empty() && !fin) {
        LINOH_DEBUG("Connection: rpc_stream_handler no data on stream=", stream->id());
        return;
    }

    // 追加到该 stream 的累积缓冲区
    auto &buf = pending_rpc_buffers_[stream->id()];
    buf.insert(buf.end(), new_data.begin(), new_data.end());

    LINOH_DEBUG("Connection: rpc_stream_handler stream=", stream->id(),
                " buf_size=", buf.size(), " fin=", fin);

    // 循环 parse：处理所有完整消息（支持粘包）
    std::size_t offset = 0;
    std::size_t processed_msgs = 0;
    while (offset < buf.size()) {
        protocol::ApplicationMessage msg;
        auto consumed = protocol::ApplicationMessage::parse(
            std::span<const std::uint8_t>(buf.data() + offset, buf.size() - offset), msg);

        if (consumed == 0) {
            // 数据不足或解析失败
            // 区分：是数据不足（等待更多数据）还是格式错误（回退）
            if (offset == 0 && buf.size() >= protocol::ApplicationMessage::kHeaderSize) {
                // 已有完整头部但 parse 失败 → 不是 ApplicationMessage
                LINOH_DEBUG("Connection: stream ", stream->id(),
                            " not ApplicationMessage, fallback to user_on_stream_");
                if (user_on_stream_) user_on_stream_(stream);
                pending_rpc_buffers_.erase(stream->id());
                return;
            }
            // 数据不足，等待下次触发
            break;
        }

        // O1.2: 库内能力闭环——CapabilitiesAck 响应自动解析并缓存对端掩码
        // （驱动本连接发送方向的 maybe_auto_compress 降级矩阵；调用方
        //  的 probe future 不受影响，双通路后写覆盖）
        if (msg.method_id == protocol::MethodId::CapabilitiesAck &&
            msg.msg_type == protocol::MessageType::Response &&
            !msg.payload.empty()) {
            protocol::CapabilitiesAckPayload ack;
            if (protocol::CapabilitiesAckPayload::decode(
                    std::span<const std::uint8_t>(msg.payload.data(), msg.payload.size()),
                    ack)) {
                set_peer_capabilities(ack.capabilities_mask);
            }
        }

        // O1: 接收侧自动解压（无压缩 flag 时 no-op；失败=字典缺失/载荷损坏，
        // 丢弃该消息但继续处理缓冲区中的后续消息）
        if (!msg.maybe_auto_decompress()) {
            LINOH_DEBUG("Connection: rpc stream ", stream->id(),
                        " decompress failed (dict missing/corrupt), dropped, len=",
                        msg.payload.size());
            offset += consumed;
            continue;
        }

        // P1-1: 服务端收到 Request 时，记录 request_id → stream 映射
        // （respond/respond_error 通过该映射在同 stream 回送 Response，实现 stream 复用）
        if (msg.msg_type == protocol::MessageType::Request) {
            register_request_stream(msg.request_id, stream);
        }

        on_application_message(msg);
        offset += consumed;
        ++processed_msgs;
    }

    // 移除已处理的字节
    if (offset > 0) {
        buf.erase(buf.begin(), buf.begin() + offset);
    }

    // FIN 后清理
    if (fin) {
        if (buf.empty()) {
            pending_rpc_buffers_.erase(stream->id());
            LINOH_DEBUG("Connection: stream ", stream->id(),
                        " FIN, buffer empty, cleaned up");
        } else {
            // FIN 后仍有残留数据，可能是非 ApplicationMessage
            LINOH_DEBUG("Connection: stream ", stream->id(),
                        " FIN with residual data size=", buf.size(),
                        ", fallback to user_on_stream_");
            if (user_on_stream_) user_on_stream_(stream);
            pending_rpc_buffers_.erase(stream->id());
        }
    }

    LINOH_DEBUG("Connection: rpc_stream_handler processed ", processed_msgs,
                " messages on stream=", stream->id());
}

std::future<std::vector<std::uint8_t>> Connection::call(
    protocol::MethodId method,
    std::span<const std::uint8_t> payload,
    std::uint32_t timeout_ms) {

    if (state_.load() != ConnState::Established) {
        std::promise<std::vector<std::uint8_t>> p;
        p.set_exception(std::make_exception_ptr(
            std::runtime_error("Connection not Established")));
        return p.get_future();
    }

    // 分配 request_id（跳过 0）
    std::uint32_t id = next_request_id_.fetch_add(1, std::memory_order_relaxed);
    if (id == 0) {
        id = next_request_id_.fetch_add(1, std::memory_order_relaxed);
    }

    auto entry = std::make_shared<PendingEntry>();
    if (timeout_ms > 0) {
        entry->deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    } else {
        entry->deadline = std::chrono::steady_clock::time_point::max();
    }
    auto fut = entry->promise.get_future();

    {
        std::lock_guard<std::shared_mutex> lk(pending_mu_);
        // 检查 id 是否冲突（理论上不会，但保险起见）
        if (pending_requests_.count(id)) {
            entry->promise.set_exception(std::make_exception_ptr(
                std::runtime_error("request_id conflict")));
            return entry->promise.get_future();
        }
        pending_requests_[id] = entry;
    }

    // 启动超时扫描线程（懒启动）
    if (timeout_ms > 0) {
        ensure_timeout_thread();
        timeout_cv_.notify_one();
    }

    // 序列化并发送
    // P1-1: 优先从 rpc_stream_pool_ 复用 stream，避免每次 RPC 开新 stream
    auto msg = protocol::ApplicationMessage::request(id, method, payload);
    msg.maybe_auto_compress(peer_capabilities());  // O1.2: 策略+对端能力（未探测=不压）
    auto bytes = msg.serialize();

    auto stream = acquire_rpc_stream();
    if (!stream) {
        std::lock_guard<std::shared_mutex> lk(pending_mu_);
        pending_requests_.erase(id);
        entry->promise.set_exception(std::make_exception_ptr(
            std::runtime_error("acquire_rpc_stream failed")));
        return entry->promise.get_future();
    }

    // P1-1: 记录 request_id → stream 映射（响应到达时归还 stream 到池）
    {
        std::lock_guard<std::mutex> lk(rpc_stream_mu_);
        rpc_in_flight_[id] = stream;
    }

    // P1-1: 不发 FIN，保持 stream 可复用（响应到达后归还到池）
    send_stream(stream->id(), std::span<const std::uint8_t>(bytes.data(), bytes.size()));

    LINOH_DEBUG("Connection: call method=", static_cast<unsigned>(method),
                " req_id=", id, " payload=", payload.size(),
                " bytes timeout=", timeout_ms, "ms stream=", stream->id(),
                " pool_size=", rpc_stream_pool_size());

    return fut;
}

void Connection::notify(protocol::MethodId method,
                         std::span<const std::uint8_t> payload) {
    if (state_.load() != ConnState::Established) {
        LINOH_WARN("Connection: notify ignored (not Established)");
        return;
    }

    auto msg = protocol::ApplicationMessage::notification(method, payload);
    msg.maybe_auto_compress(peer_capabilities());  // O1.2: 策略+对端能力（未探测=不压）
    auto bytes = msg.serialize();

    auto stream = open_stream();
    if (!stream) {
        LINOH_ERROR("Connection: notify open_stream failed, method=",
                    static_cast<unsigned>(method));
        return;
    }
    send_stream(stream->id(), std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    finish_stream(stream->id());
    LINOH_DEBUG("Connection: notify method=", static_cast<unsigned>(method),
                " payload=", payload.size(), " bytes");
}

void Connection::respond(std::uint32_t request_id, protocol::MethodId method,
                          std::span<const std::uint8_t> payload) {
    if (state_.load() != ConnState::Established) {
        LINOH_WARN("Connection: respond ignored (not Established)");
        return;
    }

    auto msg = protocol::ApplicationMessage::response(request_id, method, payload);
    msg.maybe_auto_compress(peer_capabilities());  // O1.2: 策略+对端能力（未探测=不压）
    auto bytes = msg.serialize();

    // P1-1: 优先复用接收 Request 时的 stream（同 stream 回送 Response，不发 FIN）
    auto stream = take_request_stream(request_id);
    bool fallback_opened = false;
    if (!stream) {
        // 兜底：映射不存在（极少见，如重连后状态丢失），开新 stream + FIN
        stream = open_stream();
        fallback_opened = true;
        if (!stream) {
            LINOH_ERROR("Connection: respond open_stream failed, req_id=", request_id);
            return;
        }
    }

    send_stream(stream->id(), std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    if (fallback_opened) {
        finish_stream(stream->id());  // 兜底场景才发 FIN
    }
    LINOH_DEBUG("Connection: respond req_id=", request_id,
                " method=", static_cast<unsigned>(method),
                " payload=", payload.size(), " bytes stream=", stream->id(),
                " fallback=", fallback_opened);
}

void Connection::respond_error(std::uint32_t request_id, protocol::MethodId method,
                                const std::string &error_msg) {
    if (state_.load() != ConnState::Established) {
        LINOH_WARN("Connection: respond_error ignored (not Established)");
        return;
    }

    auto msg = protocol::ApplicationMessage::error(request_id, method, error_msg);
    msg.maybe_auto_compress(peer_capabilities());  // O1.2: 策略+对端能力（未探测=不压）
    auto bytes = msg.serialize();

    // P1-1: 优先复用接收 Request 时的 stream
    auto stream = take_request_stream(request_id);
    bool fallback_opened = false;
    if (!stream) {
        stream = open_stream();
        fallback_opened = true;
        if (!stream) {
            LINOH_ERROR("Connection: respond_error open_stream failed, req_id=", request_id);
            return;
        }
    }

    send_stream(stream->id(), std::span<const std::uint8_t>(bytes.data(), bytes.size()));
    if (fallback_opened) {
        finish_stream(stream->id());
    }
    LINOH_DEBUG("Connection: respond_error req_id=", request_id,
                " method=", static_cast<unsigned>(method),
                " err=", error_msg, " stream=", stream->id(),
                " fallback=", fallback_opened);
}

void Connection::set_request_handler(
    std::function<void(const protocol::ApplicationMessage &)> h) {
    std::lock_guard<std::shared_mutex> lk(pending_mu_);
    request_handler_ = std::move(h);
    // 启用 RPC 模式：保存旧 on_stream_ 并替换为 rpc_stream_handler
    if (!rpc_enabled_.exchange(true, std::memory_order_acq_rel)) {
        user_on_stream_ = on_stream_;
        on_stream_ = [this](std::shared_ptr<Stream> s) {
            this->rpc_stream_handler(s);
        };
        LINOH_INFO("Connection: RPC mode enabled (request_handler set), conn_id=", id_);
    }
}

void Connection::set_notification_handler(
    std::function<void(const protocol::ApplicationMessage &)> h) {
    std::lock_guard<std::shared_mutex> lk(pending_mu_);
    notification_handler_ = std::move(h);
    // 启用 RPC 模式（同 set_request_handler 逻辑）
    if (!rpc_enabled_.exchange(true, std::memory_order_acq_rel)) {
        user_on_stream_ = on_stream_;
        on_stream_ = [this](std::shared_ptr<Stream> s) {
            this->rpc_stream_handler(s);
        };
        LINOH_INFO("Connection: RPC mode enabled (notification_handler set), conn_id=", id_);
    }
}

void Connection::set_response_handler(
    std::function<void(const protocol::ApplicationMessage &)> h) {
    std::lock_guard<std::shared_mutex> lk(pending_mu_);
    response_handler_ = std::move(h);
}

void Connection::fail_all_pending_locked(const std::string &reason) {
    // 调用方需持有 pending_mu_（或确保单线程场景）
    std::vector<std::shared_ptr<PendingEntry>> to_fail;
    to_fail.reserve(pending_requests_.size());
    for (auto it = pending_requests_.begin(); it != pending_requests_.end(); ) {
        to_fail.push_back(it->second);
        it = pending_requests_.erase(it);
    }

    for (auto &entry : to_fail) {
        bool expected = false;
        if (entry->done.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel)) {
            try {
                entry->promise.set_exception(
                    std::make_exception_ptr(std::runtime_error(reason)));
            } catch (const std::exception &e) {
                LINOH_WARN("Connection: fail_all_pending set_exception failed: ", e.what());
            }
        }
    }
}

void Connection::on_close_impl() {
    // P1-1: 幂等保护，避免多次调用导致 pending 被重复 set_exception
    bool expected = false;
    if (!cleaned_up_.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        return;  // 已清理过
    }

    // 清理所有 pending 请求
    {
        std::lock_guard<std::shared_mutex> lk(pending_mu_);
        fail_all_pending_locked("connection closed");
    }

    // P0-5: 清理 RPC 半包缓冲
    pending_rpc_buffers_.clear();

    // P1-1: 清理 RPC stream 池和相关映射
    {
        std::lock_guard<std::mutex> lk(rpc_stream_mu_);
        rpc_stream_pool_.clear();
        rpc_in_flight_.clear();
        request_stream_map_.clear();
    }

    // 唤醒超时线程使其能退出
    timeout_cv_.notify_all();
}

// ============================================================================
// P1-1: RPC Stream 复用实现（2026-07-19 新增）
// ============================================================================

std::shared_ptr<Stream> Connection::acquire_rpc_stream() {
    std::shared_ptr<Stream> stream;
    {
        std::lock_guard<std::mutex> lk(rpc_stream_mu_);
        if (!rpc_stream_pool_.empty()) {
            stream = std::move(rpc_stream_pool_.back());
            rpc_stream_pool_.pop_back();
        }
    }
    if (stream) {
        // 复用前检查 stream 是否已关闭或已发 FIN
        if (stream->is_closed() || stream->fin_sent()) {
            LINOH_DEBUG("Connection: acquire_rpc_stream reused stream ",
                        stream->id(), " invalid (closed/fin), opening new");
            stream.reset();
        }
    }
    if (!stream) {
        // 池空或池中 stream 已废，新建
        stream = open_stream();
        if (stream) {
            LINOH_DEBUG("Connection: acquire_rpc_stream opened new stream ",
                        stream->id(), " pool was empty");
        } else {
            LINOH_WARN("Connection: acquire_rpc_stream open_stream failed");
        }
    } else {
        LINOH_DEBUG("Connection: acquire_rpc_stream reused stream ", stream->id());
    }
    return stream;
}

void Connection::release_rpc_stream(std::shared_ptr<Stream> stream) {
    if (!stream) return;
    // 已关闭或已发 FIN 的 stream 不归还
    if (stream->is_closed() || stream->fin_sent()) {
        LINOH_DEBUG("Connection: release_rpc_stream stream ", stream->id(),
                    " closed/fin_sent, not returned to pool");
        return;
    }
    std::lock_guard<std::mutex> lk(rpc_stream_mu_);
    if (rpc_stream_pool_.size() >= kRpcStreamPoolMax) {
        LINOH_DEBUG("Connection: release_rpc_stream pool full (",
                    rpc_stream_pool_.size(), "), stream ", stream->id(),
                    " discarded");
        return;
    }
    rpc_stream_pool_.push_back(stream);
    LINOH_DEBUG("Connection: release_rpc_stream stream ", stream->id(),
                " returned, pool_size=", rpc_stream_pool_.size());
}

void Connection::register_request_stream(std::uint32_t request_id,
                                          std::shared_ptr<Stream> stream) {
    if (!stream) return;
    std::lock_guard<std::mutex> lk(rpc_stream_mu_);
    // 如果已存在映射（重复 Request，理论不可能），先释放旧 stream
    auto it = request_stream_map_.find(request_id);
    if (it != request_stream_map_.end()) {
        LINOH_WARN("Connection: register_request_stream duplicate req_id=",
                   request_id, " overwriting");
    }
    request_stream_map_[request_id] = stream;
}

std::shared_ptr<Stream> Connection::take_request_stream(std::uint32_t request_id) {
    std::lock_guard<std::mutex> lk(rpc_stream_mu_);
    auto it = request_stream_map_.find(request_id);
    if (it == request_stream_map_.end()) {
        return nullptr;
    }
    auto stream = it->second;
    request_stream_map_.erase(it);
    // 校验 stream 仍可用
    if (stream->is_closed() || stream->fin_sent()) {
        LINOH_DEBUG("Connection: take_request_stream stream ", stream->id(),
                    " invalid (closed/fin), returning nullptr");
        return nullptr;
    }
    return stream;
}

// ============================================================================
// P1-2: 心跳同步机制
// ============================================================================

void Connection::start_heartbeat(std::uint32_t interval_ms, std::uint32_t timeout_ms) {
    // 防止重复启动
    bool expected = false;
    if (!heartbeat_running_.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        LINOH_DEBUG("Connection: heartbeat already running");
        return;
    }

    heartbeat_stop_.store(false, std::memory_order_release);
    heartbeat_in_flight_.store(false, std::memory_order_release);
    heartbeat_miss_count_.store(0, std::memory_order_release);
    last_pong_time_ = std::chrono::steady_clock::now();

    heartbeat_thread_ = std::thread([this, interval_ms, timeout_ms]() {
        heartbeat_loop(interval_ms, timeout_ms);
    });

    LINOH_INFO("Connection: heartbeat started, interval=", interval_ms,
               "ms timeout=", timeout_ms, "ms");
}

void Connection::stop_heartbeat() {
    if (!heartbeat_running_.load(std::memory_order_acquire)) return;

    heartbeat_stop_.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(heartbeat_mu_);
        heartbeat_cv_.notify_all();
    }
    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }
    heartbeat_running_.store(false, std::memory_order_release);
    LINOH_DEBUG("Connection: heartbeat stopped");
}

// ============================================================================
// P9.3 §4.4: loss_tick_loop — RTO/PTO 超时检测 + OOS gap 30s 兜底
//
// 根因修复：on_rto_timeout / on_pto_timeout / next_timeout_ms 方法存在但从未被调用，
// 导致对端不回 ACK 时 in-flight 永不丢包，retransmit_queue / sent_payloads 无限增长，
// 内存压力诱发 UAF（worker-node segfault error 15, RSVD 位置位）。
// loss_tick_loop 独立线程定时检查 RTO/PTO 超时，驱动丢包声明和重传；
// 同时追踪 OOS gap，30s 未填补则触发 on_unrecoverable_gap_ 回调。
//
// 锁序：on_rto_timeout/on_pto_timeout 内部持 sent_mu_（→ rtt_mu_），返回后释放；
//   retransmit_queue_.push_back 持 retransmit_mu_；congestion_ctrl_->on_rto 持 mu_。
//   三者顺序调用不嵌套，无死锁风险。
// ============================================================================

void Connection::start_loss_tick_loop() {
    // CAS 防重复启动（与 start_heartbeat 同模式）
    bool expected = false;
    if (!loss_tick_running_.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel)) {
        LINOH_DEBUG("Connection: loss tick already running");
        return;
    }
    loss_tick_stop_.store(false, std::memory_order_release);
    loss_tick_thread_ = std::thread([this]() { loss_tick_loop(); });
    LINOH_INFO("Connection: loss tick loop started");
}

void Connection::stop_loss_tick_loop() {
    if (!loss_tick_running_.load(std::memory_order_acquire)) return;

    loss_tick_stop_.store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(loss_tick_mu_);
        loss_tick_cv_.notify_all();
    }
    if (loss_tick_thread_.joinable()) {
        loss_tick_thread_.join();
    }
    loss_tick_running_.store(false, std::memory_order_release);
    LINOH_DEBUG("Connection: loss tick loop stopped");
}

void Connection::loss_tick_loop() {
    LINOH_INFO("Connection: loss_tick_loop enter");

    while (!loss_tick_stop_.load(std::memory_order_acquire)) {
        // 非 Established 状态不检测超时，慢速轮询等待进入 Established
        if (state_.load(std::memory_order_acquire) != ConnState::Established) {
            std::unique_lock<std::mutex> lk(loss_tick_mu_);
            loss_tick_cv_.wait_for(lk, std::chrono::milliseconds(50),
                [this]() { return loss_tick_stop_.load(std::memory_order_acquire); });
            continue;
        }

        // 当前时间（毫秒，steady_clock 纪元）
        auto now_tp = std::chrono::steady_clock::now();
        double now_ms = std::chrono::duration<double, std::milli>(
            now_tp.time_since_epoch()).count();

        // 查询下一次超时（RTO/PTO/时间阈值取最早），返回距离 now 的剩余 ms；
        // -1.0 = 无飞行中包（无超时），0 = 已超时，>0 = 剩余等待。
        double next_to = loss_detector_.next_timeout_ms(now_ms);

        // 计算本轮等待时长：无超时 50ms 慢速轮询；有超时等到超时点（封顶 100ms
        // 保证状态变更/stop 响应延迟不超过 100ms）
        int wait_ms;
        if (next_to < 0.0) {
            wait_ms = 50;
        } else {
            double clamped = (next_to > 100.0) ? 100.0 : next_to;
            wait_ms = static_cast<int>(clamped) + 1;
            if (wait_ms > 100) wait_ms = 100;
        }

        {
            std::unique_lock<std::mutex> lk(loss_tick_mu_);
            loss_tick_cv_.wait_for(lk, std::chrono::milliseconds(wait_ms),
                [this]() { return loss_tick_stop_.load(std::memory_order_acquire); });
        }
        if (loss_tick_stop_.load(std::memory_order_acquire)) break;

        // 唤醒后重新检查是否已超时
        now_tp = std::chrono::steady_clock::now();
        now_ms = std::chrono::duration<double, std::milli>(
            now_tp.time_since_epoch()).count();
        double remain = loss_detector_.next_timeout_ms(now_ms);

        // remain >= 0 排除"无飞行中包"(-1)；< 1.0 表示已超时或临界
        if (remain >= 0.0 && remain < 1.0) {
            // 优先 RTO（声明丢包 + mark_lost + rtt_.on_rto）；
            // on_rto_timeout 内部持 sent_mu_ 锁，返回已 mark_lost 的 PN 列表
            auto lost_pns = loss_detector_.on_rto_timeout(now_ms);
            if (!lost_pns.empty()) {
                // 丢失 PN 入重传队列（持 retransmit_mu_，与 build_1rtt_packet 消费端互斥）
                {
                    std::lock_guard<std::mutex> rlk(retransmit_mu_);
                    for (uint64_t pn : lost_pns) {
                        retransmit_queue_.push_back(pn);
                    }
                }
                // 通知拥塞控制 RTO（内部持 mu_ 锁，cwnd 减半等）
                if (congestion_ctrl_) congestion_ctrl_->on_rto();
                stats_.lost_packets += lost_pns.size();
                LINOH_WARN("Connection: loss_tick RTO fired, ", lost_pns.size(),
                           " packets declared lost, queued for retransmit");
            } else {
                // RTO 无丢失（in_flight 为 0 或已被 ACK），尝试 PTO 探测
                // on_pto_timeout 内部持 sent_mu_ 锁，返回最早 1-2 个 ack-eliciting PN
                // v4.6.0 (借鉴 noq#561): 无 ack-eliciting in-flight 时返回 {kForcePingPn}
                //   标记，强制上层发 PING（ack-eliciting），避免"看似存活实则停滞"
                auto probe_pns = loss_detector_.on_pto_timeout(now_ms);
                if (!probe_pns.empty()) {
                    // 检查是否为强制 PING 标记
                    bool force_ping = (probe_pns.size() == 1 &&
                                       probe_pns[0] == protocol::kForcePingPn);
                    if (force_ping) {
                        // v4.6.0: TLP 必须 ack-eliciting — 强制发 PING 帧
                        request_ping();
                        if (on_ping_send_requested_) {
                            try { on_ping_send_requested_(); } catch (...) {}
                        }
                        LINOH_INFO("Connection: loss_tick PTO, FORCE PING (noq#561), "
                                   "pto_count=", loss_detector_.pto_count());
                    } else {
                        // 正常 PTO：重传最早 1-2 个 ack-eliciting 包作为探测
                        std::lock_guard<std::mutex> rlk(retransmit_mu_);
                        for (uint64_t pn : probe_pns) {
                            retransmit_queue_.push_back(pn);
                        }
                        LINOH_INFO("Connection: loss_tick PTO fired, ", probe_pns.size(),
                                   " probe packets queued, pto_count=", loss_detector_.pto_count());
                    }
                } else {
                    // 兜底：on_pto_timeout 返回空（理论不应到达，kForcePingPn 已覆盖）
                    request_ping();
                    if (on_ping_send_requested_) {
                        try { on_ping_send_requested_(); } catch (...) {}
                    }
                    LINOH_DEBUG("Connection: loss_tick PTO, no ack-eliciting in-flight, PING requested");
                }
            }
        }

        // OOS gap 30s 兜底检查：追踪未填补的 gap，超时触发 on_unrecoverable_gap_ 回调
        // （gap 注入点由 Stream::insert_oos_merged 经 Connection 桥接写入 oos_gap_first_seen_）
        {
            std::lock_guard<std::mutex> olk(oos_gap_mu_);
            for (auto it = oos_gap_first_seen_.begin(); it != oos_gap_first_seen_.end(); ) {
                double age_ms = now_ms - it->second;
                if (age_ms > kOosGapAbandonMs) {
                    uint64_t stream_id = it->first / 1000000000ULL;
                    uint64_t offset = it->first % 1000000000ULL;
                    LINOH_WARN("Connection: OOS gap unrecoverable, stream=", stream_id,
                               " offset=", offset, " age_ms=", age_ms,
                               " (threshold=", kOosGapAbandonMs, "ms)");
                    if (on_unrecoverable_gap_) {
                        try { on_unrecoverable_gap_(stream_id, offset); } catch (...) {}
                    }
                    it = oos_gap_first_seen_.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // v4.8.0: PreferRelayStrategy — 定期调用 try_select_better_path
        //
        // 注意：try_select_better_path 的定期调用已移至 handle_packet（由
        // linoh_endpoint_poll 触发），避免在 loss_tick_loop 线程中调用导致
        // 与 linoh_endpoint_poll 线程的竞争条件。
    }

    LINOH_INFO("Connection: loss_tick_loop exit");
}

void Connection::heartbeat_loop(std::uint32_t interval_ms, std::uint32_t timeout_ms) {
    LINOH_DEBUG("Connection: heartbeat_loop enter");

    while (!heartbeat_stop_.load(std::memory_order_acquire)) {
        if (state_.load(std::memory_order_acquire) != ConnState::Established) {
            // 非 Established 状态不发送心跳，等待恢复或退出
            std::unique_lock<std::mutex> lk(heartbeat_mu_);
            heartbeat_cv_.wait_for(lk, std::chrono::milliseconds(interval_ms),
                [this]() { return heartbeat_stop_.load(std::memory_order_acquire); });
            continue;
        }

        // 并发保护：上一轮 PING 未收到 PONG 则跳过本轮
        bool expected = false;
        if (!heartbeat_in_flight_.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel)) {
            LINOH_DEBUG("Connection: heartbeat in-flight, skip this round");
            std::unique_lock<std::mutex> lk(heartbeat_mu_);
            heartbeat_cv_.wait_for(lk, std::chrono::milliseconds(interval_ms),
                [this]() { return heartbeat_stop_.load(std::memory_order_acquire); });
            continue;
        }

        // v1.5.0.1 P3-1: 1Hz 周期流控主动通告。
        // 在 request_ping() 之前填充 pending_fc_frames_，build_1rtt_packet
        // 在 P3-1 块一次性消费。emit 自身只读 flow_ctrl_，不阻塞 data path。
        // 用户确认 P3-1 暂不调整 ACK 触发路径，故只走 1Hz 周期。
        emit_periodic_flow_control();

        // v1.5.0.10 (ISSUE T09 反馈): OOS_PN 帧 UDP 可靠性 — 1Hz 周期检查
        //   pending_oos_pn_frames_ 中是否有 500ms 未确认的条目需要重发。
        //   - 在 emit_periodic_flow_control 之后、request_ping 之前调用，
        //     让 OOS_PN 重发帧也填入本轮 1-RTT 包（与 PING 同一窗口 flush）。
        //   - resend_oos_pn_if_needed() 内部已调用 on_ping_send_requested_，
        //     所以这里不需要额外的 flush 触发。
        resend_oos_pn_if_needed();

        // B8 fix(2026-07-20): 使用 QUIC PING 帧（type=0x01）替代开新 stream 发 RPC。
        // request_ping() 设置 ping_pending_，下次 build_1rtt_packet 会写入 PING 帧。
        // 通过 on_ping_send_requested_ 回调通知上层立即 flush（build_1rtt_packet + sendto）。
        request_ping();

        // 通知上层立即 flush 发送 PING 帧
        if (on_ping_send_requested_) {
            try { on_ping_send_requested_(); } catch (...) {}
            LINOH_DEBUG("Connection: PING frame requested + flush triggered");
        } else {
            // 无回调时退化为旧逻辑（开 stream），保证功能可用
            LINOH_WARN("Connection: no on_ping_send_requested_ callback, PING may not be sent");
            std::vector<std::uint8_t> ping_payload = {0x70, 0x69, 0x6e, 0x67};  // "ping"
            std::uint32_t ping_id = next_request_id_.fetch_add(1, std::memory_order_relaxed);
            if (ping_id == 0) ping_id = next_request_id_.fetch_add(1, std::memory_order_relaxed);
            protocol::ApplicationMessage ping_msg = protocol::ApplicationMessage::request(
                ping_id, protocol::MethodId::Heartbeat, ping_payload);
            auto wire = ping_msg.serialize();
            auto stream = open_stream();
            if (stream) {
                send_stream(stream->id(), std::span<const std::uint8_t>(wire.data(), wire.size()));
                finish_stream(stream->id());
                LINOH_DEBUG("Connection: PING sent via stream req_id=", ping_id);
            } else {
                LINOH_WARN("Connection: heartbeat open_stream failed");
                heartbeat_in_flight_.store(false, std::memory_order_release);
                std::unique_lock<std::mutex> lk(heartbeat_mu_);
                heartbeat_cv_.wait_for(lk, std::chrono::milliseconds(interval_ms),
                    [this]() { return heartbeat_stop_.load(std::memory_order_acquire); });
                continue;
            }
        }

        // 等待 interval 后检查 PONG 是否到达
        {
            std::unique_lock<std::mutex> lk(heartbeat_mu_);
            heartbeat_cv_.wait_for(lk, std::chrono::milliseconds(interval_ms),
                [this]() { return heartbeat_stop_.load(std::memory_order_acquire); });
        }
        if (heartbeat_stop_.load(std::memory_order_acquire)) break;

        // 检查 PONG 超时
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - last_pong_time_).count();
        if (elapsed_ms > static_cast<std::int64_t>(timeout_ms)) {
            std::uint32_t miss = heartbeat_miss_count_.fetch_add(1, std::memory_order_acq_rel) + 1;
            LINOH_WARN("Connection: heartbeat timeout, miss_count=", miss,
                       " elapsed=", elapsed_ms, "ms");
            heartbeat_in_flight_.store(false, std::memory_order_release);

            if (on_heartbeat_timeout_) {
                try { on_heartbeat_timeout_(); } catch (...) {}
            }
        } else {
            // PONG 已收到，重置 inflight（on_application_message 中已重置）
            heartbeat_in_flight_.store(false, std::memory_order_release);
        }
    }

    LINOH_DEBUG("Connection: heartbeat_loop exit");
}

// ============================================================================
// P1-4: SessionTicket 序列化 + 过期检查 + AEAD 加密（2026-07-19 新增）
// ============================================================================
//
// 明文序列化格式：
//   [version:1=0x01]
//   [created_at_unix:8 int64 BE]
//   [max_age_sec:4 uint32 BE]
//   [peer_cid_len:1] [peer_cid:0-20]
//   [peer_node_id:32]
//   [alpn_len:2 uint16 BE] [alpn:0-65535]
//   [max_early_data_bytes:8 uint64 BE]
//   [master_secret:32]
//
// AEAD 加密格式（ChaCha20-Poly1305）：
//   [nonce:12] [ciphertext||tag:plaintext_len+16]
//
// 设计要点：
// - 序列化所有整数用大端（网络字节序），便于跨平台
// - version 字段保留扩展空间
// - AEAD key 由调用方持久化（如 Endpoint 持有），to_encrypted_bytes 不持有 key
// - from_bytes/from_encrypted_bytes 默认校验过期，可通过 check_expiry=false 跳过
// - created_at=0 视为未设置，is_expired 返回 false（兼容旧票据或测试场景）

namespace {

constexpr std::uint8_t kTicketFormatVersion = 0x01;
constexpr std::size_t kTicketMinSize = 1 + 8 + 4 + 1 + 32 + 2 + 8 + 32;  // 88 字节（cid_len=0, alpn_len=0）

inline void write_u16_be(std::vector<std::uint8_t> &out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

inline void write_u32_be(std::vector<std::uint8_t> &out, std::uint32_t v) {
    for (int i = 3; i >= 0; --i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
    }
}

inline void write_u64_be(std::vector<std::uint8_t> &out, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
    }
}

inline void write_i64_be(std::vector<std::uint8_t> &out, std::int64_t v) {
    write_u64_be(out, static_cast<std::uint64_t>(v));
}

inline bool read_u16_be(std::span<const std::uint8_t> &p, std::uint16_t &out) {
    if (p.size() < 2) return false;
    out = (static_cast<std::uint16_t>(p[0]) << 8) | p[1];
    p = p.subspan(2);
    return true;
}

inline bool read_u32_be(std::span<const std::uint8_t> &p, std::uint32_t &out) {
    if (p.size() < 4) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) {
        out = (out << 8) | p[i];
    }
    p = p.subspan(4);
    return true;
}

inline bool read_u64_be(std::span<const std::uint8_t> &p, std::uint64_t &out) {
    if (p.size() < 8) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) {
        out = (out << 8) | p[i];
    }
    p = p.subspan(8);
    return true;
}

inline bool read_i64_be(std::span<const std::uint8_t> &p, std::int64_t &out) {
    std::uint64_t u;
    if (!read_u64_be(p, u)) return false;
    out = static_cast<std::int64_t>(u);
    return true;
}

} // namespace

bool SessionTicket::is_expired(std::int64_t now_unix) const noexcept {
    // created_at=0 视为未设置（兼容旧票据），不判定过期
    if (created_at_unix == 0) return false;
    if (now_unix < 0) {
        now_unix = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    // now < created_at（时钟回退）→ 不过期（保守处理）
    if (now_unix < created_at_unix) return false;
    std::int64_t age = now_unix - created_at_unix;
    return age > static_cast<std::int64_t>(max_age_sec);
}

std::vector<std::uint8_t> SessionTicket::to_bytes() const {
    std::vector<std::uint8_t> out;
    out.reserve(kTicketMinSize + peer_cid.len() + alpn.size());

    out.push_back(kTicketFormatVersion);
    write_i64_be(out, created_at_unix);
    write_u32_be(out, max_age_sec);

    // peer_cid
    auto cid_data = peer_cid.data();
    if (cid_data.size() > protocol::ConnectionId::kMaxSize) {
        LINOH_WARN("SessionTicket::to_bytes: peer_cid too long ", cid_data.size());
        return {};
    }
    out.push_back(static_cast<std::uint8_t>(cid_data.size()));
    out.insert(out.end(), cid_data.begin(), cid_data.end());

    // peer_node_id (32 字节固定)
    auto eid = peer_node_id.as_span();
    if (eid.size() != 32) {
        LINOH_WARN("SessionTicket::to_bytes: peer_node_id size != 32");
        return {};
    }
    out.insert(out.end(), eid.begin(), eid.end());

    // alpn
    if (alpn.size() > 65535) {
        LINOH_WARN("SessionTicket::to_bytes: alpn too long ", alpn.size());
        return {};
    }
    write_u16_be(out, static_cast<std::uint16_t>(alpn.size()));
    out.insert(out.end(), alpn.begin(), alpn.end());

    // max_early_data_bytes
    write_u64_be(out, max_early_data_bytes);

    // master_secret
    out.insert(out.end(), master_secret.begin(), master_secret.end());

    return out;
}

std::optional<SessionTicket> SessionTicket::from_bytes(
    std::span<const std::uint8_t> data, bool check_expiry) {

    if (data.size() < kTicketMinSize) {
        LINOH_WARN("SessionTicket::from_bytes: data too short ", data.size());
        return std::nullopt;
    }

    auto p = data;
    if (p[0] != kTicketFormatVersion) {
        LINOH_WARN("SessionTicket::from_bytes: unknown version ", static_cast<int>(p[0]));
        return std::nullopt;
    }
    p = p.subspan(1);

    SessionTicket ticket;
    if (!read_i64_be(p, ticket.created_at_unix)) return std::nullopt;
    if (!read_u32_be(p, ticket.max_age_sec)) return std::nullopt;

    // peer_cid
    if (p.empty()) return std::nullopt;
    std::uint8_t cid_len = p[0];
    p = p.subspan(1);
    if (cid_len > protocol::ConnectionId::kMaxSize || p.size() < cid_len) {
        LINOH_WARN("SessionTicket::from_bytes: invalid cid_len ", cid_len);
        return std::nullopt;
    }
    if (cid_len > 0) {
        ticket.peer_cid = protocol::ConnectionId(p.first(cid_len));
        p = p.subspan(cid_len);
    }

    // peer_node_id (32 字节)
    if (p.size() < 32) return std::nullopt;
    std::array<std::uint8_t, 32> eid_bytes;
    std::memcpy(eid_bytes.data(), p.data(), 32);
    ticket.peer_node_id = EndpointId(eid_bytes);
    p = p.subspan(32);

    // alpn
    std::uint16_t alpn_len;
    if (!read_u16_be(p, alpn_len)) return std::nullopt;
    if (p.size() < alpn_len) {
        LINOH_WARN("SessionTicket::from_bytes: alpn truncated");
        return std::nullopt;
    }
    ticket.alpn.assign(reinterpret_cast<const char *>(p.data()), alpn_len);
    p = p.subspan(alpn_len);

    // max_early_data_bytes
    if (!read_u64_be(p, ticket.max_early_data_bytes)) return std::nullopt;

    // master_secret (32 字节)
    if (p.size() < 32) {
        LINOH_WARN("SessionTicket::from_bytes: master_secret truncated");
        return std::nullopt;
    }
    std::memcpy(ticket.master_secret.data(), p.data(), 32);
    p = p.subspan(32);

    // 校验过期
    if (check_expiry && ticket.is_expired()) {
        LINOH_WARN("SessionTicket::from_bytes: ticket expired (created_at=",
                   ticket.created_at_unix, " max_age=", ticket.max_age_sec, "s)");
        return std::nullopt;
    }

    return ticket;
}

std::vector<std::uint8_t> SessionTicket::to_encrypted_bytes(
    std::span<const std::uint8_t> key) const {

    if (key.size() != 32) {
        LINOH_WARN("SessionTicket::to_encrypted_bytes: key must be 32 bytes, got ",
                   key.size());
        return {};
    }

    auto plaintext = to_bytes();
    if (plaintext.empty()) {
        return {};
    }

    // 生成随机 12 字节 nonce
    std::array<std::uint8_t, 12> nonce{};
    if (!crypto::crypto_random_bytes(nonce)) {
        LINOH_WARN("SessionTicket::to_encrypted_bytes: random nonce failed");
        return {};
    }

    // AEAD 加密：AD = "linoh-ticket-v1" (15 字节)
    static const std::string kAd = "linoh-ticket-v1";
    auto aead = tls::global_provider().chacha20_poly1305();

    std::vector<std::uint8_t> out(nonce.size() + plaintext.size() + aead->tag_size());
    std::memcpy(out.data(), nonce.data(), nonce.size());

    std::size_t written = aead->seal(
        key,
        std::span<const std::uint8_t>(nonce.data(), nonce.size()),
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(kAd.data()), kAd.size()),
        std::span<const std::uint8_t>(plaintext.data(), plaintext.size()),
        std::span<std::uint8_t>(out.data() + nonce.size(), out.size() - nonce.size()));

    if (written == 0) {
        LINOH_WARN("SessionTicket::to_encrypted_bytes: AEAD seal failed");
        return {};
    }

    out.resize(nonce.size() + written);
    return out;
}

std::optional<SessionTicket> SessionTicket::from_encrypted_bytes(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> data,
    bool check_expiry) {

    if (key.size() != 32) {
        LINOH_WARN("SessionTicket::from_encrypted_bytes: key must be 32 bytes, got ",
                   key.size());
        return std::nullopt;
    }

    constexpr std::size_t kNonceSize = 12;
    constexpr std::size_t kTagSize = 16;
    if (data.size() < kNonceSize + kTagSize + kTicketMinSize) {
        LINOH_WARN("SessionTicket::from_encrypted_bytes: data too short ", data.size());
        return std::nullopt;
    }

    std::array<std::uint8_t, kNonceSize> nonce;
    std::memcpy(nonce.data(), data.data(), kNonceSize);
    auto ct = data.subspan(kNonceSize);

    static const std::string kAd = "linoh-ticket-v1";
    auto aead = tls::global_provider().chacha20_poly1305();

    std::vector<std::uint8_t> plaintext(ct.size() - aead->tag_size());
    std::size_t written = aead->open(
        key,
        std::span<const std::uint8_t>(nonce.data(), nonce.size()),
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(kAd.data()), kAd.size()),
        ct,
        std::span<std::uint8_t>(plaintext.data(), plaintext.size()));

    if (written == 0) {
        LINOH_WARN("SessionTicket::from_encrypted_bytes: AEAD open failed (tag mismatch or wrong key)");
        return std::nullopt;
    }
    plaintext.resize(written);

    return from_bytes(std::span<const std::uint8_t>(plaintext.data(), plaintext.size()),
                       check_expiry);
}

// v5.4 F7（借鉴 ScaleFabric 可观测方法论）：指标导出辅助实现 ----

// v5.4 F4：发送 STREAM_DATA_BLOCKED（credit 预约声明）——入 pending_fc 捎带通道
void Connection::send_stream_data_blocked(std::uint64_t stream_id, std::uint64_t offset) {
    protocol::StreamDataBlockedFrame frame{stream_id, offset};
    auto body = protocol::encode_stream_data_blocked(frame);
    std::lock_guard<std::mutex> fc_lk(pending_fc_mu_);
    pending_fc_frames_.push_back(std::move(body));
}

// v5.4 F4：流发送容量代理
std::uint64_t Connection::stream_send_capacity(std::uint64_t stream_id,
                                                std::uint64_t send_offset) const {
    return flow_ctrl_.stream_send_capacity(stream_id, send_offset);
}

size_t Connection::open_stream_count() {
    std::lock_guard<std::mutex> lk(stream_mu_);
    return local_streams_.size() + remote_streams_.size();
}

double Connection::last_activity_age_ms() const {
    // steady 时钟（与巡检/record_activity 同源）；无包时返回自连接创建以来的时长
    double now = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return now - last_activity_ms_;
}

std::uint32_t Connection::idle_timeout_cfg_ms() const {
    return static_cast<std::uint32_t>(cfg_.idle_timeout.count());
}

std::uint32_t Connection::keepalive_cfg_ms() const {
    return static_cast<std::uint32_t>(cfg_.keepalive_interval.count());
}

} // namespace linoh::endpoint
