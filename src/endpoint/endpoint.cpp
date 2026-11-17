#include "linoh/endpoint/endpoint.hpp"

#include "linoh/nat/holepunch_cache.hpp"  // S6-③: 打洞结果缓存（TTL 复用）
#include "linoh/relay/client.hpp"
#include "linoh/util/logging.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>

namespace linoh::endpoint {

namespace {
std::atomic<uint64_t> g_next_connection_id{1};
}

std::shared_ptr<Endpoint> Endpoint::make(linoh_asio::io_context &ctx, Config cfg) {
    struct make_shared_enabler : public Endpoint {
        make_shared_enabler(linoh_asio::io_context &c, Config config)
            : Endpoint(c, std::move(config)) {}
    };
    // v1.4.4 BUG#B: 用 aliasing shared_ptr 包装 make_shared_enabler 内存为
    // shared_ptr<Endpoint>，避免 make_shared<Derived> + enable_shared_from_this<Base>
    // 继承场景下 MSVC 不正确初始化 Base 类型 weak_ptr 的 bug。
    // 原实现 std::make_shared<make_shared_enabler> 创建的 control block 中 weak_ptr
    // 指向 Derived 类型，Endpoint::shared_from_this() 内部访问 weak_ptr<Endpoint>
    // 时栈保护触发 STATUS_STACK_BUFFER_OVERRUN (0xC0000409)。
    auto ep_raw = std::make_shared<make_shared_enabler>(ctx, std::move(cfg));
    std::shared_ptr<Endpoint> ep(ep_raw, ep_raw.get());

    // v1.4.4 BUG#B: 在 make_shared 完成后才调用 shared_from_this()，此时 control
    // block 已完全建立。MSVC 的 std::make_shared 在 C++20 之前对继承 + private
    // constructor + enable_shared_from_this 的组合存在 init 时序问题；移到
    // make_shared 返回之后规避。
    std::weak_ptr<Endpoint> weak_self = ep->shared_from_this();
    ep->on_datagram([weak_self](const base::EndpointId &, util::Bytes data, const base::TransportAddr &from) {
        auto self = weak_self.lock();
        if (!self) return;  // Endpoint 已析构，丢弃 datagram
        self->handle_incoming(from, std::move(data));
    });

    return ep;
}

Endpoint::Endpoint(linoh_asio::io_context &ctx, Config cfg)
    : ctx_{ctx}, cfg_{std::move(cfg)}, token_key_{tls::HandshakeTokenKey::generate()} {
    socket_ = std::make_shared<net::Socket>(ctx_);
    auto udp4 = net::UdpTransport::make(ctx_, /*ipv6=*/false, 0);
    auto udp6 = net::UdpTransport::make(ctx_, /*ipv6=*/true, 0);
    udp4->start();
    udp6->start();
    direct_addrs_.push_back([&udp4] {
        base::TransportAddr a;
        a.kind = base::TransportKind::Ip;
        a.host = "127.0.0.1";
        a.port = udp4->local_port();
        return a;
    }());
    const auto local_port = udp4->local_port();  // 保存端口用于 external_addresses
    socket_->add_transport(std::move(udp4));
    socket_->add_transport(std::move(udp6));

    // v4.8.0 (T-LP3-003): external_addresses — 已知公网地址（借鉴 iroh#4098）
    // 配置后直接作为 direct address 通告给对端，跳过 STUN 探测。
    // 适配反向代理/云环境（已知公网 IP 时 bypass 发现）。
    for (const auto &ext : cfg_.external_addresses) {
        base::TransportAddr a;
        a.kind = base::TransportKind::Ip;
        a.host = ext;
        a.port = local_port;
        direct_addrs_.push_back(std::move(a));
    }

    // v1.4.4 BUG#B: datagram handler 注册从构造函数移到 Endpoint::make()，
    // 避免在 make_shared<Derived> 期间调用 shared_from_this() 触发 MSVC
    // enable_shared_from_this 继承 bug（栈保护 → STATUS_STACK_BUFFER_OVERRUN）。
    // 当前构造函数不再直接调用 shared_from_this() 和 socket_->set_datagram_handler。
    // socket_->set_datagram_handler 等价于 ep->on_datagram(handler)，由 make() 在
    // make_shared 返回后统一完成。

    LINOH_INFO("Endpoint started. node_id=", id().fmt_short(),
               "udp4_port=", local_udp_port());

    // ─── Bootstrap: auto-connect to relay servers ───
    if (cfg_.bootstrap.auto_connect && !cfg_.bootstrap.relay_urls.empty()) {
        for (auto &relay_url : cfg_.bootstrap.relay_urls) {
            add_relay(relay_url);
            LINOH_INFO("Bootstrap: added relay", relay_url.url());
        }
        // Note: actual relay connection happens in add_relay() →
        // will be triggered when data needs to be sent via relay.
        // Full relay auto-connect on startup requires async handling
        // which will be implemented in Phase 3 (TLS + real Asio).
    }

    // ─── Bootstrap: seed known nodes into address lookup ───
    if (cfg_.lookup && !cfg_.bootstrap.known_nodes.empty()) {
        for (auto &node_id : cfg_.bootstrap.known_nodes) {
            // Register known node with a placeholder address
            // (actual address will be discovered via relay/DNS)
            base::EndpointAddr addr(node_id);
            cfg_.lookup->publish(addr);
            LINOH_INFO("Bootstrap: seeded known node", node_id.fmt_short());
        }
    }

    // ─── P5-D-3: NAT 穿透强化组件初始化 ───
    // 方案 A：PortPredictor / NatStats 构造函数已自动加载持久化数据（单一加载点），
    // Endpoint 不再显式 load_from_file，避免双重加载导致 observation_count 翻倍。
    if (cfg_.enable_nat_hardening) {
        port_predictor_ = std::make_unique<nat::PortPredictor>(cfg_.port_predictor_config);
        nat_stats_ = std::make_unique<nat::NatStats>(cfg_.nat_stats_config);
        LINOH_INFO("Endpoint: NAT hardening enabled (port_predictor + nat_stats)");
    } else {
        LINOH_INFO("Endpoint: NAT hardening disabled (v3.5 fallback mode)");
    }

    // ─── P0-G3: 被动端点更新器初始化 ───
    // 收包路径联动 ensure_path_for_peer：源地址与记录不符时限频更新端点地址，
    // 适配对称 NAT 端口跳跃（NAT 为每个新目的分配新映射，对端响应源端口与 STUN
    // 观测端口不同）。限频 cooldown 防止频繁抖动。
    if (cfg_.enable_passive_endpoint_update) {
        passive_endpoint_updater_ = std::make_unique<nat::PassiveEndpointUpdater>(
            cfg_.passive_endpoint_updater_config);
        LINOH_INFO("Endpoint: passive endpoint updater enabled (cooldown=",
                   cfg_.passive_endpoint_updater_config.cooldown.count(), "ms)");
    } else {
        LINOH_INFO("Endpoint: passive endpoint updater disabled (v4.4.0 fallback mode)");
    }
}

void Endpoint::handle_incoming(const base::TransportAddr &from, util::Bytes wire) {
    LINOH_DEBUG("Endpoint::handle_incoming entered. wire_size=", wire.size());
    if (wire.size() < 2) {
        LINOH_DEBUG("Endpoint::handle_incoming: wire too small, return");
        return;
    }

    std::span<const uint8_t> wire_span(wire.data(), wire.size());
    protocol::PacketParser parser(wire_span);

    auto pkt_opt = parser.parse();
    if (!pkt_opt) {
        LINOH_DEBUG("Endpoint: packet parse failed! wire[0]=",
                   static_cast<int>(wire.data()[0]));
        return;
    }

    auto &pkt = *pkt_opt;
    auto &hdr = pkt.header;
    LINOH_DEBUG("Endpoint: parsed packet type=",
               static_cast<int>(hdr.type()),
               " dcid=", hdr.dcid().fmt_short(),
               " scid=", hdr.scid().fmt_short());

    // 查找或创建 Connection
    std::shared_ptr<Connection> conn;
    {
        std::lock_guard lock(conn_mu_);
        // v1.4.3 P2-#2: 移除无条件 LINOH_DEBUG（每次 handle_incoming 都遍历 + 输出，
        // 高 QPS 场景下日志量爆炸）。仅在 conn 未命中时按需诊断。
        auto it = connections_.find(hdr.dcid());
        if (it != connections_.end()) {
            conn = it->second;
        } else {
            // v1.5.0.1 E2E stress: from_addr fallback (针对 1-RTT 包 DCID=0 长度的场景)
            // 根因：linoh 1.4/1.5 简化握手下，client 端 conn.remote_cid 为空，
            //       发 1-RTT 包时 DCID=0 长度，server 端按 dcid 永远查不到 conn。
            //       修复：按 from_addr 反向查 conn（conn 创建时记录 from_addr）
            conn = find_conn_by_addr(from);
            if (conn) {
                LINOH_INFO("Endpoint: matched existing conn by from_addr (",
                           from.host, ":", from.port, ")");
            } else {
                LINOH_INFO("Endpoint: no existing conn for dcid=",
                           hdr.dcid().fmt_short(), " size=", connections_.size());
            }
        }
    }

    // 如果找不到 Connection 且是 Initial 包，则创建新连接（入站）
    // 注意：客户端后续的 1-RTT 包会把自己的 client_cid 作为 dcid 发送给服务器
    // 因此连接需要以 scid(客户端cid) 作为 key 存储，而不是 dcid(空)
    if (!conn && hdr.type() == protocol::PacketType::Initial) {
        Connection::Config cfg;
        cfg.secret_key = SecretKey::generate();
        cfg.local_cid = hdr.scid();  // 服务器用客户端的 scid 作为连接标识
        cfg.remote_cid = hdr.scid();
        cfg.direction = Direction::Inbound;
        cfg.alpn = "";

        auto new_conn = std::make_shared<Connection>(std::move(cfg));
        conn = new_conn;

        {
            std::lock_guard lock(conn_mu_);
            connections_.emplace(hdr.scid(), new_conn);
        }

        // v1.5.0.1 E2E stress: 记录 from_addr → conn 反向映射（用于 1-RTT 包 DCID=0 长度场景）
        {
            std::lock_guard lock(addr_conn_mu_);
            addr_to_conn_[from] = new_conn;
        }

        // 路径迁移：为新连接的 peer 注册第一条 Path
        ensure_path_for_peer(new_conn->peer_id(), from);

        std::span<const uint8_t> pkt_span1(wire.data(), wire.size());
        LINOH_DEBUG("Endpoint: calling handle_packet for new conn");
        new_conn->handle_packet(util::Bytes(pkt_span1));
        LINOH_DEBUG("Endpoint: handle_packet done. state=",
                   (int)new_conn->state(), " Established=",
                   (int)ConnState::Established);

        if (new_conn->state() == ConnState::Established) {
            std::lock_guard lock(incoming_mu_);
            LINOH_DEBUG("Endpoint: building Incoming struct");
            Incoming inc;
            inc.conn = new_conn;
            inc.peer = new_conn->peer_id();
            inc.from = from;
            inc.alpn = new_conn->alpn();
            pending_incoming_.push(inc);
            LINOH_DEBUG("Endpoint: pushed to pending_incoming_. queue size=",
                       pending_incoming_.size());
        } else {
            LINOH_DEBUG("Endpoint: conn state is not Established");
        }
        return;
    }

    if (conn) {
        LINOH_DEBUG("Endpoint: found existing conn id=", conn->id(),
                   " state=", (int)conn->state());
        // 路径迁移：检测来自已知 peer 的新地址，自动注册为新 Path
        ensure_path_for_peer(conn->peer_id(), from);

        std::span<const uint8_t> pkt_span2(wire.data(), wire.size());
        bool was_est = (conn->state() == ConnState::Established);
        LINOH_DEBUG("Endpoint: calling handle_packet for existing conn");
        conn->handle_packet(util::Bytes(pkt_span2));
        LINOH_DEBUG("Endpoint: handle_packet done");

        if (!was_est && conn->state() == ConnState::Established) {
            std::lock_guard lock(incoming_mu_);
            Incoming inc;
            inc.conn = conn;
            inc.peer = conn->peer_id();
            inc.from = from;
            inc.alpn = conn->alpn();
            pending_incoming_.push(inc);
        }
    }
}

std::shared_ptr<Connection> Endpoint::find_conn_by_addr(const base::TransportAddr &from) {
    std::lock_guard lock(addr_conn_mu_);
    auto it = addr_to_conn_.find(from);
    if (it != addr_to_conn_.end()) {
        return it->second;
    }
    return nullptr;
}

std::optional<Incoming> Endpoint::accept() {
    std::lock_guard lock(incoming_mu_);
    // v3.9.5 (M5): 角色 ALPN 子集校验（入站方向）
    // role != Unknown 时，跳过未授权 ALPN 的入站连接，只返回授权的
    while (!pending_incoming_.empty()) {
        auto inc = pending_incoming_.front();
        pending_incoming_.pop();
        if (!multimodal::is_role_authorized(cfg_.role, inc.alpn)) {
            LINOH_INFO("Endpoint: role=", multimodal::role_name(cfg_.role),
                       " not authorized for ALPN=", inc.alpn, " (inbound skipped)");
            continue;
        }

        // v4.8.0 (T-LP3-002): 握手前入站过滤器链（借鉴 iroh#3951）
        // 默认 incoming_filters 为空（无过滤，回退 v4.7.0 行为）
        if (!cfg_.incoming_filters.empty()) {
            IncomingRequest req{
                .remote_addr = inc.from,
                .endpoint_id = inc.peer,
                .alpn = std::string_view(inc.alpn),
                .remote_addr_validated = inc.address_validated,
            };
            bool rejected = false;
            for (auto &f : cfg_.incoming_filters) {
                if (!f) continue;
                auto outcome = f->filter(req);
                if (outcome == IncomingFilterOutcome::kAccept) {
                    continue;  // 放行，检查下一个过滤器
                }
                if (outcome == IncomingFilterOutcome::kReject ||
                    outcome == IncomingFilterOutcome::kRetry) {
                    LINOH_INFO("Endpoint: incoming filter '", f->name(),
                               "' rejected connection from ", inc.from.host,
                               " (alpn=", inc.alpn, ")");
                    rejected = true;
                    break;
                }
                // kIgnore: 静默丢弃（不记录日志）
                rejected = true;
                break;
            }
            if (rejected) {
                continue;  // 丢弃此连接，检查队列中下一个
            }
        }

        return inc;  // 授权 + 过滤通过
    }
    return std::nullopt;
}

void Endpoint::ensure_path_for_peer(const EndpointId &peer_id, const base::TransportAddr &addr) {
    // 检查是否已注册过此地址（线性查找，因为地址数量很少）
    {
        std::lock_guard lock(peer_addr_mu_);
        auto it = peer_addrs_.find(peer_id);
        if (it != peer_addrs_.end()) {
            for (const auto &a : it->second) {
                if (a.kind == addr.kind && a.host == addr.host && a.port == addr.port) {
                    return;  // 地址已注册，跳过
                }
            }
        }
    }

    // P0-G3: 被动端点更新限频检查
    // 对称 NAT 端口跳跃场景：对端响应包源端口与 STUN 观测端口不同，触发频繁路径
    // 迁移。PassiveEndpointUpdater 按 per-peer cooldown 限频，窗口内抑制更新避免抖动。
    // 仅在 passive_endpoint_updater_ 启用且 peer 有已记录地址时执行；否则回退
    // v4.4.0 行为（直接注册新 Path）。
    if (passive_endpoint_updater_) {
        base::TransportAddr recorded_addr;
        bool has_recorded = false;
        {
            std::lock_guard lock(peer_addr_mu_);
            auto it = peer_addrs_.find(peer_id);
            if (it != peer_addrs_.end() && !it->second.empty()) {
                recorded_addr = it->second.back();
                has_recorded = true;
            }
        }
        if (has_recorded) {
            auto update = passive_endpoint_updater_->maybe_update(
                peer_id, recorded_addr, addr);
            if (!update.has_value()) {
                // 地址一致或限频窗口内抑制，跳过路径注册
                LINOH_DEBUG("Endpoint: G3 suppressed path update for peer=",
                            peer_id.fmt_short(), " addr=", addr.host, ":", addr.port);
                return;
            }
            // 返回新地址（与 addr 一致），继续注册新 Path
        }
    }

    // 创建 EndpointAddr 并注册新 Path
    EndpointAddr peer_addr(peer_id);
    peer_addr.add_direct_address(addr);
    socket_->resolve(peer_addr);

    // 记录已注册的地址
    {
        std::lock_guard lock(peer_addr_mu_);
        peer_addrs_[peer_id].push_back(addr);
    }

    LINOH_INFO("Endpoint: registered new path for peer=",
               peer_id.fmt_short(), " addr=", addr.host, ":", addr.port);
}

Endpoint::~Endpoint() {
    close();
    // P5-D-3: 析构时持久化 NAT 强化数据（跨重启保留历史）
    save_nat_hardening_state();
}

// P5-D-3: 手动保存 NAT 强化数据到磁盘
void Endpoint::save_nat_hardening_state() {
    if (port_predictor_) {
        if (!cfg_.port_predictor_config.persistence_path.empty()) {
            bool ok = port_predictor_->save_to_file(cfg_.port_predictor_config.persistence_path);
            if (!ok) {
                LINOH_WARN("Endpoint: port_predictor save failed:", cfg_.port_predictor_config.persistence_path);
            }
        }
    }
    if (nat_stats_) {
        if (!cfg_.nat_stats_config.persistence_path.empty()) {
            bool ok = nat_stats_->save_to_file(cfg_.nat_stats_config.persistence_path);
            if (!ok) {
                LINOH_WARN("Endpoint: nat_stats save failed:", cfg_.nat_stats_config.persistence_path);
            }
        }
    }
}

// ============================================================================
// P5-D-4: Relay 兜底前最后尝试
// ============================================================================
//
// 设计要点（plan §3.3.1）：
//   - 全失败降级 Relay 前，若 PortPredictor 置信度足够，再触发一次 SymmetricNat 尝试
//   - 用最高置信度候选端口（top 5）做最后尝试
//   - 成功 → 记录 NatStats + 返回直连结果，避免 Relay 降级
//   - 失败 → 记录 NatStats + 返回 std::nullopt，应用层继续降级 Relay
//
// 实现选择：
//   - 直接调用静态 Holepuncher::attempt_symmetric_adaptive（无需 holepuncher_ 成员）
//   - 本地地址从 socket_ 获取（first_udp4_port），local_ip 用 "0.0.0.0" 让系统决定
//   - 不串联到 connect()，由应用层在穿透失败降级 Relay 前显式调用
std::optional<net::HolepunchResult> Endpoint::try_last_attempt_before_relay(
    const base::EndpointId &peer,
    const std::string &remote_ip,
    std::uint16_t remote_port,
    std::uint16_t remote_observed_port_1,
    std::uint16_t remote_observed_port_2,
    const nat::StatsKey &stats_key,
    std::chrono::milliseconds timeout) {

    // 1. 开关与组件检查
    if (!cfg_.enable_nat_hardening) {
        LINOH_DEBUG("Endpoint: last-attempt skipped, nat_hardening disabled");
        return std::nullopt;
    }
    if (!cfg_.enable_last_attempt_before_relay) {
        LINOH_DEBUG("Endpoint: last-attempt skipped, enable_last_attempt_before_relay=false");
        return std::nullopt;
    }
    if (!port_predictor_) {
        LINOH_DEBUG("Endpoint: last-attempt skipped, port_predictor is null");
        return std::nullopt;
    }

    // 2. S6-③（v5.3）打洞结果缓存：TTL 内同对端直接复用上次成功 tuple
    //    （UDP NAT 映射 30-120s 生命周期内重连场景，省一轮打洞 ~1-10s；
    //     ttl=0 禁用——Config.holepunch_cache_ttl_ms）
    if (cfg_.holepunch_cache_ttl_ms > 0) {
        if (auto cached = nat::HolepunchCache::global().lookup(
                peer, std::chrono::milliseconds{cfg_.holepunch_cache_ttl_ms})) {
            net::HolepunchResult hit;
            hit.success = true;
            hit.established_tuple = *cached;
            hit.error_msg = "holepunch-cache-hit";
            hit.duration = std::chrono::milliseconds{0};
            LINOH_INFO("Endpoint: holepunch CACHE HIT, peer=", peer.fmt_short(),
                       " via=", cached->to_string(),
                       " (ttl=", cfg_.holepunch_cache_ttl_ms, "ms)");
            return hit;
        }
    }

    // 3. 取 top 5 高置信度候选
    auto pred = port_predictor_->predict(peer, 5);
    if (pred.confidence < cfg_.last_attempt_min_confidence) {
        LINOH_INFO("Endpoint: last-attempt skipped, confidence=", pred.confidence,
                   "< threshold=", cfg_.last_attempt_min_confidence,
                   "peer=", peer.fmt_short());
        return std::nullopt;
    }

    // 4. 超时回退（timeout=0 时用 Config.last_attempt_timeout）
    auto actual_timeout = (timeout.count() > 0) ? timeout : cfg_.last_attempt_timeout;

    // 5. 本地端口从 socket_ 获取（first_udp4_port），local_ip 用 "0.0.0.0"
    std::uint16_t local_port = socket_ ? socket_->first_udp4_port() : 0;
    const std::string local_ip = "0.0.0.0";

    // 6. S6-②（v5.3）并发扇出自适应：按 nat_stats 该 NAT 类型对的历史
    //    成功率调 fallback 候选扇出——成功率越低扇出越大
    //    （<30%：40 个；30-60%：20 个；≥60%/冷启动：默认 10 个）
    std::size_t fanout_hint = 0;  // 0 = 默认（10）
    if (nat_stats_) {
        auto snap = nat_stats_->query(stats_key);
        if (!snap.is_cold_start(20)) {  // 样本 ≥20 才调参（防早期抖动）
            if (snap.success_rate < 0.3) {
                fanout_hint = 40;
            } else if (snap.success_rate < 0.6) {
                fanout_hint = 20;
            }
            if (fanout_hint > 0) {
                LINOH_INFO("Endpoint: adaptive fanout=", fanout_hint,
                           " (success_rate=", snap.success_rate,
                           ", total=", snap.total, ")");
            }
        }
    }

    LINOH_INFO("Endpoint: last-attempt before relay, confidence=", pred.confidence,
               "candidates=", pred.candidates.size(),
               "model=", static_cast<int>(pred.model_used),
               "fanout=", fanout_hint,
               "peer=", peer.fmt_short(),
               "timeout_ms=", actual_timeout.count());

    // 7. 调用 Holepuncher::attempt_symmetric_adaptive（静态方法）
    //    内部会：构建自适应候选 + attempt_symmetric + feedback 反馈
    auto result = net::Holepuncher::attempt_symmetric_adaptive(
        local_ip, local_port,
        remote_ip, remote_port,
        remote_observed_port_1, remote_observed_port_2,
        port_predictor_.get(),
        peer,
        actual_timeout,
        fanout_hint);

    // 8. 记录 NatStats（成功/失败均记录，用于动态阈值调整）
    if (nat_stats_) {
        nat::PenetrationRecord r(
            stats_key.nat_type,
            stats_key.carrier,
            stats_key.region,
            nat::CgnStrategy::SymmetricNat,
            result.success,
            result.duration);
        nat_stats_->record(r);
    }

    // 9. S6-③：成功映射入缓存（供下次 TTL 内复用）
    if (result.success && cfg_.holepunch_cache_ttl_ms > 0) {
        nat::HolepunchCache::global().record(peer, result.established_tuple);
    }

    // 10. 返回结果
    if (result.success) {
        LINOH_INFO("Endpoint: last-attempt SUCCEEDED, relay avoided,",
                   "duration_ms=", result.duration.count(),
                   "peer=", peer.fmt_short());
        return result;
    }

    LINOH_INFO("Endpoint: last-attempt failed, falling back to relay,",
               "error=", result.error_msg,
               "duration_ms=", result.duration.count());
    return std::nullopt;
}

EndpointAddr Endpoint::local_addr() const {
    EndpointAddr a{id()};
    for (const auto &r : relays_) a.add_relay(r);
    for (const auto &d : direct_addrs_) a.add_direct_address(d);
    return a;
}

std::shared_ptr<Connection> Endpoint::connect(const EndpointAddr &addr, std::string alpn) {
    if (closed_) return nullptr;
    // v1.7.0.5 P4 (C3): 拒绝空 ALPN 连接（借鉴 iroh #4427 v1.0.3）
    // 空 ALPN 会导致握手期对端无法路由到正确处理函数，引发静默失败。
    if (alpn.empty()) {
        LINOH_ERROR("Endpoint: cannot connect with empty ALPN (iroh #4427)");
        return nullptr;
    }
    if (cfg_.hooks.before_connect && !cfg_.hooks.before_connect(addr, alpn)) {
        LINOH_INFO("Endpoint: before_connect rejected");
        return nullptr;
    }
    // v3.9.5 (M5): 角色 ALPN 子集校验（出站方向）
    // role != Unknown 时，检查 ALPN 是否在角色授权子集内，未授权则拒绝
    if (!multimodal::is_role_authorized(cfg_.role, alpn)) {
        LINOH_INFO("Endpoint: role=", multimodal::role_name(cfg_.role),
                   " not authorized for ALPN=", alpn, " (outbound rejected)");
        return nullptr;
    }
    if (addr.id() == id()) {
        LINOH_ERROR("Endpoint: cannot connect to self");
        return nullptr;
    }
    socket_->resolve(addr);
    Connection::Config conn_cfg{};
    conn_cfg.secret_key = cfg_.secret_key;
    conn_cfg.local_cid = protocol::ConnectionId::generate();
    conn_cfg.remote_cid = protocol::ConnectionId::generate();
    conn_cfg.direction = Direction::Outbound;
    conn_cfg.alpn = std::move(alpn);
    auto conn = std::make_shared<Connection>(std::move(conn_cfg));
    if (cfg_.hooks.after_handshake) cfg_.hooks.after_handshake(*conn);
    {
        // 修复 A2: 出站连接注册到 connections_ map，使 handle_incoming 可按 dcid
        // 命中本端出站连接（对端发来包的 dcid = 我方 local_cid）。
        // 原实现漏掉此注册，导致出站连接无法被 handle_incoming 定位，且不受
        // close()/生命周期管理，造成连接泄漏。
        std::lock_guard lk(conn_mu_);
        connections_.emplace(conn->local_cid(), conn);
    }
    LINOH_INFO("Endpoint: outbound connection id=", conn->id(),
               " to peer=", addr.id().fmt_short());
    return conn;
}

// P5-A-1: 多模态连接对建立
//
// 双连接模型实现策略：
//   1. 先建立 ctrl_conn（控制信令可用）
//   2. 再建立 data_conn（数据通道）
//   3. 任一失败则关闭已建立的连接，promise 设异常
//
// 当前实现为同步串行（简化版），后续 P5-C-3 集成 TaskPool 后可改为异步并行。
// 异步语义通过 std::future + std::async 包装提供，调用方不阻塞。
std::future<Endpoint::MultimodalConnectionPair> Endpoint::connect_multimodal(
    const EndpointAddr &addr,
    multimodal::ChannelType data_channel,
    multimodal::ChannelConfig data_config) {
    // 异步执行（避免调用方阻塞；future 语义符合方案设计）
    return std::async(std::launch::async, [this, addr, data_channel, data_config]() {
        MultimodalConnectionPair result;
        result.data_channel = data_channel;
        result.data_config = data_config.type == data_channel
                                 ? data_config
                                 : multimodal::ChannelConfig::for_channel(data_channel);

        if (closed_) {
            throw std::runtime_error("Endpoint: closed");
        }
        if (addr.id() == id()) {
            throw std::runtime_error("Endpoint: cannot connect to self");
        }

        // Step 1: 建立控制连接（ALPN=ctrl/1）
        std::string ctrl_alpn{multimodal::alpn_for(multimodal::ChannelType::CONTROL)};
        result.ctrl_conn = connect(addr, ctrl_alpn);
        if (!result.ctrl_conn) {
            throw std::runtime_error("Endpoint::connect_multimodal: ctrl_conn failed");
        }

        // Step 2: 建立数据连接（ALPN=pp-*/1，按模态决定）
        std::string data_alpn{multimodal::alpn_for(data_channel)};
        result.data_conn = connect(addr, data_alpn);
        if (!result.data_conn) {
            // data_conn 失败：关闭已建立的 ctrl_conn
            result.ctrl_conn.reset();
            throw std::runtime_error("Endpoint::connect_multimodal: data_conn failed");
        }

        LINOH_INFO("Endpoint: multimodal connection pair established "
                   "peer=", addr.id().fmt_short(),
                   " data_channel=", multimodal::channel_type_name(data_channel),
                   " ctrl_alpn=", ctrl_alpn,
                   " data_alpn=", data_alpn);

        return result;
    });
}

std::size_t Endpoint::send_datagram(const EndpointId &peer, std::span<const uint8_t> payload) {
    if (closed_) return 0;
    auto n = socket_->send(peer, payload);
    // v1.7.0.2 P1: Endpoint 层 send 路径默认按 CONTROL 通道记录字节基线
    // （精细 per-channel 统计由上层应用按实际 ChannelType 主动调用 channel_stats().record_send）
    if (n > 0) {
        channel_stats_.record_send(multimodal::ChannelType::CONTROL, n, 1);
    }
    return n;
}

void Endpoint::on_datagram(DatagramHandler h) {
    if (!socket_) return;
    socket_->set_datagram_handler(std::move(h));
}

void Endpoint::close() {
    bool expected = false;
    if (closed_.compare_exchange_strong(expected, true)) {
        // v1.7.0.3 P2: 先停止嵌入式 Relay（避免 socket stop 后 Relay 线程访问已释放资源）
        stop_embedded_relay();
        // v1.7.0.1 P0: 停止网络变更监测
        stop_route_monitoring();
        if (socket_) socket_->stop_all();
    }
}

// ============================================================================
// v1.7.0.3 P2: 嵌入式 Relay Server（借鉴 iroh-relay library embedding）
// 测试/开发场景下无需独立进程，Endpoint 直接内嵌一个 RelayServer。
// ============================================================================

unsigned short Endpoint::run_embedded_relay(relay::RelayServerBuilder builder) {
    if (closed_.load()) {
        LINOH_WARN("Endpoint::run_embedded_relay: endpoint closed");
        return 0;
    }
    if (embedded_relay_) {
        LINOH_WARN("Endpoint::run_embedded_relay: embedded relay already running on port",
                   embedded_relay_->local_port());
        return embedded_relay_->local_port();
    }
    embedded_relay_ = builder.build();
    if (!embedded_relay_) {
        LINOH_ERROR("Endpoint::run_embedded_relay: builder returned nullptr");
        return 0;
    }
    if (!embedded_relay_->start()) {
        LINOH_ERROR("Endpoint::run_embedded_relay: RelayServer::start() failed");
        embedded_relay_.reset();
        return 0;
    }
    LINOH_INFO("Endpoint::run_embedded_relay: listening on port",
               embedded_relay_->local_port());
    return embedded_relay_->local_port();
}

void Endpoint::stop_embedded_relay() {
    if (embedded_relay_) {
        LINOH_INFO("Endpoint::stop_embedded_relay: stopping embedded relay on port",
                   embedded_relay_->local_port());
        embedded_relay_->stop();
        embedded_relay_.reset();
    }
}

void Endpoint::add_direct_address(base::TransportAddr addr) {
    direct_addrs_.push_back(std::move(addr));
}

void Endpoint::add_relay(base::RelayUrl relay) {
    relays_.push_back(std::move(relay));
}

// ============================================================================
// S7（v5.3）relay 预热：与打洞并行建立 relay 连接，fallback 直取
// ============================================================================

void Endpoint::prewarm_relays() {
    if (closed_ || relays_.empty()) return;
    bool expected = false;
    if (!prewarm_started_.compare_exchange_strong(expected, true)) {
        return;  // 幂等：已启动过
    }
    // S7：relay 候选**并行竞速**预热（每 relay 一线程同时发起建连——
    // happy-eyeballs 语义：先通先用由 take 时的 is_connected 过滤保证）。
    // relay::Client::connect 为阻塞式 TCP+WS+认证；io_context 生命周期
    // 由调用方保证覆盖 endpoint（make(ctx, cfg) 既有约定）。
    for (const auto &url : relays_) {
        std::thread([this, url]() {
            if (closed_) return;
            try {
                auto c = std::make_shared<relay::Client>(ctx_, url,
                                                         cfg_.secret_key);
                if (c->connect() && c->is_authenticated()) {
                    std::lock_guard<std::mutex> lk(prewarm_mu_);
                    prewarmed_.push_back(std::move(c));
                    LINOH_INFO("Endpoint: relay prewarmed OK, url=", url.url());
                } else {
                    LINOH_INFO("Endpoint: relay prewarm failed, url=", url.url());
                }
            } catch (const std::exception &e) {
                LINOH_INFO("Endpoint: relay prewarm exception, url=", url.url(),
                           " what=", e.what());
            }
        }).detach();
    }
}

std::shared_ptr<relay::Client> Endpoint::take_prewarmed_relay() {
    std::lock_guard<std::mutex> lk(prewarm_mu_);
    while (!prewarmed_.empty()) {
        auto c = prewarmed_.back();
        prewarmed_.pop_back();
        if (c && c->is_connected()) return c;  // 仍活的连接才交付
    }
    return nullptr;
}

std::size_t Endpoint::prewarmed_count() const {
    std::lock_guard<std::mutex> lk(prewarm_mu_);
    std::size_t n = 0;
    for (auto &c : prewarmed_) {
        if (c && c->is_connected()) ++n;
    }
    return n;
}

// ============================================================================
// v1.7.0.1 P0: 网络变更监测 + 重打洞
// ============================================================================

bool Endpoint::start_route_monitoring() {
    if (closed_.load()) return false;
    if (!cfg_.auto_reholepunch_on_network_change) {
        route_monitor_mode_ = "none";
        return false;
    }

    // 弱引用避免循环（Endpoint -> RouteMonitor -> callback -> Endpoint）
    std::weak_ptr<Endpoint> weak_self = shared_from_this();
    auto cb = [weak_self](net::RouteEvent ev) {
        auto self = weak_self.lock();
        if (!self || self->is_closed()) return;
        if (ev == net::RouteEvent::DefaultRouteChanged) {
            LINOH_INFO("RouteMonitor: DefaultRouteChanged -> trigger reholepunch + network_change_notify + relay_health_check");
            // v4.6.0 (借鉴 noq#545): 先重置 PTO/RTT，再重打洞
            // 重打洞建立新路径后，PTO 基于新 RTT 样本收敛，避免旧 RTT 误导
            self->notify_all_network_change();
            // v4.6.0 (借鉴 iroh#4041): 立即触发 Relay 健康检查
            // 网络切换后 Relay 可能不可达，需快速探测以切换到可用 Relay
            if (self->on_relay_health_check_requested_) {
                try { self->on_relay_health_check_requested_(); } catch (...) {}
            }
            self->trigger_all_reholepunch();
        }
    };

    // 优先使用 RouteMonitor
    if (cfg_.prefer_route_monitor && net::RouteMonitor::platform_supported()) {
        route_monitor_ = std::make_unique<net::RouteMonitor>();
        if (route_monitor_->start(cb)) {
            route_monitor_mode_ = "route_monitor";
            LINOH_INFO("RouteMonitor: started (platform native)");
            return true;
        }
        // 启动失败，降级到 Poller
        LINOH_INFO("RouteMonitor: start failed, fallback to DefaultRoutePoller");
        route_monitor_.reset();
    }

    // 兜底：DefaultRoutePoller
    route_poller_ = std::make_unique<net::DefaultRoutePoller>();
    route_poller_->start(cb);
    route_monitor_mode_ = "route_poller";
    LINOH_INFO("RouteMonitor: started (poller mode)");
    return true;
}

void Endpoint::stop_route_monitoring() {
    if (route_monitor_) {
        route_monitor_->stop();
        route_monitor_.reset();
    }
    if (route_poller_) {
        route_poller_->stop();
        route_poller_.reset();
    }
    route_monitor_mode_ = "none";
}

std::size_t Endpoint::trigger_all_reholepunch() {
    std::size_t triggered = 0;
    std::lock_guard<std::mutex> lk(conn_mu_);
    for (auto &[cid, conn] : connections_) {
        if (conn && conn->state() == ConnState::Established) {
            if (conn->trigger_reholepunch()) {
                ++triggered;
            }
        }
    }
    if (triggered > 0) {
        LINOH_INFO("trigger_all_reholepunch: fired on", triggered, "connections");
    }
    return triggered;
}

std::size_t Endpoint::notify_all_network_change() {
    std::size_t notified = 0;
    std::lock_guard<std::mutex> lk(conn_mu_);
    for (auto &[cid, conn] : connections_) {
        if (!conn) continue;
        ConnState s = conn->state();
        // 跳过已关闭/排空连接，其余状态（Initial/Handshake/Established）均通知
        // 握手期连接也需要重置 RTT，避免基于旧网络估算导致握手超时误判
        if (s != ConnState::Closed && s != ConnState::Draining) {
            conn->on_network_change();
            ++notified;
        }
    }
    if (notified > 0) {
        LINOH_INFO("notify_all_network_change: notified", notified,
                   "connections (PTO backoff + RTT reset)");
    }
    return notified;
}

std::string Endpoint::route_monitor_mode() const {
    return route_monitor_mode_;
}

} // namespace linoh::endpoint
