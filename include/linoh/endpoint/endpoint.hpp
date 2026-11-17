#pragma once

#include "linoh/address_lookup/lookup.hpp"
#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/endpoint/connection.hpp"
#include "linoh/endpoint/incoming_filter.hpp"
#include "linoh/multimodal/channel.hpp"
#include "linoh/multimodal/channel_stats.hpp"
#include "linoh/nat/nat_stats.hpp"
#include "linoh/nat/passive_endpoint_updater.hpp"
#include "linoh/nat/port_predictor.hpp"
#include "linoh/net/holepuncher.hpp"
#include "linoh/net/route_monitor.hpp"
#include "linoh/relay/server.hpp"

// S7（v5.3）: relay::Client 前向声明（client.hpp 的 linoh_asio alias 与
// transport.hpp 冲突；shared_ptr 成员 + 方法声明只需不完整类型）
namespace linoh::relay {
class Client;
}
#include "linoh/net/socket.hpp"
#include "linoh/tls/handshake_token_key.hpp"
#include "linoh/util/bytes.hpp"

#include <atomic>
#include <future>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef LINOH_WITH_BOOST_ASIO
#include <boost/asio.hpp>
namespace linoh_asio = boost::asio;
#else
#include <asio.hpp>
#ifndef LINOH_USE_STUB_ASIO
namespace linoh_asio = asio;
#endif
#endif

namespace linoh::endpoint {

using base::EndpointAddr;
using base::EndpointId;
using base::SecretKey;
using base::PublicKey;

/// 尚未接受的入站连接（accept loop 产出的对象）。
struct Incoming {
    std::shared_ptr<Connection> conn;  ///< 入站连接对象，可用于收发数据
    EndpointId peer;                   ///< 对端公钥/节点 ID
    base::TransportAddr from;          ///< 对端传输地址
    std::string alpn;                  ///< 应用层协议标识
    bool address_validated{false};
};

/// 连接中状态：对应 iroh 的 `Connecting`。
struct Connecting {
    EndpointId peer;
    EndpointAddr addr;
    std::string alpn;
};

/// Bootstrap 配置：Endpoint 启动时自动连接的服务列表。
/// 用于让节点在启动后立即加入网络。
struct BootstrapConfig {
    /// Relay server URLs. Endpoint connects to each relay on startup,
    /// authenticates, and registers its EndpointId.
    std::vector<base::RelayUrl> relay_urls;

    /// DNS-over-HTTPS server URLs for Pkarr address publishing/lookup.
    /// If empty, Pkarr publish/lookup uses in-process cache only.
    std::vector<std::string> dns_urls;

    /// Known node EndpointIds to seed the address lookup cache.
    /// Useful for testing or small networks where DHT discovery is not available.
    std::vector<base::EndpointId> known_nodes;

    /// JSON config file path. If non-empty, BootstrapConfig is loaded from this file
    /// on startup, overriding any values set in the struct.
    /// File format: { "relay_urls": [...], "dns_urls": [...], "known_nodes": [...] }
    std::string config_path;

    /// Whether to auto-connect to relay servers on Endpoint startup.
    /// Default: true. Set to false for offline/local-only mode.
    bool auto_connect{true};
};
struct EndpointHooks {
    std::function<bool(const EndpointAddr &, std::string_view alpn)> before_connect;
    std::function<void(const Connection &)> after_handshake;
};

/// Endpoint 对外 API：是所有对外连接与接受连接的根对象。
///
/// 设计为 shared_ptr 持有——生命周期由用户和 Router 共同决定。
class Endpoint : public std::enable_shared_from_this<Endpoint> {
public:
    struct Config {
        SecretKey secret_key;
        std::vector<std::string> alpns;

        /// v3.9.5 (M5): 节点角色（默认 Unknown = 支持所有 ALPN，向后兼容）
        /// 设置为 Master/Worker/Relay/Observer 后，accept/connect 时校验
        /// ALPN 是否在角色授权子集内（is_role_authorized），未授权则拒绝连接
        multimodal::NodeRole role{multimodal::NodeRole::Unknown};

        std::shared_ptr<address_lookup::AddressLookup> lookup;
        EndpointHooks hooks;
        BootstrapConfig bootstrap;  // relay/DNS/known-node bootstrap config

        /// v1.7.0.1 P0: 网络变更后自动重新打洞（默认 true）
        /// 监测到 RouteEvent::DefaultRouteChanged 时触发对端重打洞
        bool auto_reholepunch_on_network_change{true};

        /// v1.7.0.1 P0: 使用 RouteMonitor 优先，失败时降级到 DefaultRoutePoller
        /// false 则只使用轮询（适合受限环境）
        bool prefer_route_monitor{true};

        /// P5-D-3: NAT 穿透强化开关（默认 true）
        /// true: 创建 PortPredictor + NatStats，启用端口预测学习与统计模型
        /// false: 回退 v3.5 行为（纯 CGN 规则 + 2 点线性外推）
        bool enable_nat_hardening{true};

        /// P5-D-3: 端口预测器配置（enable_nat_hardening=true 时生效）
        nat::PortPredictorConfig port_predictor_config;

        /// P5-D-3: NAT 统计配置（enable_nat_hardening=true 时生效）
        nat::NatStatsConfig nat_stats_config;

        /// P0-G3: 被动端点更新开关（默认 true）
        /// true: 创建 PassiveEndpointUpdater，收包时检测源地址与记录不符则
        ///       自适应更新端点地址（适配对称 NAT 端口跳跃），限频防抖动
        /// false: 回退 v4.4.0 行为（ensure_path_for_peer 无限频直接注册新 Path）
        bool enable_passive_endpoint_update{true};

        /// P0-G3: 被动端点更新配置（enable_passive_endpoint_update=true 时生效）
        nat::PassiveEndpointUpdaterConfig passive_endpoint_updater_config;

        /// P5-D-4: 是否启用 Relay 兜底前最后尝试（默认 true）
        /// true: 全失败降级 Relay 前，若 PortPredictor 置信度足够，再触发一次
        ///       SymmetricNat 尝试（用最高置信度候选端口）
        /// false: 直接降级 Relay（与 v3.6.0 行为一致）
        bool enable_last_attempt_before_relay{true};

        /// P5-D-4: Relay 兜底前最后尝试的最小置信度阈值（默认 0.8）
        /// PortPredictor::predict() 返回的 confidence < 此值时跳过最后尝试
        /// 范围 [0.0, 1.0]：值越高越保守（少触发），值越低越激进（多触发）
        double last_attempt_min_confidence{0.8};

        /// P5-D-4: 最后尝试的超时时间（默认 2s）
        /// 全失败降级 Relay 前的额外延迟，过大会增加用户感知延迟
        std::chrono::milliseconds last_attempt_timeout{std::chrono::seconds(2)};

        /// S6-③（v5.3）打洞结果缓存 TTL（默认 60s；0=禁用）。
        /// 同对端 EndpointId 近期成功 FourTuple 在 TTL 内直接复用
        ///（UDP NAT 映射生命周期 30-120s 内的重连场景省一轮打洞）。
        std::int64_t holepunch_cache_ttl_ms{60 * 1000};

        // ===== v3.9.0: QUIC 传输参数（PP 链长保活 + 连接池管理）=====

        /// 最大空闲超时（默认 300s）。原 30s 对 PP 长链路过短，频繁断连重连；
        /// 扩展到 300s 适应跨域长推理任务（单次 PP 推理 hidden_state 转发可达数分钟）。
        std::chrono::seconds max_idle_timeout{300};

        /// keep_alive 探测间隔（默认 15s）。原 10s 过频增加控制面开销，
        /// 15s 平衡保活可靠性与带宽占用。
        std::chrono::seconds keep_alive_interval{15};

        /// 连接池上限（默认 1024）。超出时拒绝新连接，防资源耗尽。
        /// PP 链典型规模 N≤32 worker，1024 足够余量。
        std::uint32_t max_connections{1024};

        /// ICE Candidate 收集上限（默认 12）。限制 NAT 穿透候选地址数，
        /// 防探测风暴（原无上限可能触发大量 STUN 探测）。
        std::uint32_t max_remote_nat_traversal_addresses{12};

        // ===== v4.8.0: 安全与配置（阶段三）=====

        /// v4.8.0 (T-LP3-001/002): 握手前入站连接过滤器链（借鉴 iroh#3951）
        /// 默认为空（无过滤，回退 v4.7.0 行为）。
        /// 非空时，accept() 在返回 Incoming 前依次执行每个过滤器：
        ///   kAccept → 继续下一个过滤器
        ///   kReject → 关闭连接，返回 nullopt
        ///   kRetry  → 当前等同 kReject
        ///   kIgnore → 静默丢弃，返回 nullopt
        std::vector<std::shared_ptr<IncomingFilter>> incoming_filters;

        /// v4.8.0 (T-LP3-003): 已知外部地址（借鉴 iroh#4098）
        /// 配置后跳过 STUN 探测，直接用配置地址作为 srflx 候选。
        /// 适配反向代理/云环境（已知公网 IP 时 bypass 发现）。
        /// 默认为空（走 STUN 发现，回退 v4.7.0 行为）。
        std::vector<std::string> external_addresses;
    };

    static std::shared_ptr<Endpoint> make(linoh_asio::io_context &ctx, Config cfg);

    ~Endpoint();

    /// 当前节点 ID（公钥）。
    EndpointId id() const { return cfg_.secret_key.public_key(); }

    /// 返回本地 EndpointAddr（含监听地址 + 可选的 relay）。
    EndpointAddr local_addr() const;

    /// 发起一条到 `addr` 的出站连接。
    /// 返回 shared_ptr 以便异步任务延长其生命期。
    std::shared_ptr<Connection> connect(const EndpointAddr &addr, std::string alpn);

    /// P5-A-1: 多模态连接对（控制连接 + 数据连接）
    ///
    /// 双连接模型（借鉴 Sunshine 控制信道独立）：
    ///   - ctrl_conn: ALPN=ctrl/1，可靠 stream，承载 RPC/心跳/状态上报
    ///   - data_conn: ALPN=pp-*/1（按模态决定），多 stream 并行，承载推理数据
    ///
    /// 控制连接与数据连接使用独立 stream 池，互不阻塞。
    /// 建立顺序：先建 ctrl_conn（控制信令可用），再并行建 data_conn。
    struct MultimodalConnectionPair {
        std::shared_ptr<Connection> ctrl_conn;    ///< 控制连接（ALPN=ctrl/1）
        std::shared_ptr<Connection> data_conn;    ///< 数据连接（ALPN=pp-*/1）
        multimodal::ChannelType data_channel;     ///< 数据通道模态
        multimodal::ChannelConfig data_config;    ///< 数据通道配置
    };

    /// 建立多模态连接对（新增 API，P5-A-1）
    ///
    /// @param addr 对端地址
    /// @param data_channel 数据通道模态（控制通道固定为 CONTROL）
    /// @param data_config 数据通道配置（默认按模态生成）
    /// @return future，resolve 后包含 ctrl_conn 和 data_conn
    ///
    /// 失败场景：
    ///   - ctrl_conn 建立失败：future 抛出 std::runtime_error
    ///   - data_conn 建立失败：future 抛出 std::runtime_error（ctrl_conn 会被关闭）
    std::future<MultimodalConnectionPair> connect_multimodal(
        const EndpointAddr &addr,
        multimodal::ChannelType data_channel,
        multimodal::ChannelConfig data_config = {});

    /// 向 peer 发送一个 UDP 数据报（绕过完整 QUIC 握手，仅用于演示）。
    /// 需先调用 resolve(addr) 让 Socket 知道 peer 地址。
    /// 返回实际发送字节数；0 表示失败。
    std::size_t send_datagram(const EndpointId &peer, std::span<const uint8_t> payload);

    /// 注册一个入站数据报回调。
    using DatagramHandler = std::function<void(const EndpointId &from, util::Bytes data, const base::TransportAddr &from_addr)>;
    void on_datagram(DatagramHandler h);

    /// 注册入站连接的接受回调（accept loop 用）。
    using AcceptHandler = std::function<void(Incoming)>;
    void set_accept_handler(AcceptHandler h) { accept_handler_ = std::move(h); }

    /// 轮询方式：返回一个新的已接受连接（内部调用 handle_incoming 完成实际接收）。
    /// 返回 nullptr 表示当前没有已建立的新连接。
    std::optional<Incoming> accept();

    /// 手动向 Endpoint 提交一个收到的 UDP 包（由外部 socket 调用，或示例程序用）。
    void handle_incoming(const base::TransportAddr &from, util::Bytes wire);

    /// 获取底层的多路径 Socket 句柄。
    net::Socket &socket() { return *socket_; }

    /// 关闭 Endpoint。
    void close();

    bool is_closed() const { return closed_.load(); }

    /// 返回用户配置。
    const Config &config() const { return cfg_; }

    /// 返回握手令牌密钥（供 QUIC 重试帧用）。
    const tls::HandshakeTokenKey &token_key() const { return token_key_; }

    /// 添加一条直连地址（用于 peer 发现）。
    void add_direct_address(base::TransportAddr addr);

    /// 添加 relay URL。
    void add_relay(base::RelayUrl relay);

    /// S7（v5.3）relay 预热：后台线程提前与 relay 列表逐个建立 relay::Client
    /// 连接（TCP+WS+认证），成功的缓存供穿透失败 fallback 时直取——
    /// 与打洞并行就绪，省去 fallback 后的建连时间（patchbay S5 场景
    /// 34.9s 优化项之一）。幂等：仅首次调用生效。io_context 生命周期
    /// 需覆盖 endpoint（make(ctx, cfg) 既有约定）。
    void prewarm_relays();

    /// S7: 取一个已预热的 relay 客户端（连接仍活才返回；无则 nullptr）。
    /// 取出后归调用方持有；可多次取（池内逐个出队）。
    std::shared_ptr<relay::Client> take_prewarmed_relay();

    /// S7: 当前仍活的预热连接数（监控/测试只读；实现于 .cpp，需完整类型）
    std::size_t prewarmed_count() const;

    /// 返回第一个 UDP v4 的本地端口（示例程序用）。
    uint16_t local_udp_port() const { return socket_ ? socket_->first_udp4_port() : 0; }

    /// 确保已知 peer 的最新传输地址已被注册为一条新 Path（路径迁移）。
    void ensure_path_for_peer(const EndpointId &peer_id, const base::TransportAddr &addr);

    /// v1.7.0.1 P0: 手动触发所有 ACTIVE 连接的重打洞
    /// 用于网络变更后主动恢复连接。返回触发的连接数。
    /// @note 当 auto_reholepunch_on_network_change=true 时会自动调用，无需用户介入。
    std::size_t trigger_all_reholepunch();

    /// v4.6.0 (借鉴 noq#545): 通知所有活跃连接网络已变化
    ///
    /// 遍历所有非 Closed/Draining 状态的 Connection，调用 on_network_change()
    /// 重置 PTO backoff 和 RTT 估计器，避免网络切换后基于过时 RTT 估算导致
    /// 连接假死（PTO 过迟）或重传风暴（RTO 过频）。
    ///
    /// @return 被通知的连接数
    /// @note 当 auto_reholepunch_on_network_change=true 时由 RouteMonitor 回调自动调用
    std::size_t notify_all_network_change();

    /// v4.6.0 (借鉴 iroh#4041): 注册 Relay 健康检查回调
    ///
    /// RouteMonitor 检测到 DefaultRouteChanged 时自动调用此回调，
    /// 上层应在回调内触发 RelayPool::check_all_async() 立即探测 Relay 可达性。
    ///
    /// @param cb 回调函数（传 nullptr 清除）
    void set_relay_health_check_callback(std::function<void()> cb) {
        on_relay_health_check_requested_ = std::move(cb);
    }

    /// v1.7.0.1 P0: 返回当前使用的路由监测方式
    /// @return "route_monitor" / "route_poller" / "none"
    std::string route_monitor_mode() const;

    /// v1.7.0.2 P1: 获取通道统计注册表（可写引用，用于 send/recv 路径记录）
    multimodal::ChannelStatsRegistry &channel_stats() { return channel_stats_; }

    /// v1.7.0.2 P1: 获取通道统计注册表（只读引用）
    const multimodal::ChannelStatsRegistry &channel_stats() const { return channel_stats_; }

    /// v1.7.0.3 P2: 启动嵌入式 Relay Server
    /// @param builder RelayServer 配置器（若 port=0 自动选择空闲端口）
    /// @return Relay 实际监听端口（0 表示启动失败）
    /// @note 借鉴 iroh-relay library embedding 模式，无需独立进程
    unsigned short run_embedded_relay(relay::RelayServerBuilder builder);

    /// v1.7.0.3 P2: 停止嵌入式 Relay Server
    void stop_embedded_relay();

    /// v1.7.0.3 P2: 获取嵌入式 Relay 实例（可能为 nullptr）
    relay::RelayServer *embedded_relay() { return embedded_relay_.get(); }

    // ------------------------------------------------------------------
    // P5-D-3: NAT 穿透强化 API
    // ------------------------------------------------------------------

    /// P5-D-3: 获取端口预测器（未启用 NAT 强化时返回 nullptr）
    /// 调用方应在为空时回退 v3.5 行为（2 点线性外推）
    nat::PortPredictor *port_predictor() { return port_predictor_.get(); }

    /// P5-D-3: 获取 NAT 统计模型（未启用 NAT 强化时返回 nullptr）
    /// 调用方应在为空时回退 CGN 规则
    nat::NatStats *nat_stats() { return nat_stats_.get(); }

    /// P0-G3: 获取被动端点更新器（未启用时返回 nullptr）
    /// 用于收包路径联动：源地址与记录不符时限频更新端点地址
    nat::PassiveEndpointUpdater *passive_endpoint_updater() {
        return passive_endpoint_updater_.get();
    }

    /// P5-D-3: 是否启用 NAT 强化
    bool nat_hardening_enabled() const { return port_predictor_ != nullptr; }

    /// P5-D-3: 手动保存 NAT 强化数据到磁盘（正常由析构自动保存）
    void save_nat_hardening_state();

    /// P5-D-4: Relay 兜底前最后尝试（公开 API，供应用层在穿透失败降级 Relay 前调用）
    ///
    /// 决策逻辑（参见 plan §3.3.1）：
    ///   1. enable_nat_hardening=false 或 enable_last_attempt_before_relay=false
    ///      或 port_predictor_ 为空 → 直接返回 std::nullopt
    ///   2. predictor->predict(peer, 5) 取 top 5 高置信度候选
    ///   3. confidence < last_attempt_min_confidence → 返回 std::nullopt（跳过）
    ///   4. 调用 Holepuncher::attempt_symmetric_adaptive 做最后一次 SymmetricNat 尝试
    ///   5. 成功 → 记录 NatStats（PenetrationRecord{strategy=SymmetricNat, success=true}）+ 返回 result
    ///   6. 失败 → 返回 std::nullopt（应用层继续降级 Relay）
    ///
    /// @param peer 对端 EndpointId（用于 predictor 查询 per-peer 历史）
    /// @param remote_ip 对端 IP
    /// @param remote_port 对端 contact 端口（非 NAT 外部映射端口）
    /// @param remote_observed_port_1 对端第一次 STUN 观测到的外部映射端口
    /// @param remote_observed_port_2 对端第二次 STUN 观测到的外部映射端口
    /// @param stats_key 统计维度键（NAT 类型/运营商/区域，用于 NatStats::record）
    /// @param timeout 单次尝试超时（默认用 Config.last_attempt_timeout）
    /// @return 非空表示尝试成功（应使用直连），空表示应继续降级 Relay
    std::optional<net::HolepunchResult> try_last_attempt_before_relay(
        const base::EndpointId &peer,
        const std::string &remote_ip,
        std::uint16_t remote_port,
        std::uint16_t remote_observed_port_1,
        std::uint16_t remote_observed_port_2,
        const nat::StatsKey &stats_key,
        std::chrono::milliseconds timeout = std::chrono::milliseconds{0});

private:
    Endpoint(linoh_asio::io_context &ctx, Config cfg);

    linoh_asio::io_context &ctx_;
    Config cfg_;
    std::shared_ptr<net::Socket> socket_;
    tls::HandshakeTokenKey token_key_;
    std::vector<base::TransportAddr> direct_addrs_;
    std::vector<base::RelayUrl> relays_;
    AcceptHandler accept_handler_;
    std::atomic<bool> closed_{false};

    /// S7（v5.3）relay 预热缓存与状态
    mutable std::mutex prewarm_mu_;  // S7: prewarmed_count() const 方法加锁
    std::vector<std::shared_ptr<relay::Client>> prewarmed_;
    std::atomic<bool> prewarm_started_{false};

    /// v1.7.0.1 P0: 网络变更监测器（RouteMonitor 优先）
    std::unique_ptr<net::RouteMonitor> route_monitor_;
    /// v1.7.0.1 P0: 默认路由轮询器（RouteMonitor 不可用时的兜底）
    std::unique_ptr<net::DefaultRoutePoller> route_poller_;
    /// v1.7.0.1 P0: 当前活跃的监测方式（"route_monitor" / "route_poller" / "none"）
    std::string route_monitor_mode_;

    /// v4.6.0 (借鉴 iroh#4041): Relay 健康检查请求回调
    /// RouteMonitor 检测到网络变更时触发，由上层（拥有 RelayPool 的组件）注册。
    /// 回调内应调用 RelayPool::check_all_async() 立即探测所有 Relay 的可达性，
    /// 避免网络切换后使用已失效的 Relay 路径。
    std::function<void()> on_relay_health_check_requested_;

    /// v1.7.0.2 P1: 通道公平性统计注册表
    /// send_datagram 路径按当前 ALPN 推断 ChannelType 并 record_send
    multimodal::ChannelStatsRegistry channel_stats_;

    /// v1.7.0.3 P2: 嵌入式 Relay Server（测试/开发场景无需独立进程）
    std::unique_ptr<relay::RelayServer> embedded_relay_;

    /// P5-D-3: NAT 穿透强化组件（enable_nat_hardening=true 时创建，否则为 nullptr）
    /// PortPredictor: per-peer 端口预测历史序列 + 多模型预测
    /// NatStats: (NAT类型, 运营商, 区域) 三维统计 + 策略推荐
    std::unique_ptr<nat::PortPredictor> port_predictor_;
    std::unique_ptr<nat::NatStats> nat_stats_;

    /// P0-G3: 被动端点更新器（enable_passive_endpoint_update=true 时创建）
    /// 收包路径联动：源地址与记录不符时限频更新端点地址，适配对称 NAT 端口跳跃
    std::unique_ptr<nat::PassiveEndpointUpdater> passive_endpoint_updater_;

    /// v1.7.0.1 P0: 启动网络变更监测
    /// 根据 Config.prefer_route_monitor 决定使用 RouteMonitor 还是 DefaultRoutePoller。
    /// @return true 表示至少有一种监测方式启动成功
    bool start_route_monitoring();

    /// v1.7.0.1 P0: 停止网络变更监测
    void stop_route_monitoring();

    // Connection 管理
    struct CIDHash {
        std::size_t operator()(const protocol::ConnectionId &cid) const {
            auto d = cid.data();
            std::size_t h = d.size();
            for (auto b : d) h = h * 31 + b;
            return h;
        }
    };
    std::mutex conn_mu_;
    std::unordered_map<protocol::ConnectionId, std::shared_ptr<Connection>, CIDHash> connections_;
    std::mutex incoming_mu_;
    std::queue<Incoming> pending_incoming_;

    /// v1.5.0.1 E2E stress: 按 from_addr 反查 conn（针对 1-RTT 包 DCID=0 长度场景）
    struct AddrHash {
        std::size_t operator()(const base::TransportAddr &a) const {
            std::size_t h = static_cast<size_t>(a.kind);
            for (auto b : a.host) h = h * 31 + b;
            h = h * 31 + a.port;
            return h;
        }
    };
    std::mutex addr_conn_mu_;
    std::unordered_map<base::TransportAddr, std::shared_ptr<Connection>, AddrHash> addr_to_conn_;
    std::shared_ptr<Connection> find_conn_by_addr(const base::TransportAddr &from);

    /// 按 peer 地址追踪已注册的 Path（用于路径迁移检测）。
    struct KeyHash {
        std::size_t operator()(const EndpointId &k) const {
            auto d = k.as_span();
            std::size_t h = d.size();
            for (auto b : d) h = h * 31 + b;
            return h;
        }
    };
    std::mutex peer_addr_mu_;
    std::unordered_map<EndpointId, std::vector<base::TransportAddr>, KeyHash> peer_addrs_;
};

} // namespace linoh::endpoint
