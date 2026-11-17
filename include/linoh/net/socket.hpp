#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/net/path.hpp"
#include "linoh/net/transport.hpp"
#include "linoh/protocol/multipath_selector.hpp"  // S2: StripPolicy
#include "linoh/util/bytes.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace linoh::net {

/// 对一个远端 endpoint 的路径集合与当前选中路径。
///
/// 所有修改路径的方法都必须在 executor 线程内调用。读取 `select()`
/// 的字段是原子的，允许其他线程读取。
class RemoteState {
public:
    explicit RemoteState(EndpointId peer) : peer_{std::move(peer)} {}

    const EndpointId &peer() const { return peer_; }

    void add_path(std::shared_ptr<Path> p) {
        std::lock_guard<std::mutex> lk(mu_);
        paths_.push_back(std::move(p));
    }

    std::vector<std::shared_ptr<Path>> paths() const {
        std::lock_guard<std::mutex> lk(mu_);
        return paths_;
    }

    /// 设置自定义路径选择器（不设置则使用默认 BiasedRttPathSelector）。
    void set_selector(std::shared_ptr<PathSelector> s) {
        std::lock_guard<std::mutex> lk(mu_);
        selector_ = std::move(s);
    }

    /// 选择最佳路径。返回索引，调用方用它访问 `paths()[i]`。
    std::shared_ptr<Path> best_path() const {
        std::vector<std::shared_ptr<Path>> snap;
        std::shared_ptr<PathSelector> sel;
        {
            std::lock_guard<std::mutex> lk(mu_);
            snap = paths_;
            sel = selector_;
        }
        if (snap.empty()) return nullptr;
        PathSelector *selector = sel ? sel.get() : &default_selector_;
        return snap[selector->select(snap)];
    }

private:
    EndpointId peer_;
    mutable std::mutex mu_;
    std::vector<std::shared_ptr<Path>> paths_;
    std::shared_ptr<PathSelector> selector_;
    mutable BiasedRttPathSelector default_selector_;
};

/// 多路径 socket：管理多个 Transport（UDP IPv4 / IPv6 / Relay / Custom）
/// 和每个对端的 `RemoteState`。
///
/// 生命周期说明：Socket 继承 enable_shared_from_this，必须通过 shared_ptr
/// 持有。Transport 的 packet_handler_ 回调通过 weak_ptr<Socket> 捕获本对象，
/// 避免析构后回调悬空（UAF）。
class Socket : public std::enable_shared_from_this<Socket> {
public:
    explicit Socket(linoh_asio::io_context &ctx);

    /// 添加一个 transport，移交所有权。
    void add_transport(std::shared_ptr<Transport> t);

    /// 启动所有 transports。
    void start_all();

    /// 停止所有 transports。
    void stop_all();

    /// 注册/查找一个 peer，返回其 `RemoteState`。
    std::shared_ptr<RemoteState> resolve(const EndpointAddr &addr);

    /// 向 peer 发送一个包。返回实际发送字节数。
    std::size_t send(const EndpointId &peer, std::span<const uint8_t> payload);

    // ========== S2（v5.3）：多路径保守分集（Socket 层接线） ==========

    /// 设置 strip 分发策略（进程级；默认 RoundRobin=关闭，send 行为不变）
    void set_strip_policy(protocol::StripPolicy p) { strip_policy_ = p; }
    protocol::StripPolicy strip_policy() const { return strip_policy_; }

    /// S2：按流+角色发送（RoleHash 策略入口）。
    /// peer 可用路径 ≥2 时：data 块与冗余块稳定异轨
    ///（data=h(flow)%n，redundancy=(data+1)%n——单轨故障只损失一类块）；
    /// 单路径/未启用时退化为 send()（best_path）。
    /// @param flow_key 流标识（建议 stream_id 或 FEC 组 id）
    /// @param is_redundancy 是否冗余/校验块
    /// @return 实际发送字节数（0=无可用路径）
    std::size_t send_strip(const EndpointId &peer, std::span<const uint8_t> payload,
                           std::uint64_t flow_key, bool is_redundancy);

    /// 设置全局入站数据报回调。Transport 收到包时，会解析发送者 EndpointId 并分发。
    using DatagramHandler = std::function<void(const EndpointId &from, util::Bytes data, const base::TransportAddr &from_addr)>;
    void set_datagram_handler(DatagramHandler h);

    /// 从内存 table 中查找对端的 RemoteState（无则返回 nullptr）。
    std::shared_ptr<RemoteState> lookup(const EndpointId &peer);

    /// 所有 transports。
    const std::vector<std::shared_ptr<Transport>> &transports() const { return transports_; }

    /// 返回所有 transports 中第一个 UDP v4 的本地端口（用于示例程序）。
    uint16_t first_udp4_port() const;

private:
    /// 被每个 Transport 回调入口；调用用户 DatagramHandler_；内部根据包中解析来自 peer 的数据报
    void dispatch_recv(RecvPacket pkt);

    linoh_asio::io_context &ctx_;
    std::vector<std::shared_ptr<Transport>> transports_;
    std::unordered_map<EndpointId, std::shared_ptr<RemoteState>> remotes_;
    DatagramHandler datagram_handler_;
    protocol::StripPolicy strip_policy_{protocol::StripPolicy::RoundRobin};  // S2
    mutable std::mutex mu_;  // v1.7.0.7: mutable 允许 const 方法（first_udp4_port）加锁
};

} // namespace linoh::net
