#include "linoh/net/socket.hpp"

#include "linoh/util/logging.hpp"

#include <algorithm>
#include <chrono>

namespace linoh::net {

Socket::Socket(linoh_asio::io_context &ctx) : ctx_{ctx} {}

void Socket::add_transport(std::shared_ptr<Transport> t) {
    if (!t) return;
    {
        std::lock_guard<std::mutex> lk(mu_);
        transports_.push_back(t);
    }
    // 使用 weak_ptr 捕获，避免 Socket 析构后 Transport 回调悬空（UAF）。
    // 回调触发时先 lock，若 Socket 已析构则安全跳过。
    std::weak_ptr<Socket> weak_self = shared_from_this();
    t->set_packet_handler([weak_self](RecvPacket pkt) {
        if (auto self = weak_self.lock()) {
            self->dispatch_recv(std::move(pkt));
        }
    });
}

void Socket::start_all() {
    // v1.7.0.7 H1: transports_ 加锁保护，拷贝到局部 vector 后锁外 start
    // （start 可能触发回调，避免锁内回调死锁）
    std::vector<std::shared_ptr<Transport>> snapshot;
    {
        std::lock_guard<std::mutex> lk(mu_);
        snapshot = transports_;
    }
    for (auto &t : snapshot) t->start();
}

void Socket::stop_all() {
    // v1.7.0.7 H1: 同 start_all，锁内拷贝后锁外 stop
    std::vector<std::shared_ptr<Transport>> snapshot;
    {
        std::lock_guard<std::mutex> lk(mu_);
        snapshot = transports_;
    }
    for (auto &t : snapshot) t->stop();
}

std::shared_ptr<RemoteState> Socket::resolve(const EndpointAddr &addr) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = remotes_.find(addr.id());
    if (it != remotes_.end()) return it->second;

    auto rs = std::make_shared<RemoteState>(addr.id());
    for (const auto &da : addr.direct_addresses()) {
        // 每个直连地址都为每个 UDP Transport 创建一条 Path。
        for (const auto &t : transports_) {
            if (t->name() == "udp4" || t->name() == "udp6") {
                auto p = std::make_shared<Path>(t->name(), da);
                rs->add_path(std::move(p));
            }
        }
    }
    for (const auto &relay : addr.relays()) {
        base::TransportAddr a;
        a.kind = base::TransportKind::Relay;
        a.host = relay.host();
        a.port = relay.port();
        auto p = std::make_shared<Path>("relay", std::move(a));
        rs->add_path(std::move(p));
    }
    remotes_[addr.id()] = rs;
    LINOH_INFO("Socket::resolve: new peer", addr.id().fmt_short(),
               "with", static_cast<int>(rs->paths().size()), "paths");
    return rs;
}

std::size_t Socket::send(const EndpointId &peer, std::span<const uint8_t> payload) {
    std::shared_ptr<RemoteState> rs;
    std::vector<std::shared_ptr<Transport>> snapshot;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = remotes_.find(peer);
        if (it == remotes_.end()) return 0;
        rs = it->second;
        snapshot = transports_;  // v1.7.0.7 H1: 拷贝 transports_ 快照避免锁外数据竞争
    }
    auto best = rs->best_path();
    if (!best) return 0;

    for (auto &t : snapshot) {
        if (t->name() == best->transport_name()) {
            return t->send_to(best->addr(), payload);
        }
    }
    return 0;
}

// S2（v5.3）：按流+角色的多路径保守分集发送
std::size_t Socket::send_strip(const EndpointId &peer,
                               std::span<const uint8_t> payload,
                               std::uint64_t flow_key, bool is_redundancy) {
    // 未启用 RoleHash 或无 peer：退化为单路径 send
    if (strip_policy_ != protocol::StripPolicy::RoleHash) {
        return send(peer, payload);
    }
    std::shared_ptr<RemoteState> rs;
    std::vector<std::shared_ptr<Transport>> snapshot;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = remotes_.find(peer);
        if (it == remotes_.end()) return 0;
        rs = it->second;
        snapshot = transports_;
    }
    auto paths = rs->paths();
    if (paths.size() < 2) {
        return send(peer, payload);  // 单路径：无分集，退化为 best_path
    }

    // RoleHash：data = h(flow) % n；redundancy = (data+1) % n（稳定异轨）
    std::uint64_t h = flow_key * 0x9E3779B97F4A7C15ULL;
    h ^= h >> 32;
    std::size_t idx = static_cast<std::size_t>(h) % paths.size();
    if (is_redundancy) idx = (idx + 1) % paths.size();

    auto &target = paths[idx];
    for (auto &t : snapshot) {
        if (t->name() == target->transport_name()) {
            LINOH_DEBUG("Socket::send_strip: peer=", peer.fmt_short(),
                        " flow=", flow_key, " red=", is_redundancy,
                        " path_idx=", idx, "/", paths.size(),
                        " via=", target->addr().host, ":", target->addr().port);
            return t->send_to(target->addr(), payload);
        }
    }
    // 目标路径的 transport 不可用：退回 best_path（倒退保底）
    return send(peer, payload);
}

std::shared_ptr<RemoteState> Socket::lookup(const EndpointId &peer) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = remotes_.find(peer);
    return it == remotes_.end() ? nullptr : it->second;
}

uint16_t Socket::first_udp4_port() const {
    // v1.7.0.7 H1: transports_ 加锁保护
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto &t : transports_) {
        if (t->name() == "udp4") return t->local_port();
    }
    return 0;
}

void Socket::set_datagram_handler(DatagramHandler h) {
    std::lock_guard<std::mutex> lk(mu_);
    datagram_handler_ = std::move(h);
}

void Socket::dispatch_recv(RecvPacket pkt) {
    DatagramHandler h;
    {
        std::lock_guard<std::mutex> lk(mu_);
        h = datagram_handler_;
    }
    if (!h) return;
    // 最简约定：将 TransportAddr 中已记录的 EndpointId 作为"from"传入；
    // 若未记录（UDP Transport 仅知道 IP:port），我们用一个由 "custom_payload" 字段
    // 推测出的 EndpointId——对于 UDP，默认回退为基于 `host:port` 的临时 hash id。
    EndpointId peer;
    // 尝试用 custom_payload 中记录的 fmt_short 字符串反推一个"伪" EndpointId；
    // 真实 iroh 协议会把 EndpointId 放在 QUIC Initial 包内；这里我们简化用 host:port
    // 作为 peer 标识。
    //
    // 为了简化：把 pkt.from.host + ":" + std::to_string(pkt.from.port) 做一次 hash，
    // 用 host:port 作为 peer 标识（演示用；真实 QUIC 会从 Initial 包解析 EndpointId）
    std::string tag = pkt.from.custom_payload.empty()
                          ? (pkt.from.host + ":" + std::to_string(pkt.from.port))
                          : pkt.from.custom_payload;
    std::size_t seed = 0;
    for (char c : tag) seed = seed * 131 + static_cast<std::uint8_t>(c);
    std::array<uint8_t, EndpointId::kSize> bytes{};
    for (int i = 0; i < 8; ++i) bytes[i] = static_cast<uint8_t>((seed >> (i * 8)) & 0xFF);
    const base::PublicKey id{bytes};
    h(id, std::move(pkt.data), pkt.from);
}

} // namespace linoh::net
