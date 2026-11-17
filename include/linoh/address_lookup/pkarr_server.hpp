// linoh/address_lookup/pkarr_server.hpp — 自建 Pkarr DNS Server（地址发现闭环）
//
// 一个本地 UDP DNS 服务端：监听固定端口（默认 5333），维护内存表
// NodeId -> SignedPacket。收到 Pkarr DNS 查询后提取 NodeId、查表，
// 命中则直接回传 publisher 预签的 [sig][dns_packet]（服务端不重新签名，
// 契合 Pkarr 信任模型：地址由节点自签，server 仅作哑存储/转发），
// 未命中回 NXDOMAIN。
//
// 默认不启用（显式 start），零回归。

#pragma once

#include "linoh/address_lookup/pkarr_dns.hpp"
#include "linoh/base/key.hpp"
#include "linoh/util/result.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace linoh::address_lookup {

/// 本地 Pkarr DNS 服务端（UDP :5333 + 内存发布表）。
class PkarrDnsServer {
public:
    PkarrDnsServer() = default;
    ~PkarrDnsServer();

    /// 启动 UDP 监听。bind 默认 127.0.0.1，port 默认 5333（非特权）。
    util::ResultVoid start(std::string listen_host = "127.0.0.1", uint16_t port = 5333);

    /// 停止并释放资源（可重入）。
    void stop();

    bool running() const { return running_.load(); }

    /// publisher 写入：NodeId -> SignedPacket（线程安全）。
    void publish(const base::EndpointId &id, const pkarr::SignedPacket &sp);

    /// 当前内存记录数（测试用）。
    size_t record_count() const;

    uint16_t port() const { return port_; }
    std::string bind_addr() const { return bind_; }

private:
    void run_loop();

    mutable std::mutex mu_;
    std::unordered_map<base::EndpointId, pkarr::SignedPacket> records_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::string bind_;
    uint16_t port_{5333};
    std::intptr_t sock_{-1};  // SOCKET (win) 或 int (unix)
};

}  // namespace linoh::address_lookup
