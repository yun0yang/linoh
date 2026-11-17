#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/endpoint/endpoint.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace linoh::protocol {

/// 协议处理器抽象：按 ALPN 路由到对应 handler。
class ProtocolHandler {
public:
    virtual ~ProtocolHandler() = default;

    /// 当一条新的连接完成握手后被调用。
    virtual void on_connected(std::shared_ptr<linoh::endpoint::Connection> conn) {
        // 默认实现：什么都不做，交给 accept()。
        (void)conn;
    }

    /// 主循环：处理一条已建立的连接。
    virtual void accept(std::shared_ptr<linoh::endpoint::Connection> conn) = 0;

    /// Router 关闭时调用，给 handler 释放资源的机会。
    virtual void shutdown() {}
};

/// 早期过滤：对未完成握手的入站请求决定 accept / retry / reject / ignore。
enum class FilterOutcome { Accept, Retry, Reject, Ignore };
using IncomingFilter = std::function<FilterOutcome(const linoh::endpoint::Incoming &)>;

/// ALPN Router：持有 Endpoint，循环接受入站连接，按 ALPN 分派给 ProtocolHandler。
class Router : public std::enable_shared_from_this<Router> {
public:
    explicit Router(std::shared_ptr<linoh::endpoint::Endpoint> ep) : ep_{std::move(ep)} {}

    /// 注册某 ALPN 的处理器。
    Router &accept(std::string alpn, std::shared_ptr<ProtocolHandler> handler) {
        std::lock_guard<std::mutex> lk(mu_);
        handlers_[alpn] = std::move(handler);
        return *this;
    }

    /// 设置入站过滤器（可选）。
    Router &filter(IncomingFilter f) {
        std::lock_guard<std::mutex> lk(mu_);
        filter_ = std::move(f);
        return *this;
    }

    /// 启动 accept loop。返回后 loop 会在 Endpoint 的 io_context 上继续跑，
    /// 直到 `shutdown()` 被调用或 Endpoint 关闭。
    void spawn();

    /// 停止 accept loop 并给所有 handler 发 shutdown 通知。
    void shutdown();

    bool is_shutdown() const { return shutdown_.load(); }
    linoh::endpoint::Endpoint &endpoint() { return *ep_; }

private:
    /// 循环 body：每次等待一次 accept 并分派。
    void accept_step();

    std::shared_ptr<linoh::endpoint::Endpoint> ep_;
    std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<ProtocolHandler>> handlers_;
    IncomingFilter filter_;
    std::atomic<bool> shutdown_{false};
    std::thread accept_thread_;
    std::vector<std::thread> handler_threads_;
    std::mutex thread_mu_;
};

} // namespace linoh::protocol
