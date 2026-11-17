#include "linoh/protocol/router.hpp"

#include "linoh/util/logging.hpp"

#include <thread>
#include <vector>

namespace linoh::protocol {

void Router::spawn() {
    LINOH_INFO("Router: starting accept loop");
    accept_thread_ = std::thread([self = shared_from_this()] {
        while (!self->shutdown_.load()) {
            self->accept_step();
        }
        LINOH_DEBUG("Router: accept loop exited");
    });
}

void Router::shutdown() {
    LINOH_DEBUG("Router: shutting down");
    shutdown_.store(true);
    if (accept_thread_.joinable()) accept_thread_.join();
    // mp-L4 (v1.7.0.8): shutdown 遍历 handlers_ 必须加 mu_ 锁，
    //   防止与 accept_step 的 handlers_.find 并发（accept_thread_ join 之前
    //   仍可能并发，且 register_handler 可能在 shutdown 期间被调用）。
    //   锁内拷贝 shared_ptr 到局部 vector，锁外调用 h->shutdown()
    //   避免 h->shutdown() 回调重入 register_handler 死锁。
    std::vector<std::shared_ptr<ProtocolHandler>> handlers_snapshot;
    {
        std::lock_guard<std::mutex> lk(mu_);
        handlers_snapshot.reserve(handlers_.size());
        for (auto &[alpn, h] : handlers_) {
            handlers_snapshot.push_back(h);
        }
    }
    for (auto &h : handlers_snapshot) {
        h->shutdown();
    }
    // Join all handler threads
    {
        std::lock_guard<std::mutex> lk(thread_mu_);
        for (auto &t : handler_threads_) {
            if (t.joinable()) t.join();
        }
        handler_threads_.clear();
    }
}

void Router::accept_step() {
    // 从 Endpoint 轮询一个已完成的入站连接（无则立即返回）
    auto inc_opt = ep_->accept();
    if (!inc_opt) {
        // 没有待处理连接，短暂让出 CPU
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        return;
    }

    auto &inc = *inc_opt;
    auto conn = inc.conn;
    if (!conn) {
        LINOH_WARN("Router: Incoming connection already expired");
        return;
    }

    // 应用过滤器（如果设置了）
    FilterOutcome outcome = FilterOutcome::Accept;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (filter_) {
            outcome = filter_(inc);
        }
    }

    switch (outcome) {
        case FilterOutcome::Ignore:
        case FilterOutcome::Reject:
            LINOH_INFO("Router: incoming conn rejected/ignored, peer=",
                      inc.peer.fmt_short());
            return;
        case FilterOutcome::Retry:
            // v1.4.3 P2-#1: 完整 Retry 帧实现待后续版本（需 Token 验证 +
            // 完整 RFC 9000 §17.2.5 ODCID/Token 编码）。当前仅记录日志 + 丢弃连接。
            // 临时方案：调用方可在 filter 回调中自行构造 Retry 帧（返回 Accept 后
            // 通过 conn->close() 通知客户端改用新 DCID 重试）。
            LINOH_INFO("Router: incoming conn marked retry, peer=",
                      inc.peer.fmt_short());
            return;
        case FilterOutcome::Accept:
            break;
    }

    // 按 ALPN 查找 handler
    std::shared_ptr<ProtocolHandler> handler;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = handlers_.find(inc.alpn);
        if (it != handlers_.end()) {
            handler = it->second;
        }
    }

    if (!handler) {
        LINOH_INFO("Router: no handler for alpn='", inc.alpn,
                   "', rejecting");
        conn->close(/*error=*/1, "no handler for alpn");
        return;
    }

    // 交给 handler：先 on_connected，再在独立线程中 accept
    LINOH_INFO("Router: routing conn to alpn='", inc.alpn,
               "' handler");
    try {
        handler->on_connected(conn);
        // Run handler accept loop in a tracked thread (joined on shutdown)
        std::lock_guard<std::mutex> lk(thread_mu_);
        handler_threads_.emplace_back([h = handler, c = conn]() {
            h->accept(std::move(c));
        });
    } catch (const std::exception &e) {
        LINOH_ERROR("Router: handler exception: ", e.what());
    }
}

} // namespace linoh::protocol
