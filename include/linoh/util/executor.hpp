#pragma once

#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifdef LINOH_WITH_BOOST_ASIO
#include <boost/asio.hpp>
namespace linoh_asio = boost::asio;
#else
#include <asio.hpp>
namespace linoh_asio = asio;
#endif

namespace linoh::util {

/// 对 `asio::io_context` 的轻量封装。
///
/// 设计为单线程执行：所有 socket / timer / 协程 都被绑定到同一个 strand，
/// 避免跨线程同步开销——这是 linoh 相对 iroh 的主要优化之一。
class Executor {
public:
    Executor() : ctx_{1}, work_{std::make_shared<linoh_asio::io_context::work>(ctx_)} {}

    Executor(const Executor &) = delete;
    Executor &operator=(const Executor &) = delete;

    ~Executor() {
        work_.reset();
        if (thread_.joinable()) {
            ctx_.stop();
            thread_.join();
        }
    }

    /// 在后台启动一个线程运行 `io_context::run()`。
    void start() {
        if (!thread_.joinable()) {
            thread_ = std::thread([this] { ctx_.run(); });
        }
    }

    /// 阻塞当前线程直到 `io_context` 跑完所有任务（用于示例与测试）。
    void run() { ctx_.run(); }

    /// 返回底层 `io_context` 引用。
    linoh_asio::io_context &ctx() { return ctx_; }

    /// 把任意可调用对象投递到 executor 线程执行。
    template <typename F>
    void post(F &&f) {
        linoh_asio::post(ctx_, std::forward<F>(f));
    }

private:
    linoh_asio::io_context ctx_;
    std::shared_ptr<linoh_asio::io_context::work> work_;
    std::thread thread_;
};

/// 全局默认 executor 访问器（首次调用时构造）。
inline Executor &default_executor() {
    static Executor e;
    return e;
}

} // namespace linoh::util
