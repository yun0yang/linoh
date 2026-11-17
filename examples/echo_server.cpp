/// linoh echo server
///
/// 监听 UDP v4/v6。对收到的每个数据报，打印其内容并回写一个确认
/// 报文给发送者——演示 Endpoint 的 datagram API。
///
/// 运行方式：
///   ./echo_server                   # 监听一个随机端口
///   SERVER_PORT=12345 ./echo_server  # 监听指定端口

#include "linoh/endpoint/builder.hpp"
#include "linoh/endpoint/endpoint.hpp"
#include "linoh/util/logging.hpp"

#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

using namespace linoh;

int main(int argc, char **argv) {
    util::log::set_level(util::log::Level::Info);

    linoh_asio::io_context ctx;
    auto ep = endpoint::Builder{}.build(ctx);

    uint16_t port = ep->local_udp_port();
    std::cout << "[echo_server] node_id = " << ep->id().fmt_short()
              << ", udp4_port = " << port << "\n";

    // 统计收到的包数量。
    std::atomic<std::size_t> counter{0};

    ep->on_datagram([ep, &counter](const base::EndpointId &from, util::Bytes data) {
        std::size_t n = counter.fetch_add(1) + 1;
        std::string text(reinterpret_cast<const char *>(data.data()), data.size());
        std::cout << "[echo_server] #" << n << " from=" << from.fmt_short()
                  << " len=" << data.size() << ": " << text << "\n";

        // 回复一个确认报文。
        std::string ack = "ACK(" + std::to_string(n) + "): " + text;
        ep->send_datagram(from, std::span<const uint8_t>(
            reinterpret_cast<const uint8_t *>(ack.data()), ack.size()));
    });

    std::cout << "[echo_server] ready — use './echo_client --port " << port
              << "' in another terminal.\n";

    ctx.run();
    return 0;
}
