/// linoh echo client
///
/// 向 echo_server 发送若干 UDP 数据报，并等待响应。
///
/// 用法：
///   ./echo_client --port <server_port> [--count N] [--host HOST]
///
/// 示例：
///   终端 A： ./echo_server                 # 打印监听端口，例如 54321
///   终端 B： ./echo_client --port 54321    # 向 127.0.0.1:54321 发送 3 个包

#include "linoh/endpoint/builder.hpp"
#include "linoh/endpoint/endpoint.hpp"
#include "linoh/util/logging.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

using namespace linoh;

namespace {
/// 演示用：把 "server" 字符串映射到一个固定的 EndpointId。
/// 真实用法中，客户端会从 DNS/AddressLookup 中拿到 server 公钥。
base::EndpointId make_demo_server_id() {
    std::array<uint8_t, base::PublicKey::kSize> bytes{};
    const char *tag = "linoh-demo-server---";
    std::memcpy(bytes.data(), tag, std::min<std::size_t>(32, std::strlen(tag)));
    return base::PublicKey{bytes};
}

void print_usage(const char *prog) {
    std::cerr << "usage: " << prog
              << " [--port N] [--host HOST] [--count N] [--interval_ms N]\n";
    std::cerr << "       default: --port 12345 --host 127.0.0.1 "
                 "--count 3 --interval_ms 500\n";
}
} // namespace

int main(int argc, char **argv) {
    util::log::set_level(util::log::Level::Info);

    uint16_t server_port = 12345;
    std::string host = "127.0.0.1";
    int count = 3;
    int interval_ms = 500;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) {
                print_usage(argv[0]);
                std::exit(1);
            }
            return argv[++i];
        };
        if (arg == "--port") server_port = static_cast<uint16_t>(std::stoi(next()));
        else if (arg == "--host") host = next();
        else if (arg == "--count") count = std::stoi(next());
        else if (arg == "--interval-ms" || arg == "--interval_ms") {
            interval_ms = std::stoi(next());
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "unknown arg: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    linoh_asio::io_context ctx;
    auto ep = endpoint::Builder{}.build(ctx);

    std::cout << "[echo_client] local node_id = " << ep->id().fmt_short()
              << ", udp4_port = " << ep->local_udp_port() << "\n";

    // 构造"目标服务器的 EndpointAddr"——演示用，真实情况下从 AddressLookup 获取。
    base::EndpointAddr target{make_demo_server_id()};
    base::TransportAddr addr;
    addr.kind = base::TransportKind::Ip;
    addr.host = host;
    addr.port = server_port;
    target.add_direct_address(addr);

    // connect 只是把"这条 peer 的可达地址"注册进 socket。
    auto conn = ep->connect(target, "echo/1");
    if (!conn) {
        std::cerr << "[echo_client] failed to register peer route\n";
        return 1;
    }

    // 准备接收响应。
    std::atomic<int> remaining{count};
    ep->on_datagram([&remaining](const base::EndpointId &from, util::Bytes data) {
        std::string text(reinterpret_cast<const char *>(data.data()), data.size());
        std::cout << "[echo_client] got response from " << from.fmt_short()
                  << " len=" << data.size() << ": " << text << "\n";
        remaining.fetch_sub(1);
    });

    // 用单独的线程来"定时发送"——真实应用会用 asio::steady_timer。
    std::thread worker([&] {
        auto peer_id = make_demo_server_id();
        for (int i = 0; i < count; ++i) {
            std::string msg = "hello linoh #" + std::to_string(i + 1);
            std::span<const uint8_t> payload(
                reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
            std::size_t n = ep->send_datagram(peer_id, payload);
            if (n > 0) {
                std::cout << "[echo_client] sent " << n << " bytes: " << msg << "\n";
            } else {
                std::cerr << "[echo_client] send failed\n";
            }
            if (i + 1 < count) std::this_thread::sleep_for(
                std::chrono::milliseconds(interval_ms));
        }
    });

    // 等所有响应或超时 5s。
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (remaining.load() > 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    worker.join();
    ep->close();
    int got = count - remaining.load();
    std::cout << "[echo_client] sent=" << count << ", got_responses=" << got << "\n";
    return got == count ? 0 : 2;
}
