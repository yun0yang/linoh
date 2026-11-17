/// linoh pkarr DNS server — standalone Pkarr DNS Server entry point
///
/// 监听 UDP 端口，提供 Pkarr 风格的地址发现服务。
/// 节点启动时将自己的 EndpointId -> 地址映射发布到此服务器，
/// 其他节点通过查询此服务器发现 peer 的地址。
///
/// 运行方式：
///   ./linoh_pkarr_server               # 默认 0.0.0.0:5333
///   ./linoh_pkarr_server --port 9003   # 指定端口
///   ./linoh_pkarr_server --bind 0.0.0.0 --port 9003
///
/// 部署位置：orchestrator 服务器 (203.0.113.10:9003)

#include "linoh/address_lookup/pkarr_server.hpp"
#include "linoh/util/logging.hpp"

#include <atomic>
#include <csignal>
#include <iostream>
#include <string>

using namespace linoh;

static std::atomic<bool> g_should_exit{false};

static void on_signal(int /*sig*/) {
    g_should_exit.store(true);
}

static void print_usage(const char *prog) {
    std::cerr << "Usage: " << prog << " [--bind ADDR] [--port N] [--help]\n"
              << "  --bind ADDR  Bind address (default 0.0.0.0)\n"
              << "  --port N     UDP port to bind (default 5333)\n"
              << "  --help       Show this help\n";
}

int main(int argc, char **argv) {
    linoh::util::log::set_level(linoh::util::log::Level::Info);

    std::string bind_addr = "0.0.0.0";
    uint16_t port = 5333;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--bind" && i + 1 < argc) {
            bind_addr = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    linoh::address_lookup::PkarrDnsServer server;

    auto result = server.start(bind_addr, port);
    if (!result.is_ok()) {
        std::cerr << "[pkarr_dns] failed to start: "
                  << result.error().msg() << "\n";
        return 1;
    }

    std::cout << "[pkarr_dns] listening on " << bind_addr << ":" << port
              << " (UDP)\n";
    std::cout << "[pkarr_dns] press Ctrl+C to stop\n";

    while (!g_should_exit.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cout << "[pkarr_dns] shutting down...\n";
    server.stop();
    std::cout << "[pkarr_dns] stopped\n";
    return 0;
}
