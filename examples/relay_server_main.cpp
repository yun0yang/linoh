/// linoh relay server — standalone Relay Server entry point
///
/// 监听 TCP 端口，提供 iroh relay v2 兼容的 WebSocket 中转服务。
/// 用于 P2P 网络中 NAT 穿透失败时的数据中转。
///
/// 运行方式：
///   ./linoh_relay_server               # 默认端口 9002
///   ./linoh_relay_server --port 8100    # 指定端口
///   ./linoh_relay_server --no-auth     # 关闭 Ed25519 认证（仅测试用）
///
/// 部署位置：orchestrator 服务器 (203.0.113.10:9002)

#include "linoh/relay/server.hpp"
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
    std::cerr << "Usage: " << prog << " [--port N] [--no-auth] [--help]\n"
              << "  --port N    TCP port to bind (default 9002)\n"
              << "  --no-auth   Disable Ed25519 challenge-response auth\n"
              << "  --help      Show this help\n";
}

int main(int argc, char **argv) {
    linoh::util::log::set_level(linoh::util::log::Level::Info);

    uint16_t port = 9002;
    bool require_auth = true;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--no-auth") {
            require_auth = false;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    linoh::relay::RelayServer server(port);
    server.set_require_auth(require_auth);

    if (!server.start()) {
        std::cerr << "[relay_server] failed to bind port " << port << "\n";
        return 1;
    }

    std::cout << "[relay_server] listening on port " << server.local_port()
              << " (auth=" << (require_auth ? "on" : "off") << ")\n";
    std::cout << "[relay_server] node_id = <derived from server-side Ed25519>\n";
    std::cout << "[relay_server] press Ctrl+C to stop\n";

    while (!g_should_exit.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cout << "[relay_server] shutting down...\n";
    server.stop();
    std::cout << "[relay_server] stopped\n";
    return 0;
}
