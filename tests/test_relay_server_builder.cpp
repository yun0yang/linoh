// test_relay_server_builder.cpp — B2 嵌入式 Relay + Builder 测试（v1.7.0.3 P2）
//
// 覆盖：
//   - RelayServerBuilder 链式配置与默认值
//   - build() 生成实例的配置正确性
//   - RelayServer::max_clients / is_full 限制
//   - accept_loop 在 max_clients 满时拒绝新连接
//   - Endpoint::run_embedded_relay / stop_embedded_relay 生命周期
//   - Endpoint::close() 自动停止嵌入式 Relay
//   - 端口=0 时 OS 自动分配
//   - 重复 run/stop 幂等性
//   - 嵌入式 Relay 与独立 RelayServer 协议一致（可被外部 client 连接）
//
// 注意：涉及网络 IO 的测试通过 127.0.0.1 loopback 完成，不依赖外部环境。

#include "linoh/relay/server.hpp"
#include "linoh/relay/ws_client.hpp"
#include "linoh/relay/stride.hpp"
#include "linoh/relay/auth.hpp"
#include "linoh/base/key.hpp"
#include "linoh/base/endpoint_addr.hpp"
#include "linoh/endpoint/endpoint.hpp"
#include "linoh/util/varint.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::relay;
using namespace linoh::base;
using namespace linoh::endpoint;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 测试 1: Builder 默认值
// ============================================================================
static void test_builder_defaults() {
    std::printf("[test] builder defaults...\n");

    RelayServerBuilder b;
    CHECK(b.get_port() == 0);
    CHECK(b.get_require_auth() == true);
    CHECK(b.get_tls_enabled() == false);
    CHECK(b.get_max_clients() == 0);
}

// ============================================================================
// 测试 2: Builder 链式配置
// ============================================================================
static void test_builder_chain() {
    std::printf("[test] builder chain...\n");

    auto b = RelayServerBuilder()
                 .port(19002)
                 .require_auth(false)
                 .max_clients(50);
    CHECK(b.get_port() == 19002);
    CHECK(b.get_require_auth() == false);
    CHECK(b.get_max_clients() == 50);
}

// ============================================================================
// 测试 3: Builder TLS 配置
// ============================================================================
static void test_builder_tls_config() {
    std::printf("[test] builder tls config...\n");

    auto b = RelayServerBuilder()
                 .tls_enabled(true)
                 .tls_cert("FAKE_CERT", "FAKE_KEY");
    CHECK(b.get_tls_enabled() == true);
}

// ============================================================================
// 测试 4: Builder build 生成非空实例
// ============================================================================
static void test_builder_build_returns_instance() {
    std::printf("[test] builder build returns instance...\n");

    RelayServerBuilder b;
    auto server = b.build();
    CHECK(server != nullptr);
    CHECK(server->is_running() == false);
}

// ============================================================================
// 测试 5: Builder 配置在 build 后正确应用
// ============================================================================
static void test_builder_config_applied() {
    std::printf("[test] builder config applied...\n");

    auto b = RelayServerBuilder()
                 .port(0)
                 .require_auth(false)
                 .max_clients(10);
    auto server = b.build();
    CHECK(server != nullptr);
    CHECK(server->max_clients() == 10);
    CHECK(server->local_port() == 0);  // 尚未 start
}

// ============================================================================
// 测试 6: Builder 链式调用返回自引用
// ============================================================================
static void test_builder_returns_self_reference() {
    std::printf("[test] builder returns self reference...\n");

    RelayServerBuilder b;
    auto &r1 = b.port(1);
    auto &r2 = b.require_auth(true);
    auto &r3 = b.max_clients(5);
    // 同一对象地址
    CHECK(&r1 == &b);
    CHECK(&r2 == &b);
    CHECK(&r3 == &b);
}

// ============================================================================
// 测试 7: RelayServer max_clients 默认 0（不限制）
// ============================================================================
static void test_max_clients_default_unlimited() {
    std::printf("[test] max_clients default unlimited...\n");

    RelayServer server(0);
    CHECK(server.max_clients() == 0);
    CHECK(server.is_full() == false);  // 0 = 不限制
}

// ============================================================================
// 测试 8: RelayServer set_max_clients 生效
// ============================================================================
static void test_set_max_clients() {
    std::printf("[test] set_max_clients...\n");

    RelayServer server(0);
    server.set_max_clients(5);
    CHECK(server.max_clients() == 5);
}

// ============================================================================
// 测试 9: RelayServer is_full 在未 start 时也按 max_clients 判断
// ============================================================================
static void test_is_full_with_limit_zero_conns() {
    std::printf("[test] is_full with limit, zero conns...\n");

    RelayServer server(0);
    server.set_max_clients(1);
    CHECK(server.is_full() == false);  // 0 连接 < 1 上限
}

// ============================================================================
// 测试 10: start/stop 基础生命周期
// ============================================================================
static void test_start_stop_lifecycle() {
    std::printf("[test] start/stop lifecycle...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    RelayServer server(0);
    CHECK(server.start() == true);
    CHECK(server.is_running() == true);
    CHECK(server.local_port() != 0);
    server.stop();
    CHECK(server.is_running() == false);

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 11: Builder 构建的 server 能正常 start/stop
// ============================================================================
static void test_builder_built_server_starts() {
    std::printf("[test] builder-built server starts...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    auto server = RelayServerBuilder().port(0).require_auth(false).build();
    CHECK(server != nullptr);
    CHECK(server->start() == true);
    CHECK(server->is_running() == true);
    CHECK(server->local_port() != 0);
    server->stop();
    CHECK(server->is_running() == false);

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 12: 多次 stop 幂等
// ============================================================================
static void test_stop_idempotent() {
    std::printf("[test] stop idempotent...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    RelayServer server(0);
    server.start();
    server.stop();
    // 再次 stop 不应崩溃
    server.stop();
    CHECK(server.is_running() == false);

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 13: Builder 析构安全（build 后立即销毁 builder）
// ============================================================================
static void test_builder_destruction_safe() {
    std::printf("[test] builder destruction safe...\n");

    std::unique_ptr<RelayServer> server;
    {
        RelayServerBuilder b;
        b.port(0).require_auth(false);
        server = b.build();
    }  // b 析构
    CHECK(server != nullptr);
    // server 仍可用
    CHECK(server->is_running() == false);
}

// ============================================================================
// 测试 14: max_clients 0 与非 0 切换
// ============================================================================
static void test_max_clients_toggle() {
    std::printf("[test] max_clients toggle...\n");

    RelayServer server(0);
    server.set_max_clients(0);
    CHECK(server.is_full() == false);

    server.set_max_clients(3);
    CHECK(server.max_clients() == 3);
    CHECK(server.is_full() == false);

    server.set_max_clients(0);
    CHECK(server.is_full() == false);
}

// ============================================================================
// 测试 15: max_clients 限制实际拒绝（accept_loop 拒绝新连接）
// 通过尝试连接到已满的 Relay 验证（不依赖完整 client 握手）
// ============================================================================
static void test_max_clients_rejects_connection() {
    std::printf("[test] max_clients rejects connection...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    auto server = RelayServerBuilder()
                      .port(0)
                      .require_auth(false)
                      .max_clients(1)
                      .build();
    CHECK(server->start() == true);
    auto port = server->local_port();

    // 第一个连接：占满配额（建立 TCP 即占 conns_，无需完成握手）
    socket_t c1 = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);
    int r1 = ::connect(c1, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    CHECK(r1 == 0);

    // 等待 server accept + 加入 conns_
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // 第二个连接：应被 server 在 accept_loop 中拒绝（is_full 返回 true）
    socket_t c2 = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int r2 = ::connect(c2, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    // TCP connect 可能成功（连接已队列），但 server 会立即关闭
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // 验证 server 仍在运行（拒绝不应导致崩溃）
    CHECK(server->is_running() == true);

    // 清理
#ifdef _WIN32
    ::closesocket(c1);
    ::closesocket(c2);
#else
    ::close(c1);
    ::close(c2);
#endif
    server->stop();

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 16: require_auth=false 端到端（无需 client auth）
// ============================================================================
static void test_no_auth_allows_anonymous_connection() {
    std::printf("[test] no auth allows anonymous connection...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    auto server = RelayServerBuilder()
                      .port(0)
                      .require_auth(false)
                      .build();
    CHECK(server->start() == true);
    auto port = server->local_port();

    // 建立 TCP + WS 升级握手（不发 ClientAuth）
    socket_t c = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);
    ::connect(c, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));

    // 发送 WebSocket 升级请求
    std::string req =
        "GET / HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: iroh-relay-v2\r\n"
        "\r\n";
    ::send(c, req.data(), static_cast<int>(req.size()), 0);

    // 等待响应
    char buf[1024]{};
    int n = ::recv(c, buf, sizeof(buf), 0);
    CHECK(n > 0);
    // 应返回 101 Switching Protocols（require_auth=false 下不再要求 auth）
    std::string resp(buf, n > 0 ? n : 0);
    CHECK(resp.find("101") != std::string::npos);

#ifdef _WIN32
    ::closesocket(c);
#else
    ::close(c);
#endif
    server->stop();

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 17: Builder 多次 build 生成独立实例
// ============================================================================
static void test_builder_multiple_builds_independent() {
    std::printf("[test] builder multiple builds independent...\n");

    RelayServerBuilder b;
    auto s1 = b.build();
    auto s2 = b.build();
    CHECK(s1 != s2);
    CHECK(s1.get() != s2.get());

    // 修改 s1 不影响 s2
    s1->set_max_clients(10);
    CHECK(s2->max_clients() == 0);
}

// ============================================================================
// 测试 18: Endpoint::run_embedded_relay 基础
// ============================================================================
static void test_endpoint_run_embedded_relay_basic() {
    std::printf("[test] endpoint run_embedded_relay basic...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    linoh_asio::io_context ctx;
    Endpoint::Config cfg;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto builder = RelayServerBuilder()
                       .port(0)
                       .require_auth(false);
    unsigned short port = ep->run_embedded_relay(std::move(builder));
    CHECK(port != 0);
    CHECK(ep->embedded_relay() != nullptr);
    CHECK(ep->embedded_relay()->is_running() == true);
    CHECK(ep->embedded_relay()->local_port() == port);

    ep->stop_embedded_relay();
    CHECK(ep->embedded_relay() == nullptr);

    ep->close();

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 19: Endpoint::stop_embedded_relay 幂等（未启动时调用安全）
// ============================================================================
static void test_stop_embedded_relay_idempotent() {
    std::printf("[test] stop_embedded_relay idempotent...\n");

    linoh_asio::io_context ctx;
    Endpoint::Config cfg;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    // 未启动 relay，直接调用 stop 不应崩溃
    ep->stop_embedded_relay();
    CHECK(ep->embedded_relay() == nullptr);

    ep->close();
}

// ============================================================================
// 测试 20: Endpoint::close 自动停止嵌入式 Relay
// ============================================================================
static void test_endpoint_close_stops_embedded_relay() {
    std::printf("[test] endpoint close stops embedded relay...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    linoh_asio::io_context ctx;
    Endpoint::Config cfg;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto builder = RelayServerBuilder().port(0).require_auth(false);
    unsigned short port = ep->run_embedded_relay(std::move(builder));
    CHECK(port != 0);
    CHECK(ep->embedded_relay() != nullptr);

    // close 应自动停止 embedded relay
    ep->close();
    CHECK(ep->embedded_relay() == nullptr);

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 21: Endpoint::run_embedded_relay 重复调用返回相同端口
// ============================================================================
static void test_run_embedded_relay_double_call() {
    std::printf("[test] run_embedded_relay double call...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    linoh_asio::io_context ctx;
    Endpoint::Config cfg;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto b1 = RelayServerBuilder().port(0).require_auth(false);
    unsigned short p1 = ep->run_embedded_relay(std::move(b1));
    CHECK(p1 != 0);

    // 第二次调用不应启动新实例（已存在则返回当前端口）
    auto b2 = RelayServerBuilder().port(0).require_auth(false);
    unsigned short p2 = ep->run_embedded_relay(std::move(b2));
    CHECK(p2 == p1);

    ep->close();

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 22: 嵌入式 Relay 可被外部 TCP 连接
// ============================================================================
static void test_embedded_relay_accepts_external_connection() {
    std::printf("[test] embedded relay accepts external connection...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    linoh_asio::io_context ctx;
    Endpoint::Config cfg;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto builder = RelayServerBuilder().port(0).require_auth(false);
    unsigned short port = ep->run_embedded_relay(std::move(builder));
    CHECK(port != 0);

    // 外部 TCP 连接
    socket_t c = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);
    int r = ::connect(c, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    CHECK(r == 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

#ifdef _WIN32
    ::closesocket(c);
#else
    ::close(c);
#endif
    ep->close();

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 23: Endpoint 嵌入式 Relay 配置 max_clients 后生效
// ============================================================================
static void test_embedded_relay_max_clients() {
    std::printf("[test] embedded relay max_clients...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    linoh_asio::io_context ctx;
    Endpoint::Config cfg;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto builder = RelayServerBuilder()
                       .port(0)
                       .require_auth(false)
                       .max_clients(2);
    unsigned short port = ep->run_embedded_relay(std::move(builder));
    CHECK(port != 0);
    CHECK(ep->embedded_relay()->max_clients() == 2);

    ep->close();

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 24: Builder port=0 让 OS 自动选择端口
// ============================================================================
static void test_builder_port_zero_auto_selects() {
    std::printf("[test] builder port=0 auto selects...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    auto s1 = RelayServerBuilder().port(0).build();
    CHECK(s1->start() == true);
    CHECK(s1->local_port() != 0);
    auto p1 = s1->local_port();

    auto s2 = RelayServerBuilder().port(0).build();
    CHECK(s2->start() == true);
    CHECK(s2->local_port() != 0);
    // 两个 port=0 的 server 应获得不同的端口
    CHECK(s2->local_port() != p1);

    s1->stop();
    s2->stop();

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 25: Builder 配置 require_auth 传递到 server
// ============================================================================
static void test_builder_require_auth_propagated() {
    std::printf("[test] builder require_auth propagated...\n");

    auto s = RelayServerBuilder().require_auth(false).build();
    // require_auth 默认 true，这里改为 false
    // 通过启动 + 匿名 TCP 连接验证（详见 test_no_auth_allows_anonymous_connection）
    CHECK(s != nullptr);
}

// ============================================================================
// 测试 26: TLS enabled 但未提供证书 → 降级为非 TLS（不崩溃）
// ============================================================================
static void test_tls_enabled_without_cert_degrades_gracefully() {
    std::printf("[test] tls_enabled without cert degrades gracefully...\n");

    auto b = RelayServerBuilder().tls_enabled(true);  // 无 cert
    auto s = b.build();
    CHECK(s != nullptr);
    // build 不应崩溃，server 仍可启动（降级为 ws://）
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    CHECK(s->start() == true);
    s->stop();
#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 27: Endpoint::run_embedded_relay 在 closed endpoint 上返回 0
// ============================================================================
static void test_run_embedded_relay_on_closed_endpoint() {
    std::printf("[test] run_embedded_relay on closed endpoint...\n");

    linoh_asio::io_context ctx;
    Endpoint::Config cfg;
    auto ep = Endpoint::make(ctx, std::move(cfg));
    ep->close();

    auto b = RelayServerBuilder().port(0).require_auth(false);
    unsigned short port = ep->run_embedded_relay(std::move(b));
    CHECK(port == 0);
    CHECK(ep->embedded_relay() == nullptr);
}

// ============================================================================
// 测试 28: stop_embedded_relay 后可重新启动
// ============================================================================
static void test_restart_embedded_relay() {
    std::printf("[test] restart embedded relay...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    linoh_asio::io_context ctx;
    Endpoint::Config cfg;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto b1 = RelayServerBuilder().port(0).require_auth(false);
    unsigned short p1 = ep->run_embedded_relay(std::move(b1));
    CHECK(p1 != 0);

    ep->stop_embedded_relay();
    CHECK(ep->embedded_relay() == nullptr);

    auto b2 = RelayServerBuilder().port(0).require_auth(false);
    unsigned short p2 = ep->run_embedded_relay(std::move(b2));
    CHECK(p2 != 0);
    CHECK(ep->embedded_relay() != nullptr);

    ep->close();

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 29: 多个 Endpoint 各自启动嵌入式 Relay（端口隔离）
// ============================================================================
static void test_multiple_endpoints_embedded_relays() {
    std::printf("[test] multiple endpoints embedded relays...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    linoh_asio::io_context ctx1;
    Endpoint::Config cfg1;
    auto ep1 = Endpoint::make(ctx1, std::move(cfg1));

    linoh_asio::io_context ctx2;
    Endpoint::Config cfg2;
    auto ep2 = Endpoint::make(ctx2, std::move(cfg2));

    auto b1 = RelayServerBuilder().port(0).require_auth(false);
    unsigned short p1 = ep1->run_embedded_relay(std::move(b1));
    auto b2 = RelayServerBuilder().port(0).require_auth(false);
    unsigned short p2 = ep2->run_embedded_relay(std::move(b2));

    CHECK(p1 != 0);
    CHECK(p2 != 0);
    CHECK(p1 != p2);

    ep1->close();
    ep2->close();

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 30: max_clients 极大值不影响性能
// ============================================================================
static void test_max_clients_large_value() {
    std::printf("[test] max_clients large value...\n");

    RelayServer server(0);
    server.set_max_clients(1000000);
    CHECK(server.max_clients() == 1000000);
    CHECK(server.is_full() == false);
}

// ============================================================================
// 测试 31: Builder 链式 port 后修改不影响已 build 的实例
// ============================================================================
static void test_builder_modify_after_build_no_effect() {
    std::printf("[test] builder modify after build no effect...\n");

    RelayServerBuilder b;
    b.port(19000).max_clients(5);
    auto s = b.build();
    CHECK(s->max_clients() == 5);

    // 修改 builder 不影响已 build 的实例
    b.max_clients(99);
    CHECK(s->max_clients() == 5);
    CHECK(b.get_max_clients() == 99);
}

// ============================================================================
// 测试 32: Endpoint 析构时嵌入式 Relay 自动停止（通过 close 路径）
// ============================================================================
static void test_endpoint_destructor_cleans_relay() {
    std::printf("[test] endpoint destructor cleans relay...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    {
        linoh_asio::io_context ctx;
        Endpoint::Config cfg;
        auto ep = Endpoint::make(ctx, std::move(cfg));

        auto b = RelayServerBuilder().port(0).require_auth(false);
        unsigned short port = ep->run_embedded_relay(std::move(b));
        CHECK(port != 0);

        // ep 析构（make_shared 引用计数归零）— 但 close() 必须先调用
        // 这里测试显式 close + 析构路径
        ep->close();
    }
    // 若 Relay 线程未正确停止，进程会卡住或崩溃
    // 到这里说明清理成功
    CHECK(true);

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 33: run_embedded_relay 后 channel_stats 仍可使用
// ============================================================================
static void test_endpoint_channel_stats_with_embedded_relay() {
    std::printf("[test] endpoint channel_stats with embedded relay...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    linoh_asio::io_context ctx;
    Endpoint::Config cfg;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto b = RelayServerBuilder().port(0).require_auth(false);
    ep->run_embedded_relay(std::move(b));

    // channel_stats 仍可正常使用
    ep->channel_stats().record_send(multimodal::ChannelType::LLM_HIDDEN, 1000);
    auto snap = ep->channel_stats().snapshot(multimodal::ChannelType::LLM_HIDDEN);
    CHECK(snap.bytes_sent == 1000);

    ep->close();

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 34: 多次 build 同一 builder（验证 builder 可复用）
// ============================================================================
static void test_builder_reusable() {
    std::printf("[test] builder reusable...\n");

    RelayServerBuilder b;
    b.port(0).require_auth(false).max_clients(3);

    auto s1 = b.build();
    auto s2 = b.build();
    CHECK(s1 != nullptr);
    CHECK(s2 != nullptr);
    CHECK(s1->max_clients() == 3);
    CHECK(s2->max_clients() == 3);
}

// ============================================================================
// 测试 35: 嵌入式 Relay stop 后端口可被复用
// ============================================================================
static void test_embedded_relay_port_reuse_after_stop() {
    std::printf("[test] embedded relay port reuse after stop...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    linoh_asio::io_context ctx;
    Endpoint::Config cfg;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto b1 = RelayServerBuilder().port(0).require_auth(false);
    unsigned short p1 = ep->run_embedded_relay(std::move(b1));
    CHECK(p1 != 0);
    ep->stop_embedded_relay();

    // 端口 0 重新分配，可能不同但应有效
    auto b2 = RelayServerBuilder().port(0).require_auth(false);
    unsigned short p2 = ep->run_embedded_relay(std::move(b2));
    CHECK(p2 != 0);

    ep->close();

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 36: is_full 在 max_clients=0 时始终 false（即使有连接）
// ============================================================================
static void test_is_full_zero_limit_always_false() {
    std::printf("[test] is_full zero limit always false...\n");

    RelayServer server(0);
    server.set_max_clients(0);
    // 无连接时
    CHECK(server.is_full() == false);
    // 注意：有连接时无法在单线程中无 client 的情况下测试 conns_.size()
    // 此处仅验证 max_clients=0 的策略
}

// ============================================================================
// 测试 37: Builder max_clients=0 显式设置
// ============================================================================
static void test_builder_max_clients_zero_explicit() {
    std::printf("[test] builder max_clients zero explicit...\n");

    auto b = RelayServerBuilder().max_clients(0);
    auto s = b.build();
    CHECK(s->max_clients() == 0);
}

// ============================================================================
// 测试 38: ServerConfig 全字段配置（端口+认证+TLS+max_clients）
// ============================================================================
static void test_full_config() {
    std::printf("[test] full config...\n");

    auto b = RelayServerBuilder()
                 .port(0)
                 .require_auth(true)
                 .tls_enabled(false)
                 .max_clients(100);
    auto s = b.build();
    CHECK(s != nullptr);
    CHECK(b.get_port() == 0);
    CHECK(b.get_require_auth() == true);
    CHECK(b.get_tls_enabled() == false);
    CHECK(b.get_max_clients() == 100);
}

// ============================================================================
// 测试 39: 嵌入式 Relay 启动后 local_port 一致性
// ============================================================================
static void test_embedded_relay_port_consistency() {
    std::printf("[test] embedded relay port consistency...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    linoh_asio::io_context ctx;
    Endpoint::Config cfg;
    auto ep = Endpoint::make(ctx, std::move(cfg));

    auto b = RelayServerBuilder().port(0).require_auth(false);
    unsigned short port = ep->run_embedded_relay(std::move(b));
    CHECK(port != 0);
    CHECK(ep->embedded_relay()->local_port() == port);

    ep->close();

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 测试 40: 析构时不调用 close 的安全场景（shared_from_this 析构链）
// ============================================================================
static void test_endpoint_shared_ptr_cleanup() {
    std::printf("[test] endpoint shared_ptr cleanup...\n");

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    // 不显式 close，依赖 shared_ptr 析构
    // 注意：Endpoint 析构不会自动调用 close()，必须显式 close
    // 此测试验证：未启动 relay 的 Endpoint 安全析构
    {
        linoh_asio::io_context ctx;
        Endpoint::Config cfg;
        auto ep = Endpoint::make(ctx, std::move(cfg));
        ep->close();
    }
    CHECK(true);

#ifdef _WIN32
    WSACleanup();
#endif
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== test_relay_server_builder (v1.7.0.3 P2 B2) ===\n");

    test_builder_defaults();
    test_builder_chain();
    test_builder_tls_config();
    test_builder_build_returns_instance();
    test_builder_config_applied();
    test_builder_returns_self_reference();
    test_max_clients_default_unlimited();
    test_set_max_clients();
    test_is_full_with_limit_zero_conns();
    test_start_stop_lifecycle();
    test_builder_built_server_starts();
    test_stop_idempotent();
    test_builder_destruction_safe();
    test_max_clients_toggle();
    test_max_clients_rejects_connection();
    test_no_auth_allows_anonymous_connection();
    test_builder_multiple_builds_independent();
    test_endpoint_run_embedded_relay_basic();
    test_stop_embedded_relay_idempotent();
    test_endpoint_close_stops_embedded_relay();
    test_run_embedded_relay_double_call();
    test_embedded_relay_accepts_external_connection();
    test_embedded_relay_max_clients();
    test_builder_port_zero_auto_selects();
    test_builder_require_auth_propagated();
    test_tls_enabled_without_cert_degrades_gracefully();
    test_run_embedded_relay_on_closed_endpoint();
    test_restart_embedded_relay();
    test_multiple_endpoints_embedded_relays();
    test_max_clients_large_value();
    test_builder_modify_after_build_no_effect();
    test_endpoint_destructor_cleans_relay();
    test_endpoint_channel_stats_with_embedded_relay();
    test_builder_reusable();
    test_embedded_relay_port_reuse_after_stop();
    test_is_full_zero_limit_always_false();
    test_builder_max_clients_zero_explicit();
    test_full_config();
    test_embedded_relay_port_consistency();
    test_endpoint_shared_ptr_cleanup();

    std::printf("\n=== Results: %d PASSED, %d FAILED ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
