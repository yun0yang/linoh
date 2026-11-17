// test_socket_strip.cpp — S2（v5.3）Socket 层多路径保守分集测试
//
// 覆盖：
//   T1 策略状态机（默认 RoundRobin / set_strip_policy）
//   T2 send_strip 在无 transport 注册时的安全退化（不崩，返回 0）
//   T3 双路径 RemoteState 构造 + 路径可见性
//
// 注：RoleHash 的异轨数学已由 test_multipath_role_hash（270 断言）覆盖；
//    本文件验证 Socket 层 API 面与安全退化。真实双 transport 数据面
//    归 patchbay/集成回归。
#include "linoh/net/socket.hpp"

#include <cstdio>

using namespace linoh;
using namespace linoh::net;

static int g_pass = 0, g_fail = 0;
#define CHECK(c) do { if (c) ++g_pass; else { ++g_fail; \
    std::printf("FAIL: %s (line %d)\n", #c, __LINE__); } } while (0)

static std::shared_ptr<Path> make_path(const std::string &host, uint16_t port,
                                       const std::string &transport) {
    base::TransportAddr a{};
    a.kind = base::TransportKind::Ip;
    a.host = host;
    a.port = port;
    return std::make_shared<Path>(transport, std::move(a));
}

int main() {
    std::printf("=== S2 Socket strip API tests ===\n");

    linoh_asio::io_context ctx;
    Socket sock(ctx);

    // T1: 策略状态机
    CHECK(sock.strip_policy() == protocol::StripPolicy::RoundRobin);
    sock.set_strip_policy(protocol::StripPolicy::RoleHash);
    CHECK(sock.strip_policy() == protocol::StripPolicy::RoleHash);
    sock.set_strip_policy(protocol::StripPolicy::RoundRobin);
    CHECK(sock.strip_policy() == protocol::StripPolicy::RoundRobin);
    std::printf("[T1] policy state machine\n");

    // T3: 双路径 peer 构造
    base::EndpointAddr addr{};
    auto rs = sock.resolve(addr);
    CHECK(rs != nullptr);
    rs->add_path(make_path("10.0.0.1", 1001, "udp4"));
    rs->add_path(make_path("10.0.0.2", 1002, "udp4"));
    CHECK(rs->paths().size() == 2);
    std::printf("[T3] dual-path RemoteState ok\n");

    // T2: 无 transport 注册 → send/send_strip 安全返回 0（不崩）
    {
        uint8_t buf[8] = {1};
        CHECK(sock.send(addr.id(), buf) == 0);
        sock.set_strip_policy(protocol::StripPolicy::RoleHash);
        CHECK(sock.send_strip(addr.id(), buf, 7, false) == 0);
        CHECK(sock.send_strip(addr.id(), buf, 7, true) == 0);
        // 单路径 peer：RoleHash 退化路径同样安全
        base::EndpointAddr single{};
        auto rs2 = sock.resolve(single);
        rs2->add_path(make_path("10.0.0.3", 1003, "udp4"));
        CHECK(sock.send_strip(single.id(), buf, 9, true) == 0);
        std::printf("[T2] safe degrade without transports\n");
    }

    std::printf("=== %d PASS / %d FAIL ===\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
