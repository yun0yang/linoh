/// connection_test.cpp - Connection/Endpoint 状态机集成测试
///
/// 测试:
///   1. Connection 构造与初始状态
///   2. 连接状态转换: Initial → Handshake → Established
///   3. Stream 打开/接受
///   4. 1-RTT 包构建与加密
///   5. 状态机关闭

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WINSOCKAPI_
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include "linoh/endpoint/connection.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/util/bytes.hpp"

#include <iostream>
#include <cassert>

using namespace linoh;
using namespace linoh::endpoint;
using namespace linoh::protocol;

static int g_pass = 0;
static int g_fail = 0;

#define PASS(msg) do { \
    std::cout << "  [PASS] " << msg << std::endl; \
    g_pass++; \
} while(0)

#define FAIL(msg) do { \
    std::cout << "  [FAIL] " << msg << std::endl; \
    g_fail++; \
} while(0)

// ============================================================================
// 测试 1: Connection 构造与初始状态
// ============================================================================
void test_connection_creation() {
    std::cout << "\n=== 测试 1: Connection 构造与初始状态 ===" << std::endl;

    SecretKey sk = SecretKey::generate();
    ConnectionId local_cid = ConnectionId::generate();
    ConnectionId remote_cid = ConnectionId::generate();

    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = local_cid;
    cfg.remote_cid = remote_cid;
    cfg.direction = Direction::Outbound;
    cfg.alpn = "test-alpn";

    auto conn = std::make_shared<Connection>(std::move(cfg));

    if (conn->state() == ConnState::Initial) {
        PASS("初始状态为 Initial");
    } else {
        FAIL("初始状态应为 Initial");
    }

    if (conn->id() > 0) {
        PASS("Connection ID > 0");
    } else {
        FAIL("Connection ID 应 > 0");
    }

    if (!conn->is_closed()) {
        PASS("新连接未关闭");
    } else {
        FAIL("新连接不应已关闭");
    }

    if (conn->local_cid() == local_cid) {
        PASS("local_cid 正确保存");
    } else {
        FAIL("local_cid 不匹配");
    }

    if (conn->remote_cid() == remote_cid) {
        PASS("remote_cid 正确保存");
    } else {
        FAIL("remote_cid 不匹配");
    }

    if (conn->direction() == Direction::Outbound) {
        PASS("direction 为 Outbound");
    } else {
        FAIL("direction 应为 Outbound");
    }

    if (conn->alpn() == "test-alpn") {
        PASS("alpn 正确保存");
    } else {
        FAIL("alpn 不匹配");
    }

    ConnectionStats stats = conn->stats();
    if (stats.packets_sent == 0 && stats.packets_received == 0) {
        PASS("初始统计为 0");
    } else {
        FAIL("初始统计应全为 0");
    }
}

// ============================================================================
// 测试 2: 连接状态转换
// ============================================================================
void test_connection_state_transitions() {
    std::cout << "\n=== 测试 2: 连接状态转换 ===" << std::endl;

    SecretKey sk = SecretKey::generate();
    ConnectionId local_cid = ConnectionId::generate();
    ConnectionId remote_cid = ConnectionId::generate();

    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = local_cid;
    cfg.remote_cid = remote_cid;
    cfg.direction = Direction::Inbound;
    cfg.alpn = "test";

    auto conn = std::make_shared<Connection>(std::move(cfg));

    // 模拟收到 Initial 后进入 Handshake 状态
    {
        // 使用 1-RTT 包触发 Established (简化流程)
        conn->on_handshake_completed();
        if (conn->state() == ConnState::Established) {
            PASS("on_handshake_completed 后进入 Established");
        } else {
            FAIL("on_handshake_completed 后应为 Established");
        }
    }

    // 测试 close
    conn->close(0, "test close");
    if (conn->state() == ConnState::Closed) {
        PASS("close() 后进入 Closed");
    } else {
        FAIL("close() 后应为 Closed");
    }

    if (conn->is_closed()) {
        PASS("is_closed() 返回 true");
    } else {
        FAIL("is_closed() 应返回 true");
    }
}

// ============================================================================
// 测试 3: Stream 打开与接受
// ============================================================================
void test_stream_operations() {
    std::cout << "\n=== 测试 3: Stream 打开与接受 ===" << std::endl;

    SecretKey sk = SecretKey::generate();
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = ConnectionId::generate();
    cfg.remote_cid = ConnectionId::generate();
    cfg.direction = Direction::Outbound;
    cfg.alpn = "test";

    auto conn = std::make_shared<Connection>(std::move(cfg));

    // 打开两个流
    auto s1 = conn->open_stream();
    if (s1 && s1->id() == 0) {
        PASS("第一个打开的流 ID 为 0");
    } else {
        FAIL("第一个流的 ID 应为 0");
    }

    auto s2 = conn->open_stream();
    if (s2 && s2->id() == 1) {
        // 简单递增: 0, 1, 2, ...
        PASS("第二个 BIDIRECTIONAL 流 ID 为 1");
    } else {
        FAIL("第二个流的 ID 应为 1");
    }

    // 发送数据
    uint8_t test_data[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    conn->send_stream(s1->id(), test_data);

    // 确认流中数据已写入
    // P1-P3 fix(2026-07-20): 用 send_readable_size() 替代 send_buffer().size()
    if (s1->send_readable_size() == 5) {
        PASS("send_stream 将数据写入流的发送缓冲区");
    } else {
        FAIL("发送缓冲区大小应为 5");
    }

    // finish_send
    conn->finish_stream(s1->id());
    if (s1->send_finished()) {
        PASS("finish_stream 设置 send_finished 标志");
    } else {
        FAIL("send_finished 应为 true");
    }

    // accept_stream 应返回 null (没有远程流)
    auto accepted = conn->accept_stream();
    if (!accepted) {
        PASS("accept_stream 在没有待接受流时返回 nullptr");
    } else {
        FAIL("没有待接受流时应返回 nullptr");
    }
}

// ============================================================================
// 测试 4: 1-RTT 包构建
// ============================================================================
void test_1rtt_packet_build() {
    std::cout << "\n=== 测试 4: 1-RTT 包构建 ===" << std::endl;

    SecretKey sk = SecretKey::generate();
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = ConnectionId::generate();
    cfg.remote_cid = ConnectionId::generate();
    cfg.direction = Direction::Outbound;
    cfg.alpn = "test";

    auto conn = std::make_shared<Connection>(std::move(cfg));
    conn->on_handshake_completed(); // 进入 Established

    // 打开一个流并写入数据
    auto s = conn->open_stream();
    uint8_t msg[] = "Hello QUIC!";
    conn->send_stream(s->id(), msg);

    // 构建 1-RTT 包
    std::vector<uint8_t> out(2048);
    std::size_t len = conn->build_1rtt_packet(out);

    if (len > 0) {
        PASS("build_1rtt_packet 返回非零长度");
    } else {
        FAIL("build_1rtt_packet 应返回非零长度");
    }

    if (out[0] == 0x40 || (out[0] & 0x80) == 0) {
        // Short Header 第一个字节 bit 7 = 0
        PASS("输出以 Short Header 开始 (bit 7 = 0)");
    } else {
        FAIL("输出应以 Short Header 开始");
    }

    ConnectionStats stats = conn->stats();
    if (stats.packets_sent > 0) {
        PASS("packets_sent 统计已更新");
    } else {
        FAIL("packets_sent 应 > 0");
    }

    if (stats.bytes_sent > 0) {
        PASS("bytes_sent 统计已更新");
    } else {
        FAIL("bytes_sent 应 > 0");
    }
}

// ============================================================================
// 测试 5: RTT 更新
// ============================================================================
void test_rtt_update() {
    std::cout << "\n=== 测试 5: RTT 更新 ===" << std::endl;

    SecretKey sk = SecretKey::generate();
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = ConnectionId::generate();
    cfg.remote_cid = ConnectionId::generate();
    cfg.direction = Direction::Outbound;
    cfg.alpn = "test";

    auto conn = std::make_shared<Connection>(std::move(cfg));

    // 第一次更新
    conn->update_rtt(100.0);
    auto stats1 = conn->stats();
    if (stats1.rtt_ema_ms == 100.0) {
        PASS("第一次 RTT 更新后为 100.0");
    } else {
        FAIL("第一次 RTT 应为 100.0");
    }

    // 第二次更新 (EMA: 0.875 * 100 + 0.125 * 200 = 112.5)
    conn->update_rtt(200.0);
    auto stats2 = conn->stats();
    if (stats2.rtt_ema_ms > 100.0 && stats2.rtt_ema_ms < 200.0) {
        PASS("EMA RTT 在 100~200 之间");
    } else {
        FAIL("EMA RTT 应在 100~200 之间");
    }
}

// ============================================================================
// 测试 6: 回调函数注册
// ============================================================================
void test_callbacks() {
    std::cout << "\n=== 测试 6: 回调函数注册 ===" << std::endl;

    SecretKey sk = SecretKey::generate();
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = ConnectionId::generate();
    cfg.remote_cid = ConnectionId::generate();
    cfg.direction = Direction::Outbound;
    cfg.alpn = "test";

    auto conn = std::make_shared<Connection>(std::move(cfg));

    bool stream_called = false;
    bool close_called = false;

    conn->on_stream([&](std::shared_ptr<Stream> s) {
        stream_called = true;
        (void)s;
    });

    conn->on_close([&]() {
        close_called = true;
    });

    // 触发 close 回调
    conn->close();
    if (close_called) {
        PASS("on_close 回调被触发");
    } else {
        FAIL("on_close 回调应被触发");
    }
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::cout << "=====================================================" << std::endl;
    std::cout << "  linoh Connection/Endpoint 集成测试" << std::endl;
    std::cout << "=====================================================" << std::endl;

    // Winsock 初始化
    WSADATA wsa{};
    int ret = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (ret != 0) {
        std::cout << "[错误] WSAStartup 失败: " << ret << std::endl;
        return 1;
    }

    test_connection_creation();
    test_connection_state_transitions();
    test_stream_operations();
    test_1rtt_packet_build();
    test_rtt_update();
    test_callbacks();

    WSACleanup();

    std::cout << "\n=====================================================" << std::endl;
    std::cout << "  测试结果: " << g_pass << " 通过, " << g_fail << " 失败" << std::endl;
    std::cout << "=====================================================" << std::endl;

    return g_fail > 0 ? 1 : 0;
}
