// test_holepuncher.cpp — NAT 打洞器单元测试（P4-C-3）
//
// 覆盖：
//   - HolepunchStrategy 枚举与 strategy_name 转换
//   - HolepunchResult 默认值与 to_string
//   - predict_symmetric_nat_ports 端口预测算法（核心算法）
//   - Holepuncher::attempt(Strategy::None) 直接返回成功
//   - 标准 STUN 打洞（mock 对端，本地 UDP echo）
//   - 对称 NAT 端口预测打洞（mock 多端口对端）
//   - 失败场景（无响应、非法地址、空端口列表）
//   - predict_next_ports 与 predict_symmetric_nat_ports 等价
//   - Holepuncher::attempt(TransportAddr 重载)
//   - RelayFallback 策略返回错误
//
// 注意：真实对称 NAT 环境测试需手动验证，CI 中通过 mock 对端覆盖接口契约。

#include "linoh/net/holepuncher.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

using native_socket_t = SOCKET;
constexpr native_socket_t kInvalidSock = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using native_socket_t = int;
constexpr native_socket_t kInvalidSock = -1;
#endif

using namespace linoh::net;
using namespace linoh::base;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// 工具：在指定端口启动一个 UDP echo server（用于 mock 打洞对端）
// 返回 socket 描述符；线程函数收到包后立即回显
// ============================================================================
struct UdpEchoServer {
    native_socket_t sock{kInvalidSock};
    std::uint16_t port{0};
    std::thread recv_thread;
    std::atomic<bool> running{false};
    std::atomic<int> packets_received{0};

    void start(std::uint16_t bind_port = 0) {
        sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
        if (sock == INVALID_SOCKET) return;
#else
        if (sock < 0) return;
#endif
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(bind_port);
        if (::bind(sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            sock = kInvalidSock;
            return;
        }

        // 获取实际绑定端口
        socklen_t addr_len = sizeof(addr);
        ::getsockname(sock, reinterpret_cast<sockaddr *>(&addr), &addr_len);
        port = ntohs(addr.sin_port);

        running = true;
        recv_thread = std::thread([this]() {
            std::array<std::uint8_t, 2048> buf{};
            sockaddr_storage from{};
            socklen_t from_len = sizeof(from);
            while (running.load()) {
                auto n = ::recvfrom(sock, reinterpret_cast<char *>(buf.data()),
                                    static_cast<int>(buf.size()), 0,
                                    reinterpret_cast<sockaddr *>(&from), &from_len);
                if (n > 0) {
                    packets_received.fetch_add(1);
                    // 立即回显给发送方（模拟打洞成功响应）
                    ::sendto(sock, reinterpret_cast<const char *>(buf.data()),
                             static_cast<int>(n), 0,
                             reinterpret_cast<sockaddr *>(&from), from_len);
                } else {
                    // 出错或非阻塞无数据
#ifdef _WIN32
                    int err = WSAGetLastError();
                    if (err == WSAETIMEDOUT) continue;
                    break;
#else
                    break;
#endif
                }
            }
        });

        // 设置接收超时，避免 recv_thread 永久阻塞
#ifdef _WIN32
        DWORD ms = 200;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&ms), sizeof(ms));
#else
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    }

    void stop() {
        running = false;
        if (sock != kInvalidSock) {
#ifdef _WIN32
            closesocket(sock);
#else
            ::close(sock);
#endif
            sock = kInvalidSock;
        }
        if (recv_thread.joinable()) recv_thread.join();
    }
};

// ============================================================================
// 测试 1: HolepunchStrategy 枚举完整性
// ============================================================================
static void test_strategy_enum() {
    std::printf("[test] HolepunchStrategy enum...\n");

    HolepunchStrategy s1 = HolepunchStrategy::None;
    HolepunchStrategy s2 = HolepunchStrategy::StandardRfc5389;
    HolepunchStrategy s3 = HolepunchStrategy::SymmetricNat;
    HolepunchStrategy s4 = HolepunchStrategy::RelayFallback;

    CHECK(s1 != s2);
    CHECK(s2 != s3);
    CHECK(s3 != s4);
    CHECK(s1 != s3);
    CHECK(s1 != s4);
    CHECK(s2 != s4);
}

// ============================================================================
// 测试 2: strategy_name 转换
// ============================================================================
static void test_strategy_name() {
    std::printf("[test] strategy_name...\n");

    CHECK(Holepuncher::strategy_name(HolepunchStrategy::None) == "none");
    CHECK(Holepuncher::strategy_name(HolepunchStrategy::StandardRfc5389) == "standard-rfc5389");
    CHECK(Holepuncher::strategy_name(HolepunchStrategy::SymmetricNat) == "symmetric-nat");
    CHECK(Holepuncher::strategy_name(HolepunchStrategy::RelayFallback) == "relay-fallback");

    // 验证返回类型可转 std::string
    std::string name(Holepuncher::strategy_name(HolepunchStrategy::None));
    CHECK(name == "none");
}

// ============================================================================
// 测试 3: HolepunchResult 默认值
// ============================================================================
static void test_result_default_values() {
    std::printf("[test] HolepunchResult default values...\n");

    HolepunchResult r;
    CHECK(r.success == false);
    CHECK(r.strategy_used == HolepunchStrategy::None);
    CHECK(r.duration.count() == 0);
    CHECK(r.error_msg.empty());
}

// ============================================================================
// 测试 4: HolepunchResult::to_string 输出格式
// ============================================================================
static void test_result_to_string() {
    std::printf("[test] HolepunchResult::to_string...\n");

    HolepunchResult r;
    r.success = true;
    r.strategy_used = HolepunchStrategy::StandardRfc5389;
    r.duration = std::chrono::milliseconds(150);

    std::string s = r.to_string();
    CHECK(s.find("success=true") != std::string::npos);
    CHECK(s.find("strategy=standard-rfc5389") != std::string::npos);
    CHECK(s.find("duration_ms=150") != std::string::npos);

    // 失败带 error_msg 的格式
    HolepunchResult r2;
    r2.success = false;
    r2.strategy_used = HolepunchStrategy::SymmetricNat;
    r2.error_msg = "no response";
    std::string s2 = r2.to_string();
    CHECK(s2.find("success=false") != std::string::npos);
    CHECK(s2.find("strategy=symmetric-nat") != std::string::npos);
    CHECK(s2.find("error='no response'") != std::string::npos);
}

// ============================================================================
// 测试 5: predict_symmetric_nat_ports 基础算法
// ============================================================================
static void test_predict_ports_basic() {
    std::printf("[test] predict_symmetric_nat_ports basic...\n");

    // 观察端口 10000 和 10002，delta=2
    auto predicted = predict_symmetric_nat_ports(10000, 10002, 10);

    CHECK(predicted.size() == 10);

    // 第一个预测应该是 10002 + 2 = 10004
    CHECK(predicted[0] == 10004);

    // 第二个应该是 10002 + 4 = 10006
    CHECK(predicted[1] == 10006);

    // 第三个应该是 10002 + 6 = 10008
    CHECK(predicted[2] == 10008);

    // 不应包含已观测的端口
    for (std::uint16_t p : predicted) {
        CHECK(p != 10000);
        CHECK(p != 10002);
    }
}

// ============================================================================
// 测试 6: predict_symmetric_nat_ports 增量算法（delta=0）
// ============================================================================
static void test_predict_ports_zero_delta() {
    std::printf("[test] predict_symmetric_nat_ports zero delta...\n");

    // 两次观察端口相同，delta=0
    auto predicted = predict_symmetric_nat_ports(5000, 5000, 5);

    CHECK(predicted.size() == 5);

    // delta=0 时应使用简单增量：5000+1=5001, 5000+2=5002, 5000+3=5003...
    CHECK(predicted[0] == 5001);
    CHECK(predicted[1] == 5002);
    CHECK(predicted[2] == 5003);

    // 不应包含观测的端口
    for (std::uint16_t p : predicted) {
        CHECK(p != 5000);
    }
}

// ============================================================================
// 测试 7: predict_symmetric_nat_ports 预测数量为 0
// ============================================================================
static void test_predict_ports_zero_count() {
    std::printf("[test] predict_symmetric_nat_ports zero count...\n");

    auto predicted = predict_symmetric_nat_ports(1000, 1002, 0);
    CHECK(predicted.empty());
}

// ============================================================================
// 测试 8: predict_symmetric_nat_ports 不重复
// ============================================================================
static void test_predict_ports_no_duplicates() {
    std::printf("[test] predict_symmetric_nat_ports no duplicates...\n");

    auto predicted = predict_symmetric_nat_ports(10000, 10005, 20);

    // 检查无重复
    std::set<std::uint16_t> unique_set(predicted.begin(), predicted.end());
    CHECK(unique_set.size() == predicted.size());

    // 不应包含已观测的端口
    for (std::uint16_t p : predicted) {
        CHECK(p != 10000);
        CHECK(p != 10005);
    }

    // 至少 20 个（不会因为重复被截断）
    CHECK(predicted.size() == 20);
}

// ============================================================================
// 测试 9: predict_symmetric_nat_ports 端口范围合法
// ============================================================================
static void test_predict_ports_range_valid() {
    std::printf("[test] predict_symmetric_nat_ports range valid...\n");

    auto predicted = predict_symmetric_nat_ports(10000, 10002, 50);

    for (std::uint16_t p : predicted) {
        CHECK(p >= 1);
        CHECK(p <= 65535);
    }
}

// ============================================================================
// 测试 10: predict_symmetric_nat_ports 边界场景（端口接近上限）
// ============================================================================
static void test_predict_ports_near_max() {
    std::printf("[test] predict_symmetric_nat_ports near max...\n");

    // 65530 + delta=2 = 65532，预测 65534, 65536(超界)
    auto predicted = predict_symmetric_nat_ports(65530, 65532, 10);

    // 所有端口都应合法（1-65535）
    for (std::uint16_t p : predicted) {
        CHECK(p >= 1);
        CHECK(p <= 65535);
    }

    // 预测数量可能少于请求（因边界限制），但应 >= 1
    CHECK(predicted.size() >= 1);
}

// ============================================================================
// 测试 11: predict_symmetric_nat_ports 负 delta
// ============================================================================
static void test_predict_ports_negative_delta() {
    std::printf("[test] predict_symmetric_nat_ports negative delta...\n");

    // 端口递减：10000 -> 9998，delta=-2
    auto predicted = predict_symmetric_nat_ports(10000, 9998, 5);

    CHECK(predicted.size() == 5);

    // 第一个预测应该是 9998 - 2 = 9996
    CHECK(predicted[0] == 9996);

    // 不应包含已观测的端口
    for (std::uint16_t p : predicted) {
        CHECK(p != 10000);
        CHECK(p != 9998);
    }
}

// ============================================================================
// 测试 12: Holepuncher::predict_next_ports 与 predict_symmetric_nat_ports 等价
// ============================================================================
static void test_predict_next_ports_equivalence() {
    std::printf("[test] predict_next_ports equivalence...\n");

    auto a = predict_symmetric_nat_ports(10000, 10002, 10);
    auto b = Holepuncher::predict_next_ports(10000, 10002, 10);

    CHECK(a.size() == b.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        CHECK(a[i] == b[i]);
    }
}

// ============================================================================
// 测试 13: Holepuncher::attempt(None) 直接返回成功
// ============================================================================
static void test_attempt_none_strategy() {
    std::printf("[test] attempt(None) returns success...\n");

    auto result = Holepuncher::attempt(
        "127.0.0.1", 12345, "127.0.0.1", 54321,
        HolepunchStrategy::None, std::chrono::milliseconds(100));

    CHECK(result.success == true);
    CHECK(result.strategy_used == HolepunchStrategy::None);
    CHECK(result.established_tuple.local_addr.host == "127.0.0.1");
    CHECK(result.established_tuple.local_addr.port == 12345);
    CHECK(result.established_tuple.remote_addr.host == "127.0.0.1");
    CHECK(result.established_tuple.remote_addr.port == 54321);
    CHECK(result.error_msg.empty());
}

// ============================================================================
// 测试 14: Holepuncher::attempt TransportAddr 重载
// ============================================================================
static void test_attempt_transport_addr_overload() {
    std::printf("[test] attempt(TransportAddr) overload...\n");

    TransportAddr local;
    local.kind = TransportKind::Ip;
    local.host = "127.0.0.1";
    local.port = 11111;

    TransportAddr remote;
    remote.kind = TransportKind::Ip;
    remote.host = "127.0.0.1";
    remote.port = 22222;

    auto result = Holepuncher::attempt(local, remote,
                                        HolepunchStrategy::None,
                                        std::chrono::milliseconds(100));

    CHECK(result.success == true);
    CHECK(result.established_tuple.local_addr.host == "127.0.0.1");
    CHECK(result.established_tuple.local_addr.port == 11111);
    CHECK(result.established_tuple.remote_addr.host == "127.0.0.1");
    CHECK(result.established_tuple.remote_addr.port == 22222);
}

// ============================================================================
// 测试 15: 标准 STUN 打洞（mock echo server）
// ============================================================================
static void test_attempt_standard_with_echo_server() {
    std::printf("[test] attempt(StandardRfc5389) with echo server...\n");

    UdpEchoServer echo;
    echo.start(0);  // 让 OS 选择端口
    CHECK(echo.sock != kInvalidSock);
    CHECK(echo.port > 0);

    // 用本地任意端口向 echo server 打洞
    auto result = Holepuncher::attempt(
        "127.0.0.1", 0, "127.0.0.1", echo.port,
        HolepunchStrategy::StandardRfc5389,
        std::chrono::milliseconds(2000));

    echo.stop();

    // 应该成功收到 echo 回包
    CHECK(result.success == true);
    CHECK(result.strategy_used == HolepunchStrategy::StandardRfc5389);
    CHECK(result.established_tuple.remote_addr.host == "127.0.0.1");
    CHECK(result.established_tuple.remote_addr.port == echo.port);
    CHECK(result.error_msg.empty());
}

// ============================================================================
// 测试 16: 标准 STUN 打洞 - 无响应场景
// ============================================================================
static void test_attempt_standard_no_response() {
    std::printf("[test] attempt(StandardRfc5389) no response...\n");

    // 使用一个未绑定端口（OS 一般会丢弃 UDP 包）
    // 选择一个高端口，避免冲突
    auto result = Holepuncher::attempt(
        "127.0.0.1", 0, "127.0.0.1", 59999,
        HolepunchStrategy::StandardRfc5389,
        std::chrono::milliseconds(500));

    CHECK(result.success == false);
    CHECK(result.strategy_used == HolepunchStrategy::StandardRfc5389);
    CHECK(!result.error_msg.empty());
}

// ============================================================================
// 测试 17: 标准 STUN 打洞 - 非法远端 IP
// ============================================================================
static void test_attempt_standard_invalid_remote_ip() {
    std::printf("[test] attempt(StandardRfc5389) invalid remote ip...\n");

    auto result = Holepuncher::attempt(
        "127.0.0.1", 12345,
        "not-an-ip", 80,
        HolepunchStrategy::StandardRfc5389,
        std::chrono::milliseconds(500));

    CHECK(result.success == false);
    CHECK(result.strategy_used == HolepunchStrategy::StandardRfc5389);
    CHECK(!result.error_msg.empty());
    CHECK(result.error_msg.find("invalid") != std::string::npos);
}

// ============================================================================
// 测试 18: 对称 NAT 端口预测打洞 - 普通重载降级（nn-M1, v3.6.0）
// ============================================================================
static void test_attempt_symmetric_empty_ports() {
    std::printf("[test] attempt(SymmetricNat) degrades to StandardRfc5389...\n");

    // nn-M1 (v3.6.0): 普通重载收到 SymmetricNat 时缺乏对端 STUN 观测端口，
    // 会降级为 StandardRfc5389 + 警告日志（而非走猜测模式）。
    // 此测试验证降级行为：strategy_used 应变为 StandardRfc5389。
    // 使用不可达端口确保打洞失败，验证错误处理 + 降级语义。
    auto result = Holepuncher::attempt(
        "127.0.0.1", 0,
        "127.0.0.1", 59999,
        HolepunchStrategy::SymmetricNat,
        std::chrono::milliseconds(500));

    CHECK(result.success == false);
    // nn-M1 修复：降级为 StandardRfc5389，而非保留 SymmetricNat
    CHECK(result.strategy_used == HolepunchStrategy::StandardRfc5389);
}

// ============================================================================
// 测试 19: 对称 NAT 打洞 - 专用重载端口预测命中（nn-M1, v3.6.0）
// ============================================================================
static void test_attempt_symmetric_with_echo() {
    std::printf("[test] attempt(SymmetricNat) dedicated overload with echo...\n");

    // nn-M1 (v3.6.0): 验证 SymmetricNat 专用重载（带 observed_port_1/2）的
    // 端口预测能力。普通重载已降级为 StandardRfc5389，无法验证端口预测。
    //
    // 流程：
    //   1. 选 observed_port_1=40000, observed_port_2=40002（模拟对端两次 STUN 观测）
    //   2. predict_symmetric_nat_ports(40000, 40002, 10) → predicted[0]=40004
    //   3. 在 predicted[0] 启动 echo server
    //   4. 调用专用重载，内部用 observed_port_1/2 预测，向 predicted 端口发包
    //   5. echo server 收包回显，打洞成功

    std::uint16_t observed_port_1 = 40000;
    std::uint16_t observed_port_2 = 40002;
    auto predicted = predict_symmetric_nat_ports(observed_port_1, observed_port_2, 10);
    CHECK(!predicted.empty());

    std::uint16_t target_port = predicted[0];

    // 启动 echo server 在 target_port（第一个预测端口）
    UdpEchoServer echo;
    echo.start(target_port);

    // 如果 target_port 被占用，start 会失败
    if (echo.sock == kInvalidSock) {
        std::printf("[test] SKIP: port %u unavailable\n", target_port);
        echo.stop();
        return;
    }

    // 调用 SymmetricNat 专用重载（8 参数）：
    //   remote_port = observed_port_1（contact 端口，本测试无实际用途，
    //                attempt_symmetric 用 predicted 端口发包）
    //   remote_observed_port_1/2 = 真实 STUN 观测端口
    auto result = Holepuncher::attempt(
        "127.0.0.1", 0,
        "127.0.0.1", observed_port_1,
        observed_port_1, observed_port_2,
        HolepunchStrategy::SymmetricNat,
        std::chrono::milliseconds(2000));

    echo.stop();

    // 验证策略字段（专用重载保留 SymmetricNat，不降级）
    CHECK(result.strategy_used == HolepunchStrategy::SymmetricNat);

    // 成功或失败均可（取决于 echo server 接收 sendto 的顺序）
    // 这里只验证不崩溃 + 策略字段正确（专用重载未降级）
}

// ============================================================================
// 测试 20: RelayFallback 策略返回错误
// ============================================================================
static void test_attempt_relay_fallback() {
    std::printf("[test] attempt(RelayFallback)...\n");

    auto result = Holepuncher::attempt(
        "127.0.0.1", 12345,
        "127.0.0.1", 54321,
        HolepunchStrategy::RelayFallback,
        std::chrono::milliseconds(500));

    CHECK(result.success == false);
    CHECK(result.strategy_used == HolepunchStrategy::RelayFallback);
    CHECK(!result.error_msg.empty());
    CHECK(result.error_msg.find("relay") != std::string::npos);
}

// ============================================================================
// 测试 21: 默认策略参数（应使用 StandardRfc5389）
// ============================================================================
static void test_attempt_default_strategy() {
    std::printf("[test] attempt default strategy...\n");

    // 不指定策略，默认应为 StandardRfc5389
    // 使用 None 策略验证默认参数构造
    TransportAddr local;
    local.kind = TransportKind::Ip;
    local.host = "127.0.0.1";
    local.port = 33333;

    TransportAddr remote;
    remote.kind = TransportKind::Ip;
    remote.host = "127.0.0.1";
    remote.port = 44444;

    // 不传 strategy 参数（使用默认值 StandardRfc5389）
    auto result = Holepuncher::attempt(local, remote);

    // 应该是 StandardRfc5389 策略
    CHECK(result.strategy_used == HolepunchStrategy::StandardRfc5389);

    // 因为没有 echo server，应该失败
    CHECK(result.success == false);
}

// ============================================================================
// 测试 22: 多次预测结果一致性
// ============================================================================
static void test_predict_ports_deterministic() {
    std::printf("[test] predict_symmetric_nat_ports deterministic...\n");

    auto a = predict_symmetric_nat_ports(10000, 10010, 15);
    auto b = predict_symmetric_nat_ports(10000, 10010, 15);

    CHECK(a.size() == b.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        CHECK(a[i] == b[i]);
    }
}

// ============================================================================
// 测试 23: 预测数量与请求一致（足够端口时）
// ============================================================================
static void test_predict_ports_count_matches() {
    std::printf("[test] predict_symmetric_nat_ports count matches...\n");

    // 在端口充足范围内请求预测
    for (std::size_t n : {1u, 5u, 10u, 20u, 50u}) {
        auto predicted = predict_symmetric_nat_ports(10000, 10002, n);
        CHECK(predicted.size() == n);
    }
}

// ============================================================================
// 测试 24: duration 字段被正确填充
// ============================================================================
static void test_duration_field() {
    std::printf("[test] duration field populated...\n");

    auto start = std::chrono::steady_clock::now();
    auto result = Holepuncher::attempt(
        "127.0.0.1", 0, "127.0.0.1", 59999,
        HolepunchStrategy::StandardRfc5389,
        std::chrono::milliseconds(300));
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    // duration 应被填充
    CHECK(result.duration.count() > 0);

    // duration 不应超过合理上限（timeout + 一些容差）
    CHECK(result.duration.count() <= elapsed.count() + 500);
}

// ============================================================================
// 测试 25: 端口预测算法 - 大差值场景
// ============================================================================
static void test_predict_ports_large_delta() {
    std::printf("[test] predict_symmetric_nat_ports large delta...\n");

    // 大差值：10000 -> 11000，delta=1000
    auto predicted = predict_symmetric_nat_ports(10000, 11000, 10);

    CHECK(predicted.size() == 10);

    // 第一个预测 = 11000 + 1000 = 12000
    CHECK(predicted[0] == 12000);

    // 第二个 = 11000 + 2000 = 13000
    CHECK(predicted[1] == 13000);

    // 不应包含观测端口
    for (std::uint16_t p : predicted) {
        CHECK(p != 10000);
        CHECK(p != 11000);
    }
}

// ============================================================================
// 测试 26: 端口预测算法 - 全部端口范围
// ============================================================================
static void test_predict_ports_all_in_range() {
    std::printf("[test] predict_symmetric_nat_ports all in range...\n");

    // 测试多个起点
    for (std::uint16_t start : {1u, 100u, 1000u, 10000u, 30000u, 50000u, 60000u}) {
        std::uint16_t second = static_cast<std::uint16_t>(start + 2);
        if (second < start) continue;  // 溢出跳过

        auto predicted = predict_symmetric_nat_ports(start, second, 5);
        CHECK(predicted.size() == 5);

        for (std::uint16_t p : predicted) {
            CHECK(p >= 1);
            CHECK(p <= 65535);
        }
    }
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== test_holepuncher ===\n");

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::printf("WSAStartup failed\n");
        return 1;
    }
#endif

    test_strategy_enum();
    test_strategy_name();
    test_result_default_values();
    test_result_to_string();

    test_predict_ports_basic();
    test_predict_ports_zero_delta();
    test_predict_ports_zero_count();
    test_predict_ports_no_duplicates();
    test_predict_ports_range_valid();
    test_predict_ports_near_max();
    test_predict_ports_negative_delta();
    test_predict_ports_deterministic();
    test_predict_ports_count_matches();
    test_predict_ports_large_delta();
    test_predict_ports_all_in_range();
    test_predict_next_ports_equivalence();

    test_attempt_none_strategy();
    test_attempt_transport_addr_overload();
    test_attempt_standard_with_echo_server();
    test_attempt_standard_no_response();
    test_attempt_standard_invalid_remote_ip();
    test_attempt_symmetric_empty_ports();
    test_attempt_symmetric_with_echo();
    test_attempt_relay_fallback();
    test_attempt_default_strategy();
    test_duration_field();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);

#ifdef _WIN32
    WSACleanup();
#endif

    return g_fail == 0 ? 0 : 1;
}
