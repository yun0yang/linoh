/// linoh_echo_node.cpp — Linux 兼容的 patchbay echo 节点（T-LP2-003）
///
/// 基于 linoh C API 实现，支持 server 和 client 两种模式，
/// 用于 patchbay NAT 穿透测试矩阵验证连接和数据传输。
///
/// 用法:
///   server 模式: linoh_echo_node --port 9100 --role server --log server.log
///   client 模式: linoh_echo_node --port 9100 --role client --log client.log \
///                --remote-ip 10.99.0.2 --remote-port 9100
///   网络监听:   linoh_echo_node ... --monitor-network（client 模式默认启用）
///
/// 日志标记（供 patchbay 脚本 grep）:
///   LISTENING   — server 已绑定端口，等待连接
///   CONNECTED   — client 已建立连接
///   ECHO_OK     — echo 数据传输验证通过
///   ECHO_FAIL   — echo 数据传输验证失败
///   endpoint_id=<hex> — 本节点 EndpointId（32 字节 hex 编码）
///   network_change detected: old=X new=Y — IP 变化检测（K-LP-002 修复）

#include "linoh/linoh_c.h"

// K-LP-001: relay 模式使用 C++ 协议头（stride/ws_client/auth 都是 header-only inline）
#include "linoh/relay/stride.hpp"
#include "linoh/relay/ws_client.hpp"
#include "linoh/relay/auth.hpp"
#include "linoh/base/key.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <unistd.h>
// K-LP-002: 网络接口监听（getifaddrs 轮询检测 IP 变化）
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
// K-LP-001: relay 模式原生 socket I/O
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>

static std::atomic<bool> g_running{true};

// K-LP-002: 网络变化检测相关全局状态
// g_need_reconnect 由监听线程设置，主线程（continuous 循环）检测后执行重连
static std::atomic<bool> g_need_reconnect{false};
static std::atomic<bool> g_monitor_enabled{false};  // 控制回调行为
static std::mutex g_ip_change_mu;
static std::string g_old_ip_summary;
static std::string g_new_ip_summary;

static void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

// ============================================================================
// K-LP-002: 网络接口监听线程（getifaddrs 轮询检测 IP 变化）
// ============================================================================
//
// patchbay S4 场景通过 `ip netns exec <ns> ip addr del/add` 改变命名空间内
// 接口的 IP。linoh C-API 的 endpoint 是独立实现（不包装 C++ Endpoint），
// 没有内置 RouteMonitor，因此 echo_node 需要自行轮询本地 IP 变化。
//
// 检测策略：
//   - 每 500ms 调用 getifaddrs 枚举所有非环回 IPv4 地址
//   - 将地址集排序后拼接为签名字符串，与上次比较
//   - 签名变化时设置 g_need_reconnect=true，输出 network_change 标记
//
// 主线程（continuous 循环）检测到 g_need_reconnect 后执行重连：
//   关闭旧连接 → 重新 connect → 等待 Established → 继续 echo

/// 收集所有非环回 IPv4 地址，排序后拼接为签名字符串
static std::string collect_local_ip_signature() {
    struct ifaddrs *ifap = nullptr;
    std::string sig;
    if (getifaddrs(&ifap) != 0) return sig;
    std::vector<std::string> addrs;
    for (struct ifaddrs *p = ifap; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (p->ifa_flags & IFF_LOOPBACK) continue;
        if (!(p->ifa_flags & IFF_UP)) continue;
        auto *sin = reinterpret_cast<struct sockaddr_in*>(p->ifa_addr);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        addrs.push_back(std::string(p->ifa_name) + "=" + buf);
    }
    freeifaddrs(ifap);
    std::sort(addrs.begin(), addrs.end());
    for (size_t i = 0; i < addrs.size(); ++i) {
        if (i > 0) sig += ",";
        sig += addrs[i];
    }
    return sig;
}

/// 网络监听线程函数：轮询本地 IP，变化时设置 g_need_reconnect
static void network_monitor_loop() {
    std::string last_sig = collect_local_ip_signature();
    printf("[NET-MONITOR] 监听线程启动, 初始 IP: %s\n",
           last_sig.empty() ? "(none)" : last_sig.c_str());
    fflush(stdout);

    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (!g_running.load()) break;

        std::string cur_sig = collect_local_ip_signature();
        if (cur_sig != last_sig) {
            // IP 变化检测到
            {
                std::lock_guard<std::mutex> lk(g_ip_change_mu);
                g_old_ip_summary = last_sig;
                g_new_ip_summary = cur_sig;
            }
            // 输出标记（S4 脚本 grep "network_change"）
            printf("network_change detected: old=[%s] new=[%s]\n",
                   last_sig.c_str(), cur_sig.c_str());
            fflush(stdout);
            g_need_reconnect.store(true);
            last_sig = cur_sig;
        }
    }
    printf("[NET-MONITOR] 监听线程退出\n");
    fflush(stdout);
}

/// 将 32 字节公钥编码为 64 字符 hex 字符串
static std::string to_hex(const uint8_t *data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(hex[(data[i] >> 4) & 0xF]);
        result.push_back(hex[data[i] & 0xF]);
    }
    return result;
}

/// 简单命令行参数解析
struct Args {
    uint16_t port = 0;
    std::string role;
    std::string log_file;
    std::string remote_ip;
    uint16_t remote_port = 0;
    std::string mode = "single";        // single | continuous
    int interval_sec = 2;               // continuous 模式 echo 间隔
    bool monitor_network = true;        // K-LP-002: client 模式默认启用网络监听
    // K-LP-001: relay 模式参数
    std::string relay_addr;             // relay 服务器地址 (host:port)，非空时启用 relay 模式
    std::string relay_backup;           // 备用 relay 地址（S5 故障切换）
    std::string peer_endpoint_id;       // 对端 EndpointId（64 字符 hex，client relay 模式必填）
};

static Args parse_args(int argc, char *argv[]) {
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto next_val = [&]() -> std::string {
            if (i + 1 >= argc) {
                fprintf(stderr, "[ERROR] 缺少参数值: %s\n", argv[i]);
                exit(1);
            }
            return argv[++i];
        };
        if (arg == "--port") {
            args.port = static_cast<uint16_t>(std::atoi(next_val().c_str()));
        } else if (arg == "--role") {
            args.role = next_val();
        } else if (arg == "--log") {
            args.log_file = next_val();
        } else if (arg == "--remote-ip") {
            args.remote_ip = next_val();
        } else if (arg == "--remote-port") {
            args.remote_port = static_cast<uint16_t>(std::atoi(next_val().c_str()));
        } else if (arg == "--mode") {
            args.mode = next_val();
        } else if (arg == "--interval") {
            args.interval_sec = std::atoi(next_val().c_str());
        } else if (arg == "--monitor-network") {
            args.monitor_network = true;
        } else if (arg == "--no-monitor-network") {
            args.monitor_network = false;
        } else if (arg == "--relay-addr") {
            args.relay_addr = next_val();
        } else if (arg == "--relay-backup") {
            args.relay_backup = next_val();
        } else if (arg == "--peer-endpoint-id") {
            args.peer_endpoint_id = next_val();
        } else if (arg == "--help" || arg == "-h") {
            printf("用法: linoh_echo_node --port <port> --role <server|client> "
                   "--log <file> [--remote-ip <ip> --remote-port <port>] "
                   "[--mode single|continuous] [--interval N] "
                   "[--monitor-network|--no-monitor-network]\n"
                   "  relay 模式: --relay-addr <host:port> [--relay-backup <host:port>] "
                   "[--peer-endpoint-id <hex64>]（client relay 模式必填）\n");
            exit(0);
        } else {
            fprintf(stderr, "[WARN] 未知参数: %s\n", argv[i]);
        }
    }
    return args;
}

// ============================================================================
// Server 模式 — 单线程轮询 + 回调驱动
// ============================================================================

static int run_server(uint16_t port, const std::string &log_file) {
    // 重定向 stdout/stderr 到日志文件
    if (!log_file.empty()) {
        FILE *f = freopen(log_file.c_str(), "w", stdout);
        if (!f) {
            fprintf(stderr, "[ERROR] 无法打开日志文件: %s\n", log_file.c_str());
            return 1;
        }
        freopen(log_file.c_str(), "a", stderr);
    }

    printf("[BOOT] echo server 启动中... port=%u\n", port);
    fflush(stdout);

    // 生成密钥对
    linoh_secret_key_t sk;
    linoh_public_key_t pk;
    if (linoh_generate_keypair(&sk, &pk) != LINOH_OK) {
        fprintf(stderr, "[ERROR] 密钥生成失败\n");
        return 1;
    }

    // 创建 endpoint
    linoh_endpoint_config_t config;
    memset(&config, 0, sizeof(config));
    config.secret_key = sk;
    config.alpn = "echo/1";
    config.udp_port = port;
    config.user_data = nullptr;

    linoh_endpoint_t *ep = linoh_endpoint_create(&config);
    if (!ep) {
        fprintf(stderr, "[ERROR] endpoint 创建失败\n");
        return 1;
    }

    // 获取 endpoint_id
    const linoh_endpoint_id_t *eid = linoh_endpoint_id(ep);
    if (eid) {
        std::string eid_hex = to_hex(eid->bytes, LINOH_KEY_SIZE);
        printf("endpoint_id=%s\n", eid_hex.c_str());
        fflush(stdout);
    }

    uint16_t actual_port = linoh_endpoint_udp_port(ep);
    printf("[BOOT] endpoint 已创建, UDP port=%u\n", actual_port);
    printf("LISTENING\n");
    fflush(stdout);

    // 注册 on_connection 回调（使连接入队 accept 队列）
    linoh_endpoint_on_connection(ep, [](linoh_connection_t *conn, void *user_data) {
        printf("[ACCEPT] on_connection 回调触发\n");
        fflush(stdout);
    });

    // 注册 on_stream 回调（在回调中直接处理 echo）
    linoh_endpoint_on_stream(ep, [](linoh_stream_t *stream, void *user_data) {
        printf("[STREAM] on_stream 回调触发\n");
        fflush(stdout);

        // 读取数据
        uint8_t buf[4096];
        size_t n = linoh_stream_read(stream, buf, sizeof(buf));
        if (n > 0) {
            printf("[ECHO] 收到 %zu 字节，回显中...\n", n);
            fflush(stdout);
            linoh_stream_write(stream, buf, n);
            linoh_stream_finish(stream);
            printf("ECHO_OK\n");
            fflush(stdout);
        } else {
            printf("[WARN] stream 无数据 (n=%zu)\n", n);
            fflush(stdout);
        }
        linoh_stream_free(stream);
    });

    // 主循环：单线程 poll
    int echo_count = 0;

    while (g_running) {
        linoh_endpoint_poll(ep);

        // 接受新连接（回调已触发，accept 从队列获取）
        linoh_connection_t *conn = linoh_endpoint_accept(ep);
        if (conn) {
            printf("[ACCEPT] accept 返回连接\n");
            fflush(stdout);
            // 连接由 on_stream 回调处理，不需要手动管理
            // 但需要保留引用避免被释放
            // linoh_connection_retain(conn);  // 如需要可 retain
        }

        usleep(10000);  // 10ms 避免空转
    }

    printf("[BOOT] server 正在关闭... echo_count=%d\n", echo_count);
    linoh_endpoint_free(ep);
    return 0;
}

// ============================================================================
// Client 模式 — 单线程轮询，支持 single / continuous 两种模式
// ============================================================================

/// 执行单次 echo：开 stream → 发送 → 等回显 → 验证
/// 返回 0=成功, 1=失败
static int do_single_echo(linoh_endpoint_t *ep, linoh_connection_t *conn) {
    linoh_stream_t *stream = linoh_connection_open_stream(conn);
    if (!stream) {
        fprintf(stderr, "[ERROR] 无法打开 stream\n");
        return 1;
    }

    const char *test_msg = "Hello from patchbay echo client!";
    size_t msg_len = strlen(test_msg);
    size_t written = linoh_stream_write(stream,
                                         reinterpret_cast<const uint8_t *>(test_msg),
                                         msg_len);
    printf("[SEND] 发送 %zu/%zu 字节\n", written, msg_len);
    linoh_stream_finish(stream);
    fflush(stdout);

    uint8_t buf[4096];
    size_t read_total = 0;
    for (int i = 0; i < 200 && g_running; ++i) {  // 最多等 10 秒
        linoh_endpoint_poll(ep);
        if (linoh_stream_has_readable(stream)) {
            size_t n = linoh_stream_read(stream, buf + read_total,
                                          sizeof(buf) - read_total);
            if (n == 0) break;
            read_total += n;
            if (read_total >= written) break;
        }
        usleep(50000);  // 50ms
    }

    int ok = (read_total == msg_len && memcmp(buf, test_msg, msg_len) == 0);
    if (ok) {
        printf("[RECV] 收到回显 %zu 字节，验证通过\n", read_total);
        printf("ECHO_OK\n");
    } else {
        printf("[RECV] 回显验证失败: 期望 %zu 字节, 收到 %zu 字节\n",
               msg_len, read_total);
        printf("ECHO_FAIL\n");
    }
    fflush(stdout);

    linoh_stream_free(stream);
    return ok ? 0 : 1;
}

static int run_client(uint16_t port, const std::string &log_file,
                      const std::string &remote_ip, uint16_t remote_port,
                      const std::string &mode, int interval_sec,
                      bool monitor_network) {
    // 重定向 stdout/stderr 到日志文件
    if (!log_file.empty()) {
        FILE *f = freopen(log_file.c_str(), "w", stdout);
        if (!f) {
            fprintf(stderr, "[ERROR] 无法打开日志文件: %s\n", log_file.c_str());
            return 1;
        }
        freopen(log_file.c_str(), "a", stderr);
    }

    printf("[BOOT] echo client 启动中... port=%u mode=%s monitor=%s\n",
           port, mode.c_str(), monitor_network ? "enabled" : "disabled");
    printf("[BOOT] 目标: %s:%u\n", remote_ip.c_str(), remote_port);
    fflush(stdout);

    // 生成密钥对
    linoh_secret_key_t sk;
    linoh_public_key_t pk;
    if (linoh_generate_keypair(&sk, &pk) != LINOH_OK) {
        fprintf(stderr, "[ERROR] 密钥生成失败\n");
        return 1;
    }

    // 创建 endpoint
    linoh_endpoint_config_t config;
    memset(&config, 0, sizeof(config));
    config.secret_key = sk;
    config.alpn = "echo/1";
    config.udp_port = port;
    config.user_data = nullptr;

    linoh_endpoint_t *ep = linoh_endpoint_create(&config);
    if (!ep) {
        fprintf(stderr, "[ERROR] endpoint 创建失败\n");
        return 1;
    }

    // 注册连接状态变化回调（输出标记供 patchbay 场景脚本检测）
    // K-LP-002: monitor_network 启用时，CONN_CLOSED 触发重连而非退出
    g_monitor_enabled.store(monitor_network);
    linoh_endpoint_on_conn_state(ep, [](linoh_connection_t *conn,
                                         linoh_conn_state_t state, void *user_data) {
        printf("CONN_STATE_CHANGED state=%d\n", static_cast<int>(state));
        fflush(stdout);
        if (state == LINOH_CONN_CLOSED || state == LINOH_CONN_CLOSING) {
            if (g_monitor_enabled.load()) {
                // 监听启用时：标记需要重连（不退出）
                g_need_reconnect.store(true);
            } else {
                g_running = false;
            }
        }
    });

    // 获取 endpoint_id
    const linoh_endpoint_id_t *eid = linoh_endpoint_id(ep);
    if (eid) {
        std::string eid_hex = to_hex(eid->bytes, LINOH_KEY_SIZE);
        printf("endpoint_id=%s\n", eid_hex.c_str());
        fflush(stdout);
    }

    // K-LP-002: 启动网络监听线程（client 模式默认启用）
    std::thread monitor_thread;
    if (monitor_network) {
        monitor_thread = std::thread(network_monitor_loop);
        printf("[BOOT] 网络监听线程已启动\n");
        fflush(stdout);
    }

    printf("[BOOT] 正在连接到 %s:%u...\n", remote_ip.c_str(), remote_port);
    fflush(stdout);

    // 连接到 server
    linoh_connection_t *conn = linoh_endpoint_connect(ep, remote_ip.c_str(), remote_port);
    if (!conn) {
        fprintf(stderr, "[ERROR] 连接失败\n");
        g_running = false;
        if (monitor_thread.joinable()) monitor_thread.join();
        linoh_endpoint_free(ep);
        return 1;
    }

    // 等待连接建立
    bool connected = false;
    for (int i = 0; i < 200 && g_running; ++i) {  // 最多等 10 秒
        linoh_endpoint_poll(ep);
        linoh_conn_state_t state = linoh_connection_state(conn);
        if (state == LINOH_CONN_ESTABLISHED) {
            connected = true;
            break;
        }
        if (state == LINOH_CONN_CLOSED || state == LINOH_CONN_CLOSING) {
            fprintf(stderr, "[ERROR] 连接被关闭，状态=%d\n", state);
            linoh_connection_free(conn);
            g_running = false;
            if (monitor_thread.joinable()) monitor_thread.join();
            linoh_endpoint_free(ep);
            return 1;
        }
        usleep(50000);  // 50ms
    }

    if (!connected) {
        fprintf(stderr, "[ERROR] 连接超时，状态=%d\n", linoh_connection_state(conn));
        linoh_connection_free(conn);
        g_running = false;
        if (monitor_thread.joinable()) monitor_thread.join();
        linoh_endpoint_free(ep);
        return 1;
    }

    printf("CONNECTED\n");
    fflush(stdout);

    int result = 0;

    if (mode == "continuous") {
        // 持续 echo 模式：循环发送 echo，每次成功输出 ECHO_OK
        // 用于 S4/S6/S7 场景验证网络恢复后数据传输恢复
        int echo_count = 0;
        int fail_count = 0;
        while (g_running) {
            // K-LP-002: 检测网络变化，执行重连
            if (monitor_network && g_need_reconnect.exchange(false)) {
                printf("[RECONNECT] 检测到网络变化，正在重连...\n");
                fflush(stdout);
                // 关闭旧连接
                linoh_connection_free(conn);
                conn = nullptr;
                // 等待 500ms 让 socket 稳定
                usleep(500000);
                // 重新连接
                conn = linoh_endpoint_connect(ep, remote_ip.c_str(), remote_port);
                if (!conn) {
                    fprintf(stderr, "[RECONNECT] 重连失败: connect 返回 NULL\n");
                    fflush(stderr);
                    break;
                }
                // 等待连接建立
                bool reconnected = false;
                for (int i = 0; i < 200 && g_running; ++i) {  // 最多等 10 秒
                    linoh_endpoint_poll(ep);
                    linoh_conn_state_t state = linoh_connection_state(conn);
                    if (state == LINOH_CONN_ESTABLISHED) {
                        reconnected = true;
                        break;
                    }
                    if (state == LINOH_CONN_CLOSED || state == LINOH_CONN_CLOSING) {
                        break;
                    }
                    usleep(50000);  // 50ms
                }
                if (reconnected) {
                    printf("[RECONNECT] 重连成功，继续 echo\n");
                    fflush(stdout);
                    // 清除重连过程中可能由回调副作用产生的 spurious 标记
                    g_need_reconnect.store(false);
                } else {
                    fprintf(stderr, "[RECONNECT] 重连失败或超时，退出\n");
                    fflush(stderr);
                    linoh_connection_free(conn);
                    conn = nullptr;
                    break;
                }
            }

            int ret = do_single_echo(ep, conn);
            if (ret == 0) {
                echo_count++;
                printf("ECHO_OK count=%d fails=%d\n", echo_count, fail_count);
                fflush(stdout);
            } else {
                fail_count++;
                printf("ECHO_FAIL count=%d fails=%d\n", echo_count, fail_count);
                fflush(stdout);
                // 连接可能已断开
                if (!g_running) break;
                // K-LP-002: 失败时也触发重连尝试
                if (monitor_network) {
                    g_need_reconnect.store(true);
                }
            }

            // 等待间隔（可被打断）
            for (int i = 0; i < interval_sec * 100 && g_running; ++i) {
                linoh_endpoint_poll(ep);
                // K-LP-002: 间隔中检测重连需求，快速响应
                if (monitor_network && g_need_reconnect.load()) break;
                usleep(10000);  // 10ms
            }
        }
        printf("[DONE] continuous 模式结束: echo_count=%d fail_count=%d\n",
               echo_count, fail_count);
        fflush(stdout);
        result = (echo_count > 0) ? 0 : 1;
    } else {
        // 单次 echo 模式
        result = do_single_echo(ep, conn);
    }

    // 清理
    if (conn) linoh_connection_free(conn);
    g_running = false;
    if (monitor_thread.joinable()) monitor_thread.join();
    linoh_endpoint_free(ep);
    return result;
}

// ============================================================================
// K-LP-001: Relay 模式 — 原生 socket relay client
//
// 双向 Symmetric NAT 场景下直连不可能，通过 relay 服务器中转数据。
// 使用 POSIX 原生 socket（非 asio stub）实现真实 TCP I/O，
// 复用 linoh relay 协议函数（stride/ws_client/auth 均为 header-only inline）。
//
// 数据流:
//   client → relay (TCP/WS) → server (TCP/WS)
//   server → relay (TCP/WS) → client (TCP/WS)
// ============================================================================

/// relay 接收到的数据报
struct RelayDatagram {
    linoh::base::EndpointId from;       // 发送方 EndpointId
    std::vector<uint8_t> contents;      // 数据内容
};

/// relay client 状态
struct RelayClient {
    int sock = -1;
    linoh::base::SecretKey sk;
    linoh::base::EndpointId local_id;
    linoh::base::EndpointId peer_id;
    std::mutex send_mu;                                     // 保护 socket send
    std::mutex recv_mu;                                     // 保护 recv_queue
    std::condition_variable recv_cv;
    std::vector<RelayDatagram> recv_queue;
    std::atomic<bool> running{true};
    std::atomic<bool> connected{false};
    std::vector<uint8_t> ws_read_buf;                       // WS 帧解析剩余字节
};

/// 解析 "host:port" 地址
static bool parse_relay_addr(const std::string &addr, std::string &host, uint16_t &port) {
    auto pos = addr.rfind(':');
    if (pos == std::string::npos) return false;
    host = addr.substr(0, pos);
    port = static_cast<uint16_t>(std::atoi(addr.substr(pos + 1).c_str()));
    return !host.empty() && port > 0;
}

/// 解析 64 字符 hex 为 EndpointId
static bool parse_endpoint_id_hex(const std::string &hex, linoh::base::EndpointId &out) {
    if (hex.size() != 64) return false;
    auto from_hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < 32; ++i) {
        int hi = from_hex(hex[i * 2]);
        int lo = from_hex(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out.data()[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

/// TCP 连接到 relay 服务器
static int relay_tcp_connect(const std::string &host, uint16_t port) {
    struct addrinfo hints = {}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        return -1;
    }
    int sock = -1;
    for (auto *p = res; p; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

/// 发送全部字节（循环直到完成）
static bool relay_send_all(int sock, const uint8_t *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(sock, data + off, len - off, 0);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

/// 带 select 超时的 recv
static ssize_t relay_recv_timeout(int sock, uint8_t *buf, size_t len, int timeout_ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = select(sock + 1, &fds, nullptr, nullptr, &tv);
    if (r < 0) return -1;
    if (r == 0) return -2;  // timeout
    return recv(sock, buf, len, 0);
}

/// 从 socket 读取一个完整 WebSocket 帧（阻塞，带超时）
static bool relay_read_ws_frame(RelayClient &rc, linoh::relay::WsFrame &out_frame,
                                 int timeout_ms = 30000) {
    while (true) {
        auto decoded = linoh::relay::ws_decode_frame(
            std::span<const uint8_t>(rc.ws_read_buf.data(), rc.ws_read_buf.size()));
        if (decoded.ok) {
            out_frame = decoded.frame;
            rc.ws_read_buf.erase(rc.ws_read_buf.begin(),
                                 rc.ws_read_buf.begin() + decoded.bytes_consumed);
            return true;
        }
        if (decoded.invalid) {
            fprintf(stderr, "[RELAY] 非法 WebSocket 帧\n");
            fflush(stderr);
            return false;
        }
        // need_more — 读取更多数据
        uint8_t buf[4096];
        ssize_t n = relay_recv_timeout(rc.sock, buf, sizeof(buf), timeout_ms);
        if (n <= 0) {
            fprintf(stderr, "[RELAY] recv 失败 (ret=%zd)\n", n);
            fflush(stderr);
            return false;
        }
        rc.ws_read_buf.insert(rc.ws_read_buf.end(), buf, buf + n);
    }
}

/// 连接到 relay 服务器：TCP + WebSocket 升级 + 认证握手
static bool relay_connect(RelayClient &rc, const std::string &host, uint16_t port) {
    // 1. TCP 连接
    rc.sock = relay_tcp_connect(host, port);
    if (rc.sock < 0) {
        fprintf(stderr, "[RELAY] TCP 连接失败: %s:%u\n", host.c_str(), port);
        fflush(stderr);
        return false;
    }
    printf("[RELAY] TCP 已连接到 %s:%u\n", host.c_str(), port);
    fflush(stdout);

    // 2. WebSocket 升级
    std::string ws_req = linoh::relay::ws_build_handshake_request(
        host, "/", std::to_string(port));
    {
        std::lock_guard<std::mutex> lk(rc.send_mu);
        if (!relay_send_all(rc.sock,
                reinterpret_cast<const uint8_t *>(ws_req.data()), ws_req.size())) {
            fprintf(stderr, "[RELAY] WS 握手发送失败\n");
            return false;
        }
    }

    // 读取 WS 握手响应
    std::vector<uint8_t> resp_buf(4096);
    size_t total = 0;
    while (total < resp_buf.size()) {
        ssize_t n = relay_recv_timeout(rc.sock, resp_buf.data() + total,
                                        resp_buf.size() - total, 5000);
        if (n <= 0) {
            fprintf(stderr, "[RELAY] WS 握手响应接收失败\n");
            return false;
        }
        total += static_cast<size_t>(n);
        auto hdr_end = linoh::relay::ws_http_header_end(
            std::span<const uint8_t>(resp_buf.data(), total));
        if (hdr_end > 0) {
            if (!linoh::relay::ws_validate_handshake_response(
                    std::span<const uint8_t>(resp_buf.data(), hdr_end))) {
                fprintf(stderr, "[RELAY] WS 握手响应无效\n");
                return false;
            }
            if (hdr_end < total) {
                rc.ws_read_buf.assign(resp_buf.begin() + hdr_end,
                                      resp_buf.begin() + total);
            }
            break;
        }
    }
    printf("[RELAY] WebSocket 升级完成\n");
    fflush(stdout);

    // 3. 认证握手 — 等待 ServerChallenge（或 ServerConfirmsAuth 表示无认证）
    linoh::relay::WsFrame frame;
    if (!relay_read_ws_frame(rc, frame, 10000)) return false;
    if (frame.opcode != linoh::relay::WsOpcode::Binary) {
        fprintf(stderr, "[RELAY] 期望 binary 帧获取 challenge\n");
        return false;
    }
    auto stride = linoh::relay::decode_frame(frame.payload);
    if (!stride) {
        fprintf(stderr, "[RELAY] STRIDE 帧解码失败\n");
        return false;
    }

    if (stride->type == linoh::relay::FrameType::ServerConfirmsAuth) {
        // relay 服务器禁用了认证
        printf("[RELAY] 认证已跳过（服务器 --no-auth）\n");
        fflush(stdout);
    } else if (stride->type == linoh::relay::FrameType::ServerChallenge) {
        auto challenge = linoh::relay::decode_server_challenge(stride->payload);
        if (!challenge) {
            fprintf(stderr, "[RELAY] ServerChallenge 载荷无效\n");
            return false;
        }
        // 签名并发送 ClientAuth
        auto client_auth = linoh::relay::sign_challenge(*challenge, rc.sk);
        auto auth_frame = linoh::relay::encode_client_auth(client_auth);
        auto ws_auth = linoh::relay::ws_encode_binary_frame(auth_frame);
        {
            std::lock_guard<std::mutex> lk(rc.send_mu);
            if (!relay_send_all(rc.sock, ws_auth.data(), ws_auth.size())) {
                fprintf(stderr, "[RELAY] ClientAuth 发送失败\n");
                return false;
            }
        }
        // 等待 ServerConfirmsAuth
        if (!relay_read_ws_frame(rc, frame, 10000)) return false;
        if (frame.opcode != linoh::relay::WsOpcode::Binary) {
            fprintf(stderr, "[RELAY] 期望 binary 帧获取认证确认\n");
            return false;
        }
        auto confirm = linoh::relay::decode_frame(frame.payload);
        if (!confirm) {
            fprintf(stderr, "[RELAY] 认证确认帧解码失败\n");
            return false;
        }
        if (confirm->type == linoh::relay::FrameType::ServerConfirmsAuth) {
            printf("[RELAY] 认证成功\n");
            fflush(stdout);
        } else if (confirm->type == linoh::relay::FrameType::ServerDeniesAuth) {
            auto deny = linoh::relay::decode_server_denies(confirm->payload);
            fprintf(stderr, "[RELAY] 认证被拒: %s\n", deny.reason.c_str());
            return false;
        } else {
            fprintf(stderr, "[RELAY] 意外的帧类型 %d\n", (int)confirm->type);
            return false;
        }
    } else {
        fprintf(stderr, "[RELAY] 期望 ServerChallenge，收到 type=%d\n", (int)stride->type);
        return false;
    }

    rc.connected.store(true);
    return true;
}

/// 通过 relay 发送数据报到对端
static bool relay_send_datagram(RelayClient &rc, const uint8_t *data, size_t len) {
    if (!rc.connected.load() || rc.sock < 0) return false;
    linoh::relay::Datagram dg;
    dg.dst = rc.peer_id;
    dg.contents.assign(data, data + len);
    auto stride_frame = linoh::relay::encode_client_to_relay_datagram(dg);
    auto ws_frame = linoh::relay::ws_encode_binary_frame(stride_frame);
    std::lock_guard<std::mutex> lk(rc.send_mu);
    return relay_send_all(rc.sock, ws_frame.data(), ws_frame.size());
}

/// 接收线程：持续读取 WebSocket 帧，将数据报放入队列
static void relay_recv_loop(RelayClient &rc) {
    while (rc.running.load() && rc.connected.load()) {
        auto decoded = linoh::relay::ws_decode_frame(
            std::span<const uint8_t>(rc.ws_read_buf.data(), rc.ws_read_buf.size()));

        if (decoded.ok) {
            rc.ws_read_buf.erase(rc.ws_read_buf.begin(),
                                 rc.ws_read_buf.begin() + decoded.bytes_consumed);
            auto &frame = decoded.frame;
            if (frame.opcode == linoh::relay::WsOpcode::Binary) {
                auto stride = linoh::relay::decode_frame(frame.payload);
                if (stride) {
                    switch (stride->type) {
                    case linoh::relay::FrameType::RelayToClientDatagram: {
                        auto dg = linoh::relay::decode_datagram(stride->payload);
                        if (dg) {
                            std::lock_guard<std::mutex> lk(rc.recv_mu);
                            rc.recv_queue.push_back({dg->dst, std::move(dg->contents)});
                            rc.recv_cv.notify_one();
                        }
                        break;
                    }
                    case linoh::relay::FrameType::Ping: {
                        // 回复 STRIDE Pong（封装在 WS Binary 帧中，非 WS Pong 控制帧）
                        if (stride->payload.size() >= 8) {
                            std::array<uint8_t, 8> pong_data;
                            std::memcpy(pong_data.data(), stride->payload.data(), 8);
                            auto pong_stride = linoh::relay::encode_pong(pong_data);
                            auto ws_pong = linoh::relay::ws_encode_binary_frame(pong_stride);
                            std::lock_guard<std::mutex> lk(rc.send_mu);
                            relay_send_all(rc.sock, ws_pong.data(), ws_pong.size());
                        }
                        break;
                    }
                    case linoh::relay::FrameType::EndpointGone:
                        fprintf(stderr, "[RELAY] 对端已断开\n");
                        fflush(stderr);
                        rc.connected.store(false);
                        rc.recv_cv.notify_all();
                        return;
                    default:
                        break;  // 忽略其他帧类型
                    }
                }
            } else if (frame.opcode == linoh::relay::WsOpcode::Close) {
                fprintf(stderr, "[RELAY] WebSocket Close 帧收到\n");
                fflush(stderr);
                rc.connected.store(false);
                rc.recv_cv.notify_all();
                return;
            }
        } else if (decoded.invalid) {
            fprintf(stderr, "[RELAY] 非法 WebSocket 帧，断开\n");
            fflush(stderr);
            rc.connected.store(false);
            rc.recv_cv.notify_all();
            return;
        } else {
            // need_more — 读取更多数据
            uint8_t buf[4096];
            ssize_t n = relay_recv_timeout(rc.sock, buf, sizeof(buf), 2000);
            if (n > 0) {
                rc.ws_read_buf.insert(rc.ws_read_buf.end(), buf, buf + n);
            } else if (n == 0) {
                fprintf(stderr, "[RELAY] relay 连接已关闭\n");
                fflush(stderr);
                rc.connected.store(false);
                rc.recv_cv.notify_all();
                return;
            } else if (n != -2) {
                // -2 = timeout（正常），其他 = 错误
                fprintf(stderr, "[RELAY] recv 错误 (ret=%zd)\n", n);
                fflush(stderr);
                rc.connected.store(false);
                rc.recv_cv.notify_all();
                return;
            }
        }
    }
}

/// 等待接收数据报（带超时），返回完整 RelayDatagram（含发送方 EndpointId）
static RelayDatagram relay_wait_datagram(RelayClient &rc, int timeout_ms) {
    std::unique_lock<std::mutex> lk(rc.recv_mu);
    if (rc.recv_queue.empty()) {
        rc.recv_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                            [&] { return !rc.recv_queue.empty() || !rc.connected.load(); });
    }
    if (rc.recv_queue.empty()) return {};
    auto dg = std::move(rc.recv_queue.front());
    rc.recv_queue.erase(rc.recv_queue.begin());
    return dg;
}

/// 关闭 relay 连接
static void relay_disconnect(RelayClient &rc) {
    rc.connected.store(false);
    rc.running.store(false);
    if (rc.sock >= 0) {
        shutdown(rc.sock, SHUT_RDWR);
        close(rc.sock);
        rc.sock = -1;
    }
}

// ============================================================================
// Relay Server 模式 — 通过 relay 中转接收/回显数据
// ============================================================================

static int run_relay_server(const std::string &relay_addr,
                             const std::string &relay_backup,
                             const std::string &log_file) {
    if (!log_file.empty()) {
        FILE *f = freopen(log_file.c_str(), "w", stdout);
        if (!f) { fprintf(stderr, "[ERROR] 无法打开日志: %s\n", log_file.c_str()); return 1; }
        freopen(log_file.c_str(), "a", stderr);
    }

    printf("[BOOT] relay echo server 启动... relay=%s\n", relay_addr.c_str());
    fflush(stdout);

    std::string relay_host;
    uint16_t relay_port = 0;
    if (!parse_relay_addr(relay_addr, relay_host, relay_port)) {
        fprintf(stderr, "[ERROR] relay 地址无效: %s\n", relay_addr.c_str());
        return 1;
    }

    RelayClient rc;
    rc.sk = linoh::base::SecretKey::generate();
    rc.local_id = rc.sk.public_key();

    std::string eid_hex = to_hex(rc.local_id.data(), 32);
    printf("endpoint_id=%s\n", eid_hex.c_str());
    fflush(stdout);

    if (!relay_connect(rc, relay_host, relay_port)) {
        return 1;
    }

    printf("LISTENING\n");
    fflush(stdout);

    std::thread recv_thread(relay_recv_loop, std::ref(rc));

    int echo_count = 0;
    while (g_running && rc.connected.load()) {
        auto dg = relay_wait_datagram(rc, 1000);
        if (!dg.contents.empty()) {
            // 设置 peer_id 为发送方 EndpointId，用于回显
            rc.peer_id = dg.from;
            if (relay_send_datagram(rc, dg.contents.data(), dg.contents.size())) {
                echo_count++;
                printf("ECHO_OK count=%d\n", echo_count);
                fflush(stdout);
            } else {
                printf("ECHO_FAIL count=%d\n", echo_count);
                fflush(stdout);
            }
        }
    }

    relay_disconnect(rc);
    if (recv_thread.joinable()) recv_thread.join();
    printf("[DONE] relay server 结束, echo_count=%d\n", echo_count);
    fflush(stdout);
    return 0;
}

// ============================================================================
// Relay Client 模式 — 通过 relay 中转发送/接收 echo 数据
// ============================================================================

static int run_relay_client(const std::string &relay_addr,
                             const std::string &relay_backup,
                             const std::string &peer_id_hex,
                             const std::string &log_file,
                             const std::string &mode,
                             int interval_sec) {
    if (!log_file.empty()) {
        FILE *f = freopen(log_file.c_str(), "w", stdout);
        if (!f) { fprintf(stderr, "[ERROR] 无法打开日志: %s\n", log_file.c_str()); return 1; }
        freopen(log_file.c_str(), "a", stderr);
    }

    printf("[BOOT] relay echo client 启动... relay=%s mode=%s\n",
           relay_addr.c_str(), mode.c_str());
    fflush(stdout);

    std::string relay_host;
    uint16_t relay_port = 0;
    if (!parse_relay_addr(relay_addr, relay_host, relay_port)) {
        fprintf(stderr, "[ERROR] relay 地址无效: %s\n", relay_addr.c_str());
        return 1;
    }

    RelayClient rc;
    rc.sk = linoh::base::SecretKey::generate();
    rc.local_id = rc.sk.public_key();

    // 解析对端 EndpointId
    if (!parse_endpoint_id_hex(peer_id_hex, rc.peer_id)) {
        fprintf(stderr, "[ERROR] 对端 EndpointId 无效: %s (需要 64 字符 hex)\n",
                peer_id_hex.c_str());
        return 1;
    }

    std::string eid_hex = to_hex(rc.local_id.data(), 32);
    printf("endpoint_id=%s\n", eid_hex.c_str());
    fflush(stdout);

    if (!relay_connect(rc, relay_host, relay_port)) {
        return 1;
    }

    printf("CONNECTED\n");
    fflush(stdout);

    std::thread recv_thread(relay_recv_loop, std::ref(rc));

    int result = 0;
    const char *test_msg = "Hello from patchbay relay echo client!";
    size_t msg_len = strlen(test_msg);

    auto do_relay_echo = [&]() -> int {
        if (!relay_send_datagram(rc, reinterpret_cast<const uint8_t *>(test_msg), msg_len)) {
            fprintf(stderr, "[ERROR] relay 发送失败\n");
            fflush(stderr);
            return 1;
        }
        printf("[SEND] 已通过 relay 发送 %zu 字节\n", msg_len);
        fflush(stdout);

        auto resp = relay_wait_datagram(rc, 30000);  // 30s 超时
        if (resp.contents.size() == msg_len &&
            memcmp(resp.contents.data(), test_msg, msg_len) == 0) {
            printf("[RECV] 收到回显 %zu 字节，验证通过\n", resp.contents.size());
            printf("ECHO_OK\n");
            fflush(stdout);
            return 0;
        } else {
            fprintf(stderr, "[RECV] 回显验证失败: 期望 %zu 字节, 收到 %zu 字节\n",
                    msg_len, resp.contents.size());
            printf("ECHO_FAIL\n");
            fflush(stdout);
            return 1;
        }
    };

    if (mode == "continuous") {
        int echo_count = 0;
        int fail_count = 0;
        while (g_running && rc.connected.load()) {
            int ret = do_relay_echo();
            if (ret == 0) {
                echo_count++;
                printf("ECHO_OK count=%d fails=%d\n", echo_count, fail_count);
            } else {
                fail_count++;
                printf("ECHO_FAIL count=%d fails=%d\n", echo_count, fail_count);
                // relay 连接可能断开，尝试重连
                if (!rc.connected.load() && !relay_addr.empty()) {
                    printf("[RECONNECT] relay 连接断开，尝试重连...\n");
                    fflush(stdout);
                    relay_disconnect(rc);
                    if (recv_thread.joinable()) recv_thread.join();
                    usleep(500000);
                    rc.running.store(true);
                    if (relay_connect(rc, relay_host, relay_port)) {
                        printf("[RECONNECT] 重连成功\n");
                        fflush(stdout);
                        recv_thread = std::thread(relay_recv_loop, std::ref(rc));
                    } else if (!relay_backup.empty()) {
                        // 尝试备用 relay
                        std::string bk_host;
                        uint16_t bk_port = 0;
                        if (parse_relay_addr(relay_backup, bk_host, bk_port)) {
                            printf("[RECONNECT] 尝试备用 relay %s\n", relay_backup.c_str());
                            fflush(stdout);
                            rc.running.store(true);
                            if (relay_connect(rc, bk_host, bk_port)) {
                                printf("[RECONNECT] 备用 relay 连接成功\n");
                                fflush(stdout);
                                recv_thread = std::thread(relay_recv_loop, std::ref(rc));
                            } else {
                                fprintf(stderr, "[RECONNECT] 备用 relay 连接失败\n");
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
            for (int i = 0; i < interval_sec * 100 && g_running; ++i) {
                if (!rc.connected.load()) break;
                usleep(10000);
            }
        }
        printf("[DONE] continuous 模式结束: echo_count=%d fail_count=%d\n",
               echo_count, fail_count);
        fflush(stdout);
        result = (echo_count > 0) ? 0 : 1;
    } else {
        result = do_relay_echo();
    }

    relay_disconnect(rc);
    if (recv_thread.joinable()) recv_thread.join();
    return result;
}

// ============================================================================
// main
// ============================================================================

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    Args args = parse_args(argc, argv);

    if (args.role.empty()) {
        fprintf(stderr, "[ERROR] 缺少 --role 参数\n");
        return 1;
    }

    // K-LP-001: relay 模式（--relay-addr 非空时启用）
    if (!args.relay_addr.empty()) {
        if (args.role == "server") {
            return run_relay_server(args.relay_addr, args.relay_backup, args.log_file);
        } else if (args.role == "client") {
            if (args.peer_endpoint_id.empty()) {
                fprintf(stderr, "[ERROR] relay client 模式需要 --peer-endpoint-id\n");
                return 1;
            }
            return run_relay_client(args.relay_addr, args.relay_backup,
                                    args.peer_endpoint_id, args.log_file,
                                    args.mode, args.interval_sec);
        } else {
            fprintf(stderr, "[ERROR] 无效 role: %s\n", args.role.c_str());
            return 1;
        }
    }

    // 直连模式（原有逻辑）
    if (args.port == 0) {
        fprintf(stderr, "[ERROR] 缺少 --port 参数\n");
        return 1;
    }

    if (args.role == "server") {
        return run_server(args.port, args.log_file);
    } else if (args.role == "client") {
        if (args.remote_ip.empty() || args.remote_port == 0) {
            fprintf(stderr, "[ERROR] client 模式需要 --remote-ip 和 --remote-port\n");
            return 1;
        }
        return run_client(args.port, args.log_file, args.remote_ip, args.remote_port,
                          args.mode, args.interval_sec, args.monitor_network);
    } else {
        fprintf(stderr, "[ERROR] 无效 role: %s (应为 server 或 client)\n", args.role.c_str());
        return 1;
    }
}
