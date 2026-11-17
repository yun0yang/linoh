// e2e_harness.hpp — v4.3.0 M21 端到端测试夹具
//
// 设计原则（职责边界 2026-08-03）：
//   - linoh 侧只提供"事件循环引擎 + 传输原语"
//   - E2eHarness 内置最小化模拟 orchestrator，不依赖真实集群管家代码
//   - 通过 linoh C-API 直接建立 endpoint / 连接 / 流，验证 PP 链全流程
//
// 数据流（PP 链）：
//   master register_return_slot(req_id) → token
//   master open_stream(w1_conn) → write [token(4B,LE)][hidden_state...]
//   w1 on_stream: read → forward to w2 via open_stream(w2_conn)
//   w2 on_stream: read → open_return_stream(master) → send_result_direct
//   master await_return_result(token) → 收到结果
//
// 多模态覆盖：
//   pp-llm/1  — LLM hidden_state PP 链
//   pp-img/1  — 图片特征传输
//   pp-video/1 — 视频特征传输
//   pp-audio/1 — 音频特征传输
//
// 事件循环模式：
//   LinohEventSource(ExternalDriven) + EventLoop 替代 poll_all 循环
//   select() → drive() 多路复用驱动所有 endpoint

#pragma once

#include "linoh/linoh_c.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

namespace e2e {

// ============================================================================
// 辅助编码/解码
// ============================================================================
inline void encode_u32_le(std::vector<uint8_t> &out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

inline uint32_t decode_u32_le(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline void encode_u64_le(std::vector<uint8_t> &out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

inline uint64_t decode_u64_le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(p[i]) << (i * 8);
    }
    return v;
}

// ============================================================================
// 节点上下文
// ============================================================================
struct NodeContext {
    std::string name;
    linoh_endpoint_t *ep{nullptr};
    uint16_t udp_port{0};
    uint16_t layer_start{0};
    uint16_t layer_end{0};

    // 角色控制 on_stream 回调行为
    enum Role {
        RoleMaster,    // PP 链 master（使用 await_return_result，不走 on_stream）
        RoleMiddle,    // PP 链中间 worker（转发到 next_conn）
        RoleLast,      // PP 链末节点（通过 direct return 回传结果）
        RoleEcho,      // 多模态 echo server（存储收到的数据，按 ALPN 分类）
    } role{RoleEcho};

    // PP 链转发指针
    linoh_connection_t *next_conn{nullptr};   // 到下一跳的连接 (pp-llm/1)
    std::string master_host;                   // 末节点回传目标
    uint16_t master_port{0};

    // Echo 模式：按 ALPN 存储收到的数据
    std::mutex mu;
    std::condition_variable cv;
    std::map<std::string, std::vector<uint8_t>> received_by_alpn;
    std::map<std::string, bool> got_data_by_alpn;

    // 统计
    std::atomic<int> streams_received{0};
    std::atomic<int> bytes_forwarded{0};
    std::atomic<int> bytes_returned{0};

    void reset_echo() {
        std::lock_guard<std::mutex> lk(mu);
        received_by_alpn.clear();
        got_data_by_alpn.clear();
    }

    bool wait_for_data(const std::string &alpn,
                       std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lk(mu);
        return cv.wait_for(lk, timeout, [&] {
            auto it = got_data_by_alpn.find(alpn);
            return it != got_data_by_alpn.end() && it->second;
        });
    }

    std::optional<std::vector<uint8_t>> get_received(const std::string &alpn) {
        std::lock_guard<std::mutex> lk(mu);
        auto it = received_by_alpn.find(alpn);
        if (it == received_by_alpn.end()) return std::nullopt;
        return it->second;
    }
};

// ============================================================================
// on_stream 回调（static，通过 user_data 分派）
// ============================================================================
// 注意：on_stream 在 linoh recv_thread 中触发，仅 stream 创建时调用一次。
// 数据可能分多个 QUIC packet 到达，因此在独立线程中循环读取直到 FIN，
// 避免 recv_thread 阻塞导致后续 packet 无法接收（死锁）。
inline void on_stream_cb(linoh_stream_t *stream, void *user_data) {
    auto *ctx = static_cast<NodeContext *>(user_data);
    if (!ctx || !stream) return;

    // 启动独立线程读取+处理，recv_thread 立即返回继续接收后续 packet
    std::thread([ctx, stream]() {
        // 循环读取直到 FIN 或超时
        uint8_t buf[65536];
        size_t total = 0;
        size_t n;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (total < sizeof(buf)) {
            n = linoh_stream_read(stream, buf + total, sizeof(buf) - total);
            if (n > 0) {
                total += n;
                continue;
            }
            // n == 0：暂无数据可读，检查是否收到 FIN
            if (linoh_stream_fin_received(stream)) {
                break;  // FIN 已收到，stream 结束
            }
            // 未收到 FIN，短暂等待更多数据到达（recv_thread 可继续 recv）
            if (std::chrono::steady_clock::now() >= deadline) {
                break;  // 超时保护
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (total == 0) {
            std::printf("[diag %s] on_stream: total=0 (timeout/FIN without data)\n", ctx->name.c_str());
            linoh_stream_free(stream);
            return;
        }

        ctx->streams_received.fetch_add(1, std::memory_order_relaxed);

        switch (ctx->role) {
        case NodeContext::RoleMiddle: {
            // 转发到下一跳
            std::printf("[diag %s] RoleMiddle: total=%zu, next_conn=%p\n",
                        ctx->name.c_str(), total, (void*)ctx->next_conn);
            if (ctx->next_conn) {
                linoh_stream_t *fwd = linoh_connection_open_stream(ctx->next_conn);
                if (fwd) {
                    size_t written = linoh_stream_write(fwd, buf, total);
                    (void)written;
                    linoh_stream_finish(fwd);
                    linoh_connection_flush(ctx->next_conn);
                    linoh_stream_free(fwd);
                    ctx->bytes_forwarded.fetch_add(
                        static_cast<int>(total), std::memory_order_relaxed);
                }
            }
            break;
        }
        case NodeContext::RoleLast: {
            // 末节点：提取 token + req_id，通过 direct return 回传结果
            // master 发送格式: [token(4B,LE)][req_id(8B,LE)][hidden_state...]
            std::printf("[diag %s] RoleLast: total=%zu, master=%s:%u\n",
                        ctx->name.c_str(), total,
                        ctx->master_host.c_str(), (unsigned)ctx->master_port);
            if (total < 12) {
                std::printf("[diag %s] RoleLast: total<12, break\n", ctx->name.c_str());
                break;  // 至少要有 token + req_id
            }
            uint32_t token = decode_u32_le(buf);
            // 跳过 token(4) + req_id(8) = 12 字节头部，剩余为 hidden_state
            const uint8_t *hidden = buf + 12;
            size_t hidden_len = total - 12;

            // 构造结果 = hidden_state + "_done"（证明数据经过链路）
            std::vector<uint8_t> result(hidden, hidden + hidden_len);
            const char suffix[] = "_done";
            result.insert(result.end(), suffix, suffix + sizeof(suffix) - 1);

            linoh_stream_t *rs = linoh_open_return_stream(
                ctx->ep, ctx->master_host.c_str(), ctx->master_port, token);
            std::printf("[diag %s] RoleLast: token=%u, rs=%p, result_size=%zu\n",
                        ctx->name.c_str(), (unsigned)token, (void*)rs, result.size());
            if (rs) {
                int sr = linoh_send_result_direct(ctx->ep, rs, token,
                                         result.data(), result.size(), 1);
                std::printf("[diag %s] RoleLast: send_result_direct rc=%d\n",
                            ctx->name.c_str(), sr);
                linoh_close_return_stream(ctx->ep, rs);
                ctx->bytes_returned.fetch_add(
                    static_cast<int>(result.size()), std::memory_order_relaxed);
            }
            break;
        }
        case NodeContext::RoleEcho: {
            // Echo 模式：按 ALPN 存储收到的数据
            const linoh_connection_t *conn = linoh_stream_connection(stream);
            std::string alpn = "unknown";
            if (conn) {
                const char *a = linoh_connection_alpn(conn);
                if (a) alpn = a;
            }
            std::lock_guard<std::mutex> lk(ctx->mu);
            ctx->received_by_alpn[alpn].assign(buf, buf + total);
            ctx->got_data_by_alpn[alpn] = true;
            ctx->cv.notify_all();
            break;
        }
        case NodeContext::RoleMaster:
            // Master 不通过 on_stream 接收数据（使用 await_return_result）
            break;
        }

        linoh_stream_free(stream);
    }).detach();
}

// ============================================================================
// E2eHarness — 端到端测试夹具
// ============================================================================
class E2eHarness {
public:
    E2eHarness() {
#ifdef _WIN32
        WSADATA wsa{};
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    }

    ~E2eHarness() { shutdown(); }

    // ------------------------------------------------------------------------
    // 创建节点
    // ------------------------------------------------------------------------
    NodeContext *start_node(const std::string &name,
                            uint16_t layer_start, uint16_t layer_end,
                            const char *alpn = "default/1") {
        auto ctx = std::make_unique<NodeContext>();
        ctx->name = name;
        ctx->layer_start = layer_start;
        ctx->layer_end = layer_end;
        ctx->role = NodeContext::RoleEcho;

        linoh_endpoint_config_t cfg{};
        linoh_secret_key_t sk{};
        linoh_public_key_t pk{};
        linoh_generate_keypair(&sk, &pk);
        cfg.secret_key = sk;
        cfg.alpn = alpn;
        cfg.udp_port = 0;  // 随机端口
        cfg.user_data = ctx.get();

        ctx->ep = linoh_endpoint_create(&cfg);
        if (!ctx->ep) return nullptr;

        ctx->udp_port = linoh_endpoint_udp_port(ctx->ep);

        // 注册 on_stream 回调
        linoh_endpoint_on_stream(ctx->ep, on_stream_cb);

        NodeContext *raw = ctx.get();
        nodes_.push_back(std::move(ctx));
        return raw;
    }

    // ------------------------------------------------------------------------
    // 建立 PP 链：chain[0]=master → chain[1] → ... → chain[last]
    // ------------------------------------------------------------------------
    bool build_pp_chain(const std::vector<NodeContext *> &chain,
                        std::chrono::milliseconds setup_timeout =
                            std::chrono::milliseconds(8000)) {
        if (chain.size() < 2) return false;

        // 设置角色
        chain[0]->role = NodeContext::RoleMaster;
        for (size_t i = 1; i < chain.size(); ++i) {
            if (i == chain.size() - 1) {
                chain[i]->role = NodeContext::RoleLast;
            } else {
                chain[i]->role = NodeContext::RoleMiddle;
            }
        }

        // master 启用 direct return 入站
        if (linoh_direct_return_enable_inbound(chain[0]->ep) != 0) return false;

        // 建立连接：chain[i] → chain[i+1] via pp-llm/1
        for (size_t i = 0; i + 1 < chain.size(); ++i) {
            NodeContext *from = chain[i];
            NodeContext *to = chain[i + 1];

            linoh_connection_t *conn = linoh_endpoint_connect_with_alpn(
                from->ep, "127.0.0.1", to->udp_port, "pp-llm/1");
            if (!conn) return false;

            from->next_conn = conn;
            connections_.push_back(conn);

            // 末节点记录 master 地址（用于 direct return）
            if (to->role == NodeContext::RoleLast) {
                to->master_host = "127.0.0.1";
                to->master_port = chain[0]->udp_port;
            }
        }

        // 轮询等待握手完成
        poll_all(setup_timeout);
        return true;
    }

    // ------------------------------------------------------------------------
    // PP 推理：master 发送 hidden_state，等待末节点回传结果
    // ------------------------------------------------------------------------
    std::optional<std::vector<uint8_t>> pp_inference(
        NodeContext *master,
        const std::vector<uint8_t> &hidden_state,
        uint64_t req_id = 1001,
        std::chrono::milliseconds timeout = std::chrono::seconds(15)) {

        // 1. master 注册 return slot
        uint32_t token = linoh_register_return_slot(master->ep, req_id);
        if (token == 0) return std::nullopt;

        // 2. 启动后台轮询线程（驱动所有节点）
        std::atomic<bool> polling{true};
        std::thread poll_thread([this, &polling]() {
            while (polling.load(std::memory_order_acquire)) {
                for (auto &n : nodes_) {
                    if (n->ep) linoh_endpoint_poll(n->ep);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        });

        // 3. master 打开 stream 到 worker1，发送 [token][hidden_state]
        if (!master->next_conn) {
            polling.store(false, std::memory_order_release);
            poll_thread.join();
            return std::nullopt;
        }

        linoh_stream_t *s = linoh_connection_open_stream(master->next_conn);
        if (!s) {
            polling.store(false, std::memory_order_release);
            poll_thread.join();
            return std::nullopt;
        }

        std::vector<uint8_t> payload;
        encode_u32_le(payload, token);
        encode_u64_le(payload, req_id);
        payload.insert(payload.end(), hidden_state.begin(), hidden_state.end());

        linoh_stream_write(s, payload.data(), payload.size());
        linoh_stream_finish(s);
        linoh_connection_flush(master->next_conn);
        linoh_stream_free(s);

        // 4. 等待结果
        uint8_t buf[65536];
        int64_t len = linoh_await_return_result(
            master->ep, token,
            static_cast<int>(timeout.count()),
            buf, sizeof(buf));
        std::printf("[diag master %s] await_return_result: token=%u, len=%lld\n",
                    master->name.c_str(), (unsigned)token, (long long)len);

        polling.store(false, std::memory_order_release);
        poll_thread.join();

        if (len > 0) {
            return std::vector<uint8_t>(buf, buf + len);
        }
        return std::nullopt;
    }

    // ------------------------------------------------------------------------
    // 多模态：建立指定 ALPN 的连接
    // ------------------------------------------------------------------------
    linoh_connection_t *connect_alpn(NodeContext *from, NodeContext *to,
                                     const char *alpn,
                                     std::chrono::milliseconds setup_timeout =
                                         std::chrono::milliseconds(5000)) {
        linoh_connection_t *conn = linoh_endpoint_connect_with_alpn(
            from->ep, "127.0.0.1", to->udp_port, alpn);
        if (!conn) return nullptr;

        connections_.push_back(conn);
        poll_all(setup_timeout);
        return conn;
    }

    // ------------------------------------------------------------------------
    // 在连接上发送数据并等待 echo 端接收
    // ------------------------------------------------------------------------
    bool send_and_wait_echo(linoh_connection_t *conn,
                            NodeContext *echo_node,
                            const std::string &alpn,
                            const uint8_t *data, size_t len,
                            std::chrono::milliseconds timeout =
                                std::chrono::seconds(10)) {
        if (!conn || !echo_node) return false;

        echo_node->reset_echo();

        // 启动后台轮询
        std::atomic<bool> polling{true};
        std::thread poll_thread([this, &polling]() {
            while (polling.load(std::memory_order_acquire)) {
                for (auto &n : nodes_) {
                    if (n->ep) linoh_endpoint_poll(n->ep);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        });

        // 打开 stream 发送数据
        linoh_stream_t *s = linoh_connection_open_stream(conn);
        if (!s) {
            polling.store(false, std::memory_order_release);
            poll_thread.join();
            return false;
        }

        linoh_stream_write(s, data, len);
        linoh_stream_finish(s);
        linoh_connection_flush(conn);
        linoh_stream_free(s);

        // 等待 echo 端收到数据
        bool ok = echo_node->wait_for_data(alpn, timeout);

        polling.store(false, std::memory_order_release);
        poll_thread.join();
        return ok;
    }

    // ------------------------------------------------------------------------
    // 轮询所有节点一段时间
    // ------------------------------------------------------------------------
    void poll_all(std::chrono::milliseconds duration) {
        auto start = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - start)
                   .count() < duration.count()) {
            for (auto &n : nodes_) {
                if (n->ep) linoh_endpoint_poll(n->ep);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // ------------------------------------------------------------------------
    // 事件循环驱动：用 LinohEventSource + EventLoop 替代 poll_all
    // ------------------------------------------------------------------------
    bool run_event_loop_driven(NodeContext *master,
                               NodeContext *worker,
                               linoh_connection_t *worker_conn,
                               const std::vector<uint8_t> &data,
                               std::chrono::milliseconds timeout) {
        if (!master || !worker || !worker_conn) return false;

        master->reset_echo();

        // 创建事件循环 + 两个 LinohEventSource（ExternalDriven）
        linoh_event_loop_t *loop = linoh_event_loop_create();
        if (!loop) return false;

        linoh_event_source_t *master_src = linoh_linoh_event_create(
            master->ep, LINOH_EVENT_MODE_EXTERNAL);
        linoh_event_source_t *worker_src = linoh_linoh_event_create(
            worker->ep, LINOH_EVENT_MODE_EXTERNAL);

        if (!master_src || !worker_src) {
            if (master_src) linoh_event_source_destroy(master_src);
            if (worker_src) linoh_event_source_destroy(worker_src);
            linoh_event_loop_destroy(loop);
            return false;
        }

        int sid_master = linoh_event_loop_register(loop, master_src, 0);
        int sid_worker = linoh_event_loop_register(loop, worker_src, 1);
        if (sid_master < 0 || sid_worker < 0) {
            linoh_event_source_destroy(master_src);
            linoh_event_source_destroy(worker_src);
            linoh_event_loop_destroy(loop);
            return false;
        }

        // 发送数据
        linoh_stream_t *s = linoh_connection_open_stream(worker_conn);
        if (!s) {
            linoh_event_source_destroy(master_src);
            linoh_event_source_destroy(worker_src);
            linoh_event_loop_destroy(loop);
            return false;
        }
        linoh_stream_write(s, data.data(), data.size());
        linoh_stream_finish(s);
        linoh_connection_flush(worker_conn);
        linoh_stream_free(s);

        // 事件循环驱动
        auto deadline = std::chrono::steady_clock::now() + timeout;
        bool got_data = false;

        while (std::chrono::steady_clock::now() < deadline) {
            int ids[8];
            int n = linoh_event_loop_select(loop, ids, 8, 1000);
            for (int i = 0; i < n; ++i) {
                if (ids[i] == sid_master) {
                    linoh_linoh_event_drive(master_src);
                }
                if (ids[i] == sid_worker) {
                    linoh_linoh_event_drive(worker_src);
                }
            }
            // 检查是否收到数据
            if (master->got_data_by_alpn.size() > 0) {
                std::lock_guard<std::mutex> lk(master->mu);
                for (auto &[alpn, got] : master->got_data_by_alpn) {
                    if (got) { got_data = true; break; }
                }
            }
            if (got_data) break;
        }

        linoh_event_source_destroy(master_src);
        linoh_event_source_destroy(worker_src);
        linoh_event_loop_destroy(loop);
        return got_data;
    }

    // ------------------------------------------------------------------------
    // 清理
    // ------------------------------------------------------------------------
    void shutdown() {
        for (auto *conn : connections_) {
            if (conn) linoh_connection_free(conn);
        }
        connections_.clear();

        for (auto &n : nodes_) {
            if (n->ep) linoh_endpoint_free(n->ep);
            n->ep = nullptr;
        }
        nodes_.clear();
    }

private:
    std::vector<std::unique_ptr<NodeContext>> nodes_;
    std::vector<linoh_connection_t *> connections_;
};

} // namespace e2e
