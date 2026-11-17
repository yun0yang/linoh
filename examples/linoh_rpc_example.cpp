/// linoh_rpc_example.cpp — 演示 ApplicationApi 语义封装层用法（P1-3）
///
/// 本示例不建立真实网络连接，仅展示 ApplicationApi 的 API 形态。
/// 真实使用时需要：
///   1. 创建 Endpoint 并 connect 到对端
///   2. 握手完成后得到 std::shared_ptr<Connection>
///   3. 用 ApplicationApi 包装 Connection，调用具名方法

#include "linoh/application_api.hpp"
#include "linoh/endpoint/connection.hpp"
#include "linoh/protocol/application_message.hpp"

#include <cstdio>
#include <string>
#include <vector>

static int demonstrate_api_usage() {
    // 示例：构造一个最小的 Connection 配置（不实际连接）
    // 真实场景由 Endpoint::connect 返回 shared_ptr<Connection>
    linoh::endpoint::Connection::Config cfg{};
    cfg.alpn = "pp-hidden/1";

    // 注：此处仅展示 API 形态，构造的 conn 不会建立真实连接
    auto conn = std::make_shared<linoh::endpoint::Connection>(std::move(cfg));
    linoh::ApplicationApi api(conn);

    // 1. 注册请求处理器（服务端侧）
    // 注：lambda 持有 conn 副本会形成循环引用，实际使用应改用 weak_ptr
    std::weak_ptr<linoh::endpoint::Connection> weak_conn = conn;
    conn->set_request_handler([weak_conn](const linoh::protocol::ApplicationMessage &msg) {
        std::printf("[server] received request method=0x%04x req_id=%u payload_len=%zu\n",
                    static_cast<unsigned>(msg.method_id),
                    msg.request_id,
                    msg.payload.size());
        if (auto c = weak_conn.lock()) {
            std::vector<std::uint8_t> resp = {0x00, 0x01, 0x02};
            c->respond(msg.request_id, msg.method_id, resp);
        }
    });

    // 2. 启动心跳（Established 后才能实际工作）
    api.start_heartbeat(10000, 30000);
    api.on_heartbeat_timeout([]() {
        std::printf("[client] heartbeat timeout, will close connection\n");
    });

    // 3. 通知：状态变更
    api.notify_state_change("ACTIVE");

    // 4. 通知：错误上报
    api.notify_error("demo error message");

    // 5. 请求-响应：forward_pp（此处 future 不会实际完成，因为没有真实连接）
    std::vector<std::uint8_t> hidden_state(1024, 0x42);
    auto fut = api.forward_pp(hidden_state, 120000);
    (void)fut;

    // 6. 请求-响应：join
    std::string node_info = R"({"device_id":"abc123","layer_range":[28,47]})";
    auto join_fut = api.join(node_info, 30000);
    (void)join_fut;

    // 7. 请求-响应：load_model
    auto lm_fut = api.load_model("Qwen3.5-122B-A10B-Q4_K_XL", 28, 47, 60000);
    (void)lm_fut;

    // 8. 请求-响应：drain
    auto drain_fut = api.drain(10000);
    (void)drain_fut;

    // 9. 停止心跳
    api.stop_heartbeat();

    std::printf("\n[demo] ApplicationApi calls dispatched (no real network)\n");
    return 0;
}

int main() {
    std::printf("========================================\n");
    std::printf("  linoh ApplicationApi Demo (P1-3)\n");
    std::printf("========================================\n\n");

    return demonstrate_api_usage();
}
