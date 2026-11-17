// test_custom_transport.cpp — 自定义传输注册机制单元测试（P4-C-4）
//
// 覆盖：
//   - TransportId 知名常量与工具函数
//   - CustomTransportAddr parse/to_string/from_hex/to_bytes/from_bytes 往返
//   - CustomTransport 抽象接口（Mock 实现）
//   - TransportRegistry 注册/查找/注销
//   - EndpointAddr custom_addrs 字段
//   - 多传输并发连接尝试
//   - 边界场景（保留 ID 拒绝、重复注册、空注册表等）

#include "linoh/net/custom_transport.hpp"
#include "linoh/base/endpoint_addr.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace linoh::net;
using namespace linoh::base;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s (line %d)\n", #cond, __LINE__); } \
} while (0)

// ============================================================================
// MockCustomTransport 实现
// ============================================================================
//
class MockTransport : public CustomTransport {
public:
    TransportId id() const override { return id_; }
    std::string_view name() const override { return name_; }

    TransportConnHandle connect(
        const CustomTransportAddr &addr,
        std::chrono::milliseconds timeout) override {
        (void)addr;
        (void)timeout;

        ++connect_count_;

        if (connect_should_fail_.load()) {
            return nullptr;
        }

        // 模拟延迟
        if (connect_delay_ms_.load() > 0) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(connect_delay_ms_.load()));
        }

        // 返回一个简单的"连接"句柄（指向自身）
        ++conn_id_counter_;
        last_conn_id_ = conn_id_counter_.load();
        return std::make_shared<int>(static_cast<int>(last_conn_id_));
    }

    bool listen(const CustomTransportAddr &bind_addr,
                TransportAcceptCallback on_accept) override {
        (void)bind_addr;
        listen_callback_ = std::move(on_accept);
        listening_ = true;
        return true;
    }

    void stop_listen() override {
        listening_ = false;
        listen_callback_ = nullptr;
    }

    void close() override {}

    bool supports_address(const CustomTransportAddr &addr) const override {
        return addr.transport_id == id_;
    }

    bool is_ready() const override { return ready_.load(); }

    void set_id(TransportId id) { id_ = id; }
    void set_name(std::string name) { name_ = std::move(name); }
    void set_ready(bool r) { ready_ = r; }
    void set_connect_should_fail(bool f) { connect_should_fail_ = f; }
    void set_connect_delay_ms(int ms) { connect_delay_ms_ = ms; }

    int connect_count() const { return connect_count_.load(); }
    int last_conn_id() const { return last_conn_id_; }
    bool is_listening() const { return listening_; }

    /// 模拟收到一个连接
    void simulate_accept(TransportConnHandle conn, const CustomTransportAddr &from) {
        if (listen_callback_) {
            listen_callback_(conn, from);
        }
    }

private:
    TransportId id_{kTransportIdMock};
    std::string name_{"mock"};
    std::atomic<bool> ready_{true};
    std::atomic<bool> connect_should_fail_{false};
    std::atomic<int> connect_delay_ms_{0};
    std::atomic<int> connect_count_{0};
    std::atomic<int> conn_id_counter_{0};
    std::atomic<int> last_conn_id_{0};
    bool listening_{false};
    TransportAcceptCallback listen_callback_;
};

// ============================================================================
// 测试 1: TransportId 知名常量
// ============================================================================
static void test_well_known_transport_ids() {
    std::printf("[test] well-known transport ids...\n");

    CHECK(kTransportIdTest == 0x20);
    CHECK(kTransportIdMock == 0x21);
    CHECK(kTransportIdTor == 0x544F52);
    CHECK(kTransportIdBle == 0x424C45);
    CHECK(kTransportIdWifiDirect == 0x574952);
    CHECK(kTransportIdUserStart == 0x80);
}

// ============================================================================
// 测试 2: is_user_transport / is_reserved_transport
// ============================================================================
static void test_transport_id_ranges() {
    std::printf("[test] transport id ranges...\n");

    CHECK(is_reserved_transport(0x00) == true);
    CHECK(is_reserved_transport(0x01) == true);
    CHECK(is_reserved_transport(0x1F) == true);
    CHECK(is_reserved_transport(0x20) == false);  // Test
    CHECK(is_reserved_transport(kTransportIdMock) == false);
    CHECK(is_reserved_transport(kTransportIdTor) == false);

    CHECK(is_user_transport(0x7F) == false);
    CHECK(is_user_transport(0x80) == true);
    CHECK(is_user_transport(0x100) == true);
    CHECK(is_user_transport(kTransportIdTor) == false);
}

// ============================================================================
// 测试 3: well_known_transport_name
// ============================================================================
static void test_well_known_names() {
    std::printf("[test] well_known_transport_name...\n");

    CHECK(well_known_transport_name(kTransportIdTest) == "test");
    CHECK(well_known_transport_name(kTransportIdMock) == "mock");
    CHECK(well_known_transport_name(kTransportIdTor) == "tor");
    CHECK(well_known_transport_name(kTransportIdBle) == "ble");
    CHECK(well_known_transport_name(kTransportIdWifiDirect) == "wifi-direct");
    CHECK(well_known_transport_name(0x99) == "unknown");
}

// ============================================================================
// 测试 4: transport_id_to_hex / transport_id_from_hex 往返
// ============================================================================
static void test_transport_id_hex_roundtrip() {
    std::printf("[test] transport_id hex roundtrip...\n");

    struct Case { TransportId id; const char *hex; };
    Case cases[] = {
        {0x20,       "0x20"},
        {0x21,       "0x21"},
        {0x544F52,   "0x544F52"},
        {0x424C45,   "0x424C45"},
        {0x80,       "0x80"},
        {0x100,      "0x100"},
        {0xABCDEF,   "0xABCDEF"},
    };

    for (const auto &c : cases) {
        std::string h = transport_id_to_hex(c.id);
        auto parsed = transport_id_from_hex(c.hex);
        CHECK(parsed.has_value());
        CHECK(*parsed == c.id);
    }

    // 无前缀形式也可解析
    auto p1 = transport_id_from_hex("544F52");
    CHECK(p1.has_value());
    CHECK(*p1 == 0x544F52);

    auto p2 = transport_id_from_hex("20");
    CHECK(p2.has_value());
    CHECK(*p2 == 0x20);

    // 大写 0X 前缀
    auto p3 = transport_id_from_hex("0X544F52");
    CHECK(p3.has_value());
    CHECK(*p3 == 0x544F52);
}

// ============================================================================
// 测试 5: transport_id_from_hex 非法输入
// ============================================================================
static void test_transport_id_from_hex_invalid() {
    std::printf("[test] transport_id_from_hex invalid inputs...\n");

    CHECK(!transport_id_from_hex("").has_value());
    CHECK(!transport_id_from_hex("0x").has_value());
    CHECK(!transport_id_from_hex("xyz").has_value());
    CHECK(!transport_id_from_hex("0xGG").has_value());
    CHECK(!transport_id_from_hex("123456789").has_value());  // 超长（>8 hex digits）
}

// ============================================================================
// 测试 6: CustomTransportAddr 默认构造
// ============================================================================
static void test_addr_default() {
    std::printf("[test] CustomTransportAddr default...\n");

    CustomTransportAddr a;
    CHECK(a.transport_id == 0);
    CHECK(a.address_bytes.empty());
    CHECK(a.empty() == true);
}

// ============================================================================
// 测试 7: CustomTransportAddr from_hex
// ============================================================================
static void test_addr_from_hex() {
    std::printf("[test] CustomTransportAddr from_hex...\n");

    auto a = CustomTransportAddr::from_hex(kTransportIdTor, "deadbeef");
    CHECK(a.transport_id == kTransportIdTor);
    CHECK(a.address_bytes.size() == 4);
    CHECK(a.address_bytes[0] == 0xde);
    CHECK(a.address_bytes[1] == 0xad);
    CHECK(a.address_bytes[2] == 0xbe);
    CHECK(a.address_bytes[3] == 0xef);
    CHECK(a.empty() == false);
}

// ============================================================================
// 测试 8: CustomTransportAddr to_string / parse 往返
// ============================================================================
static void test_addr_string_roundtrip() {
    std::printf("[test] CustomTransportAddr to_string/parse roundtrip...\n");

    CustomTransportAddr a(kTransportIdTor, {0xde, 0xad, 0xbe, 0xef});
    std::string s = a.to_string();
    // transport_id_to_hex 使用小写 hex 输出
    CHECK(s.find("0x544f52") != std::string::npos);
    CHECK(s.find("deadbeef") != std::string::npos);

    auto parsed = CustomTransportAddr::parse(s);
    CHECK(parsed.has_value());
    CHECK(parsed->transport_id == kTransportIdTor);
    CHECK(parsed->address_bytes == a.address_bytes);
}

// ============================================================================
// 测试 9: CustomTransportAddr parse 非法输入
// ============================================================================
static void test_addr_parse_invalid() {
    std::printf("[test] CustomTransportAddr parse invalid...\n");

    CHECK(!CustomTransportAddr::parse("").has_value());
    CHECK(!CustomTransportAddr::parse("invalid").has_value());
    CHECK(!CustomTransportAddr::parse("0x20").has_value());  // 缺少冒号
    CHECK(!CustomTransportAddr::parse("xyz:deadbeef").has_value());  // 非法 id
    CHECK(!CustomTransportAddr::parse("0x20:xyz").has_value());  // 非法地址 hex
    CHECK(!CustomTransportAddr::parse("0x20:abc").has_value());  // 奇数 hex 长度
}

// ============================================================================
// 测试 10: CustomTransportAddr 空地址字符串
// ============================================================================
static void test_addr_empty_address() {
    std::printf("[test] CustomTransportAddr empty address...\n");

    // 空地址 hex 也是合法的
    auto a = CustomTransportAddr::parse("0x21:");
    CHECK(a.has_value());
    CHECK(a->transport_id == kTransportIdMock);
    CHECK(a->address_bytes.empty());

    std::string s = a->to_string();
    auto b = CustomTransportAddr::parse(s);
    CHECK(b.has_value());
    CHECK(b->transport_id == kTransportIdMock);
    CHECK(b->address_bytes.empty());
}

// ============================================================================
// 测试 11: CustomTransportAddr to_bytes / from_bytes 往返
// ============================================================================
static void test_addr_bytes_roundtrip() {
    std::printf("[test] CustomTransportAddr to_bytes/from_bytes roundtrip...\n");

    CustomTransportAddr a(kTransportIdTor, {0x01, 0x02, 0x03, 0x04, 0x05});
    auto bytes = a.to_bytes();

    // 长度应为 6 (header) + 5 (address) = 11
    CHECK(bytes.size() == 11);

    // transport_id 大端
    CHECK(bytes[0] == 0x00);
    CHECK(bytes[1] == 0x54);
    CHECK(bytes[2] == 0x4F);
    CHECK(bytes[3] == 0x52);

    // 长度大端
    CHECK(bytes[4] == 0x00);
    CHECK(bytes[5] == 0x05);

    auto parsed = CustomTransportAddr::from_bytes(bytes);
    CHECK(parsed.has_value());
    CHECK(parsed->transport_id == a.transport_id);
    CHECK(parsed->address_bytes == a.address_bytes);
}

// ============================================================================
// 测试 12: CustomTransportAddr from_bytes 长度不足
// ============================================================================
static void test_addr_from_bytes_short() {
    std::printf("[test] CustomTransportAddr from_bytes short input...\n");

    std::vector<std::uint8_t> empty;
    CHECK(!CustomTransportAddr::from_bytes(empty).has_value());

    std::vector<std::uint8_t> too_short = {0x00, 0x54};
    CHECK(!CustomTransportAddr::from_bytes(too_short).has_value());

    // 声明长度超过实际数据
    std::vector<std::uint8_t> truncated = {
        0x00, 0x54, 0x4F, 0x52,  // transport_id
        0x00, 0xFF,               // 长度 255
        0x01, 0x02, 0x03,         // 但只有 3 字节
    };
    CHECK(!CustomTransportAddr::from_bytes(truncated).has_value());
}

// ============================================================================
// 测试 13: TransportRegistry 注册与查找
// ============================================================================
static void test_registry_register_and_find() {
    std::printf("[test] registry register and find...\n");

    TransportRegistry registry;
    CHECK(registry.size() == 0);

    auto mock = std::make_shared<MockTransport>();
    mock->set_id(kTransportIdMock);
    mock->set_name("mock");

    bool ok = registry.register_transport(mock);
    CHECK(ok == true);
    CHECK(registry.size() == 1);

    auto found = registry.find(kTransportIdMock);
    CHECK(found != nullptr);
    CHECK(found.get() == mock.get());
    CHECK(found->id() == kTransportIdMock);
    CHECK(found->name() == "mock");
}

// ============================================================================
// 测试 14: TransportRegistry 重复注册返回 false
// ============================================================================
static void test_registry_duplicate_rejected() {
    std::printf("[test] registry duplicate rejected...\n");

    TransportRegistry registry;
    auto mock1 = std::make_shared<MockTransport>();
    mock1->set_id(kTransportIdMock);
    mock1->set_name("mock1");

    auto mock2 = std::make_shared<MockTransport>();
    mock2->set_id(kTransportIdMock);  // 相同 ID
    mock2->set_name("mock2");

    CHECK(registry.register_transport(mock1) == true);
    CHECK(registry.register_transport(mock2) == false);  // 拒绝重复
    CHECK(registry.size() == 1);

    // 第一个仍存在
    auto found = registry.find(kTransportIdMock);
    CHECK(found != nullptr);
    CHECK(found->name() == "mock1");
}

// ============================================================================
// 测试 15: TransportRegistry 保留 ID 拒绝注册
// ============================================================================
static void test_registry_reserved_id_rejected() {
    std::printf("[test] registry reserved id rejected...\n");

    TransportRegistry registry;
    auto t = std::make_shared<MockTransport>();
    t->set_id(0x00);  // 保留 ID
    t->set_name("reserved");

    CHECK(registry.register_transport(t) == false);
    CHECK(registry.size() == 0);

    auto t2 = std::make_shared<MockTransport>();
    t2->set_id(0x1F);  // 保留 ID 上限
    CHECK(registry.register_transport(t2) == false);
    CHECK(registry.size() == 0);
}

// ============================================================================
// 测试 16: TransportRegistry unregister
// ============================================================================
static void test_registry_unregister() {
    std::printf("[test] registry unregister...\n");

    TransportRegistry registry;
    auto mock = std::make_shared<MockTransport>();
    mock->set_id(kTransportIdMock);
    registry.register_transport(mock);

    CHECK(registry.unregister_transport(kTransportIdMock) == true);
    CHECK(registry.size() == 0);
    CHECK(registry.find(kTransportIdMock) == nullptr);

    // 重复注销返回 false
    CHECK(registry.unregister_transport(kTransportIdMock) == false);
}

// ============================================================================
// 测试 17: TransportRegistry registered_ids / registered_names
// ============================================================================
static void test_registry_ids_and_names() {
    std::printf("[test] registry ids and names...\n");

    TransportRegistry registry;

    auto t1 = std::make_shared<MockTransport>();
    t1->set_id(kTransportIdMock);
    t1->set_name("mock");
    registry.register_transport(t1);

    auto t2 = std::make_shared<MockTransport>();
    t2->set_id(kTransportIdTor);
    t2->set_name("tor");
    registry.register_transport(t2);

    auto t3 = std::make_shared<MockTransport>();
    t3->set_id(0x100);
    t3->set_name("custom1");
    registry.register_transport(t3);

    CHECK(registry.size() == 3);

    auto ids = registry.registered_ids();
    CHECK(ids.size() == 3);

    auto names = registry.registered_names();
    CHECK(names.size() == 3);

    // 检查所有名称都在
    bool has_mock = false, has_tor = false, has_custom = false;
    for (const auto &n : names) {
        if (n == "mock") has_mock = true;
        if (n == "tor") has_tor = true;
        if (n == "custom1") has_custom = true;
    }
    CHECK(has_mock);
    CHECK(has_tor);
    CHECK(has_custom);
}

// ============================================================================
// 测试 18: TransportRegistry clear
// ============================================================================
static void test_registry_clear() {
    std::printf("[test] registry clear...\n");

    TransportRegistry registry;
    auto t = std::make_shared<MockTransport>();
    t->set_id(kTransportIdMock);
    registry.register_transport(t);
    CHECK(registry.size() == 1);

    registry.clear();
    CHECK(registry.size() == 0);
    CHECK(registry.find(kTransportIdMock) == nullptr);
}

// ============================================================================
// 测试 19: TransportRegistry find_for_address
// ============================================================================
static void test_registry_find_for_address() {
    std::printf("[test] registry find_for_address...\n");

    TransportRegistry registry;
    auto mock = std::make_shared<MockTransport>();
    mock->set_id(kTransportIdMock);
    registry.register_transport(mock);

    CustomTransportAddr addr(kTransportIdMock, {0x01, 0x02});
    auto found = registry.find_for_address(addr);
    CHECK(found != nullptr);
    CHECK(found->id() == kTransportIdMock);

    // 地址不匹配的传输 ID
    CustomTransportAddr addr2(kTransportIdTor, {0x03});
    auto not_found = registry.find_for_address(addr2);
    CHECK(not_found == nullptr);
}

// ============================================================================
// 测试 20: EndpointAddr with custom_addrs
// ============================================================================
static void test_endpoint_addr_custom_addrs() {
    std::printf("[test] EndpointAddr custom_addrs...\n");

    EndpointAddr ea;
    CHECK(ea.has_custom() == false);

    CustomTransportAddr addr1(kTransportIdTor, {0xde, 0xad});
    CustomTransportAddr addr2(kTransportIdBle, {0xbe, 0xef});
    ea.add_custom_addr(addr1);
    ea.add_custom_addr(addr2);

    CHECK(ea.has_custom() == true);
    CHECK(ea.custom_addrs().size() == 2);
    CHECK(ea.custom_addrs()[0].transport_id == kTransportIdTor);
    CHECK(ea.custom_addrs()[1].transport_id == kTransportIdBle);
}

// ============================================================================
// 测试 21: MockTransport connect 基础
// ============================================================================
static void test_mock_transport_connect() {
    std::printf("[test] mock transport connect...\n");

    MockTransport t;
    t.set_id(kTransportIdMock);
    t.set_connect_should_fail(false);

    CustomTransportAddr addr(kTransportIdMock, {0x01});
    auto conn = t.connect(addr, std::chrono::milliseconds(100));
    CHECK(conn != nullptr);
    CHECK(t.connect_count() == 1);
}

// ============================================================================
// 测试 22: MockTransport connect 失败
// ============================================================================
static void test_mock_transport_connect_fail() {
    std::printf("[test] mock transport connect fail...\n");

    MockTransport t;
    t.set_id(kTransportIdMock);
    t.set_connect_should_fail(true);

    CustomTransportAddr addr(kTransportIdMock, {0x01});
    auto conn = t.connect(addr, std::chrono::milliseconds(100));
    CHECK(conn == nullptr);
    CHECK(t.connect_count() == 1);
}

// ============================================================================
// 测试 23: MockTransport listen / simulate_accept
// ============================================================================
static void test_mock_transport_listen() {
    std::printf("[test] mock transport listen...\n");

    MockTransport t;
    t.set_id(kTransportIdMock);

    CustomTransportAddr bind_addr(kTransportIdMock, {0x00});
    std::atomic<bool> accepted{false};
    std::atomic<int> received_id{0};

    bool ok = t.listen(bind_addr, [&](TransportConnHandle conn,
                                       const CustomTransportAddr &from) {
        if (conn) {
            accepted = true;
            received_id = from.transport_id;
        }
    });

    CHECK(ok == true);
    CHECK(t.is_listening() == true);

    // 模拟收到一个连接
    auto fake_conn = std::make_shared<int>(42);
    CustomTransportAddr from_addr(kTransportIdMock, {0xAB, 0xCD});
    t.simulate_accept(fake_conn, from_addr);

    CHECK(accepted.load() == true);
    CHECK(received_id.load() == static_cast<int>(kTransportIdMock));

    t.stop_listen();
    CHECK(t.is_listening() == false);
}

// ============================================================================
// 测试 24: TransportRegistry try_connect_concurrent - 单个传输成功
// ============================================================================
static void test_registry_concurrent_connect_single() {
    std::printf("[test] registry concurrent connect single...\n");

    TransportRegistry registry;
    auto mock = std::make_shared<MockTransport>();
    mock->set_id(kTransportIdMock);
    mock->set_connect_should_fail(false);
    registry.register_transport(mock);

    CustomTransportAddr addr(kTransportIdMock, {0x01});
    auto conn = registry.try_connect_concurrent(
        {kTransportIdMock}, addr, std::chrono::milliseconds(500));

    CHECK(conn != nullptr);
    CHECK(mock->connect_count() == 1);
}

// ============================================================================
// 测试 25: TransportRegistry try_connect_concurrent - 多传输，第一个成功
// ============================================================================
static void test_registry_concurrent_connect_multi_success() {
    std::printf("[test] registry concurrent connect multi success...\n");

    TransportRegistry registry;

    auto t1 = std::make_shared<MockTransport>();
    t1->set_id(kTransportIdMock);
    t1->set_connect_should_fail(true);  // 失败
    t1->set_connect_delay_ms(0);
    registry.register_transport(t1);

    auto t2 = std::make_shared<MockTransport>();
    t2->set_id(0x100);
    t2->set_connect_should_fail(false);  // 成功
    t2->set_connect_delay_ms(10);
    registry.register_transport(t2);

    // 注意：address_bytes 与 transport_id 对应
    CustomTransportAddr addr(0x100, {0x01});
    auto conn = registry.try_connect_concurrent(
        {kTransportIdMock, 0x100}, addr, std::chrono::milliseconds(500));

    // 由于 t1 失败、t2 成功，最终应得到 t2 的连接
    CHECK(conn != nullptr);
}

// ============================================================================
// 测试 26: TransportRegistry try_connect_concurrent - 全部失败
// ============================================================================
static void test_registry_concurrent_connect_all_fail() {
    std::printf("[test] registry concurrent connect all fail...\n");

    TransportRegistry registry;

    auto t1 = std::make_shared<MockTransport>();
    t1->set_id(kTransportIdMock);
    t1->set_connect_should_fail(true);
    registry.register_transport(t1);

    auto t2 = std::make_shared<MockTransport>();
    t2->set_id(0x100);
    t2->set_connect_should_fail(true);
    registry.register_transport(t2);

    CustomTransportAddr addr(kTransportIdMock, {0x01});
    auto conn = registry.try_connect_concurrent(
        {kTransportIdMock, 0x100}, addr, std::chrono::milliseconds(500));

    CHECK(conn == nullptr);
}

// ============================================================================
// 测试 27: TransportRegistry try_connect_concurrent - 空候选列表
// ============================================================================
static void test_registry_concurrent_connect_empty() {
    std::printf("[test] registry concurrent connect empty...\n");

    TransportRegistry registry;
    CustomTransportAddr addr(kTransportIdMock, {0x01});
    auto conn = registry.try_connect_concurrent({}, addr, std::chrono::milliseconds(100));
    CHECK(conn == nullptr);
}

// ============================================================================
// 测试 28: TransportRegistry try_connect_concurrent - 候选 ID 未注册
// ============================================================================
static void test_registry_concurrent_connect_unregistered() {
    std::printf("[test] registry concurrent connect unregistered...\n");

    TransportRegistry registry;
    CustomTransportAddr addr(0x999, {0x01});
    auto conn = registry.try_connect_concurrent({0x999}, addr, std::chrono::milliseconds(100));
    CHECK(conn == nullptr);
}

// ============================================================================
// 测试 29: CustomTransport 接口 supports_address
// ============================================================================
static void test_supports_address() {
    std::printf("[test] supports_address...\n");

    MockTransport t;
    t.set_id(kTransportIdMock);

    CustomTransportAddr addr1(kTransportIdMock, {0x01});
    CustomTransportAddr addr2(kTransportIdTor, {0x02});

    CHECK(t.supports_address(addr1) == true);
    CHECK(t.supports_address(addr2) == false);
}

// ============================================================================
// 测试 30: CustomTransport is_ready
// ============================================================================
static void test_is_ready() {
    std::printf("[test] is_ready...\n");

    MockTransport t;
    CHECK(t.is_ready() == true);

    t.set_ready(false);
    CHECK(t.is_ready() == false);

    t.set_ready(true);
    CHECK(t.is_ready() == true);
}

// ============================================================================
// 测试 31: CustomTransportAddr 比较
// ============================================================================
static void test_addr_comparison() {
    std::printf("[test] CustomTransportAddr comparison...\n");

    CustomTransportAddr a1(kTransportIdMock, {0x01, 0x02});
    CustomTransportAddr a2(kTransportIdMock, {0x01, 0x02});
    CustomTransportAddr a3(kTransportIdTor, {0x01, 0x02});
    CustomTransportAddr a4(kTransportIdMock, {0x03});

    CHECK(a1 == a2);
    CHECK(a1 != a3);
    CHECK(a1 != a4);
}

// ============================================================================
// 测试 32: EndpointAddr 整合 - 多种地址类型共存
// ============================================================================
static void test_endpoint_addr_mixed() {
    std::printf("[test] EndpointAddr mixed addresses...\n");

    EndpointAddr ea;

    // 直连
    TransportAddr direct;
    direct.kind = TransportKind::Ip;
    direct.host = "1.2.3.4";
    direct.port = 9999;
    ea.add_direct_address(direct);

    // Relay
    ea.add_relay(RelayUrl("https://relay.example.com/"));

    // 自定义
    ea.add_custom_addr(CustomTransportAddr(kTransportIdTor, {0x01, 0x02}));

    CHECK(ea.has_direct() == true);
    CHECK(ea.has_relay() == true);
    CHECK(ea.has_custom() == true);
    CHECK(ea.direct_addresses().size() == 1);
    CHECK(ea.relays().size() == 1);
    CHECK(ea.custom_addrs().size() == 1);
}

// ============================================================================
// 测试 33: TransportRegistry 多传输同时注册（验证并发安全）
// ============================================================================
static void test_registry_concurrent_register() {
    std::printf("[test] registry concurrent register...\n");

    TransportRegistry registry;
    constexpr int N = 10;
    std::vector<std::thread> threads;

    for (int i = 0; i < N; ++i) {
        threads.emplace_back([&registry, i]() {
            auto t = std::make_shared<MockTransport>();
            t->set_id(static_cast<TransportId>(0x100 + i));
            t->set_name("t" + std::to_string(i));
            registry.register_transport(t);
        });
    }

    for (auto &th : threads) th.join();

    CHECK(registry.size() == N);
    auto ids = registry.registered_ids();
    CHECK(ids.size() == N);
}

// ============================================================================
// 主函数
// ============================================================================
int main() {
    std::printf("=== test_custom_transport ===\n");

    test_well_known_transport_ids();
    test_transport_id_ranges();
    test_well_known_names();
    test_transport_id_hex_roundtrip();
    test_transport_id_from_hex_invalid();

    test_addr_default();
    test_addr_from_hex();
    test_addr_string_roundtrip();
    test_addr_parse_invalid();
    test_addr_empty_address();
    test_addr_bytes_roundtrip();
    test_addr_from_bytes_short();
    test_addr_comparison();

    test_registry_register_and_find();
    test_registry_duplicate_rejected();
    test_registry_reserved_id_rejected();
    test_registry_unregister();
    test_registry_ids_and_names();
    test_registry_clear();
    test_registry_find_for_address();
    test_registry_concurrent_register();

    test_endpoint_addr_custom_addrs();
    test_endpoint_addr_mixed();

    test_mock_transport_connect();
    test_mock_transport_connect_fail();
    test_mock_transport_listen();
    test_supports_address();
    test_is_ready();

    test_registry_concurrent_connect_single();
    test_registry_concurrent_connect_multi_success();
    test_registry_concurrent_connect_all_fail();
    test_registry_concurrent_connect_empty();
    test_registry_concurrent_connect_unregistered();

    std::printf("\n=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
