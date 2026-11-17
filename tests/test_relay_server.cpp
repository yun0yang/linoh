// test_relay_server.cpp — Self-hosted Relay Server end-to-end test
//
// Uses a REAL Winsock-based relay client (not relay::Client, whose socket
// layer currently sits on the compile-only `linoh_asio` stub). The test client
// reuses the exact same wire-codec (ws_client.hpp / stride.hpp / auth.hpp) that
// relay::Client uses, so it validates the real relay protocol end-to-end:
//   TCP -> HTTP Upgrade -> auth handshake -> datagram forwarding.

#include <winsock2.h>
#include <ws2tcpip.h>

#include "linoh/relay/server.hpp"
#include "linoh/relay/tls_channel.hpp"
#ifdef LINOH_RELAY_TLS
#include "relay_test_cert.inc"  // kTestCertPem / kTestKeyPem (self-signed)
#endif
#include "linoh/relay/ws_client.hpp"
#include "linoh/relay/stride.hpp"
#include "linoh/relay/auth.hpp"
#include "linoh/base/key.hpp"
#include "linoh/base/endpoint_addr.hpp"
#include "linoh/util/varint.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace linoh;
using namespace linoh::relay;
using namespace linoh::base;

#define TEST(name) do { printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { printf("PASSED\n"); return 0; } while (0)
#define FAIL(msg) do { printf("FAILED: %s\n", msg); return 1; } while(0)

// ─── Real Winsock relay client (test harness) ───

class TestRelayClient {
public:
    TestRelayClient(SecretKey sk, std::string host, unsigned short port,
                    bool tamper = false, bool use_tls = false)
        : sk_(std::move(sk)), host_(std::move(host)), port_(port),
          id_(sk_.public_key()), tamper_(tamper), use_tls_(use_tls) {}

    ~TestRelayClient() { disconnect(); }

    bool connect() {
        if (sk_.is_zero()) return false;  // client policy: need a key
        sock_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock_ == INVALID_SOCKET) return false;
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(host_.c_str());
        addr.sin_port = htons(port_);
        if (::connect(sock_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
            return false;
        if (use_tls_) {
            std::string terr;
            auto t = TlsChannel::connect(sock_, host_,
                                         /*insecure_skip_verify=*/true, &terr);
            if (!t) {
                fprintf(stderr, "TestRelayClient: TLS connect failed: %s\n",
                        terr.c_str());
                return false;
            }
            tls_ = t;
        }
        if (!ws_handshake()) return false;
        if (!auth_handshake()) return false;
        connected_ = true;
        read_thread_ = std::thread([this] { read_loop(); });
        return true;
    }

    std::size_t send_via(const EndpointId &dst, std::span<const uint8_t> payload) {
        if (!connected_ || payload.empty()) return 0;
        Datagram dg;
        dg.dst = dst;
        dg.ecn = EcnCodepoint::None;
        dg.contents.assign(payload.begin(), payload.end());
        auto frame = encode_client_to_relay_datagram(dg);
        auto ws = ws_encode_binary_frame(frame);  // masked (client frame)
        return send_all(ws) ? payload.size() : 0;
    }

    void set_handler(std::function<void(EndpointId, std::vector<uint8_t>)> h) {
        handler_ = std::move(h);
    }

    bool is_connected() const { return connected_; }
    const EndpointId &id() const { return id_; }

    void disconnect() {
        connected_ = false;
        if (sock_ != INVALID_SOCKET) {
            ::closesocket(sock_);
            sock_ = INVALID_SOCKET;
        }
        if (read_thread_.joinable()) read_thread_.join();
        tls_.reset();
    }

private:
    bool ws_handshake() {
        std::string req = ws_build_handshake_request(host_, "/",
                                                    std::to_string(port_));
        if (!send_all(std::span<const uint8_t>(
                reinterpret_cast<const uint8_t *>(req.data()), req.size())))
            return false;

        // Read into the shared read_buf_ (which may also contain trailing
        // WebSocket frames such as the ServerChallenge) until we see the end
        // of the HTTP headers. Do NOT discard bytes past the header end.
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(5);
        while (true) {
            auto hend = ws_http_header_end(
                std::span<const uint8_t>(read_buf_.data(), read_buf_.size()));
            if (hend > 0) {
                bool ok = ws_validate_handshake_response(
                    std::span<const uint8_t>(read_buf_.data(), hend));
                // Strip the HTTP header bytes. Any bytes past the header are
                // WebSocket frames (e.g. the ServerChallenge) and must remain
                // in read_buf_ for the auth handshake to decode.
                read_buf_.erase(
                    read_buf_.begin(),
                    read_buf_.begin() + static_cast<std::ptrdiff_t>(hend));
                return ok;
            }
            if (std::chrono::steady_clock::now() > deadline) return false;
            int n = recv_more(1000);
            if (n < 0) return false;
        }
    }

    bool auth_handshake() {
        WsFrame f;
        while (next_ws_frame(f)) {
            if (f.opcode == WsOpcode::Binary) {
                auto stride = decode_frame(f.payload);
                if (stride && stride->type == FrameType::ServerChallenge) {
                    auto ch = decode_server_challenge(stride->payload);
                    if (!ch) return false;
                    auto ca = sign_challenge(*ch, sk_);
                    if (tamper_) ca.signature = Signature{};  // invalid sig
                    auto auth_frame = encode_client_auth(ca);
                    auto ws = ws_encode_binary_frame(auth_frame);
                    if (!send_all(ws)) return false;
                    // Wait for confirmation.
                    while (next_ws_frame(f)) {
                        if (f.opcode == WsOpcode::Binary) {
                            auto s2 = decode_frame(f.payload);
                            if (s2 &&
                                s2->type == FrameType::ServerConfirmsAuth)
                                return true;
                            if (s2 &&
                                s2->type == FrameType::ServerDeniesAuth)
                                return false;
                        } else if (f.opcode == WsOpcode::Close) {
                            return false;
                        }
                    }
                    return false;
                }
            } else if (f.opcode == WsOpcode::Close) {
                return false;
            }
        }
        return false;
    }

    void read_loop() {
        WsFrame f;
        while (connected_ && next_ws_frame(f)) {
            if (f.opcode == WsOpcode::Binary) {
                auto stride = decode_frame(f.payload);
                if (stride && stride->type == FrameType::RelayToClientDatagram) {
                    auto dg = decode_datagram(stride->payload);
                    if (dg && handler_)
                        handler_(dg->dst, dg->contents);  // dg->dst is the source
                }
            } else if (f.opcode == WsOpcode::Ping) {
                auto pong = ws_encode_pong_frame(f.payload);
                send_all(pong);
            } else if (f.opcode == WsOpcode::Close) {
                break;
            }
        }
        connected_ = false;
    }

    // ── socket helpers ──

    bool send_all(std::span<const uint8_t> data) {
        if (tls_) return tls_->write(data.data(), data.size());
        std::size_t off = 0;
        while (off < data.size()) {
            int n = ::send(sock_,
                           reinterpret_cast<const char *>(data.data() + off),
                           static_cast<int>(data.size() - off), 0);
            if (n <= 0) return false;
            off += static_cast<std::size_t>(n);
        }
        return true;
    }

    int recv_more(int timeout_ms) {
        if (tls_) {
            uint8_t tmp[4096];
            int n = tls_->read(tmp, sizeof(tmp), timeout_ms);
            if (n > 0) {
                read_buf_.insert(read_buf_.end(), tmp, tmp + n);
                return n;
            }
            if (n == -2) return 0;  // timeout, keep polling
            return -1;              // close or error
        }
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock_, &fds);
        timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        int r = ::select(static_cast<int>(sock_) + 1, &fds, nullptr, nullptr, &tv);
        if (r <= 0) return 0;
        uint8_t tmp[4096];
        int n = ::recv(sock_, reinterpret_cast<char *>(tmp), sizeof(tmp), 0);
        if (n <= 0) return -1;
        read_buf_.insert(read_buf_.end(), tmp, tmp + n);
        return n;
    }

    bool next_ws_frame(WsFrame &out) {
        while (true) {
            auto dec = ws_decode_frame(
                std::span<const uint8_t>(read_buf_.data(), read_buf_.size()));
            if (dec.invalid) {
                // C8: 非法帧，关闭连接
                return false;
            }
            if (dec.ok) {
                out = dec.frame;
                read_buf_.erase(read_buf_.begin(),
                                read_buf_.begin() +
                                    static_cast<std::ptrdiff_t>(dec.bytes_consumed));
                return true;
            }
            // need_more: 继续接收数据
            int n = recv_more(2000);
            if (n <= 0) return false;
        }
    }

    SecretKey sk_;
    std::string host_;
    unsigned short port_;
    EndpointId id_;
    bool tamper_;
    bool use_tls_{false};
    std::shared_ptr<TlsChannel> tls_;
    SOCKET sock_{INVALID_SOCKET};
    std::atomic<bool> connected_{false};
    std::vector<uint8_t> read_buf_;
    std::thread read_thread_;
    std::function<void(EndpointId, std::vector<uint8_t>)> handler_;
};

// ─── Test 1: A -> B forwarding ───

int test_relay_forwarding() {
    TEST("Relay server forwards datagram A -> B (correct source + payload)");
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) FAIL("WSAStartup failed");

    RelayServer server(0);
    if (!server.start()) FAIL("server start failed");
    unsigned short port = server.local_port();
    if (port == 0) FAIL("server bound to port 0");

    auto skA = SecretKey::generate();
    auto skB = SecretKey::generate();
    EndpointId idA = skA.public_key();
    EndpointId idB = skB.public_key();

    TestRelayClient clientA(skA, "127.0.0.1", port);
    TestRelayClient clientB(skB, "127.0.0.1", port);

    std::mutex m;
    std::vector<uint8_t> received;
    EndpointId from;
    bool got = false;
    clientB.set_handler([&](EndpointId f, std::vector<uint8_t> b) {
        std::lock_guard<std::mutex> lk(m);
        from = f;
        received = std::move(b);
        got = true;
    });
    clientA.set_handler([](EndpointId, std::vector<uint8_t>) {});

    if (!clientA.connect()) FAIL("clientA connect failed");
    if (!clientB.connect()) FAIL("clientB connect failed");
    if (server.registered_count() != 2) FAIL("server should have 2 registered");

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::string msg = "hello relay";
    std::vector<uint8_t> payload(msg.begin(), msg.end());
    std::size_t sent = clientA.send_via(idB, payload);
    if (sent != payload.size()) FAIL("send_via returned wrong size");

    bool delivered = false;
    for (int i = 0; i < 200; i++) {
        { std::lock_guard<std::mutex> lk(m); if (got) delivered = true; }
        if (delivered) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!delivered) FAIL("datagram not delivered to B");

    {
        std::lock_guard<std::mutex> lk(m);
        if (from != idA) FAIL("source id mismatch (should be A)");
        if (received.size() != payload.size()) FAIL("payload size mismatch");
        if (std::memcmp(received.data(), payload.data(), payload.size()) != 0)
            FAIL("payload content mismatch");
    }

    clientA.disconnect();
    clientB.disconnect();
    server.stop();
    WSACleanup();
    PASS();
}

// ─── Test 2: server rejects a bad signature ───

int test_relay_rejects_bad_signature() {
    TEST("Relay server rejects client with invalid signature");

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) FAIL("WSAStartup failed");

    RelayServer server(0);
    if (!server.start()) FAIL("server start failed");
    unsigned short port = server.local_port();

    // tamper=true -> sends an all-zero signature, which must be denied.
    auto sk = SecretKey::generate();
    TestRelayClient client(sk, "127.0.0.1", port, /*tamper=*/true);
    client.set_handler([](EndpointId, std::vector<uint8_t>) {});

    bool ok = client.connect();
    if (ok) FAIL("client with bad signature should be rejected");

    if (server.registered_count() != 0) FAIL("bad-signature client must not register");

    server.stop();
    WSACleanup();
    PASS();
}

// ─── Test 3: unknown destination -> dropped, no crash ───

int test_relay_unknown_destination() {
    TEST("Relay server drops datagram to unknown destination (no crash)");

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) FAIL("WSAStartup failed");

    RelayServer server(0);
    if (!server.start()) FAIL("server start failed");
    unsigned short port = server.local_port();

    auto skA = SecretKey::generate();
    TestRelayClient clientA(skA, "127.0.0.1", port);
    std::atomic<bool> got{false};
    clientA.set_handler([&](EndpointId, std::vector<uint8_t>) { got.store(true); });

    if (!clientA.connect()) FAIL("clientA connect failed");
    if (!clientA.is_connected()) FAIL("clientA not connected");

    EndpointId ghost = SecretKey::generate().public_key();
    std::vector<uint8_t> payload = {'x'};
    std::size_t sent = clientA.send_via(ghost, payload);
    if (sent != payload.size()) FAIL("send_via should report bytes sent");

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (!clientA.is_connected()) FAIL("client disconnected after unknown dst");
    if (got.load()) FAIL("should not receive anything for unknown dst");

    clientA.disconnect();
    server.stop();
    WSACleanup();
    PASS();
}

// ─── Test 4 (TLS build only): wss:// roundtrip A -> B ───

#ifdef LINOH_RELAY_TLS
int test_relay_wss_roundtrip() {
    TEST("Relay server wss:// (TLS) forwards datagram A -> B");
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) FAIL("WSAStartup failed");

    RelayServer server(0);
    server.set_tls(kTestCertPem, kTestKeyPem);
    server.set_tls_enabled(true);
    if (!server.start()) FAIL("server start failed");
    unsigned short port = server.local_port();
    if (port == 0) FAIL("server bound to port 0");

    auto skA = SecretKey::generate();
    auto skB = SecretKey::generate();
    EndpointId idA = skA.public_key();
    EndpointId idB = skB.public_key();

    TestRelayClient clientA(skA, "127.0.0.1", port, false, /*use_tls=*/true);
    TestRelayClient clientB(skB, "127.0.0.1", port, false, /*use_tls=*/true);

    std::mutex m;
    std::vector<uint8_t> received;
    EndpointId from;
    bool got = false;
    clientB.set_handler([&](EndpointId f, std::vector<uint8_t> b) {
        std::lock_guard<std::mutex> lk(m);
        from = f;
        received = std::move(b);
        got = true;
    });
    clientA.set_handler([](EndpointId, std::vector<uint8_t>) {});

    if (!clientA.connect()) FAIL("clientA (wss) connect failed");
    if (!clientB.connect()) FAIL("clientB (wss) connect failed");
    if (server.registered_count() != 2) FAIL("server should have 2 registered");

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::string msg = "hello over tls";
    std::vector<uint8_t> payload(msg.begin(), msg.end());
    std::size_t sent = clientA.send_via(idB, payload);
    if (sent != payload.size()) FAIL("send_via returned wrong size");

    bool delivered = false;
    for (int i = 0; i < 200; i++) {
        { std::lock_guard<std::mutex> lk(m); if (got) delivered = true; }
        if (delivered) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!delivered) FAIL("datagram not delivered over wss");

    {
        std::lock_guard<std::mutex> lk(m);
        if (from != idA) FAIL("source id mismatch (should be A)");
        if (received.size() != payload.size()) FAIL("payload size mismatch");
        if (std::memcmp(received.data(), payload.data(), payload.size()) != 0)
            FAIL("payload content mismatch");
    }

    clientA.disconnect();
    clientB.disconnect();
    server.stop();
    WSACleanup();
    PASS();
}

int test_relay_wss_rejects_plaintext() {
    TEST("Relay server wss:// rejects plaintext (non-TLS) client");
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) FAIL("WSAStartup failed");

    RelayServer server(0);
    server.set_tls(kTestCertPem, kTestKeyPem);
    server.set_tls_enabled(true);
    if (!server.start()) FAIL("server start failed");
    unsigned short port = server.local_port();

    // Plaintext client: TCP connects, but the server performs a TLS accept
    // first. The client's raw WS bytes are not a TLS ClientHello, so the
    // server's TLS accept fails and the connection is closed.
    auto sk = SecretKey::generate();
    TestRelayClient client(sk, "127.0.0.1", port, false, /*use_tls=*/false);
    client.set_handler([](EndpointId, std::vector<uint8_t>) {});

    bool ok = client.connect();
    if (ok) FAIL("plaintext client should be rejected by wss server");

    if (server.registered_count() != 0)
        FAIL("plaintext client must not register");

    server.stop();
    WSACleanup();
    PASS();
}
#endif  // LINOH_RELAY_TLS

// ─── Main ───

int run_tests() {
    int failures = 0;
    int total = 3;
    failures += test_relay_forwarding();
    failures += test_relay_rejects_bad_signature();
    failures += test_relay_unknown_destination();
#ifdef LINOH_RELAY_TLS
    total += 2;
    failures += test_relay_wss_roundtrip();
    failures += test_relay_wss_rejects_plaintext();
#endif
    printf("\n=== Results: %d PASSED, %d FAILED ===\n", total - failures,
           failures);
    return failures;
}

int main() {
    printf("=== Relay Server Tests ===\n\n");
    int failures = run_tests();
    return failures;
}
