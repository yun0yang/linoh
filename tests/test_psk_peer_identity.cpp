// v5.1.0: PSK_IDENTITY 帧（K-LINOH-PEERMISMATCH 根治）测试
//
// 覆盖五类断言：
//   1. 帧 encode/decode round-trip + parse_frames 识别（末帧 rest-of-payload）
//   2. 1-RTT 路径双向认证：双方 force PSK 后身份帧随包交换，peer_id_ = 对端公钥
//   3. Initial 路径认证：身份帧附在 Initial 包尾（C-API outbound 生产路径）
//   4. 伪造签名拒绝：验签失败时 peer_id_ 保持旧行为、不置 authenticated
//   5. 超窗时间戳拒绝（防跨时段重放）+ 老对端兼容（无身份帧照常 Established）
//   6. L3: 0-RTT resume ticket 构造时 peer_id_ = ticket.peer_node_id
#include "linoh/base/key.hpp"
#include "linoh/endpoint/connection.hpp"
#include "linoh/endpoint/state_machine.hpp"
#include "linoh/protocol/packet.hpp"
#include "linoh/util/bytes.hpp"

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <vector>

static int g_pass = 0, g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  [PASS] %s\n", msg); g_pass++; } \
    else { printf("  [FAIL] %s\n", msg); g_fail++; } \
} while (0)

using namespace linoh;
using namespace linoh::endpoint;

static Connection::Config make_cfg(const base::SecretKey &sk, Direction dir,
                                   const protocol::ConnectionId &local,
                                   const protocol::ConnectionId &remote) {
    Connection::Config cfg;
    cfg.secret_key = sk;
    cfg.local_cid = local;
    cfg.remote_cid = remote;
    cfg.direction = dir;
    cfg.alpn = "ctrl/1";
    cfg.handshake.psk_mode = true;  // 生产同款 PSK 模式
    return cfg;
}

// 构造与 linoh_c.cpp 生产路径一致的 Initial 线包：头 + 可选身份帧（包尾）
static std::vector<std::uint8_t> build_initial_wire(
    const protocol::ConnectionId &dcid, const protocol::ConnectionId &scid,
    const std::vector<std::uint8_t> *identity_body /*= nullptr*/) {
    auto hdr = protocol::PacketHeader::make_initial(dcid, scid);
    std::vector<std::uint8_t> wire(512);
    std::size_t n = hdr.serialize_to(wire.data(), wire.size());
    wire.resize(n);
    if (identity_body) {
        wire.push_back(static_cast<std::uint8_t>(protocol::FrameType::PSK_IDENTITY));
        wire.insert(wire.end(), identity_body->begin(), identity_body->end());
    }
    return wire;
}

// 用指定密钥构造一个合法身份帧体（不含 type 字节）
static std::vector<std::uint8_t> make_identity_body(const base::SecretKey &sk,
                                                    std::int64_t ts_offset_sec = 0) {
    protocol::PskIdentityFrame f;
    f.caps = protocol::PskIdentityFrame::kCapIdentity;
    f.created_at_unix = static_cast<std::uint64_t>(
        static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()) +
        ts_offset_sec);
    auto pub = sk.public_key();
    std::memcpy(f.node_pub.data(), pub.data(), pub.size());
    auto msg = protocol::psk_identity_signed_content(f);
    auto sig = sk.sign(std::span<const std::uint8_t>(msg.data(), msg.size()));
    std::memcpy(f.signature.data(), sig.data(), sig.size());
    return protocol::encode_psk_identity_frame(f);
}

static void test_frame_codec() {
    printf("\n=== 1. PSK_IDENTITY 帧 codec + parse_frames ===\n");
    auto sk = base::SecretKey::generate();
    auto body = make_identity_body(sk);
    CHECK(body.size() == protocol::PskIdentityFrame::kBodyBytes,
          "body size == 107");

    auto decoded = protocol::decode_psk_identity_frame(
        std::span<const std::uint8_t>(body.data(), body.size()));
    CHECK(decoded.has_value(), "decode ok");
    auto pub = sk.public_key();
    CHECK(decoded && std::memcmp(decoded->node_pub.data(), pub.data(), 32) == 0,
          "node_pub round-trip");
    CHECK(decoded && (decoded->caps & protocol::PskIdentityFrame::kCapIdentity),
          "caps bit0 set");

    // parse_frames 识别（身份帧作为 payload 最后一个帧）
    std::vector<std::uint8_t> payload;
    payload.push_back(static_cast<std::uint8_t>(protocol::FrameType::PING));
    payload.push_back(static_cast<std::uint8_t>(protocol::FrameType::PSK_IDENTITY));
    payload.insert(payload.end(), body.begin(), body.end());
    auto frames = protocol::PacketParser::parse_frames(
        std::span<const std::uint8_t>(payload.data(), payload.size()));
    bool found = false;
    for (auto &f : frames) {
        if (f.type == protocol::FrameType::PSK_IDENTITY) {
            found = f.data.size() == body.size();
        }
    }
    CHECK(found, "parse_frames yields PSK_IDENTITY with full body");

    // 签名内容稳定性（同输入同输出，验证/签名两侧共用）
    auto f2 = *decoded;
    auto c1 = protocol::psk_identity_signed_content(*decoded);
    auto c2 = protocol::psk_identity_signed_content(f2);
    CHECK(c1 == c2, "signed_content deterministic");
}

static void test_identity_via_1rtt() {
    printf("\n=== 2. 1-RTT 路径双向认证 ===\n");
    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    auto client = std::make_shared<Connection>(make_cfg(
        c_sk, Direction::Outbound,
        protocol::ConnectionId::generate(), protocol::ConnectionId()));
    auto server = std::make_shared<Connection>(make_cfg(
        s_sk, Direction::Inbound,
        protocol::ConnectionId::generate(), protocol::ConnectionId()));

    // 生产同款：两侧 force PSK Established + 标记身份帧待发
    client->force_psk_established();
    server->force_psk_established();
    client->send_psk_identity();
    server->send_psk_identity();

    // client -> server：首个 1-RTT 包尾带身份帧
    std::vector<std::uint8_t> pkt(2048);
    auto n = client->build_1rtt_packet(std::span<std::uint8_t>(pkt.data(), pkt.size()));
    CHECK(n > 0, "client built 1-RTT packet with identity");
    auto pre_default = server->peer_id();  // 旧默认（本端公钥）
    server->handle_packet(util::Bytes(std::span<const std::uint8_t>(pkt.data(), n)));
    CHECK(server->peer_authenticated(), "server peer_authenticated after 1-RTT");
    CHECK(server->peer_id() == c_sk.public_key(),
          "server peer_id == client pubkey");
    CHECK(!(server->peer_id() == pre_default) || pre_default == c_sk.public_key(),
          "peer_id upgraded from default");

    // server -> client：回包带身份帧
    std::vector<std::uint8_t> pkt2(2048);
    auto n2 = server->build_1rtt_packet(std::span<std::uint8_t>(pkt2.data(), pkt2.size()));
    CHECK(n2 > 0, "server built 1-RTT packet with identity");
    client->handle_packet(util::Bytes(std::span<const std::uint8_t>(pkt2.data(), n2)));
    CHECK(client->peer_authenticated(), "client peer_authenticated");
    CHECK(client->peer_id() == s_sk.public_key(),
          "client peer_id == server pubkey");
}

static void test_identity_via_initial() {
    printf("\n=== 3. Initial 路径认证（C-API outbound 生产路径） ===\n");
    auto c_sk = base::SecretKey::generate();
    auto s_sk = base::SecretKey::generate();
    auto s_cid = protocol::ConnectionId::generate();
    auto c_cid = protocol::ConnectionId::generate();

    // 服务端 inbound conn（Initial 到达时仍处 Initial 状态，走 B9 bypass 完成）
    auto server = std::make_shared<Connection>(
        make_cfg(s_sk, Direction::Inbound, s_cid, c_cid));

    auto body = make_identity_body(c_sk);
    auto wire = build_initial_wire(s_cid, c_cid, &body);
    server->handle_packet(util::Bytes(
        std::span<const std::uint8_t>(wire.data(), wire.size())));
    CHECK(server->peer_authenticated(), "server peer_authenticated after Initial");
    CHECK(server->peer_id() == c_sk.public_key(),
          "server peer_id == client pubkey (Initial path)");
    CHECK(server->state() == ConnState::Established,
          "server Established (old fast-complete path intact)");
}

static void test_forged_signature_rejected() {
    printf("\n=== 4. 伪造签名拒绝 ===\n");
    auto s_sk = base::SecretKey::generate();
    auto attacker_sk = base::SecretKey::generate();
    auto server = std::make_shared<Connection>(make_cfg(
        s_sk, Direction::Inbound,
        protocol::ConnectionId::generate(), protocol::ConnectionId()));
    server->force_psk_established();
    auto old_peer = server->peer_id();

    // 声明受害者公钥，但用攻击者私钥签名 → 验签必败
    protocol::PskIdentityFrame f;
    f.created_at_unix = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    auto victim_pub = attacker_sk.public_key();  // 自报任意 pub
    std::memcpy(f.node_pub.data(), victim_pub.data(), 32);
    auto msg = protocol::psk_identity_signed_content(f);
    auto sig = attacker_sk.sign(std::span<const std::uint8_t>(msg.data(), msg.size()));
    std::memcpy(f.signature.data(), sig.data(), sig.size());
    sig[0] ^= 0xFF;  // 篡改签名
    std::memcpy(f.signature.data(), sig.data(), sig.size());
    auto body = protocol::encode_psk_identity_frame(f);

    CHECK(!server->handle_psk_identity_frame(
              std::span<const std::uint8_t>(body.data(), body.size())),
          "tampered signature rejected");
    CHECK(!server->peer_authenticated(), "not authenticated after forgery");
    CHECK(server->peer_id() == old_peer, "peer_id unchanged (old behavior)");
}

static void test_expired_timestamp_rejected() {
    printf("\n=== 5a. 超窗时间戳拒绝（防重放） ===\n");
    auto c_sk = base::SecretKey::generate();
    auto server = std::make_shared<Connection>(make_cfg(
        base::SecretKey::generate(), Direction::Inbound,
        protocol::ConnectionId::generate(), protocol::ConnectionId()));
    server->force_psk_established();

    auto body = make_identity_body(c_sk, -3600);  // 1 小时前
    CHECK(!server->handle_psk_identity_frame(
              std::span<const std::uint8_t>(body.data(), body.size())),
          "expired timestamp rejected");
    CHECK(!server->peer_authenticated(), "not authenticated after replay");
}

static void test_old_peer_compat() {
    printf("\n=== 5b. 老对端兼容（Initial 无身份帧） ===\n");
    auto s_sk = base::SecretKey::generate();
    auto s_cid = protocol::ConnectionId::generate();
    auto c_cid = protocol::ConnectionId::generate();
    auto server = std::make_shared<Connection>(
        make_cfg(s_sk, Direction::Inbound, s_cid, c_cid));

    auto wire = build_initial_wire(s_cid, c_cid, nullptr);  // 裸 Initial
    server->handle_packet(util::Bytes(
        std::span<const std::uint8_t>(wire.data(), wire.size())));
    CHECK(server->state() == ConnState::Established,
          "old peer still fast-completes to Established");
    CHECK(!server->peer_authenticated(),
          "no identity frame -> not authenticated (downgrade)");
    CHECK(server->peer_id() == s_sk.public_key(),
          "peer_id keeps old default (local key)");
}

static void test_zerortt_ticket_peer_id() {
    printf("\n=== 6. L3: 0-RTT resume ticket peer_id ===\n");
    auto local_sk = base::SecretKey::generate();
    auto peer_sk = base::SecretKey::generate();
    SessionTicket ticket;
    ticket.peer_cid = protocol::ConnectionId::generate();
    ticket.peer_node_id = peer_sk.public_key();
    ticket.alpn = "ctrl/1";

    auto cfg = make_cfg(local_sk, Direction::Outbound,
                        protocol::ConnectionId::generate(), protocol::ConnectionId());
    cfg.resume_ticket = ticket;
    auto conn = std::make_shared<Connection>(std::move(cfg));
    CHECK(conn->peer_id() == peer_sk.public_key(),
          "resumed conn peer_id == ticket.peer_node_id");
    CHECK(conn->peer_authenticated() == false,
          "ticket alone does not set authenticated (needs fresh verify)");
}

int main() {
    test_frame_codec();
    test_identity_via_1rtt();
    test_identity_via_initial();
    test_forged_signature_rejected();
    test_expired_timestamp_rejected();
    test_old_peer_compat();
    test_zerortt_ticket_peer_id();

    printf("\n========================================\n");
    printf("PASS: %d  FAIL: %d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
